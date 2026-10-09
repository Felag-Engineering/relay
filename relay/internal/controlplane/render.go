package controlplane

import (
	"context"
	"fmt"
	"sort"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/capability"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/jobs"
)

// The renderers below turn what the capability layer already decided — a
// capability.PlanResult, a Job's persisted Tasks — into the values both
// execution surfaces put on the wire. They are pure presentation: nothing
// here dispatches, evaluates Policy, or chooses an outcome (invariant 10).
//
// Each surface keeps its own tagged output structs, because the two wire
// contracts differ in omitempty and schema annotations. The Rendered* types
// carry no tags and list the same fields, in the same order and of the same
// types, as those surface structs, so a surface converts with a plain Go
// struct conversion (tags are ignored by it). A field added to one side but
// not the other stops compiling rather than silently drifting.

// PlanAdvisory is the fixed point-in-time disclaimer every plan response
// carries (ADR-0011): a Plan's verdicts are a snapshot, not a guarantee —
// Policy may change between the Plan and a later real run.
const PlanAdvisory = "point-in-time; Policy may change between plan and apply (ADR-0011)"

// JobResultReader is the read-only view over a Job's persisted Tasks that
// RenderJobResults needs. Read-only by construction: no Create/Update. Each
// surface's own reader interface has the same method set and satisfies it.
type JobResultReader interface {
	GetJob(ctx context.Context, id string) (jobs.Job, error)
	TasksByJob(ctx context.Context, jobID string) ([]jobs.Task, error)
}

// RenderedTaskResult is one Task's per-Node result, before a surface tags it.
type RenderedTaskResult struct {
	NodeID             string
	Outcome            string
	ExitCode           *int32
	Stdout             string
	Stderr             string
	StdoutTruncated    bool
	StderrTruncated    bool
	DurationMS         int64
	RefusalExplanation string
}

// RenderedVerdict is one Node's Plan verdict, before a surface tags it.
type RenderedVerdict struct {
	NodeID             string
	Verdict            string
	DecidingRule       string
	Reason             string
	RefusalExplanation string
	Outdated           bool
}

// RenderedRejection is why a Plan would be refused, before a surface tags it.
type RenderedRejection struct {
	Reason  string
	Matched int
	Cap     int
	Class   string
}

// RenderedPlan is a rendered capability.PlanResult. Verdicts is never nil.
type RenderedPlan struct {
	Matched         int
	Verdicts        []RenderedVerdict
	WouldBeRejected *RenderedRejection
	Advisory        string
}

// ExitCode returns the exit_code to render for task, or nil when no real
// process exit status exists — the #207/#253 did-not-run disambiguation (see
// each surface's per-Node result doc comment). A real status exists only when
// the Task actually resolved as success/failure AND the daemon reported a
// non-negative code: the daemon's -1 "no exit status" sentinel (spawn failure,
// wait failure, signal-kill, timeout/cancel kill, denied-before-spawn — a real
// Unix exit status is always 0-255), the Relay's synthesized zero value
// (unreachable, version_refused), and — since #632 — the Relay's own -1 on a
// failure row whose daemon report the wire boundary refused as a protocol
// violation (it may well have executed; what happened is unknown) all render
// as no exit_code at all. This is pure presentation — the stored jobs.Task
// and the wire contract (/proto) are untouched.
func ExitCode(task jobs.Task) *int32 {
	switch task.Outcome {
	case jobs.OutcomeSuccess, jobs.OutcomeFailure:
		if task.ExitCode >= 0 {
			code := task.ExitCode
			return &code
		}
	}
	return nil
}

// RenderTaskResult renders one jobs.Task. DurationMS is 0 when the Task was
// never dispatched (DispatchedAt zero — e.g. OutcomeUnreachable/an offline
// Node, or a Pending Task cancelled before it was ever sent), never a
// fabricated negative/huge value. ExitCode is nil whenever no real process
// exit status exists — see ExitCode.
func RenderTaskResult(task jobs.Task) RenderedTaskResult {
	stdout, stdoutTruncated := TruncateOutput(task.Stdout)
	stderr, stderrTruncated := TruncateOutput(task.Stderr)

	var durationMS int64
	if !task.DispatchedAt.IsZero() && !task.ResolvedAt.IsZero() {
		durationMS = task.ResolvedAt.Sub(task.DispatchedAt).Milliseconds()
	}

	return RenderedTaskResult{
		NodeID:             task.NodeID,
		Outcome:            jobs.OutcomeName(task.Outcome),
		ExitCode:           ExitCode(task),
		Stdout:             stdout,
		Stderr:             stderr,
		StdoutTruncated:    stdoutTruncated,
		StderrTruncated:    stderrTruncated,
		DurationMS:         durationMS,
		RefusalExplanation: capability.RefusalExplanation(task.Outcome),
	}
}

// RenderJobResults re-reads jobID and renders every one of its Tasks, sorted
// by NodeID for a stable response. It is the shared path for a dispatch's own
// result and a later polling re-read of the same Job, on both surfaces.
func RenderJobResults(ctx context.Context, results JobResultReader, jobID string) ([]RenderedTaskResult, error) {
	items, _, err := RenderJobState(ctx, results, jobID)
	return items, err
}

// Job statuses reported by a surface that returns a Job before it finishes
// (#895). A Job is running while any of its Tasks is unresolved, and complete
// once every Task has a terminal outcome.
const (
	JobStatusRunning  = "running"
	JobStatusComplete = "complete"
)

// RenderJobState is RenderJobResults plus the Job's status: JobStatusRunning if
// any Task is not yet Resolved, else JobStatusComplete.
func RenderJobState(ctx context.Context, results JobResultReader, jobID string) ([]RenderedTaskResult, string, error) {
	if _, err := results.GetJob(ctx, jobID); err != nil {
		return nil, "", fmt.Errorf("get job %q: %w", jobID, err)
	}
	tasks, err := results.TasksByJob(ctx, jobID)
	if err != nil {
		return nil, "", fmt.Errorf("list tasks for job %q: %w", jobID, err)
	}

	status := JobStatusComplete
	items := make([]RenderedTaskResult, 0, len(tasks))
	for _, task := range tasks {
		if task.State != jobs.DispatchStateResolved {
			status = JobStatusRunning
		}
		items = append(items, RenderTaskResult(task))
	}
	sort.Slice(items, func(i, j int) bool { return items[i].NodeID < items[j].NodeID })
	return items, status, nil
}

// RenderPlan renders a capability.PlanResult: verdicts sorted by NodeID for a
// stable response, and WouldBeRejected derived from pr.NoNodesMatched (reason
// "no_nodes_matched"), else pr.CapExceeded (reason "exceeds_cap"), else
// pr.Frozen (reason "frozen"). A zero match is reported first because
// Verdicts is empty and nothing would dispatch even after a Freeze lifted —
// the same "the reason nothing was asked" rule that already puts exceeds_cap
// ahead of frozen. Zero-match and over-cap cannot occur together under
// BlastCap, whose caps are clamped positive. A Plan can otherwise be both
// over-cap and Frozen at once (Service.Plan computes Frozen before the cap
// check); the over-cap report takes priority there since it is the reason the
// query fan-out never even ran (Verdicts is empty in that case too).
//
// The ordering reports decisions the capability layer already made; it
// decides nothing itself.
func RenderPlan(pr capability.PlanResult) RenderedPlan {
	verdicts := make([]RenderedVerdict, 0, len(pr.Verdicts))
	for _, v := range pr.Verdicts {
		verdicts = append(verdicts, RenderedVerdict{
			NodeID:             v.NodeID,
			Verdict:            VerdictName(v.Status),
			DecidingRule:       v.DecidingRule,
			Reason:             v.Reason,
			RefusalExplanation: capability.VerdictExplanation(v.Status),
			Outdated:           v.Outdated,
		})
	}
	sort.Slice(verdicts, func(i, j int) bool { return verdicts[i].NodeID < verdicts[j].NodeID })

	out := RenderedPlan{Matched: pr.Matched, Verdicts: verdicts, Advisory: PlanAdvisory}
	switch {
	case pr.NoNodesMatched:
		out.WouldBeRejected = &RenderedRejection{Reason: "no_nodes_matched"}
	case pr.CapExceeded != nil:
		out.WouldBeRejected = &RenderedRejection{
			Reason:  "exceeds_cap",
			Matched: pr.CapExceeded.Matched,
			Cap:     pr.CapExceeded.Cap,
			Class:   jobs.RiskClassName(pr.CapExceeded.Class),
		}
	case pr.Frozen:
		out.WouldBeRejected = &RenderedRejection{Reason: "frozen"}
	}
	return out
}
