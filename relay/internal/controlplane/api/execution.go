package api

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sort"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/authz"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/capability"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/jobs"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/opvocab"
)

// execution.go is the Control API's execution slice (#356, ADR-0010): the REST
// twin of the MCP execution tools, over the SAME capability layer.
//
// Every route here is a thin adapter — decode → parse Selector → build the
// Action → dispatch (or Plan) through the injected Executor → render. It
// evaluates no Policy, checks no blast cap, and makes no authorization
// decision of its own; each of those is the capability layer's, so both
// surfaces inherit one answer (invariant 10). The structural half of that
// promise is no_dispatch_test.go in this package: a route that reached around
// the Executor to a capability.Service, capability.New, or newDispatch fails
// the guard.
//
// **Raw Exec's admin gate is deliberately NOT re-implemented here.**
// authz.RoleGate already maps jobs.ActionRawExec → RoleAdmin for every
// surface, and package authz's own doc states the reason: "A surface that
// gated Raw Exec itself would be a second control path, and the first one to
// be forgotten." So handleRawExec dispatches and renders the refusal the
// capability layer returns (403), rather than pre-checking the role. The
// admin-only acceptance is proven against that path, not against a local copy
// of the ladder.

// Executor is the narrow capability-layer entry point the execution routes
// dispatch through — capability.Service.Run/Plan's exact shape, declared
// locally so this package never names *capability.Service itself (mirroring
// mcp.Executor, and TokenMinter/Freezer's style here). *capability.Service
// satisfies it structurally; the composition root passes it in.
//
// CancelJob arrived with the Job routes (#357, jobs.go) and completes the
// mirror of capability.Service's execution methods. It stays on this one
// interface rather than a separate JobCanceller because the composition root
// passes a single *capability.Service for all three — one capability layer,
// one seam (invariant 10).
type Executor interface {
	Run(ctx context.Context, p capability.Principal, sel capability.Selector, act jobs.Action) ([]capability.NodeResult, error)
	Plan(ctx context.Context, p capability.Principal, sel capability.Selector, act jobs.Action) (capability.PlanResult, error)
	CancelJob(ctx context.Context, p capability.Principal, jobID string) error
}

// JobResultReader is the read-only view over a Job's persisted Tasks the
// execution routes use to render per-Node results after a dispatch returns.
// Read-only by construction: no Create/Update — a route cannot write Job state
// through it.
type JobResultReader interface {
	GetJob(ctx context.Context, id string) (jobs.Job, error)
	TasksByJob(ctx context.Context, jobID string) ([]jobs.Task, error)
}

// maxTimeoutSeconds bounds timeout_seconds on both execution routes: 24h.
// Deliberately identical to the MCP execution tools' bound — the two surfaces
// adapt one capability layer, so a caller must not discover a different
// contract depending on which door it used. [3/7]'s OpenAPI spec publishes it.
const maxTimeoutSeconds = 24 * 60 * 60

// maxRenderedOutputBytes caps how much of a Task's stdout/stderr each per-Node
// result carries inline; beyond it the matching *_truncated flag is set rather
// than growing the response unbounded (a Raw Exec Task's output is otherwise
// unconstrained). Mirrors the MCP tools' cap for the same parity reason.
const maxRenderedOutputBytes = 4096

// planAdvisory is the fixed point-in-time disclaimer every plan response
// carries (ADR-0011): verdicts are a snapshot, not a guarantee — Policy may
// change between the plan and a later real run.
const planAdvisory = "point-in-time; Policy may change between plan and apply (ADR-0011)"

// ---------------------------------------------------------------------------
// Request bodies
// ---------------------------------------------------------------------------

// runOperationRequest is POST /api/v1/operations' body — the typed path
// (ADR-0001). Args are named Operation arguments, validated by NAME against
// the vocabulary before dispatch (see buildOperationAction).
type runOperationRequest struct {
	Selector       string            `json:"selector"`
	Operation      string            `json:"operation"`
	Args           map[string]string `json:"args"`
	TimeoutSeconds int32             `json:"timeout_seconds"`
	Plan           bool              `json:"plan"`
}

// rawExecRequest is POST /api/v1/raw-exec's body: argv ONLY — no shell, no
// client-side splitting, no string-command field (ADR-0001, invariant 1).
// Always risk class mutate (ADR-0012), so it always takes the mutate-cap, and
// it always requires the admin role via authz.RoleGate.
type rawExecRequest struct {
	Selector       string   `json:"selector"`
	Argv           []string `json:"argv"`
	TimeoutSeconds int32    `json:"timeout_seconds"`
	Plan           bool     `json:"plan"`
}

// ---------------------------------------------------------------------------
// Response bodies
// ---------------------------------------------------------------------------

// perNodeResult is one Node's Task outcome.
//
// ExitCode is a pointer so it is OMITTED whenever no real process exit status
// exists (#207/#253): the daemon uses -1 exclusively as its "no exit status"
// sentinel (denied-before-spawn, spawn failure, signal-kill, timeout/cancel
// kill) and Relay-synthesized outcomes (unreachable, version_refused) carry
// only a zero value. Rendering either as a plausible `0` would let a caller
// read "did not run" as "ran and succeeded"; Outcome is the authoritative
// did-it-run state.
type perNodeResult struct {
	NodeID          string `json:"node_id"`
	Outcome         string `json:"outcome"`
	ExitCode        *int32 `json:"exit_code,omitempty"`
	Stdout          string `json:"stdout,omitempty"`
	Stderr          string `json:"stderr,omitempty"`
	StdoutTruncated bool   `json:"stdout_truncated,omitempty"`
	StderrTruncated bool   `json:"stderr_truncated,omitempty"`
	DurationMS      int64  `json:"duration_ms"`
}

// perNodeVerdict is one Node's plan-mode Policy verdict (ADR-0011).
type perNodeVerdict struct {
	NodeID       string `json:"node_id"`
	Verdict      string `json:"verdict"`
	DecidingRule string `json:"deciding_rule,omitempty"`
	Reason       string `json:"reason,omitempty"`
	Outdated     bool   `json:"outdated,omitempty"`
}

// wouldBeRejected reports why a Plan's real counterpart would be refused
// before dispatch — over the blast cap, or the Relay frozen. A Plan reports
// these INSIDE the response rather than erroring (ADR-0011): the whole point
// is to learn the answer without triggering it.
type wouldBeRejected struct {
	Reason  string `json:"reason"`
	Matched int    `json:"matched,omitempty"`
	Cap     int    `json:"cap,omitempty"`
	Class   string `json:"class,omitempty"`
}

// planResponse is a plan=true response. It carries no job_id: a Plan creates
// no Job (see executionResponse).
type planResponse struct {
	Matched         int              `json:"matched"`
	Verdicts        []perNodeVerdict `json:"verdicts"`
	WouldBeRejected *wouldBeRejected `json:"would_be_rejected,omitempty"`
	Advisory        string           `json:"advisory"`
}

// pendingApprovalResponse is what a PARKED dispatch returns (#270, ADR-0027).
//
// It is a 202, not an error, and the distinction is deliberate. Nothing was
// denied and nothing ran: the dispatch is suspended awaiting a decision it may
// well receive. Rendering a park as a failure teaches operators that the
// approval mechanism is something breaking — which is how a safety feature gets
// switched off — and rendering it as a 200 would let a caller read "waiting for
// a human" as "done".
//
// There is no job_id and no results field at all, rather than empty ones: a
// parked dispatch creates no Job, so there is nothing to poll and nothing to
// read back. What the caller gets instead is everything needed to move it
// along — who to point at what, and by when.
type pendingApprovalResponse struct {
	// Status is the constant "pending_approval", so a client branches on a
	// stable value rather than on the absence of other fields.
	Status       string   `json:"status"`
	RequestID    string   `json:"request_id"`
	PlanHash     string   `json:"plan_hash"`
	Summary      string   `json:"summary"`
	MatchedRules []string `json:"matched_rules"`
	Progress     string   `json:"progress"`
	ExpiresAt    string   `json:"expires_at"`
	// DecisionPath is where an approver answers. A convenience for building a
	// link, never a capability: following it still requires an Account
	// credential the requesting session does not hold.
	DecisionPath string `json:"decision_path"`
}

// statusPendingApproval is pendingApprovalResponse.Status's only value.
const statusPendingApproval = "pending_approval"

// executionResponse is a real (plan=false) dispatch response.
//
// JobID carries omitempty deliberately (#207/#253): it is present only when a
// Job was actually created, so an ABSENT job_id always means nothing was
// dispatched (a zero-match Selector), never a failed-but-created Job. Results
// is always rendered as an array, never null.
type executionResponse struct {
	JobID   string          `json:"job_id,omitempty"`
	Results []perNodeResult `json:"results"`
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

// handleRunOperation implements POST /api/v1/operations: run a structured
// Operation against a Selector's matched Nodes through the capability layer,
// or (plan=true) report per-Node Policy verdicts without executing.
//
// Requires the operator role, enforced centrally by authz.RoleGate via the
// capability layer — never re-derived here.
func handleRunOperation(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, ok := principal(w, r)
		if !ok {
			return
		}

		var req runOperationRequest
		if err := decodeJSON(w, r, &req); err != nil {
			writeProblem(w, http.StatusBadRequest, "invalid request body", err.Error())
			return
		}

		sel, err := capability.ParseSelector(req.Selector)
		if err != nil {
			writeProblem(w, http.StatusBadRequest, "invalid selector", err.Error())
			return
		}

		act, err := buildOperationAction(req.Operation, req.Args, req.TimeoutSeconds)
		if err != nil {
			// Unknown operation name, unknown/missing argument name, or an
			// out-of-range timeout: all malformed input, never a Policy verdict.
			// Rendering these as 400 rather than letting them reach dispatch is
			// what keeps a misspelled argument from coming back as
			// denied_by_policy (#345).
			writeProblem(w, http.StatusBadRequest, "invalid operation request", err.Error())
			return
		}

		dispatchOrPlan(w, r, d, p, sel, act, req.Plan)
	}
}

// handleRawExec implements POST /api/v1/raw-exec: run an arbitrary argv
// verbatim against a Selector's matched Nodes — ADR-0001's regex-gated escape
// hatch, always risk class mutate (ADR-0012), always admin-only.
//
// The admin requirement is NOT checked here: authz.RoleGate answers it for
// every surface (see this file's header). An operator's call therefore reaches
// the capability layer and comes back as a 403 refusal, audited as a refusal
// like any other — which is the behaviour the acceptance criterion pins.
func handleRawExec(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, ok := principal(w, r)
		if !ok {
			return
		}

		var req rawExecRequest
		if err := decodeJSON(w, r, &req); err != nil {
			writeProblem(w, http.StatusBadRequest, "invalid request body", err.Error())
			return
		}
		if len(req.Argv) == 0 {
			writeProblem(w, http.StatusBadRequest, "argv required",
				"raw_exec requires a non-empty argv; it is executed verbatim, never through a shell (ADR-0001)")
			return
		}

		sel, err := capability.ParseSelector(req.Selector)
		if err != nil {
			writeProblem(w, http.StatusBadRequest, "invalid selector", err.Error())
			return
		}

		timeout, err := resolveTimeoutSeconds(req.TimeoutSeconds)
		if err != nil {
			writeProblem(w, http.StatusBadRequest, "invalid timeout_seconds", err.Error())
			return
		}

		act := jobs.Action{
			Kind:           jobs.ActionRawExec,
			RawExecArgv:    req.Argv,
			RiskClass:      jobs.RiskClassMutate, // always (ADR-0012, invariant 13)
			TimeoutSeconds: timeout,
		}

		dispatchOrPlan(w, r, d, p, sel, act, req.Plan)
	}
}

// dispatchOrPlan is the one branch both execution routes share: plan=true
// queries verdicts and executes nothing; plan=false dispatches and renders the
// resulting Job. Keeping it single-sourced means the two routes cannot drift
// in how they treat the plan flag or render a refusal.
func dispatchOrPlan(w http.ResponseWriter, r *http.Request, d Deps, p capability.Principal, sel capability.Selector, act jobs.Action, plan bool) {
	ctx := r.Context()

	// Defensive 500 on an unwired execution dependency, mirroring principal()'s
	// documented stance: the composition root always supplies both (see
	// apiSurface.Mount), so this is unreachable in production. It exists because
	// the alternative is a nil-interface panic that reaches the caller as a bare
	// connection reset — a composition mistake should read as a legible server
	// error, not as a network fault. Never a security decision.
	if d.Exec == nil || d.Jobs == nil {
		writeProblem(w, http.StatusInternalServerError, "execution unavailable",
			"the Control API was mounted without its execution dependencies")
		return
	}

	if plan {
		pr, err := d.Exec.Plan(ctx, p, sel, act)
		if err != nil {
			writeExecError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, renderPlan(pr))
		return
	}

	nodeResults, err := d.Exec.Run(ctx, p, sel, act)
	if err != nil {
		// A park is checked BEFORE writeExecError, because it is the one
		// non-nil error here that is not a refusal — see
		// pendingApprovalResponse.
		var parked *capability.ParkedError
		if errors.As(err, &parked) {
			writeJSON(w, http.StatusAccepted, pendingApprovalResponse{
				Status:       statusPendingApproval,
				RequestID:    parked.RequestID,
				PlanHash:     parked.PlanHash,
				Summary:      parked.Summary,
				MatchedRules: nonNil(parked.Rules),
				Progress:     parked.Progress,
				ExpiresAt:    rfc3339(parked.ExpiresAt),
				DecisionPath: "/api/v1/approvals/" + parked.RequestID + "/decision",
			})
			return
		}
		writeExecError(w, err)
		return
	}
	// Zero matched Nodes: no Job was created, so there is nothing to re-read
	// and no job_id to report (#207/#253) — an explicit empty result set.
	if len(nodeResults) == 0 {
		writeJSON(w, http.StatusOK, executionResponse{Results: []perNodeResult{}})
		return
	}

	out, err := renderJob(ctx, d.Jobs, nodeResults[0].JobID)
	if err != nil {
		// The dispatch itself already happened; only the read-back failed.
		writeProblem(w, http.StatusInternalServerError, "read job results failed", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, out)
}

// ---------------------------------------------------------------------------
// Action construction
// ---------------------------------------------------------------------------

// buildOperationAction resolves name in the native Operation vocabulary for its
// declared risk class (ADR-0012), validates the argument NAMES, and builds the
// jobs.Action.
//
// Both checks are fail-fast legibility pre-checks, never a second Policy
// decision (ADR-0002/0011, invariant 12): the daemon's live engine remains the
// gate on argument VALUES. The name validation is [opvocab.ValidateArgNames] —
// the same function the MCP surface calls — so a misspelled argument cannot
// come back as denied_by_policy on one surface and a clean 400 on the other
// (#345).
func buildOperationAction(name string, args map[string]string, timeoutSeconds int32) (jobs.Action, error) {
	timeout, err := resolveTimeoutSeconds(timeoutSeconds)
	if err != nil {
		return jobs.Action{}, err
	}

	d, ok := opvocab.Lookup(name)
	if !ok {
		return jobs.Action{}, fmt.Errorf("unknown operation %q", name)
	}
	if err := opvocab.ValidateArgNames(d, args); err != nil {
		return jobs.Action{}, err
	}

	return jobs.Action{
		Kind:           jobs.ActionOperation,
		OperationName:  name,
		OperationArgs:  args,
		RiskClass:      d.Risk,
		TimeoutSeconds: timeout,
	}, nil
}

// resolveTimeoutSeconds validates timeout_seconds against [0, maxTimeoutSeconds]
// (0 or omitted means "the daemon/engine default"). It never silently clamps an
// out-of-range value on an execution surface.
func resolveTimeoutSeconds(timeoutSeconds int32) (int32, error) {
	if timeoutSeconds < 0 {
		return 0, fmt.Errorf("timeout_seconds must be >= 0, got %d", timeoutSeconds)
	}
	if timeoutSeconds > maxTimeoutSeconds {
		return 0, fmt.Errorf("timeout_seconds must be <= %d (24h), got %d", maxTimeoutSeconds, timeoutSeconds)
	}
	return timeoutSeconds, nil
}

// ---------------------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------------------

// writeExecError maps an Executor error onto the HTTP status that describes it
// truthfully. Every case is a refusal the capability layer already decided and
// audited; this function only chooses how to say it.
//
//   - Freeze engaged  → 409 Conflict: the request is well-formed and the caller
//     is entitled, but the Relay's state refuses all new dispatch (ADR-0013).
//   - Blast cap       → 422 Unprocessable Content: well-formed and authorized,
//     rejected by a guardrail on the resolved fan-out (ADR-0004/0012). The
//     error text already states matched/cap/class.
//   - Unauthorized    → 403 Forbidden: the role ladder refused (authz.RoleGate)
//     — an operator reaching for Raw Exec lands here.
//   - anything else   → 500.
//
// Detail carries the error's own text: these are rule statements (which role
// is required, what the cap is), never secrets.
func writeExecError(w http.ResponseWriter, err error) {
	var frozenErr *capability.FrozenError
	if errors.As(err, &frozenErr) {
		writeProblem(w, http.StatusConflict, "relay is frozen", err.Error())
		return
	}
	var capErr *capability.CapExceededError
	if errors.As(err, &capErr) {
		writeProblem(w, http.StatusUnprocessableEntity, "blast radius cap exceeded", capErr.Error())
		return
	}
	if errors.Is(err, authz.ErrUnauthorized) {
		writeProblem(w, http.StatusForbidden, "forbidden", err.Error())
		return
	}
	writeProblem(w, http.StatusInternalServerError, "dispatch failed", err.Error())
}

// renderPlan renders a capability.PlanResult, verdicts sorted by NodeID for a
// stable response. would_be_rejected reports the cap rejection in preference to
// the Freeze when both apply: an over-cap Plan never ran its verdict fan-out at
// all (Verdicts is empty), so it is the more informative reason.
func renderPlan(pr capability.PlanResult) planResponse {
	verdicts := make([]perNodeVerdict, 0, len(pr.Verdicts))
	for _, v := range pr.Verdicts {
		verdicts = append(verdicts, perNodeVerdict{
			NodeID:       v.NodeID,
			Verdict:      verdictString(v.Status),
			DecidingRule: v.DecidingRule,
			Reason:       v.Reason,
			Outdated:     v.Outdated,
		})
	}
	sort.Slice(verdicts, func(i, j int) bool { return verdicts[i].NodeID < verdicts[j].NodeID })

	out := planResponse{Matched: pr.Matched, Verdicts: verdicts, Advisory: planAdvisory}
	switch {
	case pr.CapExceeded != nil:
		out.WouldBeRejected = &wouldBeRejected{
			Reason:  "exceeds_cap",
			Matched: pr.CapExceeded.Matched,
			Cap:     pr.CapExceeded.Cap,
			Class:   riskClassString(pr.CapExceeded.Class),
		}
	case pr.Frozen:
		out.WouldBeRejected = &wouldBeRejected{Reason: "frozen"}
	}
	return out
}

// renderJob re-reads jobID and renders every one of its Tasks, sorted by
// NodeID for a stable response.
func renderJob(ctx context.Context, results JobResultReader, jobID string) (executionResponse, error) {
	if _, err := results.GetJob(ctx, jobID); err != nil {
		return executionResponse{}, fmt.Errorf("get job %q: %w", jobID, err)
	}
	tasks, err := results.TasksByJob(ctx, jobID)
	if err != nil {
		return executionResponse{}, fmt.Errorf("list tasks for job %q: %w", jobID, err)
	}

	items := make([]perNodeResult, 0, len(tasks))
	for _, t := range tasks {
		items = append(items, perNodeResultFromTask(t))
	}
	sort.Slice(items, func(i, j int) bool { return items[i].NodeID < items[j].NodeID })

	return executionResponse{JobID: jobID, Results: items}, nil
}

// perNodeResultFromTask renders one jobs.Task. DurationMS is 0 when the Task
// was never dispatched (an unreachable Node, or a Pending Task cancelled before
// it was sent), never a fabricated value.
func perNodeResultFromTask(t jobs.Task) perNodeResult {
	stdout, stdoutTruncated := truncateOutput(t.Stdout)
	stderr, stderrTruncated := truncateOutput(t.Stderr)

	var durationMS int64
	if !t.DispatchedAt.IsZero() && !t.ResolvedAt.IsZero() {
		durationMS = t.ResolvedAt.Sub(t.DispatchedAt).Milliseconds()
	}

	return perNodeResult{
		NodeID:          t.NodeID,
		Outcome:         outcomeString(t.Outcome),
		ExitCode:        exitCodePtr(t),
		Stdout:          stdout,
		Stderr:          stderr,
		StdoutTruncated: stdoutTruncated,
		StderrTruncated: stderrTruncated,
		DurationMS:      durationMS,
	}
}

// exitCodePtr returns the exit_code to render, or nil when no real process
// exit status exists — see perNodeResult.ExitCode for why the distinction is
// load-bearing rather than cosmetic.
func exitCodePtr(t jobs.Task) *int32 {
	switch t.Outcome {
	case jobs.OutcomeSuccess, jobs.OutcomeFailure:
		if t.ExitCode >= 0 {
			code := t.ExitCode
			return &code
		}
	}
	return nil
}

// truncateOutput caps b at maxRenderedOutputBytes, reporting whether it did.
func truncateOutput(b []byte) (string, bool) {
	if len(b) <= maxRenderedOutputBytes {
		return string(b), false
	}
	return string(b[:maxRenderedOutputBytes]), true
}

// outcomeString renders a jobs.Outcome as the lowercase wire string. It must
// stay identical to the MCP surface's rendering: the same Task read through
// either door has to report the same outcome.
func outcomeString(o jobs.Outcome) string {
	switch o {
	case jobs.OutcomeSuccess:
		return "success"
	case jobs.OutcomeFailure:
		return "failure"
	case jobs.OutcomeTimeout:
		return "timeout"
	case jobs.OutcomeDeniedByPolicy:
		return "denied_by_policy"
	case jobs.OutcomeCancelled:
		return "cancelled"
	case jobs.OutcomeUnreachable:
		return "unreachable"
	case jobs.OutcomeVersionRefused:
		return "version_refused"
	case jobs.OutcomeUnsupported:
		return "unsupported"
	default:
		return "unspecified"
	}
}

// verdictString renders a capability.VerdictStatus as the lowercase wire
// string, mirroring the MCP surface for the same parity reason.
func verdictString(v capability.VerdictStatus) string {
	switch v {
	case capability.VerdictAllow:
		return "allow"
	case capability.VerdictDeny:
		return "deny"
	case capability.VerdictUnsupported:
		return "unsupported"
	default:
		return "unknown"
	}
}

// nonNil renders a nil slice as an empty JSON array rather than null, so a
// client never has to distinguish "no rules" from "the field was absent".
func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

// riskClassString renders a jobs.RiskClass for the would_be_rejected report.
func riskClassString(c jobs.RiskClass) string {
	switch c {
	case jobs.RiskClassRead:
		return "read"
	case jobs.RiskClassMutate:
		return "mutate"
	default:
		return "unspecified"
	}
}
