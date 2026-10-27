package api

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"github.com/Felag-Engineering/relay/relay/internal/authz"
	"github.com/Felag-Engineering/relay/relay/internal/capability"
	"github.com/Felag-Engineering/relay/relay/internal/controlplane"
	"github.com/Felag-Engineering/relay/relay/internal/jobs"
	"github.com/Felag-Engineering/relay/relay/internal/opvocab"
)

// execution.go is the Control API's execution slice (ADR-0010): the REST
// twin of the MCP execution tools, over the SAME capability layer.
//
// Every route here is a thin adapter — decode → parse Selector → build the
// Action → dispatch (or Plan) through the injected Executor → render. It
// evaluates no Policy, checks no blast cap, and makes no authorization
// decision of its own; each of those is the capability layer's, so both
// surfaces inherit one answer (invariant 10). The structural half of that
// promise is .golangci.yml's "adapter boundary" patterns and
// no_dispatch_test.go in this package: a route that reached around the
// Executor to a capability.Execution, capability.NewExecution, or newDispatch
// fails one of them.
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
// dispatch through — capability.Execution.Run/Plan's exact shape, declared
// locally so this package never names *capability.Execution itself (mirroring
// mcp.Executor, and TokenMinter/Freezer's style here). *capability.Execution
// satisfies it structurally; the composition root passes it in.
//
// CancelJob arrived with the Job routes (jobs.go) and completes the
// mirror of capability.Execution's execution methods. It stays on this one
// interface rather than a separate JobCanceller because the composition root
// passes the one *capability.Execution for all three — one capability layer,
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
// exists: the daemon's -1 "no exit status" sentinel
// (denied-before-spawn, spawn failure, signal-kill, timeout/cancel kill), the
// Relay's synthesized zero value (unreachable, version_refused), and the
// Relay's own -1 on a Task whose daemon report the wire boundary
// refused as a protocol violation (it may well have executed; what happened
// is unknown). Rendering any of these as a plausible `0` would let a caller
// read "did not run" or "unknown" as "ran and succeeded"; Outcome is the
// authoritative did-it-run state.
//
// RefusalExplanation carries a second author on a denied_by_policy row: stderr
// stays the Node's own verbatim reason, and RefusalExplanation is the Relay's
// framing of the boundary that reason belongs to. On a version_refused row the
// Relay authored both, so RefusalExplanation repeats stderr. Never infer the
// two agree, and never infer they differ.
type perNodeResult struct {
	NodeID             string `json:"node_id"`
	Outcome            string `json:"outcome"`
	ExitCode           *int32 `json:"exit_code,omitempty"`
	Stdout             string `json:"stdout,omitempty"`
	Stderr             string `json:"stderr,omitempty"`
	StdoutTruncated    bool   `json:"stdout_truncated,omitempty"`
	StderrTruncated    bool   `json:"stderr_truncated,omitempty"`
	DurationMS         int64  `json:"duration_ms"`
	RefusalExplanation string `json:"refusal_explanation,omitempty"`
}

// perNodeVerdict is one Node's plan-mode Policy verdict (ADR-0011).
//
// RefusalExplanation is the Relay's framing of the boundary a deny verdict
// belongs to; DecidingRule remains the daemon's rule text, verbatim — two
// different authors on the same verdict, exactly as on perNodeResult. Pass,
// RuleSection, RuleIndex, RuleLine and MatchedOn are likewise the daemon's
// answer, verbatim and display-only; RuleIndex is absent unless RuleSection is
// set.
type perNodeVerdict struct {
	NodeID             string `json:"node_id"`
	Verdict            string `json:"verdict"`
	DecidingRule       string `json:"deciding_rule,omitempty"`
	Pass               string `json:"pass,omitempty"`
	RuleSection        string `json:"rule_section,omitempty"`
	RuleIndex          *int   `json:"rule_index,omitempty"`
	RuleLine           int    `json:"rule_line,omitempty"`
	MatchedOn          string `json:"matched_on,omitempty"`
	Reason             string `json:"reason,omitempty"`
	RefusalExplanation string `json:"refusal_explanation,omitempty"`
	Outdated           bool   `json:"outdated,omitempty"`
}

// wouldBeRejected reports why a Plan's real counterpart would be refused
// before dispatch — over the blast cap, the Relay frozen, or no Node
// matched. A Plan reports these INSIDE the response rather than erroring
// (ADR-0011): the whole point is to learn the answer without triggering it.
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

// pendingApprovalResponse is what a PARKED dispatch returns (ADR-0027).
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
// JobID carries omitempty deliberately: it is present only when a
// Job was actually created, so an ABSENT job_id always means nothing was
// dispatched, never a failed-but-created Job. A zero-match dispatch is a 422
// no_nodes_matched refusal, so every 200 dispatch carries a job_id. Results
// is always rendered as an array, never null.
type executionResponse struct {
	JobID   string          `json:"job_id,omitempty"`
	Results []perNodeResult `json:"results"`
	Halt    *haltResponse   `json:"halt,omitempty"`
}

// haltResponse is why a mutate Job stopped sending after its first failure or
// timeout (execution.md, Halting a failing mutation). It is the field-for-field
// image of controlplane.RenderedHalt, so a surface cannot drift from the shared
// rendering. resolved has no omitempty: false is information.
type haltResponse struct {
	NodeID   string `json:"node_id"`
	Outcome  string `json:"outcome"`
	Resolved bool   `json:"resolved"`
	Reason   string `json:"reason"`
}

// haltResponseFrom is the struct conversion haltResponse exists for: a
// rendered halt, or nil for a Job that did not halt.
func haltResponseFrom(h *controlplane.RenderedHalt) *haltResponse {
	if h == nil {
		return nil
	}
	out := haltResponse(*h)
	return &out
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
		if !readJSONBody(w, r, &req) {
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
			// denied_by_policy.
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
		if !readJSONBody(w, r, &req) {
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

		timeout, err := controlplane.ResolveTimeoutSeconds(req.TimeoutSeconds)
		if err != nil {
			writeProblem(w, http.StatusBadRequest, "invalid timeout_seconds", err.Error())
			return
		}

		// No risk class: the capability layer fixes Raw Exec to mutate
		// (ADR-0012, invariant 13), and this adapter must not set it.
		act := jobs.Action{
			Kind:           jobs.ActionRawExec,
			RawExecArgv:    req.Argv,
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
				ExpiresAt:    controlplane.RFC3339(parked.ExpiresAt),
				DecisionPath: "/api/v1/approvals/" + parked.RequestID + "/decision",
			})
			return
		}
		writeExecError(w, err)
		return
	}
	// *capability.Execution can never reach this branch: a zero-match Selector
	// is refused as no_nodes_matched before Run returns. It exists only so an
	// out-of-contract Executor can't index an empty slice below.
	if len(nodeResults) == 0 {
		writeJSON(w, http.StatusOK, executionResponse{Results: []perNodeResult{}})
		return
	}

	out, err := renderJob(ctx, d.Jobs, nodeResults[0].JobID)
	if err != nil {
		// The Job already exists — either this call dispatched it, or it
		// re-attached to one an approval had already released (AP-77) —
		// only the read-back failed.
		writeProblem(w, http.StatusInternalServerError, "read job results failed", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, out)
}

// ---------------------------------------------------------------------------
// Action construction
// ---------------------------------------------------------------------------

// buildOperationAction resolves a Native name in the Operation vocabulary,
// validates the argument NAMES, and builds the jobs.Action. This adapter
// decides no risk class for any Operation (ADR-0012, invariant 13): the
// capability layer derives it. Any other name is a Template Operation and is
// forwarded with no argument check: the capability layer decides that too
// (ADR-0042, invariant 10).
//
// Both checks are fail-fast legibility pre-checks, never a second Policy
// decision (ADR-0002/0011, invariant 12): the daemon's live engine remains the
// gate on argument VALUES. The name validation is [opvocab.ValidateArgNames] —
// the same function the MCP surface calls — so a misspelled argument cannot
// come back as denied_by_policy on one surface and a clean 400 on the other.
func buildOperationAction(name string, args map[string]string, timeoutSeconds int32) (jobs.Action, error) {
	timeout, err := controlplane.ResolveTimeoutSeconds(timeoutSeconds)
	if err != nil {
		return jobs.Action{}, err
	}

	d, ok := opvocab.Lookup(name)
	if !ok {
		// Not Native, so a Template Operation (ADR-0021). This adapter decides
		// nothing about it (ADR-0042, invariant 10): no risk class, no
		// argument check — the capability layer resolves both over the
		// matched Nodes' own reports, and refuses a name none of them reports.
		if name == "" {
			return jobs.Action{}, fmt.Errorf("operation is required")
		}
		return jobs.Action{
			Kind:           jobs.ActionOperation,
			OperationName:  name,
			OperationArgs:  args,
			TimeoutSeconds: timeout,
		}, nil
	}
	if err := opvocab.ValidateArgNames(d, args); err != nil {
		return jobs.Action{}, err
	}

	return jobs.Action{
		Kind:           jobs.ActionOperation,
		OperationName:  name,
		OperationArgs:  args,
		TimeoutSeconds: timeout,
	}, nil
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
//   - No nodes matched → 422 Unprocessable Content: well-formed and
//     authorized, refused on the resolved fan-out (zero Nodes) before any
//     Job exists. Title "no nodes matched" is what distinguishes it from the
//     cap's 422; detail carries no_nodes_matched and the canonical Selector.
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
	var nnmErr *capability.NoNodesMatchedError
	if errors.As(err, &nnmErr) {
		// err itself, not just the unwrapped NoNodesMatchedError: a joined
		// audit-write failure must stay visible to the caller (errors.As
		// still finds the type on the joined err).
		writeProblem(w, http.StatusUnprocessableEntity, "no nodes matched", err.Error())
		return
	}
	// A Template no matched Node reports, or a Template call whose argument
	// names do not fit its slots (ADR-0042): malformed input, refused by the
	// capability layer after authorization, never a Policy verdict — the same
	// 400 an unknown Native argument gets at this adapter.
	var unknownErr *capability.UnknownOperationError
	var malformedErr *capability.MalformedCallError
	if errors.As(err, &unknownErr) || errors.As(err, &malformedErr) {
		writeProblem(w, http.StatusBadRequest, "invalid operation request", err.Error())
		return
	}
	if errors.Is(err, authz.ErrUnauthorized) {
		writeProblem(w, http.StatusForbidden, "forbidden", err.Error())
		return
	}
	writeProblem(w, http.StatusInternalServerError, "dispatch failed", err.Error())
}

// renderPlan maps controlplane.RenderPlan onto this surface's tagged types;
// the ordering of would_be_rejected is documented there.
func renderPlan(pr capability.PlanResult) planResponse {
	rp := controlplane.RenderPlan(pr)
	out := planResponse{Matched: rp.Matched, Verdicts: controlplane.MapSlice(rp.Verdicts, convertVerdict), Advisory: rp.Advisory}
	if rp.WouldBeRejected != nil {
		r := wouldBeRejected(*rp.WouldBeRejected)
		out.WouldBeRejected = &r
	}
	return out
}

// renderJob re-reads jobID and renders every one of its Tasks, sorted by
// NodeID for a stable response, with its halt when the capability layer halted
// it (controlplane.RenderJob).
func renderJob(ctx context.Context, results JobResultReader, jobID string) (executionResponse, error) {
	rendered, err := controlplane.RenderJob(ctx, results, jobID)
	if err != nil {
		return executionResponse{}, err
	}
	return executionResponse{
		JobID:   jobID,
		Results: controlplane.MapSlice(rendered.Results, perNodeResultFromRendered),
		Halt:    haltResponseFrom(rendered.Halt),
	}, nil
}

// perNodeResultFromTask renders one jobs.Task (controlplane.RenderTaskResult).
// ExitCode is nil whenever no real process exit status exists — see
// perNodeResult.ExitCode for why the distinction is load-bearing.
func perNodeResultFromTask(t jobs.Task) perNodeResult {
	return perNodeResultFromRendered(controlplane.RenderTaskResult(t))
}

// perNodeResultFromRendered and convertVerdict are the field-for-field struct
// conversions the Rendered* types exist for (see controlplane/render.go).
func perNodeResultFromRendered(r controlplane.RenderedTaskResult) perNodeResult {
	return perNodeResult(r)
}

func convertVerdict(v controlplane.RenderedVerdict) perNodeVerdict {
	return perNodeVerdict(v)
}

// nonNil renders a nil slice as an empty JSON array rather than null, so a
// client never has to distinguish "no rules" from "the field was absent".
func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}
