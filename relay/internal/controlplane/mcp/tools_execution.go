package mcp

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	schema "github.com/google/jsonschema-go/jsonschema"
	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/capability"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/controlplane"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/jobs"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/opvocab"
)

// This is an EXEC file (no_dispatch_test.go's relaxed partition, RB1 in the
// plan review): unlike mcp.go/tools_nodes.go/tools_operations.go/
// attribution.go, it is allowed to spell capability.Principal/Selector/
// NodeResult/FrozenError/CapExceededError — needed for Executor's signature
// and renderRunError's error rendering. It must never spell capability.
// Service, capability.New, or newDispatch — those remain forbidden in every
// mcp file, exec or not, by no_dispatch_test.go's unconditional rules; this
// file's only path to a real dispatch is the Executor interface below,
// injected by the composition root (cmd/relay/main.go), never constructed
// here.
//
// #118 wires these tools against a capability.Service but does NOT flip
// production dispatch on: main.go's capSvc still has no WithExecution call,
// so its dispatcher is the v0.0.5 default noopDispatcher — every matched
// Node reports OutcomeUnspecified, nothing is actually sent. That flip is
// isolated to #154 (owner DECISION 1). All acceptance for #118 is proven
// in-package against a test-wired execution capability (mcp_test.go/
// mcp_exec_test.go).
//
// #727 (ADR-0029 decision 6): run_operation and raw_exec are the answered
// retry's only callers. This file reaches exactly ONE decision-side function
// in tools_approval.go, the one file ADR-0029 decision 5 exempts —
// acceptElicitedAnswer — and renders whatever it returns through that same
// file's methods (decisionOutput, refusalOutput, dispatchError,
// reattachError, answerStateRefusedOutput); it never names DecideApproval,
// ApprovalDecision, Channel* or RecordDecision. The Job-bound branch
// (elicitedApprovedJobBound) is an AUDITED read (ADR-0025), exactly like
// get_job's own read-back: a bound Job's captured output may belong to
// another Account's dispatch, so it is read only after auditRead succeeds,
// and fails closed otherwise.

// Executor is the narrow capability-layer entry point the execution tools
// dispatch through — Service.Run and Service.CancelJob's exact shape,
// declared locally so no mcp file needs to import *capability.Service
// itself (mirrors NodeReader/PolicyReader/OperationLister in mcp.go, but for
// the execution stages: Selector -> authz -> blast-cap -> dispatch -> audit,
// invariant 10). *capability.Service satisfies Executor structurally (Go
// structural typing) — the composition root passes it in directly.
type Executor interface {
	Run(ctx context.Context, p capability.Principal, sel capability.Selector, act jobs.Action) ([]capability.NodeResult, error)
	CancelJob(ctx context.Context, p capability.Principal, jobID string) error

	// Plan is Service.Plan's exact shape (#119, ADR-0011): resolves sel,
	// authorizes p against act, and reports per-Node PolicyVerdicts instead
	// of dispatching — no Job/Task/dedup entry is ever created.
	Plan(ctx context.Context, p capability.Principal, sel capability.Selector, act jobs.Action) (capability.PlanResult, error)
}

// execAdapter narrows an arbitrary Executor down to a value whose dynamic
// type is execAdapter itself, exposing only Run/CancelJob — the execution-
// tool sibling of nodeReaderAdapter/policyReaderAdapter/operationListerAdapter
// (mcp.go): it is what makes a `.(*capability.Service)` type assertion on
// the value New() was given fail at runtime, not just at the static-
// interface boundary, so an exec tool can never reach back through it to
// EngageFreeze/ReleaseFreeze (which *capability.Service also exposes but
// Executor does not). RB1 (plan review): defined HERE, an exec file, rather
// than mcp.go, so mcp.go's source never spells a capability. token and stays
// a strict readFile under no_dispatch_test.go's guard — mcp.go wires this
// with an unqualified `execAdapter{r: exec}` composite literal.
type execAdapter struct {
	r Executor
}

func (a execAdapter) Run(ctx context.Context, p capability.Principal, sel capability.Selector, act jobs.Action) ([]capability.NodeResult, error) {
	return a.r.Run(ctx, p, sel, act)
}

func (a execAdapter) CancelJob(ctx context.Context, p capability.Principal, jobID string) error {
	return a.r.CancelJob(ctx, p, jobID)
}

func (a execAdapter) Plan(ctx context.Context, p capability.Principal, sel capability.Selector, act jobs.Action) (capability.PlanResult, error) {
	return a.r.Plan(ctx, p, sel, act)
}

// requirePrincipal returns the Principal controlplane.Authenticator.Middleware
// injected into ctx, or a legible tool error if none is present (RB4, plan
// review): run_operation/raw_exec/cancel_job must never dispatch or cancel
// with an unattributed (zero-value) capability.Principal. This is the
// execution tools' stricter sibling of attribution.go's logPrincipal, which
// silently no-ops on !ok — fine for a read tool, not for an RCE surface.
// Middleware always injects FoundingAdmin in production, so !ok is
// unreachable there; "prefer the more restrictive option" (AGENTS.md)
// requires the explicit guard anyway.
func requirePrincipal(ctx context.Context) (capability.Principal, error) {
	p, ok := controlplane.PrincipalFromContext(ctx)
	if !ok {
		return capability.Principal{}, fmt.Errorf("mcp: no authenticated principal in context; refusing to dispatch or cancel unattributed")
	}
	return p, nil
}

// renderPlan maps controlplane.RenderPlan onto the tool's PlanOutput; the
// ordering of would_be_rejected is documented there.
func renderPlan(pr capability.PlanResult) PlanOutput {
	rp := controlplane.RenderPlan(pr)
	verdicts := make([]PerNodeVerdict, 0, len(rp.Verdicts))
	for _, v := range rp.Verdicts {
		verdicts = append(verdicts, PerNodeVerdict(v))
	}
	out := PlanOutput{Matched: rp.Matched, Verdicts: verdicts, Advisory: rp.Advisory}
	if rp.WouldBeRejected != nil {
		r := WouldBeRejected(*rp.WouldBeRejected)
		out.WouldBeRejected = &r
	}
	return out
}

// planAndRender runs act against sel through exec.Plan and renders the
// result — plan=true's counterpart to dispatch. err from exec.Plan is ONLY
// an authz-refusal or infra failure (renderRunError's existing cases):
// cap/Freeze/no-Nodes-matched are reported INSIDE pr, never as an error
// (ADR-0011).
func planAndRender(ctx context.Context, exec Executor, p capability.Principal, sel capability.Selector, act jobs.Action) (PlanOutput, error) {
	pr, err := exec.Plan(ctx, p, sel, act)
	if err != nil {
		return PlanOutput{}, renderRunError(err)
	}
	return renderPlan(pr), nil
}

// perNodeResultFromTask renders one jobs.Task as a PerNodeResult
// (controlplane.RenderTaskResult). ExitCode is omitted whenever no real
// process exit status exists — see controlplane.ExitCode.
func perNodeResultFromTask(task jobs.Task) PerNodeResult {
	return PerNodeResult(controlplane.RenderTaskResult(task))
}

// renderJob re-reads jobID via results (the injected JobResultReader) and
// renders every one of its Tasks as a PerNodeResult, sorted by NodeID for a
// stable response (controlplane.RenderJobResults). It is the shared rendering
// path for run_operation/raw_exec's own result (once exec.Run returns a
// non-empty NodeResult set) and get_job's polling re-read of the same Job
// later.
func renderJob(ctx context.Context, results JobResultReader, jobID string) (ExecutionOutput, error) {
	rendered, err := controlplane.RenderJobResults(ctx, results, jobID)
	if err != nil {
		return ExecutionOutput{}, err
	}
	items := make([]PerNodeResult, 0, len(rendered))
	for _, r := range rendered {
		items = append(items, PerNodeResult(r))
	}
	return ExecutionOutput{JobID: jobID, Results: items}, nil
}

// renderRunError translates an error returned by Executor.Run into the tool
// error the SDK renders (IsError=true, message = err.Error()): a Freeze
// refusal becomes a distinct, legible "the Relay is frozen" message; a
// blast-radius cap rejection is returned verbatim (CapExceededError.Error()
// already states matched/cap/class); a zero-match refusal is returned
// verbatim too (NoNodesMatchedError.Error() already carries the token and
// the canonical Selector) — err itself, not just the unwrapped
// NoNodesMatchedError, so a joined audit-write failure stays visible to the
// caller (errors.As still finds the type on the joined err); anything else
// is wrapped generically.
func renderRunError(err error) error {
	var frozenErr *capability.FrozenError
	if errors.As(err, &frozenErr) {
		return fmt.Errorf("the Relay is frozen: %w", err)
	}
	var capErr *capability.CapExceededError
	if errors.As(err, &capErr) {
		return capErr
	}
	var nnmErr *capability.NoNodesMatchedError
	if errors.As(err, &nnmErr) {
		return err
	}
	return fmt.Errorf("mcp: dispatch failed: %w", err)
}

// buildOperationAction looks up name in ops' vocabulary for its declared
// RiskClass (ADR-0012), validates the argument NAMES against that Operation's
// published arg_constraints, and builds the resulting jobs.Action.
//
// The name checks are a thin **legibility pre-check** before ever reaching Run,
// never a second Policy decision (ADR-0002/0011, invariant 12): the daemon's
// live Policy engine and its validate_* functions remain the real gate on
// argument VALUES. What this catches is the failure mode where a malformed call
// is indistinguishable from a forbidden one (#345):
//
//   - an unknown Operation name → "unknown operation";
//   - an unknown ARGUMENT name (e.g. a misspelled "unitt") — otherwise silently
//     dropped, leaving the required arg empty so the daemon reports
//     denied_by_policy, which sends the agent into describe_node/narrow/retry
//     loops it can never exit because the request was malformed, not forbidden;
//   - a missing REQUIRED argument — otherwise the same empty-value denial.
//
// The argument-name half lives in [opvocab.ValidateArgNames], beside the
// ArgConstraints convention it reads, so this surface and the Control API's
// execution routes share ONE definition and cannot reopen #345 independently.
func buildOperationAction(ops OperationLister, name string, args map[string]string, timeoutSeconds int32) (jobs.Action, error) {
	timeoutSeconds, err := controlplane.ResolveTimeoutSeconds(timeoutSeconds)
	if err != nil {
		return jobs.Action{}, err
	}
	for _, d := range ops.Operations() {
		if d.Name == name {
			if err := opvocab.ValidateArgNames(d, args); err != nil {
				return jobs.Action{}, err
			}
			return jobs.Action{
				Kind:           jobs.ActionOperation,
				OperationName:  name,
				OperationArgs:  args,
				RiskClass:      d.Risk,
				TimeoutSeconds: timeoutSeconds,
			}, nil
		}
	}
	return jobs.Action{}, fmt.Errorf("unknown operation %q (see list_operations)", name)
}

// runOperationInput is run_operation's argument. Plan is additive (#119):
// omitted or false keeps today's real-dispatch behavior byte-identical to
// #118; plan=true resolves/authorizes/checks exactly as a real run would but
// executes nothing, returning per-Node Policy verdicts instead.
type runOperationInput struct {
	Selector  string            `json:"selector,omitempty" jsonschema:"Selector filter, e.g. 'node:role=web, relay:quarantine=on'. Every term must carry a node: or relay: prefix. Empty or omitted matches every Node."`
	Operation string            `json:"operation" jsonschema:"Operation name, e.g. 'system.facts' (see list_operations for the full vocabulary and each Operation's risk class)."`
	Args      map[string]string `json:"args,omitempty" jsonschema:"Operation arguments, validated against the Operation's own constraints (never a shell) — see list_operations for each Operation's argument names, types, and constraints."`
	// TimeoutSeconds omitted or 0 keeps today's default (the daemon/engine
	// default); [0, controlplane.MaxTimeoutSeconds] is enforced (RB6).
	TimeoutSeconds int32 `json:"timeout_seconds,omitempty" jsonschema:"Optional per-Task timeout in seconds. 0 or omitted uses the daemon/engine default; max 86400 (24h)."`
	// Plan: see the type doc comment above.
	Plan bool `json:"plan,omitempty" jsonschema:"If true, resolve/authorize/check exactly as a real run would but execute nothing — return per-Node Policy verdicts (allow/deny(rule)/unknown(offline)) plus would_be_rejected instead of dispatching (ADR-0011). Advisory and point-in-time: Policy may change before a real run."`
}

// rawExecInput is raw_exec's argument: argv only — no shell, no
// client-side splitting, no string-command field (ADR-0001, invariant 1).
type rawExecInput struct {
	Selector string   `json:"selector,omitempty" jsonschema:"Selector filter, e.g. 'node:role=web, relay:quarantine=on'. Every term must carry a node: or relay: prefix. Empty or omitted matches every Node."`
	Argv     []string `json:"argv" jsonschema:"Argv to execute verbatim on each matched Node — no shell, no client-side splitting (ADR-0001). The daemon's Policy regex decides per Node whether it is allowed."`
	// TimeoutSeconds: see runOperationInput's field doc.
	TimeoutSeconds int32 `json:"timeout_seconds,omitempty" jsonschema:"Optional per-Task timeout in seconds. 0 or omitted uses the daemon/engine default; max 86400 (24h)."`
	// Plan: see runOperationInput's field doc. raw_exec's Plan still probes
	// argv verbatim and always risk class mutate (ADR-0012, invariant 13) —
	// no client field can change either.
	Plan bool `json:"plan,omitempty" jsonschema:"If true, resolve/authorize/check exactly as a real run would but execute nothing — return per-Node Policy verdicts (allow/deny(rule)/unknown(offline)) plus would_be_rejected instead of dispatching (ADR-0011). Advisory and point-in-time: Policy may change before a real run."`
}

// tightenExecInputSchema infers In's schema, then makes it stricter than the
// reflect defaults on the two fields the reflected schema gets wrong for this
// RCE surface: argv (required, so drop the spurious "null" variant a
// []string picks up) and timeout_seconds (advertise the real
// [0, controlplane.MaxTimeoutSeconds] bound instead of int32 min/max). Pure tightening:
// the handler still unmarshals into In and controlplane.ResolveTimeoutSeconds stays as
// defense-in-depth. Invariant 10: this only narrows advertised inputs, it
// does not add a control path.
func tightenExecInputSchema[In any]() *schema.Schema {
	s, err := schema.For[In](nil)
	if err != nil {
		panic(fmt.Sprintf("mcp: infer input schema: %v", err))
	}
	if p := s.Properties["argv"]; p != nil {
		p.Type = "array" // was Types:["null","array"]
		p.Types = nil
	}
	if p := s.Properties["timeout_seconds"]; p != nil {
		p.Minimum = schema.Ptr(float64(0))
		p.Maximum = schema.Ptr(float64(controlplane.MaxTimeoutSeconds)) // 86400
	}
	return s
}

// dispatch runs act against sel through exec, then renders the full per-Node
// result set — the shared body of run_operation and raw_exec once each has
// built its own jobs.Action. A zero-match dispatch is refused by the
// capability layer as no_nodes_matched and comes back as a tool error via
// renderRunError.
//
// A PARKED dispatch (ADR-0027) is the one non-nil error from Run that is not a
// refusal, and it is rendered as a successful result carrying
// pending_approval — see PendingApprovalOutput for why reporting it as a tool
// error would actively mislead the agent that receives it. The parked value
// is ALSO returned directly (nil otherwise), so a caller can decide whether
// to render a question instead (elicit.go) without re-deriving it from the
// rendered output.
//
// It returns the whole RunOrPlanOutput rather than an ExecutionOutput so both
// execution tools share one construction of the result shape; having each call
// site assemble its own is how the park branch would get added to one tool and
// forgotten in the other.
func dispatch(ctx context.Context, exec Executor, results JobResultReader, p capability.Principal, sel capability.Selector, act jobs.Action) (RunOrPlanOutput, *capability.ParkedError, error) {
	nodeResults, err := exec.Run(ctx, p, sel, act)
	if err != nil {
		var parked *capability.ParkedError
		if errors.As(err, &parked) {
			return RunOrPlanOutput{
				Results:         []PerNodeResult{},
				PendingApproval: renderParked(parked),
			}, parked, nil
		}
		return RunOrPlanOutput{}, nil, renderRunError(err)
	}
	// *capability.Service can never return a zero-length nodeResults with a
	// nil error (a zero-match Selector is refused as no_nodes_matched before
	// this call returns). This branch exists only so an out-of-contract
	// Executor can't index an empty slice below.
	if len(nodeResults) == 0 {
		return RunOrPlanOutput{Results: []PerNodeResult{}}, nil, nil
	}
	out, err := renderJob(ctx, results, nodeResults[0].JobID)
	if err != nil {
		return RunOrPlanOutput{}, nil, err
	}
	return RunOrPlanOutput{JobID: out.JobID, Results: out.Results}, nil, nil
}

// renderParked projects a capability.ParkedError into the agent-facing
// pending_approval result. Every field is Relay-authored: the agent chose the
// Action, but none of the words describing it (ADR-0027).
func renderParked(parked *capability.ParkedError) *PendingApprovalOutput {
	rules := parked.Rules
	if rules == nil {
		rules = []string{}
	}
	return &PendingApprovalOutput{
		Status:        statusPendingApproval,
		RequestID:     parked.RequestID,
		PlanHash:      parked.PlanHash,
		Summary:       parked.Summary,
		MatchedRules:  rules,
		Progress:      parked.Progress,
		ExpiresAt:     parked.ExpiresAt.UTC().Format(time.RFC3339),
		DecisionPath:  "/api/v1/approvals/" + parked.RequestID + "/decision",
		NextStep:      pendingApprovalNextStep,
		TaskID:        parked.TaskID,
		TaskExpiresAt: controlplane.RFC3339(parked.TaskExpiresAt),
	}
}

// statusPendingApproval is PendingApprovalOutput.Status's only value. It is
// deliberately the same literal the Control API renders, so an operator
// watching both surfaces sees one vocabulary for one state.
const statusPendingApproval = "pending_approval"

// planModeClause is the SINGLE, IDENTICAL sentence cross-referencing plan
// mode from both run_operation's and raw_exec's Description (#120's plan:
// "IDENTICAL single delimited <PLAN CLAUSE>"). It is deliberately
// concept-level — it names plan mode and ADR-0011 but no param name — so it
// stays accurate regardless of whether #119 (which adds an actual `plan`
// input field to these same two tools) has landed yet, keeping that merge
// trivial.
const planModeClause = "Plan mode — the no-execution preview of whether each Node's live Policy would allow " +
	"the action (ADR-0011) — is the sanctioned probe before mutating; prefer it over learning Policy " +
	"boundaries by triggering real executions."

// resultShapeClause is the SINGLE, IDENTICAL result-shape contract sentence
// shared by run_operation's and raw_exec's Description (#207/#253, mirroring
// planModeClause's pattern): both tools render the same RunOrPlanOutput, so
// the documented job_id/exit_code presence semantics must be stated once and
// never drift between the two.
const resultShapeClause = "Result shape: per-Node exit_code is present only when a process actually ran and " +
	"exited with a status — a Task that never executed (denied_by_policy, unreachable, version_refused) or " +
	"was killed without one (timeout, cancelled, spawn failure) has no exit_code key at all, and outcome is " +
	"the authoritative state. A Task whose daemon report the Relay refused as a protocol violation (outcome " +
	"failure with no exit_code) may well have executed — what happened there is unknown, and stderr is " +
	"Relay-authored rather than the daemon's own bytes. job_id is present only when a Job was created; it is " +
	"absent on plan=true responses (a Plan executes nothing) and on a dispatch parked for approval, so an " +
	"absent job_id always means nothing was dispatched. A Selector that matches no Nodes is refused as " +
	"no_nodes_matched and creates no Job; with plan=true it is reported as would_be_rejected no_nodes_matched."

// toolRunOperation and toolRawExec are the two execution tools' registered
// Names, for elicit.go's question() call (and its own tests) to pass the
// same value sealed into a question's requestState as what is actually
// registered below.
//
// The sdkmcp.Tool{Name: ...} literals below MUST stay literal STRINGS,
// duplicating these constants' values, rather than referencing them:
// preflight_surface_test.go's PF-1 guard (security review cycle 2, SR1)
// AST-walks every &sdkmcp.Tool{Name: "..."} registration and fails closed —
// a t.Errorf naming the file and line, never a silent skip — on a Name that
// does not resolve to a string literal, specifically so a tool registered
// under a package-level name constant cannot evade the preflight-detector
// scan. Keep the two in sync; TestNoPreflightToolOrMethodIsRegistered's
// exact-set assertion catches a drift immediately.
const (
	toolRunOperation = "run_operation"
	toolRawExec      = "raw_exec"
)

// isAnsweredRetry reports whether req is a retried tool call carrying an
// answer to a parked approval (#727) — the one condition under which
// run_operation/raw_exec call answerThenDispatch instead of dispatching
// directly. True only when ALL of:
//
//   - ask is non-nil (nil exactly when the option is off, mcp.go:280 — a
//     server that never asks a question also never accepts an answer);
//   - clientCanBeAsked(req, p) is true (elicit.go): a client that could never
//     have been asked could never have received a question, so any
//     requestState/inputResponses it sends are stray, and the call is
//     treated exactly as today's call (AP-70, read literally) — its fields
//     are ignored rather than fed to the decision path. For claude-code this
//     also means off an OAuth session of a human Account (AP-78): such a
//     session's requestState/inputResponses are ignored exactly like an
//     unrecognised client's;
//   - the call actually carries a requestState, or at least one answered
//     input request.
//
// This only NARROWS which calls are treated as an answered retry (invariant
// 10): it can never turn an ordinary call into one, only the reverse.
func isAnsweredRetry(ask *questioner, req *sdkmcp.CallToolRequest, p capability.Principal) bool {
	if ask == nil || !clientCanBeAsked(req, p) {
		return false
	}
	return req.Params.RequestState != "" || len(req.Params.InputResponses) > 0
}

// answerThenDispatch is the ONE function run_operation and raw_exec both call
// for an answered retry (#727), so the branch cannot drift between them: it
// decides the answer FIRST, then re-enters the whole dispatch pipeline at
// most once. See the issue's decision table for the outcome-by-outcome
// contract; every branch here returns a tool RESULT carrying a decision or a
// refusal block, never a tool error, EXCEPT a dispatch error after the
// answer was taken (an ordinary dispatch failure, the accepted judgement
// call) and the Job-bound branch's unauditable-read failure.
//
// tool is the calling tool's registered name (toolRunOperation/toolRawExec)
// and in is its own typed input value — the SAME value passed to
// dispatch/ask.question, so the digest acceptElicitedAnswer checks can never
// drift from what emission sealed (issue #727 comment 2, point 1: there is
// no second digest function).
//
// From the decision side this names ONLY acceptElicitedAnswer, its result
// type, the elicitedOutcome constants, answerStateRefusedOutput and the
// result's own rendering methods (decisionOutput, refusalOutput,
// dispatchError, reattachError) — never DecideApproval, ApprovalDecision,
// Channel* or RecordDecision (ADR-0029 decision 5; no_decision_test.go).
func answerThenDispatch(
	ctx context.Context, req *sdkmcp.CallToolRequest, p capability.Principal,
	exec Executor, results JobResultReader, reads ReadAuditor, decider ApprovalDecider,
	ask *questioner, now func() time.Time, tool string, in any, sel capability.Selector, act jobs.Action,
) (*sdkmcp.CallToolResult, RunOrPlanOutput, error) {
	digest, err := callArgsDigest(in)
	if err != nil {
		return nil, RunOrPlanOutput{Results: []PerNodeResult{}, AnswerRefused: answerStateRefusedOutput()}, nil
	}

	r := acceptElicitedAnswer(ctx, decider, ask.opener(), now(), p, elicitedAnswer{
		RequestState:   req.Params.RequestState,
		InputResponses: req.Params.InputResponses,
		CallMeta:       req.Params.GetMeta(),
		Tool:           tool,
		ArgsDigest:     digest,
	})
	slog.Debug("mcp: answered retry", "tool", tool, "request_id", r.RequestID, "outcome", r.Outcome)

	switch r.Outcome {
	case elicitedApproved, elicitedLapsed, elicitedStillPending:
		// A concurrent approving retry, or a plain re-drive carrying no
		// request state at all, is now resolved in the capability layer
		// (#713, AP-77): Service.Run claims a single-Plan approval's release
		// exactly once, inside a store transaction, before it dispatches, and
		// a loser re-attaches to the winner's Job instead of dispatching a
		// second one. This branch therefore cannot mint a second Job.
		//
		// The elicitedApprovedJobBound branch below remains AP-67's narrower
		// answered-retry re-attach, and the two differ in one respect worth
		// keeping straight: that branch trusts the sealed request state and
		// re-attaches without re-checking the approval's deadline, while this
		// capability-layer claim is bounded by Satisfied(now) — a re-drive
		// past the deadline parks afresh rather than re-attaching forever
		// (AP-25).
		out, parked, err := dispatch(ctx, exec, results, p, sel, act)
		if err != nil {
			return nil, RunOrPlanOutput{}, r.dispatchError(err)
		}
		if parked != nil {
			// Whether a question replaces pending_approval is the capability
			// layer's created/observed askability call (AP-62), not this
			// function's: a partial quorum's park is OBSERVED and renders
			// pending_approval, while a fleet change or a lapse creates a
			// fresh, askable park. A question result cannot carry the
			// decision block either way — the SDK forbids structured content
			// alongside InputRequests — but the decision it answers is still
			// audited and readable on the Control API.
			if q, ok := ask.question(req, p, parked, tool, in); ok {
				return q, RunOrPlanOutput{}, nil
			}
		}
		out.Decision = r.decisionOutput(out)
		// If the caller advertises Tasks and this result is a
		// pending_approval, taskshim.go's confident rewrite replaces it with
		// a task result and the decision block above does not survive that
		// rewrite (plan review, ADOPTED as a comment). The decision stays
		// audited and readable on the Control API either way.
		return nil, out, nil

	case elicitedApprovedJobBound:
		if err := auditRead(ctx, reads, tool, ReadEvent{JobID: r.JobID}); err != nil {
			return nil, RunOrPlanOutput{}, r.reattachError(err)
		}
		job, err := renderJob(ctx, results, r.JobID)
		if err != nil {
			return nil, RunOrPlanOutput{}, r.reattachError(err)
		}
		out := RunOrPlanOutput{JobID: job.JobID, Results: job.Results}
		out.Decision = r.decisionOutput(out)
		return nil, out, nil

	case elicitedDenied:
		return nil, RunOrPlanOutput{Results: []PerNodeResult{}, Decision: r.decisionOutput(RunOrPlanOutput{})}, nil

	default:
		// elicitedRefused, and (fail closed) any Outcome this switch does not
		// recognise.
		return nil, RunOrPlanOutput{Results: []PerNodeResult{}, AnswerRefused: r.refusalOutput()}, nil
	}
}

// registerExecutionTools registers run_operation and raw_exec on srv — the
// two ADR-0003 execution meta-tools. Both are thin: ParseSelector -> build
// the Action -> requirePrincipal -> branch on plan -> render. Neither
// evaluates Policy or the blast-radius cap itself (invariant 10/12); both
// dispatch (or, when plan=true, query) through the SAME injected Executor,
// so every acceptance the capability layer already proves (Freeze/authz/cap/
// audit, at-most-once, plan mode) carries through unchanged.
//
// Their Descriptions are the ADR-0001 typed-path-by-default safety
// assumption engineered into words (#120): run_operation presents itself as
// the DEFAULT and raw_exec as the ESCAPE HATCH, both cross-reference plan
// mode via the identical planModeClause, and run_operation's steers a
// denied_by_policy result toward describe_node rather than blind retries.
//
// ask (elicit.go, S2b) is nil-receiver safe: a nil *questioner never asks, so
// a park always renders pending_approval exactly as before it existed.
// isAnsweredRetry gates the same nil-receiver-safe path (#727): an answered
// retry can only exist where a question could have been asked in the first
// place.
//
// reads is used only by the Job-bound re-attach branch (auditRead, ADR-0025:
// the re-attached Job's captured output may belong to another Account's
// dispatch, exactly get_job's case); decider and now are acceptElicitedAnswer's
// own parameters, threaded straight through from mcp.New's cfg.
func registerExecutionTools(srv *sdkmcp.Server, exec Executor, results JobResultReader, ops OperationLister, ask *questioner, reads ReadAuditor, decider ApprovalDecider, now func() time.Time) {
	sdkmcp.AddTool(srv, &sdkmcp.Tool{
		Name: "run_operation", // keep in sync with toolRunOperation (PF-1, see the const doc above)
		Description: "The default way to act on Nodes. Run a structured Operation (ADR-0001's typed, " +
			"native-argv path — never a shell) against a Selector's matched Nodes through the capability " +
			"layer (Selector -> authz -> blast-cap -> dispatch -> audit). Prefer run_operation over raw_exec " +
			"whenever a structured Operation expresses what you want to do; call list_operations first for " +
			"the vocabulary — each Operation's purpose, risk class, argument names/types/constraints, and a " +
			"usage example — so you pick the right one and build its args correctly, without trial-and-error. " +
			planModeClause + " If a result comes back outcome=denied_by_policy, call describe_node to see the " +
			"Node's effective Policy and narrow your request rather than guessing again. Blocks until every " +
			"matched Node's Task reaches a terminal outcome and returns per-Node results plus the Job id; " +
			"get_job re-reads the same Job later. " + resultShapeClause,
		InputSchema: tightenExecInputSchema[runOperationInput](),
	}, func(ctx context.Context, req *sdkmcp.CallToolRequest, in runOperationInput) (*sdkmcp.CallToolResult, RunOrPlanOutput, error) {
		logPrincipal(ctx, "run_operation")
		p, err := requirePrincipal(ctx)
		if err != nil {
			return nil, RunOrPlanOutput{}, err
		}

		sel, err := capability.ParseSelector(in.Selector)
		if err != nil {
			return nil, RunOrPlanOutput{}, fmt.Errorf("invalid selector: %w", err)
		}

		act, err := buildOperationAction(ops, in.Operation, in.Args, in.TimeoutSeconds)
		if err != nil {
			return nil, RunOrPlanOutput{}, err
		}

		if in.Plan {
			plan, err := planAndRender(ctx, exec, p, sel, act)
			if err != nil {
				return nil, RunOrPlanOutput{}, err
			}
			// JobID stays absent (a Plan creates no Job) and Results stays an
			// empty array, never null — #207/#253, see RunOrPlanOutput.
			return nil, RunOrPlanOutput{Results: []PerNodeResult{}, Plan: &plan}, nil
		}

		// An answered retry (#727) decides before anything dispatches, then
		// re-enters the pipeline below at most once itself — it never falls
		// through to the plain dispatch() call that follows. A plan=true
		// call never reaches here (it returned above), so a retry carrying
		// plan=true is handled exactly like today's call regardless of this
		// check (AP-70: "a call that did not park").
		if isAnsweredRetry(ask, req, p) {
			return answerThenDispatch(ctx, req, p, exec, results, reads, decider, ask, now, toolRunOperation, in, sel, act)
		}

		out, parked, err := dispatch(ctx, exec, results, p, sel, act)
		if err != nil {
			return nil, RunOrPlanOutput{}, err
		}
		// A question replaces pending_approval outright: the returned
		// CallToolResult carries InputRequests and no structuredContent, so
		// the SEP-2663 task shim — which keys off
		// structuredContent.pending_approval — passes it through untouched
		// and mints no task envelope (AP-71; ADR-0028 amendment 2026-09-24).
		// Service.Run may still have minted an orphan task handle above
		// (parked.TaskID) — expected and harmless, because nothing ever reads
		// it once the question is rendered instead; do NOT add a conditional
		// to Service.Run to suppress it.
		if parked != nil {
			if q, ok := ask.question(req, p, parked, toolRunOperation, in); ok {
				return q, RunOrPlanOutput{}, nil
			}
		}
		return nil, out, nil
	})

	sdkmcp.AddTool(srv, &sdkmcp.Tool{
		Name: "raw_exec", // keep in sync with toolRawExec (PF-1, see the const doc above)
		Description: "The escape hatch — use only when no structured Operation expresses the task. Run an " +
			"arbitrary argv (ADR-0001's regex-gated escape hatch) against a Selector's matched Nodes. Prefer " +
			"run_operation's typed path first: call list_operations to check whether a structured Operation " +
			"already covers your intent before reaching for raw_exec. Always risk class mutate (ADR-0012) " +
			"regardless of what argv does — raw_exec always takes the strict mutate-cap, even for a " +
			"read-only-looking command. argv runs verbatim — no shell, no client-side splitting — and the " +
			"daemon's Policy regex decides per Node whether it is allowed (a per-Node refusal renders " +
			"outcome=denied_by_policy). " + planModeClause + " " + resultShapeClause,
		InputSchema: tightenExecInputSchema[rawExecInput](),
	}, func(ctx context.Context, req *sdkmcp.CallToolRequest, in rawExecInput) (*sdkmcp.CallToolResult, RunOrPlanOutput, error) {
		logPrincipal(ctx, "raw_exec")
		p, err := requirePrincipal(ctx)
		if err != nil {
			return nil, RunOrPlanOutput{}, err
		}

		if len(in.Argv) == 0 {
			return nil, RunOrPlanOutput{}, fmt.Errorf("argv must not be empty")
		}

		sel, err := capability.ParseSelector(in.Selector)
		if err != nil {
			return nil, RunOrPlanOutput{}, fmt.Errorf("invalid selector: %w", err)
		}

		timeoutSeconds, err := controlplane.ResolveTimeoutSeconds(in.TimeoutSeconds)
		if err != nil {
			return nil, RunOrPlanOutput{}, err
		}
		// Raw Exec always takes RiskClassMutate by construction, regardless
		// of what argv does (ADR-0012, invariant 13) — no client field can
		// change this, plan mode included.
		act := jobs.Action{Kind: jobs.ActionRawExec, RawExecArgv: in.Argv, RiskClass: jobs.RiskClassMutate, TimeoutSeconds: timeoutSeconds}

		if in.Plan {
			plan, err := planAndRender(ctx, exec, p, sel, act)
			if err != nil {
				return nil, RunOrPlanOutput{}, err
			}
			// JobID stays absent (a Plan creates no Job) and Results stays an
			// empty array, never null — #207/#253, see RunOrPlanOutput.
			return nil, RunOrPlanOutput{Results: []PerNodeResult{}, Plan: &plan}, nil
		}

		// See run_operation's identical branch above.
		if isAnsweredRetry(ask, req, p) {
			return answerThenDispatch(ctx, req, p, exec, results, reads, decider, ask, now, toolRawExec, in, sel, act)
		}

		out, parked, err := dispatch(ctx, exec, results, p, sel, act)
		if err != nil {
			return nil, RunOrPlanOutput{}, err
		}
		// See run_operation's identical branch above for why this replaces
		// pending_approval outright and emits no task envelope (AP-71;
		// ADR-0028 amendment 2026-09-24).
		if parked != nil {
			if q, ok := ask.question(req, p, parked, toolRawExec, in); ok {
				return q, RunOrPlanOutput{}, nil
			}
		}
		return nil, out, nil
	})
}
