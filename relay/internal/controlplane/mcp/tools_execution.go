package mcp

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	schema "github.com/google/jsonschema-go/jsonschema"
	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/Felag-Engineering/relay/relay/internal/capability"
	"github.com/Felag-Engineering/relay/relay/internal/controlplane"
	"github.com/Felag-Engineering/relay/relay/internal/jobs"
	"github.com/Felag-Engineering/relay/relay/internal/opvocab"
)

// This is an EXEC file (listed in no_dispatch_test.go's execFiles): unlike
// mcp.go/tools_nodes.go/tools_operations.go/attribution.go, it is allowed to
// spell capability.Principal/Selector/NodeResult/FrozenError/CapExceededError
// — needed for Executor's signature and renderRunError's error rendering. It
// must never spell capability.Execution, capability.NewExecution, or
// newDispatch — those remain forbidden in every mcp file, exec or not, by
// .golangci.yml's "adapter boundary" patterns and no_dispatch_test.go; this
// file's only path to a real dispatch is the
// Executor interface below, injected by the composition root
// (cmd/relay/main.go), never constructed here.
//
// These tools are wired against the capability layer's execution service
// but do NOT flip production dispatch on: whether an Execution is built at
// all is Config.ControlEnabled's call. Their acceptance is proven in-package
// against a test-wired execution capability (mcp_test.go/mcp_exec_test.go).
//
// ADR-0029 decision 6: run_operation and raw_exec are the answered
// retry's only callers. This file reaches acceptElicitedAnswer in
// tools_approval.go and renders whatever it returns through that same
// file's methods (decisionOutput, refusalOutput, dispatchError,
// reattachError, answerStateRefusedOutput); like every file in the package
// it names no decision identifier (no_decision_test.go). The Job-bound branch
// (elicitedApprovedJobBound) is an AUDITED read (ADR-0025), exactly like
// get_job's own read-back: a bound Job's captured output may belong to
// another Account's dispatch, so it is read only after auditRead succeeds,
// and fails closed otherwise.

// Executor is the narrow capability-layer entry point the execution tools
// dispatch through — Execution.Start and Execution.CancelJob's exact shape,
// declared locally so no mcp file needs to import *capability.Execution
// itself (mirrors NodeReader/PolicyReader/OperationLister in mcp.go, but for
// the execution stages: Selector -> authz -> blast-cap -> dispatch -> audit,
// invariant 10). *capability.Execution satisfies Executor structurally (Go
// structural typing) — the composition root passes it in directly.
type Executor interface {
	// Start is Execution.Start: the same pipeline as Run, returning once
	// the Job's Tasks are persisted. This adapter chooses how long to wait for
	// the Job afterwards (wait_seconds); it decides nothing about the dispatch.
	Start(ctx context.Context, p capability.Principal, sel capability.Selector, act jobs.Action, o capability.StartOptions) (capability.StartedJob, error)
	CancelJob(ctx context.Context, p capability.Principal, jobID string) error

	// Plan is Execution.Plan's exact shape (ADR-0011): resolves sel,
	// authorizes p against act, and reports per-Node PolicyVerdicts instead
	// of dispatching — no Job/Task/dedup entry is ever created.
	Plan(ctx context.Context, p capability.Principal, sel capability.Selector, act jobs.Action) (capability.PlanResult, error)
}

// execAdapter narrows an arbitrary Executor down to a value whose dynamic
// type is execAdapter itself, exposing only Run/CancelJob — the execution-
// tool sibling of nodeReaderAdapter/policyReaderAdapter/operationListerAdapter
// (mcp.go): it is what makes a `.(*capability.Execution)` type assertion on
// the value New() was given fail at runtime, not just at the static-
// interface boundary, so an exec tool can never reach back through it to a
// wider method set (*capability.Execution exposes Plan, Start and more than
// Executor does). The Freeze is not one of them: it lives on
// *capability.Control, which Execution does not expose.
//
// RB1 (plan review): defined HERE, an exec file, rather than mcp.go, so
// mcp.go's source never spells capability.Principal and stays a strict
// file under no_dispatch_test.go's guard — mcp.go wires this with an
// unqualified `execAdapter{r: exec}` composite literal.
type execAdapter struct {
	r Executor
}

func (a execAdapter) Start(ctx context.Context, p capability.Principal, sel capability.Selector, act jobs.Action, o capability.StartOptions) (capability.StartedJob, error) {
	return a.r.Start(ctx, p, sel, act, o)
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
// Middleware always injects a Principal in production, so !ok is
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
	out := PlanOutput{Matched: rp.Matched, Verdicts: controlplane.MapSlice(rp.Verdicts, convertVerdict), Advisory: rp.Advisory}
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
	return perNodeResultFromRendered(controlplane.RenderTaskResult(task))
}

// perNodeResultFromRendered and convertVerdict are the field-for-field struct
// conversions the Rendered* types exist for (see controlplane/render.go).
func perNodeResultFromRendered(r controlplane.RenderedTaskResult) PerNodeResult {
	return PerNodeResult(r)
}

func convertVerdict(v controlplane.RenderedVerdict) PerNodeVerdict {
	return PerNodeVerdict(v)
}

// renderJob re-reads jobID via results (the injected JobResultReader) and
// renders every one of its Tasks as a PerNodeResult, sorted by NodeID for a
// stable response, with the Job's status and halt (controlplane.RenderJob). It is
// the shared rendering path for run_operation/raw_exec's own result (once
// exec.Start returns a Job) and get_job's polling re-read of the same Job later.
func renderJob(ctx context.Context, results JobResultReader, jobID string) (ExecutionOutput, error) {
	rendered, err := controlplane.RenderJob(ctx, results, jobID)
	if err != nil {
		return ExecutionOutput{}, err
	}
	return ExecutionOutput{
		JobID:     jobID,
		JobStatus: rendered.Status,
		Results:   controlplane.MapSlice(rendered.Results, perNodeResultFromRendered),
		Halt:      haltOutput(rendered.Halt),
	}, nil
}

// haltOutput is the struct conversion HaltOutput exists for: a rendered halt,
// or nil for a Job that did not halt.
func haltOutput(h *controlplane.RenderedHalt) *HaltOutput {
	if h == nil {
		return nil
	}
	out := HaltOutput(*h)
	return &out
}

// renderRunError translates an error returned by Executor.Start into the tool
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
	// Template refusals (ADR-0042) already say what to do next.
	var unknownErr *capability.UnknownOperationError
	var malformedErr *capability.MalformedCallError
	if errors.As(err, &unknownErr) || errors.As(err, &malformedErr) {
		return err
	}
	// Idempotency outcomes each say precisely what the caller may do
	// next, and whether a new key is safe; wrapping them would bury that.
	var conflictErr *capability.IdempotencyConflictError
	var keyErr *capability.IdempotencyKeyError
	var pendingErr *capability.IdempotencyPendingError
	var releasedErr *capability.IdempotencyReleasedError
	var abandonedErr *capability.IdempotencyAbandonedError
	if errors.As(err, &conflictErr) || errors.As(err, &keyErr) || errors.As(err, &pendingErr) ||
		errors.As(err, &releasedErr) || errors.As(err, &abandonedErr) || errors.Is(err, capability.ErrIdempotencyUnavailable) {
		return err
	}
	return fmt.Errorf("mcp: dispatch failed: %w", err)
}

// buildOperationAction looks up a Native name in ops' vocabulary, validates
// the argument NAMES against that Operation's published arg_constraints, and
// builds the resulting jobs.Action. It sets no risk class: the capability
// layer derives it (ADR-0012, invariant 13). Any other name is a Template
// Operation (see the last paragraph).
//
// The name checks are a thin **legibility pre-check** before ever reaching Run,
// never a second Policy decision (ADR-0002/0011, invariant 12): the daemon's
// live Policy engine and its validate_* functions remain the real gate on
// argument VALUES. What this catches is the failure mode where a malformed call
// is indistinguishable from a forbidden one:
//
//   - an unknown ARGUMENT name (e.g. a misspelled "unitt") — otherwise silently
//     dropped, leaving the required arg empty so the daemon reports
//     denied_by_policy, which sends the AI-agent into describe_node/narrow/retry
//     loops it can never exit because the request was malformed, not forbidden;
//   - a missing REQUIRED argument — otherwise the same empty-value denial.
//
// The argument-name half lives in [opvocab.ValidateArgNames], beside the
// ArgConstraints convention it reads, so this surface and the Control API's
// execution routes share ONE definition: a misspelled argument is a
// malformed call on both, never a per-Node denial (ADR-0042).
//
// A name outside the Native vocabulary is a Template Operation (ADR-0021),
// and this adapter decides NOTHING about it (ADR-0042, invariant 10): it
// builds the Action with no risk class and no argument check, and the
// capability layer resolves the class over the matched Nodes' own reports,
// checks the argument names against their slots, and refuses a name no
// matched Node reports as an unknown operation.
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
				TimeoutSeconds: timeoutSeconds,
			}, nil
		}
	}
	if name == "" {
		return jobs.Action{}, fmt.Errorf("operation is required (see list_operations)")
	}
	return jobs.Action{
		Kind:           jobs.ActionOperation,
		OperationName:  name,
		OperationArgs:  args,
		TimeoutSeconds: timeoutSeconds,
	}, nil
}

// runOperationInput is run_operation's argument. Plan is additive:
// omitted or false is a real dispatch; plan=true resolves/authorizes/checks exactly as a real run would but
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
	// WaitSeconds and IdempotencyKey: omitempty, so callArgsDigest is unchanged
	// for a call that omits them (AP-65).
	WaitSeconds    int32  `json:"wait_seconds,omitempty" jsonschema:"0/omitted returns as soon as every Task is persisted, with job_id and job_status=running; poll get_job. 1-300 waits up to that many seconds for every Task to finish and returns full per-Node results if they did, otherwise the running Job. A lapsed wait never cancels the Job. A call that re-attaches to an existing Job (a repeated idempotency_key) does not wait: it returns the Job as it stands. Ignored with plan=true. Re-send the call unchanged (wait_seconds and idempotency_key included) when answering an approval."`
	IdempotencyKey string `json:"idempotency_key,omitempty" jsonschema:"Optional, at most 128 printable ASCII bytes. A repeat of the same key by the same Account within 24h returns the existing Job and dispatches nothing; the same key with different arguments is refused. Send a fresh key per intended run, and re-send it unchanged when re-issuing after a lost response. Ignored with plan=true: a preflight claims no key."`
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
	// WaitSeconds and IdempotencyKey: see runOperationInput's field docs.
	WaitSeconds    int32  `json:"wait_seconds,omitempty" jsonschema:"0/omitted returns as soon as every Task is persisted, with job_id and job_status=running; poll get_job. 1-300 waits up to that many seconds for every Task to finish and returns full per-Node results if they did, otherwise the running Job. A lapsed wait never cancels the Job. A call that re-attaches to an existing Job (a repeated idempotency_key) does not wait: it returns the Job as it stands. Ignored with plan=true. Re-send the call unchanged (wait_seconds and idempotency_key included) when answering an approval."`
	IdempotencyKey string `json:"idempotency_key,omitempty" jsonschema:"Optional, at most 128 printable ASCII bytes. A repeat of the same key by the same Account within 24h returns the existing Job and dispatches nothing; the same key with different arguments is refused. Send a fresh key per intended run, and re-send it unchanged when re-issuing after a lost response. Ignored with plan=true: a preflight claims no key."`
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
	if p := s.Properties["wait_seconds"]; p != nil {
		p.Minimum = schema.Ptr(float64(0))
		p.Maximum = schema.Ptr(float64(controlplane.MaxWaitSeconds))
	}
	if p := s.Properties["idempotency_key"]; p != nil {
		p.MaxLength = schema.Ptr(capability.MaxIdempotencyKeyBytes)
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
// error would actively mislead the AI-agent that receives it. The parked value
// is ALSO returned directly (nil otherwise), so a caller can decide whether
// to render a question instead (elicit.go) without re-deriving it from the
// rendered output.
//
// It returns the whole RunOrPlanOutput rather than an ExecutionOutput so both
// execution tools share one construction of the result shape; having each call
// site assemble its own is how the park branch would get added to one tool and
// forgotten in the other.
func dispatch(ctx context.Context, exec Executor, results JobResultReader, p capability.Principal, sel capability.Selector, act jobs.Action, o dispatchOpts) (RunOrPlanOutput, *capability.ParkedError, error) {
	sj, err := exec.Start(ctx, p, sel, act, capability.StartOptions{IdempotencyKey: o.key})
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
	// *capability.Execution can never return an empty JobID with a nil error from
	// the real engine (a zero-match Selector is refused as no_nodes_matched
	// before this call returns). The no-op dispatcher, which creates no Job,
	// does; nothing was dispatched then, so there is nothing to read back.
	if sj.JobID == "" {
		return RunOrPlanOutput{Results: []PerNodeResult{}}, nil, nil
	}
	// wait_seconds is presentation only: it decides how long this call holds
	// before reading the Job back, never what was dispatched. A lapsed wait, a
	// dropped caller and a re-attach all leave the Job exactly as it was.
	if o.wait > 0 && !sj.Reattached && sj.Done != nil {
		t := time.NewTimer(o.wait)
		select {
		case <-sj.Done:
		case <-t.C:
		case <-ctx.Done():
		}
		t.Stop()
	}
	out, err := renderJob(ctx, results, sj.JobID)
	if err != nil {
		return RunOrPlanOutput{}, nil, err
	}
	return RunOrPlanOutput{JobID: out.JobID, Results: out.Results, JobStatus: out.JobStatus, Halt: out.Halt, Reattached: sj.Reattached}, nil, nil
}

// dispatchOpts are the two presentation inputs of a real (non-plan) call: how
// long to hold for the Job (wait_seconds) and the idempotency key to forward.
type dispatchOpts struct {
	wait time.Duration
	key  string
}

// renderParked projects a capability.ParkedError into the AI-agent-facing
// pending_approval result. Every field is Relay-authored: the AI-agent chose the
// Action, but none of the words describing it (ADR-0027).
func renderParked(parked *capability.ParkedError) *PendingApprovalOutput {
	rules := parked.Rules
	if rules == nil {
		rules = []string{}
	}
	return &PendingApprovalOutput{
		Status:       statusPendingApproval,
		RequestID:    parked.RequestID,
		PlanHash:     parked.PlanHash,
		Summary:      parked.Summary,
		MatchedRules: rules,
		ExpiresAt:    parked.ExpiresAt.UTC().Format(time.RFC3339),
		DecisionPath: "/api/v1/approvals/" + parked.RequestID + "/decision",
		NextStep:     pendingApprovalNextStep,
	}
}

// statusPendingApproval is PendingApprovalOutput.Status's only value. It is
// deliberately the same literal the Control API renders, so an operator
// watching both surfaces sees one vocabulary for one state.
const statusPendingApproval = "pending_approval"

// planModeClause is the SINGLE, IDENTICAL sentence cross-referencing plan
// mode from both run_operation's and raw_exec's Description. It is
// deliberately concept-level — it names plan mode and ADR-0011 but no param
// name.
const planModeClause = "Plan mode — the no-execution preview of whether each Node's live Policy would allow " +
	"the action (ADR-0011) — is the sanctioned probe before mutating; prefer it over learning Policy " +
	"boundaries by triggering real executions."

// jobReturnClause is the SINGLE, IDENTICAL sentence stating when run_operation
// and raw_exec return and how to get the outcomes (ADR-0004's wait
// budget). Shared for the reason planModeClause is.
const jobReturnClause = "Returns as soon as every matched Node's Task is persisted, with job_id and " +
	"job_status=running; poll get_job with job_id until job_status=complete. Pass wait_seconds (max 300) to " +
	"wait up to that long for full per-Node results; a lapsed wait never cancels the Job, and a call that re-attaches through its idempotency_key does not wait. Pass an " +
	"idempotency_key (a fresh one per intended run) so a call re-issued after a lost response returns the " +
	"existing Job instead of dispatching again — re-send it unchanged. Without a key, a repeated call is a new dispatch."

// resultShapeClause is the SINGLE, IDENTICAL result-shape contract sentence
// shared by run_operation's and raw_exec's Description (mirroring
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
	"no_nodes_matched and creates no Job; with plan=true it is reported as would_be_rejected no_nodes_matched. " +
	"job_status is running while any Task is unresolved (its outcome reads unspecified) and complete once " +
	"every Task has a terminal outcome; reattached is true when this call dispatched nothing and returned " +
	"the Job an earlier call created."

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
// answer to a parked approval — the one condition under which
// run_operation/raw_exec call answerThenDispatch instead of dispatching
// directly. True only when ALL of:
//
//   - ask is non-nil (nil exactly when the option is off, mcp.go:280 — a
//     server that never asks a question also never accepts an answer);
//   - clientCanBeAsked(req) is true (elicit.go): a client that could never
//     have been asked could never have received a question, so any
//     requestState/inputResponses it sends are stray, and the call is
//     treated exactly as today's call (AP-85) — its fields
//     are ignored rather than fed to the decision path;
//   - the call actually carries a requestState, or at least one answered
//     input request.
//
// This only NARROWS which calls are treated as an answered retry (invariant
// 10): it can never turn an ordinary call into one, only the reverse.
func isAnsweredRetry(ask *questioner, req *sdkmcp.CallToolRequest) bool {
	if ask == nil || !clientCanBeAsked(req) {
		return false
	}
	return req.Params.RequestState != "" || len(req.Params.InputResponses) > 0
}

// answerThenDispatch is the ONE function run_operation and raw_exec both call
// for an answered retry, so the branch cannot drift between them: it
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
// drift from what emission sealed (there is no second digest function).
//
// From the answer side this names ONLY acceptElicitedAnswer, its result
// type, the elicitedOutcome constants, answerStateRefusedOutput and the
// result's own rendering methods (decisionOutput, refusalOutput,
// dispatchError, reattachError) and, like every file in the package, no
// decision identifier (no_decision_test.go).
func answerThenDispatch(
	ctx context.Context, req *sdkmcp.CallToolRequest, p capability.Principal,
	exec Executor, results JobResultReader, reads ReadAuditor, answerer ApprovalAnswerer,
	ask *questioner, now func() time.Time, tool string, in any, sel capability.Selector, act jobs.Action, o dispatchOpts,
) (*sdkmcp.CallToolResult, RunOrPlanOutput, error) {
	digest, err := callArgsDigest(in)
	if err != nil {
		return nil, RunOrPlanOutput{Results: []PerNodeResult{}, AnswerRefused: answerStateRefusedOutput()}, nil //nolint:nilerr // the refusal is the tool result; a protocol error would hide it from the AI-agent
	}

	r := acceptElicitedAnswer(ctx, answerer, ask.opener(), now(), p, elicitedAnswer{
		RequestState:   req.Params.RequestState,
		InputResponses: req.Params.InputResponses,
		CallMeta:       req.Params.GetMeta(),
		Tool:           tool,
		ArgsDigest:     digest,
	})
	slog.Debug("mcp: answered retry", "tool", tool, "request_id", r.RequestID, "outcome", r.Outcome)

	switch r.Outcome {
	case elicitedApproved, elicitedLapsed:
		// A concurrent approving retry, or a plain re-drive carrying no
		// request state at all, is now resolved in the capability layer
		// (AP-77): Execution.Run claims a single-Plan approval's release
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
		out, parked, err := dispatch(ctx, exec, results, p, sel, act, o)
		if err != nil {
			return nil, RunOrPlanOutput{}, r.dispatchError(err)
		}
		if parked != nil {
			// Whether a question replaces pending_approval is the capability
			// layer's created/observed askability call (AP-62), not this
			// function's: an observed re-drive's park renders pending_approval,
			// while a fleet change or a lapse creates a fresh, askable park. A question result cannot carry the
			// decision block either way — the SDK forbids structured content
			// alongside InputRequests — but the decision it answers is still
			// audited and readable on the Control API.
			if q, ok := ask.question(req, p, parked, tool, in); ok {
				return q, RunOrPlanOutput{}, nil
			}
		}
		out.Decision = r.decisionOutput(out)
		return nil, out, nil

	case elicitedApprovedJobBound:
		if err := auditRead(ctx, reads, tool, ReadEvent{JobID: r.JobID}); err != nil {
			return nil, RunOrPlanOutput{}, r.reattachError(err)
		}
		job, err := renderJob(ctx, results, r.JobID)
		if err != nil {
			return nil, RunOrPlanOutput{}, r.reattachError(err)
		}
		out := RunOrPlanOutput{JobID: job.JobID, Results: job.Results, JobStatus: job.JobStatus, Halt: job.Halt}
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
// assumption engineered into words: run_operation presents itself as
// the DEFAULT and raw_exec as the ESCAPE HATCH, both cross-reference plan
// mode via the identical planModeClause, and run_operation's steers a
// denied_by_policy result toward describe_node rather than blind retries.
//
// ask (elicit.go, S2b) is nil-receiver safe: a nil *questioner never asks, so
// a park always renders pending_approval exactly as before it existed.
// isAnsweredRetry gates the same nil-receiver-safe path: an answered
// retry can only exist where a question could have been asked in the first
// place.
//
// reads is used only by the Job-bound re-attach branch (auditRead, ADR-0025:
// the re-attached Job's captured output may belong to another Account's
// dispatch, exactly get_job's case); answerer and now are acceptElicitedAnswer's
// own parameters, threaded straight through from mcp.New's cfg.
func registerExecutionTools(srv *sdkmcp.Server, exec Executor, results JobResultReader, ops OperationLister, ask *questioner, reads ReadAuditor, answerer ApprovalAnswerer, now func() time.Time) {
	sdkmcp.AddTool(srv, &sdkmcp.Tool{
		Name: "run_operation", // keep in sync with toolRunOperation (PF-1, see the const doc above)
		Description: "The default way to act on Nodes. Run a structured Operation (ADR-0001's typed, " +
			"native-argv path — never a shell) against a Selector's matched Nodes through the capability " +
			"layer (Selector -> authz -> blast-cap -> dispatch -> audit). Prefer run_operation over raw_exec " +
			"whenever a structured Operation expresses what you want to do; call list_operations first for " +
			"the vocabulary — each Operation's purpose, risk class, argument names/types/constraints, and a " +
			"usage example — so you pick the right one and build its args correctly, without trial-and-error. " +
			planModeClause + " If a result comes back outcome=denied_by_policy, call describe_node to see the " +
			"Node's effective Policy and narrow your request rather than guessing again. " +
			jobReturnClause + " " + resultShapeClause,
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
			// idempotency_key and wait_seconds are deliberately ignored here: a
			// preflight creates nothing, no dedup entry (PF-8).
			plan, err := planAndRender(ctx, exec, p, sel, act)
			if err != nil {
				return nil, RunOrPlanOutput{}, err
			}
			// JobID stays absent (a Plan creates no Job) and Results stays an
			// empty array, never null — see RunOrPlanOutput.
			return nil, RunOrPlanOutput{Results: []PerNodeResult{}, Plan: &plan}, nil
		}

		wait, err := controlplane.ResolveWaitSeconds(in.WaitSeconds)
		if err != nil {
			return nil, RunOrPlanOutput{}, err
		}
		o := dispatchOpts{wait: wait, key: in.IdempotencyKey}

		// An answered retry decides before anything dispatches, then
		// re-enters the pipeline below at most once itself — it never falls
		// through to the plain dispatch() call that follows. A plan=true
		// call never reaches here (it returned above), so a retry carrying
		// plan=true is handled exactly like today's call regardless of this
		// check (a plan is not a park).
		if isAnsweredRetry(ask, req) {
			return answerThenDispatch(ctx, req, p, exec, results, reads, answerer, ask, now, toolRunOperation, in, sel, act, o)
		}

		out, parked, err := dispatch(ctx, exec, results, p, sel, act, o)
		if err != nil {
			return nil, RunOrPlanOutput{}, err
		}
		// A question replaces pending_approval outright: the returned
		// CallToolResult carries InputRequests and no structuredContent, and
		// nothing renders a park as an MCP task handle (AP-85).
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
			"outcome=denied_by_policy). " + planModeClause + " " + jobReturnClause + " " + resultShapeClause,
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
		// Raw Exec always takes mutate (ADR-0012, invariant 13). The
		// capability layer fixes it, and no client field and no adapter can
		// change that, plan mode included.
		act := jobs.Action{Kind: jobs.ActionRawExec, RawExecArgv: in.Argv, TimeoutSeconds: timeoutSeconds}

		if in.Plan {
			// See run_operation's identical branch: the key is ignored (PF-8).
			plan, err := planAndRender(ctx, exec, p, sel, act)
			if err != nil {
				return nil, RunOrPlanOutput{}, err
			}
			// JobID stays absent (a Plan creates no Job) and Results stays an
			// empty array, never null — see RunOrPlanOutput.
			return nil, RunOrPlanOutput{Results: []PerNodeResult{}, Plan: &plan}, nil
		}

		wait, err := controlplane.ResolveWaitSeconds(in.WaitSeconds)
		if err != nil {
			return nil, RunOrPlanOutput{}, err
		}
		o := dispatchOpts{wait: wait, key: in.IdempotencyKey}

		// See run_operation's identical branch above.
		if isAnsweredRetry(ask, req) {
			return answerThenDispatch(ctx, req, p, exec, results, reads, answerer, ask, now, toolRawExec, in, sel, act, o)
		}

		out, parked, err := dispatch(ctx, exec, results, p, sel, act, o)
		if err != nil {
			return nil, RunOrPlanOutput{}, err
		}
		// See run_operation's identical branch above: a question replaces
		// pending_approval outright (AP-85).
		if parked != nil {
			if q, ok := ask.question(req, p, parked, toolRawExec, in); ok {
				return q, RunOrPlanOutput{}, nil
			}
		}
		return nil, out, nil
	})
}
