package mcp

import (
	"context"
	"errors"
	"fmt"
	"sort"

	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/capability"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/controlplane"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/jobs"
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
// unreachable there; "prefer the more restrictive option" (CLAUDE.md)
// requires the explicit guard anyway.
func requirePrincipal(ctx context.Context) (capability.Principal, error) {
	p, ok := controlplane.PrincipalFromContext(ctx)
	if !ok {
		return capability.Principal{}, fmt.Errorf("mcp: no authenticated principal in context; refusing to dispatch or cancel unattributed")
	}
	return p, nil
}

// maxRenderedOutputBytes caps how much of a Task's Stdout/Stderr the
// execution tools render inline, per the plan's per-Node result shape:
// beyond this, the *Truncated flag is set rather than growing the response
// unbounded (a Raw Exec Task's output size is otherwise unconstrained).
const maxRenderedOutputBytes = 4096

// maxTimeoutSeconds is the sane upper bound run_operation/raw_exec enforce
// on timeout_seconds (RB6, plan review, owner DECISION 3): 24h. Flagged
// explicitly in the PR alongside DECISIONS 1/2 — a missing bound on an RCE
// surface must read as deliberate, not an oversight.
const maxTimeoutSeconds = 24 * 60 * 60

// resolveTimeoutSeconds validates an incoming timeout_seconds value (0 or
// omitted means "no explicit timeout" — today's default, unchanged) against
// [0, maxTimeoutSeconds], returning a legible error otherwise. It never
// silently clamps or ignores an out-of-range value on an RCE surface.
func resolveTimeoutSeconds(timeoutSeconds int32) (int32, error) {
	if timeoutSeconds < 0 {
		return 0, fmt.Errorf("timeout_seconds must be >= 0, got %d", timeoutSeconds)
	}
	if timeoutSeconds > maxTimeoutSeconds {
		return 0, fmt.Errorf("timeout_seconds must be <= %d (24h), got %d", maxTimeoutSeconds, timeoutSeconds)
	}
	return timeoutSeconds, nil
}

// planAdvisory is the fixed point-in-time disclaimer every PlanOutput
// carries (ADR-0011): a Plan's verdicts are a snapshot, not a guarantee —
// Policy may change between the Plan and a later real run.
const planAdvisory = "point-in-time; Policy may change between plan and apply (ADR-0011)"

// verdictString renders a capability.VerdictStatus as the lowercase string
// the execution tools emit, mirroring outcomeString's style.
func verdictString(v capability.VerdictStatus) string {
	switch v {
	case capability.VerdictAllow:
		return "allow"
	case capability.VerdictDeny:
		return "deny"
	default:
		return "unknown"
	}
}

// renderPlan renders a capability.PlanResult as the tool's PlanOutput:
// verdicts sorted by NodeID for a stable response (mirrors renderJob), and
// would_be_rejected derived from pr.CapExceeded (reason "exceeds_cap") or,
// absent that, pr.Frozen (reason "frozen"). A Plan can be both over-cap and
// Frozen at once (Service.Plan computes Frozen before the cap check); the
// over-cap report takes priority here since it is the reason the query
// fan-out never even ran (Verdicts is empty in that case too).
func renderPlan(pr capability.PlanResult) PlanOutput {
	verdicts := make([]PerNodeVerdict, 0, len(pr.Verdicts))
	for _, v := range pr.Verdicts {
		verdicts = append(verdicts, PerNodeVerdict{
			NodeID:       v.NodeID,
			Verdict:      verdictString(v.Status),
			DecidingRule: v.DecidingRule,
			Reason:       v.Reason,
			Outdated:     v.Outdated,
		})
	}
	sort.Slice(verdicts, func(i, j int) bool { return verdicts[i].NodeID < verdicts[j].NodeID })

	out := PlanOutput{Matched: pr.Matched, Verdicts: verdicts, Advisory: planAdvisory}
	switch {
	case pr.CapExceeded != nil:
		out.WouldBeRejected = &WouldBeRejected{
			Reason:  "exceeds_cap",
			Matched: pr.CapExceeded.Matched,
			Cap:     pr.CapExceeded.Cap,
			Class:   riskClassString(pr.CapExceeded.Class),
		}
	case pr.Frozen:
		out.WouldBeRejected = &WouldBeRejected{Reason: "frozen"}
	}
	return out
}

// planAndRender runs act against sel through exec.Plan and renders the
// result — plan=true's counterpart to dispatchAndRender. err from exec.Plan
// is ONLY an authz-refusal or infra failure (renderRunError's existing
// cases): cap/Freeze are reported INSIDE pr, never as an error (ADR-0011).
func planAndRender(ctx context.Context, exec Executor, p capability.Principal, sel capability.Selector, act jobs.Action) (PlanOutput, error) {
	pr, err := exec.Plan(ctx, p, sel, act)
	if err != nil {
		return PlanOutput{}, renderRunError(err)
	}
	return renderPlan(pr), nil
}

// outcomeString renders a jobs.Outcome as the lowercase string the
// execution tools emit, mirroring tools_operations.go's riskClassString
// style ("read"/"mutate" there, "success"/"failure"/... here).
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
	default:
		return "unspecified"
	}
}

// truncateOutput caps b at maxRenderedOutputBytes, reporting whether it did.
func truncateOutput(b []byte) (string, bool) {
	if len(b) <= maxRenderedOutputBytes {
		return string(b), false
	}
	return string(b[:maxRenderedOutputBytes]), true
}

// perNodeResultFromTask renders one jobs.Task as a PerNodeResult.
// DurationMS is 0 when the Task was never dispatched (DispatchedAt zero —
// e.g. OutcomeUnreachable/an offline Node, or a Pending Task cancelled
// before it was ever sent), never a fabricated negative/huge value.
func perNodeResultFromTask(task jobs.Task) PerNodeResult {
	stdout, stdoutTruncated := truncateOutput(task.Stdout)
	stderr, stderrTruncated := truncateOutput(task.Stderr)

	var durationMS int64
	if !task.DispatchedAt.IsZero() && !task.ResolvedAt.IsZero() {
		durationMS = task.ResolvedAt.Sub(task.DispatchedAt).Milliseconds()
	}

	return PerNodeResult{
		NodeID:          task.NodeID,
		Outcome:         outcomeString(task.Outcome),
		ExitCode:        task.ExitCode,
		Stdout:          stdout,
		Stderr:          stderr,
		StdoutTruncated: stdoutTruncated,
		StderrTruncated: stderrTruncated,
		DurationMS:      durationMS,
	}
}

// renderJob re-reads jobID via results (the injected JobResultReader) and
// renders every one of its Tasks as a PerNodeResult, sorted by NodeID for a
// stable response. It is the shared rendering path for run_operation/
// raw_exec's own result (once exec.Run returns a non-empty NodeResult set)
// and get_job's polling re-read of the same Job later.
func renderJob(ctx context.Context, results JobResultReader, jobID string) (ExecutionOutput, error) {
	if _, err := results.GetJob(ctx, jobID); err != nil {
		return ExecutionOutput{}, fmt.Errorf("get job %q: %w", jobID, err)
	}
	tasks, err := results.TasksByJob(ctx, jobID)
	if err != nil {
		return ExecutionOutput{}, fmt.Errorf("list tasks for job %q: %w", jobID, err)
	}

	items := make([]PerNodeResult, 0, len(tasks))
	for _, task := range tasks {
		items = append(items, perNodeResultFromTask(task))
	}
	sort.Slice(items, func(i, j int) bool { return items[i].NodeID < items[j].NodeID })

	return ExecutionOutput{JobID: jobID, Results: items}, nil
}

// renderRunError translates an error returned by Executor.Run into the tool
// error the SDK renders (IsError=true, message = err.Error()): a Freeze
// refusal becomes a distinct, legible "the Relay is frozen" message; a
// blast-radius cap rejection is returned verbatim (CapExceededError.Error()
// already states matched/cap/class); anything else is wrapped generically.
func renderRunError(err error) error {
	var frozenErr *capability.FrozenError
	if errors.As(err, &frozenErr) {
		return fmt.Errorf("the Relay is frozen: %w", err)
	}
	var capErr *capability.CapExceededError
	if errors.As(err, &capErr) {
		return capErr
	}
	return fmt.Errorf("mcp: dispatch failed: %w", err)
}

// buildOperationAction looks up name in ops' vocabulary for its declared
// RiskClass (ADR-0012) and builds the resulting jobs.Action. This is a thin
// pre-check for a legible "unknown operation" error before ever reaching
// Run — the daemon's live Policy engine remains the real gate (ADR-0002/
// 0011); an operation name this package doesn't recognize is refused here
// only to fail fast with a clear message, not as a second Policy decision.
func buildOperationAction(ops OperationLister, name string, args map[string]string, timeoutSeconds int32) (jobs.Action, error) {
	timeoutSeconds, err := resolveTimeoutSeconds(timeoutSeconds)
	if err != nil {
		return jobs.Action{}, err
	}
	for _, d := range ops.Operations() {
		if d.Name == name {
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
	// default); [0, maxTimeoutSeconds] is enforced (RB6).
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

// dispatchAndRender runs act against sel through exec, then renders the
// full per-Node result set — the shared body of run_operation and raw_exec
// once each has built its own jobs.Action. A zero-match Run (no Node matched
// the Selector) renders as {results: []} without ever reading a Job back;
// Run never reached the dispatcher, so there is no Job.
func dispatchAndRender(ctx context.Context, exec Executor, results JobResultReader, p capability.Principal, sel capability.Selector, act jobs.Action) (ExecutionOutput, error) {
	nodeResults, err := exec.Run(ctx, p, sel, act)
	if err != nil {
		return ExecutionOutput{}, renderRunError(err)
	}
	if len(nodeResults) == 0 {
		return ExecutionOutput{Results: []PerNodeResult{}}, nil
	}
	return renderJob(ctx, results, nodeResults[0].JobID)
}

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
func registerExecutionTools(srv *sdkmcp.Server, exec Executor, results JobResultReader, ops OperationLister) {
	sdkmcp.AddTool(srv, &sdkmcp.Tool{
		Name: "run_operation",
		Description: "The default way to act on Nodes. Run a structured Operation (ADR-0001's typed, " +
			"native-argv path — never a shell) against a Selector's matched Nodes through the capability " +
			"layer (Selector -> authz -> blast-cap -> dispatch -> audit). Prefer run_operation over raw_exec " +
			"whenever a structured Operation expresses what you want to do; call list_operations first for " +
			"the vocabulary — each Operation's purpose, risk class, argument names/types/constraints, and a " +
			"usage example — so you pick the right one and build its args correctly, without trial-and-error. " +
			planModeClause + " If a result comes back outcome=denied_by_policy, call describe_node to see the " +
			"Node's effective Policy and narrow your request rather than guessing again. Blocks until every " +
			"matched Node's Task reaches a terminal outcome and returns per-Node results plus the Job id; " +
			"get_job re-reads the same Job later.",
	}, func(ctx context.Context, _ *sdkmcp.CallToolRequest, in runOperationInput) (*sdkmcp.CallToolResult, RunOrPlanOutput, error) {
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
			return nil, RunOrPlanOutput{Plan: &plan}, nil
		}

		out, err := dispatchAndRender(ctx, exec, results, p, sel, act)
		if err != nil {
			return nil, RunOrPlanOutput{}, err
		}
		return nil, RunOrPlanOutput{JobID: out.JobID, Results: out.Results}, nil
	})

	sdkmcp.AddTool(srv, &sdkmcp.Tool{
		Name: "raw_exec",
		Description: "The escape hatch — use only when no structured Operation expresses the task. Run an " +
			"arbitrary argv (ADR-0001's regex-gated escape hatch) against a Selector's matched Nodes. Prefer " +
			"run_operation's typed path first: call list_operations to check whether a structured Operation " +
			"already covers your intent before reaching for raw_exec. Always risk class mutate (ADR-0012) " +
			"regardless of what argv does — raw_exec always takes the strict mutate-cap, even for a " +
			"read-only-looking command. argv runs verbatim — no shell, no client-side splitting — and the " +
			"daemon's Policy regex decides per Node whether it is allowed (a per-Node refusal renders " +
			"outcome=denied_by_policy). " + planModeClause,
	}, func(ctx context.Context, _ *sdkmcp.CallToolRequest, in rawExecInput) (*sdkmcp.CallToolResult, RunOrPlanOutput, error) {
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

		timeoutSeconds, err := resolveTimeoutSeconds(in.TimeoutSeconds)
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
			return nil, RunOrPlanOutput{Plan: &plan}, nil
		}

		out, err := dispatchAndRender(ctx, exec, results, p, sel, act)
		if err != nil {
			return nil, RunOrPlanOutput{}, err
		}
		return nil, RunOrPlanOutput{JobID: out.JobID, Results: out.Results}, nil
	})
}
