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

// perNodeResult is one Node's rendered Task outcome — exit code, size-capped
// output, and duration — the shape run_operation/raw_exec/get_job all
// render (renderJob below). Outcome/denied_by_policy come straight off the
// Task the daemon resolved: this package never evaluates Policy itself
// (invariant 12).
type perNodeResult struct {
	NodeID          string `json:"node_id"`
	Outcome         string `json:"outcome"`
	ExitCode        int32  `json:"exit_code"`
	Stdout          string `json:"stdout"`
	Stderr          string `json:"stderr"`
	StdoutTruncated bool   `json:"stdout_truncated"`
	StderrTruncated bool   `json:"stderr_truncated"`
	DurationMS      int64  `json:"duration_ms"`
}

// executionOutput is run_operation/raw_exec/get_job's shared result shape:
// the Job id (so a caller can later cancel_job/get_job it) plus every
// matched Node's rendered result. A zero-match dispatch (no Node matched the
// Selector) renders as {job_id: "", results: []} — Run never reached the
// dispatcher, so there is no Job to read back.
type executionOutput struct {
	JobID   string          `json:"job_id"`
	Results []perNodeResult `json:"results"`
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

// perNodeResultFromTask renders one jobs.Task as a perNodeResult.
// DurationMS is 0 when the Task was never dispatched (DispatchedAt zero —
// e.g. OutcomeUnreachable/an offline Node, or a Pending Task cancelled
// before it was ever sent), never a fabricated negative/huge value.
func perNodeResultFromTask(task jobs.Task) perNodeResult {
	stdout, stdoutTruncated := truncateOutput(task.Stdout)
	stderr, stderrTruncated := truncateOutput(task.Stderr)

	var durationMS int64
	if !task.DispatchedAt.IsZero() && !task.ResolvedAt.IsZero() {
		durationMS = task.ResolvedAt.Sub(task.DispatchedAt).Milliseconds()
	}

	return perNodeResult{
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
// renders every one of its Tasks as a perNodeResult, sorted by NodeID for a
// stable response. It is the shared rendering path for run_operation/
// raw_exec's own result (once exec.Run returns a non-empty NodeResult set)
// and get_job's polling re-read of the same Job later.
func renderJob(ctx context.Context, results JobResultReader, jobID string) (executionOutput, error) {
	if _, err := results.GetJob(ctx, jobID); err != nil {
		return executionOutput{}, fmt.Errorf("get job %q: %w", jobID, err)
	}
	tasks, err := results.TasksByJob(ctx, jobID)
	if err != nil {
		return executionOutput{}, fmt.Errorf("list tasks for job %q: %w", jobID, err)
	}

	items := make([]perNodeResult, 0, len(tasks))
	for _, task := range tasks {
		items = append(items, perNodeResultFromTask(task))
	}
	sort.Slice(items, func(i, j int) bool { return items[i].NodeID < items[j].NodeID })

	return executionOutput{JobID: jobID, Results: items}, nil
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

// runOperationInput is run_operation's argument. Deliberately does not carry
// a "plan" field yet: plan mode (plan=true) is #119's scope, not this one —
// this shape is written so #119 can add an optional plan bool later without
// breaking any existing caller.
type runOperationInput struct {
	Selector  string            `json:"selector,omitempty" jsonschema:"Selector filter, e.g. 'node:role=web, relay:quarantine=on'. Every term must carry a node: or relay: prefix. Empty or omitted matches every Node."`
	Operation string            `json:"operation" jsonschema:"Operation name, e.g. 'system.facts' (see list_operations for the full vocabulary and each Operation's risk class)."`
	Args      map[string]string `json:"args,omitempty" jsonschema:"Operation arguments, validated against the Operation's own constraints (never a shell)."`
	// TimeoutSeconds omitted or 0 keeps today's default (the daemon/engine
	// default); [0, maxTimeoutSeconds] is enforced (RB6).
	TimeoutSeconds int32 `json:"timeout_seconds,omitempty" jsonschema:"Optional per-Task timeout in seconds. 0 or omitted uses the daemon/engine default; max 86400 (24h)."`
}

// rawExecInput is raw_exec's argument: argv only — no shell, no
// client-side splitting, no string-command field (ADR-0001, invariant 1).
type rawExecInput struct {
	Selector string   `json:"selector,omitempty" jsonschema:"Selector filter, e.g. 'node:role=web, relay:quarantine=on'. Every term must carry a node: or relay: prefix. Empty or omitted matches every Node."`
	Argv     []string `json:"argv" jsonschema:"Argv to execute verbatim on each matched Node — no shell, no client-side splitting (ADR-0001). The daemon's Policy regex decides per Node whether it is allowed."`
	// TimeoutSeconds: see runOperationInput's field doc.
	TimeoutSeconds int32 `json:"timeout_seconds,omitempty" jsonschema:"Optional per-Task timeout in seconds. 0 or omitted uses the daemon/engine default; max 86400 (24h)."`
}

// dispatchAndRender runs act against sel through exec, then renders the
// full per-Node result set — the shared body of run_operation and raw_exec
// once each has built its own jobs.Action. A zero-match Run (no Node matched
// the Selector) renders as {results: []} without ever reading a Job back;
// Run never reached the dispatcher, so there is no Job.
func dispatchAndRender(ctx context.Context, exec Executor, results JobResultReader, p capability.Principal, sel capability.Selector, act jobs.Action) (executionOutput, error) {
	nodeResults, err := exec.Run(ctx, p, sel, act)
	if err != nil {
		return executionOutput{}, renderRunError(err)
	}
	if len(nodeResults) == 0 {
		return executionOutput{Results: []perNodeResult{}}, nil
	}
	return renderJob(ctx, results, nodeResults[0].JobID)
}

// registerExecutionTools registers run_operation and raw_exec on srv — the
// two ADR-0003 execution meta-tools. Both are thin: ParseSelector -> build
// the Action -> requirePrincipal -> exec.Run -> render. Neither evaluates
// Policy or the blast-radius cap itself (invariant 10/12); both dispatch
// through the SAME injected Executor, so every acceptance the capability
// layer already proves (Freeze/authz/cap/audit, at-most-once) carries
// through unchanged.
func registerExecutionTools(srv *sdkmcp.Server, exec Executor, results JobResultReader, ops OperationLister) {
	sdkmcp.AddTool(srv, &sdkmcp.Tool{
		Name: "run_operation",
		Description: "Run a structured Operation (ADR-0001's typed, native-argv path — never a shell) " +
			"against a Selector's matched Nodes through the capability layer (Selector -> authz -> " +
			"blast-cap -> dispatch -> audit). Blocks until every matched Node's Task reaches a terminal " +
			"outcome and returns per-Node results plus the Job id; get_job re-reads the same Job later.",
	}, func(ctx context.Context, _ *sdkmcp.CallToolRequest, in runOperationInput) (*sdkmcp.CallToolResult, executionOutput, error) {
		logPrincipal(ctx, "run_operation")
		p, err := requirePrincipal(ctx)
		if err != nil {
			return nil, executionOutput{}, err
		}

		sel, err := capability.ParseSelector(in.Selector)
		if err != nil {
			return nil, executionOutput{}, fmt.Errorf("invalid selector: %w", err)
		}

		act, err := buildOperationAction(ops, in.Operation, in.Args, in.TimeoutSeconds)
		if err != nil {
			return nil, executionOutput{}, err
		}

		out, err := dispatchAndRender(ctx, exec, results, p, sel, act)
		if err != nil {
			return nil, executionOutput{}, err
		}
		return nil, out, nil
	})

	sdkmcp.AddTool(srv, &sdkmcp.Tool{
		Name: "raw_exec",
		Description: "Run an arbitrary argv (ADR-0001's regex-gated escape hatch) against a Selector's " +
			"matched Nodes, always risk class mutate (ADR-0012) regardless of what argv does. argv runs " +
			"verbatim — no shell, no client-side splitting — and the daemon's Policy regex decides per " +
			"Node whether it is allowed (a per-Node refusal renders outcome=denied_by_policy). Prefer " +
			"run_operation's typed path when a structured Operation covers the same intent.",
	}, func(ctx context.Context, _ *sdkmcp.CallToolRequest, in rawExecInput) (*sdkmcp.CallToolResult, executionOutput, error) {
		logPrincipal(ctx, "raw_exec")
		p, err := requirePrincipal(ctx)
		if err != nil {
			return nil, executionOutput{}, err
		}

		if len(in.Argv) == 0 {
			return nil, executionOutput{}, fmt.Errorf("argv must not be empty")
		}

		sel, err := capability.ParseSelector(in.Selector)
		if err != nil {
			return nil, executionOutput{}, fmt.Errorf("invalid selector: %w", err)
		}

		timeoutSeconds, err := resolveTimeoutSeconds(in.TimeoutSeconds)
		if err != nil {
			return nil, executionOutput{}, err
		}
		// Raw Exec always takes RiskClassMutate by construction, regardless
		// of what argv does (ADR-0012, invariant 13) — no client field can
		// change this.
		act := jobs.Action{Kind: jobs.ActionRawExec, RawExecArgv: in.Argv, RiskClass: jobs.RiskClassMutate, TimeoutSeconds: timeoutSeconds}

		out, err := dispatchAndRender(ctx, exec, results, p, sel, act)
		if err != nil {
			return nil, executionOutput{}, err
		}
		return nil, out, nil
	})
}
