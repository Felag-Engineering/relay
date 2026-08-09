package mcp

// This file is the single source of truth for every MCP tool's JSON output
// shape (#161): the 13 structs below were previously unexported, forcing
// every test package that needed to unmarshal a tool's response — the
// external mcp_test package (can't see unexported types across a package
// boundary) and cmd/relay's own e2e suite (can't import _test.go-only types
// at all) — to hand-copy a "JSON mirror" struct field-for-field instead. That
// produced 24 mirror decls across 5 files, and one of them (cmd/relay's
// perNodeResultJSON) had silently drifted to 4 fields against PerNodeResult's
// real 8 — a green e2e asserting a stale wire shape. Exporting these types
// here lets every test import and unmarshal into the real type directly, so
// drift becomes a compile error instead of a silent gap.
//
// Render funcs (renderJob, renderPlan, perNodeResultFromTask, …) stay in
// tools_execution.go/tools_nodes.go/tools_operations.go — this file is pure
// data, no methods, no capability.*/newDispatch references (no_dispatch_test.go
// classifies it as a strict readFile). Input types (runOperationInput,
// rawExecInput, describeNodeInput, …) stay unexported: tests never unmarshal
// INTO them, only out of these output types.

// FactsOutput mirrors registry.Facts for MCP tool output — a proto-free
// domain type rendered straight to wire JSON, no proto dependency.
type FactsOutput struct {
	Hostname    string   `json:"hostname"`
	OS          string   `json:"os"`
	Kernel      string   `json:"kernel"`
	Arch        string   `json:"arch"`
	IPAddresses []string `json:"ip_addresses"`
}

// NodeItem is one Node's registry view, rendered by list_nodes and (as the
// base of) describe_node. NodeLabels and RelayLabels are separate top-level
// JSON keys — never merged into one map (ADR-0006, invariant 7): a caller
// must always be able to tell which namespace a label came from.
type NodeItem struct {
	NodeID            string            `json:"node_id"`
	NodeLabels        map[string]string `json:"node_labels"`
	RelayLabels       map[string]string `json:"relay_labels"`
	Facts             FactsOutput       `json:"facts"`
	LastSeen          string            `json:"last_seen"`
	PolicyFingerprint string            `json:"policy_fingerprint"`
	Revoked           bool              `json:"revoked"`
	RevokedAt         string            `json:"revoked_at,omitempty"`
	Outdated          bool              `json:"outdated"`
}

// ListNodesOutput is list_nodes' result shape.
type ListNodesOutput struct {
	Nodes []NodeItem `json:"nodes"`
}

// OperationRuleOutput is one [[operation]] allow rule, mirrored verbatim
// from the daemon's loaded Policy (policyview.OperationRule; ADR-0002).
// AllowedArgs[i] is the permitted-value set at argv position i, with "*" as
// the explicit per-position wildcard. AllowedArgs is ALWAYS a JSON array,
// never null (#207/#253): an empty array means the Operation is allowed with
// zero arguments — an empty set of argv positions, not an absent constraint
// ("any value" is only ever spelled as the explicit "*"). A policyview rule
// whose AllowedArgs arrived as nil (proto empty repeated) means exactly the
// same zero-argument set, so the renderer (tools_nodes.go) normalizes nil to
// [] rather than making consumers branch on two spellings. Display-only:
// the Relay never evaluates these (ADR-0011).
type OperationRuleOutput struct {
	Name        string     `json:"name"`
	AllowedArgs [][]string `json:"allowed_args" jsonschema:"Always an array, never null. allowed_args[i] is the permitted-value set at argv position i ('*' is the explicit any-value wildcard for that position); an empty array means the Operation is allowed with zero arguments only."`
}

// DenyRuleOutput is one [[deny]] rule, mirrored verbatim from the daemon's
// loaded Policy (policyview.DenyRule; ADR-0002). Args[i] is the denied-value
// set at argv position i. Args is ALWAYS a JSON array, never null
// (#207/#253, same normalization as OperationRuleOutput.AllowedArgs): an
// empty array denies the whole Operation regardless of arguments.
// Display-only: the Relay never evaluates these (ADR-0011).
type DenyRuleOutput struct {
	Name string     `json:"name"`
	Args [][]string `json:"args" jsonschema:"Always an array, never null. args[i] is the denied-value set at argv position i; an empty array denies the whole Operation regardless of arguments."`
}

// EffectivePolicyOutput is the display-only effective-Policy view
// (policyview.Snapshot; invariant 12, ADR-0002/0011): the Relay never
// evaluates Policy, only displays what the daemon last reported. Reported is
// false when no snapshot has been captured yet for this Node — e.g. it
// hasn't (re)connected since the Relay last started, or the daemon doesn't
// yet emit PolicySnapshot (follow-up #151) — never treat absence as "no
// restrictions".
type EffectivePolicyOutput struct {
	RawExecEnabled    bool     `json:"raw_exec_enabled"`
	RawAllowPatterns  []string `json:"raw_allow_patterns"`
	RawDenyPatterns   []string `json:"raw_deny_patterns"`
	AllowedOperations []string `json:"allowed_operations"`
	PolicyFingerprint string   `json:"policy_fingerprint"`
	Reported          bool     `json:"reported"`
	// OperationRules and DenyRules are raw mirrors of the daemon's loaded
	// Policy file (every [[operation]]/[[deny]] block, in file order; no
	// dedup, no evaluation) — see the OperationRuleOutput/DenyRuleOutput
	// doc comments. Both are ALWAYS JSON arrays, never null (#207/#253):
	// empty when the reported Policy has no operation/deny blocks, and also
	// when Reported is false — Reported is the only "no data yet" signal,
	// never a null here.
	OperationRules []OperationRuleOutput `json:"operation_rules" jsonschema:"Always an array, never null: empty when the reported Policy has no [[operation]] blocks, or when reported is false. reported is the only no-data-yet signal."`
	DenyRules      []DenyRuleOutput      `json:"deny_rules" jsonschema:"Always an array, never null: empty when the reported Policy has no [[deny]] blocks, or when reported is false. reported is the only no-data-yet signal."`
}

// DescribeNodeOutput is NodeItem's fields (flattened via Go's anonymous
// embedding, both in JSON and in the inferred tool output schema) plus the
// effective Policy view.
type DescribeNodeOutput struct {
	NodeItem
	EffectivePolicy EffectivePolicyOutput `json:"effective_policy"`
}

// OperationItem is one Operation's vocabulary entry, rendered by
// list_operations: name, risk class, and (#120) the model-facing legibility
// prose — Purpose, ArgConstraints, and a concrete Example — that lives
// Relay-side in opvocab.Descriptor, never on the wire (invariant 8, central
// decision in #120's plan). This is what makes list_operations legible
// enough that a model chooses the right Operation, and builds valid args for
// it, without trial-and-error. Raw Exec is deliberately absent from this
// list: it is not an Operation (ADR-0003, CONTEXT.md) and has no
// OperationDescriptor on the wire; it surfaces through its own tool (#118)
// and is always risk class mutate.
type OperationItem struct {
	Name           string            `json:"name"`
	RiskClass      string            `json:"risk_class"`
	Purpose        string            `json:"purpose"`
	ArgConstraints map[string]string `json:"arg_constraints"`
	Example        string            `json:"example"`
}

// ListOperationsOutput is list_operations' result shape.
type ListOperationsOutput struct {
	Operations []OperationItem `json:"operations"`
}

// PerNodeResult is one Node's rendered Task outcome — exit code, size-capped
// output, and duration — the shape run_operation/raw_exec/get_job all
// render (renderJob, tools_execution.go). Outcome/denied_by_policy come
// straight off the Task the daemon resolved: this package never evaluates
// Policy itself (invariant 12).
//
// ExitCode is a pointer so a Task with no real process exit status renders
// with NO exit_code key at all (#207/#253): the daemon's -1 "no exit status"
// sentinel (spawn failure, timeout/cancel kill, signal-kill,
// denied_by_policy) and the Relay's synthesized zero value (unreachable,
// version_refused) both read as plausible real exit codes, which is exactly
// the ambiguity ADR-0001/0003's legibility posture forbids. Present iff a
// process actually ran and exited with a status (exitCodePtr,
// tools_execution.go); Outcome is always the authoritative did-it-run state.
type PerNodeResult struct {
	NodeID          string `json:"node_id"`
	Outcome         string `json:"outcome"`
	ExitCode        *int32 `json:"exit_code,omitempty" jsonschema:"Present only when a process actually ran and exited with a status. Absent when nothing executed (denied_by_policy, unreachable, version_refused) or the process was killed without an exit status (timeout, cancelled, spawn failure) — outcome is the authoritative state, see stderr for the reason."`
	Stdout          string `json:"stdout"`
	Stderr          string `json:"stderr"`
	StdoutTruncated bool   `json:"stdout_truncated"`
	StderrTruncated bool   `json:"stderr_truncated"`
	DurationMS      int64  `json:"duration_ms"`
}

// ExecutionOutput is get_job's result shape: the Job id (echoed back, always
// present — get_job is keyed by it) plus every one of the Job's rendered
// per-Node results. run_operation/raw_exec render the superset
// RunOrPlanOutput instead — see its JobID presence rules.
type ExecutionOutput struct {
	JobID   string          `json:"job_id"`
	Results []PerNodeResult `json:"results"`
}

// PerNodeVerdict is one matched Node's Plan-mode result (#119, ADR-0011):
// "allow"/"deny"/"unknown", with DecidingRule set only on deny and Reason
// (e.g. "offline") set only on unknown — mirrors PerNodeResult's per-Node
// shape but for a verdict, never an executed outcome.
type PerNodeVerdict struct {
	NodeID       string `json:"node_id"`
	Verdict      string `json:"verdict"`
	DecidingRule string `json:"deciding_rule,omitempty"`
	Reason       string `json:"reason,omitempty"`
	// Outdated is the ADR-0014 apply-time-refusal hint: true when this
	// Node's relay-daemon is below the Relay's configured minimum version,
	// so a real dispatch (plan=false) would refuse it with
	// version_refused regardless of Verdict.
	Outdated bool `json:"outdated"`
}

// WouldBeRejected reports why real dispatch (plan=false against the same
// Selector/Action) would currently be refused, without erroring the Plan
// itself (ADR-0011/0013: a Plan reports guardrails, never hard-fails on
// them). "exceeds_cap" carries Matched/Cap/Class; "frozen" carries neither —
// the Relay-wide Freeze is not Selector/Action-specific.
type WouldBeRejected struct {
	Reason  string `json:"reason"`
	Matched int    `json:"matched,omitempty"`
	Cap     int    `json:"cap,omitempty"`
	Class   string `json:"class,omitempty"`
}

// PlanOutput is plan=true's result shape: the resolved fan-out size, the
// per-Node verdicts (empty when WouldBeRejected is set — the query fan-out
// is skipped over-cap), an optional would-be-rejected report, and a fixed
// point-in-time advisory string (ADR-0011: Policy may change between plan
// and apply).
type PlanOutput struct {
	Matched         int              `json:"matched"`
	Verdicts        []PerNodeVerdict `json:"verdicts"`
	WouldBeRejected *WouldBeRejected `json:"would_be_rejected,omitempty"`
	Advisory        string           `json:"advisory"`
}

// RunOrPlanOutput is run_operation/raw_exec's shared result shape (#119):
// additive over ExecutionOutput. JobID carries omitempty (#207/#253,
// superseding #119's byte-identical-to-#118 freeze): it is present exactly
// when a Job was created, and absent on a plan=true response (a Plan
// executes nothing — an empty "job_id" read as a missing/failed id) and on
// a zero-match plan=false run (Run never reached the dispatcher, so there
// is no Job to read back). An absent job_id therefore always means "nothing
// was dispatched", never a failed id. Results is always an array — empty,
// never null, when nothing was dispatched (plan=true or zero-match). Plan
// is omitempty, populated only when plan=true.
type RunOrPlanOutput struct {
	JobID   string          `json:"job_id,omitempty" jsonschema:"Present only when a Job was created (a real dispatch that matched at least one Node); use it with get_job/cancel_job. Absent on plan=true responses and zero-match dispatches — an absent job_id always means nothing was dispatched, never a failed id."`
	Results []PerNodeResult `json:"results" jsonschema:"Always an array, never null: one entry per matched Node on a real dispatch, empty when nothing was dispatched (plan=true or zero Nodes matched)."`
	Plan    *PlanOutput     `json:"plan,omitempty"`
}
