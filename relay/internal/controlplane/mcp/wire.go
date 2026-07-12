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
}

// ListNodesOutput is list_nodes' result shape.
type ListNodesOutput struct {
	Nodes []NodeItem `json:"nodes"`
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
type PerNodeResult struct {
	NodeID          string `json:"node_id"`
	Outcome         string `json:"outcome"`
	ExitCode        int32  `json:"exit_code"`
	Stdout          string `json:"stdout"`
	Stderr          string `json:"stderr"`
	StdoutTruncated bool   `json:"stdout_truncated"`
	StderrTruncated bool   `json:"stderr_truncated"`
	DurationMS      int64  `json:"duration_ms"`
}

// ExecutionOutput is run_operation/raw_exec/get_job's shared result shape:
// the Job id (so a caller can later cancel_job/get_job it) plus every
// matched Node's rendered result. A zero-match dispatch (no Node matched the
// Selector) renders as {job_id: "", results: []} — Run never reached the
// dispatcher, so there is no Job to read back.
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
// additive over #118's ExecutionOutput. JobID/Results keep EXACTLY
// ExecutionOutput's tags — no omitempty — so a zero-match plan=false run
// still renders {"job_id":"","results":[]}, byte-identical to #118; Plan is
// the only new, omitempty field, populated only when plan=true.
type RunOrPlanOutput struct {
	JobID   string          `json:"job_id"`
	Results []PerNodeResult `json:"results"`
	Plan    *PlanOutput     `json:"plan,omitempty"`
}
