package mcp

// This file is the single source of truth for every MCP tool's JSON output
// shape: the 13 structs below were previously unexported, forcing
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
	NodeID      string            `json:"node_id"`
	NodeLabels  map[string]string `json:"node_labels"`
	RelayLabels map[string]string `json:"relay_labels"`
	Facts       FactsOutput       `json:"facts"`
	LastSeen    string            `json:"last_seen"`

	PolicyFingerprint string `json:"policy_fingerprint"`
	// TemplateSetFingerprint is the Node's reported Template Operation set
	// fingerprint (ADR-0021), beside policy_fingerprint: the drift signal that
	// confirms a template rollout the same way policy_fingerprint confirms a
	// Policy rollout. Empty means no templates are installed on that Node; the
	// literal "unloadable" means its local template set failed to load, so its
	// template vocabulary is empty (fail closed, daemon-side).
	TemplateSetFingerprint string `json:"template_set_fingerprint" jsonschema:"SHA-256 hex of the Node's loaded Template Operation set. Empty means no templates installed; 'unloadable' means the Node's template set failed to load and it has no Template Operations."`

	Revoked   bool   `json:"revoked"`
	RevokedAt string `json:"revoked_at,omitempty"`
	Outdated  bool   `json:"outdated"`

	// Connected is whether the Node holds a live Tunnel right now.
	//
	// Distinct from LastSeen, and the distinction is the point: a Node that
	// reported four seconds ago and then dropped its stream is unreachable for
	// dispatch *now*, and ADR-0004 resolves such a Task `unreachable` without
	// sending it. A caller that inferred reachability from last_seen would
	// disagree with the dispatcher about what its own fleet can do.
	Connected bool `json:"connected" jsonschema:"Whether the Node holds a live Tunnel right now. A Task dispatched to a Node that is not connected resolves 'unreachable' without being sent — this is NOT inferable from last_seen."`

	// StateLabels are the `state:` namespace (ADR-0034): Relay-DERIVED
	// labels, evaluated at read time and set by nobody — not the Node, not an
	// operator, not an admin. Rendered in Selector syntax with the `state:`
	// prefix (e.g. "state:offline", "state:daemon-version=1.4.2") and
	// targetable verbatim in any Selector. Closed vocabulary: every value here
	// is one of the markers or facts nodestate.Labels enumerates. Always a
	// non-nil array, never null.
	StateLabels []string `json:"state_labels" jsonschema:"Relay-derived state: labels (ADR-0034), evaluated at read time and set by nobody. Rendered in Selector syntax with the state: prefix (e.g. 'state:offline', 'state:daemon-version=1.4.2') and targetable verbatim in any selector. Closed vocabulary. Always an array, never null."`
}

// ListNodesOutput is list_nodes' result shape.
type ListNodesOutput struct {
	Nodes []NodeItem `json:"nodes"`
}

// OperationRuleOutput is one [[operation]] allow rule, mirrored verbatim
// from the daemon's loaded Policy (policyview.OperationRule; ADR-0002).
// AllowedArgs[i] is the permitted-value set at argv position i, with "*" as
// the explicit per-position wildcard. AllowedArgs is ALWAYS a JSON array,
// never null: an empty array means the Operation is allowed with
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
// (same normalization as OperationRuleOutput.AllowedArgs): an
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
	// doc comments. Both are ALWAYS JSON arrays, never null:
	// empty when the reported Policy has no operation/deny blocks, and also
	// when Reported is false — Reported is the only "no data yet" signal,
	// never a null here.
	OperationRules []OperationRuleOutput `json:"operation_rules" jsonschema:"Always an array, never null: empty when the reported Policy has no [[operation]] blocks, or when reported is false. reported is the only no-data-yet signal."`
	DenyRules      []DenyRuleOutput      `json:"deny_rules" jsonschema:"Always an array, never null: empty when the reported Policy has no [[deny]] blocks, or when reported is false. reported is the only no-data-yet signal."`
}

// TemplateSlotOutput is one typed parameter slot of a Template Operation, as
// reported by the Node (nodevocab.Slot; ADR-0021). Type is the daemon's slot
// type — "identifier", "integer", "path", or "enum" — and EnumValues is the
// author's finite allow-list, populated only for "enum". Display-only: the
// daemon validates every parameter at execution time; this is what lets a
// caller build valid args without trial-and-error (ADR-0001 legibility).
type TemplateSlotOutput struct {
	Name       string   `json:"name"`
	Type       string   `json:"type" jsonschema:"Slot type validated daemon-side: identifier, integer, path, or enum."`
	EnumValues []string `json:"enum_values" jsonschema:"Always an array, never null: the finite allow-list for an enum slot, empty for every other slot type."`
}

// TemplateOperationOutput is one Template Operation in a Node's vocabulary
// (nodevocab.Template; ADR-0021): the name it registers in that Node's Policy
// vocabulary, its mandatory risk class (ADR-0012), and its typed parameter
// slots in declaration order — which is the positional order Policy evaluates
// its args in. The template's shell body is deliberately absent: it never
// crosses the wire (see /proto), because only the daemon ever renders it.
type TemplateOperationOutput struct {
	Name      string               `json:"name"`
	RiskClass string               `json:"risk_class"`
	Slots     []TemplateSlotOutput `json:"slots" jsonschema:"Always an array, never null: the template's parameter slots in declaration order; empty for a template with no parameters."`
}

// TemplateVocabularyOutput is one Node's reported Template Operation
// vocabulary. Reported is false when the Node has not reported a template
// snapshot yet (it has not reconnected since the Relay restarted, or it runs a
// daemon predating the template tier) — never read absence as "this Node has
// no templates": a reported snapshot with an empty templates array says that.
type TemplateVocabularyOutput struct {
	Fingerprint string                    `json:"template_set_fingerprint"`
	Reported    bool                      `json:"reported" jsonschema:"false means no template snapshot has been captured for this Node yet — never that the Node has no templates."`
	Templates   []TemplateOperationOutput `json:"templates" jsonschema:"Always an array, never null: this Node's loaded Template Operations, empty when it has none or when reported is false."`
}

// DescribeNodeOutput is NodeItem's fields (flattened via Go's anonymous
// embedding, both in JSON and in the inferred tool output schema) plus the
// effective Policy view and the Node's Template Operation vocabulary.
type DescribeNodeOutput struct {
	NodeItem
	EffectivePolicy    EffectivePolicyOutput    `json:"effective_policy"`
	TemplateVocabulary TemplateVocabularyOutput `json:"template_vocabulary"`

	// Certificate is the Node's identity provenance. Present only on
	// describe_node: it is per-Node detail, and list_nodes is deliberately a
	// fleet-shaped view.
	Certificate CertificateOutput `json:"certificate"`
}

// CertificateOutput is what the Relay knows about the identity it issued to a
// Node — all of it Relay-knowledge, none of it Node-reported. A daemon cannot
// influence any value here; the Relay signed the certificate.
//
// Recorded is the field to read FIRST. A Node that enrolled before this was
// stored carries no provenance until its next renewal, and every other field is
// then a zero value. A caller that skipped this flag would read `not_after` as
// an expiry in 1970 — catastrophically overdue rather than simply unknown.
type CertificateOutput struct {
	Recorded bool `json:"recorded" jsonschema:"False when the Relay has not recorded this Node's certificate provenance — every other field here is then meaningless, NOT an expiry in the past. Nodes enrolled before provenance was stored fill in at their next renewal."`

	// Fingerprint is the SHA-256 of the DER bytes: the Node's identity on the
	// wire, and what mTLS authenticates it by.
	Fingerprint string `json:"fingerprint,omitempty"`

	// NotAfter is when this identity stops working. A Node past it cannot
	// connect at all, and nothing else warns first.
	NotAfter string `json:"not_after,omitempty"`

	// EnrolledAt is when the Node FIRST joined, and it survives every renewal.
	// Renewal is certificate-authenticated and preserves node_id, so this is one
	// end of an unbroken chain whose other end is enrolling_token_id.
	EnrolledAt string `json:"enrolled_at,omitempty"`

	// RenewalCount and LastRenewedAt describe whether renewal is still working.
	// A count that has stopped climbing while not_after approaches is the exact
	// silent failure that ends with a Node dropping off the fleet.
	RenewalCount  int    `json:"renewal_count"`
	LastRenewedAt string `json:"last_renewed_at,omitempty"`
}

// OperationItem is one Operation's vocabulary entry, rendered by
// list_operations: name, risk class, and the model-facing legibility
// prose — Purpose, ArgConstraints, and a concrete Example — that lives
// Relay-side in opvocab.Descriptor, never on the wire (invariant 8, central
// decision in #120's plan). This is what makes list_operations legible
// enough that a model chooses the right Operation, and builds valid args for
// it, without trial-and-error. Raw Exec is deliberately absent from this
// list: it is not an Operation (ADR-0003, GLOSSARY.md) and has no
// OperationDescriptor on the wire; it surfaces through its own tool
// and is always risk class mutate.
type OperationItem struct {
	Name           string            `json:"name"`
	RiskClass      string            `json:"risk_class"`
	Purpose        string            `json:"purpose"`
	ArgConstraints map[string]string `json:"arg_constraints"`
	Example        string            `json:"example"`
	// Source is "native" for the frozen Native Operation vocabulary (present
	// on every Node) and "template" for a Template Operation loaded from local
	// root-owned files on ONE Node (ADR-0021). A template entry appears only
	// when list_operations was called with a node_id, and dispatching it to a
	// Node that lacks it reports the `unsupported` outcome — nothing runs and
	// Policy is never consulted.
	Source string `json:"source" jsonschema:"'native' (frozen vocabulary, present on every Node) or 'template' (loaded on the queried Node only)."`
}

// ListOperationsOutput is list_operations' result shape. NodeID and
// TemplateSetFingerprint are populated only when the caller asked about a
// specific Node; TemplatesReported then says whether that Node's template
// vocabulary was actually captured (false = not reported yet, NOT "no
// templates").
type ListOperationsOutput struct {
	Operations             []OperationItem `json:"operations"`
	NodeID                 string          `json:"node_id,omitempty" jsonschema:"Echoed only when the request named a Node; its Template Operations are then included alongside the native vocabulary."`
	TemplatesReported      bool            `json:"templates_reported" jsonschema:"Only meaningful when node_id was given: false means no template snapshot has been captured for that Node yet, never that it has no templates."`
	TemplateSetFingerprint string          `json:"template_set_fingerprint,omitempty"`
}

// PerNodeResult is one Node's rendered Task outcome — exit code, size-capped
// output, and duration — the shape run_operation/raw_exec/get_job all
// render (renderJob, tools_execution.go). Outcome/denied_by_policy come
// straight off the Task the daemon resolved: this package never evaluates
// Policy itself (invariant 12).
//
// ExitCode is a pointer so a Task with no real process exit status renders
// with NO exit_code key at all: the daemon's -1 "no exit status"
// sentinel (spawn failure, timeout/cancel kill, signal-kill,
// denied_by_policy), the Relay's synthesized zero value (unreachable,
// version_refused), and — since #632 — the Relay's own -1 on a Task whose
// daemon report the wire boundary refused as a protocol violation (it may
// well have executed; what happened is unknown) all read as plausible real
// exit codes, which is exactly the ambiguity ADR-0001/0003's legibility
// posture forbids. Present iff a process actually ran and exited with a
// status (controlplane.ExitCode); Outcome is always the
// authoritative did-it-run state.
//
// RefusalExplanation carries a second author on a denied_by_policy row: stderr
// stays the Node's own verbatim reason, and RefusalExplanation is the Relay's
// framing of the boundary that reason belongs to. On a version_refused row the
// Relay authored both, so RefusalExplanation repeats stderr. Never infer the
// two agree, and never infer they differ.
type PerNodeResult struct {
	NodeID             string `json:"node_id"`
	Outcome            string `json:"outcome"`
	ExitCode           *int32 `json:"exit_code,omitempty" jsonschema:"Present only when a process actually ran and exited with a status. Absent when nothing executed (denied_by_policy, unreachable, version_refused) or the process was killed without an exit status (timeout, cancelled, spawn failure) — outcome is the authoritative state, see stderr for the reason. Also absent on a failure row whose daemon report the Relay refused as a protocol violation: the Task may well have executed, but what happened is unknown, so stderr is Relay-authored rather than the daemon's own bytes."`
	Stdout             string `json:"stdout"`
	Stderr             string `json:"stderr"`
	StdoutTruncated    bool   `json:"stdout_truncated"`
	StderrTruncated    bool   `json:"stderr_truncated"`
	DurationMS         int64  `json:"duration_ms"`
	RefusalExplanation string `json:"refusal_explanation,omitempty" jsonschema:"Present when a named boundary refused this Task and nothing executed (denied_by_policy, version_refused). Relay-authored — on a denied_by_policy row stderr still carries the Node's own verbatim reason; on a version_refused row the Relay authored both and this repeats stderr. Absent means no boundary refusal, not that the Task succeeded — outcome is authoritative."`
}

// ExecutionOutput is get_job's result shape: the Job id (echoed back, always
// present — get_job is keyed by it) plus every one of the Job's rendered
// per-Node results. run_operation/raw_exec render the superset
// RunOrPlanOutput instead — see its JobID presence rules.
type ExecutionOutput struct {
	JobID     string          `json:"job_id"`
	JobStatus string          `json:"job_status" jsonschema:"running while any Task is unresolved (its outcome reads unspecified); complete once every Task has a terminal outcome. Poll get_job with job_id until complete."`
	Results   []PerNodeResult `json:"results"`
}

// PerNodeVerdict is one matched Node's Plan-mode result (ADR-0011):
// "allow"/"deny"/"unknown", with DecidingRule set only on deny and Reason
// (e.g. "offline") set only on unknown — mirrors PerNodeResult's per-Node
// shape but for a verdict, never an executed outcome.
//
// RefusalExplanation is the Relay's framing of the boundary a deny verdict
// belongs to; DecidingRule remains the daemon's rule text, verbatim — two
// different authors on the same verdict, exactly as on PerNodeResult.
type PerNodeVerdict struct {
	NodeID             string `json:"node_id"`
	Verdict            string `json:"verdict"`
	DecidingRule       string `json:"deciding_rule,omitempty"`
	Reason             string `json:"reason,omitempty"`
	RefusalExplanation string `json:"refusal_explanation,omitempty" jsonschema:"Present only on verdict=deny: the Relay's framing of the boundary that would refuse it. Nothing would be dispatched. deciding_rule remains the daemon's rule text, verbatim."`
	// Outdated is the ADR-0014 apply-time-refusal hint: true when this
	// Node's relay-daemon is below the Relay's configured minimum version,
	// so a real dispatch (plan=false) would refuse it with
	// version_refused regardless of Verdict.
	Outdated bool `json:"outdated"`
}

// WouldBeRejected reports why real dispatch (plan=false against the same
// Selector/Action) would currently be refused, without erroring the Plan
// itself (ADR-0011/0013: a Plan reports guardrails, never hard-fails on
// them). Three reasons: "exceeds_cap" carries Matched/Cap/Class; "frozen" and
// "no_nodes_matched" carry neither — the Freeze is Relay-wide, and the zero
// count is already the top-level Matched.
type WouldBeRejected struct {
	Reason  string `json:"reason"`
	Matched int    `json:"matched,omitempty"`
	Cap     int    `json:"cap,omitempty"`
	Class   string `json:"class,omitempty"`
}

// PlanOutput is plan=true's result shape: the resolved fan-out size, the
// per-Node verdicts (empty over-cap, since the fan-out is skipped, and when
// no Node matched — there was no Node to ask), an optional would-be-rejected
// report, and a fixed point-in-time advisory string (ADR-0011: Policy may
// change between plan and apply).
type PlanOutput struct {
	Matched         int              `json:"matched"`
	Verdicts        []PerNodeVerdict `json:"verdicts"`
	WouldBeRejected *WouldBeRejected `json:"would_be_rejected,omitempty"`
	Advisory        string           `json:"advisory"`
}

// RunOrPlanOutput is run_operation/raw_exec's shared result shape:
// additive over ExecutionOutput. JobID carries omitempty (#207/#253,
// superseding #119's byte-identical-to-#118 freeze): it is present exactly
// when a Job was created, and absent on a plan=true response (a Plan
// executes nothing — an empty "job_id" read as a missing/failed id) and on
// a parked dispatch (nothing was dispatched, so there is no Job to read
// back yet). A zero-match dispatch is refused as no_nodes_matched and never
// produces this shape at all. An absent job_id therefore always means
// "nothing was dispatched", never a failed id. Results is always an array —
// empty, never null, when nothing was dispatched (plan=true or a parked
// dispatch). Plan is omitempty, populated only when plan=true.
type RunOrPlanOutput struct {
	JobID   string          `json:"job_id,omitempty" jsonschema:"Present only when a Job was created (every dispatch that ran; a Selector matching no Nodes is refused as no_nodes_matched and creates no Job); use it with get_job/cancel_job. Absent on plan=true and pending_approval responses — an absent job_id always means nothing was dispatched, never a failed id."`
	Results []PerNodeResult `json:"results" jsonschema:"Always an array, never null: one entry per matched Node on a real dispatch, empty when nothing was dispatched (plan=true or a parked dispatch)."`
	Plan    *PlanOutput     `json:"plan,omitempty"`

	// JobStatus and Reattached describe a Job returned at persist.
	JobStatus  string `json:"job_status,omitempty" jsonschema:"running while any Task is unresolved (its outcome reads unspecified); complete once every Task has a terminal outcome; absent when no Job was created. Poll get_job with job_id until complete."`
	Reattached bool   `json:"reattached,omitempty" jsonschema:"true when this call dispatched nothing and returned the Job an earlier call created (same idempotency_key, or an approval already released)."`

	// PendingApproval is set when the dispatch PARKED for human approval
	// (ADR-0027) instead of running. When it is present, job_id is absent and
	// results is empty — nothing was dispatched and no Job exists.
	PendingApproval *PendingApprovalOutput `json:"pending_approval,omitempty"`

	// Decision is present only on an answered retry (#727: an MRTR
	// elicitation answer to a parked approval, ADR-0029 decision 6): what was
	// decided, alongside whatever ran. Absent on every ordinary call — a
	// question result cannot carry it either, because the SDK forbids
	// structured content alongside InputRequests (see answerThenDispatch,
	// tools_execution.go).
	Decision *ApprovalDecisionOutput `json:"decision,omitempty"`

	// AnswerRefused is present only when an answered retry's answer was
	// refused. Nothing was dispatched. Whether the request, if it exists, is
	// unchanged by this call depends on WHEN the refusal happened: NextStep
	// says so precisely (tools_approval.go's refusalOutput) — a refusal
	// raised before the decider was ever reached leaves the request
	// unchanged and answerable again, but a non-domain failure reaching this
	// call AFTER the decider ran (for example an audit write failing once
	// the decision was already durable) may mean the request already
	// reflects this very answer, and NextStep tells the caller to confirm
	// its state rather than assuming either way (security review #727
	// finding 1).
	AnswerRefused *AnswerRefusalOutput `json:"answer_refused,omitempty"`
}

// AnswerRefusalOutput is what an answered retry renders when its
// answer was refused before or instead of reaching a decision: a tampered or
// unbound requestState, a malformed responder assertion, a machine
// self-decision, or a request the domain refuses for a reason
// renderApprovalError already has a message for. See the NextStep field:
// what to do about the refusal depends on whether the decider was ever
// reached, and its text says so rather than always claiming the request is
// unchanged.
//
// It holds only the state, the Job ID and the deadline from a refused
// decision, never the Decisions (#735 review; issue #727 comment 1): a
// refused decision's Request may carry OTHER approvers' identities and
// reasons, and this type is deliberately too narrow to reach any of that —
// see elicitedAnswerResult (tools_approval.go), which is what it is built
// from.
type AnswerRefusalOutput struct {
	RequestID string `json:"request_id,omitempty" jsonschema:"The request this answer aimed at, from the verified seal. Empty when the requestState never opened at all."`
	Reason    string `json:"reason" jsonschema:"Why the answer was refused, and what to do about it."`
	State     string `json:"state,omitempty" jsonschema:"The request's state at the moment this answer was refused, when known."`
	JobID     string `json:"job_id,omitempty" jsonschema:"Set only when the request had already released a Job before this answer arrived."`
	ExpiresAt string `json:"expires_at,omitempty" jsonschema:"When the request lapses (RFC 3339), when known."`
	NextStep  string `json:"next_step" jsonschema:"What to do next."`
}

// PendingApprovalOutput is the Relay-authored description of a dispatch that
// parked for human approval (ADR-0027) — the MCP twin of the Control API's
// 202 `pending_approval` body.
//
// It is rendered as a successful tool RESULT, never as a tool error, and that
// choice is security-relevant rather than cosmetic (ADR-0001/0003 legibility).
// A park is neither a failure nor a completion: nothing was denied and nothing
// ran. An AI-agent told "dispatch failed" learns the wrong lesson twice over —
// it may retry the call in a loop against a gate that will park it every time,
// and it may report to its operator that the fleet action errored when in fact
// a human is being asked to approve it.
//
// What it deliberately does NOT carry is any way to answer. The decision lands
// on the authenticated Control API endpoint, riding a credential this MCP
// session does not hold (ADR-0027) — that separation is the entire guarantee,
// and it is enforced structurally by no_decision_test.go. DecisionPath is
// therefore a POINTER for a human to follow, not a capability the AI-agent can
// exercise.
type PendingApprovalOutput struct {
	// Status is the constant "pending_approval", so a client branches on a
	// stable value rather than on the presence of a sibling field.
	Status string `json:"status" jsonschema:"Always the literal 'pending_approval'. The dispatch is waiting for a human decision; it has neither failed nor run."`

	RequestID string `json:"request_id" jsonschema:"The approval request's id. Quote it to whoever is being asked to decide; it is also the id the Control API's decision endpoint is keyed by."`
	PlanHash  string `json:"plan_hash" jsonschema:"Content address of the Operation, its arguments, and the resolved fan-out. A decision is bound to this exact Plan, so if the fleet changes before it is answered the dispatch re-parks rather than running against a different set of Nodes."`

	Summary string `json:"summary" jsonschema:"The Relay-authored description of what is waiting, exactly as the approver will see it. Relay writes this text, not the caller — report it verbatim rather than paraphrasing, so what you tell a human matches what they are asked to approve."`

	MatchedRules []string `json:"matched_rules" jsonschema:"Which approval-gate rules required a human for this dispatch. Always an array, never null."`
	Progress     string   `json:"progress" jsonschema:"Partial quorum, e.g. '0 of 2' — how many of the required distinct approvals have been recorded."`
	ExpiresAt    string   `json:"expires_at" jsonschema:"When the parked request lapses (RFC 3339). After this it can no longer be approved and the dispatch must be re-requested."`

	// DecisionPath names the Control API route an approver uses. See the type
	// doc: a pointer, never a capability of this session.
	DecisionPath string `json:"decision_path" jsonschema:"The Control API route where an authorized human can answer this request. Do not approve this yourself; surface it to a human."`

	// NextStep is plain-language guidance for the AI-agent holding this result.
	NextStep string `json:"next_step" jsonschema:"What to do next."`

	// TaskID is the MCP task handle attached to this park (SEP-2663), or
	// absent when the Relay has no handle store wired.
	//
	// It is carried in the ORDINARY result — not only in a Tasks-shaped one —
	// because it is how a client learns the handle exists at all. Note this is
	// not the SEP's task envelope: rewriting the response into a
	// CreateTaskResult is gated on the client advertising the Tasks capability
	// ([4/6]), and this field is merely a piece of Relay's own JSON. A client
	// that cannot use it ignores it and re-drives, exactly as before.
	//
	// It is a POLL handle, never a decision one. Resolving it reports state; no
	// MCP method answers an approval (ADR-0028, no_decision_test.go).
	TaskID string `json:"task_id,omitempty" jsonschema:"An MCP task handle for this parked dispatch, if the Relay has the Tasks extension enabled. A Tasks-capable client may poll tasks/get with it instead of re-driving the call. It cannot be used to approve anything."`

	// TaskExpiresAt is when that handle stops being pollable. It is NOT the
	// same as ExpiresAt above: that one is when the approval lapses, this is
	// when the handle does, and the handle is capped independently.
	//
	// It exists so the Tasks shim can render SEP-2663's ttlMs from the Relay's
	// own answer rather than deriving one — a shim that computed a lifetime
	// would be a second copy of the cap, drifting from the first.
	TaskExpiresAt string `json:"task_expires_at,omitempty" jsonschema:"When the MCP task handle stops being pollable (RFC 3339). Distinct from expires_at, which is when the approval itself lapses."`
}

// pendingApprovalNextStep is the fixed guidance every parked result carries.
//
// It is spelled out rather than left implicit because the failure mode it
// prevents is specific and expensive: an AI-agent that reads a park as a
// transient error retries, and each retry finds the SAME pending request by
// plan hash (so it neither duplicates the request nor makes progress) while
// burning the operator's attention. Telling the AI-agent plainly that waiting is
// correct, and that re-driving is how an approved Plan proceeds, is cheaper
// than any amount of inference.
const pendingApprovalNextStep = "Do not retry in a loop and do not treat this as an error. " +
	"Tell the requesting human that approval is required, quoting summary and request_id verbatim. " +
	"Once a human has approved it out-of-band, re-issue this same call unchanged to run it; " +
	"an unapproved or expired request will simply park again."
