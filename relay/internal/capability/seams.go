package capability

import (
	"context"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/approval"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/jobs"
)

// ControlAction names one administrative act on the control plane ITSELF —
// the acts that are not dispatches and so carry no jobs.Action and no
// Selector, but still have a role floor (#397).
//
// It exists because "who may ask" was previously answered only for things
// that reach a Node. Minting an Enrollment Token, revoking one, revoking a
// Node, and engaging or releasing the Freeze never touch the dispatch
// pipeline, so authz.RoleGate was never consulted for any of them and every
// one of them was reachable by a viewer. Naming them here — in the capability
// layer, beside the Action-shaped question — is what lets a single Authorizer
// answer both, so MCP, the Control API, and the Console inherit one table
// rather than each surface carrying its own (invariant 10).
//
// The values are stable, low-cardinality identifiers: they appear in refusal
// reasons that land in the audit trail.
type ControlAction string

const (
	// ControlMintEnrollmentToken is POST /api/v1/enrollment-tokens. A token's
	// scope becomes the enrolling Node's relay: labels — the namespace
	// reserved for the security-sensitive lane (invariant 7, ADR-0020) — so
	// minting is a claim the control plane vouches for, not a convenience.
	ControlMintEnrollmentToken ControlAction = "mint_enrollment_token"

	// ControlRevokeEnrollmentToken is DELETE /api/v1/enrollment-tokens/{id},
	// which cascade-revokes every Node the token enrolled.
	ControlRevokeEnrollmentToken ControlAction = "revoke_enrollment_token"

	// ControlRevokeNode is POST /api/v1/nodes/{node_id}/revoke: the middle
	// rung of ADR-0020's incident ladder (quarantine < revoke < Freeze).
	ControlRevokeNode ControlAction = "revoke_node"

	// ControlFreezeEngage is POST /api/v1/freeze/engage (ADR-0013).
	ControlFreezeEngage ControlAction = "freeze_engage"

	// ControlFreezeRelease is POST /api/v1/freeze/release (ADR-0013).
	ControlFreezeRelease ControlAction = "freeze_release"
)

// ControlAuthorizer decides whether p may perform a ControlAction — the
// administrative half of the authorization question, split out as its own
// interface so a surface that only needs *this* half (the Control API's
// enrollment and revocation routes, which never dispatch) can depend on it
// without holding anything that can reach a Node.
type ControlAuthorizer interface {
	AuthorizeControl(ctx context.Context, p Principal, act ControlAction) error
}

// Authorizer decides whether p may perform act against sel, and — since
// #397 — whether p may perform an administrative ControlAction. v0.0.5 had
// no real authn (the seeded credential arrived in v0.0.6, Accounts in
// v0.3.0 — ADR-0010's staged adoption); this seam exists so surfaces
// (MCP, Control API, Admin Console) plug into the pipeline without it being
// reshaped later.
//
// The two questions live on ONE interface deliberately. They are the same
// question asked about different objects, and the production implementation
// (authz.RoleGate) is one object holding one ladder; splitting them into two
// independently-wired seams is how a deployment ends up with a real gate on
// dispatch and an allow-all gate on enrollment, which is precisely the defect
// #397 records.
type Authorizer interface {
	Authorize(ctx context.Context, p Principal, act jobs.Action, sel Selector) error
	ControlAuthorizer
}

// allowAllAuthorizer is the v0.0.5 default: every request is authorized.
// Real Grant-based authorization is a later v0.0.5/v0.0.6 issue.
//
// New's fail-open guard refuses to build a Service that pairs this with a
// real dispatcher, which is what keeps it out of production for BOTH halves
// of the interface — a Relay whose Freeze anyone may engage is the same class
// of wiring bug as one whose Raw Exec anyone may run.
type allowAllAuthorizer struct{}

func (allowAllAuthorizer) Authorize(context.Context, Principal, jobs.Action, Selector) error {
	return nil
}

func (allowAllAuthorizer) AuthorizeControl(context.Context, Principal, ControlAction) error {
	return nil
}

// CapChecker enforces the blast-radius cap (ADR-0004) before any dispatch.
// The real read-cap/mutate-cap enforcement — including the Raw-Exec-always-
// mutate-cap rule (ADR-0012) — lands in v0.0.5 [5/8]/#100; the pipeline
// already passes the resolved RiskClass and matched-Node count, so this
// signature is final for that issue to implement against.
type CapChecker interface {
	Check(class jobs.RiskClass, matched int) error
}

// noopCapChecker is the v0.0.5 default: no cap is enforced.
type noopCapChecker struct{}

func (noopCapChecker) Check(jobs.RiskClass, int) error {
	return nil
}

// AuditSink records a completed dispatch, a refusal, a Freeze
// engage/release, or a Job cancel. The real adapter to audit.Repository
// (deliberately not imported here; capability stays free of the audit
// package) is internal/auditsink, added in v0.0.5 [7/8]/#102.
type AuditSink interface {
	Record(ctx context.Context, e AuditEntry) error

	// RecordFreeze records a Freeze engage/release event (ADR-0013). #102
	// only adds this sink method; #101 implements Freeze itself and calls it.
	RecordFreeze(ctx context.Context, e FreezeEvent) error

	// RecordCancel records a Job cancel action, attributed to p (v0.0.6
	// [5/8], owner DECISION 2). Cancellation is durably recorded on each
	// affected Task via OutcomeCancelled regardless (ADR-0013) — this adds
	// the principal-attributed audit row so *who* asked for the stop is
	// queryable, mirroring RecordFreeze. Service.CancelJob calls this only
	// after the cancel itself was attempted successfully; see CancelJob's
	// doc comment.
	RecordCancel(ctx context.Context, p Principal, jobID string) error

	// RecordRead records one metadata-only read-access event (#288, ADR-0025;
	// #441 extends it to the trail's own read lane): who read, which tool,
	// what they aimed it at, and when — never the result. tool is a
	// low-cardinality name (readlane.go's constants); selector, nodeID, and
	// jobID are whichever of "what was aimed at" apply, empty otherwise.
	//
	// *auditsink.Sink already implements exactly this signature
	// (auditsink.go), so it joins the AuditSink interface rather than
	// getting its own seam — the same reason Record/RecordFreeze/
	// RecordCancel are one interface (this file's doc comment above): a
	// separately-wired read auditor is how a deployment ends up with audited
	// dispatch and an unaudited trail, and New's real-dispatcher fail-open
	// guard (service.go) then covers the read lane for free, with no new
	// guard to remember.
	RecordRead(ctx context.Context, p Principal, tool, selector, nodeID, jobID string) error
}

// AuditKind distinguishes what kind of Run outcome an AuditEntry describes.
type AuditKind int

const (
	AuditKindDispatch AuditKind = iota
	AuditKindRefusal

	// AuditKindPlan is a no-execution Plan (#119, ADR-0011): Principal,
	// Selector, and Action are set exactly as for AuditKindDispatch, but
	// JobID/Results/Reason are always empty — a Plan creates no Job/Task, so
	// there is nothing to reference by ID and no per-Node NodeResult set,
	// only the transient (unaudited) per-Node Verdicts returned to the
	// caller directly.
	AuditKindPlan

	// AuditKindApprovalRequested is a dispatch parked for a human (ADR-0027):
	// Principal, Selector, and Action are set exactly as for a dispatch, plus
	// ApprovalID and PlanHash, and Reason carries the Relay-authored summary.
	// JobID and Results are empty — nothing ran and no Job exists yet.
	//
	// It is a distinct kind rather than a Refusal because it is not one:
	// nothing was denied. Filing parks under refusals would make the approval
	// mechanism look like breakage on every dashboard that counts them, which
	// is how a safety feature gets switched off.
	AuditKindApprovalRequested

	// AuditKindApprovalGrantRequested is a request for a batch/window Grant
	// (#546, ADR-0027 decision 12) — an ask for STANDING authority over many
	// future dispatches, written by RequestGrant. Distinct from
	// AuditKindApprovalRequested so that kind keeps meaning "one Plan is
	// parked": a Grant and a park have blast radii that are not comparable,
	// and filing them together made the trail say they were the same act.
	// ApprovalID, PlanHash and GrantID are all set on it.
	AuditKindApprovalGrantRequested

	// AuditKindApprovalPendingObserved is a re-drive of a dispatch that is
	// ALREADY parked (#379): checkApproval found an existing pending Request
	// rather than creating one. Fields are set exactly as for
	// AuditKindApprovalRequested — ApprovalID and PlanHash name the request the
	// caller bounced off.
	//
	// It is a distinct kind because re-driving is how a caller polls while
	// waiting, and filing every poll as approval_requested would let the trail
	// inflate until "how many approvals were asked for" needs de-duplication to
	// answer — and would bury a genuine second request among the polls. Kept as
	// a record at all (rather than silently dropped, as the notifier correctly
	// does) because an agent hammering a parked request is something an auditor
	// plausibly wants to see; it just isn't a repeat ask.
	AuditKindApprovalPendingObserved

	// AuditKindApprovalDecided is one recorded answer to a parked dispatch
	// (#270, ADR-0027): Principal is the decider, ApprovalID and PlanHash name
	// what they answered, and Reason states the answer, the resulting request
	// state, the quorum progress, and the decider's own note.
	//
	// Selector, Action, JobID, and Results are all empty. A decision is not a
	// dispatch and does not describe one — it is an act on the approval object,
	// and the Job it eventually releases is joined through ApprovalID rather
	// than by copying the Action into a second place where the two could
	// disagree.
	//
	// Every decision is recorded, not only the one that completes a quorum, so
	// "one approver signed and then it expired" is answerable. A partial
	// approval that leaves no trace is how an audit trail loses the interesting
	// half of the story.
	//
	// ApprovalAnswer and DecisionChannel (#545) are set by DecideApproval on
	// this kind only, and are deliberately empty on the grant-revocation entry
	// RevokeGrant writes — a revocation is not a Decision, so nobody answered
	// a parked Job.
	AuditKindApprovalDecided
)

// ApprovalAnswer is the structured answer a Decision carries (#545). package
// capability may not import internal/audit (TestCapabilityImportsOnlyRegistryAndJobs),
// so this mirrors — rather than shares — audit.ApprovalAnswer*; auditsink,
// the one package that imports capability, audit, AND approval, pins the two
// vocabularies equal.
//
// ApprovalAnswerUnrecorded (the zero value) means "no answer" — a grant
// revocation, or an AuditEntry a future kind writes without one — and NEVER
// "denied". Conflating "no value" with "a value that means no" is the #487
// bug.
type ApprovalAnswer string

const (
	ApprovalAnswerUnrecorded ApprovalAnswer = ""
	ApprovalAnswerApproved   ApprovalAnswer = "approved"
	ApprovalAnswerDenied     ApprovalAnswer = "denied"
)

// AuditEntry is everything the pipeline knows about one Run call, passed to
// AuditSink.Record. Principal is threaded through here so every future real
// AuditSink can attribute the entry without the pipeline itself needing to
// know audit's storage shape.
//
// For AuditKindDispatch, JobID and Results are set and Reason is empty. For
// AuditKindRefusal (authz-deny or cap-reject), Reason is set and JobID/
// Results are empty — the dispatcher was never reached. For AuditKindPlan
// (#119), only Principal/Selector/Action are set — JobID, Results, and
// Reason are all empty, since a Plan never dispatches (no Job/Task exists to
// reference) even when it reports a would-be-rejected cap/Freeze condition.
type AuditEntry struct {
	Kind      AuditKind
	Principal Principal
	Selector  Selector
	Action    jobs.Action
	JobID     string
	Results   []NodeResult
	Reason    string

	// ApprovalID and PlanHash tie a record to the approval callout (ADR-0027).
	// Both are set on AuditKindApprovalRequested; ApprovalID is also set on an
	// AuditKindDispatch that an approval released, so "who approved what
	// actually ran" is one join rather than a correlation by timestamp.
	ApprovalID string
	PlanHash   string

	// GrantID is the batch/window Grant that released this dispatch (ADR-0027
	// decision 12), empty when a single-Plan approval or no gate did. Recorded
	// so a grant's full blast radius — every Job it released, across its whole
	// window — is one query rather than a reconstruction from timestamps.
	GrantID string

	// Asserted is the caller-claimed attribution lane (#300), read off the
	// request context by Service.Run/Plan. Recorded, never consulted — see
	// assertions.go.
	Asserted Assertions

	// ApprovalAnswer and DecisionChannel are the structured counterpart to a
	// KindApprovalDecided entry's prose Reason (#545, ADR-0027 decision 10).
	// Set by DecideApproval, and deliberately EMPTY on the grant-revocation
	// entry RevokeGrant writes — a revocation is not a Decision; nobody
	// answered a parked Job.
	//
	// DecisionChannel is approval.Channel, not a string, so the value cannot
	// be forged into a channel the surface did not stamp.
	ApprovalAnswer  ApprovalAnswer
	DecisionChannel approval.Channel
}

// FreezeEvent is a Freeze engage/release, passed to AuditSink.RecordFreeze
// (ADR-0013). Freeze is Relay-wide, so unlike AuditEntry there is no
// Selector/NodeID to record. Reason is expected to be set on release.
type FreezeEvent struct {
	Principal Principal
	Engage    bool
	Reason    string
	Asserted  Assertions
}

// noopAuditSink is the v0.0.5 default: nothing is recorded.
type noopAuditSink struct{}

func (noopAuditSink) Record(context.Context, AuditEntry) error {
	return nil
}

func (noopAuditSink) RecordFreeze(context.Context, FreezeEvent) error {
	return nil
}

func (noopAuditSink) RecordCancel(context.Context, Principal, string) error {
	return nil
}

func (noopAuditSink) RecordRead(context.Context, Principal, string, string, string, string) error {
	return nil
}

// FreezeStore is the persisted, Relay-wide emergency stop (ADR-0013): "I
// don't trust what's driving this, stop dispatching everything." Service.Run
// consults Frozen before every dispatch (both risk classes); EngageFreeze/
// ReleaseFreeze call Engage/Release. This seam takes only a context, so it is
// allowlist-safe for capability's import-boundary guard
// (TestCapabilityImportsOnlyRegistryAndJobs); the SQLite-backed
// implementation (internal/store, behind internal/freeze.Repository, whose
// method set mirrors this one) is wired in via WithFreeze, kept out of
// package capability for the same import-boundary reason as Conduit/
// AuditSink.
type FreezeStore interface {
	// Frozen reports whether the Freeze is currently engaged.
	Frozen(ctx context.Context) (bool, error)

	// Engage sets the Freeze, recording principal as who engaged it.
	Engage(ctx context.Context, principal string) error

	// Release clears the Freeze, recording principal as who released it and
	// reason as why.
	Release(ctx context.Context, principal, reason string) error
}

// noopFreezeStore is the v0.0.5 default: "never frozen". This is a missing
// stop-button, not a fail-open of authz/cap/audit — but see New's fail-open
// guard (service.go), which requires a real FreezeStore alongside a real
// dispatcher for exactly that reason: an un-stoppable real executor is the
// same class of composition-root wiring bug.
type noopFreezeStore struct{}

func (noopFreezeStore) Frozen(context.Context) (bool, error) {
	return false, nil
}

func (noopFreezeStore) Engage(context.Context, string) error {
	return nil
}

func (noopFreezeStore) Release(context.Context, string, string) error {
	return nil
}

// RefusalKind classifies why Service.Run or Service.Plan short-circuited
// before dispatch, for MetricsSink.IncRefusal. It is a fixed, small enum —
// never the human-readable refusal error text — so /metrics stays free of
// unbounded cardinality.
type RefusalKind int

const (
	RefusalFrozen RefusalKind = iota
	RefusalUnauthorized
	RefusalBlastCap
	RefusalInternal

	// RefusalPendingApproval counts dispatches parked for a human (ADR-0027).
	// It rides the refusal counter because it is a "did not dispatch" outcome
	// and belongs on the same dashboard, but it is NOT a refusal: nothing was
	// denied. Kept a distinct value precisely so an operator can tell "the
	// gate is working" apart from "the fleet is rejecting work".
	RefusalPendingApproval
)

// MetricsSink records best-effort observability counters for the capability
// pipeline: a dispatch outcome per Node, or a refusal kind. Mirrors AuditSink's
// seam doc: this must never affect a dispatch decision — it is purely
// observational. The real adapter (internal/metrics) is wired in via
// WithMetrics; this seam only imports jobs, staying within capability's
// import allowlist (execution_test.go guard).
type MetricsSink interface {
	IncDispatch(outcome jobs.Outcome)
	IncRefusal(kind RefusalKind)
}

// noopMetricsSink is the default: nothing is recorded.
type noopMetricsSink struct{}

func (noopMetricsSink) IncDispatch(jobs.Outcome) {}

func (noopMetricsSink) IncRefusal(RefusalKind) {}

// JobTransition is one Job-grained lifecycle fact the event seam (#416)
// publishes for the Admin Console's live view.
type JobTransition int

const (
	JobCreated JobTransition = iota
	JobCompleted
	JobCancelled
)

// JobEvent is one Job-grained transition, published through JobEventSink.
// Purely observational, exactly like MetricsSink's doc above: it must never
// affect a dispatch decision, and nothing here can — it is built and
// published AFTER the decision it describes was already made.
//
// Outcomes carries per-outcome COUNTS — never []NodeResult. This is
// deliberate and is the second place (alongside internal/events itself)
// the no-read-output property is made structural: NodeResult carries
// Stdout/Stderr (dispatch.go), and the audit path already proves how easily
// output rides along on a "Job-grained" record (AuditEntry.Results,
// auditsink copies Stdout/Stderr verbatim). Counts are the Job-grained
// fact; the internal/eventsink adapter that maps this onto the bus (#416)
// never holds output at all.
type JobEvent struct {
	Transition JobTransition
	JobID      string
	Principal  Principal
	Selector   Selector
	Action     jobs.Action
	Nodes      int
	Outcomes   map[jobs.Outcome]int
}

// JobEventSink records a Job-grained transition. Mirrors MetricsSink's
// shape exactly (no ctx, no error) so it stays inside capability's narrow
// import allowlist (execution_test.go's TestCapabilityImportsOnlyRegistryAndJobs).
type JobEventSink interface {
	RecordJob(e JobEvent)
}

// noopJobEventSink is the default: nothing is recorded.
type noopJobEventSink struct{}

func (noopJobEventSink) RecordJob(JobEvent) {}

// FrozenError is returned by Service.Run when the Relay-wide Freeze is
// engaged: dispatch is refused before any Task is sent. It is exported and
// typed so a surface can recognize a Freeze refusal via errors.As without
// string-matching (mirrors CapExceededError, caps.go).
type FrozenError struct{}

func (*FrozenError) Error() string {
	return "capability: dispatch refused: the Relay-wide Freeze is engaged (ADR-0013); no new Tasks dispatch " +
		"until an admin releases the Freeze. Use plan mode to preview verdicts while frozen."
}
