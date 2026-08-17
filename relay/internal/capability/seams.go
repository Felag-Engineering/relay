package capability

import (
	"context"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/jobs"
)

// Authorizer decides whether p may perform act against sel. v0.0.5 has no
// real authn yet (the seeded credential arrives in v0.0.6, Accounts in
// v0.3.0 — ADR-0010's staged adoption); this seam exists now so surfaces
// (MCP, Control API, Admin Console) plug into the pipeline without it being
// reshaped later.
type Authorizer interface {
	Authorize(ctx context.Context, p Principal, act jobs.Action, sel Selector) error
}

// allowAllAuthorizer is the v0.0.5 default: every request is authorized.
// Real Grant-based authorization is a later v0.0.5/v0.0.6 issue.
type allowAllAuthorizer struct{}

func (allowAllAuthorizer) Authorize(context.Context, Principal, jobs.Action, Selector) error {
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
	AuditKindApprovalDecided
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

// FrozenError is returned by Service.Run when the Relay-wide Freeze is
// engaged: dispatch is refused before any Task is sent. It is exported and
// typed so a surface can recognize a Freeze refusal via errors.As without
// string-matching (mirrors CapExceededError, caps.go).
type FrozenError struct{}

func (*FrozenError) Error() string {
	return "capability: dispatch refused: the Relay-wide Freeze is engaged (ADR-0013); no new Tasks dispatch " +
		"until an admin releases the Freeze. Use plan mode to preview verdicts while frozen."
}
