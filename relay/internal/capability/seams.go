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

// AuditSink records a completed dispatch, a refusal, or a Freeze
// engage/release. The real adapter to audit.Repository (deliberately not
// imported here; capability stays free of the audit package) is
// internal/auditsink, added in v0.0.5 [7/8]/#102.
type AuditSink interface {
	Record(ctx context.Context, e AuditEntry) error

	// RecordFreeze records a Freeze engage/release event (ADR-0013). #102
	// only adds this sink method; #101 implements Freeze itself and calls it.
	RecordFreeze(ctx context.Context, e FreezeEvent) error
}

// AuditKind distinguishes what kind of Run outcome an AuditEntry describes.
type AuditKind int

const (
	AuditKindDispatch AuditKind = iota
	AuditKindRefusal
)

// AuditEntry is everything the pipeline knows about one Run call, passed to
// AuditSink.Record. Principal is threaded through here so every future real
// AuditSink can attribute the entry without the pipeline itself needing to
// know audit's storage shape.
//
// For AuditKindDispatch, JobID and Results are set and Reason is empty. For
// AuditKindRefusal (authz-deny or cap-reject), Reason is set and JobID/
// Results are empty — the dispatcher was never reached.
type AuditEntry struct {
	Kind      AuditKind
	Principal Principal
	Selector  Selector
	Action    jobs.Action
	JobID     string
	Results   []NodeResult
	Reason    string
}

// FreezeEvent is a Freeze engage/release, passed to AuditSink.RecordFreeze
// (ADR-0013). Freeze is Relay-wide, so unlike AuditEntry there is no
// Selector/NodeID to record. Reason is expected to be set on release.
type FreezeEvent struct {
	Principal Principal
	Engage    bool
	Reason    string
}

// noopAuditSink is the v0.0.5 default: nothing is recorded.
type noopAuditSink struct{}

func (noopAuditSink) Record(context.Context, AuditEntry) error {
	return nil
}

func (noopAuditSink) RecordFreeze(context.Context, FreezeEvent) error {
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

// FrozenError is returned by Service.Run when the Relay-wide Freeze is
// engaged: dispatch is refused before any Task is sent. It is exported and
// typed so a surface can recognize a Freeze refusal via errors.As without
// string-matching (mirrors CapExceededError, caps.go).
type FrozenError struct{}

func (*FrozenError) Error() string {
	return "capability: dispatch refused: the Relay-wide Freeze is engaged (ADR-0013)"
}
