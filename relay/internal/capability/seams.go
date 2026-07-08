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

// AuditSink records a completed dispatch. Real audit writes — an adapter to
// audit.Repository (deliberately not imported here; capability stays free
// of the audit package until that adapter exists) — land in v0.0.5 [7/8]/#102.
type AuditSink interface {
	Record(ctx context.Context, e AuditEntry) error
}

// AuditEntry is everything the pipeline knows about one Run call, passed to
// AuditSink.Record. Principal is threaded through here so every future real
// AuditSink can attribute the entry without the pipeline itself needing to
// know audit's storage shape.
type AuditEntry struct {
	Principal Principal
	Selector  Selector
	Action    jobs.Action
	Results   []NodeResult
}

// noopAuditSink is the v0.0.5 default: nothing is recorded.
type noopAuditSink struct{}

func (noopAuditSink) Record(context.Context, AuditEntry) error {
	return nil
}
