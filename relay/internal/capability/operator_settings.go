package capability

import "time"

// OperatorSettings is the reach-bounding operator settings the capability layer
// reads on every request: how much a dispatch may touch and how fast Nodes may
// enroll. They are file-configured today (RC-21) and store-backed later
// (RC-29); no request can set them (invariant 11).
type OperatorSettings struct {
	// ReadBlastCap and MutateBlastCap are the blast-radius caps by risk class
	// (ADR-0004). A non-positive value is clamped to the package default by
	// BlastCap, never read as unlimited.
	ReadBlastCap   int
	MutateBlastCap int

	// DispatchConcurrency bounds in-flight Tasks of one Job; at least 1.
	DispatchConcurrency int

	// MinDaemonVersion is the dispatch-level minimum daemon version
	// (invariant 14). Empty means the gate is off.
	MinDaemonVersion string

	// CertExpiringWithin is the state:cert-expiring warning window (ADR-0034).
	// It is a Duration rather than the configured fraction because this
	// package may not import internal/ca, where the leaf validity lives.
	CertExpiringWithin time.Duration

	// The enrollment rate limits, enforced by the node plane's limiter.
	EnrollIPRatePerMinute     int
	EnrollIPBurst             int
	EnrollGlobalRatePerMinute int
	EnrollGlobalBurst         int
	EnrollMaxTrackedIPs       int

	// MaxNodes is the Node cap enforced inside the registry's Upsert
	// transaction. Zero means no cap.
	MaxNodes int
}

// OperatorSettingsSource supplies the current OperatorSettings. It is the
// settings seam: the composition root backs it with the live configuration
// snapshot (RC-21) and RC-29 will back it with the store. No adapter holds
// one (invariants 10 and 11).
//
// OperatorSettings must be safe for concurrent use and cheap: it is called
// per request.
//
// Implementations must be pointer types (or otherwise comparable):
// NewExecution compares sources by identity to refuse a split layer, and a
// non-comparable dynamic type would panic with a runtime comparison error
// instead of the intended message.
type OperatorSettingsSource interface {
	OperatorSettings() OperatorSettings
}

// StaticOperatorSettings is the fixed source for callers that never reload.
// Use it by pointer: two equal-valued statics are still two sources.
type StaticOperatorSettings struct{ S OperatorSettings }

// OperatorSettings implements OperatorSettingsSource.
func (s *StaticOperatorSettings) OperatorSettings() OperatorSettings { return s.S }
