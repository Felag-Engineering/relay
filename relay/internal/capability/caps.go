package capability

import (
	"fmt"

	"github.com/Felag-Engineering/relay/relay/internal/jobs"
)

// DefaultReadCap and DefaultMutateCap are the blast-radius caps used when the
// Relay's settings supply a non-positive value (see NewBlastCap). The
// read-cap is generous; the mutate-cap — which Raw Exec always takes
// (ADR-0012) — is small, matching the v0.0.5 deliverable.
const (
	DefaultReadCap   = 10000
	DefaultMutateCap = 100
)

// CapExceededError is returned by BlastCap.Check when a Selector resolves to
// more Nodes than the applicable cap. It is exported and typed so a later
// audit layer can recognize a cap rejection via errors.As without
// string-matching.
type CapExceededError struct {
	Class   jobs.RiskClass
	Matched int
	Cap     int
}

func (e *CapExceededError) Error() string {
	return fmt.Sprintf(
		"capability: blast-radius cap exceeded: selector matched %d nodes, exceeds the %s of %d (risk class %s); "+
			"narrow the Selector to at most %d Nodes (or split the Job into batches)",
		e.Matched, capName(e.Class), e.Cap, jobs.RiskClassName(e.Class), e.Cap,
	)
}

// capName names the cap for the error message: "read-cap" for RiskClassRead,
// "mutate-cap" for everything else (RiskClassMutate and RiskClassUnspecified
// both take the mutate-cap — see BlastCap.Check).
func capName(class jobs.RiskClass) string {
	if class == jobs.RiskClassRead {
		return "read-cap"
	}
	return "mutate-cap"
}

// BlastCap is the real CapChecker (ADR-0004): it enforces two blast-radius
// caps chosen by the Action's declared RiskClass, read from its
// OperatorSettingsSource on every Check. The caps change only through that
// source, which no request reaches (invariant 11).
type BlastCap struct {
	settings OperatorSettingsSource
}

// NewBlastCap returns a BlastCap reading its caps from settings. A guardrail
// must fail closed: any non-positive cap the source reports is clamped to the
// package default for that lane rather than being treated as "unlimited". A
// nil source is a composition-root bug and panics.
func NewBlastCap(settings OperatorSettingsSource) *BlastCap {
	if settings == nil {
		panic("capability: NewBlastCap: settings must not be nil")
	}
	return &BlastCap{settings: settings}
}

// Check implements CapChecker. RiskClassRead uses the read-cap; both
// RiskClassMutate and RiskClassUnspecified use the mutate-cap — mapping
// Unspecified to the strict lane is the fail-closed default that guarantees
// Raw Exec (and any future miswired Action) lands in the mutate-cap rather
// than the generous one. The cap is an inclusive maximum: matched == cap is
// allowed.
func (b *BlastCap) Check(class jobs.RiskClass, matched int) error {
	cfg := b.settings.OperatorSettings()
	limit := cfg.MutateBlastCap
	if limit <= 0 {
		limit = DefaultMutateCap
	}
	if class == jobs.RiskClassRead {
		limit = cfg.ReadBlastCap
		if limit <= 0 {
			limit = DefaultReadCap
		}
	}
	if matched > limit {
		return &CapExceededError{Class: class, Matched: matched, Cap: limit}
	}
	return nil
}
