package capability

import (
	"fmt"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/jobs"
)

// DefaultReadCap and DefaultMutateCap are the blast-radius caps used when the
// Relay's startup config supplies a non-positive value (see NewBlastCap). The
// read-cap is generous; the mutate-cap — which Raw Exec always takes
// (ADR-0012) — is small, matching the ROADMAP v0.0.5 deliverable.
const (
	DefaultReadCap   = 10000
	DefaultMutateCap = 100
)

// CapExceededError is returned by BlastCap.Check when a Selector resolves to
// more Nodes than the applicable cap. It is exported and typed so a later
// audit layer (#102) can recognize a cap rejection via errors.As without
// string-matching.
type CapExceededError struct {
	Class   jobs.RiskClass
	Matched int
	Cap     int
}

func (e *CapExceededError) Error() string {
	return fmt.Sprintf(
		"capability: blast-radius cap exceeded: selector matched %d nodes, exceeds the %s of %d (risk class %s)",
		e.Matched, capName(e.Class), e.Cap, className(e.Class),
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

// className renders class for the error message, mirroring
// store/tasks.go's riskClassToString. Kept local rather than promoted to a
// jobs.RiskClass.String() method to stay in scope for this issue.
func className(class jobs.RiskClass) string {
	switch class {
	case jobs.RiskClassRead:
		return "read"
	case jobs.RiskClassMutate:
		return "mutate"
	default:
		return "unspecified"
	}
}

// BlastCap is the real CapChecker (ADR-0004): it enforces two file-configured
// blast-radius caps chosen by the Action's declared RiskClass. Construct it
// with NewBlastCap; readCap and mutateCap are unexported so the caps can only
// change via reconstruction (Relay startup), never at runtime.
type BlastCap struct {
	readCap   int
	mutateCap int
}

// NewBlastCap returns a BlastCap enforcing readCap for RiskClassRead and
// mutateCap for RiskClassMutate/RiskClassUnspecified. A guardrail must fail
// closed: any non-positive input is clamped to the package default for that
// lane rather than being treated as "unlimited".
func NewBlastCap(readCap, mutateCap int) *BlastCap {
	if readCap <= 0 {
		readCap = DefaultReadCap
	}
	if mutateCap <= 0 {
		mutateCap = DefaultMutateCap
	}
	return &BlastCap{readCap: readCap, mutateCap: mutateCap}
}

// Check implements CapChecker. RiskClassRead uses the read-cap; both
// RiskClassMutate and RiskClassUnspecified use the mutate-cap — mapping
// Unspecified to the strict lane is the fail-closed default that guarantees
// Raw Exec (and any future miswired Action) lands in the mutate-cap rather
// than the generous one. The cap is an inclusive maximum: matched == cap is
// allowed.
func (b *BlastCap) Check(class jobs.RiskClass, matched int) error {
	limit := b.mutateCap
	if class == jobs.RiskClassRead {
		limit = b.readCap
	}
	if matched > limit {
		return &CapExceededError{Class: class, Matched: matched, Cap: limit}
	}
	return nil
}
