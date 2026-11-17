// Call-shape refusals: a call that cannot be asked of any Node. They need no
// Node, so this layer decides them from the Action alone and acts on them after
// authorization (invariant 10; EX-59, EX-64, EX-67). They check names, presence and
// one number only, never argument values, which are the daemon's (invariant 12).
package capability

import (
	"fmt"

	"github.com/Felag-Engineering/relay/relay/internal/jobs"
	"github.com/Felag-Engineering/relay/relay/internal/opvocab"
)

const (
	// rawExecCallName is the GLOSSARY term, so both surfaces render the same
	// bytes whichever route or tool carried the call.
	rawExecCallName = "Raw Exec"
	emptyArgvReason = "argv is empty: Raw Exec needs a non-empty argv, which it runs verbatim and never through a shell (ADR-0001)"
)

// MaxTaskTimeoutSeconds is the ceiling on a Task's timeout_seconds (EX-59). It
// equals the daemon's own cap (EX-24), so no Task carries a timeout the daemon
// would shorten. A constant, never a setting (invariant 11); a value above it
// is refused, never clamped. It shares 300 with controlplane.MaxWaitSeconds by
// coincidence: a separate claim.
const MaxTaskTimeoutSeconds = 300

// TimeoutError is the refusal for a call whose timeout_seconds is below 0 or
// above MaxTaskTimeoutSeconds (EX-59). Malformed, never a Policy verdict: it is
// decided from the Action alone and refused before any Node is asked.
type TimeoutError struct{ Asked int32 }

func (e *TimeoutError) Error() string {
	return fmt.Sprintf("timeout_seconds %d is refused: a Task timeout must be from 0 to %d seconds "+
		"(%d is the ceiling, and 0 takes the daemon default of 30); the Relay never clamps it. "+
		"Nothing was dispatched.", e.Asked, MaxTaskTimeoutSeconds, MaxTaskTimeoutSeconds)
}

// checkCallShape returns the refusal for a call whose shape is wrong, or a nil
// error. The timeout ceiling is the last check, for every kind. The kind means
// something only when the error is non-nil.
func checkCallShape(act jobs.Action) (RefusalKind, error) {
	switch act.Kind {
	case jobs.ActionOperation:
		// Native only: a Template's names are checked in template.go over its slots.
		if d, ok := opvocab.Lookup(act.OperationName); ok {
			if err := opvocab.ValidateArgNames(d, act.OperationArgs); err != nil {
				return RefusalMalformed, &MalformedCallError{Operation: act.OperationName, Reason: err.Error()}
			}
		}
	case jobs.ActionRawExec:
		if len(act.RawExecArgv) == 0 { // nil and empty alike
			return RefusalMalformed, &MalformedCallError{Operation: rawExecCallName, Reason: emptyArgvReason}
		}
	}
	if act.TimeoutSeconds < 0 || act.TimeoutSeconds > MaxTaskTimeoutSeconds {
		return RefusalMalformed, &TimeoutError{Asked: act.TimeoutSeconds}
	}
	return 0, nil
}
