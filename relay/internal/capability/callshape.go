// Call-shape refusals: a call that cannot be asked of any Node. They need no
// Node, so this layer decides them from the Action alone and acts on them after
// authorization (invariant 10; EX-64, EX-67). They check names and presence
// only, never argument values, which are the daemon's (invariant 12).
package capability

import (
	"github.com/Felag-Engineering/relay/relay/internal/jobs"
	"github.com/Felag-Engineering/relay/relay/internal/opvocab"
)

const (
	// rawExecCallName is the GLOSSARY term, so both surfaces render the same
	// bytes whichever route or tool carried the call.
	rawExecCallName = "Raw Exec"
	emptyArgvReason = "argv is empty: Raw Exec needs a non-empty argv, which it runs verbatim and never through a shell (ADR-0001)"
)

// checkCallShape returns the refusal for a call whose shape is wrong, or a nil
// error. The kind means something only when the error is non-nil.
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
	return 0, nil
}
