// The risk class of a Native Operation or a Raw Exec Action (ADR-0012,
// ADR-0042, invariant 13): decided here and nowhere else. template.go does
// the same for a Template Operation, whose class is Node-reported.
//
// No caller can set or loosen a class, so an Action that arrives carrying one
// is refused (ClassPresetError) rather than trusted, even when the value is
// the right one: a surface that writes the field at all is a surface that can
// write it wrong.
package capability

import (
	"fmt"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/jobs"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/opvocab"
)

// fixedRiskClass is the class of a Native Operation (from opvocab, by name) or
// a Raw Exec Action (always mutate, whatever the argv). It fails closed: a
// descriptor whose class is unspecified or out of range, an unknown Native
// name, and an Action of unspecified Kind are all mutate, never the looser
// class — the same reading reportedClass gives a Node's report.
func fixedRiskClass(act jobs.Action) jobs.RiskClass {
	if act.Kind == jobs.ActionOperation {
		if d, ok := opvocab.Lookup(act.OperationName); ok && d.Risk == jobs.RiskClassRead {
			return jobs.RiskClassRead
		}
	}
	return jobs.RiskClassMutate
}

// ClassPresetError is the refusal for a Native Operation or Raw Exec Action
// that reached the capability layer already carrying a risk class. Only this
// layer decides an Action's class (ADR-0012, invariant 13); an adapter that
// set one has a bug, and the dispatch fails closed rather than trusting it.
type ClassPresetError struct {
	Kind      jobs.ActionKind
	Operation string
	Class     jobs.RiskClass
}

func (e *ClassPresetError) Error() string {
	what := "Raw Exec"
	if e.Kind == jobs.ActionOperation {
		what = fmt.Sprintf("Native Operation %q", e.Operation)
	}
	return fmt.Sprintf("capability: refusing %s: it arrived with risk class %q already set, "+
		"but only the capability layer decides an Action's class (ADR-0012, invariant 13)",
		what, jobs.RiskClassName(e.Class))
}
