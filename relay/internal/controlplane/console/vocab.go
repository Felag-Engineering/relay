package console

// vocab.go is the ONE place this package infers an Operation's risk class from
// an audit record, and the one place it names the read half of the catalog.
//
// # Why an inference is needed at all
//
// Every Operation declares a risk class (ADR-0012, invariant 13) and the class
// chooses the blast cap — but audit.Record does not carry it. It carries the
// Operation NAME, the ActionKind, and the kind of record. So a screen that wants
// to say "this was a read" has to work it out, and the first build of the agent
// stream worked it out wrongly in both directions at once: `file.read` rendered
// as `mutate`, and a parked `raw_exec` rendered as `read`.
//
// Both errors are worse than they look. The risk chip is how an operator reads
// the blast radius of what an agent just did, and a Raw Exec — which ALWAYS
// takes the mutate cap, without exception (ADR-0012) — displayed as a read is
// the single most misleading thing this Console could say.
//
// # Why the fix is here and not at each call site
//
// Three screens ask this question. Three answers is three chances to drift, and
// the drift would be invisible: each screen would look right in isolation. So
// the inference lives in one function with its limits written down, and the real
// fix — putting the declared class on the audit record — replaces this file
// rather than hunting for the places that guessed.

import (
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/audit"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/jobs"
)

// readOperations is the read-class half of the shipped catalog (ADR-0021's
// vocabulary).
//
// Named explicitly rather than inferred from a prefix: `service.status` reads
// and `service.restart` mutates, and a prefix rule would get that exactly
// backwards for the most consequential pair in the vocabulary.
//
// A customer's Template Operation is not in this list and is therefore treated
// as a mutate. That is the safe direction for the risk chip — it over-states
// blast radius rather than under-stating it — and the wrong direction for the
// read-egress screen, which under-counts exposure as a result. Both are stated
// on the screens themselves rather than left to be discovered.
var readOperations = map[string]bool{
	"system.facts":   true,
	"file.read":      true,
	"file.stat":      true,
	"log.tail":       true,
	"disk.usage":     true,
	"proc.list":      true,
	"net.listening":  true,
	"service.status": true,
	"pkg.query":      true,
}

func isReadOperation(name string) bool { return readOperations[name] }

// riskOf infers the risk class an audit record describes.
//
// The order of the cases is the whole function. Raw Exec is checked FIRST and
// unconditionally: it always takes the mutate cap regardless of what it runs
// (ADR-0012), so no later case may soften it.
func riskOf(rec audit.Record) jobs.RiskClass {
	// Raw Exec, however it is recorded — as argv on a dispatch, or as an
	// ActionKind on a park where no argv survived.
	if len(rec.RawExecArgv) > 0 || rec.ActionKind == rawExecActionKind {
		return jobs.RiskClassMutate
	}
	// The non-dispatching read tools (list_nodes, describe_node,
	// list_operations, get_job) are recorded as their own kind.
	if rec.Kind == audit.KindRead {
		return jobs.RiskClassRead
	}
	if isReadOperation(rec.OperationName) {
		return jobs.RiskClassRead
	}
	// An unknown Operation is treated as a mutate. Over-stating blast radius is
	// the safe direction for a chip an operator reads before deciding whether
	// to worry.
	return jobs.RiskClassMutate
}

// rawExecActionKind is how the audit trail spells Raw Exec in ActionKind.
const rawExecActionKind = "raw_exec"

// denyExplanation renders what the Console can honestly say about WHY a Task
// was denied.
//
// The three answers are genuinely different and must not collapse:
//
//   - The daemon's verdict, verbatim, when the trail retained it.
//   - "Not retained" for a READ-class Task. Read output is never kept
//     (ADR-0025), and the daemon's explanation arrives in that output — so the
//     rule is gone by design, not missing by accident. Saying "the daemon did
//     not report the deciding rule" here blames the daemon for the Relay
//     correctly declining to store something.
//   - "The daemon did not report it" for a mutate-class Task, which is the only
//     case where that sentence is true.
func denyExplanation(rec audit.Record) string {
	if r := trimmed(rec.Stderr); r != "" {
		return r
	}
	if rec.Reason != "" {
		return rec.Reason
	}
	if riskOf(rec) == jobs.RiskClassRead {
		return "The deciding rule is not recorded for a read-class Task.\n\n" +
			"The daemon explains a refusal in the Task's output, and read output is never\n" +
			"retained — reading is exfiltration, so what left the Node is audited and what it\n" +
			"said is not kept. Query this Node's effective Policy to see the rule."
	}
	return "The daemon refused this Operation and did not report the deciding rule."
}

func trimmed(b []byte) string {
	s := string(b)
	for len(s) > 0 && (s[len(s)-1] == '\n' || s[len(s)-1] == '\r' || s[len(s)-1] == ' ' || s[len(s)-1] == '\t') {
		s = s[:len(s)-1]
	}
	for len(s) > 0 && (s[0] == '\n' || s[0] == '\r' || s[0] == ' ' || s[0] == '\t') {
		s = s[1:]
	}
	return s
}
