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
	"sort"
	"strings"

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

// denyExplanation renders what the Console can honestly say about WHY an
// audited Task was denied. The Task lane calls denyText below directly.
func denyExplanation(rec audit.Record) string {
	return denyText(rec.Stderr, rec.Reason, riskOf(rec) == jobs.RiskClassRead)
}

// denyText is the one explanation both lanes share — the audit trail's
// records (denyExplanation above) and the Task query lane's rows (job.go).
//
// The four answers are genuinely different and must not collapse:
//
//   - The daemon's verdict, verbatim, when it was retained.
//   - The recorded reason, when the trail has one and no verdict text. The
//     Task lane never has one (jobs.TaskSummary carries no Reason field), so
//     there the rule comes from the daemon's stderr or from nothing.
//   - "Not recorded in the trail" for a READ-class Task. The audit trail never
//     retains read output (ADR-0025) and the daemon's explanation arrives in
//     that output — so the rule is absent from the trail by design, not missing
//     by accident. Saying "the daemon did not report the deciding rule" here
//     blames the daemon for the Relay correctly declining to record something.
//     Note the scope: the TRAIL never kept it. The Task row may still hold it
//     until the Job is collected, which is why this sentence names the trail
//     rather than claiming the bytes do not exist anywhere.
//   - "The daemon did not report it" for a mutate-class Task, which is the only
//     case where that sentence is true.
//
// It exists as its own function because a second call site re-spelling the
// last two answers is how the same refusal comes to be explained two
// different ways on two screens.
func denyText(stderr []byte, reason string, readClass bool) string {
	if r := trimmed(stderr); r != "" {
		return r
	}
	if reason != "" {
		return reason
	}
	if readClass {
		return "The deciding rule is not recorded in the trail for a read-class Task.\n\n" +
			"The daemon explains a refusal in the Task's output, and the audit trail never\n" +
			"retains read output — reading is exfiltration, so what left the Node is audited\n" +
			"and what it said is not (ADR-0025). Query this Node's effective Policy to see\n" +
			"the rule."
	}
	return "The daemon refused this Operation and did not report the deciding rule."
}

// argsSummary renders what was asked for: Raw Exec's argv, or an Operation's
// arguments in a stable key order.
//
// Sorted, never map order: two renders of the same dispatch that disagree
// about the order of `unit=nginx path=/etc` read as two different dispatches.
func argsSummary(args map[string]string, argv []string) string {
	if len(argv) > 0 {
		return strings.Join(argv, " ")
	}
	if len(args) == 0 {
		return ""
	}
	keys := make([]string, 0, len(args))
	for k := range args {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, k+"="+args[k])
	}
	return strings.Join(parts, " ")
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
