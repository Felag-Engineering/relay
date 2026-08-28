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
	"time"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/audit"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/capability"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/jobs"
)

// trailFacts is ONE recorded event, in the fields the Console's display copy
// reads.
//
// It exists because the trail now reaches this package as TWO types:
// audit.Record, for the screens that still read the whole trail through
// AuditReader (agent history, read egress, node detail — #424/#425), and
// capability.AuditRow, for the ones that have migrated to the read lane. The
// copy functions below — what an Operation is called, what it was asked to
// do, who asked — must not fork along that seam. A second spelling of
// "enumerated list_nodes" is exactly how two screens come to name one audit
// record two different ways, which is the drift readTargetOf was extracted to
// end in the first place.
//
// It carries NO Stdout, Stderr or Truncated field, at any age (ADR-0025).
// That is why denyExplanation and riskOf below still take an audit.Record:
// both read rec.Stderr, which is precisely what this type must not have.
type trailFacts struct {
	Kind      string
	Principal string

	VerifiedAccountName string
	VerifiedAccountID   string
	OnBehalfOf          string

	Selector      string
	JobID         string
	NodeID        string
	ActionKind    string
	OperationName string
	Reason        string
	ApprovalID    string
	GrantID       string

	Args        map[string]string
	RawExecArgv []string

	Outcome   jobs.Outcome
	Timestamp time.Time
}

// factsOfRecord projects a whole-trail audit.Record onto the shared facts.
func factsOfRecord(rec audit.Record) trailFacts {
	return trailFacts{
		Kind:                rec.Kind,
		Principal:           rec.Principal,
		VerifiedAccountName: rec.Attribution.Verified.AccountName,
		VerifiedAccountID:   rec.Attribution.Verified.AccountID,
		OnBehalfOf:          rec.Attribution.Asserted.OnBehalfOf,
		Selector:            rec.Selector,
		JobID:               rec.JobID,
		NodeID:              rec.NodeID,
		ActionKind:          rec.ActionKind,
		OperationName:       rec.OperationName,
		Reason:              rec.Reason,
		ApprovalID:          rec.ApprovalID,
		GrantID:             rec.GrantID,
		Args:                rec.Args,
		RawExecArgv:         rec.RawExecArgv,
		Outcome:             rec.Outcome,
		Timestamp:           rec.Timestamp,
	}
}

// factsOfRow projects a read-lane capability.AuditRow onto the shared facts.
func factsOfRow(row capability.AuditRow) trailFacts {
	return trailFacts{
		Kind:                row.Kind,
		Principal:           row.Principal,
		VerifiedAccountName: row.Verified.AccountName,
		VerifiedAccountID:   row.Verified.AccountID,
		OnBehalfOf:          row.Asserted.OnBehalfOf,
		Selector:            row.Selector,
		JobID:               row.JobID,
		NodeID:              row.NodeID,
		ActionKind:          row.ActionKind,
		OperationName:       row.OperationName,
		Reason:              row.Reason,
		ApprovalID:          row.ApprovalID,
		GrantID:             row.GrantID,
		Args:                row.Args,
		RawExecArgv:         row.RawExecArgv,
		Outcome:             row.Outcome,
		Timestamp:           row.Timestamp,
	}
}

// operationText names what ran: the Operation, or Raw Exec, or the bare
// ActionKind for a record that is neither.
func operationText(f trailFacts) string {
	if f.OperationName != "" {
		return f.OperationName
	}
	if len(f.RawExecArgv) > 0 {
		return "raw_exec"
	}
	return f.ActionKind
}

// argsText renders what was asked for.
func argsText(f trailFacts) string { return argsSummary(f.Args, f.RawExecArgv) }

// principalText prefers the verified Account name.
//
// Record.Principal is the "name:role" string kept because it is what an
// operator reads at a glance, but the structured Attribution is authoritative
// — see audit's own doc. Reading the structured lane first is what keeps the
// trust chip honest: a name that came from the verified lane is filled, and
// one that did not is dashed.
func principalText(f trailFacts) string {
	if f.VerifiedAccountName != "" {
		return f.VerifiedAccountName
	}
	if f.Principal != "" {
		return f.Principal
	}
	return "unattributed"
}

// readTargetOf names WHAT was read, in the terms an operator would search for.
//
// The naming itself lives in reads.go's readTargetName, which iterates
// audit.TargetArgKeys so that this package and the store's reach aggregate
// agree on what counts as one target — see that function for the precedence
// order and the one residual divergence. This wrapper exists so that both
// families of record reach that core through the same projection.
func readTargetOf(f trailFacts) string {
	return readTargetName(f.OperationName, f.ActionKind, f.Args)
}

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

// riskOf infers the risk class a recorded event describes.
//
// The order of the cases is the whole function. Raw Exec is checked FIRST and
// unconditionally: it always takes the mutate cap regardless of what it runs
// (ADR-0012), so no later case may soften it.
//
// It takes trailFacts rather than an audit.Record because both lanes need it
// and neither may get its own answer — see the type's doc comment. Where the
// DECLARED class is available (the Job lane's tasks.risk_class), that is used
// instead and this function is not called at all: an inference is what a
// screen falls back to, never what it prefers.
func riskOf(f trailFacts) jobs.RiskClass {
	// Raw Exec, however it is recorded — as argv on a dispatch, or as an
	// ActionKind on a park where no argv survived.
	if len(f.RawExecArgv) > 0 || f.ActionKind == rawExecActionKind {
		return jobs.RiskClassMutate
	}
	// The non-dispatching read tools (list_nodes, describe_node,
	// list_operations, get_job) are recorded as their own kind.
	if f.Kind == audit.KindRead {
		return jobs.RiskClassRead
	}
	if isReadOperation(f.OperationName) {
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
	return denyText(rec.Stderr, rec.Reason, riskOf(factsOfRecord(rec)) == jobs.RiskClassRead)
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
