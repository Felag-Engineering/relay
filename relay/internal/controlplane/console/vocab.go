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
// Three screens ask this question: the Activity trail lane, agent history, and
// node detail's deny explanation. (Job detail and read egress used to be
// callers too, but #490/#497 moved both onto the DECLARED class carried by
// capability.TaskRow/JobFilter, so they no longer infer anything and are not
// listed here.) Three answers is three chances to drift, and the drift would
// be invisible: each screen would look right in isolation. So the inference
// lives in one function with its limits written down, and the real fix —
// putting the declared class on the audit record — replaces this file rather
// than hunting for the places that guessed.

import (
	"sort"
	"strings"
	"time"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/audit"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/capability"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/jobs"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/opvocab"
)

// trailFacts is ONE recorded event, in the fields the Console's display copy
// reads.
//
// It exists because the trail reaches this package as TWO types: audit.Record,
// for what has not migrated onto the read lane — after #542, that is node
// detail's Recent Tasks panel and its node_revoke lookup, and nothing else —
// and capability.AuditRow, for every screen that has (Activity, read egress,
// agent history). The copy functions below — what an Operation is called,
// what it was asked to do, who asked — must not fork along that seam. A
// second spelling of "enumerated list_nodes" is exactly how two screens come
// to name one audit record two different ways, which is the drift
// readTargetOf was extracted to end in the first place.
//
// It carries NO Stdout, Stderr or Truncated field, at any age (ADR-0025).
// That is why denyExplanation below still takes an audit.Record: it reads
// rec.Stderr, which is precisely what this type must not have, and node
// detail's Recent Tasks is the one caller left. Agent history's own deny
// prose reads off trailFacts alone (denyRuleOffLane, below) for exactly that
// reason — capability.AuditRow has no Stderr to read, and riskOf works from
// trailFacts already because both lanes need it.
type trailFacts struct {
	Kind      string
	Principal string

	VerifiedAccountName string
	VerifiedAccountID   string
	// Role is the authority the Account held AT THAT MOMENT, VERIFIED lane
	// only (CONTEXT.md's Attribution). Empty means the Relay authenticated no
	// role for this record, and nothing may substitute one — see agents.go's
	// buildAgents for why the asserted lane's "account:role" principal string
	// must never fill this field.
	Role       string
	OnBehalfOf string

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
		Role:                rec.Attribution.Verified.Role,
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
		Role:                row.Verified.Role,
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

// readOutcomeAudited is the outcome word for a metadata-only read record.
//
// A read record has no per-Node verdict to render: nothing was dispatched and
// no daemon decided anything, so audit.Record.Outcome is the zero value and an
// outcome chip built from it falls to "unspecified" — "we don't know" about the
// one family of record whose disposition is completely known (#517).
//
// The word is "audited", and the three alternatives were each rejected for a
// reason worth keeping:
//
//   - "read" restates the Kind. The row already names the tool through
//     readTargetOf in the cell beside the chip, so a chip that says "read"
//     spends the operator's attention repeating what they just read.
//   - "succeeded" is a claim the record cannot support. The access record is
//     written BEFORE the query runs, and fails closed so an unauditable read
//     never happens (capability's read lane, mcp/readaudit.go). A read that
//     failed downstream is therefore recorded exactly like one that returned,
//     and no result ever comes back to amend the record.
//   - "recorded" says the same thing as "audited" with none of the ADR-0025
//     weight, and does not pair with the sentence the row already renders.
//
// "audited" names the one property the record does carry — and the only one it
// is written to guarantee: the access is on the trail whatever the result was,
// and the result itself is never retained (ADR-0025). It is the chip form of
// the note the row already carries beneath it, "The call is audited; the
// result is not retained."
//
// It lives here, beside readTargetOf, for the reason this file exists: a second
// screen naming these records is a second chance to name them differently.
const readOutcomeAudited = "audited"

// readOperations is every Operation name this package can call read: the
// native half DERIVED from opvocab, unioned with the shipped-template half
// MIRRORED below. It is built once, at var-init, so isReadOperation stays a
// single map lookup rather than a scan of opvocab.Operations() on every
// rendered trail row.
//
// The native half needs no listing of its own: it is every
// opvocab.Operations() descriptor whose Risk is jobs.RiskClassRead. opvocab is
// already golden-checked against the daemon's schema (ADR-0015), so a change
// to the native vocabulary rides that chain of custody straight into this set
// instead of requiring a second, hand-kept list to be remembered.
//
// The template half has no such source: there is no Go-reachable vocabulary
// of "what does the daemon package ship", because the packaged catalog.toml
// is a Node-side artifact the Relay does not read at runtime (see
// vocab_contract_test.go's doc comment for why). shippedReadCatalog is
// therefore a hand-kept MIRROR of exactly the seven templates
// daemon/packaging/templates.d/relay-read/catalog.toml ships, all read-class,
// and vocab_contract_test.go binds it to that file bidirectionally so the two
// cannot silently diverge.
//
// A customer-authored Template Operation is in neither half and is therefore
// treated as a mutate — the safe direction for the risk chip, since it
// over-states blast radius rather than under-stating it. This is a change
// from the literal it replaces: the old list also fed the read-egress screen,
// where the same default under-counted exposure. That screen no longer reads
// this set — reads.go derives its vocabulary from the Job's DECLARED
// RiskClass — so the only residual bias this set introduces is in the chip,
// the note, and denyExplanation's fallback sentence, and it errs safe there.
//
// A Node-local template that REUSES one of the seven shipped names with a
// different declared class is still misread by this inference in the
// dangerous direction (a local mutate template named, say, `log.tail`, would
// chip as read). The only real fix is carrying the declared class on the
// record itself rather than inferring it here (Option 2, escalated, #475).
var readOperations = func() map[string]bool {
	set := make(map[string]bool, len(shippedReadCatalog))
	for name := range shippedReadCatalog {
		set[name] = true
	}
	for _, d := range opvocab.Operations() {
		if d.Risk == jobs.RiskClassRead {
			set[d.Name] = true
		}
	}
	return set
}()

// shippedReadCatalog names exactly the seven templates
// daemon/packaging/templates.d/relay-read/catalog.toml ships, all read-class
// (ADR-0021). vocab_contract_test.go hand-parses that file and asserts this
// set against it bidirectionally, so adding, removing or reclassifying a
// template there without updating this literal fails the Go suite.
var shippedReadCatalog = map[string]bool{
	"proc.list":      true,
	"service.status": true,
	"disk.usage":     true,
	"net.listening":  true,
	"pkg.inventory":  true,
	"log.tail":       true,
	"file.checksum":  true,
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

// denyRuleOffLane renders Deny.Rule for a row that reached this package
// through the read lane (capability.AuditRow) rather than through
// audit.Record — agent history, since #542.
//
// It cannot call denyText the way denyExplanation does, because denyText's
// last resort — "The daemon refused this Operation and did not report the
// deciding rule" — is FALSE on this lane for a denied MUTATE-class row. That
// sentence is only true when the trail genuinely has nothing: on the WHOLE
// trail a mutate-class denial's verdict lives in Stderr, and denyText's
// fallback fires only once that is checked and empty. capability.AuditRow
// never carries Stderr AT ALL (query.go's own doc comment; adding it back is
// the acceptance criterion #441 exists to forbid), so calling denyText here
// would report "not recorded" over a rule the trail IS holding — on the
// Job's own Tasks, which this row already links to via JobHref. That is the
// exact failure family #463/#517/#520 were each about: a screen asserting a
// negative the record does not support.
//
// So this function answers the same question a different way, in the same
// three-case shape as denyText but never reaching for Stderr at all, and
// never calling denyText itself:
//
//   - f.Reason, when the row carries one. This is the SAME first check
//     denyText makes, just spelled without the stderr argument the lane has
//     nothing to pass.
//   - A read-class sentence SCOPED TO THIS LANE, when riskOf(f) says this was
//     a read. It does NOT call denyText(nil, "", true): that sentence asserts
//     what the TRAIL holds ("not recorded in the trail"), and that assertion
//     is an inference away from being false. riskOf is documented as fallible
//     in exactly one direction (above) — a Node-local Template Operation that
//     reuses a shipped read name at mutate class (#475) — and in that case the
//     daemon's verdict IS on the trail, in Stderr, which the pre-migration
//     code self-corrected for by checking stderr before ever reaching this
//     sentence (denyText's own case order). This lane has no stderr to check,
//     so it must not assert a negative about the trail at all; it says only
//     what THIS SCREEN's rows carry — nothing, ever, for a read-class Task
//     (ADR-0025) — and where to look if anything was reported.
//   - A parallel sentence for the mutate-class remainder, naming WHERE the
//     rule actually is rather than claiming it is nowhere: this lane's rows
//     carry no daemon output at any age, but the Task the row's JobHref
//     points at still does, until the Job is collected (job.go).
//
// THE LOSS IS REAL: an operator reading agent history sees a pointer to the
// rule instead of the rule itself, where node detail (still on
// denyExplanation, still reading the whole trail) shows it verbatim. That
// asymmetry is deliberate and stays until node detail's own Recent Tasks
// panel migrates onto this same lane, at which point the same trade recurs
// there rather than being solved by growing AuditRow a field #441 named as
// the thing it must never have.
func denyRuleOffLane(f trailFacts) string {
	if f.Reason != "" {
		return f.Reason
	}
	if riskOf(f) == jobs.RiskClassRead {
		return "This screen's rows carry no daemon output for a read-class Task, at any\n" +
			"age (ADR-0025) — reading is exfiltration, so what left the Node is audited and\n" +
			"what it said is not. If the daemon reported a rule, it is on the Job this row\n" +
			"links to, on that Job's own Tasks, retained until the Job is collected — open\n" +
			"the Job to see it."
	}
	return "The daemon's verdict is not on this lane's rows: this screen carries no\n" +
		"daemon output at any age (ADR-0025). It is on the Job this row links to, on that\n" +
		"Job's own Tasks, retained until the Job is collected — open the Job to see it."
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
