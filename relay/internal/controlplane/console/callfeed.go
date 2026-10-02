package console

// callfeed.go is Activity's call-feed code (spec 04): the polling collapse
// and the reads-made-from-this-Console exclusion.
//
// Each is presentation over a page the read lane already returned. None of them
// adds a query, widens a filter or changes a page size.

import (
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/audit"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/capability"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/jobs"
)

// consoleParam and consoleShow spell the one link that lists reads made
// from a Console session. Only the exact value shows them; anything else is
// the default, which the page states beside the feed either way.
const (
	consoleParam = "console"
	consoleShow  = "show"
)

// consoleRead reports whether the default leaves this call out (spec 04,
// "Reads made from this Console"). BOTH halves must hold, and each is read from
// the row as the lane returned it, never from anything else:
//
//   - made from a Console session: the verified lane's Method is what the
//     authentication boundary recorded when the call was made
//     (capability.AuthMethodConsoleSession). It proves a Console session
//     cookie authenticated the call — not that a person was at the keyboard.
//     A stolen cookie, or software driving an operator's browser, records
//     the same thing, which is why only reads are ever left out.
//   - a read: the record kind is audit.KindRead (the non-dispatching read
//     tools this Console's own page loads are recorded as) AND riskOf — the
//     one inference behind the risk chip the row renders — answers read.
//     Where the row cannot tell, the answer is "not a read" and the call
//     stays listed: a mutate, an approval decision, a Cancel, a refusal or a
//     Preflight is never left out, whatever its method.
//
// Nothing here reads the Account registry or an Account's kind: #540's
// reasoning stands (spec 04: a Kind is never read from the Account registry's
// current kind), and this rule does not depend on it. The method is never
// rendered; it decides what is listed and nothing else.
func consoleRead(row capability.AuditRow) bool {
	if capability.AuthMethod(row.Verified.Method) != capability.AuthMethodConsoleSession {
		return false
	}
	if row.Kind != audit.KindRead {
		return false
	}
	return riskOf(factsOfRow(row)) == jobs.RiskClassRead
}

// foldRuns folds each run of CONSECUTIVE rows that share a key into one row,
// preserving order and never reordering.
//
// It compares each incoming row ONLY against the last row already in the
// output — no map[key]index, so a non-adjacent match is UNREACHABLE, not merely
// un-done. This collapse folds ROWS, so reaching past an adjacent row would
// either move the merged row (reordering the trail) or leave it in place while
// silently claiming calls that happened after rows rendered below it — both of
// which stop a row's position from meaning "when", the one thing these feeds
// have to be honest about.
//
// key returns the row's fold key and whether the row may fold at all; two rows
// merge only when BOTH are foldable and the keys are ==. rows arrive
// newest-first, so on a merge the incoming row is OLDER than the run
// accumulated so far, and fold receives the run and that older row.
//
// Builds into a fresh slice (rows[:0:0]) rather than appending in place, so the
// caller's backing array is never aliased by a shorter result.
func foldRuns[T any, K comparable](rows []T, key func(T) (K, bool), fold func(run *T, older T)) []T {
	out := rows[:0:0]
	for _, r := range rows {
		if len(out) > 0 {
			run := &out[len(out)-1]
			if runKey, ok := key(*run); ok {
				if rKey, ok := key(r); ok && runKey == rKey {
					fold(run, r)
					continue
				}
			}
		}
		out = append(out, r)
	}
	return out
}

// foldedSummary reports how much of a rendered feed foldRuns folded:
// foldedCalls is the sum of calls(row) over every row that stands for more than
// one, and foldedRows is how many such rows there are. A row that collapsed
// nothing (one call, the common case) contributes to neither — so foldedCalls
// is always 0 or >= 2, never 1, which collapseNote's grammar ("are collapsed")
// depends on.
func foldedSummary[T any](rows []T, calls func(T) int) (foldedCalls, foldedRows int) {
	for _, r := range rows {
		if n := calls(r); n > 1 {
			foldedCalls += n
			foldedRows++
		}
	}
	return foldedCalls, foldedRows
}

// collapseNote is the sentence saying what the collapse did to the page, or ""
// when it folded nothing.
func collapseNote(foldedCalls, foldedRows int) string {
	if foldedRows == 0 {
		return ""
	}
	return countOf(foldedCalls, "call", "calls") + " on this page are collapsed into " +
		countOf(foldedRows, "row", "rows") + "."
}
