package console

// callfeed.go is the code the Agents screen and Activity share: the "Who is
// active" strip (or rail), the polling collapse, and the reads-made-from-this-
// Console exclusion. Activity is the screen these belong to (spec 04); Agents
// still calls them until it is removed (#787).
//
// Each is presentation over a page the read lane already returned. None of them
// adds a query, widens a filter or changes a page size.

import (
	"sort"
	"time"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/audit"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/capability"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/jobs"
)

// activeWindow is the strip's (or rail's) MEMBERSHIP rule (#540): an Account
// with no call in the last 15 minutes drops off it entirely. It used to color a
// dot and nothing else, so the header's "active" claim was never enforced — a
// page of nothing but stale calls listed every Account with an inactive dot
// rather than listing none. Fifteen minutes, per spec 04, Who is active — long
// enough that an agent thinking between calls does not blink out, short enough
// that "active" means something.
const activeWindow = 15 * time.Minute

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

// withoutConsoleReads drops the page's Console-session reads, preserving
// order. It reports how many it dropped, and — for the ?account= view — how
// many calls the named Account has on the page and how many of those it
// dropped, naming Accounts exactly as buildAgents does (principalText).
//
// It is presentation over the page the lane already returned, like
// collapseRuns: the query, its filter and its page size are untouched, so
// no read is added or widened.
func withoutConsoleReads(rows []capability.AuditRow, account string) (kept []capability.AuditRow, dropped, accountCalls, accountDropped int) {
	kept = make([]capability.AuditRow, 0, len(rows))
	for _, row := range rows {
		mine := account != "" && principalText(factsOfRow(row)) == account
		if mine {
			accountCalls++
		}
		if consoleRead(row) {
			dropped++
			if mine {
				accountDropped++
			}
			continue
		}
		kept = append(kept, row)
	}
	return kept, dropped, accountCalls, accountDropped
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
// when it folded nothing. counter names what still counts every call: "rail" on
// Agents, "strip" on Activity.
func collapseNote(foldedCalls, foldedRows int, counter string) string {
	if foldedRows == 0 {
		return ""
	}
	return countOf(foldedCalls, "call", "calls") + " on this page are collapsed into " +
		countOf(foldedRows, "row", "rows") + ", each saying how many calls it stands for. " +
		"The " + counter + " still counts every call."
}

// stripCall is one call as the strip counts it. Key groups calls into an
// entry; Name and Verified are what the entry shows.
type stripCall struct {
	Key, Name string
	Verified  bool
	Role      string
	Mutate    bool
	Denied    bool
	At        time.Time
}

// stripEntry is one Account (or asserted principal) on the strip.
type stripEntry struct {
	Key, Name string
	Verified  bool
	// Role is the verified role at the entry's most recent role-carrying call
	// ON THIS PAGE — empty renders nothing. Sourced ONLY from the verified lane
	// and cleared unless Verified is true: an asserted-lane role must never
	// occupy this position beside the trust chip (#540).
	Role    string
	Calls   int
	Mutates int
	Denied  int
	// FirstSeen is the earliest call on this page, EMPTY when it would render
	// the identical TEXT as LastSeen (timeSince buckets by whole minutes, so two
	// calls 20s apart both read "12m ago" and showing both reads as a bug rather
	// than as two calls).
	FirstSeen string
	LastSeen  string
	Current   bool
	// Href is left empty by buildStrip: each screen links its own way.
	Href string
}

// buildStrip rolls one page's calls up per Key.
//
// calls arrive NEWEST FIRST on both screens. Precedence, stated because the
// two screens' keys differ:
//
//   - Name and Verified come from the FIRST call seen for a Key and never
//     change, so they are the Key's newest call on the page. For Agents the Key
//     is the name, so this is the first row seen; for Activity's "id:" keys an
//     Account renamed mid-page is listed under its newest name.
//   - Role comes from the newest call (by At) carrying a role, so a role change
//     mid-page shows the later authority and one role-less call later in the
//     page does not blank it. It is cleared unless Verified.
//   - Calls, Mutates and Denied count calls, never rendered rows; FirstSeen and
//     LastSeen are the earliest and latest At.
//   - Membership: an entry whose last call is more than activeWindow before now
//     is dropped and counted in dropped. The feed itself is never time-filtered.
//   - Entries sort busiest first, then by Name, then by Key.
func buildStrip(calls []stripCall, current string, now time.Time) (entries []stripEntry, dropped int) {
	type acc struct {
		stripEntry
		first, last, roleAt time.Time
	}
	byKey := map[string]*acc{}
	for _, c := range calls {
		a, seen := byKey[c.Key]
		if !seen {
			a = &acc{stripEntry: stripEntry{Key: c.Key, Name: c.Name, Verified: c.Verified}}
			byKey[c.Key] = a
		}
		a.Calls++
		if c.Denied {
			a.Denied++
		}
		if c.Mutate {
			a.Mutates++
		}
		if a.first.IsZero() || c.At.Before(a.first) {
			a.first = c.At
		}
		if c.At.After(a.last) {
			a.last = c.At
		}
		if c.Role != "" && c.At.After(a.roleAt) {
			a.Role, a.roleAt = c.Role, c.At
		}
	}

	entries = make([]stripEntry, 0, len(byKey))
	for _, a := range byKey {
		// Membership, not a dot colour: every field below is computed only for
		// an entry that survives this.
		if now.Sub(a.last) > activeWindow {
			dropped++
			continue
		}
		a.LastSeen = timeSince(a.last, now)
		if first := timeSince(a.first, now); first != a.LastSeen {
			a.FirstSeen = first
		}
		// Belt-and-braces: a call carrying a verified role with no verified
		// name cannot put a role on an asserted entry.
		if !a.Verified {
			a.Role = ""
		}
		a.Current = a.Key == current
		entries = append(entries, a.stripEntry)
	}
	sort.SliceStable(entries, func(i, j int) bool {
		if entries[i].Calls != entries[j].Calls {
			return entries[i].Calls > entries[j].Calls
		}
		if entries[i].Name != entries[j].Name {
			return entries[i].Name < entries[j].Name
		}
		return entries[i].Key < entries[j].Key
	})
	return entries, dropped
}
