package console

// agents_window_test.go is #540's acceptance criteria: the 15-minute window
// becomes a real membership filter on the Accounts rail, the rail gains the
// two spec-03 fields it lacked (verified role, first call), and every empty
// or partially-filtered rail says so.
//
// Its own file for the reason agents_paging_test.go already states:
// screens_test.go is huge and has already silently fused two test functions
// in a three-way merge. New coverage for a signature change this large goes
// here instead.

import (
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/accounts"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/audit"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/capability"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/jobs"
)

// TestAgents_AnAccountOutsideTheWindowDropsOffTheRail is the issue's own
// title: the window used to color a dot and nothing else, so a stale Account
// stayed on the rail forever. Two Accounts, one fresh and one stale, both
// with a mutate row: the stale name must be absent from BOTH the rail slice
// and the rendered rail, the fresh Account must be present, and dropped must
// report exactly 1.
func TestAgents_AnAccountOutsideTheWindowDropsOffTheRail(t *testing.T) {
	const fresh = "gleipnir-prod:operator"
	const stale = "legacy-agent:operator"
	rows := []capability.AuditRow{
		{Kind: audit.KindDispatch, ActionKind: "operation", OperationName: "service.restart",
			Principal: fresh, NodeID: "node-a", Outcome: jobs.OutcomeSuccess, Timestamp: testNow.Add(-1 * time.Minute)},
		{Kind: audit.KindDispatch, ActionKind: "operation", OperationName: "service.restart",
			Principal: stale, NodeID: "node-b", Outcome: jobs.OutcomeSuccess, Timestamp: testNow.Add(-45 * time.Minute)},
	}

	rail, _, dropped := buildAgents(rows, "", testNow)
	if len(rail) != 1 || rail[0].Name != fresh {
		t.Fatalf("rail = %+v, want exactly the fresh Account %q", rail, fresh)
	}
	if dropped != 1 {
		t.Errorf("dropped = %d, want 1", dropped)
	}

	d := renderableDeps()
	d.Queries = &fakeQueries{rows: rows}
	body := get(t, newTestHandler(d, accounts.RoleAdmin), "/console/agents").Body.String()
	// Scoped to the RAIL, not the whole body: the stale Account's row is
	// supposed to keep rendering in the feed below — that is the history
	// spec 03 promises stays reachable. Only the rail must drop it.
	railHTML := railSection(t, body)
	if !strings.Contains(railHTML, fresh) {
		t.Errorf("the fresh Account does not render on the rail:\n%s", railHTML)
	}
	if strings.Contains(railHTML, stale) {
		t.Errorf("the stale Account still renders on the rail although its last call is outside "+
			"the 15-minute window:\n%s", railHTML)
	}
	if !strings.Contains(body, stale) {
		t.Errorf("the stale Account's call disappeared from the feed entirely — its history "+
			"must stay reachable even though it drops off the rail:\n%s", body)
	}
}

// railSection returns the <aside class="agentrail">…</aside> slice of a
// rendered Agents page, so a test can assert what the RAIL shows without
// also matching the feed below it — the feed intentionally keeps rendering
// an Account's calls after it drops off the rail.
func railSection(t *testing.T, body string) string {
	t.Helper()
	start := strings.Index(body, `<aside class="agentrail">`)
	if start < 0 {
		t.Fatalf("no <aside class=\"agentrail\"> in body:\n%s", body)
	}
	end := strings.Index(body[start:], `</aside>`)
	if end < 0 {
		t.Fatalf("unterminated agentrail aside in body:\n%s", body)
	}
	return body[start : start+end]
}

// TestAgents_APageOfStaleCallsEmptiesTheRailAndSaysSo is THE issue's named
// requirement: a fixture whose records are all older than the window must
// produce an empty rail AND say so, and the feed must still render every row
// — a rail that empties by silently discarding rows is a different bug.
//
// Two Accounts (three rows total) so the dropped count in the sentence is
// itself discriminating, both entirely outside the window, page one
// (unscrolled).
func TestAgents_APageOfStaleCallsEmptiesTheRailAndSaysSo(t *testing.T) {
	rows := []capability.AuditRow{
		{Kind: audit.KindDispatch, ActionKind: "operation", OperationName: "service.restart",
			Principal: "acct-a:operator", NodeID: "node-a", Outcome: jobs.OutcomeSuccess, Timestamp: testNow.Add(-45 * time.Minute)},
		{Kind: audit.KindDispatch, ActionKind: "operation", OperationName: "service.restart",
			Principal: "acct-a:operator", NodeID: "node-b", Outcome: jobs.OutcomeSuccess, Timestamp: testNow.Add(-30 * time.Minute)},
		{Kind: audit.KindRead, OperationName: "list_nodes", Principal: "acct-b:operator", Timestamp: testNow.Add(-20 * time.Minute)},
	}

	rail, _, dropped := buildAgents(rows, "", testNow)
	if len(rail) != 0 {
		t.Fatalf("rail = %+v, want empty — every row is older than the 15-minute window", rail)
	}
	if dropped != 2 {
		t.Fatalf("dropped = %d, want 2", dropped)
	}

	d := renderableDeps()
	d.Queries = &fakeQueries{rows: rows}
	body := get(t, newTestHandler(d, accounts.RoleAdmin), "/console/agents").Body.String()

	// (i) rail slice empty — asserted above via buildAgents directly.

	// (ii) says so, AND names the dropped count.
	if !strings.Contains(body, "No Account has called in the last 15 minutes") {
		t.Errorf("an empty rail over stale calls does not say so:\n%s", body)
	}
	if !strings.Contains(body, "2 Accounts") {
		t.Errorf("the empty-rail sentence does not name the dropped count:\n%s", body)
	}

	// (iii) does NOT render the no-calls-at-all sentence — there ARE calls,
	// just none inside the window.
	if strings.Contains(body, "No Account has called a control surface yet.") {
		t.Errorf("a page WITH stale calls renders the no-calls-at-all sentence, which claims "+
			"something false:\n%s", body)
	}

	// (iv) the feed still renders EVERY row: emptying the rail must never
	// silently drop a row the lane returned.
	if n := strings.Count(body, `data-kind="call"`); n != len(rows) {
		t.Errorf("the feed renders %d calls, want %d — the stream is the history and must "+
			"never be time-filtered", n, len(rows))
	}
}

// TestAgents_AnEmptyPageAndAStalePageSayDifferentThings pins the three
// distinct empty/partial sentences apart: a genuinely empty page (page one),
// an empty scrolled page, and a page holding only stale calls (scrolled) must
// each say something the other two do not.
func TestAgents_AnEmptyPageAndAStalePageSayDifferentThings(t *testing.T) {
	const (
		noCallsAtAll  = "No Account has called a control surface yet."
		emptyScrolled = "This page holds no calls."
		staleScrolled = "No Account has called in the last 15 minutes, which is expected on a page " +
			"reached by following Older"
	)

	cases := []struct {
		name string
		rows []capability.AuditRow
		path string
		want string
	}{
		{
			name: "zero rows, page one",
			path: "/console/agents",
			want: noCallsAtAll,
		},
		{
			name: "zero rows, scrolled",
			path: "/console/agents?cursor=0",
			want: emptyScrolled,
		},
		{
			name: "stale rows, scrolled",
			rows: []capability.AuditRow{
				{Kind: audit.KindDispatch, ActionKind: "operation", OperationName: "service.restart",
					Principal: "agent:operator", NodeID: "node-a", Outcome: jobs.OutcomeSuccess,
					Timestamp: testNow.Add(-45 * time.Minute)},
			},
			path: "/console/agents?cursor=0",
			want: staleScrolled,
		},
	}

	all := []string{noCallsAtAll, emptyScrolled, staleScrolled}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			d := renderableDeps()
			d.Queries = &fakeQueries{rows: c.rows}
			body := get(t, newTestHandler(d, accounts.RoleAdmin), c.path).Body.String()

			if !strings.Contains(body, c.want) {
				t.Errorf("%s: body does not contain %q:\n%s", c.name, c.want, body)
			}
			for _, other := range all {
				if other == c.want {
					continue
				}
				if strings.Contains(body, other) {
					t.Errorf("%s: body also contains %q, which belongs to a different case:\n%s",
						c.name, other, body)
				}
			}
		})
	}
}

// TestAgents_TheRailNoteAlwaysExplainsAnEmptyRail is the guard for deleting
// the template's {{else}} arm: railNote must be non-empty whenever the rail
// is empty, and empty ONLY when the rail lists something and nothing was
// dropped.
func TestAgents_TheRailNoteAlwaysExplainsAnEmptyRail(t *testing.T) {
	for _, listed := range []int{0, 1, 2} {
		for _, dropped := range []int{0, 1, 2} {
			for _, scrolled := range []bool{false, true} {
				got := railNote(listed, dropped, scrolled)
				wantEmpty := listed > 0 && dropped == 0
				if wantEmpty && got != "" {
					t.Errorf("railNote(%d, %d, %v) = %q, want \"\"", listed, dropped, scrolled, got)
				}
				if !wantEmpty && got == "" {
					t.Errorf("railNote(%d, %d, %v) = \"\", want a non-empty explanation", listed, dropped, scrolled)
				}
			}
		}
	}
}

// TestAgents_ThePageNeverSaysCallsAreInTheWindow pins #542's de-collision
// against this ticket's new copy: on this screen "window" is always spelled
// "the last 15 minutes", never "in the window".
func TestAgents_ThePageNeverSaysCallsAreInTheWindow(t *testing.T) {
	staleRow := capability.AuditRow{Kind: audit.KindDispatch, ActionKind: "operation",
		OperationName: "service.restart", Principal: "agent:operator", NodeID: "node-a",
		Outcome: jobs.OutcomeSuccess, Timestamp: testNow.Add(-45 * time.Minute)}
	freshRow := capability.AuditRow{Kind: audit.KindDispatch, ActionKind: "operation",
		OperationName: "service.restart", Principal: "agent:operator", NodeID: "node-a",
		Outcome: jobs.OutcomeSuccess, Timestamp: testNow}
	// Two rows that collapseRuns folds into one (#541): they render
	// identically apart from timestamp, so pageNote's collapse clause fires
	// too, and the word rule must hold over that new copy as much as the
	// position clauses it already covered.
	collapsingRows := []capability.AuditRow{freshRow, freshRow}

	for _, c := range []struct {
		name string
		rows []capability.AuditRow
		path string
	}{
		{"empty, page one", nil, "/console/agents"},
		{"empty, scrolled", nil, "/console/agents?cursor=0"},
		{"stale, page one", []capability.AuditRow{staleRow}, "/console/agents"},
		{"stale, scrolled", []capability.AuditRow{staleRow}, "/console/agents?cursor=0"},
		{"populated, page one", []capability.AuditRow{freshRow}, "/console/agents"},
		{"populated, scrolled", []capability.AuditRow{freshRow}, "/console/agents?cursor=0"},
		{"collapsing, page one", collapsingRows, "/console/agents"},
		{"collapsing, scrolled", collapsingRows, "/console/agents?cursor=0"},
	} {
		t.Run(c.name, func(t *testing.T) {
			d := renderableDeps()
			d.Queries = &fakeQueries{rows: c.rows}
			body := get(t, newTestHandler(d, accounts.RoleAdmin), c.path).Body.String()
			if strings.Contains(body, "in the window") {
				t.Errorf("%s: body says \"in the window\":\n%s", c.name, body)
			}
		})
	}
}

// TestAgents_TheWindowIsNeverPushedIntoTheLane pins decision 1b: the 15
// minutes never becomes AuditFilter.Since (which would cap history
// reachability at the window forever) and the rail never triggers a second
// query.
func TestAgents_TheWindowIsNeverPushedIntoTheLane(t *testing.T) {
	q := &fakeQueries{}
	d := renderableDeps()
	d.Queries = q

	get(t, newTestHandler(d, accounts.RoleAdmin), "/console/agents")

	if q.auditCalls != 1 {
		t.Fatalf("QueryAudit was called %d times, want exactly 1", q.auditCalls)
	}
	f := q.auditFilters[0]
	if !f.Since.IsZero() {
		t.Errorf("the filter carries a Since of %v, want zero — the window must never narrow the lane", f.Since)
	}
	if !f.Until.IsZero() {
		t.Errorf("the filter carries an Until of %v, want zero", f.Until)
	}
}

// TestAgents_TheRailAgreesPerAccountWhenAnAccountDropsOff is decision 2's
// narrowed replacement property, built per the plan-review corollary (E1):
// "one fresh, one stale" alone makes M5 (counting Calls/Mutates over the
// window rather than the page) vacuous, because a fresh Account's rows sit
// entirely inside the window and a window-scoped count then equals the
// page-scoped one.
//
// So the LISTED (fresh) Account here carries a mutate row OLDER than the
// window that is NOT its most recent call (a read is), and a stale Account
// contributes a second mutate row that drops off the rail entirely.
// Page-scoped Mutates for the fresh Account is then strictly greater than a
// window-scoped count would produce, and the two assertions below fail
// independently:
//
//	(i)  the listed Account's Mutates equals ITS OWN chipped mutate rows —
//	     red under M5 (window-scoped counting reports 0, not 1).
//	(ii) the page's total mutate chips is strictly greater than the sum of
//	     rail Mutates — red under M4 (filtering the feed removes both mutate
//	     rows, collapsing both sides to 0).
//
// Both counting loops sum c.Calls rather than counting rows (+= 1): #541 lets
// a mutate row collapse and stand for more than one call, and the rail's
// Mutates counts CALLS, never rendered rows — see buildAgents' "rail counts
// CALLS" doc. This fixture's rows collapse nothing (no two are adjacent and
// identical), so the rewrite is provably behaviour-preserving here; the
// fixture built to discriminate the two forms is
// TestAgents_TheRailCountsCallsNotCollapsedRows (agents_collapse_test.go).
func TestAgents_TheRailAgreesPerAccountWhenAnAccountDropsOff(t *testing.T) {
	const fresh = "gleipnir-prod:operator"
	const stale = "legacy-agent:operator"
	rows := []capability.AuditRow{
		// fresh: a mutate OLDER than the window, NOT its most recent call.
		{Kind: audit.KindDispatch, ActionKind: "operation", OperationName: "service.restart",
			Principal: fresh, NodeID: "node-a", Outcome: jobs.OutcomeSuccess, Timestamp: testNow.Add(-45 * time.Minute)},
		// fresh: its most recent call, INSIDE the window, and not a mutate.
		{Kind: audit.KindRead, OperationName: "list_nodes", Principal: fresh, Timestamp: testNow.Add(-1 * time.Minute)},
		// stale: every row outside the window; drops off the rail entirely.
		{Kind: audit.KindDispatch, ActionKind: "operation", OperationName: "service.restart",
			Principal: stale, NodeID: "node-b", Outcome: jobs.OutcomeSuccess, Timestamp: testNow.Add(-45 * time.Minute)},
	}

	rail, calls, dropped := buildAgents(rows, "", testNow)
	if len(rail) != 1 || rail[0].Name != fresh {
		t.Fatalf("rail = %+v, want exactly the fresh Account %q", rail, fresh)
	}
	if dropped != 1 {
		t.Fatalf("dropped = %d, want 1", dropped)
	}

	// (i) per-Account: the listed Account's Mutates equals ITS OWN rendered
	// mutate-chipped calls, page-scoped — the property that must survive a
	// dropped sibling Account.
	freshChipped := 0
	for _, c := range calls {
		if c.Principal == fresh && c.Risk == RiskLabel(jobs.RiskClassMutate) {
			freshChipped += c.Calls
		}
	}
	if rail[0].Mutates != freshChipped {
		t.Errorf("the listed Account's rail Mutates = %d, want %d (its own chipped rows) — "+
			"counting over the window instead of the page reports a number that agrees with "+
			"nothing else on its own row", rail[0].Mutates, freshChipped)
	}

	// (ii) aggregate: the page's total mutate chips exceeds the sum of rail
	// Mutates, because the stale Account's mutate row still renders below a
	// rail that no longer lists it.
	totalChipped := 0
	for _, c := range calls {
		if c.Risk == RiskLabel(jobs.RiskClassMutate) {
			totalChipped += c.Calls
		}
	}
	sumRail := 0
	for _, a := range rail {
		sumRail += a.Mutates
	}
	if totalChipped <= sumRail {
		t.Errorf("page mutate chips = %d, sum(rail Mutates) = %d — want the page total strictly "+
			"greater, since the dropped Account's row still renders below a rail that no "+
			"longer lists it", totalChipped, sumRail)
	}
}

// TestAgents_TheRailShowsTheVerifiedRoleAndNeverAnAssertedOne is the
// security-relevant half of #540: Role comes from the verified lane or not
// at all, and needs its own markup hook because "operator" is a substring of
// the unverified principal text "alice:operator" — a plain-text assertion
// cannot tell the two apart.
func TestAgents_TheRailShowsTheVerifiedRoleAndNeverAnAssertedOne(t *testing.T) {
	const aroleOpen = `<span class="arole" title="The role the Relay authenticated this Account with at its most recent call on this page.">`

	t.Run("verified renders the role", func(t *testing.T) {
		d := renderableDeps()
		d.Queries = &fakeQueries{rows: []capability.AuditRow{
			{Kind: audit.KindDispatch, ActionKind: "operation", OperationName: "service.restart",
				Principal: "gleipnir-prod:operator", NodeID: "node-a", Outcome: jobs.OutcomeSuccess,
				Timestamp: testNow, Verified: capability.VerifiedIdentity{
					AccountID: "acct-1", AccountName: "gleipnir-prod", Role: "operator",
				}},
		}}
		body := get(t, newTestHandler(d, accounts.RoleAdmin), "/console/agents").Body.String()
		if !strings.Contains(body, aroleOpen+"operator</span>") {
			t.Errorf("a verified Account's role does not render through the arole hook:\n%s", body)
		}
	})

	t.Run("unverified never fakes a role from the principal string", func(t *testing.T) {
		d := renderableDeps()
		d.Queries = &fakeQueries{rows: []capability.AuditRow{
			// "operator" is a SUBSTRING of this Principal, and Verified is
			// entirely zero — the exact trap principalText's fallback sets.
			{Kind: audit.KindDispatch, ActionKind: "operation", OperationName: "service.restart",
				Principal: "alice:operator", NodeID: "node-a", Outcome: jobs.OutcomeSuccess, Timestamp: testNow},
		}}
		body := get(t, newTestHandler(d, accounts.RoleAdmin), "/console/agents").Body.String()
		if strings.Contains(body, `class="arole"`) {
			t.Errorf("an unverified entry renders a role split out of its asserted principal "+
				"string:\n%s", body)
		}
	})

	t.Run("a verified role with no verified name renders no role", func(t *testing.T) {
		// Adversarial: Verified.Role is set but AccountName/AccountID are
		// not, so the entry is NOT verified. A role must not leak onto an
		// asserted entry just because SOME field on the verified lane was set.
		d := renderableDeps()
		d.Queries = &fakeQueries{rows: []capability.AuditRow{
			{Kind: audit.KindDispatch, ActionKind: "operation", OperationName: "service.restart",
				Principal: "mallory:admin", NodeID: "node-a", Outcome: jobs.OutcomeSuccess,
				Timestamp: testNow, Verified: capability.VerifiedIdentity{Role: "admin"}},
		}}
		body := get(t, newTestHandler(d, accounts.RoleAdmin), "/console/agents").Body.String()
		if strings.Contains(body, `class="arole"`) {
			t.Errorf("a Verified.Role with no verified AccountID/AccountName still renders a "+
				"role:\n%s", body)
		}
	})

	t.Run("a role change mid-page shows the newer authority", func(t *testing.T) {
		// The OLDER row (operator) is listed FIRST and the newer one
		// (admin) SECOND — deliberately reversed from the real lane's
		// documented newest-first order, so this fixture can only pass if
		// the picking logic compares Timestamp and not array position. A
		// "first row encountered wins" bug (M9) would pick "operator" here
		// precisely because it is first in this slice.
		d := renderableDeps()
		d.Queries = &fakeQueries{rows: []capability.AuditRow{
			{Kind: audit.KindDispatch, ActionKind: "operation", OperationName: "service.restart",
				Principal: "gleipnir-prod:operator", NodeID: "node-b", Outcome: jobs.OutcomeSuccess,
				Timestamp: testNow.Add(-10 * time.Minute), Verified: capability.VerifiedIdentity{
					AccountID: "acct-1", AccountName: "gleipnir-prod", Role: "operator",
				}},
			{Kind: audit.KindDispatch, ActionKind: "operation", OperationName: "service.restart",
				Principal: "gleipnir-prod:admin", NodeID: "node-a", Outcome: jobs.OutcomeSuccess,
				Timestamp: testNow, Verified: capability.VerifiedIdentity{
					AccountID: "acct-1", AccountName: "gleipnir-prod", Role: "admin",
				}},
		}}
		body := get(t, newTestHandler(d, accounts.RoleAdmin), "/console/agents").Body.String()
		if !strings.Contains(body, aroleOpen+"admin</span>") {
			t.Errorf("the newer row's role (admin) does not render:\n%s", body)
		}
		if strings.Contains(body, aroleOpen+"operator</span>") {
			t.Errorf("the OLDER row's role (operator) rendered instead of the newer one:\n%s", body)
		}
	})
}

// TestAgents_TheRailShowsTheFirstCallOnThePage covers the new `first` field
// and its same-rendered-text suppression rule: two calls that bucket to the
// same minute-granular text must render only ONE "ago" phrase, or "first 12m
// ago · last 12m ago" reads as a bug rather than as two calls.
func TestAgents_TheRailShowsTheFirstCallOnThePage(t *testing.T) {
	t.Run("distinct first and last", func(t *testing.T) {
		d := renderableDeps()
		d.Queries = &fakeQueries{rows: []capability.AuditRow{
			{Kind: audit.KindDispatch, ActionKind: "operation", OperationName: "service.restart",
				Principal: "agent:operator", NodeID: "node-a", Outcome: jobs.OutcomeSuccess,
				Timestamp: testNow.Add(-12 * time.Minute)},
			{Kind: audit.KindDispatch, ActionKind: "operation", OperationName: "service.restart",
				Principal: "agent:operator", NodeID: "node-b", Outcome: jobs.OutcomeSuccess,
				Timestamp: testNow.Add(-1 * time.Minute)},
		}}
		body := get(t, newTestHandler(d, accounts.RoleAdmin), "/console/agents").Body.String()
		if !strings.Contains(body, "first 12m ago") {
			t.Errorf("the earliest call on the page does not render as \"first 12m ago\":\n%s", body)
		}
		if !strings.Contains(body, "last 1m ago") {
			t.Errorf("the most recent call on the page does not render as \"last 1m ago\":\n%s", body)
		}
	})

	t.Run("same rendered text renders exactly once", func(t *testing.T) {
		d := renderableDeps()
		d.Queries = &fakeQueries{rows: []capability.AuditRow{
			{Kind: audit.KindDispatch, ActionKind: "operation", OperationName: "service.restart",
				Principal: "agent:operator", NodeID: "node-a", Outcome: jobs.OutcomeSuccess,
				Timestamp: testNow.Add(-5*time.Minute - 20*time.Second)},
			{Kind: audit.KindDispatch, ActionKind: "operation", OperationName: "service.restart",
				Principal: "agent:operator", NodeID: "node-b", Outcome: jobs.OutcomeSuccess,
				Timestamp: testNow.Add(-5 * time.Minute)},
		}}
		body := get(t, newTestHandler(d, accounts.RoleAdmin), "/console/agents").Body.String()
		if n := strings.Count(body, "ago"); n != 1 {
			t.Errorf(`body contains "ago" %d times, want exactly 1 — two calls 20s apart both `+
				`render "5m ago" and showing both reads as a bug:%s`, n, body)
		}
		if !strings.Contains(body, "last 5m ago") {
			t.Errorf("the rail does not render \"last 5m ago\":\n%s", body)
		}
		if strings.Contains(body, "first") {
			t.Errorf("the rail renders a redundant \"first\" beside an identical \"last\":\n%s", body)
		}
	})
}

// TestVocab_BothProjectionsCarryTheSameFacts is decision 4's parity guard:
// agents.go reads factsOfRow, node detail's Recent Tasks and node_revoke
// still read factsOfRecord, and nothing before this test noticed a field
// filled by one projection and not the other.
//
// Every trailFacts-relevant field on the fixture Record is set non-zero, so
// that dropping Role (or anything else) from either projection function is
// caught by the zero-sweep rather than by two projections merely agreeing
// with each other on an all-zero field.
func TestVocab_BothProjectionsCarryTheSameFacts(t *testing.T) {
	rec := audit.Record{
		ID:        "rec-1",
		Timestamp: testNow,
		Kind:      audit.KindDispatch,
		Principal: "gleipnir-prod:operator",
		Attribution: audit.Attribution{
			Verified: audit.Verified{
				AccountID:   "acct-1",
				AccountName: "gleipnir-prod",
				Role:        "operator",
				TokenID:     "tok-1",
				Method:      "token",
				Source:      "10.0.0.1",
			},
			Asserted: audit.Asserted{OnBehalfOf: "alice", Traceparent: "00-trace"},
		},
		Selector:      "tag:web",
		JobID:         "job-1",
		NodeID:        "node-a",
		ActionKind:    "operation",
		OperationName: "service.restart",
		Args:          map[string]string{"unit": "nginx"},
		RawExecArgv:   []string{"systemctl", "restart", "nginx"},
		Outcome:       jobs.OutcomeSuccess,
		Reason:        "because",
		ApprovalID:    "appr-1",
		GrantID:       "grant-1",
	}

	f := factsOfRecord(rec)
	v := reflect.ValueOf(f)
	for i := 0; i < v.NumField(); i++ {
		if v.Field(i).IsZero() {
			t.Errorf("the fixture leaves trailFacts.%s zero — it must set every field so a "+
				"projection that drops one is caught by this test", v.Type().Field(i).Name)
		}
	}

	row := rowOfRecord(rec)
	if got := factsOfRow(row); !reflect.DeepEqual(f, got) {
		t.Errorf("factsOfRecord and factsOfRow disagree on the same record:\n"+
			"factsOfRecord = %+v\nfactsOfRow    = %+v", f, got)
	}
}
