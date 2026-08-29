package console

// screens_test.go asserts the properties the per-screen specifications call out
// as acceptance criteria — the ones a plausible implementation passes by
// accident and a careless one breaks silently.
//
// The bias throughout is towards asserting ABSENCE. "The fleet view renders a
// row" is easy and worth little; "no Fact appears on a fleet row or in a facet"
// is the property that stops the targeting model from being quietly widened by
// a helpful change six months from now.

import (
	"context"
	"fmt"
	"math"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/accounts"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/approval"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/audit"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/capability"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/jobs"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/nodestate"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/policyview"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/registry"
)

// fleetFixture is a small, deliberately lopsided fleet: two healthy web Nodes,
// one quarantined database Node that is also offline, and one Node on a
// different Policy fingerprint. Lopsided because every interesting property of
// these screens is about the minority.
func fleetFixture() Deps {
	d := renderableDeps()
	d.Fleet = fakeFleet{nodes: []registry.Node{
		{
			NodeID:            "node-web-1",
			NodeLabels:        map[string]string{"role": "web", "env": "prod"},
			PolicyFingerprint: "aaaa111122223333",
			DaemonVersion:     "0.6.0",
			Facts:             registry.Facts{Hostname: "web-1", OS: "debian", Kernel: "6.1.0", Arch: "x86_64"},
			LastSeen:          testNow.Add(-4 * time.Second),
			Connected:         true,
		},
		{
			NodeID:            "node-web-2",
			NodeLabels:        map[string]string{"role": "web", "env": "prod"},
			PolicyFingerprint: "aaaa111122223333",
			DaemonVersion:     "0.6.0",
			Facts:             registry.Facts{Hostname: "web-2", OS: "debian"},
			LastSeen:          testNow.Add(-9 * time.Second),
			Connected:         true,
		},
		{
			NodeID:            "node-web-3",
			NodeLabels:        map[string]string{"role": "web", "env": "prod"},
			PolicyFingerprint: "bbbb444455556666",
			DaemonVersion:     "0.6.0",
			Facts:             registry.Facts{Hostname: "web-3", OS: "debian"},
			LastSeen:          testNow.Add(-3 * time.Second),
			Connected:         true,
		},
		{
			NodeID:            "node-db-1",
			NodeLabels:        map[string]string{"role": "db", "env": "prod"},
			RelayLabels:       map[string]string{"quarantine": "on"},
			PolicyFingerprint: "cccc777788889999",
			DaemonVersion:     "0.5.0",
			Facts:             registry.Facts{Hostname: "db-1", OS: "debian"},
			LastSeen:          testNow.Add(-2 * time.Hour),
			// Not connected: this is the fixture's offline, quarantined Node.
		},
	}}
	return d
}

// TestFleet_EmptyRegistryRendersDayOneNotAnEmptyTable is spec 01's "Empty fleet
// → the day-one screen. Do not render an empty table."
//
// The distinction is not cosmetic. Column headings over nothing is a confident
// statement about a fleet — "this works and you have no machines" — made at the
// exact moment the operator has not started and cannot tell a working Relay
// from a broken one.
func TestFleet_EmptyRegistryRendersDayOneNotAnEmptyTable(t *testing.T) {
	d := renderableDeps()
	d.Fleet = fakeFleet{}
	body := get(t, newTestHandler(d, accounts.RoleAdmin), "/console/").Body.String()

	if !strings.Contains(body, "No Nodes have enrolled yet") {
		t.Error("an empty registry did not render the day-one screen")
	}
	if strings.Contains(body, "<thead>") {
		t.Error("an empty registry rendered a table — spec 10 says do not render an empty table")
	}
	if !strings.Contains(body, "Rejected attempts are not shown yet") {
		t.Error("day one did not state that rejected enrollment attempts are invisible — an operator " +
			"must not read an empty fleet as the absence of attempts")
	}
}

// TestFleet_NoFactAppearsOnARowOrInAFacet is the fleet view's acceptance
// criterion, and the one most likely to be broken by a well-meaning change.
//
// Facts are self-reported. A compromised Node can put anything it likes in one,
// so a Fact used as a targeting axis is a targeting axis an attacker can opt
// into. They live on node detail and nowhere else.
func TestFleet_NoFactAppearsOnARowOrInAFacet(t *testing.T) {
	body := get(t, newTestHandler(fleetFixture(), accounts.RoleAdmin), "/console/").Body.String()

	// Hostnames are the one Fact permitted on a row, as a subtitle under the
	// node id — they are how an operator recognises a machine. Everything else
	// must be absent.
	for _, fact := range []string{"debian", "6.1.0", "x86_64"} {
		if strings.Contains(body, fact) {
			t.Errorf("the fleet view rendered the Fact %q — Facts belong on node detail and nowhere else", fact)
		}
	}
}

// TestFleet_DerivesStateAndBucketsTheWall covers the deviation model: offline
// comes from connectedness, quarantine is a declaration rather than a derived
// state, and the pixel wall has exactly four buckets.
func TestFleet_DerivesStateAndBucketsTheWall(t *testing.T) {
	d := fleetFixture()
	v := buildFleetView(d, d.Fleet.List(), "", "role")

	byKey := map[string]fleetGroup{}
	for _, g := range v.Groups {
		byKey[g.Key] = g
	}

	web, ok := byKey["web"]
	if !ok {
		t.Fatalf("no web group; got %v", v.Groups)
	}
	if web.Count != 3 {
		t.Errorf("web group count = %d, want 3", web.Count)
	}
	if web.Offline != 0 {
		t.Errorf("web group offline = %d, want 0 — all three have live Tunnels", web.Offline)
	}
	// One of the three web Nodes reports a different Policy fingerprint. That
	// is DRIFT: an observation counted on the card, never a state label.
	if web.OffMode != 1 {
		t.Errorf("web group off-mode fingerprints = %d, want 1", web.OffMode)
	}

	db := byKey["db"]
	if db.Quarantined != 1 {
		t.Errorf("db group quarantined = %d, want 1", db.Quarantined)
	}
	if db.Offline != 1 {
		t.Errorf("db group offline = %d, want 1 — it has no live Tunnel", db.Offline)
	}
	// The bucket lives on the row now that the wall is fleet-wide; the db group
	// has exactly one Node and it is the quarantined one.
	if len(db.Deviations) != 1 || db.Deviations[0].Bucket != wallFenced {
		t.Errorf("the quarantined Node did not land in the quarantined bucket: %+v", db.Deviations)
	}
}

// TestFleet_OfflineComesFromConnectednessNotLastSeen is worth its own test
// because the bug it prevents is invisible: a Node that reported four seconds
// ago and then dropped its connection renders green while every Task to it
// resolves `unreachable`, and the screen and the dispatcher disagree.
func TestFleet_OfflineComesFromConnectednessNotLastSeen(t *testing.T) {
	d := renderableDeps()
	d.Fleet = fakeFleet{nodes: []registry.Node{{
		NodeID:   "node-a",
		LastSeen: testNow.Add(-1 * time.Second), // seen a heartbeat ago
		// Connected left false: not connected now, despite the recent LastSeen.
	}}}

	v := buildFleetView(d, d.Fleet.List(), "", "-")
	if len(v.Groups) != 1 || v.Groups[0].Offline != 1 {
		t.Fatalf("a Node seen 1s ago but not connected was not rendered offline: %+v", v.Groups)
	}
}

// TestFleet_FilterUsesTheRealSelectorParser is spec 01's central idea: browsing
// trains targeting, so the filter box must be the same language, run through
// the same code. A second parser that agreed today would drift.
func TestFleet_FilterUsesTheRealSelectorParser(t *testing.T) {
	d := fleetFixture()

	v := buildFleetView(d, d.Fleet.List(), "node:role=web", "-")
	if !v.FilterOK {
		t.Fatalf("a valid node: selector was rejected: %s", v.FilterError)
	}
	if v.Matched != 3 {
		t.Errorf("node:role=web matched %d Nodes, want 3", v.Matched)
	}

	v = buildFleetView(d, d.Fleet.List(), "relay:quarantine=on", "-")
	if v.Matched != 1 {
		t.Errorf("relay:quarantine=on matched %d Nodes, want 1", v.Matched)
	}
}

// TestFleet_UnresolvableNamespacesAreRefusedByName covers the honesty rule: a
// filter on `tag:` would match nothing today (no storage until #430), and a
// filter box that silently returns zero rows for a valid-looking term teaches
// an operator that the box is unreliable.
func TestFleet_UnresolvableNamespacesAreRefusedByName(t *testing.T) {
	d := fleetFixture()
	term := "tag:pci"
	v := buildFleetView(d, d.Fleet.List(), term, "-")
	if v.FilterOK {
		t.Errorf("%s was accepted as a filter, but nothing can resolve it yet", term)
	}
	if v.Matched != len(d.Fleet.List()) {
		t.Errorf("%s blanked the fleet — a rejected filter must leave the fleet on screen", term)
	}
	if !strings.Contains(v.FilterError, "#") {
		t.Errorf("the refusal for %q does not name the issue that will fix it: %q", term, v.FilterError)
	}
}

// TestFleet_StateFilterResolvesLikeAnyOtherNamespace is #414's acceptance 1
// at the fleet-view level: a `state:` filter is NOT refused — it resolves
// through the same capability.ParseSelector/Matches every other namespace
// does, and the filtered set is exactly the set carrying the matching chip.
func TestFleet_StateFilterResolvesLikeAnyOtherNamespace(t *testing.T) {
	d := fleetFixture()

	v := buildFleetView(d, d.Fleet.List(), "state:offline", "-")
	if !v.FilterOK {
		t.Fatalf("state:offline was rejected as a filter: %s", v.FilterError)
	}
	if v.Matched != 1 {
		t.Fatalf("state:offline matched %d Nodes, want 1 (node-db-1, the only one not connected)", v.Matched)
	}

	// The drawn set and the targetable set are the same set: every matched
	// Node's row must carry the state:offline chip.
	for _, g := range v.Groups {
		for _, n := range g.Deviations {
			found := false
			for _, s := range n.States {
				if s.Key == string(nodestate.MarkerOffline) {
					found = true
				}
			}
			if !found {
				t.Errorf("Node %q matched state:offline but its row carries no state:offline chip", n.ID)
			}
		}
	}
}

// TestNode_FactsAppearHereAndPolicySaysWhenItIsUnknown covers the two halves of
// spec 02 that are easy to get subtly wrong.
func TestNode_FactsAppearHereAndPolicySaysWhenItIsUnknown(t *testing.T) {
	body := get(t, newTestHandler(fleetFixture(), accounts.RoleAdmin), "/console/nodes/node-web-1").Body.String()

	for _, fact := range []string{"debian", "6.1.0", "x86_64"} {
		if !strings.Contains(body, fact) {
			t.Errorf("node detail is missing the Fact %q — this is the one page they belong on", fact)
		}
	}
	// No policyview snapshot was wired, so the panel must say the Node has not
	// reported rather than render an empty Policy. An empty Policy reads as
	// "this Node permits nothing", which is a different and far more alarming
	// claim than "we have not been told".
	if !strings.Contains(body, "has not reported its Policy") {
		t.Error("the effective-Policy panel did not say the Policy is unreported")
	}
	// The fixture Node has no recorded provenance, so the panel must say which —
	// a missing "expires" row reads as the reassuring answer.
	if !strings.Contains(body, "certificate provenance is not recorded") {
		t.Error("node detail did not state the certificate-provenance gap — a missing expiry row reads as 'fine'")
	}
}

// queueRows builds the queue's rows for a caller with no identity and no
// Grants, which is what most ordering and grouping tests are about.
func queueRows(reqs []approval.Request) []approvalRow {
	return buildApprovalRows(reqs, nil, capability.Principal{}, testNow)
}

// TestApprovals_OrderIsByDurationNotTheRenderedString is spec 14's ordering
// rule, and the bug it pins is a real one: the sort key was the RENDERED TTL,
// so "10m left" < "12h left" < "5m left" < "9m left" lexicographically and the
// most urgent request in the queue sorted into the middle of it.
//
// An approval that lapses because it sat below the fold is a failure of this
// screen, and a sort on the display string is exactly how that happens without
// anybody noticing.
func TestApprovals_OrderIsByDurationNotTheRenderedString(t *testing.T) {
	rows := queueRows([]approval.Request{
		{ID: "twelve-hours", CreatedAt: testNow, ExpiresAt: testNow.Add(12 * time.Hour), Require: approval.Requirement{Count: 1}},
		{ID: "five-minutes", CreatedAt: testNow, ExpiresAt: testNow.Add(5 * time.Minute), Require: approval.Requirement{Count: 1}},
		{ID: "nine-minutes", CreatedAt: testNow, ExpiresAt: testNow.Add(9 * time.Minute), Require: approval.Requirement{Count: 1}},
		{ID: "ten-minutes", CreatedAt: testNow, ExpiresAt: testNow.Add(10 * time.Minute), Require: approval.Requirement{Count: 1}},
	})

	want := []string{"five-minutes", "nine-minutes", "ten-minutes", "twelve-hours"}
	for i, id := range want {
		if rows[i].ID != id {
			t.Fatalf("row %d is %s, want %s — the queue is ordered on the DURATION, not on the string it renders",
				i, rows[i].ID, id)
		}
	}
	if !rows[0].Urgent {
		t.Error("a request expiring in 5 minutes is not marked urgent")
	}
	if rows[3].Urgent {
		t.Error("a request with 12 hours left is marked urgent")
	}
}

// TestApprovals_LapsedSortsLastAndSaysSo reverses what this screen used to do.
// A lapsed request cannot be decided by anyone; putting it first pushes the
// decidable ones below the fold, which is the precise failure spec 14 names.
func TestApprovals_LapsedSortsLastAndSaysSo(t *testing.T) {
	rows := queueRows([]approval.Request{
		{ID: "already-lapsed", CreatedAt: testNow.Add(-2 * time.Hour), ExpiresAt: testNow.Add(-time.Minute), Require: approval.Requirement{Count: 1}},
		{ID: "five-minutes", CreatedAt: testNow, ExpiresAt: testNow.Add(5 * time.Minute), Require: approval.Requirement{Count: 1}},
	})

	if rows[0].ID != "five-minutes" {
		t.Errorf("first row is %s, want five-minutes — a lapsed request sorts LAST", rows[0].ID)
	}
	if !rows[1].Lapsed || rows[1].TTL != "expired" {
		t.Errorf("the lapsed row does not say so: lapsed=%v ttl=%q", rows[1].Lapsed, rows[1].TTL)
	}
}

// TestApprovals_QueueOffersNoApproveControl is spec 14's hard rule. A row-level
// Approve lets someone approve without seeing what they approved, which is the
// entire failure the mechanism exists to prevent.
func TestApprovals_QueueOffersNoApproveControl(t *testing.T) {
	d := renderableDeps()
	d.Approvals = &fakeApprovals{pending: []approval.Request{{
		ID: "ap-1", Summary: "restart nginx on 412 Nodes",
		CreatedAt: testNow, ExpiresAt: testNow.Add(time.Hour),
		Require: approval.Requirement{Count: 2},
	}}}
	h := newTestHandler(d, accounts.RoleAdmin)
	body := get(t, h, "/console/approvals").Body.String()

	// Scoped to each screen's own content. The layout carries a sign-out form,
	// which is a mutating route and is meant to be there — the assertion is
	// about what the QUEUE and the CARD offer, not about the shell around them.
	for _, path := range []string{"/console/approvals", "/console/approvals/ap-1"} {
		content := contentOf(get(t, h, path).Body.String())
		for _, control := range []string{"<form", "<button", "<input"} {
			if strings.Contains(content, control) {
				t.Errorf("%s rendered %s — v0.6.0 is read-only on both approval screens, and every "+
					"filter is an anchor", path, control)
			}
		}
	}
	if !strings.Contains(body, "restart nginx on 412 Nodes") {
		t.Error("the queue did not render the Relay-authored summary")
	}
}

// TestApprovals_EmptyQueueSaysSoPlainly — an empty approval queue is good news,
// not a blank screen.
func TestApprovals_EmptyQueueSaysSoPlainly(t *testing.T) {
	d := renderableDeps()
	d.Approvals = &fakeApprovals{}
	body := get(t, newTestHandler(d, accounts.RoleAdmin), "/console/approvals").Body.String()
	if !strings.Contains(body, "Nothing is waiting") {
		t.Error("an empty approval queue did not say so")
	}
}

// TestBanner_FreezeStatesWhatIsStillTrue — an emergency stop that reads as a
// total outage gets released in a panic by the next person to look at it.
func TestBanner_FreezeStatesWhatIsStillTrue(t *testing.T) {
	d := fleetFixture()
	d.Freeze = fakeFreeze{frozen: true}
	body := get(t, newTestHandler(d, accounts.RoleAdmin), "/console/").Body.String()

	if !strings.Contains(body, "Freeze engaged") {
		t.Fatal("an engaged Freeze produced no banner")
	}
	if !strings.Contains(body, "In-flight Tasks keep running") {
		t.Error("the Freeze banner does not say what is still true")
	}
}

// TestBanner_UnreadableFreezeIsNotReportedAsUnfrozen — the whole value of an
// emergency stop is that its state is never guessed.
func TestBanner_UnreadableFreezeIsNotReportedAsUnfrozen(t *testing.T) {
	d := fleetFixture()
	d.Freeze = fakeFreeze{err: constErr("store unavailable")}
	body := get(t, newTestHandler(d, accounts.RoleAdmin), "/console/").Body.String()

	if !strings.Contains(body, "could not be read") {
		t.Error("an unreadable Freeze rendered no banner — silence here reads as 'not frozen'")
	}
}

// TestScreens_UnwiredSeamRefusesRatherThanRenderingEmpty is the whole reason
// unavailable() exists. An empty fleet view is a claim about the fleet.
func TestScreens_UnwiredSeamRefusesRatherThanRenderingEmpty(t *testing.T) {
	h := newTestHandler(Deps{}, accounts.RoleAdmin)
	rec := get(t, h, "/console/")
	if rec.Code != http.StatusInternalServerError {
		t.Errorf("the fleet view with no registry wired = %d, want 500", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "not an empty fleet") {
		t.Error("the refusal does not distinguish a wiring problem from an empty fleet")
	}
}

// TestScreens_NoInlineScriptSurvivesAnywhere extends the shell's CSP guarantee
// across every new screen. The content security policy admits no inline script,
// so an `hx-on:` attribute — which IS script — would be silently dead rather
// than merely non-conforming.
func TestScreens_NoInlineScriptSurvivesAnywhere(t *testing.T) {
	d := withExecution(fleetFixture(), true)
	d.Approvals = &fakeApprovals{pending: []approval.Request{{ID: "ap-1", ExpiresAt: testNow.Add(time.Hour), Require: approval.Requirement{Count: 1}}}}
	d.Audit = fakeAudit{records: []audit.Record{{Kind: audit.KindDispatch, JobID: "job-1", NodeID: "node-web-1", OperationName: "service.restart", Timestamp: testNow}}}
	// Job detail reads through the capability layer's query lane and refuses
	// rather than rendering an empty Job when it is not wired (#423), so this
	// cross-screen sweep has to wire it to reach the screen at all.
	d.Queries = &fakeQueries{
		jobs: []capability.JobSummary{{
			JobID: "job-1", CreatedAt: testNow, OperationName: "service.restart",
			RiskClass: jobs.RiskClassMutate, Total: 1,
			Counts: map[jobs.Outcome]int{jobs.OutcomeSuccess: 1},
		}},
		tasks: []capability.TaskRow{{
			TaskID: "task-1", NodeID: "node-web-1", Outcome: jobs.OutcomeSuccess,
			RiskClass: jobs.RiskClassMutate, Stdout: []byte("restarted"),
		}},
		rows: []capability.AuditRow{{Kind: audit.KindDispatch, JobID: "job-1", OperationName: "service.restart"}},
	}
	h := newTestHandler(d, accounts.RoleAdmin)

	// Derived from the mounted route table (walkableScreens), so a screen
	// added later is swept without anyone remembering to add it here.
	var renders []struct {
		name    string
		handler http.Handler
		path    string
	}
	for _, path := range walkableScreens(Routes(d), fixtureIDs) {
		renders = append(renders, struct {
			name    string
			handler http.Handler
			path    string
		}{path, h, path})
	}
	if len(renders) < 8 {
		t.Fatalf("the sweep derived only %d screens — it is not walking the route table", len(renders))
	}

	// A SECOND rendering of "/console/", with a zero-Node fleet and the event
	// seam wired, so the sweep actually walks the one screen in the package
	// that loads a script. Every other fixture here wires Nodes, so the fleet
	// view renders and day one never does — which is why this needs its own
	// entry rather than another path.
	renders = append(renders, struct {
		name    string
		handler http.Handler
		path    string
	}{"/console/ (day one)", newTestHandler(dayOneDeps(), accounts.RoleAdmin), "/console/"})

	for _, r := range renders {
		path := r.name
		rec := get(t, r.handler, r.path)
		if rec.Code != http.StatusOK {
			t.Errorf("GET %s = %d, want 200", path, rec.Code)
			continue
		}
		body := rec.Body.String()
		assertNoInlineScript(t, path, body)
		if strings.Contains(body, "hx-on:") {
			t.Errorf("%s rendered an hx-on: attribute, which IS script and would be dead under the CSP", path)
		}
		for _, handler := range []string{" onclick=", " onload=", " onerror=", " onfocus="} {
			if strings.Contains(body, handler) {
				t.Errorf("%s rendered %q — an event-handler attribute is inline script", path, handler)
			}
		}
		// An inline STYLE is blocked by `style-src 'self'` exactly as an inline
		// script is blocked by `script-src 'self'` — and it fails far more
		// quietly, because the element still renders, just unstyled.
		//
		// This assertion exists because the outcome bar shipped with
		// style="width:N%" and every segment painted at zero width: the bar the
		// specification calls "the entire reason anyone is looking" had never
		// once been visible. The Go tests all passed, because they asserted the
		// segment was in the HTML and it was.
		if strings.Contains(body, `style="`) || strings.Contains(body, "style='") {
			t.Errorf("%s rendered an inline style attribute — the content security policy discards it, "+
				"so the element renders unstyled and nothing says so. Use a class or a data attribute.", path)
		}
	}
}

// contentOf extracts a page's screen content, excluding the shell.
//
// The shell legitimately holds one mutating control — sign out — so an
// assertion about what a SCREEN offers has to be scoped, or it tests the
// layout and passes or fails for the wrong reason.
func contentOf(body string) string {
	const open = `<main id="content">`
	i := strings.Index(body, open)
	if i < 0 {
		return body
	}
	rest := body[i+len(open):]
	if j := strings.Index(rest, "</main>"); j >= 0 {
		return rest[:j]
	}
	return rest
}

// TestFleet_SmallHealthyFleetStillShowsItsNodes is the regression guard for the
// bug the dev fleet found: three healthy Nodes compressed to two one-line cards
// and the operator was shown nothing at all.
//
// "A list is a bug" is a claim about ten thousand Nodes. At three, the list is
// the answer, and spec 01 says so in its small-fleet clause — "the deviation
// table simply IS the fleet. Nothing special-cased."
func TestFleet_SmallHealthyFleetStillShowsItsNodes(t *testing.T) {
	d := renderableDeps()
	d.Fleet = fakeFleet{nodes: []registry.Node{
		{NodeID: "node-a", NodeLabels: map[string]string{"role": "web"}, PolicyFingerprint: "same", Connected: true},
		{NodeID: "node-b", NodeLabels: map[string]string{"role": "web"}, PolicyFingerprint: "same", Connected: true},
	}}

	v := buildFleetView(d, d.Fleet.List(), "", "role")
	g := v.Groups[0]

	if !g.Open {
		t.Fatal("a small, entirely healthy group compressed to one line — the operator sees nothing")
	}
	if !g.ListsWholeFleet {
		t.Error("the group did not mark itself as listing the whole fleet")
	}
	if len(g.Deviations) != 2 {
		t.Errorf("the table holds %d rows, want 2 — at this size the table is the fleet", len(g.Deviations))
	}

	body := get(t, newTestHandler(d, accounts.RoleAdmin), "/console/").Body.String()
	for _, id := range []string{"node-a", "node-b"} {
		if !strings.Contains(body, id) {
			t.Errorf("a healthy two-Node fleet did not render %s", id)
		}
	}
}

// TestFleet_LargeHealthyGroupStillCompresses is the other half of the same rule:
// the compression exists, and it must still apply where it was designed to.
func TestFleet_LargeHealthyGroupStillCompresses(t *testing.T) {
	var nodes []registry.Node
	for i := 0; i < legibleGroup+10; i++ {
		id := "node-" + itoa(i)
		nodes = append(nodes, registry.Node{
			NodeID: id, NodeLabels: map[string]string{"role": "web"}, PolicyFingerprint: "same", Connected: true,
		})
	}
	d := renderableDeps()
	d.Fleet = fakeFleet{nodes: nodes}

	v := buildFleetView(d, d.Fleet.List(), "", "role")
	if v.Groups[0].Open {
		t.Error("a large, entirely healthy group did not compress to one line")
	}
}

// TestOutcomeBar_SegmentsCarryAVisibleWeight is the unit-level half of the same
// bug: every segment that exists must render wide enough to see.
//
// The floor exists because 14 denies in 10,000 Nodes is 0.14% of the bar and
// they are the entire reason anyone opened the page. A quantisation that
// rounded them back to nothing would undo the component.
func TestOutcomeBar_SegmentsCarryAVisibleWeight(t *testing.T) {
	bar := NewOutcomeBar([]OutcomeCount{
		{Outcome: jobs.OutcomeSuccess, Count: 9986},
		{Outcome: jobs.OutcomeDeniedByPolicy, Count: 14},
	})

	total := 0
	for _, seg := range bar.Segments {
		if seg.Grow < 1 {
			t.Errorf("segment %s has flex weight %d — a segment that exists must be visible", seg.Label, seg.Grow)
		}
		total += seg.Grow
	}

	var denied Segment
	for _, seg := range bar.Segments {
		if seg.Outcome == jobs.OutcomeDeniedByPolicy {
			denied = seg
		}
	}
	// 14 in 10,000 is 0.14%; the floor lifts it to 2.5%, which at 200 steps is
	// 5. Anything at or near 1 means the floor was lost in the rounding.
	if denied.Grow < 4 {
		t.Errorf("the 14 denies got flex weight %d of %d — the minority floor did not survive quantisation",
			denied.Grow, total)
	}
	if denied.Percent > 1 {
		t.Errorf("Percent is %.2f, want the TRUE 0.14%% share — Percent must never be the floored value", denied.Percent)
	}
}

// TestActivity_NodeRevokeKeepsItsNode is the surviving, falsifiable half of the
// old "a Job row carries no single Node" test. A Job row cannot name a Node —
// capability.JobSummary has no such field, so the assertion became a tautology
// once the dispatch lane moved to QueryJobs. A node_revoke IS about one Node
// and must keep its link, and that can still break.
func TestActivity_NodeRevokeKeepsItsNode(t *testing.T) {
	row := eventRowFromTrail(factsOfRow(capability.AuditRow{
		Kind: audit.KindNodeRevoke, NodeID: "n3", Timestamp: testNow,
	}))
	if row.NodeID != "n3" || row.NodeHref != "/console/nodes/n3" {
		t.Errorf("the node_revoke row lost its Node: %+v", row)
	}
}

// TestVocab_RiskClassInference is the guard for the pair of errors the dev fleet
// exposed at once: `file.read` rendered as a mutate, and a parked `raw_exec`
// rendered as a read.
//
// The second is the serious one. Raw Exec ALWAYS takes the mutate cap
// (ADR-0012), and a Console that shows it as a read has told an operator the
// blast radius was small when it was the largest the product allows.
func TestVocab_RiskClassInference(t *testing.T) {
	cases := []struct {
		name string
		rec  audit.Record
		want jobs.RiskClass
	}{
		{"file.read is a read even though it dispatches",
			audit.Record{Kind: audit.KindDispatch, OperationName: "file.read"}, jobs.RiskClassRead},
		{"system.facts is a read",
			audit.Record{Kind: audit.KindDispatch, OperationName: "system.facts"}, jobs.RiskClassRead},
		{"service.restart is a mutate",
			audit.Record{Kind: audit.KindDispatch, OperationName: "service.restart"}, jobs.RiskClassMutate},
		{"raw exec with argv is always a mutate",
			audit.Record{Kind: audit.KindDispatch, RawExecArgv: []string{"/bin/systemctl", "status", "nginx"}}, jobs.RiskClassMutate},
		{"raw exec PARKED, with no argv retained, is still a mutate",
			audit.Record{Kind: audit.KindApprovalRequested, ActionKind: "raw_exec"}, jobs.RiskClassMutate},
		{"a registry read tool is a read",
			audit.Record{Kind: audit.KindRead, ActionKind: "list_nodes"}, jobs.RiskClassRead},
		{"an unknown Operation is treated as a mutate",
			audit.Record{Kind: audit.KindDispatch, OperationName: "customer.template.thing"}, jobs.RiskClassMutate},
		{"file.checksum is a read (shipped read catalog, issue #461)",
			audit.Record{Kind: audit.KindDispatch, OperationName: "file.checksum"}, jobs.RiskClassRead},
		{"pkg.inventory is a read (shipped read catalog, issue #461)",
			audit.Record{Kind: audit.KindDispatch, OperationName: "pkg.inventory"}, jobs.RiskClassRead},
		{"file.stat is a mutate: it ships nowhere in /proto or daemon/, so it is an unknown Operation, not a read",
			audit.Record{Kind: audit.KindDispatch, OperationName: "file.stat"}, jobs.RiskClassMutate},
	}
	for _, c := range cases {
		if got := riskOf(factsOfRecord(c.rec)); got != c.want {
			t.Errorf("%s: riskOf = %s, want %s", c.name, RiskLabel(got), RiskLabel(c.want))
		}
	}
}

// TestVocab_DenyExplanationDoesNotBlameTheDaemonForADeliberateOmission.
//
// A read-class Task's deny reason is gone because ADR-0025 says read output is
// never retained, and the daemon explains a refusal in that output. Rendering
// "the daemon did not report the deciding rule" there blames the daemon for the
// Relay correctly declining to store something.
func TestVocab_DenyExplanationDoesNotBlameTheDaemonForADeliberateOmission(t *testing.T) {
	readDeny := audit.Record{Kind: audit.KindDispatch, OperationName: "file.read", Outcome: jobs.OutcomeDeniedByPolicy}
	got := denyExplanation(readDeny)
	if strings.Contains(got, "did not report") {
		t.Errorf("a read-class deny blames the daemon:\n%s", got)
	}
	if !strings.Contains(got, "not retained") && !strings.Contains(got, "not recorded") {
		t.Errorf("a read-class deny does not explain WHY the rule is absent:\n%s", got)
	}

	mutateDeny := audit.Record{Kind: audit.KindDispatch, OperationName: "service.restart", Outcome: jobs.OutcomeDeniedByPolicy}
	if got := denyExplanation(mutateDeny); !strings.Contains(got, "did not report") {
		t.Errorf("a mutate-class deny with no stderr should say the daemon did not report it:\n%s", got)
	}

	verbatim := audit.Record{Kind: audit.KindDispatch, OperationName: "service.restart",
		Outcome: jobs.OutcomeDeniedByPolicy, Stderr: []byte("denied by explicit rule for operation 'service.restart'\n")}
	if got := denyExplanation(verbatim); got != "denied by explicit rule for operation 'service.restart'" {
		t.Errorf("the daemon's verdict was not rendered verbatim: %q", got)
	}
}

// TestAgents_ParkedCallsDoNotRenderAsAnUnspecifiedOutcome — a parked dispatch
// has a perfectly well known outcome, and "unspecified" reads as "we don't
// know".
func TestAgents_ParkedCallsDoNotRenderAsAnUnspecifiedOutcome(t *testing.T) {
	_, calls, _ := buildAgents([]audit.Record{
		{Kind: audit.KindApprovalRequested, ActionKind: "raw_exec", Principal: "agent:operator", Timestamp: testNow},
	}, "", testNow)

	if len(calls) != 1 {
		t.Fatalf("got %d calls, want 1", len(calls))
	}
	if calls[0].Outcome == "unspecified" {
		t.Error("a parked dispatch rendered outcome 'unspecified'")
	}
	if calls[0].Outcome != "parked" {
		t.Errorf("outcome = %q, want \"parked\"", calls[0].Outcome)
	}
	if calls[0].Risk != "mutate" {
		t.Errorf("a parked raw_exec rendered risk %q — Raw Exec always takes the mutate cap", calls[0].Risk)
	}
}

// TestNode_RepeatedDeniesExplainThemselvesOnce — the same rule refusing the same
// read every hour is one fact, not twenty, and twenty identical explanations
// bury the Policy panel the operator came for.
//
// The row itself is never dropped: only the duplicated prose is, and the outcome
// chip stays, so nothing about what happened is hidden.
func TestNode_RepeatedDeniesExplainThemselvesOnce(t *testing.T) {
	var recs []audit.Record
	for i := 0; i < 5; i++ {
		recs = append(recs, audit.Record{
			Kind: audit.KindDispatch, NodeID: "node-web-1", OperationName: "service.restart",
			Args: map[string]string{"unit": "sshd"}, Outcome: jobs.OutcomeDeniedByPolicy,
			Stderr: []byte("denied by explicit rule for operation 'service.restart'"), Timestamp: testNow,
		})
	}
	d := fleetFixture()
	d.Audit = fakeAudit{records: recs}

	rec := get(t, newTestHandler(d, accounts.RoleAdmin), "/console/nodes/node-web-1")
	body := rec.Body.String()

	if n := strings.Count(body, `class="deny"`); n != 1 {
		t.Errorf("the same rule rendered %d deny blocks, want 1", n)
	}
	if n := strings.Count(body, "Same rule as above"); n != 4 {
		t.Errorf("got %d repeat markers, want 4 — every row must still be visible", n)
	}
	if n := strings.Count(body, `data-outcome="denied_by_policy"`); n < 5 {
		t.Errorf("only %d rows carry a denied chip; all 5 must, or the page hides what happened", n)
	}
}

// TestFleet_OneWallForTheWholeFleet is the acceptance criterion read literally:
// "one segmented summary, ONE pixel wall, and the deviating rows".
//
// The first build put a wall inside every group card. At three Nodes that is
// three specks nobody sees; at ten thousand across forty groups it is forty
// images nobody can compare. The wall's whole value is being one picture of the
// system.
func TestFleet_OneWallForTheWholeFleet(t *testing.T) {
	d := fleetFixture()
	v := buildFleetView(d, d.Fleet.List(), "", "role")

	if len(v.Wall) != 2 {
		t.Fatalf("the wall has %d groups, want 2 (web, db)", len(v.Wall))
	}
	total := 0
	for _, g := range v.Wall {
		total += len(g.Nodes)
	}
	if total != 4 {
		t.Errorf("the wall draws %d cells for a 4-Node fleet, want 4", total)
	}

	body := get(t, newTestHandler(d, accounts.RoleAdmin), "/console/").Body.String()
	if n := strings.Count(body, `class="wall"`); n != 1 {
		t.Errorf("the page renders %d walls, want exactly 1", n)
	}
	if !strings.Contains(body, "System state") {
		t.Error("the wall is not introduced as system state")
	}
}

// TestFleet_WallLegendCountsEveryBucketAndLeadsWithTheWorst.
//
// The quarantined Node is the reason the wall exists. A legend sorted by count
// would put it last, because it is rare — which is precisely why it matters.
func TestFleet_WallLegendCountsEveryBucketAndLeadsWithTheWorst(t *testing.T) {
	d := fleetFixture()
	v := buildFleetView(d, d.Fleet.List(), "", "role")

	if len(v.Legend) == 0 {
		t.Fatal("the wall has no legend")
	}
	if v.Legend[0].Bucket != wallFenced {
		t.Errorf("the legend leads with %q, want fenced — rarity is not unimportance", v.Legend[0].Bucket)
	}

	byBucket := map[wallBucket]int{}
	for _, l := range v.Legend {
		byBucket[l.Bucket] = l.Count
	}
	if byBucket[wallFenced] != 1 {
		t.Errorf("legend counts %d fenced, want 1", byBucket[wallFenced])
	}
	if byBucket[wallNormal] != 3 {
		t.Errorf("legend counts %d normal, want 3", byBucket[wallNormal])
	}
	sum := 0
	for _, l := range v.Legend {
		sum += l.Count
	}
	if sum != v.Matched {
		t.Errorf("the legend accounts for %d Nodes but %d matched — every Node is in exactly one bucket", sum, v.Matched)
	}
}

// TestFleet_CellScaleAdaptsToFleetSize — a fixed cell cannot serve three Nodes
// and ten thousand. The scale is a class because the CSP discards inline styles.
func TestFleet_CellScaleAdaptsToFleetSize(t *testing.T) {
	for _, c := range []struct {
		n    int
		want string
	}{{3, "lg"}, {24, "lg"}, {25, "md"}, {150, "md"}, {151, "sm"}, {1500, "sm"}, {10000, "xs"}} {
		if got := cellSize(c.n); got != c.want {
			t.Errorf("cellSize(%d) = %q, want %q", c.n, got, c.want)
		}
	}
}

// TestFleet_RevokedNodeIsVisibleAndDistinctFromOffline is the review's first and
// worst finding: the registry keeps a revoked Node's record — deliberately, so
// it stays investigable and its audit history stays answerable — and the fleet
// view dropped the field entirely.
//
// The consequence was not cosmetic. A revoked Node rendered identically to
// `state:offline`, so an operator would raise a ticket against a machine nobody
// will ever reach again.
func TestFleet_RevokedNodeIsVisibleAndDistinctFromOffline(t *testing.T) {
	revokedAt := testNow.Add(-3 * time.Hour)
	d := renderableDeps()
	d.Fleet = fakeFleet{nodes: []registry.Node{
		{NodeID: "node-revoked", NodeLabels: map[string]string{"role": "web"}, RevokedAt: revokedAt},
		{NodeID: "node-offline", NodeLabels: map[string]string{"role": "web"}},
		{NodeID: "node-fine", NodeLabels: map[string]string{"role": "web"}, Connected: true},
	}}

	v := buildFleetView(d, d.Fleet.List(), "", "role")
	g := v.Groups[0]

	if g.Revoked != 1 {
		t.Errorf("the rollup card counts %d revoked, want 1", g.Revoked)
	}

	byID := map[string]fleetNode{}
	for _, n := range g.Deviations {
		byID[n.ID] = n
	}
	if !byID["node-revoked"].Revoked {
		t.Fatal("the revoked Node does not report itself revoked")
	}
	// The distinction the finding is about: revoked and offline must not land
	// in the same bucket, or the wall says a deliberate irreversible act and a
	// dead power supply are the same thing.
	if byID["node-revoked"].Bucket != wallFenced {
		t.Errorf("revoked landed in %q, want fenced", byID["node-revoked"].Bucket)
	}
	if byID["node-offline"].Bucket != wallAttention {
		t.Errorf("offline landed in %q, want attention", byID["node-offline"].Bucket)
	}
	if byID["node-revoked"].signature == byID["node-offline"].signature {
		t.Error("revoked and offline share a deviation signature — they would collapse into one ladder rung")
	}

	body := get(t, newTestHandler(d, accounts.RoleAdmin), "/console/").Body.String()
	if !strings.Contains(body, ">revoked<") {
		t.Error("the fleet view does not say the Node is revoked")
	}
	// It must remain reachable: the whole reason the record is retained is that
	// somebody needs to go and look at it.
	if !strings.Contains(body, "/console/nodes/node-revoked") {
		t.Error("the revoked Node is not linked — the record is kept precisely so it can be investigated")
	}
}

// TestFleet_DeviatingRowsLeadEvenWhenTheyAreTheMajority.
//
// Sorting on rarity alone inverts the table whenever the deviating Nodes
// outnumber the healthy ones: a normal Node's rarity is the count of normal
// Nodes, so the calm rows lead and the incident sits below them.
func TestFleet_DeviatingRowsLeadEvenWhenTheyAreTheMajority(t *testing.T) {
	var nodes []registry.Node
	for i := 0; i < 8; i++ { // offline: the majority
		nodes = append(nodes, registry.Node{NodeID: "off-" + itoa(i), NodeLabels: map[string]string{"role": "web"}})
	}
	for i := 0; i < 2; i++ { // healthy: the minority
		id := "ok-" + itoa(i)
		nodes = append(nodes, registry.Node{NodeID: id, NodeLabels: map[string]string{"role": "web"}, Connected: true})
	}
	d := renderableDeps()
	d.Fleet = fakeFleet{nodes: nodes}

	v := buildFleetView(d, d.Fleet.List(), "", "role")
	rows := v.Groups[0].Deviations

	if len(rows) != 10 {
		t.Fatalf("got %d rows, want all 10", len(rows))
	}
	if rows[0].signature == "" {
		t.Errorf("row one is a healthy Node (%s) in a table captioned \"oddest first\"", rows[0].ID)
	}
	for i, n := range rows[:8] {
		if n.signature == "" {
			t.Errorf("row %d is healthy but 8 deviating Nodes exist — deviations must lead", i)
		}
	}
}

// TestFleet_HighCardinalityGroupingDoesNotRebuildTheList.
//
// "A list is a bug" is a claim about the page, not about one card. Deciding it
// per group let a thousand-valued label key produce a thousand open cards of ten
// rows each — verbatim the acceptance criterion this screen must satisfy.
func TestFleet_HighCardinalityGroupingDoesNotRebuildTheList(t *testing.T) {
	var nodes []registry.Node
	for i := 0; i < 600; i++ {
		id := "node-" + itoa(i)
		// One distinct group value per three Nodes: 200 groups.
		nodes = append(nodes, registry.Node{
			NodeID: id, NodeLabels: map[string]string{"shard": "s" + itoa(i/3)},
			PolicyFingerprint: "same",
			Connected:         true,
		})
	}
	d := renderableDeps()
	d.Fleet = fakeFleet{nodes: nodes}

	v := buildFleetView(d, d.Fleet.List(), "", "shard")

	if len(v.Groups) > groupCards {
		t.Errorf("rendered %d group cards, want at most %d", len(v.Groups), groupCards)
	}
	if v.GroupsElided == 0 {
		t.Error("groups were dropped without saying so — a truncated page that looks complete is the worse failure")
	}
	for _, g := range v.Groups {
		if g.ListsWholeFleet {
			t.Fatalf("group %q lists every Node on a 600-Node fleet — the whole-fleet listing is a PAGE decision", g.Key)
		}
	}
}

// TestFleet_StateChipsCarryTheirSeverity — one grey for every derived state says
// "refuses every Task" and "template set failed to load" are the same problem.
func TestFleet_StateChipsCarryTheirSeverity(t *testing.T) {
	d := renderableDeps()
	d.Fleet = fakeFleet{nodes: []registry.Node{{
		NodeID:                 "node-a",
		TemplateSetFingerprint: nodestate.TemplateUnloadable,
		// Connected left false: offline.
	}}}

	v := buildFleetView(d, d.Fleet.List(), "", "-")
	bySeverity := map[string]bool{}
	for _, c := range v.Groups[0].Deviations[0].States {
		bySeverity[c.Key] = c.Attention
	}
	if !bySeverity[string(nodestate.MarkerOffline)] {
		t.Error("state:offline is not marked as needing attention — every dispatch to it returns unreachable")
	}
	if bySeverity[string(nodestate.MarkerTemplateUnloadable)] {
		t.Error("state:template-unloadable is marked as needing attention — it is inertness, not an alarm")
	}

	body := get(t, newTestHandler(d, accounts.RoleAdmin), "/console/").Body.String()
	if !strings.Contains(body, `data-sev="attention"`) {
		t.Error("no state chip renders its severity")
	}
}

// TestFleet_CertExpiringMarkerFires is #414's positive case: a Node whose
// identity certificate has fallen inside the configured warning window
// carries state:cert-expiring — chipped on its own row, counted in its
// group's rollup line, and sorted into the attention bucket — exactly like
// the other alarm markers.
func TestFleet_CertExpiringMarkerFires(t *testing.T) {
	d := renderableDeps()
	d.CertExpiringWithin = 84 * time.Hour
	d.Fleet = fakeFleet{nodes: []registry.Node{
		{NodeID: "node-a", Connected: true, CertNotAfter: testNow.Add(10 * time.Hour)},
	}}

	v := buildFleetView(d, d.Fleet.List(), "", "-")
	g := v.Groups[0]
	if g.Expiring != 1 {
		t.Fatalf("group Expiring = %d, want 1", g.Expiring)
	}
	n := g.Deviations[0]
	found := false
	for _, s := range n.States {
		if s.Key == string(nodestate.MarkerCertExpiring) {
			found = true
			if !s.Attention {
				t.Error("the state:cert-expiring chip does not carry Attention")
			}
		}
	}
	if !found {
		t.Error("a Node inside the cert-expiring window does not carry the state:cert-expiring chip")
	}
	if n.Bucket != wallAttention {
		t.Errorf("Node bucket = %q, want %q (state:cert-expiring is an alarm)", n.Bucket, wallAttention)
	}

	body := get(t, newTestHandler(d, accounts.RoleAdmin), "/console/").Body.String()
	if !strings.Contains(body, "certificate expiring") {
		t.Error("the group card does not render the certificate-expiring rollup line")
	}
}

// TestFleet_NamesTheNodesWithNoRecordedValidity covers the second, conditional
// half of the same note: Nodes that enrolled before #440 and have not renewed
// have no CertNotAfter at all, and the screen counts them rather than implying
// the gap is fleet-wide. The fixture sets validity on none of its four.
func TestFleet_NamesTheNodesWithNoRecordedValidity(t *testing.T) {
	body := get(t, newTestHandler(fleetFixture(), accounts.RoleAdmin), "/console/").Body.String()
	if !strings.Contains(body, "4 Nodes here") || !strings.Contains(body, "no recorded validity at all") {
		t.Error("the note does not count the Nodes whose certificate validity is unrecorded")
	}
}

// TestFleet_SilentAboutValidityWhenEveryNodeHasIt is the other side: with
// CertNotAfter on every matched Node there is no data gap to report, so the
// gap note must not render at all — silence is the correct answer once the
// judgement can be complete, exactly as it is for every other clean marker.
func TestFleet_SilentAboutValidityWhenEveryNodeHasIt(t *testing.T) {
	d := fleetFixture()
	f := d.Fleet.(fakeFleet)
	nodes := make([]registry.Node, len(f.nodes))
	copy(nodes, f.nodes)
	for i := range nodes {
		nodes[i].CertNotAfter = testNow.Add(30 * 24 * time.Hour)
	}
	d.Fleet = fakeFleet{nodes: nodes}

	body := get(t, newTestHandler(d, accounts.RoleAdmin), "/console/").Body.String()
	if strings.Contains(body, "no recorded validity at all") {
		t.Error("the fleet view reports a validity gap when every Node has recorded validity")
	}
}

// TestFleet_EveryWallBucketHasAColour is a structural guard against exactly the
// drift that shipped: the bucket constant was renamed from "quarantined" to
// "fenced" and its CSS rule was not, so fenced cells rendered with no
// background at all — invisible, on the one bucket the wall exists to make
// impossible to miss.
//
// Nothing in Go could catch it. The constant compiled, the attribute rendered,
// the tests passed, and the cell was simply not there on screen. This asserts
// the two halves agree.
func TestFleet_EveryWallBucketHasAColour(t *testing.T) {
	css := get(t, newTestHandler(renderableDeps(), accounts.RoleAdmin),
		"/console/assets/console.css").Body.String()

	for _, b := range []wallBucket{wallNormal, wallDrift, wallAttention, wallFenced} {
		rule := `.cell[data-bucket="` + string(b) + `"]`
		if !strings.Contains(css, rule) {
			t.Errorf("no stylesheet rule for %s — cells in this bucket render with no colour, "+
				"which no Go test can see", rule)
		}
	}

	// And the reverse: a rule for a bucket that no longer exists is dead weight
	// that hides the missing one.
	for _, stale := range []string{"quarantined", "warning", "error"} {
		if strings.Contains(css, `.cell[data-bucket="`+stale+`"]`) {
			t.Errorf("stylesheet still styles the retired bucket %q", stale)
		}
	}
}

// TestFleet_WallIsOneImageToAssistiveTechnology is the shape decision for the
// pixel wall: clickable with a mouse, absent from the tab order.
//
// The alternative shipped first and was worse than either principled option —
// role="img" on the container with nameless FOCUSABLE links inside it. At
// 10,000 Nodes that is 10,000 unnamed tab stops within an element declaring
// itself a single image. Ten thousand nameless tab stops is not access.
//
// The accessible path is the deviation table: named, ordered, and complete for
// every Node that deviates, which is every Node anyone needs to reach.
func TestFleet_WallIsOneImageToAssistiveTechnology(t *testing.T) {
	body := get(t, newTestHandler(fleetFixture(), accounts.RoleAdmin), "/console/").Body.String()

	wall := body[strings.Index(body, `<div class="wall"`):]
	wall = wall[:strings.Index(wall, "</div>\n  </div>")]

	if !strings.Contains(wall, `role="img"`) {
		t.Error("the wall does not present itself as one image")
	}
	cells := strings.Count(wall, `class="cell"`)
	if cells == 0 {
		t.Fatal("the wall drew no cells")
	}
	if n := strings.Count(wall, `tabindex="-1"`); n != cells {
		t.Errorf("%d of %d cells are in the tab order — at fleet scale that is thousands of nameless stops", cells-n, cells)
	}
	if n := strings.Count(wall, `aria-hidden="true"`); n < cells {
		t.Errorf("only %d of %d cells are hidden from assistive technology", n, cells)
	}
	// Still clickable: the specification says clicking a cell opens that Node.
	if !strings.Contains(wall, `href="/console/nodes/`) {
		t.Error("wall cells lost their link — the spec says clicking a cell opens that Node")
	}
	// The hover title must speak the legend's language, not an internal token.
	if strings.Contains(wall, "· attention") {
		t.Error(`a cell title says "attention"; the key three inches above says "needs attention"`)
	}
}

// TestFleet_FacetLinksComposeRatherThanReplace — browsing trains targeting, and
// a filter you can only ever set one term of trains nothing.
func TestFleet_FacetLinksComposeRatherThanReplace(t *testing.T) {
	c := linkContext{Filter: "node:env=prod", GroupBy: "env"}

	href := c.href("node:role=web")
	if !strings.Contains(href, "group=env") {
		t.Errorf("the facet link drops the grouping: %s", href)
	}
	if !strings.Contains(href, url.QueryEscape("node:env=prod, node:role=web")) {
		t.Errorf("the facet link replaces the filter instead of composing it: %s", href)
	}

	// Idempotent: clicking the same facet twice must not build a redundant
	// predicate that reads as a bug in the product.
	if got := appendTerm("node:env=prod", "node:env=prod"); got != "node:env=prod" {
		t.Errorf("appendTerm duplicated a term: %q", got)
	}
	if got := appendTerm("", "node:role=web"); got != "node:role=web" {
		t.Errorf("appendTerm on an empty filter = %q", got)
	}
	// "Group by nothing" must survive a facet click as nothing, not re-default.
	if h := (linkContext{GroupBy: ""}).href("node:role=web"); !strings.Contains(h, "group=-") {
		t.Errorf("grouping by nothing was not preserved: %s", h)
	}
}

// TestFleet_AmberIsLegibleAsText guards the token split.
//
// --color-amber is #a88608 in light: 3.26:1 on the surface, correct for a fill
// or a dot (WCAG 1.4.11 asks 3:1) and below AA for 11-13px type. It painted the
// Freeze banner, which is the Console's loudest alarm and the one thing on any
// screen that must never be squinted at.
//
// The token stays verbatim from Gleipnir; --attention-text is the Console's own
// alias and is what text uses.
func TestFleet_AmberIsLegibleAsText(t *testing.T) {
	css := get(t, newTestHandler(renderableDeps(), accounts.RoleAdmin),
		"/console/assets/console.css").Body.String()

	if !strings.Contains(css, "--attention-text: #6d5605") {
		t.Error("the light theme has no text-legible amber")
	}
	// The banner is the case that matters most.
	banner := css[strings.Index(css, ".banner {"):]
	banner = banner[:strings.Index(banner, "}")]
	if !strings.Contains(banner, "var(--attention-text)") {
		t.Errorf("the Freeze banner uses fill-amber as text:\n%s", banner)
	}
}

// TestFleet_TablesAndLivenessAreNamed — a dot in an unnamed column in an unnamed
// table encodes "can I reach this machine" in colour alone (WCAG 1.4.1), and on
// a page that can now carry forty tables, an unnamed table is forty identical
// announcements.
func TestFleet_TablesAndLivenessAreNamed(t *testing.T) {
	body := get(t, newTestHandler(fleetFixture(), accounts.RoleAdmin), "/console/").Body.String()

	if !strings.Contains(body, `aria-label="not connected"`) || !strings.Contains(body, `aria-label="connected"`) {
		t.Error("the liveness dot carries no accessible name — reachability is encoded in colour alone")
	}
	if !strings.Contains(body, `<caption`) {
		t.Error("the deviation table has no caption; forty of them announce identically")
	}
	if !strings.Contains(body, `<span class="vh">Reachable</span>`) {
		t.Error("the liveness column has no header")
	}
	// Every header cell must be scoped, or the association is guesswork.
	//
	// Counted precisely: `<th` also matches `<thead>`, which is how the first
	// version of this assertion reported a phantom unscoped cell.
	scoped := strings.Count(body, `<th scope="col">`)
	total := strings.Count(body, "<th>") + strings.Count(body, "<th ")
	if scoped != total {
		t.Errorf("%d of %d header cells carry scope", scoped, total)
	}
	if total == 0 {
		t.Fatal("no header cells rendered — the assertion is checking nothing")
	}
}

// TestFleet_TemplateSetFacetExists — question two of the four is "will it take
// work?", and its second half is template vocabulary. Without this facet a
// half-landed template rollout is invisible at fleet level: the unloadable
// marker was countable, the fingerprint that says which set is installed was
// nowhere.
func TestFleet_TemplateSetFacetExists(t *testing.T) {
	d := renderableDeps()
	d.Fleet = fakeFleet{nodes: []registry.Node{
		{NodeID: "a", TemplateSetFingerprint: "aaaa1111", Connected: true},
		{NodeID: "b", TemplateSetFingerprint: "aaaa1111", Connected: true},
		{NodeID: "c", TemplateSetFingerprint: "bbbb2222", Connected: true},
		{NodeID: "d", TemplateSetFingerprint: nodestate.TemplateUnloadable, Connected: true},
		{NodeID: "e", Connected: true},
	}}

	v := buildFleetView(d, d.Fleet.List(), "", "-")
	var tf *facet
	for i := range v.Groups[0].Facets {
		if v.Groups[0].Facets[i].Title == "Template set" {
			tf = &v.Groups[0].Facets[i]
		}
	}
	if tf == nil {
		t.Fatalf("no template-set facet; got %v", v.Groups[0].Facets)
	}
	got := map[string]int{}
	for _, val := range tf.Values {
		got[val.Label] = val.Count
	}
	// "no templates installed" and "the template set failed to load" are
	// different facts and must not collapse.
	if got["unloadable"] != 1 || got["none installed"] != 1 {
		t.Errorf("unloadable and none-installed collapsed: %v", got)
	}
	if got[shortHash("aaaa1111")] != 2 {
		t.Errorf("fingerprint distribution wrong: %v", got)
	}
}

// TestFleet_FingerprintFacetTermsResolveToTheFullValue covers the fingerprint
// facets' term-building: the facet is KEYED by shortHash for display, but the
// Selector term it links to must carry the FULL fingerprint — ParseSelector
// has no notion of a short hash — and that term must actually resolve back to
// the Nodes the facet counted.
func TestFleet_FingerprintFacetTermsResolveToTheFullValue(t *testing.T) {
	d := renderableDeps()
	d.Fleet = fakeFleet{nodes: []registry.Node{
		{NodeID: "a", PolicyFingerprint: "aaaa111122223333", Connected: true},
		{NodeID: "b", PolicyFingerprint: "aaaa111122223333", Connected: true},
		{NodeID: "c", PolicyFingerprint: "bbbb444455556666", Connected: true},
	}}

	v := buildFleetView(d, d.Fleet.List(), "", "-")
	var pf *facet
	for i := range v.Groups[0].Facets {
		if v.Groups[0].Facets[i].Title == "Policy fingerprint" {
			pf = &v.Groups[0].Facets[i]
		}
	}
	if pf == nil {
		t.Fatal("no Policy fingerprint facet")
	}
	var term string
	for _, val := range pf.Values {
		if val.Label == shortHash("aaaa111122223333") {
			if !val.Targetable {
				t.Fatalf("Policy fingerprint facet value %q is not targetable", val.Label)
			}
			term = val.Term
		}
	}
	if term != "state:policy-fingerprint=aaaa111122223333" {
		t.Fatalf("facet term = %q, want the FULL fingerprint, not the short hash", term)
	}

	got := buildFleetView(d, d.Fleet.List(), term, "-")
	if !got.FilterOK {
		t.Fatalf("the facet's own term %q was rejected as a filter: %s", term, got.FilterError)
	}
	if got.Matched != 2 {
		t.Fatalf("filtering on the facet term matched %d Nodes, want 2 (a, b)", got.Matched)
	}
}

// TestFleet_FacetTermsAreAlwaysExactlyOneSelectorTerm is a property test over
// every facet value buildFleetView renders: #488 was a Node injecting a
// second Selector term into a facet link the Console advertises as
// targetable by concatenating a raw, self-reported value. Two honest Nodes
// share a Policy fingerprint; a third Node self-reports a hostile Policy
// fingerprint, template fingerprint and daemon version, each carrying a
// Selector separator.
func TestFleet_FacetTermsAreAlwaysExactlyOneSelectorTerm(t *testing.T) {
	d := renderableDeps()
	d.Fleet = fakeFleet{nodes: []registry.Node{
		{NodeID: "node-a", Connected: true, PolicyFingerprint: "aaaa111122223333"},
		{NodeID: "node-b", Connected: true, PolicyFingerprint: "aaaa111122223333"},
		{
			NodeID:                 "node-hostile",
			Connected:              true,
			PolicyFingerprint:      "aaaa111122223333, relay:quarantine=on",
			TemplateSetFingerprint: "bbbb4444, tag:pci=yes",
			DaemonVersion:          "1.4.2, tag:x=y",
		},
	}}

	v := buildFleetView(d, d.Fleet.List(), "", "-")
	checked := 0
	for _, g := range v.Groups {
		for _, f := range g.Facets {
			for _, val := range f.Values {
				if !val.Targetable {
					if val.Term != "" || val.Href != "" {
						t.Errorf("%s: non-targetable value %q carries Term=%q Href=%q",
							f.Title, val.Label, val.Term, val.Href)
					}
					continue
				}
				if val.Term == "" {
					t.Errorf("%s: targetable value %q has an empty Term", f.Title, val.Label)
					continue
				}
				if !strings.HasPrefix(val.Term, "state:") {
					// node:-prefixed terms are deliberately NOT asserted here: node:
					// values are Node-forgeable and ungated at ingress (buildFacets'
					// comment on the node:role facet), so this test does not claim a
					// coverage it does not have.
					continue
				}
				checked++
				sel, err := capability.ParseSelector(val.Term)
				if err != nil {
					t.Errorf("%s: term %q does not parse: %s", f.Title, val.Term, err)
					continue
				}
				if len(sel.Predicates) != 1 {
					t.Errorf("%s: term %q parsed to %d predicates, want exactly 1",
						f.Title, val.Term, len(sel.Predicates))
				}
			}
		}
	}
	if checked == 0 {
		t.Fatal("no state: term was checked — the assertion is checking nothing")
	}
}

// TestFleet_ACollidingShortHashDoesNotHijackTheHonestBucket is the crux: on
// HEAD the Policy fingerprint facet buckets by shortHash, and the short-to-
// full map is last-writer-wins over the nodes slice (registry/memory.go sorts
// ascending by NodeID). A hostile Node sharing the honest bucket's first
// twelve characters and given the lexicographically GREATEST NodeID — the
// strongest case for the old bug — either hijacks the honest link or poisons
// its count. Keying by the full value makes both impossible.
func TestFleet_ACollidingShortHashDoesNotHijackTheHonestBucket(t *testing.T) {
	d := renderableDeps()
	honest := "aaaa111122223333"
	hostile := honest + ", relay:quarantine=on"
	d.Fleet = fakeFleet{nodes: []registry.Node{
		{NodeID: "node-a", Connected: true, PolicyFingerprint: honest},
		{NodeID: "node-b", Connected: true, PolicyFingerprint: honest},
		{NodeID: "node-z-hostile", Connected: true, PolicyFingerprint: hostile},
	}}

	v := buildFleetView(d, d.Fleet.List(), "", "-")
	var pf *facet
	for i := range v.Groups[0].Facets {
		if v.Groups[0].Facets[i].Title == "Policy fingerprint" {
			pf = &v.Groups[0].Facets[i]
		}
	}
	if pf == nil {
		t.Fatal("no Policy fingerprint facet")
	}

	label := shortHash(honest)
	var honestRow, hostileRow *facetValue
	for i := range pf.Values {
		if pf.Values[i].Label != label {
			continue
		}
		switch pf.Values[i].Count {
		case 2:
			honestRow = &pf.Values[i]
		case 1:
			hostileRow = &pf.Values[i]
		}
	}
	if honestRow == nil || hostileRow == nil {
		t.Fatalf("want two rows sharing label %q (count 2 and count 1); got %+v", label, pf.Values)
	}
	if !honestRow.Targetable || honestRow.Term != "state:policy-fingerprint="+honest {
		t.Errorf("the honest bucket's link was hijacked: Targetable=%v Term=%q",
			honestRow.Targetable, honestRow.Term)
	}
	if hostileRow.Targetable || hostileRow.Href != "" {
		t.Errorf("the colliding value's row is targetable: %+v", hostileRow)
	}

	got := buildFleetView(d, d.Fleet.List(), honestRow.Term, "-")
	if !got.FilterOK {
		t.Fatalf("the honest bucket's own term %q was rejected as a filter: %s", honestRow.Term, got.FilterError)
	}
	if got.Matched != 2 {
		t.Fatalf("filtering on the honest term matched %d Nodes, want 2 (node-a, node-b)", got.Matched)
	}
}

// TestFleet_ASelfReportedSentinelDoesNotJoinTheSentinelBucket is the
// regression guard for the sentinel key-space fix: the template-set facet's
// counts map mixes real fingerprints with two closed-vocabulary sentinels
// ("unloadable", "none installed"), and re-keying the real branch by the FULL
// value — needed to close the short-hash collision above — would put a
// self-reported string straight into the sentinel key space unless the
// sentinel keys live somewhere a raw value structurally cannot reach.
//
// HEAD satisfies "a self-reported 'none installed' cannot join the sentinel
// bucket" only INCIDENTALLY: the sentinel key on HEAD is the 14-character
// literal "none installed", and the real branch keys by shortHash, which
// truncates anything a Node reports over 12 characters to "none install…"
// before it is ever compared — missing the sentinel by an accident of
// length, not by design. This test pins the property deliberately, because
// this change removes that accident.
func TestFleet_ASelfReportedSentinelDoesNotJoinTheSentinelBucket(t *testing.T) {
	d := renderableDeps()
	d.Fleet = fakeFleet{nodes: []registry.Node{
		// Genuine "no templates installed" — the field is simply empty.
		{NodeID: "node-genuine", Connected: true},
		// A Node self-reporting the sentinel's own operator-facing words as if
		// they were a template-set fingerprint.
		{NodeID: "node-hostile", Connected: true, TemplateSetFingerprint: "none installed"},
	}}

	v := buildFleetView(d, d.Fleet.List(), "", "-")
	var tf *facet
	for i := range v.Groups[0].Facets {
		if v.Groups[0].Facets[i].Title == "Template set" {
			tf = &v.Groups[0].Facets[i]
		}
	}
	if tf == nil {
		t.Fatal("no Template set facet")
	}

	var sentinelRow, hostileRow *facetValue
	sum := 0
	for i := range tf.Values {
		sum += tf.Values[i].Count
		if tf.Values[i].Label == "none installed" {
			sentinelRow = &tf.Values[i]
			continue
		}
		hostileRow = &tf.Values[i]
	}
	if sum != len(d.Fleet.List()) {
		t.Errorf("facet counts sum to %d, want %d (one row per Node)", sum, len(d.Fleet.List()))
	}
	if sentinelRow == nil || sentinelRow.Count != 1 {
		t.Fatalf("want exactly one Node in the genuine 'none installed' bucket; got %+v", tf.Values)
	}
	if hostileRow == nil {
		t.Fatal("the self-reported literal did not get its own row — it was merged into the sentinel bucket")
	}
	if hostileRow.Label == "none installed" {
		t.Errorf("the self-reported literal's row shares the sentinel's exact label %q", hostileRow.Label)
	}
	if hostileRow.Targetable || hostileRow.Href != "" {
		t.Errorf("the self-reported literal's row is targetable: %+v", hostileRow)
	}

	// Sibling: the protocol literal "unloadable" (ADR-0021's own vocabulary —
	// the daemon reports it when its template set failed to load, not when it
	// wants to name a fingerprint) is counted as unloadable, unaffected by any
	// other value reported alongside it.
	d2 := renderableDeps()
	d2.Fleet = fakeFleet{nodes: []registry.Node{
		{NodeID: "node-a", Connected: true, TemplateSetFingerprint: nodestate.TemplateUnloadable},
		{NodeID: "node-b", Connected: true, TemplateSetFingerprint: "none installed"},
	}}
	v2 := buildFleetView(d2, d2.Fleet.List(), "", "-")
	for i := range v2.Groups[0].Facets {
		if v2.Groups[0].Facets[i].Title != "Template set" {
			continue
		}
		got := map[string]int{}
		for _, val := range v2.Groups[0].Facets[i].Values {
			got[val.Label] += val.Count
		}
		if got["unloadable"] != 1 {
			t.Errorf("unloadable count = %d, want 1: %v", got["unloadable"], got)
		}
	}
}

// TestFleet_DaemonVersionFacetIsGatedLikeTheFingerprints: the daemon-version
// facet has the identical bypass as the fingerprint facets — no short hash,
// so the raw value went straight into the href — and validFactValue's own
// doc comment uses a daemon version carrying a comma as ITS example of the
// injection. Not named by the issue, but in scope for the same reason.
func TestFleet_DaemonVersionFacetIsGatedLikeTheFingerprints(t *testing.T) {
	d := renderableDeps()
	d.Fleet = fakeFleet{nodes: []registry.Node{
		{NodeID: "node-a", Connected: true, DaemonVersion: "1.4.2"},
		{NodeID: "node-b", Connected: true, DaemonVersion: "1.4.2"},
		{NodeID: "node-hostile", Connected: true, DaemonVersion: "1.4.2, tag:x=y"},
	}}

	v := buildFleetView(d, d.Fleet.List(), "", "-")
	var vf *facet
	for i := range v.Groups[0].Facets {
		if v.Groups[0].Facets[i].Title == "Daemon version" {
			vf = &v.Groups[0].Facets[i]
		}
	}
	if vf == nil {
		t.Fatal("no Daemon version facet")
	}

	var honest, hostile *facetValue
	for i := range vf.Values {
		switch vf.Values[i].Label {
		case "1.4.2":
			honest = &vf.Values[i]
		case "1.4.2, tag:x=y":
			hostile = &vf.Values[i]
		}
	}
	if honest == nil || !honest.Targetable || honest.Term != "state:daemon-version=1.4.2" {
		t.Fatalf("the honest version is not targeted correctly: %+v", honest)
	}
	if hostile == nil || hostile.Count != 1 {
		t.Fatalf("the hostile version was not counted: %+v", vf.Values)
	}
	if hostile.Targetable || hostile.Term != "" || hostile.Href != "" {
		t.Errorf("the hostile version is targetable: %+v", hostile)
	}
}

// TestFleet_FacetSaysWhyAValueIsNotALink renders /console/ end to end: a hint
// naming the reason ("a comma, whitespace or a namespace prefix") must be
// visible on a fleet carrying a refused value, the injected term must never
// reach a query string anywhere on the page, and a clean fleet must render no
// hint at all — the hint is driven by a refusal, never by !Targetable.
func TestFleet_FacetSaysWhyAValueIsNotALink(t *testing.T) {
	d := renderableDeps()
	d.Fleet = fakeFleet{nodes: []registry.Node{
		{NodeID: "node-a", Connected: true, PolicyFingerprint: "aaaa111122223333"},
		{NodeID: "node-hostile", Connected: true, PolicyFingerprint: "aaaa111122223333, relay:quarantine=on"},
	}}
	body := get(t, newTestHandler(d, accounts.RoleAdmin), "/console/").Body.String()

	if !strings.Contains(body, `class="fhint"`) {
		t.Error("no facet hint rendered on a fleet carrying a refused value")
	}
	// No honest Node in this fixture could produce this query string; its
	// presence would mean the injected term reached a link the Console
	// advertises as targetable.
	injected := url.QueryEscape("relay:quarantine=on")
	if strings.Contains(body, injected) {
		t.Errorf("the injected term %q appears in a query string on the page", injected)
	}

	clean := renderableDeps()
	clean.Fleet = fakeFleet{nodes: []registry.Node{
		{NodeID: "node-a", Connected: true, PolicyFingerprint: "aaaa111122223333"},
		{NodeID: "node-b", Connected: true, PolicyFingerprint: "aaaa111122223333"},
	}}
	cleanBody := get(t, newTestHandler(clean, accounts.RoleAdmin), "/console/").Body.String()
	if strings.Contains(cleanBody, `class="fhint"`) {
		t.Error("a clean fixture rendered a facet hint — no value here was refused")
	}
}

// TestFleet_StateFacetKeepsNamespacesApart — the facet once listed `offline` and
// the literal `quarantine (relay:)` as bare strings under one heading: a derived
// observation and a declared act, told apart by a parenthetical, on a screen
// whose whole chip grammar exists to keep those apart.
func TestFleet_StateFacetKeepsNamespacesApart(t *testing.T) {
	d := fleetFixture()
	v := buildFleetView(d, d.Fleet.List(), "", "-")

	var sf *facet
	for i := range v.Groups[0].Facets {
		if v.Groups[0].Facets[i].Title == "State" {
			sf = &v.Groups[0].Facets[i]
		}
	}
	if sf == nil {
		t.Fatal("no State facet")
	}
	for _, val := range sf.Values {
		// Revocation is a declared act, not a label — the deviation table
		// renders it as a fenced chip and the facet must agree. One screen
		// describing one fact in two grammars is exactly the confusion the
		// namespace model exists to prevent.
		if val.Fenced != "" {
			if val.Chip != nil {
				t.Errorf("%q renders as both a declared act and a label", val.Label)
			}
			continue
		}
		if val.Chip == nil {
			t.Errorf("facet value %q renders as a bare string, not a chip", val.Label)
			continue
		}
		// Both relay: fences and state: markers resolve as a Selector term
		// (#414) — every non-fenced value here must be a live link.
		if !val.Targetable {
			t.Errorf("%q is not offered as a Selector term, even though its namespace resolves", val.Label)
		}
	}
}

// TestFleet_SaysWhenItWasTrue — a tab left open overnight otherwise shows a
// confidently green fleet from twelve hours ago.
func TestFleet_SaysWhenItWasTrue(t *testing.T) {
	body := get(t, newTestHandler(fleetFixture(), accounts.RoleAdmin), "/console/").Body.String()
	if !strings.Contains(body, "as at "+testNow.Format("2006-01-02 15:04:05Z")) {
		t.Error("the fleet view does not say when it was rendered")
	}
}

// TestRegistry_QuarantineIsPinnedToItsValue is the decision recorded on
// 2026-08-26: the fence is `relay:quarantine=on`, key AND value.
//
// A reader that tests only the key treats `=off` as fenced, while a Selector
// tests both — so the set the Console draws and the set an operator can target
// would differ, on the one namespace the security lane may target.
func TestRegistry_QuarantineIsPinnedToItsValue(t *testing.T) {
	on := registry.Node{RelayLabels: map[string]string{registry.QuarantineKey: registry.QuarantineOn}}
	if !on.Quarantined() || !nodestate.Quarantined(on) {
		t.Error("relay:quarantine=on is not read as quarantined")
	}
	for _, v := range []string{"off", "", "true", "yes"} {
		n := registry.Node{RelayLabels: map[string]string{registry.QuarantineKey: v}}
		if n.Quarantined() || nodestate.Quarantined(n) {
			t.Errorf("relay:quarantine=%q was read as quarantined; only %q is the fence",
				v, registry.QuarantineOn)
		}
	}
	// The console and the registry must never disagree.
	if nodestate.Quarantined(on) != on.Quarantined() {
		t.Error("nodestate and registry disagree about what quarantined means")
	}
}

// TestFleet_RevokedIsDeclaredInTheFacetToo — the deviation table renders
// revocation as a fenced act and the State facet once rendered it as
// `state:revoked`, a derived observation. Same screen, same fact, two grammars,
// and specifically the two that must never blur.
func TestFleet_RevokedIsDeclaredInTheFacetToo(t *testing.T) {
	d := renderableDeps()
	d.Fleet = fakeFleet{nodes: []registry.Node{
		{NodeID: "gone", RevokedAt: testNow.Add(-time.Hour)},
	}}
	v := buildFleetView(d, d.Fleet.List(), "", "-")

	var found bool
	for _, f := range v.Groups[0].Facets {
		if f.Title != "State" {
			continue
		}
		for _, val := range f.Values {
			if strings.Contains(val.Label, "revoked") {
				found = true
				if val.Chip != nil && val.Chip.Namespace == NamespaceState {
					t.Error("revocation renders as a state: label — nothing derives it; a person did it")
				}
				if val.Fenced == "" {
					t.Error("revocation does not render as a declared act in the facet")
				}
			}
		}
	}
	if !found {
		t.Error("the State facet does not count revoked Nodes at all")
	}
}

// TestNode_ReportedPolicyComesFromTheDaemonsOwnEngine is node detail's headline
// acceptance criterion (spec 02, invariant 12): the effective-Policy panel is
// rendered from a daemon-evaluated query, never from a Relay-side
// reimplementation, and carries the fact that it was.
//
// It exists because the unused-linter noticed that nothing wired the policyview
// seam: only the "has not reported" branch was covered, so the panel that
// actually renders a Node's Policy — the showpiece of the whole screen — was
// never once exercised.
func TestNode_ReportedPolicyComesFromTheDaemonsOwnEngine(t *testing.T) {
	d := fleetFixture()
	d.Policy = fakePolicy{"node-web-1": policyview.Snapshot{
		RawExecEnabled:    true,
		RawAllowPatterns:  []string{`^/usr/bin/systemctl (status|restart) (nginx|php-fpm)$`},
		RawDenyPatterns:   []string{`\brm\b`},
		AllowedOperations: []string{"service.restart", "system.facts", "file.read"},
		OperationRules:    []policyview.OperationRule{{Name: "service.restart", AllowedArgs: [][]string{{"nginx", "php-fpm"}}}},
		DenyRules:         []policyview.DenyRule{{Name: "file.read", Args: [][]string{{"/etc/shadow"}}}},
		PolicyFingerprint: "aaaa111122223333",
	}}

	body := get(t, newTestHandler(d, accounts.RoleAdmin), "/console/nodes/node-web-1").Body.String()

	if strings.Contains(body, "has not reported its Policy") {
		t.Fatal("a reported Policy still rendered the unreported branch")
	}
	// The provenance claim is the point of the panel.
	if !strings.Contains(body, "this Node's own engine") {
		t.Error("the panel does not say the answer came from the Node's own engine")
	}
	if !strings.Contains(body, "has no code path that writes it") {
		t.Error("the panel does not state that the Relay cannot write Policy (ADR-0002, invariant 2)")
	}
	// The rules render verbatim. A paraphrased rule is a rule an operator has
	// to go and check.
	for _, want := range []string{
		"service.restart", "system.facts", "file.read",
		"nginx | php-fpm",
		"/etc/shadow",
		`\brm\b`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("the effective-Policy panel does not render %q", want)
		}
	}
	// Raw Exec being enabled is the most consequential line in a Policy and
	// must not render as an ordinary chip.
	if !strings.Contains(body, `data-risk="mutate">enabled`) {
		t.Error("raw exec enabled does not render at mutate weight")
	}
	// And a different Node with no snapshot still says so, so the fixture is
	// not accidentally global.
	other := get(t, newTestHandler(d, accounts.RoleAdmin), "/console/nodes/node-web-2").Body.String()
	if !strings.Contains(other, "has not reported its Policy") {
		t.Error("a Node with no snapshot did not render the unreported branch")
	}
}

// TestNode_RecordedCertificateProvenanceRenders is the other half of #440 on
// this screen: once the Relay knows when an identity expires, the panel must say
// so rather than keep apologising.
func TestNode_RecordedCertificateProvenanceRenders(t *testing.T) {
	joined := testNow.Add(-30 * 24 * time.Hour)
	d := fleetFixture()
	nodes := d.Fleet.List()
	for i := range nodes {
		if nodes[i].NodeID == "node-web-1" {
			nodes[i].EnrolledAt = joined
			nodes[i].CertNotAfter = testNow.Add(11 * 24 * time.Hour)
			nodes[i].RenewalCount = 2
			nodes[i].LastRenewedAt = testNow.Add(-3 * 24 * time.Hour)
		}
	}
	d.Fleet = fakeFleet{nodes: nodes}

	body := get(t, newTestHandler(d, accounts.RoleAdmin), "/console/nodes/node-web-1").Body.String()

	if strings.Contains(body, "certificate provenance is not recorded") {
		t.Fatal("a Node with recorded provenance still renders the gap note")
	}
	for _, want := range []string{
		joined.Format("2006-01-02 15:04:05Z"), // enrolled
		"in 11d",                              // expiry, in units worth reading
		"last " + testNow.Add(-3*24*time.Hour).Format("2006-01-02 15:04:05Z"),
	} {
		if !strings.Contains(body, want) {
			t.Errorf("the certificate panel does not render %q", want)
		}
	}

	// A lapsed identity reads as overdue, not as negative validity.
	nodes[0].CertNotAfter = testNow.Add(-2 * 24 * time.Hour)
	for i := range nodes {
		if nodes[i].NodeID == "node-web-1" {
			nodes[i].CertNotAfter = testNow.Add(-2 * 24 * time.Hour)
		}
	}
	d.Fleet = fakeFleet{nodes: nodes}
	body = get(t, newTestHandler(d, accounts.RoleAdmin), "/console/nodes/node-web-1").Body.String()
	if !strings.Contains(body, "expired 2d ago") {
		t.Error("a lapsed certificate does not read as expired")
	}
}

// consoleShapeKey is the real shape key for one Action over one Selector, so
// these grouping tests exercise the same key production stores rather than a
// stand-in string.
func consoleShapeKey(operation string, args map[string]string) string {
	return approval.HashPlanShape(jobs.Action{
		Kind:          jobs.ActionOperation,
		OperationName: operation,
		OperationArgs: args,
		RiskClass:     jobs.RiskClassMutate,
	}, approval.SelectorShape{
		Known: true,
		Terms: []approval.SelectorTerm{{Namespace: "node", Key: "env", Value: "dev"}},
	})
}

// TestApprovals_DifferentPlansAreNeverCalledIdentical.
//
// The queue's grouping hint once claimed two parked dispatches were "the same
// shape" whenever they shared an ActionKind, a risk class and a gate rule —
// which one fixture gate rule makes true of nearly everything it parks. A dev
// fleet parked service.restart(unit="sshd") and pkg.install(name="nginx") and
// the screen told the approver they were alike.
//
// On the one surface whose job is telling a human what they are about to
// authorise, a hint that overclaims is worse than no hint. The key is now the
// stored shape key (#415), which is computed from the Action and the normalised
// Selector, so two different actions can never share it.
func TestApprovals_DifferentPlansAreNeverCalledIdentical(t *testing.T) {
	rows := queueRows([]approval.Request{
		{
			ID: "restart-sshd", PlanHash: "hash-restart-sshd",
			ShapeKey:     consoleShapeKey("service.restart", map[string]string{"unit": "sshd"}),
			Summary:      `service.restart(unit="sshd") [mutate] on 3 node(s)`,
			ActionKind:   jobs.ActionOperation,
			RiskClass:    jobs.RiskClassMutate,
			MatchedRules: []string{"dev-fleet-wide-mutates-need-a-human"},
			CreatedAt:    testNow, ExpiresAt: testNow.Add(time.Hour),
			Require: approval.Requirement{Count: 1},
		},
		{
			ID: "install-nginx", PlanHash: "hash-install-nginx",
			ShapeKey:     consoleShapeKey("pkg.install", map[string]string{"name": "nginx"}),
			Summary:      `pkg.install(name="nginx") [mutate] on 3 node(s)`,
			ActionKind:   jobs.ActionOperation,
			RiskClass:    jobs.RiskClassMutate,
			MatchedRules: []string{"dev-fleet-wide-mutates-need-a-human"},
			CreatedAt:    testNow, ExpiresAt: testNow.Add(time.Hour),
			Require: approval.Requirement{Count: 1},
		},
	})

	for _, r := range rows {
		if r.Identical != 1 {
			t.Errorf("%s is grouped with %d others — two different actions are not alike",
				r.ID, r.Identical-1)
		}
	}
	if rows[0].shapeKey == rows[1].shapeKey {
		t.Error("two different actions share a grouping key")
	}
}

// TestApprovals_SameShapeTwiceIsGrouped is the case the hint exists for:
// re-issuing a gated call parks it again, and approving the same thing three
// times without noticing is the fatigue failure being caught. The two rows here
// carry DIFFERENT plan hashes — a different fan-out — which is exactly the
// grouping the plan hash could not express and the shape key can.
func TestApprovals_SameShapeTwiceIsGrouped(t *testing.T) {
	shape := consoleShapeKey("service.restart", map[string]string{"unit": "nginx"})
	rows := queueRows([]approval.Request{
		{
			ID: "first", PlanHash: "hash-3-nodes", ShapeKey: shape,
			CreatedAt: testNow, ExpiresAt: testNow.Add(time.Hour),
			Require: approval.Requirement{Count: 1},
		},
		{
			ID: "second", PlanHash: "hash-9-nodes", ShapeKey: shape,
			CreatedAt: testNow, ExpiresAt: testNow.Add(time.Hour),
			Require: approval.Requirement{Count: 1},
		},
	})

	for _, r := range rows {
		if r.Identical != 2 {
			t.Errorf("%s reports %d of the same shape, want 2", r.ID, r.Identical)
		}
		if r.ShapeGroup == "" {
			t.Errorf("%s is in a group of two and carries no group ordinal to render", r.ID)
		}
	}
}

// TestApprovals_UncomparableShapesAreNeverGrouped: a pre-#415 record carries a
// legacy key and its true shape is unknowable. Bucketing every such record
// together would tell an approver that records with nothing in common are
// alike, which is the precise failure the shape key exists to prevent.
func TestApprovals_UncomparableShapesAreNeverGrouped(t *testing.T) {
	rows := queueRows([]approval.Request{
		{
			ID: "legacy-a", PlanHash: "hash-a", ShapeKey: approval.LegacyShapeKey("legacy-a"),
			CreatedAt: testNow, ExpiresAt: testNow.Add(time.Hour),
			Require: approval.Requirement{Count: 1},
		},
		{
			ID: "legacy-b", PlanHash: "hash-b", ShapeKey: approval.LegacyShapeKey("legacy-b"),
			CreatedAt: testNow, ExpiresAt: testNow.Add(time.Hour),
			Require: approval.Requirement{Count: 1},
		},
		{
			// No shape key at all — a Request built as a struct literal.
			ID: "unkeyed-a", PlanHash: "hash-c",
			CreatedAt: testNow, ExpiresAt: testNow.Add(time.Hour),
			Require: approval.Requirement{Count: 1},
		},
		{
			ID: "unkeyed-b", PlanHash: "hash-d",
			CreatedAt: testNow, ExpiresAt: testNow.Add(time.Hour),
			Require: approval.Requirement{Count: 1},
		},
	})

	for _, r := range rows {
		if r.Identical != 1 {
			t.Errorf("%s is grouped with %d others — a record with no comparable shape groups with nothing",
				r.ID, r.Identical-1)
		}
		if r.shapeKey != "" {
			t.Errorf("%s carries grouping key %q, want none", r.ID, r.shapeKey)
		}
	}
}

// TestConsole_ShipsNoEmoji is a house rule with a structural guard.
//
// Relay is an administrative instrument for a fleet-execution surface, and
// emoji are not its register. The rule also has a mechanical edge: the
// stylesheet marked the `relay:` security lane with a lock (U+1F512) that IBM
// Plex does not carry, so it fell through to whatever emoji font the viewer had
// — and on a bare server or a locked-down corporate image, that is none. The
// glyph distinguishing the one namespace the security lane may target rendered
// as a replacement box, silently, on exactly the machines least likely to have
// fonts installed.
//
// Both the taste and the failure mode point the same way, so this asserts the
// absence rather than trusting review to catch the next one. It checks the CSS
// escape forms too: `content: "\01F512"` carries no literal emoji byte and
// would pass a naive scan of the source.
func TestConsole_ShipsNoEmoji(t *testing.T) {
	h := newTestHandler(fleetFixture(), accounts.RoleAdmin)

	emojiRange := func(r rune) bool {
		switch {
		case r >= 0x1F300 && r <= 0x1FAFF: // pictographs, symbols, supplements
			return true
		case r >= 0x2600 && r <= 0x27BF: // misc symbols, dingbats
			return true
		case r == 0xFE0F || r == 0x200D: // variation selector, ZWJ
			return true
		}
		return false
	}

	for _, path := range []string{
		"/console/assets/console.css",
		"/console/", "/console/agents", "/console/activity",
		"/console/reads", "/console/approvals", "/console/login",
		"/console/nodes/node-web-1", "/console/compare?nodes=node-web-1,node-web-2",
	} {
		body := get(t, h, path).Body.String()

		for _, r := range body {
			if emojiRange(r) {
				t.Errorf("%s renders emoji %q (U+%04X) — Relay is an administrative "+
					"instrument, and a glyph IBM Plex lacks degrades to a replacement box", path, r, r)
				break
			}
		}

		// The CSS escape form, which carries no emoji byte in the source.
		for _, esc := range []string{`\01F5`, `\1F5`, `\01F6`, `\1F6`, `\26`, `\27`} {
			if strings.Contains(body, `content: "`+esc) {
				t.Errorf("%s injects an emoji through a CSS escape (%s…)", path, esc)
			}
		}
	}
}

// TestConsole_EveryRenderedWeightHasAFace.
//
// The templates carry dozens of <b> and <strong> tags, and the UA default for
// both is font-weight: bold — 700. The stylesheet shipped 400/500/600 only, so
// every one of them was SYNTHESISED off the 600 face rather than drawn, which
// is why emphasis read as smeared instead of heavier. Nothing in Go could see
// it: the markup was correct, the font loaded, and the browser quietly faked
// the weight.
//
// 700 is the same latin subset the Gleipnir frontend loads
// (@fontsource/ibm-plex-sans 400/500/600/700), so the two surfaces render the
// same word the same way.
func TestConsole_EveryRenderedWeightHasAFace(t *testing.T) {
	h := newTestHandler(fleetFixture(), accounts.RoleAdmin)
	css := get(t, h, "/console/assets/console.css").Body.String()

	for _, weight := range []string{"400", "500", "600", "700"} {
		if !strings.Contains(css, "font-weight: "+weight+";\n  font-display") {
			t.Errorf("no @font-face at weight %s — the browser synthesises it", weight)
		}
		if got := get(t, h, "/console/assets/fonts/ibm-plex-sans-"+weight+".woff2"); got.Code != 200 {
			t.Errorf("ibm-plex-sans-%s.woff2 is declared but not served (%d)", weight, got.Code)
		}
	}

	// The markup that needs 700. If this ever stops being true the face above
	// becomes dead weight rather than a fix.
	body := get(t, h, "/console/").Body.String()
	if !strings.Contains(body, "<b>") && !strings.Contains(body, "<strong>") {
		t.Skip("no bold markup on the fleet view any more")
	}
}

// TestAgents_RepeatedDenyProseIsCollapsed.
//
// One fleet-wide dispatch produces one deny per Node, every one carrying the
// same explanation. The agent stream rendered the full block for each: a
// three-Node refusal ran three screens, and a thousand-Node refusal would bury
// every call after it. The stream then hides the next call rather than showing
// this one.
//
// The first keeps the prose; the rest keep their outcome chip, their Node and a
// one-line marker. Node detail has collapsed these the same way all along.
func TestAgents_RepeatedDenyProseIsCollapsed(t *testing.T) {
	var recs []audit.Record
	for _, n := range []string{"n1", "n2", "n3"} {
		recs = append(recs, audit.Record{
			Kind: audit.KindDispatch, OperationName: "file.read",
			Args: map[string]string{"path": "/etc/shadow"}, NodeID: n,
			Outcome: jobs.OutcomeDeniedByPolicy, Timestamp: testNow,
		})
	}

	_, calls, _ := buildAgents(recs, "", testNow)
	if len(calls) != 3 {
		t.Fatalf("got %d calls, want 3 — collapsing prose must never drop a row", len(calls))
	}

	explained := 0
	for _, c := range calls {
		if c.Deny != nil {
			explained++
		}
		if c.Deny == nil && !c.RepeatDeny {
			t.Error("a denied call carries neither an explanation nor the repeat marker")
		}
		if c.Outcome == "" || c.NodeID == "" {
			t.Error("collapsing the prose also dropped the outcome or the Node")
		}
	}
	if explained != 1 {
		t.Errorf("%d rows carry the full deny block, want exactly 1", explained)
	}
}

// TestAgents_DifferentOperationsKeepTheirOwnDenyProse.
//
// The collapse is keyed on Operation AND rule, not the rule alone. Read-class
// denies share one generic explanation ("the deciding rule is not recorded for
// a read-class Task"), so keying on the text would silently collapse refusals
// of DIFFERENT Operations into one — hiding the second refusal entirely.
func TestAgents_DifferentOperationsKeepTheirOwnDenyProse(t *testing.T) {
	recs := []audit.Record{
		{
			Kind: audit.KindDispatch, OperationName: "file.read",
			Args: map[string]string{"path": "/etc/shadow"}, NodeID: "n1",
			Outcome: jobs.OutcomeDeniedByPolicy, Timestamp: testNow,
		},
		{
			Kind: audit.KindDispatch, OperationName: "service.restart",
			Args: map[string]string{"unit": "sshd"}, NodeID: "n1",
			Outcome: jobs.OutcomeDeniedByPolicy, Timestamp: testNow,
		},
	}

	_, calls, _ := buildAgents(recs, "", testNow)
	for _, c := range calls {
		if c.Deny == nil {
			t.Errorf("the refusal of %s was collapsed into another Operation's explanation", c.Args)
		}
	}
}

// TestNode_RecentTasksScrollsInsideItsPanel.
//
// The Recent Tasks table has five columns, two of them full identifiers, and it
// carried no scroll container. The whole DOCUMENT scrolled sideways instead —
// at every viewport including 1600px — and the Job column, the one cell that
// links onward, was clipped off the right edge.
//
// The fleet view's .devtable already did this correctly; node detail simply
// missed the wrapper.
func TestNode_RecentTasksScrollsInsideItsPanel(t *testing.T) {
	d := fleetFixture()
	d.Audit = fakeAudit{records: []audit.Record{{
		Kind: audit.KindDispatch, OperationName: "file.read",
		Args: map[string]string{"path": "/etc/os-release"}, NodeID: "node-web-1",
		JobID: "job-1", Outcome: jobs.OutcomeSuccess, Timestamp: testNow,
	}}}
	h := newTestHandler(d, accounts.RoleAdmin)
	css := get(t, h, "/console/assets/console.css").Body.String()

	if !strings.Contains(css, ".tablescroll { overflow-x: auto; }") {
		t.Error("no .tablescroll rule — the wrapper exists in markup but does nothing")
	}

	body := get(t, h, "/console/nodes/node-web-1").Body.String()
	i := strings.Index(body, `<table class="rows">`)
	if i < 0 {
		t.Skip("the Recent Tasks table did not render for this fixture")
	}
	if before := body[:i]; !strings.Contains(before[max0(len(before)-120):], `<div class="tablescroll">`) {
		t.Error("the Recent Tasks table is not wrapped in a scroll container — " +
			"it pushes the whole page sideways and clips the Job column")
	}
}

func max0(n int) int {
	if n < 0 {
		return 0
	}
	return n
}

// TestConsole_TextTokensClearAA computes the actual contrast ratio of every
// text token against every background token, in both themes.
//
// This has already regressed once. A previous pass found --text-muted at
// 2.98:1, moved `th` off it, wrote the measurement into a comment — and left
// the token itself alone, so everything else still on it stayed below AA: the
// as-at staleness stamp, the facet hints, the scope notes and both nav labels.
// Nearly all of it renders at --text-xs or --text-2xs, where WCAG's large-text
// allowance does not apply, so 4.5:1 is the floor and not 3:1.
//
// A comment recording a measurement is not a guard. This is.
func TestConsole_TextTokensClearAA(t *testing.T) {
	css := get(t, newTestHandler(renderableDeps(), accounts.RoleAdmin),
		"/console/assets/console.css").Body.String()

	dark, light := splitThemes(t, css)

	// --text-faint is #3a4840 == --border-subtle: it draws rules, never text.
	texts := []string{"--text-primary", "--text-second", "--text-muted"}
	bgs := []string{"--bg-canvas", "--bg-surface", "--bg-elevated", "--bg-sidebar", "--bg-code", "--bg-subtle"}

	for _, theme := range []struct {
		name   string
		tokens map[string]string
	}{{"dark", dark}, {"light", light}} {
		for _, tk := range texts {
			fg, ok := theme.tokens[tk]
			if !ok {
				t.Fatalf("%s theme declares no %s", theme.name, tk)
			}
			for _, bk := range bgs {
				bg, ok := theme.tokens[bk]
				if !ok {
					t.Fatalf("%s theme declares no %s", theme.name, bk)
				}
				if r := contrastRatio(fg, bg); r < 4.5 {
					t.Errorf("%s: %s on %s is %.2f:1, below the 4.5:1 floor "+
						"(these tokens carry --text-xs and --text-2xs body copy)",
						theme.name, tk, bk, r)
				}
			}
		}
	}
}

// splitThemes pulls the custom-property declarations out of the dark :root
// block and the light prefers-color-scheme block.
func splitThemes(t *testing.T, css string) (dark, light map[string]string) {
	t.Helper()
	i := strings.Index(css, "@media (prefers-color-scheme: light)")
	if i < 0 {
		t.Fatal("no light-theme block in the stylesheet")
	}
	dark = tokensIn(css[:i])

	// The light block redeclares only what differs; everything else cascades
	// from :root. A map holding only the overrides would report inherited
	// tokens as undeclared and quietly skip half the assertions.
	light = map[string]string{}
	for k, v := range dark {
		light[k] = v
	}
	for k, v := range tokensIn(css[i:]) {
		light[k] = v
	}
	return dark, light
}

// Literal colours and one-level var() aliases both count: the palette declares
// --attention as var(--color-amber), and a test that only saw hex would report
// half the tokens as undeclared.
var tokenDecl = regexp.MustCompile(`(--[a-z-]+):\s*(#[0-9a-fA-F]{6}|var\(--[a-z-]+\))\s*;`)

func tokensIn(s string) map[string]string {
	out := map[string]string{}
	for _, m := range tokenDecl.FindAllStringSubmatch(s, -1) {
		// First declaration wins: a later override inside a narrower rule is
		// not the theme's value.
		if _, seen := out[m[1]]; !seen {
			out[m[1]] = m[2]
		}
	}
	return out
}

func contrastRatio(a, b string) float64 {
	l1, l2 := relLuminance(a), relLuminance(b)
	if l1 < l2 {
		l1, l2 = l2, l1
	}
	return (l1 + 0.05) / (l2 + 0.05)
}

func relLuminance(hex string) float64 {
	c := func(i int) float64 {
		v, err := strconv.ParseInt(hex[i:i+2], 16, 0)
		if err != nil {
			return 0
		}
		f := float64(v) / 255
		if f <= 0.03928 {
			return f / 12.92
		}
		return math.Pow((f+0.055)/1.055, 2.4)
	}
	return 0.2126*c(1) + 0.7152*c(3) + 0.0722*c(5)
}

// TestLayout_NavigationIsALandmark.
//
// The sidebar was an <aside class="nav">, so assistive technology was told the
// primary navigation was "complementary" content and the jump-to-navigation
// gesture found nothing. The three groupings — observe, then act, then
// administer — are what nav.go calls the teaching, and they reached sighted
// operators only: styled divs carry no heading semantics and a bare run of
// anchors is not announced as a list with a length.
func TestLayout_NavigationIsALandmark(t *testing.T) {
	d := fleetFixture()
	body := get(t, newTestHandler(d, accounts.RoleAdmin), "/console/").Body.String()

	if !strings.Contains(body, `<nav class="navgroups" aria-label="Console">`) {
		t.Error("the navigation is not inside a <nav> landmark")
	}

	// Derived from what Nav actually returns for this role, not a hard-coded
	// three-group list: since #464 removed the four v0.7.0 placeholders, the
	// Administer heading has no route left to draw and nav.go's drop-empty-
	// section rule means it will not appear even for an admin.
	sections := Nav(d, accounts.RoleAdmin, "/console/")
	if len(sections) == 0 {
		t.Fatal("Nav returned zero sections — the sweep is not running")
	}
	for _, sec := range sections {
		slug := sec.Slug()
		if !strings.Contains(body, `<h2 class="navsec" id="navsec-`+slug+`">`) {
			t.Errorf("the %s group is not a heading", sec.Group)
		}
		if !strings.Contains(body, `<ul class="navlist" aria-labelledby="navsec-`+slug+`">`) {
			t.Errorf("the %s group is not a list labelled by its own heading", sec.Group)
		}
	}
	// The current destination is marked in the accessibility tree, not only by
	// a CSS class that a screen reader cannot see.
	if !strings.Contains(body, `aria-current="page"`) {
		t.Error("the current navigation item is not marked aria-current")
	}
	// And a keyboard user can get past the whole sidebar in one stroke.
	if !strings.Contains(body, `<a class="skiplink" href="#content">`) {
		t.Error("no skip link — reaching the content means tabbing the whole nav on every page")
	}
}

// TestLayout_AccountFooterIsNotNavigation keeps the landmark honest. Signing
// out and the identity chip are not destinations, and a <nav> that swallows
// them makes the landmark less useful, not more.
func TestLayout_AccountFooterIsNotNavigation(t *testing.T) {
	body := get(t, newTestHandler(fleetFixture(), accounts.RoleAdmin), "/console/").Body.String()

	nav := body[strings.Index(body, `<nav class="navgroups"`):]
	nav = nav[:strings.Index(nav, "</nav>")]
	if strings.Contains(nav, "navfoot") || strings.Contains(nav, "Sign out") {
		t.Error("the account footer is inside the navigation landmark")
	}
}

// TestActivity_ControlPlaneReadsSayWhatWasRead.
//
// A read that reaches a Node arrives as a read-class dispatch and is rolled up
// by Job. The other family — the non-dispatching tools — fell through to the
// default branch of summarize and rendered as the bare word "read": no target,
// no Node, no outcome, on the surface billed as the audit trail. The same
// records were meanwhile driving the Read-egress screen's enumeration panel,
// so the trail had the fact and this screen declined to say it.
//
// The cross-screen half is the point and it is why this survives the move to
// the read lane: Activity now reads capability.AuditRow and Read egress still
// reads audit.Record, so the two would name one record two ways unless BOTH
// went through readTargetOf on the shared trailFacts.
func TestActivity_ControlPlaneReadsSayWhatWasRead(t *testing.T) {
	// Both shapes the trail actually produces. The real records carry the tool
	// in OperationName; ActionKind is the older shape and is empty on them.
	// The first fix here read ActionKind only, so Activity said "the registry"
	// while Read egress said "list_nodes" about the same row — which is why
	// both screens now go through readTargetOf.
	recs := []audit.Record{
		{Kind: audit.KindRead, OperationName: "list_nodes", Timestamp: testNow},
		{Kind: audit.KindRead, OperationName: "list_operations", Timestamp: testNow},
		{Kind: audit.KindRead, ActionKind: "describe_node", Timestamp: testNow},
	}
	d := renderableDeps()
	d.Audit = fakeAudit{records: recs}
	d.Queries = &fakeQueries{rows: []capability.AuditRow{
		{Kind: audit.KindRead, OperationName: "list_nodes", Timestamp: testNow},
		{Kind: audit.KindRead, OperationName: "list_operations", Timestamp: testNow},
		{Kind: audit.KindRead, ActionKind: "describe_node", Timestamp: testNow},
	}}

	body := get(t, newTestHandler(d, accounts.RoleAdmin), "/console/activity?kind=read").Body.String()
	for _, want := range []string{"enumerated list_nodes", "enumerated list_operations", "enumerated describe_node"} {
		if !strings.Contains(body, want) {
			t.Errorf("the activity trail does not say %q — the row renders as the bare word \"read\"", want)
		}
	}
	if strings.Contains(body, "enumerated registry read") {
		t.Error("a read fell back to the generic name although the record names its tool")
	}

	// The two screens must name the same record the same way. They read the
	// same trail through two different types, and an operator who sees "the
	// registry" on one and "list_nodes" on the other stops trusting both.
	// Read egress reads the query lane now, not this trail, so the
	// cross-check is against the shared naming core both screens go through
	// rather than against the other screen's view.
	for _, rec := range recs {
		want := readTargetOf(factsOfRecord(rec))
		if !strings.Contains(body, "enumerated "+want) {
			t.Errorf("Read egress names this record %q and Activity does not", want)
		}
	}
}

// TestAgents_NarrowViewportsStackRatherThanOverflow.
//
// A 64-character node id is the widest unbreakable token the Console renders,
// and at 900px the 252px account rail plus the feed could not hold one — so
// the document scrolled sideways. The rail stacks above the feed instead.
//
// The ids are deliberately neither broken nor shortened: comparing identifiers
// is most of what this stream is for. The container moves, the identifier does
// not — the same choice .devtable and .tablescroll make.
func TestAgents_NarrowViewportsStackRatherThanOverflow(t *testing.T) {
	css := get(t, newTestHandler(renderableDeps(), accounts.RoleAdmin),
		"/console/assets/console.css").Body.String()

	if !strings.Contains(css, "@media (max-width: 1000px)") {
		t.Error("no narrow-viewport rule for the agent stream")
	}
	if !strings.Contains(css, ".evmeta, .denyhead { min-width: 0; overflow-x: auto; }") {
		t.Error("no overflow backstop on the rows that carry full node ids")
	}
	// The backstop is worthless without min-width:0 — a flex item will not
	// shrink below its content, so overflow-x never engages.
	i := strings.Index(css, ".evmeta, .denyhead {")
	if rule := css[i : i+80]; !strings.Contains(rule, "min-width: 0") {
		t.Error("the overflow backstop has no min-width:0 and will never engage")
	}
}

// TestFleet_EveryWallBucketIsVisible.
//
// TestFleet_EveryWallBucketHasAColour proves each bucket has a RULE. It cannot
// prove the colour can be seen, and one could not: `normal` borrowed
// --border-mid, a token chosen to be just visible as a 1px hairline, and used
// it as a 20px filled cell. It measured 2.31:1 against the card in dark and
// 2.02:1 in light, against the 3:1 floor for non-text — the only bucket under
// it, and the one that draws the shape of the fleet.
//
// That is the wall's whole purpose. It preserves the fleet's structure so that
// a colour appearing in an unusual place is itself information, and a baseline
// nobody can see gives the unusual colour nothing to appear against. On a
// healthy fleet — nearly every fleet, nearly always — the entire instrument
// read as faint grey smudges.
//
// The 3:1 floor is WCAG 1.4.11 for non-text content, which is what a 20px
// swatch carrying meaning is.
func TestFleet_EveryWallBucketIsVisible(t *testing.T) {
	css := get(t, newTestHandler(renderableDeps(), accounts.RoleAdmin),
		"/console/assets/console.css").Body.String()
	dark, light := splitThemes(t, css)

	// The wall sits in a card, which sits on the canvas.
	cards := []string{"--bg-surface", "--bg-elevated"}

	for _, theme := range []struct {
		name   string
		tokens map[string]string
	}{{"dark", dark}, {"light", light}} {
		for _, bucket := range []string{"--wall-normal", "--wall-drift", "--wall-attention", "--wall-fenced"} {
			fg, ok := resolveToken(theme.tokens, bucket)
			if !ok {
				t.Errorf("%s theme does not resolve %s to a colour", theme.name, bucket)
				continue
			}
			for _, bk := range cards {
				if r := contrastRatio(fg, theme.tokens[bk]); r < 3 {
					t.Errorf("%s: %s on %s is %.2f:1, below the 3:1 floor for a swatch that carries meaning",
						theme.name, bucket, bk, r)
				}
			}
		}
	}
}

// TestFleet_WallBucketsDoNotBorrowTextOrBorderTokens.
//
// The wall borrowed --border-mid for normal and --inert (an alias of
// --text-muted) for drift, which coupled two unrelated things: raising
// --text-muted to clear AA for body copy silently moved a cell colour on the
// fleet view. A swatch governed by a rule about READING will move again the
// next time that rule is applied.
//
// Attention and fenced deliberately DO alias the semantic tokens — an amber
// cell and the amber Freeze banner mean the same thing, and the colour budget
// spends one hue on each meaning.
func TestFleet_WallBucketsDoNotBorrowTextOrBorderTokens(t *testing.T) {
	css := get(t, newTestHandler(renderableDeps(), accounts.RoleAdmin),
		"/console/assets/console.css").Body.String()

	for _, borrowed := range []string{
		"--wall-normal: var(--border-mid)",
		"--wall-drift: var(--inert)",
		"--wall-drift: var(--text-muted)",
		"--wall-normal: var(--text-muted)",
	} {
		if strings.Contains(css, borrowed) {
			t.Errorf("the wall borrows a text or border token (%s) — legibility work on text will move a cell colour", borrowed)
		}
	}
	// And the rules must read from the wall's own tokens, not the old ones.
	for _, stale := range []string{
		`.cell[data-bucket="normal"]      { background: var(--border-mid); }`,
		`.cell[data-bucket="drift"]       { background: var(--inert); }`,
	} {
		if strings.Contains(css, stale) {
			t.Errorf("a cell rule still points at a borrowed token: %s", stale)
		}
	}
}

// resolveToken follows a var() chain to the literal colour at its end.
//
// The palette aliases deliberately — --wall-attention is var(--attention) is
// var(--color-amber) — so a token's value is only meaningful once the chain is
// walked. The bound stops a cycle from hanging the suite.
func resolveToken(tokens map[string]string, name string) (string, bool) {
	for range 8 {
		v, ok := tokens[name]
		if !ok {
			return "", false
		}
		if strings.HasPrefix(v, "var(") {
			name = strings.TrimSuffix(strings.TrimPrefix(v, "var("), ")")
			continue
		}
		return v, true
	}
	return "", false
}

// TestFleet_WallBucketsSurviveColourBlindness.
//
// The wall codes meaning in hue across four buckets, and hue is the one
// channel a dichromat does not fully have. When `normal` became green (owner
// decision, 2026-08-27) it landed at 1.09:1 in luminance against the amber of
// `attention` — the two differing almost purely on the red-green axis, which
// is exactly the axis deuteranopes and protanopes cannot see. "Everything is
// fine" and "needs attention now" would have been one colour for roughly one
// man in twelve, on a fleet-execution surface.
//
// The fix is not more hue, it is luminance: hue carries the meaning, luminance
// carries the separation. This asserts every pair stays apart under normal
// vision AND under simulated deuteranopia and protanopia (Viénot 1999).
//
// The floor is 1.2:1, which is where two 20px swatches stop being reliably
// tellable apart. The weakest pair today is drift/fenced in dark at 1.22 —
// grey against indigo, a collision that predates the green decision. Four
// recognisable hues above a 3:1 visibility floor cannot all be separated on
// luminance; closing that last one needs a non-colour channel, not a different
// hex value.
func TestFleet_WallBucketsSurviveColourBlindness(t *testing.T) {
	css := get(t, newTestHandler(renderableDeps(), accounts.RoleAdmin),
		"/console/assets/console.css").Body.String()
	dark, light := splitThemes(t, css)

	buckets := []string{"--wall-normal", "--wall-drift", "--wall-attention", "--wall-fenced"}

	for _, theme := range []struct {
		name   string
		tokens map[string]string
	}{{"dark", dark}, {"light", light}} {
		for i := 0; i < len(buckets); i++ {
			for j := i + 1; j < len(buckets); j++ {
				a, okA := resolveToken(theme.tokens, buckets[i])
				b, okB := resolveToken(theme.tokens, buckets[j])
				if !okA || !okB {
					t.Fatalf("%s: cannot resolve %s or %s", theme.name, buckets[i], buckets[j])
				}
				for _, vision := range []string{"normal", "deuteranopia", "protanopia"} {
					r := contrastRatio(simulateCVD(a, vision), simulateCVD(b, vision))
					if r < 1.2 {
						t.Errorf("%s/%s: %s and %s are %.2f:1 apart — indistinguishable",
							theme.name, vision, buckets[i], buckets[j], r)
					}
				}
			}
		}
		// And the pair that matters most: fine versus needs-attention.
		n, _ := resolveToken(theme.tokens, "--wall-normal")
		a, _ := resolveToken(theme.tokens, "--wall-attention")
		for _, vision := range []string{"deuteranopia", "protanopia"} {
			if r := contrastRatio(simulateCVD(n, vision), simulateCVD(a, vision)); r < 1.25 {
				t.Errorf("%s/%s: normal and attention are %.2f:1 apart — "+
					"\"everything is fine\" and \"look at this now\" are one colour", theme.name, vision, r)
			}
		}
	}
}

// simulateCVD renders hex as a dichromat sees it (Viénot, Brettel & Mollon
// 1999), returning hex. "normal" passes the colour through unchanged.
func simulateCVD(hex, vision string) string {
	if vision == "normal" {
		return hex
	}
	toLinear := func(i int) float64 {
		v, err := strconv.ParseInt(hex[i:i+2], 16, 0)
		if err != nil {
			return 0
		}
		f := float64(v) / 255
		if f <= 0.04045 {
			return f / 12.92
		}
		return math.Pow((f+0.055)/1.055, 2.4)
	}
	r, g, b := toLinear(1), toLinear(3), toLinear(5)

	l := 17.8824*r + 43.5161*g + 4.11935*b
	m := 3.45565*r + 27.1554*g + 3.86714*b
	s := 0.0299566*r + 0.184309*g + 1.46709*b
	switch vision {
	case "deuteranopia":
		m = 0.494207*l + 1.24827*s
	case "protanopia":
		l = 2.02344*m - 2.52581*s
	}

	toSRGB := func(v float64) int64 {
		v = math.Max(0, math.Min(1, v))
		if v <= 0.0031308 {
			v *= 12.92
		} else {
			v = 1.055*math.Pow(v, 1/2.4) - 0.055
		}
		return int64(math.Round(v * 255))
	}
	return fmt.Sprintf("#%02x%02x%02x",
		toSRGB(0.080944*l-0.130504*m+0.116721*s),
		toSRGB(-0.0102485*l+0.0540194*m-0.113615*s),
		toSRGB(-0.000365294*l-0.00412163*m+0.693513*s))
}

// --- The approval queue and the approval object (#426) -----------------------
//
// The fixtures below build REAL shape keys (consoleShapeKey, consoleGrantShape)
// rather than stand-in strings, so a test that says two records group is
// asserting against the same key production stores.

// approvalScope is a small, fully bounded Scope, the shape a real grant request
// has. maxFanOut varies because the ceiling is precisely what HashGrantShape
// EXCLUDES, which is what makes the diff callout renderable at all.
func approvalScope(maxFanOut int) approval.Scope {
	return approval.Scope{
		Account:    "gleipnir-prod",
		RiskClass:  jobs.RiskClassMutate,
		MaxFanOut:  maxFanOut,
		Operations: []string{"service.restart"},
	}
}

func consoleGrant(id, requestID string, maxFanOut, maxUses int) approval.Grant {
	scope := approvalScope(maxFanOut)
	return approval.Grant{
		ID: id, RequestID: requestID, Scope: scope,
		StartsAt: testNow.Add(-time.Minute), ExpiresAt: testNow.Add(2 * time.Hour),
		MaxUses: maxUses, Uses: 1,
		Summary:   approval.SummarizeScope(scope, testNow, testNow.Add(2*time.Hour), maxUses),
		CreatedAt: testNow.Add(-time.Minute),
	}
}

// grantRequest is the pending approval Request that authorizes g, exactly as
// NewGrantRequest builds it — including the shape key, which is the Grant's own.
func grantRequest(g approval.Grant, state approval.State) approval.Request {
	return approval.Request{
		ID:         g.RequestID,
		PlanHash:   approval.HashScope(g.Scope, g.StartsAt, g.ExpiresAt, g.MaxUses),
		ShapeKey:   g.ShapeKey(),
		Summary:    g.Summary,
		ActionKind: g.Scope.ActionKind(),
		RiskClass:  g.Scope.RiskClass,
		Require:    approval.Requirement{Count: 1},
		State:      state,
		CreatedAt:  testNow.Add(-time.Minute),
		ExpiresAt:  testNow.Add(time.Hour),
	}
}

// TestApprovals_GrantOccupiesExactlyOneRow is spec 14's hard rule: "a Grant that
// fragments into one row per Job it could release has defeated the mechanism
// before anyone opens it". The released Jobs belong on the card.
func TestApprovals_GrantOccupiesExactlyOneRow(t *testing.T) {
	g := consoleGrant("grant-1", "ap-grant", 200, 20)
	d := renderableDeps()
	d.Approvals = &fakeApprovals{pending: []approval.Request{grantRequest(g, approval.StatePending)}, grants: []approval.Grant{g}}
	d.Queries = &fakeQueries{rows: []capability.AuditRow{
		{Kind: audit.KindDispatch, GrantID: "grant-1", JobID: "job-a"},
		{Kind: audit.KindDispatch, GrantID: "grant-1", JobID: "job-b"},
		{Kind: audit.KindDispatch, GrantID: "grant-1", JobID: "job-c"},
	}}

	content := contentOf(get(t, newTestHandler(d, accounts.RoleAdmin), "/console/approvals").Body.String())

	if n := strings.Count(content, `class="qrow`); n != 1 {
		t.Errorf("the queue rendered %d rows for one Grant, want exactly 1", n)
	}
	if !strings.Contains(content, "up to 200 Nodes per dispatch") || !strings.Contains(content, "20 dispatches") {
		t.Error("the Grant's row does not name its Scope, so a reader cannot triage it without opening it")
	}
	for _, job := range []string{"job-a", "job-b", "job-c"} {
		if strings.Contains(content, job) {
			t.Errorf("the queue names released Job %s — released Jobs live on the card, never as queue rows", job)
		}
	}
}

// TestApprovals_SameShapeIsGroupedAndTheKeyIsNeverRendered.
//
// The grouping is the anti-fatigue hint; the key is an unsalted SHA-256 over a
// small preimage (for Raw Exec, every argv element), so rendering it — or
// accepting it as a lookup parameter — would be an offline-confirmation oracle.
// The screen renders an ORDINAL instead, which says "these two are alike" and
// identifies nothing outside the page.
func TestApprovals_SameShapeIsGroupedAndTheKeyIsNeverRendered(t *testing.T) {
	shape := consoleShapeKey("service.restart", map[string]string{"unit": "nginx"})
	d := renderableDeps()
	d.Approvals = &fakeApprovals{pending: []approval.Request{
		{ID: "first", PlanHash: "hash-3", ShapeKey: shape, CreatedAt: testNow, ExpiresAt: testNow.Add(time.Hour), Require: approval.Requirement{Count: 1}},
		{ID: "second", PlanHash: "hash-9", ShapeKey: shape, CreatedAt: testNow, ExpiresAt: testNow.Add(time.Hour), Require: approval.Requirement{Count: 1}},
	}}

	body := get(t, newTestHandler(d, accounts.RoleAdmin), "/console/approvals").Body.String()

	if !strings.Contains(body, "2 pending of the same shape") {
		t.Error("two pending approvals of one shape are not grouped — this is the fatigue failure the hint exists for")
	}
	if strings.Contains(body, shape) {
		t.Error("the queue rendered the shape key itself; it must never leave the handler")
	}
	if strings.Contains(body, "data-shape") {
		t.Error("the queue put a shape key in a data attribute")
	}
}

// TestApprovals_ShapeKeyIsNotAcceptedAsAParameter: no route or query parameter
// on this screen takes a shape key, so it cannot become a lookup oracle.
//
// Compared on the CONTENT rather than the whole body: a fresh CSRF token is
// minted per request and rendered into the <body> tag, so two GETs of the same
// page never match byte for byte.
func TestApprovals_ShapeKeyIsNotAcceptedAsAParameter(t *testing.T) {
	shape := consoleShapeKey("service.restart", map[string]string{"unit": "nginx"})
	d := renderableDeps()
	d.Approvals = &fakeApprovals{pending: []approval.Request{
		{ID: "first", ShapeKey: shape, CreatedAt: testNow, ExpiresAt: testNow.Add(time.Hour), Require: approval.Requirement{Count: 1}},
		{ID: "second", ShapeKey: shape, CreatedAt: testNow, ExpiresAt: testNow.Add(time.Hour), Require: approval.Requirement{Count: 1}},
	}}
	h := newTestHandler(d, accounts.RoleAdmin)

	plain := contentOf(get(t, h, "/console/approvals").Body.String())
	probed := contentOf(get(t, h, "/console/approvals?shape="+shape).Body.String())

	if plain != probed {
		t.Error("a ?shape= parameter changed what the queue rendered — no shape lookup may exist on this surface")
	}
	if strings.Contains(probed, shape) {
		t.Error("the queue echoed the shape key it was handed back into the page")
	}
}

// TestApprovals_WaitingOnMeIsTheDefault is spec 14's filtering rule: "an
// approver arriving from a link should not have to find their own item in
// someone else's list".
func TestApprovals_WaitingOnMeIsTheDefault(t *testing.T) {
	me := testAccountName(accounts.RoleAdmin)
	d := renderableDeps()
	d.Approvals = &fakeApprovals{pending: []approval.Request{
		{ID: "for-me", Summary: "restart nginx on 3 Nodes", CreatedAt: testNow, ExpiresAt: testNow.Add(time.Hour),
			Require: approval.Requirement{Count: 1, Audience: []string{me}}},
		{ID: "for-dana", Summary: "install pkg on 9 Nodes", CreatedAt: testNow, ExpiresAt: testNow.Add(30 * time.Minute),
			Require: approval.Requirement{Count: 1, Audience: []string{"dana"}}},
	}}

	content := contentOf(get(t, newTestHandler(d, accounts.RoleAdmin), "/console/approvals").Body.String())

	if !strings.Contains(content, "restart nginx on 3 Nodes") {
		t.Error("the request naming this caller is not shown under the default filter")
	}
	if strings.Contains(content, "install pkg on 9 Nodes") {
		t.Error("a request addressed to somebody else is shown under the default 'waiting on me' filter")
	}
	if !strings.Contains(content, "hiding 1 addressed to somebody else") {
		t.Error("the screen hid a row without saying how many it hid")
	}
	if !strings.Contains(content, "Show everything") {
		t.Error("there is no way back to the full queue")
	}
}

// TestApprovals_WaitingOnMeKeepsTheUndeterminableOnes is the eligibility
// default, and the direction matters: a Request with NO audience is
// unrestricted, and who may decide it is the capability layer's answer. Hiding
// the rows this Console cannot classify while showing the ones it can is the
// spec's own failure with the sign flipped.
func TestApprovals_WaitingOnMeKeepsTheUndeterminableOnes(t *testing.T) {
	d := renderableDeps()
	d.Approvals = &fakeApprovals{pending: []approval.Request{
		{ID: "named", Summary: "named audience", CreatedAt: testNow, ExpiresAt: testNow.Add(time.Hour),
			Require: approval.Requirement{Count: 1, Audience: []string{testAccountName(accounts.RoleAdmin)}}},
		{ID: "unrestricted", Summary: "no audience at all", CreatedAt: testNow, ExpiresAt: testNow.Add(2 * time.Hour),
			Require: approval.Requirement{Count: 1}},
	}}

	content := contentOf(get(t, newTestHandler(d, accounts.RoleAdmin), "/console/approvals").Body.String())

	if !strings.Contains(content, "no audience at all") {
		t.Error("the default filter hid a request with an unrestricted audience — the one row this " +
			"Console cannot classify is the one it must not hide")
	}
}

// TestApprovals_WaitingOnMeNeverEmptiesTheQueue: a defaulted filter that turns a
// full queue into "Nothing is waiting" is the worst lie this screen can tell.
func TestApprovals_WaitingOnMeNeverEmptiesTheQueue(t *testing.T) {
	d := renderableDeps()
	d.Approvals = &fakeApprovals{pending: []approval.Request{
		{ID: "for-dana", Summary: "restart nginx on 3 Nodes", CreatedAt: testNow, ExpiresAt: testNow.Add(time.Hour),
			Require: approval.Requirement{Count: 1, Audience: []string{"dana"}}},
		{ID: "for-sam", Summary: "install pkg on 9 Nodes", CreatedAt: testNow, ExpiresAt: testNow.Add(2 * time.Hour),
			Require: approval.Requirement{Count: 1, Audience: []string{"sam"}}},
	}}

	content := contentOf(get(t, newTestHandler(d, accounts.RoleAdmin), "/console/approvals").Body.String())

	for _, summary := range []string{"restart nginx on 3 Nodes", "install pkg on 9 Nodes"} {
		if !strings.Contains(content, summary) {
			t.Errorf("%q is missing: the default filter emptied a queue that has entries in it", summary)
		}
	}
	if strings.Contains(content, "Nothing is waiting") {
		t.Error("a queue with two pending requests told the operator nothing is waiting")
	}
	if !strings.Contains(content, `"Waiting on me" was not applied`) {
		t.Error("the screen silently dropped its own default filter instead of saying so")
	}
}

// TestApprovals_RequesterExclusionIsExplainedNotHidden is spec 14's "requester
// excluded" state: "the requester sees their own item and cannot act on it; say
// why rather than hiding the control".
func TestApprovals_RequesterExclusionIsExplainedNotHidden(t *testing.T) {
	req := approval.Request{
		ID: "ap-mine", Summary: "restart nginx on 412 Nodes",
		RequestedByID: testAccountID(accounts.RoleAdmin), RequestedBy: testAccountName(accounts.RoleAdmin),
		CreatedAt: testNow, ExpiresAt: testNow.Add(time.Hour),
		State:   approval.StatePending,
		Require: approval.Requirement{Count: 2, RequesterAllowed: false, Audience: []string{"dana"}},
	}
	// A SECOND row that unambiguously names the caller, so the "waiting on me"
	// filter is non-empty and the never-empty rule does not apply. Without it
	// this fixture proves nothing: one row alone renders whatever mine()
	// answers, and deleting the own-request clause would leave the test green.
	alsoMine := approval.Request{
		ID: "ap-theirs", Summary: "install pkg on 9 Nodes",
		CreatedAt: testNow, ExpiresAt: testNow.Add(30 * time.Minute),
		State:   approval.StatePending,
		Require: approval.Requirement{Count: 1, Audience: []string{testAccountName(accounts.RoleAdmin)}},
	}
	d := renderableDeps()
	d.Approvals = &fakeApprovals{pending: []approval.Request{req, alsoMine}}
	h := newTestHandler(d, accounts.RoleAdmin)

	queue := contentOf(get(t, h, "/console/approvals").Body.String())
	if !strings.Contains(queue, "install pkg on 9 Nodes") {
		t.Fatal("the row that names the caller is missing, so this fixture cannot test anything")
	}
	if !strings.Contains(queue, "restart nginx on 412 Nodes") {
		t.Error("the caller's own request was hidden from them by the default filter — spec 14: " +
			"the requester sees their own item and cannot act on it")
	}
	if !strings.Contains(queue, "you asked for this one") {
		t.Error("the queue does not explain why the caller's own row is not theirs to sign")
	}

	card := contentOf(get(t, h, "/console/approvals/ap-mine").Body.String())
	if !strings.Contains(card, "You are that requester") {
		t.Error("the card does not say the reader is the excluded requester — the exclusion must be " +
			"stated, not left to look like an absence")
	}
}

// TestApprovals_AnUnattributedRequestIsNotYourOwn.
//
// The exclusion rule compares identities, and both sides can legitimately be
// empty: a Request may carry no verified requester, and a Principal may carry no
// Account ID. Comparing "" to "" would classify EVERY unattributed record as the
// caller's own — wrong on screen, and the kind of wrong that makes an assertion
// pass while meaning nothing.
func TestApprovals_AnUnattributedRequestIsNotYourOwn(t *testing.T) {
	unattributed := approval.Request{ID: "ap-1", Require: approval.Requirement{Count: 1, Audience: []string{"dana"}}}

	if st := approvalStandingFor(unattributed, capability.Principal{}); st.Own || st.ExcludedRequester {
		t.Error("an unattributed Request read as the caller's own for a caller with no Account ID")
	}
	if st := approvalStandingFor(unattributed, capability.Principal{AccountID: "acct-1", Account: "ana"}); st.Own {
		t.Error("an unattributed Request read as an identified caller's own")
	}
	if st := approvalStandingFor(approval.Request{RequestedByID: "acct-1"}, capability.Principal{}); st.Own {
		t.Error("an attributed Request read as the own request of a caller with no Account ID")
	}
}

// TestApproval_DiffNamesWhatChangedOnAGrant is the spec's headline sentence,
// rendered from stored columns and nothing else: "same scope as what you
// approved — except the fan-out ceiling grew".
//
// It also pins #415's decision from the consumer side. If HashGrantShape ever
// included MaxFanOut, these two Grants would carry DIFFERENT shape keys, no
// prior would be found, and this callout would silently become "nothing of this
// shape has been approved before" — which is the failure the exclusion exists
// to prevent.
func TestApproval_DiffNamesWhatChangedOnAGrant(t *testing.T) {
	prior := consoleGrant("grant-old", "ap-old", 10, 20)
	current := consoleGrant("grant-new", "ap-new", 500, 20)
	priorReq := grantRequest(prior, approval.StateApproved)
	priorReq.ResolvedAt = testNow.Add(-2 * time.Hour)
	priorReq.Decisions = []approval.Decision{{Account: "dana", Approve: true, At: testNow.Add(-2 * time.Hour)}}
	currentReq := grantRequest(current, approval.StatePending)

	d := renderableDeps()
	d.Approvals = &fakeApprovals{
		pending:  []approval.Request{currentReq},
		resolved: []approval.Request{priorReq},
		grants:   []approval.Grant{prior, current},
	}

	content := contentOf(get(t, newTestHandler(d, accounts.RoleAdmin), "/console/approvals/ap-new").Body.String())

	if !strings.Contains(content, "fan-out ceiling 10 Nodes → 500 Nodes") {
		t.Error("the diff callout does not name the one thing that changed between two Grants of the same shape")
	}
	if !strings.Contains(content, "dana") {
		t.Error("the callout does not say who approved the prior Grant")
	}
}

// TestApprovalDiff_NeverClaimsAFanOutItDoesNotHave.
//
// A park creates NO JOB AT ALL, so there is no Task and no result anywhere to
// count Nodes from for the record being rendered — only for a prior one that
// already ran. The node count in the summary is Relay-authored prose, and
// parsing a number back out of it is exactly the fidelity trap the summary
// exists to prevent. So the callout names the fan-out as UNCOMPARABLE rather
// than deriving one.
func TestApprovalDiff_NeverClaimsAFanOutItDoesNotHave(t *testing.T) {
	shape := consoleShapeKey("pkg.install", map[string]string{"name": "nginx"})
	priorReq := approval.Request{
		ID: "ap-old", PlanHash: "hash-1180", ShapeKey: shape, State: approval.StateApproved,
		Summary: `pkg.install(name="nginx") [mutate] on 1180 node(s)`, ResolvedAt: testNow.Add(-time.Hour),
	}
	currentReq := approval.Request{
		ID: "ap-new", PlanHash: "hash-2214", ShapeKey: shape, State: approval.StatePending,
		Summary: `pkg.install(name="nginx") [mutate] on 2214 node(s)`,
		Require: approval.Requirement{Count: 1}, ExpiresAt: testNow.Add(time.Hour),
	}

	d := renderableDeps()
	d.Approvals = &fakeApprovals{
		pending:  []approval.Request{currentReq},
		resolved: []approval.Request{priorReq},
	}
	d.Queries = &fakeQueries{rows: []capability.AuditRow{
		{Kind: audit.KindApprovalRequested, ApprovalID: "ap-old", ActionKind: "operation", OperationName: "pkg.install", Args: map[string]string{"name": "nginx"}},
		{Kind: audit.KindApprovalRequested, ApprovalID: "ap-new", ActionKind: "operation", OperationName: "pkg.install", Args: map[string]string{"name": "nginx"}},
	}}

	action := buildApprovalAction(context.Background(), d, capability.Principal{}, "ap-new")
	diff := buildApprovalDiff(context.Background(), d, capability.Principal{}, currentReq, approval.Grant{}, grantIsAPlan, action, testNow)

	if !containsString(diff.NotComparable, "fan-out") {
		t.Errorf("the diff does not name the fan-out as uncomparable: %v", diff.NotComparable)
	}
	for _, c := range diff.Changes {
		if strings.Contains(c.Field, "fan-out") || strings.Contains(c.To, "2214") || strings.Contains(c.To, "2,214") {
			t.Errorf("the diff manufactured a fan-out change (%+v) — no source here carries one", c)
		}
	}
}

// TestApprovalDiff_ScaleArgumentChangeIsTheHeadline is the spec's other example
// — "except 1.24.0 → 1.25.0". Both records' arguments come from their own park
// audit records, joined on approval_id; approval_requests stores neither.
func TestApprovalDiff_ScaleArgumentChangeIsTheHeadline(t *testing.T) {
	shape := consoleShapeKey("pkg.install", map[string]string{"name": "nginx"})
	priorReq := approval.Request{ID: "ap-old", ShapeKey: shape, PlanHash: "hash-old", State: approval.StateApproved, ResolvedAt: testNow.Add(-time.Hour)}
	currentReq := approval.Request{
		ID: "ap-new", ShapeKey: shape, PlanHash: "hash-new", State: approval.StatePending,
		Require: approval.Requirement{Count: 1}, ExpiresAt: testNow.Add(time.Hour),
	}

	d := renderableDeps()
	d.Approvals = &fakeApprovals{
		pending:  []approval.Request{currentReq},
		resolved: []approval.Request{priorReq},
	}
	d.Queries = &fakeQueries{rows: []capability.AuditRow{
		{Kind: audit.KindApprovalRequested, ApprovalID: "ap-old", ActionKind: "operation", Args: map[string]string{"name": "nginx", "version": "1.24.0"}},
		{Kind: audit.KindApprovalRequested, ApprovalID: "ap-new", ActionKind: "operation", Args: map[string]string{"name": "nginx", "version": "1.25.0"}},
	}}

	content := contentOf(get(t, newTestHandler(d, accounts.RoleAdmin), "/console/approvals/ap-new").Body.String())

	if !strings.Contains(content, "version 1.24.0 → 1.25.0") {
		t.Error("the diff callout does not name the scale argument that moved")
	}
	if strings.Contains(content, "name nginx → nginx") {
		t.Error("the callout listed an argument that did not change")
	}
}

// TestApproval_LegacyShapeIsNeverAskedAbout: a record whose shape was never
// computed has no comparable prior BY CONSTRUCTION, so the Console does not ask.
// Not asking is the clearer statement of intent than asking and being refused.
func TestApproval_LegacyShapeIsNeverAskedAbout(t *testing.T) {
	req := approval.Request{
		ID: "ap-legacy", ShapeKey: approval.LegacyShapeKey("ap-legacy"), State: approval.StatePending,
		Require: approval.Requirement{Count: 1}, ExpiresAt: testNow.Add(time.Hour),
	}
	approvals := &fakeApprovals{pending: []approval.Request{req}}
	d := renderableDeps()
	d.Approvals = approvals

	content := contentOf(get(t, newTestHandler(d, accounts.RoleAdmin), "/console/approvals/ap-legacy").Body.String())

	if approvals.shapeCalls != 0 {
		t.Errorf("the Console asked for a same-shape prior %d times for a record with a legacy key", approvals.shapeCalls)
	}
	if !strings.Contains(content, "shape was never computed") {
		t.Error("the card does not state why nothing is compared")
	}
}

// TestApproval_NoPriorIsStatedNotManufactured: "when there is no comparable
// prior approval, say so plainly. Do not manufacture a diff."
func TestApproval_NoPriorIsStatedNotManufactured(t *testing.T) {
	req := approval.Request{
		ID: "ap-1", ShapeKey: consoleShapeKey("service.restart", map[string]string{"unit": "nginx"}),
		State: approval.StatePending, Require: approval.Requirement{Count: 1}, ExpiresAt: testNow.Add(time.Hour),
	}
	d := renderableDeps()
	d.Approvals = &fakeApprovals{pending: []approval.Request{req}}

	content := contentOf(get(t, newTestHandler(d, accounts.RoleAdmin), "/console/approvals/ap-1").Body.String())

	if !strings.Contains(content, "Nothing of this shape has been approved on this Relay before") {
		t.Error("the card does not state the absence of a comparable prior approval")
	}
	callout := content[strings.Index(content, `<section class="diff">`):strings.Index(content, "</section>")]
	if strings.Contains(callout, "→") {
		t.Error("an empty diff rendered as a diff")
	}
}

// TestApproval_TerminalStatesAreNotPaintedAsSuccess (#468).
//
// A denied approval is a HUMAN's refusal and never denied_by_policy — slate is
// reserved for Policy decisions, and borrowing it would say a daemon refused
// something it was never asked. An expired one is not a success either, and a
// pending one is not "unsupported".
func TestApproval_TerminalStatesAreNotPaintedAsSuccess(t *testing.T) {
	denied := approval.Request{
		ID: "ap-denied", State: approval.StateDenied, ResolvedAt: testNow.Add(-time.Hour),
		Require: approval.Requirement{Count: 1}, CreatedAt: testNow.Add(-2 * time.Hour), ExpiresAt: testNow.Add(time.Hour),
		Decisions: []approval.Decision{{Account: "dana", Approve: false, Reason: "not during the freeze", At: testNow.Add(-time.Hour)}},
	}
	lapsed := approval.Request{
		ID: "ap-lapsed", State: approval.StatePending,
		Require: approval.Requirement{Count: 1}, CreatedAt: testNow.Add(-2 * time.Hour), ExpiresAt: testNow.Add(-time.Minute),
	}
	d := renderableDeps()
	d.Approvals = &fakeApprovals{resolved: []approval.Request{denied, lapsed}}
	h := newTestHandler(d, accounts.RoleAdmin)

	for _, tc := range []struct{ id, state string }{{"ap-denied", "denied"}, {"ap-lapsed", "expired"}} {
		content := contentOf(get(t, h, "/console/approvals/"+tc.id).Body.String())
		if !strings.Contains(content, `data-state="`+tc.state+`"`) {
			t.Errorf("%s does not carry data-state=%q", tc.id, tc.state)
		}
		if strings.Contains(content, `data-outcome="success"`) {
			t.Errorf("%s renders as a successful Task outcome; an approval is not a Task", tc.id)
		}
		if strings.Contains(content, `data-outcome="denied_by_policy"`) {
			t.Errorf("%s reuses the Policy-decision colour for a human's answer", tc.id)
		}
		if strings.Contains(content, "Deciding is not available in this Console yet") {
			t.Errorf("%s offers deciding on a record nobody can decide", tc.id)
		}
	}
}

// TestApproval_DecisionsCarryTheirTimestamps (#468): "1 of 2 approvals · mike
// signed 2h ago" needs the when, which IS persisted and was simply never read
// into the view.
func TestApproval_DecisionsCarryTheirTimestamps(t *testing.T) {
	req := approval.Request{
		ID: "ap-1", State: approval.StatePending, Require: approval.Requirement{Count: 2},
		CreatedAt: testNow.Add(-3 * time.Hour), ExpiresAt: testNow.Add(time.Hour),
		Decisions: []approval.Decision{{
			Account: "dana", Approve: true, Channel: approval.ChannelOutOfBand,
			DeciderHuman: true, At: testNow.Add(-2 * time.Hour),
		}},
	}
	d := renderableDeps()
	d.Approvals = &fakeApprovals{pending: []approval.Request{req}}

	content := contentOf(get(t, newTestHandler(d, accounts.RoleAdmin), "/console/approvals/ap-1").Body.String())

	if !strings.Contains(content, "2026-08-25 10:00:00Z") {
		t.Error("the decisions table does not carry the stamped decision time")
	}
	if !strings.Contains(content, "dana signed 2h ago") {
		t.Error("the quorum line does not say when the first approver signed")
	}
}

// TestApproval_ScopeIsAClosedDisclosure: spec 08 makes expanding a Grant's Scope
// a deliberate cost — "it exists to buy attention, not to sell it". v0.6.0 ships
// the closed disclosure and states the rule; the enforcement needs a submit
// control to gate, which does not exist yet.
func TestApproval_ScopeIsAClosedDisclosure(t *testing.T) {
	g := consoleGrant("grant-1", "ap-grant", 200, 20)
	d := renderableDeps()
	d.Approvals = &fakeApprovals{pending: []approval.Request{grantRequest(g, approval.StatePending)}, grants: []approval.Grant{g}}

	content := contentOf(get(t, newTestHandler(d, accounts.RoleAdmin), "/console/approvals/ap-grant").Body.String())

	if !strings.Contains(content, `<details class="scope">`) {
		t.Fatal("the Grant's Scope is not a disclosure")
	}
	if strings.Contains(content, `<details class="scope" open`) {
		t.Error("the Scope disclosure is open by default, which gives away the attention it exists to buy")
	}
	if !strings.Contains(content, "Approving a Grant requires expanding this Scope at least once") {
		t.Error("the card does not state the rule")
	}
	if !strings.Contains(content, "at most <b>200</b> Nodes per dispatch") {
		t.Error("the Scope disclosure does not carry the fan-out ceiling")
	}
}

// TestApproval_AGrantRendersNoActionBlock.
//
// RequestGrant records its park with NO Selector and NO Action, so a Grant's
// audit row carries an empty Selector, an "unspecified" ActionKind and no
// arguments. Rendering that as an action block labelled "read from the park's
// audit record" would fabricate a fact on exactly the record type spec 08 calls
// a Grant. The Scope is what that card has to show.
func TestApproval_AGrantRendersNoActionBlock(t *testing.T) {
	g := consoleGrant("grant-1", "ap-grant", 200, 20)
	d := renderableDeps()
	d.Approvals = &fakeApprovals{pending: []approval.Request{grantRequest(g, approval.StatePending)}, grants: []approval.Grant{g}}
	d.Queries = &fakeQueries{rows: []capability.AuditRow{
		{Kind: audit.KindApprovalRequested, ApprovalID: "ap-grant", ActionKind: "unspecified"},
	}}

	content := contentOf(get(t, newTestHandler(d, accounts.RoleAdmin), "/console/approvals/ap-grant").Body.String())

	if strings.Contains(content, "What was asked for") {
		t.Error("a Grant rendered the action block — its park record carries no Selector and no Action, " +
			"so the block would be empty and labelled as if it had been read from the trail")
	}
	if !strings.Contains(content, "The Scope") {
		t.Error("a Grant did not render its Scope")
	}
}

// TestApproval_SelectorIsNotShownWhenTheRecordCannotSayWhatItWas.
//
// An empty stored Selector is AMBIGUOUS: Selector.String() returns "" both for
// "none recorded" and for a Selector with no predicates — and no predicates
// MATCHES EVERY NODE. Rendering the second as "(none)" would tell a human the
// widest dispatch there is targeted nothing, which is the highest-consequence
// lie this screen can tell.
func TestApproval_SelectorIsNotShownWhenTheRecordCannotSayWhatItWas(t *testing.T) {
	req := approval.Request{ID: "ap-1", State: approval.StatePending, Require: approval.Requirement{Count: 1}, ExpiresAt: testNow.Add(time.Hour)}

	fleetWide := renderableDeps()
	fleetWide.Approvals = &fakeApprovals{pending: []approval.Request{req}}
	fleetWide.Queries = &fakeQueries{rows: []capability.AuditRow{
		{Kind: audit.KindApprovalRequested, ApprovalID: "ap-1", ActionKind: "operation", Selector: ""},
	}}
	content := contentOf(get(t, newTestHandler(fleetWide, accounts.RoleAdmin), "/console/approvals/ap-1").Body.String())
	if !strings.Contains(content, "<b>every Node</b> (no Selector terms)") {
		t.Error("a known Action with an empty Selector must read as every Node, not as an absent Selector")
	}

	unknown := renderableDeps()
	unknown.Approvals = &fakeApprovals{pending: []approval.Request{req}}
	unknown.Queries = &fakeQueries{rows: []capability.AuditRow{
		{Kind: audit.KindApprovalRequested, ApprovalID: "ap-1", ActionKind: "unspecified", Selector: ""},
	}}
	content = contentOf(get(t, newTestHandler(unknown, accounts.RoleAdmin), "/console/approvals/ap-1").Body.String())
	if strings.Contains(content, "<dt>selector</dt>") {
		t.Error("a record with no Action kind rendered a Selector line — an empty stored Selector is " +
			"either 'none recorded' or 'every Node', and neither may be claimed from the other's absence")
	}
	if strings.Contains(content, "<b>every Node</b> (no Selector terms)") {
		t.Error("a record with no Action kind was rendered as a fleet-wide dispatch")
	}
	if !strings.Contains(content, "will not guess which") {
		t.Error("the card does not say why the Selector is absent")
	}
}

// TestApproval_ReleasedJobsAreListedOnTheCard, and the reason it needs 120 audit
// rows: the trail fans a dispatch out to ONE RECORD PER NODE, so a Grant over
// many Nodes buries its second Job well past the first page. A card that read
// one page would list one Job under a stated cap of fifty.
func TestApproval_ReleasedJobsAreListedOnTheCard(t *testing.T) {
	g := consoleGrant("grant-1", "ap-grant", 200, 20)
	var rows []capability.AuditRow
	// 520 Node rows for the first Job, so the second one starts BEYOND the
	// first page however large the page is. A fixture that fits in one page
	// cannot tell a walk from a single read.
	for i := 0; i < 520; i++ {
		rows = append(rows, capability.AuditRow{Kind: audit.KindDispatch, GrantID: "grant-1", JobID: "job-a", NodeID: "node-" + itoa(i)})
	}
	for i := 0; i < 80; i++ {
		rows = append(rows, capability.AuditRow{Kind: audit.KindDispatch, GrantID: "grant-1", JobID: "job-b", NodeID: "node-" + itoa(i)})
	}
	rows = append(rows, capability.AuditRow{Kind: audit.KindDispatch, GrantID: "grant-other", JobID: "job-elsewhere", NodeID: "node-x"})

	q := &fakeQueries{rows: rows}
	d := renderableDeps()
	d.Approvals = &fakeApprovals{pending: []approval.Request{grantRequest(g, approval.StatePending)}, grants: []approval.Grant{g}}
	d.Queries = q

	content := contentOf(get(t, newTestHandler(d, accounts.RoleAdmin), "/console/approvals/ap-grant").Body.String())

	for _, job := range []string{"job-a", "job-b"} {
		if !strings.Contains(content, "/console/jobs/"+job) {
			t.Errorf("the card does not link released Job %s — the list stopped at the first page of "+
				"per-Node rows", job)
		}
	}
	if strings.Contains(content, "job-elsewhere") {
		t.Error("the card listed a Job released by a different Grant; the grant_id filter is not applied")
	}
	if n := strings.Count(content, "/console/jobs/"); n != 2 {
		t.Errorf("the card rendered %d Job links for 2 distinct Jobs across 600 audit rows", n)
	}

	// Every QueryAudit writes its own read-audit record (ADR-0025), and each of
	// those lands on the read-egress screen as this principal's own exposure.
	// 600 rows at the maximum page size is TWO reads; at the default page size
	// it was thirteen, and a viewer refreshing this URL was an amplifier on an
	// append-only table and on a security screen at the same time.
	if q.auditCalls != 2 {
		t.Errorf("rendering one Grant card cost %d audit reads over 600 rows, want 2 — the walk must "+
			"page at the maximum, not at the default", q.auditCalls)
	}
}

// TestApproval_DiffIsTheFirstThingOnTheCard: spec 08 calls the callout "the
// single most valuable element on the screen", and a reader who has approved
// this shape before needs to see what is DIFFERENT before re-reading what is
// the same. That is a deviation from the spec's own card order, recorded in
// 99-open-decisions.md.
func TestApproval_DiffIsTheFirstThingOnTheCard(t *testing.T) {
	req := approval.Request{
		ID: "ap-1", PlanHash: "hash-1", State: approval.StatePending,
		Require: approval.Requirement{Count: 2}, ExpiresAt: testNow.Add(time.Hour),
	}
	d := renderableDeps()
	d.Approvals = &fakeApprovals{pending: []approval.Request{req}}

	content := contentOf(get(t, newTestHandler(d, accounts.RoleAdmin), "/console/approvals/ap-1").Body.String())

	diff := strings.Index(content, `class="diff"`)
	hash := strings.Index(content, "plan hash")
	quorum := strings.Index(content, "quorum")
	if diff < 0 || hash < 0 || quorum < 0 {
		t.Fatalf("the card is missing a block: diff=%d hash=%d quorum=%d", diff, hash, quorum)
	}
	if diff > hash || diff > quorum {
		t.Error("the diff callout is not the first thing on the card")
	}
}

// TestApproval_ObjectIsSelfContained is spec 08's first line: "mobile-first and
// self-contained: no nav, nothing competing, one card". An approver arrives from
// a link, on a phone, mid-something-else.
func TestApproval_ObjectIsSelfContained(t *testing.T) {
	req := approval.Request{ID: "ap-1", State: approval.StatePending, Require: approval.Requirement{Count: 1}, ExpiresAt: testNow.Add(time.Hour)}
	d := renderableDeps()
	d.Approvals = &fakeApprovals{pending: []approval.Request{req}}
	h := newTestHandler(d, accounts.RoleAdmin)

	card := get(t, h, "/console/approvals/ap-1").Body.String()
	if strings.Contains(card, `<aside class="nav">`) {
		t.Error("the approval object rendered the navigation rail — nothing may compete with the card")
	}
	if !strings.Contains(card, `href="#content"`) {
		t.Error("the focus-mode page dropped the skip link along with the nav")
	}
	if !strings.Contains(contentOf(card), `href="/console/approvals"`) {
		t.Error("the card offers no way back to the queue")
	}

	if queue := get(t, h, "/console/approvals").Body.String(); !strings.Contains(queue, `<aside class="nav">`) {
		t.Error("the queue lost its navigation; focus mode is for the object route only")
	}
}

// TestApprovals_MobileRulesShip is spec 08's 390px criterion, as far as Go can
// take it: it proves the rules SHIP, not that a browser lays them out. The
// criterion also needs the manual pass.
func TestApprovals_MobileRulesShip(t *testing.T) {
	css := get(t, newTestHandler(renderableDeps(), accounts.RoleAdmin), "/console/assets/console.css").Body.String()

	for _, rule := range []string{
		"@media (max-width: 480px)",
		".qrow { min-height: 44px; }",
		// The card has no queue rows: ITS touch targets are the back link and
		// the released-Job links, and a 44px rule on .qrow covers neither.
		".back a, .joblist a { display: inline-flex; align-items: center; min-height: 44px; }",
		"dl.kv dd { min-width: 0; }",
		".planhash { display: block; overflow-x: auto; }",
	} {
		if !strings.Contains(css, rule) {
			t.Errorf("the stylesheet no longer ships %q — the approval card is read on a phone", rule)
		}
	}
}

// TestApprovals_AGrantStoreFailureDoesNotCostTheQueue: the Grant read decorates
// some rows with their Scope. A queue is what an operator opens when something
// is about to lapse, so a seam that decorates it must not be able to take the
// whole screen down.
func TestApprovals_AGrantStoreFailureDoesNotCostTheQueue(t *testing.T) {
	d := renderableDeps()
	d.Approvals = &fakeApprovals{
		pending: []approval.Request{{
			ID: "ap-1", Summary: "restart nginx on 3 Nodes", CreatedAt: testNow,
			ExpiresAt: testNow.Add(time.Hour), Require: approval.Requirement{Count: 1},
		}},
		grantsErr: errNotFound,
	}

	rec := get(t, newTestHandler(d, accounts.RoleAdmin), "/console/approvals")
	if rec.Code != http.StatusOK {
		t.Fatalf("a Grant-store failure returned %d for the whole queue, want 200", rec.Code)
	}
	content := contentOf(rec.Body.String())
	if !strings.Contains(content, "restart nginx on 3 Nodes") {
		t.Error("the queue lost its rows because the Grant store failed")
	}
	if !strings.Contains(content, "The Grant store could not be read") {
		t.Error("the queue degraded silently — a row that is a Grant now renders without saying its Scope is missing")
	}
}

// TestApprovals_FiltersMatchOnEveryDimension is the filter set spec 14 asks for
// — "by requester, Operation, risk class, quorum state, and whether this Account
// is an eligible approver". Every value is compared IN MEMORY against rows the
// capability layer already returned; none of them reaches a seam.
func TestApprovals_FiltersMatchOnEveryDimension(t *testing.T) {
	row := approvalRow{
		Requester: "gleipnir-prod", Operation: "run_operation", Risk: "mutate",
		Signed: 1, Required: 2,
	}
	unsigned := row
	unsigned.Signed = 0
	complete := row
	complete.Signed = 2

	for _, tc := range []struct {
		name  string
		f     approvalFilter
		row   approvalRow
		match bool
	}{
		{"empty filter matches everything", approvalFilter{}, row, true},
		{"requester hit", approvalFilter{Who: "gleipnir-prod"}, row, true},
		{"requester is case-insensitive", approvalFilter{Who: "Gleipnir-Prod"}, row, true},
		{"requester miss", approvalFilter{Who: "dana"}, row, false},
		{"operation hit", approvalFilter{Op: "run_operation"}, row, true},
		{"operation miss", approvalFilter{Op: "raw_exec"}, row, false},
		{"risk hit", approvalFilter{Risk: "mutate"}, row, true},
		{"risk miss", approvalFilter{Risk: "read"}, row, false},
		{"unsigned hit", approvalFilter{Quorum: "unsigned"}, unsigned, true},
		{"unsigned miss on a partly-signed row", approvalFilter{Quorum: "unsigned"}, row, false},
		{"partial hit", approvalFilter{Quorum: "partial"}, row, true},
		{"partial miss on an unsigned row", approvalFilter{Quorum: "partial"}, unsigned, false},
		{"partial miss on a complete row", approvalFilter{Quorum: "partial"}, complete, false},
		{"an unknown quorum value narrows nothing", approvalFilter{Quorum: "nonsense"}, row, true},
		{"every dimension at once", approvalFilter{Who: "gleipnir-prod", Op: "run_operation", Risk: "mutate", Quorum: "partial"}, row, true},
		{"one wrong dimension refuses the row", approvalFilter{Who: "gleipnir-prod", Risk: "read"}, row, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.f.matches(tc.row); got != tc.match {
				t.Errorf("matches() = %v, want %v", got, tc.match)
			}
		})
	}
}

// TestApprovals_FilterValuesAreBoundedAndNeverEchoedUnbounded.
//
// The bound is a property, not hygiene: these values are rendered back into
// every chip href on the page, and an over-long one is DROPPED rather than
// truncated, because a truncated filter would silently match something the
// operator never typed.
func TestApprovals_FilterValuesAreBoundedAndNeverEchoedUnbounded(t *testing.T) {
	huge := strings.Repeat("a", maxApprovalFilterBytes+1)
	f := parseApprovalFilter(url.Values{"who": []string{huge}, "risk": []string{"mutate"}})

	if f.Who != "" {
		t.Errorf("a %d-byte requester filter was accepted", len(huge))
	}
	if f.Risk != "mutate" {
		t.Error("dropping an over-long value dropped the other filters with it")
	}
	if strings.Contains(f.with("op", "raw_exec"), huge) {
		t.Error("the over-long value was carried into a filter link")
	}

	atLimit := strings.Repeat("b", maxApprovalFilterBytes)
	if got := parseApprovalFilter(url.Values{"who": []string{atLimit}}).Who; got != atLimit {
		t.Error("a value exactly at the bound was dropped; the bound is a maximum, not an exclusive one")
	}

	d := renderableDeps()
	d.Approvals = &fakeApprovals{pending: []approval.Request{{
		ID: "ap-1", Summary: "restart nginx on 3 Nodes", RequestedBy: "gleipnir-prod",
		CreatedAt: testNow, ExpiresAt: testNow.Add(time.Hour), Require: approval.Requirement{Count: 1},
	}}}
	body := get(t, newTestHandler(d, accounts.RoleAdmin), "/console/approvals?who="+huge).Body.String()
	if strings.Contains(body, huge) {
		t.Error("the screen echoed an over-long query value back into the page")
	}
	if !strings.Contains(contentOf(body), "restart nginx on 3 Nodes") {
		t.Error("an over-long filter value silently emptied the queue instead of being ignored")
	}
}

// TestApprovals_FilterLinksPreserveTheOtherFiltersAndToggleTheirOwn. Every
// filter on this screen is an ANCHOR — there is no form, button or input in
// v0.6.0 — so the URL is the whole of the interaction.
func TestApprovals_FilterLinksPreserveTheOtherFiltersAndToggleTheirOwn(t *testing.T) {
	f := approvalFilter{Who: "dana", Risk: "mutate"}

	added := f.toggle("op", "raw_exec")
	for _, want := range []string{"who=dana", "risk=mutate", "op=raw_exec"} {
		if !strings.Contains(added, want) {
			t.Errorf("%s is missing %s — a filter link must preserve the others", added, want)
		}
	}
	if cleared := f.toggle("risk", "mutate"); strings.Contains(cleared, "risk=") {
		t.Errorf("%s still carries risk= — clicking the active value must clear it", cleared)
	} else if !strings.Contains(cleared, "who=dana") {
		t.Errorf("%s dropped the other filters while clearing one", cleared)
	}
	if bare := (approvalFilter{}).with("scope", ""); bare != "/console/approvals" {
		t.Errorf("an empty filter renders as %q, want a bare path", bare)
	}
	if strings.Contains(f.with("scope", scopeAll), "shape=") {
		t.Error("a filter link carries a shape parameter")
	}
}

// TestApprovals_FilterBarCountsAndOffersTheDimensionsThatVary. A dimension with
// one value is not a filter — it selects everything and says nothing.
func TestApprovals_FilterBarCountsAndOffersTheDimensionsThatVary(t *testing.T) {
	rows := []approvalRow{
		{Requester: "gleipnir-prod", Operation: "run_operation", Risk: "mutate", Signed: 0, Required: 1, Waiting: waitingUnknown},
		{Requester: "gleipnir-prod", Operation: "raw_exec", Risk: "mutate", Signed: 1, Required: 2, Waiting: waitingNo},
	}
	groups := approvalFilterGroups(rows, approvalFilter{})

	by := map[string]filterGroup{}
	for _, g := range groups {
		by[g.Name] = g
	}
	if _, offered := by["risk"]; offered {
		t.Error("a risk filter is offered for a queue where every row is a mutate")
	}
	ops, offered := by["operation"]
	if !offered || len(ops.Options) != 2 {
		t.Fatalf("the operation filter offers %d options, want both values", len(ops.Options))
	}
	who := by["requester"]
	if len(who.Options) != 1 || who.Options[0].Count != 2 {
		t.Errorf("the requester chip counts %v, want one chip counting both rows", who.Options)
	}
	waiting := by["waiting"]
	if len(waiting.Options) != 2 || waiting.Options[0].Count != 1 {
		t.Errorf("the waiting chip counts %v, want 1 of the 2 rows waiting on this caller", waiting.Options)
	}
}

// TestApprovals_HidingIsAttributedToTheFilterThatDidIt. "Hiding 3 addressed to
// somebody else" beside a risk filter that hid two of them is the screen
// explaining itself wrongly, on the screen whose job is explaining itself.
func TestApprovals_HidingIsAttributedToTheFilterThatDidIt(t *testing.T) {
	rows := []approvalRow{
		{ID: "mine-mutate", Risk: "mutate", Waiting: waitingYes},
		{ID: "mine-read", Risk: "read", Waiting: waitingYes},
		{ID: "theirs-mutate", Risk: "mutate", Waiting: waitingNo},
	}

	v := buildApprovalsView(rows, approvalFilter{Risk: "mutate"})
	if v.Shown != 1 {
		t.Fatalf("shown = %d, want 1", v.Shown)
	}
	if v.Hidden != 2 {
		t.Errorf("hidden = %d, want 2 — Hidden is every row not on screen", v.Hidden)
	}
	if v.HiddenByScope != 1 {
		t.Errorf("hidden by audience = %d, want 1 — the risk filter's row must not be attributed "+
			"to the audience", v.HiddenByScope)
	}
}

// TestApproval_AnUnreadableGrantStoreIsItsOwnState (S3).
//
// approval.ErrGrantNotFound travels unwrapped from the capability layer
// precisely so a surface can tell "this is not a Grant" from "the store did not
// answer". Collapsing them renders a standing authorization as a one-off Plan —
// no ceiling, no window, no use limit — with an action block reading "arguments:
// none recorded". Inert while nothing can be decided, and a decision-safety bug
// the day it can be.
func TestApproval_AnUnreadableGrantStoreIsItsOwnState(t *testing.T) {
	g := consoleGrant("grant-1", "ap-grant", 200, 20)
	d := renderableDeps()
	d.Approvals = &fakeApprovals{
		pending:   []approval.Request{grantRequest(g, approval.StatePending)},
		grants:    []approval.Grant{g},
		grantsErr: errNotFound,
	}
	d.Queries = &fakeQueries{rows: []capability.AuditRow{
		{Kind: audit.KindApprovalRequested, ApprovalID: "ap-grant", ActionKind: "unspecified"},
	}}

	content := contentOf(get(t, newTestHandler(d, accounts.RoleAdmin), "/console/approvals/ap-grant").Body.String())

	if !strings.Contains(content, "the Grant store did not answer") {
		t.Error("an unreadable Grant store is not stated on the card")
	}
	if strings.Contains(content, "none recorded") {
		t.Error("the card fell through to the Plan action block, so a Request that may authorize a " +
			"Scope reads as a one-off dispatch with no arguments")
	}
	if strings.Contains(content, "<details class=\"scope\">") {
		t.Error("the card rendered a Scope it could not read")
	}
	if !strings.Contains(content, "nothing is being compared") {
		t.Error("the diff callout compared a record whose kind is unknown")
	}
}

// TestApprovalDiff_AnArgumentValueWithASpaceIsNotTruncated. The diff compares
// the audit row's argument MAP; comparing the rendered "k=v k=v" string would
// split "msg=hello world" on the space and report a truncation as a change.
func TestApprovalDiff_AnArgumentValueWithASpaceIsNotTruncated(t *testing.T) {
	prior := approvalAction{Known: true, args: map[string]string{"msg": "hello world"}}
	current := approvalAction{Known: true, args: map[string]string{"msg": "hello world"}}
	if changes := argChanges(prior, current); len(changes) != 0 {
		t.Errorf("identical arguments diffed as %v", changes)
	}

	current.args = map[string]string{"msg": "goodbye world"}
	changes := argChanges(prior, current)
	if len(changes) != 1 || changes[0].From != "hello world" || changes[0].To != "goodbye world" {
		t.Errorf("argChanges() = %+v, want the whole value on both sides", changes)
	}
}

// TestApprovals_LapsedRowsAreOrderedMostRecentFirst. Within the lapsed group the
// order flips: "it expired a minute ago" is a different conversation from "it
// expired on Tuesday", and only one of them is still live.
func TestApprovals_LapsedRowsAreOrderedMostRecentFirst(t *testing.T) {
	rows := queueRows([]approval.Request{
		{ID: "lapsed-tuesday", CreatedAt: testNow.Add(-72 * time.Hour), ExpiresAt: testNow.Add(-48 * time.Hour), Require: approval.Requirement{Count: 1}},
		{ID: "lapsed-a-minute-ago", CreatedAt: testNow.Add(-2 * time.Hour), ExpiresAt: testNow.Add(-time.Minute), Require: approval.Requirement{Count: 1}},
		{ID: "live", CreatedAt: testNow, ExpiresAt: testNow.Add(time.Hour), Require: approval.Requirement{Count: 1}},
	})

	want := []string{"live", "lapsed-a-minute-ago", "lapsed-tuesday"}
	for i, id := range want {
		if rows[i].ID != id {
			t.Fatalf("row %d is %s, want %s", i, rows[i].ID, id)
		}
	}
}
