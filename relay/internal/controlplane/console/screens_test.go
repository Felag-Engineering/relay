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

// TestApprovals_OrderIsNearestExpiryFirst is spec 14's ordering rule. An
// approval that lapses because it sat below the fold is a failure of the screen,
// and arrival order is exactly how that happens.
func TestApprovals_OrderIsNearestExpiryFirst(t *testing.T) {
	rows := buildApprovalRows([]approval.Request{
		{ID: "old-but-roomy", CreatedAt: testNow.Add(-2 * time.Hour), ExpiresAt: testNow.Add(4 * time.Hour), Require: approval.Requirement{Count: 1}},
		{ID: "new-and-urgent", CreatedAt: testNow.Add(-1 * time.Minute), ExpiresAt: testNow.Add(3 * time.Minute), Require: approval.Requirement{Count: 2}},
	}, testNow)

	if rows[0].ID != "new-and-urgent" {
		t.Errorf("first row is %s, want new-and-urgent — order is by expiry, never by arrival", rows[0].ID)
	}
	if !rows[0].Urgent {
		t.Error("a request expiring in 3 minutes is not marked urgent")
	}
	if rows[1].Urgent {
		t.Error("a request with 4 hours left is marked urgent")
	}
}

// TestApprovals_QueueOffersNoApproveControl is spec 14's hard rule. A row-level
// Approve lets someone approve without seeing what they approved, which is the
// entire failure the mechanism exists to prevent.
func TestApprovals_QueueOffersNoApproveControl(t *testing.T) {
	d := renderableDeps()
	d.Approvals = fakeApprovals{pending: []approval.Request{{
		ID: "ap-1", Summary: "restart nginx on 412 Nodes",
		CreatedAt: testNow, ExpiresAt: testNow.Add(time.Hour),
		Require: approval.Requirement{Count: 2},
	}}}
	body := get(t, newTestHandler(d, accounts.RoleAdmin), "/console/approvals").Body.String()

	// Scoped to the screen's own content. The layout carries a sign-out form,
	// which is a mutating route and is meant to be there — the assertion is
	// about what the QUEUE offers, not about the shell around it.
	if content := contentOf(body); strings.Contains(content, "<form") || strings.Contains(content, "<button") {
		t.Error("the approval queue rendered a form or button — v0.6.0 is read-only and no row may carry a decision")
	}
	if !strings.Contains(body, "restart nginx on 412 Nodes") {
		t.Error("the queue did not render the Relay-authored summary")
	}
}

// TestApprovals_EmptyQueueSaysSoPlainly — an empty approval queue is good news,
// not a blank screen.
func TestApprovals_EmptyQueueSaysSoPlainly(t *testing.T) {
	d := renderableDeps()
	d.Approvals = fakeApprovals{}
	body := get(t, newTestHandler(d, accounts.RoleAdmin), "/console/approvals").Body.String()
	if !strings.Contains(body, "Nothing is waiting") {
		t.Error("an empty approval queue did not say so")
	}
}

// TestReads_CountsCallsTargetsAndNodesSeparately is spec 17's headline: one
// file.read across 4,000 Nodes is one target and four thousand exposures, and
// which number matters depends on the question.
func TestReads_CountsCallsTargetsAndNodesSeparately(t *testing.T) {
	v := buildReads([]audit.Record{
		{Kind: audit.KindDispatch, OperationName: "file.read", Args: map[string]string{"path": "/etc/hosts"}, NodeID: "n1", Timestamp: testNow},
		{Kind: audit.KindDispatch, OperationName: "file.read", Args: map[string]string{"path": "/etc/hosts"}, NodeID: "n2", Timestamp: testNow},
		{Kind: audit.KindDispatch, OperationName: "file.read", Args: map[string]string{"path": "/etc/shadow"}, NodeID: "n1",
			Outcome: jobs.OutcomeDeniedByPolicy, Timestamp: testNow},
		{Kind: audit.KindRead, ActionKind: "list_nodes", Timestamp: testNow},
		// A mutate must not be counted as a read.
		{Kind: audit.KindDispatch, OperationName: "service.restart", NodeID: "n1", Timestamp: testNow},
	})

	// Node reads and control-plane enumerations are counted apart. list_nodes
	// touches no Node and can carry no Policy verdict, so folding it into these
	// figures only ever moved the denominators — and it sat in the by-target
	// table reporting "0 Nodes" beside rows with a real reach.
	if v.Calls != 3 {
		t.Errorf("reads from Nodes = %d, want 3 — service.restart is a mutate and "+
			"list_nodes is an enumeration; neither is a read from a Node", v.Calls)
	}
	if v.Enumerations != 1 {
		t.Errorf("control-plane enumerations = %d, want 1 (list_nodes)", v.Enumerations)
	}
	if v.Nodes != 2 {
		t.Errorf("Nodes touched = %d, want 2", v.Nodes)
	}
	if v.Targets != 2 {
		t.Errorf("distinct targets = %d, want 2 (the two paths read off a Node)", v.Targets)
	}
	if len(v.EnumTargets) != 1 || v.EnumTargets[0].Target != "list_nodes" {
		t.Errorf("enumeration targets = %+v, want one list_nodes row", v.EnumTargets)
	}
	if v.Refused != 1 {
		t.Errorf("refused reads = %d, want 1", v.Refused)
	}
	// The refused target sorts first: the deny-list catching something is the
	// row worth reading.
	if v.Targets2[0].Refused == 0 {
		t.Errorf("the refused target did not sort first: %+v", v.Targets2)
	}

	// Per-target Node counts are DISTINCT Nodes. Counting records instead makes
	// a repeated read report more Nodes than the fleet contains, on the one
	// screen whose job is to say how far an agent reached.
	// And no enumeration leaks into the by-target table, where every row is
	// supposed to have reached a machine.
	for _, tg := range v.Targets2 {
		if tg.Nodes == 0 {
			t.Errorf("%s is in the Node-read table with no Node — it is an enumeration", tg.Target)
		}
		if tg.Target == "file.read /etc/hosts" && tg.Nodes != 2 {
			t.Errorf("%s reports %d Nodes, want 2 distinct", tg.Target, tg.Nodes)
		}
		if tg.Nodes > v.Nodes {
			t.Errorf("%s reports %d Nodes, more than the %d the whole window touched",
				tg.Target, tg.Nodes, v.Nodes)
		}
	}
}

// TestReads_RepeatedReadOfOnePathDoesNotInflateItsNodeCount is the regression
// guard for the count the dev fleet exposed: three Nodes read five times must
// read "3 Nodes", not "15".
func TestReads_RepeatedReadOfOnePathDoesNotInflateItsNodeCount(t *testing.T) {
	var recs []audit.Record
	for i := 0; i < 5; i++ {
		for _, n := range []string{"n1", "n2", "n3"} {
			recs = append(recs, audit.Record{
				Kind: audit.KindDispatch, OperationName: "file.read",
				Args: map[string]string{"path": "/etc/shadow"}, NodeID: n,
				Outcome: jobs.OutcomeDeniedByPolicy, Timestamp: testNow,
			})
		}
	}
	v := buildReads(recs)

	if len(v.Targets2) != 1 {
		t.Fatalf("got %d targets, want 1", len(v.Targets2))
	}
	if got := v.Targets2[0].Nodes; got != 3 {
		t.Errorf("the target reports %d Nodes across a 3-Node fleet, want 3", got)
	}
	if v.Targets2[0].Calls != 15 {
		t.Errorf("calls = %d, want 15 — calls and Nodes are different questions", v.Targets2[0].Calls)
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
	d.Approvals = fakeApprovals{pending: []approval.Request{{ID: "ap-1", ExpiresAt: testNow.Add(time.Hour), Require: approval.Requirement{Count: 1}}}}
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
	for _, path := range walkableScreens(d, fixtureIDs) {
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
	rows := buildApprovalRows([]approval.Request{
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
	}, testNow)

	for _, r := range rows {
		if r.Identical != 1 {
			t.Errorf("%s is grouped with %d others — two different actions are not alike",
				r.ID, r.Identical-1)
		}
	}
	if rows[0].IdenticalKey == rows[1].IdenticalKey {
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
	rows := buildApprovalRows([]approval.Request{
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
	}, testNow)

	for _, r := range rows {
		if r.Identical != 2 {
			t.Errorf("%s reports %d of the same shape, want 2", r.ID, r.Identical)
		}
	}
}

// TestApprovals_UncomparableShapesAreNeverGrouped: a pre-#415 record carries a
// legacy key and its true shape is unknowable. Bucketing every such record
// together would tell an approver that records with nothing in common are
// alike, which is the precise failure the shape key exists to prevent.
func TestApprovals_UncomparableShapesAreNeverGrouped(t *testing.T) {
	rows := buildApprovalRows([]approval.Request{
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
	}, testNow)

	for _, r := range rows {
		if r.Identical != 1 {
			t.Errorf("%s is grouped with %d others — a record with no comparable shape groups with nothing",
				r.ID, r.Identical-1)
		}
		if r.IdenticalKey != "" {
			t.Errorf("%s carries grouping key %q, want none", r.ID, r.IdenticalKey)
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
	body := get(t, newTestHandler(fleetFixture(), accounts.RoleAdmin), "/console/").Body.String()

	if !strings.Contains(body, `<nav class="navgroups" aria-label="Console">`) {
		t.Error("the navigation is not inside a <nav> landmark")
	}
	for _, group := range []NavGroup{NavObserve, NavAct, NavAdminister} {
		slug := strings.ToLower(string(group))
		if !strings.Contains(body, `<h2 class="navsec" id="navsec-`+slug+`">`) {
			t.Errorf("the %s group is not a heading", group)
		}
		if !strings.Contains(body, `<ul class="navlist" aria-labelledby="navsec-`+slug+`">`) {
			t.Errorf("the %s group is not a list labelled by its own heading", group)
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
	for _, tg := range buildReads(recs).EnumTargets {
		if !strings.Contains(body, "enumerated "+tg.Target) {
			t.Errorf("Read egress calls it %q and Activity does not", tg.Target)
		}
	}
}

// TestReads_EnumerationsAreCountedApartFromNodeReads.
//
// list_nodes and list_operations touch no Node and can carry no Policy verdict
// — Policy is a Node's, and there is no Node. They sat inside the headline
// "read calls" and "distinct targets" beside file.read /etc/shadow, and in the
// by-target table reporting "0 Nodes" next to rows with a real reach. Both are
// exposure and both are still counted; blending them made each number mean
// less, on the screen whose whole argument is that reading is exfiltration.
func TestReads_EnumerationsAreCountedApartFromNodeReads(t *testing.T) {
	v := buildReads([]audit.Record{
		{Kind: audit.KindDispatch, OperationName: "file.read",
			Args: map[string]string{"path": "/etc/shadow"}, NodeID: "n1",
			Outcome: jobs.OutcomeDeniedByPolicy, Timestamp: testNow},
		{Kind: audit.KindRead, ActionKind: "list_nodes", Timestamp: testNow},
		{Kind: audit.KindRead, ActionKind: "list_nodes", Timestamp: testNow},
		{Kind: audit.KindRead, ActionKind: "list_operations", Timestamp: testNow},
	})

	if v.Calls != 1 {
		t.Errorf("reads from Nodes = %d, want 1", v.Calls)
	}
	if v.Enumerations != 3 {
		t.Errorf("enumerations = %d, want 3", v.Enumerations)
	}
	if len(v.Targets2) != 1 {
		t.Errorf("by-target has %d rows, want 1 — enumerations belong in their own panel", len(v.Targets2))
	}
	if len(v.EnumTargets) != 2 {
		t.Fatalf("enumeration targets = %d, want 2 distinct tools", len(v.EnumTargets))
	}
	// Busiest tool first.
	if v.EnumTargets[0].Target != "list_nodes" || v.EnumTargets[0].Calls != 2 {
		t.Errorf("enumeration targets are %+v, want list_nodes with 2 calls first", v.EnumTargets)
	}

	// Per-principal, the two families stay in their own columns.
	if len(v.Principals) != 1 {
		t.Fatalf("principals = %d, want 1", len(v.Principals))
	}
	if p := v.Principals[0]; p.Calls != 1 || p.Enum != 3 {
		t.Errorf("principal reports %d Node reads and %d enumerations, want 1 and 3", p.Calls, p.Enum)
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
