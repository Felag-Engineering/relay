package console

// node_test.go holds the node-detail and comparison coverage added by #421.
//
// The five older TestNode_* cases stay in screens_test.go, where the reviewer
// of #449 left them: moving them would make this diff rename-shaped and hide
// the real change. Everything here is new, and it is here rather than there
// because screens_test.go is 2,500 lines shared by seven screens, which makes
// it the merge point for every screen issue at once.
//
// The bias is the same as screens_test.go's: assert ABSENCE. That a Node page
// renders is easy; that no role, no flag and no route on it can change
// anything is the property the v0.6.0 acceptance criteria are about.

import (
	"context"
	"fmt"
	"html"
	"net/http"
	"net/url"
	"reflect"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/accounts"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/audit"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/jobs"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/policyview"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/registry"
)

// policyPanelOf slices the effective-Policy panel out of a rendered page, so an
// assertion about what the panel says is not satisfied by the same words
// appearing in the page header.
func policyPanelOf(body string) string {
	const open = "<h3>Effective Policy</h3>"
	i := strings.Index(body, open)
	if i < 0 {
		return ""
	}
	rest := body[i:]
	if j := strings.Index(rest, "</section>"); j >= 0 {
		return rest[:j]
	}
	return rest
}

// TestNode_PolicyPanelCarriesTheReceiptTime is spec 02's second acceptance
// criterion: the panel carries a timestamp and cannot be mistaken for
// Relay-held state.
//
// The timestamp is a RECEIPT time — when the Relay was told — because a
// snapshot is captured when a Node connects and the Relay has no live query to
// stamp. It is deliberately NOT LastSeen: LastSeen moves with every heartbeat
// while the snapshot does not, so rendering LastSeen here would overstate the
// Policy view's freshness by hours, which is precisely the confusion this
// criterion exists to prevent.
func TestNode_PolicyPanelCarriesTheReceiptTime(t *testing.T) {
	d := fleetFixture()
	d = withPolicy(d, map[string]policyview.Snapshot{"node-web-1": reportedSnapshot(policyview.Snapshot{
		AllowedOperations: []string{"service.restart"},
	}, testNow.Add(-90*time.Second))})

	body := get(t, newTestHandler(d, accounts.RoleAdmin), "/console/nodes/node-web-1").Body.String()
	panel := policyPanelOf(body)
	if panel == "" {
		t.Fatal("no effective-Policy panel rendered")
	}

	if !strings.Contains(panel, "2026-08-25 11:58:30Z") {
		t.Error("the Policy panel does not carry the absolute receipt time")
	}
	if !strings.Contains(panel, "1m ago") {
		t.Error("the Policy panel does not say how long ago the report was received")
	}
	// The Node was last seen four seconds ago and its Policy was reported
	// ninety. If the panel carried the heartbeat, this is what it would say.
	if strings.Contains(panel, "2026-08-25 11:59:56Z") {
		t.Error("the Policy panel rendered the Node's last-seen time as the Policy timestamp — " +
			"LastSeen moves with every heartbeat and the snapshot does not")
	}
	// And it says which kind of time it is. "Queried at" would be a claim the
	// Relay cannot make: nothing re-asked the Node.
	if !strings.Contains(panel, "receipt time, not a query time") {
		t.Error("the Policy panel does not distinguish the receipt time from a query time")
	}
}

// TestNode_PolicyPanelWithNoReceiptTimeSaysSo: a Snapshot that never went
// through policyview.Cache.Set has a zero receipt time, and a zero time
// rendered absolutely is a Policy read in 1970.
func TestNode_PolicyPanelWithNoReceiptTimeSaysSo(t *testing.T) {
	d := fleetFixture()
	d = withPolicy(d, map[string]policyview.Snapshot{"node-web-1": {AllowedOperations: []string{"service.restart"}}})

	panel := policyPanelOf(get(t, newTestHandler(d, accounts.RoleAdmin), "/console/nodes/node-web-1").Body.String())

	if !strings.Contains(panel, "a time that was not recorded") {
		t.Error("a snapshot with no receipt time did not say so")
	}
	if strings.Contains(panel, "1970") {
		t.Error("a zero receipt time rendered as 1970")
	}
}

// TestNode_OfflineNodePolicyCannotBeRefreshed is spec 02's offline state: the
// panel renders the last thing the engine said and states that nothing can
// re-ask it, rather than presenting a stale answer as a live one.
func TestNode_OfflineNodePolicyCannotBeRefreshed(t *testing.T) {
	d := fleetFixture() // node-db-1 is the fixture's offline Node.
	d = withPolicy(d, map[string]policyview.Snapshot{"node-db-1": reportedSnapshot(policyview.Snapshot{
		AllowedOperations: []string{"system.facts"},
	}, testNow.Add(-2*time.Hour))})

	panel := policyPanelOf(get(t, newTestHandler(d, accounts.RoleAdmin), "/console/nodes/node-db-1").Body.String())

	if !strings.Contains(panel, "cannot be refreshed") {
		t.Error("an offline Node's Policy panel does not say it cannot be refreshed")
	}
	// The rules still render. Hiding them would answer "what will it permit?"
	// with silence for exactly the Nodes an operator is most likely to be
	// investigating.
	if !strings.Contains(panel, "system.facts") {
		t.Error("an offline Node's Policy panel dropped the rules it had been told")
	}
	// A connected Node must not carry the claim.
	live := policyPanelOf(get(t, newTestHandler(withNodePolicy(d, "node-web-1"), accounts.RoleAdmin),
		"/console/nodes/node-web-1").Body.String())
	if strings.Contains(live, "cannot be refreshed") {
		t.Error("a connected Node's Policy panel claims it cannot be refreshed")
	}
}

// withNodePolicy wires a reported Snapshot for nodeID onto d, over the
// shared withPolicy fixture helper (fakes_test.go, #680).
func withNodePolicy(d Deps, nodeID string) Deps {
	return withPolicy(d, map[string]policyview.Snapshot{nodeID: reportedSnapshot(policyview.Snapshot{
		AllowedOperations: []string{"system.facts"},
	}, testNow.Add(-time.Minute))})
}

// TestNode_IsStructurallyReadOnly is the rendered half of "read-only
// structurally, not by permission".
//
// It runs as ADMIN — the strongest role — so a pass means NO role is offered a
// control, rather than that the role this test happened to pick was not. The
// seam type (PolicyReader has Get only), the AST guard in no_dispatch_test.go
// and the route walk below are the other three halves.
func TestNode_IsStructurallyReadOnly(t *testing.T) {
	d := fleetFixture()
	d = withPolicy(d, map[string]policyview.Snapshot{"node-web-1": reportedSnapshot(policyview.Snapshot{
		RawExecEnabled:    true,
		AllowedOperations: []string{"service.restart"},
	}, testNow.Add(-time.Minute))})
	h := newTestHandler(withExecution(d, true), accounts.RoleAdmin)

	for _, path := range []string{
		"/console/nodes/node-web-1?pin=node-web-1,node-web-2",
		"/console/nodes/node-web-1?pin=node-web-1",
		"/console/compare?nodes=node-web-1,node-web-2",
	} {
		content := contentOf(get(t, h, path).Body.String())
		for _, banned := range []string{
			"<form", "<button", "<input", `method="post"`,
			"hx-post", "hx-put", "hx-patch", "hx-delete",
		} {
			if strings.Contains(strings.ToLower(content), banned) {
				t.Errorf("%s renders %q — this screen has no write path to offer, at any role", path, banned)
			}
		}
	}
}

// TestNode_NoRouteUnderThisScreenMutates is the route half. It fails the day
// someone adds a POST here, not the day someone notices one.
func TestNode_NoRouteUnderThisScreenMutates(t *testing.T) {
	for _, r := range Routes(withExecution(renderableDeps(), true)) {
		if !strings.HasPrefix(r.Path, "/console/nodes/") && r.Path != "/console/compare" {
			continue
		}
		if r.Method != http.MethodGet {
			t.Errorf("route %s %s is not a GET — node detail and compare are read screens "+
				"(v0.6.0: zero routes reaching the capability layer's write or dispatch path)", r.Method, r.Path)
		}
	}
}

// TestNode_FingerprintLinksTargetTheSameValueAsASelector: spec 02 asks the
// fingerprint rows to link to the same value as a Selector. The link must
// carry the FULL fingerprint (ParseSelector has no notion of a short hash),
// and a value a Selector cannot carry must render with no link rather than a
// sanitised one — the Node reports these unvalidated, and a link the Console
// advertises as targetable is the wrong place to discover that.
func TestNode_FingerprintLinksTargetTheSameValueAsASelector(t *testing.T) {
	d := renderableDeps()
	d = withFleet(d, []registry.Node{
		{
			NodeID: "node-ok", Connected: true,
			PolicyFingerprint:      "aaaa111122223333",
			TemplateSetFingerprint: "bbbb444455556666",
		},
		{
			// A Node that reported a fingerprint with a Selector separator in
			// it. nodestate drops the value rather than trimming it.
			NodeID: "node-hostile", Connected: true,
			PolicyFingerprint: "aaaa1111, tag:pci=yes",
		},
	}...)
	h := newTestHandler(d, accounts.RoleAdmin)

	body := get(t, h, "/console/nodes/node-ok").Body.String()
	for _, term := range []string{
		"state:policy-fingerprint=aaaa111122223333",
		"state:template-fingerprint=bbbb444455556666",
	} {
		want := strings.ReplaceAll(linkContext{}.href(term), "&", "&amp;")
		if !strings.Contains(body, `href="`+want+`"`) {
			t.Errorf("no fingerprint link targeting %q (want href %q)", term, want)
		}
	}

	hostile := get(t, h, "/console/nodes/node-hostile").Body.String()
	if strings.Contains(hostile, "filter=state%3Apolicy-fingerprint") {
		t.Error("a fingerprint carrying a Selector separator was rendered as a link — " +
			"a self-reported value must never be sanitised into a targetable one")
	}
	// It is still SHOWN. Hiding it would leave the operator with no idea why
	// the row is odd.
	if !strings.Contains(hostile, "aaaa1111") {
		t.Error("the unlinkable fingerprint is not rendered at all")
	}
}

// TestNode_LabelRowNamesAllFourNamespaces: invariant 7's grammar is four
// namespaces with four different writers, and the explainer taught three.
func TestNode_LabelRowNamesAllFourNamespaces(t *testing.T) {
	body := get(t, newTestHandler(fleetFixture(), accounts.RoleAdmin), "/console/nodes/node-db-1").Body.String()

	for _, ns := range []string{"<b>node:</b>", "<b>tag:</b>", "<b>relay:</b>", "<b>state:</b>"} {
		if !strings.Contains(body, ns) {
			t.Errorf("the label explainer does not name %s", ns)
		}
	}
	// The security lane is `relay:` and only `relay:`. A tag rendered into it
	// is the one confusion the grammar exists to prevent.
	if strings.Contains(body, `data-ns="tag" data-lane="security"`) {
		t.Error("a tag: chip rendered in the security lane")
	}
	// And the explainer is honest about there being no tag storage yet.
	if !strings.Contains(body, "cannot store tag: labels yet") {
		t.Error("the explainer does not say tag: labels have no storage yet")
	}
	// And no tracker number is put in front of an operator.
	if m := trackerRef.FindString(html.UnescapeString(body)); m != "" {
		t.Errorf("the page carries a tracker reference %q", m)
	}
}

// TestNode_RunHereFollowsTheExecutionFlagAndTheRole covers both of spec 02's
// gating states at once: `viewer` gets no "Run here", and neither does anyone
// when console_execution is off. Absent, never disabled — a greyed-out control
// gives away the property the flag exists to preserve.
func TestNode_RunHereFollowsTheExecutionFlagAndTheRole(t *testing.T) {
	cases := []struct {
		name      string
		execution bool
		role      accounts.Role
		want      bool
	}{
		{"execution off, admin", false, accounts.RoleAdmin, false},
		{"execution on, viewer", true, accounts.RoleViewer, false},
		{"execution on, operator", true, accounts.RoleOperator, true},
		{"execution on, admin", true, accounts.RoleAdmin, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			h := newTestHandler(withExecution(fleetFixture(), c.execution), c.role)
			content := contentOf(get(t, h, "/console/nodes/node-web-1").Body.String())
			if got := strings.Contains(content, ">Run here</a>"); got != c.want {
				t.Errorf("Run here present = %v, want %v", got, c.want)
			}
		})
	}
}

// TestNode_RevokedNodeRendersItsRevocationRecord is spec 02's revoked state.
//
// The registry retains RevokedAt whether or not the trail was wired, so a
// revoked Node with no record must say the trail has none rather than go
// quiet: "we do not know who" and "nobody" are different answers.
func TestNode_RevokedNodeRendersItsRevocationRecord(t *testing.T) {
	revoked := registry.Node{NodeID: "node-gone", RevokedAt: testNow.Add(-time.Hour)}
	d := renderableDeps()
	d = withFleet(d, []registry.Node{revoked}...)

	// The revoke record is the OLDEST of many: a Node with more later records
	// than the recent-Task window holds must not lose the one act that
	// explains its state.
	recs := []audit.Record{{
		Kind: audit.KindNodeRevoke, NodeID: "node-gone",
		Principal: "alice:admin", Timestamp: testNow.Add(-time.Hour),
	}}
	for i := 0; i < nodeTaskRows+5; i++ {
		recs = append(recs, audit.Record{
			Kind: audit.KindDispatch, NodeID: "node-gone", OperationName: "system.facts",
			Outcome: jobs.OutcomeUnreachable, Timestamp: testNow.Add(-time.Duration(i) * time.Minute),
		})
	}
	d.Audit = fakeAudit{records: recs}

	body := get(t, newTestHandler(d, accounts.RoleAdmin), "/console/nodes/node-gone").Body.String()
	if !strings.Contains(body, "alice:admin") {
		t.Error("the revocation record's principal is not rendered — the middle rung of the " +
			"incident ladder is the irreversible one and must be attributable")
	}
	// This record predates #487, when the route accepted no reason to record.
	// The page must say THAT rather than render an empty field: "the operator
	// gave no reason" and "this Relay could not ask for one" are different
	// facts, and only the second is true here.
	if !strings.Contains(body, "revoked before the endpoint accepted one") {
		t.Error("the page does not explain why a pre-#487 record shows no reason")
	}

	// And a post-#487 record renders the reason the operator actually gave.
	withReason := append([]audit.Record(nil), recs...)
	withReason[0].Reason = "compromised host, INC-4471"
	d.Audit = fakeAudit{records: withReason}
	reasoned := get(t, newTestHandler(d, accounts.RoleAdmin), "/console/nodes/node-gone").Body.String()
	if !strings.Contains(reasoned, "compromised host, INC-4471") {
		t.Error("the recorded revocation reason is not rendered (#487)")
	}
	if strings.Contains(reasoned, "revoked before the endpoint accepted one") {
		t.Error("a record that HAS a reason still claims the endpoint could not accept one")
	}

	// The CAUSATIVE revocation is the one shown, not the latest. Revoke is
	// idempotent-204, so re-POSTing an already-revoked Node appends a second
	// record; showing that one would let the reason be relabelled after the
	// fact by the same principal.
	relabelled := append([]audit.Record(nil), withReason...)
	relabelled = append(relabelled, audit.Record{
		Kind: audit.KindNodeRevoke, NodeID: "node-gone",
		Principal: "alice:admin", Reason: "routine decommission",
		Timestamp: testNow,
	})
	d.Audit = fakeAudit{records: relabelled}
	page := get(t, newTestHandler(d, accounts.RoleAdmin), "/console/nodes/node-gone").Body.String()
	if !strings.Contains(page, "compromised host, INC-4471") {
		t.Error("a later revoke record relabelled the reason shown for the causative one")
	}
	if strings.Contains(page, "routine decommission") {
		t.Error("the summary shows a later revoke record instead of the causative one")
	}

	// And a revoked Node whose trail holds nothing says so.
	d.Audit = fakeAudit{}
	quiet := get(t, newTestHandler(d, accounts.RoleAdmin), "/console/nodes/node-gone").Body.String()
	if !strings.Contains(quiet, "The audit trail holds no record of this revocation") {
		t.Error("a revoked Node with no audit record rendered nothing about the revocation")
	}
}

// TestNode_PinIsCarriedInTheUrlAndCapsAtThree covers the pin's whole contract:
// it lives in the query string (so pinning is a link, not a write), it is
// idempotent, it caps at three, and the comparison only appears once there are
// two Nodes to compare.
func TestNode_PinIsCarriedInTheUrlAndCapsAtThree(t *testing.T) {
	d := renderableDeps()
	d = withFleet(d, []registry.Node{
		{NodeID: "n1", Connected: true}, {NodeID: "n2", Connected: true},
		{NodeID: "n3", Connected: true}, {NodeID: "n4", Connected: true},
	}...)
	h := newTestHandler(d, accounts.RoleAdmin)

	unpinned := get(t, h, "/console/nodes/n1").Body.String()
	if !strings.Contains(unpinned, `href="/console/nodes/n1?pin=n1"`) {
		t.Error("an unpinned Node offers no link that pins it")
	}
	if strings.Contains(unpinned, `class="pinbar"`) {
		t.Error("a page with nothing pinned still drew the pin bar")
	}

	one := get(t, h, "/console/nodes/n1?pin=n1").Body.String()
	if !strings.Contains(one, `class="pinbar"`) {
		t.Error("a pinned Node draws no pin bar")
	}
	if strings.Contains(one, "/console/compare") {
		t.Error("one pinned Node linked a comparison — a diff of one column is not a diff")
	}
	if !strings.Contains(one, "Pin 1 more to compare") {
		t.Error("one pinned Node was left with no word on how to reach a comparison")
	}

	// Pinning the same Node twice is a double click, not two columns.
	twice := get(t, h, "/console/nodes/n1?pin=n1,n1").Body.String()
	if strings.Count(twice, `class="pinchip"`) != 1 {
		t.Errorf("a duplicated pin rendered %d chips, want 1", strings.Count(twice, `class="pinchip"`))
	}

	two := get(t, h, "/console/nodes/n1?pin=n1,n2").Body.String()
	if !strings.Contains(two, `href="/console/compare?nodes=n1%2Cn2"`) {
		t.Error("two pinned Nodes offer no comparison link")
	}

	full := get(t, h, "/console/nodes/n4?pin=n1,n2,n3").Body.String()
	if strings.Count(full, `class="pinchip"`) != 3 {
		t.Errorf("a full pin set rendered %d chips, want 3", strings.Count(full, `class="pinchip"`))
	}
	if strings.Contains(full, `href="/console/nodes/n4?pin=n1%2Cn2%2Cn3%2Cn4"`) {
		t.Error("a fourth Node could still be pinned — the comparison caps at three")
	}
	if !strings.Contains(full, "Three is the maximum") {
		t.Error("a full pin set does not say why the pin link is gone")
	}
}

// TestPin_BarIsOneComponentAndAlwaysCarriesTheSetOnward.
//
// The bar is on three screens, and the first version of it was three copies
// that had already diverged: the comparison screen's "pick another from the
// fleet" — the only link on the only screen whose purpose is adding a third
// Node — dropped both pins. So this asserts the property on every screen that
// draws it, rather than on the one that happened to be wrong.
func TestPin_BarIsOneComponentAndAlwaysCarriesTheSetOnward(t *testing.T) {
	d := renderableDeps()
	d = withFleet(d, []registry.Node{
		{NodeID: "n1", Connected: true}, {NodeID: "n2", Connected: true}, {NodeID: "n3", Connected: true},
	}...)
	h := newTestHandler(d, accounts.RoleAdmin)

	for _, c := range []struct {
		path        string
		wantFleet   string // the "pick another from the fleet" href, "" = must not be drawn
		wantCompare bool
	}{
		{"/console/compare?nodes=n1,n2", "/console/?pin=n1%2Cn2", false},
		{"/console/nodes/n3?pin=n1,n2", "/console/?pin=n1%2Cn2", true},
		// On the fleet itself there is nowhere to send them.
		{"/console/?pin=n1,n2", "", true},
	} {
		body := get(t, h, c.path).Body.String()
		if !strings.Contains(body, `class="pinbar"`) {
			t.Fatalf("%s drew no pin bar", c.path)
		}
		if c.wantFleet == "" {
			if strings.Contains(body, "Pick another from the fleet") {
				t.Errorf("%s offers to send the operator to the fleet it is already on", c.path)
			}
		} else if !strings.Contains(body, `href="`+c.wantFleet+`">Pick another from the fleet`) {
			t.Errorf("%s: the fleet link does not carry the pin set (want href %q) — "+
				"a link that loses the pins is a link that cannot add a third Node", c.path, c.wantFleet)
		}
		if got := strings.Contains(body, "Compare these Nodes"); got != c.wantCompare {
			t.Errorf("%s: comparison link present = %v, want %v", c.path, got, c.wantCompare)
		}
	}
}

// TestPin_UnresolvableIdIsNotDrawnAsANode: a pinned id is whatever the link
// carried. A crafted URL must not make the Console render `node-prod-7` as a
// machine that exists, on any screen that draws the bar.
func TestPin_UnresolvableIdIsNotDrawnAsANode(t *testing.T) {
	d := renderableDeps()
	d = withFleet(d, []registry.Node{{NodeID: "n1", Connected: true}}...)
	h := newTestHandler(d, accounts.RoleAdmin)

	for _, path := range []string{
		"/console/nodes/n1?pin=n1,node-prod-7",
		"/console/?pin=n1,node-prod-7",
		"/console/compare?nodes=n1,node-prod-7",
	} {
		body := get(t, h, path).Body.String()
		if strings.Contains(body, `href="/console/nodes/node-prod-7`) {
			t.Errorf("%s links a pinned id that resolves to no Node", path)
		}
		if !strings.Contains(body, "not in this registry") {
			t.Errorf("%s renders an unresolvable pinned id without saying it is not a Node", path)
		}
	}
}

var hiddenInputPattern = regexp.MustCompile(`<input type="hidden" name="([^"]+)" value="([^"]*)">`)

// rowPinForm returns the pin toggle's form for one Fleet row.
func rowPinForm(t *testing.T, body, id string) string {
	t.Helper()
	at := strings.Index(body, `aria-label="Pin `+id+` to compare"`)
	if at < 0 {
		t.Fatalf("no pin toggle for %s", id)
	}
	start := strings.LastIndex(body[:at], "<form")
	end := strings.Index(body[at:], "</form>")
	if start < 0 || end < 0 {
		t.Fatalf("the pin toggle for %s is not inside a form", id)
	}
	return body[start : at+end]
}

// formQuery reads the hidden inputs a form would submit. Values are
// unescaped: html/template escapes some characters in attributes.
func formQuery(form string) url.Values {
	q := url.Values{}
	for _, m := range hiddenInputPattern.FindAllStringSubmatch(form, -1) {
		q.Set(m[1], html.UnescapeString(m[2]))
	}
	return q
}

func TestFleet_RowPinIsAGetFormThatTogglesTheNode(t *testing.T) {
	h := newTestHandler(fleetFixture(), accounts.RoleAdmin)

	body := get(t, h, "/console/?filter=node:env=prod&group=role").Body.String()
	form := rowPinForm(t, body, "node-web-1")
	for _, want := range []string{`method="get"`, `action="/console/#pin-node-web-1"`, `type="submit"`, `aria-pressed="false"`} {
		if !strings.Contains(form, want) {
			t.Errorf("row pin form lacks %s: %s", want, form)
		}
	}
	for _, banned := range []string{`method="post"`, "csrf_token"} {
		if strings.Contains(form, banned) {
			t.Errorf("row pin form carries %s — a pin is a query string, not a write", banned)
		}
	}
	if !strings.Contains(body, `id="pin-node-web-1"`) {
		t.Error("the pin cell has no id for the form to return the keyboard to")
	}
	q := formQuery(form)
	if q.Get("filter") != "node:env=prod" || q.Get("group") != "role" || q.Get("pin") != "node-web-1" {
		t.Errorf("toggle query = %v, want filter, group kept and pin=node-web-1", q)
	}

	body = get(t, h, "/console/?pin=node-web-1").Body.String()
	form = rowPinForm(t, body, "node-web-1")
	if !strings.Contains(form, `aria-pressed="true"`) {
		t.Error("a pinned row's toggle is not pressed")
	}
	if formQuery(form).Has("pin") {
		t.Error("unpinning the only pin still carries a pin parameter")
	}
	q = formQuery(rowPinForm(t, body, "node-web-2"))
	if q.Get("pin") != "node-web-1,node-web-2" {
		t.Errorf("pin = %q, want node-web-1,node-web-2", q.Get("pin"))
	}
	if q.Get("group") != "env" {
		t.Errorf("group = %q, want the default grouping env kept", q.Get("group"))
	}

	body = get(t, h, "/console/?group=-").Body.String()
	if g := formQuery(rowPinForm(t, body, "node-web-1")).Get("group"); g != "-" {
		t.Errorf("group = %q, want - (no grouping must not be re-defaulted)", g)
	}

	body = get(t, h, "/console/?pin=node-web-1,node-web-2,node-web-3").Body.String()
	if !strings.Contains(rowPinForm(t, body, "node-db-1"), " disabled") {
		t.Error("with three pinned, an unpinned row's toggle is not disabled")
	}
	if got := formQuery(rowPinForm(t, body, "node-web-2")).Get("pin"); got != "node-web-1,node-web-3" {
		t.Errorf("unpin pin = %q, want node-web-1,node-web-3", got)
	}
}

func TestFleet_HostilePinIsEscapedAndRoundTrips(t *testing.T) {
	h := newTestHandler(fleetFixture(), accounts.RoleAdmin)
	payload := `x"><img src=x onerror=alert(1)>`

	body := get(t, h, "/console/?pin="+url.QueryEscape(payload)).Body.String()
	if strings.Contains(body, payload) || strings.Contains(body, "<img src=x") {
		t.Fatal("a hostile pin id reached the page unescaped")
	}
	form := rowPinForm(t, body, "node-web-1")
	if got := formQuery(form).Get("pin"); !strings.Contains(got, payload) {
		t.Errorf("row pin value = %q, want it to unescape back to the hostile id", got)
	}
}

func TestPin_BothEntryPointsReachCompare(t *testing.T) {
	h := newTestHandler(fleetFixture(), accounts.RoleAdmin)

	// Fleet entry point.
	body := get(t, h, "/console/").Body.String()
	body = get(t, h, "/console/?"+formQuery(rowPinForm(t, body, "node-web-1")).Encode()).Body.String()
	if !strings.Contains(body, "Pin 1 more to compare") || strings.Contains(body, `href="/console/compare`) {
		t.Error("one pin from Fleet: want the disabled Compare and no comparison link")
	}
	body = get(t, h, "/console/?"+formQuery(rowPinForm(t, body, "node-web-2")).Encode()).Body.String()
	link := `href="/console/compare?nodes=node-web-1%2Cnode-web-2"`
	if !strings.Contains(body, link) {
		t.Fatalf("two pins from Fleet offer no comparison link")
	}
	if cmp := get(t, h, "/console/compare?nodes=node-web-1%2Cnode-web-2").Body.String(); !strings.Contains(cmp, `<table class="cmp">`) {
		t.Error("the comparison reached from Fleet renders no table")
	}

	// Node detail entry point.
	body = get(t, h, "/console/nodes/node-web-1").Body.String()
	if !strings.Contains(body, `href="/console/nodes/node-web-1?pin=node-web-1"`) {
		t.Fatal("Node detail offers no pin link")
	}
	body = get(t, h, "/console/nodes/node-web-1?pin=node-web-1").Body.String()
	if !strings.Contains(body, "Pin 1 more to compare") {
		t.Error("one pin from Node detail: want the disabled Compare")
	}
	body = get(t, h, "/console/nodes/node-web-2?pin=node-web-1").Body.String()
	if !strings.Contains(body, `href="/console/nodes/node-web-2?pin=node-web-1%2Cnode-web-2"`) {
		t.Fatal("Node detail offers no link that adds this Node to the pin")
	}
	body = get(t, h, "/console/nodes/node-web-2?pin=node-web-1%2Cnode-web-2").Body.String()
	if !strings.Contains(body, link) || strings.Contains(body, "Pin 1 more") {
		t.Error("two pins from Node detail: want an enabled Compare")
	}
}

func TestPin_BarAlwaysOffersCompareBelowTwo(t *testing.T) {
	d := withFleet(renderableDeps(),
		registry.Node{NodeID: "n1", Connected: true},
		registry.Node{NodeID: "n2", Connected: true},
		registry.Node{NodeID: "n3", Connected: true})
	h := newTestHandler(d, accounts.RoleAdmin)

	for _, path := range []string{"/console/?pin=n1", "/console/nodes/n2?pin=n1"} {
		body := get(t, h, path).Body.String()
		if !strings.Contains(body, `<span class="act dim">Compare these Nodes</span>`) {
			t.Errorf("%s draws no disabled Compare action", path)
		}
		if !strings.Contains(body, "Pin 1 more to compare") {
			t.Errorf("%s does not say how many more to pin", path)
		}
		if strings.Contains(body, `href="/console/compare`) {
			t.Errorf("%s links a comparison of one Node", path)
		}
	}

	body := get(t, h, "/console/compare?nodes=n1").Body.String()
	if strings.Contains(body, "Compare these Nodes") || strings.Contains(body, "more to compare") {
		t.Error("the comparison screen offers Compare to itself")
	}

	// An id the registry does not know still counts toward two, as it did.
	d = withFleet(renderableDeps(), registry.Node{NodeID: "n1", Connected: true})
	body = get(t, newTestHandler(d, accounts.RoleAdmin), "/console/nodes/n1?pin=n1,node-typo").Body.String()
	if !strings.Contains(body, `href="/console/compare?nodes=n1%2Cnode-typo"`) || strings.Contains(body, "Pin 1 more") {
		t.Error("an unresolvable second pin changed whether Compare is offered")
	}
}

func TestNode_OwnPinReadsAsThisNode(t *testing.T) {
	d := withFleet(renderableDeps(),
		registry.Node{NodeID: "n1", Connected: true},
		registry.Node{NodeID: "n2", Connected: true})
	h := newTestHandler(d, accounts.RoleAdmin)

	body := get(t, h, "/console/nodes/n1?pin=n1").Body.String()
	if !strings.Contains(body, `<span class="dim">this Node</span>`) {
		t.Error("a Node's own chip does not read as this Node")
	}
	if strings.Contains(body, `<a href="/console/nodes/n1?pin=n1"><code>n1</code></a>`) {
		t.Error("a Node's own chip links to the page already open")
	}
	if !strings.Contains(body, `href="/console/nodes/n1"`) {
		t.Error("the own chip lost its unpin link")
	}

	body = get(t, h, "/console/nodes/n2?pin=n1").Body.String()
	if !strings.Contains(body, `<a href="/console/nodes/n1?pin=n1"><code>n1</code></a>`) || strings.Contains(body, `<span class="dim">this Node</span>`) {
		t.Error("another Node's chip should be a link and never read as this Node")
	}
}

// TestParsePins_CapsAsItReadsRatherThanAfterwards. The input is a query string,
// so the only bound on it is the server's header limit; collecting half a
// million entries to keep three is per-request work a URL should not be able to
// ask for.
func TestParsePins_CapsAsItReadsRatherThanAfterwards(t *testing.T) {
	ids, overflow := parsePins("a, b , a,c,d,e")
	if want := []string{"a", "b", "c"}; len(ids) != len(want) || ids[0] != "a" || ids[1] != "b" || ids[2] != "c" {
		t.Errorf("parsePins = %v, want %v (trimmed, deduped, capped in reading order)", ids, want)
	}
	if !overflow {
		t.Error("parsePins did not report that more Nodes were named than a comparison holds")
	}

	// A long list of DISTINCT ids: the answer is the first three in reading
	// order, and the reader stops there rather than materialising the rest.
	var long strings.Builder
	for i := 0; i < 10_000; i++ {
		fmt.Fprintf(&long, "n%d,", i)
	}
	ids, overflow = parsePins(long.String())
	if len(ids) != maxPins || ids[0] != "n0" || ids[2] != "n2" || !overflow {
		t.Errorf("parsePins(10k ids) = %v, overflow %v; want the first %d and overflow", ids, overflow, maxPins)
	}

	// A long list of DUPLICATES still terminates and still dedupes.
	if ids, _ := parsePins(strings.Repeat("n,", 10_000) + "last"); len(ids) != 2 {
		t.Errorf("parsePins(10k duplicates) = %v, want two distinct ids", ids)
	}

	if ids, overflow := parsePins(""); ids != nil || overflow {
		t.Errorf("parsePins(\"\") = %v, %v; want no ids and no overflow", ids, overflow)
	}
}

// TestCompare_ResolvesOnlyThePinnedNodesAndNeverEnumeratesTheFleet is the
// structural guard that keeps the comparison off the "no Facts on a fleet
// surface" line: it resolves the ids it was named, one at a time, and never
// asks the registry for the fleet.
func TestCompare_ResolvesOnlyThePinnedNodesAndNeverEnumeratesTheFleet(t *testing.T) {
	nodes := []registry.Node{
		{NodeID: "n1", Connected: true}, {NodeID: "n2", Connected: true},
		{NodeID: "n-unasked", Connected: true},
	}
	d := renderableDeps()
	q := &fakeQueries{nodes: nodes}
	d.Queries = q

	body := get(t, newTestHandler(d, accounts.RoleAdmin), "/console/compare?nodes=n1,n2").Body.String()

	if q.listNodeCalls != 0 {
		t.Errorf("the comparison called ListNodes %d times — an enumerating comparison "+
			"is a fleet surface, and this one may not become one", q.listNodeCalls)
	}
	wantDescribed := []string{"n1", "n2"}
	if !reflect.DeepEqual(q.describedNodes, wantDescribed) {
		t.Errorf("describedNodes = %v, want exactly the pinned ids %v — one describe_node record "+
			"per pinned Node, nothing else", q.describedNodes, wantDescribed)
	}
	if strings.Contains(body, "n-unasked") {
		t.Error("a Node in the registry but not in ?nodes= appeared in the comparison")
	}
}

// TestCompare_MarksDifferencesAndNeverAdjudicatesThem is invariant 12 on this
// screen: it states that two daemons reported different things. It never says
// what either would do with a Task, because that is Policy evaluation and it
// happens in the daemon's engine.
func TestCompare_MarksDifferencesAndNeverAdjudicatesThem(t *testing.T) {
	d := renderableDeps()
	d = withFleet(d, []registry.Node{
		{NodeID: "n1", Connected: true, PolicyFingerprint: "aaaa1111"},
		{NodeID: "n2", Connected: true, PolicyFingerprint: "bbbb2222"},
	}...)
	d = withPolicy(d, map[string]policyview.Snapshot{
		"n1": reportedSnapshot(policyview.Snapshot{
			RawExecEnabled:    true,
			AllowedOperations: []string{"service.restart", "system.facts"},
			DenyRules:         []policyview.DenyRule{{Name: "file.read", Args: [][]string{{"/etc/shadow"}}}},
		}, testNow.Add(-time.Minute)),
		"n2": reportedSnapshot(policyview.Snapshot{
			AllowedOperations: []string{"service.restart", "system.facts"},
		}, testNow.Add(-time.Minute)),
	})

	body := get(t, newTestHandler(d, accounts.RoleAdmin), "/console/compare?nodes=n1,n2").Body.String()

	if !strings.Contains(body, `data-diff="1"`) {
		t.Fatal("nothing was marked as differing, though raw exec and the deny rule do")
	}
	// The receipt time is provenance for the column, not a diffed row: two
	// Nodes reporting at different instants have not diverged.
	if !strings.Contains(body, "Policy received 2026-08-25 11:59:00Z") {
		t.Error("a column does not say when the Relay received that Node's Policy")
	}
	// The rows that agree are not marked. A screen where everything is marked
	// tells you nothing.
	if strings.Count(body, `data-diff="1"`) >= strings.Count(body, `<th scope="row" class="cmpkey">`) {
		t.Error("every row was marked as differing — the operations row is identical on both Nodes")
	}
	for _, verdict := range []string{
		"would be allowed", "would be denied", "allowed here", "denied here", "would deny", "would allow",
	} {
		if strings.Contains(strings.ToLower(body), verdict) {
			t.Errorf("the comparison rendered %q — it states differences and never adjudicates them "+
				"(invariant 12: Policy is evaluated by the Node's engine and by nothing else)", verdict)
		}
	}
}

// TestCompare_NothingReportedIsNotAgreement: when NO column has a snapshot,
// every Policy cell holds the same absence, so markDiffs marks nothing. An
// unmarked table means "these Nodes said the same thing" everywhere else on
// this screen, and here it would mean "the Relay has not been told" — the
// screen has to say which of the two it is.
func TestCompare_NothingReportedIsNotAgreement(t *testing.T) {
	d := renderableDeps() // no policyview wired at all: a legal Deps.
	d = withFleet(d, []registry.Node{
		{NodeID: "n1", Connected: true, PolicyFingerprint: "aaaa1111"},
		{NodeID: "n2", Connected: true, PolicyFingerprint: "aaaa1111"},
	}...)

	body := get(t, newTestHandler(d, accounts.RoleAdmin), "/console/compare?nodes=n1,n2").Body.String()

	if strings.Contains(body, `data-diff="1"`) {
		t.Fatal("a row was marked as differing though no column reported anything")
	}
	if !strings.Contains(body, "Neither Node has reported its Policy") {
		t.Error("an all-absent comparison does not say the rows compare nothing — " +
			"an unmarked table would read as agreement")
	}
	// And the ordinary "one column is missing" wording must not fire here: it
	// says the absence shows as a difference, which is exactly what it does not
	// do when every column is absent.
	if strings.Contains(body, "shows as a difference and is marked as one") {
		t.Error("the all-absent case rendered the some-absent note, which claims a mark that is not there")
	}
}

// TestCompare_RendersNoFact keeps the v0.6.0 promise node detail makes to the
// operator's face: Facts appear on that page and no other. A side-by-side diff
// of hostname, os, kernel, arch and ip would be the second page they live on,
// whatever the screen is called.
func TestCompare_RendersNoFact(t *testing.T) {
	d := renderableDeps()
	d = withFleet(d, []registry.Node{
		{NodeID: "n1", Connected: true, Facts: registry.Facts{
			Hostname: "web-1", OS: "debian", Kernel: "6.1.0", Arch: "x86_64",
			IPAddresses: []string{"10.0.0.1"},
		}},
		{NodeID: "n2", Connected: true, Facts: registry.Facts{
			Hostname: "web-2", OS: "alpine", Kernel: "5.15.0", Arch: "aarch64",
			IPAddresses: []string{"10.0.0.2"},
		}},
	}...)

	body := get(t, newTestHandler(d, accounts.RoleAdmin), "/console/compare?nodes=n1,n2").Body.String()

	for _, fact := range []string{
		"debian", "alpine", "6.1.0", "5.15.0", "x86_64", "aarch64", "10.0.0.1", "10.0.0.2",
	} {
		if strings.Contains(body, fact) {
			t.Errorf("the comparison rendered the Fact %q — Facts live on node detail and nowhere else", fact)
		}
	}
	// Nor as a row key. The hostname IS permitted, and only as the column
	// HEADING that says which Node the column is — the same use a fleet row
	// makes of it. It is not a dimension being diffed, and the note on the
	// screen claims exactly that and no more.
	for _, key := range []string{"hostname", "os", "kernel", "arch", "ip"} {
		if strings.Contains(strings.ToLower(body), `<th scope="row" class="cmpkey">`+key+`</th>`) {
			t.Errorf("the comparison diffs the Fact %q as a row", key)
		}
	}
}

// TestCompare_OneNodeAsksForASecondRatherThanRenderingHalfATable, and an
// unknown id is named rather than silently dropped: a mistyped id and a Node
// that was never enrolled look the same from here, and both are answers.
func TestCompare_OneNodeAsksForASecondRatherThanRenderingHalfATable(t *testing.T) {
	d := renderableDeps()
	d = withFleet(d, []registry.Node{{NodeID: "n1", Connected: true}}...)
	h := newTestHandler(d, accounts.RoleAdmin)

	one := get(t, h, "/console/compare?nodes=n1").Body.String()
	if !strings.Contains(one, "Pin at least two Nodes") {
		t.Error("a single-Node comparison did not ask for a second Node")
	}
	if !strings.Contains(one, `href="/console/?pin=n1"`) {
		t.Error("the Compare placeholder's fleet link does not carry the pin set")
	}
	if strings.Contains(one, `<table class="cmp">`) {
		t.Error("a single-Node comparison rendered a table with one column")
	}

	unknown := get(t, h, "/console/compare?nodes=n1,node-typo").Body.String()
	if !strings.Contains(unknown, "node-typo") {
		t.Error("an unknown Node id was dropped silently rather than named")
	}
}

// tasksPanelOf slices the Recent Tasks panel out of a rendered Node page, so an
// assertion about a chip in that table is not satisfied by the same chip in the
// header or the effective-Policy panel above it.
func tasksPanelOf(body string) string {
	const open = "<h3>Recent Tasks</h3>"
	i := strings.Index(body, open)
	if i < 0 {
		return ""
	}
	rest := body[i:]
	if j := strings.Index(rest, "</section>"); j >= 0 {
		return rest[:j]
	}
	return rest
}

// TestNode_RecentTasksListsTasksNotControlPlaneReads (#640).
//
// Every visit to a Node's detail page is itself a describe_node read, so
// before this fix, repeatedly opening the page filled Recent Tasks with its
// own control-plane reads and pushed real Tasks out of the fixed window.
// Spec 02 defines the panel as Tasks dispatched to the Node, denies included
// — not reads ABOUT the Node. This proves the panel now filters to
// KindDispatch, that denies still render, and that the audit trail itself is
// untouched: those reads are still there for Activity and Agents to
// show, this panel just does not list them.
func TestNode_RecentTasksListsTasksNotControlPlaneReads(t *testing.T) {
	repo := &captureRepo{}
	ctx := context.Background()
	if err := repo.Append(ctx, audit.Record{
		Kind: audit.KindDispatch, NodeID: "node-web-1", OperationName: "file.read",
		Outcome: jobs.OutcomeSuccess, JobID: "job-1", Timestamp: testNow,
	}); err != nil {
		t.Fatalf("Append(file.read): %v", err)
	}
	if err := repo.Append(ctx, audit.Record{
		Kind: audit.KindDispatch, NodeID: "node-web-1", OperationName: "service.restart",
		Outcome: jobs.OutcomeDeniedByPolicy, Timestamp: testNow.Add(time.Second),
	}); err != nil {
		t.Fatalf("Append(service.restart): %v", err)
	}
	// The real auditsink path, as the old test used: several times over, so
	// this panel's window (nodeTaskRows) would have been blown out by the
	// Console's own reads before this fix.
	sinkReadsInto(t, repo, "node-web-1", repeat("describe_node", nodeTaskRows+5)...)
	// Aimed at a different Node in the same trail: proves the screen still
	// reads by ByNode rather than rendering the whole trail.
	sinkReadsInto(t, repo, "node-web-2", "proc.list")

	d := fleetFixture()
	d.Audit = repo
	body := get(t, newTestHandler(d, accounts.RoleAdmin), "/console/nodes/node-web-1").Body.String()
	panel := tasksPanelOf(body)

	if panel == "" {
		t.Fatal("the Node page has no Recent Tasks panel")
	}
	// Anti-vacuity first: both dispatched Operations must actually be there,
	// or every assertion below would pass on an empty or read-only table.
	for _, op := range []string{"file.read", "service.restart"} {
		if !strings.Contains(panel, "<code>"+op+"</code>") {
			t.Fatalf("the dispatched Operation %q is not in Recent Tasks", op)
		}
	}
	if !strings.Contains(panel, `data-outcome="denied_by_policy"`) {
		t.Error("the denied Task's outcome chip is not rendered — Recent Tasks must include denies")
	}
	if strings.Contains(panel, "describe_node") {
		t.Error("describe_node — a control-plane read ABOUT this Node — appears in Recent Tasks, " +
			"which spec 02 defines as Tasks dispatched TO the Node")
	}
	if strings.Contains(panel, `data-outcome="audited"`) || strings.Contains(panel, `data-outcome="unspecified"`) {
		t.Error(`Recent Tasks renders a read-only outcome chip ("audited" or "unspecified") — ` +
			"only dispatched Tasks, whose outcome is a real per-Node verdict, belong here")
	}
	if strings.Contains(panel, "Older Tasks are not shown") {
		t.Error("the elided-Tasks note renders even though only two real Tasks exist — the " +
			"control-plane reads are still filling the window, so the filter is not running " +
			"before windowing")
	}
	if !strings.Contains(panel, "read — output not retained") {
		t.Error(`the read-class Task (file.read) does not carry the "output not retained" note`)
	}
	if n := strings.Count(panel, "read — output not retained"); n != 1 {
		t.Errorf("%d rows carry the read-class note, want 1 (file.read only, not service.restart)", n)
	}

	// The audit record is unchanged: item 3 filters what this panel QUERIES,
	// never what is written. Every describe_node record the sink wrote for
	// node-web-1 is still in the trail (plus the one aimed at node-web-2).
	var describeNodeCount int
	for _, rec := range repo.recs {
		if rec.Kind == audit.KindRead && rec.NodeID == "node-web-1" {
			describeNodeCount++
		}
	}
	if want := nodeTaskRows + 5; describeNodeCount != want {
		t.Errorf("the audit trail holds %d KindRead records for node-web-1, want %d — this panel "+
			"must never change what is written, only what it displays", describeNodeCount, want)
	}
}

// repeat returns s repeated n times, for building a fixture that names one
// tool many times over without a literal slice of duplicates in the test body.
func repeat(s string, n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = s
	}
	return out
}

// --- #833: an unreported Node's Policy snapshot is rendered with facts only ---

// unreportedNodeBody renders node-web-1 with the given recorded fields and a
// captured snapshot whose own fingerprint is "sha256:snapfp".
func unreportedNodeBody(t *testing.T, version, fingerprint string) string {
	t.Helper()
	d := withFleet(renderableDeps(), registry.Node{
		NodeID: "node-web-1", NodeLabels: map[string]string{"env": "prod"},
		DaemonVersion: version, PolicyFingerprint: fingerprint,
		LastSeen: testNow.Add(-4 * time.Second), Connected: true,
	})
	d = withPolicy(d, map[string]policyview.Snapshot{"node-web-1": reportedSnapshot(policyview.Snapshot{
		AllowedOperations: []string{"service.restart"},
		PolicyFingerprint: "sha256:snapfp",
	}, testNow.Add(-90*time.Second))})
	body := get(t, newTestHandler(d, accounts.RoleAdmin), "/console/nodes/node-web-1").Body.String()
	panel := policyPanelOf(body)
	if panel == "" {
		t.Fatal("no effective-Policy panel rendered")
	}
	return panel
}

func TestNode_UnreportedSnapshotStatesFactsNotAVerdict(t *testing.T) {
	panel := unreportedNodeBody(t, "0.6.0", "")
	for _, want := range []string{
		"Not corroborated by a recorded Hello",
		shortHash("sha256:snapfp"),
		"no Hello-recorded Policy fingerprint",
		"cannot be cross-checked",
		"not count this Node as current or permitted",
		"The Relay never evaluates Policy", // the rule text (QRY-7) is still there
		"service.restart",
	} {
		if !strings.Contains(panel, want) {
			t.Errorf("panel lacks %q", want)
		}
	}
	if strings.Contains(panel, "daemon version or Policy fingerprint") {
		t.Error("panel names the daemon version as missing, but only the fingerprint is")
	}
	for _, banned := range []string{"effective Policy until", "Do not treat", "unconfirmed"} {
		if strings.Contains(panel, banned) {
			t.Errorf("panel contains the verdict phrasing %q", banned)
		}
	}
}

func TestNode_UnreportedVersionAloneAlsoCaveats(t *testing.T) {
	panel := unreportedNodeBody(t, "", "aaaa111122223333")
	if !strings.Contains(panel, "Not corroborated by a recorded Hello") {
		t.Error("a missing daemon version alone did not raise the caveat")
	}
	if !strings.Contains(panel, "no Hello-recorded daemon version") {
		t.Error("the caveat does not name the daemon version")
	}
	if strings.Contains(panel, "cannot be cross-checked") {
		t.Error("the fingerprint is recorded, so the cross-check claim must not appear")
	}
}

func TestNode_ReportedNodeHasNoCaveat(t *testing.T) {
	d := withPolicy(fleetFixture(), map[string]policyview.Snapshot{"node-web-1": reportedSnapshot(policyview.Snapshot{
		AllowedOperations: []string{"service.restart"},
	}, testNow.Add(-90*time.Second))})
	body := get(t, newTestHandler(d, accounts.RoleAdmin), "/console/nodes/node-web-1").Body.String()
	panel := policyPanelOf(body)
	if panel == "" {
		t.Fatal("no effective-Policy panel rendered")
	}
	if strings.Contains(panel, "Not corroborated") {
		t.Error("a Node with a recorded version and fingerprint carries the caveat")
	}
}

// TestCompare_RendersMixedCaseNodeIDsVerbatimInsideAnIdentifierClass: a Node ID
// is case-sensitive hex, and the column heading that holds it sits in an
// upper-cased th. The ID must reach the page as given, inside the identifier
// class the stylesheet exempts from text-transform, and the heading must carry
// the class that resets the case for the hostname and connection lines too.
func TestCompare_RendersMixedCaseNodeIDsVerbatimInsideAnIdentifierClass(t *testing.T) {
	d := renderableDeps()
	d = withFleet(d, []registry.Node{
		{NodeID: "node-AbCd01", Connected: true},
		{NodeID: "node-eFgH02", Connected: true},
	}...)

	body := get(t, newTestHandler(d, accounts.RoleAdmin), "/console/compare?nodes=node-AbCd01,node-eFgH02").Body.String()

	for _, id := range []string{"node-AbCd01", "node-eFgH02"} {
		if !strings.Contains(body, `class="nodeid">`+id+`</a>`) {
			t.Errorf("the Node ID %q is not rendered verbatim inside class=\"nodeid\"", id)
		}
	}
	if !strings.Contains(body, `<th scope="col" class="cmpnode">`) {
		t.Error("the Node column heading does not carry cmpnode, so the heading's uppercase reaches the hostname and connection lines")
	}
}

// TestCompare_RowKeysShareOneCase: the row keys render verbatim now, so the
// source case is the displayed case. Every key starts upper-case, and the rule
// name after Allow/Deny is an identifier and keeps its own case.
func TestCompare_RowKeysShareOneCase(t *testing.T) {
	d := renderableDeps()
	d = withFleet(d, []registry.Node{
		{NodeID: "n1", Connected: true},
		{NodeID: "n2", Connected: true},
	}...)
	d = withPolicy(d, map[string]policyview.Snapshot{
		"n1": reportedSnapshot(policyview.Snapshot{
			OperationRules: []policyview.OperationRule{{Name: "service.Restart", AllowedArgs: [][]string{{"nginx"}}}},
			DenyRules:      []policyview.DenyRule{{Name: "file.Read", Args: [][]string{{"/etc/shadow"}}}},
		}, testNow),
		"n2": reportedSnapshot(policyview.Snapshot{}, testNow),
	})

	body := get(t, newTestHandler(d, accounts.RoleAdmin), "/console/compare?nodes=n1,n2").Body.String()

	const open = `<th scope="row" class="cmpkey">`
	keys := 0
	for rest := body; ; {
		i := strings.Index(rest, open)
		if i < 0 {
			break
		}
		rest = rest[i+len(open):]
		key := rest[:strings.Index(rest, "</th>")]
		keys++
		if first := key[:1]; first != strings.ToUpper(first) || first == strings.ToLower(first) {
			t.Errorf("row key %q does not start with an upper-case letter", key)
		}
	}
	if keys == 0 {
		t.Fatal("no row keys rendered — this test is not running")
	}
	for _, want := range []string{open + "Allow service.Restart</th>", open + "Deny file.Read</th>"} {
		if !strings.Contains(body, want) {
			t.Errorf("the rule name was recased or the row is missing: want %q", want)
		}
	}
}

// TestNode_IdentityValuesWrapInsideTheirCard: the Node ID beneath the hostname
// heading, the H1 that carries the Node ID when no hostname leads, and the
// Identity card's values all soft-wrap rather than overflowing. The CSS reaches
// them by class, so a string pin on both halves catches the markup moving and
// the rule silently ceasing to apply.
func TestNode_IdentityValuesWrapInsideTheirCard(t *testing.T) {
	d := fleetFixture()
	d = withFleet(d, registry.Node{
		NodeID: "node-web-1", Connected: true, DaemonVersion: "0.6.0",
		EnrollingTokenID: "tok-9f8e7d6c5b4a39281706f5e4d3c2b1a0ffee",
		Facts:            registry.Facts{Hostname: "web-1"},
	})
	h := newTestHandler(d, accounts.RoleAdmin)

	body := get(t, h, "/console/nodes/node-web-1").Body.String()
	for _, want := range []string{
		`<div class="nodehead">`,
		`<code class="nodeid" title="The identity this Node`,
		`<dl class="kv wrapid">`,
		`<dd><code>tok-9f8e7d6c5b4a39281706f5e4d3c2b1a0ffee</code></dd>`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("node detail does not contain %q", want)
		}
	}

	css := get(t, h, "/console/assets/console.css").Body.String()
	for _, want := range []string{
		".nodehead .nodeid { white-space: normal; overflow-wrap: anywhere;",
		"letter-spacing: -0.02em; margin: 0;\n  overflow-wrap: anywhere; min-width: 0;",
		"dl.wrapid dd code { overflow-wrap: anywhere; }",
	} {
		if !strings.Contains(css, want) {
			t.Errorf("console.css does not contain %q", want)
		}
	}
}
