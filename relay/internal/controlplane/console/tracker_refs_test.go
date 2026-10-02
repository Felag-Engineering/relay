package console

// tracker_refs_test.go proves that no tracker number ("#430") reaches an
// operator: an issue number is a note to the people building the Relay, and it
// means nothing, and rots, on a screen an operator reads.

import (
	"html"
	"net/http"
	"regexp"
	"slices"
	"testing"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/accounts"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/approval"
)

// trackerRef matches "#<number>" as a word of its own. It is applied to
// UNESCAPED text, so an apostrophe's &#39; is not a tracker number.
var trackerRef = regexp.MustCompile(`(?:^|[^&\w])#[0-9]+\b`)

func TestTrackerRef_PatternMatchesIssueNumbersAndNothingElse(t *testing.T) {
	for _, s := range []string{"(#430)", "tracked in #779.", "#1"} {
		if !trackerRef.MatchString(s) {
			t.Errorf("trackerRef does not match %q", s)
		}
	}
	for _, s := range []string{"Node&#39;s", "Node's", "#main", "&#x27;", "abc#12"} {
		if trackerRef.MatchString(s) {
			t.Errorf("trackerRef matches %q, which is not a tracker number", s)
		}
	}
}

func assertNoTrackerRef(t *testing.T, path, body string) {
	t.Helper()
	text := html.UnescapeString(body)
	if loc := trackerRef.FindStringIndex(text); loc != nil {
		from, to := max(loc[0]-60, 0), min(loc[1]+60, len(text))
		t.Errorf("%s renders a tracker reference: ...%s...", path, text[from:to])
	}
}

func TestConsole_NoRenderedScreenCarriesATrackerReference(t *testing.T) {
	d := withExecution(sweepFixture(), true)
	h := newTestHandler(d, accounts.RoleAdmin)

	paths := walkableScreens(routesFor(d, accounts.RoleAdmin), fixtureIDs)
	// The guard is the walk reaching the two screens that carried a reference.
	if len(paths) == 0 || !slices.Contains(paths, "/console/approvals") || !slices.Contains(paths, "/console/nodes/node-web-1") {
		t.Fatalf("the route walk did not reach the Approvals queue and a Node page: %v", paths)
	}
	// Situational paths the walk does not reach.
	paths = append(paths,
		fleetPath+"?filter=tag:pci",
		fleetPath+"?filter=foo",
		fleetPath+"?filter=node:role=nonesuch",
	)
	for _, path := range paths {
		rec := get(t, h, path)
		assertNoTrackerRef(t, path, rec.Body.String())
	}

	// Two pages built from other fixtures.
	rec := get(t, newTestHandler(dayOneDeps(), accounts.RoleAdmin), fleetPath)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET %s on a day-one Relay = %d, want 200", fleetPath, rec.Code)
	}
	assertNoTrackerRef(t, fleetPath+" (day one)", rec.Body.String())

	g := consoleGrant("grant-1", "ap-grant", 200, 20)
	g.LegacyNamespacePin = "node"
	gd := renderableDeps()
	gd.Approvals = &fakeApprovals{pending: []approval.Request{grantRequest(g, approval.StatePending)}, grants: []approval.Grant{g}}
	rec = get(t, newTestHandler(gd, accounts.RoleAdmin), "/console/approvals/ap-grant")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET the legacy-pinned Grant card = %d, want 200", rec.Code)
	}
	assertNoTrackerRef(t, "/console/approvals/ap-grant", rec.Body.String())
}
