package console

// standing_notes_test.go proves 00-foundations.md's "Standing notes and
// situational messages" (D31): no screen renders an "About this screen"
// disclosure. A standing note is one visible sentence beside what it
// qualifies, or it is deleted; a message rendered because of this request,
// this caller or this record's state stays visible where it renders.

import (
	"strings"
	"testing"
	"time"

	"github.com/Felag-Engineering/relay/relay/internal/accounts"
	"github.com/Felag-Engineering/relay/relay/internal/capability"
	"github.com/Felag-Engineering/relay/relay/internal/policyview"
)

// mustBeInline asserts msg renders visibly and sits no more than within bytes
// after the nearest preceding anchor, so a standing note is beside what it
// qualifies and not at the screen's foot.
func mustBeInline(t *testing.T, body, msg, anchor string, within int) {
	t.Helper()
	mustBeSituational(t, body, msg)
	content := contentOf(body)
	at := strings.Index(content, msg)
	from := strings.LastIndex(content[:at], anchor)
	if from < 0 {
		t.Errorf("%q has no %q before it", msg, anchor)
		return
	}
	if at-from > within {
		t.Errorf("%q starts %d bytes after %q, want at most %d", msg, at-from, anchor, within)
	}
}

func mustNotRender(t *testing.T, body string, msgs ...string) {
	t.Helper()
	content := contentOf(body)
	for _, m := range msgs {
		if strings.Contains(content, m) {
			t.Errorf("%q is rendered, but it was deleted from the screen", m)
		}
	}
}

// mustBeSituational asserts msg renders, and renders outside any About
// disclosure.
func mustBeSituational(t *testing.T, body, msg string) {
	t.Helper()
	content := contentOf(body)
	if !strings.Contains(content, msg) {
		t.Fatalf("situational message %q is not rendered", msg)
	}
	if collapsedInAbout(content, msg) {
		t.Errorf("situational message %q is collapsed inside the About disclosure", msg)
	}
}

// collapsedInAbout reports whether the first occurrence of msg in content
// sits inside an About disclosure.
func collapsedInAbout(content, msg string) bool {
	idx := strings.Index(content, msg)
	if idx < 0 {
		return false
	}
	open := strings.LastIndex(content[:idx], `<details class="about"`)
	return open >= 0 && !strings.Contains(content[open:idx], "</details>")
}

// TestStandingNotes_HelperDetectsACollapsedMessage guards mustBeSituational
// against a vacuous pass.
func TestStandingNotes_HelperDetectsACollapsedMessage(t *testing.T) {
	in := `<p class="gap">shown</p><details class="about"><summary>About this screen</summary><p class="gap">collapsed</p></details>`
	if !collapsedInAbout(in, "collapsed") {
		t.Error("a message inside the About disclosure was not reported as collapsed")
	}
	if collapsedInAbout(in, "shown") {
		t.Error("a message before the About disclosure was reported as collapsed")
	}
}

// TestStandingNotes_NoScreenRendersAnAboutDisclosure: no rendered page carries the
// disclosure and no template source can, so it cannot return unseen.
func TestStandingNotes_NoScreenRendersAnAboutDisclosure(t *testing.T) {
	check := func(name, body string) {
		content := contentOf(body)
		for _, banned := range []string{"About this screen", `class="about"`} {
			if strings.Contains(content, banned) {
				t.Errorf("%s renders %q", name, banned)
			}
		}
	}
	d := copyBudgetFixture()
	pages := 0
	for _, role := range sessionRoles {
		h := newTestHandler(d, role)
		for _, path := range walkableScreens(routesFor(d, role), fixtureIDs) {
			check(string(role)+" "+path, get(t, h, path).Body.String())
			pages++
		}
	}
	if pages == 0 {
		t.Fatal("no screen was rendered, so nothing was checked")
	}
	check("day one", get(t, newTestHandler(dayOneDeps(), accounts.RoleAdmin), "/console/").Body.String())
	for _, pg := range budgetPages(t) {
		if pg.key == "grant card" {
			check("grant card", get(t, pg.h, pg.path).Body.String())
		}
	}
	for _, src := range consoleTemplateSources(t) {
		for _, banned := range []string{`class="about"`, `"about-docs"`} {
			if strings.Contains(src.text, banned) {
				t.Errorf("%s:%d: a template carries %s", src.file, src.line, banned)
			}
		}
	}
}

// --- Activity ---------------------------------------------------------------

// TestActivity_DrawsNoStandingNote: Activity carries no explanatory sentence
// beside its controls or rows (00-foundations.md, D34).
func TestActivity_DrawsNoStandingNote(t *testing.T) {
	body := get(t, newTestHandler(activityDeps(&fakeQueries{}), accounts.RoleAdmin), "/console/activity").Body.String()
	mustNotRender(t, body, "are on the audit trail, not here", `class="lede"`, "Calls the Relay received",
		"Every Refresh is an audited read", "Each page holds up to", "Counts job events",
		"Output was not retained", "consecutive identical calls", "collapsed into", "Longest-running first;")
}

func TestActivity_SituationalMessagesStayVisible(t *testing.T) {
	h := newTestHandler(activityDeps(&fakeQueries{}), accounts.RoleAdmin)
	for _, tc := range []struct{ path, msg string }{
		{"/console/activity?window=fortnight", "Part of this URL could not be read:"},
		{"/console/activity?kind=nonesuch", "There is no row kind called"},
		{"/console/activity?q=nginx", "matches text within the rows already on this page"},
		{"/console/activity?outcome=failure", "Outcome keeps Jobs with at least one"},
	} {
		t.Run(tc.path, func(t *testing.T) {
			mustBeSituational(t, get(t, h, tc.path).Body.String(), tc.msg)
		})
	}
	// The Older-page sentence and the awaiting note are situational too.
	scrolled := newTestHandler(activityDeps(&fakeQueries{}), accounts.RoleAdmin)
	mustBeSituational(t, get(t, scrolled, "/console/activity?ac=0").Body.String(), "These are not the most recent events.")
	running := newTestHandler(cancelDeps(&fakeQueries{jobs: []capability.JobSummary{runningJob("job-1", "p", "a")}}, &fakeCanceller{}), accounts.RoleAdmin)
	mustBeSituational(t, get(t, running, "/console/activity").Body.String(), "No dispatch record is joined to it yet")
	// Refine's note is situational: without a Refine term it is not drawn.
	if strings.Contains(get(t, h, "/console/activity").Body.String(), "matches text within the rows") {
		t.Error("the Refine note renders when nothing was refined")
	}
}

// --- Access -------------------------------------------------------------

// TestAccess_DrawsNoStandingNote: Access carries only the one sentence the
// spec names, and only where OAuth is configured (20-access.md, D34).
func TestAccess_DrawsNoStandingNote(t *testing.T) {
	body := get(t, newTestHandler(accessDeps(&fakeQueries{}), accounts.RoleAdmin), "/console/access").Body.String()
	mustNotRender(t, body, "limited to admins", "There is no filter by the changed Account", "An older failed sign-in",
		"Every Refresh is an audited read", "Each page holds up to", "OAuth sign-ins happen")
	if strings.Contains(body, "not on the trail") {
		t.Error("the Access screen still says something is not on the trail")
	}
	// The Control API has no audit-read route (docs/api/openapi.yaml;
	// 20-access.md), so a sentence saying these records are readable there
	// was false and is gone.
	if strings.Contains(body, "readable through the Control API") {
		t.Error("the Access screen says its records are readable through the Control API, which has no audit-read route")
	}
}

func TestAccess_OAuthSentenceOnlyWhereOAuthIsConfigured(t *testing.T) {
	const sentence = "OAuth sign-ins happen at the identity provider and are not listed."
	d := accessDeps(&fakeQueries{})
	d.OAuthConfigured = true
	mustBeInline(t, get(t, newTestHandler(d, accounts.RoleAdmin), "/console/access").Body.String(), sentence, "failures only</a>", 80)
	d.OAuthConfigured = false
	mustNotRender(t, get(t, newTestHandler(d, accounts.RoleAdmin), "/console/access").Body.String(), sentence)
}

func TestAccess_SituationalMessagesStayVisible(t *testing.T) {
	h := newTestHandler(accessDeps(&fakeQueries{}), accounts.RoleAdmin)
	for _, tc := range []struct{ path, msg string }{
		{"/console/access?window=fortnight", "Part of this URL could not be read:"},
		{"/console/access?kind=nonesuch", "There is no row kind called"},
	} {
		t.Run(tc.path, func(t *testing.T) {
			mustBeSituational(t, get(t, h, tc.path).Body.String(), tc.msg)
		})
	}
}

// --- Day one ----------------------------------------------------------------

func TestDayOne_RefusingDaemonNoteIsInline(t *testing.T) {
	body := get(t, newTestHandler(dayOneDeps(), accounts.RoleAdmin), "/console/").Body.String()
	mustBeInline(t, body, "A daemon that refuses this Relay&#39;s certificate never appears here.", "</section>", 80)
	// 10-day-one.md holds the CA-fingerprint check; the CA row carries the
	// value to compare.
	mustNotRender(t, body, "Check the CA fingerprint above")
}

func TestDayOne_UnwatchedEnrollmentNoteStaysVisible(t *testing.T) {
	d := withFleet(renderableDeps()) // no event seam: nothing is watching
	mustBeSituational(t, get(t, newTestHandler(d, accounts.RoleAdmin), "/console/").Body.String(),
		"Rejected attempts are not shown yet</b>")
}

// --- Approval object: every message is about this caller or this record -----

// --- The two stale strings ---------------------------------------------------

func TestFleet_NoHostMetricsNoteIsDeleted(t *testing.T) {
	body := get(t, newTestHandler(fleetFixture(), accounts.RoleAdmin), fleetPath).Body.String()
	mustNotRender(t, body, "no host metrics")
}

func TestFleet_SituationalMessagesStayVisible(t *testing.T) {
	mustBeSituational(t, get(t, newTestHandler(fleetFixture(), accounts.RoleAdmin),
		fleetPath+"?group=nonesuch").Body.String(), "Part of this URL could not be read:")
}

func TestFleet_NoMatchEmptyStateIsSituational(t *testing.T) {
	h := newTestHandler(fleetFixture(), accounts.RoleAdmin)
	const heading = "No Nodes match this Selector."

	body := get(t, h, fleetPath+"?filter=node:role=nonesuch&group=-").Body.String()
	mustBeSituational(t, body, heading)
	if !strings.Contains(body, `href="/console/?group=-"`) {
		t.Errorf("the Clear link does not keep the grouping:\n%s", contentOf(body))
	}

	for _, q := range []string{"?filter=node:role=nonesuch", "?filter=node:role=nonesuch&group=-"} {
		got := get(t, h, fleetPath+q).Body.String()
		if !strings.Contains(got, heading) {
			t.Errorf("%s: the empty state is missing", q)
		}
		for _, stray := range []string{`class="group`, "every Node here is reachable", "no deviations", `class="systemstate"`} {
			if strings.Contains(got, stray) {
				t.Errorf("%s: %q renders beneath the empty state", q, stray)
			}
		}
	}

	for _, path := range []string{fleetPath, fleetPath + "?filter=tag:pci"} {
		if got := get(t, h, path).Body.String(); strings.Contains(got, heading) {
			t.Errorf("%s renders the empty state, but its fleet is not empty", path)
		}
	}
}

// retiredNotes are the sentences the show-don't-tell amendment (D34) deleted
// from Fleet, Node detail, Compare, Activity, Access and Job detail. Only the
// strings this change deleted are listed, so another screen's own notes are not
// judged here.
var retiredNotes = []string{
	"Every Refresh is an audited read",
	"every Node here is reachable, current and permitted",
	`class="labelnote"`,
	"These counts are observations",
	"receipt time, not a query time",
	"There is no path from this screen",
	"output not retained",
	"Only rows that differ are shown",
	"Rows that differ are marked",
	"Each cell is what that Node",
	"hostname is self-reported; no other Fact",
	"never read as agreement",
	"Calls the Relay received",
	"Each page holds up to",
	"Output was not retained",
	"consecutive identical calls",
	"collapsed into",
	"Longest-running first;",
	"Counts job events",
	"limited to admins",
	"There is no filter by the changed Account",
	"An older failed sign-in",
	"the usual result, folded",
	"Reload to see new events",
}

// TestShowDontTell_RetiredNotesAreAbsent renders every walkable screen for every
// role, plus the states that drew a retired note (Compare with an unreported
// Node, Activity with a collapsed run and with a kind filter), and asserts none
// of the retired sentences returns (D34; the issue's acceptance).
func TestShowDontTell_RetiredNotesAreAbsent(t *testing.T) {
	check := func(name, body string) {
		content := contentOf(body)
		for _, note := range retiredNotes {
			if strings.Contains(content, note) {
				t.Errorf("%s renders the retired %q", name, note)
			}
		}
	}
	d := copyBudgetFixture()
	pages := 0
	for _, role := range sessionRoles {
		h := newTestHandler(d, role)
		for _, path := range walkableScreens(routesFor(d, role), fixtureIDs) {
			check(string(role)+" "+path, get(t, h, path).Body.String())
			pages++
		}
	}
	if pages == 0 {
		t.Fatal("no screen was rendered, so nothing was checked")
	}
	h := newTestHandler(d, accounts.RoleAdmin)
	for _, path := range []string{
		"/console/compare?nodes=node-web-1,node-web-3",
		"/console/compare?nodes=node-web-1,node-web-3&rows=all",
		"/console/activity?kind=dispatch",
		"/console/activity?window=1h",
	} {
		check(path, get(t, h, path).Body.String())
	}
	who := apiIdentity("acct-1", "alice", "operator")
	q := &fakeQueries{rows: []capability.AuditRow{
		refusalBy(who, time.Second, "same"), refusalBy(who, 2*time.Second, "same"), refusalBy(who, 3*time.Second, "same"),
	}}
	check("a collapsed run", activityAs(t, q, "/console/activity"))
}

// TestNode_HasNoAboutDisclosure: every note Node detail carries qualifies a
// value beside it, so each one is visible and the screen has no standing note
// left to collapse (00-foundations.md as amended for #849). An About
// disclosure here would be a place for qualifiers to be hidden.
func TestNode_HasNoAboutDisclosure(t *testing.T) {
	d := withPolicy(fleetFixture(), map[string]policyview.Snapshot{"node-web-1": reportedSnapshot(policyview.Snapshot{
		AllowedOperations: []string{"service.restart"},
	}, testNow.Add(-90*time.Second))})
	content := contentOf(get(t, newTestHandler(d, accounts.RoleAdmin), "/console/nodes/node-web-1").Body.String())
	if !strings.Contains(content, "<h3>Effective Policy") {
		t.Fatal("the Node page did not render its Policy panel, so its absence of an About proves nothing")
	}
	if n := strings.Count(content, `<details class="about"`); n != 0 {
		t.Errorf("Node detail carries %d About disclosures, want 0", n)
	}
}

func TestNode_MandatedNotesStayVisible(t *testing.T) {
	d := withPolicy(fleetFixture(), map[string]policyview.Snapshot{"node-web-1": reportedSnapshot(policyview.Snapshot{
		AllowedOperations: []string{"service.restart"},
	}, testNow.Add(-90*time.Second))})
	body := get(t, newTestHandler(d, accounts.RoleAdmin), "/console/nodes/node-web-1").Body.String()
	for _, msg := range []string{
		"self-reported · this page only · never targeted",
		"reported by the daemon",
	} {
		mustBeSituational(t, body, msg)
	}
	// The relay: chip's tooltip contains "never the Node", so only the retired
	// legend's markup is asserted absent, not that phrase.
	mustNotRender(t, body, `class="labelnote"`, "<b>node:</b>", "<b>relay:</b>", "<b>state:</b>",
		"There is no path from this screen", "receipt time, not a query time", "These counts are observations")
	for _, claim := range []string{"security-lane", "security lane"} {
		if strings.Contains(body, claim) {
			t.Errorf("the Node detail page makes a security-lane claim (%q)", claim)
		}
	}
}

// TestAccounts_TheD34NotesAreGone: the three Accounts notes design 00 (D34)
// deletes appear on no Accounts screen, and the trail is never called a bare
// "agent call trail".
func TestAccounts_TheD34NotesAreGone(t *testing.T) {
	h := newTestHandler(accountsFixture(), accounts.RoleAdmin)
	for _, path := range []string{accountsPath, accountPagePath("gleipnir-prod"), newAccountPath} {
		body := get(t, h, path).Body.String()
		for _, gone := range []string{
			"own Policy is the real ceiling",
			"Console password; it signs in through OAuth",
			"on the response to this form, and never again",
		} {
			if strings.Contains(body, gone) {
				t.Errorf("%s still renders the deleted note %q", path, gone)
			}
		}
	}

	body := get(t, h, accountsPath).Body.String()
	for i := 0; ; {
		j := strings.Index(body[i:], "agent call trail")
		if j < 0 {
			break
		}
		at := i + j
		if at < 3 || body[at-3:at] != "AI-" {
			t.Errorf("a bare %q is rendered", "agent call trail")
		}
		i = at + 1
	}
}

func TestAccounts_NotWiredSentenceStaysVisible(t *testing.T) {
	d := accountsFixture()
	d.AccountAdmin = nil
	body := get(t, newTestHandler(d, accounts.RoleAdmin), accountsPath).Body.String()
	mustBeSituational(t, body, "are not wired into this Relay")
}
