package console

// standing_notes_test.go proves 00-foundations.md's "Standing notes and
// situational messages": a note rendered on every view of a screen lives in
// ONE closed "About this screen" disclosure at the screen's foot; a message
// rendered because of this request, this caller or this record's state stays
// visible where it always was.

import (
	"html/template"
	"strings"
	"testing"
	"time"

	"github.com/Felag-Engineering/relay/relay/internal/accounts"
	"github.com/Felag-Engineering/relay/relay/internal/approval"
	"github.com/Felag-Engineering/relay/relay/internal/capability"
	"github.com/Felag-Engineering/relay/relay/internal/policyview"
)

const aboutOpen = `<details class="about">`

// splitAbout returns the page's single About disclosure and everything
// outside it. It fails the test unless there is exactly one, it is closed by
// default, it carries a summary, and nothing but closing markup follows it in
// the screen's content — the foot of the screen.
func splitAbout(t *testing.T, body string) (inside, outside string) {
	t.Helper()
	content := contentOf(body)
	if n := strings.Count(content, `<details class="about"`); n != 1 {
		t.Fatalf("the screen carries %d About disclosures, want exactly 1", n)
	}
	i := strings.Index(content, aboutOpen)
	if i < 0 {
		t.Fatal("the About disclosure is open by default, or carries attributes beyond its class")
	}
	rest := content[i:]
	j := strings.Index(rest, "</details>")
	if j < 0 {
		t.Fatal("the About disclosure is never closed")
	}
	inside = rest[:j]
	if !strings.Contains(inside, "<summary>About this screen</summary>") {
		t.Error("the disclosure does not carry its plain label")
	}
	after := rest[j+len("</details>"):]
	if strings.Contains(after, "<p") || strings.Contains(after, "<section") {
		t.Errorf("content follows the About disclosure, so it is not at the screen's foot:\n%s", after)
	}
	return inside, content[:i] + after
}

func mustBeStanding(t *testing.T, inside, outside string, notes ...string) {
	t.Helper()
	for _, n := range notes {
		if !strings.Contains(inside, n) {
			t.Errorf("standing note %q is not inside the About disclosure", n)
		}
		if strings.Contains(outside, n) {
			t.Errorf("standing note %q is still rendered outside the About disclosure", n)
		}
	}
}

// mustBeSituational asserts msg renders, and renders outside any About
// disclosure — including on a screen that has none.
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

// --- Activity ---------------------------------------------------------------

func TestActivity_StandingNotesAreInOneClosedDisclosure(t *testing.T) {
	body := get(t, newTestHandler(activityDeps(&fakeQueries{}), accounts.RoleAdmin), "/console/activity").Body.String()
	inside, outside := splitAbout(t, body)
	mustBeStanding(t, inside, outside,
		"Each page holds up to",
		"Every Refresh is an audited read",
	)
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

func TestAccess_StandingNotesAreInOneClosedDisclosure(t *testing.T) {
	body := get(t, newTestHandler(accessDeps(&fakeQueries{}), accounts.RoleAdmin), "/console/access").Body.String()
	inside, outside := splitAbout(t, body)
	mustBeStanding(t, inside, outside,
		"OAuth sign-ins are not listed.",
		"There is no filter by the changed Account.",
		"Every Refresh is an audited read",
		"limited to admins in the Console only",
	)
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

func TestDayOne_StandingNoteIsInOneClosedDisclosure(t *testing.T) {
	body := get(t, newTestHandler(dayOneDeps(), accounts.RoleAdmin), "/console/").Body.String()
	inside, outside := splitAbout(t, body)
	mustBeStanding(t, inside, outside, "A daemon that refuses this Relay&#39;s certificate never appears here.")
}

func TestDayOne_UnwatchedEnrollmentNoteStaysVisible(t *testing.T) {
	d := withFleet(renderableDeps()) // no event seam: nothing is watching
	mustBeSituational(t, get(t, newTestHandler(d, accounts.RoleAdmin), "/console/").Body.String(),
		"Rejected attempts are not shown yet</b>")
}

// --- Approval object: every message is about this caller or this record -----

func TestApproval_SituationalMessagesStayVisible(t *testing.T) {
	t.Run("already signed", func(t *testing.T) {
		req := pendingApprovalRequest("ap-1")
		req.Require.Count = 2
		req.Decisions = []approval.Decision{{
			Account: testAccountName(accounts.RoleOperator), AccountID: testAccountID(accounts.RoleOperator),
			Approve: true, DeciderHuman: true, At: testNow.Add(-time.Hour),
		}}
		d := decideRenderDeps(req, &fakeDecider{}, &fakeAuth{})
		mustBeSituational(t, get(t, newTestHandler(d, accounts.RoleOperator), "/console/approvals/ap-1").Body.String(),
			"You already signed this at")
	})
	t.Run("excluded requester", func(t *testing.T) {
		req := pendingApprovalRequest("ap-1")
		req.Require.RequesterAllowed = false
		req.RequestedBy, req.RequestedByID = testAccountName(accounts.RoleOperator), testAccountID(accounts.RoleOperator)
		d := decideRenderDeps(req, &fakeDecider{}, &fakeAuth{})
		mustBeSituational(t, get(t, newTestHandler(d, accounts.RoleOperator), "/console/approvals/ap-1").Body.String(),
			"You cannot decide this one</b>")
	})
	t.Run("role below the floor", func(t *testing.T) {
		d := decideRenderDeps(pendingApprovalRequest("ap-1"), &fakeDecider{}, &fakeAuth{})
		mustBeSituational(t, get(t, newTestHandler(d, accounts.RoleViewer), "/console/approvals/ap-1").Body.String(),
			"Your role cannot decide this</b>")
	})
	t.Run("expired", func(t *testing.T) {
		req := pendingApprovalRequest("ap-1")
		req.ExpiresAt = testNow.Add(-time.Minute)
		d := decideRenderDeps(req, &fakeDecider{}, &fakeAuth{})
		mustBeSituational(t, get(t, newTestHandler(d, accounts.RoleOperator), "/console/approvals/ap-1").Body.String(),
			"The TTL lapsed at")
	})
}

// --- The two stale strings ---------------------------------------------------

// TestApprovals_DecidingCopySaysWhatIsTrue: the Console decides a single-Plan
// approval behind step-up today (decide.go). The queue and the Grant card said
// it could not; both said so wrongly. It still does not decide a Grant, and
// that true statement stays.
func TestApprovals_DecidingCopySaysWhatIsTrue(t *testing.T) {
	stale := []string{
		"Deciding arrives with step-up in the administration milestone.",
		"cannot decide anything yet",
		"administration milestone",
	}

	d := renderableDeps()
	d.Approvals = &fakeApprovals{pending: []approval.Request{pendingApprovalRequest("ap-1")}}
	queue := contentOf(get(t, newTestHandler(d, accounts.RoleAdmin), "/console/approvals?waiting=all").Body.String())
	if !strings.Contains(queue, "Deciding happens on the request itself, behind step-up") {
		t.Error("the queue does not say where and how deciding happens")
	}
	if !strings.Contains(queue, "this Console does not decide an Approval grant") {
		t.Error("the queue dropped the true statement that an Approval grant is not decided here")
	}

	g := consoleGrant("grant-1", "ap-grant", 200, 20)
	gd := renderableDeps()
	gd.Approvals = &fakeApprovals{pending: []approval.Request{grantRequest(g, approval.StatePending)}, grants: []approval.Grant{g}}
	card := contentOf(get(t, newTestHandler(gd, accounts.RoleAdmin), "/console/approvals/ap-grant").Body.String())
	if !strings.Contains(card, "so this Console does not decide an Approval grant") {
		t.Error("the Approval grant card does not say this Console does not decide it")
	}

	for _, page := range []string{queue, card} {
		for _, s := range stale {
			if strings.Contains(page, s) {
				t.Errorf("stale copy %q is still rendered", s)
			}
		}
	}
}

func TestFleet_StandingNoteIsInOneClosedDisclosure(t *testing.T) {
	body := get(t, newTestHandler(fleetFixture(), accounts.RoleAdmin), fleetPath).Body.String()
	inside, outside := splitAbout(t, body)
	mustBeStanding(t, inside, outside, "There are no host metrics here, and there will not be.")
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
		"There is no path from this screen to this Node's Policy",
		"receipt time, not a query time",
		"self-reported · this page only · never targeted",
		"reported by the daemon",
		"These counts are observations",
		"never the Node",
	} {
		mustBeSituational(t, body, msg)
	}
	content := contentOf(body)
	for _, ns := range []string{"<b>node:</b>", "<b>relay:</b>", "<b>state:</b>"} {
		if !strings.Contains(content, ns) {
			t.Errorf("the visible legend does not name %s", ns)
		}
	}
	if strings.Contains(content, "<b>tag:</b>") {
		t.Error("the visible legend names tag:, a namespace no chip on this screen can carry yet")
	}
	for _, claim := range []string{"security-lane", "security lane"} {
		if strings.Contains(body, claim) {
			t.Errorf("the Node detail page makes a security-lane claim (%q)", claim)
		}
	}
}

func TestAccounts_StandingNotesAreInOneClosedDisclosure(t *testing.T) {
	body := get(t, newTestHandler(accountsFixture(), accounts.RoleAdmin), accountsPath).Body.String()
	inside, outside := splitAbout(t, body)
	mustBeStanding(t, inside, outside, template.HTMLEscapeString(policyCeilingNote))
	mustBeSituational(t, body, "cannot sign in until a password is set")
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
