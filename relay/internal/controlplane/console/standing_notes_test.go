package console

// standing_notes_test.go proves 00-foundations.md's "Standing notes and
// situational messages": a note rendered on every view of a screen lives in
// ONE closed "About this screen" disclosure at the screen's foot; a message
// rendered because of this request, this caller or this record's state stays
// visible where it always was.

import (
	"strings"
	"testing"
	"time"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/accounts"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/approval"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/capability"
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
		"The default feed leaves out the trail&#39;s own read records.",
		"Two row kinds are not built here yet: enrollments and label changes.",
		"The filter box carries no Selector and no Node.",
		"The chips above list every family this screen shows, including empty ones.",
		"Every Refresh is an audited read",
		"Cancel is offered on a running Job&#39;s row",
	)
}

func TestActivity_SituationalMessagesStayVisible(t *testing.T) {
	h := newTestHandler(activityDeps(&fakeQueries{}), accounts.RoleAdmin)
	for _, tc := range []struct{ path, msg string }{
		{"/console/activity?window=fortnight", "Part of this URL could not be read:"},
		{"/console/activity?kind=nonesuch", "There is no row kind called"},
		{"/console/activity?q=nginx", "matches text within the rows already on this page"},
		{"/console/activity?outcome=failure", "Outcome narrows dispatch rows after the page is fetched."},
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
		"Password changes and the first API Token are not on the trail.",
		"(#782)",
		"OAuth sign-ins are not listed.",
		"There is no filter by the changed Account.",
		"Every Refresh is an audited read",
		"limited to admins in the Console only",
	)
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

// --- Read egress ------------------------------------------------------------

func TestReads_StandingNotesAreInOneClosedDisclosure(t *testing.T) {
	body := readsBody(t, &fakeQueries{}, "")
	inside, outside := splitAbout(t, body)
	mustBeStanding(t, inside, outside,
		"The audit trail keeps outcomes and timings and never read output",
		"deciding rule is not shown here.",
		"Reading this page is itself a read, and it is counted here.",
		"The two halves of this page read different clocks.",
		"Two filters this screen does not offer.",
	)
}

func TestReads_SituationalMessagesStayVisible(t *testing.T) {
	// No read-class Job in the window: the lane was not queried, and the page
	// says so where the operator is reading, not behind a click.
	mustBeSituational(t, readsBody(t, &fakeQueries{}, ""), "The audit lane was not queried for Node reads.")
	// A window this page does not offer is a note about THIS request.
	mustBeSituational(t, readsBody(t, &fakeQueries{}, "window=fortnight"), "The window asked for is not one of")
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
		"Rejected attempts are not shown yet.")
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
			"You cannot decide this one.")
	})
	t.Run("role below the floor", func(t *testing.T) {
		d := decideRenderDeps(pendingApprovalRequest("ap-1"), &fakeDecider{}, &fakeAuth{})
		mustBeSituational(t, get(t, newTestHandler(d, accounts.RoleViewer), "/console/approvals/ap-1").Body.String(),
			"Your role cannot decide this.")
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
	if !strings.Contains(queue, "This Console does not decide a Grant") {
		t.Error("the queue dropped the true statement that a Grant is not decided here")
	}

	g := consoleGrant("grant-1", "ap-grant", 200, 20)
	gd := renderableDeps()
	gd.Approvals = &fakeApprovals{pending: []approval.Request{grantRequest(g, approval.StatePending)}, grants: []approval.Grant{g}}
	card := contentOf(get(t, newTestHandler(gd, accounts.RoleAdmin), "/console/approvals/ap-grant").Body.String())
	if !strings.Contains(card, "so it does not decide a Grant at all: it decides a single\n  Plan, behind step-up") {
		t.Error("the Grant card does not say what this Console does decide")
	}

	for _, page := range []string{queue, card} {
		for _, s := range stale {
			if strings.Contains(page, s) {
				t.Errorf("stale copy %q is still rendered", s)
			}
		}
	}
}
