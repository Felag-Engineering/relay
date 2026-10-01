package console

// activity_strip_test.go proves spec 04's "Who is active" on Activity: the
// strip's membership, its counts, what it links to (the verified Account ID,
// never a name, D18) and what it says when it is empty. The Agents rail's
// window and paging tests are ported here.

import (
	"fmt"
	"html"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/audit"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/capability"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/jobs"
)

// apiIdentity is a verified identity authenticated with an API Token, so none
// of its calls is a read made from a Console session.
func apiIdentity(id, name, role string) capability.VerifiedIdentity {
	return capability.VerifiedIdentity{
		AccountID: id, AccountName: name, Role: role, Method: string(capability.AuthMethodAPIToken),
	}
}

// refusalBy is one refusal row. The reason is what tells two refusals apart on
// screen, so two refusals with the same reason render identically.
func refusalBy(v capability.VerifiedIdentity, age time.Duration, reason string) capability.AuditRow {
	return capability.AuditRow{
		Kind: audit.KindRefusal, ActionKind: "operation", OperationName: "service.restart",
		Reason: reason, Timestamp: testNow.Add(-age), Verified: v,
	}
}

// finishedJob is a resolved Job: nothing unresolved, so not running.
func finishedJob(id, requester, accountID string) capability.JobSummary {
	sum := runningJob(id, requester, accountID)
	sum.Unresolved = 0
	sum.Selector = "role=web"
	sum.Counts = map[jobs.Outcome]int{jobs.OutcomeSuccess: 3}
	return sum
}

// stripSection is the whoactive section of a rendered page.
func stripSection(t *testing.T, body string) string {
	t.Helper()
	start := strings.Index(body, `<section class="whoactive"`)
	if start < 0 {
		t.Fatalf("no whoactive section in body:\n%s", body)
	}
	end := strings.Index(body[start:], `</section>`)
	if end < 0 {
		t.Fatalf("unterminated whoactive section:\n%s", body)
	}
	return body[start : start+end]
}

type stripView struct {
	Name     string
	Href     string
	Account  string
	On       bool
	Unlinked bool
	Text     string
}

var (
	stripRowRE  = regexp.MustCompile(`(?s)<(a|div) class="arow([^"]*)"([^>]*)>(.*?)</(?:a|div)>`)
	stripHrefRE = regexp.MustCompile(`href="([^"]*)"`)
	stripChipRE = regexp.MustCompile(`<span class="chip trust"[^>]*>([^<]*)</span>`)
)

// stripEntries reads each entry off the strip: its name, where it links ("" for
// an unlinked one) and the account that link scopes to.
func stripEntries(t *testing.T, body string) []stripView {
	t.Helper()
	var out []stripView
	for _, m := range stripRowRE.FindAllStringSubmatch(stripSection(t, body), -1) {
		v := stripView{
			On:       strings.Contains(m[2], " on"),
			Unlinked: strings.Contains(m[2], "unlinked"),
			Text:     m[4],
		}
		if n := stripChipRE.FindStringSubmatch(m[4]); n != nil {
			v.Name = html.UnescapeString(n[1])
		}
		if h := stripHrefRE.FindStringSubmatch(m[3]); h != nil {
			v.Href = html.UnescapeString(h[1])
			u, err := url.Parse(v.Href)
			if err != nil {
				t.Fatalf("strip href %q: %v", v.Href, err)
			}
			v.Account = u.Query().Get("account")
		}
		out = append(out, v)
	}
	return out
}

func stripNames(t *testing.T, body string) []string {
	t.Helper()
	var names []string
	for _, e := range stripEntries(t, body) {
		names = append(names, e.Name)
	}
	return names
}

// stripNoteOf is the strip's own sentence, the paragraph after its entries.
func stripNoteOf(t *testing.T, body string) string {
	t.Helper()
	sec := stripSection(t, body)
	i := strings.LastIndex(sec, `<p class="dim">`)
	if i < 0 {
		return ""
	}
	rest := sec[i+len(`<p class="dim">`):]
	return html.UnescapeString(rest[:strings.Index(rest, "</p>")])
}

func stripHint(t *testing.T, body string) string {
	t.Helper()
	sec := stripSection(t, body)
	i := strings.Index(sec, `<span class="phint">`)
	if i < 0 {
		t.Fatalf("the strip has no hint:\n%s", sec)
	}
	rest := sec[i+len(`<span class="phint">`):]
	return html.UnescapeString(rest[:strings.Index(rest, "</span>")])
}

// --- The note's contract, exhaustively ---------------------------------------

func TestActivityStripNote_NeverSpeaksForTheFleet(t *testing.T) {
	bools := []bool{false, true}
	for _, listed := range []int{0, 1} {
		for _, dropped := range []int{0, 2} {
			for _, scrolled := range bools {
				for _, exhausted := range bools {
					for _, scoped := range bools {
						for _, awaiting := range []int{0, 1} {
							for _, unrecorded := range []int{0, 1} {
								for _, pc := range [][2]int{{0, 0}, {0, 3}, {3, 3}, {1, 3}} {
									n := activityStripFacts{
										Listed: listed, Dropped: dropped, Scrolled: scrolled, Exhausted: exhausted,
										AccountScoped: scoped, Awaiting: awaiting, Unrecorded: unrecorded,
										ConsoleLeftOut: pc[0], PageCalls: pc[1],
									}
									got := activityStripNote(n)
									for _, banned := range []string{
										"No Account has called a control surface yet",
										"No Account has called in the last 15 minutes",
										"in the window",
									} {
										if strings.Contains(got, banned) {
											t.Errorf("%+v: note %q contains %q", n, got, banned)
										}
									}
									if empty := listed > 0 && dropped == 0; (got == "") != empty {
										t.Errorf("%+v: note %q, empty only when listed > 0 and dropped == 0", n, got)
									}
								}
							}
						}
					}
				}
			}
		}
	}
}

func TestActivityStripNote_TheConsoleReadArmNeedsTheWholePage(t *testing.T) {
	const every = "Every call on this page is a read made from this Console"
	if got := activityStripNote(activityStripFacts{ConsoleLeftOut: 1, PageCalls: 3}); strings.Contains(got, every) {
		t.Errorf("a partly excluded page blames the Console for all of it: %q", got)
	}
	if got := activityStripNote(activityStripFacts{ConsoleLeftOut: 3, PageCalls: 3}); !strings.Contains(got, every) {
		t.Errorf("an entirely excluded page does not say so: %q", got)
	}
	scoped := activityStripNote(activityStripFacts{ConsoleLeftOut: 3, PageCalls: 3, AccountScoped: true})
	if !strings.Contains(scoped, "Every call by this Account on this page") {
		t.Errorf("the scoped sentence does not name the Account: %q", scoped)
	}
}

func TestActivityStripNote_AnExhaustedPageHoldsNoCalls(t *testing.T) {
	got := activityStripNote(activityStripFacts{Exhausted: true})
	if got != "This page holds no calls." {
		t.Errorf("an exhausted page says %q", got)
	}
}

// --- Membership and what it says ----------------------------------------------

func TestActivity_AnAccountOutsideTheWindowDropsOffTheStrip(t *testing.T) {
	q := &fakeQueries{rows: []capability.AuditRow{
		refusalBy(apiIdentity("acct-fresh", "fresh", "operator"), time.Minute, "a"),
		refusalBy(apiIdentity("acct-stale", "stale", "operator"), 45*time.Minute, "b"),
	}}
	body := activityAs(t, q, "/console/activity")

	if names := stripNames(t, body); len(names) != 1 || names[0] != "fresh" {
		t.Errorf("strip lists %v, want only fresh", names)
	}
	if !strings.Contains(body, "b</div>") {
		t.Errorf("the stale Account's call left the feed as well as the strip:\n%s", body)
	}
	if note := stripNoteOf(t, body); !strings.HasPrefix(note, "1 Account called on this page but not in the last 15 minutes") {
		t.Errorf("note = %q", note)
	}
}

func TestActivity_APageOfStaleCallsEmptiesTheStripAndSaysSo(t *testing.T) {
	a, b := apiIdentity("acct-a", "a", "operator"), apiIdentity("acct-b", "b", "operator")
	q := &fakeQueries{rows: []capability.AuditRow{
		refusalBy(a, 20*time.Minute, "r1"),
		refusalBy(b, 30*time.Minute, "r2"),
		{Kind: audit.KindApprovalDecided, ApprovalID: "ap-1", Reason: "r3", Timestamp: testNow.Add(-40 * time.Minute), Verified: a},
	}}
	body := activityAs(t, q, "/console/activity")

	if names := stripNames(t, body); len(names) != 0 {
		t.Errorf("strip lists %v, want nobody", names)
	}
	want := "No Account on this page has called in the last 15 minutes. 2 Accounts called earlier — their calls are below."
	if note := stripNoteOf(t, body); note != want {
		t.Errorf("note = %q, want %q", note, want)
	}
	for _, reason := range []string{"r1", "r2", "r3"} {
		if !strings.Contains(body, reason) {
			t.Errorf("the feed lost the call with reason %s", reason)
		}
	}
}

// TestActivity_ADefaultStalePageNeverSpeaksForTheFleet: the default feed leaves
// read records out, so a fresh read by an Account is not on it. A stale page
// must not say "nobody called" about the fleet while that Account is calling.
func TestActivity_ADefaultStalePageNeverSpeaksForTheFleet(t *testing.T) {
	q := &fakeQueries{rows: []capability.AuditRow{
		// api_token, so these are not reads made from a Console session.
		{Kind: audit.KindRead, OperationName: "list_nodes", Timestamp: testNow.Add(-time.Minute),
			Verified: apiIdentity("acct-reader", "reader", "operator")},
		refusalBy(apiIdentity("acct-a", "a", "operator"), 30*time.Minute, "r1"),
		refusalBy(apiIdentity("acct-b", "b", "operator"), 40*time.Minute, "r2"),
	}}
	body := activityAs(t, q, "/console/activity")

	if containsString(q.auditFilters[0].Kinds, audit.KindRead) {
		t.Fatal("the default feed requested read records")
	}
	if names := stripNames(t, body); len(names) != 0 {
		t.Errorf("strip lists %v, want nobody", names)
	}
	for _, banned := range []string{"No Account has called in the last 15 minutes", "No Account has called a control surface yet."} {
		if strings.Contains(body, banned) {
			t.Errorf("a filtered page says %q about the fleet", banned)
		}
	}
	if note := stripNoteOf(t, body); !strings.HasPrefix(note, "No Account on this page has called in the last 15 minutes") {
		t.Errorf("note = %q", note)
	}
	if hint := stripHint(t, body); !strings.Contains(hint, "Read records are left out of this view, so an Account that only read is not listed.") {
		t.Errorf("the hint does not qualify the strip: %q", hint)
	}
}

func TestActivity_AnEmptyDefaultFeedWithOnlyReadsNeverSaysNobodyCalled(t *testing.T) {
	q := &fakeQueries{rows: []capability.AuditRow{
		{Kind: audit.KindRead, OperationName: "list_nodes", Timestamp: testNow.Add(-time.Minute),
			Verified: apiIdentity("acct-reader", "reader", "operator")},
	}}
	body := activityAs(t, q, "/console/activity")

	if strings.Contains(body, "No Account has called a control surface yet.") {
		t.Error("the strip speaks for the fleet")
	}
	if note := stripNoteOf(t, body); note != "This page holds no calls." {
		t.Errorf("note = %q", note)
	}
	if !strings.Contains(stripHint(t, body), "Read records are left out of this view") {
		t.Error("the hint does not carry the read-records sentence")
	}
}

func TestActivity_AnEmptyPageAndAStalePageSayDifferentThings(t *testing.T) {
	empty := stripNoteOf(t, activityAs(t, &fakeQueries{}, "/console/activity"))
	if empty != "This page holds no calls." {
		t.Errorf("an empty page says %q", empty)
	}

	stale := &fakeQueries{rows: []capability.AuditRow{refusalBy(apiIdentity("acct-a", "a", "operator"), time.Hour, "r")}}
	staleNote := stripNoteOf(t, activityAs(t, stale, "/console/activity"))
	if !strings.HasPrefix(staleNote, "No Account on this page has called in the last 15 minutes. 1 Account called earlier") {
		t.Errorf("a stale page says %q", staleNote)
	}

	stale = &fakeQueries{
		rows:      []capability.AuditRow{refusalBy(apiIdentity("acct-a", "a", "operator"), time.Hour, "r")},
		auditNext: "next",
	}
	older := stripNoteOf(t, activityAs(t, stale, "/console/activity?ac=c1"))
	if !strings.Contains(older, "which is expected on a page reached by following Older") {
		t.Errorf("a stale page reached by Older says %q", older)
	}
	if empty == staleNote || staleNote == older {
		t.Error("two different situations share one sentence")
	}
}

func TestActivity_ThePageNeverSaysCallsAreInTheWindow(t *testing.T) {
	for name, rows := range map[string][]capability.AuditRow{
		"empty": nil,
		"stale": {refusalBy(apiIdentity("acct-a", "a", "operator"), time.Hour, "r")},
		"fresh": {refusalBy(apiIdentity("acct-a", "a", "operator"), time.Minute, "r")},
	} {
		body := activityAs(t, &fakeQueries{rows: rows}, "/console/activity")
		if strings.Contains(stripSection(t, body), "in the window") {
			t.Errorf("%s: the strip says \"in the window\"", name)
		}
	}
}

func TestActivity_ANarrowedEmptyPageDoesNotSpeakForTheFleet(t *testing.T) {
	body := activityAs(t, &fakeQueries{}, "/console/activity?kind=freeze")
	if note := stripNoteOf(t, body); note != "This page holds no calls." {
		t.Errorf("a narrowed empty page says %q", note)
	}
	if strings.Contains(body, "No Account has called a control surface yet.") {
		t.Error("a narrowed page speaks for the fleet")
	}

	q := &fakeQueries{rows: []capability.AuditRow{refusalBy(apiIdentity("acct-a", "a", "operator"), time.Hour, "r")}}
	body = activityAs(t, q, "/console/activity?kind=refusal&q=zz-nomatch")
	if note := stripNoteOf(t, body); note != "No call on this page matches this filter." {
		t.Errorf("a refined-away page says %q", note)
	}
}

func TestActivity_TheStripHintIsQualifiedOnlyWhenReadsAreLeftOut(t *testing.T) {
	const qualifier = "Read records are left out of this view"
	if h := stripHint(t, activityAs(t, &fakeQueries{}, "/console/activity?kind=read")); strings.Contains(h, qualifier) {
		t.Errorf("at kind=read the hint says reads are left out: %q", h)
	}
	for _, path := range []string{"/console/activity?kind=refusal", "/console/activity"} {
		if h := stripHint(t, activityAs(t, &fakeQueries{}, path)); !strings.Contains(h, qualifier) {
			t.Errorf("%s: the hint does not say reads are left out: %q", path, h)
		}
	}
}

// --- Ported from the Agents rail ---------------------------------------------

func TestActivity_TheStripAgreesPerAccountWhenAnAccountDropsOff(t *testing.T) {
	busy, quiet := apiIdentity("acct-busy", "busy", "operator"), apiIdentity("acct-quiet", "quiet", "operator")
	q := &fakeQueries{rows: []capability.AuditRow{
		refusalBy(busy, time.Minute, "b1"),
		refusalBy(busy, 2*time.Minute, "b2"),
		refusalBy(quiet, 3*time.Minute, "q1"),
		refusalBy(quiet, 40*time.Minute, "q2"),
	}}
	body := activityAs(t, q, "/console/activity")

	entries := stripEntries(t, body)
	if len(entries) != 2 || entries[0].Name != "busy" {
		t.Fatalf("strip = %+v, want busy first and quiet second", entries)
	}
	// Counted over the page, not over the window: quiet's old call still counts.
	if !strings.Contains(entries[0].Text, "<b>2</b> calls") || !strings.Contains(entries[1].Text, "<b>2</b> calls") {
		t.Errorf("the strip does not count each Account's calls on the page:\n%s", stripSection(t, body))
	}
	if !strings.Contains(entries[0].Text, "2 mutate") {
		t.Errorf("the strip does not count mutate-class calls:\n%s", entries[0].Text)
	}
}

func TestActivity_TheStripShowsTheVerifiedRoleAndNeverAnAssertedOne(t *testing.T) {
	const aroleOpen = `<span class="arole" title="The role the Relay authenticated this Account with at its most recent call on this page.">`

	t.Run("verified renders the role", func(t *testing.T) {
		q := &fakeQueries{rows: []capability.AuditRow{refusalBy(apiIdentity("acct-1", "prod", "operator"), time.Minute, "r")}}
		if body := activityAs(t, q, "/console/activity"); !strings.Contains(stripSection(t, body), aroleOpen+"operator</span>") {
			t.Errorf("a verified role does not render:\n%s", stripSection(t, body))
		}
	})
	t.Run("an asserted principal never fakes a role", func(t *testing.T) {
		row := refusalBy(capability.VerifiedIdentity{}, time.Minute, "r")
		row.Principal = "alice:operator"
		body := activityAs(t, &fakeQueries{rows: []capability.AuditRow{row}}, "/console/activity")
		if strings.Contains(stripSection(t, body), `class="arole"`) {
			t.Errorf("an asserted entry renders a role:\n%s", stripSection(t, body))
		}
	})
	t.Run("a role with no verified Account renders no role", func(t *testing.T) {
		row := refusalBy(capability.VerifiedIdentity{Role: "admin"}, time.Minute, "r")
		row.Principal = "mallory:admin"
		body := activityAs(t, &fakeQueries{rows: []capability.AuditRow{row}}, "/console/activity")
		if strings.Contains(stripSection(t, body), `class="arole"`) {
			t.Errorf("a role leaked onto an unverified entry:\n%s", stripSection(t, body))
		}
	})
	t.Run("a role change mid-page shows the newer authority", func(t *testing.T) {
		// Listed oldest first on purpose: the newer role wins by time, not by position.
		q := &fakeQueries{rows: []capability.AuditRow{
			refusalBy(apiIdentity("acct-1", "prod", "operator"), 10*time.Minute, "old"),
			refusalBy(apiIdentity("acct-1", "prod", "admin"), time.Minute, "new"),
		}}
		sec := stripSection(t, activityAs(t, q, "/console/activity"))
		if !strings.Contains(sec, aroleOpen+"admin</span>") || strings.Contains(sec, aroleOpen+"operator</span>") {
			t.Errorf("the strip does not show the newer role:\n%s", sec)
		}
	})
}

func TestActivity_TheStripShowsTheFirstCallOnThePage(t *testing.T) {
	who := apiIdentity("acct-1", "agent", "operator")
	t.Run("distinct first and last", func(t *testing.T) {
		q := &fakeQueries{rows: []capability.AuditRow{refusalBy(who, time.Minute, "a"), refusalBy(who, 12*time.Minute, "b")}}
		sec := stripSection(t, activityAs(t, q, "/console/activity"))
		if !strings.Contains(sec, "first 12m ago") || !strings.Contains(sec, "last 1m ago") {
			t.Errorf("first and last are not both shown:\n%s", sec)
		}
	})
	t.Run("the same text renders once", func(t *testing.T) {
		q := &fakeQueries{rows: []capability.AuditRow{
			refusalBy(who, 5*time.Minute, "a"), refusalBy(who, 5*time.Minute+20*time.Second, "b"),
		}}
		sec := stripSection(t, activityAs(t, q, "/console/activity"))
		if strings.Count(sec, "ago") != 1 || !strings.Contains(sec, "last 5m ago") || strings.Contains(sec, "first") {
			t.Errorf("two calls 20s apart render as a span:\n%s", sec)
		}
	})
}

func TestActivity_TheWindowIsNeverPushedIntoTheLane(t *testing.T) {
	q := &fakeQueries{}
	activityAs(t, q, "/console/activity")
	for _, f := range q.auditFilters {
		if !f.Since.IsZero() {
			t.Errorf("the audit lane got Since = %v derived from the 15 minutes", f.Since)
		}
	}
	for _, f := range q.jobFilters {
		if !f.Since.IsZero() {
			t.Errorf("the Job lane got Since = %v derived from the 15 minutes", f.Since)
		}
	}
}

func TestActivity_TheStripSaysWhatItCountedOver(t *testing.T) {
	q := &fakeQueries{rows: []capability.AuditRow{refusalBy(apiIdentity("acct-1", "a", "operator"), time.Minute, "r")}}
	body := activityAs(t, q, "/console/activity")
	if hint := stripHint(t, body); !strings.HasPrefix(hint, "Accounts on this page with a call in the last 15 minutes.") {
		t.Errorf("hint = %q", hint)
	}
	if !strings.Contains(stripSection(t, body), "Who is active") {
		t.Error("the newest page's strip is not titled Who is active")
	}

	q = &fakeQueries{rows: q.rows, auditNext: "next"}
	scrolled := stripSection(t, activityAs(t, q, "/console/activity?ac=c1"))
	if !strings.Contains(scrolled, `<div class="ftitle">Accounts on this page`) {
		t.Errorf("a scrolled page's strip is not titled for the page:\n%s", scrolled)
	}
}

// --- D18 and #617 --------------------------------------------------------------

func TestActivity_TheStripLinksByVerifiedAccountIDNeverByName(t *testing.T) {
	q := &fakeQueries{rows: []capability.AuditRow{refusalBy(apiIdentity("acct-1", "alice", "operator"), time.Minute, "r")}}
	body := activityAs(t, q, "/console/activity")

	entries := stripEntries(t, body)
	if len(entries) != 1 || entries[0].Account != "acct-1" {
		t.Fatalf("strip = %+v, want one entry linking account=acct-1", entries)
	}
	if strings.Contains(stripSection(t, body), "account=alice") {
		t.Error("a strip link names the Account by its name")
	}
}

func TestActivity_AnEntryWithNoVerifiedIDIsListedButNotLinked(t *testing.T) {
	row := refusalBy(capability.VerifiedIdentity{}, time.Minute, "r")
	row.Principal = "mallory:admin"
	body := activityAs(t, &fakeQueries{rows: []capability.AuditRow{row}}, "/console/activity")

	entries := stripEntries(t, body)
	if len(entries) != 1 || !entries[0].Unlinked || entries[0].Href != "" || entries[0].Name != "mallory:admin" {
		t.Fatalf("strip = %+v, want one unlinked mallory:admin entry", entries)
	}
	if strings.Contains(stripSection(t, body), "<a ") {
		t.Error("an entry with no verified ID is inside an anchor")
	}
}

func TestActivity_AnUnattributedCallIsListedOnTheStripButNotLinked(t *testing.T) {
	row := refusalBy(capability.VerifiedIdentity{}, time.Minute, "r")
	body := activityAs(t, &fakeQueries{rows: []capability.AuditRow{row}}, "/console/activity")

	entries := stripEntries(t, body)
	if len(entries) != 1 || entries[0].Name != "unattributed" || !entries[0].Unlinked {
		t.Fatalf("strip = %+v, want an unlinked unattributed entry", entries)
	}
	if !strings.Contains(entries[0].Text, `data-trust="asserted"`) {
		t.Error("the unattributed entry's chip is not the asserted (dashed) one")
	}
}

func TestActivity_TwoAccountsSharingANameAreTwoEntries(t *testing.T) {
	q := &fakeQueries{rows: []capability.AuditRow{
		refusalBy(apiIdentity("acct-1", "sam", "operator"), time.Minute, "a"),
		refusalBy(apiIdentity("acct-2", "sam", "operator"), 2*time.Minute, "b"),
	}}
	entries := stripEntries(t, activityAs(t, q, "/console/activity"))
	if len(entries) != 2 || entries[0].Account == entries[1].Account {
		t.Errorf("strip = %+v, want two entries with different account links", entries)
	}
}

func TestActivity_AStripEntryNamesTheAccountByItsNewestName(t *testing.T) {
	q := &fakeQueries{rows: []capability.AuditRow{
		refusalBy(apiIdentity("acct-1", "alice2", "operator"), time.Minute, "new"),
		refusalBy(apiIdentity("acct-1", "alice", "operator"), 2*time.Minute, "old"),
	}}
	body := activityAs(t, q, "/console/activity")
	entries := stripEntries(t, body)
	if len(entries) != 1 || entries[0].Name != "alice2" || entries[0].Account != "acct-1" {
		t.Fatalf("strip = %+v, want one alice2 entry linking acct-1", entries)
	}
	if !strings.Contains(entries[0].Text, "<b>2</b> calls") {
		t.Errorf("the renamed Account's calls are not one entry's count:\n%s", entries[0].Text)
	}
}

// TestActivity_FollowingAStripLinkScopesBothLanes: the link is the Account ID,
// and both lanes are filtered by it.
func TestActivity_FollowingAStripLinkScopesBothLanes(t *testing.T) {
	q := &fakeQueries{
		rows: []capability.AuditRow{
			refusalBy(apiIdentity("acct-1", "alice", "operator"), time.Minute, "mine"),
			refusalBy(apiIdentity("acct-2", "bob", "operator"), 2*time.Minute, "theirs"),
		},
		jobs: []capability.JobSummary{finishedJob("job-1", "alice", "acct-1"), finishedJob("job-2", "bob", "acct-2")},
	}
	body := activityAs(t, q, "/console/activity?account=acct-1")

	if q.jobFilters[0].RequesterAccountID != "acct-1" || q.auditFilters[0].AccountID != "acct-1" {
		t.Errorf("account= reached job=%q audit=%q", q.jobFilters[0].RequesterAccountID, q.auditFilters[0].AccountID)
	}
	entries := stripEntries(t, body)
	if len(entries) != 1 || !entries[0].On || entries[0].Account != "acct-1" {
		t.Fatalf("strip = %+v, want the one current entry scoped to acct-1", entries)
	}
	if !strings.Contains(stripSection(t, body), `aria-current="page"`) {
		t.Error("the current entry is not marked aria-current=page")
	}
	all := regexp.MustCompile(`href="([^"]*)">Show every Account`).FindStringSubmatch(body)
	if all == nil {
		t.Fatal("no Show every Account link")
	}
	if strings.Contains(html.UnescapeString(all[1]), "account=") {
		t.Errorf("Show every Account keeps the account: %s", all[1])
	}
}

func TestActivity_RunningRowsDoNotCountOnTheStrip(t *testing.T) {
	t.Run("awaiting its record", func(t *testing.T) {
		running := runningJob("job-1", "alice", "acct-1") // no Selector, arguments, approval, Grant or on-behalf-of
		body := activityAs(t, &fakeQueries{jobs: []capability.JobSummary{running}}, "/console/activity")
		if names := stripNames(t, body); len(names) != 0 {
			t.Errorf("strip lists %v for a Job whose dispatch is not recorded", names)
		}
		want := "No Account has a recorded call on this page yet. Running Jobs whose dispatch is not recorded yet are shown below and join the strip once it is."
		if note := stripNoteOf(t, body); note != want {
			t.Errorf("note = %q, want %q", note, want)
		}
		if n := strings.Count(body, `<article class="ev"`); n != 1 {
			t.Errorf("rows = %d, want the running Job shown once", n)
		}
	})
	t.Run("recorded and still running", func(t *testing.T) {
		running := runningJob("job-1", "alice", "acct-1")
		running.Selector = "role=web"
		body := activityAs(t, &fakeQueries{jobs: []capability.JobSummary{running}}, "/console/activity")
		entries := stripEntries(t, body)
		if len(entries) != 1 || !strings.Contains(entries[0].Text, "<b>1</b> call") {
			t.Fatalf("strip = %+v, want acct-1 with 1 call", entries)
		}
		if note := stripNoteOf(t, body); note != "" {
			t.Errorf("note = %q, want none", note)
		}
	})
	t.Run("finished", func(t *testing.T) {
		body := activityAs(t, &fakeQueries{jobs: []capability.JobSummary{finishedJob("job-1", "alice", "acct-1")}}, "/console/activity")
		entries := stripEntries(t, body)
		if len(entries) != 1 || !strings.Contains(entries[0].Text, "<b>1</b> call") || !strings.Contains(entries[0].Text, "1 mutate") {
			t.Fatalf("strip = %+v, want 1 call, 1 mutate from the Job's declared class", entries)
		}
	})
}

func TestActivity_EmptyStripSentenceIsUnchangedWithNoRunningJobs(t *testing.T) {
	body := activityAs(t, &fakeQueries{}, "/console/activity")
	if note := stripNoteOf(t, body); note != "This page holds no calls." {
		t.Errorf("note = %q", note)
	}
	if strings.Contains(body, "not recorded yet are shown below") {
		t.Error("an empty page talks about running Jobs")
	}
}

func TestActivity_AJobWithNoRecordedRequesterIsNotOnTheStrip(t *testing.T) {
	orphan := finishedJob("job-1", "", "")
	body := activityAs(t, &fakeQueries{jobs: []capability.JobSummary{orphan}}, "/console/activity")

	if names := stripNames(t, body); len(names) != 0 {
		t.Errorf("strip lists %v for a Job with no requester", names)
	}
	want := "No Account has a recorded call on this page. Jobs below with no recorded requester have no caller to list."
	if note := stripNoteOf(t, body); note != want {
		t.Errorf("note = %q, want %q", note, want)
	}
	if !strings.Contains(body, "finished with no recorded principal") {
		t.Error("the row no longer surfaces its own defect")
	}
}

func TestActivity_ADispatchRowCountsOnTheStripAsOneCall(t *testing.T) {
	sum := finishedJob("job-1", "alice", "acct-1")
	sum.Total = 3
	entries := stripEntries(t, activityAs(t, &fakeQueries{jobs: []capability.JobSummary{sum}}, "/console/activity"))
	if len(entries) != 1 || !strings.Contains(entries[0].Text, "<b>1</b> call") {
		t.Errorf("a Job across 3 Nodes counts as %+v, want 1 call", entries)
	}
}

// stripCallCount is the call count the strip prints for the named entry.
func stripCallCount(t *testing.T, body, name string) int {
	t.Helper()
	for _, e := range stripEntries(t, body) {
		if e.Name == name {
			var n int
			if _, err := fmt.Sscanf(e.Text[strings.Index(e.Text, "<b>"):], "<b>%d</b>", &n); err != nil {
				t.Fatalf("no call count in %q: %v", e.Text, err)
			}
			return n
		}
	}
	t.Fatalf("no strip entry named %q in %v", name, stripNames(t, body))
	return 0
}
