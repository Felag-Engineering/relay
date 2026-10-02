package console

// activity_console_calls_test.go proves spec 04's "Reads made from this Console"
// on Activity: a call whose record says BOTH that a Console session
// authenticated it AND that it was a read is left out of the shown reads by
// default, counted, and one click away (?console=show); everything else stays
// listed; and every link the page draws carries ?account= and ?console= as it
// found them. The Agents tests are ported here, at kind=read, which is where
// read records are on this screen at all.

import (
	"html"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/accounts"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/audit"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/capability"
)

// consoleCallsQueries is the page consoleCallsRows describes, as the fake lane.
func consoleCallsQueries() *fakeQueries { return &fakeQueries{rows: consoleCallsRows()} }

// consoleReadsOnly is n reads made from a Console session, newest first.
func consoleReadsOnly(n int) []capability.AuditRow {
	var rows []capability.AuditRow
	for i := 0; i < n; i++ {
		rows = append(rows, capability.AuditRow{Kind: audit.KindRead, OperationName: "query_audit",
			Timestamp: testNow.Add(-time.Duration(i+1) * time.Second), Verified: consoleActor})
	}
	return rows
}

// activityFeedOf is the feed, without the one sentence about Console reads whose count
// legitimately differs. It slices from <div class="feed"> because the strip that
// used to precede the feed is gone (#829), so nothing above the feed is included.
func activityFeedOf(t *testing.T, content string) string {
	t.Helper()
	i := strings.Index(content, `<div class="feed"`)
	j := strings.Index(content, `<div class="pager">`)
	if i < 0 || j < i {
		t.Fatalf("no feed in body:\n%s", content)
	}
	return content[i:j]
}

func TestActivity_ConsoleSessionReadsAreLeftOutByDefault(t *testing.T) {
	body := contentOf(activityAs(t, consoleCallsQueries(), "/console/activity?kind=read"))

	for _, tool := range []string{"query_audit", "query_jobs", "query_tasks"} {
		if strings.Contains(body, tool) {
			t.Errorf("a read made from a Console session (%s) is listed by default", tool)
		}
	}
	if !strings.Contains(body, "list_nodes") {
		t.Error("the AI-agent's read is missing")
	}
}

func TestActivity_ConsoleSessionReadsAreListedWithTheParameter(t *testing.T) {
	shown := contentOf(activityAs(t, consoleCallsQueries(), "/console/activity?kind=read&console=show"))

	for _, tool := range []string{"query_audit", "query_jobs", "query_tasks", "list_nodes"} {
		if !strings.Contains(shown, tool) {
			t.Errorf("with ?console=show, %s is not listed", tool)
		}
	}

	// "Exactly as it does today": the feed equals what the screen
	// renders over the same page with no Console-session reads to leave out.
	stripped := consoleCallsRows()
	for i := range stripped {
		stripped[i].Verified.Method = ""
	}
	plain := contentOf(activityAs(t, &fakeQueries{rows: stripped}, "/console/activity?kind=read&console=show"))
	if activityFeedOf(t, shown) != activityFeedOf(t, plain) {
		t.Error("with ?console=show the feed differs from the same page with nothing to leave out")
	}
}

func TestActivity_TheExclusionIsStatedWithALinkAndACount(t *testing.T) {
	body := contentOf(activityAs(t, consoleCallsQueries(), "/console/activity?kind=read"))
	if !strings.Contains(body, "Reads made from this Console are left out: 3 of the 4 calls on this page.") {
		t.Errorf("the default does not say how many Console reads it left out:\n%s", body)
	}
	if !strings.Contains(body, `href="/console/activity?console=show&amp;kind=read">Show them</a>`) {
		t.Errorf("the sentence does not link to the view that shows them:\n%s", body)
	}
	mustBeSituational(t, body, "Reads made from this Console are left out")

	shown := contentOf(activityAs(t, consoleCallsQueries(), "/console/activity?kind=read&console=show"))
	if !strings.Contains(shown, "Reads made from this Console are shown.") ||
		!strings.Contains(shown, `href="/console/activity?kind=read">Leave them out</a>`) {
		t.Errorf("with ?console=show the sentence does not offer the way back:\n%s", shown)
	}

	// Still stated on a page where nothing was left out: never silent.
	none := contentOf(activityAs(t, &fakeQueries{rows: consoleCallsRows()[4:]}, "/console/activity?kind=read"))
	if !strings.Contains(none, "Reads made from this Console are left out. <a") {
		t.Errorf("with nothing to leave out the rule is not stated:\n%s", none)
	}
}

func TestActivity_AccountFilterComposesWithTheConsoleDefault(t *testing.T) {
	own := contentOf(activityAs(t, consoleCallsQueries(), "/console/activity?kind=read&account=acct-mike"))
	if strings.Contains(own, "query_audit") {
		t.Error("?account= alone listed that Account's Console-session reads")
	}
	if !strings.Contains(own, "Reads made from this Console are left out: 3 of the 3 calls on this page.") ||
		!strings.Contains(own, "Showing one Account only.") {
		t.Errorf("the sentence does not give the filtered Account's count:\n%s", own)
	}
	if !strings.Contains(own, `href="/console/activity?account=acct-mike&amp;console=show&amp;kind=read">Show them</a>`) {
		t.Errorf("the Show link drops the Account filter:\n%s", own)
	}

	both := contentOf(activityAs(t, consoleCallsQueries(), "/console/activity?kind=read&account=acct-mike&console=show"))
	if !strings.Contains(both, "query_audit") || strings.Contains(both, "list_nodes") {
		t.Error("?account=acct-mike&console=show does not list exactly that Account's reads")
	}
	if !strings.Contains(both, `href="/console/activity?console=show&amp;kind=read">Show every Account</a>`) {
		t.Errorf("Show every Account drops ?console=show:\n%s", both)
	}
	if !strings.Contains(both, `href="/console/activity?account=acct-mike&amp;kind=read">Leave them out</a>`) {
		t.Errorf("Leave them out drops the Account filter:\n%s", both)
	}
}

// TestActivity_TheExclusionReadsTheRecordNotTheAccount: the method on the record
// decides, whatever the Account's kind or name. The method itself is never
// displayed.
func TestActivity_TheExclusionReadsTheRecordNotTheAccount(t *testing.T) {
	reg := &countingAccounts{}
	d := renderableDeps()
	d.Accounts = reg
	d.Queries = &fakeQueries{rows: []capability.AuditRow{
		{Kind: audit.KindRead, OperationName: "describe_node", Timestamp: testNow,
			Verified: capability.VerifiedIdentity{AccountID: sweepMachineAccountID, AccountName: "gleipnir-prod",
				Method: string(capability.AuthMethodConsoleSession)}},
		{Kind: audit.KindRead, OperationName: "list_operations", Timestamp: testNow,
			Verified: capability.VerifiedIdentity{AccountID: "acct-mike", AccountName: "mike",
				Method: string(capability.AuthMethodAPIToken)}},
		{Kind: audit.KindRead, OperationName: "get_job", Timestamp: testNow,
			Verified: capability.VerifiedIdentity{AccountID: "acct-ana", AccountName: "ana",
				Method: string(capability.AuthMethodOAuth)}},
	}}
	body := get(t, newTestHandler(d, accounts.RoleAdmin), "/console/activity?kind=read").Body.String()

	if strings.Contains(body, "describe_node") {
		t.Error("a machine Account's Console-session read is listed")
	}
	if !strings.Contains(body, "list_operations") || !strings.Contains(body, "get_job") {
		t.Error("a human Account's API Token or OAuth read is left out")
	}
	for _, m := range []string{"console_session", "api_token", "oauth"} {
		if strings.Contains(body, m) {
			t.Errorf("the authentication method %q is displayed", m)
		}
	}
	if reg.calls != 0 {
		t.Errorf("the exclusion consulted the Account registry %d times", reg.calls)
	}
}

// TestActivity_ARowThatCannotTellIsNotARead: a Console-session record carrying
// raw argv is a Raw Exec, not a read, and stays listed.
func TestActivity_ARowThatCannotTellIsNotARead(t *testing.T) {
	q := &fakeQueries{rows: []capability.AuditRow{
		{Kind: audit.KindRead, RawExecArgv: []string{"/bin/true"}, Timestamp: testNow, Verified: consoleActor},
	}}
	body := contentOf(activityAs(t, q, "/console/activity?kind=read"))
	if !strings.Contains(body, `data-tier="raw_exec"`) {
		t.Errorf("a Console-session record that cannot tell it was a read was left out:\n%s", body)
	}
	if strings.Contains(body, "Reads made from this Console are left out:") {
		t.Error("the page counts a row that is not a read")
	}
}

// TestActivity_TheDefaultAddsNoRead: the exclusion is presentation over the
// page the lane already returned, with or without it.
func TestActivity_TheDefaultAddsNoRead(t *testing.T) {
	run := func(path string) *fakeQueries {
		q := consoleCallsQueries()
		activityAs(t, q, path)
		return q
	}
	def, shown := run("/console/activity?kind=read"), run("/console/activity?kind=read&console=show")
	if def.auditCalls != shown.auditCalls || def.jobCalls != shown.jobCalls || def.auditCalls != 1 {
		t.Errorf("reads differ: audit %d vs %d, jobs %d vs %d", def.auditCalls, shown.auditCalls, def.jobCalls, shown.jobCalls)
	}
	if len(def.auditFilters) != 1 || len(def.auditFilters[0].Kinds) != len(shown.auditFilters[0].Kinds) {
		t.Errorf("the lane filter changed: %+v vs %+v", def.auditFilters, shown.auditFilters)
	}
	if def.auditPages[0] != shown.auditPages[0] || def.auditLimits[0] != auditPageSize {
		t.Errorf("the page request changed: %+v vs %+v", def.auditPages, shown.auditPages)
	}
}

// TestActivity_OnlyConsoleSessionReadsAreLeftOut: a Console session proves a
// cookie, not a person, so an approval decision, a cancel, a refusal and a
// Preflight made from one stay listed. Only a read is left out.
func TestActivity_OnlyConsoleSessionReadsAreLeftOut(t *testing.T) {
	q := &fakeQueries{rows: []capability.AuditRow{
		{Kind: audit.KindRead, OperationName: "query_audit", Timestamp: testNow, Verified: consoleActor},
		{Kind: audit.KindApprovalDecided, ApprovalID: "ap-9", Reason: "approved over out-of-band",
			Timestamp: testNow, Verified: consoleActor},
		{Kind: audit.KindJobCancel, JobID: "job-c", Timestamp: testNow, Verified: consoleActor},
		{Kind: audit.KindRefusal, ActionKind: "raw_exec", Reason: "role floor", Timestamp: testNow, Verified: consoleActor},
		{Kind: audit.KindPlan, ActionKind: "operation", OperationName: "pkg.install", Timestamp: testNow, Verified: consoleActor},
	}}
	body := contentOf(activityAs(t, q, "/console/activity"))

	for _, want := range []string{"asked to cancel Job", "role floor", "pkg.install", audit.KindApprovalDecided} {
		if !strings.Contains(body, want) {
			t.Errorf("a Console-session row (%s) is not listed by default", want)
		}
	}
	if strings.Contains(body, "query_audit") {
		t.Error("a Console-session read is listed on the default feed")
	}
}

func TestActivity_AFeedEmptiedByTheDefaultSaysWhy(t *testing.T) {
	body := contentOf(activityAs(t, &fakeQueries{rows: consoleCallsRows()[:2]}, "/console/activity?kind=read"))

	if !strings.Contains(body, "No calls on this page other than reads made from this Console.") {
		t.Errorf("the feed does not say why it is empty:\n%s", body)
	}
	if strings.Contains(body, "nobody called") {
		t.Error("the page claims nobody called, when the operator did from this Console")
	}
}

func TestActivity_AnAllExcludedPageReadsCoherently(t *testing.T) {
	q := &fakeQueries{rows: consoleReadsOnly(3), auditNext: "c2"}
	body := contentOf(activityAs(t, q, "/console/activity?kind=read"))

	order := []string{
		"Reads made from this Console are left out: 3 of the 3 calls on this page.",
		"No calls on this page other than reads made from this Console.",
		">Older<",
	}
	at := 0
	for _, s := range order {
		i := strings.Index(body[at:], s)
		if i < 0 {
			t.Fatalf("missing, or out of order: %q\n%s", s, body)
		}
		at += i
	}
}

// TestActivity_APartlyExcludedPageRefinedToNothingDoesNotBlameTheConsole: the
// Refine removed a call that was not a Console read, so neither sentence may say
// every call was one.
func TestActivity_APartlyExcludedPageRefinedToNothingDoesNotBlameTheConsole(t *testing.T) {
	rows := append(consoleReadsOnly(2), capability.AuditRow{Kind: audit.KindRead, OperationName: "list_nodes",
		Timestamp: testNow.Add(-time.Minute), Verified: apiIdentity("acct-a", "a", "operator")})
	body := contentOf(activityAs(t, &fakeQueries{rows: rows}, "/console/activity?kind=read&q=zz-nomatch"))

	if !strings.Contains(body, "Nothing matches.") {
		t.Errorf("the feed does not show the narrowing arm:\n%s", body)
	}
	for _, banned := range []string{"other than reads made from this Console", "Every call on this page is a read made from this Console"} {
		if strings.Contains(body, banned) {
			t.Errorf("the page says %q although a call that was not a Console read was refined away", banned)
		}
	}
}

func TestActivity_AFilteredAccountWhoseCallsWereAllLeftOutSaysSo(t *testing.T) {
	body := contentOf(activityAs(t, consoleCallsQueries(), "/console/activity?kind=read&account=acct-mike"))
	if !strings.Contains(body, "This Account has no calls on this page other than reads made from this Console.") {
		t.Errorf("the empty feed does not say why:\n%s", body)
	}

	agent := contentOf(activityAs(t, consoleCallsQueries(), "/console/activity?kind=read&account=acct-agent"))
	if !strings.Contains(agent, "Reads made from this Console are left out. <a") {
		t.Errorf("an Account with nothing left out is given a count:\n%s", agent)
	}
}

func TestActivity_NeverReadsTheAccountRegistry(t *testing.T) {
	for _, path := range []string{
		"/console/activity?kind=read", "/console/activity?kind=read&console=show",
		"/console/activity?kind=read&account=acct-mike", "/console/activity?kind=read&account=acct-mike&console=show",
	} {
		reg := &countingAccounts{}
		d := activityDeps(consoleCallsQueries())
		d.Accounts = reg
		if rec := get(t, newTestHandler(d, accounts.RoleAdmin), path); rec.Code != 200 {
			t.Fatalf("%s: status %d", path, rec.Code)
		}
		if reg.calls != 0 {
			t.Errorf("%s consulted the Account registry %d times", path, reg.calls)
		}
	}
}

func TestActivity_TheDefaultFeedDrawsNoConsoleSentence(t *testing.T) {
	body := contentOf(activityAs(t, consoleCallsQueries(), "/console/activity"))
	if strings.Contains(body, `consolecalls`) {
		t.Error("the default feed, which holds no read records, draws the Console-reads sentence")
	}
}

func TestActivity_AnOlderPageStillStatesTheConsoleRule(t *testing.T) {
	body := contentOf(activityAs(t, consoleCallsQueries(), "/console/activity?kind=read&ac=c1&adone=1"))
	if !strings.Contains(body, `class="scoped consolecalls"`) {
		t.Errorf("an Older page whose trail lane is finished does not state the rule:\n%s", body)
	}
}

func TestActivity_TheFilterFormKeepsConsoleShow(t *testing.T) {
	form := func(path string) string {
		body := contentOf(activityAs(t, consoleCallsQueries(), path))
		i := strings.Index(body, `<form class="viewbar"`)
		return body[i : i+strings.Index(body[i:], "</form>")]
	}
	if f := form("/console/activity?kind=read&console=show"); !strings.Contains(f, `<input type="hidden" name="console" value="show">`) {
		t.Errorf("Apply would drop console=show:\n%s", f)
	}
	if f := form("/console/activity?kind=read"); strings.Contains(f, `name="console"`) {
		t.Errorf("the form carries a console input without the parameter:\n%s", f)
	}
}

func TestActivity_TheExportIgnoresTheConsoleDefault(t *testing.T) {
	body := get(t, newTestHandler(activityDeps(consoleCallsQueries()), accounts.RoleAdmin),
		"/console/activity?kind=read&format=csv").Body.String()
	for _, tool := range []string{"query_audit", "query_jobs", "query_tasks", "list_nodes"} {
		if !strings.Contains(body, tool) {
			t.Errorf("the export leaves out %s", tool)
		}
	}
}

// TestActivity_EveryLinkCarriesAccountAndConsole: every link the page draws
// keeps ?account= and ?console= as it found them. Three exceptions, all
// deliberate: Clear and Start again reset everything, Show every Account is the
// one link that clears the account, and the Console toggle flips console.
func TestActivity_EveryLinkCarriesAccountAndConsole(t *testing.T) {
	rows := []capability.AuditRow{
		{Kind: audit.KindRead, OperationName: "list_nodes", Timestamp: testNow.Add(-time.Second),
			Verified: apiIdentity("acct-1", "alice", "operator")},
		{Kind: audit.KindRead, OperationName: "query_audit", Timestamp: testNow.Add(-2 * time.Second),
			Verified: capability.VerifiedIdentity{AccountID: "acct-1", AccountName: "alice", Method: string(capability.AuthMethodConsoleSession)}},
	}
	activityHref := regexp.MustCompile(`href="(/console/activity[^"]*)"`)

	check := func(t *testing.T, path string, want ...string) {
		t.Helper()
		body := contentOf(activityAs(t, &fakeQueries{rows: rows, auditNext: "next"}, path))
		seen := map[string]bool{}
		for _, m := range activityHref.FindAllStringSubmatch(body, -1) {
			href := html.UnescapeString(m[1])
			seen[href] = true
			all := strings.Contains(body, `href="`+m[1]+`">Show every Account`)
			switch {
			case href == "/console/activity": // Clear and Start again
			case all:
				if strings.Contains(href, "account=") || !strings.Contains(href, "console=show") {
					t.Errorf("Show every Account = %s, want console=show and no account", href)
				}
			case strings.Contains(body, `href="`+m[1]+`">Leave them out`):
				// The toggle flips console by definition and keeps everything else.
				if !strings.Contains(href, "account=acct-1") || strings.Contains(href, "console=") {
					t.Errorf("Leave them out = %s, want account kept and console dropped", href)
				}
			default:
				if !strings.Contains(href, "account=acct-1") || !strings.Contains(href, "console=show") {
					t.Errorf("a link drops the account or console parameter: %s", href)
				}
			}
		}
		for _, w := range want {
			if !regexp.MustCompile(w).MatchString(body) {
				t.Errorf("%s draws no link matching %s", path, w)
			}
		}
		if !seen["/console/activity"] {
			t.Error("Clear is not exactly /console/activity")
		}
	}

	check(t, "/console/activity?kind=read&account=acct-1&console=show",
		`>Older</a>`, `class="refreshbtn"`, `class="kchip`, `Export this filter as CSV`,
		`Show every Account`, `Leave them out`)
	check(t, "/console/activity?kind=read&account=acct-1&console=show&ac=next", `>Newest</a>`)
}
