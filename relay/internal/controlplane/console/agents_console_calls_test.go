package console

// agents_console_calls_test.go proves spec 03's "Reads made from this
// Console": where the Agents screen lists calls and counts them on the rail,
// a call whose record says BOTH that a Console session authenticated it AND
// that it was a read is left out by default; everything else stays listed;
// the exclusion is stated beside the feed with a link that shows them;
// ?account= composes with it.

import (
	"context"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/accounts"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/audit"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/capability"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/jobs"
)

// consoleCallsRows is one page mixing an AI-agent's calls (API Token) with
// the signed-in operator's own page loads (Console session). The operator's
// reads name tools the agent never calls, so a substring test cannot confuse
// the two.
func consoleCallsRows() []capability.AuditRow {
	agent := capability.VerifiedIdentity{
		AccountID: "acct-agent", AccountName: "gleipnir-prod", Role: "operator",
		Method: string(capability.AuthMethodAPIToken),
	}
	operator := capability.VerifiedIdentity{
		AccountID: "acct-mike", AccountName: "mike", Role: "admin",
		Method: string(capability.AuthMethodConsoleSession),
	}
	at := func(s int) time.Time { return testNow.Add(-time.Duration(s) * time.Second) }
	return []capability.AuditRow{
		{Kind: audit.KindRead, OperationName: "query_audit", Timestamp: at(5), Verified: operator},
		{Kind: audit.KindRead, OperationName: "query_jobs", Timestamp: at(6), Verified: operator},
		{Kind: audit.KindDispatch, ActionKind: "operation", OperationName: "service.restart",
			JobID: "job-9", NodeID: "node-a", Outcome: jobs.OutcomeSuccess, Timestamp: at(30), Verified: agent},
		{Kind: audit.KindRead, OperationName: "query_tasks", Timestamp: at(40), Verified: operator},
		{Kind: audit.KindRead, OperationName: "list_nodes", Timestamp: at(60), Verified: agent},
	}
}

func consoleCallsDeps() Deps {
	d := renderableDeps()
	d.Queries = &fakeQueries{rows: consoleCallsRows()}
	return d
}

// railNames returns the Account names the rail lists, read from its links.
func railNames(t *testing.T, body string) []string {
	t.Helper()
	var names []string
	rest := body
	for {
		i := strings.Index(rest, `<a class="arow`)
		if i < 0 {
			return names
		}
		rest = rest[i:]
		j := strings.Index(rest, `href="`)
		k := strings.Index(rest[j+len(`href="`):], `"`)
		href := strings.ReplaceAll(rest[j+len(`href="`):j+len(`href="`)+k], "&amp;", "&")
		u, err := url.Parse(href)
		if err != nil {
			t.Fatalf("rail href %q: %v", href, err)
		}
		names = append(names, u.Query().Get("account"))
		rest = rest[j:]
	}
}

func TestAgents_ConsoleSessionCallsAreLeftOutByDefault(t *testing.T) {
	body := contentOf(get(t, newTestHandler(consoleCallsDeps(), accounts.RoleAdmin), "/console/agents").Body.String())

	for _, tool := range []string{"query_audit", "query_jobs", "query_tasks"} {
		if strings.Contains(body, tool) {
			t.Errorf("a call made from a Console session (%s) is listed by default", tool)
		}
	}
	for _, tool := range []string{"service.restart", "list_nodes"} {
		if !strings.Contains(body, tool) {
			t.Errorf("the AI-agent's call %s is missing", tool)
		}
	}
	names := railNames(t, body)
	if len(names) != 1 || names[0] != "gleipnir-prod" {
		t.Errorf("rail lists %v, want only the Account that called from outside this Console", names)
	}
	if !strings.Contains(body, "<b>2</b> calls") {
		t.Errorf("the rail does not count the agent's 2 calls:\n%s", body)
	}
}

func TestAgents_ConsoleSessionCallsAreListedWithTheParameter(t *testing.T) {
	shown := contentOf(get(t, newTestHandler(consoleCallsDeps(), accounts.RoleAdmin), "/console/agents?console=show").Body.String())

	for _, tool := range []string{"query_audit", "query_jobs", "query_tasks", "service.restart", "list_nodes"} {
		if !strings.Contains(shown, tool) {
			t.Errorf("with ?console=show, %s is not listed", tool)
		}
	}
	names := railNames(t, shown)
	if len(names) != 2 {
		t.Errorf("with ?console=show the rail lists %v, want both Accounts", names)
	}

	// "Exactly as it does today": the feed and the rail equal what the screen
	// renders over the same page with no Console-session calls to leave out.
	stripped := consoleCallsRows()
	for i := range stripped {
		stripped[i].Verified.Method = ""
	}
	d := renderableDeps()
	d.Queries = &fakeQueries{rows: stripped}
	plain := contentOf(get(t, newTestHandler(d, accounts.RoleAdmin), "/console/agents?console=show").Body.String())
	if feedOf(shown) != feedOf(plain) {
		t.Error("with ?console=show the feed differs from the same page with nothing to leave out")
	}
}

// feedOf is the rendered rail and feed, without the one sentence about
// Console calls whose count legitimately differs.
func feedOf(content string) string {
	i := strings.Index(content, `<div class="agentcols">`)
	if i < 0 {
		return content
	}
	s := content[i:]
	if a := strings.Index(s, `<p class="scoped consolecalls">`); a >= 0 {
		if b := strings.Index(s[a:], "</p>"); b >= 0 {
			s = s[:a] + s[a+b+len("</p>"):]
		}
	}
	return s
}

func TestAgents_TheExclusionIsStatedBesideTheFeedWithALink(t *testing.T) {
	h := newTestHandler(consoleCallsDeps(), accounts.RoleAdmin)

	body := contentOf(get(t, h, "/console/agents").Body.String())
	if !strings.Contains(body, "Reads made from this Console are left out: 3 of the 5 calls on this page.") {
		t.Errorf("the default does not say how many Console calls it left out:\n%s", body)
	}
	if !strings.Contains(body, `href="/console/agents?console=show">Show them</a>`) {
		t.Error("the sentence does not link to the view that shows them")
	}
	mustBeSituational(t, body, "Reads made from this Console are left out")

	shown := contentOf(get(t, h, "/console/agents?console=show").Body.String())
	if !strings.Contains(shown, "Reads made from this Console are shown.") ||
		!strings.Contains(shown, `href="/console/agents">Leave them out</a>`) {
		t.Errorf("with ?console=show the sentence does not offer the way back:\n%s", shown)
	}

	// Still stated on a page where nothing was left out: never silent.
	d := renderableDeps()
	d.Queries = &fakeQueries{rows: consoleCallsRows()[2:3]}
	none := contentOf(get(t, newTestHandler(d, accounts.RoleAdmin), "/console/agents").Body.String())
	if !strings.Contains(none, "Reads made from this Console are left out. <a") {
		t.Errorf("with nothing to leave out the rule is not stated:\n%s", none)
	}
}

func TestAgents_AccountFilterComposesWithTheConsoleDefault(t *testing.T) {
	h := newTestHandler(consoleCallsDeps(), accounts.RoleAdmin)

	own := contentOf(get(t, h, "/console/agents?account=mike").Body.String())
	if strings.Contains(own, "query_audit") {
		t.Error("?account= alone listed that Account's Console-session calls")
	}
	if !strings.Contains(own, `href="/console/agents?account=mike&amp;console=show">Show them</a>`) {
		t.Errorf("the Show link drops the Account filter:\n%s", own)
	}

	both := contentOf(get(t, h, "/console/agents?account=mike&console=show").Body.String())
	if !strings.Contains(both, "query_audit") || strings.Contains(both, "service.restart") {
		t.Error("?account=mike&console=show does not list exactly mike's calls")
	}
	if !strings.Contains(both, `href="/console/agents?console=show">Show every Account</a>`) {
		t.Errorf("Show every Account drops ?console=show:\n%s", both)
	}
	if !strings.Contains(both, `href="/console/agents?account=mike">Leave them out</a>`) {
		t.Errorf("Leave them out drops the Account filter:\n%s", both)
	}
	if !strings.Contains(both, `href="/console/agents?account=gleipnir-prod&amp;console=show"`) {
		t.Errorf("a rail link drops ?console=show:\n%s", both)
	}
}

// TestAgents_TheExclusionReadsTheRecordNotTheAccount: the method on the record
// decides, whatever the Account's kind or name — a machine Account's call
// made from a Console session is left out, and a human Account's call made
// with an API Token is listed. The method itself is never displayed.
func TestAgents_TheExclusionReadsTheRecordNotTheAccount(t *testing.T) {
	d := renderableDeps()
	d.Accounts = sweepAccounts()
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
	body := get(t, newTestHandler(d, accounts.RoleAdmin), "/console/agents").Body.String()

	if strings.Contains(body, "describe_node") {
		t.Error("a machine Account's Console-session call is listed")
	}
	if !strings.Contains(body, "list_operations") || !strings.Contains(body, "get_job") {
		t.Error("a human Account's API Token or OAuth call is left out")
	}
	for _, m := range []string{"console_session", "api_token", "oauth"} {
		if strings.Contains(body, m) {
			t.Errorf("the authentication method %q is displayed", m)
		}
	}
}

func TestAgents_ARailEmptiedByTheDefaultSaysWhy(t *testing.T) {
	d := renderableDeps()
	d.Queries = &fakeQueries{rows: consoleCallsRows()[:2]}
	body := contentOf(get(t, newTestHandler(d, accounts.RoleAdmin), "/console/agents").Body.String())

	if strings.Contains(body, "No Account has called a control surface yet.") {
		t.Error("the rail claims nobody called, when the operator did from this Console")
	}
	if !strings.Contains(body, "Every call on this page is a read made from this Console, and those are left out.") {
		t.Errorf("the rail does not say why it is empty:\n%s", body)
	}
	if !strings.Contains(body, "No calls on this page other than reads made from this Console.") {
		t.Errorf("the feed does not say why it is empty:\n%s", body)
	}
}

// TestAgents_TheDefaultAddsNoRead: the exclusion is presentation over the
// page the lane already returned — the same single query, the same filter,
// the same page size, with or without it.
func TestAgents_TheDefaultAddsNoRead(t *testing.T) {
	for _, path := range []string{"/console/agents", "/console/agents?console=show"} {
		q := &fakeQueries{rows: consoleCallsRows()}
		d := renderableDeps()
		d.Queries = q
		get(t, newTestHandler(d, accounts.RoleAdmin), path)
		if q.auditCalls != 1 {
			t.Errorf("%s made %d audit reads, want 1", path, q.auditCalls)
		}
		if len(q.auditFilters) != 1 || len(q.auditFilters[0].Kinds) != len(agentCallKinds) {
			t.Errorf("%s changed the lane filter: %+v", path, q.auditFilters)
		}
		if q.auditLimits[0] != agentsPageSize {
			t.Errorf("%s asked for %d rows, want %d", path, q.auditLimits[0], agentsPageSize)
		}
	}
}

// consoleActor is a Console-session identity: what a session cookie
// establishes, whoever or whatever is driving the browser.
var consoleActor = capability.VerifiedIdentity{
	AccountID: "acct-mike", AccountName: "mike", Role: "admin",
	Method: string(capability.AuthMethodConsoleSession),
}

// TestAgents_OnlyConsoleSessionReadsAreLeftOut: a Console session proves a
// cookie, not a person, so a mutate, an approval decision, a cancel, a
// refusal and a Preflight made from one stay listed by default. Only a read
// is left out.
func TestAgents_OnlyConsoleSessionReadsAreLeftOut(t *testing.T) {
	d := renderableDeps()
	d.Queries = &fakeQueries{rows: []capability.AuditRow{
		{Kind: audit.KindRead, OperationName: "query_audit", Timestamp: testNow, Verified: consoleActor},
		{Kind: audit.KindDispatch, ActionKind: "operation", OperationName: "service.restart", JobID: "job-m",
			NodeID: "node-a", Outcome: jobs.OutcomeSuccess, Timestamp: testNow, Verified: consoleActor},
		{Kind: audit.KindApprovalDecided, ApprovalID: "ap-9", Reason: "approved over out-of-band",
			Timestamp: testNow, Verified: consoleActor},
		{Kind: audit.KindJobCancel, JobID: "job-c", Timestamp: testNow, Verified: consoleActor},
		{Kind: audit.KindRefusal, ActionKind: "raw_exec", Reason: "role floor", Timestamp: testNow, Verified: consoleActor},
		{Kind: audit.KindPlan, ActionKind: "operation", OperationName: "pkg.install", Timestamp: testNow, Verified: consoleActor},
	}}
	body := contentOf(get(t, newTestHandler(d, accounts.RoleAdmin), "/console/agents").Body.String())

	if strings.Contains(body, "query_audit") {
		t.Error("a Console-session read is listed by default")
	}
	for _, want := range []string{"service.restart", "approval decision", "cancel_job", "refused", "pkg.install"} {
		if !strings.Contains(body, want) {
			t.Errorf("a Console-session %s is not listed by default", want)
		}
	}
	if !strings.Contains(body, "Reads made from this Console are left out: 1 of the 6 calls on this page.") {
		t.Errorf("the sentence does not count the one read:\n%s", body)
	}
	if !strings.Contains(body, "<b>5</b> calls") {
		t.Errorf("the rail does not count the five Console-session non-reads:\n%s", body)
	}
}

// TestConsoleRead_ARowThatCannotTellIsNotARead: both halves come from the
// row, and a row that does not say it was a read stays listed.
func TestConsoleRead_ARowThatCannotTellIsNotARead(t *testing.T) {
	for name, row := range map[string]capability.AuditRow{
		"no kind":             {Verified: consoleActor},
		"unknown kind":        {Kind: "something_new", Verified: consoleActor},
		"read kind, raw argv": {Kind: audit.KindRead, RawExecArgv: []string{"/bin/true"}, Verified: consoleActor},
		"read, not console": {Kind: audit.KindRead, OperationName: "list_nodes",
			Verified: capability.VerifiedIdentity{AccountName: "x", Method: string(capability.AuthMethodAPIToken)}},
		"read, no method": {Kind: audit.KindRead, OperationName: "list_nodes"},
	} {
		if consoleRead(row) {
			t.Errorf("%s: treated as a Console-session read", name)
		}
	}
	if !consoleRead(capability.AuditRow{Kind: audit.KindRead, OperationName: "list_nodes", Verified: consoleActor}) {
		t.Error("a Console-session read is not recognised")
	}
}

// TestAgents_AFilteredAccountWhoseCallsWereAllLeftOutSaysSo: under
// ?account=, the sentence counts that Account's calls, and an empty feed
// does not claim the Account has none.
func TestAgents_AFilteredAccountWhoseCallsWereAllLeftOutSaysSo(t *testing.T) {
	h := newTestHandler(consoleCallsDeps(), accounts.RoleAdmin)
	body := contentOf(get(t, h, "/console/agents?account=mike").Body.String())

	if !strings.Contains(body, "Reads made from this Console are left out: 3 of the 3 calls by <b>mike</b> on this page.") {
		t.Errorf("the sentence does not give the filtered Account's count:\n%s", body)
	}
	if strings.Contains(body, "No calls on this page.") {
		t.Error("the feed says the filtered Account has no calls on this page, and it has three")
	}
	if !strings.Contains(body, "This Account has no calls on this page other than reads made from this Console.") {
		t.Errorf("the empty feed does not say why:\n%s", body)
	}

	agent := contentOf(get(t, h, "/console/agents?account=gleipnir-prod").Body.String())
	if !strings.Contains(agent, "Reads made from this Console are left out. <a") {
		t.Errorf("an Account with nothing left out is given a count:\n%s", agent)
	}
}

// TestAgents_AnAllExcludedPageReadsCoherently: every call on the page is a
// Console-session read and there are older calls. From top to bottom: the
// rail and the sentence say what was left out, the feed says why it is
// empty, and the page note says what the page holds rather than what it
// shows.
func TestAgents_AnAllExcludedPageReadsCoherently(t *testing.T) {
	var rows []capability.AuditRow
	for i := 0; i < 3; i++ {
		rows = append(rows, capability.AuditRow{Kind: audit.KindRead, OperationName: "query_audit",
			Timestamp: testNow.Add(-time.Duration(i) * time.Second), Verified: consoleActor})
	}
	d := renderableDeps()
	d.Queries = &fakeQueries{rows: rows, auditNext: "c2"}
	body := contentOf(get(t, newTestHandler(d, accounts.RoleAdmin), "/console/agents").Body.String())

	order := []string{
		"Every call on this page is a read made from this Console, and those are left out.",
		"Reads made from this Console are left out: 3 of the 3 calls on this page.",
		"No calls on this page other than reads made from this Console.",
		"This page holds the most recent 200 calls. There are older calls.",
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
	if strings.Contains(body, "Showing the most recent") {
		t.Error("the page note claims to show calls it left out")
	}
}

// countingAccounts counts every call into the Account registry seam.
type countingAccounts struct{ calls int }

func (c *countingAccounts) Accounts(context.Context, capability.Principal) ([]accounts.Account, error) {
	c.calls++
	return nil, nil
}

func (c *countingAccounts) Account(context.Context, capability.Principal, string) (accounts.Account, error) {
	c.calls++
	return accounts.Account{}, nil
}

func (c *countingAccounts) APITokens(context.Context, capability.Principal, string) ([]accounts.APIToken, error) {
	c.calls++
	return nil, nil
}

// TestAgents_NeverReadsTheAccountRegistry: the exclusion is read from the
// record as written (#540), in every view of the screen.
func TestAgents_NeverReadsTheAccountRegistry(t *testing.T) {
	for _, path := range []string{
		"/console/agents", "/console/agents?console=show",
		"/console/agents?account=mike", "/console/agents?account=mike&console=show",
	} {
		reg := &countingAccounts{}
		d := consoleCallsDeps()
		d.Accounts = reg
		if rec := get(t, newTestHandler(d, accounts.RoleAdmin), path); rec.Code != 200 {
			t.Fatalf("%s: status %d", path, rec.Code)
		}
		if reg.calls != 0 {
			t.Errorf("%s consulted the Account registry %d times", path, reg.calls)
		}
	}
}
