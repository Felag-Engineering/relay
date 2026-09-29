package console

// agents_console_calls_test.go proves spec 03's "Calls made from this
// Console": where the Agents screen lists calls and counts them on the rail,
// a call whose verified lane records a Console session is left out by
// default, read from the record as written; the exclusion is stated beside
// the feed with a link that shows them; ?account= composes with it.

import (
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
	if !strings.Contains(body, "Calls made from this Console are left out: 3 of the 5 calls on this page.") {
		t.Errorf("the default does not say how many Console calls it left out:\n%s", body)
	}
	if !strings.Contains(body, `href="/console/agents?console=show">Show them</a>`) {
		t.Error("the sentence does not link to the view that shows them")
	}
	mustBeSituational(t, body, "Calls made from this Console are left out")

	shown := contentOf(get(t, h, "/console/agents?console=show").Body.String())
	if !strings.Contains(shown, "Calls made from this Console are shown.") ||
		!strings.Contains(shown, `href="/console/agents">Leave them out</a>`) {
		t.Errorf("with ?console=show the sentence does not offer the way back:\n%s", shown)
	}

	// Still stated on a page where nothing was left out: never silent.
	d := renderableDeps()
	d.Queries = &fakeQueries{rows: consoleCallsRows()[2:3]}
	none := contentOf(get(t, newTestHandler(d, accounts.RoleAdmin), "/console/agents").Body.String())
	if !strings.Contains(none, "Calls made from this Console are left out. <a") {
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
	if !strings.Contains(body, "Every call on this page was made from this Console, and those are left out.") {
		t.Errorf("the rail does not say why it is empty:\n%s", body)
	}
	if !strings.Contains(body, "No calls on this page other than calls made from this Console.") {
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
