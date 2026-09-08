package console

// agents_paging_test.go is #542's acceptance criteria: agent history moved
// off AuditReader.List onto the capability layer's audited read lane
// (QueryAudit), which reshapes the screen around the lane's paging rather
// than a 200-record window.
//
// It has its own file rather than a corner of screens_test.go for the reason
// the plan states: screens_test.go is huge and is where a three-way merge
// has already silently fused two test functions that shared a loop body.
// Converting its existing Agents fixtures is risk enough without landing new
// tests in the same file.

import (
	"net/url"
	"reflect"
	"strings"
	"testing"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/accounts"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/audit"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/capability"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/jobs"
)

// TestAgents_ReadsTheTrailThroughTheAuditedLane is the issue's own acceptance
// line, and the mutation it names explicitly: reverting to d.Audit.List must
// turn this red, along with TestConsole_AuditedRoutesRecordTheirReadThroughTheRealLane
// and TestConsole_AnUnauditableReadRefusesTheScreen once GET /console/agents
// carries a tool in consoleReadAudit.
func TestAgents_ReadsTheTrailThroughTheAuditedLane(t *testing.T) {
	q := &fakeQueries{}
	d := renderableDeps()
	d.Queries = q

	get(t, newTestHandler(d, accounts.RoleAdmin), "/console/agents")

	if q.auditCalls != 1 {
		t.Fatalf("QueryAudit was called %d times, want exactly 1", q.auditCalls)
	}
	if !reflect.DeepEqual(q.auditFilters[0].Kinds, agentCallKinds) {
		t.Errorf("QueryAudit filter Kinds = %v, want %v", q.auditFilters[0].Kinds, agentCallKinds)
	}
}

// TestAgents_TheLaneFilterNamesEveryAgentCallKind pins agentCallKinds as
// DERIVED from audit.Kinds() through isAgentCallKind, never hand-listed —
// the same shape buildKindsByFamily (activity.go) uses. A hand-list can go
// stale the moment a new Kind is classified by isAgentCallKind and nobody
// remembers to add it to a second list.
func TestAgents_TheLaneFilterNamesEveryAgentCallKind(t *testing.T) {
	var want []string
	for _, k := range audit.Kinds() {
		if isAgentCallKind(k) {
			want = append(want, k)
		}
	}
	if !reflect.DeepEqual(agentCallKinds, want) {
		t.Fatalf("agentCallKinds = %v, want the kinds isAgentCallKind admits, %v", agentCallKinds, want)
	}
	for _, k := range agentCallKinds {
		if k == audit.KindApprovalExpired {
			t.Error("agentCallKinds includes approval_expired — an expiry is the clock, not a caller")
		}
	}
}

// TestAgents_ControlPlaneEventsAreNotAgentCalls proves the Kinds filter
// actually reaches the lane: a login and a Freeze engagement in the fake's
// rows must render nowhere on this screen once the real filter is applied.
//
// This is the test that makes "do not re-filter by kind in Go" (buildAgents,
// agents.go) load-bearing: if the Kinds filter is ever dropped from the
// query, buildAgents has nothing left to catch these two rows with, and this
// test is what notices.
func TestAgents_ControlPlaneEventsAreNotAgentCalls(t *testing.T) {
	d := renderableDeps()
	d.Queries = &fakeQueries{rows: []capability.AuditRow{
		{Kind: audit.KindLoginSucceeded, Principal: "alice:operator", Timestamp: testNow},
		{Kind: audit.KindFreezeEngage, Principal: "alice:operator", Timestamp: testNow},
	}}

	body := get(t, newTestHandler(d, accounts.RoleAdmin), "/console/agents").Body.String()

	if strings.Contains(body, audit.KindLoginSucceeded) || strings.Contains(body, audit.KindFreezeEngage) {
		t.Errorf("a control-plane event rendered on the trust surface:\n%s", body)
	}
	if !strings.Contains(body, "No calls on this page.") {
		t.Error("the screen does not say the page is empty, although both rows should have been filtered out")
	}
}

// TestAgents_TheStreamAsksForOneBoundedPage is D1: ONE QueryAudit call, at
// agentsPageSize, never a second fetch and never an unbounded one (Limit: 0
// silently becomes capability.DefaultPageSize, which is not this screen's
// stated page size).
func TestAgents_TheStreamAsksForOneBoundedPage(t *testing.T) {
	q := &fakeQueries{}
	d := renderableDeps()
	d.Queries = q

	get(t, newTestHandler(d, accounts.RoleAdmin), "/console/agents")

	if q.auditCalls != 1 {
		t.Fatalf("QueryAudit was called %d times, want exactly 1", q.auditCalls)
	}
	if got := q.auditPages[0].Limit; got != agentsPageSize {
		t.Errorf("the page request's Limit = %d, want %d", got, agentsPageSize)
	}
}

// TestAgents_OlderIsDrawnOnlyWhenThereIsAnOlderPage. An unconditional Older
// link loops forever the moment a page runs out — the bug lanePos was
// introduced for on Activity — so the link must track pg.Next, never its own
// assumption that there is always more.
func TestAgents_OlderIsDrawnOnlyWhenThereIsAnOlderPage(t *testing.T) {
	row := capability.AuditRow{Kind: audit.KindDispatch, ActionKind: "operation",
		OperationName: "service.restart", Principal: "agent:op", Outcome: jobs.OutcomeSuccess, Timestamp: testNow}

	withNext := renderableDeps()
	withNext.Queries = &fakeQueries{rows: []capability.AuditRow{row}, auditNext: "c2"}
	body := get(t, newTestHandler(withNext, accounts.RoleAdmin), "/console/agents").Body.String()
	if !strings.Contains(body, `href="/console/agents?cursor=c2">Older<`) {
		t.Errorf("no Older link carrying the next cursor:\n%s", body)
	}

	// The anchor TEXT, not merely the absence of a cursor param: an
	// unconditional Older link whose href happens to carry no cursor when
	// pg.Next is empty would still render the word "Older" and still loop —
	// clicking it reissues page one forever. Checking for "cursor=" alone
	// cannot see that link at all, since agentsHref("", "") drops every
	// parameter.
	withoutNext := renderableDeps()
	withoutNext.Queries = &fakeQueries{rows: []capability.AuditRow{row}}
	body = get(t, newTestHandler(withoutNext, accounts.RoleAdmin), "/console/agents").Body.String()
	if strings.Contains(body, ">Older<") {
		t.Errorf("an Older link rendered although the page reported no next page:\n%s", body)
	}
}

// TestAgents_AnOlderPageDoesNotClaimToBeTheMostRecent is the sentence
// today's copy could not say (1i): a page reached by following Older must
// say so, and must offer a way back to the newest page, rather than
// repeating the "most recent" claim that was only ever true of page one.
func TestAgents_AnOlderPageDoesNotClaimToBeTheMostRecent(t *testing.T) {
	d := renderableDeps()
	d.Queries = &fakeQueries{rows: []capability.AuditRow{
		{Kind: audit.KindDispatch, ActionKind: "operation", OperationName: "service.restart",
			Principal: "agent:op", Outcome: jobs.OutcomeSuccess, Timestamp: testNow},
	}}

	body := get(t, newTestHandler(d, accounts.RoleAdmin), "/console/agents?cursor=0").Body.String()

	// "NOT the most recent" is the sentence this page must say — checked for
	// the phrase page one uses to claim freshness, not the bare substring
	// "most recent", which that very sentence also contains.
	if strings.Contains(body, "Showing the most recent") {
		t.Errorf("a page reached by following Older still claims to hold the most recent calls:\n%s", body)
	}
	if !strings.Contains(body, "NOT the most recent") {
		t.Errorf("a scrolled page does not say it is not the most recent calls:\n%s", body)
	}
	if !strings.Contains(body, `href="/console/agents"`) {
		t.Errorf("a scrolled page offers no way back to the newest page:\n%s", body)
	}
}

// TestAgents_ScopingToAnAccountSurvivesPaging. The rail's own Href already
// had to survive an Account name with reserved characters (#467,
// TestAgents_RailLinkSurvivesAnAccountNameWithReservedCharacters); the Older
// link is a second place the same string is concatenated into a URL, and it
// has to survive the same way.
func TestAgents_ScopingToAnAccountSurvivesPaging(t *testing.T) {
	const account = "bob&co:operator"

	d := renderableDeps()
	d.Queries = &fakeQueries{
		rows: []capability.AuditRow{
			{Kind: audit.KindDispatch, ActionKind: "operation", OperationName: "service.restart",
				Principal: account, Outcome: jobs.OutcomeSuccess, Timestamp: testNow},
		},
		auditNext: "c2",
	}

	body := get(t, newTestHandler(d, accounts.RoleAdmin), "/console/agents?account="+url.QueryEscape(account)).Body.String()

	// A ROUND TRIP through the same decoder the handler uses
	// (r.URL.Query().Get, agents.go), not a comparison against agentsHref's
	// own output: asserting against the function under test would let a bug
	// in that very function agree with itself, exactly the trap
	// TestAgents_RailLinkSurvivesAnAccountNameWithReservedCharacters avoids
	// for the rail's Href.
	got := hrefContaining(t, body, "cursor=c2")
	href, err := url.Parse(unescapeHref(t, got))
	if err != nil {
		t.Fatalf("the Older href %q does not parse: %v", got, err)
	}
	if decoded := href.Query().Get("account"); decoded != account {
		t.Errorf("the Older link decodes account to %q, want %q — scoping to an Account must "+
			"survive paging", decoded, account)
	}
	if decoded := href.Query().Get("cursor"); decoded != "c2" {
		t.Errorf("the Older link decodes cursor to %q, want %q", decoded, "c2")
	}
}

// TestAgents_ADenyWithoutTheDaemonsRuleSaysWhereToFindIt is 1g: a denied
// mutate-class row with no Reason must not render denyText's whole-trail
// fallback ("did not report the deciding rule"), which is FALSE on this
// lane — the rule is on the Job's own Tasks, which this row already links to.
func TestAgents_ADenyWithoutTheDaemonsRuleSaysWhereToFindIt(t *testing.T) {
	d := renderableDeps()
	d.Queries = &fakeQueries{rows: []capability.AuditRow{
		{Kind: audit.KindDispatch, ActionKind: "operation", OperationName: "service.restart",
			Principal: "agent:op", NodeID: "node-a", JobID: "job-1",
			Outcome: jobs.OutcomeDeniedByPolicy, Timestamp: testNow},
	}}

	body := get(t, newTestHandler(d, accounts.RoleAdmin), "/console/agents").Body.String()

	if strings.Contains(body, "did not report the deciding rule") {
		t.Errorf("a denied mutate row with no Reason renders the whole-trail fallback, which is "+
			"false on this lane — the rule is on the Job's own Tasks:\n%s", body)
	}
	if !strings.Contains(body, "/console/jobs/job-1") {
		t.Errorf("the deny prose does not point at the Job holding the daemon's verdict:\n%s", body)
	}
}

// TestAgents_TheRailSaysWhatItCountedOver is 1j: the rail is computed from
// the fetched page, and the hint beside it must say so — the same rule
// TestActivity's page-boundary note follows for the trail lane.
func TestAgents_TheRailSaysWhatItCountedOver(t *testing.T) {
	body := get(t, newTestHandler(renderableDeps(), accounts.RoleAdmin), "/console/agents").Body.String()

	if !strings.Contains(body, "counted over the calls on this page") {
		t.Errorf("the rail's hint does not say it is counted over the fetched page:\n%s", body)
	}
}
