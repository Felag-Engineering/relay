package console

// agents_running_test.go is #617's acceptance criteria: the Agents stream's
// Running section, built ONLY from the Job row (through the same
// QueryJobs{State: Running} read Cancel already made, #595), so a Job that is
// still running shows up — and can be cancelled — long before the Job engine
// writes its first dispatch audit record.

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/accounts"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/audit"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/capability"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/consoleauth"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/jobs"
)

// runningJob is a running Job with one Task resolved of three — a fixture
// whose Total/Unresolved a test does not have to keep consistent by hand.
func runningJob(id, requester, accountID string) capability.JobSummary {
	return capability.JobSummary{
		JobID:              id,
		CreatedAt:          testNow,
		State:              jobs.JobStateRunning,
		ActionKind:         jobs.ActionOperation,
		OperationName:      "service.restart",
		RiskClass:          jobs.RiskClassMutate,
		Requester:          requester,
		RequesterAccountID: accountID,
		Total:              3,
		Unresolved:         2,
	}
}

// ---- AC1: the stream shows a running Job from its Job row, marked running ----

func TestAgents_ARunningJobWithNoDispatchRecordAppearsFromItsJobRow(t *testing.T) {
	q := &fakeQueries{jobs: []capability.JobSummary{runningJob("job-1", "gleipnir-prod", "acct-1")}}
	d := cancelDeps(q, &fakeCanceller{})
	body := get(t, newTestHandler(d, accounts.RoleAdmin), "/console/agents").Body.String()

	for _, want := range []string{
		`data-kind="running"`,
		"gleipnir-prod",
		`data-state="running"`,
		"run_operation · service.restart",
		`data-risk="mutate"`,
		"1 of 3 Tasks resolved",
		`href="/console/jobs/job-1"`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("the running card does not contain %q:\n%s", want, body)
		}
	}
}

func TestAgents_AResolvedJobIsNeitherCardedNorMarkedRunning(t *testing.T) {
	rows := []capability.AuditRow{dispatchRow("job-1", "node-a")}
	// A "resolved" fixture must set State explicitly: JobStateRunning is
	// iota 0, so a JobSummary with no State set would be running by
	// accident rather than by the fixture's own word.
	sum := runningJob("job-1", "gleipnir-prod", "acct-1")
	sum.State = jobs.JobStateComplete
	q := &fakeQueries{rows: rows, jobs: []capability.JobSummary{sum}}
	d := cancelDeps(q, &fakeCanceller{})
	body := get(t, newTestHandler(d, accounts.RoleAdmin), "/console/agents").Body.String()

	if strings.Contains(body, `data-kind="running"`) {
		t.Error("a resolved Job rendered a running card")
	}
	if strings.Contains(body, "job running") {
		t.Error("a resolved Job's dispatch row carries the running marker")
	}
	if strings.Contains(body, `class="jobcancel"`) {
		t.Error("a resolved Job's dispatch row offers Cancel")
	}
}

func TestAgents_ADispatchRowOfARunningJobIsMarkedRunningAndNotCardedTwice(t *testing.T) {
	rows := []capability.AuditRow{
		dispatchRow("job-1", "node-a"),
		dispatchRow("job-1", "node-b"),
	}
	q := &fakeQueries{rows: rows, jobs: []capability.JobSummary{runningJob("job-1", "gleipnir-prod", "acct-1")}}
	d := cancelDeps(q, &fakeCanceller{})
	body := get(t, newTestHandler(d, accounts.RoleAdmin), "/console/agents").Body.String()

	if strings.Contains(body, `data-kind="running"`) {
		t.Error("job-1 has a dispatch row on the page and must not also get a running card")
	}
	blocks := agentRowBlocks(body)
	if len(blocks) != 2 {
		t.Fatalf("got %d stream rows, want 2", len(blocks))
	}
	for _, block := range blocks {
		if !strings.Contains(block, "job running") {
			t.Error("a job-1 dispatch row does not carry the running marker")
		}
	}
	if n := strings.Count(body, `class="jobcancel"`); n != 1 {
		t.Errorf("cancel forms rendered = %d, want exactly 1", n)
	}
}

func TestAgents_RunningCardWithNoRecordedRequesterSaysUnattributed(t *testing.T) {
	q := &fakeQueries{jobs: []capability.JobSummary{runningJob("job-1", "", "")}}
	d := cancelDeps(q, &fakeCanceller{})
	body := get(t, newTestHandler(d, accounts.RoleAdmin), "/console/agents").Body.String()

	if !strings.Contains(body, `data-trust="asserted" title="The caller claimed this. Nothing checked it.">unattributed<`) {
		t.Errorf("a running Job with no recorded requester does not render as unattributed and unverified:\n%s", body)
	}
}

func TestAgents_RunningCardsFollowTheAccountScope(t *testing.T) {
	q := &fakeQueries{jobs: []capability.JobSummary{
		runningJob("job-1", "gleipnir-prod", "acct-1"),
		runningJob("job-2", "", ""),
	}}
	d := cancelDeps(q, &fakeCanceller{})

	other := get(t, newTestHandler(d, accounts.RoleAdmin), "/console/agents?account=other").Body.String()
	if strings.Contains(other, "job-1") {
		t.Error("?account=other includes the gleipnir-prod running card")
	}

	scoped := get(t, newTestHandler(d, accounts.RoleAdmin), "/console/agents?account=gleipnir-prod").Body.String()
	if !strings.Contains(scoped, "job-1") {
		t.Error("?account=gleipnir-prod excludes its own running card")
	}
	if strings.Contains(scoped, "job-2") {
		t.Error("?account=gleipnir-prod includes the unattributed running card")
	}

	unattributed := get(t, newTestHandler(d, accounts.RoleAdmin), "/console/agents?account=unattributed").Body.String()
	if !strings.Contains(unattributed, "job-2") {
		t.Error("?account=unattributed excludes a running Job with no recorded requester")
	}
	if strings.Contains(unattributed, "job-1") {
		t.Error("?account=unattributed includes the gleipnir-prod running card")
	}
}

func TestAgents_RunningCardsAreNotCountedOnTheRail(t *testing.T) {
	q := &fakeQueries{jobs: []capability.JobSummary{runningJob("job-1", "gleipnir-prod", "acct-1")}}
	d := cancelDeps(q, &fakeCanceller{})
	body := get(t, newTestHandler(d, accounts.RoleAdmin), "/console/agents").Body.String()

	if strings.Contains(body, `data-kind="call"`) {
		t.Error("a page with no audit rows rendered a call row")
	}
	if strings.Contains(body, "No Account has called a control surface yet.") {
		t.Error("the empty-rail sentence was not replaced although a running card fills the page")
	}
	if !strings.Contains(body, "join the rail once their dispatch is recorded") {
		t.Error("the replacement rail sentence is missing")
	}
}

func TestAgents_EmptyRailSentenceIsUnchangedWithNoRunningJobs(t *testing.T) {
	d := cancelDeps(&fakeQueries{}, &fakeCanceller{})
	body := get(t, newTestHandler(d, accounts.RoleAdmin), "/console/agents").Body.String()

	if !strings.Contains(body, "No Account has called a control surface yet.") {
		t.Error("the empty-rail sentence changed although there is no running Job on the page at all")
	}
}

func TestAgents_OlderPageShowsNoRunningSection(t *testing.T) {
	rows := []capability.AuditRow{
		{Kind: audit.KindRead, Principal: "agent:op", Timestamp: testNow},
	}
	q := &fakeQueries{rows: rows}
	d := cancelDeps(q, &fakeCanceller{})
	body := get(t, newTestHandler(d, accounts.RoleAdmin), "/console/agents?cursor=0").Body.String()

	if strings.Contains(body, `class="agentrunning"`) {
		t.Error("an older page with no dispatch row rendered a Running section")
	}
	if q.jobCalls != 0 {
		t.Errorf("QueryJobs calls = %d, want 0", q.jobCalls)
	}
}

func TestAgents_RunningCardMeetsAccessibilityTagRules(t *testing.T) {
	q := &fakeQueries{jobs: []capability.JobSummary{runningJob("job-1", "gleipnir-prod", "acct-1")}}
	d := cancelDeps(q, &fakeCanceller{})
	body := get(t, newTestHandler(d, accounts.RoleAdmin), "/console/agents").Body.String()

	if !strings.Contains(body, `data-kind="running"`) {
		t.Fatal("no running card rendered — this test proves nothing without one")
	}
	_, times, _ := checkA11yTags(t, "agents (running card)", body)
	if times == 0 {
		t.Fatal("swept zero <time> tags off a page holding a running card — the card's own <time> " +
			"element was not exercised by this check")
	}
}

func TestBuildRunning_DedupsScopesAndKeepsOrder(t *testing.T) {
	newer := runningJob("job-1", "gleipnir-prod", "acct-1")
	newer.CreatedAt = testNow
	older := runningJob("job-2", "gleipnir-prod", "acct-1")
	older.CreatedAt = testNow.Add(-time.Minute)
	unattributed := runningJob("job-3", "", "")

	js := []capability.JobSummary{newer, older, unattributed}
	onPage := map[string]bool{"job-2": true} // already shown by a dispatch row on the page

	out := buildRunning(js, "", onPage, true)
	if len(out) != 2 {
		t.Fatalf("got %d running cards, want 2 — job-2 is already on the page", len(out))
	}
	if out[0].JobID != "job-1" || out[1].JobID != "job-3" {
		t.Errorf("buildRunning did not keep the lane's newest-first order: got %q, %q", out[0].JobID, out[1].JobID)
	}
	if out[1].Principal != "unattributed" {
		t.Errorf("an unrequested Job's card principal = %q, want %q", out[1].Principal, "unattributed")
	}

	scoped := buildRunning(js, "unattributed", onPage, true)
	if len(scoped) != 1 || scoped[0].JobID != "job-3" {
		t.Fatalf("?account=unattributed did not scope to the unattributed running Job alone: got %v", scoped)
	}
}

func TestRunningToolName_NamesRawExecOperationAndBareDispatch(t *testing.T) {
	rawExec := runningJob("job-1", "gleipnir-prod", "acct-1")
	rawExec.ActionKind = jobs.ActionRawExec
	rawExec.OperationName = ""
	if got := runningToolName(rawExec); got != rawExecActionKind {
		t.Errorf("runningToolName(Raw Exec) = %q, want %q", got, rawExecActionKind)
	}

	// An Operation actually NAMED "raw_exec" (ActionKind Operation) must not
	// be mistaken for the Raw Exec tier itself.
	namedRawExec := runningJob("job-2", "gleipnir-prod", "acct-1")
	namedRawExec.ActionKind = jobs.ActionOperation
	namedRawExec.OperationName = "raw_exec"
	if got := runningToolName(namedRawExec); got != "run_operation · raw_exec" {
		t.Errorf("runningToolName(Operation named %q) = %q, want %q", "raw_exec", got, "run_operation · raw_exec")
	}

	bare := runningJob("job-3", "gleipnir-prod", "acct-1")
	bare.ActionKind = jobs.ActionUnspecified
	bare.OperationName = ""
	if got := runningToolName(bare); got != "dispatch" {
		t.Errorf("runningToolName(no Operation, no Raw Exec) = %q, want %q", got, "dispatch")
	}
}

// ---- AC2: Cancel on a running Job's row, gated exactly as Job detail's is ----

func TestAgents_RunningCardOffersCancelToAnOperator(t *testing.T) {
	q := &fakeQueries{jobs: []capability.JobSummary{runningJob("job-1", "gleipnir-prod", "acct-1")}}
	d := cancelDeps(q, &fakeCanceller{})
	body := get(t, newTestHandler(d, accounts.RoleOperator), "/console/agents").Body.String()

	if n := strings.Count(body, `class="jobcancel"`); n != 1 {
		t.Errorf("cancel forms rendered = %d, want exactly 1", n)
	}
	if !strings.Contains(body, cancelJobAction("job-1")) {
		t.Error("the rendered control's action does not target job-1")
	}
}

func TestAgents_ViewerSeesTheRunningJobButNoCancel(t *testing.T) {
	q := &fakeQueries{jobs: []capability.JobSummary{runningJob("job-1", "gleipnir-prod", "acct-1")}}
	d := cancelDeps(q, &fakeCanceller{})
	body := get(t, newTestHandler(d, accounts.RoleViewer), "/console/agents").Body.String()

	if !strings.Contains(body, `data-kind="running"`) {
		t.Error("a viewer's page does not show the running card")
	}
	if strings.Contains(body, `class="jobcancel"`) {
		t.Error("a viewer's page offers Cancel")
	}
}

func TestAgents_NoCancelWhenTheCancelRouteIsNotMounted(t *testing.T) {
	q := &fakeQueries{jobs: []capability.JobSummary{runningJob("job-1", "gleipnir-prod", "acct-1")}}
	d := renderableDeps()
	d.Queries = q
	// d.Cancel left nil: the route is not mounted at all.
	body := get(t, newTestHandler(d, accounts.RoleAdmin), "/console/agents").Body.String()

	if !strings.Contains(body, `data-kind="running"`) {
		t.Error("the running card did not render, although showing it does not depend on Cancel being mounted")
	}
	if strings.Contains(body, `class="jobcancel"`) {
		t.Error("Cancel rendered although the cancel route is not mounted — cancelOffered via routesFor is the only thing that may draw it")
	}
}

func TestAgents_ReadFailureNoteNamesCancelOnlyWhenOffered(t *testing.T) {
	q := &fakeQueries{jobsErr: errQueryFailed}
	d := cancelDeps(q, &fakeCanceller{})

	viewerBody := get(t, newTestHandler(d, accounts.RoleViewer), "/console/agents").Body.String()
	if !strings.Contains(viewerBody, "could not be read") {
		t.Error("a viewer's page does not say the running-Jobs read failed")
	}
	if strings.Contains(viewerBody, "Cancel is not offered") {
		t.Error("a viewer's page names Cancel, although a viewer is never offered it")
	}

	adminBody := get(t, newTestHandler(d, accounts.RoleAdmin), "/console/agents").Body.String()
	if !strings.Contains(adminBody, "could not be read") {
		t.Error("an admin's page does not say the running-Jobs read failed")
	}
	if !strings.Contains(adminBody, "Cancel is not offered") {
		t.Error("an admin's page does not say Cancel is not offered")
	}
}

// TestAgents_RunningCardCancelFormCarriesARealCSRFToken is a sibling of
// TestAgents_CancelFormCarriesARealCSRFToken (agents_cancel_test.go), with a
// running Job and NO audit rows — the control this proves is on a card, not
// a dispatch row.
func TestAgents_RunningCardCancelFormCarriesARealCSRFToken(t *testing.T) {
	q := &fakeQueries{jobs: []capability.JobSummary{runningJob("job-1", "gleipnir-prod", "acct-1")}}
	canceller := &fakeCanceller{}
	f := newLoginFixtureWith(t, func(d *Deps) {
		d.Queries = q
		d.Cancel = canceller
	})

	rec, cookies := f.signIn(t, "mike", consolePassword)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("sign-in status = %d, want %d", rec.Code, http.StatusSeeOther)
	}
	session := cookieNamed(cookies, consoleauth.SessionCookieName)
	if session == nil {
		t.Fatal("no session cookie was set")
	}

	agentsRec := f.do(t, httptest.NewRequest(http.MethodGet, "/console/agents", nil), session)
	if agentsRec.Code != http.StatusOK {
		t.Fatalf("GET /console/agents = %d, want 200; body %s", agentsRec.Code, agentsRec.Body.String())
	}
	body := agentsRec.Body.String()
	if !strings.Contains(body, `class="jobcancel"`) {
		t.Fatal("the Agents page rendered no Cancel control for its one running Job")
	}
	if renderedCSRFToken(body) == "" {
		t.Error("the running card's Cancel form carries no CSRF token")
	}
}

// ---- AC3: no second event source; the read stays on the capability lane ----

func TestAgents_RunningJobsComeFromTheOneLaneRead(t *testing.T) {
	q := &fakeQueries{jobs: []capability.JobSummary{runningJob("job-1", "gleipnir-prod", "acct-1")}}
	d := cancelDeps(q, &fakeCanceller{})
	get(t, newTestHandler(d, accounts.RoleAdmin), "/console/agents")

	if q.jobCalls != 1 {
		t.Fatalf("QueryJobs calls = %d, want exactly 1", q.jobCalls)
	}
	if q.auditCalls != 1 {
		t.Fatalf("QueryAudit calls = %d, want exactly 1", q.auditCalls)
	}
	f := q.jobFilters[0]
	if f.State == nil || *f.State != jobs.JobStateRunning {
		t.Errorf("QueryJobs filter State = %v, want a pointer to Running", f.State)
	}
	if f.JobID != "" {
		t.Errorf("QueryJobs filter JobID = %q, want empty", f.JobID)
	}
	if got := q.jobLimits[0]; got != capability.MaxPageSize {
		t.Errorf("QueryJobs Limit = %d, want %d", got, capability.MaxPageSize)
	}
	if len(q.subscriptionKinds) != 0 {
		t.Errorf("subscriptionKinds = %v, want none — the running Jobs read must never touch the event-subscription seam", q.subscriptionKinds)
	}
}

func TestAgents_UnauditableRunningJobsReadRefusesThePage(t *testing.T) {
	unauditable := errors.Join(capability.ErrReadUnaudited, errQueryFailed)
	q := &fakeQueries{jobsErr: unauditable}
	d := cancelDeps(q, &fakeCanceller{})
	rec := get(t, newTestHandler(d, accounts.RoleViewer), "/console/agents")

	if rec.Code == http.StatusOK {
		t.Fatal("GET /console/agents = 200 with an unauditable running-Jobs read. A read this Relay " +
			"cannot record must be REFUSED, not served unrecorded (ADR-0025 decision 4).")
	}
	body := rec.Body.String()
	for _, want := range []string{"audit trail", "refused"} {
		if !strings.Contains(body, want) {
			t.Errorf("the refusal page does not say %q:\n%s", want, body)
		}
	}
}
