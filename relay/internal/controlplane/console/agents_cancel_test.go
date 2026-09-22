package console

// agents_cancel_test.go covers the Agents stream's half of the Cancel
// control (#595): one button per running Job, drawn on its newest dispatch
// row. The same single lane read also feeds the Agents stream's Running
// section (#617), so every role makes it on the newest page — a viewer is
// shown running Jobs but is never offered the control.

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/accounts"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/audit"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/capability"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/consoleauth"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/jobs"
)

// dispatchRow is one dispatch audit record for jobID, the shape the Job
// engine writes once per matched Node.
func dispatchRow(jobID, nodeID string) capability.AuditRow {
	return capability.AuditRow{
		Kind: audit.KindDispatch, ActionKind: "operation", OperationName: "service.restart",
		Principal: "agent:op", NodeID: nodeID, JobID: jobID, Outcome: jobs.OutcomeSuccess, Timestamp: testNow,
	}
}

func TestAgents_OneCancelControlPerRunningJob(t *testing.T) {
	rows := []capability.AuditRow{
		dispatchRow("job-1", "node-a"),
		dispatchRow("job-1", "node-b"),
		dispatchRow("job-1", "node-c"),
	}
	q := &fakeQueries{rows: rows, jobs: []capability.JobSummary{{JobID: "job-1", State: jobs.JobStateRunning}}}
	d := cancelDeps(q, &fakeCanceller{})
	body := get(t, newTestHandler(d, accounts.RoleAdmin), "/console/agents").Body.String()

	if n := strings.Count(body, `class="jobcancel"`); n != 1 {
		t.Errorf("cancel forms rendered = %d, want exactly 1 (one per Job, on its newest row)", n)
	}
	if !strings.Contains(body, cancelJobAction("job-1")) {
		t.Error("the rendered control's action does not target job-1")
	}
}

// TestAgents_NonDispatchRowsDrawNoControlButTheRunningCardDoes replaces
// TestAgents_NoControlForACompleteJobOrANonDispatchRow (#617): neither a read
// row nor a job_cancel row is a dispatch row, so onPage (assignRunning) never
// counts them — job-1 still running with neither on the page draws its
// Running-section card instead of nothing, and the ONE Cancel control on the
// page is on that card, not on either row. The "complete Job" half of the old
// name is now TestAgents_AResolvedJobIsNeitherCardedNorMarkedRunning
// (agents_running_test.go).
func TestAgents_NonDispatchRowsDrawNoControlButTheRunningCardDoes(t *testing.T) {
	rows := []capability.AuditRow{
		{Kind: audit.KindRead, Principal: "agent:op", JobID: "job-1", Timestamp: testNow},
		{Kind: audit.KindJobCancel, Principal: "agent:op", JobID: "job-1", Timestamp: testNow},
	}
	q := &fakeQueries{rows: rows, jobs: []capability.JobSummary{{JobID: "job-1", State: jobs.JobStateRunning}}}
	d := cancelDeps(q, &fakeCanceller{})
	body := get(t, newTestHandler(d, accounts.RoleAdmin), "/console/agents").Body.String()

	if n := strings.Count(body, `class="jobcancel"`); n != 1 {
		t.Fatalf("cancel forms rendered = %d, want exactly 1 — on the running card, never on the read or job_cancel row", n)
	}
	start := strings.Index(body, `class="agentrunning"`)
	if start < 0 {
		t.Fatal("no Running section rendered for job-1")
	}
	end := strings.Index(body[start:], "</section>")
	if end < 0 {
		t.Fatal("the Running section has no closing </section>")
	}
	section := body[start : start+end]
	if !strings.Contains(section, `class="jobcancel"`) {
		t.Error("the page's one Cancel control is not inside the running card — a read row or a job_cancel row drew it instead")
	}
	if !strings.Contains(body, `data-kind="running"`) {
		t.Error("no running card rendered — onPage must count dispatch rows only, and neither fixture row is one")
	}
	for _, block := range agentRowBlocks(body) {
		if strings.Contains(block, "job running") {
			t.Error("a stream row carries the \"job running\" marker, but neither the read row nor the job_cancel row is a dispatch row")
		}
	}
}

func TestAgents_RunningCheckIsOneStateFilteredRead(t *testing.T) {
	rows := []capability.AuditRow{
		dispatchRow("job-1", "node-a"),
		dispatchRow("job-2", "node-b"),
		dispatchRow("job-3", "node-c"),
	}
	q := &fakeQueries{rows: rows, jobs: []capability.JobSummary{
		{JobID: "job-1", State: jobs.JobStateRunning},
		{JobID: "job-2", State: jobs.JobStateRunning},
		{JobID: "job-3", State: jobs.JobStateComplete},
	}}
	d := cancelDeps(q, &fakeCanceller{})
	get(t, newTestHandler(d, accounts.RoleAdmin), "/console/agents")

	if q.jobCalls != 1 {
		t.Fatalf("QueryJobs calls = %d, want exactly 1", q.jobCalls)
	}
	f := q.jobFilters[0]
	if f.State == nil || *f.State != jobs.JobStateRunning {
		t.Errorf("QueryJobs filter State = %v, want a pointer to Running", f.State)
	}
	if f.JobID != "" {
		t.Errorf("QueryJobs filter JobID = %q, want empty — this is the fleet-wide running set, not a per-Job probe", f.JobID)
	}
	if got := q.jobLimits[0]; got != capability.MaxPageSize {
		t.Errorf("QueryJobs Limit = %d, want %d", got, capability.MaxPageSize)
	}
}

// TestAgents_OlderPageWithoutADispatchRowMakesNoRunningJobsRead renames
// TestAgents_NoRunningJobsReadWithoutADispatchRow (#617): on the NEWEST page
// the running-Jobs read is now made unconditionally (AC1), so proving "a page
// with nothing to explain makes no read" needs an OLDER page — built with a
// cursor, as agents_paging_test.go's own scrolled tests are.
func TestAgents_OlderPageWithoutADispatchRowMakesNoRunningJobsRead(t *testing.T) {
	rows := []capability.AuditRow{
		{Kind: audit.KindRead, Principal: "agent:op", Timestamp: testNow},
	}
	q := &fakeQueries{rows: rows}
	d := cancelDeps(q, &fakeCanceller{})
	get(t, newTestHandler(d, accounts.RoleAdmin), "/console/agents?cursor=0")

	if q.jobCalls != 0 {
		t.Errorf("QueryJobs calls = %d, want 0 — an older page with no dispatch row has nothing for the running-Jobs read to explain", q.jobCalls)
	}
}

// TestAgents_ViewerPaysOneRunningJobsRead renames
// TestAgents_ViewerMakesNoRunningJobsRead (#617): a viewer now makes the same
// running-Jobs read every role makes on the newest page (AC1's "the stream
// shows the Job to whoever can read it"), and is still shown no control.
func TestAgents_ViewerPaysOneRunningJobsRead(t *testing.T) {
	rows := []capability.AuditRow{dispatchRow("job-1", "node-a")}
	q := &fakeQueries{rows: rows, jobs: []capability.JobSummary{{JobID: "job-1", State: jobs.JobStateRunning}}}
	d := cancelDeps(q, &fakeCanceller{})
	body := get(t, newTestHandler(d, accounts.RoleViewer), "/console/agents").Body.String()

	if q.jobCalls != 1 {
		t.Errorf("QueryJobs calls = %d, want 1 — a viewer now sees running Jobs too (#617)", q.jobCalls)
	}
	if q.auditCalls != 1 {
		t.Errorf("QueryAudit calls = %d, want 1", q.auditCalls)
	}
	if strings.Contains(body, `class="jobcancel"`) {
		t.Error("a viewer's page rendered a Cancel control — cancelOffered is false for a viewer")
	}
}

func TestAgents_RunningJobsReadFailureOffersNoControlAndSaysSo(t *testing.T) {
	rows := []capability.AuditRow{dispatchRow("job-1", "node-a")}
	q := &fakeQueries{
		rows:    rows,
		jobs:    []capability.JobSummary{{JobID: "job-1", State: jobs.JobStateRunning}},
		jobsErr: errQueryFailed,
	}
	d := cancelDeps(q, &fakeCanceller{})
	body := get(t, newTestHandler(d, accounts.RoleAdmin), "/console/agents").Body.String()

	if strings.Contains(body, `class="jobcancel"`) {
		t.Error("a control rendered even though the running-Jobs read failed")
	}
	if !strings.Contains(body, "could not be read") {
		t.Error("the page does not say the running-Jobs read failed")
	}
}

func TestAgents_TruncatedRunningSetSaysSo(t *testing.T) {
	rows := []capability.AuditRow{dispatchRow("job-1", "node-a")}
	q := &fakeQueries{
		rows:    rows,
		jobs:    []capability.JobSummary{{JobID: "job-1", State: jobs.JobStateRunning}},
		jobNext: "cursor-2",
	}
	d := cancelDeps(q, &fakeCanceller{})
	body := get(t, newTestHandler(d, accounts.RoleAdmin), "/console/agents").Body.String()

	want := fmt.Sprintf("newest %d running Jobs", capability.MaxPageSize)
	if !strings.Contains(body, want) {
		t.Errorf("a truncated running-Jobs page does not say %q", want)
	}
}

// TestAgents_CancelFormCarriesARealCSRFToken proves the per-row control on
// this screen is wired into the SAME session CSRF token every other Console
// form uses (screen.go's Page.CSRFToken), through a real signed-in session
// rather than the bearer lane cancel_test.go's other route tests use — a
// control with no token, or with the bearer lane's necessarily-empty one,
// would submit to a POST route Secure refuses on sight (security.go).
func TestAgents_CancelFormCarriesARealCSRFToken(t *testing.T) {
	rows := []capability.AuditRow{dispatchRow("job-1", "node-a")}
	q := &fakeQueries{rows: rows, jobs: []capability.JobSummary{{JobID: "job-1", State: jobs.JobStateRunning}}}
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
		t.Error("the Agents page's Cancel form carries no CSRF token")
	}
}
