package console

// agents_cancel_test.go covers the Agents stream's half of the Cancel
// control (#595): one button per running Job, drawn on its newest dispatch
// row, backed by exactly one extra lane read that a viewer never pays for.

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

func TestAgents_NoControlForACompleteJobOrANonDispatchRow(t *testing.T) {
	rows := []capability.AuditRow{
		{Kind: audit.KindRead, Principal: "agent:op", JobID: "job-1", Timestamp: testNow},
		{Kind: audit.KindJobCancel, Principal: "agent:op", JobID: "job-1", Timestamp: testNow},
	}
	q := &fakeQueries{rows: rows, jobs: []capability.JobSummary{{JobID: "job-1", State: jobs.JobStateRunning}}}
	d := cancelDeps(q, &fakeCanceller{})
	body := get(t, newTestHandler(d, accounts.RoleAdmin), "/console/agents").Body.String()

	if strings.Contains(body, `class="jobcancel"`) {
		t.Error("a read row and a job_cancel row (neither a dispatch) drew a Cancel control")
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

func TestAgents_NoRunningJobsReadWithoutADispatchRow(t *testing.T) {
	rows := []capability.AuditRow{
		{Kind: audit.KindRead, Principal: "agent:op", Timestamp: testNow},
	}
	q := &fakeQueries{rows: rows}
	d := cancelDeps(q, &fakeCanceller{})
	get(t, newTestHandler(d, accounts.RoleAdmin), "/console/agents")

	if q.jobCalls != 0 {
		t.Errorf("QueryJobs calls = %d, want 0 — a page with no dispatch row has nothing for Cancel to explain", q.jobCalls)
	}
}

func TestAgents_ViewerMakesNoRunningJobsRead(t *testing.T) {
	rows := []capability.AuditRow{dispatchRow("job-1", "node-a")}
	q := &fakeQueries{rows: rows, jobs: []capability.JobSummary{{JobID: "job-1", State: jobs.JobStateRunning}}}
	d := cancelDeps(q, &fakeCanceller{})
	get(t, newTestHandler(d, accounts.RoleViewer), "/console/agents")

	if q.jobCalls != 0 {
		t.Errorf("QueryJobs calls = %d, want 0 for a viewer — cancelOffered is false", q.jobCalls)
	}
	if q.auditCalls != 1 {
		t.Errorf("QueryAudit calls = %d, want 1 — a viewer's page costs exactly what it did before #595", q.auditCalls)
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
