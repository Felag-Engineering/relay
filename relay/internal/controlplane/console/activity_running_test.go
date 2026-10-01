package console

import (
	"context"
	"errors"
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

// Running rows on Activity (spec 04, #617, #786). A running Job is its own
// Job-lane row: the state comes from the one QueryJobs read the page already
// makes, so none of these tests expects a State-filtered read.

func activityRunning(t *testing.T, q *fakeQueries, role accounts.Role, path string) string {
	t.Helper()
	return get(t, newTestHandler(cancelDeps(q, &fakeCanceller{}), role), path).Body.String()
}

func TestActivity_ARunningJobWithNoDispatchRecordAppearsFromItsJobRow(t *testing.T) {
	q := &fakeQueries{jobs: []capability.JobSummary{runningJob("job-1", "gleipnir-prod", "acct-1")}}
	body := activityRunning(t, q, accounts.RoleAdmin, "/console/activity")

	if n := strings.Count(body, `<article class="ev"`); n != 1 {
		t.Fatalf("rows = %d, want exactly 1", n)
	}
	for _, want := range []string{
		"gleipnir-prod",
		`data-state="running"`,
		"service.restart",
		`data-risk="mutate"`,
		"1 of 3 Tasks resolved",
		"/console/jobs/job-1",
		"No dispatch record is joined to it yet",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("the running row lacks %q:\n%s", want, body)
		}
	}
}

func TestActivity_ARecordedDispatchWithAnEmptySelectorIsNotAwaiting(t *testing.T) {
	sum := runningJob("job-1", "gleipnir-prod", "acct-1")
	sum.Args = map[string]string{"unit": "nginx"}
	q := &fakeQueries{jobs: []capability.JobSummary{sum}}
	body := activityRunning(t, q, accounts.RoleAdmin, "/console/activity")

	if strings.Contains(body, "No dispatch record is joined") {
		t.Error("a Job with recorded arguments says no dispatch record is joined")
	}
	if !strings.Contains(body, `data-state="running"`) || strings.Count(body, `class="jobcancel"`) != 1 {
		t.Error("the recorded running Job is not marked running or does not offer Cancel")
	}
}

func TestActivity_AResolvedJobIsNeitherMarkedRunningNorCancellable(t *testing.T) {
	sum := runningJob("job-1", "gleipnir-prod", "acct-1")
	// A resolved Job is Complete; the zero State is Running (iota 0), and
	// Running now lists by State.
	sum.Unresolved, sum.State = 0, jobs.JobStateComplete
	q := &fakeQueries{jobs: []capability.JobSummary{sum}}
	body := activityRunning(t, q, accounts.RoleAdmin, "/console/activity")

	for _, banned := range []string{`data-state="running"`, "Tasks resolved", `class="jobcancel"`} {
		if strings.Contains(body, banned) {
			t.Errorf("a resolved Job renders %q", banned)
		}
	}
}

func TestActivity_ARecordedRunningJobIsOneRowWithOneCancel(t *testing.T) {
	sum := runningJob("job-1", "gleipnir-prod", "acct-1")
	sum.Selector = "role=web"
	q := &fakeQueries{
		jobs: []capability.JobSummary{sum},
		rows: []capability.AuditRow{
			{Kind: audit.KindDispatch, JobID: "job-1", NodeID: "n1", OperationName: "service.restart", Timestamp: testNow},
			{Kind: audit.KindDispatch, JobID: "job-1", NodeID: "n2", OperationName: "service.restart", Timestamp: testNow},
			{Kind: audit.KindDispatch, JobID: "job-1", NodeID: "n3", OperationName: "service.restart", Timestamp: testNow},
		},
	}
	body := activityRunning(t, q, accounts.RoleAdmin, "/console/activity")

	if n := strings.Count(body, `<article class="ev"`); n != 1 {
		t.Errorf("rows = %d, want 1 (the per-Node dispatch records are the Job lane's)", n)
	}
	if n := strings.Count(body, `class="jobcancel"`); n != 1 {
		t.Errorf("cancel forms = %d, want exactly 1", n)
	}
	if strings.Contains(body, "No dispatch record is joined") {
		t.Error("a recorded running Job carries the awaiting note")
	}
}

func TestActivity_ARunningJobWithNoRecordedRequesterIsNotRenderedVerified(t *testing.T) {
	q := &fakeQueries{jobs: []capability.JobSummary{runningJob("job-1", "", "")}}
	body := activityRunning(t, q, accounts.RoleAdmin, "/console/activity")

	if strings.Contains(body, `data-trust="verified"`) {
		t.Error("a running Job with no recorded requester renders a verified chip")
	}
	if !strings.Contains(body, "attribution is recorded when the dispatch completes") {
		t.Error("the Pending sentence is missing")
	}
	if strings.Contains(body, `class="kind"`) {
		t.Error("a running Job with no recorded requester draws a human/machine kind label")
	}
}

func TestActivity_RunningRowsFollowTheAccountFilter(t *testing.T) {
	q := &fakeQueries{jobs: []capability.JobSummary{
		runningJob("job-1", "gleipnir-prod", "acct-1"),
		runningJob("job-2", "other", "acct-2"),
	}}
	body := activityRunning(t, q, accounts.RoleAdmin, "/console/activity?account=acct-1")

	if got := q.jobFilters[0].RequesterAccountID; got != "acct-1" {
		t.Errorf("the Job lane was asked for Account %q, want acct-1", got)
	}
	if !strings.Contains(body, "job-1") || strings.Contains(body, "job-2") {
		t.Error("?account=acct-1 did not scope the running rows to that Account")
	}
}

// pagedJobs serves one Job per page, so the running Job below is reachable
// only by following Older.
type pagedJobs struct {
	*fakeQueries
	older capability.JobSummary
}

func (p pagedJobs) QueryJobs(ctx context.Context, who capability.Principal, f capability.JobFilter, page capability.PageRequest) (capability.JobPage, error) {
	// Running now's read lists the old running Job on its first page, which
	// is the point: it is out of the stream's first page and never out of sight.
	if f.Order == jobs.JobOrderOldestFirst {
		return capability.JobPage{Jobs: []capability.JobSummary{p.older}, Limit: page.Limit, Matching: 1}, nil
	}
	if page.Cursor == "" {
		sum := runningJob("job-new", "gleipnir-prod", "acct-1")
		sum.Unresolved = 0
		return capability.JobPage{Jobs: []capability.JobSummary{sum}, Next: "jc-2", Limit: page.Limit}, nil
	}
	return capability.JobPage{Jobs: []capability.JobSummary{p.older}, Limit: page.Limit}, nil
}

// A running Job far back in the stream is never out of sight: Running now
// holds it, with its one Cancel, on the first page; once the stream reaches
// its row (the Older page) that row links up and carries no Cancel.
func TestActivity_ARunningJobOnAnOlderPageIsInRunningNowWithItsOneCancel(t *testing.T) {
	q := pagedJobs{fakeQueries: &fakeQueries{}, older: runningJob("job-old", "gleipnir-prod", "acct-1")}
	d := cancelDeps(q.fakeQueries, &fakeCanceller{})
	d.Queries = q
	h := newTestHandler(d, accounts.RoleAdmin)

	first := get(t, h, "/console/activity").Body.String()
	section, stream := splitRunningNow(t, first)
	if strings.Contains(stream, "job-old") {
		t.Fatal("the newest page of the stream already shows the old running Job")
	}
	if !strings.Contains(section, "job-old") || strings.Count(section, `class="jobcancel"`) != 1 {
		t.Error("the old running Job is not in Running now on the first page with its one Cancel")
	}

	older := unescapeHref(t, hrefContaining(t, first, "jc=jc-2"))
	body := get(t, h, older).Body.String()
	section, stream = splitRunningNow(t, body)
	if strings.Count(body, `action="/console/jobs/job-old/cancel"`) != 1 || !strings.Contains(section, `action="/console/jobs/job-old/cancel"`) {
		t.Error("on the Older page the old running Job does not draw exactly one Cancel, in Running now")
	}
	row := activityRowContaining(t, stream, `data-job-id="job-old"`)
	if strings.Contains(row, `class="jobcancel"`) {
		t.Error("the stream row of a running Job carries a Cancel")
	}
	if !strings.Contains(row, `href="#rn-job-old"`) {
		t.Errorf("the stream row does not link up to its Running now entry:\n%s", row)
	}
}

func TestActivity_RunningRowMeetsAccessibilityTagRules(t *testing.T) {
	q := &fakeQueries{jobs: []capability.JobSummary{runningJob("job-1", "gleipnir-prod", "acct-1")}}
	body := activityRunning(t, q, accounts.RoleAdmin, "/console/activity")

	if !strings.Contains(body, `data-state="running"`) {
		t.Fatal("no running row rendered — this test proves nothing without one")
	}
	if _, times, _ := checkA11yTags(t, "activity (running row)", body); times == 0 {
		t.Fatal("swept zero <time> tags off a page holding a running row")
	}
}

func TestActivity_TheRawExecTierIsNeverImpersonated(t *testing.T) {
	rawExec := runningJob("job-1", "p", "a")
	rawExec.ActionKind, rawExec.OperationName = jobs.ActionRawExec, ""
	named := runningJob("job-2", "p", "a")
	named.ActionKind, named.OperationName = jobs.ActionOperation, "raw_exec"
	neither := runningJob("job-3", "p", "a")
	neither.ActionKind, neither.OperationName = jobs.ActionUnspecified, ""

	q := &fakeQueries{jobs: []capability.JobSummary{rawExec, named, neither}}
	body := activityRunning(t, q, accounts.RoleAdmin, "/console/activity")

	r1 := activityRowContaining(t, body, `data-job-id="job-1"`)
	for _, want := range []string{`data-tier="raw_exec"`, ">Raw Exec<", "<code>raw_exec</code>"} {
		if !strings.Contains(r1, want) {
			t.Errorf("the real Raw Exec row lacks %q:\n%s", want, r1)
		}
	}
	r2 := activityRowContaining(t, body, `data-job-id="job-2"`)
	if !strings.Contains(r2, "<code>run_operation · raw_exec</code>") {
		t.Errorf("an Operation named raw_exec is not marked as a run_operation:\n%s", r2)
	}
	if strings.Contains(r2, "data-tier") {
		t.Errorf("an Operation named raw_exec carries the tier marker:\n%s", r2)
	}
	r3 := activityRowContaining(t, body, `data-job-id="job-3"`)
	if !strings.Contains(r3, `<span class="evsum">dispatch</span>`) || !strings.Contains(r3, "/console/jobs/job-3") {
		t.Errorf("a Job with neither name nor tier is not summarised as a dispatch with its Job link:\n%s", r3)
	}
	if strings.Contains(r3, "data-tier") || strings.Contains(r3, "<code></code>") || strings.Contains(r3, `<span class="evsum"></span>`) {
		t.Errorf("a Job with neither name nor tier renders an impersonation or an empty cell:\n%s", r3)
	}

	for _, c := range []struct {
		sum  capability.JobSummary
		want string
		tier bool
	}{
		{rawExec, "raw_exec", true},
		{named, "run_operation · raw_exec", false},
		{neither, "", false},
		{runningJob("j", "p", "a"), "service.restart", false},
	} {
		if got, tier := jobRowName(c.sum); got != c.want || tier != c.tier {
			t.Errorf("jobRowName(%q/%v) = %q, %v; want %q, %v", c.sum.OperationName, c.sum.ActionKind, got, tier, c.want, c.tier)
		}
	}
}

func TestActivity_OperatorIsOfferedCancelOnARunningRow(t *testing.T) {
	q := &fakeQueries{jobs: []capability.JobSummary{runningJob("job-1", "gleipnir-prod", "acct-1")}}
	body := activityRunning(t, q, accounts.RoleOperator, "/console/activity")

	if n := strings.Count(body, `class="jobcancel"`); n != 1 {
		t.Errorf("cancel forms = %d, want exactly 1", n)
	}
	if !strings.Contains(body, `action="/console/jobs/job-1/cancel"`) {
		t.Error("the form action is not /console/jobs/job-1/cancel")
	}
}

func TestActivity_ViewerSeesTheRunningJobButNoCancel(t *testing.T) {
	q := &fakeQueries{jobs: []capability.JobSummary{runningJob("job-1", "gleipnir-prod", "acct-1")}}
	body := activityRunning(t, q, accounts.RoleViewer, "/console/activity")

	if !strings.Contains(body, `data-state="running"`) {
		t.Error("a viewer does not see the running Job")
	}
	if strings.Contains(body, `class="jobcancel"`) {
		t.Error("a viewer is offered Cancel")
	}
	// The stream's read, and Running now's: the viewer is offered no Cancel
	// but still reads both.
	if q.jobCalls != 2 {
		t.Fatalf("QueryJobs calls = %d, want 2", q.jobCalls)
	}
	if !isRunningNowRead(q.jobFilters[1]) {
		t.Errorf("the second Job read is not Running now's: %+v", q.jobFilters[1])
	}
}

func TestActivity_NoCancelWhenTheCancelRouteIsNotMounted(t *testing.T) {
	q := &fakeQueries{jobs: []capability.JobSummary{runningJob("job-1", "gleipnir-prod", "acct-1")}}
	d := activityDeps(q) // d.Cancel left nil
	body := get(t, newTestHandler(d, accounts.RoleAdmin), "/console/activity").Body.String()

	if !strings.Contains(body, `data-state="running"`) {
		t.Error("the running row did not render")
	}
	if strings.Contains(body, `class="jobcancel"`) {
		t.Error("Cancel rendered although the cancel route is not mounted")
	}
}

func TestActivity_CancelFormCarriesARealCSRFToken(t *testing.T) {
	q := &fakeQueries{jobs: []capability.JobSummary{runningJob("job-1", "gleipnir-prod", "acct-1")}}
	f := newLoginFixtureWith(t, func(d *Deps) {
		d.Queries = q
		d.Cancel = &fakeCanceller{}
	})
	rec, cookies := f.signIn(t, "mike", consolePassword)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("sign-in status = %d, want %d", rec.Code, http.StatusSeeOther)
	}
	session := cookieNamed(cookies, consoleauth.SessionCookieName)
	if session == nil {
		t.Fatal("no session cookie was set")
	}
	page := f.do(t, httptest.NewRequest(http.MethodGet, "/console/activity", nil), session)
	if page.Code != http.StatusOK {
		t.Fatalf("GET /console/activity = %d", page.Code)
	}
	body := page.Body.String()
	if !strings.Contains(body, `class="jobcancel"`) {
		t.Fatal("no Cancel control for the running Job")
	}
	form := body[strings.Index(body, `class="jobcancel"`):]
	form = form[:strings.Index(form, "</form>")]
	token := renderedCSRFToken(form)
	if token == "" {
		t.Fatal("the Cancel form carries no CSRF token")
	}
	if token != renderedCSRFToken(body[strings.Index(body, `name="csrf_token"`):]) {
		t.Error("the Cancel form's token is not the session's token")
	}
}

func TestActivity_NonDispatchRowsNamingAJobDrawNoCancel(t *testing.T) {
	q := &fakeQueries{
		jobs: []capability.JobSummary{runningJob("job-1", "gleipnir-prod", "acct-1")},
		rows: []capability.AuditRow{
			{Kind: audit.KindJobCancel, JobID: "job-1", Principal: "p", Timestamp: testNow},
			{Kind: audit.KindRead, JobID: "job-1", OperationName: "get_job", Principal: "p", Timestamp: testNow},
		},
	}
	// Running now ignores the kind chips, so the running Job's one Cancel is
	// on these pages too — in the section. The assertion is aimed at the
	// stream: no row in it draws one.
	for _, kind := range []string{"cancel", "read"} {
		body := activityRunning(t, q, accounts.RoleAdmin, "/console/activity?kind="+kind)
		section, stream := splitRunningNow(t, body)
		if strings.Contains(stream, `class="jobcancel"`) {
			t.Errorf("a %s row draws a Cancel control", kind)
		}
		if n := strings.Count(section, `class="jobcancel"`); n != 1 {
			t.Errorf("?kind=%s: Running now draws %d Cancel controls for the running Job, want 1", kind, n)
		}
	}
	body := activityRunning(t, q, accounts.RoleAdmin, "/console/activity")
	if n := strings.Count(body, `class="jobcancel"`); n != 1 {
		t.Errorf("the feed draws %d Cancel controls for one running Job, want 1", n)
	}
}

func TestActivity_RunningStateComesFromTheOneJobLaneRead(t *testing.T) {
	q := &fakeQueries{jobs: []capability.JobSummary{runningJob("job-1", "gleipnir-prod", "acct-1")}}
	activityRunning(t, q, accounts.RoleAdmin, "/console/activity")

	if q.jobCalls != 2 || q.auditCalls != 1 {
		t.Fatalf("reads = %d Job, %d audit; want the stream's and Running now's Job reads and 1 audit", q.jobCalls, q.auditCalls)
	}
	if q.jobFilters[0].State != nil {
		t.Errorf("QueryJobs filter State = %v, want none: running comes from the row's own Unresolved", q.jobFilters[0].State)
	}
	if !isRunningNowRead(q.jobFilters[1]) {
		t.Errorf("the second Job read is not Running now's: %+v", q.jobFilters[1])
	}
	if len(q.subscriptionKinds) != 0 {
		t.Errorf("subscriptionKinds = %v, want none", q.subscriptionKinds)
	}
}

func TestActivity_ANonDispatchFilterMakesOnlyTheRunningNowRead(t *testing.T) {
	q := &fakeQueries{jobs: []capability.JobSummary{runningJob("job-1", "gleipnir-prod", "acct-1")}}
	activityRunning(t, q, accounts.RoleAdmin, "/console/activity?kind=approval")
	if q.jobCalls != 1 {
		t.Fatalf("QueryJobs calls = %d, want 1: the stream makes none, Running now ignores the kind", q.jobCalls)
	}
	if !isRunningNowRead(q.jobFilters[0]) {
		t.Errorf("the one Job read is not Running now's: %+v", q.jobFilters[0])
	}
}

func TestActivity_AFailedJobLaneOffersNoCancel(t *testing.T) {
	for _, role := range []accounts.Role{accounts.RoleAdmin, accounts.RoleViewer} {
		q := &fakeQueries{jobsErr: errQueryFailed}
		d := cancelDeps(q, &fakeCanceller{})
		rec := get(t, newTestHandler(d, role), "/console/activity")
		if rec.Code == http.StatusOK {
			t.Errorf("%s: a failed Job lane still served the page", role)
		}
		if strings.Contains(rec.Body.String(), `class="jobcancel"`) {
			t.Errorf("%s: a failed Job lane offers Cancel", role)
		}
	}
}

func TestActivity_UnauditableJobLaneRefusesThePage(t *testing.T) {
	q := &fakeQueries{jobsErr: errors.Join(capability.ErrReadUnaudited, errQueryFailed)}
	rec := get(t, newTestHandler(cancelDeps(q, &fakeCanceller{}), accounts.RoleViewer), "/console/activity")

	if rec.Code == http.StatusOK {
		t.Fatal("GET /console/activity = 200 with an unauditable Job read (ADR-0025 decision 4)")
	}
	for _, want := range []string{"audit trail", "refused"} {
		if !strings.Contains(rec.Body.String(), want) {
			t.Errorf("the refusal page does not say %q", want)
		}
	}
}
