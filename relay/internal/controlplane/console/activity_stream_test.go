package console

import (
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/Felag-Engineering/relay/relay/internal/accounts"
	"github.com/Felag-Engineering/relay/relay/internal/audit"
	"github.com/Felag-Engineering/relay/relay/internal/capability"
	"github.com/Felag-Engineering/relay/relay/internal/jobs"
)

// The call-grained stream on Activity (spec 04, #786): paging, the kinds the
// default feed requests, and the result line every call row carries.

func activityAs(t *testing.T, q *fakeQueries, path string) string {
	t.Helper()
	return get(t, newTestHandler(activityDeps(q), accounts.RoleAdmin), path).Body.String()
}

func TestActivity_AsksForOneBoundedPagePerLane(t *testing.T) {
	q := &fakeQueries{}
	activityAs(t, q, "/console/activity")

	// The stream's page, then Running now's (activity_runningnow.go).
	if len(q.jobLimits) != 2 || q.jobLimits[0] != jobPageSize || q.jobLimits[1] != runningNowPageSize {
		t.Errorf("Job lane limits = %v, want [%d %d]", q.jobLimits, jobPageSize, runningNowPageSize)
	}
	if len(q.auditLimits) != 1 || q.auditLimits[0] != auditPageSize {
		t.Errorf("audit lane limits = %v, want [%d]", q.auditLimits, auditPageSize)
	}
}

func TestActivity_TheDefaultFeedRequestsEveryCallKind(t *testing.T) {
	q := &fakeQueries{}
	activityAs(t, q, "/console/activity")

	if len(q.auditFilters) != 1 {
		t.Fatalf("audit reads = %d, want 1", len(q.auditFilters))
	}
	got := q.auditFilters[0].Kinds
	for _, k := range agentCallKinds {
		// dispatch is the Job lane's, and read is one chip away: both are
		// left out of the default feed on purpose (activityLaneExcluded).
		if k == audit.KindDispatch || k == audit.KindRead {
			if containsString(got, k) {
				t.Errorf("the default feed requests %q, which it leaves to its own lane or chip", k)
			}
			continue
		}
		if !containsString(got, k) {
			t.Errorf("the default feed does not request the call kind %q", k)
		}
	}
}

// TestActivity_OnlyToolCallsAreRows: Activity is a log of tool calls (spec 04,
// Grain). Fleet events that are not tool calls, and Access events, are not
// drawn, and the seam never asks for them.
func TestActivity_OnlyToolCallsAreRows(t *testing.T) {
	q := &fakeQueries{rows: []capability.AuditRow{
		{Kind: audit.KindFreezeEngage, Principal: "alice:operator", Timestamp: testNow},
		{Kind: audit.KindFreezeRelease, Principal: "alice:operator", Timestamp: testNow},
		{Kind: audit.KindNodeRevoke, NodeID: "node-7", Principal: "alice:operator", Timestamp: testNow},
		{Kind: audit.KindTokenMint, Principal: "alice:operator", Timestamp: testNow},
		{Kind: audit.KindTokenRevoke, Principal: "alice:operator", Timestamp: testNow},
		{Kind: audit.KindProtocolViolation, NodeID: "node-7", Timestamp: testNow},
		{Kind: audit.KindLoginSucceeded, Principal: "alice:operator", Timestamp: testNow},
		refusalBy(apiIdentity("acct-1", "alice", "operator"), time.Second, "r"),
	}}
	body := activityAs(t, q, "/console/activity")

	if !strings.Contains(body, `<span class="evkind">`+audit.KindRefusal+`</span>`) {
		t.Error("the refusal row did not render")
	}
	for _, k := range append([]string{audit.KindLoginSucceeded}, activityNonCallKinds...) {
		if strings.Contains(body, `<span class="evkind">`+k+`</span>`) {
			t.Errorf("a %s row rendered on Activity", k)
		}
	}
	content := contentOf(body)
	for _, banned := range []string{"Relay-wide Freeze", "minted an Enrollment Token", "revoked an Enrollment Token", "revoked Node"} {
		if strings.Contains(content, banned) {
			t.Errorf("the page says %q, a fleet event Activity does not draw", banned)
		}
	}
	for i, f := range q.auditFilters {
		for _, k := range activityNonCallKinds {
			if containsString(f.Kinds, k) {
				t.Errorf("audit read %d asks for the non-call kind %q", i, k)
			}
		}
	}
	for _, chip := range []string{"freeze", "node", "token", "other"} {
		if strings.Contains(body, "kind="+chip+`"`) || strings.Contains(body, "kind="+chip+"&") {
			t.Errorf("the page draws a kind chip for %q", chip)
		}
	}

	q.auditFilters = nil
	activityAs(t, q, "/console/activity?format=csv")
	if len(q.auditFilters) == 0 {
		t.Fatal("the export read nothing from the trail")
	}
	for _, f := range q.auditFilters {
		for _, k := range activityNonCallKinds {
			if containsString(f.Kinds, k) {
				t.Errorf("the export asks for the non-call kind %q", k)
			}
		}
	}
}

// TestActivity_RendersNoWhoIsActiveStrip: the strip was removed (spec 04, owner
// decision 2026-10-01), and ?account= still scopes the stream.
func TestActivity_RendersNoWhoIsActiveStrip(t *testing.T) {
	for _, path := range []string{"/console/activity", "/console/activity?account=acct-1", "/console/activity?ac=0"} {
		q := &fakeQueries{rows: []capability.AuditRow{
			refusalBy(apiIdentity("acct-1", "alice", "operator"), time.Minute, "r"),
		}}
		body := activityAs(t, q, path)
		for _, banned := range []string{`class="whoactive"`, "Who is active", "Accounts on this page", `class="arow`} {
			if strings.Contains(body, banned) {
				t.Errorf("%s draws %q", path, banned)
			}
		}
		if path == "/console/activity?account=acct-1" {
			if !strings.Contains(body, "Show every Account") {
				t.Error("the Account filter no longer offers Show every Account")
			}
			if len(q.auditFilters) == 0 || q.auditFilters[0].AccountID != "acct-1" {
				t.Errorf("the Account filter was not applied to the stream: %+v", q.auditFilters)
			}
		}
	}
}

func TestActivity_OlderIsDrawnOnlyWhenThereIsAnOlderPage(t *testing.T) {
	row := capability.AuditRow{Kind: audit.KindRefusal, Principal: "p", Timestamp: testNow}

	with := activityAs(t, &fakeQueries{rows: []capability.AuditRow{row}, auditNext: "c2"}, "/console/activity")
	if !strings.Contains(with, ">Older<") {
		t.Error("no Older link although the lane reported a next page")
	}
	without := activityAs(t, &fakeQueries{rows: []capability.AuditRow{row}}, "/console/activity")
	if strings.Contains(without, ">Older<") {
		t.Error("an Older link rendered although no lane reported a next page")
	}
}

func TestActivity_AnOlderPageDoesNotClaimToBeTheMostRecent(t *testing.T) {
	q := &fakeQueries{rows: []capability.AuditRow{{Kind: audit.KindRefusal, Principal: "p", Timestamp: testNow}}}
	older := activityAs(t, q, "/console/activity?ac=0")

	if !strings.Contains(older, "These are not the most recent events.") {
		t.Error("a scrolled page does not say it is not the most recent")
	}
	if !strings.Contains(older, `<a href="/console/activity">Newest</a>`) {
		t.Error("a scrolled page offers no way back to the newest page")
	}
	newest := activityAs(t, q, "/console/activity")
	if strings.Contains(newest, "not the most recent events") {
		t.Error("the newest page says it is not the most recent")
	}
}

func TestActivity_TheFilterSurvivesPaging(t *testing.T) {
	const account = "bob&co"
	q := &fakeQueries{
		rows:      []capability.AuditRow{{Kind: audit.KindRefusal, Verified: capability.VerifiedIdentity{AccountID: account}, Principal: "p", Timestamp: testNow}},
		auditNext: "c2",
	}
	body := activityAs(t, q, "/console/activity?account="+url.QueryEscape(account))
	older := unescapeHref(t, hrefContaining(t, body, "ac=c2"))
	u, err := url.Parse(older)
	if err != nil {
		t.Fatal(err)
	}
	if got := u.Query().Get("account"); got != account {
		t.Errorf("the Older link carries account=%q, want %q", got, account)
	}

	scrolled := activityAs(t, q, "/console/activity?ac=0&account="+url.QueryEscape(account))
	m := regexp.MustCompile(`<a href="([^"]*)">Newest</a>`).FindStringSubmatch(scrolled)
	if m == nil {
		t.Fatal("no Newest link on a scrolled page")
	}
	newest := unescapeHref(t, m[1])
	if nu, _ := url.Parse(newest); nu == nil || nu.Query().Get("account") != account {
		t.Errorf("the Newest link %q drops the account filter", newest)
	}
}

func TestActivity_ADeniedFanOutIsOneJobRowPointingToItsJob(t *testing.T) {
	q := &fakeQueries{jobs: []capability.JobSummary{{
		JobID: "job-1", CreatedAt: testNow, OperationName: "service.restart",
		RiskClass: jobs.RiskClassMutate, Requester: "gleipnir", Total: 3,
		Counts: map[jobs.Outcome]int{jobs.OutcomeDeniedByPolicy: 3},
	}}}
	body := activityAs(t, q, "/console/activity")

	if n := strings.Count(body, `<article class="ev"`); n != 1 {
		t.Fatalf("a denied 3-Node fan-out rendered %d rows, want 1", n)
	}
	row := activityRowContaining(t, body, "job-1")
	if !strings.Contains(row, "denied_by_policy") || !strings.Contains(row, "/console/jobs/job-1") {
		t.Errorf("the row does not carry the denial and a link to the Job, where the rule is:\n%s", row)
	}
}

// TestActivity_EveryToolRendersARequestAndAResult is spec 04's second
// acceptance criterion: each of the eight tools renders a request line and a
// result line.
func TestActivity_EveryToolRendersARequestAndAResult(t *testing.T) {
	q := &fakeQueries{
		jobs: []capability.JobSummary{
			{JobID: "job-run", CreatedAt: testNow, OperationName: "service.restart", ActionKind: jobs.ActionOperation,
				RiskClass: jobs.RiskClassMutate, Requester: "p", Total: 2,
				Counts: map[jobs.Outcome]int{jobs.OutcomeSuccess: 2}},
			{JobID: "job-raw", CreatedAt: testNow, ActionKind: jobs.ActionRawExec,
				RiskClass: jobs.RiskClassMutate, Requester: "p", Total: 1,
				Counts: map[jobs.Outcome]int{jobs.OutcomeSuccess: 1}},
		},
		rows: []capability.AuditRow{
			{Kind: audit.KindRead, OperationName: "list_nodes", Principal: "p", Timestamp: testNow},
			{Kind: audit.KindRead, OperationName: "describe_node", NodeID: "node-1", Principal: "p", Timestamp: testNow},
			{Kind: audit.KindRead, OperationName: "list_operations", Principal: "p", Timestamp: testNow},
			{Kind: audit.KindRead, OperationName: "get_job", JobID: "job-run", Principal: "p", Timestamp: testNow},
			{Kind: audit.KindJobCancel, JobID: "job-run", Principal: "p", Timestamp: testNow},
			{Kind: audit.KindApprovalDecided, ApprovalID: "ap-1", ApprovalAnswer: audit.ApprovalAnswerApproved,
				Principal: "p", Timestamp: testNow},
		},
	}
	reads := activityAs(t, q, "/console/activity?kind=read")
	for _, tool := range []string{"enumerated list_nodes", "read describe_node", "enumerated list_operations", "<code>get_job</code>"} {
		row := activityRowContaining(t, reads, tool)
		if !strings.Contains(row, `data-outcome="audited"`) {
			t.Errorf("the read row %q has no audited result:\n%s", tool, row)
		}
	}

	cancel := activityRowContaining(t, activityAs(t, q, "/console/activity?kind=cancel"), "asked to cancel Job")
	if !strings.HasPrefix(cancel, `cancel"`) || !strings.Contains(cancel, `data-outcome="requested"`) {
		t.Errorf("the cancel row lacks its request or its result:\n%s", cancel)
	}

	approval := activityRowContaining(t, activityAs(t, q, "/console/activity?kind=approval"), "ap-1")
	if !strings.Contains(approval, `data-state="approved"`) {
		t.Errorf("the approval row lacks its answer:\n%s", approval)
	}

	dispatch := activityAs(t, q, "/console/activity?kind=dispatch")
	run := activityRowContaining(t, dispatch, `data-job-id="job-run"`)
	if !strings.Contains(run, "<code>service.restart</code>") || !strings.Contains(run, `data-outcome="success"`) {
		t.Errorf("the run_operation Job row lacks its request or its result:\n%s", run)
	}
	raw := activityRowContaining(t, dispatch, `data-job-id="job-raw"`)
	if !strings.Contains(raw, `data-tier="raw_exec"`) || !strings.Contains(raw, `data-outcome="success"`) {
		t.Errorf("the raw_exec Job row lacks its tier or its result:\n%s", raw)
	}

	for _, body := range []string{reads, cancel, approval, dispatch} {
		for _, banned := range []string{`data-outcome="unspecified"`, "approve_request"} {
			if strings.Contains(body, banned) {
				t.Errorf("a tool row renders %q", banned)
			}
		}
	}
}

// A plan or refusal record for a real Raw Exec carries the tier chip; one for
// an Operation that is merely NAMED raw_exec must not impersonate it.
func TestActivity_TrailRowsNeverLetAnOperationNameImpersonateRawExec(t *testing.T) {
	q := &fakeQueries{rows: []capability.AuditRow{
		{Kind: audit.KindApprovalRequested, ActionKind: "raw_exec", RawExecArgv: []string{"uptime"},
			Principal: "p", Timestamp: testNow},
		{Kind: audit.KindRefusal, ActionKind: "run_operation", OperationName: "raw_exec",
			Principal: "p", Timestamp: testNow.Add(-time.Minute)},
	}}
	body := activityAs(t, q, "/console/activity")

	genuine := activityRowContaining(t, body, "uptime")
	if !strings.Contains(genuine, `data-tier="raw_exec"`) {
		t.Errorf("a real Raw Exec trail row lacks the tier chip:\n%s", genuine)
	}
	fake := activityRowContaining(t, body, "run_operation · raw_exec")
	if strings.Contains(fake, `data-tier="raw_exec"`) {
		t.Errorf("an Operation named raw_exec wears the Raw Exec tier chip:\n%s", fake)
	}
}

func TestActivity_ParkedIsNotUnspecified(t *testing.T) {
	q := &fakeQueries{rows: []capability.AuditRow{
		{Kind: audit.KindApprovalRequested, ActionKind: "raw_exec", Principal: "agent:operator", Timestamp: testNow},
	}}
	body := activityAs(t, q, "/console/activity")
	if strings.Contains(body, "unspecified") {
		t.Error("a parked dispatch renders \"unspecified\"")
	}
	if !strings.Contains(body, `data-outcome="parked"`) {
		t.Error("a parked dispatch has no \"parked\" chip")
	}
}

func TestActivity_PreflightRowIsItsOwnKindWithItsOwnBadge(t *testing.T) {
	q := &fakeQueries{rows: []capability.AuditRow{
		{Kind: audit.KindPlan, ActionKind: "operation", OperationName: "service.restart", Principal: "p", Timestamp: testNow},
	}}
	body := activityAs(t, q, "/console/activity?kind=plan")

	row := activityRowContaining(t, body, "service.restart")
	if !strings.HasPrefix(row, `plan"`) {
		t.Errorf("the Preflight row is not data-kind=\"plan\":\n%s", row)
	}
	if !strings.Contains(row, `data-outcome="preflight"`) || !strings.Contains(row, `data-risk="mutate"`) {
		t.Errorf("the Preflight row lacks its badge or risk chip:\n%s", row)
	}
}

func TestActivity_RevokedGrantHasItsOwnTreatment(t *testing.T) {
	q := &fakeQueries{rows: []capability.AuditRow{
		{Kind: audit.KindApprovalDecided, GrantID: "gr-1", Principal: "p", Timestamp: testNow},
	}}
	row := activityRowContaining(t, activityAs(t, q, "/console/activity"), "gr-1")
	if n := strings.Count(row, `data-outcome="revoked"`); n != 1 {
		t.Errorf("a revoked grant carries %d \"revoked\" chips, want 1:\n%s", n, row)
	}
}

func TestActivity_ARoleGateRefusalIsNeutral(t *testing.T) {
	q := &fakeQueries{rows: []capability.AuditRow{
		{Kind: audit.KindRefusal, ActionKind: "raw_exec", RawExecArgv: []string{"id"}, Principal: "p", Timestamp: testNow},
	}}
	row := activityRowContaining(t, activityAs(t, q, "/console/activity"), "raw_exec")

	if !strings.Contains(row, `chip outcome" data-outcome="refused"`) {
		t.Errorf("a refused raw_exec is not a neutral refused chip:\n%s", row)
	}
	for _, o := range []string{"failure", "timeout", "denied_by_policy", "unreachable"} {
		if strings.Contains(row, `data-outcome="`+o+`"`) {
			t.Errorf("a role-gate refusal renders as the failure outcome %q", o)
		}
	}
}

func TestActivity_HasNoLede(t *testing.T) {
	body := activityAs(t, &fakeQueries{}, "/console/activity")

	if strings.Contains(body, `class="lede"`) || strings.Contains(body, "Calls the Relay received") {
		t.Error("Activity draws a lede")
	}
	for _, banned := range []string{"every call an AI-agent makes", "connected"} {
		if strings.Contains(contentOf(body), banned) {
			t.Errorf("the lede says %q", banned)
		}
	}
}

func TestActivity_ResultChipIsDrawnOnlyForCalls(t *testing.T) {
	for _, k := range []string{audit.KindFreezeEngage, audit.KindTokenMint, audit.KindNodeRevoke, audit.KindApprovalExpired, audit.KindProtocolViolation} {
		if o, s := callOutcome(trailFacts{Kind: k}); o != "" || s != "" {
			t.Errorf("callOutcome(%s) = %q, %q; an event that is not a call draws no chip", k, o, s)
		}
	}
	// What the retired Agents screen's outcome chip said (callOutcome), pinned.
	for k, want := range map[string]string{
		audit.KindRead: "audited", audit.KindRefusal: "refused", audit.KindApprovalRequested: "parked",
		audit.KindApprovalGrantRequested: "grant requested", audit.KindApprovalPendingObserved: "already parked",
		audit.KindJobCancel: "requested", audit.KindPlan: "preflight",
		audit.KindDispatch: jobs.OutcomeName(jobs.OutcomeSuccess),
	} {
		f := trailFacts{Kind: k}
		if k == audit.KindDispatch {
			f.Outcome = jobs.OutcomeSuccess
		}
		if got, _ := callOutcome(f); got != want {
			t.Errorf("callOutcome(%s) outcome = %q, want %q", k, got, want)
		}
	}
}
