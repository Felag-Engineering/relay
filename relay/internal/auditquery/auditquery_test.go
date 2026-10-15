package auditquery

import (
	"context"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/Felag-Engineering/relay/relay/internal/audit"
	"github.com/Felag-Engineering/relay/relay/internal/capability"
	"github.com/Felag-Engineering/relay/relay/internal/jobs"
	"github.com/Felag-Engineering/relay/relay/internal/store"
)

// openQueryStore opens a temp SQLite store, mirroring auditsink_test.go's
// openSinkStore.
func openQueryStore(t *testing.T) *store.Store {
	t.Helper()
	path := filepath.Join(t.TempDir(), "relay.db")
	st, err := store.Open(path)
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	return st
}

// TestQueries_QueryAudit_RoundTrips is the mapping's audit half: a Record
// written through the real store comes back through Queries.QueryAudit with
// every AuditRow field intact, and every field of the capability.AuditFilter
// that was passed reaches the store (proven by the filter actually
// selecting/excluding the right rows).
func TestQueries_QueryAudit_RoundTrips(t *testing.T) {
	st := openQueryStore(t)
	ctx := context.Background()

	ts := time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)
	rec := audit.Record{
		ID:        "audit-1",
		Timestamp: ts,
		Kind:      audit.KindRead,
		Principal: "gleipnir:operator",
		Attribution: audit.Attribution{
			Verified: audit.Verified{
				AccountID: "acct-1", AccountName: "gleipnir", Role: "operator",
				TokenID: "tok-1", Method: "api_token", Source: "10.0.0.1",
			},
			Asserted: audit.Asserted{
				OnBehalfOf: "ops-team", Traceparent: "00-trace", SessionRef: "sess-1", ChangeRef: "CHG-1",
			},
		},
		Selector:      "relay:env=prod",
		JobID:         "job-1",
		NodeID:        "node-1",
		ActionKind:    "operation",
		OperationName: "file.read",
		Args:          map[string]string{"path": "/etc/hosts"},
		RawExecArgv:   nil,
		Outcome:       jobs.OutcomeSuccess,
		Reason:        "",
		ApprovalID:    "appr-1",
		GrantID:       "grant-1",

		ApprovalAnswer:  audit.ApprovalAnswerApproved,
		DecisionChannel: "out_of_band",
		PlanHash:        "hash-1",
	}
	if err := st.Audit().Append(ctx, rec); err != nil {
		t.Fatalf("append: %v", err)
	}

	decoy := rec
	decoy.ID = "audit-2"
	decoy.Kind = audit.KindDispatch
	decoy.Attribution.Verified.AccountID = "acct-2"
	if err := st.Audit().Append(ctx, decoy); err != nil {
		t.Fatalf("append decoy: %v", err)
	}

	q := New(st.AuditQueries(), st.JobQueries())

	page, err := q.QueryAudit(ctx, capability.AuditFilter{
		Kinds:     []string{audit.KindRead},
		AccountID: "acct-1",
	}, capability.PageRequest{})
	if err != nil {
		t.Fatalf("QueryAudit: %v", err)
	}
	if len(page.Rows) != 1 {
		t.Fatalf("Rows = %d, want 1", len(page.Rows))
	}
	got := page.Rows[0]

	want := capability.AuditRow{
		ID:        "audit-1",
		Timestamp: ts,
		Kind:      audit.KindRead,
		Principal: "gleipnir:operator",
		Verified: capability.VerifiedIdentity{
			AccountID: "acct-1", AccountName: "gleipnir", Role: "operator",
			TokenID: "tok-1", Method: "api_token", Source: "10.0.0.1",
		},
		Asserted: capability.Assertions{
			OnBehalfOf: "ops-team", Traceparent: "00-trace", SessionRef: "sess-1", ChangeRef: "CHG-1",
		},
		Selector:      "relay:env=prod",
		JobID:         "job-1",
		NodeID:        "node-1",
		ActionKind:    "operation",
		OperationName: "file.read",
		Args:          map[string]string{"path": "/etc/hosts"},
		Outcome:       jobs.OutcomeSuccess,
		ApprovalID:    "appr-1",
		GrantID:       "grant-1",

		ApprovalAnswer:  capability.ApprovalAnswerApproved,
		DecisionChannel: "out_of_band",
		PlanHash:        "hash-1",
	}
	if !got.Timestamp.Equal(want.Timestamp) {
		t.Errorf("Timestamp = %v, want %v", got.Timestamp, want.Timestamp)
	}
	got.Timestamp = want.Timestamp
	if !reflect.DeepEqual(got, want) {
		t.Errorf("QueryAudit row =\n%+v, want\n%+v", got, want)
	}
}

// TestQueries_AuditCounts_AuditReach exercises the two aggregate methods
// through the real store.
func TestQueries_AuditCounts_AuditReach(t *testing.T) {
	st := openQueryStore(t)
	ctx := context.Background()

	base := time.Date(2026, 8, 20, 0, 0, 0, 0, time.UTC)
	for i, nodeID := range []string{"node-1", "node-2"} {
		rec := audit.Record{
			ID: "audit-" + nodeID, Timestamp: base.Add(time.Duration(i) * time.Minute),
			Kind:      audit.KindRead,
			Principal: "gleipnir:operator",
			Attribution: audit.Attribution{
				Verified: audit.Verified{AccountID: "acct-1", AccountName: "gleipnir", Role: "operator"},
			},
			NodeID:        nodeID,
			OperationName: "file.read",
			Args:          map[string]string{"path": "/etc/hosts"},
		}
		if err := st.Audit().Append(ctx, rec); err != nil {
			t.Fatalf("append: %v", err)
		}
	}

	q := New(st.AuditQueries(), st.JobQueries())

	buckets, err := q.AuditCounts(ctx, capability.AuditFilter{}, time.Hour)
	if err != nil {
		t.Fatalf("AuditCounts: %v", err)
	}
	if len(buckets) != 1 || buckets[0].Count != 2 || buckets[0].AccountID != "acct-1" {
		t.Fatalf("buckets = %+v, want one bucket, AccountID=acct-1, Count=2", buckets)
	}

	reach, err := q.AuditReach(ctx, capability.AuditFilter{})
	if err != nil {
		t.Fatalf("AuditReach: %v", err)
	}
	if reach.Calls != 2 || reach.DistinctTargets != 1 || reach.DistinctNodes != 2 {
		t.Fatalf("reach = %+v, want Calls=2 DistinctTargets=1 DistinctNodes=2", reach)
	}
}

// TestQueries_QueryJobs_QueryTasks_RoundTrip is the mapping's Job/Task half.
func TestQueries_QueryJobs_QueryTasks_RoundTrip(t *testing.T) {
	st := openQueryStore(t)
	ctx := context.Background()

	base := time.Date(2026, 8, 20, 0, 0, 0, 0, time.UTC)
	if err := st.Jobs().CreateJob(ctx, jobs.Job{ID: "job-1", CreatedAt: base}); err != nil {
		t.Fatalf("CreateJob: %v", err)
	}
	if err := st.Jobs().AddStage(ctx, jobs.Stage{ID: "stage-1", JobID: "job-1", Index: 0}); err != nil {
		t.Fatalf("AddStage: %v", err)
	}
	task := jobs.Task{
		ID: "task-1", JobID: "job-1", StageID: "stage-1", NodeID: "node-1",
		Action:    jobs.Action{Kind: jobs.ActionOperation, OperationName: "system.facts", RiskClass: jobs.RiskClassMutate},
		CreatedAt: base,
	}
	if err := st.Tasks().CreateTask(ctx, task); err != nil {
		t.Fatalf("CreateTask: %v", err)
	}
	if err := st.Tasks().MarkDispatched(ctx, "task-1", base); err != nil {
		t.Fatalf("MarkDispatched: %v", err)
	}
	if err := st.Tasks().Resolve(ctx, "task-1", jobs.Result{Outcome: jobs.OutcomeSuccess, Stdout: []byte("hello")}); err != nil {
		t.Fatalf("Resolve: %v", err)
	}

	q := New(st.AuditQueries(), st.JobQueries())

	jobPage, err := q.QueryJobs(ctx, capability.JobFilter{}, capability.PageRequest{})
	if err != nil {
		t.Fatalf("QueryJobs: %v", err)
	}
	if len(jobPage.Jobs) != 1 || jobPage.Jobs[0].JobID != "job-1" {
		t.Fatalf("QueryJobs = %+v, want exactly [job-1]", jobPage.Jobs)
	}
	if jobPage.Jobs[0].State != jobs.JobStateComplete {
		t.Errorf("Job state = %v, want Complete", jobPage.Jobs[0].State)
	}
	if jobPage.Jobs[0].RiskClass != jobs.RiskClassMutate {
		t.Errorf("Job risk class = %v, want Mutate", jobPage.Jobs[0].RiskClass)
	}

	// JobFilter.JobID round-trips through toJobQuery — the Job-detail
	// screen's one aggregate read (#423). An unknown id is an empty page,
	// never every Job.
	onePage, err := q.QueryJobs(ctx, capability.JobFilter{JobID: "job-1"}, capability.PageRequest{})
	if err != nil {
		t.Fatalf("QueryJobs(JobID): %v", err)
	}
	if len(onePage.Jobs) != 1 || onePage.Jobs[0].JobID != "job-1" {
		t.Fatalf("QueryJobs(JobID) = %+v, want exactly [job-1]", onePage.Jobs)
	}
	nonePage, err := q.QueryJobs(ctx, capability.JobFilter{JobID: "job-nope"}, capability.PageRequest{})
	if err != nil {
		t.Fatalf("QueryJobs(unknown JobID): %v", err)
	}
	if len(nonePage.Jobs) != 0 {
		t.Fatalf("QueryJobs(unknown JobID) = %+v, want an empty page", nonePage.Jobs)
	}

	taskPage, err := q.QueryTasks(ctx, capability.TaskFilter{JobID: "job-1"}, capability.PageRequest{})
	if err != nil {
		t.Fatalf("QueryTasks: %v", err)
	}
	if len(taskPage.Tasks) != 1 {
		t.Fatalf("QueryTasks = %+v, want exactly 1 Task", taskPage.Tasks)
	}
	got := taskPage.Tasks[0]
	if got.TaskID != "task-1" || got.NodeID != "node-1" || got.Outcome != jobs.OutcomeSuccess ||
		got.RiskClass != jobs.RiskClassMutate || string(got.Stdout) != "hello" {
		t.Errorf("QueryTasks row = %+v, want task-1/node-1/Success/Mutate/hello", got)
	}
}

// TestQueries_InvalidCursor_MapsToCapabilitySentinel asserts a malformed
// cursor surfaces as capability.ErrInvalidCursor, never a store-package
// sentinel a caller of the capability layer should not have to know about.
func TestQueries_InvalidCursor_MapsToCapabilitySentinel(t *testing.T) {
	st := openQueryStore(t)
	ctx := context.Background()
	q := New(st.AuditQueries(), st.JobQueries())

	if _, err := q.QueryAudit(ctx, capability.AuditFilter{}, capability.PageRequest{Cursor: "not-a-cursor!!"}); err != capability.ErrInvalidCursor {
		t.Errorf("QueryAudit: err = %v, want capability.ErrInvalidCursor", err)
	}
	if _, err := q.QueryJobs(ctx, capability.JobFilter{}, capability.PageRequest{Cursor: "not-a-cursor!!"}); err != capability.ErrInvalidCursor {
		t.Errorf("QueryJobs: err = %v, want capability.ErrInvalidCursor", err)
	}
}

// TestMapping_JobSummaryCarriesTheWholeDispatchAttribution pins the mapping
// this package exists to be: TOTAL in both directions. A field added to
// jobs.JobSummary and forgotten here is a field the capability layer's callers
// never see, and the omission is silent — the row still renders, just without
// the half of spec 04's acceptance criterion 2 that says FOR WHOM and WHO
// APPROVED.
func TestMapping_JobSummaryCarriesTheWholeDispatchAttribution(t *testing.T) {
	args := map[string]string{"unit": "nginx"}
	argv := []string{"/bin/systemctl", "restart", "nginx"}
	counts := map[jobs.Outcome]int{jobs.OutcomeSuccess: 3}

	got := fromJobSummary(jobs.JobSummary{
		JobID:              "job-1",
		OnBehalfOf:         "agent-7",
		ApprovalID:         "appr-9",
		GrantID:            "grant-3",
		Args:               args,
		RawExecArgv:        argv,
		Counts:             counts,
		Requester:          "gleipnir",
		RequesterAccountID: "acct-1",
		RequesterKind:      "machine",
	})

	if got.OnBehalfOf != "agent-7" || got.ApprovalID != "appr-9" || got.GrantID != "grant-3" {
		t.Errorf("attribution did not cross the seam: %+v", got)
	}
	if got.RequesterKind != "machine" {
		t.Errorf("RequesterKind did not cross the seam: %+v", got)
	}
	if !reflect.DeepEqual(got.Args, args) || !reflect.DeepEqual(got.RawExecArgv, argv) {
		t.Errorf("what was asked for did not cross the seam: Args=%#v Argv=%#v", got.Args, got.RawExecArgv)
	}

	// Nothing shares a backing store across the boundary. An alias is the
	// capability layer's caller quietly mutating internal/jobs' value.
	args["unit"] = "mutated"
	argv[0] = "mutated"
	counts[jobs.OutcomeSuccess] = 99
	if got.Args["unit"] != "nginx" {
		t.Error("JobSummary.Args is an ALIAS of the internal map, not a copy")
	}
	if got.RawExecArgv[0] != "/bin/systemctl" {
		t.Error("JobSummary.RawExecArgv is an ALIAS of the internal slice, not a copy")
	}
	if got.Counts[jobs.OutcomeSuccess] != 3 {
		t.Error("JobSummary.Counts is an ALIAS of the internal map, not a copy")
	}
}

// TestMapping_AuditRowDoesNotAliasItsSource is the same property on the trail
// side, so the two rows this package maps carry ONE contract rather than
// whichever one was written second.
func TestMapping_AuditRowDoesNotAliasItsSource(t *testing.T) {
	args := map[string]string{"path": "/etc/hosts"}
	argv := []string{"/bin/cat", "/etc/hosts"}

	got := fromAuditRow(audit.Row{ID: "a1", Args: args, RawExecArgv: argv})

	args["path"] = "/etc/shadow"
	argv[1] = "/etc/shadow"
	if got.Args["path"] != "/etc/hosts" {
		t.Error("AuditRow.Args is an ALIAS of the internal map, not a copy")
	}
	if got.RawExecArgv[1] != "/etc/hosts" {
		t.Error("AuditRow.RawExecArgv is an ALIAS of the internal slice, not a copy")
	}
}

// TestMapping_JobFilterCarriesOnBehalfOf: a filter field the mapping drops is
// a filter that silently matches everything.
func TestMapping_JobFilterCarriesOnBehalfOf(t *testing.T) {
	if got := toJobQuery(capability.JobFilter{OnBehalfOf: "agent-7"}).OnBehalfOf; got != "agent-7" {
		t.Errorf("toJobQuery dropped OnBehalfOf (got %q) — the filter would silently match every Job", got)
	}
}

func TestMapping_JobFilterCarriesOrderAndCount(t *testing.T) {
	got := toJobQuery(capability.JobFilter{Order: jobs.JobOrderOldestFirst, CountMatching: true})
	if got.Order != jobs.JobOrderOldestFirst || !got.CountMatching {
		t.Errorf("toJobQuery = %+v — dropping either asks the store for a different page than the Console named", got)
	}
	if zero := toJobQuery(capability.JobFilter{}); zero.Order != jobs.JobOrderNewestFirst || zero.CountMatching {
		t.Errorf("a zero filter maps to %+v, want newest first with no count", zero)
	}
}

func TestMapping_JobPageCarriesMatching(t *testing.T) {
	if got := fromJobPage(jobs.JobPage{Matching: 12, Next: "n", Limit: 5}); got.Matching != 12 || got.Next != "n" || got.Limit != 5 {
		t.Errorf("fromJobPage = %+v, want Matching 12 carried with Next and Limit", got)
	}
}

// TestCapabilityJobSummary_HasNoOutputField mirrors the store-side guard on
// the seam the Console actually reads. ADR-0025: a Job list is not a path to
// captured output, at any age.
func TestCapabilityJobSummary_HasNoOutputField(t *testing.T) {
	rt := reflect.TypeOf(capability.JobSummary{})
	for i := 0; i < rt.NumField(); i++ {
		f := rt.Field(i)
		switch f.Name {
		case "Stdout", "Stderr", "Output", "Truncated":
			t.Errorf("capability.JobSummary has a %s field — see AuditRow's doc comment (ADR-0025)", f.Name)
		}
		if f.Type.Kind() == reflect.Slice && f.Type.Elem().Kind() == reflect.Uint8 {
			t.Errorf("capability.JobSummary.%s is a []byte — the only bytes a Task produces are its output", f.Name)
		}
	}
}
