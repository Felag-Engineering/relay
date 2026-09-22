package store

import (
	"context"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/audit"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/jobs"
)

// createJobFixture persists a Job with no recorded Requester, one Stage, and
// the given Tasks (each CreateTask'd Pending, then transitioned per its own
// State/Outcome), for the jobquery.go tests below.
func createJobFixture(t *testing.T, ctx context.Context, st *Store, jobID string, createdAt time.Time, tasks []jobs.Task) {
	t.Helper()
	createJobFixtureBy(t, ctx, st, jobID, jobs.Requester{}, createdAt, tasks)
}

// createJobFixtureBy is createJobFixture with an explicit Requester (#616),
// for the tests that need to prove the requester now comes from the Job row
// rather than the audit trail.
func createJobFixtureBy(t *testing.T, ctx context.Context, st *Store, jobID string, req jobs.Requester, createdAt time.Time, tasks []jobs.Task) {
	t.Helper()
	if err := st.Jobs().CreateJob(ctx, jobs.Job{ID: jobID, CreatedAt: createdAt, Requester: req}); err != nil {
		t.Fatalf("CreateJob(%s): %v", jobID, err)
	}
	stageID := jobID + "-stage"
	if err := st.Jobs().AddStage(ctx, jobs.Stage{ID: stageID, JobID: jobID, Index: 0}); err != nil {
		t.Fatalf("AddStage(%s): %v", jobID, err)
	}
	taskRepo := st.Tasks()
	for _, task := range tasks {
		task.JobID = jobID
		task.StageID = stageID
		if task.CreatedAt.IsZero() {
			task.CreatedAt = createdAt
		}
		wantState := task.State
		task.State = jobs.DispatchStatePending
		if err := taskRepo.CreateTask(ctx, task); err != nil {
			t.Fatalf("CreateTask(%s): %v", task.ID, err)
		}
		if wantState == jobs.DispatchStatePending {
			continue
		}
		if err := taskRepo.MarkDispatched(ctx, task.ID, createdAt); err != nil {
			t.Fatalf("MarkDispatched(%s): %v", task.ID, err)
		}
		if wantState == jobs.DispatchStateDispatched {
			continue
		}
		if err := taskRepo.Resolve(ctx, task.ID, jobs.Result{
			Outcome: task.Outcome, ExitCode: task.ExitCode, Stdout: task.Stdout, Stderr: task.Stderr,
		}); err != nil {
			t.Fatalf("Resolve(%s): %v", task.ID, err)
		}
	}
}

// dispatchAuditRecord appends a KindDispatch audit row attributing jobID to
// accountID/accountName over selector — the record jobquery.go's
// QueryJobs joins Requester/RequesterAccountID/Selector from.
func dispatchAuditRecord(t *testing.T, ctx context.Context, st *Store, id, jobID, selector, accountID, accountName string, ts time.Time) {
	t.Helper()
	if err := st.Audit().Append(ctx, audit.Record{
		ID:        id,
		Timestamp: ts,
		Kind:      audit.KindDispatch,
		Principal: accountName + ":operator",
		Attribution: audit.Attribution{
			Verified: audit.Verified{AccountID: accountID, AccountName: accountName, Role: "operator"},
		},
		Selector:      selector,
		JobID:         jobID,
		ActionKind:    "operation",
		OperationName: "system.facts",
	}); err != nil {
		t.Fatalf("append dispatch audit record %s: %v", id, err)
	}
}

// TestJobQuery_StateDerivation covers pending/dispatched/resolved/zero-Task
// Jobs.
func TestJobQuery_StateDerivation(t *testing.T) {
	st, _ := openTestStore(t)
	ctx := context.Background()
	base := time.Date(2026, 8, 20, 0, 0, 0, 0, time.UTC)

	createJobFixture(t, ctx, st, "job-pending", base, []jobs.Task{
		{ID: "job-pending-t1", NodeID: "node-1", Action: jobs.Action{Kind: jobs.ActionOperation, OperationName: "system.facts", RiskClass: jobs.RiskClassRead}, State: jobs.DispatchStatePending},
	})
	createJobFixture(t, ctx, st, "job-dispatched", base, []jobs.Task{
		{ID: "job-dispatched-t1", NodeID: "node-1", Action: jobs.Action{Kind: jobs.ActionOperation, OperationName: "system.facts", RiskClass: jobs.RiskClassRead}, State: jobs.DispatchStateDispatched},
	})
	createJobFixture(t, ctx, st, "job-resolved", base, []jobs.Task{
		{ID: "job-resolved-t1", NodeID: "node-1", Action: jobs.Action{Kind: jobs.ActionOperation, OperationName: "system.facts", RiskClass: jobs.RiskClassRead}, State: jobs.DispatchStateResolved, Outcome: jobs.OutcomeSuccess},
	})
	createJobFixture(t, ctx, st, "job-empty", base, nil)

	page, err := st.JobQueries().QueryJobs(ctx, jobs.JobQuery{}, 0, "")
	if err != nil {
		t.Fatalf("QueryJobs: %v", err)
	}

	want := map[string]jobs.JobState{
		"job-pending":    jobs.JobStateRunning,
		"job-dispatched": jobs.JobStateRunning,
		"job-resolved":   jobs.JobStateComplete,
		"job-empty":      jobs.JobStateComplete,
	}
	got := map[string]jobs.JobState{}
	for _, j := range page.Jobs {
		got[j.JobID] = j.State
	}
	for id, w := range want {
		if got[id] != w {
			t.Errorf("job %s state = %v, want %v", id, got[id], w)
		}
	}
}

// nonDispatchAuditRecord appends a job_id-carrying audit row of the given
// Kind (KindRefusal or KindJobCancel) attributed to accountID — the shape
// CancelJob's refuseCancel/RecordCancel write (capability/service.go). Used
// by TestJobQuery_RequesterJoinIgnoresNonDispatchRows to prove these rows
// never feed the requester join.
func nonDispatchAuditRecord(t *testing.T, ctx context.Context, st *Store, id, kind, jobID, accountID, accountName string, ts time.Time) {
	t.Helper()
	if err := st.Audit().Append(ctx, audit.Record{
		ID:        id,
		Timestamp: ts,
		Kind:      kind,
		Principal: accountName + ":operator",
		Attribution: audit.Attribution{
			Verified: audit.Verified{AccountID: accountID, AccountName: accountName, Role: "operator"},
		},
		JobID: jobID,
	}); err != nil {
		t.Fatalf("append %s audit record %s: %v", kind, id, err)
	}
}

// TestJobQuery_RequesterIsNeverTakenFromTheAuditTrail (#616) proves the
// requester now comes ONLY from the Job row: an audit dispatch/refusal/
// cancel row attributed to a different Account never wins over the Job's
// own recorded Requester, and a Job with no recorded Requester reads back
// empty even though its audit trail names somebody.
//
// This supersedes the pre-#616 concern the old test name recorded — that a
// refused caller's account_id might win a MIN(account_id) audit join — which
// no longer applies now that the requester is a plain column on the jobs
// row, not an aggregate over audit at all.
func TestJobQuery_RequesterIsNeverTakenFromTheAuditTrail(t *testing.T) {
	st, _ := openTestStore(t)
	ctx := context.Background()
	base := time.Date(2026, 8, 20, 0, 0, 0, 0, time.UTC)

	const recordedRequester = "acct-x-recorded"
	const auditDispatcher = "acct-y-audit-dispatch"
	const auditRefuser = "acct-z-audit-refusal"

	// Job A: recorded requester X, but its audit trail holds a dispatch row
	// for Y and refusal/cancel rows for Z. Its requester must read X.
	req := jobs.Requester{AccountID: recordedRequester, AccountName: "recorded-machine", Kind: "machine"}
	createJobFixtureBy(t, ctx, st, "job-a", req, base, []jobs.Task{
		{ID: "job-a-t1", NodeID: "node-1", Action: jobs.Action{Kind: jobs.ActionOperation, OperationName: "system.facts", RiskClass: jobs.RiskClassRead}, State: jobs.DispatchStateResolved, Outcome: jobs.OutcomeSuccess},
	})
	dispatchAuditRecord(t, ctx, st, "audit-a-dispatch", "job-a", "relay:env=prod", auditDispatcher, "audit-dispatcher", base)
	nonDispatchAuditRecord(t, ctx, st, "audit-a-refusal", audit.KindRefusal, "job-a", auditRefuser, "audit-refuser", base)
	nonDispatchAuditRecord(t, ctx, st, "audit-a-cancel", audit.KindJobCancel, "job-a", auditRefuser, "audit-refuser", base)

	// Job B: no recorded requester, but a dispatch audit row for Y. Its
	// requester must read empty — never inferred from the trail.
	createJobFixture(t, ctx, st, "job-b", base, []jobs.Task{
		{ID: "job-b-t1", NodeID: "node-1", Action: jobs.Action{Kind: jobs.ActionOperation, OperationName: "system.facts", RiskClass: jobs.RiskClassRead}, State: jobs.DispatchStateResolved, Outcome: jobs.OutcomeSuccess},
	})
	dispatchAuditRecord(t, ctx, st, "audit-b-dispatch", "job-b", "relay:env=prod", auditDispatcher, "audit-dispatcher", base)

	page, err := st.JobQueries().QueryJobs(ctx, jobs.JobQuery{}, 0, "")
	if err != nil {
		t.Fatalf("QueryJobs: %v", err)
	}
	byID := map[string]jobs.JobSummary{}
	for _, j := range page.Jobs {
		byID[j.JobID] = j
	}

	a, ok := byID["job-a"]
	if !ok {
		t.Fatal("job-a missing from QueryJobs")
	}
	if a.RequesterAccountID != recordedRequester || a.Requester != "recorded-machine" || a.RequesterKind != "machine" {
		t.Errorf("job-a requester = %+v, want ID=%s Name=recorded-machine Kind=machine", a, recordedRequester)
	}
	// Selector still comes from the dispatch row, and only the dispatch row:
	// kind = 'dispatch' still guards it against the refusal row.
	if a.Selector != "relay:env=prod" {
		t.Errorf("job-a.Selector = %q, want relay:env=prod (from the dispatch row, not the refusal row)", a.Selector)
	}

	b, ok := byID["job-b"]
	if !ok {
		t.Fatal("job-b missing from QueryJobs")
	}
	if b.RequesterAccountID != "" || b.Requester != "" || b.RequesterKind != "" {
		t.Errorf("job-b requester = %+v, want all empty (no recorded requester, despite a dispatch audit row)", b)
	}
}

// TestJobQuery_RequesterReadsFromTheJobRow (#616) proves an IN-FLIGHT Job (a
// Dispatched Task, no audit row yet) already carries its requester — read
// from the Job row, not the audit trail — while Selector stays empty until
// the audit row lands.
func TestJobQuery_RequesterReadsFromTheJobRow(t *testing.T) {
	st, _ := openTestStore(t)
	ctx := context.Background()
	base := time.Date(2026, 8, 20, 0, 0, 0, 0, time.UTC)

	req := jobs.Requester{AccountID: "acct-1", AccountName: "gleipnir", Kind: "machine"}
	createJobFixtureBy(t, ctx, st, "job-inflight", req, base, []jobs.Task{
		{ID: "job-inflight-t1", NodeID: "node-1", Action: jobs.Action{Kind: jobs.ActionOperation, OperationName: "system.facts", RiskClass: jobs.RiskClassRead}, State: jobs.DispatchStateDispatched},
	})

	page, err := st.JobQueries().QueryJobs(ctx, jobs.JobQuery{}, 0, "")
	if err != nil {
		t.Fatalf("QueryJobs: %v", err)
	}
	if len(page.Jobs) != 1 || page.Jobs[0].JobID != "job-inflight" {
		t.Fatalf("QueryJobs = %+v, want exactly [job-inflight]", page.Jobs)
	}

	inflight := page.Jobs[0]
	if inflight.RequesterAccountID != "acct-1" || inflight.Requester != "gleipnir" || inflight.RequesterKind != "machine" {
		t.Errorf("job-inflight requester = %+v, want ID=acct-1 Name=gleipnir Kind=machine — read while every Task is still in flight, no audit row exists yet",
			inflight)
	}
	if inflight.Selector != "" {
		t.Errorf("job-inflight.Selector = %q, want empty — the audit row has not been written yet", inflight.Selector)
	}
	if inflight.State != jobs.JobStateRunning {
		t.Errorf("job-inflight.State = %v, want Running", inflight.State)
	}
}

// TestJobQuery_Filters exercises State, RequesterAccountID, Operation,
// RiskClass, and the time window, each alone and combined in one call. The
// requester is seeded on the Job row (#616), not the audit trail.
func TestJobQuery_Filters(t *testing.T) {
	st, _ := openTestStore(t)
	ctx := context.Background()
	base := time.Date(2026, 8, 20, 0, 0, 0, 0, time.UTC)

	target := jobs.Requester{AccountID: "acct-target", AccountName: "gleipnir", Kind: "machine"}
	other := jobs.Requester{AccountID: "acct-other", AccountName: "someone-else", Kind: "machine"}

	createJobFixtureBy(t, ctx, st, "job-target", target, base, []jobs.Task{
		{ID: "job-target-t1", NodeID: "node-1", Action: jobs.Action{Kind: jobs.ActionOperation, OperationName: "file.read", RiskClass: jobs.RiskClassRead}, State: jobs.DispatchStateResolved, Outcome: jobs.OutcomeSuccess},
	})
	dispatchAuditRecord(t, ctx, st, "audit-target", "job-target", "relay:env=prod", "acct-target", "gleipnir", base)

	createJobFixtureBy(t, ctx, st, "job-other-op", target, base, []jobs.Task{
		{ID: "job-other-op-t1", NodeID: "node-1", Action: jobs.Action{Kind: jobs.ActionOperation, OperationName: "system.facts", RiskClass: jobs.RiskClassRead}, State: jobs.DispatchStateResolved, Outcome: jobs.OutcomeSuccess},
	})
	dispatchAuditRecord(t, ctx, st, "audit-other-op", "job-other-op", "relay:env=prod", "acct-target", "gleipnir", base)

	createJobFixtureBy(t, ctx, st, "job-other-account", other, base, []jobs.Task{
		{ID: "job-other-account-t1", NodeID: "node-1", Action: jobs.Action{Kind: jobs.ActionOperation, OperationName: "file.read", RiskClass: jobs.RiskClassRead}, State: jobs.DispatchStateResolved, Outcome: jobs.OutcomeSuccess},
	})
	dispatchAuditRecord(t, ctx, st, "audit-other-account", "job-other-account", "relay:env=prod", "acct-other", "someone-else", base)

	createJobFixtureBy(t, ctx, st, "job-mutate", target, base, []jobs.Task{
		{ID: "job-mutate-t1", NodeID: "node-1", Action: jobs.Action{Kind: jobs.ActionOperation, OperationName: "file.read", RiskClass: jobs.RiskClassMutate}, State: jobs.DispatchStateResolved, Outcome: jobs.OutcomeSuccess},
	})
	dispatchAuditRecord(t, ctx, st, "audit-mutate", "job-mutate", "relay:env=prod", "acct-target", "gleipnir", base)

	createJobFixtureBy(t, ctx, st, "job-outside-window", target, base.Add(48*time.Hour), []jobs.Task{
		{ID: "job-outside-window-t1", NodeID: "node-1", Action: jobs.Action{Kind: jobs.ActionOperation, OperationName: "file.read", RiskClass: jobs.RiskClassRead}, State: jobs.DispatchStateResolved, Outcome: jobs.OutcomeSuccess},
	})
	dispatchAuditRecord(t, ctx, st, "audit-outside-window", "job-outside-window", "relay:env=prod", "acct-target", "gleipnir", base.Add(48*time.Hour))

	// No recorded requester, even though its audit trail names acct-target:
	// the RequesterAccountID filter must not match it (#616, no inference).
	createJobFixture(t, ctx, st, "job-no-requester", base, []jobs.Task{
		{ID: "job-no-requester-t1", NodeID: "node-1", Action: jobs.Action{Kind: jobs.ActionOperation, OperationName: "file.read", RiskClass: jobs.RiskClassRead}, State: jobs.DispatchStateResolved, Outcome: jobs.OutcomeSuccess},
	})
	dispatchAuditRecord(t, ctx, st, "audit-no-requester", "job-no-requester", "relay:env=prod", "acct-target", "gleipnir", base)

	readClass := jobs.RiskClassRead
	complete := jobs.JobStateComplete

	page, err := st.JobQueries().QueryJobs(ctx, jobs.JobQuery{
		State:              &complete,
		RequesterAccountID: "acct-target",
		Operation:          "file.read",
		RiskClass:          &readClass,
		Since:              base.Add(-time.Hour),
		Until:              base.Add(time.Hour),
	}, 0, "")
	if err != nil {
		t.Fatalf("QueryJobs: %v", err)
	}
	if len(page.Jobs) != 1 || page.Jobs[0].JobID != "job-target" {
		t.Fatalf("QueryJobs = %+v, want exactly [job-target]", page.Jobs)
	}
}

// TestJobQuery_OutcomeCounts covers Total/Unresolved/Counts across a mix of
// resolved and unresolved Tasks.
func TestJobQuery_OutcomeCounts(t *testing.T) {
	st, _ := openTestStore(t)
	ctx := context.Background()
	base := time.Date(2026, 8, 20, 0, 0, 0, 0, time.UTC)

	createJobFixture(t, ctx, st, "job-mixed", base, []jobs.Task{
		{ID: "job-mixed-t1", NodeID: "node-1", Action: jobs.Action{Kind: jobs.ActionOperation, OperationName: "system.facts", RiskClass: jobs.RiskClassRead}, State: jobs.DispatchStateResolved, Outcome: jobs.OutcomeSuccess},
		{ID: "job-mixed-t2", NodeID: "node-2", Action: jobs.Action{Kind: jobs.ActionOperation, OperationName: "system.facts", RiskClass: jobs.RiskClassRead}, State: jobs.DispatchStateResolved, Outcome: jobs.OutcomeSuccess},
		{ID: "job-mixed-t3", NodeID: "node-3", Action: jobs.Action{Kind: jobs.ActionOperation, OperationName: "system.facts", RiskClass: jobs.RiskClassRead}, State: jobs.DispatchStateResolved, Outcome: jobs.OutcomeFailure},
		{ID: "job-mixed-t4", NodeID: "node-4", Action: jobs.Action{Kind: jobs.ActionOperation, OperationName: "system.facts", RiskClass: jobs.RiskClassRead}, State: jobs.DispatchStateDispatched},
	})

	page, err := st.JobQueries().QueryJobs(ctx, jobs.JobQuery{}, 0, "")
	if err != nil {
		t.Fatalf("QueryJobs: %v", err)
	}
	var summary jobs.JobSummary
	for _, j := range page.Jobs {
		if j.JobID == "job-mixed" {
			summary = j
		}
	}
	if summary.Total != 4 {
		t.Errorf("Total = %d, want 4", summary.Total)
	}
	if summary.Unresolved != 1 {
		t.Errorf("Unresolved = %d, want 1", summary.Unresolved)
	}
	want := map[jobs.Outcome]int{jobs.OutcomeSuccess: 2, jobs.OutcomeFailure: 1}
	if !reflect.DeepEqual(summary.Counts, want) {
		t.Errorf("Counts = %v, want %v", summary.Counts, want)
	}
	if summary.State != jobs.JobStateRunning {
		t.Errorf("State = %v, want Running (one Task still Dispatched)", summary.State)
	}
}

// TestQueryTasks_FilterAndPaginate covers Outcome filtering and pagination
// over a single Job's Tasks.
func TestQueryTasks_FilterAndPaginate(t *testing.T) {
	st, _ := openTestStore(t)
	ctx := context.Background()
	base := time.Date(2026, 8, 20, 0, 0, 0, 0, time.UTC)

	var tasks []jobs.Task
	for i := 0; i < 7; i++ {
		outcome := jobs.OutcomeSuccess
		if i%3 == 0 {
			outcome = jobs.OutcomeFailure
		}
		tasks = append(tasks, jobs.Task{
			ID:     taskIDFor(i),
			NodeID: taskIDFor(i) + "-node",
			Action: jobs.Action{Kind: jobs.ActionOperation, OperationName: "system.facts", RiskClass: jobs.RiskClassMutate},
			State:  jobs.DispatchStateResolved, Outcome: outcome,
			Stdout: []byte("out-" + taskIDFor(i)),
		})
	}
	createJobFixture(t, ctx, st, "job-tasks", base, tasks)

	// Unfiltered pagination: page through at limit 2 and assert set equality
	// with an unpaginated read, no duplicates, no gaps.
	var pagedIDs []string
	cursor := ""
	for i := 0; i < 10; i++ {
		page, err := st.JobQueries().QueryTasks(ctx, jobs.TaskQuery{JobID: "job-tasks"}, 2, cursor)
		if err != nil {
			t.Fatalf("QueryTasks: %v", err)
		}
		for _, task := range page.Tasks {
			pagedIDs = append(pagedIDs, task.TaskID)
			if task.RiskClass != jobs.RiskClassMutate {
				t.Errorf("task %s RiskClass = %v, want RiskClassMutate", task.TaskID, task.RiskClass)
			}
			if len(task.Stdout) == 0 {
				t.Errorf("task %s Stdout is empty, want captured output", task.TaskID)
			}
		}
		if page.Next == "" {
			break
		}
		cursor = page.Next
	}
	if len(pagedIDs) != len(tasks) {
		t.Fatalf("paged task count = %d, want %d", len(pagedIDs), len(tasks))
	}
	seen := map[string]bool{}
	for _, id := range pagedIDs {
		if seen[id] {
			t.Errorf("task %s returned more than once across pages", id)
		}
		seen[id] = true
	}

	// Outcome filter.
	failure := jobs.OutcomeFailure
	page, err := st.JobQueries().QueryTasks(ctx, jobs.TaskQuery{JobID: "job-tasks", Outcome: &failure}, 0, "")
	if err != nil {
		t.Fatalf("QueryTasks with Outcome filter: %v", err)
	}
	if len(page.Tasks) != 3 { // i = 0, 3, 6
		t.Errorf("filtered task count = %d, want 3", len(page.Tasks))
	}
	for _, task := range page.Tasks {
		if task.Outcome != jobs.OutcomeFailure {
			t.Errorf("task %s Outcome = %v, want Failure", task.TaskID, task.Outcome)
		}
	}
}

func taskIDFor(i int) string {
	const letters = "abcdefghij"
	return "task-" + string(letters[i])
}

// TestTaskSummary_NoTruncatedField pins the coordinator's B3 ruling: the
// tasks table has no truncated column, so jobs.TaskSummary must not claim one.
func TestTaskSummary_NoTruncatedField(t *testing.T) {
	typ := reflect.TypeOf(jobs.TaskSummary{})
	if _, ok := typ.FieldByName("Truncated"); ok {
		t.Error("jobs.TaskSummary has a Truncated field with no backing column (coordinator ruling B3)")
	}
}

// TestJobQuery_SingleJob is the Job-detail screen's whole data acquisition:
// one Job's exact per-outcome tally as ONE aggregate row, and an unknown
// JobID as an EMPTY page rather than every Job. The second half is the
// fail-open shape to guard against — a filter that silently degrades to "no
// predicate" would hand a screen the wrong Job's counts.
func TestJobQuery_SingleJob(t *testing.T) {
	st, _ := openTestStore(t)
	ctx := context.Background()
	base := time.Date(2026, 8, 20, 0, 0, 0, 0, time.UTC)

	createJobFixtureBy(t, ctx, st, "job-wanted", jobs.Requester{AccountID: "acct-1", AccountName: "gleipnir", Kind: "machine"}, base, []jobs.Task{
		{ID: "job-wanted-t1", NodeID: "node-1", Action: jobs.Action{Kind: jobs.ActionOperation, OperationName: "service.restart", RiskClass: jobs.RiskClassMutate}, State: jobs.DispatchStateResolved, Outcome: jobs.OutcomeSuccess},
		{ID: "job-wanted-t2", NodeID: "node-2", Action: jobs.Action{Kind: jobs.ActionOperation, OperationName: "service.restart", RiskClass: jobs.RiskClassMutate}, State: jobs.DispatchStateResolved, Outcome: jobs.OutcomeDeniedByPolicy},
		{ID: "job-wanted-t3", NodeID: "node-3", Action: jobs.Action{Kind: jobs.ActionOperation, OperationName: "service.restart", RiskClass: jobs.RiskClassMutate}, State: jobs.DispatchStateDispatched},
	})
	dispatchAuditRecord(t, ctx, st, "audit-wanted", "job-wanted", "node:role=web", "acct-1", "gleipnir", base)

	createJobFixture(t, ctx, st, "job-other", base, []jobs.Task{
		{ID: "job-other-t1", NodeID: "node-9", Action: jobs.Action{Kind: jobs.ActionOperation, OperationName: "system.facts", RiskClass: jobs.RiskClassRead}, State: jobs.DispatchStateResolved, Outcome: jobs.OutcomeFailure},
	})
	dispatchAuditRecord(t, ctx, st, "audit-other", "job-other", "node:role=db", "acct-2", "someone-else", base)

	page, err := st.JobQueries().QueryJobs(ctx, jobs.JobQuery{JobID: "job-wanted"}, 0, "")
	if err != nil {
		t.Fatalf("QueryJobs: %v", err)
	}
	if len(page.Jobs) != 1 || page.Jobs[0].JobID != "job-wanted" {
		t.Fatalf("QueryJobs = %+v, want exactly [job-wanted]", page.Jobs)
	}
	got := page.Jobs[0]
	if got.Total != 3 || got.Unresolved != 1 {
		t.Errorf("Total/Unresolved = %d/%d, want 3/1", got.Total, got.Unresolved)
	}
	want := map[jobs.Outcome]int{jobs.OutcomeSuccess: 1, jobs.OutcomeDeniedByPolicy: 1}
	if !reflect.DeepEqual(got.Counts, want) {
		t.Errorf("Counts = %v, want %v — the other Job's failure leaked into this tally", got.Counts, want)
	}
	if got.Selector != "node:role=web" || got.Requester != "gleipnir" {
		t.Errorf("Selector/Requester = %q/%q, want node:role=web/gleipnir", got.Selector, got.Requester)
	}
	if got.RiskClass != jobs.RiskClassMutate {
		t.Errorf("RiskClass = %v, want mutate — the declared class the Job-detail screen gates output on", got.RiskClass)
	}

	page, err = st.JobQueries().QueryJobs(ctx, jobs.JobQuery{JobID: "job-that-never-existed"}, 0, "")
	if err != nil {
		t.Fatalf("QueryJobs(unknown): %v", err)
	}
	if len(page.Jobs) != 0 {
		t.Fatalf("an unknown JobID returned %d Jobs, want 0 — the filter must not fail open", len(page.Jobs))
	}
}

// TestJobQuery_SingleJobDoesNotScanEveryTask is the boundedness property of
// the Job-detail screen, asserted where it can actually be lost.
//
// SQLite cannot flatten an aggregate subquery and will not push an outer
// WHERE into the right operand of a LEFT JOIN, so `WHERE j.job_id = ?` alone
// leaves both derived tables aggregating the WHOLE of tasks and audit on
// every page view. The predicate has to be pushed into each of them, and
// nothing about the RESULTS changes when it is not — which is why the plan
// itself is the assertion.
func TestJobQuery_SingleJobDoesNotScanEveryTask(t *testing.T) {
	st, _ := openTestStore(t)
	ctx := context.Background()

	stmt, args := jobQuerySelect(jobs.JobQuery{JobID: "job-wanted"})
	conds, whereArgs := buildJobWhere(jobs.JobQuery{JobID: "job-wanted"})
	args = append(args, whereArgs...)
	stmt += ` WHERE ` + strings.Join(conds, " AND ") + ` ORDER BY j.created_at DESC, j.job_id DESC LIMIT ?`
	args = append(args, 2)

	rows, err := st.db.QueryContext(ctx, `EXPLAIN QUERY PLAN `+stmt, args...)
	if err != nil {
		t.Fatalf("EXPLAIN QUERY PLAN: %v", err)
	}
	defer rows.Close()
	var plan strings.Builder
	for rows.Next() {
		var id, parent, notused int
		var detail string
		if err := rows.Scan(&id, &parent, &notused, &detail); err != nil {
			t.Fatalf("scan plan row: %v", err)
		}
		plan.WriteString(detail)
		plan.WriteString("\n")
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate plan: %v", err)
	}

	if strings.Contains(plan.String(), "SCAN tasks") {
		t.Errorf("a single-Job query plans a full SCAN of tasks — every Job-detail page view would aggregate the whole table:\n%s", plan.String())
	}
	// Both derived tables, not just the Task one: without the pushdown the
	// audit aggregate plans "SEARCH audit ... (kind=?)", which is every
	// dispatch row ever written rather than this Job's.
	for _, want := range []string{"SEARCH tasks", "SEARCH audit"} {
		if !strings.Contains(plan.String(), want) {
			t.Errorf("a single-Job query does not %q:\n%s", want, plan.String())
		}
	}
	if strings.Contains(plan.String(), "(kind=?)") {
		t.Errorf("the audit aggregate is keyed on kind alone, so it reads every dispatch row in the trail:\n%s", plan.String())
	}
}

// dispatchAuditRecordFull appends a KindDispatch audit row carrying the whole
// attribution the Job list joins: the verified Account, the ASSERTED
// on-behalf-of, the approval and grant that released it, and what was asked
// for. One record per Node, exactly as the fan-out loop writes them.
func dispatchAuditRecordFull(t *testing.T, ctx context.Context, st *Store, id, jobID, nodeID string, outcome jobs.Outcome, ts time.Time) {
	t.Helper()
	if err := st.Audit().Append(ctx, audit.Record{
		ID:        id,
		Timestamp: ts,
		Kind:      audit.KindDispatch,
		Principal: "gleipnir:operator",
		Attribution: audit.Attribution{
			Verified: audit.Verified{AccountID: "acct-1", AccountName: "gleipnir", Role: "operator"},
			Asserted: audit.Asserted{OnBehalfOf: "agent-7"},
		},
		Selector:    "role=web",
		JobID:       jobID,
		NodeID:      nodeID,
		ActionKind:  "raw_exec",
		RawExecArgv: []string{"/bin/systemctl", "restart", "nginx"},
		Args:        map[string]string{"unit": "nginx"},
		Outcome:     outcome,
		ApprovalID:  "appr-9",
		GrantID:     "grant-3",
		Stdout:      []byte("output that must never reach a Job summary"),
	}); err != nil {
		t.Fatalf("append dispatch audit record %s: %v", id, err)
	}
}

// TestJobQuery_SummaryCarriesTheDispatchRecordsAttribution is spec 04's
// acceptance criterion 2 at the store: "who asked, FOR WHOM, WHO APPROVED,
// what happened" out of ONE query.
//
// Three dispatch records for one Job, differing only in Node and outcome — the
// shape auditsink actually writes. MIN over them must return the single base
// value they all carry, not a sample of one of them.
func TestJobQuery_SummaryCarriesTheDispatchRecordsAttribution(t *testing.T) {
	st, _ := openTestStore(t)
	ctx := context.Background()
	base := time.Date(2026, 8, 20, 0, 0, 0, 0, time.UTC)

	createJobFixture(t, ctx, st, "job-1", base, []jobs.Task{
		{ID: "job-1-t1", NodeID: "node-1", Action: jobs.Action{Kind: jobs.ActionRawExec, RiskClass: jobs.RiskClassMutate}, State: jobs.DispatchStateResolved, Outcome: jobs.OutcomeSuccess},
	})
	dispatchAuditRecordFull(t, ctx, st, "audit-1", "job-1", "node-1", jobs.OutcomeSuccess, base)
	dispatchAuditRecordFull(t, ctx, st, "audit-2", "job-1", "node-2", jobs.OutcomeDeniedByPolicy, base)
	dispatchAuditRecordFull(t, ctx, st, "audit-3", "job-1", "node-3", jobs.OutcomeSuccess, base)

	page, err := st.JobQueries().QueryJobs(ctx, jobs.JobQuery{JobID: "job-1"}, 0, "")
	if err != nil {
		t.Fatalf("QueryJobs: %v", err)
	}
	if len(page.Jobs) != 1 {
		t.Fatalf("QueryJobs returned %d rows, want 1", len(page.Jobs))
	}
	got := page.Jobs[0]

	if got.OnBehalfOf != "agent-7" {
		t.Errorf("OnBehalfOf = %q, want agent-7 — the asserted lane is half of spec 04's acceptance 2", got.OnBehalfOf)
	}
	if got.ApprovalID != "appr-9" {
		t.Errorf("ApprovalID = %q, want appr-9", got.ApprovalID)
	}
	if got.GrantID != "grant-3" {
		t.Errorf("GrantID = %q, want grant-3", got.GrantID)
	}
	if !reflect.DeepEqual(got.Args, map[string]string{"unit": "nginx"}) {
		t.Errorf("Args = %#v, want {unit: nginx}", got.Args)
	}
	if !reflect.DeepEqual(got.RawExecArgv, []string{"/bin/systemctl", "restart", "nginx"}) {
		t.Errorf("RawExecArgv = %#v, want the dispatched argv", got.RawExecArgv)
	}
}

// TestJobQuery_OnBehalfOfFilterSelects: the asserted lane is a real filter,
// matched exactly, and it selects rather than merely being carried.
func TestJobQuery_OnBehalfOfFilterSelects(t *testing.T) {
	st, _ := openTestStore(t)
	ctx := context.Background()
	base := time.Date(2026, 8, 20, 0, 0, 0, 0, time.UTC)

	for _, c := range []struct{ jobID, onBehalfOf string }{
		{"job-a", "agent-7"},
		{"job-b", "agent-9"},
	} {
		createJobFixture(t, ctx, st, c.jobID, base, []jobs.Task{
			{ID: c.jobID + "-t1", NodeID: "node-1", Action: jobs.Action{Kind: jobs.ActionOperation, OperationName: "system.facts", RiskClass: jobs.RiskClassRead}, State: jobs.DispatchStateResolved, Outcome: jobs.OutcomeSuccess},
		})
		if err := st.Audit().Append(ctx, audit.Record{
			ID: c.jobID + "-audit", Timestamp: base, Kind: audit.KindDispatch, JobID: c.jobID,
			Attribution: audit.Attribution{Asserted: audit.Asserted{OnBehalfOf: c.onBehalfOf}},
		}); err != nil {
			t.Fatalf("append %s: %v", c.jobID, err)
		}
	}

	page, err := st.JobQueries().QueryJobs(ctx, jobs.JobQuery{OnBehalfOf: "agent-7"}, 0, "")
	if err != nil {
		t.Fatalf("QueryJobs(OnBehalfOf): %v", err)
	}
	if len(page.Jobs) != 1 || page.Jobs[0].JobID != "job-a" {
		t.Fatalf("QueryJobs(OnBehalfOf=agent-7) = %+v, want exactly [job-a]", page.Jobs)
	}

	// Exact, never a prefix: the asserted lane is caller-claimed, and a fuzzy
	// match over it would let one agent's claim answer a question asked about
	// another's.
	none, err := st.JobQueries().QueryJobs(ctx, jobs.JobQuery{OnBehalfOf: "agent"}, 0, "")
	if err != nil {
		t.Fatalf("QueryJobs(prefix): %v", err)
	}
	if len(none.Jobs) != 0 {
		t.Errorf("OnBehalfOf=%q matched %+v — the asserted lane is an EXACT match", "agent", none.Jobs)
	}
}

// TestJobSummary_NoOutputField: a Job list must never become a path to
// captured output (ADR-0025). The SELECT names no BLOB column; this pins the
// struct so nobody adds a field for one to be scanned into.
func TestJobSummary_NoOutputField(t *testing.T) {
	rt := reflect.TypeOf(jobs.JobSummary{})
	for i := 0; i < rt.NumField(); i++ {
		f := rt.Field(i)
		switch f.Name {
		case "Stdout", "Stderr", "Output", "Truncated":
			t.Errorf("jobs.JobSummary has a %s field — a Job list must not carry captured output (ADR-0025)", f.Name)
		}
		if f.Type.Kind() == reflect.Slice && f.Type.Elem().Kind() == reflect.Uint8 {
			t.Errorf("jobs.JobSummary.%s is a []byte — the only bytes a Task produces are its output", f.Name)
		}
	}
}
