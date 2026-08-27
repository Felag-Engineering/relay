package store

import (
	"context"
	"reflect"
	"testing"
	"time"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/audit"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/jobs"
)

// createJobFixture persists a Job with one Stage and the given Tasks (each
// CreateTask'd Pending, then transitioned per its own State/Outcome), for the
// jobquery.go tests below.
func createJobFixture(t *testing.T, ctx context.Context, st *Store, jobID string, createdAt time.Time, tasks []jobs.Task) {
	t.Helper()
	if err := st.Jobs().CreateJob(ctx, jobs.Job{ID: jobID, CreatedAt: createdAt}); err != nil {
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

// TestJobQuery_RequesterJoin covers a Job WITH an audit dispatch row and a
// Job WITHOUT one yet (in-flight): both must still be listed, and only the
// first carries Requester/RequesterAccountID/Selector.
func TestJobQuery_RequesterJoin(t *testing.T) {
	st, _ := openTestStore(t)
	ctx := context.Background()
	base := time.Date(2026, 8, 20, 0, 0, 0, 0, time.UTC)

	createJobFixture(t, ctx, st, "job-attributed", base, []jobs.Task{
		{ID: "job-attributed-t1", NodeID: "node-1", Action: jobs.Action{Kind: jobs.ActionOperation, OperationName: "system.facts", RiskClass: jobs.RiskClassRead}, State: jobs.DispatchStateResolved, Outcome: jobs.OutcomeSuccess},
	})
	dispatchAuditRecord(t, ctx, st, "audit-1", "job-attributed", "relay:env=prod", "acct-1", "gleipnir", base)

	// In-flight: the Task exists (Dispatched), but the audit record has not
	// been written yet — capability/service.go writes it only after
	// disp.run returns.
	createJobFixture(t, ctx, st, "job-inflight", base, []jobs.Task{
		{ID: "job-inflight-t1", NodeID: "node-1", Action: jobs.Action{Kind: jobs.ActionOperation, OperationName: "system.facts", RiskClass: jobs.RiskClassRead}, State: jobs.DispatchStateDispatched},
	})

	page, err := st.JobQueries().QueryJobs(ctx, jobs.JobQuery{}, 0, "")
	if err != nil {
		t.Fatalf("QueryJobs: %v", err)
	}
	byID := map[string]jobs.JobSummary{}
	for _, j := range page.Jobs {
		byID[j.JobID] = j
	}

	attributed, ok := byID["job-attributed"]
	if !ok {
		t.Fatal("job-attributed missing from QueryJobs")
	}
	if attributed.Requester != "gleipnir" || attributed.RequesterAccountID != "acct-1" || attributed.Selector != "relay:env=prod" {
		t.Errorf("job-attributed = %+v, want Requester=gleipnir RequesterAccountID=acct-1 Selector=relay:env=prod", attributed)
	}

	inflight, ok := byID["job-inflight"]
	if !ok {
		t.Fatal("job-inflight (no audit row yet) missing from QueryJobs — an in-flight Job must never be hidden by a race with its own audit write")
	}
	if inflight.Requester != "" || inflight.RequesterAccountID != "" || inflight.Selector != "" {
		t.Errorf("job-inflight = %+v, want empty Requester/RequesterAccountID/Selector", inflight)
	}
	if inflight.State != jobs.JobStateRunning {
		t.Errorf("job-inflight.State = %v, want Running", inflight.State)
	}
}

// TestJobQuery_Filters exercises State, RequesterAccountID, Operation,
// RiskClass, and the time window, each alone and combined in one call.
func TestJobQuery_Filters(t *testing.T) {
	st, _ := openTestStore(t)
	ctx := context.Background()
	base := time.Date(2026, 8, 20, 0, 0, 0, 0, time.UTC)

	createJobFixture(t, ctx, st, "job-target", base, []jobs.Task{
		{ID: "job-target-t1", NodeID: "node-1", Action: jobs.Action{Kind: jobs.ActionOperation, OperationName: "file.read", RiskClass: jobs.RiskClassRead}, State: jobs.DispatchStateResolved, Outcome: jobs.OutcomeSuccess},
	})
	dispatchAuditRecord(t, ctx, st, "audit-target", "job-target", "relay:env=prod", "acct-target", "gleipnir", base)

	createJobFixture(t, ctx, st, "job-other-op", base, []jobs.Task{
		{ID: "job-other-op-t1", NodeID: "node-1", Action: jobs.Action{Kind: jobs.ActionOperation, OperationName: "system.facts", RiskClass: jobs.RiskClassRead}, State: jobs.DispatchStateResolved, Outcome: jobs.OutcomeSuccess},
	})
	dispatchAuditRecord(t, ctx, st, "audit-other-op", "job-other-op", "relay:env=prod", "acct-target", "gleipnir", base)

	createJobFixture(t, ctx, st, "job-other-account", base, []jobs.Task{
		{ID: "job-other-account-t1", NodeID: "node-1", Action: jobs.Action{Kind: jobs.ActionOperation, OperationName: "file.read", RiskClass: jobs.RiskClassRead}, State: jobs.DispatchStateResolved, Outcome: jobs.OutcomeSuccess},
	})
	dispatchAuditRecord(t, ctx, st, "audit-other-account", "job-other-account", "relay:env=prod", "acct-other", "someone-else", base)

	createJobFixture(t, ctx, st, "job-mutate", base, []jobs.Task{
		{ID: "job-mutate-t1", NodeID: "node-1", Action: jobs.Action{Kind: jobs.ActionOperation, OperationName: "file.read", RiskClass: jobs.RiskClassMutate}, State: jobs.DispatchStateResolved, Outcome: jobs.OutcomeSuccess},
	})
	dispatchAuditRecord(t, ctx, st, "audit-mutate", "job-mutate", "relay:env=prod", "acct-target", "gleipnir", base)

	createJobFixture(t, ctx, st, "job-outside-window", base.Add(48*time.Hour), []jobs.Task{
		{ID: "job-outside-window-t1", NodeID: "node-1", Action: jobs.Action{Kind: jobs.ActionOperation, OperationName: "file.read", RiskClass: jobs.RiskClassRead}, State: jobs.DispatchStateResolved, Outcome: jobs.OutcomeSuccess},
	})
	dispatchAuditRecord(t, ctx, st, "audit-outside-window", "job-outside-window", "relay:env=prod", "acct-target", "gleipnir", base.Add(48*time.Hour))

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
