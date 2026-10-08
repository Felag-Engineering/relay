package store

import (
	"context"
	"testing"
	"time"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/audit"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/jobs"
)

// intentFixture creates an empty Job with one Stage and returns the Tasks an
// engine would hand to AppendWithTasks for it.
func intentFixture(t *testing.T, st *Store, jobID string, nodes ...string) []jobs.Task {
	t.Helper()
	ctx := context.Background()
	at := time.Date(2026, 10, 8, 0, 0, 0, 0, time.UTC)
	if err := st.Jobs().CreateJob(ctx, jobs.Job{ID: jobID, CreatedAt: at}); err != nil {
		t.Fatalf("CreateJob: %v", err)
	}
	stageID := jobID + "-stage"
	if err := st.Jobs().AddStage(ctx, jobs.Stage{ID: stageID, JobID: jobID, Index: 0}); err != nil {
		t.Fatalf("AddStage: %v", err)
	}
	var tasks []jobs.Task
	for _, n := range nodes {
		tasks = append(tasks, jobs.Task{
			ID: jobID + "-task-" + n, JobID: jobID, StageID: stageID, NodeID: n, CreatedAt: at,
			Action: jobs.Action{Kind: jobs.ActionOperation, OperationName: "system.facts", RiskClass: jobs.RiskClassRead},
		})
	}
	return tasks
}

func intentRecord(id, jobID string) audit.Record {
	return audit.Record{
		ID:         id,
		Timestamp:  time.Date(2026, 10, 8, 0, 0, 1, 0, time.UTC),
		Kind:       audit.KindDispatchIntent,
		Principal:  "alice",
		Selector:   "node:env=test",
		JobID:      jobID,
		ActionKind: "operation",
		Reason:     "risk_class=read blast_cap=passed cap_cleared=2 excluded=0 node_count=2 node_ids=n1,n2",
	}
}

func TestAppendWithTasks_CommitsTheTasksAndTheIntentTogether(t *testing.T) {
	st, path := openTestStore(t)
	ctx := context.Background()
	tasks := intentFixture(t, st, "job-1", "n1", "n2")

	if err := st.Audit().AppendWithTasks(ctx, intentRecord("aud-1", "job-1"), tasks); err != nil {
		t.Fatalf("AppendWithTasks: %v", err)
	}

	got, err := st.Tasks().ByJob(ctx, "job-1")
	if err != nil {
		t.Fatalf("ByJob tasks: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("%d Tasks persisted, want 2", len(got))
	}
	for _, task := range got {
		if task.State != jobs.DispatchStatePending {
			t.Errorf("Task %s state = %v, want Pending", task.ID, task.State)
		}
	}
	recs, err := st.Audit().ByJob(ctx, "job-1")
	if err != nil {
		t.Fatalf("ByJob audit: %v", err)
	}
	if len(recs) != 1 || recs[0].Kind != audit.KindDispatchIntent {
		t.Fatalf("audit rows = %+v, want exactly one dispatch_intent", recs)
	}
	if v := verify(t, path); !v.Intact() || v.Rows != 1 {
		t.Errorf("chain verdict = %+v, want intact with 1 row", v)
	}
}

func TestAppendWithTasks_AnUnwritableIntentLeavesNoTask(t *testing.T) {
	st, _ := openTestStore(t)
	ctx := context.Background()
	tasks := intentFixture(t, st, "job-1", "n1", "n2")
	if err := st.Audit().Append(ctx, intentRecord("aud-dup", "other-job")); err != nil {
		t.Fatalf("Append: %v", err)
	}
	before := headAt(t, st)

	if err := st.Audit().AppendWithTasks(ctx, intentRecord("aud-dup", "job-1"), tasks); err == nil {
		t.Fatal("AppendWithTasks succeeded with a colliding audit id")
	}

	got, err := st.Tasks().ByJob(ctx, "job-1")
	if err != nil {
		t.Fatalf("ByJob: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("%d Tasks survived a failed intent write, want 0", len(got))
	}
	if after := headAt(t, st); after != before {
		t.Errorf("chain head moved from %+v to %+v", before, after)
	}
}

func TestAppendWithTasks_AnUnwritableTaskLeavesNoIntent(t *testing.T) {
	st, _ := openTestStore(t)
	ctx := context.Background()
	tasks := intentFixture(t, st, "job-1", "n1", "n2")
	// The second Task collides with one that already exists.
	if err := st.Tasks().CreateTask(ctx, tasks[1]); err != nil {
		t.Fatalf("CreateTask: %v", err)
	}
	before := headAt(t, st)

	if err := st.Audit().AppendWithTasks(ctx, intentRecord("aud-1", "job-1"), tasks); err == nil {
		t.Fatal("AppendWithTasks succeeded with a colliding task id")
	}

	recs, err := st.Audit().ByJob(ctx, "job-1")
	if err != nil {
		t.Fatalf("ByJob: %v", err)
	}
	if len(recs) != 0 {
		t.Errorf("%d audit rows survived a failed Task write, want 0", len(recs))
	}
	got, _ := st.Tasks().ByJob(ctx, "job-1")
	if len(got) != 1 {
		t.Errorf("%d Tasks, want only the pre-existing one", len(got))
	}
	if after := headAt(t, st); after != before {
		t.Errorf("chain head moved from %+v to %+v", before, after)
	}
}

func TestAppendWithTasks_Refusals(t *testing.T) {
	st, _ := openTestStore(t)
	ctx := context.Background()
	tasks := intentFixture(t, st, "job-1", "n1")
	foreign := append([]jobs.Task(nil), tasks...)
	foreign[0].JobID = "job-other"

	for _, tc := range []struct {
		name  string
		rec   audit.Record
		tasks []jobs.Task
	}{
		{"a Task from another Job", intentRecord("aud-1", "job-1"), foreign},
		{"no Tasks", intentRecord("aud-1", "job-1"), nil},
		{"a record with no id", intentRecord("", "job-1"), tasks},
		{"a record with no job id", intentRecord("aud-1", ""), tasks},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := st.Audit().AppendWithTasks(ctx, tc.rec, tc.tasks); err == nil {
				t.Fatal("AppendWithTasks accepted a malformed call")
			}
			if got, _ := st.Tasks().ByJob(ctx, "job-1"); len(got) != 0 {
				t.Errorf("%d Tasks written by a refused call", len(got))
			}
			if recs, _ := st.Audit().List(ctx); len(recs) != 0 {
				t.Errorf("%d audit rows written by a refused call", len(recs))
			}
		})
	}
}
