package main

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/Felag-Engineering/relay/relay/internal/audit"
	"github.com/Felag-Engineering/relay/relay/internal/auditsink"
	"github.com/Felag-Engineering/relay/relay/internal/dispatch"
	"github.com/Felag-Engineering/relay/relay/internal/jobs"
	"github.com/Felag-Engineering/relay/relay/internal/registry"
	relayv1 "github.com/Felag-Engineering/relay/relay/internal/relay/v1"
	"github.com/Felag-Engineering/relay/relay/internal/store"
)

// A restart re-sends a Task marked Dispatched inside the resend limit and
// resolves one outside it without sending it: the past-limit Task of a mutate
// Job halts the Job, the past-limit Task of a read Job does not, and both
// outcomes are audited (invariant 4).
// Proves EX-71.
func TestDispatchWiring_ARestartResendsInsideTheLimitAndResolvesAMutateTaskPastItWithAHalt(t *testing.T) {
	ctx := context.Background()
	dbPath := filepath.Join(t.TempDir(), "relay.db")
	st, err := store.Open(dbPath)
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { st.Close() })

	now := time.Now().UTC()
	for _, id := range []string{"node-1", "node-2"} {
		if _, err := st.Registry().Upsert(registry.Report{NodeID: id}); err != nil {
			t.Fatalf("Upsert(%s): %v", id, err)
		}
	}
	for _, jobID := range []string{"job-mutate", "job-read"} {
		if err := st.Jobs().CreateJob(ctx, jobs.Job{ID: jobID, CreatedAt: now}); err != nil {
			t.Fatalf("CreateJob(%s): %v", jobID, err)
		}
		if err := st.Jobs().AddStage(ctx, jobs.Stage{ID: "stage-" + jobID, JobID: jobID, Index: 0}); err != nil {
			t.Fatalf("AddStage(%s): %v", jobID, err)
		}
	}
	seed := func(jobID, taskID, nodeID string, class jobs.RiskClass, dispatchedAt time.Time) {
		t.Helper()
		act := jobs.Action{Kind: jobs.ActionRawExec, RawExecArgv: []string{"/bin/true"}, RiskClass: class}
		task := jobs.Task{ID: taskID, JobID: jobID, StageID: "stage-" + jobID, NodeID: nodeID, Action: act, CreatedAt: now}
		if err := st.Tasks().CreateTask(ctx, task); err != nil {
			t.Fatalf("CreateTask(%s): %v", taskID, err)
		}
		if err := st.Tasks().MarkDispatched(ctx, taskID, dispatchedAt); err != nil {
			t.Fatalf("MarkDispatched(%s): %v", taskID, err)
		}
	}
	seed("job-mutate", "task-inside", "node-1", jobs.RiskClassMutate, now.Add(-time.Minute))
	seed("job-mutate", "task-past", "node-2", jobs.RiskClassMutate, now.Add(-11*time.Minute))
	seed("job-read", "task-read-past", "node-2", jobs.RiskClassRead, now.Add(-11*time.Minute))

	sink := auditsink.New(st.Audit())
	router, _, _ := newDispatchStack(st.Tasks(), nil, nil,
		dispatch.WithReconcilerClock(func() time.Time { return now }),
		dispatch.WithResendLimitSettlement(st.Jobs(), sink))

	sent := make(chan string, 8)
	unregister1 := router.Register("node-1", func(msg *relayv1.RelayMessage) error {
		if task := msg.GetTask(); task != nil {
			sent <- task.GetTaskId()
			go router.Deliver("node-1", &relayv1.TaskResult{TaskId: task.GetTaskId(), Outcome: relayv1.Outcome_OUTCOME_SUCCESS})
		}
		return nil
	})
	defer unregister1()
	unregister2 := router.Register("node-2", func(msg *relayv1.RelayMessage) error {
		if task := msg.GetTask(); task != nil {
			sent <- task.GetTaskId()
		}
		return nil
	})
	defer unregister2()

	resolved := func(id string) func() bool {
		return func() bool {
			got, err := st.Tasks().Get(ctx, id)
			return err == nil && got.State == jobs.DispatchStateResolved
		}
	}
	for _, id := range []string{"task-inside", "task-past", "task-read-past"} {
		if !pollUntil(5*time.Second, 10*time.Millisecond, resolved(id)) {
			t.Fatalf("task %s was not Resolved by the reconcile", id)
		}
	}
	// The halt and its audit land after the Task's own resolution.
	halted := func() bool {
		job, err := st.Jobs().GetJob(ctx, "job-mutate")
		return err == nil && job.Halt.Halted()
	}
	if !pollUntil(5*time.Second, 10*time.Millisecond, halted) {
		t.Fatal("the mutate Job was not halted by its past-limit Task")
	}

	close(sent)
	var got []string
	for id := range sent {
		got = append(got, id)
	}
	if len(got) != 1 || got[0] != "task-inside" {
		t.Errorf("TaskRequests sent = %v, want only task-inside", got)
	}

	inside, _ := st.Tasks().Get(ctx, "task-inside")
	if inside.Outcome != jobs.OutcomeSuccess {
		t.Errorf("task-inside outcome = %v, want the delivered success", inside.Outcome)
	}
	for _, id := range []string{"task-past", "task-read-past"} {
		task, _ := st.Tasks().Get(ctx, id)
		if task.Outcome != jobs.OutcomeFailure || task.ExitCode != -1 || string(task.Stderr) != jobs.NodeOfflineMessage {
			t.Errorf("%s = outcome %v exit %d stderr %q, want failure, exit -1, NodeOfflineMessage", id, task.Outcome, task.ExitCode, task.Stderr)
		}
	}

	mutate, err := st.Jobs().GetJob(ctx, "job-mutate")
	if err != nil {
		t.Fatalf("GetJob(job-mutate): %v", err)
	}
	if h := mutate.Halt; h.TaskID != "task-past" || !h.Resolved || h.Outcome != jobs.OutcomeFailure {
		t.Errorf("job-mutate halt = %+v, want task-past, resolved, failure", h)
	}
	if read, err := st.Jobs().GetJob(ctx, "job-read"); err != nil || read.Halt.Halted() {
		t.Errorf("job-read = %+v, %v; want a read Job left un-halted", read.Halt, err)
	}

	count := func(jobID string, kind, reason string) int {
		records, err := st.Audit().ByJob(ctx, jobID)
		if err != nil {
			t.Fatalf("Audit().ByJob(%s): %v", jobID, err)
		}
		n := 0
		for _, rec := range records {
			if rec.Kind == kind && (reason == "" || rec.Reason == reason) {
				n++
			}
		}
		return n
	}
	if n := count("job-mutate", audit.KindDispatch, "not_resent=past_resend_limit task_id=task-past"); n != 1 {
		t.Errorf("settlement rows for task-past = %d, want 1", n)
	}
	if n := count("job-mutate", audit.KindJobHalt, ""); n != 1 {
		t.Errorf("job_halt rows for job-mutate = %d, want 1", n)
	}
	if n := count("job-read", audit.KindJobHalt, ""); n != 0 {
		t.Errorf("job_halt rows for job-read = %d, want 0", n)
	}

	verdict, err := store.VerifyAuditChain(ctx, dbPath, nil)
	if err != nil || !verdict.Intact() {
		t.Errorf("audit chain = %+v, %v; want intact", verdict, err)
	}
}
