package capability

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/jobs"
)

// TestCancelJobStopsPendingSendsCancelToDispatchedLeavesResolved is
// acceptance criteria 3/4: a Job with a Pending, a Dispatched, and an
// already-Resolved (success) Task. CancelJob marks the Pending Task
// cancelled without ever sending it, asks the Dispatched Task's Conduit to
// cancel without rewriting its state, and leaves the Resolved Task's
// truthful outcome untouched.
func TestCancelJobStopsPendingSendsCancelToDispatchedLeavesResolved(t *testing.T) {
	jobsRepo, tasksRepo := testEngineStore(t)
	ctx := context.Background()
	at := time.Date(2026, 7, 8, 0, 0, 0, 0, time.UTC)

	jobID := "job-1"
	if err := jobsRepo.CreateJob(ctx, jobs.Job{ID: jobID, CreatedAt: at}); err != nil {
		t.Fatalf("CreateJob: %v", err)
	}
	if err := jobsRepo.AddStage(ctx, jobs.Stage{ID: "stage-1", JobID: jobID, Index: 0}); err != nil {
		t.Fatalf("AddStage: %v", err)
	}

	pendingTask := jobs.Task{ID: "task-pending", JobID: jobID, StageID: "stage-1", NodeID: "node-pending",
		Action: jobs.Action{Kind: jobs.ActionOperation, OperationName: "system.facts", RiskClass: jobs.RiskClassRead}, CreatedAt: at}
	dispatchedTask := jobs.Task{ID: "task-dispatched", JobID: jobID, StageID: "stage-1", NodeID: "node-dispatched",
		Action: jobs.Action{Kind: jobs.ActionOperation, OperationName: "system.facts", RiskClass: jobs.RiskClassRead}, CreatedAt: at}
	resolvedTask := jobs.Task{ID: "task-resolved", JobID: jobID, StageID: "stage-1", NodeID: "node-resolved",
		Action: jobs.Action{Kind: jobs.ActionOperation, OperationName: "system.facts", RiskClass: jobs.RiskClassRead}, CreatedAt: at}

	for _, task := range []jobs.Task{pendingTask, dispatchedTask, resolvedTask} {
		if err := tasksRepo.CreateTask(ctx, task); err != nil {
			t.Fatalf("CreateTask(%s): %v", task.ID, err)
		}
	}
	if err := tasksRepo.MarkDispatched(ctx, dispatchedTask.ID, at); err != nil {
		t.Fatalf("MarkDispatched(dispatched): %v", err)
	}
	if err := tasksRepo.MarkDispatched(ctx, resolvedTask.ID, at); err != nil {
		t.Fatalf("MarkDispatched(resolved): %v", err)
	}
	if err := tasksRepo.Resolve(ctx, resolvedTask.ID, jobs.Result{Outcome: jobs.OutcomeSuccess}); err != nil {
		t.Fatalf("Resolve(resolved): %v", err)
	}

	var log []string
	conduit := newFakeConduit(&log)

	e := &jobEngine{
		jobsRepo:  jobsRepo,
		tasksRepo: tasksRepo,
		conduit:   conduit,
		newID:     sequentialIDs("id-"),
		now:       func() time.Time { return at },
	}
	svc := &Service{disp: e}

	if err := svc.CancelJob(ctx, jobID); err != nil {
		t.Fatalf("CancelJob: %v", err)
	}

	gotPending, err := tasksRepo.Get(ctx, pendingTask.ID)
	if err != nil {
		t.Fatalf("Get(pending): %v", err)
	}
	if gotPending.State != jobs.DispatchStateResolved {
		t.Errorf("pending Task state = %v, want DispatchStateResolved", gotPending.State)
	}
	if gotPending.Outcome != jobs.OutcomeCancelled {
		t.Errorf("pending Task outcome = %v, want OutcomeCancelled", gotPending.Outcome)
	}
	if !gotPending.DispatchedAt.IsZero() {
		t.Errorf("pending Task DispatchedAt = %v, want zero (never sent)", gotPending.DispatchedAt)
	}
	for _, entry := range log {
		if entry == "cancel:"+pendingTask.NodeID+":"+pendingTask.ID {
			t.Errorf("Conduit.Cancel was called for the Pending Task, which was never dispatched; log = %v", log)
		}
	}

	gotDispatched, err := tasksRepo.Get(ctx, dispatchedTask.ID)
	if err != nil {
		t.Fatalf("Get(dispatched): %v", err)
	}
	if gotDispatched.State != jobs.DispatchStateDispatched {
		t.Errorf("dispatched Task state = %v, want DispatchStateDispatched (no rewrite)", gotDispatched.State)
	}
	wantCancelLog := "cancel:" + dispatchedTask.NodeID + ":" + dispatchedTask.ID
	found := false
	for _, entry := range log {
		if entry == wantCancelLog {
			found = true
		}
	}
	if !found {
		t.Errorf("Conduit.Cancel was not called for the Dispatched Task; log = %v, want to contain %q", log, wantCancelLog)
	}

	gotResolved, err := tasksRepo.Get(ctx, resolvedTask.ID)
	if err != nil {
		t.Fatalf("Get(resolved): %v", err)
	}
	if gotResolved.Outcome != jobs.OutcomeSuccess {
		t.Errorf("resolved Task outcome = %v, want OutcomeSuccess (a cancelled Job's already-completed Tasks keep their truthful outcome)", gotResolved.Outcome)
	}
}

// TestCancelJobUnknownJobReturnsErrJobNotFound: CancelJob on a jobID that
// does not exist surfaces jobs.ErrJobNotFound.
func TestCancelJobUnknownJobReturnsErrJobNotFound(t *testing.T) {
	jobsRepo, tasksRepo := testEngineStore(t)
	e := &jobEngine{
		jobsRepo:  jobsRepo,
		tasksRepo: tasksRepo,
		conduit:   newFakeConduit(nil),
		newID:     sequentialIDs("id-"),
		now:       func() time.Time { return time.Now().UTC() },
	}
	svc := &Service{disp: e}

	err := svc.CancelJob(context.Background(), "job-does-not-exist")
	if !errors.Is(err, jobs.ErrJobNotFound) {
		t.Errorf("CancelJob(unknown) error = %v, want jobs.ErrJobNotFound", err)
	}
}
