package store

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/jobs"
)

// testAction returns a minimal valid Action for tests that don't care about
// its contents, only that a Task exists.
func testAction() jobs.Action {
	return jobs.Action{Kind: jobs.ActionOperation, OperationName: "system.facts", RiskClass: jobs.RiskClassRead}
}

// seedJobAndStage creates a Job and its single Stage for task tests.
func seedJobAndStage(t *testing.T, st *Store, jobID, stageID string) {
	t.Helper()
	ctx := context.Background()
	if err := st.Jobs().CreateJob(ctx, jobs.Job{ID: jobID, CreatedAt: time.Now().UTC()}); err != nil {
		t.Fatalf("CreateJob: %v", err)
	}
	if err := st.Jobs().AddStage(ctx, jobs.Stage{ID: stageID, JobID: jobID, Index: 0}); err != nil {
		t.Fatalf("AddStage: %v", err)
	}
}

// TestInFlightResolve is acceptance #4: CreateTask -> pending; MarkDispatched
// -> InFlight returns it, dispatched_at set and outcome unresolved; Resolve
// -> InFlight empty, outcome/exit/stdout/stderr/resolved_at populated.
func TestInFlightResolve(t *testing.T) {
	st, _ := openTestStore(t)
	ctx := context.Background()
	seedJobAndStage(t, st, "job-1", "stage-1")
	taskRepo := st.Tasks()

	task := jobs.Task{
		ID:      "task-1",
		JobID:   "job-1",
		StageID: "stage-1",
		NodeID:  "node-1",
		Action: jobs.Action{
			Kind:          jobs.ActionOperation,
			OperationName: "service.restart",
			RiskClass:     jobs.RiskClassMutate,
		},
		CreatedAt: time.Now().UTC(),
	}
	if err := taskRepo.CreateTask(ctx, task); err != nil {
		t.Fatalf("CreateTask: %v", err)
	}

	got, err := taskRepo.Get(ctx, "task-1")
	if err != nil {
		t.Fatalf("Get after create: %v", err)
	}
	if got.State != jobs.DispatchStatePending {
		t.Errorf("state after create: got %v, want DispatchStatePending", got.State)
	}

	inFlight, err := taskRepo.InFlight(ctx)
	if err != nil {
		t.Fatalf("InFlight before dispatch: %v", err)
	}
	if len(inFlight) != 0 {
		t.Errorf("InFlight before dispatch: got %v, want empty", inFlight)
	}

	dispatchedAt := time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)
	if err := taskRepo.MarkDispatched(ctx, "task-1", dispatchedAt); err != nil {
		t.Fatalf("MarkDispatched: %v", err)
	}

	inFlight, err = taskRepo.InFlight(ctx)
	if err != nil {
		t.Fatalf("InFlight after dispatch: %v", err)
	}
	if len(inFlight) != 1 || inFlight[0].ID != "task-1" {
		t.Fatalf("InFlight after dispatch: got %v, want [task-1]", inFlight)
	}
	if !inFlight[0].DispatchedAt.Equal(dispatchedAt) {
		t.Errorf("InFlight[0].DispatchedAt: got %v, want %v", inFlight[0].DispatchedAt, dispatchedAt)
	}
	if inFlight[0].Outcome != jobs.OutcomeUnspecified {
		t.Errorf("InFlight[0].Outcome: got %v, want OutcomeUnspecified", inFlight[0].Outcome)
	}

	if err := taskRepo.Resolve(ctx, "task-1", jobs.Result{
		Outcome:  jobs.OutcomeSuccess,
		ExitCode: 0,
		Stdout:   []byte("restarted"),
		Stderr:   nil,
	}); err != nil {
		t.Fatalf("Resolve: %v", err)
	}

	inFlight, err = taskRepo.InFlight(ctx)
	if err != nil {
		t.Fatalf("InFlight after resolve: %v", err)
	}
	if len(inFlight) != 0 {
		t.Errorf("InFlight after resolve: got %v, want empty", inFlight)
	}

	resolved, err := taskRepo.Get(ctx, "task-1")
	if err != nil {
		t.Fatalf("Get after resolve: %v", err)
	}
	if resolved.State != jobs.DispatchStateResolved {
		t.Errorf("state after resolve: got %v, want DispatchStateResolved", resolved.State)
	}
	if resolved.Outcome != jobs.OutcomeSuccess {
		t.Errorf("Outcome after resolve: got %v, want OutcomeSuccess", resolved.Outcome)
	}
	if string(resolved.Stdout) != "restarted" {
		t.Errorf("Stdout after resolve: got %q, want %q", resolved.Stdout, "restarted")
	}
	if resolved.ResolvedAt.IsZero() {
		t.Error("ResolvedAt after resolve: got zero value, want set")
	}
}

// TestInFlight_SurvivesRestart is the crash-across-restart precondition:
// reopening a store with a dispatched-but-unresolved Task must still surface
// it via InFlight.
func TestInFlight_SurvivesRestart(t *testing.T) {
	st, path := openTestStore(t)
	ctx := context.Background()
	seedJobAndStage(t, st, "job-1", "stage-1")
	taskRepo := st.Tasks()

	task := jobs.Task{
		ID:        "task-1",
		JobID:     "job-1",
		StageID:   "stage-1",
		NodeID:    "node-1",
		Action:    jobs.Action{Kind: jobs.ActionRawExec, RawExecArgv: []string{"/bin/sleep", "5"}, RiskClass: jobs.RiskClassMutate},
		CreatedAt: time.Now().UTC(),
	}
	if err := taskRepo.CreateTask(ctx, task); err != nil {
		t.Fatalf("CreateTask: %v", err)
	}
	if err := taskRepo.MarkDispatched(ctx, "task-1", time.Now().UTC()); err != nil {
		t.Fatalf("MarkDispatched: %v", err)
	}

	if err := st.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	st2, err := Open(path)
	if err != nil {
		t.Fatalf("re-Open: %v", err)
	}
	t.Cleanup(func() { st2.Close() }) //nolint:errcheck

	inFlight, err := st2.Tasks().InFlight(ctx)
	if err != nil {
		t.Fatalf("InFlight after restart: %v", err)
	}
	if len(inFlight) != 1 || inFlight[0].ID != "task-1" {
		t.Errorf("InFlight after restart: got %v, want [task-1]", inFlight)
	}
}

func TestMarkDispatched_InvalidState(t *testing.T) {
	st, _ := openTestStore(t)
	ctx := context.Background()
	seedJobAndStage(t, st, "job-1", "stage-1")
	taskRepo := st.Tasks()

	task := jobs.Task{ID: "task-1", JobID: "job-1", StageID: "stage-1", NodeID: "node-1", Action: testAction(), CreatedAt: time.Now().UTC()}
	if err := taskRepo.CreateTask(ctx, task); err != nil {
		t.Fatalf("CreateTask: %v", err)
	}
	if err := taskRepo.MarkDispatched(ctx, "task-1", time.Now().UTC()); err != nil {
		t.Fatalf("first MarkDispatched: %v", err)
	}

	// Second MarkDispatched on an already-dispatched Task must fail.
	if err := taskRepo.MarkDispatched(ctx, "task-1", time.Now().UTC()); !errors.Is(err, jobs.ErrInvalidTaskState) {
		t.Errorf("second MarkDispatched: want ErrInvalidTaskState, got %v", err)
	}

	if err := taskRepo.MarkDispatched(ctx, "does-not-exist", time.Now().UTC()); !errors.Is(err, jobs.ErrTaskNotFound) {
		t.Errorf("MarkDispatched unknown task: want ErrTaskNotFound, got %v", err)
	}
}

func TestResolve_InvalidState(t *testing.T) {
	st, _ := openTestStore(t)
	ctx := context.Background()
	seedJobAndStage(t, st, "job-1", "stage-1")
	taskRepo := st.Tasks()

	task := jobs.Task{ID: "task-1", JobID: "job-1", StageID: "stage-1", NodeID: "node-1", Action: testAction(), CreatedAt: time.Now().UTC()}
	if err := taskRepo.CreateTask(ctx, task); err != nil {
		t.Fatalf("CreateTask: %v", err)
	}

	// Resolve before MarkDispatched must fail.
	err := taskRepo.Resolve(ctx, "task-1", jobs.Result{Outcome: jobs.OutcomeSuccess})
	if !errors.Is(err, jobs.ErrInvalidTaskState) {
		t.Errorf("Resolve on pending task: want ErrInvalidTaskState, got %v", err)
	}

	if err := taskRepo.Resolve(ctx, "does-not-exist", jobs.Result{}); !errors.Is(err, jobs.ErrTaskNotFound) {
		t.Errorf("Resolve unknown task: want ErrTaskNotFound, got %v", err)
	}
}

// TestMarkUnreachable_FromPending is the offline-fail-fast contract
// (ADR-0004): a Pending Task moves straight to Resolved/OutcomeUnreachable
// with no DispatchedAt, and is absent from InFlight (it was never sent).
func TestMarkUnreachable_FromPending(t *testing.T) {
	st, _ := openTestStore(t)
	ctx := context.Background()
	seedJobAndStage(t, st, "job-1", "stage-1")
	taskRepo := st.Tasks()

	task := jobs.Task{ID: "task-1", JobID: "job-1", StageID: "stage-1", NodeID: "node-1", Action: testAction(), CreatedAt: time.Now().UTC()}
	if err := taskRepo.CreateTask(ctx, task); err != nil {
		t.Fatalf("CreateTask: %v", err)
	}

	resolvedAt := time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)
	if err := taskRepo.MarkUnreachable(ctx, "task-1", resolvedAt); err != nil {
		t.Fatalf("MarkUnreachable: %v", err)
	}

	got, err := taskRepo.Get(ctx, "task-1")
	if err != nil {
		t.Fatalf("Get after MarkUnreachable: %v", err)
	}
	if got.State != jobs.DispatchStateResolved {
		t.Errorf("state after MarkUnreachable: got %v, want DispatchStateResolved", got.State)
	}
	if got.Outcome != jobs.OutcomeUnreachable {
		t.Errorf("Outcome after MarkUnreachable: got %v, want OutcomeUnreachable", got.Outcome)
	}
	if !got.DispatchedAt.IsZero() {
		t.Errorf("DispatchedAt after MarkUnreachable: got %v, want zero (never dispatched)", got.DispatchedAt)
	}
	if !got.ResolvedAt.Equal(resolvedAt) {
		t.Errorf("ResolvedAt after MarkUnreachable: got %v, want %v", got.ResolvedAt, resolvedAt)
	}

	inFlight, err := taskRepo.InFlight(ctx)
	if err != nil {
		t.Fatalf("InFlight after MarkUnreachable: %v", err)
	}
	if len(inFlight) != 0 {
		t.Errorf("InFlight after MarkUnreachable: got %v, want empty (an unreachable Task was never dispatched)", inFlight)
	}
}

// TestMarkUnreachable_InvalidState mirrors TestResolve_InvalidState: a
// Dispatched Task cannot be marked unreachable — that transition only
// applies to a Task that was never sent.
func TestMarkUnreachable_InvalidState(t *testing.T) {
	st, _ := openTestStore(t)
	ctx := context.Background()
	seedJobAndStage(t, st, "job-1", "stage-1")
	taskRepo := st.Tasks()

	task := jobs.Task{ID: "task-1", JobID: "job-1", StageID: "stage-1", NodeID: "node-1", Action: testAction(), CreatedAt: time.Now().UTC()}
	if err := taskRepo.CreateTask(ctx, task); err != nil {
		t.Fatalf("CreateTask: %v", err)
	}
	if err := taskRepo.MarkDispatched(ctx, "task-1", time.Now().UTC()); err != nil {
		t.Fatalf("MarkDispatched: %v", err)
	}

	// MarkUnreachable on an already-dispatched Task must fail.
	if err := taskRepo.MarkUnreachable(ctx, "task-1", time.Now().UTC()); !errors.Is(err, jobs.ErrInvalidTaskState) {
		t.Errorf("MarkUnreachable on dispatched task: want ErrInvalidTaskState, got %v", err)
	}

	if err := taskRepo.MarkUnreachable(ctx, "does-not-exist", time.Now().UTC()); !errors.Is(err, jobs.ErrTaskNotFound) {
		t.Errorf("MarkUnreachable unknown task: want ErrTaskNotFound, got %v", err)
	}
}

func TestByJob(t *testing.T) {
	st, _ := openTestStore(t)
	ctx := context.Background()
	seedJobAndStage(t, st, "job-1", "stage-1")
	seedJobAndStage(t, st, "job-2", "stage-2")
	taskRepo := st.Tasks()

	if err := taskRepo.CreateTask(ctx, jobs.Task{ID: "task-1", JobID: "job-1", StageID: "stage-1", NodeID: "node-1", Action: testAction(), CreatedAt: time.Now().UTC()}); err != nil {
		t.Fatalf("CreateTask task-1: %v", err)
	}
	if err := taskRepo.CreateTask(ctx, jobs.Task{ID: "task-2", JobID: "job-1", StageID: "stage-1", NodeID: "node-2", Action: testAction(), CreatedAt: time.Now().UTC()}); err != nil {
		t.Fatalf("CreateTask task-2: %v", err)
	}
	if err := taskRepo.CreateTask(ctx, jobs.Task{ID: "task-3", JobID: "job-2", StageID: "stage-2", NodeID: "node-1", Action: testAction(), CreatedAt: time.Now().UTC()}); err != nil {
		t.Fatalf("CreateTask task-3: %v", err)
	}

	got, err := taskRepo.ByJob(ctx, "job-1")
	if err != nil {
		t.Fatalf("ByJob: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("ByJob job-1: got %d tasks, want 2", len(got))
	}
}
