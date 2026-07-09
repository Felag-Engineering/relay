package dispatch

import (
	"context"
	"sync"
	"testing"
	"time"

	gleipnirv1 "github.com/Felag-Engineering/gleipnir-relay/relay/internal/gleipnir/v1"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/jobs"
)

// fakeTaskRepository is a minimal in-memory jobs.TaskRepository fake for
// hermetic Reconciler tests — no gRPC, no SQLite.
type fakeTaskRepository struct {
	mu    sync.Mutex
	tasks map[string]jobs.Task

	resolveCalls int
}

func newFakeTaskRepository(tasks ...jobs.Task) *fakeTaskRepository {
	f := &fakeTaskRepository{tasks: make(map[string]jobs.Task)}
	for _, t := range tasks {
		f.tasks[t.ID] = t
	}
	return f
}

func (f *fakeTaskRepository) CreateTask(_ context.Context, task jobs.Task) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.tasks[task.ID] = task
	return nil
}

func (f *fakeTaskRepository) MarkDispatched(_ context.Context, taskID string, at time.Time) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	task, ok := f.tasks[taskID]
	if !ok {
		return jobs.ErrTaskNotFound
	}
	if task.State != jobs.DispatchStatePending {
		return jobs.ErrInvalidTaskState
	}
	task.State = jobs.DispatchStateDispatched
	task.DispatchedAt = at
	f.tasks[taskID] = task
	return nil
}

func (f *fakeTaskRepository) Resolve(_ context.Context, taskID string, r jobs.Result) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	task, ok := f.tasks[taskID]
	if !ok {
		return jobs.ErrTaskNotFound
	}
	if task.State != jobs.DispatchStateDispatched {
		return jobs.ErrInvalidTaskState
	}
	f.resolveCalls++
	task.State = jobs.DispatchStateResolved
	task.Outcome = r.Outcome
	task.ExitCode = r.ExitCode
	task.Stdout = r.Stdout
	task.Stderr = r.Stderr
	f.tasks[taskID] = task
	return nil
}

func (f *fakeTaskRepository) MarkUnreachable(_ context.Context, taskID string, _ time.Time) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	task, ok := f.tasks[taskID]
	if !ok {
		return jobs.ErrTaskNotFound
	}
	if task.State != jobs.DispatchStatePending {
		return jobs.ErrInvalidTaskState
	}
	task.State = jobs.DispatchStateResolved
	task.Outcome = jobs.OutcomeUnreachable
	f.tasks[taskID] = task
	return nil
}

func (f *fakeTaskRepository) MarkCancelled(_ context.Context, taskID string, _ time.Time) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	task, ok := f.tasks[taskID]
	if !ok {
		return jobs.ErrTaskNotFound
	}
	if task.State != jobs.DispatchStatePending {
		return jobs.ErrInvalidTaskState
	}
	task.State = jobs.DispatchStateResolved
	task.Outcome = jobs.OutcomeCancelled
	f.tasks[taskID] = task
	return nil
}

func (f *fakeTaskRepository) Get(_ context.Context, taskID string) (jobs.Task, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	task, ok := f.tasks[taskID]
	if !ok {
		return jobs.Task{}, jobs.ErrTaskNotFound
	}
	return task, nil
}

func (f *fakeTaskRepository) InFlight(_ context.Context) ([]jobs.Task, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []jobs.Task
	for _, task := range f.tasks {
		if task.State == jobs.DispatchStateDispatched {
			out = append(out, task)
		}
	}
	return out, nil
}

func (f *fakeTaskRepository) ByJob(_ context.Context, jobID string) ([]jobs.Task, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []jobs.Task
	for _, task := range f.tasks {
		if task.JobID == jobID {
			out = append(out, task)
		}
	}
	return out, nil
}

// TestReconciler_ResendResolvesInFlightTask is the core restart-recovery
// path: an in-flight Task for nodeID is resent, its benign-or-real Result is
// Resolved, and it no longer appears in InFlight().
func TestReconciler_ResendResolvesInFlightTask(t *testing.T) {
	task := jobs.Task{ID: "task-1", NodeID: "node-1", State: jobs.DispatchStateDispatched}
	tasks := newFakeTaskRepository(task)
	router := NewRouter(nil)
	reconciler := NewReconciler(tasks, router)

	send := &recordingSend{}
	unregister := router.Register("node-1", send.send)
	defer unregister()

	done := make(chan error, 1)
	go func() { done <- reconciler.ReconcileNode(context.Background(), "node-1") }()

	waitUntil(t, time.Second, func() bool { return send.len() == 1 })
	msg := send.last()
	tr := msg.GetTask()
	if tr == nil || tr.GetTaskId() != "task-1" {
		t.Fatalf("resent message = %+v, want a TaskRequest for task-1", msg)
	}

	// Simulate the daemon's benign already-processed result (dedup.rs): the
	// Relay never re-executes, it only asks "what happened."
	router.Deliver("node-1", &gleipnirv1.TaskResult{
		TaskId:  "task-1",
		Outcome: gleipnirv1.Outcome_OUTCOME_SUCCESS,
		Stderr:  []byte("task already processed; deduplicated (at-most-once, not re-run)"),
	})

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("ReconcileNode: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("ReconcileNode did not return")
	}

	got, err := tasks.Get(context.Background(), "task-1")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.State != jobs.DispatchStateResolved || got.Outcome != jobs.OutcomeSuccess {
		t.Errorf("task-1 = %+v, want Resolved/OutcomeSuccess", got)
	}

	inFlight, err := tasks.InFlight(context.Background())
	if err != nil {
		t.Fatalf("InFlight: %v", err)
	}
	if len(inFlight) != 0 {
		t.Errorf("InFlight after reconcile = %v, want empty", inFlight)
	}
}

// TestReconciler_IdempotentUnderAlreadyResolved asserts ReconcileNode
// tolerates a Task that a concurrent reconcile already resolved out from
// under it: Resolve returning ErrInvalidTaskState is not an error.
func TestReconciler_IdempotentUnderAlreadyResolved(t *testing.T) {
	tasks := newFakeTaskRepository(jobs.Task{ID: "task-1", NodeID: "node-1", State: jobs.DispatchStateDispatched})
	router := NewRouter(nil)
	reconciler := NewReconciler(tasks, router)

	send := &recordingSend{}
	unregister := router.Register("node-1", send.send)
	defer unregister()

	done := make(chan error, 1)
	go func() { done <- reconciler.ReconcileNode(context.Background(), "node-1") }()

	waitUntil(t, time.Second, func() bool { return send.len() == 1 })

	// Resolve out from under the in-flight Dispatch call, as a concurrent
	// reconcile would: by the time router.Deliver wakes reconcileTask's
	// Dispatch, the Task is already Resolved, so its own Resolve call must
	// see ErrInvalidTaskState and treat it as done, not an error.
	if err := tasks.Resolve(context.Background(), "task-1", jobs.Result{Outcome: jobs.OutcomeSuccess}); err != nil {
		t.Fatalf("Resolve (setup): %v", err)
	}
	router.Deliver("node-1", &gleipnirv1.TaskResult{TaskId: "task-1", Outcome: gleipnirv1.Outcome_OUTCOME_SUCCESS})

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("ReconcileNode should tolerate an already-resolved task, got: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("ReconcileNode did not return")
	}
}

// TestReconciler_SkipsOtherNodesTasks asserts ReconcileNode(nodeID) only
// touches in-flight Tasks for that nodeID.
func TestReconciler_SkipsOtherNodesTasks(t *testing.T) {
	tasks := newFakeTaskRepository(
		jobs.Task{ID: "task-1", NodeID: "node-1", State: jobs.DispatchStateDispatched},
		jobs.Task{ID: "task-2", NodeID: "node-2", State: jobs.DispatchStateDispatched},
	)
	router := NewRouter(nil)
	reconciler := NewReconciler(tasks, router)

	sendA := &recordingSend{}
	unregA := router.Register("node-1", sendA.send)
	defer unregA()

	done := make(chan error, 1)
	go func() { done <- reconciler.ReconcileNode(context.Background(), "node-1") }()

	waitUntil(t, time.Second, func() bool { return sendA.len() == 1 })
	router.Deliver("node-1", &gleipnirv1.TaskResult{TaskId: "task-1", Outcome: gleipnirv1.Outcome_OUTCOME_SUCCESS})

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("ReconcileNode: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("ReconcileNode did not return")
	}

	got2, err := tasks.Get(context.Background(), "task-2")
	if err != nil {
		t.Fatalf("Get(task-2): %v", err)
	}
	if got2.State != jobs.DispatchStateDispatched {
		t.Errorf("task-2 state = %v, want unchanged DispatchStateDispatched", got2.State)
	}
}

// TestReconciler_PerNodeGuardPreventsDoubleDispatch is the R3 refinement
// test: two overlapping ReconcileNode calls for the same nodeID must not
// both resend the same in-flight Task (the second must be a no-op, not a
// second waiter overwriting the first's in Router's flat waiters map).
func TestReconciler_PerNodeGuardPreventsDoubleDispatch(t *testing.T) {
	tasks := newFakeTaskRepository(jobs.Task{ID: "task-1", NodeID: "node-1", State: jobs.DispatchStateDispatched})
	router := NewRouter(nil)
	reconciler := NewReconciler(tasks, router)

	send := &recordingSend{}
	unregister := router.Register("node-1", send.send)
	defer unregister()

	var wg sync.WaitGroup
	errs := make(chan error, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs <- reconciler.ReconcileNode(context.Background(), "node-1")
		}()
	}

	waitUntil(t, time.Second, func() bool { return send.len() >= 1 })
	// Give the second (guarded) call a moment to observe inProgress and
	// return early, in case it started concurrently with the first.
	time.Sleep(20 * time.Millisecond)
	router.Deliver("node-1", &gleipnirv1.TaskResult{TaskId: "task-1", Outcome: gleipnirv1.Outcome_OUTCOME_SUCCESS})

	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Errorf("ReconcileNode: %v", err)
		}
	}

	if got := send.len(); got != 1 {
		t.Errorf("send was called %d times, want exactly 1 (the guard must prevent a second concurrent resend)", got)
	}
	if got := tasks.resolveCalls; got != 1 {
		t.Errorf("Resolve was called %d times, want exactly 1", got)
	}
}

// TestReconciler_NoInFlightTasksIsANoOp asserts ReconcileNode on a Node with
// no in-flight Tasks returns cleanly without touching the Conduit.
func TestReconciler_NoInFlightTasksIsANoOp(t *testing.T) {
	tasks := newFakeTaskRepository()
	router := NewRouter(nil)
	reconciler := NewReconciler(tasks, router)

	send := &recordingSend{}
	unregister := router.Register("node-1", send.send)
	defer unregister()

	if err := reconciler.ReconcileNode(context.Background(), "node-1"); err != nil {
		t.Fatalf("ReconcileNode: %v", err)
	}
	if got := send.len(); got != 0 {
		t.Errorf("send was called %d times, want 0 (no in-flight tasks)", got)
	}
}
