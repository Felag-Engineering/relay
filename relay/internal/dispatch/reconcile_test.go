package dispatch

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/jobs"
	relayv1 "github.com/Felag-Engineering/gleipnir-relay/relay/internal/relay/v1"
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

func (f *fakeTaskRepository) MarkUnsupported(_ context.Context, taskID, reason string, _ time.Time) error {
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
	task.Outcome = jobs.OutcomeUnsupported
	task.Stderr = []byte(reason)
	f.tasks[taskID] = task
	return nil
}

func (f *fakeTaskRepository) MarkVersionRefused(_ context.Context, taskID string, _ time.Time) error {
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
	task.Outcome = jobs.OutcomeVersionRefused
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

func (f *fakeTaskRepository) MarkCancelledBeforeSend(_ context.Context, taskID string, _ time.Time) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	task, ok := f.tasks[taskID]
	if !ok {
		return jobs.ErrTaskNotFound
	}
	if task.State != jobs.DispatchStateDispatched {
		return jobs.ErrInvalidTaskState
	}
	task.State = jobs.DispatchStateResolved
	task.Outcome = jobs.OutcomeCancelled
	task.DispatchedAt = time.Time{}
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

// snapshotTasks wraps fakeTaskRepository so InFlight returns a fixed, ordered
// snapshot (as one taken before later changes) and Get can be made to fail.
type snapshotTasks struct {
	*fakeTaskRepository
	snapshot []jobs.Task
	getErr   error
}

func (s *snapshotTasks) InFlight(context.Context) ([]jobs.Task, error) { return s.snapshot, nil }

func (s *snapshotTasks) Get(ctx context.Context, taskID string) (jobs.Task, error) {
	if s.getErr != nil {
		return jobs.Task{}, s.getErr
	}
	return s.fakeTaskRepository.Get(ctx, taskID)
}

func hasWaiter(r *Router, taskID string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	_, ok := r.waiters[taskID]
	return ok
}

// TestReconciler_StaleSnapshotNeverSendsATaskResolvedSinceTheSnapshot asserts
// a Task resolved (withheld by its worker on a cancel, #943) after the
// InFlight snapshot was taken is not sent when the Reconciler reaches it.
func TestReconciler_StaleSnapshotNeverSendsATaskResolvedSinceTheSnapshot(t *testing.T) {
	t1 := jobs.Task{ID: "task-1", NodeID: "node-1", State: jobs.DispatchStateDispatched}
	t2 := jobs.Task{ID: "task-2", NodeID: "node-1", State: jobs.DispatchStateDispatched}
	fake := newFakeTaskRepository(t1, t2)
	tasks := &snapshotTasks{fakeTaskRepository: fake, snapshot: []jobs.Task{t1, t2}}
	router := NewRouter(nil, nil)
	reconciler := NewReconciler(tasks, router)

	send := &recordingSend{}
	unregister := router.Register("node-1", send.send)
	defer unregister()

	done := make(chan error, 1)
	go func() { done <- reconciler.ReconcileNode(context.Background(), "node-1") }()

	waitUntil(t, time.Second, func() bool { return send.len() == 1 })
	if err := fake.MarkCancelledBeforeSend(context.Background(), "task-2", time.Now()); err != nil {
		t.Fatalf("MarkCancelledBeforeSend: %v", err)
	}
	router.Deliver("node-1", &relayv1.TaskResult{TaskId: "task-1", Outcome: relayv1.Outcome_OUTCOME_SUCCESS})

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("ReconcileNode: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("ReconcileNode did not return")
	}

	if n := send.len(); n != 1 {
		t.Errorf("sends = %d, want 1 (task-2 must not be sent)", n)
	}
	got, _ := fake.Get(context.Background(), "task-2")
	if got.State != jobs.DispatchStateResolved || got.Outcome != jobs.OutcomeCancelled || !got.DispatchedAt.IsZero() {
		t.Errorf("task-2 = %+v, want unchanged Resolved/Cancelled with zero DispatchedAt", got)
	}
	if fake.resolveCalls != 1 {
		t.Errorf("resolveCalls = %d, want 1", fake.resolveCalls)
	}
	if hasWaiter(router, "task-2") {
		t.Error("waiter for task-2 left behind")
	}
}

// TestReconciler_ResendBeforeTheWorkersGuardIsNotRecordedNeverSent is the
// sequence of #943's security review: a Reconciler resends a Task its live
// worker has MarkDispatched but not yet sent, and the cancel lands afterwards.
// The worker's guard (which would commit "cancelled, never sent") must not run:
// the Task was sent, so the worker sends too and the Task resolves from the
// delivered Result with its dispatched_at kept.
func TestReconciler_ResendBeforeTheWorkersGuardIsNotRecordedNeverSent(t *testing.T) {
	dispatchedAt := time.Date(2026, 10, 8, 0, 0, 0, 0, time.UTC)
	task := jobs.Task{ID: "task-1", NodeID: "node-1", State: jobs.DispatchStateDispatched, DispatchedAt: dispatchedAt}
	fake := newFakeTaskRepository(task)
	router := NewRouter(nil, nil)
	reconciler := NewReconciler(fake, router)

	send := &recordingSend{}
	unregister := router.Register("node-1", send.send)
	defer unregister()

	rctx, stopReconcile := context.WithCancel(context.Background())
	defer stopReconcile()
	reconcileDone := make(chan error, 1)
	go func() { reconcileDone <- reconciler.ReconcileNode(rctx, "node-1") }()
	waitUntil(t, time.Second, func() bool { return send.len() == 1 })

	// The cancel lands after the Reconciler's send; the worker reaches its guard.
	var mu sync.Mutex
	var guardCalls int
	guard := func() bool {
		mu.Lock()
		guardCalls++
		mu.Unlock()
		_ = fake.MarkCancelledBeforeSend(context.Background(), "task-1", time.Now())
		return true
	}
	type out struct {
		res jobs.Result
		err error
	}
	workerDone := make(chan out, 1)
	go func() {
		res, err := router.Dispatch(jobs.WithSendGuard(context.Background(), guard), "node-1", task)
		workerDone <- out{res, err}
	}()
	waitUntil(t, time.Second, func() bool { return send.len() == 2 })
	router.Deliver("node-1", &relayv1.TaskResult{TaskId: "task-1", Outcome: relayv1.Outcome_OUTCOME_SUCCESS})

	var o out
	select {
	case o = <-workerDone:
	case <-time.After(2 * time.Second):
		t.Fatal("worker Dispatch did not return")
	}
	if o.err != nil {
		t.Fatalf("worker Dispatch: %v", o.err)
	}
	if err := fake.Resolve(context.Background(), "task-1", o.res); err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	stopReconcile() // its waiter was overwritten by the worker's; see ReconcileNode's doc
	<-reconcileDone

	mu.Lock()
	defer mu.Unlock()
	if guardCalls != 0 {
		t.Errorf("worker guard called %d times after the Task was sent, want 0", guardCalls)
	}
	got, _ := fake.Get(context.Background(), "task-1")
	if got.State != jobs.DispatchStateResolved || got.Outcome != jobs.OutcomeSuccess || !got.DispatchedAt.Equal(dispatchedAt) {
		t.Errorf("task = %+v, want Resolved/Success with dispatched_at kept", got)
	}
}

// TestReconciler_StaleSnapshotResolvedTaskIsZeroSends asserts a snapshot Task
// the store already shows Resolved is neither sent nor an error.
func TestReconciler_StaleSnapshotResolvedTaskIsZeroSends(t *testing.T) {
	stale := jobs.Task{ID: "task-1", NodeID: "node-1", State: jobs.DispatchStateDispatched}
	fake := newFakeTaskRepository(jobs.Task{ID: "task-1", NodeID: "node-1", State: jobs.DispatchStateResolved, Outcome: jobs.OutcomeCancelled})
	tasks := &snapshotTasks{fakeTaskRepository: fake, snapshot: []jobs.Task{stale}}
	router := NewRouter(nil, nil)
	reconciler := NewReconciler(tasks, router)

	send := &recordingSend{}
	unregister := router.Register("node-1", send.send)
	defer unregister()

	if err := reconciler.ReconcileNode(context.Background(), "node-1"); err != nil {
		t.Fatalf("ReconcileNode: %v", err)
	}
	if n := send.len(); n != 0 {
		t.Errorf("sends = %d, want 0", n)
	}
}

// TestReconciler_ReReadFailureWithholdsAndReportsError asserts the Reconciler
// fails closed: if it cannot re-read a Task's state it sends nothing, reports
// the error, and leaves the Task Dispatched for the next reconnect.
func TestReconciler_ReReadFailureWithholdsAndReportsError(t *testing.T) {
	task := jobs.Task{ID: "task-1", NodeID: "node-1", State: jobs.DispatchStateDispatched}
	fake := newFakeTaskRepository(task)
	readErr := errors.New("store unavailable")
	tasks := &snapshotTasks{fakeTaskRepository: fake, snapshot: []jobs.Task{task}, getErr: readErr}
	router := NewRouter(nil, nil)
	reconciler := NewReconciler(tasks, router)

	send := &recordingSend{}
	unregister := router.Register("node-1", send.send)
	defer unregister()

	err := reconciler.ReconcileNode(context.Background(), "node-1")
	if !errors.Is(err, readErr) {
		t.Fatalf("ReconcileNode error = %v, want it to wrap the read error", err)
	}
	if n := send.len(); n != 0 {
		t.Errorf("sends = %d, want 0", n)
	}
	got, _ := fake.Get(context.Background(), "task-1")
	if got.State != jobs.DispatchStateDispatched {
		t.Errorf("task-1 state = %v, want still Dispatched", got.State)
	}
}

// TestReconciler_ResendResolvesInFlightTask is the core restart-recovery
// path: an in-flight Task for nodeID is resent, its benign-or-real Result is
// Resolved, and it no longer appears in InFlight().
func TestReconciler_ResendResolvesInFlightTask(t *testing.T) {
	task := jobs.Task{ID: "task-1", NodeID: "node-1", State: jobs.DispatchStateDispatched}
	tasks := newFakeTaskRepository(task)
	router := NewRouter(nil, nil)
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
	router.Deliver("node-1", &relayv1.TaskResult{
		TaskId:  "task-1",
		Outcome: relayv1.Outcome_OUTCOME_SUCCESS,
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
	router := NewRouter(nil, nil)
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
	router.Deliver("node-1", &relayv1.TaskResult{TaskId: "task-1", Outcome: relayv1.Outcome_OUTCOME_SUCCESS})

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
	router := NewRouter(nil, nil)
	reconciler := NewReconciler(tasks, router)

	sendA := &recordingSend{}
	unregA := router.Register("node-1", sendA.send)
	defer unregA()

	done := make(chan error, 1)
	go func() { done <- reconciler.ReconcileNode(context.Background(), "node-1") }()

	waitUntil(t, time.Second, func() bool { return sendA.len() == 1 })
	router.Deliver("node-1", &relayv1.TaskResult{TaskId: "task-1", Outcome: relayv1.Outcome_OUTCOME_SUCCESS})

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
	router := NewRouter(nil, nil)
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
	router.Deliver("node-1", &relayv1.TaskResult{TaskId: "task-1", Outcome: relayv1.Outcome_OUTCOME_SUCCESS})

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

// TestReconciler_ForgedRelayOnlyOutcomeResolvesAsProtocolViolation is #632's
// regression test on the restart/reconnect path — the resend that gives a
// compromised Node a second chance to answer, which a fix scoped only to
// capability.jobEngine.dispatchOne would miss entirely.
func TestReconciler_ForgedRelayOnlyOutcomeResolvesAsProtocolViolation(t *testing.T) {
	task := jobs.Task{ID: "task-1", NodeID: "node-1", State: jobs.DispatchStateDispatched}
	tasks := newFakeTaskRepository(task)
	router := NewRouter(nil, nil)
	reconciler := NewReconciler(tasks, router)

	send := &recordingSend{}
	unregister := router.Register("node-1", send.send)
	defer unregister()

	done := make(chan error, 1)
	go func() { done <- reconciler.ReconcileNode(context.Background(), "node-1") }()

	waitUntil(t, time.Second, func() bool { return send.len() == 1 })

	router.Deliver("node-1", &relayv1.TaskResult{
		TaskId:  "task-1",
		Outcome: relayv1.Outcome_OUTCOME_VERSION_REFUSED,
		Stdout:  []byte("i actually ran"),
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
	if got.State != jobs.DispatchStateResolved {
		t.Fatalf("task-1 State = %v, want Resolved", got.State)
	}
	if got.Outcome != jobs.OutcomeFailure {
		t.Errorf("task-1 Outcome = %v, want jobs.OutcomeFailure (never the forged OutcomeVersionRefused)", got.Outcome)
	}
	if got.ExitCode != -1 {
		t.Errorf("task-1 ExitCode = %d, want -1", got.ExitCode)
	}
	if len(got.Stdout) != 0 {
		t.Errorf("task-1 Stdout = %q, want empty — the Node's claimed output must be discarded", got.Stdout)
	}
}

// TestReconciler_AForgedOutcomeOnReconnectIsRecorded is #638's reconnect-path
// acceptance test: the issue's "the reconnect path writes nothing" gap.
// reconcileTask dispatches through this same *Router (router.go), so the
// same recorder that closes the live-path gap closes this one too, with no
// audit sink on the Reconciler itself.
func TestReconciler_AForgedOutcomeOnReconnectIsRecorded(t *testing.T) {
	task := jobs.Task{ID: "task-1", JobID: "job-1", NodeID: "node-1", State: jobs.DispatchStateDispatched}
	tasks := newFakeTaskRepository(task)
	fake := &fakeViolationRecorder{}
	router := NewRouter(nil, fake)
	reconciler := NewReconciler(tasks, router)

	send := &recordingSend{}
	unregister := router.Register("node-1", send.send)
	defer unregister()

	done := make(chan error, 1)
	go func() { done <- reconciler.ReconcileNode(context.Background(), "node-1") }()

	waitUntil(t, time.Second, func() bool { return send.len() == 1 })

	router.Deliver("node-1", &relayv1.TaskResult{
		TaskId:  "task-1",
		Outcome: relayv1.Outcome_OUTCOME_VERSION_REFUSED,
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
	if got.State != jobs.DispatchStateResolved || got.Outcome != jobs.OutcomeFailure {
		t.Fatalf("task-1 State/Outcome = %v/%v, want Resolved/OutcomeFailure", got.State, got.Outcome)
	}

	events := fake.recorded()
	if len(events) != 1 {
		t.Fatalf("recorded %d protocol violation events, want exactly 1", len(events))
	}
	if events[0].JobID != "job-1" {
		t.Errorf("event JobID = %q, want job-1", events[0].JobID)
	}
	if events[0].TaskID != "task-1" {
		t.Errorf("event TaskID = %q, want task-1", events[0].TaskID)
	}
}

// TestReconciler_NoInFlightTasksIsANoOp asserts ReconcileNode on a Node with
// no in-flight Tasks returns cleanly without touching the Conduit.
func TestReconciler_NoInFlightTasksIsANoOp(t *testing.T) {
	tasks := newFakeTaskRepository()
	router := NewRouter(nil, nil)
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

// TestReconcileTask_RefusedTransitionIsTolerated pins that the in-memory
// Transition check sits in front of the Resolve write and feeds the existing
// tolerated branch. The store row is still Dispatched (so the send guard lets
// the resend through and a store Resolve WOULD succeed) while the snapshot
// the Reconciler holds says Resolved: without the check the Task would be
// resolved from a stale snapshot, with it nothing is written.
func TestReconcileTask_RefusedTransitionIsTolerated(t *testing.T) {
	stored := jobs.Task{ID: "task-1", NodeID: "node-1", State: jobs.DispatchStateDispatched}
	tasks := newFakeTaskRepository(stored)
	router := NewRouter(nil, nil)
	reconciler := NewReconciler(tasks, router)

	send := &recordingSend{}
	unregister := router.Register("node-1", send.send)
	defer unregister()

	snapshot := stored
	snapshot.State = jobs.DispatchStateResolved

	done := make(chan error, 1)
	go func() { done <- reconciler.reconcileTask(context.Background(), "node-1", snapshot) }()

	waitUntil(t, time.Second, func() bool { return send.len() == 1 })
	router.Deliver("node-1", &relayv1.TaskResult{TaskId: "task-1", Outcome: relayv1.Outcome_OUTCOME_SUCCESS})

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("reconcileTask: %v, want nil (a refused transition is tolerated)", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("reconcileTask did not return")
	}

	if send.len() != 1 {
		t.Errorf("sends = %d, want 1: the path must run past the resend", send.len())
	}
	if tasks.resolveCalls != 0 {
		t.Errorf("Resolve reached the store %d time(s); a refused transition must not", tasks.resolveCalls)
	}
}
