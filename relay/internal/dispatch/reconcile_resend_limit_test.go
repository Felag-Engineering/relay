package dispatch

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/Felag-Engineering/relay/relay/internal/jobs"
	relayv1 "github.com/Felag-Engineering/relay/relay/internal/relay/v1"
)

// testClock is a mutable injected clock; the tests move it, never sleep.
type testClock struct {
	mu  sync.Mutex
	now time.Time
}

func newTestClock() *testClock { return &testClock{now: testNow} }

func (c *testClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *testClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

type fakeHalts struct {
	mu    sync.Mutex
	calls map[string]jobs.Halt
	err   error
}

func (f *fakeHalts) RecordHalt(_ context.Context, jobID string, h jobs.Halt) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return f.err
	}
	if f.calls == nil {
		f.calls = make(map[string]jobs.Halt)
	}
	f.calls[jobID] = h
	return nil
}

func (f *fakeHalts) halt(jobID string) (jobs.Halt, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	h, ok := f.calls[jobID]
	return h, ok
}

type fakeResendLimitRecorder struct {
	mu          sync.Mutex
	settlements []jobs.Task
	results     []jobs.Result
	halts       []jobs.Halt
}

func (f *fakeResendLimitRecorder) RecordResendLimitSettlement(_ context.Context, task jobs.Task, res jobs.Result) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.settlements = append(f.settlements, task)
	f.results = append(f.results, res)
	return nil
}

func (f *fakeResendLimitRecorder) RecordResendLimitHalt(_ context.Context, _ jobs.Task, h jobs.Halt) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.halts = append(f.halts, h)
	return nil
}

func (f *fakeResendLimitRecorder) counts() (settlements, halts int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.settlements), len(f.halts)
}

type resendLimitFixture struct {
	clock      *testClock
	tasks      *fakeTaskRepository
	router     *Router
	halts      *fakeHalts
	rec        *fakeResendLimitRecorder
	reconciler *Reconciler
}

func newResendLimitFixture(tasks ...jobs.Task) *resendLimitFixture {
	f := &resendLimitFixture{
		clock: newTestClock(),
		tasks: newFakeTaskRepository(tasks...),
		halts: &fakeHalts{},
		rec:   &fakeResendLimitRecorder{},
	}
	f.router = NewRouter(nil, nil)
	f.reconciler = NewReconciler(f.tasks, f.router,
		WithReconcilerClock(f.clock.Now),
		WithResendLimitSettlement(f.halts, f.rec))
	return f
}

func dispatchedTask(id, jobID, nodeID string, class jobs.RiskClass, at time.Time) jobs.Task {
	return jobs.Task{
		ID: id, JobID: jobID, NodeID: nodeID,
		Action:       jobs.Action{RiskClass: class},
		State:        jobs.DispatchStateDispatched,
		DispatchedAt: at,
	}
}

func (f *resendLimitFixture) task(t *testing.T, id string) jobs.Task {
	t.Helper()
	got, err := f.tasks.Get(context.Background(), id)
	if err != nil {
		t.Fatalf("Get %s: %v", id, err)
	}
	return got
}

func assertResolvedAsOffline(t *testing.T, got jobs.Task, dispatchedAt time.Time) {
	t.Helper()
	if got.State != jobs.DispatchStateResolved || got.Outcome != jobs.OutcomeFailure || got.ExitCode != -1 ||
		string(got.Stderr) != jobs.NodeOfflineMessage {
		t.Errorf("task %s = %+v, want Resolved failure, exit -1, NodeOfflineMessage", got.ID, got)
	}
	if !got.DispatchedAt.Equal(dispatchedAt) {
		t.Errorf("task %s DispatchedAt = %v, want kept as %v", got.ID, got.DispatchedAt, dispatchedAt)
	}
}

// Proves EX-71.
func TestReconciler_ARestartResendsATaskDispatchedInsideTheResendLimit(t *testing.T) {
	at := testNow.Add(-ResendForResultLimit) // exactly at the limit
	f := newResendLimitFixture(dispatchedTask("task-1", "job-1", "node-1", jobs.RiskClassMutate, at))
	send := &recordingSend{}
	unregister := f.router.Register("node-1", send.send)
	defer unregister()

	done := make(chan error, 1)
	go func() { done <- f.reconciler.ReconcileNode(context.Background(), "node-1") }()

	waitUntil(t, time.Second, func() bool { return send.len() == 1 })
	if tr := send.last().GetTask(); tr == nil || tr.GetTaskId() != "task-1" {
		t.Fatalf("sent %+v, want a TaskRequest for task-1", send.last())
	}
	f.router.Deliver("node-1", &relayv1.TaskResult{TaskId: "task-1", Outcome: relayv1.Outcome_OUTCOME_SUCCESS})
	if err := <-done; err != nil {
		t.Fatalf("ReconcileNode: %v", err)
	}

	if got := f.task(t, "task-1"); got.State != jobs.DispatchStateResolved || got.Outcome != jobs.OutcomeSuccess {
		t.Errorf("task-1 = %+v, want Resolved success from the delivered result", got)
	}
	if s, h := f.rec.counts(); s != 0 || h != 0 {
		t.Errorf("recorded %d settlements and %d halts for a Task inside the limit, want none", s, h)
	}
}

// Proves EX-71.
func TestReconciler_ATaskPastTheResendLimitIsResolvedAndNothingReachesTheNode(t *testing.T) {
	at := testNow.Add(-ResendForResultLimit - time.Second)
	f := newResendLimitFixture(dispatchedTask("task-1", "job-1", "node-1", jobs.RiskClassRead, at))
	send := &recordingSend{}
	unregister := f.router.Register("node-1", send.send)
	defer unregister()

	if err := f.reconciler.ReconcileNode(context.Background(), "node-1"); err != nil {
		t.Fatalf("ReconcileNode: %v", err)
	}

	if send.len() != 0 {
		t.Errorf("sent %d messages for a Task past the limit, want none", send.len())
	}
	assertResolvedAsOffline(t, f.task(t, "task-1"), at)
	if len(f.rec.settlements) != 1 || f.rec.settlements[0].ID != "task-1" {
		t.Fatalf("settlements = %+v, want one for task-1", f.rec.settlements)
	}
	if res := f.rec.results[0]; res.Outcome != jobs.OutcomeFailure || string(res.Stderr) != jobs.NodeOfflineMessage {
		t.Errorf("audited result = %+v, want NodeOfflineResult", res)
	}
}

// Proves EX-71.
func TestReconciler_ATaskWithNoDispatchTimeIsPastTheResendLimit(t *testing.T) {
	f := newResendLimitFixture(dispatchedTask("task-1", "job-1", "node-1", jobs.RiskClassRead, time.Time{}))
	send := &recordingSend{}
	unregister := f.router.Register("node-1", send.send)
	defer unregister()

	if err := f.reconciler.ReconcileNode(context.Background(), "node-1"); err != nil {
		t.Fatalf("ReconcileNode: %v", err)
	}

	if send.len() != 0 {
		t.Errorf("sent %d messages for a Task with no dispatch time, want none", send.len())
	}
	assertResolvedAsOffline(t, f.task(t, "task-1"), time.Time{})
}

// A dispatch time later than the Relay's clock cannot be shown to be inside the
// limit, so it counts as past it.
// Proves EX-71.
func TestReconciler_ADispatchTimeInTheFutureIsPastTheResendLimit(t *testing.T) {
	f := newResendLimitFixture(dispatchedTask("task-1", "job-1", "node-1", jobs.RiskClassRead, testNow.Add(time.Minute)))
	send := &recordingSend{}
	unregister := f.router.Register("node-1", send.send)
	defer unregister()

	if err := f.reconciler.ReconcileNode(context.Background(), "node-1"); err != nil {
		t.Fatalf("ReconcileNode: %v", err)
	}
	if send.len() != 0 || f.task(t, "task-1").State != jobs.DispatchStateResolved {
		t.Errorf("sent %d, state %v; want nothing sent and Resolved", send.len(), f.task(t, "task-1").State)
	}
}

// Proves EX-71.
func TestReconciler_ATaskThatCrossesTheLimitWhileQueuedIsNotSent(t *testing.T) {
	first := dispatchedTask("task-1", "job-1", "node-1", jobs.RiskClassRead, testNow)
	second := dispatchedTask("task-2", "job-2", "node-1", jobs.RiskClassRead, testNow.Add(-ResendForResultLimit+time.Second))
	fake := newFakeTaskRepository(first, second)
	tasks := &snapshotTasks{fakeTaskRepository: fake, snapshot: []jobs.Task{first, second}}
	clock := newTestClock()
	rec := &fakeResendLimitRecorder{}
	router := NewRouter(nil, nil)
	reconciler := NewReconciler(tasks, router, WithReconcilerClock(clock.Now), WithResendLimitSettlement(&fakeHalts{}, rec))

	send := &recordingSend{}
	unregister := router.Register("node-1", func(m *relayv1.RelayMessage) error {
		// The first Task is on the wire; the second waits its turn behind it
		// and crosses its limit meanwhile.
		clock.Advance(2 * time.Second)
		return send.send(m)
	})
	defer unregister()

	done := make(chan error, 1)
	go func() { done <- reconciler.ReconcileNode(context.Background(), "node-1") }()
	waitUntil(t, time.Second, func() bool { return send.len() == 1 })
	router.Deliver("node-1", &relayv1.TaskResult{TaskId: "task-1", Outcome: relayv1.Outcome_OUTCOME_SUCCESS})
	if err := <-done; err != nil {
		t.Fatalf("ReconcileNode: %v", err)
	}

	if send.len() != 1 {
		t.Errorf("sent %d messages, want only task-1's", send.len())
	}
	got, _ := fake.Get(context.Background(), "task-2")
	assertResolvedAsOffline(t, got, second.DispatchedAt)
}

// Proves EX-71.
func TestReconciler_AReconnectAndAReplacedStreamNeverSendAPastLimitTask(t *testing.T) {
	f := newResendLimitFixture()
	var reconciler *Reconciler
	router := NewRouter(func(nodeID string) { _ = reconciler.ReconcileNode(context.Background(), nodeID) }, nil)
	reconciler = NewReconciler(f.tasks, router,
		WithReconcilerClock(f.clock.Now), WithResendLimitSettlement(f.halts, f.rec))
	send := &recordingSend{}

	seed := func(id string) {
		at := f.clock.Now().Add(-ResendForResultLimit - time.Minute)
		if err := f.tasks.CreateTask(context.Background(), dispatchedTask(id, "job-"+id, "node-1", jobs.RiskClassRead, at)); err != nil {
			t.Fatalf("CreateTask: %v", err)
		}
	}
	resolved := func(id string) func() bool {
		return func() bool { return f.task(t, id).State == jobs.DispatchStateResolved }
	}

	// A first connect (a restart).
	seed("task-restart")
	unregister := router.Register("node-1", send.send)
	waitUntil(t, time.Second, resolved("task-restart"))

	// A reconnect: the stream ends and a new one registers.
	seed("task-reconnect")
	unregister()
	unregister = router.Register("node-1", send.send)
	waitUntil(t, time.Second, resolved("task-reconnect"))

	// A replaced stream: a second stream registers over the first, with no
	// live send slot for the Task.
	seed("task-replaced")
	unregisterReplacement := router.Register("node-1", send.send)
	waitUntil(t, time.Second, resolved("task-replaced"))
	unregisterReplacement()
	unregister()

	if send.len() != 0 {
		t.Errorf("sent %d messages for Tasks past the limit, want none", send.len())
	}
	for _, id := range []string{"task-restart", "task-reconnect", "task-replaced"} {
		if got := f.task(t, id); got.Outcome != jobs.OutcomeFailure || got.ExitCode != -1 {
			t.Errorf("%s = %+v, want failure exit -1", id, got)
		}
	}
	if s, _ := f.rec.counts(); s != 3 {
		t.Errorf("settlements = %d, want one per Task (3)", s)
	}
}

// Proves EX-71.
func TestReconciler_APastLimitTaskOfAMutateJobHaltsIt(t *testing.T) {
	at := testNow.Add(-time.Hour)
	f := newResendLimitFixture(
		dispatchedTask("task-1", "job-1", "node-1", jobs.RiskClassMutate, at),
		jobs.Task{ID: "task-2", JobID: "job-1", NodeID: "node-2", Action: jobs.Action{RiskClass: jobs.RiskClassMutate}, State: jobs.DispatchStatePending},
	)
	unregister := f.router.Register("node-1", (&recordingSend{}).send)
	defer unregister()

	if err := f.reconciler.ReconcileNode(context.Background(), "node-1"); err != nil {
		t.Fatalf("ReconcileNode: %v", err)
	}

	want := jobs.Halt{TaskID: "task-1", NodeID: "node-1", Outcome: jobs.OutcomeFailure, Resolved: true, At: testNow}
	if h, ok := f.halts.halt("job-1"); !ok || h != want {
		t.Errorf("halt = %+v (recorded %v), want %+v", h, ok, want)
	}
	if s, h := f.rec.counts(); s != 1 || h != 1 {
		t.Errorf("audited %d settlements and %d halts, want 1 and 1", s, h)
	}
	if got := f.task(t, "task-2"); got.State != jobs.DispatchStatePending {
		t.Errorf("sibling task-2 state = %v, want untouched Pending (EX-28 sweeps it at the next start)", got.State)
	}
}

// Proves EX-71.
func TestReconciler_APastLimitTaskOfAReadJobDoesNotHaltIt(t *testing.T) {
	f := newResendLimitFixture(dispatchedTask("task-1", "job-1", "node-1", jobs.RiskClassRead, testNow.Add(-time.Hour)))
	unregister := f.router.Register("node-1", (&recordingSend{}).send)
	defer unregister()

	if err := f.reconciler.ReconcileNode(context.Background(), "node-1"); err != nil {
		t.Fatalf("ReconcileNode: %v", err)
	}
	if _, ok := f.halts.halt("job-1"); ok {
		t.Error("a read Job was halted")
	}
	if s, h := f.rec.counts(); s != 1 || h != 0 {
		t.Errorf("audited %d settlements and %d halts, want 1 and 0", s, h)
	}
}

// Proves EX-71.
func TestReconciler_APastLimitTaskOfATemplateJobHaltsOnItsMostRestrictiveClass(t *testing.T) {
	f := newResendLimitFixture(
		dispatchedTask("task-1", "job-1", "node-1", jobs.RiskClassRead, testNow.Add(-time.Hour)),
		dispatchedTask("task-2", "job-1", "node-2", jobs.RiskClassMutate, testNow),
	)
	unregister := f.router.Register("node-1", (&recordingSend{}).send)
	defer unregister()

	if err := f.reconciler.ReconcileNode(context.Background(), "node-1"); err != nil {
		t.Fatalf("ReconcileNode: %v", err)
	}
	if h, ok := f.halts.halt("job-1"); !ok || h.TaskID != "task-1" {
		t.Errorf("halt = %+v (recorded %v), want the Job halted by task-1", h, ok)
	}
}

// Proves EX-71.
func TestReconciler_AnAlreadyHaltedJobIsNotHaltedOrAuditedTwice(t *testing.T) {
	f := newResendLimitFixture(dispatchedTask("task-1", "job-1", "node-1", jobs.RiskClassMutate, testNow.Add(-time.Hour)))
	f.halts.err = jobs.ErrJobAlreadyHalted
	unregister := f.router.Register("node-1", (&recordingSend{}).send)
	defer unregister()

	if err := f.reconciler.ReconcileNode(context.Background(), "node-1"); err != nil {
		t.Fatalf("ReconcileNode = %v, want nil for an already halted Job", err)
	}
	if s, h := f.rec.counts(); s != 1 || h != 0 {
		t.Errorf("audited %d settlements and %d halts, want 1 and 0", s, h)
	}
}

// Proves EX-71.
func TestReconciler_APastLimitTaskWhoseNodeHasNotConnectedStaysDispatched(t *testing.T) {
	f := newResendLimitFixture(
		dispatchedTask("task-1", "job-1", "node-1", jobs.RiskClassMutate, testNow.Add(-time.Hour)),
	)
	unregister := f.router.Register("node-2", (&recordingSend{}).send)
	defer unregister()

	if err := f.reconciler.ReconcileNode(context.Background(), "node-2"); err != nil {
		t.Fatalf("ReconcileNode: %v", err)
	}
	if got := f.task(t, "task-1"); got.State != jobs.DispatchStateDispatched {
		t.Errorf("task-1 state = %v, want still Dispatched", got.State)
	}
	if s, h := f.rec.counts(); s != 0 || h != 0 {
		t.Errorf("audited %d settlements and %d halts, want none", s, h)
	}
}

// Proves EX-71.
func TestWithinResendLimit(t *testing.T) {
	cases := []struct {
		name string
		at   time.Time
		want bool
	}{
		{"now", testNow, true},
		{"at the limit", testNow.Add(-ResendForResultLimit), true},
		{"past the limit", testNow.Add(-ResendForResultLimit - time.Nanosecond), false},
		{"no dispatch time", time.Time{}, false},
		{"in the future", testNow.Add(time.Nanosecond), false},
	}
	for _, c := range cases {
		if got := withinResendLimit(c.at, testNow); got != c.want {
			t.Errorf("%s: withinResendLimit = %v, want %v", c.name, got, c.want)
		}
	}
}

// Proves EX-71.
func TestReconciler_AFailedResolveOfAPastLimitTaskLeavesItDispatchedAndIsReported(t *testing.T) {
	f := newResendLimitFixture(dispatchedTask("task-1", "job-1", "node-1", jobs.RiskClassMutate, testNow.Add(-time.Hour)))
	boom := errors.New("store down")
	repo := &failingResolve{fakeTaskRepository: f.tasks, err: boom}
	reconciler := NewReconciler(repo, f.router, WithReconcilerClock(f.clock.Now), WithResendLimitSettlement(f.halts, f.rec))
	unregister := f.router.Register("node-1", (&recordingSend{}).send)
	defer unregister()

	if err := reconciler.ReconcileNode(context.Background(), "node-1"); !errors.Is(err, boom) {
		t.Fatalf("ReconcileNode = %v, want the store error", err)
	}
	if got := f.task(t, "task-1"); got.State != jobs.DispatchStateDispatched {
		t.Errorf("task-1 state = %v, want still Dispatched", got.State)
	}
	if s, h := f.rec.counts(); s != 0 || h != 0 {
		t.Errorf("audited %d settlements and %d halts, want none", s, h)
	}
}

// Proves EX-71.
func TestReconciler_AResendPastTheLimitIsWithheldWhileTheOriginalSendStillHoldsTheSlot(t *testing.T) {
	f := newResendLimitFixture(dispatchedTask("task-1", "job-1", "node-1", jobs.RiskClassMutate, testNow))

	entered := make(chan struct{})
	release := make(chan struct{})
	stalled := func(*relayv1.RelayMessage) error {
		close(entered)
		<-release
		return nil
	}
	unregisterOld := f.router.Register("node-1", stalled)
	defer unregisterOld()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	origDone := make(chan struct{})
	go func() {
		defer close(origDone)
		_, _ = f.router.Dispatch(ctx, "node-1", jobs.Task{ID: "task-1", NodeID: "node-1"})
	}()
	<-entered // the original send holds the slot, already marked sent

	f.clock.Advance(ResendForResultLimit + time.Second)

	replacement := &recordingSend{}
	unregisterNew := f.router.Register("node-1", replacement.send)
	defer unregisterNew()
	if err := f.reconciler.ReconcileNode(context.Background(), "node-1"); err != nil {
		t.Fatalf("ReconcileNode: %v", err)
	}
	close(release)
	cancel()
	<-origDone

	if replacement.len() != 0 {
		t.Errorf("replacement stream received %d messages, want none past the limit", replacement.len())
	}
	assertResolvedAsOffline(t, f.task(t, "task-1"), testNow)
	if s, h := f.rec.counts(); s != 1 || h != 1 {
		t.Errorf("recorded %d settlements and %d halts, want 1 and 1", s, h)
	}
	if _, ok := f.halts.halt("job-1"); !ok {
		t.Error("a past-limit mutate Task did not halt its Job")
	}
}

type failingResolve struct {
	*fakeTaskRepository
	err error
}

func (f *failingResolve) Resolve(context.Context, string, jobs.Result) error { return f.err }
