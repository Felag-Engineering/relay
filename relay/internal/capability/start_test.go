package capability

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/approval"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/jobs"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/registry"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/store"
)

// start_test.go is #895's capability-seam proof: Service.Start returns once a
// Job's Tasks are persisted, finishes the fan-out and accounting in the
// background, and a keyed call re-issued after a lost response never
// dispatches twice. The existing Run suites passing unmodified prove the
// prepareDispatch/account refactor.

// gateConduit is a Conduit whose Dispatch counts calls per Node and, while gate
// is set, blocks until it is released or the context ends.
type gateConduit struct {
	mu    sync.Mutex
	gate  chan struct{}
	calls map[string]int
	once  sync.Once
}

func newGateConduit() *gateConduit { return &gateConduit{calls: map[string]int{}} }

func (c *gateConduit) block() {
	c.mu.Lock()
	c.gate = make(chan struct{})
	c.mu.Unlock()
}

func (c *gateConduit) release() {
	c.mu.Lock()
	g := c.gate
	c.mu.Unlock()
	if g != nil {
		c.once.Do(func() { close(g) })
	}
}

func (c *gateConduit) dispatched(nodeID string) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.calls[nodeID]
}

func (c *gateConduit) Connected(string) bool { return true }

func (c *gateConduit) Dispatch(ctx context.Context, nodeID string, _ jobs.Task) (jobs.Result, error) {
	c.mu.Lock()
	c.calls[nodeID]++
	g := c.gate
	c.mu.Unlock()
	if g != nil {
		select {
		case <-g:
		case <-ctx.Done():
			return jobs.Result{}, ctx.Err()
		}
	}
	return jobs.Result{Outcome: jobs.OutcomeSuccess}, nil
}

func (c *gateConduit) Cancel(context.Context, string, string) error { return nil }

func (c *gateConduit) Query(context.Context, string, jobs.Action) (jobs.Verdict, error) {
	return jobs.Verdict{}, nil
}

// hookIntents wraps nonAtomicIntents so a test can hold a Job inside
// RecordIntent (after its key is claimed, before its Tasks exist) or fail it.
type hookIntents struct {
	inner *nonAtomicIntents

	mu      sync.Mutex
	entered chan struct{}
	gate    chan struct{}
	enter   sync.Once
	fail    error
}

// arm makes the next RecordIntent block; entered closes when one has.
func (h *hookIntents) arm() (entered <-chan struct{}, release func()) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.entered = make(chan struct{})
	h.gate = make(chan struct{})
	h.enter = sync.Once{}
	g := h.gate
	var once sync.Once
	return h.entered, func() { once.Do(func() { close(g) }) }
}

func (h *hookIntents) setFail(err error) {
	h.mu.Lock()
	h.fail = err
	h.mu.Unlock()
}

func (h *hookIntents) RecordIntent(ctx context.Context, e AuditEntry, tasks []jobs.Task) error {
	h.mu.Lock()
	entered, gate, fail := h.entered, h.gate, h.fail
	h.mu.Unlock()
	if gate != nil {
		h.enter.Do(func() { close(entered) })
		<-gate
	}
	if fail != nil {
		return fail
	}
	return h.inner.RecordIntent(ctx, e, tasks)
}

// spyIdem wraps the real repository, counting calls and running a hook after a
// won Claim.
type spyIdem struct {
	jobs.IdempotencyRepository
	calls      atomic.Int32
	seen       atomic.Int32 // calls that found another call's record: a Claim that lost, or a Lookup that hit
	afterClaim func()
}

func (s *spyIdem) Claim(ctx context.Context, rec jobs.IdempotencyRecord, nb time.Time) (jobs.IdempotencyRecord, bool, error) {
	s.calls.Add(1)
	existing, won, err := s.IdempotencyRepository.Claim(ctx, rec, nb)
	if err == nil && !won {
		s.seen.Add(1)
	}
	if won && s.afterClaim != nil {
		s.afterClaim()
	}
	return existing, won, err
}

func (s *spyIdem) Lookup(ctx context.Context, a, k string, nb time.Time) (jobs.IdempotencyRecord, bool, error) {
	s.calls.Add(1)
	rec, found, err := s.IdempotencyRepository.Lookup(ctx, a, k, nb)
	if err == nil && found {
		s.seen.Add(1)
	}
	return rec, found, err
}

type startFx struct {
	svc     *testSvc
	st      *store.Store
	conduit *gateConduit
	audit   *spyAuditSink
	intents *hookIntents
	idem    *spyIdem
	freeze  *fakeFreezeStore
	authz   *spyAuthorizer

	mu  sync.Mutex
	now time.Time
}

func (f *startFx) setNow(t time.Time) {
	f.mu.Lock()
	f.now = t
	f.mu.Unlock()
}

func (f *startFx) clockNow() time.Time {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.now
}

var (
	startNow  = time.Date(2026, 10, 9, 9, 0, 0, 0, time.UTC)
	alice     = Principal{AccountID: "acct-1", Account: "alice"}
	factsAct  = jobs.Action{Kind: jobs.ActionOperation, OperationName: "system.facts"}
	startNode = []string{"node-a", "node-b"}
)

// newStartFx wires a real Job engine over a real store with the spies above.
// Cleanups run last-in-first-out: the conduit is released, the Service is
// drained, and only then does the store close.
func newStartFx(t *testing.T, mods ...func(*seams)) *startFx {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "relay.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { st.Close() })

	reg := registry.NewInMemory()
	for _, id := range startNode {
		if _, err := reg.Upsert(registry.Report{NodeID: id}); err != nil {
			t.Fatalf("seed registry: %v", err)
		}
	}
	f := &startFx{
		st:      st,
		conduit: newGateConduit(),
		audit:   &spyAuditSink{},
		freeze:  &fakeFreezeStore{},
		authz:   &spyAuthorizer{},
		idem:    &spyIdem{IdempotencyRepository: st.IdempotencyKeys()},
		now:     startNow,
	}
	f.intents = &hookIntents{inner: &nonAtomicIntents{tr: st.Tasks()}}
	s := seams{
		reg:       reg,
		authz:     f.authz,
		cap:       &spyCapChecker{},
		audit:     f.audit,
		freeze:    f.freeze,
		now:       f.clockNow,
		idem:      f.idem,
		jobsRepo:  st.Jobs(),
		tasksRepo: st.Tasks(),
		conduit:   f.conduit,
		intents:   f.intents,
	}
	// A caller's mod runs after the fixture's, so it wins: mods apply in order, last one wins.
	for _, mod := range mods {
		mod(&s)
	}
	f.svc = build(t, s)

	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := f.svc.Drain(ctx); err != nil {
			t.Errorf("background Jobs did not drain before the store closed: %v", err)
		}
	})
	t.Cleanup(f.conduit.release)
	return f
}

func (f *startFx) tasks(t *testing.T, jobID string) []jobs.Task {
	t.Helper()
	ts, err := f.st.Tasks().ByJob(context.Background(), jobID)
	if err != nil {
		t.Fatalf("Tasks().ByJob: %v", err)
	}
	return ts
}

func waitClosed(t *testing.T, ch <-chan struct{}, what string) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(10 * time.Second):
		t.Fatalf("timed out waiting for %s", what)
	}
}

func isClosed(ch <-chan struct{}) bool {
	select {
	case <-ch:
		return true
	default:
		return false
	}
}

func keyed(k string) StartOptions { return StartOptions{IdempotencyKey: k} }

type startResult struct {
	sj  StartedJob
	err error
}

// startAsync runs Start on its own goroutine.
func (f *startFx) startAsync(p Principal, act jobs.Action, o StartOptions) <-chan startResult {
	ch := make(chan startResult, 1)
	go func() {
		sj, err := f.svc.Start(context.Background(), p, Selector{}, act, o)
		ch <- startResult{sj, err}
	}()
	return ch
}

func recv(t *testing.T, ch <-chan startResult, what string) startResult {
	t.Helper()
	select {
	case r := <-ch:
		return r
	case <-time.After(10 * time.Second):
		t.Fatalf("timed out waiting for %s", what)
		return startResult{}
	}
}

func (f *startFx) readTools() []string {
	f.audit.mu.Lock()
	defer f.audit.mu.Unlock()
	var out []string
	for _, r := range f.audit.readCalls {
		out = append(out, r.Tool)
	}
	return out
}

func TestStart_ReturnsOnceTasksArePersistedBeforeAnyResolves(t *testing.T) {
	f := newStartFx(t)
	f.conduit.block()

	sj, err := f.svc.Start(context.Background(), alice, Selector{}, factsAct, StartOptions{})
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	if sj.JobID == "" || sj.Reattached {
		t.Fatalf("StartedJob = %+v, want a fresh Job", sj)
	}
	tasks := f.tasks(t, sj.JobID)
	if len(tasks) != len(startNode) {
		t.Fatalf("persisted Tasks = %d, want one per Node (%d)", len(tasks), len(startNode))
	}
	for _, tk := range tasks {
		if tk.State == jobs.DispatchStateResolved {
			t.Errorf("Task %s resolved while its Node is still silent", tk.NodeID)
		}
	}
	if isClosed(sj.Done) {
		t.Fatal("Done closed before the fan-out finished")
	}

	f.conduit.release()
	waitClosed(t, sj.Done, "Done")
	for _, tk := range f.tasks(t, sj.JobID) {
		if tk.State != jobs.DispatchStateResolved {
			t.Errorf("Task %s state = %v after Done, want Resolved", tk.NodeID, tk.State)
		}
	}
}

func TestStart_CallerCancellationDoesNotAbandonTheJob(t *testing.T) {
	f := newStartFx(t)
	f.conduit.block()

	ctx, cancel := context.WithCancel(context.Background())
	sj, err := f.svc.Start(ctx, alice, Selector{}, factsAct, StartOptions{})
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	cancel()
	f.conduit.release()
	waitClosed(t, sj.Done, "Done")

	for _, tk := range f.tasks(t, sj.JobID) {
		if tk.State != jobs.DispatchStateResolved || tk.Outcome != jobs.OutcomeSuccess {
			t.Errorf("Task %s = state %v outcome %v, want Resolved success: a cancelled caller must not abandon the Job", tk.NodeID, tk.State, tk.Outcome)
		}
	}
}

func TestStart_DoneClosesAfterTheDispatchAuditRecord(t *testing.T) {
	f := newStartFx(t)
	sj, err := f.svc.Start(context.Background(), alice, Selector{}, factsAct, StartOptions{})
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	waitClosed(t, sj.Done, "Done")

	f.audit.mu.Lock()
	defer f.audit.mu.Unlock()
	found := false
	for _, e := range f.audit.entries {
		if e.Kind == AuditKindDispatch && e.JobID == sj.JobID {
			found = true
			if len(e.Results) != len(startNode) {
				t.Errorf("dispatch record carries %d results, want %d", len(e.Results), len(startNode))
			}
		}
	}
	if !found {
		t.Fatal("no KindDispatch record for the Job by the time Done closed")
	}
}

func TestStart_DrainWaitsForBackgroundJobs(t *testing.T) {
	f := newStartFx(t)
	f.conduit.block()
	sj, err := f.svc.Start(context.Background(), alice, Selector{}, factsAct, StartOptions{})
	if err != nil {
		t.Fatalf("Start: %v", err)
	}

	short, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if err := f.svc.Drain(short); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Drain with a Job still running = %v, want the context's error", err)
	}

	f.conduit.release()
	long, cancel2 := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel2()
	if err := f.svc.Drain(long); err != nil {
		t.Fatalf("Drain after the Job finished = %v, want nil", err)
	}
	if !isClosed(sj.Done) {
		t.Error("Drain returned before Done closed")
	}
}

func TestStart_RefusesOnceDraining(t *testing.T) {
	f := newStartFx(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := f.svc.Drain(ctx); err != nil {
		t.Fatalf("Drain: %v", err)
	}
	_, err := f.svc.Start(context.Background(), alice, Selector{}, factsAct, StartOptions{})
	if !errors.Is(err, ErrDraining) {
		t.Fatalf("Start after Drain = %v, want ErrDraining", err)
	}
	if n := f.conduit.dispatched("node-a"); n != 0 {
		t.Errorf("a draining Service dispatched %d Tasks", n)
	}
}

func TestStart_SameKeyReattachesAndDispatchesNothing(t *testing.T) {
	f := newStartFx(t)
	first, err := f.svc.Start(context.Background(), alice, Selector{}, factsAct, keyed("k-1"))
	if err != nil {
		t.Fatalf("first Start: %v", err)
	}
	waitClosed(t, first.Done, "first Done")

	again, err := f.svc.Start(context.Background(), alice, Selector{}, factsAct, keyed("k-1"))
	if err != nil {
		t.Fatalf("re-issued Start: %v", err)
	}
	if !again.Reattached || again.JobID != first.JobID {
		t.Fatalf("re-issue = %+v, want Reattached to %s", again, first.JobID)
	}
	if !isClosed(again.Done) {
		t.Error("a re-attached StartedJob's Done must already be closed")
	}
	for _, n := range startNode {
		if got := f.conduit.dispatched(n); got != 1 {
			t.Errorf("node %s dispatched %d times, want 1", n, got)
		}
	}
	reads := f.readTools()
	if len(reads) != 1 || reads[0] != toolIdempotentReattach {
		t.Errorf("audited reads = %v, want exactly one %s", reads, toolIdempotentReattach)
	}
}

func TestStart_SameKeyDifferentArgumentsIsRefusedAndAudited(t *testing.T) {
	f := newStartFx(t)
	first, err := f.svc.Start(context.Background(), alice, Selector{}, factsAct, keyed("k-1"))
	if err != nil {
		t.Fatalf("first Start: %v", err)
	}
	waitClosed(t, first.Done, "first Done")

	other := factsAct
	other.TimeoutSeconds = 10
	_, err = f.svc.Start(context.Background(), alice, Selector{}, other, keyed("k-1"))
	var conflict *IdempotencyConflictError
	if !errors.As(err, &conflict) {
		t.Fatalf("Start with changed arguments = %v, want *IdempotencyConflictError", err)
	}
	if strings.Contains(err.Error(), "k-1") {
		t.Error("the conflict error names the key; errors land in the audit Reason")
	}
	f.audit.mu.Lock()
	refused := hasAuditKind(f.audit.entries, AuditKindRefusal)
	f.audit.mu.Unlock()
	if !refused {
		t.Error("the conflict was not audited as a refusal")
	}
	for _, n := range startNode {
		if got := f.conduit.dispatched(n); got != 1 {
			t.Errorf("node %s dispatched %d times, want 1", n, got)
		}
	}
}

func TestStart_ConcurrentSameKeyDispatchesExactlyOneJob(t *testing.T) {
	f := newStartFx(t)
	const n = 8
	results := make([]startResult, n)
	var wg sync.WaitGroup
	for i := range results {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sj, err := f.svc.Start(context.Background(), alice, Selector{}, factsAct, keyed("k-race"))
			results[i] = startResult{sj, err}
		}()
	}
	wg.Wait()

	fresh := 0
	var jobID string
	for _, r := range results {
		var pending *IdempotencyPendingError
		switch {
		case r.err == nil && !r.sj.Reattached:
			fresh++
			jobID = r.sj.JobID
		case r.err == nil:
		case errors.As(r.err, &pending):
		default:
			t.Errorf("unexpected error: %v", r.err)
		}
	}
	if fresh != 1 {
		t.Fatalf("%d calls dispatched, want exactly 1", fresh)
	}
	for _, r := range results {
		if r.err == nil && r.sj.JobID != jobID {
			t.Errorf("a re-attach returned %s, want the one Job %s", r.sj.JobID, jobID)
		}
	}
	for _, node := range startNode {
		deadline := time.Now().Add(5 * time.Second)
		for f.conduit.dispatched(node) < 1 && time.Now().Before(deadline) {
			time.Sleep(5 * time.Millisecond)
		}
		if got := f.conduit.dispatched(node); got != 1 {
			t.Errorf("node %s dispatched %d times, want 1", node, got)
		}
	}
}

// B1: a re-issue that arrives while the first call is still persisting waits
// for it, then re-attaches.
func TestStart_ReissueWhilePersistingWaitsThenReattaches(t *testing.T) {
	f := newStartFx(t)
	entered, release := f.intents.arm()
	defer release()

	a := f.startAsync(alice, factsAct, keyed("k-1"))
	waitClosed(t, entered, "A inside RecordIntent")
	b := f.startAsync(alice, factsAct, keyed("k-1"))

	select {
	case r := <-b:
		t.Fatalf("B returned while A was still persisting: %+v", r)
	case <-time.After(100 * time.Millisecond):
	}

	release()
	ra := recv(t, a, "A")
	rb := recv(t, b, "B")
	if ra.err != nil || rb.err != nil {
		t.Fatalf("A err=%v, B err=%v", ra.err, rb.err)
	}
	if !rb.sj.Reattached || rb.sj.JobID != ra.sj.JobID {
		t.Fatalf("B = %+v, want Reattached to A's Job %s", rb.sj, ra.sj.JobID)
	}
	if len(f.tasks(t, ra.sj.JobID)) != len(startNode) {
		t.Error("the Job's Tasks do not exist after B re-attached")
	}
	waitClosed(t, ra.sj.Done, "A's Done")
	for _, n := range startNode {
		if got := f.conduit.dispatched(n); got != 1 {
			t.Errorf("node %s dispatched %d times, want 1", n, got)
		}
	}
}

// B1: while the original might still persist, a re-issue is never told to use
// a new key.
func TestStart_ReissueWhileStuckPersistingIsPendingNeverNewKey(t *testing.T) {
	f := newStartFx(t)
	f.svc.reattachPersistWait = 50 * time.Millisecond
	entered, release := f.intents.arm()
	defer release()

	a := f.startAsync(alice, factsAct, keyed("k-1"))
	waitClosed(t, entered, "A inside RecordIntent")

	_, err := f.svc.Start(context.Background(), alice, Selector{}, factsAct, keyed("k-1"))
	var pending *IdempotencyPendingError
	if !errors.As(err, &pending) {
		t.Fatalf("re-issue while A is stuck = %v, want *IdempotencyPendingError", err)
	}
	msg := err.Error()
	if !strings.Contains(msg, "get_job") || !strings.Contains(msg, "same key") {
		t.Errorf("pending message %q must point at get_job and the same key", msg)
	}
	if !strings.Contains(msg, "Do not use a new key") || strings.Contains(msg, "new key is safe") {
		t.Errorf("pending message %q must forbid a new key while the original may still run", msg)
	}
	if reads := f.readTools(); len(reads) != 1 || reads[0] != toolIdempotentPending {
		t.Errorf("audited reads = %v, want one %s", reads, toolIdempotentPending)
	}

	release()
	ra := recv(t, a, "A")
	if ra.err != nil {
		t.Fatalf("A: %v", ra.err)
	}
	if pending.JobID != ra.sj.JobID {
		t.Errorf("pending named %s, want A's Job %s", pending.JobID, ra.sj.JobID)
	}
	third, err := f.svc.Start(context.Background(), alice, Selector{}, factsAct, keyed("k-1"))
	if err != nil || !third.Reattached || third.JobID != ra.sj.JobID {
		t.Fatalf("third re-issue = %+v, %v; want a re-attach to %s", third, err, ra.sj.JobID)
	}
}

// B1: a claim with no Job and no live claimer is Pending until the abandon
// bound, and only then may a new key be suggested.
func TestStart_UnpersistedClaimIsPendingUntilTheAbandonBound(t *testing.T) {
	f := newStartFx(t)
	rec := jobs.IdempotencyRecord{
		AccountID: alice.AccountID, Key: "k-ghost", JobID: "job-ghost", CreatedAt: startNow,
		RequestDigest: jobs.RequestDigest(Selector{}.String(), factsAct),
	}
	if _, won, err := f.st.IdempotencyKeys().Claim(context.Background(), rec, startNow.Add(-IdempotencyWindow)); err != nil || !won {
		t.Fatalf("seed claim: won=%v err=%v", won, err)
	}

	f.setNow(startNow.Add(time.Minute))
	_, err := f.svc.Start(context.Background(), alice, Selector{}, factsAct, keyed("k-ghost"))
	var pending *IdempotencyPendingError
	if !errors.As(err, &pending) || pending.JobID != "job-ghost" {
		t.Fatalf("age 1m: err = %v, want Pending for job-ghost", err)
	}

	f.setNow(startNow.Add(11 * time.Minute))
	_, err = f.svc.Start(context.Background(), alice, Selector{}, factsAct, keyed("k-ghost"))
	var abandoned *IdempotencyAbandonedError
	if !errors.As(err, &abandoned) {
		t.Fatalf("age 11m: err = %v, want *IdempotencyAbandonedError", err)
	}
	if !strings.Contains(err.Error(), "new key") {
		t.Errorf("abandoned message %q must say a new key is safe", err.Error())
	}
	if n := f.conduit.dispatched("node-a"); n != 0 {
		t.Errorf("a pending/abandoned answer dispatched %d Tasks", n)
	}
}

// waitRecordSeen blocks until a keyed call has found another call's record (a
// re-issue finds it by Lookup; a concurrent first call by a lost Claim), so
// the test releases A only once B is committed to re-attaching rather than
// claiming afresh.
func waitRecordSeen(t *testing.T, idem *spyIdem, what string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for idem.seen.Load() < 1 {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(time.Millisecond)
	}
}

func TestStart_ReissueAfterTheOriginalFailedIsToldToRetryTheSameKey(t *testing.T) {
	f := newStartFx(t)
	entered, release := f.intents.arm()
	defer release()
	f.intents.setFail(errors.New("store unavailable"))

	a := f.startAsync(alice, factsAct, keyed("k-1"))
	waitClosed(t, entered, "A inside RecordIntent")
	b := f.startAsync(alice, factsAct, keyed("k-1"))
	waitRecordSeen(t, f.idem, "B to find A's record")
	release()

	if ra := recv(t, a, "A"); ra.err == nil {
		t.Fatal("A succeeded; the test needs it to fail")
	}
	rb := recv(t, b, "B")
	var released *IdempotencyReleasedError
	if !errors.As(rb.err, &released) {
		t.Fatalf("B = %v, want *IdempotencyReleasedError", rb.err)
	}
	if !strings.Contains(rb.err.Error(), "same key") || strings.Contains(rb.err.Error(), "use a new key") {
		t.Errorf("released message %q must tell the caller to retry with the same key", rb.err.Error())
	}

	f.intents.setFail(nil)
	c, err := f.svc.Start(context.Background(), alice, Selector{}, factsAct, keyed("k-1"))
	if err != nil || c.Reattached {
		t.Fatalf("retry with the same key = %+v, %v; want a fresh dispatch", c, err)
	}
}

// S4: a dropped stream right after the claim must not leave the key bound to a
// Job that never existed.
func TestStart_KeyReleaseSurvivesCallerCancellation(t *testing.T) {
	f := newStartFx(t)
	ctx, cancel := context.WithCancel(context.Background())
	f.idem.afterClaim = cancel
	f.intents.setFail(errors.New("store unavailable"))

	if _, err := f.svc.Start(ctx, alice, Selector{}, factsAct, keyed("k-1")); err == nil {
		t.Fatal("Start succeeded; the test needs the persist to fail")
	}
	f.idem.afterClaim = nil
	if _, found, err := f.st.IdempotencyKeys().Lookup(context.Background(), alice.AccountID, "k-1", startNow.Add(-IdempotencyWindow)); err != nil || found {
		t.Fatalf("key after a cancelled, failed call: found=%v err=%v; want it released", found, err)
	}

	f.intents.setFail(nil)
	sj, err := f.svc.Start(context.Background(), alice, Selector{}, factsAct, keyed("k-1"))
	if err != nil || sj.Reattached {
		t.Fatalf("re-issue = %+v, %v; want a fresh dispatch", sj, err)
	}
}

// S5: Freeze and authorization stay outermost; a keyed call refused by either
// touches no key.
func TestStart_FrozenAndUnauthorizedRefuseBeforeAnyKeyValidationOrLookup(t *testing.T) {
	f := newStartFx(t)
	f.freeze.frozen = true
	_, err := f.svc.Start(context.Background(), alice, Selector{}, factsAct, keyed("bad key"))
	var frozen *FrozenError
	if !errors.As(err, &frozen) {
		t.Fatalf("frozen + invalid key = %v, want *FrozenError", err)
	}

	f.freeze.frozen = false
	f.authz.err = errors.New("denied")
	_, err = f.svc.Start(context.Background(), alice, Selector{}, factsAct, keyed("bad key"))
	if err == nil || errors.As(err, new(*IdempotencyKeyError)) {
		t.Fatalf("unauthorized + invalid key = %v, want the authorization refusal", err)
	}
	if n := f.idem.calls.Load(); n != 0 {
		t.Errorf("key repository called %d times before Freeze/authorization refused", n)
	}
}

func TestStart_InvalidKeyIsRefusedWithoutDispatching(t *testing.T) {
	f := newStartFx(t)
	for _, key := range []string{"has space", "tab\there", "ünï", strings.Repeat("k", MaxIdempotencyKeyBytes+1)} {
		_, err := f.svc.Start(context.Background(), alice, Selector{}, factsAct, keyed(key))
		var ke *IdempotencyKeyError
		if !errors.As(err, &ke) {
			t.Errorf("key %q: err = %v, want *IdempotencyKeyError", key, err)
		}
	}
	if n := f.conduit.dispatched("node-a"); n != 0 {
		t.Errorf("an invalid key dispatched %d Tasks", n)
	}
}

func TestStart_KeyIsScopedToTheAccount(t *testing.T) {
	f := newStartFx(t)
	bob := Principal{AccountID: "acct-2", Account: "bob"}
	a, err := f.svc.Start(context.Background(), alice, Selector{}, factsAct, keyed("k-1"))
	if err != nil {
		t.Fatalf("alice: %v", err)
	}
	b, err := f.svc.Start(context.Background(), bob, Selector{}, factsAct, keyed("k-1"))
	if err != nil {
		t.Fatalf("bob: %v", err)
	}
	if a.Reattached || b.Reattached || a.JobID == b.JobID {
		t.Fatalf("alice=%+v bob=%+v; the same key from two Accounts must be two Jobs", a, b)
	}
}

func TestStart_KeyPastTheWindowDispatchesAfresh(t *testing.T) {
	f := newStartFx(t)
	a, err := f.svc.Start(context.Background(), alice, Selector{}, factsAct, keyed("k-1"))
	if err != nil {
		t.Fatalf("first: %v", err)
	}
	waitClosed(t, a.Done, "first Done")

	f.setNow(startNow.Add(IdempotencyWindow + time.Hour))
	b, err := f.svc.Start(context.Background(), alice, Selector{}, factsAct, keyed("k-1"))
	if err != nil || b.Reattached || b.JobID == a.JobID {
		t.Fatalf("after the window = %+v, %v; want a fresh Job", b, err)
	}
}

func TestStart_KeyWithoutAnAccountStoreOrEngineIsRefused(t *testing.T) {
	t.Run("no AccountID", func(t *testing.T) {
		f := newStartFx(t)
		_, err := f.svc.Start(context.Background(), Principal{Account: "alice"}, Selector{}, factsAct, keyed("k-1"))
		if !errors.Is(err, ErrIdempotencyUnavailable) {
			t.Fatalf("err = %v, want ErrIdempotencyUnavailable", err)
		}
		if n := f.conduit.dispatched("node-a"); n != 0 {
			t.Errorf("dispatched %d Tasks", n)
		}
	})
	t.Run("no key store", func(t *testing.T) {
		f := newStartFx(t)
		f.svc.idem = nil
		_, err := f.svc.Start(context.Background(), alice, Selector{}, factsAct, keyed("k-1"))
		if !errors.Is(err, ErrIdempotencyUnavailable) {
			t.Fatalf("err = %v, want ErrIdempotencyUnavailable", err)
		}
	})
	t.Run("dispatcher cannot persist first", func(t *testing.T) {
		f := newStartFx(t)
		f.svc.disp = &spyDispatcher{jobID: "job-1"}
		_, err := f.svc.Start(context.Background(), alice, Selector{}, factsAct, keyed("k-1"))
		if !errors.Is(err, ErrIdempotencyUnavailable) {
			t.Fatalf("err = %v, want ErrIdempotencyUnavailable", err)
		}
	})
}

func TestStart_WithoutAKeyBehavesLikeRunOnANonPersistingDispatcher(t *testing.T) {
	f := newStartFx(t)
	disp := &spyDispatcher{jobID: "job-1"}
	f.svc.disp = disp
	sj, err := f.svc.Start(context.Background(), alice, Selector{}, factsAct, StartOptions{})
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	if !disp.called || sj.JobID != "job-1" || !isClosed(sj.Done) {
		t.Fatalf("called=%v StartedJob=%+v; want a synchronous run with Done closed", disp.called, sj)
	}
}

// settle must end only its own claim: a late settle by a caller whose key was
// since re-claimed must not close the new claimer's claim.
func TestStart_LateSettleDoesNotCloseALaterClaim(t *testing.T) {
	f := newStartFx(t)
	c1 := f.svc.registerClaim("acct", "k", "job-1")
	c2 := f.svc.registerClaim("acct", "k", "job-2") // re-claimed after c1 was released
	f.svc.settle(c1)
	f.svc.settle(c1)

	if isClosed(c2.settled) {
		t.Fatal("a late settle closed a later claim")
	}
	if got := f.svc.liveClaim("acct", "k", "job-2"); got != c2 {
		t.Fatal("the later claim's map entry was removed by a late settle")
	}
	f.svc.settle(c2)
	if !isClosed(c2.settled) || f.svc.liveClaim("acct", "k", "job-2") != nil {
		t.Fatal("settle did not end its own claim")
	}
}

// A waiter woken by settled closing must never find the settled claim through
// liveClaim: the map entry is removed before the close.
func TestStart_SettledClaimIsNeverVisibleToAWokenWaiter(t *testing.T) {
	f := newStartFx(t)
	for i := 0; i < 500; i++ {
		c := f.svc.registerClaim("acct", "k", "job-1")
		go f.svc.settle(c)
		<-c.settled
		if got := f.svc.liveClaim("acct", "k", "job-1"); got != nil {
			t.Fatalf("iteration %d: liveClaim returned a settled claim", i)
		}
	}
}

func TestStart_ASettleOfAnotherKeyDoesNotDisturbAWaiter(t *testing.T) {
	f := newStartFx(t)
	entered, release := f.intents.arm()
	defer release()

	// A claims and blocks inside persist; a settle of another key must leave
	// B waiting on A, then re-attaching.
	a := f.startAsync(alice, factsAct, keyed("k-1"))
	waitClosed(t, entered, "A inside RecordIntent")
	stale := f.svc.registerClaim(alice.AccountID, "other", "job-stale")
	f.svc.settle(stale)

	b := f.startAsync(alice, factsAct, keyed("k-1"))
	waitRecordSeen(t, f.idem, "B to find A's record")
	release()
	ra, rb := recv(t, a, "A"), recv(t, b, "B")
	if ra.err != nil || rb.err != nil || !rb.sj.Reattached || rb.sj.JobID != ra.sj.JobID {
		t.Fatalf("A=%+v/%v B=%+v/%v; want B re-attached to A's Job", ra.sj, ra.err, rb.sj, rb.err)
	}
}

// --- approval interaction ---

func approvalStartFx(t *testing.T, mods ...func(*seams)) (*startFx, *memApprovals) {
	t.Helper()
	store := newMemApprovals()
	approvals := func(s *seams) {
		s.gate = gateEverything(t, 1)
		s.approvals = store
		s.approvalAuthz = &spyApprovalAuthorizer{}
		s.now = func() time.Time { return apNow }
	}
	return newStartFx(t, append([]func(*seams){approvals}, mods...)...), store
}

func TestStart_ParkClaimsNoKey(t *testing.T) {
	f, store := approvalStartFx(t)
	p := Principal{AccountID: "acct-g", Account: "gleipnir-prod"}

	_, err := f.svc.Start(context.Background(), p, Selector{}, mutateAct(), keyed("k-1"))
	var parked *ParkedError
	if !errors.As(err, &parked) {
		t.Fatalf("Start = %v, want a park", err)
	}
	if _, found, _ := f.st.IdempotencyKeys().Lookup(context.Background(), p.AccountID, "k-1", apNow.Add(-IdempotencyWindow)); found {
		t.Fatal("a parked dispatch claimed its key")
	}

	store.approve(t, parked.RequestID, "acct-ana", "ana", apNow.Add(time.Minute))
	sj, err := f.svc.Start(context.Background(), p, Selector{}, mutateAct(), keyed("k-1"))
	if err != nil || sj.Reattached {
		t.Fatalf("answered retry = %+v, %v; want a dispatch", sj, err)
	}
	waitClosed(t, sj.Done, "Done")
	if store.bound[parked.RequestID] != sj.JobID {
		t.Errorf("approval bound to %q, want the keyed Job %s", store.bound[parked.RequestID], sj.JobID)
	}
	rec, found, _ := f.st.IdempotencyKeys().Lookup(context.Background(), p.AccountID, "k-1", apNow.Add(-IdempotencyWindow))
	if !found || rec.JobID != sj.JobID {
		t.Errorf("key record = %+v found=%v; want it bound to %s", rec, found, sj.JobID)
	}
}

// loseBind makes the next BindJob lose to a concurrent winner: it binds
// winnerJob first, so the real call comes back ErrAlreadyReleased.
type loseBind struct {
	ApprovalStore
	winnerJob string
}

func (l *loseBind) BindJob(ctx context.Context, id, jobID string, now time.Time) (approval.Request, error) {
	if l.winnerJob != "" {
		if _, err := l.ApprovalStore.BindJob(ctx, id, l.winnerJob, now); err != nil {
			return approval.Request{}, err
		}
		l.winnerJob = ""
	}
	return l.ApprovalStore.BindJob(ctx, id, jobID, now)
}

func TestStart_ReleasedApprovalReattachesAndRebindsTheKey(t *testing.T) {
	mem := newMemApprovals()
	lb := &loseBind{ApprovalStore: mem}
	f := newStartFx(t, func(s *seams) {
		s.gate = gateEverything(t, 1)
		s.approvals = lb
		s.approvalAuthz = &spyApprovalAuthorizer{}
		s.now = func() time.Time { return apNow }
	})
	p := Principal{AccountID: "acct-g", Account: "gleipnir-prod"}

	_, err := f.svc.Start(context.Background(), p, Selector{}, mutateAct(), keyed("k-1"))
	var parked *ParkedError
	if !errors.As(err, &parked) {
		t.Fatalf("Start = %v, want a park", err)
	}
	mem.approve(t, parked.RequestID, "acct-ana", "ana", apNow.Add(time.Minute))
	lb.winnerJob = "job-winner"

	sj, err := f.svc.Start(context.Background(), p, Selector{}, mutateAct(), keyed("k-1"))
	if err != nil {
		t.Fatalf("Start that loses the release claim: %v", err)
	}
	if !sj.Reattached || sj.JobID != "job-winner" {
		t.Fatalf("StartedJob = %+v, want a re-attach to the winner", sj)
	}
	rec, found, _ := f.st.IdempotencyKeys().Lookup(context.Background(), p.AccountID, "k-1", apNow.Add(-IdempotencyWindow))
	if !found || rec.JobID != "job-winner" {
		t.Fatalf("key record = %+v found=%v; want it rebound to the winner", rec, found)
	}
	if got := f.conduit.dispatched("node-a"); got != 0 {
		t.Errorf("a lost release claim dispatched %d Tasks", got)
	}
	f.svc.claimsMu.Lock()
	live := len(f.svc.claims)
	f.svc.claimsMu.Unlock()
	if live != 0 {
		t.Errorf("%d claims left live after the rebind", live)
	}
}

// A keyed dispatch released by a Grant must never bind the Request: a Grant
// releases many Jobs, and a Request carries one job_id.
func TestStart_KeyedGrantReleaseDoesNotBindTheRequest(t *testing.T) {
	grants := &memGrants{grant: coveringGrant()}
	f, store := approvalStartFx(t, func(s *seams) { s.grants = grants })
	p := Principal{AccountID: "acct-g", Account: "gleipnir-prod"}

	sj, err := f.svc.Start(context.Background(), p, Selector{}, mutateAct(), keyed("k-1"))
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	waitClosed(t, sj.Done, "Done")
	if len(store.bound) != 0 {
		t.Errorf("approval bindings = %v, want none for a Grant-released dispatch", store.bound)
	}
	if grants.claims != 1 {
		t.Fatalf("grant claims = %d, want 1", grants.claims)
	}

	// The sequential re-issue re-attaches and spends no further Grant use.
	again, err := f.svc.Start(context.Background(), p, Selector{}, mutateAct(), keyed("k-1"))
	if err != nil || !again.Reattached || again.JobID != sj.JobID {
		t.Fatalf("re-issue = %+v, %v; want a re-attach to %s", again, err, sj.JobID)
	}
	if grants.claims != 1 {
		t.Errorf("grant claims after a sequential re-issue = %d, want still 1", grants.claims)
	}
}
