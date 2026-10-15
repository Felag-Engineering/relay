package dispatch

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Felag-Engineering/relay/relay/internal/jobs"
	relayv1 "github.com/Felag-Engineering/relay/relay/internal/relay/v1"
)

// recordingSend is a fake send func that records every RelayMessage it is
// given, safe for concurrent use.
type recordingSend struct {
	mu   sync.Mutex
	sent []*relayv1.RelayMessage
	err  error
}

func (s *recordingSend) send(msg *relayv1.RelayMessage) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.err != nil {
		return s.err
	}
	s.sent = append(s.sent, msg)
	return nil
}

func (s *recordingSend) len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.sent)
}

func (s *recordingSend) last() *relayv1.RelayMessage {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.sent) == 0 {
		return nil
	}
	return s.sent[len(s.sent)-1]
}

// TestRouter_CorrelatesConcurrentTasksAcrossNodes dispatches several Tasks
// concurrently across two Nodes and asserts each Dispatch call receives
// exactly the Result correlated by its own task_id, never another Task's
// Result — the flat waiters[task_id] map's core correctness property.
func TestRouter_CorrelatesConcurrentTasksAcrossNodes(t *testing.T) {
	r := NewRouter(nil, nil)
	sendA := &recordingSend{}
	sendB := &recordingSend{}
	unregA := r.Register("node-a", sendA.send)
	unregB := r.Register("node-b", sendB.send)
	defer unregA()
	defer unregB()

	type dispatchCall struct {
		nodeID string
		taskID string
	}
	calls := []dispatchCall{
		{"node-a", "task-a1"},
		{"node-a", "task-a2"},
		{"node-b", "task-b1"},
		{"node-b", "task-b2"},
	}

	var wg sync.WaitGroup
	results := make(map[string]jobs.Result, len(calls))
	var mu sync.Mutex
	for _, c := range calls {
		wg.Add(1)
		go func(c dispatchCall) {
			defer wg.Done()
			res, err := r.Dispatch(context.Background(), c.nodeID, jobs.Task{ID: c.taskID, NodeID: c.nodeID})
			if err != nil {
				t.Errorf("Dispatch(%s): %v", c.taskID, err)
				return
			}
			mu.Lock()
			results[c.taskID] = res
			mu.Unlock()
		}(c)
	}

	// Wait for all four sends to land, then deliver each Result keyed by its
	// own task_id, in a deliberately scrambled order to stress correlation.
	waitUntil(t, time.Second, func() bool { return sendA.len() == 2 && sendB.len() == 2 })

	deliver := func(nodeID, taskID string, exitCode int32) {
		r.Deliver(nodeID, &relayv1.TaskResult{TaskId: taskID, Outcome: relayv1.Outcome_OUTCOME_SUCCESS, ExitCode: exitCode})
	}
	deliver("node-b", "task-b2", 2)
	deliver("node-a", "task-a1", 3)
	deliver("node-b", "task-b1", 4)
	deliver("node-a", "task-a2", 5)

	wg.Wait()

	want := map[string]int32{"task-a1": 3, "task-a2": 5, "task-b1": 4, "task-b2": 2}
	for taskID, wantExit := range want {
		got, ok := results[taskID]
		if !ok {
			t.Fatalf("no result recorded for %q", taskID)
		}
		if got.ExitCode != wantExit {
			t.Errorf("result[%q].ExitCode = %d, want %d", taskID, got.ExitCode, wantExit)
		}
	}
}

// TestRouter_DisconnectFailsPendingWaiter is the AMENDMENT-B1 test: a
// blocked Dispatch call must return ErrNodeDisconnected (not hang) when the
// Node's Tunnel unregisters while the call is still waiting.
func TestRouter_DisconnectFailsPendingWaiter(t *testing.T) {
	r := NewRouter(nil, nil)
	send := &recordingSend{}
	unregister := r.Register("node-1", send.send)

	done := make(chan error, 1)
	go func() {
		_, err := r.Dispatch(context.Background(), "node-1", jobs.Task{ID: "task-1", NodeID: "node-1"})
		done <- err
	}()

	waitUntil(t, time.Second, func() bool { return send.len() == 1 })
	unregister()

	select {
	case err := <-done:
		if !errors.Is(err, ErrNodeDisconnected) {
			t.Errorf("Dispatch error = %v, want ErrNodeDisconnected", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Dispatch did not return after unregister — goroutine leak / hang (AMENDMENT B1)")
	}
}

// TestRouter_DispatchHonorsContextCancel asserts ctx cancellation unblocks
// Dispatch and removes its waiter (no leak).
func TestRouter_DispatchHonorsContextCancel(t *testing.T) {
	r := NewRouter(nil, nil)
	send := &recordingSend{}
	unregister := r.Register("node-1", send.send)
	defer unregister()

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := r.Dispatch(ctx, "node-1", jobs.Task{ID: "task-1", NodeID: "node-1"})
		done <- err
	}()

	waitUntil(t, time.Second, func() bool { return send.len() == 1 })
	cancel()

	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Errorf("Dispatch error = %v, want context.Canceled", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Dispatch did not return after ctx cancel")
	}

	r.mu.Lock()
	_, stillWaiting := r.waiters["task-1"]
	r.mu.Unlock()
	if stillWaiting {
		t.Error("waiter for task-1 leaked after ctx cancel")
	}
}

// TestRouter_SendErrorRemovesWaiter asserts a failed send does not leave a
// dangling waiter.
func TestRouter_SendErrorRemovesWaiter(t *testing.T) {
	r := NewRouter(nil, nil)
	send := &recordingSend{err: errors.New("stream broken")}
	unregister := r.Register("node-1", send.send)
	defer unregister()

	_, err := r.Dispatch(context.Background(), "node-1", jobs.Task{ID: "task-1", NodeID: "node-1"})
	if err == nil {
		t.Fatal("Dispatch with a failing send should return an error")
	}

	r.mu.Lock()
	_, stillWaiting := r.waiters["task-1"]
	r.mu.Unlock()
	if stillWaiting {
		t.Error("waiter for task-1 leaked after a send error")
	}
}

// TestRouter_DispatchNotConnected asserts Dispatch fails fast for an
// unregistered Node (ADR-0004's offline fail-fast) rather than blocking.
func TestRouter_DispatchNotConnected(t *testing.T) {
	r := NewRouter(nil, nil)
	_, err := r.Dispatch(context.Background(), "node-absent", jobs.Task{ID: "task-1", NodeID: "node-absent"})
	if !errors.Is(err, ErrNotConnected) {
		t.Errorf("Dispatch error = %v, want ErrNotConnected", err)
	}
	if r.Connected("node-absent") {
		t.Error("Connected(node-absent) = true, want false")
	}
}

// TestRouter_DispatchWithheldBeforeSend asserts a send guard that reports
// "withhold" stops the TaskRequest reaching the Tunnel and leaves no waiter.
func TestRouter_DispatchWithheldBeforeSend(t *testing.T) {
	r := NewRouter(nil, nil)
	send := &recordingSend{}
	unregister := r.Register("node-1", send.send)
	defer unregister()

	ctx := jobs.WithSendGuard(context.Background(), func() bool { return true })
	_, err := r.Dispatch(ctx, "node-1", jobs.Task{ID: "task-1", NodeID: "node-1"})
	if !errors.Is(err, jobs.ErrSendWithheld) {
		t.Fatalf("Dispatch error = %v, want ErrSendWithheld", err)
	}
	if n := send.len(); n != 0 {
		t.Errorf("sends = %d, want 0", n)
	}
	r.mu.Lock()
	_, stillWaiting := r.waiters["task-1"]
	r.mu.Unlock()
	if stillWaiting {
		t.Error("waiter for task-1 leaked after a withheld send")
	}
}

// TestRouter_DispatchGuardNotWithheldSends asserts a guard that allows the
// send changes nothing.
func TestRouter_DispatchGuardNotWithheldSends(t *testing.T) {
	r := NewRouter(nil, nil)
	send := &recordingSend{}
	unregister := r.Register("node-1", send.send)
	defer unregister()

	ctx := jobs.WithSendGuard(context.Background(), func() bool { return false })
	type out struct {
		res jobs.Result
		err error
	}
	done := make(chan out, 1)
	go func() {
		res, err := r.Dispatch(ctx, "node-1", jobs.Task{ID: "task-1", NodeID: "node-1"})
		done <- out{res, err}
	}()
	waitUntil(t, time.Second, func() bool { return send.len() == 1 })
	r.Deliver("node-1", &relayv1.TaskResult{TaskId: "task-1", Outcome: relayv1.Outcome_OUTCOME_SUCCESS})

	select {
	case o := <-done:
		if o.err != nil {
			t.Fatalf("Dispatch: %v", o.err)
		}
		if o.res.Outcome != jobs.OutcomeSuccess {
			t.Errorf("outcome = %v, want success", o.res.Outcome)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Dispatch did not return")
	}
	if n := send.len(); n != 1 {
		t.Errorf("sends = %d, want 1", n)
	}
}

// TestRouter_DispatchNotConnectedIgnoresGuard asserts the connectivity gate
// comes first: an unregistered Node is ErrNotConnected, not a withheld send.
func TestRouter_DispatchNotConnectedIgnoresGuard(t *testing.T) {
	r := NewRouter(nil, nil)
	ctx := jobs.WithSendGuard(context.Background(), func() bool { return true })
	_, err := r.Dispatch(ctx, "node-absent", jobs.Task{ID: "task-1", NodeID: "node-absent"})
	if !errors.Is(err, ErrNotConnected) {
		t.Errorf("Dispatch error = %v, want ErrNotConnected", err)
	}
}

// TestRouter_WithheldDispatchDoesNotRemoveAnotherCallersWaiter asserts a
// withheld send removes only its own waiter: a concurrent caller that
// overwrote the entry for the same task ID (a Reconciler resend) still
// receives its Result.
func TestRouter_WithheldDispatchDoesNotRemoveAnotherCallersWaiter(t *testing.T) {
	r := NewRouter(nil, nil)
	send := &recordingSend{}
	unregister := r.Register("node-1", send.send)
	defer unregister()

	inGuard := make(chan struct{})
	releaseGuard := make(chan struct{})
	guardA := func() bool {
		close(inGuard)
		<-releaseGuard
		return true
	}
	task := jobs.Task{ID: "task-1", NodeID: "node-1"}

	errA := make(chan error, 1)
	go func() {
		_, err := r.Dispatch(jobs.WithSendGuard(context.Background(), guardA), "node-1", task)
		errA <- err
	}()
	<-inGuard // A's waiter is registered.

	type out struct {
		res jobs.Result
		err error
	}
	doneB := make(chan out, 1)
	go func() {
		res, err := r.Dispatch(context.Background(), "node-1", task)
		doneB <- out{res, err}
	}()
	// B registers its waiter (overwriting A's) and then queues on the Task's
	// send slot behind A's guard.
	waitUntil(t, time.Second, func() bool { return slotRefs(r, "task-1") == 2 })

	close(releaseGuard)
	select {
	case err := <-errA:
		if !errors.Is(err, jobs.ErrSendWithheld) {
			t.Fatalf("A error = %v, want ErrSendWithheld", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("A did not return")
	}

	waitUntil(t, time.Second, func() bool { return send.len() == 1 })
	r.Deliver("node-1", &relayv1.TaskResult{TaskId: "task-1", Outcome: relayv1.Outcome_OUTCOME_SUCCESS})
	select {
	case o := <-doneB:
		if o.err != nil || o.res.Outcome != jobs.OutcomeSuccess {
			t.Errorf("B = (%v, %v), want success", o.res.Outcome, o.err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("B never received its Result: A's withheld send removed B's waiter")
	}
}

// slotRefs reports how many Dispatch calls currently hold taskID's send slot.
func slotRefs(r *Router, taskID string) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	if s := r.sendSlots[taskID]; s != nil {
		return s.refs
	}
	return 0
}

func slotCount(r *Router) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.sendSlots)
}

// TestRouter_CallerAfterASentCallerNeverConsultsItsGuard: once one caller has
// handed a task ID to the Tunnel, a later caller for the same ID sends too (a
// resend the daemon dedups) and its guard is never called, so the Task cannot
// be recorded as never sent after it was sent.
func TestRouter_CallerAfterASentCallerNeverConsultsItsGuard(t *testing.T) {
	r := NewRouter(nil, nil)
	send := &recordingSend{}
	unregister := r.Register("node-1", send.send)
	defer unregister()
	task := jobs.Task{ID: "task-1", NodeID: "node-1"}

	firstCtx, cancelFirst := context.WithCancel(jobs.WithSendGuard(context.Background(), func() bool { return false }))
	defer cancelFirst()
	firstDone := make(chan error, 1)
	go func() {
		_, err := r.Dispatch(firstCtx, "node-1", task)
		firstDone <- err
	}()
	waitUntil(t, time.Second, func() bool { return send.len() == 1 })

	var secondGuardCalls int
	secondDone := make(chan error, 1)
	go func() {
		_, err := r.Dispatch(jobs.WithSendGuard(context.Background(), func() bool {
			secondGuardCalls++
			return true
		}), "node-1", task)
		secondDone <- err
	}()
	waitUntil(t, time.Second, func() bool { return send.len() == 2 })

	// The second call's waiter replaced the first's, so it gets the Result.
	r.Deliver("node-1", &relayv1.TaskResult{TaskId: "task-1", Outcome: relayv1.Outcome_OUTCOME_SUCCESS})
	if err := <-secondDone; err != nil {
		t.Fatalf("second Dispatch: %v", err)
	}
	if secondGuardCalls != 0 {
		t.Errorf("second caller's guard called %d times, want 0", secondGuardCalls)
	}
	cancelFirst()
	if err := <-firstDone; !errors.Is(err, context.Canceled) {
		t.Errorf("first Dispatch error = %v, want context.Canceled", err)
	}
}

// TestRouter_SecondCallerSeesTheFirstCallersWithhold: the first guard's side
// effect (the engine's store commit) is visible to the second caller's guard,
// because the guards are serialised per task ID, so both withhold.
func TestRouter_SecondCallerSeesTheFirstCallersWithhold(t *testing.T) {
	r := NewRouter(nil, nil)
	send := &recordingSend{}
	unregister := r.Register("node-1", send.send)
	defer unregister()
	task := jobs.Task{ID: "task-1", NodeID: "node-1"}

	var committed bool // guarded by the Router's per-Task slot
	first := func() bool { committed = true; return true }
	second := func() bool { return committed }

	if _, err := r.Dispatch(jobs.WithSendGuard(context.Background(), first), "node-1", task); !errors.Is(err, jobs.ErrSendWithheld) {
		t.Fatalf("first error = %v, want ErrSendWithheld", err)
	}
	if _, err := r.Dispatch(jobs.WithSendGuard(context.Background(), second), "node-1", task); !errors.Is(err, jobs.ErrSendWithheld) {
		t.Fatalf("second error = %v, want ErrSendWithheld", err)
	}
	if n := send.len(); n != 0 {
		t.Errorf("sends = %d, want 0", n)
	}
}

// TestRouter_SendSlotsDoNotLeak: the slot map is empty once every Dispatch has
// returned, on the success, withheld, send-error and ctx-timeout paths.
func TestRouter_SendSlotsDoNotLeak(t *testing.T) {
	r := NewRouter(nil, nil)
	ok := &recordingSend{}
	bad := &recordingSend{err: errors.New("boom")}
	unregOK := r.Register("node-ok", ok.send)
	unregBad := r.Register("node-bad", bad.send)
	defer unregOK()
	defer unregBad()

	// Withheld.
	_, _ = r.Dispatch(jobs.WithSendGuard(context.Background(), func() bool { return true }), "node-ok", jobs.Task{ID: "t-withheld"})
	// Send error.
	_, _ = r.Dispatch(context.Background(), "node-bad", jobs.Task{ID: "t-senderr"})
	// ctx timeout while waiting for a Result.
	tctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	_, _ = r.Dispatch(tctx, "node-ok", jobs.Task{ID: "t-timeout"})
	// Success.
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = r.Dispatch(context.Background(), "node-ok", jobs.Task{ID: "t-ok"})
	}()
	waitUntil(t, time.Second, func() bool { return ok.len() == 2 })
	r.Deliver("node-ok", &relayv1.TaskResult{TaskId: "t-ok", Outcome: relayv1.Outcome_OUTCOME_SUCCESS})
	<-done

	if n := slotCount(r); n != 0 {
		t.Errorf("sendSlots has %d entries after every Dispatch returned, want 0", n)
	}
}

// TestRouter_CancelSendsTaskCancel asserts Cancel sends the TaskCancel body
// and returns immediately (never waits for a Result).
func TestRouter_CancelSendsTaskCancel(t *testing.T) {
	r := NewRouter(nil, nil)
	send := &recordingSend{}
	unregister := r.Register("node-1", send.send)
	defer unregister()

	if err := r.Cancel(context.Background(), "node-1", "task-1"); err != nil {
		t.Fatalf("Cancel: %v", err)
	}
	msg := send.last()
	if msg == nil {
		t.Fatal("Cancel did not send anything")
	}
	tc := msg.GetTaskCancel()
	if tc == nil || tc.GetTaskId() != "task-1" {
		t.Errorf("sent message = %+v, want a TaskCancel for task-1", msg)
	}
}

// unsyncedStream stands in for a gRPC stream: like grpc.ServerStream.SendMsg,
// it is not safe for concurrent use, so it takes no lock of its own. It
// counts sends that overlap another send on the same stream, holding each one
// open briefly so an unserialised caller would overlap reliably.
type unsyncedStream struct {
	inFlight atomic.Int32
	overlaps atomic.Int32
	sent     int // written only inside send; the race detector checks it
}

func (s *unsyncedStream) send(*relayv1.RelayMessage) error {
	if s.inFlight.Add(1) > 1 {
		s.overlaps.Add(1)
	}
	s.sent++
	time.Sleep(time.Millisecond)
	s.inFlight.Add(-1)
	return nil
}

// TestRouter_SendsOnOneStreamAreSerialised drives Dispatch, Cancel and Query
// at one Node concurrently. A gRPC stream allows one SendMsg at a time, so the
// Router must never call a Node's send function from two goroutines at once.
func TestRouter_SendsOnOneStreamAreSerialised(t *testing.T) {
	r := NewRouter(nil, nil)
	stream := &unsyncedStream{}
	unregister := r.Register("node-1", stream.send)
	defer unregister()

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	act := jobs.Action{Kind: jobs.ActionOperation, OperationName: "system.facts", RiskClass: jobs.RiskClassRead}

	const perKind = 20
	var wg sync.WaitGroup
	for i := 0; i < perKind; i++ {
		id := "task-" + strconv.Itoa(i)
		wg.Add(3)
		go func() {
			defer wg.Done()
			_, _ = r.Dispatch(ctx, "node-1", jobs.Task{ID: id, NodeID: "node-1"})
		}()
		go func() {
			defer wg.Done()
			_ = r.Cancel(ctx, "node-1", id)
		}()
		go func() {
			defer wg.Done()
			_, _ = r.Query(ctx, "node-1", act)
		}()
	}
	wg.Wait()

	if n := stream.overlaps.Load(); n != 0 {
		t.Errorf("%d sends overlapped another send on the same stream; want 0", n)
	}
	if stream.sent != 3*perKind {
		t.Errorf("stream saw %d sends, want %d", stream.sent, 3*perKind)
	}
}

// TestRouter_CancelOfflineNodeIsBestEffort asserts Cancel against a Node
// with no live Tunnel is a no-op, not an error — cancellation is inherently
// best-effort (ADR-0013).
func TestRouter_CancelOfflineNodeIsBestEffort(t *testing.T) {
	r := NewRouter(nil, nil)
	if err := r.Cancel(context.Background(), "node-absent", "task-1"); err != nil {
		t.Errorf("Cancel on an offline node = %v, want nil (best-effort)", err)
	}
}

// TestRouter_DeliverUncorrelatedTaskIDDropped asserts a Result for an
// unknown (or already-delivered) task_id is silently dropped, never panics.
func TestRouter_DeliverUncorrelatedTaskIDDropped(t *testing.T) {
	r := NewRouter(nil, nil)
	unregister := r.Register("node-1", func(*relayv1.RelayMessage) error { return nil })
	defer unregister()

	// No Dispatch call is waiting on "task-unknown" — this must not panic or
	// block.
	r.Deliver("node-1", &relayv1.TaskResult{TaskId: "task-unknown", Outcome: relayv1.Outcome_OUTCOME_SUCCESS})
}

// TestRouter_DeliverWrongNodeDropped asserts the nodeID defense-in-depth
// check: a Result arriving on the wrong Node's stream for a task_id it
// should never have seen is dropped, not delivered to the waiter.
func TestRouter_DeliverWrongNodeDropped(t *testing.T) {
	r := NewRouter(nil, nil)
	sendA := &recordingSend{}
	sendB := &recordingSend{}
	unregA := r.Register("node-a", sendA.send)
	unregB := r.Register("node-b", sendB.send)
	defer unregA()
	defer unregB()

	done := make(chan error, 1)
	go func() {
		_, err := r.Dispatch(context.Background(), "node-a", jobs.Task{ID: "task-1", NodeID: "node-a"})
		done <- err
	}()
	waitUntil(t, time.Second, func() bool { return sendA.len() == 1 })

	// A Result for task-1 arrives (incorrectly) on node-b's stream: dropped.
	r.Deliver("node-b", &relayv1.TaskResult{TaskId: "task-1", Outcome: relayv1.Outcome_OUTCOME_SUCCESS})

	select {
	case <-done:
		t.Fatal("Dispatch returned after a Deliver on the wrong node — should have been dropped")
	case <-time.After(100 * time.Millisecond):
		// expected: still blocked
	}

	// The correct delivery still completes it.
	r.Deliver("node-a", &relayv1.TaskResult{TaskId: "task-1", Outcome: relayv1.Outcome_OUTCOME_SUCCESS})
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("Dispatch: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Dispatch never returned after the correct Deliver")
	}
}

// TestRouter_ConnectedAndWaitForNode covers the connectivity gate + the
// e2e sync-point helper.
func TestRouter_ConnectedAndWaitForNode(t *testing.T) {
	r := NewRouter(nil, nil)
	if r.Connected("node-1") {
		t.Error("Connected(node-1) = true before Register")
	}
	if err := r.WaitForNode("node-1", 50*time.Millisecond); err == nil {
		t.Error("WaitForNode on an unregistered node should time out")
	}

	unregister := r.Register("node-1", func(*relayv1.RelayMessage) error { return nil })
	defer unregister()
	if !r.Connected("node-1") {
		t.Error("Connected(node-1) = false after Register")
	}
	if err := r.WaitForNode("node-1", time.Second); err != nil {
		t.Errorf("WaitForNode: %v", err)
	}
}

// TestRouter_WaitForAny covers the no-known-nodeID e2e sync point.
func TestRouter_WaitForAny(t *testing.T) {
	r := NewRouter(nil, nil)
	if _, err := r.WaitForAny(50 * time.Millisecond); err == nil {
		t.Error("WaitForAny with no registered node should time out")
	}

	unregister := r.Register("node-x", func(*relayv1.RelayMessage) error { return nil })
	defer unregister()
	got, err := r.WaitForAny(time.Second)
	if err != nil {
		t.Fatalf("WaitForAny: %v", err)
	}
	if got != "node-x" {
		t.Errorf("WaitForAny() = %q, want node-x", got)
	}
}

// TestRouter_RegisterFiresOnConnect asserts the reconciliation hook fires
// asynchronously on Register (including a synthesized reconnect), and never
// blocks Register itself.
func TestRouter_RegisterFiresOnConnect(t *testing.T) {
	fired := make(chan string, 4)
	r := NewRouter(func(nodeID string) { fired <- nodeID }, nil)

	unregister := r.Register("node-1", func(*relayv1.RelayMessage) error { return nil })
	defer unregister()

	select {
	case nodeID := <-fired:
		if nodeID != "node-1" {
			t.Errorf("onConnect fired for %q, want node-1", nodeID)
		}
	case <-time.After(time.Second):
		t.Fatal("onConnect did not fire after Register")
	}
}

// TestRouter_StaleUnregisterDoesNotClobberFreshRegistration is the node-flap
// fix's core regression test: during a rapid disconnect/reconnect for the
// same cert nodeID, the OLD connection's (conn1) deferred unregister must not
// evict the NEWER connection (conn2) that has since re-registered under the
// same nodeID, and must not close a waiter conn2's Dispatch created — even
// though both waiters would share the same task_id+nodeID key.
func TestRouter_StaleUnregisterDoesNotClobberFreshRegistration(t *testing.T) {
	r := NewRouter(nil, nil)
	send1 := &recordingSend{}
	send2 := &recordingSend{}

	// conn1 registers first (the connection that is about to flap away)...
	unreg1 := r.Register("node-1", send1.send)
	// ...then conn2 registers for the SAME nodeID before conn1's deferred
	// unregister runs (the reconnect race).
	unreg2 := r.Register("node-1", send2.send)

	done := make(chan error, 1)
	go func() {
		// conn2 is now live; dispatch a Task that reuses task-1 — the same
		// task_id a conn1-era waiter might have used — to stress the
		// delete-by-identity fix.
		_, err := r.Dispatch(context.Background(), "node-1", jobs.Task{ID: "task-1", NodeID: "node-1"})
		done <- err
	}()
	waitUntil(t, time.Second, func() bool { return send2.len() == 1 })

	// The stale conn1 unregister fires (its deferred cleanup, arriving late).
	unreg1()

	if !r.Connected("node-1") {
		t.Fatal("Connected(node-1) = false after the stale (conn1) unregister — a live conn2 registration was clobbered")
	}

	select {
	case err := <-done:
		t.Fatalf("Dispatch returned early (err=%v) after the stale unregister — a live conn2 waiter was closed", err)
	case <-time.After(100 * time.Millisecond):
		// expected: still blocked, waiting for a real Deliver via conn2
	}

	r.Deliver("node-1", &relayv1.TaskResult{TaskId: "task-1", Outcome: relayv1.Outcome_OUTCOME_SUCCESS, ExitCode: 7})

	select {
	case err := <-done:
		if err != nil {
			t.Errorf("Dispatch: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Dispatch never returned after Deliver via conn2 — waiter lost")
	}

	unreg2()
}

// TestRouter_ConnectedNodes asserts ConnectedNodes returns every currently
// registered Node and drops one once it unregisters.
func TestRouter_ConnectedNodes(t *testing.T) {
	r := NewRouter(nil, nil)
	if got := r.ConnectedNodes(); len(got) != 0 {
		t.Errorf("ConnectedNodes() = %v, want empty before any Register", got)
	}

	unregA := r.Register("node-a", func(*relayv1.RelayMessage) error { return nil })
	unregB := r.Register("node-b", func(*relayv1.RelayMessage) error { return nil })

	got := r.ConnectedNodes()
	want := map[string]bool{"node-a": true, "node-b": true}
	if len(got) != len(want) {
		t.Fatalf("ConnectedNodes() = %v, want %v", got, want)
	}
	for _, nodeID := range got {
		if !want[nodeID] {
			t.Errorf("ConnectedNodes() contains unexpected node %q", nodeID)
		}
	}

	unregA()
	got = r.ConnectedNodes()
	if len(got) != 1 || got[0] != "node-b" {
		t.Errorf("ConnectedNodes() after unregistering node-a = %v, want [node-b]", got)
	}

	unregB()
	if got := r.ConnectedNodes(); len(got) != 0 {
		t.Errorf("ConnectedNodes() after unregistering all = %v, want empty", got)
	}
}

// TestRouter_QueryCorrelatesVerdict is #119's core correlation test: Query
// sends a PolicyQuery, and the query_id it minted is what DeliverVerdict
// must be called with for Query to return the mapped jobs.Verdict.
func TestRouter_QueryCorrelatesVerdict(t *testing.T) {
	r := NewRouter(nil, nil)
	send := &recordingSend{}
	unregister := r.Register("node-1", send.send)
	defer unregister()

	done := make(chan struct {
		v   jobs.Verdict
		err error
	}, 1)
	act := jobs.Action{Kind: jobs.ActionOperation, OperationName: "system.facts", RiskClass: jobs.RiskClassRead}
	go func() {
		v, err := r.Query(context.Background(), "node-1", act)
		done <- struct {
			v   jobs.Verdict
			err error
		}{v, err}
	}()

	waitUntil(t, time.Second, func() bool { return send.len() == 1 })

	msg := send.last()
	pq := msg.GetPolicyQuery()
	if pq == nil {
		t.Fatal("Query did not send a PolicyQuery")
	}
	if pq.GetQueryId() == "" {
		t.Fatal("PolicyQuery.QueryId is empty, want a minted query_id")
	}
	if op := pq.GetOperation(); op == nil || op.GetName() != "system.facts" {
		t.Errorf("PolicyQuery.Operation = %+v, want system.facts", op)
	}

	r.DeliverVerdict("node-1", &relayv1.PolicyVerdict{QueryId: pq.GetQueryId(), Allowed: true})

	select {
	case got := <-done:
		if got.err != nil {
			t.Fatalf("Query: %v", got.err)
		}
		if !got.v.Allowed {
			t.Errorf("Query() verdict = %+v, want Allowed=true", got.v)
		}
	case <-time.After(time.Second):
		t.Fatal("Query never returned after DeliverVerdict")
	}
}

// TestRouter_QueryDenyCarriesDecidingRule asserts a deny verdict's
// DecidingRule round-trips through Query.
func TestRouter_QueryDenyCarriesDecidingRule(t *testing.T) {
	r := NewRouter(nil, nil)
	send := &recordingSend{}
	unregister := r.Register("node-1", send.send)
	defer unregister()

	done := make(chan jobs.Verdict, 1)
	go func() {
		v, err := r.Query(context.Background(), "node-1", jobs.Action{Kind: jobs.ActionRawExec, RawExecArgv: []string{"/bin/rm", "-rf", "/"}})
		if err != nil {
			t.Errorf("Query: %v", err)
		}
		done <- v
	}()

	waitUntil(t, time.Second, func() bool { return send.len() == 1 })
	queryID := send.last().GetPolicyQuery().GetQueryId()
	r.DeliverVerdict("node-1", &relayv1.PolicyVerdict{QueryId: queryID, Allowed: false, DecidingRule: "deny-rm-rf"})

	select {
	case v := <-done:
		if v.Allowed {
			t.Error("verdict.Allowed = true, want false")
		}
		if v.DecidingRule != "deny-rm-rf" {
			t.Errorf("verdict.DecidingRule = %q, want deny-rm-rf", v.DecidingRule)
		}
	case <-time.After(time.Second):
		t.Fatal("Query never returned")
	}
}

// TestRouter_QueryDisconnectMidQuery mirrors
// TestRouter_DisconnectFailsPendingWaiter for the verdict-waiter ID space: a
// blocked Query call must return ErrNodeDisconnected (not hang) when the
// Node's Tunnel unregisters while the call is still waiting.
func TestRouter_QueryDisconnectMidQuery(t *testing.T) {
	r := NewRouter(nil, nil)
	send := &recordingSend{}
	unregister := r.Register("node-1", send.send)

	done := make(chan error, 1)
	go func() {
		_, err := r.Query(context.Background(), "node-1", jobs.Action{Kind: jobs.ActionOperation, OperationName: "system.facts"})
		done <- err
	}()

	waitUntil(t, time.Second, func() bool { return send.len() == 1 })
	unregister()

	select {
	case err := <-done:
		if !errors.Is(err, ErrNodeDisconnected) {
			t.Errorf("Query error = %v, want ErrNodeDisconnected", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Query did not return after unregister — goroutine leak / hang")
	}
}

// TestRouter_QueryHonorsContextCancel asserts ctx cancellation unblocks
// Query and removes its verdict waiter (no leak).
func TestRouter_QueryHonorsContextCancel(t *testing.T) {
	r := NewRouter(nil, nil)
	send := &recordingSend{}
	unregister := r.Register("node-1", send.send)
	defer unregister()

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := r.Query(ctx, "node-1", jobs.Action{Kind: jobs.ActionOperation, OperationName: "system.facts"})
		done <- err
	}()

	waitUntil(t, time.Second, func() bool { return send.len() == 1 })
	cancel()

	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Errorf("Query error = %v, want context.Canceled", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Query did not return after ctx cancel")
	}

	queryID := send.last().GetPolicyQuery().GetQueryId()
	r.mu.Lock()
	_, stillWaiting := r.verdictWaiters[queryID]
	r.mu.Unlock()
	if stillWaiting {
		t.Error("verdict waiter leaked after ctx cancel")
	}
}

// TestRouter_DeliverVerdictUncorrelatedQueryIDDropped asserts a PolicyVerdict
// for an unknown (or already-delivered) query_id is silently dropped, never
// panics — mirrors TestRouter_DeliverUncorrelatedTaskIDDropped.
func TestRouter_DeliverVerdictUncorrelatedQueryIDDropped(t *testing.T) {
	r := NewRouter(nil, nil)
	unregister := r.Register("node-1", func(*relayv1.RelayMessage) error { return nil })
	defer unregister()

	// No Query call is waiting on "query-unknown" — this must not panic or
	// block.
	r.DeliverVerdict("node-1", &relayv1.PolicyVerdict{QueryId: "query-unknown", Allowed: true})
}

// TestRouter_DeliverVerdictWrongNodeDropped mirrors
// TestRouter_DeliverWrongNodeDropped for the verdict-waiter ID space.
func TestRouter_DeliverVerdictWrongNodeDropped(t *testing.T) {
	r := NewRouter(nil, nil)
	sendA := &recordingSend{}
	sendB := &recordingSend{}
	unregA := r.Register("node-a", sendA.send)
	unregB := r.Register("node-b", sendB.send)
	defer unregA()
	defer unregB()

	done := make(chan error, 1)
	go func() {
		_, err := r.Query(context.Background(), "node-a", jobs.Action{Kind: jobs.ActionOperation, OperationName: "system.facts"})
		done <- err
	}()
	waitUntil(t, time.Second, func() bool { return sendA.len() == 1 })
	queryID := sendA.last().GetPolicyQuery().GetQueryId()

	// A verdict for queryID arrives (incorrectly) on node-b's stream: dropped.
	r.DeliverVerdict("node-b", &relayv1.PolicyVerdict{QueryId: queryID, Allowed: true})

	select {
	case <-done:
		t.Fatal("Query returned after a DeliverVerdict on the wrong node — should have been dropped")
	case <-time.After(100 * time.Millisecond):
		// expected: still blocked
	}

	// The correct delivery still completes it.
	r.DeliverVerdict("node-a", &relayv1.PolicyVerdict{QueryId: queryID, Allowed: true})
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("Query: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Query never returned after the correct DeliverVerdict")
	}
}

// TestRouter_QueryNotConnected asserts Query fails fast for an unregistered
// Node rather than blocking, mirroring TestRouter_DispatchNotConnected.
func TestRouter_QueryNotConnected(t *testing.T) {
	r := NewRouter(nil, nil)
	_, err := r.Query(context.Background(), "node-absent", jobs.Action{Kind: jobs.ActionOperation, OperationName: "system.facts"})
	if !errors.Is(err, ErrNotConnected) {
		t.Errorf("Query error = %v, want ErrNotConnected", err)
	}
}

// TestRouter_UnregisterClosesVerdictWaiter asserts unregister closes a
// verdict waiter it owns even outside a live Query call's select loop —
// i.e. the map entry itself is removed and its channel closed, mirroring
// the waiters-map half of the same guarantee.
func TestRouter_UnregisterClosesVerdictWaiter(t *testing.T) {
	r := NewRouter(nil, nil)
	send := &recordingSend{}
	unregister := r.Register("node-1", send.send)

	done := make(chan error, 1)
	go func() {
		_, err := r.Query(context.Background(), "node-1", jobs.Action{Kind: jobs.ActionOperation, OperationName: "system.facts"})
		done <- err
	}()
	waitUntil(t, time.Second, func() bool { return send.len() == 1 })

	queryID := send.last().GetPolicyQuery().GetQueryId()
	unregister()

	<-done // Query must have returned ErrNodeDisconnected by now.

	r.mu.Lock()
	_, stillWaiting := r.verdictWaiters[queryID]
	r.mu.Unlock()
	if stillWaiting {
		t.Error("verdict waiter for queryID leaked after unregister")
	}
}

// TestRouter_ForgedRelayOnlyOutcomeResolvesAsProtocolViolation is #632's
// regression test on the production Dispatch path: a compromised but
// enrolled Node reports OUTCOME_VERSION_REFUSED for a Task it actually
// received (and claims to have run), and Dispatch must resolve it as a
// terminal protocol violation — never as the outcome the Node claimed, and
// never as an error (an error would leave the Task Dispatched and hand the
// Reconciler an attacker-controlled resend loop, invariant 4).
func TestRouter_ForgedRelayOnlyOutcomeResolvesAsProtocolViolation(t *testing.T) {
	r := NewRouter(nil, nil)
	send := &recordingSend{}
	unregister := r.Register("node-1", send.send)
	defer unregister()

	resultCh := make(chan jobs.Result, 1)
	errCh := make(chan error, 1)
	go func() {
		res, err := r.Dispatch(context.Background(), "node-1", jobs.Task{ID: "task-1", NodeID: "node-1"})
		resultCh <- res
		errCh <- err
	}()

	waitUntil(t, time.Second, func() bool { return send.len() == 1 })

	r.Deliver("node-1", &relayv1.TaskResult{
		TaskId:  "task-1",
		Outcome: relayv1.Outcome_OUTCOME_VERSION_REFUSED,
		Stdout:  []byte("i actually ran"),
	})

	if err := <-errCh; err != nil {
		t.Fatalf("Dispatch returned an error for a forged outcome, want nil (terminal resolve, not a retry loop): %v", err)
	}
	res := <-resultCh
	if res.Outcome != jobs.OutcomeFailure {
		t.Errorf("Dispatch result Outcome = %v, want jobs.OutcomeFailure", res.Outcome)
	}
	if res.ExitCode != -1 {
		t.Errorf("Dispatch result ExitCode = %d, want -1", res.ExitCode)
	}
	if len(res.Stdout) != 0 {
		t.Errorf("Dispatch result Stdout = %q, want empty — the Node's claimed output must be discarded", res.Stdout)
	}
	if !strings.Contains(string(res.Stderr), "WAS dispatched") {
		t.Errorf("Dispatch result Stderr = %q, want the Relay-authored protocol-violation explanation", res.Stderr)
	}
}

func waitUntil(t *testing.T, deadline time.Duration, cond func() bool) {
	t.Helper()
	end := time.Now().Add(deadline)
	for time.Now().Before(end) {
		if cond() {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	if !cond() {
		t.Fatal("condition not met before deadline")
	}
}

// fakeViolationRecorder is a ViolationRecorder that captures every event it
// is given, safe for concurrent use, and can be made to fail on demand
// (TestDispatch_AFailedViolationRecordIsNotAReturnedError).
//
// started and release, left nil by every test but
// TestDispatch_AViolationIsRecordedAfterTheCallerContextIsCancelled, let
// that one test pin down a race window between "RecordProtocolViolation has
// begun" and "the caller's context is cancelled": a nil channel is simply
// skipped, so every other test in this file (which never sets them) runs
// exactly as before.
type fakeViolationRecorder struct {
	mu      sync.Mutex
	events  []jobs.ProtocolViolationEvent
	err     error
	started chan struct{} // closed when RecordProtocolViolation begins, if non-nil
	release chan struct{} // blocks RecordProtocolViolation until closed, if non-nil
	ctxErr  error         // ctx.Err(), captured at call time
}

func (f *fakeViolationRecorder) RecordProtocolViolation(ctx context.Context, ev jobs.ProtocolViolationEvent) error {
	if f.started != nil {
		close(f.started)
	}
	if f.release != nil {
		<-f.release
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.events = append(f.events, ev)
	f.ctxErr = ctx.Err()
	return f.err
}

func (f *fakeViolationRecorder) recorded() []jobs.ProtocolViolationEvent {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]jobs.ProtocolViolationEvent(nil), f.events...)
}

// capturedCtxErr returns the ctx.Err() RecordProtocolViolation observed on
// its most recent call.
func (f *fakeViolationRecorder) capturedCtxErr() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.ctxErr
}

// TestDispatch_AForgedRelayOnlyOutcomeIsRecordedAsAProtocolViolation is
// #638's live-path acceptance test: a forged TaskResult must produce exactly
// one durable ProtocolViolationEvent, carrying the Task's own ids, on top of
// #632's unchanged terminal-failure contract.
func TestDispatch_AForgedRelayOnlyOutcomeIsRecordedAsAProtocolViolation(t *testing.T) {
	fake := &fakeViolationRecorder{}
	r := NewRouter(nil, fake)
	send := &recordingSend{}
	unregister := r.Register("node-1", send.send)
	defer unregister()

	task := jobs.Task{
		ID:      "task-1",
		JobID:   "job-1",
		NodeID:  "node-1",
		Action:  jobs.Action{Kind: jobs.ActionOperation, OperationName: "list_files"},
		StageID: "stage-1",
	}

	resultCh := make(chan jobs.Result, 1)
	errCh := make(chan error, 1)
	go func() {
		res, err := r.Dispatch(context.Background(), "node-1", task)
		resultCh <- res
		errCh <- err
	}()

	waitUntil(t, time.Second, func() bool { return send.len() == 1 })

	r.Deliver("node-1", &relayv1.TaskResult{
		TaskId:  "task-1",
		Outcome: relayv1.Outcome_OUTCOME_VERSION_REFUSED,
		Stdout:  []byte("i actually ran"),
	})

	if err := <-errCh; err != nil {
		t.Fatalf("Dispatch returned an error for a forged outcome, want nil: %v", err)
	}
	res := <-resultCh
	if res.Outcome != jobs.OutcomeFailure {
		t.Errorf("Dispatch result Outcome = %v, want jobs.OutcomeFailure", res.Outcome)
	}
	if res.ExitCode != -1 {
		t.Errorf("Dispatch result ExitCode = %d, want -1", res.ExitCode)
	}
	if len(res.Stdout) != 0 {
		t.Errorf("Dispatch result Stdout = %q, want empty", res.Stdout)
	}

	events := fake.recorded()
	if len(events) != 1 {
		t.Fatalf("recorded %d protocol violation events, want exactly 1", len(events))
	}
	ev := events[0]
	if ev.NodeID != "node-1" {
		t.Errorf("event NodeID = %q, want node-1", ev.NodeID)
	}
	if ev.TaskID != "task-1" {
		t.Errorf("event TaskID = %q, want task-1", ev.TaskID)
	}
	if ev.JobID != "job-1" {
		t.Errorf("event JobID = %q, want job-1", ev.JobID)
	}
	if ev.OperationName != "list_files" {
		t.Errorf("event OperationName = %q, want list_files", ev.OperationName)
	}
	if ev.Violation.Rule != jobs.ViolationRelayOnlyOutcome {
		t.Errorf("event Violation.Rule = %v, want jobs.ViolationRelayOnlyOutcome", ev.Violation.Rule)
	}
	if ev.Violation.ReportedOutcome != "OUTCOME_VERSION_REFUSED" {
		t.Errorf("event Violation.ReportedOutcome = %q, want OUTCOME_VERSION_REFUSED", ev.Violation.ReportedOutcome)
	}
}

// TestDispatch_ANonViolatingResultRecordsNothing pins that an ordinary
// success does not fill the protocol-violation trail with non-events.
func TestDispatch_ANonViolatingResultRecordsNothing(t *testing.T) {
	fake := &fakeViolationRecorder{}
	r := NewRouter(nil, fake)
	send := &recordingSend{}
	unregister := r.Register("node-1", send.send)
	defer unregister()

	resultCh := make(chan jobs.Result, 1)
	go func() {
		res, _ := r.Dispatch(context.Background(), "node-1", jobs.Task{ID: "task-1", NodeID: "node-1"})
		resultCh <- res
	}()

	waitUntil(t, time.Second, func() bool { return send.len() == 1 })

	r.Deliver("node-1", &relayv1.TaskResult{
		TaskId:   "task-1",
		Outcome:  relayv1.Outcome_OUTCOME_SUCCESS,
		ExitCode: 0,
	})
	<-resultCh

	if events := fake.recorded(); len(events) != 0 {
		t.Errorf("recorded %d protocol violation events for a non-violating result, want 0", len(events))
	}
}

// TestDispatch_AFailedViolationRecordIsNotAReturnedError is the #632 loop
// property: an audit-write failure must never strand the Task as Dispatched.
func TestDispatch_AFailedViolationRecordIsNotAReturnedError(t *testing.T) {
	fake := &fakeViolationRecorder{err: errors.New("store unavailable")}
	r := NewRouter(nil, fake)
	send := &recordingSend{}
	unregister := r.Register("node-1", send.send)
	defer unregister()

	resultCh := make(chan jobs.Result, 1)
	errCh := make(chan error, 1)
	go func() {
		res, err := r.Dispatch(context.Background(), "node-1", jobs.Task{ID: "task-1", NodeID: "node-1"})
		resultCh <- res
		errCh <- err
	}()

	waitUntil(t, time.Second, func() bool { return send.len() == 1 })

	r.Deliver("node-1", &relayv1.TaskResult{
		TaskId:  "task-1",
		Outcome: relayv1.Outcome_OUTCOME_VERSION_REFUSED,
	})

	if err := <-errCh; err != nil {
		t.Fatalf("Dispatch returned an error when the audit write failed, want nil: %v", err)
	}
	res := <-resultCh
	if res.Outcome != jobs.OutcomeFailure {
		t.Errorf("Dispatch result Outcome = %v, want jobs.OutcomeFailure", res.Outcome)
	}
	if recorded := fake.recorded(); len(recorded) != 1 {
		t.Errorf("recorded %d protocol violation events, want exactly 1 attempt", len(recorded))
	}
}

// TestDispatch_AViolationIsRecordedAfterTheCallerContextIsCancelled proves
// recordViolation detaches from the caller's context (context.WithoutCancel):
// evidence must not be decided by the caller's deadline. The fake blocks
// inside RecordProtocolViolation until the test has already cancelled the
// caller's context, then captures ctx.Err() — so, unlike a bare "did an
// event eventually show up" check, this deterministically fails if
// recordViolation is changed to pass ctx straight through instead of
// context.WithoutCancel(ctx).
func TestDispatch_AViolationIsRecordedAfterTheCallerContextIsCancelled(t *testing.T) {
	fake := &fakeViolationRecorder{
		started: make(chan struct{}),
		release: make(chan struct{}),
	}
	r := NewRouter(nil, fake)
	send := &recordingSend{}
	unregister := r.Register("node-1", send.send)
	defer unregister()

	ctx, cancel := context.WithCancel(context.Background())

	resultCh := make(chan jobs.Result, 1)
	go func() {
		res, _ := r.Dispatch(ctx, "node-1", jobs.Task{ID: "task-1", NodeID: "node-1"})
		resultCh <- res
	}()

	waitUntil(t, time.Second, func() bool { return send.len() == 1 })

	r.Deliver("node-1", &relayv1.TaskResult{
		TaskId:  "task-1",
		Outcome: relayv1.Outcome_OUTCOME_VERSION_REFUSED,
	})

	select {
	case <-fake.started:
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for RecordProtocolViolation to start")
	}
	cancel()
	close(fake.release)
	<-resultCh

	if events := fake.recorded(); len(events) != 1 {
		t.Fatalf("recorded %d protocol violation events, want exactly 1", len(events))
	}
	if err := fake.capturedCtxErr(); err != nil {
		t.Errorf("RecordProtocolViolation's context was already cancelled: %v (recordViolation must detach from the caller's context)", err)
	}
}

// TestDispatch_ANilViolationRecorderIsLogOnly pins that nil is a supported
// mode: it must not panic, and Dispatch must still return #632's terminal
// contract.
func TestDispatch_ANilViolationRecorderIsLogOnly(t *testing.T) {
	r := NewRouter(nil, nil)
	send := &recordingSend{}
	unregister := r.Register("node-1", send.send)
	defer unregister()

	resultCh := make(chan jobs.Result, 1)
	errCh := make(chan error, 1)
	go func() {
		res, err := r.Dispatch(context.Background(), "node-1", jobs.Task{ID: "task-1", NodeID: "node-1"})
		resultCh <- res
		errCh <- err
	}()

	waitUntil(t, time.Second, func() bool { return send.len() == 1 })

	r.Deliver("node-1", &relayv1.TaskResult{
		TaskId:  "task-1",
		Outcome: relayv1.Outcome_OUTCOME_VERSION_REFUSED,
	})

	if err := <-errCh; err != nil {
		t.Fatalf("Dispatch returned an error with a nil ViolationRecorder, want nil: %v", err)
	}
	if res := <-resultCh; res.Outcome != jobs.OutcomeFailure {
		t.Errorf("Dispatch result Outcome = %v, want jobs.OutcomeFailure", res.Outcome)
	}
}

// captureDefaultLog swaps slog's default logger for one that writes JSON
// lines to a buffer, restoring the previous default on test cleanup, and
// returns the buffer — mirroring cmd/relay/labelscan_wiring_test.go's
// TestNewServer_RunsDeclinedLabelScanAtStartup idiom, which is what proves a
// package-level slog call happened rather than merely that a function
// returned successfully.
func captureDefaultLog(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&buf, nil)))
	t.Cleanup(func() { slog.SetDefault(prev) })
	return &buf
}

// TestNewRouter_NilViolationRecorderWarnsAtConstruction is security-review
// finding 2 (#638, Stage 6.5): a nil ViolationRecorder is a supported
// log-only mode, but it must never be a SILENT one — a production wiring
// that forgot to pass a real recorder must announce itself at start-up
// rather than only when the first protocol violation goes unrecorded.
func TestNewRouter_NilViolationRecorderWarnsAtConstruction(t *testing.T) {
	buf := captureDefaultLog(t)
	NewRouter(nil, nil)

	if !strings.Contains(buf.String(), "will not record protocol violations durably") {
		t.Errorf("NewRouter(nil, nil) did not warn that violations will not be recorded durably; log:\n%s", buf.String())
	}
}

// TestNewRouter_RealViolationRecorderDoesNotWarn is
// TestNewRouter_NilViolationRecorderWarnsAtConstruction's converse: a
// properly-wired Router must not print a warning that would train an
// operator to ignore it.
func TestNewRouter_RealViolationRecorderDoesNotWarn(t *testing.T) {
	buf := captureDefaultLog(t)
	NewRouter(nil, &fakeViolationRecorder{})

	if strings.Contains(buf.String(), "will not record protocol violations durably") {
		t.Errorf("NewRouter with a real ViolationRecorder logged the nil-recorder warning; log:\n%s", buf.String())
	}
}
