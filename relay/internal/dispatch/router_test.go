package dispatch

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/jobs"
	relayv1 "github.com/Felag-Engineering/gleipnir-relay/relay/internal/relay/v1"
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
	r := NewRouter(nil)
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
	r := NewRouter(nil)
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
	r := NewRouter(nil)
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
	r := NewRouter(nil)
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
	r := NewRouter(nil)
	_, err := r.Dispatch(context.Background(), "node-absent", jobs.Task{ID: "task-1", NodeID: "node-absent"})
	if !errors.Is(err, ErrNotConnected) {
		t.Errorf("Dispatch error = %v, want ErrNotConnected", err)
	}
	if r.Connected("node-absent") {
		t.Error("Connected(node-absent) = true, want false")
	}
}

// TestRouter_CancelSendsTaskCancel asserts Cancel sends the TaskCancel body
// and returns immediately (never waits for a Result).
func TestRouter_CancelSendsTaskCancel(t *testing.T) {
	r := NewRouter(nil)
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

// TestRouter_CancelOfflineNodeIsBestEffort asserts Cancel against a Node
// with no live Tunnel is a no-op, not an error — cancellation is inherently
// best-effort (ADR-0013).
func TestRouter_CancelOfflineNodeIsBestEffort(t *testing.T) {
	r := NewRouter(nil)
	if err := r.Cancel(context.Background(), "node-absent", "task-1"); err != nil {
		t.Errorf("Cancel on an offline node = %v, want nil (best-effort)", err)
	}
}

// TestRouter_DeliverUncorrelatedTaskIDDropped asserts a Result for an
// unknown (or already-delivered) task_id is silently dropped, never panics.
func TestRouter_DeliverUncorrelatedTaskIDDropped(t *testing.T) {
	r := NewRouter(nil)
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
	r := NewRouter(nil)
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
	r := NewRouter(nil)
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
	r := NewRouter(nil)
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
	r := NewRouter(func(nodeID string) { fired <- nodeID })

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
	r := NewRouter(nil)
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
	r := NewRouter(nil)
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
	r := NewRouter(nil)
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
	r := NewRouter(nil)
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
	r := NewRouter(nil)
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
	r := NewRouter(nil)
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
	r := NewRouter(nil)
	unregister := r.Register("node-1", func(*relayv1.RelayMessage) error { return nil })
	defer unregister()

	// No Query call is waiting on "query-unknown" — this must not panic or
	// block.
	r.DeliverVerdict("node-1", &relayv1.PolicyVerdict{QueryId: "query-unknown", Allowed: true})
}

// TestRouter_DeliverVerdictWrongNodeDropped mirrors
// TestRouter_DeliverWrongNodeDropped for the verdict-waiter ID space.
func TestRouter_DeliverVerdictWrongNodeDropped(t *testing.T) {
	r := NewRouter(nil)
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
	r := NewRouter(nil)
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
	r := NewRouter(nil)
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
	r := NewRouter(nil)
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
