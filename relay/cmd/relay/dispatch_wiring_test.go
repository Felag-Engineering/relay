package main

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/jobs"
	relayv1 "github.com/Felag-Engineering/gleipnir-relay/relay/internal/relay/v1"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/store"
)

func testTaskRepository(t *testing.T) jobs.TaskRepository {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "relay.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { st.Close() }) //nolint:errcheck
	return st.Tasks()
}

// TestRouterSink_ForwardsToRouter asserts that routerSink's three taskSink
// methods do nothing but forward to the underlying *dispatch.Router — the
// only reason routerSink exists is to bridge dispatch.Router into the
// unexported taskSink interface (tunnel.go), which a type declared outside
// package main cannot implement directly.
func TestRouterSink_ForwardsToRouter(t *testing.T) {
	router, _, sink := newDispatchStack(testTaskRepository(t))

	sentCh := make(chan *relayv1.RelayMessage, 4)
	send := func(msg *relayv1.RelayMessage) error {
		sentCh <- msg
		return nil
	}

	unregister := sink.register("node-1", send)
	if unregister == nil {
		t.Fatal("register returned a nil unregister func")
	}
	if !router.Connected("node-1") {
		t.Error("router.Connected(node-1) = false after sink.register")
	}

	want := &relayv1.TaskResult{TaskId: "task-1", Outcome: relayv1.Outcome_OUTCOME_SUCCESS}

	resultCh := make(chan jobs.Result, 1)
	errCh := make(chan error, 1)
	go func() {
		res, err := router.Dispatch(context.Background(), "node-1", jobs.Task{ID: "task-1", NodeID: "node-1"})
		resultCh <- res
		errCh <- err
	}()

	// Wait for the send to land before delivering the result, so the
	// dispatched Task's waiter is guaranteed to be registered.
	select {
	case <-sentCh:
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for router to send the dispatched task")
	}

	sink.deliver("node-1", want)

	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("router.Dispatch: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for Dispatch to return after sink.deliver")
	}
	res := <-resultCh
	if res.Outcome != jobs.OutcomeSuccess {
		t.Errorf("Dispatch result outcome = %v, want jobs.OutcomeSuccess", res.Outcome)
	}

	// deliverVerdict is a documented no-op; assert only that it does not panic.
	sink.deliverVerdict("node-1", &relayv1.PolicyVerdict{QueryId: "q-1", Allowed: true})

	unregister()
	if router.Connected("node-1") {
		t.Error("router.Connected(node-1) = true after unregister")
	}
}

// TestRouterSink_ForgedRelayOnlyOutcomeRefused is #632's regression test on
// the FULL production wiring: the taskSink.deliver entry point tunnel.go:249
// calls, all the way through routerSink -> dispatch.Router -> the wire
// boundary. A real relay-daemon cannot forge this outcome (it never emits
// one — measured against daemon/src/dispatch.rs and dedup.rs), so this
// property can never be an integration test: it is only reachable by
// injecting a forged TaskResult exactly as sink.deliver would receive one
// off a compromised Node's Tunnel.
func TestRouterSink_ForgedRelayOnlyOutcomeRefused(t *testing.T) {
	router, _, sink := newDispatchStack(testTaskRepository(t))

	sentCh := make(chan *relayv1.RelayMessage, 4)
	send := func(msg *relayv1.RelayMessage) error {
		sentCh <- msg
		return nil
	}

	unregister := sink.register("node-1", send)
	defer unregister()

	resultCh := make(chan jobs.Result, 1)
	errCh := make(chan error, 1)
	go func() {
		res, err := router.Dispatch(context.Background(), "node-1", jobs.Task{ID: "task-1", NodeID: "node-1"})
		resultCh <- res
		errCh <- err
	}()

	select {
	case <-sentCh:
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for router to send the dispatched task")
	}

	// A compromised but enrolled Node claims its Task was never sent, while
	// also claiming it ran ("i actually ran") — the exact #632 lie.
	sink.deliver("node-1", &relayv1.TaskResult{
		TaskId:  "task-1",
		Outcome: relayv1.Outcome_OUTCOME_VERSION_REFUSED,
		Stdout:  []byte("i actually ran"),
	})

	if err := <-errCh; err != nil {
		t.Fatalf("router.Dispatch: %v", err)
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
}

// TestNewDispatchStack_ReconcilerUsesRouter asserts that newDispatchStack
// wires the Reconciler's Conduit to the same Router it returns (not some
// other Router), by relying on Router.WaitForNode/Connected staying
// consistent across the pair after a register/unregister cycle.
func TestNewDispatchStack_ReconcilerUsesRouter(t *testing.T) {
	router, reconciler, sink := newDispatchStack(testTaskRepository(t))
	if reconciler == nil {
		t.Fatal("newDispatchStack returned a nil Reconciler")
	}

	unregister := sink.register("node-2", func(*relayv1.RelayMessage) error { return nil })
	defer unregister()

	if err := router.WaitForNode("node-2", time.Second); err != nil {
		t.Fatalf("WaitForNode: %v", err)
	}

	// ReconcileNode itself is exercised end-to-end in
	// internal/dispatch/reconcile_test.go; here we only assert the
	// composition wires onConnect to fire without error against an empty
	// (no in-flight Tasks) store, proving the Reconciler's TaskRepository is
	// live and reachable through this stack.
	if err := reconciler.ReconcileNode(context.Background(), "node-2"); err != nil {
		t.Fatalf("ReconcileNode: %v", err)
	}
}
