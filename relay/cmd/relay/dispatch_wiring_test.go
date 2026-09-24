package main

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/audit"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/auditsink"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/jobs"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/metrics"
	relayv1 "github.com/Felag-Engineering/gleipnir-relay/relay/internal/relay/v1"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/store"
)

func testTaskRepository(t *testing.T) jobs.TaskRepository {
	t.Helper()
	st, _ := testTaskRepositoryWithStore(t)
	return st
}

// testTaskRepositoryWithStore is testTaskRepository's sibling for tests that
// also need the underlying *store.Store — e.g. to read the audit trail a
// real auditsink.Sink wrote (#638).
func testTaskRepositoryWithStore(t *testing.T) (jobs.TaskRepository, *store.Store) {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "relay.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { st.Close() }) //nolint:errcheck
	return st.Tasks(), st
}

// TestRouterSink_ForwardsToRouter asserts that routerSink's three taskSink
// methods do nothing but forward to the underlying *dispatch.Router — the
// only reason routerSink exists is to bridge dispatch.Router into the
// unexported taskSink interface (tunnel.go), which a type declared outside
// package main cannot implement directly.
func TestRouterSink_ForwardsToRouter(t *testing.T) {
	router, _, sink := newDispatchStack(testTaskRepository(t), nil)

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
	router, _, sink := newDispatchStack(testTaskRepository(t), nil)

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
	router, reconciler, sink := newDispatchStack(testTaskRepository(t), nil)
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

// TestNewDispatchStack_AProtocolViolationOnAReadClassTaskIsRecordedWithNoOutput
// is (a) the end-to-end proof that the production assembly —
// newDispatchStack -> Router -> *auditsink.Sink -> store — is wired, which is
// the substitute for the fail-open guard decision 3 (plan.md) explains this
// seam cannot borrow from capability.New; and (b) a REGRESSION PIN on risk
// class: no branch on this path reads RiskClass today, and this test exists
// so that none ever appears. It is deliberately NOT a demonstration that some
// read-class branch was handled — there is none — and must not be read as
// one. The complementary fact (that the read lane strips the Task's OWN
// Stdout/Stderr) is proven in capability/readlane_test.go and is not
// re-tested here.
func TestNewDispatchStack_AProtocolViolationOnAReadClassTaskIsRecordedWithNoOutput(t *testing.T) {
	tasks, st := testTaskRepositoryWithStore(t)
	violations := auditsink.New(st.Audit())
	router, _, sink := newDispatchStack(tasks, violations)

	sentCh := make(chan *relayv1.RelayMessage, 4)
	send := func(msg *relayv1.RelayMessage) error {
		sentCh <- msg
		return nil
	}
	unregister := sink.register("node-1", send)
	defer unregister()

	task := jobs.Task{
		ID:     "task-1",
		JobID:  "job-1",
		NodeID: "node-1",
		Action: jobs.Action{Kind: jobs.ActionOperation, OperationName: "list_files", RiskClass: jobs.RiskClassRead},
	}

	resultCh := make(chan jobs.Result, 1)
	go func() {
		res, _ := router.Dispatch(context.Background(), "node-1", task)
		resultCh <- res
	}()

	select {
	case <-sentCh:
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for router to send the dispatched task")
	}

	sink.deliver("node-1", &relayv1.TaskResult{
		TaskId:  "task-1",
		Outcome: relayv1.Outcome_OUTCOME_VERSION_REFUSED,
		Stdout:  []byte("i actually ran"),
	})
	<-resultCh

	records, err := st.Audit().ByNode(context.Background(), "node-1")
	if err != nil {
		t.Fatalf("ByNode: %v", err)
	}
	var violationRows int
	for _, rec := range records {
		if rec.Kind != audit.KindProtocolViolation {
			continue
		}
		violationRows++
		if rec.JobID != "job-1" {
			t.Errorf("record JobID = %q, want job-1", rec.JobID)
		}
		if rec.OperationName != "list_files" {
			t.Errorf("record OperationName = %q, want list_files", rec.OperationName)
		}
		if len(rec.Stdout) != 0 || len(rec.Stderr) != 0 || rec.Truncated {
			t.Errorf("record carries Stdout/Stderr/Truncated on a read-class Task: %+v", rec)
		}
	}
	if violationRows != 1 {
		t.Fatalf("found %d KindProtocolViolation rows for node-1, want exactly 1", violationRows)
	}
}

// TestViolationRecorder_RecordProtocolViolation is the six-line composer
// dispatch_wiring.go's violationRecorder consists of — the whole fail-open
// residual argument (recordViolation's doc comment, this file's
// violationRecorder doc comment) rests on these lines actually counting and
// propagating the way they claim to.
func TestViolationRecorder_RecordProtocolViolation(t *testing.T) {
	ev := jobs.ProtocolViolationEvent{
		NodeID:        "node-1",
		TaskID:        "task-1",
		JobID:         "job-1",
		OperationName: "list_files",
		Violation:     jobs.ProtocolViolation{Rule: jobs.ViolationRelayOnlyOutcome, ReportedOutcome: "OUTCOME_VERSION_REFUSED"},
	}

	t.Run("write error increments the unrecorded counter and returns the error unchanged", func(t *testing.T) {
		idErr := errors.New("id generation failed")
		_, st := testTaskRepositoryWithStore(t)
		sink := auditsink.New(st.Audit(), auditsink.WithNewID(func() (string, error) { return "", idErr }))
		m := metrics.New(metrics.GaugeSources{})
		v := violationRecorder{audit: sink, metrics: m}

		err := v.RecordProtocolViolation(context.Background(), ev)
		if !errors.Is(err, idErr) {
			t.Fatalf("RecordProtocolViolation error = %v, want it to wrap %v unchanged", err, idErr)
		}

		_, body := scrapeMetrics(t, m)
		if !strings.Contains(body, `relay_protocol_violations_total{rule="relay_only_outcome"} 1`) {
			t.Errorf("body missing the by-rule counter even though the write failed; body = %s", body)
		}
		if !strings.Contains(body, "relay_protocol_violations_unrecorded_total 1") {
			t.Errorf("body missing relay_protocol_violations_unrecorded_total 1 after a failed write; body = %s", body)
		}
	})

	t.Run("success increments only the by-rule counter", func(t *testing.T) {
		_, st := testTaskRepositoryWithStore(t)
		sink := auditsink.New(st.Audit())
		m := metrics.New(metrics.GaugeSources{})
		v := violationRecorder{audit: sink, metrics: m}

		if err := v.RecordProtocolViolation(context.Background(), ev); err != nil {
			t.Fatalf("RecordProtocolViolation: %v", err)
		}

		_, body := scrapeMetrics(t, m)
		if !strings.Contains(body, `relay_protocol_violations_total{rule="relay_only_outcome"} 1`) {
			t.Errorf("body missing the by-rule counter; body = %s", body)
		}
		if !strings.Contains(body, "relay_protocol_violations_unrecorded_total 0") {
			t.Errorf("body counts an unrecorded violation for a successful write; body = %s", body)
		}
	})
}
