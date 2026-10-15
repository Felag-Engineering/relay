package main

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Felag-Engineering/relay/relay/internal/approval"
	"github.com/Felag-Engineering/relay/relay/internal/audit"
	"github.com/Felag-Engineering/relay/relay/internal/auditquery"
	"github.com/Felag-Engineering/relay/relay/internal/auditsink"
	"github.com/Felag-Engineering/relay/relay/internal/capability"
	"github.com/Felag-Engineering/relay/relay/internal/dispatch"
	"github.com/Felag-Engineering/relay/relay/internal/jobs"
	"github.com/Felag-Engineering/relay/relay/internal/metrics"
	"github.com/Felag-Engineering/relay/relay/internal/registry"
	relayv1 "github.com/Felag-Engineering/relay/relay/internal/relay/v1"
	"github.com/Felag-Engineering/relay/relay/internal/store"
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
	t.Cleanup(func() { st.Close() })
	return st.Tasks(), st
}

// TestRouterSink_ForwardsToRouter asserts that routerSink's three taskSink
// methods do nothing but forward to the underlying *dispatch.Router — the
// only reason routerSink exists is to bridge dispatch.Router into the
// unexported taskSink interface (tunnel.go), which a type declared outside
// package main cannot implement directly.
func TestRouterSink_ForwardsToRouter(t *testing.T) {
	router, _, sink := newDispatchStack(testTaskRepository(t), nil, nil)

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
	router, _, sink := newDispatchStack(testTaskRepository(t), nil, nil)

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
	router, reconciler, sink := newDispatchStack(testTaskRepository(t), nil, nil)
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
// seam cannot borrow from capability.NewExecution; and (b) a REGRESSION PIN on risk
// class: no branch on this path reads RiskClass today, and this test exists
// so that none ever appears. It is deliberately NOT a demonstration that some
// read-class branch was handled — there is none — and must not be read as
// one. The complementary fact (that the read lane strips the Task's OWN
// Stdout/Stderr) is proven in capability/readlane_test.go and is not
// re-tested here.
func TestNewDispatchStack_AProtocolViolationOnAReadClassTaskIsRecordedWithNoOutput(t *testing.T) {
	tasks, st := testTaskRepositoryWithStore(t)
	violations := auditsink.New(st.Audit())
	router, _, sink := newDispatchStack(tasks, violations, nil)

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

// allowAllTestAuthorizer authorizes everything; the dev harness's authorizer
// is behind a build tag, and this test is about dispatch, not authorization.
type allowAllTestAuthorizer struct{}

func (allowAllTestAuthorizer) Authorize(context.Context, capability.Principal, jobs.Action, capability.Selector) error {
	return nil
}

func (allowAllTestAuthorizer) AuthorizeControl(context.Context, capability.Principal, capability.ControlAction) error {
	return nil
}

// holdingConduit is the real Router with one seam: the second Task to enter
// Dispatch publishes its Job ID and blocks until release, BEFORE reaching
// Router.Dispatch. That makes "past MarkDispatched, not yet at the Tunnel
// write" deterministic through the public capability surface. The engine's
// send guard rides in ctx, untouched.
type holdingConduit struct {
	*dispatch.Router
	mu      sync.Mutex
	entered []string
	held    chan string // the held Task's ID
	release chan struct{}
}

func (h *holdingConduit) Dispatch(ctx context.Context, nodeID string, task jobs.Task) (jobs.Result, error) {
	h.mu.Lock()
	h.entered = append(h.entered, task.ID)
	second := len(h.entered) == 2
	h.mu.Unlock()
	if second {
		h.held <- task.ID
		<-h.release
	}
	return h.Router.Dispatch(ctx, nodeID, task)
}

// TestDispatchWiring_ACancelDuringFanOutWithholdsUnsentTasksThroughTheRealRouter
// is #943's composed guarantee: a real store, the real Router and the real
// engine. A cancel that lands while one worker is past MarkDispatched and
// before the Tunnel write means that Task is never written, and the Task
// behind the dispatch bound is never dispatched.
func TestDispatchWiring_ACancelDuringFanOutWithholdsUnsentTasksThroughTheRealRouter(t *testing.T) {
	tasks, st := testTaskRepositoryWithStore(t)
	router, _, _ := newDispatchStack(tasks, nil, nil)

	var mu sync.Mutex
	requested := map[string]string{} // task ID -> node ID, TaskRequests that reached a Tunnel
	cancelRequested := map[string]bool{}
	for _, id := range []string{"node-1", "node-2", "node-3"} {
		if _, err := st.Registry().Upsert(registry.Report{NodeID: id}); err != nil {
			t.Fatalf("Upsert(%s): %v", id, err)
		}
		router.Register(id, func(msg *relayv1.RelayMessage) error {
			switch {
			case msg.GetTask() != nil:
				mu.Lock()
				requested[msg.GetTask().GetTaskId()] = id
				mu.Unlock()
			case msg.GetTaskCancel() != nil:
				taskID := msg.GetTaskCancel().GetTaskId()
				mu.Lock()
				_, wasSent := requested[taskID]
				cancelRequested[taskID] = true
				mu.Unlock()
				// A relay-daemon reports a cancel only for a Task it received.
				if wasSent {
					router.Deliver(id, &relayv1.TaskResult{TaskId: taskID, Outcome: relayv1.Outcome_OUTCOME_CANCELLED})
				}
			}
			return nil
		})
	}

	hold := &holdingConduit{Router: router, held: make(chan string, 1), release: make(chan struct{})}
	q := auditquery.New(st.AuditQueries(), st.JobQueries())
	capSvc := newCapService(t, capSeams{
		reg:         st.Registry(),
		authz:       allowAllTestAuthorizer{},
		cap:         capability.NewBlastCap(10, 10),
		audit:       auditsink.New(st.Audit()),
		freeze:      st.Freeze(),
		auditQ:      q,
		jobQ:        q,
		jobsRepo:    st.Jobs(),
		tasksRepo:   tasks,
		conduit:     hold,
		concurrency: 2,
	})

	type runOut struct {
		results []capability.NodeResult
		err     error
	}
	done := make(chan runOut, 1)
	go func() {
		res, err := capSvc.Run(context.Background(), capability.Principal{Account: "devharness"}, capability.Selector{},
			jobs.Action{Kind: jobs.ActionOperation, OperationName: "system.facts"})
		done <- runOut{res, err}
	}()

	var heldID string
	select {
	case heldID = <-hold.held:
	case <-time.After(5 * time.Second):
		t.Fatal("no Task was held before the Tunnel write")
	}
	// The other in-flight Task has now been written (or is about to be);
	// wait until its TaskRequest is on a Tunnel.
	deadline := time.Now().Add(5 * time.Second)
	for {
		mu.Lock()
		n := len(requested)
		mu.Unlock()
		if n == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("expected exactly one TaskRequest on a Tunnel, saw %d", n)
		}
		time.Sleep(time.Millisecond)
	}

	hold.mu.Lock()
	firstID := hold.entered[0]
	hold.mu.Unlock()
	jobID := mustTask(t, tasks, firstID).JobID
	if err := capSvc.CancelJob(context.Background(), capability.Principal{Account: "devharness", Kind: capability.PrincipalKindHuman}, jobID); err != nil {
		t.Fatalf("CancelJob: %v", err)
	}
	close(hold.release)

	var out runOut
	select {
	case out = <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return")
	}
	if out.err != nil {
		t.Fatalf("Run: %v", out.err)
	}
	if len(out.results) != 3 {
		t.Fatalf("results = %d, want 3", len(out.results))
	}
	for _, r := range out.results {
		if r.Outcome != jobs.OutcomeCancelled {
			t.Errorf("result for %s = %v, want cancelled", r.NodeID, r.Outcome)
		}
	}

	mu.Lock()
	defer mu.Unlock()
	if len(requested) != 1 {
		t.Errorf("TaskRequests on Tunnels = %v, want only the first Task", requested)
	}
	if _, ok := requested[heldID]; ok {
		t.Errorf("held Task %s was written to a Tunnel after the cancel", heldID)
	}
	all, err := tasks.ByJob(context.Background(), jobID)
	if err != nil || len(all) != 3 {
		t.Fatalf("ByJob = %d tasks, %v; want 3", len(all), err)
	}
	for _, task := range all {
		if task.State != jobs.DispatchStateResolved || task.Outcome != jobs.OutcomeCancelled {
			t.Errorf("task %s = %v/%v, want Resolved/Cancelled", task.ID, task.State, task.Outcome)
		}
		_, wasSent := requested[task.ID]
		if wasSent == task.DispatchedAt.IsZero() {
			t.Errorf("task %s sent=%v but DispatchedAt=%v", task.ID, wasSent, task.DispatchedAt)
		}
	}
	inFlight, err := tasks.InFlight(context.Background())
	if err != nil || len(inFlight) != 0 {
		t.Errorf("InFlight = %v, %v; want empty", inFlight, err)
	}
}

func mustTask(t *testing.T, tasks jobs.TaskRepository, id string) jobs.Task {
	t.Helper()
	task, err := tasks.Get(context.Background(), id)
	if err != nil {
		t.Fatalf("Get(%s): %v", id, err)
	}
	return task
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

// capSeams is the set of collaborators a test hands to newCapService. A zero
// concurrency takes capability.DefaultDispatchConcurrency. audit, authz,
// freeze, both query seams, cap and the execution seams are required, as
// capability.NewExecution requires them.
type capSeams struct {
	reg         registry.Repository
	authz       capability.Authorizer
	cap         capability.CapChecker
	audit       capability.AuditSink
	freeze      capability.FreezeStore
	auditQ      capability.AuditQuery
	jobQ        capability.JobQuery
	jobsRepo    jobs.JobRepository
	tasksRepo   jobs.TaskRepository
	conduit     capability.Conduit
	concurrency int
}

// newCapService builds the capability layer for a test: a thin wrapper over
// the capability constructors, so the layer's shape changes in one place.
func newCapService(t *testing.T, s capSeams) *capability.Execution {
	t.Helper()
	if s.audit == nil || s.authz == nil || s.freeze == nil || s.auditQ == nil || s.jobQ == nil {
		t.Fatalf("newCapService: audit, authz, freeze, auditQ and jobQ are required")
	}
	rec := capability.NewRecorder(s.audit, nil, nil)
	ctl := capability.NewControl(rec, s.authz, s.freeze)
	read := capability.NewReadLane(rec, s.reg, s.auditQ, s.jobQ, nil, nil, 0, nil)
	if s.cap == nil || s.jobsRepo == nil || s.tasksRepo == nil || s.conduit == nil {
		t.Fatalf("newCapService: cap, jobsRepo, tasksRepo and conduit are required")
	}
	conc := s.concurrency
	if conc == 0 {
		conc = capability.DefaultDispatchConcurrency
	}
	// A gate with no rules: nothing parks, so the store and authorizer below it
	// are unreachable on every path these tests drive.
	gate, err := approval.NewGate(nil)
	if err != nil {
		t.Fatalf("approval.NewGate: %v", err)
	}
	appr := capability.NewApprovals(rec, gate, unreachableApprovalStore{}, denyApprovalDecisions{}, nil, nil, nil, nil)
	return capability.NewExecution(ctl, read, appr, s.cap, nil, s.jobsRepo, s.tasksRepo, s.conduit, conc, nil, nil)
}

// unreachableApprovalStore is the approval store behind an empty gate: nothing
// ungated reaches it; a call panics on the nil embed, so a test that did would
// fail loudly.
type unreachableApprovalStore struct{ capability.ApprovalStore }

// denyApprovalDecisions is the decision floor behind an empty gate.
type denyApprovalDecisions struct{}

func (denyApprovalDecisions) AuthorizeApprovalDecision(context.Context, capability.Principal, jobs.ActionKind) error {
	return errors.New("test: approval decisions are not wired")
}
