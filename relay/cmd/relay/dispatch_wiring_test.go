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
	reads := newSignalInFlight(tasks)
	router, _, _ := newDispatchStack(reads, nil, nil)

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
	reads.awaitReads(t, 3)

	hold := &holdingConduit{Router: router, held: make(chan string, 1), release: make(chan struct{})}
	q := auditquery.New(st.AuditQueries(), st.JobQueries())
	capSvc := newCapService(t, capSeams{
		reg:         st.Registry(),
		authz:       allowAllTestAuthorizer{},
		settings:    blastCaps(10, 10),
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
	reg   registry.Repository
	authz capability.Authorizer
	// settings carries the blast caps; nil means the defaults.
	settings    *capability.StaticOperatorSettings
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
	if s.jobsRepo == nil || s.tasksRepo == nil || s.conduit == nil {
		t.Fatalf("newCapService: jobsRepo, tasksRepo and conduit are required")
	}
	// One source for the read lane, the BlastCap and the Execution, as the
	// composition root wires them.
	settings := &capability.StaticOperatorSettings{}
	if s.settings != nil {
		settings.S = s.settings.S
	}
	settings.S.DispatchConcurrency = s.concurrency
	if settings.S.DispatchConcurrency == 0 {
		settings.S.DispatchConcurrency = capability.DefaultDispatchConcurrency
	}
	read := capability.NewReadLane(rec, s.reg, s.auditQ, s.jobQ, nil, nil, settings, nil)
	// A gate with no rules: nothing parks, so the store and authorizer below it
	// are unreachable on every path these tests drive.
	gate, err := approval.NewGate(nil)
	if err != nil {
		t.Fatalf("approval.NewGate: %v", err)
	}
	appr := capability.NewApprovals(rec, gate, unreachableApprovalStore{}, denyApprovalDecisions{}, nil, nil, nil)
	return capability.NewExecution(ctl, read, appr, capability.NewBlastCap(settings), nil, s.jobsRepo, s.tasksRepo, s.conduit, settings, nil, nil)
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

// blastCaps is the settings a fixture hands newCapService to give the layer
// these blast caps; zero takes the package default, as BlastCap clamps it.
func blastCaps(readCap, mutateCap int) *capability.StaticOperatorSettings {
	return &capability.StaticOperatorSettings{S: capability.OperatorSettings{ReadBlastCap: readCap, MutateBlastCap: mutateCap}}
}

// signalInFlight wraps a TaskRepository to signal each InFlight read once it
// has returned. Every registration runs a reconcile on its own goroutine, and
// a test that seeds Dispatched Tasks while that reconcile has not yet read the
// in-flight set races it: the reconcile re-sends the Tasks beside the test's
// own callers. Waiting for the read first makes the test's callers the only
// senders.
type signalInFlight struct {
	jobs.TaskRepository
	read chan struct{}
}

func newSignalInFlight(tasks jobs.TaskRepository) *signalInFlight {
	return &signalInFlight{TaskRepository: tasks, read: make(chan struct{}, 64)}
}

func (s *signalInFlight) InFlight(ctx context.Context) ([]jobs.Task, error) {
	got, err := s.TaskRepository.InFlight(ctx)
	select {
	case s.read <- struct{}{}:
	default:
	}
	return got, err
}

// awaitReads waits for n InFlight reads.
func (s *signalInFlight) awaitReads(t *testing.T, n int) {
	t.Helper()
	for range n {
		select {
		case <-s.read:
		case <-time.After(5 * time.Second):
			t.Fatal("timeout waiting for a registration's reconcile to read the in-flight set")
		}
	}
}

// A Node whose stream ends resolves the Tasks in flight to it as failures with
// the node-offline message, leaves alone a Task whose real result had already
// arrived, and never re-sends either on the Node's next connect (invariant 4).
func TestDispatchWiring_InFlightTaskResolvesWhenNodeStreamEndsAndIsNeverResent(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	repo, st := testTaskRepositoryWithStore(t)
	tasks := newSignalInFlight(repo)
	router, _, sink := newDispatchStack(tasks, nil, nil)

	now := time.Now().UTC()
	if err := st.Jobs().CreateJob(ctx, jobs.Job{ID: "job-1", CreatedAt: now}); err != nil {
		t.Fatalf("CreateJob: %v", err)
	}
	if err := st.Jobs().AddStage(ctx, jobs.Stage{ID: "stage-1", JobID: "job-1", Index: 0}); err != nil {
		t.Fatalf("AddStage: %v", err)
	}

	sentCh := make(chan *relayv1.RelayMessage, 8)
	unregister := sink.register("node-1", func(msg *relayv1.RelayMessage) error {
		sentCh <- msg
		return nil
	})
	// The connect's reconcile reads the in-flight set before any Task exists,
	// so the test's own calls below are the only senders.
	tasks.awaitReads(t, 1)

	action := jobs.Action{Kind: jobs.ActionOperation, OperationName: "system.facts", RiskClass: jobs.RiskClassRead}
	seeded := []jobs.Task{
		{ID: "task-silent", JobID: "job-1", StageID: "stage-1", NodeID: "node-1", Action: action, CreatedAt: now},
		{ID: "task-answered", JobID: "job-1", StageID: "stage-1", NodeID: "node-1", Action: action, CreatedAt: now},
	}
	settlements := map[string]*jobs.Settlement{}
	var dispatched sync.WaitGroup
	for _, task := range seeded {
		if err := tasks.CreateTask(ctx, task); err != nil {
			t.Fatalf("CreateTask(%s): %v", task.ID, err)
		}
		if err := tasks.MarkDispatched(ctx, task.ID, now); err != nil {
			t.Fatalf("MarkDispatched(%s): %v", task.ID, err)
		}
		// Each call carries a Settlement, as the capability engine's does.
		dctx, settlement := jobs.WithSettlement(ctx)
		settlements[task.ID] = settlement
		dispatched.Add(1)
		go func() {
			defer dispatched.Done()
			_, _ = router.Dispatch(dctx, "node-1", task)
		}()
	}
	for range seeded {
		select {
		case <-sentCh:
		case <-time.After(2 * time.Second):
			t.Fatal("timeout waiting for the Router to send a Task")
		}
	}

	// task-answered's result arrives, then the stream ends.
	sink.deliver("node-1", &relayv1.TaskResult{TaskId: "task-answered", Outcome: relayv1.Outcome_OUTCOME_SUCCESS})
	unregister()
	dispatched.Wait()
	settlements["task-silent"].Settle()

	silent, err := tasks.Get(ctx, "task-silent")
	if err != nil {
		t.Fatalf("Get(task-silent): %v", err)
	}
	if silent.State != jobs.DispatchStateResolved || silent.Outcome != jobs.OutcomeFailure ||
		silent.ExitCode != -1 || string(silent.Stderr) != jobs.NodeOfflineMessage {
		t.Errorf("task-silent = %+v, want Resolved failure, exit -1, the node-offline message", silent)
	}
	answered, err := tasks.Get(ctx, "task-answered")
	if err != nil {
		t.Fatalf("Get(task-answered): %v", err)
	}
	if answered.State != jobs.DispatchStateDispatched {
		t.Errorf("task-answered = %+v, want it left Dispatched for its worker to resolve with the real result", answered)
	}

	// Its worker resolves it with the real result, as the capability engine
	// does, and then settles.
	if err := tasks.Resolve(ctx, "task-answered", jobs.Result{Outcome: jobs.OutcomeSuccess}); err != nil {
		t.Fatalf("Resolve(task-answered): %v", err)
	}
	settlements["task-answered"].Settle()

	// The Node reconnects: onConnect runs the Reconciler, which must send nothing.
	reconnected := make(chan *relayv1.RelayMessage, 8)
	unregisterAgain := sink.register("node-1", func(msg *relayv1.RelayMessage) error {
		reconnected <- msg
		return nil
	})
	defer unregisterAgain()
	select {
	case msg := <-reconnected:
		t.Fatalf("reconnect sent %v for a Task already resolved", msg)
	case <-time.After(500 * time.Millisecond):
	}
}

// seedDispatchedTask stores a Job with one Stage and one Task for nodeID, and
// marks the Task Dispatched, as a worker that has begun to send it leaves it.
func seedDispatchedTask(t *testing.T, st *store.Store, tasks jobs.TaskRepository, nodeID, taskID string) jobs.Task {
	t.Helper()
	ctx := context.Background()
	now := time.Now().UTC()
	if err := st.Jobs().CreateJob(ctx, jobs.Job{ID: "job-" + taskID, CreatedAt: now}); err != nil {
		t.Fatalf("CreateJob: %v", err)
	}
	if err := st.Jobs().AddStage(ctx, jobs.Stage{ID: "stage-" + taskID, JobID: "job-" + taskID, Index: 0}); err != nil {
		t.Fatalf("AddStage: %v", err)
	}
	task := jobs.Task{
		ID: taskID, JobID: "job-" + taskID, StageID: "stage-" + taskID, NodeID: nodeID, CreatedAt: now,
		Action: jobs.Action{Kind: jobs.ActionOperation, OperationName: "system.facts", RiskClass: jobs.RiskClassRead},
	}
	if err := tasks.CreateTask(ctx, task); err != nil {
		t.Fatalf("CreateTask: %v", err)
	}
	if err := tasks.MarkDispatched(ctx, taskID, now); err != nil {
		t.Fatalf("MarkDispatched: %v", err)
	}
	return task
}

// A result that arrived is not replaced by the offline resolution however long
// its persistence takes: the protection lasts until the caller settles the
// Task, with no time horizon. The stream ends while the real result is not yet
// written; the Task is left alone, and the real result then lands.
func TestDispatchWiring_DeliveredResultSurvivesTeardownUntilItIsPersisted(t *testing.T) {
	ctx := context.Background()
	repo, st := testTaskRepositoryWithStore(t)
	tasks := newSignalInFlight(repo)
	router, _, sink := newDispatchStack(tasks, nil, nil)

	sent := make(chan *relayv1.RelayMessage, 4)
	unregister := sink.register("node-1", func(msg *relayv1.RelayMessage) error {
		sent <- msg
		return nil
	})
	tasks.awaitReads(t, 1)
	task := seedDispatchedTask(t, st, tasks, "node-1", "task-1")

	type outcome struct {
		res jobs.Result
		err error
	}
	returned := make(chan outcome, 1)
	dctx, settlement := jobs.WithSettlement(ctx)
	go func() {
		res, err := router.Dispatch(dctx, "node-1", task)
		returned <- outcome{res, err}
	}()
	select {
	case <-sent:
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for the Router to send the Task")
	}
	sink.deliver("node-1", &relayv1.TaskResult{TaskId: "task-1", Outcome: relayv1.Outcome_OUTCOME_SUCCESS})
	var got outcome
	select {
	case got = <-returned:
	case <-time.After(2 * time.Second):
		t.Fatal("Dispatch did not return the delivered result")
	}
	if got.err != nil || got.res.Outcome != jobs.OutcomeSuccess {
		t.Fatalf("Dispatch = (%+v, %v), want the delivered success", got.res, got.err)
	}

	// The caller has the result but has not written it; the stream ends.
	unregister()
	stored, err := tasks.Get(ctx, "task-1")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if stored.State != jobs.DispatchStateDispatched {
		t.Fatalf("task = %+v, want it left Dispatched for the caller's write, not resolved offline", stored)
	}

	// The caller's write lands, then it settles.
	if err := tasks.Resolve(ctx, "task-1", got.res); err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	settlement.Settle()
	stored, err = tasks.Get(ctx, "task-1")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if stored.State != jobs.DispatchStateResolved || stored.Outcome != jobs.OutcomeSuccess {
		t.Errorf("task = %+v, want Resolved with the real success result", stored)
	}
}

// TestDispatchWiring_AHaltedJobsUnsentTasksAreNeverSentAfterARestart is #1150's
// at-most-once proof over a real store and the real Router: a mutate Job whose
// first Task fails sends nothing further, records the halt, and after a
// simulated restart the Reconciler has no Task of the halted Job to send
// (invariant 4).
func TestDispatchWiring_AHaltedJobsUnsentTasksAreNeverSentAfterARestart(t *testing.T) {
	tasks, st := testTaskRepositoryWithStore(t)
	reads := newSignalInFlight(tasks)
	router, _, _ := newDispatchStack(reads, nil, nil)

	nodes := []string{"node-1", "node-2", "node-3"}
	var mu sync.Mutex
	var requested []string // node IDs whose TaskRequest reached a Tunnel
	for _, id := range nodes {
		if _, err := st.Registry().Upsert(registry.Report{NodeID: id}); err != nil {
			t.Fatalf("Upsert(%s): %v", id, err)
		}
		router.Register(id, func(msg *relayv1.RelayMessage) error {
			if task := msg.GetTask(); task != nil {
				mu.Lock()
				requested = append(requested, id)
				mu.Unlock()
				// The relay-daemon answers failure; delivered off the send path.
				go router.Deliver(id, &relayv1.TaskResult{TaskId: task.GetTaskId(), Outcome: relayv1.Outcome_OUTCOME_FAILURE})
			}
			return nil
		})
	}
	reads.awaitReads(t, len(nodes))

	q := auditquery.New(st.AuditQueries(), st.JobQueries())
	capSvc := newCapService(t, capSeams{
		reg:         st.Registry(),
		authz:       allowAllTestAuthorizer{},
		settings:    blastCaps(10, 10),
		audit:       auditsink.New(st.Audit()),
		freeze:      st.Freeze(),
		auditQ:      q,
		jobQ:        q,
		jobsRepo:    st.Jobs(),
		tasksRepo:   tasks,
		conduit:     router,
		concurrency: 1,
	})
	results, err := capSvc.Run(context.Background(), capability.Principal{Account: "devharness"}, capability.Selector{},
		jobs.Action{Kind: jobs.ActionRawExec, RawExecArgv: []string{"/bin/true"}})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	jobID := results[0].JobID

	mu.Lock()
	sent := append([]string(nil), requested...)
	mu.Unlock()
	if len(sent) != 1 {
		t.Fatalf("TaskRequests on Tunnels = %v, want exactly one", sent)
	}
	job, err := st.Jobs().GetJob(context.Background(), jobID)
	if err != nil {
		t.Fatalf("GetJob: %v", err)
	}
	if job.Halt.NodeID != sent[0] || job.Halt.Outcome != jobs.OutcomeFailure || !job.Halt.Resolved {
		t.Errorf("Job.Halt = %+v, want the Node that was sent, failure, with a recorded result", job.Halt)
	}
	all, err := tasks.ByJob(context.Background(), jobID)
	if err != nil || len(all) != len(nodes) {
		t.Fatalf("ByJob = %d tasks, %v; want %d", len(all), err, len(nodes))
	}
	for _, task := range all {
		if task.NodeID == sent[0] {
			continue
		}
		if task.State != jobs.DispatchStateResolved || task.Outcome != jobs.OutcomeCancelled ||
			!task.DispatchedAt.IsZero() || string(task.Stderr) != job.Halt.Reason() {
			t.Errorf("unsent task %s = %v/%v dispatched %v stderr %q, want Resolved/cancelled, never dispatched, the halt's reason",
				task.NodeID, task.State, task.Outcome, task.DispatchedAt, task.Stderr)
		}
	}
	records, err := st.Audit().ByJob(context.Background(), jobID)
	if err != nil {
		t.Fatalf("Audit().ByJob: %v", err)
	}
	halts := 0
	for _, rec := range records {
		if rec.Kind == audit.KindJobHalt {
			halts++
		}
	}
	if halts != 1 {
		t.Errorf("job_halt audit records = %d, want 1", halts)
	}

	// A restart keeps only the store. A second dispatch stack over it
	// reconciles each Node as it connects and must find nothing to send.
	reads2 := newSignalInFlight(tasks)
	router2, _, _ := newDispatchStack(reads2, nil, nil)
	resent := make(chan *relayv1.RelayMessage, 8)
	for _, id := range nodes {
		router2.Register(id, func(msg *relayv1.RelayMessage) error {
			resent <- msg
			return nil
		})
	}
	reads2.awaitReads(t, len(nodes))
	select {
	case msg := <-resent:
		t.Fatalf("a restart's reconcile sent %v for a halted Job", msg)
	case <-time.After(500 * time.Millisecond):
	}
	if inFlight, err := tasks.InFlight(context.Background()); err != nil || len(inFlight) != 0 {
		t.Errorf("InFlight after the restart = %v, %v; want empty", inFlight, err)
	}
}

// TestDispatchWiring_AHaltClosingAfterASiblingPassedAdmitWithholdsItsSend is
// the halt's race through the real store, Router and engine: one Task is past
// MarkDispatched and not yet at its send guard (holdingConduit pauses it before
// Router.Dispatch) when the other Task fails and the Job halts. The paused
// Task's TaskRequest is never written, it resolves cancelled with the halt as
// its reason and no DispatchedAt, and nothing is left in flight for a
// Reconciler to send (invariant 4).
func TestDispatchWiring_AHaltClosingAfterASiblingPassedAdmitWithholdsItsSend(t *testing.T) {
	tasks, st := testTaskRepositoryWithStore(t)
	reads := newSignalInFlight(tasks)
	router, _, _ := newDispatchStack(reads, nil, nil)

	nodes := []string{"node-1", "node-2", "node-3"}
	failNow := make(chan struct{}) // the relay-daemon's failure is held until the sibling is paused
	var mu sync.Mutex
	requested := map[string]string{} // task ID -> node ID, TaskRequests that reached a Tunnel
	for _, id := range nodes {
		if _, err := st.Registry().Upsert(registry.Report{NodeID: id}); err != nil {
			t.Fatalf("Upsert(%s): %v", id, err)
		}
		router.Register(id, func(msg *relayv1.RelayMessage) error {
			if task := msg.GetTask(); task != nil {
				mu.Lock()
				requested[task.GetTaskId()] = id
				mu.Unlock()
				go func() {
					<-failNow
					router.Deliver(id, &relayv1.TaskResult{TaskId: task.GetTaskId(), Outcome: relayv1.Outcome_OUTCOME_FAILURE})
				}()
			}
			return nil
		})
	}
	reads.awaitReads(t, len(nodes))

	hold := &holdingConduit{Router: router, held: make(chan string, 1), release: make(chan struct{})}
	q := auditquery.New(st.AuditQueries(), st.JobQueries())
	capSvc := newCapService(t, capSeams{
		reg:         st.Registry(),
		authz:       allowAllTestAuthorizer{},
		settings:    blastCaps(10, 10),
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
			jobs.Action{Kind: jobs.ActionRawExec, RawExecArgv: []string{"/bin/true"}})
		done <- runOut{res, err}
	}()

	var heldID string
	select {
	case heldID = <-hold.held:
	case <-time.After(5 * time.Second):
		t.Fatal("no Task was held past MarkDispatched")
	}
	held := mustTask(t, tasks, heldID)
	if held.State != jobs.DispatchStateDispatched {
		t.Fatalf("held task = %v, want Dispatched: it must be past admit", held.State)
	}
	hold.mu.Lock()
	firstID := hold.entered[0]
	hold.mu.Unlock()
	close(failNow) // the other Task fails while the held one waits before its guard

	var halt jobs.Halt
	deadline := time.Now().Add(5 * time.Second)
	for !halt.Halted() {
		job, err := st.Jobs().GetJob(context.Background(), held.JobID)
		if err != nil {
			t.Fatalf("GetJob: %v", err)
		}
		halt = job.Halt
		if !halt.Halted() && time.Now().After(deadline) {
			t.Fatal("the Job did not halt on the sibling's failure")
		}
		time.Sleep(time.Millisecond)
	}
	if halt.TaskID != firstID {
		t.Fatalf("halted by %s, want the first Task %s", halt.TaskID, firstID)
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

	mu.Lock()
	defer mu.Unlock()
	if len(requested) != 1 {
		t.Errorf("TaskRequests on Tunnels = %v, want only the failing Task", requested)
	}
	if _, ok := requested[heldID]; ok {
		t.Errorf("held Task %s was written to a Tunnel after the Job halted", heldID)
	}
	all, err := tasks.ByJob(context.Background(), held.JobID)
	if err != nil || len(all) != len(nodes) {
		t.Fatalf("ByJob = %d tasks, %v; want %d", len(all), err, len(nodes))
	}
	for _, task := range all {
		if task.ID == firstID {
			if task.State != jobs.DispatchStateResolved || task.Outcome != jobs.OutcomeFailure {
				t.Errorf("failing task = %v/%v, want Resolved/failure", task.State, task.Outcome)
			}
			continue
		}
		if task.State != jobs.DispatchStateResolved || task.Outcome != jobs.OutcomeCancelled ||
			!task.DispatchedAt.IsZero() || string(task.Stderr) != halt.Reason() {
			t.Errorf("task %s = %v/%v dispatched %v stderr %q, want Resolved/cancelled, never sent, the halt's reason",
				task.ID, task.State, task.Outcome, task.DispatchedAt, task.Stderr)
		}
	}
	for _, r := range out.results {
		if r.NodeID != held.NodeID {
			continue
		}
		if r.Outcome != jobs.OutcomeCancelled || string(r.Stderr) != halt.Reason() {
			t.Errorf("result for the held Task = %v %q, want cancelled with the halt's reason", r.Outcome, r.Stderr)
		}
	}
	if inFlight, err := tasks.InFlight(context.Background()); err != nil || len(inFlight) != 0 {
		t.Errorf("InFlight = %v, %v; want empty", inFlight, err)
	}
}
