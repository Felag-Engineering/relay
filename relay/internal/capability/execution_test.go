package capability

import (
	"context"
	"errors"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/jobs"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/registry"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/store"
)

// fakeConduit is a configurable Conduit: connected reports which Nodes have
// a live Tunnel, and results/errs supply a canned Dispatch outcome per Node.
// It also records every Dispatch/Cancel/Query call (in order) to a shared
// log so tests can assert dispatch ordering relative to persistence.
// verdicts/queryErrs supply a canned Query outcome per Node (#119).
type fakeConduit struct {
	connected map[string]bool
	results   map[string]jobs.Result
	errs      map[string]error
	cancelErr map[string]error
	verdicts  map[string]jobs.Verdict
	queryErrs map[string]error
	log       *[]string
}

func newFakeConduit(log *[]string) *fakeConduit {
	return &fakeConduit{
		connected: map[string]bool{},
		results:   map[string]jobs.Result{},
		errs:      map[string]error{},
		cancelErr: map[string]error{},
		verdicts:  map[string]jobs.Verdict{},
		queryErrs: map[string]error{},
		log:       log,
	}
}

func (f *fakeConduit) Connected(nodeID string) bool { return f.connected[nodeID] }

func (f *fakeConduit) Dispatch(_ context.Context, nodeID string, _ jobs.Task) (jobs.Result, error) {
	if f.log != nil {
		*f.log = append(*f.log, "dispatch:"+nodeID)
	}
	if err, ok := f.errs[nodeID]; ok && err != nil {
		return jobs.Result{}, err
	}
	return f.results[nodeID], nil
}

// Cancel records "cancel:<nodeID>:<taskID>" to the shared log and returns
// the canned error for nodeID, if any.
func (f *fakeConduit) Cancel(_ context.Context, nodeID, taskID string) error {
	if f.log != nil {
		*f.log = append(*f.log, "cancel:"+nodeID+":"+taskID)
	}
	return f.cancelErr[nodeID]
}

// Query records "query:<nodeID>" to the shared log and returns the canned
// jobs.Verdict/error for nodeID (#119), mirroring Dispatch's shape.
func (f *fakeConduit) Query(_ context.Context, nodeID string, _ jobs.Action) (jobs.Verdict, error) {
	if f.log != nil {
		*f.log = append(*f.log, "query:"+nodeID)
	}
	if err, ok := f.queryErrs[nodeID]; ok && err != nil {
		return jobs.Verdict{}, err
	}
	return f.verdicts[nodeID], nil
}

// recordingTasks wraps a jobs.TaskRepository, appending "create:<nodeID>" to
// a shared log on every CreateTask so tests can assert that every Task is
// persisted before any is dispatched.
type recordingTasks struct {
	jobs.TaskRepository
	log *[]string
}

func (r *recordingTasks) CreateTask(ctx context.Context, task jobs.Task) error {
	err := r.TaskRepository.CreateTask(ctx, task)
	if err == nil {
		*r.log = append(*r.log, "create:"+task.NodeID)
	}
	return err
}

// testEngineStore opens a temp SQLite store and returns its Job/Task
// repositories, satisfying the plan's "store.Open on a temp DB, as
// tasks_test does" test strategy.
func testEngineStore(t *testing.T) (jobs.JobRepository, jobs.TaskRepository) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "relay.db")
	st, err := store.Open(path)
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { st.Close() }) //nolint:errcheck
	return st.Jobs(), st.Tasks()
}

// sequentialIDs returns an idGen that yields prefix+"1", prefix+"2", ... in
// call order, so tests can assert exact IDs deterministically.
func sequentialIDs(prefix string) idGen {
	n := 0
	return func() (string, error) {
		n++
		return prefix + strconv.Itoa(n), nil
	}
}

func testNode(nodeID string) registry.Node {
	return registry.Node{NodeID: nodeID}
}

// TestEngineOneTaskPerNodePersistedBeforeDispatch is acceptance criterion 2:
// N matched Nodes yield N Tasks with unique IDs, and every CreateTask
// happens before any Dispatch.
func TestEngineOneTaskPerNodePersistedBeforeDispatch(t *testing.T) {
	jobsRepo, tasksRepo := testEngineStore(t)
	var log []string
	conduit := newFakeConduit(&log)
	conduit.connected["node-1"] = true
	conduit.connected["node-2"] = true
	conduit.connected["node-3"] = true
	conduit.results["node-1"] = jobs.Result{Outcome: jobs.OutcomeSuccess}
	conduit.results["node-2"] = jobs.Result{Outcome: jobs.OutcomeSuccess}
	conduit.results["node-3"] = jobs.Result{Outcome: jobs.OutcomeSuccess}

	e := &jobEngine{
		jobsRepo:  jobsRepo,
		tasksRepo: &recordingTasks{TaskRepository: tasksRepo, log: &log},
		conduit:   conduit,
		newID:     sequentialIDs("id-"),
		now:       func() time.Time { return time.Date(2026, 7, 8, 0, 0, 0, 0, time.UTC) },
	}

	nodes := []registry.Node{testNode("node-1"), testNode("node-2"), testNode("node-3")}
	act := jobs.Action{Kind: jobs.ActionOperation, OperationName: "system.facts", RiskClass: jobs.RiskClassRead}
	d := newDispatch(Principal{Account: "alice"}, Selector{}, nodes, act)

	dr, err := e.run(context.Background(), d)
	results := dr.results
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if len(results) != 3 {
		t.Fatalf("run() returned %d results, want 3", len(results))
	}

	jobID := "job-id-1"
	tasks, err := tasksRepo.ByJob(context.Background(), jobID)
	if err != nil {
		t.Fatalf("ByJob(%s): %v", jobID, err)
	}
	if len(tasks) != 3 {
		t.Fatalf("ByJob(%s) returned %d Tasks, want 3", jobID, len(tasks))
	}

	seen := map[string]bool{}
	for _, task := range tasks {
		if seen[task.ID] {
			t.Errorf("duplicate Task ID %q", task.ID)
		}
		seen[task.ID] = true
	}

	lastCreate, firstDispatch := -1, -1
	for i, entry := range log {
		if strings.HasPrefix(entry, "create:") {
			lastCreate = i
		}
		if strings.HasPrefix(entry, "dispatch:") && firstDispatch == -1 {
			firstDispatch = i
		}
	}
	if lastCreate == -1 || firstDispatch == -1 {
		t.Fatalf("expected both create and dispatch log entries, got %v", log)
	}
	if lastCreate > firstDispatch {
		t.Errorf("a Task was dispatched before all Tasks were persisted: log = %v", log)
	}
}

// TestEngineOfflineNodeUnreachable is docs/specs/execution.md's acceptance line: a Job
// spanning an offline Node reports unreachable for it and real results for
// the rest. It also covers #185's full-output-always plumbing: a successful
// Dispatch's Stdout/Stderr/Truncated must reach the returned NodeResult, and
// an unreachable Node (never dispatched) must carry none.
func TestEngineOfflineNodeUnreachable(t *testing.T) {
	jobsRepo, tasksRepo := testEngineStore(t)
	conduit := newFakeConduit(nil)
	conduit.connected["node-online"] = true
	conduit.results["node-online"] = jobs.Result{
		Outcome: jobs.OutcomeSuccess, ExitCode: 0,
		Stdout: []byte("all good\n"), Stderr: []byte(""), Truncated: true,
	}
	// node-offline is deliberately absent from conduit.connected (false).

	e := &jobEngine{
		jobsRepo:  jobsRepo,
		tasksRepo: tasksRepo,
		conduit:   conduit,
		newID:     sequentialIDs("id-"),
		now:       func() time.Time { return time.Date(2026, 7, 8, 0, 0, 0, 0, time.UTC) },
	}

	nodes := []registry.Node{testNode("node-online"), testNode("node-offline")}
	act := jobs.Action{Kind: jobs.ActionOperation, OperationName: "system.facts", RiskClass: jobs.RiskClassRead}
	d := newDispatch(Principal{Account: "alice"}, Selector{}, nodes, act)

	dr, err := e.run(context.Background(), d)
	results := dr.results
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if len(results) != 2 {
		t.Fatalf("run() returned %d results, want 2", len(results))
	}
	if results[0].NodeID != "node-online" || results[0].Outcome != jobs.OutcomeSuccess {
		t.Errorf("results[0] = %+v, want node-online/OutcomeSuccess", results[0])
	}
	if string(results[0].Stdout) != "all good\n" || string(results[0].Stderr) != "" || !results[0].Truncated {
		t.Errorf("results[0] Stdout/Stderr/Truncated = %q/%q/%v, want %q/%q/true",
			results[0].Stdout, results[0].Stderr, results[0].Truncated, "all good\n", "")
	}
	if results[1].NodeID != "node-offline" || results[1].Outcome != jobs.OutcomeUnreachable {
		t.Errorf("results[1] = %+v, want node-offline/OutcomeUnreachable", results[1])
	}
	if len(results[1].Stdout) != 0 || len(results[1].Stderr) != 0 || results[1].Truncated {
		t.Errorf("results[1] Stdout/Stderr/Truncated = %q/%q/%v, want all empty/false (never dispatched)",
			results[1].Stdout, results[1].Stderr, results[1].Truncated)
	}

	ctx := context.Background()
	offlineTasks, err := tasksRepo.ByJob(ctx, "job-id-1")
	if err != nil {
		t.Fatalf("ByJob: %v", err)
	}
	var offlineTask jobs.Task
	for _, task := range offlineTasks {
		if task.NodeID == "node-offline" {
			offlineTask = task
		}
	}
	if offlineTask.State != jobs.DispatchStateResolved {
		t.Errorf("offline Task state = %v, want DispatchStateResolved", offlineTask.State)
	}
	if offlineTask.Outcome != jobs.OutcomeUnreachable {
		t.Errorf("offline Task outcome = %v, want OutcomeUnreachable", offlineTask.Outcome)
	}
	if !offlineTask.DispatchedAt.IsZero() {
		t.Errorf("offline Task DispatchedAt = %v, want zero (never dispatched)", offlineTask.DispatchedAt)
	}

	inFlight, err := tasksRepo.InFlight(ctx)
	if err != nil {
		t.Fatalf("InFlight: %v", err)
	}
	if len(inFlight) != 0 {
		t.Errorf("InFlight = %v, want empty (offline Task is already terminal)", inFlight)
	}
}

// TestEngineMixedOutcomesTruthful is acceptance criterion 4: success +
// denied-by-policy + unreachable in one Job, each reported per Node, none
// fabricated.
func TestEngineMixedOutcomesTruthful(t *testing.T) {
	jobsRepo, tasksRepo := testEngineStore(t)
	conduit := newFakeConduit(nil)
	conduit.connected["node-ok"] = true
	conduit.connected["node-denied"] = true
	conduit.results["node-ok"] = jobs.Result{Outcome: jobs.OutcomeSuccess}
	conduit.results["node-denied"] = jobs.Result{Outcome: jobs.OutcomeDeniedByPolicy}
	// node-offline stays disconnected.

	e := &jobEngine{
		jobsRepo:  jobsRepo,
		tasksRepo: tasksRepo,
		conduit:   conduit,
		newID:     sequentialIDs("id-"),
		now:       func() time.Time { return time.Date(2026, 7, 8, 0, 0, 0, 0, time.UTC) },
	}

	nodes := []registry.Node{testNode("node-ok"), testNode("node-denied"), testNode("node-offline")}
	act := jobs.Action{Kind: jobs.ActionRawExec, RawExecArgv: []string{"/bin/true"}, RiskClass: jobs.RiskClassMutate}
	d := newDispatch(Principal{Account: "alice"}, Selector{}, nodes, act)

	dr, err := e.run(context.Background(), d)
	results := dr.results
	if err != nil {
		t.Fatalf("run: %v", err)
	}

	want := map[string]jobs.Outcome{
		"node-ok":      jobs.OutcomeSuccess,
		"node-denied":  jobs.OutcomeDeniedByPolicy,
		"node-offline": jobs.OutcomeUnreachable,
	}
	if len(results) != len(want) {
		t.Fatalf("run() returned %d results, want %d", len(results), len(want))
	}
	for _, r := range results {
		wantOutcome, ok := want[r.NodeID]
		if !ok {
			t.Errorf("unexpected NodeResult for %q", r.NodeID)
			continue
		}
		if r.Outcome != wantOutcome {
			t.Errorf("NodeResult[%s].Outcome = %v, want %v", r.NodeID, r.Outcome, wantOutcome)
		}
	}
}

// TestEngineConduitErrorLeavesTaskInFlight locks in the deliberate asymmetry:
// a connected Node whose Conduit.Dispatch errors leaves its Task Dispatched
// (never Resolved), reports OutcomeFailure, and the conduit error is joined
// into run's returned error.
func TestEngineConduitErrorLeavesTaskInFlight(t *testing.T) {
	jobsRepo, tasksRepo := testEngineStore(t)
	conduit := newFakeConduit(nil)
	conduit.connected["node-flaky"] = true
	sendErr := errors.New("connection reset mid-send")
	conduit.errs["node-flaky"] = sendErr

	e := &jobEngine{
		jobsRepo:  jobsRepo,
		tasksRepo: tasksRepo,
		conduit:   conduit,
		newID:     sequentialIDs("id-"),
		now:       func() time.Time { return time.Date(2026, 7, 8, 0, 0, 0, 0, time.UTC) },
	}

	nodes := []registry.Node{testNode("node-flaky")}
	act := jobs.Action{Kind: jobs.ActionOperation, OperationName: "system.facts", RiskClass: jobs.RiskClassRead}
	d := newDispatch(Principal{Account: "alice"}, Selector{}, nodes, act)

	dr, err := e.run(context.Background(), d)
	results := dr.results
	if err == nil {
		t.Fatal("run() with an erroring Conduit should return an error")
	}
	if !errors.Is(err, sendErr) {
		t.Errorf("run() error = %v, want it to wrap %v", err, sendErr)
	}
	if len(results) != 1 || results[0].NodeID != "node-flaky" || results[0].Outcome != jobs.OutcomeFailure {
		t.Errorf("results = %+v, want [{node-flaky OutcomeFailure}]", results)
	}

	ctx := context.Background()
	tasks, err := tasksRepo.ByJob(ctx, "job-id-1")
	if err != nil {
		t.Fatalf("ByJob: %v", err)
	}
	if len(tasks) != 1 {
		t.Fatalf("ByJob returned %d Tasks, want 1", len(tasks))
	}
	if tasks[0].State != jobs.DispatchStateDispatched {
		t.Errorf("Task state = %v, want DispatchStateDispatched (send failed after dispatch, never resolved)", tasks[0].State)
	}

	inFlight, err := tasksRepo.InFlight(ctx)
	if err != nil {
		t.Fatalf("InFlight: %v", err)
	}
	if len(inFlight) != 1 || inFlight[0].ID != tasks[0].ID {
		t.Errorf("InFlight = %v, want [%s] (reconciled on restart)", inFlight, tasks[0].ID)
	}
}

// TestEngineDispatchOneTreatsConcurrentCancelAsTerminal covers the
// dispatchOne gap-closure (ADR-0004/0013): a Task MarkCancelled while still
// Pending (a concurrent CancelJob reaching it before dispatchOne's own
// MarkDispatched call) must resolve to its real, already-persisted
// OutcomeCancelled — never a fabricated OutcomeFailure, and never actually
// dispatched to the Conduit.
func TestEngineDispatchOneTreatsConcurrentCancelAsTerminal(t *testing.T) {
	jobsRepo, tasksRepo := testEngineStore(t)
	var log []string
	conduit := newFakeConduit(&log)
	conduit.connected["node-1"] = true

	now := time.Date(2026, 7, 8, 0, 0, 0, 0, time.UTC)
	e := &jobEngine{
		tasksRepo: tasksRepo,
		conduit:   conduit,
		now:       func() time.Time { return now },
	}

	ctx := context.Background()
	if err := jobsRepo.CreateJob(ctx, jobs.Job{ID: "job-1", CreatedAt: now}); err != nil {
		t.Fatalf("CreateJob: %v", err)
	}
	if err := jobsRepo.AddStage(ctx, jobs.Stage{ID: "stage-1", JobID: "job-1", Index: 0}); err != nil {
		t.Fatalf("AddStage: %v", err)
	}
	task := jobs.Task{
		ID:        "task-1",
		JobID:     "job-1",
		StageID:   "stage-1",
		NodeID:    "node-1",
		Action:    jobs.Action{Kind: jobs.ActionOperation, OperationName: "system.facts", RiskClass: jobs.RiskClassRead},
		CreatedAt: now,
	}
	if err := tasksRepo.CreateTask(ctx, task); err != nil {
		t.Fatalf("CreateTask: %v", err)
	}
	// Simulate the concurrent CancelJob race: the Task is cancelled while
	// still Pending, before dispatchOne's own MarkDispatched runs.
	if err := tasksRepo.MarkCancelled(ctx, task.ID, now); err != nil {
		t.Fatalf("MarkCancelled: %v", err)
	}

	res, err := e.dispatchOne(ctx, task, false)
	if err != nil {
		t.Fatalf("dispatchOne: %v", err)
	}
	if res.Outcome != jobs.OutcomeCancelled {
		t.Errorf("dispatchOne Outcome = %v, want jobs.OutcomeCancelled", res.Outcome)
	}
	if len(log) != 0 {
		t.Errorf("Conduit.Dispatch was called for an already-cancelled task: log = %v", log)
	}

	got, err := tasksRepo.Get(ctx, task.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.State != jobs.DispatchStateResolved || got.Outcome != jobs.OutcomeCancelled {
		t.Errorf("Task = %+v, want Resolved/OutcomeCancelled unchanged by dispatchOne", got)
	}
	// dispatchOne's cancel-honored mapping reads Stdout/Stderr from the
	// already-persisted Task (via tasksRepo.Get) — MarkCancelled stores no
	// output, so both are empty; this asserts the mapping is truthful, not
	// aspirational.
	if len(res.Stdout) != 0 || len(res.Stderr) != 0 {
		t.Errorf("dispatchOne Stdout/Stderr = %q/%q, want both empty (MarkCancelled persists no output)", res.Stdout, res.Stderr)
	}
	if got.Stdout != nil || got.Stderr != nil {
		t.Errorf("Task Stdout/Stderr = %q/%q, want nil (MarkCancelled persists no output)", got.Stdout, got.Stderr)
	}
}

// TestEngineMixedFleetVersionGate is the DoD's mixed-fleet dispatch
// integration test (issue #179, ADR-0014): against a real store-backed
// registry with a minimum daemon version configured, a current Node executes
// and is sent over the Conduit, while an outdated Node is refused per-Task
// with OutcomeVersionRefused and NEVER reaches the Conduit — and the
// version-refusal is present in the AuditKindDispatch entry's Results (the
// audit trail), not a separate AuditKindRefusal.
func TestEngineMixedFleetVersionGate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "relay.db")
	st, err := store.Open(path, store.WithMinDaemonVersion("1.2.0"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { st.Close() }) //nolint:errcheck

	reg := st.Registry()
	if _, err := reg.Upsert(registry.Report{NodeID: "node-current", DaemonVersion: "1.2.0"}); err != nil {
		t.Fatalf("Upsert node-current: %v", err)
	}
	if _, err := reg.Upsert(registry.Report{NodeID: "node-old", DaemonVersion: "1.0.0"}); err != nil {
		t.Fatalf("Upsert node-old: %v", err)
	}

	var log []string
	conduit := newFakeConduit(&log)
	conduit.connected["node-current"] = true
	conduit.connected["node-old"] = true // connected, but must still be refused: the gate is connectivity-independent
	conduit.results["node-current"] = jobs.Result{Outcome: jobs.OutcomeSuccess}

	authz := &spyAuthorizer{}
	capChecker := &spyCapChecker{}
	audit := &spyAuditSink{}
	freezeStore := &fakeFreezeStore{}

	svc := New(reg,
		WithAuthorizer(authz),
		WithCapChecker(capChecker),
		WithAuditSink(audit),
		WithFreeze(freezeStore),
		WithExecution(st.Jobs(), st.Tasks(), conduit),
	)

	sel := Selector{} // Selector{} matches every Node (see selector.go)
	act := jobs.Action{Kind: jobs.ActionOperation, OperationName: "system.facts", RiskClass: jobs.RiskClassMutate}
	results, err := svc.Run(context.Background(), Principal{Account: "alice"}, sel, act)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	want := map[string]jobs.Outcome{
		"node-current": jobs.OutcomeSuccess,
		"node-old":     jobs.OutcomeVersionRefused,
	}
	if len(results) != len(want) {
		t.Fatalf("Run() returned %d results, want %d: %+v", len(results), len(want), results)
	}
	for _, r := range results {
		wantOutcome, ok := want[r.NodeID]
		if !ok {
			t.Errorf("unexpected NodeResult for %q", r.NodeID)
			continue
		}
		if r.Outcome != wantOutcome {
			t.Errorf("NodeResult[%s].Outcome = %v, want %v", r.NodeID, r.Outcome, wantOutcome)
		}
		// node-old's version-refusal carries the same Relay-synthesized
		// Stderr onto the NodeResult (and so into the audit trail) as the
		// Task row does (#122 full-output-always) — the audit trail must
		// never be less legible than the Task store for the same refusal.
		if r.NodeID == "node-old" && string(r.Stderr) != jobs.VersionRefusedMessage {
			t.Errorf("NodeResult[node-old].Stderr = %q, want VersionRefusedMessage", r.Stderr)
		}
	}

	// node-current was sent to the Conduit; node-old, though Connected, was
	// never dispatched — the gate runs before Conduit.Dispatch is ever called.
	if len(log) != 1 || log[0] != "dispatch:node-current" {
		t.Errorf("Conduit dispatch log = %v, want exactly [dispatch:node-current] (node-old must never reach the Conduit)", log)
	}

	// The audit trail: this is a AuditKindDispatch entry (the Job DID
	// dispatch, to node-current) whose Results carry the version-refusal —
	// not a whole-Job AuditKindRefusal.
	if !audit.called {
		t.Fatal("expected the audit sink to be called")
	}
	if audit.entry.Kind != AuditKindDispatch {
		t.Errorf("audit entry Kind = %v, want AuditKindDispatch", audit.entry.Kind)
	}
	foundRefusal := false
	for _, r := range audit.entry.Results {
		if r.NodeID == "node-old" && r.Outcome == jobs.OutcomeVersionRefused {
			foundRefusal = true
		}
	}
	if !foundRefusal {
		t.Errorf("audit entry Results = %+v, want a node-old/OutcomeVersionRefused entry (refusal must appear in the audit trail)", audit.entry.Results)
	}

	// The refused Task's persisted Stderr carries the legible reason.
	tasks, err := st.Tasks().ByJob(context.Background(), audit.entry.JobID)
	if err != nil {
		t.Fatalf("ByJob(%s): %v", audit.entry.JobID, err)
	}
	var oldTask jobs.Task
	for _, task := range tasks {
		if task.NodeID == "node-old" {
			oldTask = task
		}
	}
	if oldTask.State != jobs.DispatchStateResolved {
		t.Errorf("node-old Task state = %v, want DispatchStateResolved", oldTask.State)
	}
	if !oldTask.DispatchedAt.IsZero() {
		t.Errorf("node-old Task DispatchedAt = %v, want zero (never sent)", oldTask.DispatchedAt)
	}
	if string(oldTask.Stderr) != jobs.VersionRefusedMessage {
		t.Errorf("node-old Task Stderr = %q, want VersionRefusedMessage", oldTask.Stderr)
	}
}

// TestWithExecutionRefusesDefaultSeams is the New fail-open guard: wiring a
// real dispatcher via WithExecution without also supplying a real
// Authorizer/CapChecker/AuditSink must panic.
func TestWithExecutionRefusesDefaultSeams(t *testing.T) {
	jobsRepo, tasksRepo := testEngineStore(t)
	conduit := newFakeConduit(nil)
	reg := registry.NewInMemory()

	defer func() {
		if recover() == nil {
			t.Fatal("New(reg, WithExecution(...)) without real Authorizer/CapChecker/AuditSink should panic")
		}
	}()
	New(reg, WithExecution(jobsRepo, tasksRepo, conduit))
}

// TestWithExecutionAcceptsRealSeams: with real (spy) Authorizer, CapChecker,
// and AuditSink supplied, New constructs successfully and Run drives the
// engine end to end.
func TestWithExecutionAcceptsRealSeams(t *testing.T) {
	jobsRepo, tasksRepo := testEngineStore(t)
	conduit := newFakeConduit(nil)
	conduit.connected["node-1"] = true
	conduit.results["node-1"] = jobs.Result{Outcome: jobs.OutcomeSuccess}

	reg := registry.NewInMemory()
	if _, err := reg.Upsert(registry.Report{NodeID: "node-1"}.WithNodeLabels(map[string]string{"role": "web"})); err != nil {
		t.Fatalf("Upsert: %v", err)
	}

	authz := &spyAuthorizer{}
	capChecker := &spyCapChecker{}
	audit := &spyAuditSink{}
	freezeStore := &fakeFreezeStore{}

	svc := New(reg,
		WithAuthorizer(authz),
		WithCapChecker(capChecker),
		WithAuditSink(audit),
		WithFreeze(freezeStore),
		WithExecution(jobsRepo, tasksRepo, conduit, WithExecNewID(sequentialIDs("id-"))),
	)

	sel := Selector{Predicates: []Predicate{{Namespace: NamespaceNode, Key: "role", Value: "web"}}}
	act := jobs.Action{Kind: jobs.ActionOperation, OperationName: "system.facts", RiskClass: jobs.RiskClassRead}
	results, err := svc.Run(context.Background(), Principal{Account: "alice"}, sel, act)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(results) != 1 || results[0].NodeID != "node-1" || results[0].Outcome != jobs.OutcomeSuccess {
		t.Errorf("results = %+v, want [{node-1 OutcomeSuccess}]", results)
	}
	if !authz.called || !capChecker.called || !audit.called {
		t.Errorf("expected the real seams to be called: authz=%v cap=%v audit=%v", authz.called, capChecker.called, audit.called)
	}
}

// TestWithExecutionRefusesWithoutFreeze is New's fail-open guard extended
// for FreezeStore (amendment D): wiring a real dispatcher via WithExecution
// with real Authorizer/CapChecker/AuditSink but WITHOUT a real FreezeStore
// must still panic — a real executor riding the noopFreezeStore default is
// un-stoppable, exactly the composition-root wiring bug the guard exists to
// catch.
func TestWithExecutionRefusesWithoutFreeze(t *testing.T) {
	jobsRepo, tasksRepo := testEngineStore(t)
	conduit := newFakeConduit(nil)
	reg := registry.NewInMemory()

	defer func() {
		if recover() == nil {
			t.Fatal("New(reg, WithExecution(...)) with real Authorizer/CapChecker/AuditSink but no WithFreeze should panic")
		}
	}()
	New(reg,
		WithAuthorizer(&spyAuthorizer{}),
		WithCapChecker(&spyCapChecker{}),
		WithAuditSink(&spyAuditSink{}),
		WithExecution(jobsRepo, tasksRepo, conduit),
	)
}

// TestCapabilityImportsOnlyRegistryAndJobs is an import-boundary AST guard
// (mirrors jobs.TestNoDatabaseSQLImport and dispatch_construction_test.go's
// parse-and-inspect style): package capability's non-test files may only
// import a small stdlib allowlist plus internal/registry and internal/jobs
// — never internal/relay/v1 (the wire proto) or database/sql. #99 is
// exactly the issue that tempts a real-Conduit author to reach for
// relayv1.TaskRequest/TaskResult inside capability; this fails the build
// if they do (ADR-0009/0010, invariant 10).
func TestCapabilityImportsOnlyRegistryAndJobs(t *testing.T) {
	allowed := map[string]bool{
		"context":      true,
		"crypto/rand":  true,
		"encoding/hex": true,
		"errors":       true,
		"fmt":          true,
		// log/slog joined with #614: authorizeMachineCancel logs a job-query
		// failure it must not fold into the caller-facing refusal reason,
		// the same operational-detail-stays-server-side posture auditsink's
		// own logging already keeps. Stdlib, no proto, no database/sql — the
		// same admission bar every other entry here clears.
		"log/slog": true,
		// sort joined with #539: RecordEventSubscription canonicalises its
		// caller-supplied kind list (sort + dedup) before it is bounded and
		// recorded, so a subscription's read record is grouped by shape
		// rather than by the order a query string happened to list kinds
		// in. Stdlib, no proto, no database/sql — the same admission bar
		// every other entry here clears.
		"sort":    true,
		"strings": true,
		"time":    true,
		"github.com/Felag-Engineering/gleipnir-relay/relay/internal/jobs":     true,
		"github.com/Felag-Engineering/gleipnir-relay/relay/internal/registry": true,
		// internal/approval joined the allowlist with #269 (ADR-0027). It is
		// admitted on exactly the terms jobs and registry are: a domain package
		// with no proto dependency and no database/sql, guarded by its own
		// import test (approval.TestApprovalImportsStayNarrow) so widening this
		// list does not create a transitive back door into the wire types.
		"github.com/Felag-Engineering/gleipnir-relay/relay/internal/approval": true,
		// internal/mcptask joined with #374 (ADR-0028), on exactly the same
		// terms: a domain package with no proto, no database/sql, and — its own
		// guard adds this one — no MCP SDK, so admitting it here cannot become
		// a transitive route to either the wire types or the SDK.
		"github.com/Felag-Engineering/gleipnir-relay/relay/internal/mcptask": true,
		// nodestate joined with #414 (ADR-0034): the `state:` label derivation
		// over one registry.Node. Proto-free, SQL-free, and it imports only
		// time and registry (see nodestate's own package doc for why it never
		// imports internal/ca), so admitting it opens no transitive back door
		// — and it is admitted precisely so `state:` has exactly one
		// definition, shared by Selector.Matches and every rendering surface.
		"github.com/Felag-Engineering/gleipnir-relay/relay/internal/nodestate": true,
		// internal/accounts joined with #653, on the same terms approval,
		// mcptask, and nodestate were admitted: a domain package with no
		// proto, no database/sql, no HTTP, guarded by its own import test
		// (accounts.TestAccountsImportsStayNarrow). Admitted so the Account/
		// role vocabulary (accounts.Account, Role, APIToken, Plaintext) has
		// exactly ONE definition — accountadmin.go's AccountStore/
		// APITokenStore would otherwise need to mirror it, the way this
		// package already mirrors approval.Answer and audit.Kind* for
		// packages it may not import — and a mirrored copy is a copy that can
		// disagree with the vocabulary it describes. `go list` confirms
		// accounts' direct imports are exactly its own import test's
		// allowlist, with zero internal/* and no cycle — its transitive
		// imports (crypto/*, encoding/*, golang.org/x/crypto/argon2, ...) are
		// not this package's direct imports and so do not need entries here.
		"github.com/Felag-Engineering/gleipnir-relay/relay/internal/accounts": true,
	}
	forbidden := map[string]bool{
		"github.com/Felag-Engineering/gleipnir-relay/relay/internal/relay/v1": true,
		"database/sql": true,
	}

	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	dir := filepath.Dir(thisFile)

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("os.ReadDir(%s): %v", dir, err)
	}

	fset := token.NewFileSet()
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		path := filepath.Join(dir, name)
		file, err := parser.ParseFile(fset, path, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatalf("parser.ParseFile(%s): %v", path, err)
		}
		for _, imp := range file.Imports {
			importPath, err := strconv.Unquote(imp.Path.Value)
			if err != nil {
				t.Fatalf("unquote import %s in %s: %v", imp.Path.Value, name, err)
			}
			if forbidden[importPath] {
				t.Errorf("%s imports %q — package capability must stay free of the wire proto and raw SQL (ADR-0009/0010 boundary)", name, importPath)
			}
			if !allowed[importPath] {
				t.Errorf("%s imports %q, which is not in the capability package's import allowlist", name, importPath)
			}
		}
	}
}

// spyJobEventSink is a JobEventSink test double: it appends every RecordJob
// call, nothing else.
type spyJobEventSink struct {
	events []JobEvent
}

func (s *spyJobEventSink) RecordJob(e JobEvent) {
	s.events = append(s.events, e)
}

// TestEngine_JobEvents_CreatedThenCompleted is docs/specs/execution.md's acceptance line
// for the event seam's Job publisher (#416): a Job fans out to N Nodes but
// publishes exactly TWO events — JobCreated once, JobCompleted once — never
// one per Task, with JobCompleted's Outcomes matching the real per-Node
// results.
func TestEngine_JobEvents_CreatedThenCompleted(t *testing.T) {
	jobsRepo, tasksRepo := testEngineStore(t)
	conduit := newFakeConduit(nil)

	const nodeCount = 50
	nodes := make([]registry.Node, 0, nodeCount)
	for i := 0; i < nodeCount; i++ {
		id := "node-" + strconv.Itoa(i)
		nodes = append(nodes, testNode(id))
		conduit.connected[id] = true
		conduit.results[id] = jobs.Result{Outcome: jobs.OutcomeSuccess}
	}

	sink := &spyJobEventSink{}
	e := &jobEngine{
		jobsRepo:  jobsRepo,
		tasksRepo: tasksRepo,
		conduit:   conduit,
		newID:     sequentialIDs("id-"),
		now:       func() time.Time { return time.Date(2026, 7, 8, 0, 0, 0, 0, time.UTC) },
		events:    sink,
	}

	principal := Principal{Account: "alice"}
	sel := Selector{}
	act := jobs.Action{Kind: jobs.ActionOperation, OperationName: "system.facts", RiskClass: jobs.RiskClassRead}
	d := newDispatch(principal, sel, nodes, act)

	if _, err := e.run(context.Background(), d); err != nil {
		t.Fatalf("run: %v", err)
	}

	if len(sink.events) != 2 {
		t.Fatalf("got %d JobEvents for a %d-Node Job, want exactly 2 (created, completed), never one per Task: %+v",
			len(sink.events), nodeCount, sink.events)
	}
	created, completed := sink.events[0], sink.events[1]

	if created.Transition != JobCreated || created.Nodes != nodeCount {
		t.Errorf("created event = %+v, want Transition=JobCreated Nodes=%d", created, nodeCount)
	}
	if completed.Transition != JobCompleted {
		t.Errorf("completed event Transition = %v, want JobCompleted", completed.Transition)
	}
	if created.JobID == "" || created.JobID != completed.JobID {
		t.Errorf("created.JobID=%q completed.JobID=%q, want equal and non-empty", created.JobID, completed.JobID)
	}
	if got := completed.Outcomes[jobs.OutcomeSuccess]; got != nodeCount {
		t.Errorf("completed.Outcomes[OutcomeSuccess] = %d, want %d", got, nodeCount)
	}
}

// TestEngine_JobEvents_NeverCarryOutput is the behavioural leak test the
// plan review (S1) asked for: JobEvent has five free-form string fields
// (Account/AccountID/Selector/Operation/RiskClass on events.JobEvent, and
// here capability.JobEvent's own Selector/Action), so a marker planted in a
// dispatched Task's Stdout must never appear anywhere in a published
// JobEvent — only the per-outcome COUNTS may describe what happened.
func TestEngine_JobEvents_NeverCarryOutput(t *testing.T) {
	const marker = "leak-marker-capability-stdout-71c2"
	jobsRepo, tasksRepo := testEngineStore(t)
	conduit := newFakeConduit(nil)
	conduit.connected["node-1"] = true
	conduit.results["node-1"] = jobs.Result{Outcome: jobs.OutcomeSuccess, Stdout: []byte(marker)}

	sink := &spyJobEventSink{}
	e := &jobEngine{
		jobsRepo:  jobsRepo,
		tasksRepo: tasksRepo,
		conduit:   conduit,
		newID:     sequentialIDs("id-"),
		now:       func() time.Time { return time.Date(2026, 7, 8, 0, 0, 0, 0, time.UTC) },
		events:    sink,
	}

	nodes := []registry.Node{testNode("node-1")}
	act := jobs.Action{Kind: jobs.ActionOperation, OperationName: "system.facts", RiskClass: jobs.RiskClassRead}
	d := newDispatch(Principal{Account: "alice"}, Selector{}, nodes, act)

	dr, err := e.run(context.Background(), d)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if len(dr.results) != 1 || !strings.Contains(string(dr.results[0].Stdout), marker) {
		t.Fatal("test setup broken: dispatch result does not even contain the marker")
	}

	for _, ev := range sink.events {
		if strings.Contains(ev.Selector.String(), marker) {
			t.Fatalf("JobEvent leaked the marker via Selector: %+v", ev)
		}
		if strings.Contains(ev.Action.OperationName, marker) {
			t.Fatalf("JobEvent leaked the marker via Action.OperationName: %+v", ev)
		}
		// Outcomes is map[jobs.Outcome]int — an int-keyed count, not a
		// string, so it is structurally incapable of carrying the marker;
		// asserting Outcomes is untouched by run's Stdout/Stderr is
		// TestEngine_JobEvents_CreatedThenCompleted's job (it checks the
		// counts match the real per-Node outcomes).
	}
}

// TestService_CancelJob_PublishesJobCancelled proves Service.CancelJob
// publishes exactly one JobCancelled event, attributed to the calling
// Principal, after the cancel itself succeeds.
func TestService_CancelJob_PublishesJobCancelled(t *testing.T) {
	jobsRepo, tasksRepo := testEngineStore(t)
	ctx := context.Background()
	at := time.Date(2026, 7, 8, 0, 0, 0, 0, time.UTC)

	const jobID = "job-cancel-events"
	if err := jobsRepo.CreateJob(ctx, jobs.Job{ID: jobID, CreatedAt: at}); err != nil {
		t.Fatalf("CreateJob: %v", err)
	}
	if err := jobsRepo.AddStage(ctx, jobs.Stage{ID: "stage-1", JobID: jobID, Index: 0}); err != nil {
		t.Fatalf("AddStage: %v", err)
	}

	e := &jobEngine{jobsRepo: jobsRepo, tasksRepo: tasksRepo, conduit: newFakeConduit(nil), now: func() time.Time { return at }}
	sink := &spyJobEventSink{}
	svc := &Service{disp: e, audit: &spyAuditSink{}, metrics: noopMetricsSink{}, jobEvents: sink, authz: &spyAuthorizer{}}

	principal := Principal{Account: "bob", Role: "operator", Kind: PrincipalKindHuman}
	if err := svc.CancelJob(ctx, principal, jobID); err != nil {
		t.Fatalf("CancelJob: %v", err)
	}

	if len(sink.events) != 1 {
		t.Fatalf("got %d JobEvents, want exactly 1: %+v", len(sink.events), sink.events)
	}
	ev := sink.events[0]
	if ev.Transition != JobCancelled || ev.JobID != jobID || ev.Principal != principal {
		t.Errorf("event = %+v, want Transition=JobCancelled JobID=%q Principal=%+v", ev, jobID, principal)
	}
}

// TestJobEventsAreObservationalOnly asserts a JobEventSink that records
// everything (spyJobEventSink, panic-free) never changes a dispatch's
// returned results or error: with and without the sink wired, both must be
// byte-identical.
func TestJobEventsAreObservationalOnly(t *testing.T) {
	run := func(sink JobEventSink) ([]NodeResult, error) {
		jobsRepo, tasksRepo := testEngineStore(t)
		conduit := newFakeConduit(nil)
		conduit.connected["node-1"] = true
		conduit.results["node-1"] = jobs.Result{Outcome: jobs.OutcomeSuccess, Stdout: []byte("ok")}

		e := &jobEngine{
			jobsRepo:  jobsRepo,
			tasksRepo: tasksRepo,
			conduit:   conduit,
			newID:     sequentialIDs("id-"),
			now:       func() time.Time { return time.Date(2026, 7, 8, 0, 0, 0, 0, time.UTC) },
			events:    sink,
		}
		nodes := []registry.Node{testNode("node-1")}
		act := jobs.Action{Kind: jobs.ActionOperation, OperationName: "system.facts", RiskClass: jobs.RiskClassRead}
		d := newDispatch(Principal{Account: "alice"}, Selector{}, nodes, act)
		dr, err := e.run(context.Background(), d)
		return dr.results, err
	}

	withoutSink, errWithout := run(nil)
	withSink, errWith := run(&spyJobEventSink{})

	if errWithout != nil || errWith != nil {
		t.Fatalf("unexpected errors: without=%v with=%v", errWithout, errWith)
	}
	if len(withoutSink) != len(withSink) {
		t.Fatalf("result count differs: without=%d with=%d", len(withoutSink), len(withSink))
	}
	for i := range withoutSink {
		a, b := withoutSink[i], withSink[i]
		if a.NodeID != b.NodeID || a.Outcome != b.Outcome || string(a.Stdout) != string(b.Stdout) ||
			string(a.Stderr) != string(b.Stderr) || a.Truncated != b.Truncated {
			t.Errorf("result[%d] differs: without=%+v with=%+v", i, a, b)
		}
	}
}
