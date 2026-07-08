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
// It also records every Dispatch call (in order) to a shared log so tests
// can assert dispatch ordering relative to persistence.
type fakeConduit struct {
	connected map[string]bool
	results   map[string]jobs.Result
	errs      map[string]error
	log       *[]string
}

func newFakeConduit(log *[]string) *fakeConduit {
	return &fakeConduit{
		connected: map[string]bool{},
		results:   map[string]jobs.Result{},
		errs:      map[string]error{},
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

	results, err := e.run(context.Background(), d)
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

// TestEngineOfflineNodeUnreachable is the ROADMAP acceptance line: a Job
// spanning an offline Node reports unreachable for it and real results for
// the rest.
func TestEngineOfflineNodeUnreachable(t *testing.T) {
	jobsRepo, tasksRepo := testEngineStore(t)
	conduit := newFakeConduit(nil)
	conduit.connected["node-online"] = true
	conduit.results["node-online"] = jobs.Result{Outcome: jobs.OutcomeSuccess, ExitCode: 0}
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

	results, err := e.run(context.Background(), d)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if len(results) != 2 {
		t.Fatalf("run() returned %d results, want 2", len(results))
	}
	if results[0].NodeID != "node-online" || results[0].Outcome != jobs.OutcomeSuccess {
		t.Errorf("results[0] = %+v, want node-online/OutcomeSuccess", results[0])
	}
	if results[1].NodeID != "node-offline" || results[1].Outcome != jobs.OutcomeUnreachable {
		t.Errorf("results[1] = %+v, want node-offline/OutcomeUnreachable", results[1])
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

	results, err := e.run(context.Background(), d)
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

	results, err := e.run(context.Background(), d)
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
	if _, err := reg.Upsert(registry.Report{NodeID: "node-1", NodeLabels: map[string]string{"role": "web"}}); err != nil {
		t.Fatalf("Upsert: %v", err)
	}

	authz := &spyAuthorizer{}
	capChecker := &spyCapChecker{}
	audit := &spyAuditSink{}

	svc := New(reg,
		WithAuthorizer(authz),
		WithCapChecker(capChecker),
		WithAuditSink(audit),
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

// TestCapabilityImportsOnlyRegistryAndJobs is an import-boundary AST guard
// (mirrors jobs.TestNoDatabaseSQLImport and dispatch_construction_test.go's
// parse-and-inspect style): package capability's non-test files may only
// import a small stdlib allowlist plus internal/registry and internal/jobs
// — never internal/gleipnir/v1 (the wire proto) or database/sql. #99 is
// exactly the issue that tempts a real-Conduit author to reach for
// gleipnirv1.TaskRequest/TaskResult inside capability; this fails the build
// if they do (ADR-0009/0010, ROADMAP invariant 10).
func TestCapabilityImportsOnlyRegistryAndJobs(t *testing.T) {
	allowed := map[string]bool{
		"context":      true,
		"crypto/rand":  true,
		"encoding/hex": true,
		"errors":       true,
		"fmt":          true,
		"strings":      true,
		"time":         true,
		"github.com/Felag-Engineering/gleipnir-relay/relay/internal/jobs":     true,
		"github.com/Felag-Engineering/gleipnir-relay/relay/internal/registry": true,
	}
	forbidden := map[string]bool{
		"github.com/Felag-Engineering/gleipnir-relay/relay/internal/gleipnir/v1": true,
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
