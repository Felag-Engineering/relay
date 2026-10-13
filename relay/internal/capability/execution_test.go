package capability

import (
	"context"
	"errors"
	"fmt"
	"go/parser"
	"go/token"
	"math/rand/v2"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/jobs"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/logctx"
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

	// mu guards log and the maps' reads: dispatchOne runs on worker goroutines.
	mu sync.Mutex
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

func (f *fakeConduit) Connected(nodeID string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.connected[nodeID]
}

func (f *fakeConduit) Dispatch(_ context.Context, nodeID string, _ jobs.Task) (jobs.Result, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
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
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.log != nil {
		*f.log = append(*f.log, "cancel:"+nodeID+":"+taskID)
	}
	return f.cancelErr[nodeID]
}

// Query records "query:<nodeID>" to the shared log and returns the canned
// jobs.Verdict/error for nodeID (#119), mirroring Dispatch's shape.
func (f *fakeConduit) Query(_ context.Context, nodeID string, _ jobs.Action) (jobs.Verdict, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
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

// CreateTask runs only in run's sequential persist phase, before any dispatch
// goroutine starts, so the unsynchronised log append is ordered by g.Go.
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
		intents:   &nonAtomicIntents{tr: &recordingTasks{TaskRepository: tasksRepo, log: &log}},
		conduit:   conduit,
		newID:     sequentialIDs("id-"),
		now:       func() time.Time { return time.Date(2026, 7, 8, 0, 0, 0, 0, time.UTC) },
		// Concurrent dispatch, so "all creates precede the first dispatch" is
		// proven under the fan-out and not under the sequential fallback.
		concurrency: 16,
	}

	nodes := []registry.Node{testNode("node-1"), testNode("node-2"), testNode("node-3")}
	act := jobs.Action{Kind: jobs.ActionOperation, OperationName: "system.facts"}
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

// TestJobEngine_RunUsesTheReservedJobID is AP-77's dispatch-side contract
// (#713): a dispatch carrying a jobID already reserved (and bound to a
// releasing approval) uses that SAME id, rather than minting a fresh one —
// the join a re-attach depends on. A dispatch with no reserved id still
// mints its own, exactly as before this issue.
func TestJobEngine_RunUsesTheReservedJobID(t *testing.T) {
	jobsRepo, tasksRepo := testEngineStore(t)
	conduit := newFakeConduit(nil)
	conduit.connected["node-1"] = true
	conduit.connected["node-2"] = true
	conduit.results["node-1"] = jobs.Result{Outcome: jobs.OutcomeSuccess}
	conduit.results["node-2"] = jobs.Result{Outcome: jobs.OutcomeSuccess}

	e := &jobEngine{
		jobsRepo:  jobsRepo,
		tasksRepo: tasksRepo,
		intents:   &nonAtomicIntents{tr: tasksRepo},
		conduit:   conduit,
		newID:     sequentialIDs("id-"),
		now:       func() time.Time { return time.Date(2026, 7, 8, 0, 0, 0, 0, time.UTC) },
	}

	nodes := []registry.Node{testNode("node-1"), testNode("node-2")}
	act := jobs.Action{Kind: jobs.ActionOperation, OperationName: "system.facts"}
	d := newDispatch(Principal{Account: "alice"}, Selector{}, nodes, act)
	d.jobID = "job-reserved"

	dr, err := e.run(context.Background(), d)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if dr.jobID != "job-reserved" {
		t.Fatalf("dispatchResult.jobID = %q, want the reserved job-reserved", dr.jobID)
	}
	if _, err := jobsRepo.GetJob(context.Background(), "job-reserved"); err != nil {
		t.Fatalf("GetJob(job-reserved): %v — the reserved id must be the Job actually created", err)
	}
	if _, err := jobsRepo.GetJob(context.Background(), "job-id-1"); err == nil {
		t.Fatal("a freshly minted job-id-1 also exists — run must not mint an id when one was reserved")
	}

	tasks, err := tasksRepo.ByJob(context.Background(), "job-reserved")
	if err != nil {
		t.Fatalf("ByJob(job-reserved): %v", err)
	}
	if len(tasks) != 2 {
		t.Fatalf("ByJob(job-reserved) returned %d Tasks, want 2", len(tasks))
	}
	for _, task := range tasks {
		if task.JobID != "job-reserved" {
			t.Errorf("Task %q JobID = %q, want job-reserved", task.ID, task.JobID)
		}
	}
	for _, r := range dr.results {
		if r.JobID != "job-reserved" {
			t.Errorf("result %+v: JobID = %q, want job-reserved", r, r.JobID)
		}
	}

	// A dispatch with NO reserved id still mints its own, unchanged.
	d2 := newDispatch(Principal{Account: "alice"}, Selector{}, []registry.Node{testNode("node-1")}, act)
	dr2, err := e.run(context.Background(), d2)
	if err != nil {
		t.Fatalf("run (unreserved): %v", err)
	}
	if dr2.jobID == "" || dr2.jobID == "job-reserved" {
		t.Errorf("dispatchResult.jobID = %q, want a freshly minted, different id", dr2.jobID)
	}
}

// cancelAfterCreateJobRepo wraps a jobs.JobRepository and cancels a
// caller-supplied context.CancelFunc the instant CreateJob RETURNS,
// mirroring a client per-call timeout (or a dropped connection) firing in the
// narrow window right after the Job row commits — the moment Codex's #713
// "final diff" review (CX-1) found unprotected: AddStage, every CreateTask,
// and dispatch all ran AFTER this point, still on the caller's own ctx.
// Every other method is promoted straight through the embedded interface.
type cancelAfterCreateJobRepo struct {
	jobs.JobRepository
	cancel context.CancelFunc
}

func (w *cancelAfterCreateJobRepo) CreateJob(ctx context.Context, j jobs.Job) error {
	err := w.JobRepository.CreateJob(ctx, j)
	w.cancel()
	return err
}

// TestJobEngine_ReservedRunSurvivesRequestCancellationAfterCreateJob is CX-1
// (#713 Codex "final diff" review): the release claim for a RESERVED Job ID
// already committed before run was ever called, and there is no un-claim
// path (store/approvals.go). An earlier fix pass only detached CreateJob
// itself from the request ctx's cancellation, leaving AddStage, every
// CreateTask, and dispatch resuming on a ctx the caller could cancel the
// instant CreateJob returned — stranding the approval on a Job with no
// Stage/Tasks that every re-drive would re-attach to without the approved
// work ever running. Cancelling the request ctx here fires at exactly that
// point, and the WHOLE rest of run must still complete: the Job gets its
// Stage, its Task, and a real dispatched-and-resolved result — nothing
// downstream of CreateJob may see a cancelled ctx for a reserved id.
func TestJobEngine_ReservedRunSurvivesRequestCancellationAfterCreateJob(t *testing.T) {
	jobsRepo, tasksRepo := testEngineStore(t)
	conduit := newFakeConduit(nil)
	conduit.connected["node-1"] = true
	conduit.results["node-1"] = jobs.Result{Outcome: jobs.OutcomeSuccess}

	ctx, cancel := context.WithCancel(context.Background())
	e := &jobEngine{
		jobsRepo:  &cancelAfterCreateJobRepo{JobRepository: jobsRepo, cancel: cancel},
		tasksRepo: tasksRepo,
		intents:   &nonAtomicIntents{tr: tasksRepo},
		conduit:   conduit,
		newID:     sequentialIDs("id-"),
		now:       func() time.Time { return time.Date(2026, 7, 8, 0, 0, 0, 0, time.UTC) },
	}

	nodes := []registry.Node{testNode("node-1")}
	act := jobs.Action{Kind: jobs.ActionOperation, OperationName: "system.facts"}
	d := newDispatch(Principal{Account: "alice"}, Selector{}, nodes, act)
	d.jobID = "job-reserved" // approval-claimed (AP-77): the claim already committed.

	dr, err := e.run(ctx, d)
	if err != nil {
		t.Fatalf("run: %v — a cancellation landing right after CreateJob must not abandon the rest of the reserved run", err)
	}
	if dr.jobID != "job-reserved" {
		t.Fatalf("dispatchResult.jobID = %q, want job-reserved", dr.jobID)
	}

	job, err := jobsRepo.GetJob(context.Background(), "job-reserved")
	if err != nil {
		t.Fatalf("GetJob(job-reserved): %v — the reserved Job must exist", err)
	}
	stages, err := jobsRepo.Stages(context.Background(), job.ID)
	if err != nil {
		t.Fatalf("Stages(job-reserved): %v", err)
	}
	if len(stages) != 1 {
		t.Fatalf("Stages(job-reserved) = %d, want 1 — a re-drive must not re-attach to a Job with no Stage", len(stages))
	}

	tasks, err := tasksRepo.ByJob(context.Background(), "job-reserved")
	if err != nil {
		t.Fatalf("ByJob(job-reserved): %v", err)
	}
	if len(tasks) != 1 {
		t.Fatalf("ByJob(job-reserved) = %d, want 1 — a re-drive must not re-attach to a Job with no Task", len(tasks))
	}
	if tasks[0].State != jobs.DispatchStateResolved || tasks[0].Outcome != jobs.OutcomeSuccess {
		t.Fatalf("task state/outcome = %v/%v, want Resolved/Success — the approved work must actually run to completion, not stall mid-dispatch", tasks[0].State, tasks[0].Outcome)
	}
}

// TestEngineRecordsRequesterOnJob (#616, AC1) proves the requester is
// written in the SAME CreateJob call that creates the Job: after run
// returns, GetJob echoes the acting Principal's AccountID, name and Kind.
func TestEngineRecordsRequesterOnJob(t *testing.T) {
	jobsRepo, tasksRepo := testEngineStore(t)
	conduit := newFakeConduit(nil)
	conduit.connected["node-1"] = true
	conduit.results["node-1"] = jobs.Result{Outcome: jobs.OutcomeSuccess}

	e := &jobEngine{
		jobsRepo:  jobsRepo,
		tasksRepo: tasksRepo,
		intents:   &nonAtomicIntents{tr: tasksRepo},
		conduit:   conduit,
		newID:     sequentialIDs("id-"),
		now:       func() time.Time { return time.Date(2026, 7, 8, 0, 0, 0, 0, time.UTC) },
	}

	p := Principal{AccountID: "acct-1", Account: "gleipnir", Kind: "machine"}
	act := jobs.Action{Kind: jobs.ActionOperation, OperationName: "system.facts"}
	d := newDispatch(p, Selector{}, []registry.Node{testNode("node-1")}, act)

	dr, err := e.run(context.Background(), d)
	if err != nil {
		t.Fatalf("run: %v", err)
	}

	job, err := jobsRepo.GetJob(context.Background(), dr.jobID)
	if err != nil {
		t.Fatalf("GetJob(%s): %v", dr.jobID, err)
	}
	want := jobs.Requester{AccountID: "acct-1", AccountName: "gleipnir", Kind: "machine"}
	if job.Requester != want {
		t.Errorf("Requester = %+v, want %+v", job.Requester, want)
	}
}

// TestEngineRecordsNoRequesterWithoutAnAccountID (#616) proves a Principal
// with no AccountID (a fixture, the dev harness) records NO requester — not
// a name-only one, which could be mistaken for a verified owner.
func TestEngineRecordsNoRequesterWithoutAnAccountID(t *testing.T) {
	jobsRepo, tasksRepo := testEngineStore(t)
	conduit := newFakeConduit(nil)
	conduit.connected["node-1"] = true
	conduit.results["node-1"] = jobs.Result{Outcome: jobs.OutcomeSuccess}

	e := &jobEngine{
		jobsRepo:  jobsRepo,
		tasksRepo: tasksRepo,
		intents:   &nonAtomicIntents{tr: tasksRepo},
		conduit:   conduit,
		newID:     sequentialIDs("id-"),
		now:       func() time.Time { return time.Date(2026, 7, 8, 0, 0, 0, 0, time.UTC) },
	}

	p := Principal{Account: "devharness"}
	act := jobs.Action{Kind: jobs.ActionOperation, OperationName: "system.facts"}
	d := newDispatch(p, Selector{}, []registry.Node{testNode("node-1")}, act)

	dr, err := e.run(context.Background(), d)
	if err != nil {
		t.Fatalf("run: %v", err)
	}

	job, err := jobsRepo.GetJob(context.Background(), dr.jobID)
	if err != nil {
		t.Fatalf("GetJob(%s): %v", dr.jobID, err)
	}
	if job.Requester != (jobs.Requester{}) {
		t.Errorf("Requester = %+v, want the zero value (no AccountID)", job.Requester)
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
		intents:   &nonAtomicIntents{tr: tasksRepo},
		conduit:   conduit,
		newID:     sequentialIDs("id-"),
		now:       func() time.Time { return time.Date(2026, 7, 8, 0, 0, 0, 0, time.UTC) },
	}

	nodes := []registry.Node{testNode("node-online"), testNode("node-offline")}
	act := jobs.Action{Kind: jobs.ActionOperation, OperationName: "system.facts"}
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
		intents:   &nonAtomicIntents{tr: tasksRepo},
		conduit:   conduit,
		newID:     sequentialIDs("id-"),
		now:       func() time.Time { return time.Date(2026, 7, 8, 0, 0, 0, 0, time.UTC) },
	}

	nodes := []registry.Node{testNode("node-ok"), testNode("node-denied"), testNode("node-offline")}
	act := jobs.Action{Kind: jobs.ActionRawExec, RawExecArgv: []string{"/bin/true"}}
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
		intents:   &nonAtomicIntents{tr: tasksRepo},
		conduit:   conduit,
		newID:     sequentialIDs("id-"),
		now:       func() time.Time { return time.Date(2026, 7, 8, 0, 0, 0, 0, time.UTC) },
	}

	nodes := []registry.Node{testNode("node-flaky")}
	act := jobs.Action{Kind: jobs.ActionOperation, OperationName: "system.facts"}
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

// panicConduit panics in Dispatch for dispatchPanic and in Connected for
// connectedPanic (#942), and behaves as the embedded fakeConduit otherwise.
type panicConduit struct {
	*fakeConduit
	dispatchPanic  string
	connectedPanic string
}

func (p *panicConduit) Connected(nodeID string) bool {
	if nodeID == p.connectedPanic {
		panic("secret-bearing connected panic")
	}
	return p.fakeConduit.Connected(nodeID)
}

func (p *panicConduit) Dispatch(ctx context.Context, nodeID string, task jobs.Task) (jobs.Result, error) {
	if nodeID == p.dispatchPanic {
		panic("secret-bearing dispatch panic")
	}
	return p.fakeConduit.Dispatch(ctx, nodeID, task)
}

func panicTestEngine(jobsRepo jobs.JobRepository, tasksRepo jobs.TaskRepository, c Conduit) *jobEngine {
	return &jobEngine{
		jobsRepo:    jobsRepo,
		tasksRepo:   tasksRepo,
		intents:     &nonAtomicIntents{tr: tasksRepo},
		conduit:     c,
		newID:       sequentialIDs("id-"),
		now:         func() time.Time { return time.Date(2026, 7, 8, 0, 0, 0, 0, time.UTC) },
		concurrency: 2,
	}
}

// TestJobEngine_DispatchPanicFailsOnlyThatTask: a panic in one dispatch worker
// (#942) is that Task's failure — the process survives, the siblings finish,
// and the panic value stays out of the returned error. The panicking Task is
// left Dispatched, like a Conduit error, so reconciliation finds it and it is
// never retried (invariant 4).
func TestJobEngine_DispatchPanicFailsOnlyThatTask(t *testing.T) {
	for _, panicNode := range []string{"node-a", "node-b", "node-c"} {
		t.Run(panicNode, func(t *testing.T) {
			jobsRepo, tasksRepo := testEngineStore(t)
			fc := newFakeConduit(nil)
			for _, n := range []string{"node-a", "node-b", "node-c"} {
				fc.connected[n] = true
				fc.results[n] = jobs.Result{Outcome: jobs.OutcomeSuccess}
			}
			e := panicTestEngine(jobsRepo, tasksRepo, &panicConduit{fakeConduit: fc, dispatchPanic: panicNode})

			nodes := []registry.Node{testNode("node-a"), testNode("node-b"), testNode("node-c")}
			act := jobs.Action{Kind: jobs.ActionOperation, OperationName: "system.facts"}
			dr, err := e.run(context.Background(), newDispatch(Principal{Account: "alice"}, Selector{}, nodes, act))
			if !errors.Is(err, errDispatchPanicked) {
				t.Fatalf("run() error = %v, want it to wrap errDispatchPanicked", err)
			}
			if strings.Contains(err.Error(), "secret-bearing") {
				t.Errorf("run() error %q leaks the panic value", err)
			}
			if len(dr.results) != 3 {
				t.Fatalf("results = %+v, want 3", dr.results)
			}
			for _, r := range dr.results {
				want := jobs.OutcomeSuccess
				if r.NodeID == panicNode {
					want = jobs.OutcomeFailure
				}
				if r.Outcome != want {
					t.Errorf("result[%s].Outcome = %v, want %v", r.NodeID, r.Outcome, want)
				}
				if r.JobID != dr.jobID {
					t.Errorf("result[%s].JobID = %q, want %q", r.NodeID, r.JobID, dr.jobID)
				}
			}

			ctx := context.Background()
			tasks, err := tasksRepo.ByJob(ctx, dr.jobID)
			if err != nil {
				t.Fatalf("ByJob: %v", err)
			}
			for _, task := range tasks {
				want := jobs.DispatchStateResolved
				if task.NodeID == panicNode {
					want = jobs.DispatchStateDispatched
				}
				if task.State != want {
					t.Errorf("Task[%s] state = %v, want %v", task.NodeID, task.State, want)
				}
			}
			inFlight, err := tasksRepo.InFlight(ctx)
			if err != nil {
				t.Fatalf("InFlight: %v", err)
			}
			if len(inFlight) != 1 || inFlight[0].NodeID != panicNode {
				t.Errorf("InFlight = %v, want only the panicking node's Task", inFlight)
			}
		})
	}
}

// TestJobEngine_DispatchPanicBeforeMarkDispatchedIsNeverSent: a panic before
// the Task got past MarkDispatched leaves it Pending and unsent. Nothing
// revisits a Pending Task, so it is not a recorded outcome — only proof that
// the Task is never sent after a panic it never got past.
func TestJobEngine_DispatchPanicBeforeMarkDispatchedIsNeverSent(t *testing.T) {
	jobsRepo, tasksRepo := testEngineStore(t)
	var log []string
	fc := newFakeConduit(&log)
	for _, n := range []string{"node-a", "node-b"} {
		fc.connected[n] = true
		fc.results[n] = jobs.Result{Outcome: jobs.OutcomeSuccess}
	}
	e := panicTestEngine(jobsRepo, tasksRepo, &panicConduit{fakeConduit: fc, connectedPanic: "node-a"})

	nodes := []registry.Node{testNode("node-a"), testNode("node-b")}
	act := jobs.Action{Kind: jobs.ActionOperation, OperationName: "system.facts"}
	dr, err := e.run(context.Background(), newDispatch(Principal{Account: "alice"}, Selector{}, nodes, act))
	if !errors.Is(err, errDispatchPanicked) {
		t.Fatalf("run() error = %v, want it to wrap errDispatchPanicked", err)
	}
	for _, r := range dr.results {
		want := jobs.OutcomeSuccess
		if r.NodeID == "node-a" {
			want = jobs.OutcomeFailure
		}
		if r.Outcome != want {
			t.Errorf("result[%s].Outcome = %v, want %v", r.NodeID, r.Outcome, want)
		}
	}
	if len(log) != 1 || log[0] != "dispatch:node-b" {
		t.Errorf("dispatch log = %v, want only [dispatch:node-b]", log)
	}
	tasks, err := tasksRepo.ByJob(context.Background(), dr.jobID)
	if err != nil {
		t.Fatalf("ByJob: %v", err)
	}
	for _, task := range tasks {
		if task.NodeID == "node-a" && task.State != jobs.DispatchStatePending {
			t.Errorf("Task[node-a] state = %v, want DispatchStatePending", task.State)
		}
		if task.NodeID == "node-b" && task.State != jobs.DispatchStateResolved {
			t.Errorf("Task[node-b] state = %v, want DispatchStateResolved", task.State)
		}
	}
	inFlight, err := tasksRepo.InFlight(context.Background())
	if err != nil {
		t.Fatalf("InFlight: %v", err)
	}
	if len(inFlight) != 0 {
		t.Errorf("InFlight = %v, want none", inFlight)
	}
}

// TestServiceRunDispatchPanicReachesAuditAndResults: through Execution.Run, the
// panicking Node's OutcomeFailure is in the returned results and in the
// KindDispatch audit record — the durable record of the failure (#942).
func TestServiceRunDispatchPanicReachesAuditAndResults(t *testing.T) {
	path := filepath.Join(t.TempDir(), "relay.db")
	st, err := store.Open(path)
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { st.Close() }) //nolint:errcheck
	reg := st.Registry()
	fc := newFakeConduit(nil)
	for _, n := range []string{"node-a", "node-b"} {
		if _, err := reg.Upsert(registry.Report{NodeID: n}); err != nil {
			t.Fatalf("Upsert %s: %v", n, err)
		}
		fc.connected[n] = true
		fc.results[n] = jobs.Result{Outcome: jobs.OutcomeSuccess}
	}
	audit := &spyAuditSink{}
	svc := build(t, seams{reg: reg,
		authz:    &spyAuthorizer{},
		cap:      &spyCapChecker{},
		audit:    audit,
		freeze:   &fakeFreezeStore{},
		jobsRepo: st.Jobs(), tasksRepo: st.Tasks(), conduit: &panicConduit{fakeConduit: fc, dispatchPanic: "node-a"},
	})

	act := jobs.Action{Kind: jobs.ActionOperation, OperationName: "system.facts"}
	results, err := svc.Run(context.Background(), Principal{Account: "alice"}, Selector{}, act)
	if !errors.Is(err, errDispatchPanicked) {
		t.Fatalf("Run() error = %v, want it to wrap errDispatchPanicked", err)
	}
	if audit.entry.Kind != AuditKindDispatch {
		t.Fatalf("audit entry Kind = %v, want AuditKindDispatch", audit.entry.Kind)
	}
	for name, rs := range map[string][]NodeResult{"returned": results, "audit": audit.entry.Results} {
		got := map[string]jobs.Outcome{}
		for _, r := range rs {
			got[r.NodeID] = r.Outcome
		}
		if got["node-a"] != jobs.OutcomeFailure || got["node-b"] != jobs.OutcomeSuccess {
			t.Errorf("%s results = %v, want node-a failure and node-b success", name, got)
		}
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

	res, err := e.dispatchOne(ctx, nil, pendingTask{task: task})
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

// TestEngineDispatchOneUnsupportedTaskCancelledFirstReportsCancelled: an
// excluded Task that a concurrent cancel resolved before MarkUnsupported ran
// reports the truthful Cancelled, not the wrapped ErrInvalidTaskState.
func TestEngineDispatchOneUnsupportedTaskCancelledFirstReportsCancelled(t *testing.T) {
	jobsRepo, tasksRepo := testEngineStore(t)
	now := time.Date(2026, 7, 8, 0, 0, 0, 0, time.UTC)
	e := &jobEngine{tasksRepo: tasksRepo, now: func() time.Time { return now }}

	ctx := context.Background()
	if err := jobsRepo.CreateJob(ctx, jobs.Job{ID: "job-1", CreatedAt: now}); err != nil {
		t.Fatalf("CreateJob: %v", err)
	}
	if err := jobsRepo.AddStage(ctx, jobs.Stage{ID: "stage-1", JobID: "job-1", Index: 0}); err != nil {
		t.Fatalf("AddStage: %v", err)
	}
	task := jobs.Task{
		ID: "task-1", JobID: "job-1", StageID: "stage-1", NodeID: "node-1",
		Action:    jobs.Action{Kind: jobs.ActionOperation, OperationName: "system.facts", RiskClass: jobs.RiskClassRead},
		CreatedAt: now,
	}
	if err := tasksRepo.CreateTask(ctx, task); err != nil {
		t.Fatalf("CreateTask: %v", err)
	}
	if err := tasksRepo.MarkCancelled(ctx, task.ID, now); err != nil {
		t.Fatalf("MarkCancelled: %v", err)
	}

	res, err := e.dispatchOne(ctx, nil, pendingTask{task: task, unsupported: "no such template"})
	if err != nil {
		t.Fatalf("dispatchOne: %v", err)
	}
	if res.Outcome != jobs.OutcomeCancelled {
		t.Errorf("Outcome = %v, want OutcomeCancelled", res.Outcome)
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

	svc := build(t, seams{reg: reg,
		authz:    authz,
		cap:      capChecker,
		audit:    audit,
		freeze:   freezeStore,
		jobsRepo: st.Jobs(), tasksRepo: st.Tasks(), conduit: conduit,
	})

	sel := Selector{} // Selector{} matches every Node (see selector.go)
	act := jobs.Action{Kind: jobs.ActionOperation, OperationName: "system.facts"}
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

// TestNewExecutionRefusesDefaultSeams is the NewExecution fail-open guard:
// building the real dispatcher over the allow-all/no-op default seams, instead
// of a real Authorizer/CapChecker/AuditSink, must panic.
func TestNewExecutionRefusesDefaultSeams(t *testing.T) {
	jobsRepo, tasksRepo := testEngineStore(t)
	conduit := newFakeConduit(nil)
	reg := registry.NewInMemory()
	rec := NewRecorder(noopAuditSink{}, nil, nil)
	ctl := newControl(rec, allowAllAuthorizer{}, noopFreezeStore{})
	read := newReadLane(rec, reg, nil, nil, nil, nil, 0, nil)
	appr := newApprovals(rec, noopApprovalGate{}, nil, nil, nil, nil, noopApprovalNotifier{}, nil)

	defer func() {
		if recover() == nil {
			t.Fatal("NewExecution over the allow-all/no-op default seams should panic")
		}
	}()
	NewExecution(ctl, read, appr, noopCapChecker{}, nil, jobsRepo, tasksRepo, conduit, DefaultDispatchConcurrency, nil, nil)
}

// TestNewExecutionAcceptsRealSeams: with real (spy) Authorizer, CapChecker,
// and AuditSink supplied, NewExecution constructs successfully and Run drives
// the engine end to end.
func TestNewExecutionAcceptsRealSeams(t *testing.T) {
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

	rec := NewRecorder(&intentSpySink{audit, &nonAtomicIntents{tr: tasksRepo}}, nil, nil)
	svc := NewExecution(NewControl(rec, authz, freezeStore),
		newReadLane(rec, reg, nil, nil, nil, nil, 0, nil),
		newApprovals(rec, noopApprovalGate{}, nil, nil, nil, nil, noopApprovalNotifier{}, nil),
		capChecker, nil, jobsRepo, tasksRepo, conduit, DefaultDispatchConcurrency, sequentialIDs("id-"), nil,
	)

	sel := Selector{Predicates: []Predicate{{Namespace: NamespaceNode, Key: "role", Value: "web"}}}
	act := jobs.Action{Kind: jobs.ActionOperation, OperationName: "system.facts"}
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

// probeAtFirstConnected wraps a Conduit, running probe exactly once — on the
// FIRST call to Connected — then delegating for real. Every Task is persisted
// Pending before any dispatch worker starts and a worker calls Connected before
// MarkDispatched, so the first Connected is the earliest point at which every
// Task is Pending and none has been dispatched — "before any MarkDispatched"
// holds here only because the Job has ONE Node, hence one worker.
type probeAtFirstConnected struct {
	Conduit
	probe  func()
	probed bool
}

func (c *probeAtFirstConnected) Connected(nodeID string) bool {
	if !c.probed {
		c.probed = true
		c.probe()
	}
	return c.Conduit.Connected(nodeID)
}

// TestRun_RequesterIsOnTheJobWhileEveryTaskIsPending (#616, AC4's narrower
// capability-package guard) proves the requester is durable and readable
// through the real store while every Task is still Pending — before
// dispatchOne's first MarkDispatched, and before the audit sink has
// recorded anything. The read-lane counterpart (through ReadLane.QueryJobs
// and CancelJob) lives in internal/auditquery, which can import capability
// without a cycle; this package cannot import auditquery.
func TestRun_RequesterIsOnTheJobWhileEveryTaskIsPending(t *testing.T) {
	path := filepath.Join(t.TempDir(), "relay.db")
	st, err := store.Open(path)
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { st.Close() }) //nolint:errcheck

	inner := newFakeConduit(nil)
	inner.connected["node-1"] = true
	inner.results["node-1"] = jobs.Result{Outcome: jobs.OutcomeSuccess}

	reg := registry.NewInMemory()
	if _, err := reg.Upsert(registry.Report{NodeID: "node-1"}.WithNodeLabels(map[string]string{"role": "web"})); err != nil {
		t.Fatalf("Upsert: %v", err)
	}

	authz := &spyAuthorizer{}
	capChecker := &spyCapChecker{}
	auditSink := &spyAuditSink{}
	freezeStore := &fakeFreezeStore{}

	const jobID = "job-id-1" // sequentialIDs("id-"): job gets the first minted id.
	var probeErrs []string
	conduit := &probeAtFirstConnected{Conduit: inner, probe: func() {
		ctx := context.Background()
		tasks, err := st.Tasks().ByJob(ctx, jobID)
		if err != nil {
			probeErrs = append(probeErrs, fmt.Sprintf("ByJob(%s): %v", jobID, err))
		}
		for _, task := range tasks {
			if task.State != jobs.DispatchStatePending {
				probeErrs = append(probeErrs, fmt.Sprintf("task %s state = %v, want Pending", task.ID, task.State))
			}
		}

		page, err := st.JobQueries().QueryJobs(ctx, jobs.JobQuery{JobID: jobID}, 0, "")
		if err != nil {
			probeErrs = append(probeErrs, fmt.Sprintf("QueryJobs(%s): %v", jobID, err))
		} else if len(page.Jobs) != 1 {
			probeErrs = append(probeErrs, fmt.Sprintf("QueryJobs(%s) returned %d rows, want 1", jobID, len(page.Jobs)))
		} else if got := page.Jobs[0]; got.RequesterAccountID != "acct-1" || got.Requester != "gleipnir" || got.RequesterKind != "machine" {
			probeErrs = append(probeErrs, fmt.Sprintf("requester = %+v, want ID=acct-1 Name=gleipnir Kind=machine", got))
		}

		if auditSink.called {
			probeErrs = append(probeErrs, "the audit sink already recorded the dispatch before every Task left Pending")
		}
	}}

	svc := build(t, seams{reg: reg,
		authz:    authz,
		cap:      capChecker,
		audit:    auditSink,
		freeze:   freezeStore,
		jobsRepo: st.Jobs(), tasksRepo: st.Tasks(), conduit: conduit, newID: sequentialIDs("id-"),
	})

	sel := Selector{Predicates: []Predicate{{Namespace: NamespaceNode, Key: "role", Value: "web"}}}
	act := jobs.Action{Kind: jobs.ActionOperation, OperationName: "system.facts"}
	p := Principal{AccountID: "acct-1", Account: "gleipnir", Kind: "machine", Role: "operator"}
	if _, err := svc.Run(context.Background(), p, sel, act); err != nil {
		t.Fatalf("Run: %v", err)
	}

	if !conduit.probed {
		t.Fatal("probe never ran — Connected was never called")
	}
	for _, msg := range probeErrs {
		t.Error(msg)
	}
}

// TestNewExecutionRefusesWithoutFreeze is NewExecution's fail-open guard
// extended for FreezeStore (amendment D): building the real dispatcher with
// real Authorizer/CapChecker/AuditSink but WITHOUT a real FreezeStore must
// still panic — a real executor riding the noopFreezeStore default is
// un-stoppable, exactly the composition-root wiring bug the guard exists to
// catch.
func TestNewExecutionRefusesWithoutFreeze(t *testing.T) {
	jobsRepo, tasksRepo := testEngineStore(t)
	conduit := newFakeConduit(nil)
	reg := registry.NewInMemory()
	// intentSpySink records an intent, so the freeze check is the only
	// real-dispatcher check left that can fire here.
	rec := NewRecorder(&intentSpySink{&spyAuditSink{}, &nonAtomicIntents{tr: tasksRepo}}, nil, nil)
	ctl := newControl(rec, &spyAuthorizer{}, noopFreezeStore{})
	read := newReadLane(rec, reg, nil, nil, nil, nil, 0, nil)
	appr := newApprovals(rec, noopApprovalGate{}, nil, nil, nil, nil, noopApprovalNotifier{}, nil)

	defer func() {
		if recover() == nil {
			t.Fatal("NewExecution with real Authorizer/CapChecker/AuditSink but a never-frozen FreezeStore should panic")
		}
	}()
	NewExecution(ctl, read, appr, &spyCapChecker{}, nil, jobsRepo, tasksRepo, conduit, DefaultDispatchConcurrency, nil, nil)
}

// TestNewExecution_RefusesEachFailOpenSeam: each fail-open seam, alone, makes
// NewExecution panic naming that seam. Every other seam is real, so only that
// row's check can fire.
func TestNewExecution_RefusesEachFailOpenSeam(t *testing.T) {
	cases := []struct {
		name   string
		marker string
		build  func(t *testing.T, tr jobs.TaskRepository) (*Control, *ReadLane, *Approvals, CapChecker)
	}{
		{"allow-all Authorizer", "allowAllAuthorizer", func(t *testing.T, tr jobs.TaskRepository) (*Control, *ReadLane, *Approvals, CapChecker) {
			rec := NewRecorder(&intentSpySink{&spyAuditSink{}, &nonAtomicIntents{tr: tr}}, nil, nil)
			return newControl(rec, allowAllAuthorizer{}, &fakeFreezeStore{}),
				newReadLane(rec, registry.NewInMemory(), nil, nil, nil, nil, 0, nil),
				newApprovals(rec, noopApprovalGate{}, nil, nil, nil, nil, noopApprovalNotifier{}, nil),
				&spyCapChecker{}
		}},
		{"no-op CapChecker", "noopCapChecker", func(t *testing.T, tr jobs.TaskRepository) (*Control, *ReadLane, *Approvals, CapChecker) {
			rec := NewRecorder(&intentSpySink{&spyAuditSink{}, &nonAtomicIntents{tr: tr}}, nil, nil)
			return newControl(rec, &spyAuthorizer{}, &fakeFreezeStore{}),
				newReadLane(rec, registry.NewInMemory(), nil, nil, nil, nil, 0, nil),
				newApprovals(rec, noopApprovalGate{}, nil, nil, nil, nil, noopApprovalNotifier{}, nil),
				noopCapChecker{}
		}},
		{"no-op AuditSink", "noopAuditSink", func(t *testing.T, tr jobs.TaskRepository) (*Control, *ReadLane, *Approvals, CapChecker) {
			rec := NewRecorder(noopAuditSink{}, nil, nil)
			return newControl(rec, &spyAuthorizer{}, &fakeFreezeStore{}),
				newReadLane(rec, registry.NewInMemory(), nil, nil, nil, nil, 0, nil),
				newApprovals(rec, noopApprovalGate{}, nil, nil, nil, nil, noopApprovalNotifier{}, nil),
				&spyCapChecker{}
		}},
		{"no-op FreezeStore", "noopFreezeStore", func(t *testing.T, tr jobs.TaskRepository) (*Control, *ReadLane, *Approvals, CapChecker) {
			rec := NewRecorder(&intentSpySink{&spyAuditSink{}, &nonAtomicIntents{tr: tr}}, nil, nil)
			return newControl(rec, &spyAuthorizer{}, noopFreezeStore{}),
				newReadLane(rec, registry.NewInMemory(), nil, nil, nil, nil, 0, nil),
				newApprovals(rec, noopApprovalGate{}, nil, nil, nil, nil, noopApprovalNotifier{}, nil),
				&spyCapChecker{}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			jobsRepo, tasksRepo := testEngineStore(t)
			ctl, read, appr, capc := tc.build(t, tasksRepo)
			defer func() {
				r := recover()
				if r == nil {
					t.Fatalf("NewExecution over a %s should panic", tc.name)
				}
				if msg, _ := r.(string); !strings.Contains(msg, tc.marker) {
					t.Errorf("panic = %v, want it to name %s", r, tc.marker)
				}
			}()
			NewExecution(ctl, read, appr, capc, nil, jobsRepo, tasksRepo, newFakeConduit(nil), DefaultDispatchConcurrency, nil, nil)
		})
	}
}

// TestNewExecution_NilOptionalSeamsTakeTheirSafeDefaults: a nil idem, newID and
// jobEvents are the documented safe absences — the no-op event sink, the
// production Job-ID generator, and a keyed call refused rather than run
// unkeyed — and the engine still takes its IntentRecorder from the Recorder's
// AuditSink.
func TestNewExecution_NilOptionalSeamsTakeTheirSafeDefaults(t *testing.T) {
	jobsRepo, tasksRepo := testEngineStore(t)
	conduit := newFakeConduit(nil)
	conduit.connected["node-1"] = true
	conduit.results["node-1"] = jobs.Result{Outcome: jobs.OutcomeSuccess}
	reg := seedOneNode(t)

	intents := &nonAtomicIntents{tr: tasksRepo}
	rec := NewRecorder(&intentSpySink{&spyAuditSink{}, intents}, nil, nil)
	x := NewExecution(NewControl(rec, &spyAuthorizer{}, &fakeFreezeStore{}),
		newReadLane(rec, reg, nil, nil, nil, nil, 0, nil),
		newApprovals(rec, noopApprovalGate{}, nil, nil, nil, nil, noopApprovalNotifier{}, nil),
		&spyCapChecker{}, nil, jobsRepo, tasksRepo, conduit, DefaultDispatchConcurrency, nil, nil)

	if _, ok := x.jobEvents.(noopJobEventSink); !ok {
		t.Errorf("jobEvents = %T, want noopJobEventSink", x.jobEvents)
	}
	if _, ok := x.disp.(*jobEngine).events.(noopJobEventSink); !ok {
		t.Errorf("engine events = %T, want noopJobEventSink", x.disp.(*jobEngine).events)
	}

	act := jobs.Action{Kind: jobs.ActionOperation, OperationName: "system.facts"}
	p := Principal{AccountID: "a1", Account: "a1"}
	results, err := x.Run(context.Background(), p, Selector{}, act)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(results) != 1 || !regexp.MustCompile(`^job-[0-9a-f]{32}$`).MatchString(results[0].JobID) {
		t.Errorf("results = %+v, want one JobID of the form job-<32 hex> (defaultID)", results)
	}
	if n := len(intents.recorded()); n != 1 {
		t.Errorf("recorded intents = %d, want 1 (taken from the Recorder's AuditSink)", n)
	}

	_, err = x.Start(context.Background(), p, Selector{}, act, StartOptions{IdempotencyKey: "k-1"})
	if !errors.Is(err, ErrIdempotencyUnavailable) {
		t.Errorf("keyed Start with a nil idem: err = %v, want ErrIdempotencyUnavailable", err)
	}
}

// TestBuild_KeepsNewExecutionsRealDispatchGuard: the test builder wires a real
// engine through the same checkRealDispatch NewExecution runs, so a fixture
// over the allow-all default Authorizer panics rather than silently dispatching.
func TestBuild_KeepsNewExecutionsRealDispatchGuard(t *testing.T) {
	jobsRepo, tasksRepo := testEngineStore(t)
	defer func() {
		r := recover()
		if r == nil {
			t.Fatal("build with an execution seam over the allow-all default should panic")
		}
		if msg, _ := r.(string); !strings.Contains(msg, "allowAllAuthorizer") {
			t.Errorf("panic = %v, want it to name allowAllAuthorizer", r)
		}
	}()
	build(t, seams{reg: registry.NewInMemory(), jobsRepo: jobsRepo, tasksRepo: tasksRepo, conduit: newFakeConduit(nil)})
}

// TestExecution_ResolvesStateAgainstTheReadLanesWindow: Run resolves a
// `state:` Selector against the ReadLane's clock and cert-expiring window — the
// same StateEval ListNodes uses — so the two can never disagree about which
// Nodes are expiring. With the window at zero the marker never fires.
func TestExecution_ResolvesStateAgainstTheReadLanesWindow(t *testing.T) {
	now := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	sel := Selector{Predicates: []Predicate{{Namespace: NamespaceState, Key: "cert-expiring"}}}
	act := jobs.Action{Kind: jobs.ActionOperation, OperationName: "system.facts"}

	run := func(t *testing.T, window time.Duration) (*testSvc, []NodeResult, error) {
		t.Helper()
		reg := registry.NewInMemory()
		if _, err := reg.Upsert(registry.Report{NodeID: "node-1"}); err != nil {
			t.Fatalf("Upsert: %v", err)
		}
		if err := reg.RecordEnrollment("node-1", registry.Certificate{NotAfter: now.Add(time.Hour)}, now); err != nil {
			t.Fatalf("RecordEnrollment: %v", err)
		}
		conduit := newFakeConduit(nil)
		conduit.connected["node-1"] = true
		conduit.results["node-1"] = jobs.Result{Outcome: jobs.OutcomeSuccess}
		jobsRepo, tasksRepo := testEngineStore(t)
		svc := build(t, seams{reg: reg,
			authz: &spyAuthorizer{}, cap: &spyCapChecker{}, audit: &spyAuditSink{}, freeze: &fakeFreezeStore{},
			jobsRepo: jobsRepo, tasksRepo: tasksRepo, conduit: conduit,
			now: func() time.Time { return now }, certWindow: window,
		})
		results, err := svc.Run(context.Background(), Principal{Account: "alice"}, sel, act)
		return svc, results, err
	}

	svc, results, err := run(t, 2*time.Hour)
	if err != nil {
		t.Fatalf("Run with a 2h window: %v", err)
	}
	if len(results) != 1 || results[0].NodeID != "node-1" {
		t.Fatalf("Run results = %+v, want one result for node-1", results)
	}
	listing, err := svc.ListNodes(context.Background(), Principal{Account: "alice"}, "state:cert-expiring")
	if err != nil {
		t.Fatalf("ListNodes: %v", err)
	}
	if len(listing.Nodes) != 1 || listing.Nodes[0].NodeID != "node-1" {
		t.Fatalf("ListNodes = %+v, want the same Node Run dispatched to", listing.Nodes)
	}

	_, _, err = run(t, 0)
	var nnm *NoNodesMatchedError
	if !errors.As(err, &nnm) {
		t.Fatalf("Run with a zero window = %v, want a *NoNodesMatchedError (the marker never fires)", err)
	}
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
		// runtime/debug joined with #942: a recovered dispatch-worker panic logs
		// its stack. Stdlib, no proto, no database/sql.
		"runtime/debug": true,
		// sort joined with #539: RecordEventSubscription canonicalises its
		// caller-supplied kind list (sort + dedup) before it is bounded and
		// recorded, so a subscription's read record is grouped by shape
		// rather than by the order a query string happened to list kinds
		// in. Stdlib, no proto, no database/sql — the same admission bar
		// every other entry here clears.
		"sort":    true,
		"strings": true,
		// sync and golang.org/x/sync/errgroup joined with #886: bounded
		// concurrent Job fan-out and the per-Job cancel gate. x/sync is the Go
		// team's own extension module — no proto, no database/sql, no network.
		"sync":                       true,
		"golang.org/x/sync/errgroup": true,
		"time":                       true,
		"github.com/Felag-Engineering/gleipnir-relay/relay/internal/jobs":     true,
		"github.com/Felag-Engineering/gleipnir-relay/relay/internal/registry": true,
		// internal/approval joined the allowlist with #269 (ADR-0027). It is
		// admitted on exactly the terms jobs and registry are: a domain package
		// with no proto dependency and no database/sql, guarded by its own
		// import test (approval.TestApprovalImportsStayNarrow) so widening this
		// list does not create a transitive back door into the wire types.
		"github.com/Felag-Engineering/gleipnir-relay/relay/internal/approval": true,
		// logctx joined with #902: request-scoped log correlation (Job id).
		// Stdlib-only (`context`, `log/slog`) — no proto, no database/sql, no
		// HTTP, no Relay configuration — and held there by logctx's own
		// TestLogctxImportsStayNarrow, the same admission bar every entry here
		// clears.
		"github.com/Felag-Engineering/gleipnir-relay/relay/internal/logctx": true,
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
		// internal/policyview and internal/nodevocab joined with #680, on
		// exactly the terms approval, mcptask, nodestate and accounts were
		// admitted: proto-free, SQL-free, stdlib-only domain mirrors, each
		// guarded by its own import test (policyview.TestPolicyViewImportsStayNarrow,
		// nodevocab.TestNodeVocabImportsStayNarrow). Admitted so the Policy
		// view and the Template vocabulary have ONE definition rather than a
		// mirrored copy here that can disagree with the cache it describes —
		// the accounts rationale, applied again. Both are DISPLAY-ONLY
		// caches with no evaluation surface (Get only; Set stays out of this
		// package's reach), so admitting them cannot become a Relay-side
		// Policy decision (invariant 12, ADR-0011).
		"github.com/Felag-Engineering/gleipnir-relay/relay/internal/policyview": true,
		"github.com/Felag-Engineering/gleipnir-relay/relay/internal/nodevocab":  true,
		// internal/opvocab joined with #626 (ADR-0042): template.go asks it
		// whether an Operation name is Native — a Template is every name that
		// is not — and reuses its ValidateArgNames, the one definition of
		// #345's argument-name check, for Template slots. Stdlib plus jobs
		// only, no proto, no database/sql, and already a transitive import
		// through internal/approval, so admitting it opens no new door.
		"github.com/Felag-Engineering/gleipnir-relay/relay/internal/opvocab": true,
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
		intents:   &nonAtomicIntents{tr: tasksRepo},
		conduit:   conduit,
		newID:     sequentialIDs("id-"),
		now:       func() time.Time { return time.Date(2026, 7, 8, 0, 0, 0, 0, time.UTC) },
		events:    sink,
	}

	principal := Principal{Account: "alice"}
	sel := Selector{}
	act := jobs.Action{Kind: jobs.ActionOperation, OperationName: "system.facts"}
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
		intents:   &nonAtomicIntents{tr: tasksRepo},
		conduit:   conduit,
		newID:     sequentialIDs("id-"),
		now:       func() time.Time { return time.Date(2026, 7, 8, 0, 0, 0, 0, time.UTC) },
		events:    sink,
	}

	nodes := []registry.Node{testNode("node-1")}
	act := jobs.Action{Kind: jobs.ActionOperation, OperationName: "system.facts"}
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

// TestService_CancelJob_PublishesJobCancelled proves Execution.CancelJob
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
	svc := buildRaw(t, seams{disp: e, audit: &spyAuditSink{}, metrics: noopMetricsSink{}, jobEvents: sink, authz: &spyAuthorizer{}})

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
			intents:   &nonAtomicIntents{tr: tasksRepo},
			conduit:   conduit,
			newID:     sequentialIDs("id-"),
			now:       func() time.Time { return time.Date(2026, 7, 8, 0, 0, 0, 0, time.UTC) },
			events:    sink,
		}
		nodes := []registry.Node{testNode("node-1")}
		act := jobs.Action{Kind: jobs.ActionOperation, OperationName: "system.facts"}
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

// scriptConduit is a Conduit whose Connected/Dispatch/Cancel behaviour is
// scripted per test, and which records every Dispatch and Cancel (node IDs, in
// arrival order) under a mutex — dispatchOne runs on worker goroutines. Query
// comes from the embedded fakeConduit and is not exercised.
type scriptConduit struct {
	Conduit

	connectedFn func(nodeID string) bool
	dispatchFn  func(ctx context.Context, nodeID string, task jobs.Task) (jobs.Result, error)
	cancelFn    func(nodeID, taskID string)

	mu         sync.Mutex
	dispatched []string
	cancelled  []string
}

func newScriptConduit() *scriptConduit {
	return &scriptConduit{Conduit: newFakeConduit(nil)}
}

func (c *scriptConduit) Connected(nodeID string) bool {
	if c.connectedFn == nil {
		return true
	}
	return c.connectedFn(nodeID)
}

func (c *scriptConduit) Dispatch(ctx context.Context, nodeID string, task jobs.Task) (jobs.Result, error) {
	c.mu.Lock()
	c.dispatched = append(c.dispatched, nodeID)
	c.mu.Unlock()
	if c.dispatchFn == nil {
		return jobs.Result{Outcome: jobs.OutcomeSuccess}, nil
	}
	return c.dispatchFn(ctx, nodeID, task)
}

func (c *scriptConduit) Cancel(_ context.Context, nodeID, taskID string) error {
	c.mu.Lock()
	c.cancelled = append(c.cancelled, nodeID)
	c.mu.Unlock()
	if c.cancelFn != nil {
		c.cancelFn(nodeID, taskID)
	}
	return nil
}

func (c *scriptConduit) dispatchedNodes() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]string(nil), c.dispatched...)
}

func (c *scriptConduit) cancelledNodes() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]string(nil), c.cancelled...)
}

// peakTracker records the highest number of concurrent enter..leave spans.
type peakTracker struct {
	cur, peak atomic.Int32
}

func (p *peakTracker) enter() {
	n := p.cur.Add(1)
	for {
		old := p.peak.Load()
		if n <= old || p.peak.CompareAndSwap(old, n) {
			return
		}
	}
}

func (p *peakTracker) leave() { p.cur.Add(-1) }

const testWaitTimeout = 5 * time.Second

// waitFor receives from ch or fails the test after testWaitTimeout, so a
// regression to sequential dispatch fails instead of hanging the package.
// It must be called from the test goroutine.
func waitFor[T any](t *testing.T, ch <-chan T, what string) T {
	t.Helper()
	select {
	case v := <-ch:
		return v
	case <-time.After(testWaitTimeout):
		t.Fatalf("timed out waiting for %s", what)
		panic("unreachable")
	}
}

func nodeSet(n int) []registry.Node {
	nodes := make([]registry.Node, n)
	for i := range nodes {
		nodes[i] = testNode(fmt.Sprintf("node-%d", i+1))
	}
	return nodes
}

func newConcurrentEngine(t *testing.T, c Conduit, concurrency int) (*jobEngine, jobs.TaskRepository) {
	t.Helper()
	jobsRepo, tasksRepo := testEngineStore(t)
	return &jobEngine{
		jobsRepo:    jobsRepo,
		tasksRepo:   tasksRepo,
		intents:     &nonAtomicIntents{tr: tasksRepo},
		conduit:     c,
		newID:       sequentialIDs("id-"),
		now:         func() time.Time { return time.Date(2026, 10, 8, 0, 0, 0, 0, time.UTC) },
		concurrency: concurrency,
	}, tasksRepo
}

var fanOutAction = jobs.Action{Kind: jobs.ActionOperation, OperationName: "system.facts"}

// TestJobEngine_FanOutRunsConcurrentlyUnderTheBound is #886's acceptance: N
// pending Tasks across N fake Nodes complete in roughly one Task's time, not N.
// The primary assertion is the measured peak concurrency; elapsed time is a
// generous one-sided secondary check.
func TestJobEngine_FanOutRunsConcurrentlyUnderTheBound(t *testing.T) {
	const n, d = 8, 200 * time.Millisecond
	var peak peakTracker
	c := newScriptConduit()
	c.dispatchFn = func(_ context.Context, _ string, _ jobs.Task) (jobs.Result, error) {
		peak.enter()
		defer peak.leave()
		time.Sleep(d)
		return jobs.Result{Outcome: jobs.OutcomeSuccess}, nil
	}
	e, _ := newConcurrentEngine(t, c, 16)

	start := time.Now()
	dr, err := e.run(context.Background(), newDispatch(Principal{Account: "alice"}, Selector{}, nodeSet(n), fanOutAction))
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if got := int(peak.peak.Load()); got != n {
		t.Errorf("peak in-flight = %d, want %d", got, n)
	}
	if elapsed >= 3*d {
		t.Errorf("elapsed = %v, want well under %v (sequential would take %v)", elapsed, 3*d, n*int(d/time.Millisecond)*int(time.Millisecond))
	}
	if len(dr.results) != n {
		t.Fatalf("results = %d, want %d", len(dr.results), n)
	}
	for i, r := range dr.results {
		if want := fmt.Sprintf("node-%d", i+1); r.NodeID != want || r.Outcome != jobs.OutcomeSuccess {
			t.Errorf("results[%d] = %s/%v, want %s/success", i, r.NodeID, r.Outcome, want)
		}
	}
}

// TestJobEngine_ContextCarriesJobID pins two things about the Conduit seam
// (#902): the context handed to Dispatch carries the Job's id for log
// correlation, and the Task it receives is still the Pending snapshot it has
// always been handed — the in-memory Dispatched copy the engine keeps for its
// own later checks never reaches the Conduit.
func TestJobEngine_ContextCarriesJobID(t *testing.T) {
	var (
		gotCtx  context.Context
		gotTask jobs.Task
	)
	c := newScriptConduit()
	c.dispatchFn = func(ctx context.Context, _ string, task jobs.Task) (jobs.Result, error) {
		gotCtx, gotTask = ctx, task
		return jobs.Result{Outcome: jobs.OutcomeSuccess}, nil
	}
	e, _ := newConcurrentEngine(t, c, 1)

	dr, err := e.run(context.Background(), newDispatch(Principal{Account: "alice"}, Selector{}, nodeSet(1), fanOutAction))
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if gotCtx == nil {
		t.Fatal("Dispatch was never called")
	}
	if id, ok := logctx.JobIDFrom(gotCtx); !ok || id != dr.jobID {
		t.Errorf("JobIDFrom(ctx) = (%q, %v), want %q", id, ok, dr.jobID)
	}
	if gotTask.State != jobs.DispatchStatePending || !gotTask.DispatchedAt.IsZero() {
		t.Errorf("Conduit received state %v, DispatchedAt %v; want the Pending snapshot", gotTask.State, gotTask.DispatchedAt)
	}
}

func TestJobEngine_FanOutNeverExceedsTheBound(t *testing.T) {
	const n, bound = 8, 3
	var peak peakTracker
	c := newScriptConduit()
	c.dispatchFn = func(_ context.Context, _ string, _ jobs.Task) (jobs.Result, error) {
		peak.enter()
		defer peak.leave()
		time.Sleep(50 * time.Millisecond)
		return jobs.Result{Outcome: jobs.OutcomeSuccess}, nil
	}
	e, _ := newConcurrentEngine(t, c, bound)

	dr, err := e.run(context.Background(), newDispatch(Principal{Account: "alice"}, Selector{}, nodeSet(n), fanOutAction))
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if got := int(peak.peak.Load()); got != bound {
		t.Errorf("peak in-flight = %d, want exactly the bound %d", got, bound)
	}
	if len(dr.results) != n {
		t.Fatalf("results = %d, want %d", len(dr.results), n)
	}
	for i, r := range dr.results {
		if want := fmt.Sprintf("node-%d", i+1); r.NodeID != want {
			t.Errorf("results[%d].NodeID = %s, want %s", i, r.NodeID, want)
		}
	}
}

// TestJobEngine_ResultsKeepNodeOrderUnderConcurrency: later Nodes answer first,
// yet results stay in pending order (excluded Task first, then the Nodes), the
// JobCompleted tally is unchanged, and one Node's send error neither cancels
// nor skips its siblings and is named by the joined error.
func TestJobEngine_ResultsKeepNodeOrderUnderConcurrency(t *testing.T) {
	const n = 5
	sendErr := errors.New("tunnel write failed")
	c := newScriptConduit()
	c.dispatchFn = func(_ context.Context, nodeID string, _ jobs.Task) (jobs.Result, error) {
		i, _ := strconv.Atoi(strings.TrimPrefix(nodeID, "node-"))
		time.Sleep(time.Duration(n-i) * 10 * time.Millisecond)
		if nodeID == "node-3" {
			return jobs.Result{}, sendErr
		}
		return jobs.Result{Outcome: jobs.OutcomeSuccess}, nil
	}
	e, _ := newConcurrentEngine(t, c, 16)
	sink := &spyJobEventSink{}
	e.events = sink

	d := newDispatch(Principal{Account: "alice"}, Selector{}, nodeSet(n), fanOutAction)
	d.excluded = []excludedNode{{node: testNode("node-x"), reason: "no such Template"}}

	dr, err := e.run(context.Background(), d)
	if err == nil || !errors.Is(err, sendErr) || !strings.Contains(err.Error(), "node-3") {
		t.Fatalf("run error = %v, want it to wrap the send error and name node-3", err)
	}
	wantIDs := []string{"node-x", "node-1", "node-2", "node-3", "node-4", "node-5"}
	wantOutcomes := []jobs.Outcome{jobs.OutcomeUnsupported, jobs.OutcomeSuccess, jobs.OutcomeSuccess, jobs.OutcomeFailure, jobs.OutcomeSuccess, jobs.OutcomeSuccess}
	if len(dr.results) != len(wantIDs) {
		t.Fatalf("results = %d, want %d", len(dr.results), len(wantIDs))
	}
	for i, r := range dr.results {
		if r.NodeID != wantIDs[i] || r.Outcome != wantOutcomes[i] {
			t.Errorf("results[%d] = %s/%v, want %s/%v", i, r.NodeID, r.Outcome, wantIDs[i], wantOutcomes[i])
		}
	}
	if got := len(c.dispatchedNodes()); got != n {
		t.Errorf("Dispatch called %d times, want %d (every sibling attempted)", got, n)
	}
	if len(sink.events) != 2 {
		t.Fatalf("events = %d, want 2", len(sink.events))
	}
	oc := sink.events[1].Outcomes
	if oc[jobs.OutcomeSuccess] != 4 || oc[jobs.OutcomeFailure] != 1 || oc[jobs.OutcomeUnsupported] != 1 {
		t.Errorf("JobCompleted outcomes = %v, want 4 success, 1 failure, 1 unsupported", oc)
	}
}

// TestJobEngine_NoTaskDispatchedAfterCancelRecorded is #886's acceptance with
// the bound (16) larger than the Job (4): node-1 is in flight while nodes 2-4
// are held in their connectivity check; a cancel is recorded; nothing but
// node-1 is ever sent.
//
// This test proves concurrency plus the acceptance behaviour but NOT the
// cancel gate itself: held Tasks are Pending in cancel's snapshot, so cancel's
// own MarkCancelled would resolve them even without the gate. The gate is
// proven by TestJobEngine_CancelGateClosesTheSnapshotToMarkCancelledWindow.
func TestJobEngine_NoTaskDispatchedAfterCancelRecorded(t *testing.T) {
	inflight := make(chan struct{}, 1)
	arrived := make(chan string, 3)
	release := make(chan struct{})
	cancelSeen := make(chan struct{})
	var once sync.Once

	c := newScriptConduit()
	c.connectedFn = func(nodeID string) bool {
		if nodeID == "node-1" {
			return true
		}
		arrived <- nodeID
		select {
		case <-release:
		case <-time.After(testWaitTimeout):
		}
		return true
	}
	c.dispatchFn = func(ctx context.Context, _ string, _ jobs.Task) (jobs.Result, error) {
		inflight <- struct{}{}
		select {
		case <-cancelSeen:
		case <-ctx.Done():
		case <-time.After(testWaitTimeout):
		}
		return jobs.Result{Outcome: jobs.OutcomeCancelled}, nil
	}
	c.cancelFn = func(_, _ string) { once.Do(func() { close(cancelSeen) }) }
	e, tasksRepo := newConcurrentEngine(t, c, 16)

	type runOut struct {
		dr  dispatchResult
		err error
	}
	done := make(chan runOut, 1)
	go func() {
		dr, err := e.run(context.Background(), newDispatch(Principal{Account: "alice"}, Selector{}, nodeSet(4), fanOutAction))
		done <- runOut{dr, err}
	}()

	waitFor(t, inflight, "node-1 in flight")
	for range 3 {
		waitFor(t, arrived, "nodes 2-4 to reach their connectivity check")
	}
	if err := e.cancel(context.Background(), "job-id-1"); err != nil {
		t.Fatalf("cancel: %v", err)
	}
	close(release)
	out := waitFor(t, done, "run to finish")
	if out.err != nil {
		t.Fatalf("run: %v", out.err)
	}

	if got := c.dispatchedNodes(); len(got) != 1 || got[0] != "node-1" {
		t.Errorf("Dispatch called for %v, want exactly [node-1]", got)
	}
	if got := c.cancelledNodes(); len(got) != 1 || got[0] != "node-1" {
		t.Errorf("Conduit.Cancel called for %v, want exactly [node-1]", got)
	}
	if len(out.dr.results) != 4 {
		t.Fatalf("results = %d, want 4", len(out.dr.results))
	}
	for i, r := range out.dr.results {
		if want := fmt.Sprintf("node-%d", i+1); r.NodeID != want || r.Outcome != jobs.OutcomeCancelled {
			t.Errorf("results[%d] = %s/%v, want %s/cancelled", i, r.NodeID, r.Outcome, want)
		}
	}
	tasks, err := tasksRepo.ByJob(context.Background(), "job-id-1")
	if err != nil {
		t.Fatalf("ByJob: %v", err)
	}
	for _, task := range tasks {
		if task.State != jobs.DispatchStateResolved || task.Outcome != jobs.OutcomeCancelled {
			t.Errorf("task %s = %v/%v, want Resolved/Cancelled", task.NodeID, task.State, task.Outcome)
		}
		if task.NodeID != "node-1" && !task.DispatchedAt.IsZero() {
			t.Errorf("task %s has DispatchedAt set, but was never sent", task.NodeID)
		}
	}
}

// windowTasks wraps a TaskRepository to drive the one window the cancel gate
// exists to close: a worker's MarkDispatched committing after cancel's ByJob
// snapshot and before cancel's MarkCancelled.
type windowTasks struct {
	jobs.TaskRepository
	t           *testing.T
	jobID       string
	watchedTask string        // node-2's Task
	release2    chan struct{} // closed from the first ByJob
	settled     chan string   // "dispatched" or "cancelled" for watchedTask
	once        sync.Once
}

func (w *windowTasks) MarkDispatched(ctx context.Context, id string, at time.Time) error {
	err := w.TaskRepository.MarkDispatched(ctx, id, at)
	if id == w.watchedTask && err == nil {
		w.settled <- "dispatched"
	}
	return err
}

func (w *windowTasks) MarkCancelled(ctx context.Context, id string, at time.Time) error {
	err := w.TaskRepository.MarkCancelled(ctx, id, at)
	if id == w.watchedTask && err == nil {
		w.settled <- "cancelled"
	}
	return err
}

func (w *windowTasks) ByJob(ctx context.Context, jobID string) ([]jobs.Task, error) {
	snap, err := w.TaskRepository.ByJob(ctx, jobID)
	if err != nil || jobID != w.jobID {
		return snap, err
	}
	w.once.Do(func() {
		for _, task := range snap {
			if task.ID == w.watchedTask && task.State != jobs.DispatchStatePending {
				w.t.Errorf("node-2's Task = %v in cancel's snapshot, want Pending", task.State)
			}
		}
		// Release node-2's worker now: its step commits strictly after the
		// snapshot and before cancel's own per-Task loop.
		close(w.release2)
		select {
		case <-w.settledPeek():
		case <-time.After(testWaitTimeout):
			w.t.Errorf("node-2's worker did not settle after release")
		}
	})
	return snap, nil
}

// settledPeek waits for the worker's signal and re-posts it for the test body.
func (w *windowTasks) settledPeek() <-chan struct{} {
	out := make(chan struct{})
	go func() {
		v := <-w.settled
		w.settled <- v
		close(out)
	}()
	return out
}

// TestJobEngine_CancelGateClosesTheSnapshotToMarkCancelledWindow drives the
// window the cancel gate exists to close. node-2's worker is parked in
// Connected, already past the early cancelled check; cancel records itself,
// snapshots (node-2 Pending), and — before cancel's own MarkCancelled runs —
// node-2's worker is released and reaches MarkDispatched. With the gate the
// admit is refused and the worker cancels its own Task; without it node-2 would
// be sent, never receive Conduit.Cancel, and cancel would return a joined
// ErrInvalidTaskState.
func TestJobEngine_CancelGateClosesTheSnapshotToMarkCancelledWindow(t *testing.T) {
	const jobID = "job-id-1"
	// sequentialIDs("id-"): job id-1, stage id-2, then one Task per Node.
	const node1Task, node2Task = "task-id-3", "task-id-4"

	inflight1 := make(chan struct{}, 1)
	arrived2 := make(chan struct{}, 1)
	release2 := make(chan struct{})
	cancelSeen := make(chan struct{})
	var cancelOnce sync.Once
	var node2Once sync.Once

	c := newScriptConduit()
	c.connectedFn = func(nodeID string) bool {
		if nodeID == "node-2" {
			node2Once.Do(func() {
				arrived2 <- struct{}{}
				select {
				case <-release2:
				case <-time.After(testWaitTimeout):
				}
			})
		}
		return true
	}
	c.dispatchFn = func(ctx context.Context, nodeID string, _ jobs.Task) (jobs.Result, error) {
		if nodeID != "node-1" {
			return jobs.Result{Outcome: jobs.OutcomeSuccess}, nil
		}
		inflight1 <- struct{}{}
		select {
		case <-cancelSeen:
		case <-ctx.Done():
		case <-time.After(testWaitTimeout):
		}
		return jobs.Result{Outcome: jobs.OutcomeCancelled}, nil
	}
	c.cancelFn = func(nodeID, taskID string) {
		if nodeID == "node-1" && taskID == node1Task {
			cancelOnce.Do(func() { close(cancelSeen) })
		}
	}

	e, tasksRepo := newConcurrentEngine(t, c, 16)
	wt := &windowTasks{
		TaskRepository: tasksRepo, t: t, jobID: jobID, watchedTask: node2Task,
		release2: release2, settled: make(chan string, 2),
	}
	e.tasksRepo = wt

	type runOut struct {
		dr  dispatchResult
		err error
	}
	done := make(chan runOut, 1)
	go func() {
		dr, err := e.run(context.Background(), newDispatch(Principal{Account: "alice"}, Selector{}, nodeSet(2), fanOutAction))
		done <- runOut{dr, err}
	}()

	waitFor(t, inflight1, "node-1 in flight")
	waitFor(t, arrived2, "node-2 to reach its connectivity check")
	if err := e.cancel(context.Background(), jobID); err != nil {
		t.Errorf("cancel returned %v, want nil", err)
	}
	out := waitFor(t, done, "run to finish")
	if out.err != nil {
		t.Errorf("run: %v", out.err)
	}

	if got := waitFor(t, wt.settled, "node-2's settle signal"); got != "cancelled" {
		t.Errorf("node-2 settled as %q inside the window, want \"cancelled\" (no MarkDispatched after the cancel is recorded)", got)
	}
	if got := c.dispatchedNodes(); len(got) != 1 || got[0] != "node-1" {
		t.Errorf("Dispatch called for %v, want exactly [node-1]", got)
	}
	if got := c.cancelledNodes(); len(got) != 1 || got[0] != "node-1" {
		t.Errorf("Conduit.Cancel called for %v, want exactly [node-1]", got)
	}
	task, err := tasksRepo.Get(context.Background(), node2Task)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if task.State != jobs.DispatchStateResolved || task.Outcome != jobs.OutcomeCancelled || !task.DispatchedAt.IsZero() {
		t.Errorf("node-2's Task = %v/%v dispatchedAt=%v, want Resolved/Cancelled and never dispatched", task.State, task.Outcome, task.DispatchedAt)
	}
	if len(out.dr.results) != 2 {
		t.Fatalf("results = %d, want 2", len(out.dr.results))
	}
	for i, r := range out.dr.results {
		if want := fmt.Sprintf("node-%d", i+1); r.NodeID != want || r.Outcome != jobs.OutcomeCancelled {
			t.Errorf("results[%d] = %s/%v, want %s/cancelled", i, r.NodeID, r.Outcome, want)
		}
	}
}

// TestJobEngine_CancelRaceStress fires cancel at a random moment across many
// Jobs under -race. Every Task must end Resolved/Cancelled, every Task that
// reached Conduit.Dispatch must have received a Conduit.Cancel, and cancel
// must return nil.
//
// The fake Dispatch remembers cancels that arrive before it is entered. That
// models only the engine's guarantee (a Cancel is issued for every dispatched
// Task); the real daemon treats a cancel for a not-yet-known id as a no-op
// (the pre-send residual, ADR-0013).
func TestJobEngine_CancelRaceStress(t *testing.T) {
	const iterations, nodes = 100, 6
	// One store for all iterations (opening one costs ~0.5s); each iteration
	// mints IDs under its own prefix so its Job is distinct.
	jobsRepo, tasksRepo := testEngineStore(t)
	for iter := range iterations {
		var mu sync.Mutex
		cancelCh := map[string]chan struct{}{}
		chFor := func(taskID string) chan struct{} {
			mu.Lock()
			defer mu.Unlock()
			ch, ok := cancelCh[taskID]
			if !ok {
				ch = make(chan struct{})
				cancelCh[taskID] = ch
			}
			return ch
		}
		cancelled := map[string]bool{}

		c := newScriptConduit()
		c.dispatchFn = func(_ context.Context, _ string, task jobs.Task) (jobs.Result, error) {
			select {
			case <-chFor(task.ID):
			case <-time.After(2 * time.Second):
				t.Errorf("iter %d: Dispatch for %s never saw a Cancel", iter, task.ID)
				return jobs.Result{Outcome: jobs.OutcomeSuccess}, nil
			}
			return jobs.Result{Outcome: jobs.OutcomeCancelled}, nil
		}
		c.cancelFn = func(_, taskID string) {
			ch := chFor(taskID)
			mu.Lock()
			defer mu.Unlock()
			if !cancelled[taskID] {
				cancelled[taskID] = true
				close(ch)
			}
		}
		jobID := fmt.Sprintf("job-i%d-1", iter)
		e := &jobEngine{
			jobsRepo:    jobsRepo,
			tasksRepo:   tasksRepo,
			intents:     &nonAtomicIntents{tr: tasksRepo},
			conduit:     c,
			newID:       sequentialIDs(fmt.Sprintf("i%d-", iter)),
			now:         func() time.Time { return time.Date(2026, 10, 8, 0, 0, 0, 0, time.UTC) },
			concurrency: 16,
		}

		done := make(chan error, 1)
		go func() {
			_, err := e.run(context.Background(), newDispatch(Principal{Account: "alice"}, Selector{}, nodeSet(nodes), fanOutAction))
			done <- err
		}()

		for {
			if _, err := e.jobsRepo.GetJob(context.Background(), jobID); err == nil {
				break
			}
			time.Sleep(100 * time.Microsecond)
		}
		time.Sleep(time.Duration(rand.Int64N(int64(5 * time.Millisecond))))
		if err := e.cancel(context.Background(), jobID); err != nil {
			t.Fatalf("iter %d: cancel returned %v, want nil", iter, err)
		}
		if err := waitFor(t, done, "run to finish"); err != nil {
			t.Fatalf("iter %d: run: %v", iter, err)
		}

		tasks, err := tasksRepo.ByJob(context.Background(), jobID)
		if err != nil {
			t.Fatalf("iter %d: ByJob: %v", iter, err)
		}
		if len(tasks) != nodes {
			t.Fatalf("iter %d: %d Tasks, want %d", iter, len(tasks), nodes)
		}
		for _, task := range tasks {
			if task.State != jobs.DispatchStateResolved || task.Outcome != jobs.OutcomeCancelled {
				t.Errorf("iter %d: task %s = %v/%v, want Resolved/Cancelled", iter, task.NodeID, task.State, task.Outcome)
			}
		}
		dispatched, cancelledNodes := c.dispatchedNodes(), c.cancelledNodes()
		for _, n := range dispatched {
			if !slices.Contains(cancelledNodes, n) {
				t.Errorf("iter %d: %s was dispatched but never received Conduit.Cancel", iter, n)
			}
		}
	}
}

// cancelBuffer remembers Conduit.Cancel calls per task ID, so a fake Dispatch
// that starts waiting after its Cancel arrived never hangs.
type cancelBuffer struct {
	mu  sync.Mutex
	chs map[string]chan struct{}
}

func newCancelBuffer() *cancelBuffer { return &cancelBuffer{chs: map[string]chan struct{}{}} }

func (b *cancelBuffer) chFor(taskID string) chan struct{} {
	b.mu.Lock()
	defer b.mu.Unlock()
	ch, ok := b.chs[taskID]
	if !ok {
		ch = make(chan struct{})
		b.chs[taskID] = ch
	}
	return ch
}

// cancel records a Cancel for taskID without ever blocking.
func (b *cancelBuffer) cancel(taskID string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	ch, ok := b.chs[taskID]
	if !ok {
		ch = make(chan struct{})
		b.chs[taskID] = ch
	}
	select {
	case <-ch:
	default:
		close(ch)
	}
}

// TestJobEngine_NoTaskSentAfterCancelObservedUnderConcurrentFanOut pins #943:
// with bound 2 over 4 Nodes, node-1 is sent before the cancel; node-2 is past
// MarkDispatched and inside Conduit.Dispatch, but has not yet evaluated its
// send guard when the cancel is recorded. node-2 must be withheld, and nodes 3
// and 4 must never be dispatched at all.
func TestJobEngine_NoTaskSentAfterCancelObservedUnderConcurrentFanOut(t *testing.T) {
	const jobID = "job-id-1"

	var mu sync.Mutex
	var sent []string
	entered1 := make(chan struct{}, 1)
	entered2 := make(chan struct{}, 1)
	release2 := make(chan struct{})
	cancels := newCancelBuffer()

	c := newScriptConduit()
	c.dispatchFn = func(ctx context.Context, nodeID string, task jobs.Task) (jobs.Result, error) {
		if nodeID == "node-2" {
			entered2 <- struct{}{}
			select {
			case <-release2:
			case <-time.After(testWaitTimeout):
			}
		}
		if jobs.SendWithheld(ctx) {
			return jobs.Result{}, jobs.ErrSendWithheld
		}
		mu.Lock()
		sent = append(sent, nodeID)
		mu.Unlock()
		if nodeID == "node-1" {
			entered1 <- struct{}{}
		}
		select {
		case <-cancels.chFor(task.ID):
		case <-time.After(testWaitTimeout):
			t.Errorf("%s was sent but never received a Cancel", nodeID)
		}
		return jobs.Result{Outcome: jobs.OutcomeCancelled}, nil
	}
	// node-2 was never sent, yet cancel() still calls Cancel for it; the fake
	// must answer without blocking.
	c.cancelFn = func(_, taskID string) { cancels.cancel(taskID) }

	e, tasksRepo := newConcurrentEngine(t, c, 2)

	type runOut struct {
		dr  dispatchResult
		err error
	}
	done := make(chan runOut, 1)
	go func() {
		dr, err := e.run(context.Background(), newDispatch(Principal{Account: "alice"}, Selector{}, nodeSet(4), fanOutAction))
		done <- runOut{dr, err}
	}()

	waitFor(t, entered1, "node-1 sent")
	waitFor(t, entered2, "node-2 inside Dispatch")
	if err := e.cancel(context.Background(), jobID); err != nil {
		t.Errorf("cancel returned %v, want nil", err)
	}
	close(release2)
	out := waitFor(t, done, "run to finish")
	if out.err != nil {
		t.Errorf("run: %v", out.err)
	}

	mu.Lock()
	gotSent := append([]string(nil), sent...)
	mu.Unlock()
	if len(gotSent) != 1 || gotSent[0] != "node-1" {
		t.Errorf("sent = %v, want exactly [node-1]", gotSent)
	}
	got := c.dispatchedNodes()
	slices.Sort(got)
	if !slices.Equal(got, []string{"node-1", "node-2"}) {
		t.Errorf("Dispatch entered for %v, want [node-1 node-2]", got)
	}
	tasks, err := tasksRepo.ByJob(context.Background(), jobID)
	if err != nil || len(tasks) != 4 {
		t.Fatalf("ByJob = %d tasks, %v; want 4", len(tasks), err)
	}
	for _, task := range tasks {
		if task.State != jobs.DispatchStateResolved || task.Outcome != jobs.OutcomeCancelled {
			t.Errorf("task %s = %v/%v, want Resolved/Cancelled", task.NodeID, task.State, task.Outcome)
		}
		if sentOnWire := task.NodeID == "node-1"; sentOnWire == task.DispatchedAt.IsZero() {
			t.Errorf("task %s DispatchedAt = %v, want set only for node-1", task.NodeID, task.DispatchedAt)
		}
	}
	inFlight, err := tasksRepo.InFlight(context.Background())
	if err != nil || len(inFlight) != 0 {
		t.Errorf("InFlight = %v, %v; want empty", inFlight, err)
	}
	if len(out.dr.results) != 4 {
		t.Fatalf("results = %d, want 4", len(out.dr.results))
	}
	for _, r := range out.dr.results {
		if r.Outcome != jobs.OutcomeCancelled {
			t.Errorf("result %s = %v, want cancelled", r.NodeID, r.Outcome)
		}
	}
}

// cancelAfterDispatchTasks cancels the Job's gate from inside MarkDispatched
// of the watched Task. That is legal here: admit holds gate.mu, so the write
// is serialised exactly as a cancel landing right after admit would be.
type cancelAfterDispatchTasks struct {
	jobs.TaskRepository
	e       *jobEngine
	jobID   string
	watched string
}

func (w *cancelAfterDispatchTasks) MarkDispatched(ctx context.Context, id string, at time.Time) error {
	err := w.TaskRepository.MarkDispatched(ctx, id, at)
	if id == w.watched && err == nil {
		w.e.gateFor(w.jobID).cancelled = true
	}
	return err
}

// TestJobEngine_CancelAfterAdmitWithholdsThroughTheGuard covers the engine's
// guard: a cancel recorded right after admit is seen by the guard the Conduit
// consults before its wire write; the guard commits the withhold itself and the
// Task is never sent. The engine has no check of its own ahead of the Conduit.
func TestJobEngine_CancelAfterAdmitWithholdsThroughTheGuard(t *testing.T) {
	const jobID, taskID = "job-id-1", "task-id-3"
	c := newScriptConduit()
	var mu sync.Mutex
	var sent int
	c.dispatchFn = func(ctx context.Context, _ string, _ jobs.Task) (jobs.Result, error) {
		if jobs.SendWithheld(ctx) {
			return jobs.Result{}, jobs.ErrSendWithheld
		}
		mu.Lock()
		sent++
		mu.Unlock()
		return jobs.Result{Outcome: jobs.OutcomeSuccess}, nil
	}
	e, tasksRepo := newConcurrentEngine(t, c, 16)
	e.tasksRepo = &cancelAfterDispatchTasks{TaskRepository: tasksRepo, e: e, jobID: jobID, watched: taskID}

	dr, err := e.run(context.Background(), newDispatch(Principal{Account: "alice"}, Selector{}, nodeSet(1), fanOutAction))
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	mu.Lock()
	if sent != 0 {
		t.Errorf("sent = %d, want 0", sent)
	}
	mu.Unlock()
	task, err := tasksRepo.Get(context.Background(), taskID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if task.State != jobs.DispatchStateResolved || task.Outcome != jobs.OutcomeCancelled || !task.DispatchedAt.IsZero() {
		t.Errorf("task = %v/%v dispatchedAt=%v, want Resolved/Cancelled and never sent", task.State, task.Outcome, task.DispatchedAt)
	}
	if len(dr.results) != 1 || dr.results[0].Outcome != jobs.OutcomeCancelled {
		t.Errorf("results = %+v, want one cancelled", dr.results)
	}
}

// TestJobEngine_WithheldErrorWithoutCancelLeavesTaskInFlight: a Conduit cannot
// turn a Task into a "never sent" record on its own. ErrSendWithheld with no
// cancel recorded is an ordinary failure and the Task stays Dispatched.
func TestJobEngine_WithheldErrorWithoutCancelLeavesTaskInFlight(t *testing.T) {
	c := newScriptConduit()
	c.dispatchFn = func(context.Context, string, jobs.Task) (jobs.Result, error) {
		return jobs.Result{}, jobs.ErrSendWithheld
	}
	e, tasksRepo := newConcurrentEngine(t, c, 16)

	dr, err := e.run(context.Background(), newDispatch(Principal{Account: "alice"}, Selector{}, nodeSet(1), fanOutAction))
	if !errors.Is(err, jobs.ErrSendWithheld) {
		t.Errorf("run error = %v, want it to wrap ErrSendWithheld", err)
	}
	if len(dr.results) != 1 || dr.results[0].Outcome != jobs.OutcomeFailure {
		t.Errorf("results = %+v, want one failure", dr.results)
	}
	inFlight, ferr := tasksRepo.InFlight(context.Background())
	if ferr != nil || len(inFlight) != 1 {
		t.Errorf("InFlight = %v, %v; want the Task still in flight", inFlight, ferr)
	}
}

// TestJobEngine_CancelRecheckRaceStress fires cancel at a random moment across
// many Jobs under -race, with a fake that honours the send guard. Every Task
// ends Resolved/Cancelled; every sent Task received a Cancel; every withheld
// Task was never sent, has no DispatchedAt and is not in flight.
func TestJobEngine_CancelRecheckRaceStress(t *testing.T) {
	const iterations, nodes = 100, 6
	jobsRepo, tasksRepo := testEngineStore(t)
	for iter := range iterations {
		var mu sync.Mutex
		sent := map[string]bool{}
		withheld := map[string]bool{}
		cancels := newCancelBuffer()

		c := newScriptConduit()
		c.dispatchFn = func(ctx context.Context, _ string, task jobs.Task) (jobs.Result, error) {
			if jobs.SendWithheld(ctx) {
				mu.Lock()
				withheld[task.ID] = true
				mu.Unlock()
				return jobs.Result{}, jobs.ErrSendWithheld
			}
			mu.Lock()
			sent[task.ID] = true
			mu.Unlock()
			select {
			case <-cancels.chFor(task.ID):
			case <-time.After(2 * time.Second):
				t.Errorf("iter %d: sent %s never saw a Cancel", iter, task.ID)
				return jobs.Result{Outcome: jobs.OutcomeSuccess}, nil
			}
			return jobs.Result{Outcome: jobs.OutcomeCancelled}, nil
		}
		c.cancelFn = func(_, taskID string) { cancels.cancel(taskID) }

		jobID := fmt.Sprintf("job-i%d-1", iter)
		e := &jobEngine{
			jobsRepo:    jobsRepo,
			tasksRepo:   tasksRepo,
			intents:     &nonAtomicIntents{tr: tasksRepo},
			conduit:     c,
			newID:       sequentialIDs(fmt.Sprintf("i%d-", iter)),
			now:         func() time.Time { return time.Date(2026, 10, 8, 0, 0, 0, 0, time.UTC) },
			concurrency: 3,
		}

		done := make(chan error, 1)
		go func() {
			_, err := e.run(context.Background(), newDispatch(Principal{Account: "alice"}, Selector{}, nodeSet(nodes), fanOutAction))
			done <- err
		}()
		for {
			if _, err := e.jobsRepo.GetJob(context.Background(), jobID); err == nil {
				break
			}
			time.Sleep(100 * time.Microsecond)
		}
		time.Sleep(time.Duration(rand.Int64N(int64(5 * time.Millisecond))))
		if err := e.cancel(context.Background(), jobID); err != nil {
			t.Fatalf("iter %d: cancel returned %v, want nil", iter, err)
		}
		if err := waitFor(t, done, "run to finish"); err != nil {
			t.Fatalf("iter %d: run: %v", iter, err)
		}

		tasks, err := tasksRepo.ByJob(context.Background(), jobID)
		if err != nil || len(tasks) != nodes {
			t.Fatalf("iter %d: ByJob = %d tasks, %v; want %d", iter, len(tasks), err, nodes)
		}
		inFlight, err := tasksRepo.InFlight(context.Background())
		if err != nil {
			t.Fatalf("iter %d: InFlight: %v", iter, err)
		}
		mu.Lock()
		for _, task := range tasks {
			if task.State != jobs.DispatchStateResolved || task.Outcome != jobs.OutcomeCancelled {
				t.Errorf("iter %d: task %s = %v/%v, want Resolved/Cancelled", iter, task.NodeID, task.State, task.Outcome)
			}
			if withheld[task.ID] {
				if sent[task.ID] {
					t.Errorf("iter %d: task %s was both withheld and sent", iter, task.NodeID)
				}
				if !task.DispatchedAt.IsZero() {
					t.Errorf("iter %d: withheld task %s has DispatchedAt set", iter, task.NodeID)
				}
				for _, f := range inFlight {
					if f.ID == task.ID {
						t.Errorf("iter %d: withheld task %s is still in flight", iter, task.NodeID)
					}
				}
			}
		}
		mu.Unlock()
		cancelledNodes := c.cancelledNodes()
		for _, task := range tasks {
			mu.Lock()
			wasSent := sent[task.ID]
			mu.Unlock()
			if wasSent && !slices.Contains(cancelledNodes, task.NodeID) {
				t.Errorf("iter %d: %s was sent but never received Conduit.Cancel", iter, task.NodeID)
			}
		}
	}
}

// staleByJob returns every Task as Pending, as a snapshot read just before a
// worker resolved them would.
type staleByJob struct {
	jobs.TaskRepository
}

func (s staleByJob) ByJob(ctx context.Context, jobID string) ([]jobs.Task, error) {
	snap, err := s.TaskRepository.ByJob(ctx, jobID)
	for i := range snap {
		snap[i].State = jobs.DispatchStatePending
	}
	return snap, err
}

// TestJobEngine_CancelToleratesAWorkerThatResolvedThePendingTaskFirst: a Task
// Pending in cancel's snapshot but already Resolved in the store is a truthful
// outcome, not an error, and cancel must not rewrite it.
func TestJobEngine_CancelToleratesAWorkerThatResolvedThePendingTaskFirst(t *testing.T) {
	c := newScriptConduit()
	e, tasksRepo := newConcurrentEngine(t, c, 16)
	if _, err := e.run(context.Background(), newDispatch(Principal{Account: "alice"}, Selector{}, nodeSet(1), fanOutAction)); err != nil {
		t.Fatalf("run: %v", err)
	}
	e.tasksRepo = staleByJob{tasksRepo}

	if err := e.cancel(context.Background(), "job-id-1"); err != nil {
		t.Fatalf("cancel = %v, want nil", err)
	}
	if got := c.cancelledNodes(); len(got) != 0 {
		t.Errorf("Conduit.Cancel called for %v, want none", got)
	}
	tasks, err := tasksRepo.ByJob(context.Background(), "job-id-1")
	if err != nil || len(tasks) != 1 {
		t.Fatalf("ByJob = %v, %v", tasks, err)
	}
	if tasks[0].Outcome != jobs.OutcomeSuccess {
		t.Errorf("Outcome = %v, want the truthful Success left untouched", tasks[0].Outcome)
	}
}

func TestJobEngine_OpenGatePanicsOnADuplicateJob(t *testing.T) {
	e := &jobEngine{}
	_, release := e.openGate("job-1")

	func() {
		defer func() {
			if recover() == nil {
				t.Error("openGate on an already-open Job ID did not panic")
			}
		}()
		e.openGate("job-1")
	}()

	release()
	if e.gateFor("job-1") != nil {
		t.Error("gate still registered after release")
	}
	_, release2 := e.openGate("job-1")
	release2()
}

func TestNewExecutionPanicsOnNonPositiveDispatchConcurrency(t *testing.T) {
	jr, tr := testEngineStore(t)
	// Every other argument is valid, so only the concurrency check can fire.
	rec := NewRecorder(&intentSpySink{&spyAuditSink{}, &nonAtomicIntents{tr: tr}}, nil, nil)
	ctl := NewControl(rec, &spyAuthorizer{}, &fakeFreezeStore{})
	read := newReadLane(rec, registry.NewInMemory(), nil, nil, nil, nil, 0, nil)
	appr := newApprovals(rec, noopApprovalGate{}, nil, nil, nil, nil, noopApprovalNotifier{}, nil)
	for _, n := range []int{0, -1} {
		func() {
			defer func() {
				if recover() == nil {
					t.Errorf("NewExecution(concurrency=%d) did not panic", n)
				}
			}()
			NewExecution(ctl, read, appr, &spyCapChecker{}, nil, jr, tr, newFakeConduit(nil), n, nil, nil)
		}()
	}
}
