package capability

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Felag-Engineering/relay/relay/internal/jobs"
	"github.com/Felag-Engineering/relay/relay/internal/registry"
)

// TestInvariant4_EveryTaskIsStoredPendingWithItsIntentBeforeAnyIsSent holds
// invariant 4: a Task ID seen once is never executed twice.
// Every Task is handed to the intent write as Pending, under its own ID, and
// all are stored before the first send; the intent carries what the dispatch was.
// Proves EX-29.
func TestInvariant4_EveryTaskIsStoredPendingWithItsIntentBeforeAnyIsSent(t *testing.T) {
	jobsRepo, tasksRepo := testEngineStore(t)
	var log []string
	conduit := newFakeConduit(&log)
	conduit.connected["node-1"] = true
	conduit.connected["node-2"] = true
	conduit.results["node-1"] = jobs.Result{Outcome: jobs.OutcomeSuccess}
	conduit.results["node-2"] = jobs.Result{Outcome: jobs.OutcomeSuccess}

	intents := &nonAtomicIntents{tr: &recordingTasks{TaskRepository: tasksRepo, log: &log}}
	e := &jobEngine{
		jobsRepo: jobsRepo, tasksRepo: tasksRepo, intents: intents, conduit: conduit,
		newID: sequentialIDs("id-"), now: time.Now, settings: concurrencyOf(4),
	}
	nodes := []registry.Node{testNode("node-1"), testNode("node-2")}
	act := jobs.Action{Kind: jobs.ActionOperation, OperationName: "system.facts", RiskClass: jobs.RiskClassRead}
	sel := Selector{Predicates: []Predicate{{Namespace: NamespaceNode, Key: "role", Value: "web"}}}
	d := newDispatch(Principal{Account: "alice"}, sel, nodes, act)
	d.approvalID = "appr-1"
	ctx := WithAssertions(context.Background(), Assertions{ChangeRef: "CHG-1"})

	if _, err := e.run(ctx, d); err != nil {
		t.Fatalf("run: %v", err)
	}

	entries := intents.recorded()
	if len(entries) != 1 {
		t.Fatalf("RecordIntent called %d times, want exactly 1", len(entries))
	}
	got := entries[0]
	if got.Kind != AuditKindDispatchIntent || got.JobID != "job-id-1" || got.Principal.Account != "alice" ||
		got.CapCleared != 2 || got.ApprovalID != "appr-1" || got.Action.OperationName != "system.facts" {
		t.Errorf("intent entry = %+v", got)
	}
	if len(got.Selector.Predicates) != 1 || got.Selector.Predicates[0] != sel.Predicates[0] {
		t.Errorf("intent Selector = %+v, want %+v", got.Selector, sel)
	}
	if got.Asserted.ChangeRef != "CHG-1" {
		t.Errorf("intent Asserted = %+v, want ChangeRef CHG-1", got.Asserted)
	}
	if len(got.Results) != 0 {
		t.Errorf("intent entry carries %d Results, want none", len(got.Results))
	}

	stored := intents.recordedTasks()
	if len(stored) != 2 {
		t.Fatalf("RecordIntent was handed %d Tasks, want 2", len(stored))
	}
	seen := map[string]bool{}
	for _, task := range stored {
		if task.State != jobs.DispatchStatePending {
			t.Errorf("Task %q handed to the intent write as %v, want Pending", task.ID, task.State)
		}
		if task.ID == "" || seen[task.ID] {
			t.Errorf("Task ID %q is empty or repeated", task.ID)
		}
		seen[task.ID] = true
	}

	firstDispatch, creates := -1, 0
	for i, l := range log {
		if strings.HasPrefix(l, "create:") {
			creates++
			if firstDispatch != -1 {
				t.Errorf("Task created after a dispatch began: %v", log)
			}
		}
		if strings.HasPrefix(l, "dispatch:") && firstDispatch == -1 {
			firstDispatch = i
		}
	}
	if creates != 2 || firstDispatch == -1 {
		t.Errorf("log = %v, want 2 creates before the dispatches", log)
	}
}

// TestInvariant4_AFailedIntentWriteSendsNothing holds invariant 4: a Task ID
// seen once is never executed twice.
// When the intent and its Tasks cannot be written there is no Task, and nothing is sent.
// Proves EX-29.
func TestInvariant4_AFailedIntentWriteSendsNothing(t *testing.T) {
	jobsRepo, tasksRepo := testEngineStore(t)
	var log []string
	conduit := newFakeConduit(&log)
	conduit.connected["node-1"] = true
	conduit.results["node-1"] = jobs.Result{Outcome: jobs.OutcomeSuccess}

	intents := &nonAtomicIntents{tr: tasksRepo, err: errors.New("disk full")}
	e := &jobEngine{
		jobsRepo: jobsRepo, tasksRepo: tasksRepo, intents: intents, conduit: conduit,
		newID: sequentialIDs("id-"), now: time.Now, settings: concurrencyOf(4),
	}
	d := newDispatch(Principal{Account: "alice"}, Selector{}, []registry.Node{testNode("node-1")},
		jobs.Action{Kind: jobs.ActionOperation, OperationName: "system.facts"})

	if _, err := e.run(context.Background(), d); err == nil {
		t.Fatal("run succeeded although the intent could not be recorded")
	}
	for _, l := range log {
		if strings.HasPrefix(l, "dispatch:") {
			t.Fatalf("a Task was dispatched without a recorded intent: %v", log)
		}
	}
	tasks, err := tasksRepo.ByJob(context.Background(), "job-id-1")
	if err != nil {
		t.Fatalf("ByJob: %v", err)
	}
	if len(tasks) != 0 {
		t.Errorf("%d Tasks persisted without an intent", len(tasks))
	}
}

func TestEngineWithoutIntentRecorderRefusesToPersist(t *testing.T) {
	jobsRepo, tasksRepo := testEngineStore(t)
	e := &jobEngine{
		jobsRepo: jobsRepo, tasksRepo: tasksRepo, conduit: newFakeConduit(nil),
		newID: sequentialIDs("id-"), now: time.Now, settings: concurrencyOf(4),
	}
	d := newDispatch(Principal{Account: "alice"}, Selector{}, []registry.Node{testNode("node-1")},
		jobs.Action{Kind: jobs.ActionOperation, OperationName: "system.facts"})

	if _, err := e.run(context.Background(), d); err == nil || !strings.Contains(err.Error(), "IntentRecorder") {
		t.Fatalf("run err = %v, want a refusal naming IntentRecorder", err)
	}
	tasks, _ := tasksRepo.ByJob(context.Background(), "job-id-1")
	if len(tasks) != 0 {
		t.Errorf("%d Tasks persisted without an IntentRecorder", len(tasks))
	}
}

func TestNewExecutionPanicsWhenAuditSinkHasNoIntentRecorder(t *testing.T) {
	jobsRepo, tasksRepo := testEngineStore(t)
	rec := NewRecorder(&spyAuditSink{}, nil, nil)
	ctl := NewControl(rec, &spyAuthorizer{}, &fakeFreezeStore{})
	read := newReadLane(rec, registry.NewInMemory(), nil, nil, nil, nil, testSettings, nil)
	appr := newApprovals(rec, noopApprovalGate{}, nil, nil, noopApprovalNotifier{}, nil)
	defer func() {
		r := recover()
		if r == nil {
			t.Fatal("NewExecution with a real dispatcher and an AuditSink that cannot record intent should panic")
		}
		if msg, _ := r.(string); !strings.Contains(msg, "IntentRecorder") {
			t.Errorf("panic = %v, want it to name IntentRecorder", r)
		}
	}()
	NewExecution(ctl, read, appr, &spyCapChecker{}, nil, jobsRepo, tasksRepo, newFakeConduit(nil), testSettings, nil, nil)
}

// nonAtomicIntents is the IntentRecorder the in-package tests use when their
// AuditSink is a spy: it records the entry and persists the Tasks one by one
// through tr. It is NOT atomic — atomicity is the store's property and is
// proven there (store/audit_intent_test.go).
type nonAtomicIntents struct {
	tr jobs.TaskRepository

	mu      sync.Mutex
	entries []AuditEntry
	tasks   []jobs.Task
	err     error
}

func (n *nonAtomicIntents) RecordIntent(ctx context.Context, e AuditEntry, tasks []jobs.Task) error {
	n.mu.Lock()
	n.entries = append(n.entries, e)
	n.tasks = append(n.tasks, tasks...)
	err := n.err
	n.mu.Unlock()
	if err != nil {
		return err
	}
	for _, t := range tasks {
		if err := n.tr.CreateTask(ctx, t); err != nil {
			return err
		}
	}
	return nil
}

func (n *nonAtomicIntents) recorded() []AuditEntry {
	n.mu.Lock()
	defer n.mu.Unlock()
	return append([]AuditEntry(nil), n.entries...)
}

func (n *nonAtomicIntents) recordedTasks() []jobs.Task {
	n.mu.Lock()
	defer n.mu.Unlock()
	return append([]jobs.Task(nil), n.tasks...)
}

// intentSpySink is a spy AuditSink that also records dispatch intent, so a test
// can call NewExecution itself, which takes the engine's IntentRecorder from
// the Recorder's sink.
type intentSpySink struct {
	*spyAuditSink
	*nonAtomicIntents
}
