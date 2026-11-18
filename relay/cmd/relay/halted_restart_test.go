package main

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Felag-Engineering/relay/relay/internal/audit"
	"github.com/Felag-Engineering/relay/relay/internal/dispatch"
	"github.com/Felag-Engineering/relay/relay/internal/jobs"
	"github.com/Felag-Engineering/relay/relay/internal/registry"
	relayv1 "github.com/Felag-Engineering/relay/relay/internal/relay/v1"
	"github.com/Felag-Engineering/relay/relay/internal/store"
)

// haltedJobAtCrash is the store a Relay crash leaves behind for a halted mutate
// Job whose siblings were not all resolved: node-1's Task failed and halted the
// Job, node-2's is marked dispatched with no result, node-3's is Pending. A
// second Job that never halted holds one Dispatched Task on node-2.
type haltedJobAtCrash struct {
	jobID, controlJobID             string
	dispatchedTaskID, pendingTaskID string
	controlTaskID                   string
	halt                            jobs.Halt
}

func seedHaltedJobAtCrash(t *testing.T, st *store.Store) haltedJobAtCrash {
	t.Helper()
	ctx := context.Background()
	now := time.Now().UTC()
	for _, id := range []string{"node-1", "node-2", "node-3"} {
		if _, err := st.Registry().Upsert(registry.Report{NodeID: id}); err != nil {
			t.Fatalf("Upsert(%s): %v", id, err)
		}
	}
	act := jobs.Action{Kind: jobs.ActionRawExec, RawExecArgv: []string{"/bin/true"}, RiskClass: jobs.RiskClassMutate}
	newJob := func(jobID string) {
		if err := st.Jobs().CreateJob(ctx, jobs.Job{ID: jobID, CreatedAt: now}); err != nil {
			t.Fatalf("CreateJob(%s): %v", jobID, err)
		}
		if err := st.Jobs().AddStage(ctx, jobs.Stage{ID: "stage-" + jobID, JobID: jobID, Index: 0}); err != nil {
			t.Fatalf("AddStage(%s): %v", jobID, err)
		}
	}
	newTask := func(jobID, taskID, nodeID string) {
		task := jobs.Task{ID: taskID, JobID: jobID, StageID: "stage-" + jobID, NodeID: nodeID, Action: act, CreatedAt: now}
		if err := st.Tasks().CreateTask(ctx, task); err != nil {
			t.Fatalf("CreateTask(%s): %v", taskID, err)
		}
	}
	markDispatched := func(taskID string) {
		if err := st.Tasks().MarkDispatched(ctx, taskID, now); err != nil {
			t.Fatalf("MarkDispatched(%s): %v", taskID, err)
		}
	}

	s := haltedJobAtCrash{
		jobID: "job-crash-halted", controlJobID: "job-crash-control",
		dispatchedTaskID: "task-crash-dispatched", pendingTaskID: "task-crash-pending",
		controlTaskID: "task-crash-control",
	}
	newJob(s.jobID)
	newTask(s.jobID, "task-crash-failed", "node-1")
	newTask(s.jobID, s.dispatchedTaskID, "node-2")
	newTask(s.jobID, s.pendingTaskID, "node-3")
	markDispatched("task-crash-failed")
	if err := st.Tasks().Resolve(ctx, "task-crash-failed", jobs.Result{Outcome: jobs.OutcomeFailure, ExitCode: 1}); err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	s.halt = jobs.Halt{TaskID: "task-crash-failed", NodeID: "node-1", Outcome: jobs.OutcomeFailure, Resolved: true, At: now}
	if err := st.Jobs().RecordHalt(ctx, s.jobID, s.halt); err != nil {
		t.Fatalf("RecordHalt: %v", err)
	}
	// Marked dispatched and never answered: the crash came before, or after, its send.
	markDispatched(s.dispatchedTaskID)

	newJob(s.controlJobID)
	newTask(s.controlJobID, s.controlTaskID, "node-2")
	markDispatched(s.controlTaskID)
	return s
}

// A halted mutate Job stays halted across a Relay restart (#1191): the start-up
// sweep resolves its unsent siblings before any Node connects, so the
// Reconciler sends none of them, while a Job that never halted is still
// reconciled (invariant 4).
// Proves EX-28.
func TestDispatchWiring_ARestartSendsNoTaskOfAHaltedJobAndCancelsEverySibling(t *testing.T) {
	ctx := context.Background()
	tasks, st := testTaskRepositoryWithStore(t)
	seed := seedHaltedJobAtCrash(t, st)

	reads := newSignalInFlight(tasks)
	router, reconciler, _ := newDispatchStack(reads, nil, nil)
	if err := settleHaltedJobs(reconciler, st.HaltedJobs(), nil, nil); err != nil {
		t.Fatalf("settleHaltedJobs: %v", err)
	}

	var mu sync.Mutex
	var sentTasks []string
	for _, id := range []string{"node-1", "node-2", "node-3"} {
		router.Register(id, func(msg *relayv1.RelayMessage) error {
			if task := msg.GetTask(); task != nil {
				mu.Lock()
				sentTasks = append(sentTasks, task.GetTaskId())
				mu.Unlock()
				// The relay-daemon answers; delivered off the send path.
				go router.Deliver(id, &relayv1.TaskResult{TaskId: task.GetTaskId(), Outcome: relayv1.Outcome_OUTCOME_SUCCESS})
			}
			return nil
		})
	}
	reads.awaitReads(t, 3)

	// The un-halted Job's resend proves the reconcile ran and that the skip is
	// specific to the halted Job.
	var control jobs.Task
	resolved := func() bool {
		got, err := tasks.Get(ctx, seed.controlTaskID)
		if err != nil {
			t.Fatalf("Get(control): %v", err)
		}
		control = got
		return got.State == jobs.DispatchStateResolved
	}
	if !pollUntil(5*time.Second, 10*time.Millisecond, resolved) {
		t.Fatalf("the un-halted Job's Task is %v, want Resolved by its reconcile", control.State)
	}

	mu.Lock()
	sent := append([]string(nil), sentTasks...)
	mu.Unlock()
	if len(sent) != 1 || sent[0] != seed.controlTaskID {
		t.Errorf("TaskRequests sent after the restart = %v, want only the un-halted Job's %q", sent, seed.controlTaskID)
	}

	pending, err := tasks.Get(ctx, seed.pendingTaskID)
	if err != nil {
		t.Fatalf("Get(pending): %v", err)
	}
	if pending.State != jobs.DispatchStateResolved || pending.Outcome != jobs.OutcomeCancelled ||
		!pending.DispatchedAt.IsZero() || string(pending.Stderr) != seed.halt.Reason() {
		t.Errorf("unsent Pending task = %v/%v dispatched %v stderr %q, want Resolved/cancelled, never dispatched, the halt's reason",
			pending.State, pending.Outcome, pending.DispatchedAt, pending.Stderr)
	}
	dispatched, err := tasks.Get(ctx, seed.dispatchedTaskID)
	if err != nil {
		t.Fatalf("Get(dispatched): %v", err)
	}
	if dispatched.State != jobs.DispatchStateResolved || dispatched.Outcome != jobs.OutcomeFailure ||
		dispatched.ExitCode != -1 || dispatched.DispatchedAt.IsZero() || string(dispatched.Stderr) != seed.halt.RestartReason() {
		t.Errorf("marked-dispatched task = %v/%v dispatched %v stderr %q, want Resolved/failure, exit -1, dispatch time kept, the restart's reason",
			dispatched.State, dispatched.Outcome, dispatched.DispatchedAt, dispatched.Stderr)
	}
	inFlight, err := tasks.InFlight(ctx)
	if err != nil {
		t.Fatalf("InFlight: %v", err)
	}
	for _, task := range inFlight {
		if task.JobID == seed.jobID {
			t.Errorf("InFlight after the restart holds %s of the halted Job", task.ID)
		}
	}
}

// settleHaltedJobs fails when the sweep cannot list the halted Jobs' Tasks.
func TestSettleHaltedJobs_ReturnsTheSweepsError(t *testing.T) {
	_, reconciler, _ := newDispatchStack(nil, nil, nil)
	if err := settleHaltedJobs(reconciler, failingHaltedJobs{}, nil, nil); err == nil {
		t.Fatal("settleHaltedJobs returned nil for a failed listing, want an error")
	}
}

type failingHaltedJobs struct{}

func (failingHaltedJobs) GetJob(context.Context, string) (jobs.Job, error) {
	return jobs.Job{}, errors.New("unavailable")
}

func (failingHaltedJobs) UnsettledTasksOfHaltedJobs(context.Context) ([]jobs.Task, error) {
	return nil, errors.New("unavailable")
}

// A halted Job the sweep cannot read refuses start-up: serving would let a
// reconnecting Node's reconcile re-send its Tasks.
func TestNewServer_ControlEnabled_RefusesToStartWhenTheSweepFails(t *testing.T) {
	cfg := baseTestConfig(t)
	cfg.ControlEnabled = true
	cfg.ControlAddr = ":0"

	seeding, err := store.Open(cfg.StorePath)
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	seed := seedHaltedJobAtCrash(t, seeding)
	if err := seeding.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	db, err := sql.Open("sqlite", cfg.StorePath)
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	// An unparseable halted_at makes GetJob, and so the sweep, fail.
	if _, err := db.Exec(`UPDATE jobs SET halted_at = 'not a time' WHERE job_id = ?`, seed.jobID); err != nil {
		t.Fatalf("corrupt halted_at: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("db.Close: %v", err)
	}

	srv, deps, err := newServer(cfg, testStartupFiles(t, cfg))
	if err == nil {
		srv.Stop()
		deps.store.Close()
		t.Fatal("newServer succeeded with a halted Job the sweep cannot read, want an error")
	}
	if !strings.Contains(err.Error(), "settle halted jobs") {
		t.Errorf("newServer error = %v, want it to come from the halted-Jobs sweep", err)
	}
}

// newServer settles a halted Job's unsent Tasks before it returns, and so
// before any Node can connect and be reconciled.
// Proves EX-28.
func TestNewServer_ControlEnabled_SettlesAHaltedJobBeforeServing(t *testing.T) {
	cfg := baseTestConfig(t)
	cfg.ControlEnabled = true
	cfg.ControlAddr = ":0"

	seeding, err := store.Open(cfg.StorePath)
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	seed := seedHaltedJobAtCrash(t, seeding)
	if err := seeding.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	srv, deps, err := newServer(cfg, testStartupFiles(t, cfg))
	if err != nil {
		t.Fatalf("newServer: %v", err)
	}
	t.Cleanup(func() { deps.store.Close() })
	t.Cleanup(srv.Stop)

	all, err := deps.store.Tasks().ByJob(context.Background(), seed.jobID)
	if err != nil {
		t.Fatalf("ByJob: %v", err)
	}
	if len(all) != 3 {
		t.Fatalf("halted Job holds %d tasks, want 3", len(all))
	}
	for _, task := range all {
		if task.State != jobs.DispatchStateResolved {
			t.Errorf("task %s of the halted Job is %v after start-up, want Resolved", task.ID, task.State)
		}
		want := jobs.OutcomeCancelled // never sent
		switch task.ID {
		case seed.halt.TaskID:
			continue
		case seed.dispatchedTaskID:
			want = jobs.OutcomeFailure // may have run
		}
		if task.Outcome != want {
			t.Errorf("task %s of the halted Job has outcome %v after start-up, want %v", task.ID, task.Outcome, want)
		}
		switch task.ID {
		case seed.dispatchedTaskID:
			if task.ExitCode != -1 || string(task.Stderr) != seed.halt.RestartReason() {
				t.Errorf("dispatched sibling = exit %d stderr %q, want exit -1 and the restart's reason", task.ExitCode, task.Stderr)
			}
		case seed.pendingTaskID:
			if string(task.Stderr) != seed.halt.Reason() || !task.DispatchedAt.IsZero() {
				t.Errorf("pending sibling = stderr %q dispatched %v, want the halt's reason and never dispatched", task.Stderr, task.DispatchedAt)
			}
		}
	}

	records, err := deps.store.Audit().ByJob(context.Background(), seed.jobID)
	if err != nil {
		t.Fatalf("Audit().ByJob: %v", err)
	}
	for _, task := range all {
		if task.ID != seed.pendingTaskID && task.ID != seed.dispatchedTaskID {
			continue
		}
		wantReason := "settled_after_restart=halted_job task_id=" + task.ID
		var rows []audit.Record
		for _, rec := range records {
			if rec.Kind == audit.KindDispatch && rec.Reason == wantReason {
				rows = append(rows, rec)
			}
		}
		if len(rows) != 1 {
			t.Errorf("task %s: %d settlement audit rows with reason %q, want exactly 1", task.ID, len(rows), wantReason)
			continue
		}
		if rows[0].Outcome != task.Outcome {
			t.Errorf("task %s: audited outcome %v, want the stored Task's %v", task.ID, rows[0].Outcome, task.Outcome)
		}
	}
}

// A restart sends no Task that was never sent into execution, and re-sends
// none that already reached a terminal state before the crash: a Pending Task
// stays unsent, and an unreachable or version-refused Task is not reconciled
// when its Node reconnects.
// Proves EX-32, EX-33.
func TestDispatchWiring_ARestartSendsNoPendingUnreachableOrVersionRefusedTask(t *testing.T) {
	ctx := context.Background()
	tasks, st := testTaskRepositoryWithStore(t)
	now := time.Now().UTC()
	for _, id := range []string{"node-1", "node-2", "node-3"} {
		if _, err := st.Registry().Upsert(registry.Report{NodeID: id}); err != nil {
			t.Fatalf("Upsert(%s): %v", id, err)
		}
	}
	const jobID = "job-restart"
	if err := st.Jobs().CreateJob(ctx, jobs.Job{ID: jobID, CreatedAt: now}); err != nil {
		t.Fatalf("CreateJob: %v", err)
	}
	if err := st.Jobs().AddStage(ctx, jobs.Stage{ID: "stage-" + jobID, JobID: jobID, Index: 0}); err != nil {
		t.Fatalf("AddStage: %v", err)
	}
	act := jobs.Action{Kind: jobs.ActionRawExec, RawExecArgv: []string{"/bin/true"}, RiskClass: jobs.RiskClassMutate}
	for _, task := range []struct{ id, node string }{
		{"task-pending", "node-1"},
		{"task-unreachable", "node-2"},
		{"task-refused", "node-3"},
		{"task-control", "node-1"},
	} {
		if err := st.Tasks().CreateTask(ctx, jobs.Task{ID: task.id, JobID: jobID, StageID: "stage-" + jobID, NodeID: task.node, Action: act, CreatedAt: now}); err != nil {
			t.Fatalf("CreateTask(%s): %v", task.id, err)
		}
	}
	if err := st.Tasks().MarkUnreachable(ctx, "task-unreachable", now); err != nil {
		t.Fatalf("MarkUnreachable: %v", err)
	}
	if err := st.Tasks().MarkVersionRefused(ctx, "task-refused", now); err != nil {
		t.Fatalf("MarkVersionRefused: %v", err)
	}
	if err := st.Tasks().MarkDispatched(ctx, "task-control", now); err != nil {
		t.Fatalf("MarkDispatched(control): %v", err)
	}
	unreachableBefore, err := tasks.Get(ctx, "task-unreachable")
	if err != nil {
		t.Fatalf("Get(unreachable): %v", err)
	}
	refusedBefore, err := tasks.Get(ctx, "task-refused")
	if err != nil {
		t.Fatalf("Get(refused): %v", err)
	}

	// The stack is built here rather than by newDispatchStack so the test can
	// wait for each reconcile to finish, not only to read the in-flight set: a
	// wrong send made late in a reconcile would otherwise land after the
	// snapshot below.
	var reconciles sync.WaitGroup
	var reconciler *dispatch.Reconciler
	router := dispatch.NewRouter(func(nodeID string) {
		defer reconciles.Done()
		if err := reconciler.ReconcileNode(ctx, nodeID); err != nil {
			t.Errorf("ReconcileNode(%s): %v", nodeID, err)
		}
	}, nil)
	reconciler = dispatch.NewReconciler(tasks, router)
	var mu sync.Mutex
	var sentTasks []string
	for _, id := range []string{"node-1", "node-2", "node-3"} {
		reconciles.Add(1)
		router.Register(id, func(msg *relayv1.RelayMessage) error {
			if task := msg.GetTask(); task != nil {
				mu.Lock()
				sentTasks = append(sentTasks, task.GetTaskId())
				mu.Unlock()
				go router.Deliver(id, &relayv1.TaskResult{TaskId: task.GetTaskId(), Outcome: relayv1.Outcome_OUTCOME_SUCCESS})
			}
			return nil
		})
	}
	reconcilesDone := make(chan struct{})
	go func() { reconciles.Wait(); close(reconcilesDone) }()
	select {
	case <-reconcilesDone:
	case <-time.After(10 * time.Second):
		t.Fatal("timeout waiting for every registration's reconcile to finish")
	}

	deadline := time.Now().Add(5 * time.Second)
	for {
		got, err := tasks.Get(ctx, "task-control")
		if err != nil {
			t.Fatalf("Get(control): %v", err)
		}
		if got.State == jobs.DispatchStateResolved {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the control Task is %v, want Resolved by its reconcile", got.State)
		}
		time.Sleep(10 * time.Millisecond)
	}

	mu.Lock()
	sent := append([]string(nil), sentTasks...)
	mu.Unlock()
	if len(sent) != 1 || sent[0] != "task-control" {
		t.Errorf("TaskRequests sent after the restart = %v, want only task-control", sent)
	}
	pending, err := tasks.Get(ctx, "task-pending")
	if err != nil {
		t.Fatalf("Get(pending): %v", err)
	}
	if pending.State != jobs.DispatchStatePending || !pending.DispatchedAt.IsZero() {
		t.Errorf("task-pending = %v dispatched %v, want still Pending and never sent into execution", pending.State, pending.DispatchedAt)
	}
	for _, c := range []struct {
		id     string
		before jobs.Task
		want   jobs.Outcome
	}{
		{"task-unreachable", unreachableBefore, jobs.OutcomeUnreachable},
		{"task-refused", refusedBefore, jobs.OutcomeVersionRefused},
	} {
		got, err := tasks.Get(ctx, c.id)
		if err != nil {
			t.Fatalf("Get(%s): %v", c.id, err)
		}
		if got.State != jobs.DispatchStateResolved || got.Outcome != c.want || !got.ResolvedAt.Equal(c.before.ResolvedAt) {
			t.Errorf("%s = %v/%v resolved %v, want unchanged Resolved/%v resolved %v", c.id, got.State, got.Outcome, got.ResolvedAt, c.want, c.before.ResolvedAt)
		}
	}
}
