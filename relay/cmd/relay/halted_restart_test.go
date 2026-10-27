package main

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

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
func TestDispatchWiring_ARestartSendsNoTaskOfAHaltedJobAndCancelsEverySibling(t *testing.T) {
	ctx := context.Background()
	tasks, st := testTaskRepositoryWithStore(t)
	seed := seedHaltedJobAtCrash(t, st)

	reads := newSignalInFlight(tasks)
	router, reconciler, _ := newDispatchStack(reads, nil, nil)
	if err := settleHaltedJobs(reconciler, st.HaltedJobs(), nil); err != nil {
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
	deadline := time.Now().Add(5 * time.Second)
	for {
		got, err := tasks.Get(ctx, seed.controlTaskID)
		if err != nil {
			t.Fatalf("Get(control): %v", err)
		}
		if got.State == jobs.DispatchStateResolved {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the un-halted Job's Task is %v, want Resolved by its reconcile", got.State)
		}
		time.Sleep(10 * time.Millisecond)
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
	if dispatched.State != jobs.DispatchStateResolved || dispatched.Outcome != jobs.OutcomeCancelled ||
		dispatched.DispatchedAt.IsZero() || string(dispatched.Stderr) != seed.halt.RestartReason() {
		t.Errorf("marked-dispatched task = %v/%v dispatched %v stderr %q, want Resolved/cancelled, dispatch time kept, the restart's reason",
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
	if err := settleHaltedJobs(reconciler, failingHaltedJobs{}, nil); err == nil {
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
		if task.ID != seed.halt.TaskID && task.Outcome != jobs.OutcomeCancelled {
			t.Errorf("task %s of the halted Job has outcome %v after start-up, want cancelled", task.ID, task.Outcome)
		}
	}
}
