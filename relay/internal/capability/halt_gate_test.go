package capability

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Felag-Engineering/relay/relay/internal/jobs"
)

// These tests prove that a mutate Job's gate closes when the engine sees a
// halting outcome, before that outcome is persisted or read, so no sibling is
// admitted in between (execution.md, Halting a failing mutation).

// gatedTasks wraps a TaskRepository so a test can hold the halting Task's store
// access: onResolve runs before every failure Resolve, onGet before a Get of
// haltingTask. Either may block.
type gatedTasks struct {
	jobs.TaskRepository
	onResolve   func()
	onGet       func()
	haltingTask atomic.Value // string
}

func (g *gatedTasks) Resolve(ctx context.Context, taskID string, res jobs.Result) error {
	if res.Outcome == jobs.OutcomeFailure && g.onResolve != nil {
		g.onResolve()
	}
	return g.TaskRepository.Resolve(ctx, taskID, res)
}

func (g *gatedTasks) Get(ctx context.Context, taskID string) (jobs.Task, error) {
	if id, _ := g.haltingTask.Load().(string); id == taskID && g.onGet != nil {
		g.onGet()
	}
	return g.TaskRepository.Get(ctx, taskID)
}

// requireHaltCancelledByNode fails unless task is a never-sent Task that a halt
// on haltNode resolved cancelled. The halt's wording is not compared: a sibling
// resolved while the halt is still settling carries the provisional wording.
func requireHaltCancelledByNode(t *testing.T, task jobs.Task, haltNode string) {
	t.Helper()
	if task.State != jobs.DispatchStateResolved || task.Outcome != jobs.OutcomeCancelled || !task.DispatchedAt.IsZero() {
		t.Errorf("Task[%s] = state %v outcome %v dispatchedAt %v, want a never-sent Resolved/cancelled Task",
			task.NodeID, task.State, task.Outcome, task.DispatchedAt)
	}
	if !strings.HasPrefix(string(task.Stderr), "halted: ") || !strings.Contains(string(task.Stderr), fmt.Sprintf("Node %q", haltNode)) {
		t.Errorf("Task[%s] stderr = %q, want a halt reason naming %s", task.NodeID, task.Stderr, haltNode)
	}
}

type runOutcome struct {
	dr  dispatchResult
	err error
}

func runAsync(e *jobEngine, nodes int) <-chan runOutcome {
	done := make(chan runOutcome, 1)
	go func() {
		dr, err := e.run(context.Background(), newDispatch(Principal{Account: "alice"}, Selector{}, nodeSet(nodes), mutateRawExec()))
		done <- runOutcome{dr, err}
	}()
	return done
}

// TestJobEngine_HaltClosesTheGateBeforeTheHaltingOutcomeIsPersisted: no sibling
// is admitted once the engine has seen a halting Conduit result, even while the
// store has not recorded it. node-1's failure Resolve is held; node-2 then
// finishes and frees a slot, and node-3 must resolve halt-cancelled without
// being sent, all before that Resolve commits.
func TestJobEngine_HaltClosesTheGateBeforeTheHaltingOutcomeIsPersisted(t *testing.T) {
	resolveEntered := make(chan struct{})
	releaseResolve := make(chan struct{})
	node2Sent := make(chan struct{})
	var jobID atomic.Value
	c := newScriptConduit()
	c.dispatchFn = func(_ context.Context, n string, task jobs.Task) (jobs.Result, error) {
		jobID.Store(task.JobID)
		switch n {
		case "node-1":
			<-node2Sent
			return jobs.Result{Outcome: jobs.OutcomeFailure}, nil
		case "node-2":
			close(node2Sent)
			// Finishes only once node-1's Resolve is held, so the slot it
			// frees is taken by node-3 while that Resolve is pending.
			<-resolveEntered
		}
		return jobs.Result{Outcome: jobs.OutcomeSuccess}, nil
	}
	e, tasksRepo := newConcurrentEngine(t, c, 2)
	e.tasksRepo = &gatedTasks{
		TaskRepository: tasksRepo,
		onResolve: func() {
			close(resolveEntered)
			<-releaseResolve
		},
	}
	done := runAsync(e, 3)

	<-resolveEntered
	waitUntil(t, "node-3 to be halt-cancelled while node-1's Resolve is held", func() bool {
		if d := c.dispatchedNodes(); len(d) > 2 {
			t.Fatalf("dispatched = %v, want node-3 never sent after the engine saw node-1 fail", d)
		}
		id, ok := jobID.Load().(string)
		if !ok {
			return false
		}
		n3, ok := tasksByNode(t, tasksRepo, id)["node-3"]
		return ok && n3.State == jobs.DispatchStateResolved
	})
	close(releaseResolve)
	got := waitFor(t, done, "run to return")
	if got.err != nil {
		t.Fatalf("run() error = %v", got.err)
	}

	tasks := tasksByNode(t, tasksRepo, got.dr.jobID)
	requireHaltCancelledByNode(t, tasks["node-3"], "node-1")
	if tasks["node-1"].State != jobs.DispatchStateResolved || tasks["node-1"].Outcome != jobs.OutcomeFailure {
		t.Errorf("Task[node-1] = %v/%v, want its real Resolved failure", tasks["node-1"].State, tasks["node-1"].Outcome)
	}
	if h := got.dr.halt; !h.Halted() || h.NodeID != "node-1" || h.Outcome != jobs.OutcomeFailure || !h.Resolved {
		t.Errorf("halt = %+v, want node-1 failure with a recorded result once the Resolve committed", h)
	}
	if d := c.dispatchedNodes(); len(d) != 2 {
		t.Errorf("dispatched = %v, want only node-1 and node-2", d)
	}
	requireNoTaskInFlight(t, tasksRepo)
}

// TestJobEngine_HaltHoldsAdmissionWhileAnErrorPathReadsTheStore: a Conduit error
// is a halting outcome only once the store has been read (a Reconciler may have
// recorded a real result), so a sibling is held at the gate, not admitted,
// while that read is in progress, and is then halt-cancelled.
func TestJobEngine_HaltHoldsAdmissionWhileAnErrorPathReadsTheStore(t *testing.T) {
	for _, tc := range []struct {
		name         string
		err          error
		offline      bool
		wantResolved bool
	}{
		{"conduit error", errors.New("tunnel write failed"), false, false},
		{"replaced stream", fmt.Errorf("send: %w", jobs.ErrStreamReplaced), false, false},
		{"node offline", errors.New("stream ended"), true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			getEntered := make(chan struct{})
			releaseGet := make(chan struct{})
			node2Sent := make(chan struct{})
			node3Probed := make(chan struct{})
			var probeOnce sync.Once
			var node1Done atomic.Bool
			var jobID atomic.Value
			var gated *gatedTasks
			c := newScriptConduit()
			c.connectedFn = func(n string) bool {
				if n == "node-3" {
					probeOnce.Do(func() { close(node3Probed) })
				}
				return !tc.offline || n != "node-1" || !node1Done.Load()
			}
			c.dispatchFn = func(_ context.Context, n string, task jobs.Task) (jobs.Result, error) {
				jobID.Store(task.JobID)
				switch n {
				case "node-1":
					<-node2Sent
					gated.haltingTask.Store(task.ID)
					node1Done.Store(true)
					return jobs.Result{}, tc.err
				case "node-2":
					close(node2Sent)
					<-getEntered
				}
				return jobs.Result{Outcome: jobs.OutcomeSuccess}, nil
			}
			e, tasksRepo := newConcurrentEngine(t, c, 2)
			gated = &gatedTasks{
				TaskRepository: tasksRepo,
				onGet: sync.OnceFunc(func() {
					close(getEntered)
					<-releaseGet
				}),
			}
			e.tasksRepo = gated
			done := runAsync(e, 3)

			// node-3 has reached the gate while node-1's store read is held.
			waitFor(t, node3Probed, "node-3 to reach the gate")
			time.Sleep(50 * time.Millisecond)
			id, _ := jobID.Load().(string)
			if n3 := tasksByNode(t, tasksRepo, id)["node-3"]; n3.State != jobs.DispatchStatePending {
				t.Fatalf("Task[node-3] state = %v, want it held Pending at the gate", n3.State)
			}
			if d := c.dispatchedNodes(); len(d) != 2 {
				t.Fatalf("dispatched = %v, want node-3 not sent while node-1's outcome is being read", d)
			}
			close(releaseGet)
			got := waitFor(t, done, "run to return")
			if tc.offline && got.err != nil {
				t.Fatalf("run() error = %v", got.err)
			}

			tasks := tasksByNode(t, tasksRepo, got.dr.jobID)
			requireHaltCancelledByNode(t, tasks["node-3"], "node-1")
			if h := got.dr.halt; !h.Halted() || h.NodeID != "node-1" || h.Resolved != tc.wantResolved {
				t.Errorf("halt = %+v, want node-1 with resolved=%v", h, tc.wantResolved)
			}
			if d := c.dispatchedNodes(); len(d) != 2 {
				t.Errorf("dispatched = %v, want only node-1 and node-2", d)
			}
		})
	}
}

// TestJobEngine_HaltOnAWorkerPanicStopsSending: a panic while a Task is in
// flight is reported as that Task's failure and halts the Job at the recover,
// before the engine does anything else with the Task.
func TestJobEngine_HaltOnAWorkerPanicStopsSending(t *testing.T) {
	c := newScriptConduit()
	c.dispatchFn = func(_ context.Context, n string, _ jobs.Task) (jobs.Result, error) {
		if n == "node-1" {
			panic("worker panic")
		}
		return jobs.Result{Outcome: jobs.OutcomeSuccess}, nil
	}
	e, tasksRepo := newConcurrentEngine(t, c, 1)

	dr, err := e.run(context.Background(), newDispatch(Principal{Account: "alice"}, Selector{}, nodeSet(3), mutateRawExec()))
	if !errors.Is(err, errDispatchPanicked) {
		t.Fatalf("run() error = %v, want the worker panic", err)
	}
	if got := c.dispatchedNodes(); len(got) != 1 || got[0] != "node-1" {
		t.Errorf("dispatched = %v, want only node-1", got)
	}
	if dr.halt.NodeID != "node-1" || dr.halt.Outcome != jobs.OutcomeFailure || dr.halt.Resolved {
		t.Errorf("halt = %+v, want node-1 failure without a recorded result", dr.halt)
	}
	tasks := tasksByNode(t, tasksRepo, dr.jobID)
	for _, n := range []string{"node-2", "node-3"} {
		requireHaltCancelledByNode(t, tasks[n], "node-1")
	}
}

// TestJobGate_AdmitWaitsForADecidingTask: a Task deciding whether it halts the
// Job holds admission until it ends or the gate closes.
func TestJobGate_AdmitWaitsForADecidingTask(t *testing.T) {
	newGate := func() *jobGate {
		g := &jobGate{}
		g.cond = sync.NewCond(&g.mu)
		return g
	}
	type admitResult struct {
		admitted bool
		marked   bool
	}
	admitAsync := func(g *jobGate) <-chan admitResult {
		out := make(chan admitResult, 1)
		go func() {
			var marked bool
			admitted, _ := g.admit(func() error { marked = true; return nil })
			out <- admitResult{admitted, marked}
		}()
		return out
	}
	requireWaiting := func(t *testing.T, out <-chan admitResult) {
		t.Helper()
		select {
		case r := <-out:
			t.Fatalf("admit returned %+v while a Task was deciding", r)
		case <-time.After(30 * time.Millisecond):
		}
	}

	t.Run("a Task that does not halt releases it", func(t *testing.T) {
		g := newGate()
		g.beginDeciding("task-1")
		out := admitAsync(g)
		requireWaiting(t, out)
		g.endDeciding("task-1")
		if r := waitFor(t, out, "admit"); !r.admitted || !r.marked {
			t.Errorf("admit = %+v, want admitted", r)
		}
	})
	t.Run("a halt refuses it", func(t *testing.T) {
		g := newGate()
		g.beginDeciding("task-1")
		out := admitAsync(g)
		requireWaiting(t, out)
		if !g.markHalted(jobs.Halt{TaskID: "task-1", NodeID: "node-1", Outcome: jobs.OutcomeFailure}) {
			t.Fatal("markHalted = false, want true")
		}
		if r := waitFor(t, out, "admit"); r.admitted || r.marked {
			t.Errorf("admit = %+v, want refused", r)
		}
	})
	t.Run("a cancel refuses it", func(t *testing.T) {
		g := newGate()
		g.beginDeciding("task-1")
		out := admitAsync(g)
		requireWaiting(t, out)
		g.markCancelled()
		if r := waitFor(t, out, "admit"); r.admitted || r.marked {
			t.Errorf("admit = %+v, want refused", r)
		}
	})
	t.Run("the first halt wins, and its Task may close it again", func(t *testing.T) {
		g := newGate()
		first := jobs.Halt{TaskID: "task-1", NodeID: "node-1", Outcome: jobs.OutcomeFailure}
		if !g.markHalted(first) {
			t.Error("markHalted = false, want true for the first halt")
		}
		if !g.markHalted(first) {
			t.Error("markHalted by the halting Task again = false, want true")
		}
		if g.markHalted(jobs.Halt{TaskID: "task-2", NodeID: "node-2", Outcome: jobs.OutcomeTimeout}) {
			t.Error("markHalted by another Task = true, want the first halt to win")
		}
		g.settleHalt("task-2", true)
		if h, _ := g.haltedBy(); h.Resolved {
			t.Error("settleHalt by a Task that does not own the halt changed it")
		}
		g.settleHalt("task-1", true)
		if h, _ := g.haltedBy(); !h.Resolved || h.NodeID != "node-1" {
			t.Errorf("halt = %+v, want node-1's, settled", h)
		}
	})
}

// TestJobEngine_HaltAfterAdmitWithholdsThroughTheGuard: a Task past
// MarkDispatched and not yet at its send guard when a sibling's failure closes
// the gate is withheld by the guard, which commits it cancelled with the halt as
// its reason and no DispatchedAt, and it is never in flight. A cancel recorded
// as well wins: the Task is then plainly cancelled.
func TestJobEngine_HaltAfterAdmitWithholdsThroughTheGuard(t *testing.T) {
	for _, tc := range []struct {
		name   string
		cancel bool
	}{{"halt", false}, {"cancel wins over halt", true}} {
		t.Run(tc.name, func(t *testing.T) {
			var mu sync.Mutex
			var sent []string
			var jobID atomic.Value
			node2Past := make(chan struct{}) // node-2 is past MarkDispatched, before its guard
			release2 := make(chan struct{})
			c := newScriptConduit()
			c.dispatchFn = func(ctx context.Context, n string, task jobs.Task) (jobs.Result, error) {
				jobID.Store(task.JobID)
				switch n {
				case "node-2":
					close(node2Past)
					<-release2
				case "node-1":
					<-node2Past
					mu.Lock()
					sent = append(sent, n)
					mu.Unlock()
					return jobs.Result{Outcome: jobs.OutcomeFailure}, nil
				}
				if jobs.SendWithheld(ctx) {
					return jobs.Result{}, jobs.ErrSendWithheld
				}
				mu.Lock()
				sent = append(sent, n)
				mu.Unlock()
				return jobs.Result{Outcome: jobs.OutcomeSuccess}, nil
			}
			e, tasksRepo := newConcurrentEngine(t, c, 2)

			type outcome struct {
				dr  dispatchResult
				err error
			}
			done := make(chan outcome, 1)
			go func() {
				dr, err := e.run(context.Background(), newDispatch(Principal{Account: "alice"}, Selector{}, nodeSet(3), mutateRawExec()))
				done <- outcome{dr, err}
			}()

			// node-1's failure closes the gate; node-3 is then halt-cancelled
			// without being sent, while node-2 still waits before its guard.
			waitUntil(t, "node-3 to be halt-cancelled", func() bool {
				id, ok := jobID.Load().(string)
				if !ok {
					return false
				}
				tasks, err := tasksRepo.ByJob(context.Background(), id)
				if err != nil || len(tasks) != 3 {
					return false
				}
				for _, task := range tasks {
					if task.NodeID == "node-3" && task.State == jobs.DispatchStateResolved {
						return true
					}
				}
				return false
			})
			if tc.cancel {
				if err := e.cancel(context.Background(), jobID.Load().(string)); err != nil {
					t.Fatalf("cancel: %v", err)
				}
			}
			close(release2)
			got := waitFor(t, done, "run to return")
			if got.err != nil {
				t.Fatalf("run() error = %v", got.err)
			}

			mu.Lock()
			if len(sent) != 1 || sent[0] != "node-1" {
				t.Errorf("sent = %v, want only node-1", sent)
			}
			mu.Unlock()
			tasks := tasksByNode(t, tasksRepo, got.dr.jobID)
			held := tasks["node-2"]
			if tc.cancel {
				if held.State != jobs.DispatchStateResolved || held.Outcome != jobs.OutcomeCancelled ||
					!held.DispatchedAt.IsZero() || len(held.Stderr) != 0 {
					t.Errorf("Task[node-2] = %+v, want plainly cancelled and never sent", held)
				}
			} else {
				requireHaltCancelled(t, held, got.dr.halt.Reason())
			}
			for _, r := range got.dr.results {
				if r.NodeID == "node-2" && r.Outcome != jobs.OutcomeCancelled {
					t.Errorf("result for node-2 = %v, want cancelled", r.Outcome)
				}
			}
			if tasks["node-1"].Outcome != jobs.OutcomeFailure {
				t.Errorf("Task[node-1] outcome = %v, want its real failure", tasks["node-1"].Outcome)
			}
			requireNoTaskInFlight(t, tasksRepo)
		})
	}
}
