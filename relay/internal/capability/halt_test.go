package capability

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Felag-Engineering/relay/relay/internal/jobs"
	"github.com/Felag-Engineering/relay/relay/internal/registry"
)

// These tests prove #1150: a mutate Job stops sending after its first failure
// or timeout (execution.md, Halting a failing mutation), decided in the
// capability layer.

func mutateRawExec() jobs.Action {
	return jobs.Action{Kind: jobs.ActionRawExec, RawExecArgv: []string{"/bin/true"}, RiskClass: jobs.RiskClassMutate}
}

func readFacts() jobs.Action {
	return jobs.Action{Kind: jobs.ActionOperation, OperationName: "system.facts", RiskClass: jobs.RiskClassRead}
}

func tasksByNode(t *testing.T, repo jobs.TaskRepository, jobID string) map[string]jobs.Task {
	t.Helper()
	tasks, err := repo.ByJob(context.Background(), jobID)
	if err != nil {
		t.Fatalf("ByJob: %v", err)
	}
	out := make(map[string]jobs.Task, len(tasks))
	for _, task := range tasks {
		out[task.NodeID] = task
	}
	return out
}

func requireNoTaskInFlight(t *testing.T, repo jobs.TaskRepository) {
	t.Helper()
	inFlight, err := repo.InFlight(context.Background())
	if err != nil {
		t.Fatalf("InFlight: %v", err)
	}
	if len(inFlight) != 0 {
		t.Errorf("InFlight = %v, want none", inFlight)
	}
}

// requireHaltCancelled fails unless task is a never-sent Task its Job's halt
// resolved cancelled with reason as its stderr.
func requireHaltCancelled(t *testing.T, task jobs.Task, reason string) {
	t.Helper()
	if task.State != jobs.DispatchStateResolved || task.Outcome != jobs.OutcomeCancelled {
		t.Errorf("Task[%s] = state %v outcome %v, want Resolved/cancelled", task.NodeID, task.State, task.Outcome)
	}
	if !task.DispatchedAt.IsZero() {
		t.Errorf("Task[%s] DispatchedAt = %v, want zero (never sent)", task.NodeID, task.DispatchedAt)
	}
	if string(task.Stderr) != reason {
		t.Errorf("Task[%s] stderr = %q, want the halt's reason %q", task.NodeID, task.Stderr, reason)
	}
}

// waitUntil polls cond until it holds, failing the test after testWaitTimeout.
func waitUntil(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(testWaitTimeout)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(time.Millisecond)
	}
}

func sameHalt(a, b jobs.Halt) bool {
	return a.TaskID == b.TaskID && a.NodeID == b.NodeID && a.Outcome == b.Outcome &&
		a.Resolved == b.Resolved && a.At.Equal(b.At)
}

// failNode returns a dispatchFn that gives node the result res and every other
// Node a success.
func failNode(node string, res jobs.Result) func(context.Context, string, jobs.Task) (jobs.Result, error) {
	return func(_ context.Context, n string, _ jobs.Task) (jobs.Result, error) {
		if n == node {
			return res, nil
		}
		return jobs.Result{Outcome: jobs.OutcomeSuccess}, nil
	}
}

// TestJobEngine_MutateJobHaltsOnFailureOrTimeout: #1150's acceptance. The first
// Task to resolve failure or timeout stops a mutate Job sending; every Task not
// yet sent resolves cancelled with the halt as its reason, and the halt is
// recorded on the Job.
func TestJobEngine_MutateJobHaltsOnFailureOrTimeout(t *testing.T) {
	for _, outcome := range []jobs.Outcome{jobs.OutcomeFailure, jobs.OutcomeTimeout} {
		t.Run(jobs.OutcomeName(outcome), func(t *testing.T) {
			c := newScriptConduit()
			c.dispatchFn = failNode("node-1", jobs.Result{Outcome: outcome})
			e, tasksRepo := newConcurrentEngine(t, c, 1)

			dr, err := e.run(context.Background(), newDispatch(Principal{Account: "alice"}, Selector{}, nodeSet(4), mutateRawExec()))
			if err != nil {
				t.Fatalf("run() error = %v, want nil", err)
			}
			if got := c.dispatchedNodes(); len(got) != 1 || got[0] != "node-1" {
				t.Fatalf("dispatched = %v, want only [node-1]", got)
			}
			job, err := e.jobsRepo.GetJob(context.Background(), dr.jobID)
			if err != nil {
				t.Fatalf("GetJob: %v", err)
			}
			tasks := tasksByNode(t, tasksRepo, dr.jobID)
			want := jobs.Halt{TaskID: tasks["node-1"].ID, NodeID: "node-1", Outcome: outcome, Resolved: true}
			if job.Halt.TaskID != want.TaskID || job.Halt.NodeID != want.NodeID || job.Halt.Outcome != want.Outcome || !job.Halt.Resolved {
				t.Fatalf("Job.Halt = %+v, want %+v", job.Halt, want)
			}
			if !sameHalt(dr.halt, job.Halt) {
				t.Errorf("dispatchResult.halt = %+v, want the stored %+v", dr.halt, job.Halt)
			}
			if !strings.Contains(job.Halt.Reason(), "resolved "+jobs.OutcomeName(outcome)) {
				t.Errorf("Reason() = %q, want it to say the Task resolved %s", job.Halt.Reason(), jobs.OutcomeName(outcome))
			}
			if tasks["node-1"].Outcome != outcome {
				t.Errorf("Task[node-1] outcome = %v, want its real %v", tasks["node-1"].Outcome, outcome)
			}
			for _, n := range []string{"node-2", "node-3", "node-4"} {
				requireHaltCancelled(t, tasks[n], job.Halt.Reason())
			}
			for _, r := range dr.results[1:] {
				if r.Outcome != jobs.OutcomeCancelled || string(r.Stderr) != job.Halt.Reason() {
					t.Errorf("result[%s] = %v %q, want cancelled with the halt's reason", r.NodeID, r.Outcome, r.Stderr)
				}
			}
			requireNoTaskInFlight(t, tasksRepo)
		})
	}
}

// TestJobEngine_UnspecifiedClassHaltsLikeMutate: an unspecified class fails
// closed into the halting lane.
func TestJobEngine_UnspecifiedClassHaltsLikeMutate(t *testing.T) {
	c := newScriptConduit()
	c.dispatchFn = failNode("node-1", jobs.Result{Outcome: jobs.OutcomeFailure})
	e, _ := newConcurrentEngine(t, c, 1)
	act := mutateRawExec()
	act.RiskClass = jobs.RiskClassUnspecified

	dr, err := e.run(context.Background(), newDispatch(Principal{Account: "alice"}, Selector{}, nodeSet(3), act))
	if err != nil {
		t.Fatalf("run() error = %v", err)
	}
	if !dr.halt.Halted() || len(c.dispatchedNodes()) != 1 {
		t.Errorf("halt = %+v, dispatched = %v, want a halt after the first Node", dr.halt, c.dispatchedNodes())
	}
}

// TestJobEngine_HaltOnAnIncompleteSendNamesTheTaskUnresolved: when the engine
// reports failure for a Task whose send did not complete, the Job still halts
// (fail closed), but the halt says the Task has no recorded result, and the
// Task stays in flight.
func TestJobEngine_HaltOnAnIncompleteSendNamesTheTaskUnresolved(t *testing.T) {
	sendErr := errors.New("tunnel write failed")
	for _, tc := range []struct {
		name string
		err  error
	}{
		{"conduit error", sendErr},
		{"replaced stream", fmt.Errorf("send: %w", jobs.ErrStreamReplaced)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := newScriptConduit()
			c.dispatchFn = func(_ context.Context, n string, _ jobs.Task) (jobs.Result, error) {
				if n == "node-1" {
					return jobs.Result{}, tc.err
				}
				return jobs.Result{Outcome: jobs.OutcomeSuccess}, nil
			}
			e, tasksRepo := newConcurrentEngine(t, c, 1)

			dr, err := e.run(context.Background(), newDispatch(Principal{Account: "alice"}, Selector{}, nodeSet(3), mutateRawExec()))
			if !errors.Is(err, tc.err) {
				t.Fatalf("run() error = %v, want it to wrap the dispatch error", err)
			}
			job, gerr := e.jobsRepo.GetJob(context.Background(), dr.jobID)
			if gerr != nil {
				t.Fatalf("GetJob: %v", gerr)
			}
			tasks := tasksByNode(t, tasksRepo, dr.jobID)
			if tasks["node-1"].State != jobs.DispatchStateDispatched {
				t.Fatalf("Task[node-1] state = %v, want it still Dispatched", tasks["node-1"].State)
			}
			if job.Halt.NodeID != "node-1" || job.Halt.Outcome != jobs.OutcomeFailure || job.Halt.Resolved {
				t.Fatalf("Job.Halt = %+v, want node-1, failure, not resolved", job.Halt)
			}
			reason := job.Halt.Reason()
			if !strings.Contains(reason, "with no recorded result") || strings.Contains(reason, "resolved failure") {
				t.Errorf("Reason() = %q, want 'with no recorded result' and never 'resolved failure'", reason)
			}
			for _, n := range []string{"node-2", "node-3"} {
				requireHaltCancelled(t, tasks[n], reason)
			}
			if got := c.dispatchedNodes(); len(got) != 1 {
				t.Errorf("dispatched = %v, want only node-1", got)
			}
			inFlight, _ := tasksRepo.InFlight(context.Background())
			if len(inFlight) != 1 || inFlight[0].NodeID != "node-1" {
				t.Errorf("InFlight = %v, want only the halting Task", inFlight)
			}
		})
	}
}

// TestJobEngine_HaltOnANodeGoingOfflineAfterSendIsResolved: a Node that goes
// offline with a Task in flight resolves that Task failure, which halts a
// mutate Job with a recorded result.
func TestJobEngine_HaltOnANodeGoingOfflineAfterSendIsResolved(t *testing.T) {
	var offline atomic.Bool
	c := newScriptConduit()
	c.connectedFn = func(n string) bool { return n != "node-1" || !offline.Load() }
	c.dispatchFn = func(_ context.Context, n string, _ jobs.Task) (jobs.Result, error) {
		if n == "node-1" {
			offline.Store(true)
			return jobs.Result{}, errors.New("stream ended")
		}
		return jobs.Result{Outcome: jobs.OutcomeSuccess}, nil
	}
	e, tasksRepo := newConcurrentEngine(t, c, 1)

	dr, err := e.run(context.Background(), newDispatch(Principal{Account: "alice"}, Selector{}, nodeSet(3), mutateRawExec()))
	if err != nil {
		t.Fatalf("run() error = %v", err)
	}
	if !dr.halt.Halted() || dr.halt.NodeID != "node-1" || !dr.halt.Resolved || dr.halt.Outcome != jobs.OutcomeFailure {
		t.Fatalf("halt = %+v, want node-1 failure with a recorded result", dr.halt)
	}
	tasks := tasksByNode(t, tasksRepo, dr.jobID)
	if tasks["node-1"].State != jobs.DispatchStateResolved || tasks["node-1"].Outcome != jobs.OutcomeFailure {
		t.Errorf("Task[node-1] = %v/%v, want Resolved/failure", tasks["node-1"].State, tasks["node-1"].Outcome)
	}
	requireHaltCancelled(t, tasks["node-2"], dr.halt.Reason())
	requireNoTaskInFlight(t, tasksRepo)
}

// secondGetPanics panics on the second Get of any one Task: the first is
// dispatchOne's storedResolution, the second is the halt's own read.
type secondGetPanics struct {
	jobs.TaskRepository
	mu   sync.Mutex
	gets map[string]int
}

func (s *secondGetPanics) Get(ctx context.Context, taskID string) (jobs.Task, error) {
	s.mu.Lock()
	s.gets[taskID]++
	n := s.gets[taskID]
	s.mu.Unlock()
	if n == 2 {
		panic("secret-bearing halt panic")
	}
	return s.TaskRepository.Get(ctx, taskID)
}

// TestJobEngine_HaltPanicStillClosesTheGate: a panic inside the halt itself
// neither ends the process nor leaves the Job sending.
func TestJobEngine_HaltPanicStillClosesTheGate(t *testing.T) {
	jobsRepo, tasksRepo := testEngineStore(t)
	wrapped := &secondGetPanics{TaskRepository: tasksRepo, gets: map[string]int{}}
	c := newScriptConduit()
	c.dispatchFn = func(_ context.Context, n string, _ jobs.Task) (jobs.Result, error) {
		if n == "node-1" {
			return jobs.Result{}, errors.New("tunnel write failed")
		}
		return jobs.Result{Outcome: jobs.OutcomeSuccess}, nil
	}
	e := &jobEngine{
		jobsRepo:  jobsRepo,
		tasksRepo: wrapped,
		intents:   &nonAtomicIntents{tr: tasksRepo},
		conduit:   c,
		newID:     sequentialIDs("id-"),
		now:       func() time.Time { return time.Date(2026, 10, 8, 0, 0, 0, 0, time.UTC) },
		settings:  concurrencyOf(1),
	}

	dr, err := e.run(context.Background(), newDispatch(Principal{Account: "alice"}, Selector{}, nodeSet(3), mutateRawExec()))
	if !errors.Is(err, errDispatchPanicked) || !strings.Contains(err.Error(), "capability: halt job") {
		t.Fatalf("run() error = %v, want the halt's own panic wrapping errDispatchPanicked", err)
	}
	if strings.Contains(err.Error(), "secret-bearing") {
		t.Errorf("run() error %q leaks the panic value", err)
	}
	if got := c.dispatchedNodes(); len(got) != 1 {
		t.Errorf("dispatched = %v, want only node-1 after the halt panicked", got)
	}
	if !dr.halt.Halted() || dr.halt.Resolved {
		t.Fatalf("halt = %+v, want a halt that does not claim a recorded result", dr.halt)
	}
	tasks := tasksByNode(t, tasksRepo, dr.jobID)
	for _, n := range []string{"node-2", "node-3"} {
		requireHaltCancelled(t, tasks[n], dr.halt.Reason())
	}
}

// TestJobEngine_NonHaltingOutcomesDoNotHalt: denied_by_policy, unsupported and
// unreachable do not halt a mutate Job, nor do the outcomes that never ran.
func TestJobEngine_NonHaltingOutcomesDoNotHalt(t *testing.T) {
	tests := []struct {
		name string
		// setup shapes the first Node's outcome; it returns the Nodes to
		// dispatch and the Nodes it expects to reach the Conduit.
		setup func(c *scriptConduit) (nodes []registry.Node, excluded []excludedNode, wantDispatched int)
	}{
		{"success", func(c *scriptConduit) ([]registry.Node, []excludedNode, int) {
			return nodeSet(3), nil, 3
		}},
		{"denied_by_policy", func(c *scriptConduit) ([]registry.Node, []excludedNode, int) {
			c.dispatchFn = failNode("node-1", jobs.Result{Outcome: jobs.OutcomeDeniedByPolicy})
			return nodeSet(3), nil, 3
		}},
		{"unsupported reported by the daemon", func(c *scriptConduit) ([]registry.Node, []excludedNode, int) {
			c.dispatchFn = failNode("node-1", jobs.Result{Outcome: jobs.OutcomeUnsupported})
			return nodeSet(3), nil, 3
		}},
		{"unsupported excluded by the Relay", func(c *scriptConduit) ([]registry.Node, []excludedNode, int) {
			return nodeSet(3)[1:], []excludedNode{{node: testNode("node-1"), reason: "not reported"}}, 2
		}},
		{"unreachable", func(c *scriptConduit) ([]registry.Node, []excludedNode, int) {
			c.connectedFn = func(n string) bool { return n != "node-1" }
			return nodeSet(3), nil, 2
		}},
		{"version_refused", func(c *scriptConduit) ([]registry.Node, []excludedNode, int) {
			nodes := nodeSet(3)
			nodes[0].Outdated = true
			return nodes, nil, 2
		}},
		{"cancelled reported by the daemon", func(c *scriptConduit) ([]registry.Node, []excludedNode, int) {
			c.dispatchFn = failNode("node-1", jobs.Result{Outcome: jobs.OutcomeCancelled})
			return nodeSet(3), nil, 3
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := newScriptConduit()
			nodes, excluded, wantDispatched := tt.setup(c)
			e, _ := newConcurrentEngine(t, c, 1)
			d := newDispatch(Principal{Account: "alice"}, Selector{}, nodes, mutateRawExec())
			d.excluded = excluded

			dr, err := e.run(context.Background(), d)
			if err != nil {
				t.Fatalf("run() error = %v", err)
			}
			if dr.halt.Halted() {
				t.Errorf("halt = %+v, want none", dr.halt)
			}
			if got := c.dispatchedNodes(); len(got) != wantDispatched {
				t.Errorf("dispatched = %v, want %d Nodes reached", got, wantDispatched)
			}
			job, _ := e.jobsRepo.GetJob(context.Background(), dr.jobID)
			if job.Halt.Halted() {
				t.Errorf("Job.Halt = %+v, want none", job.Halt)
			}
		})
	}
}

// TestJobEngine_ReadJobNeverHalts: a read Job sends to every Node whatever
// fails.
func TestJobEngine_ReadJobNeverHalts(t *testing.T) {
	for _, outcome := range []jobs.Outcome{jobs.OutcomeFailure, jobs.OutcomeTimeout} {
		t.Run(jobs.OutcomeName(outcome), func(t *testing.T) {
			c := newScriptConduit()
			c.dispatchFn = failNode("node-1", jobs.Result{Outcome: outcome})
			e, _ := newConcurrentEngine(t, c, 1)

			dr, err := e.run(context.Background(), newDispatch(Principal{Account: "alice"}, Selector{}, nodeSet(3), readFacts()))
			if err != nil {
				t.Fatalf("run() error = %v", err)
			}
			if dr.halt.Halted() || len(c.dispatchedNodes()) != 3 {
				t.Errorf("halt = %+v, dispatched = %v, want no halt and every Node reached", dr.halt, c.dispatchedNodes())
			}
		})
	}
}

// TestJobEngine_HaltLetsInFlightTasksFinishWithinTheBound: a Task in flight
// when the Job halts finishes and reports its real outcome, and the halt never
// raises the number of Tasks in flight past the dispatch bound.
func TestJobEngine_HaltLetsInFlightTasksFinishWithinTheBound(t *testing.T) {
	var peak peakTracker
	var jobID atomic.Value
	release := make(chan struct{})
	node1Sent := make(chan struct{})
	c := newScriptConduit()
	c.dispatchFn = func(_ context.Context, n string, task jobs.Task) (jobs.Result, error) {
		jobID.Store(task.JobID)
		peak.enter()
		defer peak.leave()
		if n == "node-1" {
			close(node1Sent)
			<-release
			return jobs.Result{Outcome: jobs.OutcomeSuccess, Stdout: []byte("done")}, nil
		}
		// A Task not yet admitted when the Job halts is correctly left unsent;
		// the scenario is node-1 in flight, so node-2 fails only after it is.
		<-node1Sent
		return jobs.Result{Outcome: jobs.OutcomeFailure}, nil
	}
	e, tasksRepo := newConcurrentEngine(t, c, 2)

	type outcome struct {
		dr  dispatchResult
		err error
	}
	done := make(chan outcome, 1)
	go func() {
		dr, err := e.run(context.Background(), newDispatch(Principal{Account: "alice"}, Selector{}, nodeSet(4), mutateRawExec()))
		done <- outcome{dr, err}
	}()

	// node-2 fails at once and halts the Job; its slot then resolves node-3 and
	// node-4 without sending them, while node-1 is still in flight.
	waitUntil(t, "node-3 and node-4 to be halt-cancelled", func() bool {
		id, ok := jobID.Load().(string)
		if !ok {
			return false
		}
		tasks, err := tasksRepo.ByJob(context.Background(), id)
		if err != nil || len(tasks) != 4 {
			return false
		}
		for _, task := range tasks {
			if (task.NodeID == "node-3" || task.NodeID == "node-4") && task.State != jobs.DispatchStateResolved {
				return false
			}
		}
		return true
	})
	close(release)
	got := waitFor(t, done, "run to return")
	if got.err != nil {
		t.Fatalf("run() error = %v", got.err)
	}

	tasks := tasksByNode(t, tasksRepo, got.dr.jobID)
	if n1 := tasks["node-1"]; n1.Outcome != jobs.OutcomeSuccess || n1.DispatchedAt.IsZero() || string(n1.Stdout) != "done" {
		t.Errorf("Task[node-1] = %+v, want its real success", n1)
	}
	if tasks["node-2"].Outcome != jobs.OutcomeFailure {
		t.Errorf("Task[node-2] outcome = %v, want failure", tasks["node-2"].Outcome)
	}
	for _, n := range []string{"node-3", "node-4"} {
		requireHaltCancelled(t, tasks[n], got.dr.halt.Reason())
	}
	if got.dr.halt.NodeID != "node-2" {
		t.Errorf("halt names %q, want node-2", got.dr.halt.NodeID)
	}
	if p := peak.peak.Load(); p > 2 {
		t.Errorf("peak concurrent dispatches = %d, want at most the bound 2", p)
	}
	requireNoTaskInFlight(t, tasksRepo)
}

// TestJobEngine_FirstHaltWins: two Tasks failing together in flight record one
// halt, and the Job row holds that one.
func TestJobEngine_FirstHaltWins(t *testing.T) {
	var barrier sync.WaitGroup
	barrier.Add(2)
	c := newScriptConduit()
	c.dispatchFn = func(_ context.Context, _ string, _ jobs.Task) (jobs.Result, error) {
		// Both calls return only once both have entered, so both were in
		// flight together.
		barrier.Done()
		barrier.Wait()
		return jobs.Result{Outcome: jobs.OutcomeFailure}, nil
	}
	e, tasksRepo := newConcurrentEngine(t, c, 2)

	dr, err := e.run(context.Background(), newDispatch(Principal{Account: "alice"}, Selector{}, nodeSet(2), mutateRawExec()))
	if err != nil {
		t.Fatalf("run() error = %v", err)
	}
	job, err := e.jobsRepo.GetJob(context.Background(), dr.jobID)
	if err != nil {
		t.Fatalf("GetJob: %v", err)
	}
	if !dr.halt.Halted() || (dr.halt.NodeID != "node-1" && dr.halt.NodeID != "node-2") {
		t.Fatalf("halt = %+v, want exactly one of the two Nodes", dr.halt)
	}
	if !sameHalt(job.Halt, dr.halt) {
		t.Errorf("Job.Halt = %+v, want the halt the Job reported, %+v", job.Halt, dr.halt)
	}
	for n, task := range tasksByNode(t, tasksRepo, dr.jobID) {
		if task.Outcome != jobs.OutcomeFailure {
			t.Errorf("Task[%s] outcome = %v, want its real failure", n, task.Outcome)
		}
	}
}

// TestJobEngine_CancelledJobIsNotHalted: a Job cancelled before its Task fails
// is a cancelled Job, not a halted one, and its Pending Tasks carry no halt
// reason.
func TestJobEngine_CancelledJobIsNotHalted(t *testing.T) {
	c := newScriptConduit()
	e, tasksRepo := newConcurrentEngine(t, c, 1)
	c.dispatchFn = func(ctx context.Context, n string, task jobs.Task) (jobs.Result, error) {
		if err := e.cancel(ctx, task.JobID); err != nil {
			t.Errorf("cancel: %v", err)
		}
		return jobs.Result{Outcome: jobs.OutcomeFailure}, nil
	}

	dr, err := e.run(context.Background(), newDispatch(Principal{Account: "alice"}, Selector{}, nodeSet(3), mutateRawExec()))
	if err != nil {
		t.Fatalf("run() error = %v", err)
	}
	if dr.halt.Halted() {
		t.Errorf("halt = %+v, want none for a cancelled Job", dr.halt)
	}
	job, _ := e.jobsRepo.GetJob(context.Background(), dr.jobID)
	if job.Halt.Halted() {
		t.Errorf("Job.Halt = %+v, want none", job.Halt)
	}
	tasks := tasksByNode(t, tasksRepo, dr.jobID)
	for _, n := range []string{"node-2", "node-3"} {
		if tasks[n].Outcome != jobs.OutcomeCancelled || len(tasks[n].Stderr) != 0 {
			t.Errorf("Task[%s] = %v %q, want plain cancelled with no stderr", n, tasks[n].Outcome, tasks[n].Stderr)
		}
	}
}

// TestJobEngine_HaltAndCancelRace: a cancel and a halting failure landing
// together at concurrency above one never send a Task after either stop, and
// leave every Task resolved to its real outcome or cancelled. Run under the
// race detector.
func TestJobEngine_HaltAndCancelRace(t *testing.T) {
	const bound, nodes = 4, 8
	for iter := 0; iter < 20; iter++ {
		c := newScriptConduit()
		var entered sync.WaitGroup
		entered.Add(bound)
		var jobID atomic.Value
		releaseFail, releaseOthers := make(chan struct{}), make(chan struct{})
		c.dispatchFn = func(_ context.Context, n string, task jobs.Task) (jobs.Result, error) {
			switch n {
			case "node-1":
				jobID.Store(task.JobID)
				entered.Done()
				<-releaseFail
				return jobs.Result{Outcome: jobs.OutcomeFailure}, nil
			case "node-2", "node-3", "node-4":
				entered.Done()
				<-releaseOthers
			}
			return jobs.Result{Outcome: jobs.OutcomeSuccess}, nil
		}
		e, tasksRepo := newConcurrentEngine(t, c, bound)

		type outcome struct {
			dr  dispatchResult
			err error
		}
		done := make(chan outcome, 1)
		go func() {
			dr, err := e.run(context.Background(), newDispatch(Principal{Account: "alice"}, Selector{}, nodeSet(nodes), mutateRawExec()))
			done <- outcome{dr, err}
		}()
		entered.Wait()

		cancelDone := make(chan error, 1)
		go func() { cancelDone <- e.cancel(context.Background(), jobID.Load().(string)) }()
		close(releaseFail)
		if err := waitFor(t, cancelDone, "cancel to return"); err != nil {
			t.Fatalf("iteration %d: cancel: %v", iter, err)
		}
		close(releaseOthers)
		got := waitFor(t, done, "run to return")
		if got.err != nil {
			t.Fatalf("iteration %d: run() error = %v", iter, got.err)
		}

		if n := len(c.dispatchedNodes()); n != bound {
			t.Fatalf("iteration %d: %d Dispatch calls, want exactly %d (none after either stop)", iter, n, bound)
		}
		job, _ := e.jobsRepo.GetJob(context.Background(), got.dr.jobID)
		tasks := tasksByNode(t, tasksRepo, got.dr.jobID)
		for n, task := range tasks {
			if task.State != jobs.DispatchStateResolved {
				t.Errorf("iteration %d: Task[%s] state = %v, want Resolved", iter, n, task.State)
			}
		}
		if tasks["node-1"].Outcome != jobs.OutcomeFailure {
			t.Errorf("iteration %d: Task[node-1] outcome = %v, want its real failure", iter, tasks["node-1"].Outcome)
		}
		for _, n := range []string{"node-2", "node-3", "node-4"} {
			if tasks[n].Outcome != jobs.OutcomeSuccess {
				t.Errorf("iteration %d: Task[%s] outcome = %v, want its real success", iter, n, tasks[n].Outcome)
			}
		}
		for i := bound + 1; i <= nodes; i++ {
			task := tasks[fmt.Sprintf("node-%d", i)]
			if task.Outcome != jobs.OutcomeCancelled || !task.DispatchedAt.IsZero() {
				t.Errorf("iteration %d: Task[%s] = %v dispatched %v, want cancelled and never sent", iter, task.NodeID, task.Outcome, task.DispatchedAt)
			}
			// A halt that wins still leaves the cancel to MarkCancelled the
			// Tasks no worker had reached, so a halted Job may show either.
			switch {
			case len(task.Stderr) == 0:
			case !job.Halt.Halted():
				t.Errorf("iteration %d: Task[%s] stderr %q but the Job shows no halt", iter, task.NodeID, task.Stderr)
			case string(task.Stderr) != job.Halt.Reason():
				t.Errorf("iteration %d: Task[%s] stderr = %q, want the halt's reason", iter, task.NodeID, task.Stderr)
			}
		}
		requireNoTaskInFlight(t, tasksRepo)
	}
}

// recordHaltFails is a JobRepository whose RecordHalt always errors.
type recordHaltFails struct {
	jobs.JobRepository
	err error
}

func (r recordHaltFails) RecordHalt(context.Context, string, jobs.Halt) error { return r.err }

// TestJobEngine_HaltStillStopsSendingWhenItsRecordFails: failing to record the
// halt on the Job row never reopens the gate. The Tasks it left unsent still
// carry the reason and the halt is still audited.
func TestJobEngine_HaltStillStopsSendingWhenItsRecordFails(t *testing.T) {
	recordErr := errors.New("store: disk full")
	jobsRepo, tasksRepo := testEngineStore(t)
	spy := &spyAuditSink{}
	var log []string
	conduit := connectedConduit(&log, "node-0", "node-1", "node-2")
	for _, n := range []string{"node-0", "node-1", "node-2"} {
		conduit.results[n] = jobs.Result{Outcome: jobs.OutcomeFailure}
	}
	svc := build(t, seams{
		reg: seedNodes(t, 3), authz: &spyAuthorizer{}, cap: &spyCapChecker{}, audit: spy, freeze: &fakeFreezeStore{},
		jobsRepo: recordHaltFails{JobRepository: jobsRepo, err: recordErr}, tasksRepo: tasksRepo, conduit: conduit,
		settings: concurrencyOf(1),
	})

	results, err := svc.Run(context.Background(), Principal{Account: "alice"}, webSelector(), jobs.Action{Kind: jobs.ActionRawExec, RawExecArgv: []string{"/bin/true"}})
	if !errors.Is(err, recordErr) {
		t.Fatalf("Run error = %v, want it to wrap the record failure", err)
	}
	if len(log) != 1 {
		t.Fatalf("dispatched = %v, want exactly one Task sent", log)
	}
	job, gerr := jobsRepo.GetJob(context.Background(), results[0].JobID)
	if gerr != nil {
		t.Fatalf("GetJob: %v", gerr)
	}
	if job.Halt.Halted() {
		t.Errorf("Job.Halt = %+v, want none: the record failed", job.Halt)
	}
	halt := spy.haltEntry(t)
	cancelled := 0
	for _, task := range tasksByNode(t, tasksRepo, results[0].JobID) {
		if task.Outcome == jobs.OutcomeCancelled {
			cancelled++
			requireHaltCancelled(t, task, halt.Halt.Reason())
		}
	}
	if cancelled != 2 {
		t.Errorf("halt-cancelled Tasks = %d, want the 2 siblings the halt left unsent", cancelled)
	}
}

// haltEntry returns the one AuditKindJobHalt entry the spy recorded.
func (s *spyAuditSink) haltEntry(t *testing.T) AuditEntry {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	var found []AuditEntry
	for _, e := range s.entries {
		if e.Kind == AuditKindJobHalt {
			found = append(found, e)
		}
	}
	if len(found) != 1 {
		t.Fatalf("job halt audit entries = %d, want 1", len(found))
	}
	return found[0]
}

// TestExecution_HaltIsRecordedOnTheJobAndAudited: Run records the halt on the
// Job and audits it as the Relay's act beside the per-Node outcomes.
func TestExecution_HaltIsRecordedOnTheJobAndAudited(t *testing.T) {
	jobsRepo, tasksRepo := testEngineStore(t)
	spy := &spyAuditSink{}
	var log []string
	conduit := connectedConduit(&log, "node-0", "node-1")
	for _, n := range []string{"node-0", "node-1"} {
		conduit.results[n] = jobs.Result{Outcome: jobs.OutcomeFailure}
	}
	svc := build(t, seams{
		reg: seedNodes(t, 2), authz: &spyAuthorizer{}, cap: &spyCapChecker{}, audit: spy, freeze: &fakeFreezeStore{},
		jobsRepo: jobsRepo, tasksRepo: tasksRepo, conduit: conduit, settings: concurrencyOf(1),
	})

	results, err := svc.Run(context.Background(), Principal{Account: "alice"}, webSelector(), jobs.Action{Kind: jobs.ActionRawExec, RawExecArgv: []string{"/bin/true"}})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	jobID := results[0].JobID
	job, err := jobsRepo.GetJob(context.Background(), jobID)
	if err != nil {
		t.Fatalf("GetJob: %v", err)
	}
	if !job.Halt.Halted() || !job.Halt.Resolved || job.Halt.Outcome != jobs.OutcomeFailure {
		t.Fatalf("Job.Halt = %+v, want a recorded failure halt", job.Halt)
	}

	spy.mu.Lock()
	kinds := make([]AuditKind, len(spy.entries))
	for i, e := range spy.entries {
		kinds[i] = e.Kind
	}
	spy.mu.Unlock()
	if len(kinds) != 2 || kinds[0] != AuditKindDispatch || kinds[1] != AuditKindJobHalt {
		t.Fatalf("audit kinds = %v, want [dispatch job_halt]", kinds)
	}
	halt := spy.haltEntry(t)
	if halt.JobID != jobID || !sameHalt(halt.Halt, job.Halt) {
		t.Errorf("halt entry = job %q halt %+v, want job %q halt %+v", halt.JobID, halt.Halt, jobID, job.Halt)
	}
	if !reflect.DeepEqual(halt.Principal, Principal{}) || len(halt.Results) != 0 || halt.Reason != "" {
		t.Errorf("halt entry carries a Principal, Results or Reason: %+v", halt)
	}
}

// TestExecution_HaltAuditCarriesTheApprovalLink: an approval-released Job's
// halt row names the approval and the Grant that released it, as the dispatch
// row does.
func TestExecution_HaltAuditCarriesTheApprovalLink(t *testing.T) {
	spy := &spyAuditSink{}
	svc := build(t, seams{audit: spy})
	halt := jobs.Halt{TaskID: "task-1", NodeID: "node-1", Outcome: jobs.OutcomeTimeout, Resolved: true}
	pr := prep{act: mutateRawExec(), ap: approvalDecision{requestID: "appr-1", grantID: "grant-1"}}

	if _, err := svc.account(context.Background(), Principal{Account: "alice"}, Selector{}, pr,
		dispatchResult{jobID: "job-1", halt: halt}, nil, false); err != nil {
		t.Fatalf("account: %v", err)
	}
	entry := spy.haltEntry(t)
	if entry.ApprovalID != "appr-1" || entry.GrantID != "grant-1" || entry.JobID != "job-1" {
		t.Errorf("halt entry = %+v, want job-1 under approval appr-1 and grant grant-1", entry)
	}
}

// TestExecution_HaltAuditFailureIsSurfaced: a failed halt audit write is
// returned beside the results and never swallowed.
func TestExecution_HaltAuditFailureIsSurfaced(t *testing.T) {
	spy := &spyAuditSink{err: errors.New("audit store down")}
	svc := build(t, seams{audit: spy})
	pr := prep{act: mutateRawExec()}
	halt := jobs.Halt{TaskID: "task-1", NodeID: "node-1", Outcome: jobs.OutcomeFailure}

	_, err := svc.account(context.Background(), Principal{Account: "alice"}, Selector{}, pr,
		dispatchResult{jobID: "job-1", halt: halt}, nil, false)
	if err == nil || !strings.Contains(err.Error(), "job halt audit entry") {
		t.Errorf("account error = %v, want the halt audit failure", err)
	}
}
