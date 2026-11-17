package capability

import (
	"context"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/Felag-Engineering/relay/relay/internal/jobs"
	"github.com/Felag-Engineering/relay/relay/internal/registry"
)

// stateAtSendConduit reads each Task back from the store at the moment it is
// sent, so a test sees the state the store held then rather than the state it
// holds after the engine has finished.
type stateAtSendConduit struct {
	*fakeConduit
	tasks jobs.TaskRepository

	mu      sync.Mutex
	sends   map[string]int
	atSend  map[string]jobs.DispatchState // state at the first send
	readErr error
}

func (c *stateAtSendConduit) Dispatch(ctx context.Context, nodeID string, task jobs.Task) (jobs.Result, error) {
	stored, err := c.tasks.Get(ctx, task.ID)
	c.mu.Lock()
	if err != nil {
		if c.readErr == nil {
			c.readErr = err
		}
	} else if c.sends[task.ID] == 0 {
		c.atSend[task.ID] = stored.State
	}
	c.sends[task.ID]++
	c.mu.Unlock()
	return c.fakeConduit.Dispatch(ctx, nodeID, task)
}

// TestInvariant4_ATaskIsMarkedDispatchedBeforeItIsSent holds invariant 4: a
// Task ID seen once is never executed twice.
// At the moment each Task is sent the store already holds it as Dispatched, so
// a send that never returns leaves it in flight.
// Proves EX-30.
func TestInvariant4_ATaskIsMarkedDispatchedBeforeItIsSent(t *testing.T) {
	jobsRepo, tasksRepo := testEngineStore(t)
	conduit := newFakeConduit(nil)
	nodes := []registry.Node{testNode("node-1"), testNode("node-2"), testNode("node-3")}
	for _, n := range nodes {
		conduit.connected[n.NodeID] = true
		conduit.results[n.NodeID] = jobs.Result{Outcome: jobs.OutcomeSuccess}
	}
	atSend := &stateAtSendConduit{fakeConduit: conduit, tasks: tasksRepo, sends: map[string]int{}, atSend: map[string]jobs.DispatchState{}}

	e := &jobEngine{
		jobsRepo:  jobsRepo,
		tasksRepo: tasksRepo,
		intents:   &nonAtomicIntents{tr: tasksRepo},
		conduit:   atSend,
		newID:     sequentialIDs("id-"),
		now:       func() time.Time { return time.Date(2026, 7, 8, 0, 0, 0, 0, time.UTC) },
		settings:  concurrencyOf(16),
	}
	act := jobs.Action{Kind: jobs.ActionOperation, OperationName: "system.facts", RiskClass: jobs.RiskClassRead}
	d := newDispatch(Principal{Account: "alice"}, Selector{}, nodes, act)

	if _, err := e.run(context.Background(), d); err != nil {
		t.Fatalf("run: %v", err)
	}

	atSend.mu.Lock()
	defer atSend.mu.Unlock()
	if atSend.readErr != nil {
		t.Fatalf("reading a Task back at send: %v", atSend.readErr)
	}
	if len(atSend.atSend) != 3 {
		t.Fatalf("%d Tasks were sent, want 3: %v", len(atSend.atSend), atSend.atSend)
	}
	for id, state := range atSend.atSend {
		if state != jobs.DispatchStateDispatched {
			t.Errorf("Task %q was %v at the moment it was sent, want Dispatched", id, state)
		}
	}

	for id, n := range atSend.sends {
		if n != 1 {
			t.Errorf("Task %q was sent %d times, want exactly once", id, n)
		}
	}

	stored, err := tasksRepo.ByJob(context.Background(), "job-id-1")
	if err != nil {
		t.Fatalf("ByJob: %v", err)
	}
	var storedIDs, sentIDs []string
	for _, task := range stored {
		storedIDs = append(storedIDs, task.ID)
	}
	for id := range atSend.atSend {
		sentIDs = append(sentIDs, id)
	}
	sort.Strings(storedIDs)
	sort.Strings(sentIDs)
	if len(storedIDs) != len(sentIDs) {
		t.Fatalf("sent Task IDs %v, stored Task IDs %v", sentIDs, storedIDs)
	}
	for i := range storedIDs {
		if storedIDs[i] != sentIDs[i] {
			t.Fatalf("sent Task IDs %v, stored Task IDs %v", sentIDs, storedIDs)
		}
	}
}
