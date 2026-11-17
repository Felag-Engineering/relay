package main

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/Felag-Engineering/relay/relay/internal/audit"
	"github.com/Felag-Engineering/relay/relay/internal/capability"
	"github.com/Felag-Engineering/relay/relay/internal/jobs"
	"github.com/Felag-Engineering/relay/relay/internal/relaytest"
)

// jobState reads the Job's derived state from the store.
func jobState(t *testing.T, f *relayFixture, jobID string) jobs.JobState {
	t.Helper()
	page, err := f.Deps.store.JobQueries().QueryJobs(context.Background(), jobs.JobQuery{JobID: jobID}, 1, "")
	if err != nil {
		t.Fatalf("QueryJobs(%s): %v", jobID, err)
	}
	if len(page.Jobs) != 1 {
		t.Fatalf("QueryJobs(%s) = %d Jobs, want 1", jobID, len(page.Jobs))
	}
	return page.Jobs[0].State
}

// dispatchHeld starts a system.facts Job on node without waiting and returns its
// ID, once the Node holds the Task.
func dispatchHeld(t *testing.T, f *relayFixture, node *heldNode) (string, string) {
	t.Helper()
	resp := postDispatch(context.Background(), t, f.ClientFor(""), operationsURL(f), f.Credential,
		map[string]any{"selector": node.selector(), "operation": "system.facts"}, "")
	out := requireDispatch(t, resp)
	if out.JobID == "" || out.JobStatus != "running" {
		t.Fatalf("dispatch = %+v, want a running Job", out)
	}
	return out.JobID, node.nextTask(t).GetTaskId()
}

// A clean shutdown waits for a running Job to finish and write its outcome
// record before it returns, which is where main returns and the process exits.
//
// Proves EX-11.
func TestShutdown_AJobThatFinishesInsideTheBoundHasItsOutcomeWrittenBeforeTheRelayExits(t *testing.T) {
	f := startRelay(t, WithControlPlane())
	node := startHeldNode(t, f)
	jobID, taskID := dispatchHeld(t, f, node)

	if got := recordsOfKind(auditByJob(t, f.Deps.audit, jobID), audit.KindDispatch); len(got) != 0 {
		t.Fatalf("KindDispatch records before the Node answered = %d, want 0", len(got))
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		shutdownRelay(f.Deps, 30*time.Second, slog.New(slog.NewTextHandler(io.Discard, nil)))
	}()

	// New dispatches are refused once the control-plane listener is closed.
	closed := false
	for i := 0; i < 100 && !closed; i++ {
		// A plain GET: it dispatches nothing, so a probe that lands before the
		// listener closes cannot create a second held Job.
		req, rerr := http.NewRequest(http.MethodGet, operationsURL(f), nil)
		if rerr != nil {
			t.Fatal(rerr)
		}
		resp, err := f.ClientFor("").Do(req)
		if err != nil {
			closed = true
			break
		}
		resp.Body.Close()
		time.Sleep(20 * time.Millisecond)
	}
	if !closed {
		t.Fatal("the control plane still accepted a dispatch after the shutdown began")
	}
	select {
	case <-done:
		t.Fatal("the shutdown returned while a Job was still running")
	default:
	}

	node.answer(t, taskID, "facts-out")
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("the shutdown did not return after the Job finished")
	}

	records := recordsOfKind(auditByJob(t, f.Deps.audit, jobID), audit.KindDispatch)
	if len(records) == 0 {
		t.Fatal("no KindDispatch record for the Job when the shutdown returned")
	}
	for _, r := range records {
		if r.NodeID != node.id {
			t.Errorf("KindDispatch record NodeID = %q, want %q", r.NodeID, node.id)
		}
	}
	if got := jobState(t, f, jobID); got != jobs.JobStateComplete {
		t.Fatalf("Job state = %v, want complete", got)
	}
}

// At the bound a Job still running is named in the log by ID, and the shutdown
// neither cancels it nor resolves it: the node plane stays up.
func TestShutdown_AJobStillRunningAtTheBoundIsLoggedByIDAndNeitherCancelledNorResolved(t *testing.T) {
	f := startRelay(t, WithControlPlane())
	node := startHeldNode(t, f)
	jobID, _ := dispatchHeld(t, f, node)

	var logs syncBuffer
	start := time.Now()
	shutdownRelay(f.Deps, 200*time.Millisecond, slog.New(slog.NewTextHandler(&logs, nil)))
	if took := time.Since(start); took > 200*time.Millisecond+shutdownListBudget {
		t.Errorf("the shutdown took %s, want within the bound plus the listing budget", took)
	}

	out := logs.String()
	if !strings.Contains(out, jobID) || !strings.Contains(out, "still running at the drain bound") {
		t.Errorf("log does not name Job %s as still running at the drain bound:\n%s", jobID, out)
	}
	node.noCancel(t, 200*time.Millisecond)
	if got := jobState(t, f, jobID); got != jobs.JobStateRunning {
		t.Fatalf("Job state = %v after the shutdown, want running: nothing may resolve it", got)
	}
}

// A dispatch that reaches Start after the drain began is refused, and both
// adapters carry the capability layer's text, which says nothing ran. This
// pins the existing ErrDraining path in the capability layer: it passes without
// shutdown.go.
func TestShutdown_ADispatchReachingStartAfterTheDrainBeganIsRefusedLegiblyOnBothSurfaces(t *testing.T) {
	f := startRelay(t, WithControlPlane())
	node := startHeldNode(t, f)
	session := relaytest.Connect(t, f.ControlBase, f.Client())

	if err := f.Deps.execution.Drain(context.Background()); err != nil {
		t.Fatalf("Drain: %v", err)
	}
	phrase := strings.TrimPrefix(capability.ErrDraining.Error(), "capability: ")

	resp := postDispatch(context.Background(), t, f.Client(), operationsURL(f), f.Credential,
		map[string]any{"selector": node.selector(), "operation": "system.facts"}, "")
	problem := requireProblem(t, resp, http.StatusInternalServerError)
	if !strings.Contains(problem.Detail, phrase) {
		t.Errorf("Control API problem detail = %q, want it to contain %q", problem.Detail, phrase)
	}

	res := relaytest.CallTool(t, session, "run_operation", map[string]any{
		"selector": node.selector(), "operation": "system.facts",
	})
	if text := relaytest.ToolErrorText(t, res); !strings.Contains(text, phrase) {
		t.Errorf("MCP tool error = %q, want it to contain %q", text, phrase)
	}

	node.noTask(t, 200*time.Millisecond)
}
