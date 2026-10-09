package mcp_test

import (
	"context"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/audit"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/controlplane/mcp"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/jobs"
)

// #895: run_operation and raw_exec return the Job as soon as its Tasks are
// persisted, and a call re-issued with the same idempotency key never
// dispatches a second time.

// blockNodeUntilCleanup makes nodeID's Dispatch block, and unblocks it when the
// test ends. The cleanup is registered after the fixture's, so it runs before
// the fixture's Drain (cleanups run last-in-first-out).
func blockNodeUntilCleanup(t *testing.T, ts testServer, nodeID string) (unblock func()) {
	t.Helper()
	ts.conduit.blockNode = nodeID
	ts.conduit.ready = make(chan struct{})
	ts.conduit.unblock = make(chan struct{})
	var released atomic.Bool
	unblock = func() {
		if released.CompareAndSwap(false, true) {
			close(ts.conduit.unblock)
		}
	}
	t.Cleanup(unblock)
	return unblock
}

// pollJob re-reads jobID through get_job until ok accepts the rendering, or
// fails the test at the deadline.
func pollJob(t *testing.T, session *sdkmcp.ClientSession, jobID string, ok func(mcp.ExecutionOutput) bool) mcp.ExecutionOutput {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		res := callTool(t, session, "get_job", map[string]any{"job_id": jobID})
		var out mcp.ExecutionOutput
		decodeResult(t, res, &out)
		if ok(out) {
			return out
		}
		if time.Now().After(deadline) {
			t.Fatalf("get_job(%s) never reached the wanted state; last = %+v", jobID, out)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func outcomesOf(out mcp.ExecutionOutput) map[string]string {
	m := map[string]string{}
	for _, r := range out.Results {
		m[r.NodeID] = r.Outcome
	}
	return m
}

func countAudit(t *testing.T, ts testServer, kind string) int {
	t.Helper()
	records, err := ts.store.Audit().List(context.Background())
	if err != nil {
		t.Fatalf("Audit().List: %v", err)
	}
	n := 0
	for _, rec := range records {
		if rec.Kind == kind {
			n++
		}
	}
	return n
}

// TestMCP_RunOperation_SilentNodeReturnsTheJobOncePersisted is #895's first
// acceptance line, read per Node: node-a is connected and never answers,
// node-b is registered and never connected. The call returns while node-a is
// still silent, with the Job already persisted (one Task per Node), and the
// Job later reports node-b unreachable. A connected Node that never answers
// stays Dispatched until restart reconciliation — "unacknowledged" is not
// built — so unreachable applies to node-b only.
func TestMCP_RunOperation_SilentNodeReturnsTheJobOncePersisted(t *testing.T) {
	ts := newTestServer(t)
	ts.conduit.connect(ts.nodeA)
	blockNodeUntilCleanup(t, ts, ts.nodeA)

	session := ts.connect(t)
	res := callTool(t, session, "run_operation", map[string]any{"operation": "system.facts"})
	// node-a is now mid-dispatch and nothing has released it: the call returned
	// without waiting for the silent Node.
	select {
	case <-ts.conduit.ready:
	case <-time.After(10 * time.Second):
		t.Fatal("node-a's Dispatch never started; the test proves nothing")
	}

	var out mcp.RunOrPlanOutput
	decodeResult(t, res, &out)
	if out.JobID == "" {
		t.Fatal("run_operation returned no job_id")
	}
	if out.JobStatus != "running" {
		t.Errorf("job_status = %q, want running", out.JobStatus)
	}
	if out.Reattached {
		t.Error("reattached = true on a fresh dispatch")
	}

	tasks, err := ts.store.Tasks().ByJob(context.Background(), out.JobID)
	if err != nil {
		t.Fatalf("Tasks().ByJob: %v", err)
	}
	byNode := map[string]jobs.Task{}
	for _, task := range tasks {
		byNode[task.NodeID] = task
	}
	if len(byNode) != 2 {
		t.Fatalf("persisted Tasks = %+v, want one per Node (both Nodes)", tasks)
	}

	got := pollJob(t, session, out.JobID, func(o mcp.ExecutionOutput) bool {
		return outcomesOf(o)[ts.nodeB] == "unreachable"
	})
	if got.JobStatus != "running" {
		t.Errorf("job_status = %q, want running while node-a is still silent", got.JobStatus)
	}
	if o := outcomesOf(got)[ts.nodeA]; o != "unspecified" {
		t.Errorf("silent node outcome = %q, want unspecified", o)
	}
	task, err := ts.store.Tasks().ByJob(context.Background(), out.JobID)
	if err != nil {
		t.Fatalf("Tasks().ByJob: %v", err)
	}
	for _, tk := range task {
		if tk.NodeID == ts.nodeA && tk.State != jobs.DispatchStateDispatched {
			t.Errorf("silent node Task state = %v, want Dispatched", tk.State)
		}
	}
}

// TestMCP_RunOperation_WaitSecondsReturnsFullResults: with wait_seconds the
// call blocks until the Job finishes, returns the per-Node results and
// job_status=complete, and the dispatch audit record is already written.
func TestMCP_RunOperation_WaitSecondsReturnsFullResults(t *testing.T) {
	ts := newTestServer(t)
	ts.conduit.connect(ts.nodeA, ts.nodeB)
	ts.conduit.results[ts.nodeA] = jobs.Result{Outcome: jobs.OutcomeSuccess}
	ts.conduit.results[ts.nodeB] = jobs.Result{Outcome: jobs.OutcomeSuccess}

	session := ts.connect(t)
	res := callTool(t, session, "run_operation", map[string]any{"operation": "system.facts", "wait_seconds": 5})
	var out mcp.RunOrPlanOutput
	decodeResult(t, res, &out)

	if out.JobStatus != "complete" {
		t.Errorf("job_status = %q, want complete", out.JobStatus)
	}
	for node, outcome := range outcomesOf(mcp.ExecutionOutput{Results: out.Results}) {
		if outcome != "success" {
			t.Errorf("node %s outcome = %q, want success", node, outcome)
		}
	}
	records, err := ts.store.Audit().ByJob(context.Background(), out.JobID)
	if err != nil {
		t.Fatalf("Audit().ByJob: %v", err)
	}
	dispatched := false
	for _, rec := range records {
		dispatched = dispatched || rec.Kind == audit.KindDispatch
	}
	if !dispatched {
		t.Errorf("no KindDispatch audit record on return for %s; records = %+v", out.JobID, records)
	}
}

// TestMCP_RunOperation_LapsedWaitReturnsTheRunningJob: a wait that lapses
// returns the running Job and does not cancel it.
func TestMCP_RunOperation_LapsedWaitReturnsTheRunningJob(t *testing.T) {
	ts := newTestServer(t)
	ts.conduit.connect(ts.nodeA)
	ts.conduit.results[ts.nodeA] = jobs.Result{Outcome: jobs.OutcomeSuccess}
	unblock := blockNodeUntilCleanup(t, ts, ts.nodeA)

	session := ts.connect(t)
	res := callTool(t, session, "run_operation", map[string]any{"selector": "node:role=web", "operation": "system.facts", "wait_seconds": 1})
	var out mcp.RunOrPlanOutput
	decodeResult(t, res, &out)
	if out.JobStatus != "running" {
		t.Fatalf("job_status = %q after a lapsed wait, want running", out.JobStatus)
	}

	unblock()
	got := pollJob(t, session, out.JobID, func(o mcp.ExecutionOutput) bool { return o.JobStatus == "complete" })
	if o := outcomesOf(got)[ts.nodeA]; o != "success" {
		t.Errorf("outcome after the lapsed wait = %q, want success (a lapsed wait never cancels)", o)
	}
}

// TestMCP_RunOperation_ReissueAfterDroppedResponseReturnsTheSameJob is #895's
// second acceptance line: the response stream is dropped, the call is
// re-issued with the same key, and no second Job is created.
func TestMCP_RunOperation_ReissueAfterDroppedResponseReturnsTheSameJob(t *testing.T) {
	ts := newTestServerWithAccount(t, "acct-test", 0, 0, "")
	ts.conduit.connect(ts.nodeA, ts.nodeB)
	ts.conduit.results[ts.nodeA] = jobs.Result{Outcome: jobs.OutcomeSuccess}
	ts.conduit.results[ts.nodeB] = jobs.Result{Outcome: jobs.OutcomeSuccess}
	unblock := blockNodeUntilCleanup(t, ts, ts.nodeB)

	args := func() map[string]any {
		return map[string]any{"operation": "system.facts", "idempotency_key": "k-1", "wait_seconds": 300}
	}

	session := ts.connect(t)
	ctx, cancel := context.WithCancel(context.Background())
	firstErr := make(chan error, 1)
	go func() {
		_, err := session.CallTool(ctx, &sdkmcp.CallToolParams{Name: "run_operation", Arguments: args()})
		firstErr <- err
	}()
	// the Job is persisted and node-b is mid-dispatch
	select {
	case <-ts.conduit.ready:
	case <-time.After(10 * time.Second):
		t.Fatal("node-b's Dispatch never started; the test proves nothing")
	}
	cancel()
	select {
	case err := <-firstErr:
		if err == nil {
			t.Fatal("the dropped call returned without an error")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the dropped call never returned")
	}

	res := callTool(t, ts.connect(t), "run_operation", args())
	var out mcp.RunOrPlanOutput
	decodeResult(t, res, &out)
	if !out.Reattached {
		t.Error("reattached = false on a re-issued call with the same key")
	}
	if out.JobID == "" {
		t.Fatal("re-issued call returned no job_id")
	}
	if n := countAudit(t, ts, audit.KindDispatchIntent); n != 1 {
		t.Errorf("dispatch_intent records = %d, want exactly one Job", n)
	}
	if n := ts.conduit.dispatchCount(ts.nodeB); n != 1 {
		t.Errorf("node-b dispatch count = %d, want 1", n)
	}

	unblock()
	got := pollJob(t, session, out.JobID, func(o mcp.ExecutionOutput) bool { return o.JobStatus == "complete" })
	for node, outcome := range outcomesOf(got) {
		if outcome != "success" {
			t.Errorf("node %s outcome = %q, want success", node, outcome)
		}
	}
}

// TestMCP_RunOperation_IdempotencyKeyRefusals covers the keyed call's refusals:
// a reused key with different arguments, a key the schema or capability layer
// rejects, and a key where the Relay cannot honour one. Each dispatches nothing.
func TestMCP_RunOperation_IdempotencyKeyRefusals(t *testing.T) {
	t.Run("same key, different arguments", func(t *testing.T) {
		ts := newTestServerWithAccount(t, "acct-test", 0, 0, "")
		ts.conduit.connect(ts.nodeA)
		ts.conduit.results[ts.nodeA] = jobs.Result{Outcome: jobs.OutcomeSuccess}
		session := ts.connect(t)
		sel := map[string]any{"selector": "node:role=web", "operation": "system.facts", "idempotency_key": "k-c", "wait_seconds": 5}
		first := callTool(t, session, "run_operation", sel)
		if first.IsError {
			t.Fatalf("first call: %s", toolErrorText(t, first))
		}

		sel["timeout_seconds"] = 10
		res := callTool(t, session, "run_operation", sel)
		if !res.IsError || !strings.Contains(toolErrorText(t, res), "different arguments") {
			t.Fatalf("different args under one key: want a conflict tool error, got IsError=%v", res.IsError)
		}
		if n := countAudit(t, ts, audit.KindDispatchIntent); n != 1 {
			t.Errorf("dispatch_intent records = %d, want 1", n)
		}
	})

	t.Run("key over 128 bytes", func(t *testing.T) {
		ts := newTestServerWithAccount(t, "acct-test", 0, 0, "")
		ts.conduit.connect(ts.nodeA)
		session := ts.connect(t)
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		res, err := session.CallTool(ctx, &sdkmcp.CallToolParams{Name: "run_operation", Arguments: map[string]any{
			"operation": "system.facts", "idempotency_key": strings.Repeat("k", 129),
		}})
		if err == nil && !res.IsError {
			t.Fatal("a 129-byte key was accepted; the schema must refuse it")
		}
		if n := countAudit(t, ts, audit.KindDispatchIntent); n != 0 {
			t.Errorf("dispatch_intent records = %d, want 0", n)
		}
	})

	t.Run("key with a space", func(t *testing.T) {
		ts := newTestServerWithAccount(t, "acct-test", 0, 0, "")
		ts.conduit.connect(ts.nodeA)
		session := ts.connect(t)
		res := callTool(t, session, "run_operation", map[string]any{"operation": "system.facts", "idempotency_key": "has space"})
		if !res.IsError || !strings.Contains(toolErrorText(t, res), "invalid idempotency key") {
			t.Fatalf("a key with a space: want the invalid-key tool error, got IsError=%v", res.IsError)
		}
		if n := countAudit(t, ts, audit.KindDispatchIntent); n != 0 {
			t.Errorf("dispatch_intent records = %d, want 0", n)
		}
	})

	t.Run("no verified Account", func(t *testing.T) {
		ts := newTestServer(t) // the default fixture's Account carries no ID
		ts.conduit.connect(ts.nodeA)
		session := ts.connect(t)
		res := callTool(t, session, "run_operation", map[string]any{"operation": "system.facts", "idempotency_key": "k-x"})
		if !res.IsError || !strings.Contains(toolErrorText(t, res), "cannot honour an idempotency key") {
			t.Fatalf("a key with no AccountID: want the unavailable tool error, got IsError=%v", res.IsError)
		}
		if n := countAudit(t, ts, audit.KindDispatchIntent); n != 0 {
			t.Errorf("dispatch_intent records = %d, want 0", n)
		}
	})
}

// TestMCP_RunOperation_Plan_WithKeyClaimsNothing is PF-8 on this surface: a
// preflight creates nothing, so a key sent with plan=true claims no dedup
// entry and a later real run with that key dispatches.
func TestMCP_RunOperation_Plan_WithKeyClaimsNothing(t *testing.T) {
	ts := newTestServerWithAccount(t, "acct-test", 0, 0, "")
	ts.conduit.connect(ts.nodeA)
	ts.conduit.results[ts.nodeA] = jobs.Result{Outcome: jobs.OutcomeSuccess}
	session := ts.connect(t)

	planRes := callTool(t, session, "run_operation", map[string]any{
		"selector": "node:role=web", "operation": "system.facts", "plan": true, "idempotency_key": "k-p",
	})
	if planRes.IsError {
		t.Fatalf("plan with a key: %s", toolErrorText(t, planRes))
	}
	_, found, err := ts.store.IdempotencyKeys().Lookup(context.Background(), "acct-test", "k-p", time.Unix(0, 0))
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if found {
		t.Fatal("a preflight claimed an idempotency key (PF-8: a preflight creates no dedup entry)")
	}
	if n := countAudit(t, ts, audit.KindDispatchIntent); n != 0 {
		t.Fatalf("dispatch_intent records after a plan = %d, want 0", n)
	}

	runRes := callTool(t, session, "run_operation", map[string]any{
		"selector": "node:role=web", "operation": "system.facts", "idempotency_key": "k-p", "wait_seconds": 5,
	})
	var out mcp.RunOrPlanOutput
	decodeResult(t, runRes, &out)
	if out.Reattached {
		t.Error("the real run after a keyed plan re-attached; it must dispatch")
	}
	if n := ts.conduit.dispatchCount(ts.nodeA); n != 1 {
		t.Errorf("node-a dispatch count = %d, want 1", n)
	}
}
