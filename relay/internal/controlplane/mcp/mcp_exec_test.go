package mcp_test

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"

	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/audit"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/capability"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/controlplane"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/jobs"
)

// --- fixtures shared by this file's test cases ---

// testAuthorizer is the execution-wired fixture's allow-all Authorizer, a
// DISTINCT type from capability's own unexported allowAllAuthorizer so
// capability.New's fail-open guard ("a real dispatcher must never ride the
// package's own allow-all default") is satisfied by construction, mirroring
// cmd/relay/devharness.go's devHarnessAuthorizer.
type testAuthorizer struct{}

func (testAuthorizer) Authorize(context.Context, capability.Principal, jobs.Action, capability.Selector) error {
	return nil
}

// deterministicIDs returns a capability.WithExecNewID-compatible generator
// that yields "id-1", "id-2", ... in call order, mutex-guarded (the cancel
// test drives two concurrent tool calls, and the whole suite runs under
// -race). The Job engine mints IDs job-id-N first, then stage-id-N, then one
// task-id-N per matched Node, in that order (execution.go's run) — so a
// fresh testServer's FIRST run_operation/raw_exec call always mints Job ID
// "job-id-1", predictable without reading it back first.
func deterministicIDs() func() (string, error) {
	var mu sync.Mutex
	n := 0
	return func() (string, error) {
		mu.Lock()
		defer mu.Unlock()
		n++
		return fmt.Sprintf("id-%d", n), nil
	}
}

// cancelCall records one fakeConduit.Cancel invocation's arguments.
type cancelCall struct {
	NodeID string
	TaskID string
}

// fakeConduit is a configurable capability.Conduit: per-Node
// connected/results/errs, exactly mirroring capability's own internal test
// fakeConduit (unexported to package capability's test files, so this is a
// deliberate, small duplication rather than a shared export solely for
// tests). blockNode/ready/unblock implement RB5's explicit channel
// synchronization for the cancel test: Dispatch for blockNode signals ready
// BEFORE blocking on unblock — no sleep-based race.
type fakeConduit struct {
	mu             sync.Mutex
	connected      map[string]bool
	results        map[string]jobs.Result
	errs           map[string]error
	timeoutSeconds map[string]int32
	cancelCalls    []cancelCall

	blockNode string
	ready     chan struct{}
	unblock   chan struct{}
}

func newFakeConduit() *fakeConduit {
	return &fakeConduit{
		connected:      map[string]bool{},
		results:        map[string]jobs.Result{},
		errs:           map[string]error{},
		timeoutSeconds: map[string]int32{},
	}
}

// connect marks every nodeID as having a live Tunnel.
func (f *fakeConduit) connect(nodeIDs ...string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, id := range nodeIDs {
		f.connected[id] = true
	}
}

func (f *fakeConduit) Connected(nodeID string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.connected[nodeID]
}

func (f *fakeConduit) Dispatch(ctx context.Context, nodeID string, task jobs.Task) (jobs.Result, error) {
	f.mu.Lock()
	f.timeoutSeconds[nodeID] = task.TimeoutSeconds
	block := f.blockNode != "" && nodeID == f.blockNode
	ready := f.ready
	unblock := f.unblock
	res := f.results[nodeID]
	err := f.errs[nodeID]
	f.mu.Unlock()

	if block {
		close(ready)
		select {
		case <-unblock:
		case <-ctx.Done():
			return jobs.Result{}, ctx.Err()
		}
	}
	return res, err
}

func (f *fakeConduit) Cancel(_ context.Context, nodeID, taskID string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.cancelCalls = append(f.cancelCalls, cancelCall{NodeID: nodeID, TaskID: taskID})
	return nil
}

func (f *fakeConduit) timeoutFor(nodeID string) int32 {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.timeoutSeconds[nodeID]
}

func (f *fakeConduit) cancelledCalls() []cancelCall {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]cancelCall, len(f.cancelCalls))
	copy(out, f.cancelCalls)
	return out
}

// --- wire-shape mirrors for assertions (see mcp_test.go's own note: this is
// an external test package, so it deliberately re-declares the JSON shape
// rather than reaching into the mcp package's unexported types). ---

type perNodeResultJSON struct {
	NodeID          string `json:"node_id"`
	Outcome         string `json:"outcome"`
	ExitCode        int32  `json:"exit_code"`
	Stdout          string `json:"stdout"`
	Stderr          string `json:"stderr"`
	StdoutTruncated bool   `json:"stdout_truncated"`
	StderrTruncated bool   `json:"stderr_truncated"`
	DurationMS      int64  `json:"duration_ms"`
}

type executionOutputJSON struct {
	JobID   string              `json:"job_id"`
	Results []perNodeResultJSON `json:"results"`
}

// toolErrorText extracts a tool error's message text, failing the test if
// res is not actually an error result.
func toolErrorText(t *testing.T, res *sdkmcp.CallToolResult) string {
	t.Helper()
	if !res.IsError {
		t.Fatal("toolErrorText: result is not an error")
	}
	if len(res.Content) == 0 {
		t.Fatal("toolErrorText: Content is empty")
	}
	tc, ok := res.Content[0].(*sdkmcp.TextContent)
	if !ok {
		t.Fatalf("toolErrorText: Content[0] = %T, want *sdkmcp.TextContent", res.Content[0])
	}
	return tc.Text
}

// TestMCP_RunOperation_PerNodeResults is the ROADMAP acceptance line: an
// MCP client calls run_operation(selector, "system.facts") and gets
// per-Node results plus a Job id.
func TestMCP_RunOperation_PerNodeResults(t *testing.T) {
	ts := newTestServer(t)
	ts.conduit.connect(ts.nodeA, ts.nodeB)
	ts.conduit.results[ts.nodeA] = jobs.Result{Outcome: jobs.OutcomeSuccess, ExitCode: 0, Stdout: []byte(`{"hostname":"web-1"}`)}
	ts.conduit.results[ts.nodeB] = jobs.Result{Outcome: jobs.OutcomeSuccess, ExitCode: 0, Stdout: []byte(`{"hostname":"db-1"}`)}

	session := ts.connect(t)
	res := callTool(t, session, "run_operation", map[string]any{"operation": "system.facts"})
	var out executionOutputJSON
	decodeResult(t, res, &out)

	if out.JobID == "" {
		t.Fatal("run_operation: job_id is empty, want a Job id")
	}
	if len(out.Results) != 2 {
		t.Fatalf("run_operation: got %d results, want 2: %+v", len(out.Results), out.Results)
	}
	for _, r := range out.Results {
		if r.Outcome != "success" {
			t.Errorf("result[%s].Outcome = %q, want success", r.NodeID, r.Outcome)
		}
		if r.DurationMS < 0 {
			t.Errorf("result[%s].DurationMS = %d, want >= 0", r.NodeID, r.DurationMS)
		}
		if r.Stdout == "" {
			t.Errorf("result[%s].Stdout is empty, want facts JSON", r.NodeID)
		}
	}
}

// TestMCP_RawExec_AllowedVsDenied_ThenStructuredSucceeds is the raw_exec
// acceptance line: raw_exec runs an allowed argv and is refused (per-Node,
// by the daemon's Policy regex) for a denied one, while a structured
// Operation for the same intent succeeds.
func TestMCP_RawExec_AllowedVsDenied_ThenStructuredSucceeds(t *testing.T) {
	ts := newTestServer(t)
	ts.conduit.connect(ts.nodeA, ts.nodeB)
	ts.conduit.results[ts.nodeA] = jobs.Result{Outcome: jobs.OutcomeSuccess}
	ts.conduit.results[ts.nodeB] = jobs.Result{Outcome: jobs.OutcomeDeniedByPolicy}

	session := ts.connect(t)
	res := callTool(t, session, "raw_exec", map[string]any{
		"argv": []string{"/usr/bin/systemctl", "restart", "nginx"},
	})
	var out executionOutputJSON
	decodeResult(t, res, &out)

	got := map[string]string{}
	for _, r := range out.Results {
		got[r.NodeID] = r.Outcome
	}
	if got[ts.nodeA] != "success" {
		t.Errorf("raw_exec node %s outcome = %q, want success (allowed)", ts.nodeA, got[ts.nodeA])
	}
	if got[ts.nodeB] != "denied_by_policy" {
		t.Errorf("raw_exec node %s outcome = %q, want denied_by_policy", ts.nodeB, got[ts.nodeB])
	}

	// The structured, typed path succeeds for the same intent where raw_exec
	// was refused on node B — the daemon's canned outcome now reflects
	// success for both, proving run_operation dispatches through the same
	// pipeline, not a separate one.
	ts.conduit.results[ts.nodeB] = jobs.Result{Outcome: jobs.OutcomeSuccess}
	res2 := callTool(t, session, "run_operation", map[string]any{"operation": "system.facts"})
	var out2 executionOutputJSON
	decodeResult(t, res2, &out2)
	for _, r := range out2.Results {
		if r.Outcome != "success" {
			t.Errorf("run_operation (typed path) node %s outcome = %q, want success", r.NodeID, r.Outcome)
		}
	}
}

// TestMCP_RawExec_OverCap is the over-cap acceptance line: a Selector that
// resolves to more Nodes than the mutate-cap is refused with the legible
// cap/count/class error from #100.
func TestMCP_RawExec_OverCap(t *testing.T) {
	ts := newTestServerWithBlastCap(t, 0, 1)
	ts.conduit.connect(ts.nodeA, ts.nodeB)

	session := ts.connect(t)
	res := callTool(t, session, "raw_exec", map[string]any{"argv": []string{"/bin/true"}})
	if !res.IsError {
		t.Fatal("raw_exec over the mutate-cap: IsError = false, want true")
	}
	text := toolErrorText(t, res)
	for _, want := range []string{"matched", "cap", "mutate", "class"} {
		if !strings.Contains(text, want) {
			t.Errorf("raw_exec over-cap error = %q, want it to mention %q", text, want)
		}
	}
}

// TestMCP_Frozen_RefusesBothExecutionTools is the frozen acceptance line: a
// frozen Relay refuses both execution tools with the distinct "the Relay is
// frozen" error.
func TestMCP_Frozen_RefusesBothExecutionTools(t *testing.T) {
	ts := newTestServer(t)
	if err := ts.store.Freeze().Engage(context.Background(), "test-admin"); err != nil {
		t.Fatalf("Engage: %v", err)
	}

	session := ts.connect(t)

	res := callTool(t, session, "run_operation", map[string]any{"operation": "system.facts"})
	if !res.IsError {
		t.Fatal("run_operation while frozen: IsError = false, want true")
	}
	if text := toolErrorText(t, res); !strings.Contains(text, "the Relay is frozen") {
		t.Errorf("run_operation while frozen error = %q, want it to contain %q", text, "the Relay is frozen")
	}

	res2 := callTool(t, session, "raw_exec", map[string]any{"argv": []string{"/bin/true"}})
	if !res2.IsError {
		t.Fatal("raw_exec while frozen: IsError = false, want true")
	}
	if text := toolErrorText(t, res2); !strings.Contains(text, "the Relay is frozen") {
		t.Errorf("raw_exec while frozen error = %q, want it to contain %q", text, "the Relay is frozen")
	}
}

// TestMCP_CancelJob_InFlightAndPendingSibling is the cancel acceptance line:
// a Job started over MCP can be cancelled over MCP; the in-flight Task
// reports cancelled, the pending sibling (never dispatched) also reports
// cancelled, get_job re-reads the same result, and the cancel itself is
// audited attributed to FoundingAdmin (DECISION 2).
//
// RB5 (plan review): explicit channel synchronization, no sleep — fakeConduit
// signals ready right before blocking node A's Dispatch, and this test waits
// on that channel before calling cancel_job.
func TestMCP_CancelJob_InFlightAndPendingSibling(t *testing.T) {
	ts := newTestServer(t)
	ts.conduit.connect(ts.nodeA, ts.nodeB)
	// registry.List() is sorted by NodeID ("node-a" < "node-b"), and the Job
	// engine dispatches sequentially in that order (execution.go's run), so
	// blocking node A's Dispatch leaves node B still Pending in the store —
	// exactly the "in-flight + pending sibling" scenario this test needs.
	ts.conduit.blockNode = ts.nodeA
	ts.conduit.ready = make(chan struct{})
	ts.conduit.unblock = make(chan struct{})
	ts.conduit.results[ts.nodeA] = jobs.Result{Outcome: jobs.OutcomeCancelled}

	runSession := ts.connect(t)
	cancelSession := ts.connect(t)

	runDone := make(chan *sdkmcp.CallToolResult, 1)
	go func() {
		runDone <- callTool(t, runSession, "run_operation", map[string]any{"operation": "system.facts"})
	}()

	<-ts.conduit.ready // node A's Dispatch is now in-flight, blocked.

	// deterministicIDs' first minted Job ID for a fresh testServer.
	const predictedJobID = "job-id-1"
	cancelRes := callTool(t, cancelSession, "cancel_job", map[string]any{"job_id": predictedJobID})
	if cancelRes.IsError {
		t.Fatalf("cancel_job: IsError = true, content = %+v", cancelRes.Content)
	}

	close(ts.conduit.unblock)

	runRes := <-runDone
	var runResult executionOutputJSON
	decodeResult(t, runRes, &runResult)

	outcomes := map[string]string{}
	for _, r := range runResult.Results {
		outcomes[r.NodeID] = r.Outcome
	}
	if outcomes[ts.nodeA] != "cancelled" {
		t.Errorf("in-flight node %s outcome = %q, want cancelled", ts.nodeA, outcomes[ts.nodeA])
	}
	if outcomes[ts.nodeB] != "cancelled" {
		t.Errorf("pending sibling %s outcome = %q, want cancelled", ts.nodeB, outcomes[ts.nodeB])
	}

	if calls := ts.conduit.cancelledCalls(); len(calls) != 1 || calls[0].NodeID != ts.nodeA {
		t.Errorf("Conduit.Cancel calls = %+v, want exactly one call for %s", calls, ts.nodeA)
	}

	getRes := callTool(t, cancelSession, "get_job", map[string]any{"job_id": predictedJobID})
	var getOut executionOutputJSON
	decodeResult(t, getRes, &getOut)
	if len(getOut.Results) != 2 {
		t.Fatalf("get_job: got %d results, want 2", len(getOut.Results))
	}
	for _, r := range getOut.Results {
		if r.Outcome != "cancelled" {
			t.Errorf("get_job result[%s].Outcome = %q, want cancelled", r.NodeID, r.Outcome)
		}
	}

	records, err := ts.store.Audit().ByJob(context.Background(), predictedJobID)
	if err != nil {
		t.Fatalf("Audit().ByJob: %v", err)
	}
	foundCancel := false
	for _, rec := range records {
		if rec.Kind == audit.KindJobCancel {
			foundCancel = true
			if rec.Principal != controlplane.FoundingAdmin().Attribution() {
				t.Errorf("cancel audit record Principal = %q, want %q", rec.Principal, controlplane.FoundingAdmin().Attribution())
			}
		}
	}
	if !foundCancel {
		t.Errorf("no audit.KindJobCancel record found for job %q; records = %+v", predictedJobID, records)
	}
}

// TestMCP_TimeoutSeconds_ThreadsToTask is DECISION 3's acceptance line: an
// explicit timeout_seconds is observed on the dispatched Task, and omitting
// it keeps today's default (0).
func TestMCP_TimeoutSeconds_ThreadsToTask(t *testing.T) {
	tests := []struct {
		tool string
		args map[string]any
	}{
		{"run_operation", map[string]any{"selector": "node:role=web", "operation": "system.facts"}},
		{"raw_exec", map[string]any{"selector": "node:role=web", "argv": []string{"/bin/true"}}},
	}

	for _, tt := range tests {
		t.Run(tt.tool, func(t *testing.T) {
			ts := newTestServer(t)
			ts.conduit.connect(ts.nodeA)
			ts.conduit.results[ts.nodeA] = jobs.Result{Outcome: jobs.OutcomeSuccess}

			session := ts.connect(t)

			withTimeout := map[string]any{}
			for k, v := range tt.args {
				withTimeout[k] = v
			}
			withTimeout["timeout_seconds"] = 30

			res := callTool(t, session, tt.tool, withTimeout)
			if res.IsError {
				t.Fatalf("%s(timeout_seconds=30): IsError = true, content = %+v", tt.tool, res.Content)
			}
			if got := ts.conduit.timeoutFor(ts.nodeA); got != 30 {
				t.Errorf("%s: observed Task.TimeoutSeconds = %d, want 30", tt.tool, got)
			}

			res2 := callTool(t, session, tt.tool, tt.args)
			if res2.IsError {
				t.Fatalf("%s(timeout_seconds omitted): IsError = true, content = %+v", tt.tool, res2.Content)
			}
			if got := ts.conduit.timeoutFor(ts.nodeA); got != 0 {
				t.Errorf("%s: observed Task.TimeoutSeconds (omitted) = %d, want 0 (default)", tt.tool, got)
			}
		})
	}
}

// TestMCP_RunOperation_AuditedWithPrincipal is the "every call is audited
// with principal" acceptance line: after a run, the audit trail carries an
// entry attributed to FoundingAdmin (Run's intrinsic audit fired with the
// context Principal — no new audit code needed for the tools themselves).
func TestMCP_RunOperation_AuditedWithPrincipal(t *testing.T) {
	ts := newTestServer(t)
	ts.conduit.connect(ts.nodeA)
	ts.conduit.results[ts.nodeA] = jobs.Result{Outcome: jobs.OutcomeSuccess}

	session := ts.connect(t)
	res := callTool(t, session, "run_operation", map[string]any{
		"selector":  "node:role=web",
		"operation": "system.facts",
	})
	var out executionOutputJSON
	decodeResult(t, res, &out)

	records, err := ts.store.Audit().ByJob(context.Background(), out.JobID)
	if err != nil {
		t.Fatalf("Audit().ByJob: %v", err)
	}
	if len(records) == 0 {
		t.Fatal("no audit records found for the Job")
	}
	for _, rec := range records {
		if rec.Principal != controlplane.FoundingAdmin().Attribution() {
			t.Errorf("audit record Principal = %q, want %q", rec.Principal, controlplane.FoundingAdmin().Attribution())
		}
	}
}
