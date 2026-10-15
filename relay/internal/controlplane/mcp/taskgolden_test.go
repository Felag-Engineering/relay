package mcp_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Felag-Engineering/relay/relay/internal/accounts"
	"github.com/Felag-Engineering/relay/relay/internal/capability"
	"github.com/Felag-Engineering/relay/relay/internal/controlplane"
	"github.com/Felag-Engineering/relay/relay/internal/controlplane/mcp"
	"github.com/Felag-Engineering/relay/relay/internal/jobs"
	"github.com/Felag-Engineering/relay/relay/internal/mcptask"
)

// taskgolden_test.go is #376's conformance half: fixture request -> asserted
// EXACT JSON response, across the Tasks surface.
//
// # Why exact JSON, and why here
//
// Relay implements SEP-2663 by hand, so there is no upstream suite protecting
// it. The failure mode that actually threatens the shim is not a logic bug —
// the unit tests cover those — it is an SDK UPGRADE silently changing the
// response JSON the shim matches on. That failure is invisible by construction:
// the shim's own rule is "when in doubt, pass through", so a changed shape
// degrades it into a no-op and every functional test keeps passing while
// Tasks-capable clients quietly stop getting task results.
//
// Byte-exact goldens are the only thing that turns that into a loud failure. If
// one of these changes after a dependency bump, read the diff before updating
// it: the diff IS the drift report.
//
// These run through the real mcp.New handler — real SDK dispatch, real custom
// methods, real shim — with fake collaborators and a fixed clock, so the only
// thing varying is the wire.

var goldenNow = time.Date(2026, 8, 17, 9, 0, 0, 0, time.UTC)

const (
	// The authenticator only reaches its verifier for something shaped like an
	// API Token, so the fixture has to carry the real prefix.
	goldenCredential = accounts.TokenPrefix + "0123456789abcdef.golden-secret" // test fixture, not a real credential
	goldenTaskID     = "task-golden-1"
	goldenRequestID  = "req-golden-1"
)

// -----------------------------------------------------------------------
// Fakes
// -----------------------------------------------------------------------

// goldenTasks is a TaskResolver returning a fixed view, so the JSON below is a
// function of the RENDERING and nothing else.
type goldenTasks struct {
	view      capability.TaskView
	cancelled capability.TaskView
	err       error
}

func (g goldenTasks) ResolveTask(context.Context, capability.Principal, string) (capability.TaskView, error) {
	if g.err != nil {
		return capability.TaskView{}, g.err
	}
	return g.view, nil
}

func (g goldenTasks) CancelTask(context.Context, capability.Principal, string) (capability.TaskView, error) {
	if g.err != nil {
		return capability.TaskView{}, g.err
	}
	return g.cancelled, nil
}

// goldenJobs returns one deterministic Task for the completed-poll golden.
type goldenJobs struct{}

func (goldenJobs) GetJob(_ context.Context, id string) (jobs.Job, error) {
	return jobs.Job{ID: id, CreatedAt: goldenNow}, nil
}

func (goldenJobs) TasksByJob(_ context.Context, jobID string) ([]jobs.Task, error) {
	return []jobs.Task{{
		ID: "task-1", JobID: jobID, NodeID: "node-a",
		Action:       jobs.Action{Kind: jobs.ActionOperation, OperationName: "service.restart", RiskClass: jobs.RiskClassMutate},
		State:        jobs.DispatchStateResolved,
		Outcome:      jobs.OutcomeSuccess,
		ExitCode:     0,
		Stdout:       []byte("ok"),
		CreatedAt:    goldenNow,
		DispatchedAt: goldenNow,
		ResolvedAt:   goldenNow.Add(time.Second),
	}}, nil
}

// goldenParker is an Executor whose every dispatch parks, with fixed fields —
// so the create-path goldens below are a function of the RENDERING and the
// SHIM, and of nothing that varies.
type goldenParker struct{}

func (goldenParker) Start(context.Context, capability.Principal, capability.Selector, jobs.Action, capability.StartOptions) (capability.StartedJob, error) {
	return capability.StartedJob{}, &capability.ParkedError{
		RequestID:     goldenRequestID,
		PlanHash:      "hash-golden-1",
		Summary:       `service.restart(unit="nginx") [mutate] on 1 node(s): node-a`,
		Progress:      "0 of 1",
		Rules:         []string{"all-mutates-need-a-human"},
		ExpiresAt:     goldenNow.Add(4 * time.Hour),
		TaskID:        goldenTaskID,
		TaskExpiresAt: goldenNow.Add(time.Hour),
	}
}

func (goldenParker) CancelJob(context.Context, capability.Principal, string) error { return nil }

func (goldenParker) Plan(context.Context, capability.Principal, capability.Selector, jobs.Action) (capability.PlanResult, error) {
	return capability.PlanResult{}, nil
}

// goldenVerifier authenticates exactly one credential, as a human operator.
type goldenVerifier struct{}

func (goldenVerifier) Verify(_ context.Context, credential string) (accounts.Account, accounts.APIToken, error) {
	if credential != goldenCredential {
		return accounts.Account{}, accounts.APIToken{}, accounts.ErrTokenInvalid
	}
	return accounts.Account{
		ID: "acct-golden", Name: "golden", Role: accounts.RoleOperator,
		Kind: accounts.KindHuman, Enabled: true,
	}, accounts.APIToken{ID: "tok-golden"}, nil
}

// goldenServer mounts the real handler behind the real authenticator.
func goldenServer(t *testing.T, tasks mcp.TaskResolver) *httptest.Server {
	t.Helper()
	return goldenServerWithExec(t, tasks, nil)
}

func goldenServerWithExec(t *testing.T, tasks mcp.TaskResolver, exec mcp.Executor) *httptest.Server {
	t.Helper()

	// No golden test here calls list_nodes/describe_node/list_operations, so
	// the read lane is left nil — mirroring the pre-existing nil ReadAuditor
	// argument below, both unneeded by this file's Tasks-focused goldens.
	handler := mcp.New(nil, opsLister{}, exec, goldenJobs{}, nil, tasks,
		mcp.WithClock(func() time.Time { return goldenNow }))

	mux := http.NewServeMux()
	mux.Handle("/mcp", handler)
	srv := httptest.NewServer(controlplane.NewAuthenticator(goldenVerifier{}).Middleware(mux))
	t.Cleanup(srv.Close)
	return srv
}

// postJSONRPC sends one raw JSON-RPC message and returns status and body.
func postJSONRPC(t *testing.T, srv *httptest.Server, method, name, body string) (int, string, http.Header) {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, srv.URL+"/mcp", strings.NewReader(body))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("MCP-Protocol-Version", "2026-07-28")
	req.Header.Set("Authorization", "Bearer "+goldenCredential)
	if method != "" {
		req.Header.Set("Mcp-Method", method)
	}
	if name != "" {
		req.Header.Set("Mcp-Name", name)
	}

	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatalf("POST /mcp: %v", err)
	}
	defer resp.Body.Close()
	var buf bytes.Buffer
	if _, err := buf.ReadFrom(resp.Body); err != nil {
		t.Fatalf("read body: %v", err)
	}
	return resp.StatusCode, strings.TrimSpace(buf.String()), resp.Header
}

// assertGoldenJSON compares got against want as canonicalized JSON, so key
// ORDER is not asserted (Go's map marshalling makes that unstable) while every
// key, value, and type is.
func assertGoldenJSON(t *testing.T, got, want string) {
	t.Helper()
	canon := func(s string) string {
		var v any
		if err := json.Unmarshal([]byte(s), &v); err != nil {
			t.Fatalf("not JSON: %v\n%s", err, s)
		}
		b, err := json.Marshal(v)
		if err != nil {
			t.Fatalf("re-marshal: %v", err)
		}
		return string(b)
	}
	if canon(got) != canon(want) {
		t.Errorf("wire JSON drifted.\n got: %s\nwant: %s\n\n"+
			"If a dependency was just upgraded, this diff IS the drift report — read it before "+
			"updating the golden. The shim passes through whatever it cannot identify, so a changed "+
			"response shape degrades it silently and every other test keeps passing.", got, want)
	}
}

// statelessMeta is what a >= 2026-07-28 client restates on every request
// (SEP-2575). Relay runs stateless, so there is no session carrying the
// initialize handshake forward and the server refuses a request without it —
// which is also why the shim can read the client's capabilities per request.
const statelessMeta = `"_meta":{` +
	`"io.modelcontextprotocol/protocolVersion":"2026-07-28",` +
	`"io.modelcontextprotocol/clientInfo":{"name":"golden-client","version":"0.0.1"},` +
	`"io.modelcontextprotocol/clientCapabilities":{"extensions":{"io.modelcontextprotocol/tasks":{}}}}`

func taskMethodRequest(method, taskID string) string {
	return `{"jsonrpc":"2.0","id":1,"method":"` + method + `","params":{` +
		statelessMeta + `,"taskId":"` + taskID + `"}}`
}

func tasksGetRequest(taskID string) string { return taskMethodRequest("tasks/get", taskID) }

// -----------------------------------------------------------------------
// Goldens
// -----------------------------------------------------------------------

// TestGolden_PollNonTerminal: a parked handle, still waiting on a human.
func TestGolden_PollNonTerminal(t *testing.T) {
	srv := goldenServer(t, goldenTasks{view: capability.TaskView{
		TaskID:            goldenTaskID,
		Status:            mcptask.StatusWorking,
		ApprovalRequestID: goldenRequestID,
		Summary:           `service.restart(unit="nginx") [mutate] on 1 node(s): node-a`,
		PlanHash:          "hash-1",
		CreatedAt:         goldenNow.Add(-time.Minute),
		LastUpdatedAt:     goldenNow.Add(-time.Minute),
		ExpiresAt:         goldenNow.Add(time.Hour),
	}})

	status, body, _ := postJSONRPC(t, srv, "tasks/get", "", tasksGetRequest(goldenTaskID))
	if status != http.StatusOK {
		t.Fatalf("status = %d; body = %s", status, body)
	}
	assertGoldenJSON(t, body, `{
	  "jsonrpc":"2.0","id":1,
	  "result":{
	    "_meta":{"io.modelcontextprotocol/serverInfo":{"name":"relay","version":"0.1.0"}},
	    "taskId":"task-golden-1",
	    "status":"working",
	    "createdAt":"2026-08-17T08:59:00Z",
	    "lastUpdatedAt":"2026-08-17T08:59:00Z",
	    "ttlMs":3600000,
	    "pollIntervalMs":5000,
	    "statusMessage":"service.restart(unit=\"nginx\") [mutate] on 1 node(s): node-a"
	  }
	}`)
}

// TestGolden_PollTerminalWithResults: the approval landed, the dispatch ran,
// and the handle now carries the Job's per-Node results.
func TestGolden_PollTerminalWithResults(t *testing.T) {
	srv := goldenServer(t, goldenTasks{view: capability.TaskView{
		TaskID:            goldenTaskID,
		Status:            mcptask.StatusCompleted,
		ApprovalRequestID: goldenRequestID,
		JobID:             "job-golden-1",
		Summary:           `service.restart(unit="nginx") [mutate] on 1 node(s): node-a`,
		CreatedAt:         goldenNow.Add(-time.Minute),
		LastUpdatedAt:     goldenNow,
		ExpiresAt:         goldenNow.Add(time.Hour),
	}})

	status, body, _ := postJSONRPC(t, srv, "tasks/get", "", tasksGetRequest(goldenTaskID))
	if status != http.StatusOK {
		t.Fatalf("status = %d; body = %s", status, body)
	}
	assertGoldenJSON(t, body, `{
	  "jsonrpc":"2.0","id":1,
	  "result":{
	    "_meta":{"io.modelcontextprotocol/serverInfo":{"name":"relay","version":"0.1.0"}},
	    "taskId":"task-golden-1",
	    "status":"completed",
	    "createdAt":"2026-08-17T08:59:00Z",
	    "lastUpdatedAt":"2026-08-17T09:00:00Z",
	    "ttlMs":3600000,
	    "pollIntervalMs":5000,
	    "statusMessage":"service.restart(unit=\"nginx\") [mutate] on 1 node(s): node-a",
	    "result":{
	      "job_id":"job-golden-1",
	      "job_status":"complete",
	      "results":[{
	        "node_id":"node-a",
	        "outcome":"success",
	        "exit_code":0,
	        "stdout":"ok",
	        "stderr":"",
	        "stdout_truncated":false,
	        "stderr_truncated":false,
	        "duration_ms":1000
	      }]
	    }
	  }
	}`)
}

// TestGolden_Cancel: the client withdrew. Note the error prose says plainly
// that the APPROVAL is untouched — a client told only "cancelled" might
// reasonably assume it had withdrawn the request from the human too.
func TestGolden_Cancel(t *testing.T) {
	srv := goldenServer(t, goldenTasks{cancelled: capability.TaskView{
		TaskID:            goldenTaskID,
		Status:            mcptask.StatusCancelled,
		ApprovalRequestID: goldenRequestID,
		Summary:           `service.restart(unit="nginx") [mutate] on 1 node(s): node-a`,
		CreatedAt:         goldenNow.Add(-time.Minute),
		LastUpdatedAt:     goldenNow,
		ExpiresAt:         goldenNow.Add(time.Hour),
	}})

	status, body, _ := postJSONRPC(t, srv, "tasks/cancel", "",
		taskMethodRequest("tasks/cancel", goldenTaskID))
	if status != http.StatusOK {
		t.Fatalf("status = %d; body = %s", status, body)
	}
	assertGoldenJSON(t, body, `{
	  "jsonrpc":"2.0","id":1,
	  "result":{
	    "_meta":{"io.modelcontextprotocol/serverInfo":{"name":"relay","version":"0.1.0"}},
	    "taskId":"task-golden-1",
	    "status":"cancelled",
	    "createdAt":"2026-08-17T08:59:00Z",
	    "lastUpdatedAt":"2026-08-17T09:00:00Z",
	    "ttlMs":3600000,
	    "pollIntervalMs":5000,
	    "statusMessage":"service.restart(unit=\"nginx\") [mutate] on 1 node(s): node-a",
	    "error":"this task handle was cancelled. Note that cancelling a handle ends only the client's polling: if the dispatch was still awaiting approval, that request remains pending and a human may still decide it."
	  }
	}`)
}

// TestGolden_TerminalFailed: a denied or expired approval. `failed` here means
// the CALL will never produce a result, not that anything broke.
func TestGolden_TerminalFailed(t *testing.T) {
	srv := goldenServer(t, goldenTasks{view: capability.TaskView{
		TaskID:            goldenTaskID,
		Status:            mcptask.StatusFailed,
		ApprovalRequestID: goldenRequestID,
		Summary:           `service.restart(unit="nginx") [mutate] on 1 node(s): node-a`,
		CreatedAt:         goldenNow.Add(-time.Minute),
		LastUpdatedAt:     goldenNow,
		ExpiresAt:         goldenNow.Add(time.Hour),
	}})

	status, body, _ := postJSONRPC(t, srv, "tasks/get", "", tasksGetRequest(goldenTaskID))
	if status != http.StatusOK {
		t.Fatalf("status = %d; body = %s", status, body)
	}
	assertGoldenJSON(t, body, `{
	  "jsonrpc":"2.0","id":1,
	  "result":{
	    "_meta":{"io.modelcontextprotocol/serverInfo":{"name":"relay","version":"0.1.0"}},
	    "taskId":"task-golden-1",
	    "status":"failed",
	    "createdAt":"2026-08-17T08:59:00Z",
	    "lastUpdatedAt":"2026-08-17T09:00:00Z",
	    "ttlMs":3600000,
	    "pollIntervalMs":5000,
	    "statusMessage":"service.restart(unit=\"nginx\") [mutate] on 1 node(s): node-a",
	    "error":"the approval this call was waiting on will not be granted: it was denied, or it expired. Nothing ran. Re-request the dispatch if it is still wanted — a lapsed approval is never revived."
	  }
	}`)
}

// TestGolden_UnknownHandle: legible, and identical for a handle that is not
// yours — a guessed id must not be confirmable.
func TestGolden_UnknownHandle(t *testing.T) {
	srv := goldenServer(t, goldenTasks{err: mcptask.ErrNotFound})

	// HTTP 200 with a JSON-RPC error member, NOT a 4xx — and that is load
	// bearing. The SDK client treats a non-200 as fatal for the session, and
	// polling a lapsed handle is an ordinary thing a client does; losing its
	// whole MCP session for it would be a real defect. See renderTaskError.
	status, body, _ := postJSONRPC(t, srv, "tasks/get", "", tasksGetRequest("task-nope"))
	if status != http.StatusOK {
		t.Fatalf("status = %d, want 200 — an unresolvable handle must not tear down the session; body = %s", status, body)
	}
	assertGoldenJSON(t, body, `{
	  "jsonrpc":"2.0","id":1,
	  "error":{
	    "code":-32603,
	    "message":"mcp: tasks/get: no task handle \"task-nope\" is resolvable by this account (unknown, or not yours)"
	  }
	}`)
}

// -----------------------------------------------------------------------
// The assumptions ADR-0028's design rests on
// -----------------------------------------------------------------------

// TestAssumption_BatchingIsRejected pins the first precondition.
//
// The shim is a SINGLE-message response transformer. That is only sound because
// the SDK refuses JSON-RPC batches on the protocol versions Relay speaks — one
// request in, one response out. If a future SDK started accepting batches, the
// shim would be inspecting the first message of several and rewriting a
// response that answers all of them.
//
// So this failing is not a broken test. It means ADR-0028's design assumption is
// void and the ADR must be revisited before the shim is trusted again.
func TestAssumption_BatchingIsRejected(t *testing.T) {
	srv := goldenServer(t, goldenTasks{})

	batch := `[` + taskMethodRequest("tasks/get", "a") + `,` + taskMethodRequest("tasks/get", "b") + `]`
	status, body, _ := postJSONRPC(t, srv, "tasks/get", "", batch)

	accepted := status == http.StatusOK && strings.HasPrefix(body, "[")
	if accepted {
		t.Fatalf("the SDK ACCEPTED a JSON-RPC batch (status %d): %s\n\n"+
			"ADR-0028's shim is a single-message transformer and depends on batching being "+
			"refused. This is not a test to update — it is a signal to revisit the ADR before "+
			"the shim is trusted again.", status, body)
	}
}

// TestAssumption_OneJSONObjectPerReply pins the second precondition.
//
// Relay runs the handler with JSONResponse: true, so a reply is one JSON object
// and never an SSE stream. The shim buffers and re-serializes exactly one
// object; a streamed reply would mean it had captured a fragment.
func TestAssumption_OneJSONObjectPerReply(t *testing.T) {
	srv := goldenServer(t, goldenTasks{view: capability.TaskView{
		TaskID: goldenTaskID, Status: mcptask.StatusWorking,
		CreatedAt: goldenNow, LastUpdatedAt: goldenNow, ExpiresAt: goldenNow.Add(time.Hour),
	}})

	status, body, header := postJSONRPC(t, srv, "tasks/get", "", tasksGetRequest(goldenTaskID))
	if status != http.StatusOK {
		t.Fatalf("status = %d; body = %s", status, body)
	}

	if ct := header.Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Fatalf("Content-Type = %q, want application/json — an SSE reply means the shim is "+
			"capturing a fragment rather than a message (ADR-0028)", ct)
	}
	if strings.HasPrefix(body, "[") {
		t.Fatalf("the reply is a JSON array, not a single object: %s", body)
	}
	var one map[string]any
	if err := json.Unmarshal([]byte(body), &one); err != nil {
		t.Fatalf("the reply is not a single JSON object: %v\n%s", err, body)
	}
	// And exactly one message: no trailing framing after the object.
	dec := json.NewDecoder(strings.NewReader(body))
	if err := dec.Decode(&one); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if dec.More() {
		t.Fatal("the reply carried more than one JSON value")
	}
}

// -----------------------------------------------------------------------
// The create path: what the shim actually rewrites
// -----------------------------------------------------------------------

// runOperationRequest is a gated run_operation from a client that either does
// or does not advertise the Tasks extension. The capability is the ONLY
// difference between the two goldens below, which is the point.
func runOperationRequest(capable bool) string {
	caps := `{}`
	if capable {
		caps = `{"extensions":{"io.modelcontextprotocol/tasks":{}}}`
	}
	return `{"jsonrpc":"2.0","id":9,"method":"tools/call","params":{"_meta":{` +
		`"io.modelcontextprotocol/protocolVersion":"2026-07-28",` +
		`"io.modelcontextprotocol/clientInfo":{"name":"golden-client","version":"0.0.1"},` +
		`"io.modelcontextprotocol/clientCapabilities":` + caps + `},` +
		`"name":"run_operation","arguments":{"operation":"service.restart","args":{"unit":"nginx"}}}}`
}

// TestGolden_CreateForACapableClient pins the CreateTaskResult the shim
// produces — the single most important golden in this file, because it is the
// only output in the system that no SDK code produced and no SDK test covers.
func TestGolden_CreateForACapableClient(t *testing.T) {
	srv := goldenServerWithExec(t, goldenTasks{}, goldenParker{})

	status, body, _ := postJSONRPC(t, srv, "tools/call", "run_operation", runOperationRequest(true))
	if status != http.StatusOK {
		t.Fatalf("status = %d; body = %s", status, body)
	}
	assertGoldenJSON(t, body, `{
	  "jsonrpc":"2.0","id":9,
	  "result":{
	    "_meta":{"io.modelcontextprotocol/serverInfo":{"name":"relay","version":"0.1.0"}},
	    "resultType":"task",
	    "taskId":"task-golden-1",
	    "status":"working",
	    "createdAt":"2026-08-17T09:00:00Z",
	    "lastUpdatedAt":"2026-08-17T09:00:00Z",
	    "ttlMs":3600000,
	    "pollIntervalMs":5000
	  }
	}`)
}

// TestGolden_CreateForANonCapableClient pins the universal path, byte for byte.
//
// This is ADR-0027 decision 2 as a fixture: a client that knows nothing about
// Tasks must be able to drive a gated dispatch to completion. If the shim ever
// starts touching this response, THIS is the test that says so — and the
// content below is what an approver-facing client actually needs, so a
// regression here is a functional break, not a cosmetic one.
func TestGolden_CreateForANonCapableClient(t *testing.T) {
	srv := goldenServerWithExec(t, goldenTasks{}, goldenParker{})

	status, body, _ := postJSONRPC(t, srv, "tools/call", "run_operation", runOperationRequest(false))
	if status != http.StatusOK {
		t.Fatalf("status = %d; body = %s", status, body)
	}

	var resp struct {
		Result struct {
			ResultType        string `json:"resultType"`
			StructuredContent struct {
				PendingApproval map[string]any `json:"pending_approval"`
			} `json:"structuredContent"`
		} `json:"result"`
	}
	if err := json.Unmarshal([]byte(body), &resp); err != nil {
		t.Fatalf("decode: %v; body = %s", err, body)
	}

	if resp.Result.ResultType != "complete" {
		t.Fatalf("resultType = %q, want complete — a non-advertising client must never be sent a task result", resp.Result.ResultType)
	}
	parked := resp.Result.StructuredContent.PendingApproval
	if parked == nil {
		t.Fatalf("no pending_approval in %s", body)
	}

	want := map[string]any{
		"status":          "pending_approval",
		"request_id":      goldenRequestID,
		"plan_hash":       "hash-golden-1",
		"summary":         `service.restart(unit="nginx") [mutate] on 1 node(s): node-a`,
		"progress":        "0 of 1",
		"expires_at":      "2026-08-17T13:00:00Z",
		"decision_path":   "/api/v1/approvals/" + goldenRequestID + "/decision",
		"task_id":         goldenTaskID,
		"task_expires_at": "2026-08-17T10:00:00Z",
	}
	for k, v := range want {
		if parked[k] != v {
			t.Errorf("pending_approval[%q] = %v, want %v", k, parked[k], v)
		}
	}
	if rules, ok := parked["matched_rules"].([]any); !ok || len(rules) != 1 || rules[0] != "all-mutates-need-a-human" {
		t.Errorf("matched_rules = %v, want the rule that parked it named", parked["matched_rules"])
	}
	if next, _ := parked["next_step"].(string); next == "" {
		t.Error("next_step is empty; an AI-agent reading this result needs to be told that waiting is correct")
	}
}
