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
)

// golden_test.go holds the fixtures the MCP surface's wire tests share (a fixed
// clock, a credential, a parking Executor, a raw JSON-RPC poster) and the
// exact-JSON tests of a parked dispatch's result and of the methods the surface
// does not serve.
//
// Exact-JSON goldens turn an SDK upgrade that silently changes the response
// JSON into a loud failure. If one of these changes after a dependency bump,
// read the diff before updating it: the diff IS the drift report.
//
// These run through the real mcp.New handler — real SDK dispatch — with fake
// collaborators and a fixed clock, so the only thing varying is the wire.

var goldenNow = time.Date(2026, 8, 17, 9, 0, 0, 0, time.UTC)

const (
	// The authenticator only reaches its verifier for something shaped like an
	// API Token, so the fixture has to carry the real prefix.
	goldenCredential = accounts.TokenPrefix + "0123456789abcdef.golden-secret" // test fixture, not a real credential
	goldenRequestID  = "req-golden-1"
)

// -----------------------------------------------------------------------
// Fakes
// -----------------------------------------------------------------------

// goldenJobs is a JobResultReader fake that returns one deterministic Task.
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
// so the park goldens below are a function of the RENDERING and of nothing that
// varies.
type goldenParker struct{}

func (goldenParker) Start(context.Context, capability.Principal, capability.Selector, jobs.Action, capability.StartOptions) (capability.StartedJob, error) {
	return capability.StartedJob{}, &capability.ParkedError{
		RequestID: goldenRequestID,
		PlanHash:  "hash-golden-1",
		Summary:   `service.restart(unit="nginx") [mutate] on 1 node(s): node-a`,
		Rules:     []string{"all-mutates-need-a-human"},
		ExpiresAt: goldenNow.Add(4 * time.Hour),
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
func goldenServer(t *testing.T) *httptest.Server {
	t.Helper()
	return goldenServerWithExec(t, nil)
}

func goldenServerWithExec(t *testing.T, exec mcp.Executor) *httptest.Server {
	t.Helper()

	// No golden test here calls list_nodes/describe_node/list_operations, so
	// the read lane is left nil — mirroring the nil ReadAuditor argument below.
	handler := mcp.New(nil, opsLister{}, exec, goldenJobs{}, nil,
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
			"updating the golden.", got, want)
	}
}

// statelessMeta is what a >= 2026-07-28 client restates on every request
// (SEP-2575). Relay runs stateless, so there is no session carrying the
// initialize handshake forward and the server refuses a request without it. It
// declares the Tasks extension, so the requests below come from a client that
// could use a task handle if the Relay ever rendered one.
const statelessMeta = `"_meta":{` +
	`"io.modelcontextprotocol/protocolVersion":"2026-07-28",` +
	`"io.modelcontextprotocol/clientInfo":{"name":"golden-client","version":"0.0.1"},` +
	`"io.modelcontextprotocol/clientCapabilities":{"extensions":{"io.modelcontextprotocol/tasks":{}}}}`

// runOperationRequest is a gated run_operation from a client that either does
// or does not advertise the Tasks extension. The capability is the ONLY
// difference between the two tests below, which is the point.
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

// TestPendingApproval_TasksDeclaringClientGetsPendingApproval (AP-85): a park
// that asks nobody is answered pending_approval even to a client that declares
// the Tasks extension. The result is an ordinary complete result carrying no
// task handle field and no task envelope.
func TestPendingApproval_TasksDeclaringClientGetsPendingApproval(t *testing.T) {
	srv := goldenServerWithExec(t, goldenParker{})

	status, body, _ := postJSONRPC(t, srv, "tools/call", "run_operation", runOperationRequest(true))
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
		t.Fatalf("resultType = %q, want complete — a park is never rendered as a task", resp.Result.ResultType)
	}
	parked := resp.Result.StructuredContent.PendingApproval
	if parked["status"] != "pending_approval" {
		t.Fatalf("pending_approval.status = %v in %s", parked["status"], body)
	}
	for _, key := range []string{"task_id", "task_expires_at"} {
		if _, present := parked[key]; present {
			t.Errorf("pending_approval carries %q; a park has no task handle", key)
		}
	}
	for _, marker := range []string{"taskId", "pollIntervalMs", "ttlMs", `"resultType":"task"`} {
		if strings.Contains(body, marker) {
			t.Errorf("body contains %q; nothing renders a park as an MCP task", marker)
		}
	}
}

// TestGolden_CreateForANonCapableClient pins the pending_approval result, field
// by field (AP-85).
//
// This is ADR-0027 decision 2 as a fixture: a client that knows nothing about
// Tasks must be able to drive a gated dispatch to completion. The content
// below is what an approver-facing client actually needs, so a regression here
// is a functional break, not a cosmetic one.
func TestGolden_CreateForANonCapableClient(t *testing.T) {
	srv := goldenServerWithExec(t, goldenParker{})

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
		t.Fatalf("resultType = %q, want complete", resp.Result.ResultType)
	}
	parked := resp.Result.StructuredContent.PendingApproval
	if parked == nil {
		t.Fatalf("no pending_approval in %s", body)
	}

	want := map[string]any{
		"status":        "pending_approval",
		"request_id":    goldenRequestID,
		"plan_hash":     "hash-golden-1",
		"summary":       `service.restart(unit="nginx") [mutate] on 1 node(s): node-a`,
		"expires_at":    "2026-08-17T13:00:00Z",
		"decision_path": "/api/v1/approvals/" + goldenRequestID + "/decision",
	}
	for k, v := range want {
		if parked[k] != v {
			t.Errorf("pending_approval[%q] = %v, want %v", k, parked[k], v)
		}
	}
	for _, key := range []string{"task_id", "task_expires_at"} {
		if _, present := parked[key]; present {
			t.Errorf("pending_approval carries %q; a park has no task handle", key)
		}
	}
	if rules, ok := parked["matched_rules"].([]any); !ok || len(rules) != 1 || rules[0] != "all-mutates-need-a-human" {
		t.Errorf("matched_rules = %v, want the rule that parked it named", parked["matched_rules"])
	}
	if next, _ := parked["next_step"].(string); next == "" {
		t.Error("next_step is empty; an AI-agent reading this result needs to be told that waiting is correct")
	}
}

// TestTasksMethodsAreNotServed (AP-85): tasks/get and tasks/cancel are not
// methods this surface serves. Whatever error the SDK answers an unregistered
// method with, it is never a result.
func TestTasksMethodsAreNotServed(t *testing.T) {
	srv := goldenServer(t)

	for _, method := range []string{"tasks/get", "tasks/cancel"} {
		t.Run(method, func(t *testing.T) {
			body := `{"jsonrpc":"2.0","id":1,"method":"` + method + `","params":{` +
				statelessMeta + `,"taskId":"task-nope"}}`
			status, got, _ := postJSONRPC(t, srv, method, "", body)

			var resp struct {
				Result json.RawMessage `json:"result"`
				Error  *struct {
					Code int `json:"code"`
				} `json:"error"`
			}
			if err := json.Unmarshal([]byte(got), &resp); err != nil {
				t.Fatalf("status %d: reply is not a JSON-RPC message: %v\n%s", status, err, got)
			}
			if resp.Result != nil {
				t.Fatalf("%s was served: %s", method, got)
			}
			if resp.Error == nil || resp.Error.Code != -32601 {
				t.Errorf("status %d, error = %+v, want JSON-RPC -32601 method not found; body = %s", status, resp.Error, got)
			}
		})
	}
}
