package mcp_test

import (
	"context"
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"net/http"
	"net/http/httptest"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Felag-Engineering/relay/relay/internal/approval"
	"github.com/Felag-Engineering/relay/relay/internal/capability"
	"github.com/Felag-Engineering/relay/relay/internal/controlplane"
	"github.com/Felag-Engineering/relay/relay/internal/controlplane/mcp"
	"github.com/Felag-Engineering/relay/relay/internal/jobs"
)

// elicit_test.go is S2b of #646's mcp-handler-seam proof (elicit.go): fixture
// request -> asserted response, over the SDK's real HTTP transport, mirroring
// taskgolden_test.go's fixtures rather than re-inventing them. Every test
// here reaches the option through mcp.WithApprovalElicitation directly,
// package mcp_test's own seam onto mcp.New — the composition root passes it
// too, since #730, but this file's seam is deliberately independent of that.

// askableElicitRequestID/askableElicitPlanHash/askableElicitTaskID are the
// fixed fields askableParker's park carries, mirroring goldenParker's shape
// (taskgolden_test.go) so the two fixture families stay visually comparable.
const (
	askableElicitRequestID = "req-elicit-1"
	askableElicitPlanHash  = "hash-elicit-1"
	askableElicitTaskID    = "task-elicit-1"
)

// askableParker is an Executor whose every dispatch parks with a fixed
// *capability.ParkedError, Askable set from the field — so the rendering
// tests below are a function of the RENDERING alone, mirroring
// taskgolden_test.go's goldenParker.
type askableParker struct{ askable bool }

func (p askableParker) Start(context.Context, capability.Principal, capability.Selector, jobs.Action, capability.StartOptions) (capability.StartedJob, error) {
	return capability.StartedJob{}, &capability.ParkedError{
		RequestID:     askableElicitRequestID,
		PlanHash:      askableElicitPlanHash,
		Summary:       `service.restart(unit="nginx") [mutate] on 1 node(s): node-a`,
		Progress:      "0 of 1",
		Rules:         []string{"all-mutates-need-a-human"},
		ExpiresAt:     goldenNow.Add(4 * time.Hour),
		TaskID:        askableElicitTaskID,
		TaskExpiresAt: goldenNow.Add(time.Hour),
		Askable:       p.askable,
	}
}

func (askableParker) CancelJob(context.Context, capability.Principal, string) error { return nil }

func (askableParker) Plan(context.Context, capability.Principal, capability.Selector, jobs.Action) (capability.PlanResult, error) {
	return capability.PlanResult{}, nil
}

// countingAskableParker wraps askableParker and counts every Run/Plan call,
// so TestPlanPreflightNeverEmitsAQuestion (mcp seam) can assert on the counts
// rather than on the fixture's own state.
type countingAskableParker struct {
	askableParker
	runs  *atomic.Int32
	plans *atomic.Int32
}

func (p countingAskableParker) Start(ctx context.Context, principal capability.Principal, sel capability.Selector, act jobs.Action, o capability.StartOptions) (capability.StartedJob, error) {
	p.runs.Add(1)
	return p.askableParker.Start(ctx, principal, sel, act, o)
}

func (p countingAskableParker) Plan(context.Context, capability.Principal, capability.Selector, jobs.Action) (capability.PlanResult, error) {
	p.plans.Add(1)
	return capability.PlanResult{}, nil
}

func (p countingAskableParker) CancelJob(ctx context.Context, principal capability.Principal, jobID string) error {
	return p.askableParker.CancelJob(ctx, principal, jobID)
}

// stubDecider implements mcp.ApprovalDecider and fails the test if ever
// called: this step renders a question, it never decides one (ADR-0029
// decision 5 is tools_approval.go's alone). It reports the failure with
// t.Error rather than t.Fatal: the SDK invokes DecideApproval from its own
// handler goroutine, and t.Fatal there would only stop that goroutine —
// silently, since t.Fatal is documented to require running on the test's own
// goroutine — rather than the test itself.
type stubDecider struct{ t *testing.T }

func (d stubDecider) DecideApproval(context.Context, capability.Principal, capability.ApprovalDecision) (approval.Request, error) {
	d.t.Helper()
	d.t.Error("stubDecider.DecideApproval was called — S2b never decides, it only renders a question")
	return approval.Request{}, nil
}

// elicitServer mounts the real handler behind the real authenticator, exactly
// like taskgolden_test.go's goldenServerWithExec, with opts appended after
// the fixed clock so a test can turn the option (and a decider) on.
func elicitServer(t *testing.T, exec mcp.Executor, tasks mcp.TaskResolver, opts ...mcp.Option) *httptest.Server {
	t.Helper()
	allOpts := append([]mcp.Option{mcp.WithClock(func() time.Time { return goldenNow })}, opts...)
	handler := mcp.New(nil, opsLister{}, exec, goldenJobs{}, nil, tasks, allOpts...)

	mux := http.NewServeMux()
	mux.Handle("/mcp", handler)
	srv := httptest.NewServer(controlplane.NewAuthenticator(goldenVerifier{}).Middleware(mux))
	t.Cleanup(srv.Close)
	return srv
}

// elicitRunOperationRequestAs is runOperationRequest (taskgolden_test.go)
// generalized to an arbitrary declared client name and clientCapabilities
// JSON value, so a test can drive every combination the emission predicate
// cares about — including AP-78's declared-name condition.
func elicitRunOperationRequestAs(name, caps string) string {
	return `{"jsonrpc":"2.0","id":9,"method":"tools/call","params":{"_meta":{` +
		`"io.modelcontextprotocol/protocolVersion":"2026-07-28",` +
		`"io.modelcontextprotocol/clientInfo":{"name":"` + name + `","version":"0.0.1"},` +
		`"io.modelcontextprotocol/clientCapabilities":` + caps + `},` +
		`"name":"run_operation","arguments":{"operation":"service.restart","args":{"unit":"nginx"}}}}`
}

// mcpClientNameGleipnir mirrors elicit.go's own unexported clientNameGleipnir
// — duplicated here for the same reason mcpMetaKeyRequestID/mcpMetaKeyPlanHash
// are (below): this test file is package mcp_test and cannot reach elicit.go's
// unexported constant, and a drift between the two literals would fail every
// test in this file that expects a question.
const mcpClientNameGleipnir = "gleipnir"

// elicitRunOperationRequest is elicitRunOperationRequestAs declaring the
// recognised client name "gleipnir" (AP-78) — every test in this file that
// is not itself about the declared name uses this wrapper.
func elicitRunOperationRequest(caps string) string {
	return elicitRunOperationRequestAs(mcpClientNameGleipnir, caps)
}

// elicitCaps and tasksAndElicitCaps are the clientCapabilities bodies the
// tests below need repeatedly.
const (
	elicitCaps         = `{"elicitation":{"form":{}}}`
	noElicitCaps       = `{}`
	tasksOnlyCaps      = `{"extensions":{"io.modelcontextprotocol/tasks":{}}}`
	tasksAndElicitCaps = `{"elicitation":{"form":{}},"extensions":{"io.modelcontextprotocol/tasks":{}}}`
)

// decodedResult is the subset of a tools/call JSON-RPC response elicit_test.go
// asserts against.
type decodedResult struct {
	ResultType        string          `json:"resultType"`
	Meta              map[string]any  `json:"_meta"`
	Content           json.RawMessage `json:"content"`
	StructuredContent json.RawMessage `json:"structuredContent"`
	InputRequests     json.RawMessage `json:"inputRequests"`
	RequestState      string          `json:"requestState"`
	IsError           bool            `json:"isError"`
}

// decodeElicitResult unmarshals body's JSON-RPC result.
func decodeElicitResult(t *testing.T, body string) decodedResult {
	t.Helper()
	var resp struct {
		Result decodedResult `json:"result"`
	}
	if err := json.Unmarshal([]byte(body), &resp); err != nil {
		t.Fatalf("decode: %v; body = %s", err, body)
	}
	return resp.Result
}

func isEmptyJSON(raw json.RawMessage) bool {
	s := strings.TrimSpace(string(raw))
	return s == "" || s == "null" || s == "[]"
}

// TestElicit_QuestionCarriesNoContent is the headline shape proof (AP-60):
// an askable park, from an MRTR-capable, elicitation-advertising client,
// with the option on and a decider wired, renders an input-required result
// carrying exactly one input request keyed by the request ID, a sealed
// requestState, and the request ID/plan hash in `_meta` — never Content,
// never structuredContent, never the pending_approval string anywhere.
func TestElicit_QuestionCarriesNoContent(t *testing.T) {
	srv := elicitServer(t, askableParker{askable: true}, goldenTasks{},
		mcp.WithApprovalElicitation(), mcp.WithApprovalDecider(stubDecider{t: t}))

	status, body, _ := postJSONRPC(t, srv, "tools/call", "run_operation", elicitRunOperationRequest(elicitCaps))
	if status != 200 {
		t.Fatalf("status = %d; body = %s", status, body)
	}
	if strings.Contains(body, "pending_approval") {
		t.Fatalf("body contains \"pending_approval\": %s", body)
	}

	res := decodeElicitResult(t, body)
	if res.IsError {
		t.Fatalf("isError = true, want false: %s", body)
	}
	if res.ResultType != "input_required" {
		t.Errorf("resultType = %q, want input_required", res.ResultType)
	}
	if !isEmptyJSON(res.Content) {
		t.Errorf("content = %s, want absent/null/empty", res.Content)
	}
	if !isEmptyJSON(res.StructuredContent) {
		t.Errorf("structuredContent = %s, want absent", res.StructuredContent)
	}
	if res.RequestState == "" {
		t.Error("requestState is empty, want the sealed state")
	}

	// Every InputRequestMap entry wraps its params under a "method" wire
	// discriminator (go-sdk mcp/protocol.go's InputRequestMap.MarshalJSON) —
	// methodElicit ("elicitation/create") for an *sdkmcp.ElicitParams — so the
	// message/schema live one level down, under "params".
	var reqs map[string]struct {
		Method string `json:"method"`
		Params struct {
			Mode            string         `json:"mode"`
			Message         string         `json:"message"`
			RequestedSchema map[string]any `json:"requestedSchema"`
			Meta            map[string]any `json:"_meta"`
		} `json:"params"`
	}
	if err := json.Unmarshal(res.InputRequests, &reqs); err != nil {
		t.Fatalf("decode inputRequests: %v; %s", err, res.InputRequests)
	}
	if len(reqs) != 1 {
		t.Fatalf("inputRequests has %d entries, want exactly 1: %+v", len(reqs), reqs)
	}
	entry, ok := reqs[askableElicitRequestID]
	if !ok {
		t.Fatalf("inputRequests is not keyed by the request ID %q: %+v", askableElicitRequestID, reqs)
	}
	if entry.Method != "elicitation/create" {
		t.Errorf("method = %q, want elicitation/create", entry.Method)
	}
	if entry.Params.Mode != "form" {
		t.Errorf("mode = %q, want form", entry.Params.Mode)
	}
	if entry.Params.Message != `service.restart(unit="nginx") [mutate] on 1 node(s): node-a` {
		t.Errorf("message = %q, want the Relay-authored summary verbatim", entry.Params.Message)
	}
	if entry.Params.Meta != nil {
		t.Errorf("input request _meta = %+v, want nil — no vendor elicitation-kind hint", entry.Params.Meta)
	}
	wantSchema := map[string]any{"type": "object", "properties": map[string]any{}}
	gotSchema, err := json.Marshal(entry.Params.RequestedSchema)
	if err != nil {
		t.Fatalf("marshal requestedSchema: %v", err)
	}
	wantSchemaJSON, _ := json.Marshal(wantSchema)
	if string(gotSchema) != string(wantSchemaJSON) {
		t.Errorf("requestedSchema = %s, want %s", gotSchema, wantSchemaJSON)
	}

	if got := res.Meta[mcpMetaKeyRequestID]; got != askableElicitRequestID {
		t.Errorf("_meta[%q] = %v, want %q", mcpMetaKeyRequestID, got, askableElicitRequestID)
	}
	if got := res.Meta[mcpMetaKeyPlanHash]; got != askableElicitPlanHash {
		t.Errorf("_meta[%q] = %v, want %q", mcpMetaKeyPlanHash, got, askableElicitPlanHash)
	}
}

// mcpMetaKeyRequestID/mcpMetaKeyPlanHash mirror elicit.go's own unexported
// constants — duplicated here because this test file is package mcp_test and
// cannot reach the unexported originals; a drift between the two literals
// would fail TestElicit_QuestionCarriesNoContent immediately.
const (
	mcpMetaKeyRequestID = "relay/request_id"
	mcpMetaKeyPlanHash  = "relay/plan_hash"
)

// TestElicit_NonAskableParkRendersPendingApproval is AP-61/AP-62: a park the
// capability layer marked NOT askable renders byte-for-byte the same
// pending_approval result as a server with no elicitation option at all,
// even with the option on, a decider wired, and an MRTR/elicitation-capable
// client — Askable is read, never recomputed (invariant 10).
func TestElicit_NonAskableParkRendersPendingApproval(t *testing.T) {
	req := elicitRunOperationRequest(elicitCaps)

	baseline := elicitServer(t, askableParker{askable: false}, goldenTasks{})
	_, wantBody, _ := postJSONRPC(t, baseline, "tools/call", "run_operation", req)
	if !strings.Contains(wantBody, "pending_approval") {
		t.Fatalf("baseline body has no pending_approval, the golden itself is broken: %s", wantBody)
	}

	withElicit := elicitServer(t, askableParker{askable: false}, goldenTasks{},
		mcp.WithApprovalElicitation(), mcp.WithApprovalDecider(stubDecider{t: t}))
	_, gotBody, _ := postJSONRPC(t, withElicit, "tools/call", "run_operation", req)

	assertGoldenJSON(t, gotBody, wantBody)
}

// TestElicit_OutOfBandParkNeverAsks_HandlerSeam is AP-69's weaker,
// mcp-handler-seam companion to cmd/relay/elicit_e2e_test.go's
// TestElicit_OutOfBandParkNeverAsks, which drives the real gate (the real
// source of Askable=false for an out-of-band rule); here the fixture stands
// in for that gate by setting askableParker{askable: false} directly (an
// out-of-band park is exactly a non-askable one; askableBy's channel term,
// capability/approval.go), so what this test actually proves is the same
// claim TestElicit_NonAskableParkRendersPendingApproval does — that an
// elicitation-advertising client still gets pending_approval when Askable is
// false — kept as a separate, differently-shaped assertion (substring rather
// than golden-JSON-equal) rather than folded into it, so a regression in
// either style of check is still caught.
func TestElicit_OutOfBandParkNeverAsks_HandlerSeam(t *testing.T) {
	srv := elicitServer(t, askableParker{askable: false}, goldenTasks{},
		mcp.WithApprovalElicitation(), mcp.WithApprovalDecider(stubDecider{t: t}))

	_, body, _ := postJSONRPC(t, srv, "tools/call", "run_operation", elicitRunOperationRequest(elicitCaps))
	res := decodeElicitResult(t, body)
	if res.ResultType == "input_required" {
		t.Fatalf("resultType = input_required, want pending_approval rendering (out-of-band park): %s", body)
	}
	if !strings.Contains(body, "pending_approval") {
		t.Fatalf("body has no pending_approval: %s", body)
	}
}

// TestElicit_OptionOffChangesNothing is the AP-70 option-off guard at the mcp
// handler seam: an askable park from an MRTR/elicitation-capable client
// renders identically to today whenever the option is off, or a decider is
// unwired — three servers, one canonical body.
func TestElicit_OptionOffChangesNothing(t *testing.T) {
	req := elicitRunOperationRequest(elicitCaps)

	noOptions := elicitServer(t, askableParker{askable: true}, goldenTasks{})
	_, wantBody, _ := postJSONRPC(t, noOptions, "tools/call", "run_operation", req)
	if !strings.Contains(wantBody, "pending_approval") {
		t.Fatalf("baseline body has no pending_approval, the golden itself is broken: %s", wantBody)
	}

	optionOnlyNoDecider := elicitServer(t, askableParker{askable: true}, goldenTasks{}, mcp.WithApprovalElicitation())
	_, body2, _ := postJSONRPC(t, optionOnlyNoDecider, "tools/call", "run_operation", req)
	assertGoldenJSON(t, body2, wantBody)

	deciderOnlyNoOption := elicitServer(t, askableParker{askable: true}, goldenTasks{}, mcp.WithApprovalDecider(stubDecider{t: t}))
	_, body3, _ := postJSONRPC(t, deciderOnlyNoOption, "tools/call", "run_operation", req)
	assertGoldenJSON(t, body3, wantBody)
}

// TestElicit_NoElicitationCapabilityDoesNotAsk: `_meta` is 2026-07-28 (MRTR
// capable) but clientCapabilities carries no elicitation object at all —
// predicate condition 3 refuses, so the park renders pending_approval and no
// inputRequests.
func TestElicit_NoElicitationCapabilityDoesNotAsk(t *testing.T) {
	srv := elicitServer(t, askableParker{askable: true}, goldenTasks{},
		mcp.WithApprovalElicitation(), mcp.WithApprovalDecider(stubDecider{t: t}))

	_, body, _ := postJSONRPC(t, srv, "tools/call", "run_operation", elicitRunOperationRequest(noElicitCaps))
	res := decodeElicitResult(t, body)
	if len(res.InputRequests) != 0 {
		t.Fatalf("inputRequests present with no elicitation capability advertised: %s", body)
	}
	if !strings.Contains(body, "pending_approval") {
		t.Fatalf("body has no pending_approval: %s", body)
	}
}

// TestElicit_ElicitedParkEmitsNoTaskEnvelope is AP-71: with the real task
// shim wired (goldenTasks), a client capable of BOTH elicitation and Tasks
// gets the question and no task envelope at all (no taskId/status/ttlMs), while
// a client capable of Tasks alone (cannot be asked) still gets today's task
// envelope unchanged.
func TestElicit_ElicitedParkEmitsNoTaskEnvelope(t *testing.T) {
	srv := elicitServer(t, askableParker{askable: true}, goldenTasks{},
		mcp.WithApprovalElicitation(), mcp.WithApprovalDecider(stubDecider{t: t}))

	_, bothBody, _ := postJSONRPC(t, srv, "tools/call", "run_operation", elicitRunOperationRequest(tasksAndElicitCaps))
	res := decodeElicitResult(t, bothBody)
	if res.ResultType != "input_required" {
		t.Errorf("resultType = %q, want input_required", res.ResultType)
	}
	if len(res.InputRequests) == 0 {
		t.Errorf("inputRequests missing: %s", bothBody)
	}
	if !isEmptyJSON(res.StructuredContent) {
		t.Errorf("structuredContent present, want none: %s", bothBody)
	}
	for _, forbidden := range []string{`"taskId"`, `"pollIntervalMs"`, `"ttlMs"`} {
		if strings.Contains(bothBody, forbidden) {
			t.Errorf("body contains %s, want no task envelope: %s", forbidden, bothBody)
		}
	}

	_, taskOnlyBody, _ := postJSONRPC(t, srv, "tools/call", "run_operation", elicitRunOperationRequest(tasksOnlyCaps))
	var taskResp struct {
		Result struct {
			ResultType string `json:"resultType"`
			TaskID     string `json:"taskId"`
			Status     string `json:"status"`
		} `json:"result"`
	}
	if err := json.Unmarshal([]byte(taskOnlyBody), &taskResp); err != nil {
		t.Fatalf("decode: %v; body = %s", err, taskOnlyBody)
	}
	if taskResp.Result.ResultType != "task" {
		t.Errorf("resultType = %q, want task (Tasks-capable client that cannot be asked keeps today's envelope)", taskResp.Result.ResultType)
	}
	if taskResp.Result.TaskID != askableElicitTaskID {
		t.Errorf("taskId = %q, want %q", taskResp.Result.TaskID, askableElicitTaskID)
	}
	if taskResp.Result.Status != "working" {
		t.Errorf("status = %q, want working", taskResp.Result.Status)
	}
}

// TestElicit_UnrecognisedMRTRClientGetsPendingApproval is AP-78's mcp-handler
// seam proof: an MRTR-capable, elicitation-advertising client that declares a
// name Relay does not recognise still gets today's pending_approval — no
// inputRequests, an empty requestState — exactly the shape
// TestElicit_NoElicitationCapabilityDoesNotAsk asserts for a missing
// capability, now because of an unrecognised name instead. The armed control,
// on the SAME server and fixture, only changes the declared name to a
// recognised one and really does ask — proving the refusal above is about the
// name, not some other difference in the fixture.
func TestElicit_UnrecognisedMRTRClientGetsPendingApproval(t *testing.T) {
	srv := elicitServer(t, askableParker{askable: true}, goldenTasks{},
		mcp.WithApprovalElicitation(), mcp.WithApprovalDecider(stubDecider{t: t}))

	_, body, _ := postJSONRPC(t, srv, "tools/call", "run_operation", elicitRunOperationRequestAs("elicit-client", elicitCaps))
	res := decodeElicitResult(t, body)
	if res.ResultType == "input_required" {
		t.Fatalf("resultType = input_required, want pending_approval (unrecognised client name): %s", body)
	}
	if len(res.InputRequests) != 0 {
		t.Fatalf("inputRequests present for an unrecognised client name: %s", body)
	}
	if res.RequestState != "" {
		t.Errorf("requestState = %q, want empty", res.RequestState)
	}
	if !strings.Contains(body, "pending_approval") {
		t.Fatalf("body has no pending_approval: %s", body)
	}

	// Armed control: the SAME server and fixture, only the declared client
	// name changed to a recognised one ("gleipnir").
	_, controlBody, _ := postJSONRPC(t, srv, "tools/call", "run_operation", elicitRunOperationRequest(elicitCaps))
	controlRes := decodeElicitResult(t, controlBody)
	if controlRes.ResultType != "input_required" {
		t.Errorf("armed control: resultType = %q, want input_required", controlRes.ResultType)
	}
}

// TestElicit_ClaudeCodeOnAnAPITokenSessionIsNotAsked is AP-78's other
// recognised name, with Claude Code's OWN observed capability shape (roots
// listChanged, elicitation advertising both form and url) rather than the
// minimal elicitCaps fixture — so this also proves the Form-capable branch of
// the predicate still holds when url is ALSO advertised. goldenVerifier's
// Account is a HUMAN one, but its session is an API Token, not OAuth: AP-78
// asks claude-code only on an OAuth session of a human Account, so an API
// Token human is not enough, and this still gets today's pending_approval.
func TestElicit_ClaudeCodeOnAnAPITokenSessionIsNotAsked(t *testing.T) {
	srv := elicitServer(t, askableParker{askable: true}, goldenTasks{},
		mcp.WithApprovalElicitation(), mcp.WithApprovalDecider(stubDecider{t: t}))

	const claudeCodeCaps = `{"roots":{"listChanged":true},"elicitation":{"form":{},"url":{}}}`
	_, body, _ := postJSONRPC(t, srv, "tools/call", "run_operation", elicitRunOperationRequestAs("claude-code", claudeCodeCaps))
	res := decodeElicitResult(t, body)
	if res.ResultType == "input_required" {
		t.Fatalf("resultType = input_required, want pending_approval (claude-code off an OAuth human session, AP-78): %s", body)
	}
	if len(res.InputRequests) != 0 {
		t.Errorf("inputRequests present for claude-code on an API Token session: %s", body)
	}
	if res.RequestState != "" {
		t.Errorf("requestState = %q, want empty", res.RequestState)
	}
	if !strings.Contains(body, "pending_approval") {
		t.Fatalf("body has no pending_approval: %s", body)
	}
}

// TestElicit_UnrecognisedClientsRetryFieldsAreIgnored is AP-70 applied to an
// unrecognised name: a call carrying a VALIDLY SEALED requestState — from a
// real first call, asked while declaring "gleipnir" — and a well-formed
// accept carrying a real responder assertion, but declaring a name Relay does
// not recognise on the RETRY, is treated as an ordinary call — its retry
// fields are never even read (clientCanBeAsked gates isAnsweredRetry too), so
// it parks again rather than being decided. Sealing the state for real (rather
// than a garbage string) means the only thing that can explain the park below
// is condition 5 (the declared name), never the seal failing to open on its
// own. stubDecider fails the test if it is ever called, which is this test's
// proof that the decider was never reached.
func TestElicit_UnrecognisedClientsRetryFieldsAreIgnored(t *testing.T) {
	srv := elicitServer(t, askableParker{askable: true}, goldenTasks{},
		mcp.WithApprovalElicitation(), mcp.WithApprovalDecider(stubDecider{t: t}))

	_, firstBody, _ := postJSONRPC(t, srv, "tools/call", "run_operation", elicitRunOperationRequest(elicitCaps))
	first := decodeElicitResult(t, firstBody)
	if first.ResultType != "input_required" {
		t.Fatalf("first call: resultType = %q, want input_required: %s", first.ResultType, firstBody)
	}
	if first.RequestState == "" {
		t.Fatalf("first call: requestState is empty")
	}

	retryBody := `{"jsonrpc":"2.0","id":9,"method":"tools/call","params":{"_meta":{` +
		`"io.modelcontextprotocol/protocolVersion":"2026-07-28",` +
		`"io.modelcontextprotocol/clientInfo":{"name":"some-other-client","version":"0.0.1"},` +
		`"io.modelcontextprotocol/clientCapabilities":` + elicitCaps + `},` +
		`"name":"run_operation","arguments":{"operation":"service.restart","args":{"unit":"nginx"}},` +
		`"requestState":"` + first.RequestState + `",` +
		`"inputResponses":{"` + askableElicitRequestID + `":{"action":"accept","_meta":{"io.gleipnir/responder":{"gate":"permission","username":"alice"}}}}}}`

	status, respBody, _ := postJSONRPC(t, srv, "tools/call", "run_operation", retryBody)
	if status != 200 {
		t.Fatalf("status = %d; body = %s", status, respBody)
	}
	res := decodeElicitResult(t, respBody)
	if res.ResultType == "input_required" {
		t.Fatalf("resultType = input_required, want pending_approval (an unrecognised name's retry fields are ignored): %s", respBody)
	}
	if !strings.Contains(respBody, "pending_approval") {
		t.Fatalf("body has no pending_approval: %s", respBody)
	}
	if res.RequestState != "" {
		t.Errorf("requestState = %q, want empty", res.RequestState)
	}
	if strings.Contains(respBody, "answer_refused") || strings.Contains(respBody, `"decision"`) {
		t.Errorf("body carries an answered-retry block, want none (the retry must be treated as an ordinary call): %s", respBody)
	}
}

// TestElicit_ClaudeCodeRetryOnAnAPITokenSessionIsAnOrdinaryCall is the
// handler-seam "spoofed name earns nothing" proof: a call asked while
// declaring "gleipnir" (a real sealed state, on goldenVerifier's API Token
// human session), retried with the echoed requestState and a real accept but
// declaring "claude-code" on the RETRY — clientCanBeAsked is false for the
// retry (claude-code off an OAuth human session), so isAnsweredRetry treats
// it as an ordinary call (AP-70) rather than an answer, and it parks again
// instead of being decided. stubDecider fails the test if it is ever called.
func TestElicit_ClaudeCodeRetryOnAnAPITokenSessionIsAnOrdinaryCall(t *testing.T) {
	srv := elicitServer(t, askableParker{askable: true}, goldenTasks{},
		mcp.WithApprovalElicitation(), mcp.WithApprovalDecider(stubDecider{t: t}))

	_, firstBody, _ := postJSONRPC(t, srv, "tools/call", "run_operation", elicitRunOperationRequest(elicitCaps))
	first := decodeElicitResult(t, firstBody)
	if first.ResultType != "input_required" {
		t.Fatalf("first call: resultType = %q, want input_required: %s", first.ResultType, firstBody)
	}
	if first.RequestState == "" {
		t.Fatalf("first call: requestState is empty")
	}

	retryBody := `{"jsonrpc":"2.0","id":9,"method":"tools/call","params":{"_meta":{` +
		`"io.modelcontextprotocol/protocolVersion":"2026-07-28",` +
		`"io.modelcontextprotocol/clientInfo":{"name":"claude-code","version":"0.0.1"},` +
		`"io.modelcontextprotocol/clientCapabilities":` + elicitCaps + `},` +
		`"name":"run_operation","arguments":{"operation":"service.restart","args":{"unit":"nginx"}},` +
		`"requestState":"` + first.RequestState + `",` +
		`"inputResponses":{"` + askableElicitRequestID + `":{"action":"accept"}}}}`

	status, retryBodyResp, _ := postJSONRPC(t, srv, "tools/call", "run_operation", retryBody)
	if status != 200 {
		t.Fatalf("status = %d; body = %s", status, retryBodyResp)
	}
	res := decodeElicitResult(t, retryBodyResp)
	if res.ResultType == "input_required" {
		t.Fatalf("retry: resultType = input_required, want an ordinary call's own park: %s", retryBodyResp)
	}
	if !strings.Contains(retryBodyResp, "pending_approval") {
		t.Fatalf("retry body has no pending_approval — want the ordinary call's own park, not an answer outcome: %s", retryBodyResp)
	}
	if strings.Contains(retryBodyResp, "answer_refused") || strings.Contains(retryBodyResp, `"decision"`) {
		t.Errorf("retry body carries an answered-retry block, want none (the retry must be treated as an ordinary call): %s", retryBodyResp)
	}
}

// TestPlanPreflightNeverEmitsAQuestion is PF-23's guard at the mcp seam,
// where the question path is actually wired: a plan=true call against an
// askable park — even one carrying a stray requestState/inputResponses —
// never reaches the question (or the decider) at all. run_operation and
// raw_exec both return from their plan=true branch (planAndRender, calling
// exec.Plan) before isAnsweredRetry is ever consulted (tools_execution.go),
// which is why a plan call's stray answer fields change nothing: AP-70 read
// literally, "a call that did not park". The armed control shows the SAME
// fixture's non-plan call really does ask, so the zero runs above means
// "never dispatched", not "never wired for a question at all".
func TestPlanPreflightNeverEmitsAQuestion(t *testing.T) {
	var runs, plans atomic.Int32
	parker := countingAskableParker{askableParker: askableParker{askable: true}, runs: &runs, plans: &plans}
	srv := elicitServer(t, parker, goldenTasks{},
		mcp.WithApprovalElicitation(), mcp.WithApprovalDecider(stubDecider{t: t}))

	runOpPlanBody := `{"jsonrpc":"2.0","id":9,"method":"tools/call","params":{"_meta":{` +
		`"io.modelcontextprotocol/protocolVersion":"2026-07-28",` +
		`"io.modelcontextprotocol/clientInfo":{"name":"gleipnir","version":"0.0.1"},` +
		`"io.modelcontextprotocol/clientCapabilities":` + elicitCaps + `},` +
		`"name":"run_operation","arguments":{"operation":"service.restart","args":{"unit":"nginx"},"plan":true}}}`

	rawExecPlanBody := `{"jsonrpc":"2.0","id":9,"method":"tools/call","params":{"_meta":{` +
		`"io.modelcontextprotocol/protocolVersion":"2026-07-28",` +
		`"io.modelcontextprotocol/clientInfo":{"name":"gleipnir","version":"0.0.1"},` +
		`"io.modelcontextprotocol/clientCapabilities":` + elicitCaps + `},` +
		`"name":"raw_exec","arguments":{"argv":["systemctl","restart","nginx"],"plan":true}}}`

	strayAnswerBody := `{"jsonrpc":"2.0","id":9,"method":"tools/call","params":{"_meta":{` +
		`"io.modelcontextprotocol/protocolVersion":"2026-07-28",` +
		`"io.modelcontextprotocol/clientInfo":{"name":"gleipnir","version":"0.0.1"},` +
		`"io.modelcontextprotocol/clientCapabilities":` + elicitCaps + `},` +
		`"name":"run_operation","arguments":{"operation":"service.restart","args":{"unit":"nginx"},"plan":true},` +
		`"requestState":"not-a-state",` +
		`"inputResponses":{"` + askableElicitRequestID + `":{"action":"accept","_meta":{"io.gleipnir/responder":{"gate":"permission","username":"alice"}}}}}}`

	cases := []struct {
		name string
		tool string
		body string
	}{
		{"run_operation plan", "run_operation", runOpPlanBody},
		{"raw_exec plan", "raw_exec", rawExecPlanBody},
		{"plan carrying stray answer fields", "run_operation", strayAnswerBody},
	}

	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			wantPlans := int32(i + 1)
			status, body, _ := postJSONRPC(t, srv, "tools/call", tc.tool, tc.body)
			if status != 200 {
				t.Fatalf("status = %d; body = %s", status, body)
			}
			res := decodeElicitResult(t, body)
			if res.IsError {
				t.Fatalf("isError = true, want false: %s", body)
			}
			if res.ResultType == "input_required" {
				t.Fatalf("resultType = input_required, want a plan result: %s", body)
			}
			if !isEmptyJSON(res.InputRequests) {
				t.Errorf("inputRequests = %s, want absent/empty", res.InputRequests)
			}
			if res.RequestState != "" {
				t.Errorf("requestState = %q, want empty", res.RequestState)
			}
			if !strings.Contains(string(res.StructuredContent), `"plan"`) {
				t.Errorf("structuredContent = %s, want it to carry the plan key", res.StructuredContent)
			}
			if strings.Contains(string(res.StructuredContent), "pending_approval") || strings.Contains(string(res.StructuredContent), "answer_refused") {
				t.Errorf("structuredContent = %s, want neither pending_approval nor answer_refused", res.StructuredContent)
			}
			if got := runs.Load(); got != 0 {
				t.Errorf("runs = %d, want 0 — a plan=true call must never reach Run", got)
			}
			if got := plans.Load(); got != wantPlans {
				t.Errorf("plans = %d, want %d", got, wantPlans)
			}
		})
	}

	// ARMED CONTROL (once): the same run_operation body WITHOUT plan, on the
	// same server, really does ask.
	status, body, _ := postJSONRPC(t, srv, "tools/call", "run_operation", elicitRunOperationRequest(elicitCaps))
	if status != 200 {
		t.Fatalf("status = %d; body = %s", status, body)
	}
	res := decodeElicitResult(t, body)
	if res.ResultType != "input_required" {
		t.Errorf("resultType = %q, want input_required (armed control)", res.ResultType)
	}
	if got := runs.Load(); got != 1 {
		t.Errorf("runs after the armed control = %d, want 1", got)
	}
}

// TestElicit_SealKeyIsPerProcessAndNotConfiguration proves the key is
// process-lifetime (two mcp.New instances seal the SAME fields to DIFFERENT
// states — Seal is deterministic, so a difference in output can only come
// from a difference in key) and, structurally, that the key can never be
// reached from configuration.
func TestElicit_SealKeyIsPerProcessAndNotConfiguration(t *testing.T) {
	req := elicitRunOperationRequest(elicitCaps)

	srv1 := elicitServer(t, askableParker{askable: true}, goldenTasks{},
		mcp.WithApprovalElicitation(), mcp.WithApprovalDecider(stubDecider{t: t}))
	srv2 := elicitServer(t, askableParker{askable: true}, goldenTasks{},
		mcp.WithApprovalElicitation(), mcp.WithApprovalDecider(stubDecider{t: t}))

	_, body1, _ := postJSONRPC(t, srv1, "tools/call", "run_operation", req)
	_, body2, _ := postJSONRPC(t, srv2, "tools/call", "run_operation", req)

	state1 := decodeElicitResult(t, body1).RequestState
	state2 := decodeElicitResult(t, body2).RequestState
	if state1 == "" || state2 == "" {
		t.Fatalf("empty requestState: body1=%s body2=%s", body1, body2)
	}
	if state1 == state2 {
		t.Errorf("requestState is IDENTICAL across two mcp.New instances given the same inputs — "+
			"the seal key must be minted fresh per process (invariant 11): %q", state1)
	}

	for _, finding := range scanElicitKeySurface(t) {
		t.Error(finding)
	}
}

// TestElicit_ServerNeverSendsElicitation is the structural half of "the
// server never sends elicitation/create itself": no non-test file in package
// mcp calls a selector named Elicit or CreateMessage, or spells the literal
// "elicitation/create" — the question travels as an ordinary CallToolResult,
// and it is the CLIENT's own multi-round-trip middleware that ever turns it
// into a real elicitation/create round trip.
func TestElicit_ServerNeverSendsElicitation(t *testing.T) {
	dir := mcpPackageDir(t)
	fset := token.NewFileSet()

	forEachNonTestGoFile(t, dir, func(name string, file *ast.File) {
		ast.Inspect(file, func(n ast.Node) bool {
			switch node := n.(type) {
			case *ast.SelectorExpr:
				if node.Sel.Name == "Elicit" || node.Sel.Name == "CreateMessage" {
					t.Errorf("%s calls a selector named %q — the server must never initiate elicitation/create or CreateMessage itself (ADR-0029)", name, node.Sel.Name)
				}
			case *ast.BasicLit:
				if node.Kind != token.STRING {
					return true
				}
				lit, err := strconv.Unquote(node.Value)
				if err == nil && lit == "elicitation/create" {
					t.Errorf("%s spells the literal %q — the server must never send it itself (ADR-0029)", name, lit)
				}
			}
			return true
		})
	}, fset)
}

// -----------------------------------------------------------------------
// Structural scanning helpers
// -----------------------------------------------------------------------

// requeststateImportPath is the seal-key package's import path.
const requeststateImportPath = "github.com/Felag-Engineering/relay/relay/internal/controlplane/mcp/requeststate"

// mcpPackageDir locates package mcp's own directory (this test file's
// directory) via runtime.Caller, mirroring no_dispatch_test.go/
// no_decision_test.go's own pattern.
func mcpPackageDir(t *testing.T) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	return filepath.Dir(thisFile)
}

// forEachNonTestGoFile parses every non-test .go file directly inside dir and
// calls fn with its base name and parsed *ast.File.
func forEachNonTestGoFile(t *testing.T, dir string, fn func(name string, file *ast.File), fset *token.FileSet) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("os.ReadDir(%s): %v", dir, err)
	}
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		path := filepath.Join(dir, name)
		file, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			t.Fatalf("parser.ParseFile(%s): %v", path, err)
		}
		fn(name, file)
	}
}

// isByteSliceType reports whether expr is exactly []byte.
func isByteSliceType(expr ast.Expr) bool {
	arr, ok := expr.(*ast.ArrayType)
	if !ok || arr.Len != nil {
		return false
	}
	ident, ok := arr.Elt.(*ast.Ident)
	return ok && ident.Name == "byte"
}

// isRequestStateSealerPointer reports whether expr is exactly
// *requeststate.Sealer.
func isRequestStateSealerPointer(expr ast.Expr) bool {
	star, ok := expr.(*ast.StarExpr)
	if !ok {
		return false
	}
	sel, ok := star.X.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	ident, ok := sel.X.(*ast.Ident)
	return ok && ident.Name == "requeststate" && sel.Sel.Name == "Sealer"
}

// returnsOption reports whether fn's sole return value is exactly Option —
// i.e. fn is one of the package's Option constructors (WithClock,
// WithApprovalDecider, WithApprovalElicitation, WithToolCallObserver, and any
// future WithXxx). These are THE configuration surface a caller passes into
// mcp.New, which is why the []byte/*requeststate.Sealer parameter rule below
// is scoped to them rather than to every top-level function: a plain helper
// like taskshim.go's writeShimResponse(w io.Writer, ...) or
// tools_execution.go's truncateOutput(b []byte) takes a []byte for reasons
// that have nothing to do with the seal key, and flagging it would be a false
// positive against real, benign code.
func returnsOption(fn *ast.FuncDecl) bool {
	if fn.Type.Results == nil || len(fn.Type.Results.List) != 1 {
		return false
	}
	ident, ok := fn.Type.Results.List[0].Type.(*ast.Ident)
	return ok && ident.Name == "Option"
}

// scanElicitKeySurface is the structural half of
// TestElicit_SealKeyIsPerProcessAndNotConfiguration: it returns one finding
// per way the requeststate seal key could become reachable from outside
// mcp.New's own crypto/rand mint, narrowed to top-level Option constructors
// (see returnsOption above) so it does not flag ordinary []byte-typed
// helpers with nothing to do with the seal key.
//
//   - No file in package mcp may reference requeststate.New or
//     requeststate.NewKey — only requeststate.Mint (elicit.go's
//     newQuestioner) ever constructs a Sealer.
//   - No top-level (no receiver) function in package mcp may take a
//     parameter of type *requeststate.Sealer — nothing outside elicit.go's
//     own newQuestioner should ever hold or pass one.
//   - No Option CONSTRUCTOR (a top-level function returning exactly Option
//     — see returnsOption) may take a parameter of type []byte or
//     *requeststate.Sealer: an Option is precisely the configuration
//     surface a caller passes into mcp.New, so this is where a
//     configurable key would first appear. Scoped to Option constructors
//     rather than every top-level function so it does not flag ordinary
//     []byte-typed helpers with nothing to do with the seal key (plan
//     review item 1).
//   - WithApprovalElicitation takes no parameters at all: an Option that
//     accepted an argument would be one step from a configurable key.
//   - No non-test file in cmd/relay imports the requeststate package: the
//     composition root has no business reaching the key package directly.
func scanElicitKeySurface(t *testing.T) []string {
	t.Helper()
	var findings []string

	mcpDir := mcpPackageDir(t)
	cmdRelayDir := filepath.Join(mcpDir, "..", "..", "..", "cmd", "relay")
	fset := token.NewFileSet()

	forEachNonTestGoFile(t, mcpDir, func(name string, file *ast.File) {
		ast.Inspect(file, func(n ast.Node) bool {
			sel, ok := n.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			pkgIdent, ok := sel.X.(*ast.Ident)
			if !ok || pkgIdent.Name != "requeststate" {
				return true
			}
			if sel.Sel.Name == "New" || sel.Sel.Name == "NewKey" {
				findings = append(findings, name+" references requeststate."+sel.Sel.Name+
					" — the seal key must be minted only via requeststate.Mint (invariant 11)")
			}
			return true
		})

		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Recv != nil {
				// Methods are out of scope (e.g. an io.Writer's
				// Write([]byte)) — see the doc comment above.
				continue
			}
			if fn.Name.Name == "WithApprovalElicitation" && fn.Type.Params != nil && len(fn.Type.Params.List) != 0 {
				findings = append(findings, name+": WithApprovalElicitation takes parameters, want none")
			}
			if fn.Type.Params == nil {
				continue
			}
			isOption := returnsOption(fn)
			for _, field := range fn.Type.Params.List {
				if isRequestStateSealerPointer(field.Type) {
					findings = append(findings, name+": top-level func "+fn.Name.Name+
						" takes a *requeststate.Sealer parameter — nothing outside elicit.go's "+
						"newQuestioner should ever hold or pass one")
					continue
				}
				if isOption && isByteSliceType(field.Type) {
					findings = append(findings, name+": Option constructor "+fn.Name.Name+
						" takes a []byte parameter — the seal key must never be configurable "+
						"through the surface a caller passes into mcp.New")
				}
			}
		}
	}, fset)

	forEachNonTestGoFile(t, cmdRelayDir, func(name string, file *ast.File) {
		for _, imp := range file.Imports {
			path, err := strconv.Unquote(imp.Path.Value)
			if err == nil && path == requeststateImportPath {
				findings = append(findings, name+" imports "+requeststateImportPath+
					" — the composition root must never reach the seal key package directly")
			}
		}
	}, fset)

	return findings
}

// -----------------------------------------------------------------------
// Key custody, closing the gap #737's conflict resolution named (issue #727
// comment 3): acceptElicitedAnswer no longer takes the Sealer, only a
// stateOpener built by questioner.opener() in elicit.go, and it must stay
// that way. TestElicit_SealKeyIsPerProcessAndNotConfiguration's
// scanElicitKeySurface only checks TOP-LEVEL FUNCTION PARAMETERS, so it would
// not catch a direct read of questioner.sealer, or a Seal/Open/OpenFor call,
// from any file but elicit.go.
// -----------------------------------------------------------------------

// TestElicit_SealerIsReachedOnlyInElicitGo asserts scanElicitCustody finds
// nothing in package mcp's real, shipped source.
func TestElicit_SealerIsReachedOnlyInElicitGo(t *testing.T) {
	for _, finding := range scanElicitCustody(t, mcpPackageDir(t)) {
		t.Error(finding)
	}
}

// scanElicitCustody returns one file:line finding per way dir's non-test Go
// files, other than elicit.go, could reach the requeststate seal key outside
// elicit.go's own newQuestioner/opener:
//
//   - a selector named exactly "sealer" (questioner's own field);
//   - a selector on the requeststate import — resolved by its PATH, so an
//     alias cannot evade the check — naming Mint, New, NewKey or Sealer;
//   - a call to Seal, Open or OpenFor (Sealer's method names), UNLESS its
//     receiver is an *ast.Ident naming one of the file's own imports (by the
//     import's explicit name, or the last element of its path when unnamed):
//     a package-qualified call such as os.Open or sql.Open is not a sealer,
//     but a method call on a value (x.Open) still is;
//   - a composite literal field keyed "sealer".
func scanElicitCustody(t *testing.T, dir string) []string {
	t.Helper()
	var findings []string
	fset := token.NewFileSet()

	forEachNonTestGoFile(t, dir, func(name string, file *ast.File) {
		if name == "elicit.go" {
			return
		}

		// The file's own imports, by local name (the explicit alias, or the
		// last element of the path when unnamed) -> full import path. Used
		// both to resolve the requeststate import by path (form b) and to
		// recognise a package-qualified call (form c's exclusion).
		imports := map[string]string{}
		for _, imp := range file.Imports {
			p, err := strconv.Unquote(imp.Path.Value)
			if err != nil {
				continue
			}
			localName := path.Base(p)
			if imp.Name != nil {
				localName = imp.Name.Name
			}
			imports[localName] = p
		}

		ast.Inspect(file, func(n ast.Node) bool {
			switch node := n.(type) {
			case *ast.SelectorExpr:
				if node.Sel.Name == "sealer" {
					findings = append(findings, fmt.Sprintf("%s:%d: references a selector named \"sealer\" outside elicit.go",
						name, fset.Position(node.Pos()).Line))
					return true
				}
				if ident, ok := node.X.(*ast.Ident); ok && imports[ident.Name] == requeststateImportPath {
					switch node.Sel.Name {
					case "Mint", "New", "NewKey", "Sealer":
						findings = append(findings, fmt.Sprintf("%s:%d: references requeststate.%s outside elicit.go",
							name, fset.Position(node.Pos()).Line, node.Sel.Name))
					}
					return true
				}
				switch node.Sel.Name {
				case "Seal", "Open", "OpenFor":
					if ident, ok := node.X.(*ast.Ident); ok {
						if _, isImport := imports[ident.Name]; isImport {
							// Package-qualified, e.g. os.Open or sql.Open — not a
							// sealer method call.
							return true
						}
					}
					findings = append(findings, fmt.Sprintf("%s:%d: calls .%s outside elicit.go",
						name, fset.Position(node.Pos()).Line, node.Sel.Name))
				}
			case *ast.KeyValueExpr:
				if ident, ok := node.Key.(*ast.Ident); ok && ident.Name == "sealer" {
					findings = append(findings, fmt.Sprintf("%s:%d: constructs a composite literal with a \"sealer:\" key outside elicit.go",
						name, fset.Position(node.Pos()).Line))
				}
			}
			return true
		})
	}, fset)

	return findings
}

// TestElicitCustodyGuardActuallyFires plants each forbidden form in a
// throwaway package and asserts scanElicitCustody catches it, following
// no_decision_test.go's TestNoDecisionGuardActuallyFires.
func TestElicitCustodyGuardActuallyFires(t *testing.T) {
	cases := map[string]string{
		"a bare sealer field access": `package planted
type questioner struct{ sealer *int }
func f(q *questioner) any { return q.sealer }`,

		"requeststate.Mint through an aliased import": fmt.Sprintf(`package planted
import rs %q
func f() { rs.Mint() }`, requeststateImportPath),

		"a value-receiver OpenFor call": `package planted
type opener struct{}
func (opener) OpenFor(s string) {}
func f(o opener) { o.OpenFor("x") }`,

		"a sealer key in a composite literal": `package planted
type questioner struct{ sealer *int }
func f() questioner { return questioner{sealer: nil} }`,
	}

	for name, src := range cases {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, "planted.go"), []byte(src), 0o600); err != nil {
				t.Fatalf("write planted source: %v", err)
			}
			if findings := scanElicitCustody(t, dir); len(findings) == 0 {
				t.Errorf("the guard did not catch a planted custody violation:\n%s", src)
			}
		})
	}
}

// TestElicitCustodyGuardDoesNotFireOnPackageQualifiedOpen proves form c's
// exclusion is real rather than assumed: os.Open, and the identical call
// through an aliased import of package os, must not be mistaken for a
// sealer method call.
func TestElicitCustodyGuardDoesNotFireOnPackageQualifiedOpen(t *testing.T) {
	cases := map[string]string{
		"unaliased import": `package planted
import "os"
func f() { os.Open("/tmp/x") } //nolint:errcheck`,

		"aliased import": `package planted
import osalias "os"
func f() { osalias.Open("/tmp/x") } //nolint:errcheck`,
	}

	for name, src := range cases {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, "planted.go"), []byte(src), 0o600); err != nil {
				t.Fatalf("write planted source: %v", err)
			}
			if findings := scanElicitCustody(t, dir); len(findings) != 0 {
				t.Errorf("the guard flagged a package-qualified os.Open call: %v", findings)
			}
		})
	}
}
