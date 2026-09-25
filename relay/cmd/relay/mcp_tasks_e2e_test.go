// Package main: mcp_tasks_e2e_test.go drives the MCP Tasks extension (#374,
// SEP-2663, ADR-0028) over the REAL stateless streamable handler — real
// approval gate, real store, real Account authentication, real JSON-RPC.
//
// It matters that this is wire-level rather than a handler unit test. The whole
// premise of ADR-0028 is that `tasks/get` and `tasks/cancel` can be served as
// custom methods beside the SDK's own dispatch table, with no interception and
// no fork. That claim is about the SDK's routing, so only a real client sending
// real JSON-RPC over the real transport can confirm it.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/accounts"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/approval"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/controlplane/mcp"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/relaytest"
)

// taskParams is SEP-2663's request shape, declared HERE rather than imported
// from package mcp on purpose: a test that reused the server's own params type
// would prove the two halves agree with themselves. Spelling the wire field
// independently means the JSON name is what is actually under test.
type taskParams struct {
	sdkmcp.ParamsBase
	TaskID string `json:"taskId"`
}

// connectTasksClient opens an MCP session whose client knows how to SEND the
// two extension methods.
func connectTasksClient(t *testing.T, f *relayFixture, credential string) *sdkmcp.ClientSession {
	t.Helper()
	return relaytest.ConnectWith(t, f.ControlBase, f.ClientFor(credential), func(c *sdkmcp.Client) {
		for _, method := range []string{"tasks/get", "tasks/cancel"} {
			if err := sdkmcp.AddSendingCustomMethod[*taskParams, *mcp.TaskResult](c, method); err != nil {
				t.Fatalf("AddSendingCustomMethod(%s): %v", method, err)
			}
		}
	})
}

func callTaskMethod(t *testing.T, session *sdkmcp.ClientSession, method, taskID string) (*mcp.TaskResult, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	return sdkmcp.CallCustomMethod[*taskParams, *mcp.TaskResult](ctx, session, method, &taskParams{TaskID: taskID})
}

// parkViaMCP drives a gated run_operation over MCP and returns the parked
// result, including the task handle the Relay minted for it.
func parkViaMCP(t *testing.T, session *sdkmcp.ClientSession) mcp.RunOrPlanOutput {
	t.Helper()
	res := relaytest.CallTool(t, session, "run_operation", map[string]any{
		"operation": "service.restart",
		"args":      map[string]string{"unit": "nginx"},
	})
	var out mcp.RunOrPlanOutput
	relaytest.DecodeToolJSON(t, res, &out)
	if out.PendingApproval == nil {
		t.Fatalf("run_operation did not park: %+v", out)
	}
	return out
}

// TestMCPTasks_PollAParkedDispatchThroughToCompletion is the headline
// acceptance: both methods reachable over the real handler, a parked handle
// reporting a non-terminal status, and — after an out-of-band approval and a
// re-drive — the same handle reporting `completed` with results identical to
// `get_job`'s for the same Job.
func TestMCPTasks_PollAParkedDispatchThroughToCompletion(t *testing.T) {
	f := startGatedRelay(t, gateAllMutates)
	requester := f.Credential
	approver := mintAccount(t, f, "ana", accounts.KindHuman, accounts.RoleOperator)

	session := connectTasksClient(t, f, requester)
	parked := parkViaMCP(t, session)

	// 1. The park carries a handle, and polling it is not a dispatch attempt.
	got, err := callTaskMethod(t, session, "tasks/get", parked.PendingApproval.TaskID)
	if err != nil {
		t.Fatalf("tasks/get: %v", err)
	}
	if got.TaskID != parked.PendingApproval.TaskID {
		t.Errorf("taskId = %q, want %q", got.TaskID, parked.PendingApproval.TaskID)
	}
	if got.Status != "working" {
		t.Fatalf("status = %q, want working while the dispatch is parked", got.Status)
	}
	if got.Result != nil {
		t.Error("a parked task carried a result; nothing has run")
	}
	if got.PollIntervalMs <= 0 || got.TTLMs <= 0 {
		t.Errorf("pollIntervalMs = %d, ttlMs = %d, want both positive", got.PollIntervalMs, got.TTLMs)
	}
	// The status message is the Relay-authored summary — the same text the
	// approver reads, never anything the caller wrote.
	if !strings.Contains(got.StatusMessage, "service.restart") {
		t.Errorf("statusMessage = %q, want the Relay-authored description of what is waiting", got.StatusMessage)
	}

	// 2. A human answers out of band, and the dispatch is re-driven.
	decideResp := controlAPIRequest(t, f.ClientFor(approver), http.MethodPost,
		f.ControlBase+"/api/v1/approvals/"+parked.PendingApproval.RequestID+"/decision", approver,
		map[string]any{"approve": true, "plan_hash": parked.PendingApproval.PlanHash})
	defer decideResp.Body.Close() //nolint:errcheck
	if decideResp.StatusCode != http.StatusOK {
		t.Fatalf("decision status = %d, want 200", decideResp.StatusCode)
	}

	ranRes := relaytest.CallTool(t, session, "run_operation", map[string]any{
		"operation": "service.restart",
		"args":      map[string]string{"unit": "nginx"},
	})
	var ran mcp.RunOrPlanOutput
	relaytest.DecodeToolJSON(t, ranRes, &ran)
	if ran.JobID == "" {
		t.Fatalf("re-drive after approval produced no Job: %+v", ran)
	}

	// 3. The handle now reports completed, carrying the Job's results.
	got, err = callTaskMethod(t, session, "tasks/get", parked.PendingApproval.TaskID)
	if err != nil {
		t.Fatalf("tasks/get after dispatch: %v", err)
	}
	if got.Status != "completed" {
		t.Fatalf("status = %q, want completed", got.Status)
	}
	if got.Result == nil {
		t.Fatal("a completed task carried no result")
	}
	if got.Result.JobID != ran.JobID {
		t.Errorf("result job_id = %q, want %q", got.Result.JobID, ran.JobID)
	}

	// 4. Parity with get_job, byte for byte. A Job that read one way through a
	//    task handle and another through get_job would be two accounts of one
	//    execution, and an operator comparing them could not tell which was the
	//    fleet's.
	jobRes := relaytest.CallTool(t, session, "get_job", map[string]any{"job_id": ran.JobID})
	var viaGetJob mcp.ExecutionOutput
	relaytest.DecodeToolJSON(t, jobRes, &viaGetJob)

	viaTask, err := json.Marshal(got.Result)
	if err != nil {
		t.Fatalf("marshal task result: %v", err)
	}
	viaJob, err := json.Marshal(&viaGetJob)
	if err != nil {
		t.Fatalf("marshal get_job result: %v", err)
	}
	if string(viaTask) != string(viaJob) {
		t.Errorf("task handle and get_job disagree about one Job:\n via task: %s\n via job:  %s", viaTask, viaJob)
	}
}

// TestMCPTasks_CancelAParkedTaskLeavesTheApprovalDecidable is the security
// property, proven end to end over the AI's own channel: an agent may withdraw
// its own interest and may not touch the decision a human is being asked for.
func TestMCPTasks_CancelAParkedTaskLeavesTheApprovalDecidable(t *testing.T) {
	f := startGatedRelay(t, gateAllMutates)
	requester := f.Credential
	approver := mintAccount(t, f, "ana", accounts.KindHuman, accounts.RoleOperator)

	session := connectTasksClient(t, f, requester)
	parked := parkViaMCP(t, session)

	cancelled, err := callTaskMethod(t, session, "tasks/cancel", parked.PendingApproval.TaskID)
	if err != nil {
		t.Fatalf("tasks/cancel: %v", err)
	}
	if cancelled.Status != "cancelled" {
		t.Fatalf("status = %q, want cancelled", cancelled.Status)
	}

	// The approval request is untouched: still pending, still in the queue any
	// authenticated caller reads, still decidable.
	listResp := controlAPIRequest(t, f.Client(), http.MethodGet, f.ControlBase+"/api/v1/approvals", requester, nil)
	defer listResp.Body.Close() //nolint:errcheck
	var list approvalListBody
	if err := json.NewDecoder(listResp.Body).Decode(&list); err != nil {
		t.Fatalf("decode queue: %v", err)
	}
	if len(list.Approvals) != 1 || list.Approvals[0].RequestID != parked.PendingApproval.RequestID {
		t.Fatalf("approval queue = %+v, want the request still waiting after a task cancel", list.Approvals)
	}
	if list.Approvals[0].State != approval.StatePending.String() {
		t.Errorf("approval state = %q, want pending", list.Approvals[0].State)
	}

	// And a human can still answer it, and the dispatch still runs.
	decideResp := controlAPIRequest(t, f.ClientFor(approver), http.MethodPost,
		f.ControlBase+"/api/v1/approvals/"+parked.PendingApproval.RequestID+"/decision", approver,
		map[string]any{"approve": true, "plan_hash": parked.PendingApproval.PlanHash})
	defer decideResp.Body.Close() //nolint:errcheck
	if decideResp.StatusCode != http.StatusOK {
		t.Fatalf("decision status = %d after a task cancel, want 200 — cancelling a handle must not make a request undecidable", decideResp.StatusCode)
	}

	ranRes := relaytest.CallTool(t, session, "run_operation", map[string]any{
		"operation": "service.restart",
		"args":      map[string]string{"unit": "nginx"},
	})
	var ran mcp.RunOrPlanOutput
	relaytest.DecodeToolJSON(t, ranRes, &ran)
	if ran.JobID == "" {
		t.Fatalf("the approved dispatch did not run after its handle was cancelled: %+v", ran)
	}
}

// TestMCPTasks_AnotherAccountCannotPollTheHandle: a handle is not a bearer
// capability, and an admin is no exception — resolving one is the entry point
// [4/6] extends to re-drive the stored call under the owner's authority.
func TestMCPTasks_AnotherAccountCannotPollTheHandle(t *testing.T) {
	f := startGatedRelay(t, gateAllMutates)

	owner := connectTasksClient(t, f, f.Credential)
	parked := parkViaMCP(t, owner)

	mallory := mintAccount(t, f, "mallory", accounts.KindHuman, accounts.RoleAdmin)
	intruder := connectTasksClient(t, f, mallory)

	stolen, err := callTaskMethod(t, intruder, "tasks/get", parked.PendingApproval.TaskID)
	if err == nil {
		t.Fatalf("another Account resolved the handle: %+v", stolen)
	}
	// The same answer an unminted id gets, so a guessed handle cannot be
	// confirmed to exist.
	_, unknownErr := callTaskMethod(t, intruder, "tasks/get", "task-never-minted")
	if unknownErr == nil {
		t.Fatal("an unknown task id resolved successfully")
	}

	// Compare the SERVER's sentence, not the whole error string: the SDK client
	// wraps a failed call in transport prose ("connection closed", "client is
	// closing") that varies with teardown timing and says nothing about what the
	// server disclosed. The property under test is that one sentence covers both
	// cases with only the id differing.
	sameAnswer := func(id string) string {
		return fmt.Sprintf("no task handle %q is resolvable by this account (unknown, or not yours)", id)
	}
	if !strings.Contains(err.Error(), sameAnswer(parked.PendingApproval.TaskID)) {
		t.Errorf("a stolen handle gave a distinguishable answer: %q", err.Error())
	}
	if !strings.Contains(unknownErr.Error(), sameAnswer("task-never-minted")) {
		t.Errorf("an unknown handle gave a distinguishable answer: %q", unknownErr.Error())
	}

	if _, err := callTaskMethod(t, intruder, "tasks/cancel", parked.PendingApproval.TaskID); err == nil {
		t.Error("another Account cancelled the handle")
	}
}

// TestMCPTasks_UnknownHandleIsLegible: a client that cannot tell "your handle
// lapsed" from "the server broke" will retry the wrong one.
func TestMCPTasks_UnknownHandleIsLegible(t *testing.T) {
	f := startGatedRelay(t, gateAllMutates)
	session := connectTasksClient(t, f, f.Credential)

	_, err := callTaskMethod(t, session, "tasks/get", "task-does-not-exist")
	if err == nil {
		t.Fatal("tasks/get on an unknown handle succeeded")
	}
	if !strings.Contains(err.Error(), "task handle") {
		t.Errorf("error = %q, want it to name what was not found", err)
	}

	if _, err := callTaskMethod(t, session, "tasks/get", ""); err == nil {
		t.Error("tasks/get with no taskId succeeded")
	}
}

// TestMCPTasks_AnUnresolvableHandleDoesNotKillTheSession pins a constraint that
// is easy to break while trying to improve things.
//
// The obvious error code for an unknown taskId is CodeInvalidParams. The SDK's
// transport maps that onto a non-200, and its client treats a non-200 as FATAL
// for the whole MCP session. Polling a lapsed handle is ordinary — handles
// expire by design — so a client doing the expected thing would lose its
// session and everything else it was doing.
//
// So the code is chosen to keep the connection alive (see renderTaskError), and
// this test is what says so out loud: a failed poll, then a working call on the
// SAME session.
func TestMCPTasks_AnUnresolvableHandleDoesNotKillTheSession(t *testing.T) {
	f := startGatedRelay(t, gateAllMutates)
	session := connectTasksClient(t, f, f.Credential)

	if _, err := callTaskMethod(t, session, "tasks/get", "task-does-not-exist"); err == nil {
		t.Fatal("tasks/get on an unknown handle succeeded")
	}

	// The session must still be usable. A park is the cheapest proof: it is a
	// full tools/call round trip on the same connection.
	parked := parkViaMCP(t, session)
	if parked.PendingApproval.RequestID == "" {
		t.Fatal("the session was unusable after a failed tasks/get")
	}
	if _, err := callTaskMethod(t, session, "tasks/get", parked.PendingApproval.TaskID); err != nil {
		t.Errorf("tasks/get on a real handle failed after an earlier miss: %v", err)
	}
}

// TestMCPTasks_UpdateIsNotServed is ADR-0028's boundary as a test rather than a
// paragraph: `tasks/update` is how a client answers an elicitation, which would
// be an approval decision arriving over the AI's own session. Since S2b
// (ADR-0028 amendment 2026-09-24), an askable park CAN carry `inputRequests`
// — but it never also carries a task handle (a question replaces
// pending_approval outright), so there is no task handle for `tasks/update`
// to answer either way — and nothing listens.
func TestMCPTasks_UpdateIsNotServed(t *testing.T) {
	f := startGatedRelay(t, gateAllMutates)
	session := relaytest.ConnectWith(t, f.ControlBase, f.ClientFor(f.Credential), func(c *sdkmcp.Client) {
		if err := sdkmcp.AddSendingCustomMethod[*taskParams, *mcp.TaskResult](c, "tasks/update"); err != nil {
			t.Fatalf("AddSendingCustomMethod: %v", err)
		}
	})

	if _, err := callTaskMethod(t, session, "tasks/update", "task-anything"); err == nil {
		t.Fatal("the Relay served tasks/update — an approval decision must never be answerable over the MCP session (ADR-0028)")
	}
}

// -----------------------------------------------------------------------
// The CreateTaskResult shim (#375, ADR-0028)
// -----------------------------------------------------------------------

// taskShimResult is SEP-2663's CreateTaskResult as an outside client sees it.
// Declared here rather than imported so the JSON names are what is under test.
type taskShimResult struct {
	ResultType     string `json:"resultType"`
	TaskID         string `json:"taskId"`
	Status         string `json:"status"`
	CreatedAt      string `json:"createdAt"`
	LastUpdatedAt  string `json:"lastUpdatedAt"`
	TTLMs          int64  `json:"ttlMs"`
	PollIntervalMs int64  `json:"pollIntervalMs"`
}

// tasksCapableClient dials /mcp directly with raw JSON-RPC, advertising the
// Tasks extension in the per-request `_meta`.
//
// It bypasses the SDK client on purpose. The SDK has no Tasks support — that is
// the whole reason ADR-0028 exists — so its client would reject or mangle a
// task-shaped result on the way back in. Speaking raw JSON-RPC is also the only
// way to assert what actually goes over the wire, which is the claim being
// tested.
func rawToolCall(t *testing.T, f *relayFixture, credential string, capable bool, args map[string]any) map[string]any {
	t.Helper()

	meta := map[string]any{
		"io.modelcontextprotocol/protocolVersion": "2026-07-28",
		"io.modelcontextprotocol/clientInfo":      map[string]any{"name": "raw-test-client", "version": "0.0.1"},
	}
	caps := map[string]any{}
	if capable {
		caps["extensions"] = map[string]any{"io.modelcontextprotocol/tasks": map[string]any{}}
	}
	meta["io.modelcontextprotocol/clientCapabilities"] = caps

	body, err := json.Marshal(map[string]any{
		"jsonrpc": "2.0", "id": 7, "method": "tools/call",
		"params": map[string]any{"_meta": meta, "name": "run_operation", "arguments": args},
	})
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}

	req, err := http.NewRequest(http.MethodPost, f.ControlBase+"/mcp", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("MCP-Protocol-Version", "2026-07-28")
	// Required from 2026-07-28 onward: the method is echoed in a header so a
	// proxy can route without parsing the body. The shim deliberately does NOT
	// rely on it — it reads the method from the JSON-RPC body, which is
	// version-independent and is the same read that yields the capabilities.
	req.Header.Set("Mcp-Method", "tools/call")
	req.Header.Set("Mcp-Name", "run_operation")
	req.Header.Set("Authorization", "Bearer "+credential)

	resp, err := f.ClientFor(credential).Do(req)
	if err != nil {
		t.Fatalf("POST /mcp: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d; body = %s", resp.StatusCode, raw)
	}

	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("decode response: %v; body = %s", err, raw)
	}
	if _, isErr := out["error"]; isErr {
		t.Fatalf("JSON-RPC error: %s", raw)
	}
	return out
}

func restartArgs() map[string]any {
	return map[string]any{"operation": "service.restart", "args": map[string]string{"unit": "nginx"}}
}

// TestMCPTaskShim_CapableClientGetsATaskResult is #375's headline acceptance,
// over the real handler and the real wire: a Tasks-capable client's gated
// run_operation comes back as a CreateTaskResult, and the taskId it carries
// resolves through tasks/get.
func TestMCPTaskShim_CapableClientGetsATaskResult(t *testing.T) {
	f := startGatedRelay(t, gateAllMutates)

	out := rawToolCall(t, f, f.Credential, true, restartArgs())

	resultJSON, err := json.Marshal(out["result"])
	if err != nil {
		t.Fatalf("re-marshal result: %v", err)
	}
	var task taskShimResult
	if err := json.Unmarshal(resultJSON, &task); err != nil {
		t.Fatalf("decode task result: %v; result = %s", err, resultJSON)
	}

	if task.ResultType != "task" {
		t.Fatalf(`resultType = %q, want "task" — the shim did not rewrite a parked result for a capable client`, task.ResultType)
	}
	if task.TaskID == "" || task.Status != "working" {
		t.Fatalf("task = %+v, want a working handle", task)
	}
	if task.TTLMs <= 0 || task.PollIntervalMs <= 0 {
		t.Errorf("ttlMs = %d, pollIntervalMs = %d, want both positive", task.TTLMs, task.PollIntervalMs)
	}
	if task.CreatedAt == "" || task.LastUpdatedAt == "" {
		t.Errorf("timestamps = %q / %q, want both set", task.CreatedAt, task.LastUpdatedAt)
	}

	// A rewritten response is still a well-formed JSON-RPC response answering
	// the request it belongs to — and carries no error member beside its result.
	if out["jsonrpc"] != "2.0" {
		t.Errorf("jsonrpc = %v, want 2.0", out["jsonrpc"])
	}
	if _, hasErr := out["error"]; hasErr {
		t.Error("the rewritten response carries both a result and an error member")
	}

	// The taskId the shim minted resolves through tasks/get — the two halves of
	// the extension agree about the same handle.
	session := connectTasksClient(t, f, f.Credential)
	got, err := callTaskMethod(t, session, "tasks/get", task.TaskID)
	if err != nil {
		t.Fatalf("tasks/get on the shim's taskId: %v", err)
	}
	if got.TaskID != task.TaskID || got.Status != "working" {
		t.Errorf("tasks/get = %+v, want the same handle in the same state", got)
	}
}

// TestMCPTaskShim_NonCapableClientIsUntouched is ADR-0027 decision 2 at the
// protocol level, and SEP-2663's own requirement: a client that did not
// advertise the extension must get exactly what it got before the shim existed.
func TestMCPTaskShim_NonCapableClientIsUntouched(t *testing.T) {
	f := startGatedRelay(t, gateAllMutates)

	out := rawToolCall(t, f, f.Credential, false, restartArgs())

	result, ok := out["result"].(map[string]any)
	if !ok {
		t.Fatalf("result = %T, want an object", out["result"])
	}
	if rt := result["resultType"]; rt != "complete" {
		t.Fatalf("resultType = %v, want complete — a non-capable client must never be sent a task result", rt)
	}
	structured, ok := result["structuredContent"].(map[string]any)
	if !ok {
		t.Fatalf("structuredContent = %T, want an object", result["structuredContent"])
	}
	parked, ok := structured["pending_approval"].(map[string]any)
	if !ok {
		t.Fatalf("no pending_approval in %v", structured)
	}
	if parked["status"] != "pending_approval" {
		t.Errorf("status = %v, want pending_approval", parked["status"])
	}
	// The universal path is intact, decision path and all.
	if parked["request_id"] == "" || parked["plan_hash"] == "" || parked["decision_path"] == "" {
		t.Errorf("the pending_approval result lost its decidable content: %v", parked)
	}
}

// TestMCPTaskShim_NonParkedCallsAreUntouched: a capable client's ordinary run
// and its plan must both come back exactly as they do without the shim. This is
// the acceptance criterion that a non-parked dispatch is passed through
// unmodified — asserted, not assumed.
func TestMCPTaskShim_NonParkedCallsAreUntouched(t *testing.T) {
	// A gate that parks nothing, so the same call runs instead of parking.
	const gateNothing = `{"rules":[]}`
	f := startGatedRelay(t, gateNothing)

	t.Run("an ordinary run", func(t *testing.T) {
		out := rawToolCall(t, f, f.Credential, true, restartArgs())
		result := out["result"].(map[string]any)
		if rt := result["resultType"]; rt != "complete" {
			t.Fatalf("resultType = %v, want complete for a dispatch that ran", rt)
		}
		structured := result["structuredContent"].(map[string]any)
		if _, parked := structured["pending_approval"]; parked {
			t.Fatal("a dispatch that ran came back as pending_approval")
		}
		if structured["job_id"] == nil || structured["job_id"] == "" {
			t.Errorf("the run lost its job_id: %v", structured)
		}
	})

	t.Run("a plan", func(t *testing.T) {
		args := restartArgs()
		args["plan"] = true
		out := rawToolCall(t, f, f.Credential, true, args)
		result := out["result"].(map[string]any)
		if rt := result["resultType"]; rt != "complete" {
			t.Fatalf("resultType = %v, want complete for a plan", rt)
		}
		structured := result["structuredContent"].(map[string]any)
		if _, hasPlan := structured["plan"]; !hasPlan {
			t.Errorf("the plan lost its verdicts: %v", structured)
		}
	})
}
