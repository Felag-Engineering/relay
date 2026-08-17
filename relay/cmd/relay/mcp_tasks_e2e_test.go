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
	"context"
	"encoding/json"
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
	if err.Error() != strings.Replace(unknownErr.Error(), "task-never-minted", parked.PendingApproval.TaskID, 1) {
		t.Errorf("a stolen handle and an unknown one give different answers:\n stolen:  %v\n unknown: %v", err, unknownErr)
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

// TestMCPTasks_UpdateIsNotServed is ADR-0028's boundary as a test rather than a
// paragraph: `tasks/update` is how a client answers an elicitation, which would
// be an approval decision arriving over the AI's own session. Relay emits no
// inputRequests, so nothing answers — and nothing listens.
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
