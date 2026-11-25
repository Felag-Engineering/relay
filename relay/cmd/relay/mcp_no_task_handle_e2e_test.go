// Package main: mcp_no_task_handle_e2e_test.go proves, over the REAL stateless
// streamable handler — real approval gate, real store, real Account
// authentication, real JSON-RPC — that nothing renders a parked dispatch as an
// MCP task handle (AP-85): a Tasks-declaring client whose park asks nobody gets
// the ordinary pending_approval result, and no tasks/ method is served.
package main

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestMCP_TasksDeclaringParkThatAsksNobodyIsPendingApproval (AP-85): through
// the composed Relay, a gated run_operation from a client that declares the
// Tasks extension and cannot be asked comes back as an ordinary complete
// result carrying pending_approval, with no task fields and no task envelope.
func TestMCP_TasksDeclaringParkThatAsksNobodyIsPendingApproval(t *testing.T) {
	f := startGatedRelay(t, gateAllMutates)

	out := rawToolCall(t, f, f.Credential, true, restartNginxArgs())
	raw, err := json.Marshal(out)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	result, _ := out["result"].(map[string]any)
	if rt := result["resultType"]; rt != "complete" {
		t.Fatalf("resultType = %v, want complete — a park is never rendered as a task: %s", rt, raw)
	}
	structured, _ := result["structuredContent"].(map[string]any)
	parked, _ := structured["pending_approval"].(map[string]any)
	if parked == nil {
		t.Fatalf("no pending_approval in %s", raw)
	}
	if parked["status"] != "pending_approval" {
		t.Errorf("status = %v, want pending_approval", parked["status"])
	}
	for _, key := range []string{"request_id", "plan_hash", "decision_path"} {
		if v, _ := parked[key].(string); v == "" {
			t.Errorf("pending_approval[%q] is empty: %s", key, raw)
		}
	}
	for _, key := range []string{"task_id", "task_expires_at"} {
		if _, present := parked[key]; present {
			t.Errorf("pending_approval carries %q; a park has no task handle", key)
		}
	}
	for _, marker := range []string{"taskId", "pollIntervalMs", "ttlMs", `"resultType":"task"`} {
		if strings.Contains(string(raw), marker) {
			t.Errorf("response contains %q; nothing renders a park as an MCP task: %s", marker, raw)
		}
	}
}

// TestMCP_NoTasksMethodIsServed (AP-85): tasks/get, tasks/cancel and
// tasks/update are not methods this Relay serves. An approval decision must
// never be answerable over the MCP session, and a task handle has nothing to
// resolve. Whatever the refusal looks like, it is never a result.
func TestMCP_NoTasksMethodIsServed(t *testing.T) {
	f := startGatedRelay(t, gateAllMutates)

	for _, method := range []string{"tasks/get", "tasks/cancel", "tasks/update"} {
		t.Run(method, func(t *testing.T) {
			params := map[string]any{
				"_meta":  rawClientMeta("raw-test-client", map[string]any{"extensions": tasksCapability()}),
				"taskId": "task-anything",
			}
			status, _, raw := postRawMCP(t, f, f.Credential, rawMCPProtocolVersion, method, "", params)

			var resp struct {
				Result json.RawMessage `json:"result"`
				Error  *struct {
					Code int `json:"code"`
				} `json:"error"`
			}
			if err := json.Unmarshal(raw, &resp); err != nil {
				t.Fatalf("status %d: reply is not a JSON-RPC message: %v\n%s", status, err, raw)
			}
			if resp.Result != nil {
				t.Fatalf("the Relay served %s: %s", method, raw)
			}
			if resp.Error == nil || resp.Error.Code != -32601 {
				t.Errorf("status %d, error = %+v, want JSON-RPC -32601 method not found: %s", status, resp.Error, raw)
			}
		})
	}
}
