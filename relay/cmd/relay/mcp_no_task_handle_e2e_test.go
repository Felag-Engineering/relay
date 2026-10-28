// Package main: mcp_no_task_handle_e2e_test.go proves, over the REAL stateless
// streamable handler — real approval gate, real store, real Account
// authentication, real JSON-RPC — that nothing renders a parked dispatch as an
// MCP task handle (AP-85): a Tasks-declaring client whose park asks nobody gets
// the ordinary pending_approval result, and no tasks/ method is served.
package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
)

// rawToolCall dials /mcp directly with raw JSON-RPC and calls run_operation,
// declaring the Tasks extension in the per-request `_meta` when capable is
// true.
//
// It bypasses the SDK client on purpose: speaking raw JSON-RPC is the only way
// to assert what actually goes over the wire, which is the claim being tested.
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
	// proxy can route without parsing the body.
	req.Header.Set("Mcp-Method", "tools/call")
	req.Header.Set("Mcp-Name", "run_operation")
	req.Header.Set("Authorization", "Bearer "+credential)

	resp, err := f.ClientFor(credential).Do(req)
	if err != nil {
		t.Fatalf("POST /mcp: %v", err)
	}
	defer resp.Body.Close()
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

// rawMethodCall POSTs one raw JSON-RPC request for method with params and
// returns the HTTP status and body, never failing the test on a non-200 status:
// an unserved method may be refused at either layer.
func rawMethodCall(t *testing.T, f *relayFixture, credential, method string, params map[string]any) (int, []byte) {
	t.Helper()
	body, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 7, "method": method, "params": params})
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
	req.Header.Set("Mcp-Method", method)
	req.Header.Set("Authorization", "Bearer "+credential)
	resp, err := f.ClientFor(credential).Do(req)
	if err != nil {
		t.Fatalf("POST /mcp: %v", err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	return resp.StatusCode, raw
}

// TestMCP_TasksDeclaringParkThatAsksNobodyIsPendingApproval (AP-85): through
// the composed Relay, a gated run_operation from a client that declares the
// Tasks extension and cannot be asked comes back as an ordinary complete
// result carrying pending_approval, with no task fields and no task envelope.
func TestMCP_TasksDeclaringParkThatAsksNobodyIsPendingApproval(t *testing.T) {
	f := startGatedRelay(t, gateAllMutates)

	out := rawToolCall(t, f, f.Credential, true, restartArgs())
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
				"_meta": map[string]any{
					"io.modelcontextprotocol/protocolVersion":    "2026-07-28",
					"io.modelcontextprotocol/clientInfo":         map[string]any{"name": "raw-test-client", "version": "0.0.1"},
					"io.modelcontextprotocol/clientCapabilities": map[string]any{"extensions": map[string]any{"io.modelcontextprotocol/tasks": map[string]any{}}},
				},
				"taskId": "task-anything",
			}
			status, raw := rawMethodCall(t, f, f.Credential, method, params)

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
