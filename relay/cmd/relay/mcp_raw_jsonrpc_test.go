// Package main: mcp_raw_jsonrpc_test.go is the one hand-built JSON-RPC POST to
// /mcp that the end-to-end suites share. A test speaks raw JSON-RPC instead of
// the SDK client when the claim is about what goes over the wire, or when the
// request is one the SDK will not build: a hand-advertised Tasks extension, a
// legacy protocol header, an unserved method.
package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"testing"
)

// rawMCPProtocolVersion is the protocol revision a raw request declares, in
// the MCP-Protocol-Version header and in its _meta.
const rawMCPProtocolVersion = "2026-07-28"

// postRawMCP POSTs one JSON-RPC request for method with params to /mcp,
// authenticated as credential, and returns the HTTP status, the reply's
// Content-Type and its body. It never fails the test on the status: a refusal
// may come from the SDK transport or from the handler, and the caller decides
// which it expects.
//
// protocolHeader is the MCP-Protocol-Version header and name the Mcp-Name
// header; either empty omits that header. Mcp-Method always echoes method,
// required from 2026-07-28 so a proxy can route without parsing the body.
func postRawMCP(t *testing.T, f *relayFixture, credential, protocolHeader, method, name string, params map[string]any) (status int, contentType string, body []byte) {
	t.Helper()
	reqBody, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": method, "params": params})
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}

	req, err := http.NewRequest(http.MethodPost, f.ControlBase+"/mcp", bytes.NewReader(reqBody))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	if protocolHeader != "" {
		req.Header.Set("MCP-Protocol-Version", protocolHeader)
	}
	req.Header.Set("Mcp-Method", method)
	if name != "" {
		req.Header.Set("Mcp-Name", name)
	}
	req.Header.Set("Authorization", "Bearer "+credential)

	resp, err := f.ClientFor(credential).Do(req)
	if err != nil {
		t.Fatalf("POST /mcp: %v", err)
	}
	defer resp.Body.Close()
	body, err = io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	return resp.StatusCode, resp.Header.Get("Content-Type"), body
}

// postRawToolCall POSTs one tools/call of tool with args, carrying meta as the
// request's _meta. Like postRawMCP it never fails the test on the status.
func postRawToolCall(t *testing.T, f *relayFixture, token, header string, meta map[string]any, tool string, args map[string]any) (status int, contentType string, respBody []byte) {
	t.Helper()
	params := map[string]any{"_meta": meta, "name": tool, "arguments": args}
	return postRawMCP(t, f, token, header, "tools/call", tool, params)
}

// rawClientMeta is the per-request _meta a modern client sends: the protocol
// revision, a client name, and caps as its clientCapabilities.
func rawClientMeta(clientName string, caps map[string]any) map[string]any {
	return map[string]any{
		"io.modelcontextprotocol/protocolVersion":    rawMCPProtocolVersion,
		"io.modelcontextprotocol/clientInfo":         map[string]any{"name": clientName, "version": "0.0.1"},
		"io.modelcontextprotocol/clientCapabilities": caps,
	}
}

// tasksCapability is the clientCapabilities entry that declares the Tasks
// extension, which no SDK ClientOptions knob can advertise.
func tasksCapability() map[string]any {
	return map[string]any{"io.modelcontextprotocol/tasks": map[string]any{}}
}

// rawToolCall calls run_operation with args as a client named raw-test-client,
// declaring the Tasks extension when capable is true, and returns the decoded
// JSON-RPC reply. It fails the test unless the call returns 200 with no
// JSON-RPC error.
func rawToolCall(t *testing.T, f *relayFixture, credential string, capable bool, args map[string]any) map[string]any {
	t.Helper()
	caps := map[string]any{}
	if capable {
		caps["extensions"] = tasksCapability()
	}
	meta := rawClientMeta("raw-test-client", caps)

	status, _, raw := postRawToolCall(t, f, credential, rawMCPProtocolVersion, meta, "run_operation", args)
	if status != http.StatusOK {
		t.Fatalf("status = %d; body = %s", status, raw)
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
