// Package main: elicit_e2e_test.go is S2b's (#646) e2e proof — through the
// REAL composition root (cmd/relay/control_surfaces.go), which does NOT pass
// mcp.WithApprovalElicitation() in production. Every test here that wants the
// question path reaches it only via WithMCPServerOptions
// (relayfixture_test.go's test-only hook, #721). The one exception is
// TestCompositionRoot_DoesNotYetEnableElicitation, which passes NO hook at
// all — that is the dark-state pin S4b inverts.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"

	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/audit"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/controlplane/mcp"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/relaytest"
)

// gateAllMutatesInBandAskable is gateAllMutatesInBand
// (mrtr_harness_e2e_test.go) with requester_allowed switched to true, so a
// first-call park is askable (askableBy, capability/approval.go): channel
// in-band, no audience restriction, RequesterAllowed true.
const gateAllMutatesInBandAskable = `{
  "rules": [
    {
      "name": "all-mutates-ask-in-band",
      "match": { "risk_class": "mutate" },
      "require": { "count": 1, "requester_allowed": true, "channel": "in-band", "ttl": "1h" }
    }
  ]
}`

// gateAllMutatesOutOfBandAskable is gateAllMutatesInBandAskable with its
// channel switched to out-of-band — askableBy's first, unconditional term
// (r.Require.Channel != ChannelInBand) refuses it regardless of
// RequesterAllowed or audience, so this park is never askable no matter who
// asks (AP-69).
const gateAllMutatesOutOfBandAskable = `{
  "rules": [
    {
      "name": "all-mutates-ask-out-of-band",
      "match": { "risk_class": "mutate" },
      "require": { "count": 1, "requester_allowed": true, "channel": "out-of-band", "ttl": "1h" }
    }
  ]
}`

// TestElicit_AskableParkFromMRTRClientGetsAQuestion is AP-60's e2e proof:
// through the real composition root, with the option turned on ONLY via the
// test-only hook, an askable park from an MRTR-capable, elicitation-advertising
// client renders a question — not pending_approval — and dispatches nothing
// (no Job, no Tasks — AP-2 preserved).
func TestElicit_AskableParkFromMRTRClientGetsAQuestion(t *testing.T) {
	f := startGatedRelay(t, gateAllMutatesInBandAskable, WithMCPServerOptions(mcp.WithApprovalElicitation()))

	asked := relaytest.ConnectWithOptions(t, f.ControlBase, f.Client(), relaytest.ConnectOptions{
		Client: relaytest.ElicitingClientOptions(),
	})

	// The FIRST call creates the park (rather than observing one already
	// pending), which is what makes it askable (askableBy's created/observed
	// term, AP-62).
	res := relaytest.CallToolWith(t, asked, &sdkmcp.CallToolParams{
		Name:      "run_operation",
		Arguments: restartNginxArgs(),
	})
	if !res.NeedsInput() {
		t.Fatalf("NeedsInput() = false, want true (an askable park from an MRTR/elicitation-capable client must render "+
			"a question): IsError=%v Content=%+v StructuredContent=%+v", res.IsError, res.Content, res.StructuredContent)
	}
	if res.IsError {
		t.Fatalf("IsError = true unexpectedly; content = %+v", res.Content)
	}
	if len(res.Content) != 0 {
		t.Errorf("Content = %+v, want empty", res.Content)
	}
	if res.StructuredContent != nil {
		t.Errorf("StructuredContent = %+v, want nil", res.StructuredContent)
	}

	if len(res.InputRequests) != 1 {
		t.Fatalf("InputRequests has %d entries, want exactly 1: %+v", len(res.InputRequests), res.InputRequests)
	}
	requestID, ok := res.Meta["relay/request_id"].(string)
	if !ok || requestID == "" {
		t.Fatalf("_meta[relay/request_id] = %v, want a non-empty request ID", res.Meta["relay/request_id"])
	}
	planHash, ok := res.Meta["relay/plan_hash"].(string)
	if !ok || planHash == "" {
		t.Fatalf("_meta[relay/plan_hash] = %v, want a non-empty plan hash", res.Meta["relay/plan_hash"])
	}
	if len(requestID) > 256 {
		t.Errorf("the input-request key/RequestID is %d bytes, want at most 256", len(requestID))
	}

	entry, ok := res.InputRequests[requestID]
	if !ok {
		t.Fatalf("InputRequests is not keyed by the request ID %q: %+v", requestID, res.InputRequests)
	}
	elicit, ok := entry.(*sdkmcp.ElicitParams)
	if !ok {
		t.Fatalf("InputRequests[%q] = %T, want *sdkmcp.ElicitParams", requestID, entry)
	}
	if elicit.Mode != "form" {
		t.Errorf("Mode = %q, want form", elicit.Mode)
	}
	if elicit.Meta != nil {
		t.Errorf("input request _meta = %+v, want nil — no vendor elicitation-kind hint", elicit.Meta)
	}
	wantSchema := map[string]any{"type": "object", "properties": map[string]any{}}
	gotSchema, err := json.Marshal(elicit.RequestedSchema)
	if err != nil {
		t.Fatalf("marshal RequestedSchema: %v", err)
	}
	wantSchemaJSON, _ := json.Marshal(wantSchema)
	if string(gotSchema) != string(wantSchemaJSON) {
		t.Errorf("RequestedSchema = %s, want %s", gotSchema, wantSchemaJSON)
	}

	// The message is the SAME Relay-authored summary the Control API reports
	// for this approval — read back independently, rather than trusting the
	// MCP result alone.
	getResp := controlAPIRequest(t, f.Client(), http.MethodGet, f.ControlBase+"/api/v1/approvals/"+requestID, f.Credential, nil)
	defer getResp.Body.Close() //nolint:errcheck
	if getResp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(getResp.Body)
		t.Fatalf("GET approval status = %d; body = %s", getResp.StatusCode, respBody)
	}
	var got approvalBody
	if err := json.NewDecoder(getResp.Body).Decode(&got); err != nil {
		t.Fatalf("decode approval: %v", err)
	}
	if elicit.Message != got.Summary {
		t.Errorf("Message = %q, want the approval's own summary %q", elicit.Message, got.Summary)
	}
	if got.PlanHash != planHash {
		t.Errorf("approval plan_hash = %q, want it to match _meta's %q", got.PlanHash, planHash)
	}
	if got.State != "pending" {
		t.Errorf("approval state = %q, want pending — a question does not itself decide anything", got.State)
	}

	if n := len(res.RequestState); n == 0 {
		t.Error("RequestState is empty, want the sealed state")
	} else if n > 16384 {
		t.Errorf("RequestState is %d bytes, want at most 16384 (Gleipnir's limit)", n)
	} else if n > 2048 {
		t.Errorf("RequestState is %d bytes, want at most 2048 (requeststate.MaxEncodedBytes)", n)
	}

	// No Job, no Tasks: a question replaces pending_approval outright, and
	// the capability layer's own park creates neither (AP-2 preserved).
	records, err := f.Deps.audit.List(context.Background())
	if err != nil {
		t.Fatalf("audit List: %v", err)
	}
	for _, r := range records {
		if r.Kind == audit.KindDispatch {
			t.Errorf("found an audit.KindDispatch record (JobID=%q) — nothing should have dispatched", r.JobID)
		}
	}
}

// TestElicit_OutOfBandParkNeverAsks is AP-69's e2e proof: through the real
// gate (which computes Askable itself, unlike the mcp-handler-seam fixture's
// hand-built ParkedError), an out-of-band rule's park is never askable, on
// any client — MRTR-capable and elicitation-advertising, an ordinary client,
// and a legacy client whose ElicitationHandler must never be called.
func TestElicit_OutOfBandParkNeverAsks(t *testing.T) {
	f := startGatedRelay(t, gateAllMutatesOutOfBandAskable, WithMCPServerOptions(mcp.WithApprovalElicitation()))

	asked := relaytest.ConnectWithOptions(t, f.ControlBase, f.Client(), relaytest.ConnectOptions{
		Client: relaytest.ElicitingClientOptions(),
	})

	// The FIRST call, so a pass here cannot be explained by "the park was
	// already observed, not created" (AP-62's other reason) — only the
	// channel term.
	res := relaytest.CallToolWith(t, asked, &sdkmcp.CallToolParams{
		Name:      "run_operation",
		Arguments: restartNginxArgs(),
	})
	if res.NeedsInput() {
		t.Fatal("NeedsInput() = true, want false — an out-of-band gate's park must never be askable")
	}
	if res.RequestState != "" {
		t.Errorf("RequestState = %q, want empty", res.RequestState)
	}
	var askedOut mcp.RunOrPlanOutput
	relaytest.DecodeToolJSON(t, res, &askedOut)
	if askedOut.PendingApproval == nil {
		t.Fatalf("run_operation did not park: %+v", askedOut)
	}

	plain := relaytest.Connect(t, f.ControlBase, f.Client())
	plainRes := relaytest.CallTool(t, plain, "run_operation", restartNginxArgs())
	var plainOut mcp.RunOrPlanOutput
	relaytest.DecodeToolJSON(t, plainRes, &plainOut)
	if plainOut.PendingApproval == nil {
		t.Fatalf("plain session's run_operation did not park: %+v", plainOut)
	}

	var elicitCalls atomic.Int32
	legacy := relaytest.ConnectWithOptions(t, f.ControlBase, f.Client(), relaytest.ConnectOptions{
		Client: &sdkmcp.ClientOptions{
			Capabilities: &sdkmcp.ClientCapabilities{
				Elicitation: &sdkmcp.ElicitationCapabilities{Form: &sdkmcp.FormElicitationCapabilities{}},
			},
			ElicitationHandler: func(context.Context, *sdkmcp.ElicitRequest) (*sdkmcp.ElicitResult, error) {
				elicitCalls.Add(1)
				return &sdkmcp.ElicitResult{Action: "decline"}, nil
			},
		},
		Session: &sdkmcp.ClientSessionOptions{ProtocolVersion: "2025-11-25"},
	})
	legacyRes := relaytest.CallTool(t, legacy, "run_operation", restartNginxArgs())
	var legacyOut mcp.RunOrPlanOutput
	relaytest.DecodeToolJSON(t, legacyRes, &legacyOut)
	if legacyOut.PendingApproval == nil {
		t.Fatalf("legacy session's run_operation did not park: %+v", legacyOut)
	}
	if calls := elicitCalls.Load(); calls != 0 {
		t.Errorf("ElicitationHandler was called %d times, want 0 — no server-initiated elicitation/create either", calls)
	}
}

// TestElicit_ElicitedParkEmitsNoTaskEnvelope_E2E is AP-71's e2e reinforcement:
// the SDK client cannot hand-advertise the Tasks extension's
// clientCapabilities (there is no ClientOptions knob for it —
// see mcp_tasks_e2e_test.go's rawToolCall, mirrored below), so this drives
// raw JSON-RPC through the real composition root with a client advertising
// BOTH elicitation and the Tasks extension: the question, and no task
// envelope. TestElicit_ElicitedParkEmitsNoTaskEnvelope (elicit_test.go)
// proves the same claim against a fake Executor at the mcp-handler seam;
// this is the real gate and the real task shim together.
func TestElicit_ElicitedParkEmitsNoTaskEnvelope_E2E(t *testing.T) {
	f := startGatedRelay(t, gateAllMutatesInBandAskable, WithMCPServerOptions(mcp.WithApprovalElicitation()))

	body, err := json.Marshal(map[string]any{
		"jsonrpc": "2.0", "id": 9, "method": "tools/call",
		"params": map[string]any{
			"_meta": map[string]any{
				"io.modelcontextprotocol/protocolVersion": "2026-07-28",
				"io.modelcontextprotocol/clientInfo":      map[string]any{"name": "elicit-tasks-client", "version": "0.0.1"},
				"io.modelcontextprotocol/clientCapabilities": map[string]any{
					"elicitation": map[string]any{"form": map[string]any{}},
					"extensions":  map[string]any{"io.modelcontextprotocol/tasks": map[string]any{}},
				},
			},
			"name":      "run_operation",
			"arguments": restartNginxArgs(),
		},
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
	// Required from 2026-07-28 onward (mcp_tasks_e2e_test.go's rawToolCall):
	// the method is echoed in a header so a proxy can route without parsing
	// the body.
	req.Header.Set("Mcp-Method", "tools/call")
	req.Header.Set("Mcp-Name", "run_operation")
	req.Header.Set("Authorization", "Bearer "+f.Credential)

	resp, err := f.Client().Do(req)
	if err != nil {
		t.Fatalf("POST /mcp: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d; body = %s", resp.StatusCode, respBody)
	}

	var decoded struct {
		Result struct {
			ResultType        string          `json:"resultType"`
			InputRequests     json.RawMessage `json:"inputRequests"`
			StructuredContent json.RawMessage `json:"structuredContent"`
		} `json:"result"`
	}
	if err := json.Unmarshal(respBody, &decoded); err != nil {
		t.Fatalf("decode: %v; body = %s", err, respBody)
	}
	if decoded.Result.ResultType != "input_required" {
		t.Errorf("resultType = %q, want input_required", decoded.Result.ResultType)
	}
	if len(decoded.Result.InputRequests) == 0 {
		t.Errorf("inputRequests missing: %s", respBody)
	}
	if len(decoded.Result.StructuredContent) != 0 {
		t.Errorf("structuredContent present, want none: %s", respBody)
	}
	for _, forbidden := range []string{`"taskId"`, `"pollIntervalMs"`, `"ttlMs"`} {
		if strings.Contains(string(respBody), forbidden) {
			t.Errorf("body contains %s, want no task envelope: %s", forbidden, respBody)
		}
	}
}

// TestCompositionRoot_DoesNotYetEnableElicitation is the dark-state pin: NO
// WithMCPServerOptions hook, so this is exactly what a real deployment gets
// today. An askable park from an MRTR-capable, elicitation-advertising
// client's FIRST call (askable by construction) still renders today's
// pending_approval result — no InputRequests, no RequestState, the
// pending_approval structured output present. S4b (the composition-root
// commit that passes mcp.WithApprovalElicitation() from
// control_surfaces.go) inverts this test.
func TestCompositionRoot_DoesNotYetEnableElicitation(t *testing.T) {
	f := startGatedRelay(t, gateAllMutatesInBandAskable) // no WithMCPServerOptions hook

	asked := relaytest.ConnectWithOptions(t, f.ControlBase, f.Client(), relaytest.ConnectOptions{
		Client: relaytest.ElicitingClientOptions(),
	})

	res := relaytest.CallToolWith(t, asked, &sdkmcp.CallToolParams{
		Name:      "run_operation",
		Arguments: restartNginxArgs(),
	})
	if res.NeedsInput() {
		t.Fatal("NeedsInput() = true — the composition root must not pass WithApprovalElicitation yet (S4b inverts this test)")
	}
	if res.InputRequests != nil {
		t.Errorf("InputRequests = %+v, want nil", res.InputRequests)
	}
	if res.RequestState != "" {
		t.Errorf("RequestState = %q, want empty", res.RequestState)
	}
	var out mcp.RunOrPlanOutput
	relaytest.DecodeToolJSON(t, res, &out)
	if out.PendingApproval == nil {
		t.Fatalf("run_operation did not park: %+v", out)
	}
}
