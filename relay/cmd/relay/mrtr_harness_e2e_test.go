// Package main: mrtr_harness_e2e_test.go is the smoke test for #721 (S0 of
// #646's MRTR slice) — it proves the new relaytest connect/call helpers work
// end to end against the REAL composition root before any later step relies
// on them, and it is also the first AP-70 guard: an elicitation-advertising
// client with the SDK's automatic multi-round-trip middleware disabled must
// see today's ordinary pending_approval result, byte for byte the same as a
// plain client sees, because nothing enables the MRTR answer path yet (S2
// defines the enabling mcp.Option; S4b is the first production caller of it).
package main

import (
	"reflect"
	"testing"

	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/controlplane/mcp"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/relaytest"
)

// gateAllMutatesInBand is gateAllMutates (approval_e2e_test.go) with its
// channel switched to "in-band" (internal/approval/config.go's parseChannel)
// — the channel S4b's answer path will eventually deliver a decision over,
// and the one #391/ADR-0029 already makes reachable via
// mcp.WithApprovalDecider (control_surfaces.go). requester_allowed stays
// false and ttl stays "1h", exactly as gateAllMutates.
const gateAllMutatesInBand = `{
  "rules": [
    {
      "name": "all-mutates-need-a-human",
      "match": { "risk_class": "mutate" },
      "require": { "count": 1, "requester_allowed": false, "channel": "in-band", "ttl": "1h" }
    }
  ]
}`

// restartNginxArgs is the run_operation call both sessions below park —
// identical between them, so the two parks are directly comparable.
func restartNginxArgs() map[string]any {
	return map[string]any{
		"operation": "service.restart",
		"args":      map[string]string{"unit": "nginx"},
	}
}

// TestRelaytest_ElicitationClientSeesTodaysPendingApproval is #721's smoke
// test: relaytest.ConnectWithOptions/CallToolWith/TryCallToolWith/RetryTool
// driven against the real cmd/relay composition root, with no MCP server
// option enabling the answer path — the design plan's "dark until S4b" — so
// this is also the first AP-70 guard: nothing changes for a client that CAN
// be asked but is not yet answered.
func TestRelaytest_ElicitationClientSeesTodaysPendingApproval(t *testing.T) {
	f := startGatedRelay(t, gateAllMutatesInBand)

	// asked CAN be asked (advertises form elicitation) but answers nothing by
	// itself; plain is an ordinary client with none of that. No
	// WithMCPServerOptions is passed to startGatedRelay: the enabling option
	// (S2) does not exist yet, so neither session can reach the answer path
	// even if it wanted to.
	asked := relaytest.ConnectWithOptions(t, f.ControlBase, f.Client(), relaytest.ConnectOptions{
		Client: relaytest.ElicitingClientOptions(),
	})
	plain := relaytest.Connect(t, f.ControlBase, f.Client())

	res := relaytest.CallToolWith(t, asked, &sdkmcp.CallToolParams{
		Name:      "run_operation",
		Arguments: restartNginxArgs(),
	})
	if res.NeedsInput() {
		t.Fatalf("run_operation result NeedsInput() = true, want false — nothing enables the MRTR answer path yet (#721)")
	}
	if res.InputRequests != nil {
		t.Errorf("run_operation result InputRequests = %+v, want nil", res.InputRequests)
	}
	if res.RequestState != "" {
		t.Errorf("run_operation result RequestState = %q, want empty", res.RequestState)
	}
	if res.IsError {
		t.Fatalf("run_operation returned IsError=true unexpectedly; content = %+v", res.Content)
	}

	var askedOut mcp.RunOrPlanOutput
	relaytest.DecodeToolJSON(t, res, &askedOut)
	if askedOut.PendingApproval == nil {
		t.Fatalf("run_operation did not park: %+v", askedOut)
	}
	if askedOut.PendingApproval.Status != "pending_approval" {
		t.Errorf("PendingApproval.Status = %q, want %q", askedOut.PendingApproval.Status, "pending_approval")
	}
	if askedOut.PendingApproval.RequestID == "" {
		t.Error("PendingApproval.RequestID is empty")
	}
	if askedOut.PendingApproval.PlanHash == "" {
		t.Error("PendingApproval.PlanHash is empty")
	}
	if askedOut.JobID != "" {
		t.Errorf("JobID = %q, want empty on a parked dispatch", askedOut.JobID)
	}
	if len(askedOut.Results) != 0 {
		t.Errorf("len(Results) = %d, want 0 on a parked dispatch", len(askedOut.Results))
	}

	// Park the identical call through the plain session — the "unchanged"
	// assertion: an elicitation-advertising client parks exactly like an
	// ordinary one. RequestID, PlanHash and ExpiresAt are deliberately not
	// compared: the two calls carry the same requester and the same Plan, so
	// the approval layer's own PlanHash dedup (approval.go's ByPlanHash) may
	// return the SAME pending Request rather than a second one for either of
	// them, and this test asserts identical rendering either way.
	plainRes := relaytest.CallTool(t, plain, "run_operation", restartNginxArgs())
	var plainOut mcp.RunOrPlanOutput
	relaytest.DecodeToolJSON(t, plainRes, &plainOut)
	if plainOut.PendingApproval == nil {
		t.Fatalf("plain session's run_operation did not park: %+v", plainOut)
	}
	if askedOut.PendingApproval.Status != plainOut.PendingApproval.Status {
		t.Errorf("Status differs between sessions: asked=%q plain=%q", askedOut.PendingApproval.Status, plainOut.PendingApproval.Status)
	}
	if askedOut.PendingApproval.Summary != plainOut.PendingApproval.Summary {
		t.Errorf("Summary differs between sessions: asked=%q plain=%q", askedOut.PendingApproval.Summary, plainOut.PendingApproval.Summary)
	}
	if !reflect.DeepEqual(askedOut.PendingApproval.MatchedRules, plainOut.PendingApproval.MatchedRules) {
		t.Errorf("MatchedRules differ between sessions: asked=%v plain=%v", askedOut.PendingApproval.MatchedRules, plainOut.PendingApproval.MatchedRules)
	}
	if askedOut.PendingApproval.Progress != plainOut.PendingApproval.Progress {
		t.Errorf("Progress differs between sessions: asked=%q plain=%q", askedOut.PendingApproval.Progress, plainOut.PendingApproval.Progress)
	}
	if askedOut.PendingApproval.DecisionPath != plainOut.PendingApproval.DecisionPath {
		t.Errorf("DecisionPath differs between sessions: asked=%q plain=%q", askedOut.PendingApproval.DecisionPath, plainOut.PendingApproval.DecisionPath)
	}

	// The MRTR retry, on the asked session, via relaytest.RetryTool: a
	// fabricated RequestState and a NON-empty InputResponseMap (an empty map
	// is dropped by the wire struct's `omitempty` before it ever reaches the
	// server — plan review suggestion 1). RetryTool fails the test on a
	// protocol-level error, which is fine here: the SDK sends the params as
	// given (code review, cycle 1) rather than refusing the call client-side.
	// Relay reads neither field today, so the SAME pending_approval must
	// come back, unrequested — one more "nothing changed" point, and proof
	// that the retry fields reach the wire without a client-side error.
	retryRes := relaytest.RetryTool(t, asked, "run_operation", restartNginxArgs(), "not-a-state",
		sdkmcp.InputResponseMap{"q1": &sdkmcp.ElicitResult{Action: "accept"}})
	if retryRes.NeedsInput() {
		t.Errorf("retry NeedsInput() = true, want false — Relay must ignore RequestState/InputResponses today")
	}
	if retryRes.RequestState != "" {
		t.Errorf("retry RequestState = %q, want empty — Relay must ignore RequestState/InputResponses today", retryRes.RequestState)
	}
	var retryOut mcp.RunOrPlanOutput
	relaytest.DecodeToolJSON(t, retryRes, &retryOut)
	if retryOut.PendingApproval == nil {
		t.Fatalf("retry did not park: %+v", retryOut)
	}
	if retryOut.PendingApproval.Status != "pending_approval" {
		t.Errorf("retry Status = %q, want %q — Relay must ignore RequestState/InputResponses today", retryOut.PendingApproval.Status, "pending_approval")
	}
}
