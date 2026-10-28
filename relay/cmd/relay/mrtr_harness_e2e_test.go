// Package main: mrtr_harness_e2e_test.go is the smoke test for #721 (S0 of
// #646's MRTR slice) — it proves the new relaytest connect/call helpers work
// end to end against the REAL composition root before any later step relies
// on them, and it is also the first AP-61 guard: an elicitation-advertising
// client with the SDK's automatic multi-round-trip middleware disabled must
// see today's ordinary pending_approval result, byte for byte the same as a
// plain client sees, because gateAllMutatesInBand excludes the requester
// (requester_allowed: false) — nobody is asked, whatever the composition
// root does with mcp.WithApprovalElicitation() (#730 passes it in
// production; this gate keeps this park unaskable regardless, AP-61).
package main

import (
	"reflect"
	"testing"

	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/Felag-Engineering/relay/relay/internal/controlplane/mcp"
	"github.com/Felag-Engineering/relay/relay/internal/controlplane/mcp/requeststate"
	"github.com/Felag-Engineering/relay/relay/internal/relaytest"
)

// gateAllMutatesInBand is gateAllMutates (approval_e2e_test.go) with its
// channel switched to "in-band" (internal/approval/config.go's parseChannel)
// — the channel the MRTR answer path (#730) delivers a decision over, and
// the one #391/ADR-0029 already makes reachable via mcp.WithApprovalDecider
// (control_surfaces.go). requester_allowed stays false and ttl stays "1h",
// exactly as gateAllMutates.
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
		"operation":    "service.restart",
		"args":         map[string]string{"unit": "nginx"},
		"wait_seconds": 300,
	}
}

// TestRelaytest_ElicitationClientSeesTodaysPendingApproval is #721's smoke
// test: relaytest.ConnectWithOptions/CallToolWith/TryCallToolWith/RetryTool
// driven against the real cmd/relay composition root — so this is also the
// first AP-61 guard: nothing changes for a client that CAN be asked but
// whose park is excluded from being asked (requester_allowed: false).
func TestRelaytest_ElicitationClientSeesTodaysPendingApproval(t *testing.T) {
	f := startGatedRelay(t, gateAllMutatesInBand)

	// asked CAN be asked (advertises form elicitation) but answers nothing by
	// itself; plain is an ordinary client with none of that. The composition
	// root passes mcp.WithApprovalElicitation() itself (#730), but
	// gateAllMutatesInBand's requester_allowed: false keeps this park
	// unaskable regardless (AP-61): the FIRST call still parks exactly as
	// before.
	asked := relaytest.ConnectWithOptions(t, f.ControlBase, f.Client(), relaytest.ConnectOptions{
		Client:     relaytest.ElicitingClientOptions(),
		ClientName: relaytest.GleipnirClientName,
	})
	plain := relaytest.Connect(t, f.ControlBase, f.Client())

	res := relaytest.CallToolWith(t, asked, &sdkmcp.CallToolParams{
		Name:      "run_operation",
		Arguments: restartNginxArgs(),
	})
	if res.NeedsInput() {
		t.Fatalf("run_operation result NeedsInput() = true, want false — the requester is excluded from being asked (AP-61), so nobody is asked")
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
	//
	// Since #730 the composition root passes mcp.WithApprovalElicitation()
	// in production, so this session's own MRTR capability is what now makes
	// this call an answered retry (isAnsweredRetry, tools_execution.go):
	// clientCanBeAsked does not care whether THIS park was askable, only
	// whether the CLIENT could be asked. A garbage RequestState is therefore
	// decided and REFUSED rather than silently ignored — still proof that
	// the retry fields reach the wire, just no longer proof that Relay
	// ignores them (that claim moved to the AP-85 "client that cannot be
	// asked" tests, elicit_e2e_test.go and mcp_elicitation_e2e_test.go).
	auditBefore := auditLen(t, f)
	retryRes := relaytest.RetryTool(t, asked, "run_operation", restartNginxArgs(), "not-a-state",
		sdkmcp.InputResponseMap{"q1": &sdkmcp.ElicitResult{Action: "accept"}})
	assertStateRefusedNothingRecorded(t, f, retryRes, requeststate.ErrUnknownVersion.Error(), auditBefore, askedOut.PendingApproval.RequestID)
}
