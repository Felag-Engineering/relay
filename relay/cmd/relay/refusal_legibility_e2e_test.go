//go:build integration

// Package main: refusal_legibility_e2e_test.go is #454's wire-seam proof —
// the Node-Policy deny wall's caller-facing text, proven against a real
// relay-daemon subprocess rather than a canned Conduit. Self-contained (its
// own startAccountFleet-driven fleet), so TestSurfaceE2E_v006Acceptance's
// carefully ordered subtests are not perturbed.
//
// Skip condition: RELAY_DAEMON_BIN unset (mirrors every other file in this
// package). Run via: make test-integration.
package main

import (
	"encoding/json"
	"net/http"
	"os"
	"testing"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/accounts"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/capability"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/controlplane/mcp"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/relaytest"
)

// deniedOperationArgs is the headline demo deny, shared by every test below:
// relaytest.FixturePolicy allows service.restart only for "nginx", so
// "sshd" is refused by the daemon's args-mismatch path — the exact case the
// plan review's blocking finding was about (the daemon's own stderr on this
// row says a different argument would be allowed).
var deniedOperationArgs = map[string]any{
	"operation":    "service.restart",
	"args":         map[string]string{"unit": "sshd"},
	"selector":     "relay:env=test",
	"wait_seconds": 300,
}

// TestRefusalLegibilityE2E_NodePolicyDenyExplainsItself proves box 1 at the
// wire seam: through both MCP and the Control API, a Node-Policy deny
// carries the daemon's verbatim reason in stderr AND the Relay's boundary
// framing in refusal_explanation — byte-identical between the two surfaces
// (ADR-0009/0010 parity).
func TestRefusalLegibilityE2E_NodePolicyDenyExplainsItself(t *testing.T) {
	daemonBin := os.Getenv("RELAY_DAEMON_BIN")
	if daemonBin == "" {
		relaytest.SkipMissingBin(t, "RELAY_DAEMON_BIN not set; skipping real-daemon e2e (run via make test-integration)")
	}
	f := startAccountFleet(t, daemonBin)

	session := relaytest.Connect(t, f.relay.ControlBase, f.clientFor(f.relay.Credential))
	res := relaytest.CallTool(t, session, "run_operation", deniedOperationArgs)
	if res.IsError {
		t.Fatalf("run_operation: IsError=true; content = %+v", res.Content)
	}
	var mcpOut mcp.RunOrPlanOutput
	relaytest.DecodeToolJSON(t, res, &mcpOut)
	if len(mcpOut.Results) != 1 {
		t.Fatalf("MCP: got %d results, want 1: %+v", len(mcpOut.Results), mcpOut.Results)
	}
	mr := mcpOut.Results[0]
	if mr.Outcome != "denied_by_policy" {
		t.Fatalf("MCP outcome = %q, want denied_by_policy; stderr=%q", mr.Outcome, mr.Stderr)
	}
	if mr.ExitCode != nil {
		t.Errorf("MCP exit_code = %v, want absent (nothing executed)", *mr.ExitCode)
	}
	// Deliberately non-empty rather than pinned to the exact observed string
	// from step 0: this test is robustness against daemon-version text drift
	// (#589 already changed Raw Exec's deny text once), not a second copy of
	// refusal_legibility_test.go's exact-substring pins. Verbatim-ness itself
	// is proven, indirectly but rigorously, by
	// TestRefusalLegibilityE2E_PlanAndApplyFrameTheSameBoundary's
	// deciding_rule == stderr assertion below.
	if mr.Stderr == "" {
		t.Error("MCP stderr is empty, want the daemon's verbatim reason")
	}
	if mr.RefusalExplanation != capability.PolicyDenyExplanation {
		t.Errorf("MCP refusal_explanation = %q, want capability.PolicyDenyExplanation", mr.RefusalExplanation)
	}

	// wait_seconds is an MCP-only field; the Control API body does not take it.
	apiArgs := map[string]any{}
	for k, v := range deniedOperationArgs {
		if k != "wait_seconds" {
			apiArgs[k] = v
		}
	}
	resp := controlAPIRequest(t, f.clientFor(f.relay.Credential), http.MethodPost,
		f.relay.ControlBase+"/api/v1/operations", f.relay.Credential, apiArgs)
	defer resp.Body.Close() //nolint:errcheck
	var apiOut struct {
		Results []mcp.PerNodeResult `json:"results"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&apiOut); err != nil {
		t.Fatalf("decode API body: %v", err)
	}
	if len(apiOut.Results) != 1 {
		t.Fatalf("API: got %d results, want 1: %+v", len(apiOut.Results), apiOut.Results)
	}
	ar := apiOut.Results[0]

	if ar.Outcome != mr.Outcome || ar.Stderr != mr.Stderr || ar.RefusalExplanation != mr.RefusalExplanation {
		t.Errorf("API/MCP mismatch: API {outcome=%q stderr=%q refusal_explanation=%q} vs MCP {outcome=%q stderr=%q refusal_explanation=%q}",
			ar.Outcome, ar.Stderr, ar.RefusalExplanation, mr.Outcome, mr.Stderr, mr.RefusalExplanation)
	}
}

// TestRefusalLegibilityE2E_AdminBypassIsRefusedIdentically is the bypass
// beat (box 3), pinned empirically: the SAME denied Operation, run once with
// the founding admin credential and once with a machine Account minted at
// RoleOperator, must be refused identically — same outcome, same stderr,
// same refusal_explanation. An Operation, not Raw Exec, is used deliberately
// (authz.go requires RoleAdmin for ActionRawExec, so a non-admin would be
// refused at authz and never reach the Node, making the comparison
// meaningless); TestMCPAccountAuth_RoleLadder_E2E already proves an operator
// DOES reach the Node for a structured Operation.
func TestRefusalLegibilityE2E_AdminBypassIsRefusedIdentically(t *testing.T) {
	daemonBin := os.Getenv("RELAY_DAEMON_BIN")
	if daemonBin == "" {
		relaytest.SkipMissingBin(t, "RELAY_DAEMON_BIN not set; skipping real-daemon e2e (run via make test-integration)")
	}
	f := startAccountFleet(t, daemonBin)
	_, operatorToken := f.mintAccount(t, "gleipnir-bypass", accounts.RoleOperator)

	runAndGetResult := func(t *testing.T, credential string) mcp.PerNodeResult {
		t.Helper()
		session := relaytest.Connect(t, f.relay.ControlBase, f.clientFor(credential))
		res := relaytest.CallTool(t, session, "run_operation", deniedOperationArgs)
		if res.IsError {
			t.Fatalf("run_operation: IsError=true; content = %+v", res.Content)
		}
		var out mcp.RunOrPlanOutput
		relaytest.DecodeToolJSON(t, res, &out)
		if len(out.Results) != 1 {
			t.Fatalf("got %d results, want 1: %+v", len(out.Results), out.Results)
		}
		return out.Results[0]
	}

	adminResult := runAndGetResult(t, f.relay.Credential)
	operatorResult := runAndGetResult(t, operatorToken)

	if adminResult.Outcome != "denied_by_policy" {
		t.Fatalf("admin outcome = %q, want denied_by_policy", adminResult.Outcome)
	}
	if adminResult.Outcome != operatorResult.Outcome {
		t.Errorf("outcome differs by credential: admin=%q operator=%q — the strongest credential in the system must be refused identically to a machine Account",
			adminResult.Outcome, operatorResult.Outcome)
	}
	if adminResult.Stderr != operatorResult.Stderr {
		t.Errorf("stderr differs by credential: admin=%q operator=%q", adminResult.Stderr, operatorResult.Stderr)
	}
	if adminResult.RefusalExplanation != operatorResult.RefusalExplanation {
		t.Errorf("refusal_explanation differs by credential: admin=%q operator=%q", adminResult.RefusalExplanation, operatorResult.RefusalExplanation)
	}
}

// TestRefusalLegibilityE2E_PlanAndApplyFrameTheSameBoundary is the Relay-side
// mirror of the daemon's own deny_reason_identical_between_verdict_and_stderr
// (dispatch.rs): plan=true then plan=false on the same denied Operation must
// carry deciding_rule (plan) and stderr (apply) byte-for-byte identical, and
// both rows must carry the shared boundary core. Genuinely new coverage:
// surface_e2e_test.go's plan_vs_apply/deny asserts only the verdict and
// outcome strings, never deciding_rule == stderr.
func TestRefusalLegibilityE2E_PlanAndApplyFrameTheSameBoundary(t *testing.T) {
	daemonBin := os.Getenv("RELAY_DAEMON_BIN")
	if daemonBin == "" {
		relaytest.SkipMissingBin(t, "RELAY_DAEMON_BIN not set; skipping real-daemon e2e (run via make test-integration)")
	}
	f := startAccountFleet(t, daemonBin)
	session := relaytest.Connect(t, f.relay.ControlBase, f.clientFor(f.relay.Credential))

	planArgs := map[string]any{
		"operation": "service.restart",
		"args":      map[string]string{"unit": "sshd"},
		"selector":  "relay:env=test",
		"plan":      true,
	}
	planRes := relaytest.CallTool(t, session, "run_operation", planArgs)
	if planRes.IsError {
		t.Fatalf("run_operation(plan=true): IsError=true; content = %+v", planRes.Content)
	}
	var planOut mcp.RunOrPlanOutput
	relaytest.DecodeToolJSON(t, planRes, &planOut)
	if planOut.Plan == nil || len(planOut.Plan.Verdicts) != 1 {
		t.Fatalf("plan output malformed: %+v", planOut)
	}
	verdict := planOut.Plan.Verdicts[0]
	if verdict.Verdict != "deny" {
		t.Fatalf("plan verdict = %q, want deny", verdict.Verdict)
	}
	if verdict.RefusalExplanation != capability.PolicyDenyVerdictExplanation {
		t.Errorf("plan refusal_explanation = %q, want capability.PolicyDenyVerdictExplanation", verdict.RefusalExplanation)
	}

	applyRes := relaytest.CallTool(t, session, "run_operation", deniedOperationArgs)
	if applyRes.IsError {
		t.Fatalf("run_operation(plan=false): IsError=true; content = %+v", applyRes.Content)
	}
	var applyOut mcp.RunOrPlanOutput
	relaytest.DecodeToolJSON(t, applyRes, &applyOut)
	if len(applyOut.Results) != 1 {
		t.Fatalf("apply: got %d results, want 1: %+v", len(applyOut.Results), applyOut.Results)
	}
	result := applyOut.Results[0]
	if result.Outcome != "denied_by_policy" {
		t.Fatalf("apply outcome = %q, want denied_by_policy", result.Outcome)
	}

	if verdict.DecidingRule != result.Stderr {
		t.Errorf("deciding_rule (plan) != stderr (apply): %q != %q — the daemon's own reason must be identical on both paths", verdict.DecidingRule, result.Stderr)
	}
	if result.RefusalExplanation != capability.PolicyDenyExplanation {
		t.Errorf("apply refusal_explanation = %q, want capability.PolicyDenyExplanation", result.RefusalExplanation)
	}
}
