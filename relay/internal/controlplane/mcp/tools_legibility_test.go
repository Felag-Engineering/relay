package mcp_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/Felag-Engineering/relay/relay/internal/capability"
	"github.com/Felag-Engineering/relay/relay/internal/controlplane/mcp"
	"github.com/Felag-Engineering/relay/relay/internal/jobs"
)

// TestMCP_EveryToolHasADescription is the mechanical CI floor (#120
// deliverable 4, tool side): every tool this server registers must carry a
// non-empty Description. An MCP client's only signal for "what does this
// tool do, and should I use it" is Description — an illegible or missing one
// silently defeats ADR-0001's typed-path-by-default safety assumption no
// matter how good run_operation/raw_exec's own text is, because a model that
// never reads a tool's Description in the first place can't be steered by
// it. The Description check below runs against every tool ListTools
// returns, unconditionally — not just the ones named in wantTools — so a
// future new tool that ships without a Description fails this test
// automatically. wantTools is a separate presence/completeness check (did
// the server register the tools we expect); do not turn it back into a
// skip-list for the Description check — that would silently exempt any tool
// not yet added to wantTools from the floor.
func TestMCP_EveryToolHasADescription(t *testing.T) {
	ts := newTestServer(t)
	session := ts.connect(t)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	res, err := session.ListTools(ctx, nil)
	if err != nil {
		t.Fatalf("ListTools: %v", err)
	}

	wantTools := map[string]bool{
		"list_nodes":      false,
		"describe_node":   false,
		"list_operations": false,
		"run_operation":   false,
		"raw_exec":        false,
		"cancel_job":      false,
		"get_job":         false,
	}
	for _, tool := range res.Tools {
		if strings.TrimSpace(tool.Description) == "" {
			t.Errorf("tool %q has an empty Description — a model reader has no way to know what it does", tool.Name)
		}
		if _, ok := wantTools[tool.Name]; ok {
			wantTools[tool.Name] = true
		}
	}
	for name, seen := range wantTools {
		if !seen {
			t.Errorf("ListTools() did not return expected tool %q", name)
		}
	}
}

// TestMCP_ExecutionToolsSteerTypedPath is the empirical-preference proxy
// (#120 deliverable 5): it can't run a live model in CI, so instead it pins
// the steering language the plan calls for directly in run_operation's and
// raw_exec's Descriptions — the same text a real model reader sees. Losing
// any of these phrases is the mechanism by which the typed-path preference
// would silently erode (e.g. a future edit tightening the wording for
// brevity and accidentally dropping the "prefer" framing).
//
// Each case below documents (in taskPhrasing) the kind of request it stands
// in for and the typed choice that phrasing is meant to produce — this
// table is also pasted into the PR body as #120's documented
// empirical-preference protocol (deliverable 5): a lightweight, honest
// substitute for a full eval harness (explicitly out of scope per the
// issue).
func TestMCP_ExecutionToolsSteerTypedPath(t *testing.T) {
	ts := newTestServer(t)
	session := ts.connect(t)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	res, err := session.ListTools(ctx, nil)
	if err != nil {
		t.Fatalf("ListTools: %v", err)
	}

	descriptions := make(map[string]string, len(res.Tools))
	for _, tool := range res.Tools {
		descriptions[tool.Name] = tool.Description
	}

	tests := []struct {
		name string
		tool string
		// taskPhrasing documents the kind of request this assertion stands
		// in for and the typed choice the wording should produce — see the
		// package-level comment above.
		taskPhrasing   string
		wantExpression string
	}{
		{
			name:           "run_operation frames itself as the default",
			tool:           "run_operation",
			taskPhrasing:   `"restart nginx on web nodes" should reach for run_operation(operation=service.restart), not raw_exec(argv=["systemctl","restart","nginx"])`,
			wantExpression: "default",
		},
		{
			name:           "run_operation tells the reader to prefer it",
			tool:           "run_operation",
			taskPhrasing:   `"install the nginx package everywhere" should prefer run_operation(operation=pkg.install) over hand-building a raw_exec argv for apt-get/dnf`,
			wantExpression: "prefer",
		},
		{
			name:           "run_operation points at list_operations for the vocabulary",
			tool:           "run_operation",
			taskPhrasing:   `"what can I even do to a Node?" should be answered by consulting list_operations before guessing an Operation name or falling back to raw_exec`,
			wantExpression: "list_operations",
		},
		{
			name:           "run_operation cross-references plan mode",
			tool:           "run_operation",
			taskPhrasing:   `"will this be allowed?" should be answered by plan mode (ADR-0011), not by running it for real to find out`,
			wantExpression: "Plan mode",
		},
		{
			name:           "raw_exec names itself the escape hatch",
			tool:           "raw_exec",
			taskPhrasing:   `"run this arbitrary shell one-liner" should read raw_exec's own description as "only when nothing else works", not as an equally-good alternative to run_operation`,
			wantExpression: "escape hatch",
		},
		{
			name:           "raw_exec defers to run_operation",
			tool:           "raw_exec",
			taskPhrasing:   `"restart nginx" phrased so generically a model might reach for raw_exec first should still be redirected back to run_operation's typed path`,
			wantExpression: "Prefer run_operation",
		},
		{
			name:           "raw_exec cross-references plan mode",
			tool:           "raw_exec",
			taskPhrasing:   `"will my raw command be allowed?" should be answered by plan mode, not by triggering the real (mutate-cap) execution to find out`,
			wantExpression: "Plan mode",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			desc, ok := descriptions[tt.tool]
			if !ok {
				t.Fatalf("no Description found for tool %q", tt.tool)
			}
			if !strings.Contains(desc, tt.wantExpression) {
				t.Errorf("%s Description = %q, want it to contain %q (task phrasing this guards: %s)",
					tt.tool, desc, tt.wantExpression, tt.taskPhrasing)
			}
		})
	}

	// Both execution tools' plan-mode cross-reference must be the SAME
	// sentence (planModeClause in tools_execution.go) — concept-level, no
	// param name, so it stays accurate regardless of #119's merge state.
	runOpDesc := descriptions["run_operation"]
	rawExecDesc := descriptions["raw_exec"]
	const planModeSentence = "Plan mode — the no-execution preview of whether each Node's live Policy would allow " +
		"the action (ADR-0011) — is the sanctioned probe before mutating; prefer it over learning Policy " +
		"boundaries by triggering real executions."
	if !strings.Contains(runOpDesc, planModeSentence) {
		t.Errorf("run_operation Description does not contain the exact plan-mode clause: %q", runOpDesc)
	}
	if !strings.Contains(rawExecDesc, planModeSentence) {
		t.Errorf("raw_exec Description does not contain the exact plan-mode clause: %q", rawExecDesc)
	}
}

// TestMCP_PolicyDenyNamesItsBoundary is #454's apply-path wire seam: a
// denied_by_policy Task, driven through the real run_operation pipeline,
// carries stderr as the daemon's own reason verbatim AND a new
// refusal_explanation naming the boundary — two different authors on the
// same row. This package cannot reach perNodeResultFromTask directly (it is
// external, mcp_test), so the assertion goes through the tool surface, which
// is the stronger test anyway.
func TestMCP_PolicyDenyNamesItsBoundary(t *testing.T) {
	ts := newTestServer(t)
	ts.conduit.connect(ts.nodeA, ts.nodeB)
	const daemonReason = "no allow rule matched args [\"sshd\"] for operation 'service.restart' (allow rules exist for other arguments)"
	ts.conduit.results[ts.nodeA] = jobs.Result{Outcome: jobs.OutcomeSuccess}
	ts.conduit.results[ts.nodeB] = jobs.Result{Outcome: jobs.OutcomeDeniedByPolicy, ExitCode: -1, Stderr: []byte(daemonReason)}

	session := ts.connect(t)
	res := callTool(t, session, "run_operation", map[string]any{"operation": "system.facts", "wait_seconds": 300})
	var out mcp.ExecutionOutput
	decodeResult(t, res, &out)

	byNode := map[string]mcp.PerNodeResult{}
	for _, r := range out.Results {
		byNode[r.NodeID] = r
	}
	r, ok := byNode[ts.nodeB]
	if !ok {
		t.Fatalf("no result for node %s: %+v", ts.nodeB, out.Results)
	}
	if r.Outcome != "denied_by_policy" {
		t.Errorf("outcome = %q, want denied_by_policy", r.Outcome)
	}
	if r.ExitCode != nil {
		t.Errorf("exit_code = %v, want absent (nothing executed)", *r.ExitCode)
	}
	if r.Stderr != daemonReason {
		t.Errorf("stderr = %q, want the daemon's reason verbatim and unmodified: %q", r.Stderr, daemonReason)
	}
	if r.RefusalExplanation != capability.PolicyDenyExplanation {
		t.Errorf("refusal_explanation = %q, want capability.PolicyDenyExplanation", r.RefusalExplanation)
	}
}

// TestMCP_PlanDenyNamesItsBoundary is TestMCP_PolicyDenyNamesItsBoundary's
// plan-mode counterpart: a deny verdict carries deciding_rule (the daemon's
// rule text, unchanged) AND refusal_explanation (the Relay's plan-mode
// framing).
func TestMCP_PlanDenyNamesItsBoundary(t *testing.T) {
	ts := newTestServer(t)
	ts.conduit.connect(ts.nodeA, ts.nodeB)
	ts.conduit.verdicts[ts.nodeA] = jobs.Verdict{Allowed: true}
	ts.conduit.verdicts[ts.nodeB] = jobs.Verdict{Allowed: false, DecidingRule: "deny-facts"}

	session := ts.connect(t)
	res := callTool(t, session, "run_operation", map[string]any{"operation": "system.facts", "plan": true})
	var out mcp.RunOrPlanOutput
	decodeResult(t, res, &out)

	if out.Plan == nil {
		t.Fatal("plan field is nil, want a populated PlanOutput")
	}
	byNode := verdictsByNode(*out.Plan)
	v, ok := byNode[ts.nodeB]
	if !ok {
		t.Fatalf("no verdict for node %s: %+v", ts.nodeB, out.Plan.Verdicts)
	}
	if v.Verdict != "deny" {
		t.Errorf("verdict = %q, want deny", v.Verdict)
	}
	if v.DecidingRule != "deny-facts" {
		t.Errorf("deciding_rule = %q, want unchanged (\"deny-facts\")", v.DecidingRule)
	}
	if v.RefusalExplanation != capability.PolicyDenyVerdictExplanation {
		t.Errorf("refusal_explanation = %q, want capability.PolicyDenyVerdictExplanation", v.RefusalExplanation)
	}

	// The allow verdict must carry no explanation at all.
	if allow := byNode[ts.nodeA]; allow.RefusalExplanation != "" {
		t.Errorf("node %s (allow) refusal_explanation = %q, want empty", ts.nodeA, allow.RefusalExplanation)
	}
}

// TestMCP_VersionRefusedCarriesFullExplanation extends
// TestMCP_RunOperation_OutdatedNodeVersionRefused (mcp_exec_test.go) to
// assert the FULL text, not just the outcome string: on a version_refused
// row the Relay authored both stderr and refusal_explanation, so they must
// be byte-identical to jobs.VersionRefusedMessage.
func TestMCP_VersionRefusedCarriesFullExplanation(t *testing.T) {
	ts := newTestServerWithConfig(t, 0, 0, "1.2.0")
	ts.conduit.connect(ts.nodeA, ts.nodeB) // nodeA (1.1.0, outdated) stays connected: the gate is connectivity-independent
	ts.conduit.results[ts.nodeB] = jobs.Result{Outcome: jobs.OutcomeSuccess}

	session := ts.connect(t)
	res := callTool(t, session, "run_operation", map[string]any{"operation": "system.facts", "wait_seconds": 300})
	var out mcp.ExecutionOutput
	decodeResult(t, res, &out)

	byNode := map[string]mcp.PerNodeResult{}
	for _, r := range out.Results {
		byNode[r.NodeID] = r
	}
	r, ok := byNode[ts.nodeA]
	if !ok {
		t.Fatalf("no result for node %s: %+v", ts.nodeA, out.Results)
	}
	if r.Outcome != "version_refused" {
		t.Errorf("outcome = %q, want version_refused", r.Outcome)
	}
	if r.Stderr != jobs.VersionRefusedMessage {
		t.Errorf("stderr = %q, want jobs.VersionRefusedMessage", r.Stderr)
	}
	if r.RefusalExplanation != jobs.VersionRefusedMessage {
		t.Errorf("refusal_explanation = %q, want jobs.VersionRefusedMessage (the Relay authored both fields here)", r.RefusalExplanation)
	}
}

// TestMCP_ExplanationAbsentWhenNotRefused pins the other half of the field's
// meaning: a success and a failure row must both carry an EMPTY
// refusal_explanation, so a caller can never learn "field present => a
// refusal" and then be wrong on those two outcomes.
func TestMCP_ExplanationAbsentWhenNotRefused(t *testing.T) {
	ts := newTestServer(t)
	ts.conduit.connect(ts.nodeA, ts.nodeB)
	ts.conduit.results[ts.nodeA] = jobs.Result{Outcome: jobs.OutcomeSuccess}
	ts.conduit.results[ts.nodeB] = jobs.Result{Outcome: jobs.OutcomeFailure, Stderr: []byte("spawn systemctl: No such file or directory")}

	session := ts.connect(t)
	res := callTool(t, session, "run_operation", map[string]any{"operation": "system.facts", "wait_seconds": 300})
	var out mcp.ExecutionOutput
	decodeResult(t, res, &out)

	byNode := map[string]mcp.PerNodeResult{}
	for _, r := range out.Results {
		byNode[r.NodeID] = r
	}
	if got := byNode[ts.nodeA].RefusalExplanation; got != "" {
		t.Errorf("node %s (success) refusal_explanation = %q, want empty", ts.nodeA, got)
	}
	if got := byNode[ts.nodeB].RefusalExplanation; got != "" {
		t.Errorf("node %s (failure) refusal_explanation = %q, want empty", ts.nodeB, got)
	}
}
