package mcp_test

import (
	"context"
	"strings"
	"testing"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/audit"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/controlplane/mcp"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/jobs"
)

// verdictsByNode indexes a mcp.PlanOutput's Verdicts by NodeID for
// order-independent assertions.
func verdictsByNode(p mcp.PlanOutput) map[string]mcp.PerNodeVerdict {
	m := make(map[string]mcp.PerNodeVerdict, len(p.Verdicts))
	for _, v := range p.Verdicts {
		m[v.NodeID] = v
	}
	return m
}

// TestMCP_RunOperation_Plan_VerdictsNoExecution is the core plan-mode
// acceptance line: run_operation(plan=true) returns per-Node verdicts,
// matched count, and the point-in-time advisory, with job_id/results left at
// their zero values — nothing was dispatched.
func TestMCP_RunOperation_Plan_VerdictsNoExecution(t *testing.T) {
	ts := newTestServer(t)
	ts.conduit.connect(ts.nodeA, ts.nodeB)
	ts.conduit.verdicts[ts.nodeA] = jobs.Verdict{Allowed: true}
	ts.conduit.verdicts[ts.nodeB] = jobs.Verdict{Allowed: false, DecidingRule: "deny-facts"}

	session := ts.connect(t)
	res := callTool(t, session, "run_operation", map[string]any{"operation": "system.facts", "plan": true})
	var out mcp.RunOrPlanOutput
	decodeResult(t, res, &out)

	if out.JobID != "" {
		t.Errorf("job_id = %q, want empty (a Plan never dispatches)", out.JobID)
	}
	if len(out.Results) != 0 {
		t.Errorf("results = %+v, want empty (a Plan never dispatches)", out.Results)
	}
	// #207/#253 item 2: assert the EMITTED JSON — a plan response carries no
	// job_id key at all (a Plan creates no Job; an empty "" read as a
	// missing/failed id), and results is an explicit empty array, never null.
	text := resultText(t, res)
	if strings.Contains(text, `"job_id"`) {
		t.Errorf("plan response JSON = %s, must not contain a job_id key (a Plan creates no Job)", text)
	}
	if !strings.Contains(text, `"results":[]`) {
		t.Errorf("plan response JSON = %s, want it to contain %q (an empty array, never null)", text, `"results":[]`)
	}
	if out.Plan == nil {
		t.Fatal("plan field is nil, want a populated PlanOutput")
	}
	if out.Plan.Matched != 2 {
		t.Errorf("plan.matched = %d, want 2", out.Plan.Matched)
	}
	if out.Plan.Advisory == "" || !strings.Contains(out.Plan.Advisory, "ADR-0011") {
		t.Errorf("plan.advisory = %q, want a non-empty ADR-0011 advisory string", out.Plan.Advisory)
	}
	if out.Plan.WouldBeRejected != nil {
		t.Errorf("plan.would_be_rejected = %+v, want nil (neither over-cap nor frozen)", out.Plan.WouldBeRejected)
	}

	byNode := verdictsByNode(*out.Plan)
	if v := byNode[ts.nodeA]; v.Verdict != "allow" {
		t.Errorf("node %s verdict = %+v, want allow", ts.nodeA, v)
	}
	if v := byNode[ts.nodeB]; v.Verdict != "deny" || v.DecidingRule != "deny-facts" {
		t.Errorf("node %s verdict = %+v, want deny/deny-facts", ts.nodeB, v)
	}

	if len(ts.conduit.queriedNodes()) != 2 {
		t.Errorf("Query was called %d times, want 2 (once per matched connected Node)", len(ts.conduit.queriedNodes()))
	}
}

// TestMCP_RunOperation_Plan_OfflineIsUnknown is the offline acceptance line:
// a matched-but-disconnected Node yields verdict=unknown/reason=offline, and
// Query is never called for it.
func TestMCP_RunOperation_Plan_OfflineIsUnknown(t *testing.T) {
	ts := newTestServer(t)
	ts.conduit.connect(ts.nodeA)
	ts.conduit.verdicts[ts.nodeA] = jobs.Verdict{Allowed: true}
	// nodeB is deliberately left disconnected.

	session := ts.connect(t)
	res := callTool(t, session, "run_operation", map[string]any{"operation": "system.facts", "plan": true})
	var out mcp.RunOrPlanOutput
	decodeResult(t, res, &out)

	byNode := verdictsByNode(*out.Plan)
	offline, ok := byNode[ts.nodeB]
	if !ok {
		t.Fatalf("verdicts missing %s: %+v", ts.nodeB, out.Plan.Verdicts)
	}
	if offline.Verdict != "unknown" || offline.Reason != "offline" {
		t.Errorf("%s verdict = %+v, want unknown/offline", ts.nodeB, offline)
	}
	for _, nodeID := range ts.conduit.queriedNodes() {
		if nodeID == ts.nodeB {
			t.Errorf("Query was called for offline node %s, want never", ts.nodeB)
		}
	}
}

// TestMCP_RunOperation_Plan_OutdatedAdvisory is ADR-0014's plan-mode
// surfacing, carried through the wire: an outdated matched Node's
// PerNodeVerdict still reports the daemon's real verdict AND
// outdated:true — a real dispatch would refuse it, but Plan mode never
// gates or skips the PolicyQuery for it (invariant 12).
func TestMCP_RunOperation_Plan_OutdatedAdvisory(t *testing.T) {
	// Node A reports 1.1.0, Node B reports 1.3.0 (see newTestServerWithConfig).
	ts := newTestServerWithConfig(t, 0, 0, "1.2.0")
	ts.conduit.connect(ts.nodeA, ts.nodeB)
	ts.conduit.verdicts[ts.nodeA] = jobs.Verdict{Allowed: true}
	ts.conduit.verdicts[ts.nodeB] = jobs.Verdict{Allowed: true}

	session := ts.connect(t)
	res := callTool(t, session, "run_operation", map[string]any{"operation": "system.facts", "plan": true})
	var out mcp.RunOrPlanOutput
	decodeResult(t, res, &out)

	byNode := verdictsByNode(*out.Plan)
	a, ok := byNode[ts.nodeA]
	if !ok {
		t.Fatalf("verdicts missing %s: %+v", ts.nodeA, out.Plan.Verdicts)
	}
	if a.Verdict != "allow" {
		t.Errorf("node A verdict = %+v, want allow (a real, queried verdict)", a)
	}
	if !a.Outdated {
		t.Error("node A Outdated = false, want true (below the configured minimum)")
	}

	b, ok := byNode[ts.nodeB]
	if !ok {
		t.Fatalf("verdicts missing %s: %+v", ts.nodeB, out.Plan.Verdicts)
	}
	if b.Outdated {
		t.Error("node B Outdated = true, want false (above the configured minimum)")
	}

	// Plan must still have queried the outdated Node.
	foundA := false
	for _, nodeID := range ts.conduit.queriedNodes() {
		if nodeID == ts.nodeA {
			foundA = true
		}
	}
	if !foundA {
		t.Errorf("Query was never called for outdated node %s; Plan must still query outdated Nodes", ts.nodeA)
	}
}

// TestMCP_RunOperation_Plan_OverCap_ReportsNotErrors is the over-cap
// acceptance line: a Plan against a Selector matching more Nodes than the
// applicable cap reports would_be_rejected as DATA, not a tool error.
func TestMCP_RunOperation_Plan_OverCap_ReportsNotErrors(t *testing.T) {
	ts := newTestServerWithBlastCap(t, 0, 1) // mutate-cap = 1
	ts.conduit.connect(ts.nodeA, ts.nodeB)

	session := ts.connect(t)
	res := callTool(t, session, "raw_exec", map[string]any{"argv": []string{"/bin/true"}, "plan": true})
	if res.IsError {
		t.Fatalf("raw_exec(plan=true) over the mutate-cap: IsError = true, want false (reported, not errored): content = %+v", res.Content)
	}
	var out mcp.RunOrPlanOutput
	decodeResult(t, res, &out)

	if out.Plan == nil || out.Plan.WouldBeRejected == nil {
		t.Fatalf("plan.would_be_rejected is nil, want an exceeds_cap report: %+v", out.Plan)
	}
	wbr := out.Plan.WouldBeRejected
	if wbr.Reason != "exceeds_cap" {
		t.Errorf("would_be_rejected.reason = %q, want exceeds_cap", wbr.Reason)
	}
	if wbr.Matched != 2 {
		t.Errorf("would_be_rejected.matched = %d, want 2", wbr.Matched)
	}
	if wbr.Cap != 1 {
		t.Errorf("would_be_rejected.cap = %d, want 1", wbr.Cap)
	}
	if wbr.Class != "mutate" {
		t.Errorf("would_be_rejected.class = %q, want mutate", wbr.Class)
	}
	if len(out.Plan.Verdicts) != 0 {
		t.Errorf("plan.verdicts = %+v, want empty (query fan-out skipped over-cap)", out.Plan.Verdicts)
	}
	if len(ts.conduit.queriedNodes()) != 0 {
		t.Errorf("Query was called %d times, want 0 (skipped over-cap)", len(ts.conduit.queriedNodes()))
	}
}

// TestMCP_RunOperation_Plan_FrozenReportsWhileRealRunErrors is the
// Freeze-exemption acceptance line (ADR-0013): plan=true still returns
// verdicts plus would_be_rejected{frozen}, while plan=false (a real run)
// returns the distinct "the Relay is frozen" tool error.
func TestMCP_RunOperation_Plan_FrozenReportsWhileRealRunErrors(t *testing.T) {
	ts := newTestServer(t)
	ts.conduit.connect(ts.nodeA)
	ts.conduit.verdicts[ts.nodeA] = jobs.Verdict{Allowed: true}
	if err := ts.store.Freeze().Engage(context.Background(), "test-admin"); err != nil {
		t.Fatalf("Engage: %v", err)
	}

	session := ts.connect(t)

	planRes := callTool(t, session, "run_operation", map[string]any{"selector": "node:role=web", "operation": "system.facts", "plan": true})
	if planRes.IsError {
		t.Fatalf("run_operation(plan=true) while frozen: IsError = true, want false (advisory, not a refusal): content = %+v", planRes.Content)
	}
	var planOut mcp.RunOrPlanOutput
	decodeResult(t, planRes, &planOut)
	if planOut.Plan == nil || planOut.Plan.WouldBeRejected == nil || planOut.Plan.WouldBeRejected.Reason != "frozen" {
		t.Fatalf("plan.would_be_rejected = %+v, want {reason: frozen}", planOut.Plan)
	}
	if len(planOut.Plan.Verdicts) != 1 || planOut.Plan.Verdicts[0].Verdict != "allow" {
		t.Errorf("plan.verdicts = %+v, want one allow verdict (Plan still queried while frozen)", planOut.Plan.Verdicts)
	}

	realRes := callTool(t, session, "run_operation", map[string]any{"selector": "node:role=web", "operation": "system.facts"})
	if !realRes.IsError {
		t.Fatal("run_operation(plan=false) while frozen: IsError = false, want true")
	}
	if text := toolErrorText(t, realRes); !strings.Contains(text, "the Relay is frozen") {
		t.Errorf("run_operation while frozen error = %q, want it to contain %q", text, "the Relay is frozen")
	}
}

// TestMCP_RunOperation_Plan_AuditedAsPlanNoJobOrTask is #119's audit
// acceptance line: a Plan appears in the audit trail as audit.KindPlan, and
// creates no Job (the deterministic next Job id was never minted) or Task
// (InFlight stays empty).
func TestMCP_RunOperation_Plan_AuditedAsPlanNoJobOrTask(t *testing.T) {
	ts := newTestServer(t)
	ts.conduit.connect(ts.nodeA)
	ts.conduit.verdicts[ts.nodeA] = jobs.Verdict{Allowed: true}

	session := ts.connect(t)
	res := callTool(t, session, "run_operation", map[string]any{"selector": "node:role=web", "operation": "system.facts", "plan": true})
	var out mcp.RunOrPlanOutput
	decodeResult(t, res, &out)

	records, err := ts.store.Audit().List(context.Background())
	if err != nil {
		t.Fatalf("Audit().List: %v", err)
	}
	foundPlan := false
	for _, rec := range records {
		if rec.Kind == audit.KindPlan {
			foundPlan = true
			if rec.JobID != "" {
				t.Errorf("KindPlan record JobID = %q, want empty", rec.JobID)
			}
			if rec.NodeID != "" {
				t.Errorf("KindPlan record NodeID = %q, want empty", rec.NodeID)
			}
		}
		if rec.Kind == audit.KindDispatch {
			t.Errorf("found a KindDispatch record from a plan=true call: %+v", rec)
		}
	}
	if !foundPlan {
		t.Fatalf("no audit.KindPlan record found; records = %+v", records)
	}

	// deterministicIDs mints "job-id-1" as the very first Job ID a fresh
	// testServer would create — a Plan must never have consumed it.
	if _, err := ts.store.Jobs().GetJob(context.Background(), "job-id-1"); err == nil {
		t.Fatal("GetJob(job-id-1) succeeded — a Plan must never create a Job")
	} else if err != jobs.ErrJobNotFound {
		t.Fatalf("GetJob(job-id-1) error = %v, want jobs.ErrJobNotFound", err)
	}

	inFlight, err := ts.store.Tasks().InFlight(context.Background())
	if err != nil {
		t.Fatalf("InFlight: %v", err)
	}
	if len(inFlight) != 0 {
		t.Errorf("InFlight = %+v, want empty (a Plan creates no Task)", inFlight)
	}

	// A subsequent real run still mints "job-id-1" — proof the Plan call
	// above never advanced the deterministic ID sequence either.
	runRes := callTool(t, session, "run_operation", map[string]any{"selector": "node:role=web", "operation": "system.facts"})
	var runOut mcp.RunOrPlanOutput
	decodeResult(t, runRes, &runOut)
	if runOut.JobID != "job-id-1" {
		t.Errorf("first real run's job_id = %q, want job-id-1 (the Plan call must not have minted any ID)", runOut.JobID)
	}
}

// TestMCP_RawExec_Plan_ArgvVerbatimMutateClass is raw_exec's plan-mode
// acceptance line: plan=true still probes argv verbatim, always risk class
// mutate (ADR-0012, invariant 13) — proven here via the mutate-cap
// would_be_rejected report, since RiskClass isn't otherwise observable on
// the wire.
func TestMCP_RawExec_Plan_ArgvVerbatimMutateClass(t *testing.T) {
	ts := newTestServerWithBlastCap(t, 1, 1) // read-cap generous is irrelevant; mutate-cap = 1
	ts.conduit.connect(ts.nodeA, ts.nodeB)

	session := ts.connect(t)
	res := callTool(t, session, "raw_exec", map[string]any{
		"argv": []string{"/usr/bin/systemctl", "restart", "nginx"},
		"plan": true,
	})
	if res.IsError {
		t.Fatalf("raw_exec(plan=true): IsError = true, content = %+v", res.Content)
	}
	var out mcp.RunOrPlanOutput
	decodeResult(t, res, &out)
	if out.Plan == nil || out.Plan.WouldBeRejected == nil || out.Plan.WouldBeRejected.Class != "mutate" {
		t.Fatalf("raw_exec(plan=true).would_be_rejected = %+v, want class=mutate (always mutate, ADR-0012)", out.Plan)
	}
}

// TestMCP_Plan_PlanVsRealRunParity is docs/specs/plan-mode.md's acceptance line for #119
// (also feeding #121): with Query and Dispatch configured consistently
// (allow<->Success, deny<->DeniedByPolicy, offline<->Unreachable) on the
// same unchanged fleet, a Plan's verdicts match a subsequent real run's
// outcomes.
func TestMCP_Plan_PlanVsRealRunParity(t *testing.T) {
	ts := newTestServer(t)
	ts.conduit.connect(ts.nodeA)
	// nodeB stays disconnected: offline <-> Unreachable.
	ts.conduit.verdicts[ts.nodeA] = jobs.Verdict{Allowed: true}
	ts.conduit.results[ts.nodeA] = jobs.Result{Outcome: jobs.OutcomeSuccess}

	session := ts.connect(t)

	planRes := callTool(t, session, "run_operation", map[string]any{"operation": "system.facts", "plan": true})
	var planOut mcp.RunOrPlanOutput
	decodeResult(t, planRes, &planOut)

	runRes := callTool(t, session, "run_operation", map[string]any{"operation": "system.facts"})
	var runOut mcp.RunOrPlanOutput
	decodeResult(t, runRes, &runOut)

	planByNode := verdictsByNode(*planOut.Plan)
	runByNode := map[string]mcp.PerNodeResult{}
	for _, r := range runOut.Results {
		runByNode[r.NodeID] = r
	}

	if planByNode[ts.nodeA].Verdict != "allow" || runByNode[ts.nodeA].Outcome != "success" {
		t.Errorf("node %s: plan verdict = %q, real outcome = %q, want allow/success", ts.nodeA, planByNode[ts.nodeA].Verdict, runByNode[ts.nodeA].Outcome)
	}
	if planByNode[ts.nodeB].Verdict != "unknown" || planByNode[ts.nodeB].Reason != "offline" {
		t.Errorf("node %s: plan verdict = %+v, want unknown/offline", ts.nodeB, planByNode[ts.nodeB])
	}
	if runByNode[ts.nodeB].Outcome != "unreachable" {
		t.Errorf("node %s: real outcome = %q, want unreachable", ts.nodeB, runByNode[ts.nodeB].Outcome)
	}
}
