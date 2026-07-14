package capability

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/jobs"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/registry"
)

// newPlanTestService wires a real jobEngine (fakeConduit-backed) behind a
// Service, exactly like execution_test.go's TestWithExecutionAcceptsRealSeams
// — plan_test.go's Plan tests need the real query path (jobEngine.query),
// not spyDispatcher's no-op, to prove the offline/allow/deny fan-out.
func newPlanTestService(t *testing.T, reg registry.Repository, conduit *fakeConduit, opts ...ExecOption) (*Service, *spyAuditSink, *fakeFreezeStore) {
	t.Helper()
	jobsRepo, tasksRepo := testEngineStore(t)
	audit := &spyAuditSink{}
	freezeStore := &fakeFreezeStore{}
	svc := New(reg,
		WithAuthorizer(&spyAuthorizer{}),
		WithCapChecker(&spyCapChecker{}),
		WithAuditSink(audit),
		WithFreeze(freezeStore),
		WithExecution(jobsRepo, tasksRepo, conduit, opts...),
	)
	return svc, audit, freezeStore
}

// webSelector matches every Node seedNodes/seedOneNode label "role=web".
func webSelector() Selector {
	return Selector{Predicates: []Predicate{{Namespace: NamespaceNode, Key: "role", Value: "web"}}}
}

// TestPlanReturnsPerNodeVerdictsNoJobOrTask is the core acceptance line: a
// Plan against two connected Nodes (one allow, one deny-with-rule) returns
// both verdicts and creates NO Job/Task — the repos are never touched.
func TestPlanReturnsPerNodeVerdictsNoJobOrTask(t *testing.T) {
	reg := seedNodes(t, 2)
	var log []string
	conduit := newFakeConduit(&log)
	conduit.connected["node-0"] = true
	conduit.connected["node-1"] = true
	conduit.verdicts["node-0"] = jobs.Verdict{Allowed: true}
	conduit.verdicts["node-1"] = jobs.Verdict{Allowed: false, DecidingRule: "deny-rm-rf"}

	svc, audit, _ := newPlanTestService(t, reg, conduit)

	sel := webSelector()
	act := jobs.Action{Kind: jobs.ActionRawExec, RawExecArgv: []string{"/bin/rm", "-rf", "/"}, RiskClass: jobs.RiskClassMutate}
	pr, err := svc.Plan(context.Background(), Principal{Account: "alice"}, sel, act)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}

	if pr.Matched != 2 {
		t.Errorf("PlanResult.Matched = %d, want 2", pr.Matched)
	}
	if pr.CapExceeded != nil {
		t.Errorf("PlanResult.CapExceeded = %+v, want nil", pr.CapExceeded)
	}
	if len(pr.Verdicts) != 2 {
		t.Fatalf("PlanResult.Verdicts = %+v, want 2 entries", pr.Verdicts)
	}
	got := map[string]NodeVerdict{}
	for _, v := range pr.Verdicts {
		got[v.NodeID] = v
	}
	if v := got["node-0"]; v.Status != VerdictAllow {
		t.Errorf("node-0 verdict = %+v, want VerdictAllow", v)
	}
	if v := got["node-1"]; v.Status != VerdictDeny || v.DecidingRule != "deny-rm-rf" {
		t.Errorf("node-1 verdict = %+v, want VerdictDeny/deny-rm-rf", v)
	}

	// No Job/Task was ever created: jobEngine.query never calls CreateTask or
	// CreateJob — the shared log (Dispatch/Cancel/Query calls) proves Query
	// was called for each Node, but never Dispatch.
	for _, entry := range log {
		if len(entry) >= len("dispatch:") && entry[:len("dispatch:")] == "dispatch:" {
			t.Errorf("Plan dispatched a Task (log entry %q) — a Plan must never execute", entry)
		}
	}

	// The audit trail carries exactly one AuditKindPlan entry, Principal/
	// Selector/Action set, JobID/Results empty (#119's audit acceptance).
	if !audit.called {
		t.Fatal("AuditSink was not called")
	}
	if audit.entry.Kind != AuditKindPlan {
		t.Errorf("AuditEntry.Kind = %v, want AuditKindPlan", audit.entry.Kind)
	}
	if audit.entry.JobID != "" {
		t.Errorf("AuditEntry.JobID = %q, want empty (a Plan creates no Job)", audit.entry.JobID)
	}
	if len(audit.entry.Results) != 0 {
		t.Errorf("AuditEntry.Results = %+v, want empty (a Plan creates no Task)", audit.entry.Results)
	}
	if audit.entry.Selector.Predicates[0] != sel.Predicates[0] {
		t.Errorf("AuditEntry.Selector = %+v, want %+v", audit.entry.Selector, sel)
	}
}

// TestPlanOfflineNodeIsUnknownNeverQueried is the offline acceptance line: a
// matched-but-disconnected Node yields VerdictUnknown/"offline" and Query is
// never called for it — the Relay never guesses from a cached PolicySnapshot
// (invariant 12).
func TestPlanOfflineNodeIsUnknownNeverQueried(t *testing.T) {
	reg := seedNodes(t, 2)
	var log []string
	conduit := newFakeConduit(&log)
	conduit.connected["node-0"] = true
	conduit.verdicts["node-0"] = jobs.Verdict{Allowed: true}
	// node-1 is deliberately absent from conduit.connected (offline).

	svc, _, _ := newPlanTestService(t, reg, conduit)

	pr, err := svc.Plan(context.Background(), Principal{Account: "alice"}, webSelector(), jobs.Action{Kind: jobs.ActionOperation, OperationName: "system.facts", RiskClass: jobs.RiskClassRead})
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}

	got := map[string]NodeVerdict{}
	for _, v := range pr.Verdicts {
		got[v.NodeID] = v
	}
	offline, ok := got["node-1"]
	if !ok {
		t.Fatalf("PlanResult.Verdicts missing node-1: %+v", pr.Verdicts)
	}
	if offline.Status != VerdictUnknown || offline.Reason != "offline" {
		t.Errorf("node-1 verdict = %+v, want VerdictUnknown/offline", offline)
	}

	for _, entry := range log {
		if entry == "query:node-1" {
			t.Error("Query was called for an offline Node — must conclude unknown(offline) without ever querying it")
		}
	}
}

// TestPlanOverCapReportsNotErrors is the over-cap acceptance line: a
// Selector matching more Nodes than the applicable cap reports CapExceeded
// as DATA (err == nil), with Verdicts empty (the query fan-out is skipped)
// and Query never called for any matched Node.
func TestPlanOverCapReportsNotErrors(t *testing.T) {
	reg := seedNodes(t, 5)
	var log []string
	conduit := newFakeConduit(&log)
	for i := 0; i < 5; i++ {
		nodeID := fmt.Sprintf("node-%d", i)
		conduit.connected[nodeID] = true
		conduit.verdicts[nodeID] = jobs.Verdict{Allowed: true}
	}

	jobsRepo, tasksRepo := testEngineStore(t)
	audit := &spyAuditSink{}
	svc := New(reg,
		WithAuthorizer(&spyAuthorizer{}),
		WithCapChecker(NewBlastCap(100, 2)), // mutate-cap = 2, 5 Nodes matched
		WithAuditSink(audit),
		WithFreeze(&fakeFreezeStore{}),
		WithExecution(jobsRepo, tasksRepo, conduit),
	)

	act := jobs.Action{Kind: jobs.ActionRawExec, RawExecArgv: []string{"/bin/true"}, RiskClass: jobs.RiskClassMutate}
	pr, err := svc.Plan(context.Background(), Principal{Account: "alice"}, webSelector(), act)
	if err != nil {
		t.Fatalf("Plan() with an over-cap Selector should report, not error: %v", err)
	}
	if pr.CapExceeded == nil {
		t.Fatal("PlanResult.CapExceeded = nil, want a *CapExceededError")
	}
	if pr.CapExceeded.Matched != 5 {
		t.Errorf("CapExceeded.Matched = %d, want 5", pr.CapExceeded.Matched)
	}
	if pr.CapExceeded.Cap != 2 {
		t.Errorf("CapExceeded.Cap = %d, want 2", pr.CapExceeded.Cap)
	}
	if len(pr.Verdicts) != 0 {
		t.Errorf("PlanResult.Verdicts = %+v, want empty (query fan-out skipped over-cap)", pr.Verdicts)
	}
	if len(log) != 0 {
		t.Errorf("Conduit was touched (log = %v), want no Query/Dispatch calls over-cap", log)
	}

	if !audit.called || audit.entry.Kind != AuditKindPlan {
		t.Errorf("expected an AuditKindPlan entry even for an over-cap Plan, got called=%v kind=%v", audit.called, audit.entry.Kind)
	}
}

// TestPlanFrozenReportsAdvisoryWhileRunRefuses is the Freeze-exemption
// acceptance line (ADR-0013): with the Relay-wide Freeze engaged, Plan still
// runs its query fan-out and reports Frozen==true, while Run against the
// SAME Service refuses with a *FrozenError.
func TestPlanFrozenReportsAdvisoryWhileRunRefuses(t *testing.T) {
	reg := seedOneNode(t)
	var log []string
	conduit := newFakeConduit(&log)
	conduit.connected["node-1"] = true
	conduit.verdicts["node-1"] = jobs.Verdict{Allowed: true}
	conduit.results["node-1"] = jobs.Result{Outcome: jobs.OutcomeSuccess}

	jobsRepo, tasksRepo := testEngineStore(t)
	audit := &spyAuditSink{}
	freezeStore := &fakeFreezeStore{frozen: true}
	svc := New(reg,
		WithAuthorizer(&spyAuthorizer{}),
		WithCapChecker(&spyCapChecker{}),
		WithAuditSink(audit),
		WithFreeze(freezeStore),
		WithExecution(jobsRepo, tasksRepo, conduit),
	)

	sel := Selector{Predicates: []Predicate{{Namespace: NamespaceNode, Key: "role", Value: "web"}}}
	act := jobs.Action{Kind: jobs.ActionOperation, OperationName: "system.facts", RiskClass: jobs.RiskClassRead}

	pr, err := svc.Plan(context.Background(), Principal{Account: "alice"}, sel, act)
	if err != nil {
		t.Fatalf("Plan() while frozen should still succeed: %v", err)
	}
	if !pr.Frozen {
		t.Error("PlanResult.Frozen = false, want true")
	}
	if len(pr.Verdicts) != 1 || pr.Verdicts[0].Status != VerdictAllow {
		t.Errorf("PlanResult.Verdicts = %+v, want one VerdictAllow (Plan still queried while frozen)", pr.Verdicts)
	}

	_, runErr := svc.Run(context.Background(), Principal{Account: "alice"}, sel, act)
	var frozenErr *FrozenError
	if !errors.As(runErr, &frozenErr) {
		t.Fatalf("Run() error = %v, want errors.As to find a *FrozenError", runErr)
	}
}

// TestPlanOutdatedNodeGetsRealVerdictAdvisoryOnly is ADR-0014's plan-mode
// contract: an outdated matched Node still gets a real, queried verdict
// (invariant 12 — Plan mode never gates or skips the PolicyQuery for it) AND
// NodeVerdict.Outdated is set as an advisory apply-time hint; a current
// matched Node's Outdated is false.
func TestPlanOutdatedNodeGetsRealVerdictAdvisoryOnly(t *testing.T) {
	reg := registry.NewInMemory(registry.WithMinDaemonVersion("1.2.0"))
	if _, err := reg.Upsert(registry.Report{
		NodeID:        "node-current",
		NodeLabels:    map[string]string{"role": "web"},
		DaemonVersion: "1.2.0",
	}); err != nil {
		t.Fatalf("Upsert(node-current): %v", err)
	}
	if _, err := reg.Upsert(registry.Report{
		NodeID:        "node-old",
		NodeLabels:    map[string]string{"role": "web"},
		DaemonVersion: "1.0.0",
	}); err != nil {
		t.Fatalf("Upsert(node-old): %v", err)
	}

	var log []string
	conduit := newFakeConduit(&log)
	conduit.connected["node-current"] = true
	conduit.connected["node-old"] = true
	conduit.verdicts["node-current"] = jobs.Verdict{Allowed: true}
	conduit.verdicts["node-old"] = jobs.Verdict{Allowed: true}

	svc, _, _ := newPlanTestService(t, reg, conduit)

	pr, err := svc.Plan(context.Background(), Principal{Account: "alice"}, webSelector(), jobs.Action{Kind: jobs.ActionOperation, OperationName: "system.facts", RiskClass: jobs.RiskClassRead})
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}

	got := map[string]NodeVerdict{}
	for _, v := range pr.Verdicts {
		got[v.NodeID] = v
	}

	current, ok := got["node-current"]
	if !ok {
		t.Fatalf("PlanResult.Verdicts missing node-current: %+v", pr.Verdicts)
	}
	if current.Status != VerdictAllow {
		t.Errorf("node-current verdict = %+v, want VerdictAllow", current)
	}
	if current.Outdated {
		t.Error("node-current Outdated = true, want false (at minimum version)")
	}

	old, ok := got["node-old"]
	if !ok {
		t.Fatalf("PlanResult.Verdicts missing node-old: %+v", pr.Verdicts)
	}
	// The verdict is the REAL daemon verdict, unchanged by Outdated — the gate
	// is a Run-only, dispatch-level concern (invariant 12).
	if old.Status != VerdictAllow {
		t.Errorf("node-old verdict = %+v, want VerdictAllow (a real, queried verdict — plan mode never gates on Outdated)", old)
	}
	if !old.Outdated {
		t.Error("node-old Outdated = false, want true (below configured minimum)")
	}

	// The PolicyQuery fan-out ran for the outdated Node too — Plan never
	// skips it.
	found := false
	for _, entry := range log {
		if entry == "query:node-old" {
			found = true
		}
	}
	if !found {
		t.Errorf("Conduit.Query was never called for node-old (log = %v); Plan must still query outdated Nodes", log)
	}
}

// TestPlanAuthzDeniedRecordsRefusalNoVerdicts is the authz-gates acceptance
// line (invariant 3, ADR-0011): a denied Principal gets an error and a
// KindRefusal audit entry, never verdicts.
func TestPlanAuthzDeniedRecordsRefusalNoVerdicts(t *testing.T) {
	reg := seedOneNode(t)
	authz := &spyAuthorizer{err: errors.New("denied")}
	capChecker := &spyCapChecker{}
	disp := &spyDispatcher{}
	audit := &spyAuditSink{}
	svc := &Service{reg: reg, authz: authz, cap: capChecker, disp: disp, audit: audit, freeze: noopFreezeStore{}, metrics: noopMetricsSink{}}

	sel := Selector{Predicates: []Predicate{{Namespace: NamespaceNode, Key: "role", Value: "web"}}}
	pr, err := svc.Plan(context.Background(), Principal{Account: "alice"}, sel, jobs.Action{RiskClass: jobs.RiskClassRead})
	if err == nil {
		t.Fatal("Plan() with a denying Authorizer should return an error")
	}
	if !authz.called {
		t.Error("Authorizer was not called")
	}
	if capChecker.called {
		t.Error("CapChecker must not be called when Authorize fails")
	}
	if len(pr.Verdicts) != 0 {
		t.Errorf("PlanResult.Verdicts = %+v, want empty on an authz-deny", pr.Verdicts)
	}
	if !audit.called {
		t.Fatal("AuditSink must be called when Authorize fails — refusals are audited")
	}
	if audit.entry.Kind != AuditKindRefusal {
		t.Errorf("AuditEntry.Kind = %v, want AuditKindRefusal", audit.entry.Kind)
	}
}
