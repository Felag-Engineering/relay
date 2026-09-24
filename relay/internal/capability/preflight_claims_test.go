package capability

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/approval"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/jobs"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/registry"
)

// TestVerdictZeroValueIsUnknownNeverAllow proves PF-22's first half
// (docs/specs/policy-preflight.md): "unknown is the zero value of the
// Relay's verdict — a verdict never obtained reads as 'not known', never as
// a fabricated allow." A NodeVerdict the Relay never got around to filling
// in must never silently read as permission.
//
// Negative half (no test needed to demonstrate it — reordering plan.go's
// iota block so VerdictAllow is zero fails the first two assertions below
// directly): both surfaces' verdict-rendering default arm already renders 0
// as "unknown" (mcp/tools_execution.go, api/execution.go), so the rendering
// agrees with the zero value rather than being a second place to keep in
// step.
func TestVerdictZeroValueIsUnknownNeverAllow(t *testing.T) {
	if VerdictStatus(0) != VerdictUnknown {
		t.Errorf("VerdictStatus(0) = %v, want VerdictUnknown", VerdictStatus(0))
	}
	var zero VerdictStatus
	if zero != VerdictUnknown {
		t.Errorf("a declared-but-unassigned VerdictStatus = %v, want VerdictUnknown", zero)
	}
	if v := (NodeVerdict{NodeID: "n"}).Status; v != VerdictUnknown {
		t.Errorf("NodeVerdict{NodeID: \"n\"}.Status = %v, want VerdictUnknown (a verdict never filled in must read as \"not known\", never as a fabricated allow)", v)
	}
	for _, other := range []VerdictStatus{VerdictAllow, VerdictDeny, VerdictUnsupported} {
		if VerdictUnknown == other {
			t.Errorf("VerdictUnknown must be distinct from %v", other)
		}
	}
}

// countingApprovalGate wraps a real ApprovalGate and counts every Evaluate
// call, so TestPreflightNeverConsultsTheApprovalGate can assert on the count
// rather than on inner's own state.
type countingApprovalGate struct {
	inner ApprovalGate
	calls int
}

func (g *countingApprovalGate) Evaluate(d approval.Dispatch) (approval.Requirement, []string, bool) {
	g.calls++
	return g.inner.Evaluate(d)
}

// TestPreflightNeverConsultsTheApprovalGate proves PF-23's behavioural half:
// "A preflight of an Action a Gate rule would park is answered like any
// other: it consults no gate rule, parks nothing, and its response does not
// say whether a real run would require approval."
//
// approvalFixture (approval_test.go) is deliberately NOT reused here: it
// sets the Service's dispatcher field directly rather than calling
// WithExecution, so a Plan run against it would have no real jobEngine to
// query through. This builds a Service with WithApprovals AND WithExecution
// together, which New accepts (Run parks before ever reaching the
// dispatcher, so pairing them is not a fail-open combination).
func TestPreflightNeverConsultsTheApprovalGate(t *testing.T) {
	reg := registry.NewInMemory()
	for _, id := range []string{"node-a", "node-b"} {
		if _, err := reg.Upsert(registry.Report{NodeID: id}.WithNodeLabels(map[string]string{"role": "web"})); err != nil {
			t.Fatalf("Upsert(%s): %v", id, err)
		}
	}

	var log []string
	conduit := newFakeConduit(&log)
	conduit.connected["node-a"] = true
	conduit.connected["node-b"] = true
	conduit.verdicts["node-a"] = jobs.Verdict{Allowed: true}
	conduit.verdicts["node-b"] = jobs.Verdict{Allowed: false, DecidingRule: "deny-rule"}

	jobsRepo, tasksRepo := testEngineStore(t)
	store := newMemApprovals()
	gate := &countingApprovalGate{inner: gateEverything(t, 1)}

	svc := New(reg,
		WithAuthorizer(&spyAuthorizer{}),
		WithCapChecker(&spyCapChecker{}),
		WithAuditSink(&spyAuditSink{}),
		WithFreeze(&fakeFreezeStore{}),
		WithApprovals(gate, store, &spyApprovalAuthorizer{}),
		WithClock(func() time.Time { return apNow }),
		WithExecution(jobsRepo, tasksRepo, conduit),
	)

	sel := webSelector()
	act := mutateAct()

	pr, err := svc.Plan(context.Background(), Principal{Account: "alice"}, sel, act)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	if len(pr.Verdicts) != 2 {
		t.Fatalf("PlanResult.Verdicts = %+v, want 2 entries", pr.Verdicts)
	}
	if gate.calls != 0 {
		t.Errorf("gate.calls = %d, want 0 — a preflight must never consult an approval-gate rule", gate.calls)
	}
	if len(store.byID) != 0 || len(store.byHash) != 0 || len(store.bound) != 0 {
		t.Errorf("store = {byID: %+v, byHash: %+v, bound: %+v}, want all empty — a preflight must park nothing, write nothing to the approval store", store.byID, store.byHash, store.bound)
	}

	// ARMED CONTROL, the load-bearing half: the SAME Service, Principal,
	// Selector and Action driven through the Service's dispatch entry point
	// now returns a *ParkedError — proving the gate really would have
	// parked this exact Action, so the zero-calls assertion above means
	// "never consulted", not "never wired". Without this the test is
	// vacuous — zero gate calls is also what an unwired gate gives.
	_, runErr := svc.Run(context.Background(), Principal{Account: "alice"}, sel, act)
	var parked *ParkedError
	if !errors.As(runErr, &parked) {
		t.Fatalf("Run() error = %v, want errors.As to find a *ParkedError (this exact Action must actually be gated for the zero-calls assertion above to mean anything)", runErr)
	}
	if gate.calls != 1 {
		t.Errorf("gate.calls = %d, want 1 after Run parked", gate.calls)
	}
	if len(store.byID) != 1 {
		t.Errorf("store.byID = %+v, want exactly 1 entry after Run parked", store.byID)
	}
}

// assertExactStructFieldSet fails t if typ's field-name set is not exactly
// want. expectedAddition names, in the failure message, the one addition
// this set is already known to anticipate — so a future implementer who
// trips it can tell "this is the change we expected" from "something else
// changed" without re-deriving it from the spec.
func assertExactStructFieldSet(t *testing.T, typ reflect.Type, want map[string]bool, expectedAddition string) {
	t.Helper()
	got := make(map[string]bool, typ.NumField())
	for i := 0; i < typ.NumField(); i++ {
		got[typ.Field(i).Name] = true
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("%s field set = %v, want %v — any addition must be named here and reviewed against PF-23 first (%s)", typ.Name(), got, want, expectedAddition)
	}
}

// TestPreflightResultCarriesNoApprovalField proves PF-23's response half:
// "its response does not say whether a real run would require approval."
//
// This is checked at the capability seam rather than mirrored on MCP/the
// Control API: renderPlan on both surfaces takes a capability.PlanResult and
// nothing else, and invariant 10 lets an adapter narrow only — a
// would-require-approval field on either surface would have no data behind
// it to narrow from.
func TestPreflightResultCarriesNoApprovalField(t *testing.T) {
	assertExactStructFieldSet(t, reflect.TypeOf(PlanResult{}), map[string]bool{
		"Matched": true, "Frozen": true, "CapExceeded": true, "NoNodesMatched": true, "Verdicts": true,
	}, "no addition to PlanResult is anticipated yet")
	// NodeVerdict's set is the one most likely to be legitimately tripped by
	// planned work: PF-20 (v0.8.1, Designed) adds a deny REASON KIND beside
	// DecidingRule (e.g. distinguishing "denied by rule" from "denied:
	// unsupported argument value"), which is a new field here, not a new
	// approval-shaped one — reviewers should expect that addition and check
	// it is not would_require_approval in disguise.
	assertExactStructFieldSet(t, reflect.TypeOf(NodeVerdict{}), map[string]bool{
		"NodeID": true, "Status": true, "DecidingRule": true, "Reason": true, "Outdated": true,
	}, "PF-20, v0.8.1, is expected to add a deny-reason-kind field here — that is a legitimate addition, an approval-shaped one is not")
}

// queryRecordingConduit wraps fakeConduit and records every Action passed to
// Query, since fakeConduit.Query itself discards it. Embedding keeps
// Connected/Dispatch/Cancel exactly as fakeConduit already implements them.
type queryRecordingConduit struct {
	*fakeConduit
	queried []jobs.Action
}

func (c *queryRecordingConduit) Query(ctx context.Context, nodeID string, act jobs.Action) (jobs.Verdict, error) {
	c.queried = append(c.queried, act)
	return c.fakeConduit.Query(ctx, nodeID, act)
}

// TestPreflightCarriesAnIllFormedArgumentValueToTheDaemon is the Relay-side
// link of PF-13's value half: "Argument values are validated by the
// daemon's engine, so an ill-formed value surfaces as that Node's verdict,
// not as a Relay refusal." This proves only the Relay side: the argument is
// not inspected, not normalised, not refused, and whatever the daemon
// answered is passed through unaltered. The canned DecidingRule below is a
// deliberately neutral string, not the daemon's real canonical-form text —
// this test says nothing about what the daemon would actually decide (that
// is docs/specs/policy-preflight.md's daemon-side link, proven by
// plan_and_apply_agree_on_a_non_canonical_template_path in the daemon tree).
func TestPreflightCarriesAnIllFormedArgumentValueToTheDaemon(t *testing.T) {
	reg := seedOneNode(t)
	var log []string
	inner := newFakeConduit(&log)
	inner.connected["node-1"] = true
	inner.verdicts["node-1"] = jobs.Verdict{Allowed: false, DecidingRule: "canned-by-the-fake-conduit"}
	conduit := &queryRecordingConduit{fakeConduit: inner}

	jobsRepo, tasksRepo := testEngineStore(t)
	svc := New(reg,
		WithAuthorizer(&spyAuthorizer{}),
		WithCapChecker(&spyCapChecker{}),
		WithAuditSink(&spyAuditSink{}),
		WithFreeze(&fakeFreezeStore{}),
		WithExecution(jobsRepo, tasksRepo, conduit),
	)

	const illFormedPath = "/etc/../etc/shadow"
	act := jobs.Action{
		Kind:          jobs.ActionOperation,
		OperationName: "file.read",
		OperationArgs: map[string]string{"path": illFormedPath},
		RiskClass:     jobs.RiskClassRead,
	}
	sel := Selector{Predicates: []Predicate{{Namespace: NamespaceNode, Key: "role", Value: "web"}}}

	pr, err := svc.Plan(context.Background(), Principal{Account: "alice"}, sel, act)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}

	if len(conduit.queried) != 1 {
		t.Fatalf("conduit.queried = %+v, want exactly one recorded Query", conduit.queried)
	}
	if got := conduit.queried[0].OperationArgs["path"]; got != illFormedPath {
		t.Errorf("recorded OperationArgs[\"path\"] = %q, want %q byte-for-byte — no normalisation, no canonicalisation, no Relay refusal", got, illFormedPath)
	}
	if len(pr.Verdicts) != 1 || pr.Verdicts[0].Status != VerdictDeny || pr.Verdicts[0].DecidingRule != "canned-by-the-fake-conduit" {
		t.Errorf("PlanResult.Verdicts = %+v, want one VerdictDeny carrying exactly the canned DecidingRule", pr.Verdicts)
	}
}
