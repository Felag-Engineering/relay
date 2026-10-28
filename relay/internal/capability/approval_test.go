package capability

import (
	"context"
	"errors"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Felag-Engineering/relay/relay/internal/approval"
	"github.com/Felag-Engineering/relay/relay/internal/jobs"
	"github.com/Felag-Engineering/relay/relay/internal/registry"
	"github.com/Felag-Engineering/relay/relay/internal/store"
)

// memApprovals is an in-memory ApprovalStore for these tests. It is deliberately
// simple: the store's own behaviour is tested in internal/store, and what
// matters here is the capability layer's decision-making.
//
// mu guards every method (S5, #713 plan review): the concurrent-claim tests
// (TestRun_ConcurrentReDrivesDispatchExactlyOneJob and friends) drive BindJob
// from many goroutines at once, and this fake must serialise its own map
// writes the way SetMaxOpenConns(1) serialises the real store's transactions
// — otherwise it would race on its own bookkeeping rather than exercising the
// domain's Release rule.
type memApprovals struct {
	mu     sync.Mutex
	byID   map[string]approval.Request
	byHash map[string]string // planHash -> id
	bound  map[string]string // id -> jobID
}

func newMemApprovals() *memApprovals {
	return &memApprovals{byID: map[string]approval.Request{}, byHash: map[string]string{}, bound: map[string]string{}}
}

func (m *memApprovals) Create(_ context.Context, r approval.Request) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.byID[r.ID] = r
	m.byHash[r.PlanHash] = r.ID
	return nil
}

func (m *memApprovals) ByPlanHash(_ context.Context, planHash string) (approval.Request, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	id, ok := m.byHash[planHash]
	if !ok {
		return approval.Request{}, approval.ErrNotFound
	}
	return m.byID[id], nil
}

// BindJob mirrors the store's release claim (AP-77): it calls r.Release under
// the lock, so two goroutines calling BindJob concurrently on the same
// Request race the mutex, not the domain rule — exactly what
// SetMaxOpenConns(1) plus a transaction gives the real store.
func (m *memApprovals) BindJob(_ context.Context, id, jobID string, now time.Time) (approval.Request, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.byID[id]
	if !ok {
		return approval.Request{}, approval.ErrNotFound
	}
	updated, err := r.Release(jobID, now)
	if err != nil {
		// Mirrors the SQLite store: on refusal, return r as read here (which,
		// for ErrAlreadyReleased, carries the previously bound JobID) rather
		// than the zero value.
		return r, err
	}
	m.bound[id] = jobID
	m.byID[id] = updated
	return updated, nil
}

func (m *memApprovals) Get(_ context.Context, id string) (approval.Request, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.byID[id]
	if !ok {
		return approval.Request{}, approval.ErrNotFound
	}
	return r, nil
}

func (m *memApprovals) Pending(_ context.Context) ([]approval.Request, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	ids := make([]string, 0, len(m.byID))
	for id := range m.byID {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	out := make([]approval.Request, 0, len(ids))
	for _, id := range ids {
		if r := m.byID[id]; r.State == approval.StatePending {
			out = append(out, r)
		}
	}
	return out, nil
}

// RecordDecision mirrors the SQLite store: the domain type owns every
// eligibility rule and this only persists the result, so a test that passes
// here is exercising the same decision logic production runs.
func (m *memApprovals) RecordDecision(_ context.Context, id string, d approval.Decision, now time.Time) (approval.Request, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.byID[id]
	if !ok {
		return approval.Request{}, approval.ErrNotFound
	}
	updated, err := r.Decide(d, now)
	if err != nil {
		// Mirrors the SQLite store: on a refusal, return r as read here rather
		// than the zero value, so a caller never needs a second, potentially
		// racing, lookup.
		return r, err
	}
	m.byID[id] = updated
	return updated, nil
}

// LastApprovedByShape mirrors the SQLite store's semantics: newest RESOLVED
// approved record with that key, excluding excludeID, and ErrNotFound for an
// empty or legacy key — so a capability-layer test that passes here is
// exercising the same contract production reads through.
func (m *memApprovals) LastApprovedByShape(_ context.Context, shapeKey, excludeID string) (approval.Request, error) {
	if shapeKey == "" || approval.IsLegacyShapeKey(shapeKey) {
		return approval.Request{}, approval.ErrNotFound
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	var best approval.Request
	var found bool
	ids := make([]string, 0, len(m.byID))
	for id := range m.byID {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		r := m.byID[id]
		if r.ID == excludeID || r.ShapeKey != shapeKey || r.State != approval.StateApproved {
			continue
		}
		// Ties break toward the HIGHEST request ID, matching the store's
		// ORDER BY resolved_at DESC, request_id DESC — ids is sorted
		// ascending, so a later equal-timestamped row wins.
		if !found || !r.ResolvedAt.Before(best.ResolvedAt) {
			best, found = r, true
		}
	}
	if !found {
		return approval.Request{}, approval.ErrNotFound
	}
	return best, nil
}

// spyApprovalAuthorizer is the permissive default for the #269 park tests,
// which are about the gate rather than the decision floor. The floor's own
// behaviour is exercised in approval_decide_test.go and authz_test.go.
type spyApprovalAuthorizer struct {
	err  error
	kind jobs.ActionKind
}

func (s *spyApprovalAuthorizer) AuthorizeApprovalDecision(_ context.Context, _ Principal, kind jobs.ActionKind) error {
	s.kind = kind
	return s.err
}

// approve drives a stored Request to approved, as the decision endpoint will.
func (m *memApprovals) approve(t *testing.T, id, accountID, account string, at time.Time) {
	t.Helper()
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.byID[id]
	if !ok {
		t.Fatalf("no such request %q", id)
	}
	updated, err := r.Decide(approval.Decision{
		AccountID: accountID, Account: account, Approve: true,
		Channel: approval.ChannelOutOfBand, PlanHash: r.PlanHash, DeciderHuman: true, At: at,
	}, at)
	if err != nil {
		t.Fatalf("approve %s: %v", id, err)
	}
	m.byID[id] = updated
}

// hasAuditKind reports whether entries contains at least one AuditEntry of
// kind — used where a test only needs to know a refusal (or other kind) was
// recorded somewhere in the sequence, not which one.
func hasAuditKind(entries []AuditEntry, kind AuditKind) bool {
	for _, e := range entries {
		if e.Kind == kind {
			return true
		}
	}
	return false
}

func gateEverything(t *testing.T, count int) ApprovalGate {
	t.Helper()
	g, err := approval.NewGate([]approval.Rule{{
		Name:    "everything",
		Match:   approval.Match{},
		Require: approval.Requirement{Count: count, RequesterAllowed: true, Channel: approval.ChannelOutOfBand, TTL: time.Hour},
	}})
	if err != nil {
		t.Fatalf("NewGate: %v", err)
	}
	return g
}

func approvalFixture(t *testing.T, nodes []string, gate ApprovalGate, store ApprovalStore, now func() time.Time) (*testSvc, *spyDispatcher) {
	t.Helper()
	reg := registry.NewInMemory()
	for _, id := range nodes {
		if _, err := reg.Upsert(registry.Report{NodeID: id}); err != nil {
			t.Fatalf("seed registry: %v", err)
		}
	}
	disp := &spyDispatcher{jobID: "job-1"}
	s := build(t, seams{reg: reg,
		authz:  &spyAuthorizer{},
		cap:    &spyCapChecker{},
		audit:  &spyAuditSink{},
		freeze: &fakeFreezeStore{},
		gate:   gate, approvals: store, approvalAuthz: &spyApprovalAuthorizer{},
		now: now,
	})
	s.disp = disp
	return s, disp
}

// approvalFixtureWithAudit is approvalFixture with the AuditSink handed back
// too, for the AP-77 tests that need to inspect RecordRead calls
// (toolApprovalReattach) or count AuditKindDispatch entries.
func approvalFixtureWithAudit(t *testing.T, nodes []string, gate ApprovalGate, store ApprovalStore, now func() time.Time) (*testSvc, *spyDispatcher, *spyAuditSink) {
	t.Helper()
	reg := registry.NewInMemory()
	for _, id := range nodes {
		if _, err := reg.Upsert(registry.Report{NodeID: id}); err != nil {
			t.Fatalf("seed registry: %v", err)
		}
	}
	disp := &spyDispatcher{jobID: "job-1"}
	audit := &spyAuditSink{}
	s := build(t, seams{reg: reg,
		authz:  &spyAuthorizer{},
		cap:    &spyCapChecker{},
		audit:  audit,
		freeze: &fakeFreezeStore{},
		gate:   gate, approvals: store, approvalAuthz: &spyApprovalAuthorizer{},
		now: now,
	})
	s.disp = disp
	return s, disp, audit
}

var apNow = time.Date(2026, 8, 14, 9, 0, 0, 0, time.UTC)

// mutateAct is a Native mutate Operation as an adapter builds it: with no
// class, which the capability layer derives (invariant 13).
func mutateAct() jobs.Action {
	return jobs.Action{
		Kind: jobs.ActionOperation, OperationName: "service.restart",
		OperationArgs: map[string]string{"service": "nginx"},
	}
}

// resolvedMutateAct is mutateAct as the capability layer resolves it, for a
// test that compares against what Run hashed or recorded.
func resolvedMutateAct() jobs.Action {
	act := mutateAct()
	act.RiskClass = jobs.RiskClassMutate
	return act
}

// TestGatedDispatchParksAndSendsNothing is the core of #269: a gated dispatch
// must stop BEFORE the dispatcher, not after.
func TestGatedDispatchParksAndSendsNothing(t *testing.T) {
	store := newMemApprovals()
	s, disp := approvalFixture(t, []string{"node-a", "node-b"}, gateEverything(t, 1), store, func() time.Time { return apNow })

	res, err := s.Run(context.Background(), Principal{AccountID: "acct-g", Account: "gleipnir-prod"}, Selector{}, mutateAct())

	var parked *ParkedError
	if !errors.As(err, &parked) {
		t.Fatalf("err = %v, want a *ParkedError", err)
	}
	if res != nil {
		t.Errorf("results = %v, want nil — a parked dispatch produces no per-Node results", res)
	}
	if disp.called {
		t.Errorf("dispatcher was called; a parked dispatch must never reach it")
	}
	if parked.RequestID == "" || parked.PlanHash == "" {
		t.Error("ParkedError must carry the request ID and plan hash a decider needs")
	}
	if parked.Progress != "0 of 1" {
		t.Errorf("Progress = %q, want %q", parked.Progress, "0 of 1")
	}
	if len(parked.Rules) != 1 || parked.Rules[0] != "everything" {
		t.Errorf("Rules = %v, want the rule that fired to be named", parked.Rules)
	}
	if len(store.byID) != 1 {
		t.Errorf("stored %d requests, want exactly 1", len(store.byID))
	}
}

// blankAudienceGate is a minimal ApprovalGate that hands back a Requirement
// carrying a blank audience entry — something a real *approval.Gate can no
// longer produce (approval.Rule.Validate), so this stands in for any other
// ApprovalGate implementation checkApproval's own guard must defend against.
type blankAudienceGate struct {
	req   approval.Requirement
	rules []string
}

func (g blankAudienceGate) Evaluate(approval.Dispatch) (approval.Requirement, []string, bool) {
	return g.req, g.rules, true
}

// TestGatedDispatchRefusesABlankAudienceEntryBeforeAnyWrite is #608's
// dispatch-path (park) regression: the park path has no capability-level
// audience check of its own on main, and relies entirely on
// approval.Rule.Validate to have kept a blank entry out of the gate in the
// first place. A non-validating ApprovalGate must still be refused here,
// before a Request is created.
func TestGatedDispatchRefusesABlankAudienceEntryBeforeAnyWrite(t *testing.T) {
	store := newMemApprovals()
	gate := blankAudienceGate{
		req:   approval.Requirement{Count: 1, Audience: []string{"ana", ""}, Channel: approval.ChannelOutOfBand, TTL: time.Hour},
		rules: []string{"blank-rule"},
	}
	s, disp := approvalFixture(t, []string{"node-a"}, gate, store, func() time.Time { return apNow })

	_, err := s.Run(context.Background(), Principal{AccountID: "acct-g", Account: "gleipnir-prod"}, Selector{}, mutateAct())
	if !errors.Is(err, approval.ErrAudienceBlankEntry) {
		t.Fatalf("err = %v, want errors.Is(err, ErrAudienceBlankEntry)", err)
	}
	if !strings.Contains(err.Error(), "require.audience") || !strings.Contains(err.Error(), "blank-rule") {
		t.Errorf("error = %q, want it to mention require.audience and the offending rule", err)
	}
	if disp.called {
		t.Error("dispatcher was called; a refused dispatch must never reach it")
	}
	if len(store.byID) != 0 {
		t.Error("a refused dispatch must not create an approval request")
	}
}

// TestUngatedDispatchIsUntouched: an empty gate must leave the pre-approval
// pipeline exactly as it was.
func TestUngatedDispatchIsUntouched(t *testing.T) {
	empty, err := approval.NewGate(nil)
	if err != nil {
		t.Fatalf("NewGate: %v", err)
	}
	store := newMemApprovals()
	s, disp := approvalFixture(t, []string{"node-a"}, empty, store, func() time.Time { return apNow })

	if _, err := s.Run(context.Background(), Principal{Account: "gleipnir-prod"}, Selector{}, mutateAct()); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !disp.called {
		t.Error("dispatcher was not called")
	}
	if len(store.byID) != 0 {
		t.Error("an ungated dispatch must not create an approval request")
	}
}

// TestApprovedPlanDispatchesAndBindsTheJob: once the requirement is satisfied,
// the same dispatch proceeds and the approval is joined to the Job it released.
func TestApprovedPlanDispatchesAndBindsTheJob(t *testing.T) {
	store := newMemApprovals()
	s, disp := approvalFixture(t, []string{"node-a", "node-b"}, gateEverything(t, 1), store, func() time.Time { return apNow })
	p := Principal{AccountID: "acct-g", Account: "gleipnir-prod"}

	_, err := s.Run(context.Background(), p, Selector{}, mutateAct())
	var parked *ParkedError
	if !errors.As(err, &parked) {
		t.Fatalf("first Run: err = %v, want a park", err)
	}

	store.approve(t, parked.RequestID, "acct-ana", "ana", apNow.Add(time.Minute))

	if _, err := s.Run(context.Background(), p, Selector{}, mutateAct()); err != nil {
		t.Fatalf("second Run after approval: %v", err)
	}
	if !disp.called {
		t.Fatal("dispatcher was not called")
	}
	if got := store.bound[parked.RequestID]; got != "job-1" {
		t.Errorf("approval %s bound to job %q, want job-1 — audit must be able to join approval to execution", parked.RequestID, got)
	}
	if disp.ranWithJobID != "job-1" {
		t.Errorf("dispatcher ran with jobID %q, want job-1 — the reserved, already-bound id (AP-77)", disp.ranWithJobID)
	}
}

// TestRegistryDriftReParksAnApprovedPlan is ADR-0027's park-something-innocuous-
// then-mutate-the-world guard, end to end. An approval covering two Nodes must
// not release a dispatch that now reaches three.
func TestRegistryDriftReParksAnApprovedPlan(t *testing.T) {
	reg := registry.NewInMemory()
	for _, id := range []string{"node-a", "node-b"} {
		if _, err := reg.Upsert(registry.Report{NodeID: id}); err != nil {
			t.Fatalf("seed: %v", err)
		}
	}
	store := newMemApprovals()
	disp := &spyDispatcher{jobID: "job-1"}
	s := build(t, seams{reg: reg,
		authz: &spyAuthorizer{}, cap: &spyCapChecker{},
		audit: &spyAuditSink{}, freeze: &fakeFreezeStore{},
		gate: gateEverything(t, 1), approvals: store, approvalAuthz: &spyApprovalAuthorizer{}, now: func() time.Time { return apNow },
	})
	s.disp = disp
	p := Principal{AccountID: "acct-g", Account: "gleipnir-prod"}

	_, err := s.Run(context.Background(), p, Selector{}, mutateAct())
	var first *ParkedError
	if !errors.As(err, &first) {
		t.Fatalf("first Run: err = %v, want a park", err)
	}
	store.approve(t, first.RequestID, "acct-ana", "ana", apNow.Add(time.Minute))

	// A third Node joins the fleet between approval and dispatch.
	if _, err := reg.Upsert(registry.Report{NodeID: "node-c"}); err != nil {
		t.Fatalf("drift: %v", err)
	}

	_, err = s.Run(context.Background(), p, Selector{}, mutateAct())
	var second *ParkedError
	if !errors.As(err, &second) {
		t.Fatalf("after drift: err = %v, want a fresh park — an approval for 2 Nodes must not release a dispatch to 3", err)
	}
	if second.RequestID == first.RequestID {
		t.Error("drift must produce a NEW approval request, not reuse the one approved for the old fan-out")
	}
	if second.PlanHash == first.PlanHash {
		t.Error("a changed fan-out must change the plan hash")
	}
	if disp.called {
		t.Error("dispatcher was called — nothing may run against a fan-out nobody approved")
	}
}

// TestRepeatedRunReusesTheSamePark: retrying while a decision is outstanding
// must not fan out a second request for the same Plan, which would double every
// notification and let a requester shop for a friendlier approver.
func TestRepeatedRunReusesTheSamePark(t *testing.T) {
	store := newMemApprovals()
	s, _ := approvalFixture(t, []string{"node-a"}, gateEverything(t, 2), store, func() time.Time { return apNow })
	p := Principal{AccountID: "acct-g", Account: "gleipnir-prod"}

	var ids []string
	for i := 0; i < 3; i++ {
		_, err := s.Run(context.Background(), p, Selector{}, mutateAct())
		var parked *ParkedError
		if !errors.As(err, &parked) {
			t.Fatalf("run %d: err = %v, want a park", i, err)
		}
		ids = append(ids, parked.RequestID)
	}
	for _, id := range ids[1:] {
		if id != ids[0] {
			t.Fatalf("request IDs differ across retries (%v); one Plan must have one pending request", ids)
		}
	}
	if len(store.byID) != 1 {
		t.Errorf("stored %d requests, want 1", len(store.byID))
	}
}

// TestFrozenRelayNeverEvenParks: Freeze is the outermost gate, so a frozen Relay
// refuses before the approval gate is consulted. A park during a Freeze would
// queue up work to run the moment the emergency stop is released, which is the
// opposite of what an emergency stop is for.
func TestFrozenRelayNeverEvenParks(t *testing.T) {
	store := newMemApprovals()
	reg := registry.NewInMemory()
	if _, err := reg.Upsert(registry.Report{NodeID: "node-a"}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	s := build(t, seams{reg: reg,
		authz: &spyAuthorizer{}, cap: &spyCapChecker{},
		audit: &spyAuditSink{}, freeze: &fakeFreezeStore{frozen: true},
		gate: gateEverything(t, 1), approvals: store, approvalAuthz: &spyApprovalAuthorizer{}, now: func() time.Time { return apNow },
	})

	_, err := s.Run(context.Background(), Principal{Account: "gleipnir-prod"}, Selector{}, mutateAct())
	var frozen *FrozenError
	if !errors.As(err, &frozen) {
		t.Fatalf("err = %v, want a FrozenError", err)
	}
	if len(store.byID) != 0 {
		t.Error("a frozen Relay must not park work for later — the Freeze is a stop, not a queue")
	}
}

// --- the shape key on the parked record (#415) ----------------------------

// shapeFixture is approvalFixture with the registry handed back, so a test can
// grow the fleet BETWEEN dispatches — which is the whole point of test
// TestSameShapeDifferentPlanStillParks.
func shapeFixture(t *testing.T, labelled map[string]map[string]string, gate ApprovalGate, store ApprovalStore) (*testSvc, *spyDispatcher, registry.Repository) {
	t.Helper()
	reg := registry.NewInMemory()
	for id, labels := range labelled {
		if _, err := reg.Upsert(registry.Report{NodeID: id}.WithNodeLabels(labels)); err != nil {
			t.Fatalf("seed registry: %v", err)
		}
	}
	disp := &spyDispatcher{jobID: "job-1"}
	s := build(t, seams{reg: reg,
		authz:  &spyAuthorizer{},
		cap:    &spyCapChecker{},
		audit:  &spyAuditSink{},
		freeze: &fakeFreezeStore{},
		gate:   gate, approvals: store, approvalAuthz: &spyApprovalAuthorizer{},
		now: func() time.Time { return apNow },
	})
	s.disp = disp
	return s, disp, reg
}

// TestPark_RecordsShapeKey: the parked Request carries a real computed key over
// the same Action and the same parsed Selector — not an empty one, not a legacy
// one.
func TestPark_RecordsShapeKey(t *testing.T) {
	store := newMemApprovals()
	s, _, _ := shapeFixture(t, map[string]map[string]string{
		"node-a": {"role": "web"},
	}, gateEverything(t, 1), store)

	sel, err := ParseSelector("node:role=web")
	if err != nil {
		t.Fatalf("ParseSelector: %v", err)
	}
	act := mutateAct()
	_, err = s.Run(context.Background(), Principal{AccountID: "acct-g", Account: "gleipnir-prod"}, sel, act)
	var parked *ParkedError
	if !errors.As(err, &parked) {
		t.Fatalf("Run: err = %v, want a park", err)
	}

	got := store.byID[parked.RequestID]
	shape, err := sel.Shape()
	if err != nil {
		t.Fatalf("Shape: %v", err)
	}
	want := approval.HashPlanShape(resolvedMutateAct(), shape)
	if got.ShapeKey != want {
		t.Errorf("stored ShapeKey = %q, want %q", got.ShapeKey, want)
	}
	if approval.IsLegacyShapeKey(got.ShapeKey) {
		t.Error("a freshly parked Request carries a legacy shape key")
	}
}

// TestSameShapeDifferentPlanStillParks IS THE GUARD THAT THE SHAPE KEY NEVER
// BECOMES A RELEASE LOOKUP.
//
// The same Action over the same Selector, after the registry grew, has the SAME
// shape key and a DIFFERENT plan hash. It must park again. Anything else is an
// approval-gate bypass: a human approved three Nodes and the fleet delivered
// four.
func TestSameShapeDifferentPlanStillParks(t *testing.T) {
	store := newMemApprovals()
	s, disp, reg := shapeFixture(t, map[string]map[string]string{
		"node-a": {"role": "web"},
	}, gateEverything(t, 1), store)

	sel, err := ParseSelector("node:role=web")
	if err != nil {
		t.Fatalf("ParseSelector: %v", err)
	}
	p := Principal{AccountID: "acct-g", Account: "gleipnir-prod"}

	_, err = s.Run(context.Background(), p, sel, mutateAct())
	var first *ParkedError
	if !errors.As(err, &first) {
		t.Fatalf("first Run: err = %v, want a park", err)
	}
	store.approve(t, first.RequestID, "acct-ana", "ana", apNow.Add(time.Minute))

	// The fleet grows underneath the approval.
	if _, err := reg.Upsert(registry.Report{NodeID: "node-b"}.WithNodeLabels(map[string]string{"role": "web"})); err != nil {
		t.Fatalf("grow registry: %v", err)
	}

	_, err = s.Run(context.Background(), p, sel, mutateAct())
	var second *ParkedError
	if !errors.As(err, &second) {
		t.Fatalf("second Run: err = %v, want a NEW park — the approved fan-out no longer describes this dispatch", err)
	}
	if disp.called {
		t.Fatal("the dispatcher ran: a wider Node set was released against an approval for a narrower one")
	}
	if second.RequestID == first.RequestID {
		t.Error("the second dispatch reused the first Request; the plan hash must not have matched")
	}

	approved := store.byID[first.RequestID]
	reparked := store.byID[second.RequestID]
	if approved.ShapeKey != reparked.ShapeKey {
		t.Fatalf("the two records do not share a shape key (%q vs %q), so this test proves nothing",
			approved.ShapeKey, reparked.ShapeKey)
	}
	if approved.PlanHash == reparked.PlanHash {
		t.Error("the plan hashes are equal; the fan-out stopped being bound")
	}
}

// TestLastApprovedOfSameShape is the anti-fatigue read: the newest APPROVED
// record of the same shape, never the record being rendered, and never a
// pending, denied or uncomparable one.
func TestLastApprovedOfSameShape(t *testing.T) {
	store := newMemApprovals()
	s, _, _ := shapeFixture(t, map[string]map[string]string{"node-a": {"role": "web"}}, gateEverything(t, 1), store)
	ctx := context.Background()

	shape := approval.HashPlanShape(resolvedMutateAct(), approval.SelectorShape{
		Known: true,
		Terms: []approval.SelectorTerm{{Namespace: "node", Key: "role", Value: "web"}},
	})
	other := approval.HashPlanShape(resolvedMutateAct(), approval.SelectorShape{Known: true})

	seed := func(id, shapeKey string, state approval.State, resolved time.Time) approval.Request {
		r := approval.Request{
			ID: id, PlanHash: "hash-" + id, ShapeKey: shapeKey, State: state,
			CreatedAt: apNow, ExpiresAt: apNow.Add(time.Hour), ResolvedAt: resolved,
		}
		store.byID[id] = r
		return r
	}

	oldest := seed("req-old", shape, approval.StateApproved, apNow.Add(-2*time.Hour))
	newest := seed("req-new", shape, approval.StateApproved, apNow.Add(-time.Hour))
	seed("req-pending", shape, approval.StatePending, time.Time{})
	seed("req-denied", shape, approval.StateDenied, apNow)
	seed("req-elsewhere", other, approval.StateApproved, apNow)
	rendering := seed("req-rendering", shape, approval.StateApproved, apNow.Add(time.Minute))

	got, err := s.LastApprovedOfSameShape(ctx, rendering)
	if err != nil {
		t.Fatalf("LastApprovedOfSameShape: %v", err)
	}
	if got.ID != newest.ID {
		t.Errorf("got %q, want the newest approved record of the same shape (%q)", got.ID, newest.ID)
	}

	// Rendering the oldest still excludes itself but finds the newer one.
	if got, err := s.LastApprovedOfSameShape(ctx, oldest); err != nil || got.ID == oldest.ID {
		t.Errorf("LastApprovedOfSameShape(%q) = %q, %v — a record must never find itself", oldest.ID, got.ID, err)
	}

	// A shape nobody else shares has no comparable prior.
	lonely := seed("req-lonely", approval.HashPlanShape(jobs.Action{
		Kind: jobs.ActionRawExec, RawExecArgv: []string{"uptime"}, RiskClass: jobs.RiskClassMutate,
	}, approval.SelectorShape{Known: true}), approval.StateApproved, apNow)
	if _, err := s.LastApprovedOfSameShape(ctx, lonely); !errors.Is(err, approval.ErrNotFound) {
		t.Errorf("err = %v, want approval.ErrNotFound unwrapped", err)
	}

	// Uncomparable keys are refused before the store is touched.
	for _, key := range []string{"", approval.LegacyShapeKey("req-legacy")} {
		r := approval.Request{ID: "req-x", ShapeKey: key, State: approval.StateApproved}
		if _, err := s.LastApprovedOfSameShape(ctx, r); !errors.Is(err, approval.ErrNotFound) {
			t.Errorf("shape key %q: err = %v, want approval.ErrNotFound", key, err)
		}
	}
}

// TestLastApprovedOfSameShape_Unwired: the read is unavailable rather
// than a nil-map panic on a Service built without approvals.
func TestLastApprovedOfSameShape_Unwired(t *testing.T) {
	s := build(t, seams{reg: registry.NewInMemory()})
	if _, err := s.LastApprovedOfSameShape(context.Background(), approval.Request{ShapeKey: "abc"}); !errors.Is(err, ErrApprovalUnavailable) {
		t.Errorf("err = %v, want ErrApprovalUnavailable", err)
	}
}

// --- AP-77: an approval releases one execution (#713) ----------------------

// approveViaRecordDecision drives id to StateApproved through the real
// approval.Repository interface, for the tests below that exercise a real
// SQLite store rather than memApprovals.
func approveViaRecordDecision(t *testing.T, repo approval.Repository, id, planHash string, at time.Time) {
	t.Helper()
	if _, err := repo.RecordDecision(context.Background(), id, approval.Decision{
		AccountID: "acct-ana", Account: "ana", Approve: true, Channel: approval.ChannelOutOfBand,
		PlanHash: planHash, DeciderHuman: true, At: at,
	}, at); err != nil {
		t.Fatalf("approve %s: %v", id, err)
	}
}

// TestRun_ReDriveOfAReleasedApprovalReAttachesAndDispatchesNothing is AP-77's
// core capability-layer proof: a sequential re-drive of an already-released
// approval re-attaches to the Job it released, dispatches nothing, and
// records an audited read rather than a second dispatch.
func TestRun_ReDriveOfAReleasedApprovalReAttachesAndDispatchesNothing(t *testing.T) {
	store := newMemApprovals()
	s, disp, audit := approvalFixtureWithAudit(t, []string{"node-a", "node-b"}, gateEverything(t, 1), store, func() time.Time { return apNow })
	p := Principal{AccountID: "acct-g", Account: "gleipnir-prod"}

	_, err := s.Run(context.Background(), p, Selector{}, mutateAct())
	var parked *ParkedError
	if !errors.As(err, &parked) {
		t.Fatalf("first Run: err = %v, want a park", err)
	}
	store.approve(t, parked.RequestID, "acct-ana", "ana", apNow.Add(time.Minute))

	if _, err := s.Run(context.Background(), p, Selector{}, mutateAct()); err != nil {
		t.Fatalf("release Run: %v", err)
	}
	if !disp.called {
		t.Fatal("dispatcher was not called on release")
	}

	// Reset the spy so the re-drive's behaviour is unambiguous.
	disp.called = false
	audit.entries = nil
	audit.readCalls = nil

	res, err := s.Run(context.Background(), p, Selector{}, mutateAct())
	if err != nil {
		t.Fatalf("re-drive Run: %v", err)
	}
	if disp.called {
		t.Error("dispatcher was called on a re-drive of an already-released approval (AP-77)")
	}
	if len(res) != 2 {
		t.Fatalf("results = %d, want 2 (one per approved Node)", len(res))
	}
	for _, r := range res {
		if r.JobID != "job-1" {
			t.Errorf("result %+v: JobID = %q, want job-1", r, r.JobID)
		}
	}

	var dispatchEntries int
	for _, e := range audit.entries {
		if e.Kind == AuditKindDispatch {
			dispatchEntries++
		}
	}
	if dispatchEntries != 0 {
		t.Errorf("dispatch audit entries after the re-drive = %d, want 0", dispatchEntries)
	}
	if len(audit.readCalls) != 1 || audit.readCalls[0].Tool != toolApprovalReattach {
		t.Fatalf("read calls = %+v, want exactly one approval_reattach read", audit.readCalls)
	}
	if audit.readCalls[0].JobID != "job-1" {
		t.Errorf("reattach read JobID = %q, want job-1", audit.readCalls[0].JobID)
	}
	if got := store.bound[parked.RequestID]; got != "job-1" {
		t.Errorf("store.bound = %q, want job-1 still", got)
	}
}

// TestRun_DifferentRequesterReAttachesToTheReleasedJob: AP-77's re-attach is
// requester-agnostic ("any later dispatch whose plan hash matches"). A
// different Account re-driving the same plan re-attaches, sees the Job as an
// audited read attributed to itself, and dispatches nothing — the original
// Request's requester is unchanged.
func TestRun_DifferentRequesterReAttachesToTheReleasedJob(t *testing.T) {
	store := newMemApprovals()
	s, disp, audit := approvalFixtureWithAudit(t, []string{"node-a"}, gateEverything(t, 1), store, func() time.Time { return apNow })
	accountA := Principal{AccountID: "acct-a", Account: "alice"}
	accountB := Principal{AccountID: "acct-b", Account: "bob"}

	_, err := s.Run(context.Background(), accountA, Selector{}, mutateAct())
	var parked *ParkedError
	if !errors.As(err, &parked) {
		t.Fatalf("first Run: err = %v, want a park", err)
	}
	store.approve(t, parked.RequestID, "acct-ana", "ana", apNow.Add(time.Minute))

	if _, err := s.Run(context.Background(), accountA, Selector{}, mutateAct()); err != nil {
		t.Fatalf("release Run: %v", err)
	}
	disp.called = false
	audit.readCalls = nil

	res, err := s.Run(context.Background(), accountB, Selector{}, mutateAct())
	if err != nil {
		t.Fatalf("account B Run: %v", err)
	}
	if disp.called {
		t.Error("dispatcher was called for a different Account's re-drive")
	}
	for _, r := range res {
		if r.JobID != "job-1" {
			t.Errorf("result JobID = %q, want job-1", r.JobID)
		}
	}
	if len(audit.readCalls) != 1 || audit.readCalls[0].Principal != accountB {
		t.Fatalf("read calls = %+v, want exactly 1 attributed to account B", audit.readCalls)
	}

	got, err := store.Get(context.Background(), parked.RequestID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.RequestedByID != "acct-a" {
		t.Errorf("RequestedByID = %q, want acct-a — the original requester is unchanged", got.RequestedByID)
	}
}

// failingReadAuditSink wraps spyAuditSink and, once armed, fails only
// RecordRead — so a test can let a park and a release audit normally and then
// make ONLY the reattach's read fail.
type failingReadAuditSink struct {
	*spyAuditSink
	readErr error
}

func (f *failingReadAuditSink) RecordRead(ctx context.Context, p Principal, tool, selector, nodeID, jobID string) error {
	if f.readErr != nil {
		return f.readErr
	}
	return f.spyAuditSink.RecordRead(ctx, p, tool, selector, nodeID, jobID)
}

// TestRun_ReAttachThatCannotBeAuditedReturnsNothing: an unaudited re-attach
// must not hand out a Job (ADR-0025), mirroring AP-67's precedent at the
// adapter layer.
func TestRun_ReAttachThatCannotBeAuditedReturnsNothing(t *testing.T) {
	store := newMemApprovals()
	reg := registry.NewInMemory()
	if _, err := reg.Upsert(registry.Report{NodeID: "node-a"}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	disp := &spyDispatcher{jobID: "job-1"}
	audit := &failingReadAuditSink{spyAuditSink: &spyAuditSink{}}
	s := build(t, seams{reg: reg,
		authz: &spyAuthorizer{}, cap: &spyCapChecker{},
		audit: audit, freeze: &fakeFreezeStore{},
		gate: gateEverything(t, 1), approvals: store, approvalAuthz: &spyApprovalAuthorizer{},
		now: func() time.Time { return apNow },
	})
	s.disp = disp
	p := Principal{AccountID: "acct-g", Account: "gleipnir-prod"}

	_, err := s.Run(context.Background(), p, Selector{}, mutateAct())
	var parked *ParkedError
	if !errors.As(err, &parked) {
		t.Fatalf("first Run: err = %v, want a park", err)
	}
	store.approve(t, parked.RequestID, "acct-ana", "ana", apNow.Add(time.Minute))

	if _, err := s.Run(context.Background(), p, Selector{}, mutateAct()); err != nil {
		t.Fatalf("release Run: %v", err)
	}
	disp.called = false
	audit.readErr = errors.New("audit store down")

	res, err := s.Run(context.Background(), p, Selector{}, mutateAct())
	if res != nil {
		t.Errorf("results = %v, want nil on an unauditable re-attach", res)
	}
	if !errors.Is(err, ErrReadUnaudited) {
		t.Fatalf("err = %v, want it to wrap ErrReadUnaudited", err)
	}
	if disp.called {
		t.Error("dispatcher was called on an unauditable re-attach")
	}
}

// TestRun_ReleasedApprovalPastItsDeadlineParksAfresh: AP-77's re-attach window
// is the approval's validity (Satisfied), not forever (AP-25, ADR-0027
// decision 9). Past the deadline, a re-drive parks a brand-new Request rather
// than re-attaching to the stale one.
func TestRun_ReleasedApprovalPastItsDeadlineParksAfresh(t *testing.T) {
	store := newMemApprovals()
	clock := apNow
	s, disp := approvalFixture(t, []string{"node-a"}, gateEverything(t, 1), store, func() time.Time { return clock })
	p := Principal{AccountID: "acct-g", Account: "gleipnir-prod"}

	_, err := s.Run(context.Background(), p, Selector{}, mutateAct())
	var first *ParkedError
	if !errors.As(err, &first) {
		t.Fatalf("first Run: err = %v, want a park", err)
	}
	store.approve(t, first.RequestID, "acct-ana", "ana", clock.Add(time.Minute))

	if _, err := s.Run(context.Background(), p, Selector{}, mutateAct()); err != nil {
		t.Fatalf("release Run: %v", err)
	}
	disp.called = false

	// Past gateEverything's one-hour TTL.
	clock = clock.Add(2 * time.Hour)

	_, err = s.Run(context.Background(), p, Selector{}, mutateAct())
	var second *ParkedError
	if !errors.As(err, &second) {
		t.Fatalf("err = %v, want a fresh park after the deadline", err)
	}
	if second.RequestID == first.RequestID {
		t.Error("a released approval past its deadline must park a NEW Request, not re-attach forever")
	}
	if disp.called {
		t.Error("dispatcher was called; a park must never dispatch")
	}
}

// TestRun_ClaimedReleaseThatFailsToDispatchStaysSpent: there is no un-bind
// path (Key decisions). A claim that wins and then fails before a real Job is
// created leaves the approval spent; a re-drive re-attaches to the reserved
// id rather than claiming and dispatching again.
func TestRun_ClaimedReleaseThatFailsToDispatchStaysSpent(t *testing.T) {
	store := newMemApprovals()
	s, disp := approvalFixture(t, []string{"node-a"}, gateEverything(t, 1), store, func() time.Time { return apNow })
	p := Principal{AccountID: "acct-g", Account: "gleipnir-prod"}

	_, err := s.Run(context.Background(), p, Selector{}, mutateAct())
	var parked *ParkedError
	if !errors.As(err, &parked) {
		t.Fatalf("first Run: err = %v, want a park", err)
	}
	store.approve(t, parked.RequestID, "acct-ana", "ana", apNow.Add(time.Minute))

	disp.failWithNoJobID = true
	disp.err = errors.New("dispatch exploded before CreateJob returned")

	_, err = s.Run(context.Background(), p, Selector{}, mutateAct())
	if err == nil {
		t.Fatal("Run: want an error from the failing dispatcher")
	}
	if disp.ranWithJobID == "" {
		t.Fatal("dispatcher never ran — the claim did not even attempt a dispatch")
	}
	claimedID := disp.ranWithJobID

	// A second Run re-attaches to the reserved id rather than claiming (and
	// dispatching) again — the approval stays spent even though no real Job
	// was ever created for it.
	disp.called = false
	disp.err = nil
	res, err := s.Run(context.Background(), p, Selector{}, mutateAct())
	if err != nil {
		t.Fatalf("second Run: %v", err)
	}
	if disp.called {
		t.Error("dispatcher ran a second time — a claimed release must stay spent even after a failed dispatch")
	}
	for _, r := range res {
		if r.JobID != claimedID {
			t.Errorf("result JobID = %q, want the originally reserved %q", r.JobID, claimedID)
		}
	}
}

// TestRun_ReserveJobIDFailureRefusesWithoutDispatching: when the dispatcher
// cannot even mint a reservation, the claim never starts, nothing runs, and
// the refusal is audited exactly like any other internal refusal.
func TestRun_ReserveJobIDFailureRefusesWithoutDispatching(t *testing.T) {
	store := newMemApprovals()
	s, disp := approvalFixture(t, []string{"node-a"}, gateEverything(t, 1), store, func() time.Time { return apNow })
	p := Principal{AccountID: "acct-g", Account: "gleipnir-prod"}

	_, err := s.Run(context.Background(), p, Selector{}, mutateAct())
	var parked *ParkedError
	if !errors.As(err, &parked) {
		t.Fatalf("first Run: err = %v, want a park", err)
	}
	store.approve(t, parked.RequestID, "acct-ana", "ana", apNow.Add(time.Minute))

	disp.reserveErr = errors.New("dispatcher out of ids")
	_, err = s.Run(context.Background(), p, Selector{}, mutateAct())
	if err == nil {
		t.Fatal("Run: want an error when reserveJobID fails")
	}
	if disp.called {
		t.Error("dispatcher's run was called even though reserveJobID failed")
	}
	if got, getErr := store.Get(context.Background(), parked.RequestID); getErr != nil || got.JobID != "" {
		t.Errorf("Get = %+v, %v — nothing must be bound when the reservation itself failed", got, getErr)
	}
}

// errByPlanHashApprovalStore wraps an ApprovalStore and always fails
// ByPlanHash with err, mirroring a store outage for exactly the read
// checkApproval uses to find an already-released Request for this plan
// (SEC-2/C2-S1, #713 security review).
type errByPlanHashApprovalStore struct {
	ApprovalStore
	err error
}

func (w errByPlanHashApprovalStore) ByPlanHash(context.Context, string) (approval.Request, error) {
	return approval.Request{}, w.err
}

// TestRun_StoreErrorReadingForAPlanIsRefused: a store failure reading whether
// THIS plan already has a released Request fails the dispatch closed.
// A Request the Relay cannot currently read, possibly already released, must
// never be treated as absent and run a second time.
func TestRun_StoreErrorReadingForAPlanIsRefused(t *testing.T) {
	failing := errByPlanHashApprovalStore{ApprovalStore: newMemApprovals(), err: errors.New("approvals store unavailable")}
	reg := registry.NewInMemory()
	for _, id := range []string{"node-a", "node-b"} {
		if _, err := reg.Upsert(registry.Report{NodeID: id}); err != nil {
			t.Fatalf("seed registry: %v", err)
		}
	}
	disp := &spyDispatcher{jobID: "job-1"}
	audit := &spyAuditSink{}
	s := build(t, seams{reg: reg,
		authz: &spyAuthorizer{}, cap: &spyCapChecker{},
		audit: audit, freeze: &fakeFreezeStore{},
		gate: gateEverything(t, 1), approvals: failing, approvalAuthz: &spyApprovalAuthorizer{},
		now: func() time.Time { return apNow },
	})
	s.disp = disp

	_, err := s.Run(context.Background(), machineRequester, Selector{}, mutateAct())
	if err == nil {
		t.Fatal("Run: want a refusal when the plan-hash read fails")
	}
	if disp.called {
		t.Error("dispatcher ran despite a store failure reading for this plan")
	}
	if !hasAuditKind(audit.entries, AuditKindRefusal) {
		t.Error("want a refusal audited")
	}
}

// cancelMidRunDispatcher simulates a client per-call timeout firing while the
// dispatcher is running: it cancels the caller's own context and returns
// ctx.Err(), carrying the jobID it was asked to run with (mirroring
// jobEngine's real CreateJob-then-persist-then-send shape, where the Job
// already exists by the time dispatch can fail).
type cancelMidRunDispatcher struct {
	cancelFn  context.CancelFunc
	runs      int32 // atomic
	lastJobID atomic.Value
}

func (d *cancelMidRunDispatcher) run(ctx context.Context, disp dispatch) (dispatchResult, error) {
	atomic.AddInt32(&d.runs, 1)
	d.lastJobID.Store(disp.jobID)
	d.cancelFn()
	return dispatchResult{jobID: disp.jobID}, ctx.Err()
}

func (d *cancelMidRunDispatcher) cancel(context.Context, string) error { return nil }
func (d *cancelMidRunDispatcher) query(context.Context, dispatch) (planResult, error) {
	return planResult{}, nil
}
func (d *cancelMidRunDispatcher) reserveJobID() (string, error) { return "job-reserved", nil }

// TestRun_ReleasedJobStaysBoundWhenTheCallIsCancelledMidDispatch is AP-77's
// central claim-before-dispatch proof (#713, the "ordinary trigger" the owner
// named): a client-side timeout firing after the claim commits but while the
// dispatcher is still running must not leave the approval unbound. Real
// SQLite, because the claim's atomicity is the store's contract, not
// memApprovals' mirror of it.
func TestRun_ReleasedJobStaysBoundWhenTheCallIsCancelledMidDispatch(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "relay.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	repo := st.Approvals()

	reg := registry.NewInMemory()
	if _, err := reg.Upsert(registry.Report{NodeID: "node-a"}); err != nil {
		t.Fatalf("seed: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	disp := &cancelMidRunDispatcher{cancelFn: cancel}
	s := build(t, seams{reg: reg,
		authz: &spyAuthorizer{}, cap: &spyCapChecker{},
		audit: &spyAuditSink{}, freeze: &fakeFreezeStore{},
		gate: gateEverything(t, 1), approvals: repo, approvalAuthz: &spyApprovalAuthorizer{},
		now: func() time.Time { return apNow },
	})
	s.disp = disp
	p := Principal{AccountID: "acct-g", Account: "gleipnir-prod"}

	_, err = s.Run(ctx, p, Selector{}, mutateAct())
	var parked *ParkedError
	if !errors.As(err, &parked) {
		t.Fatalf("first Run: err = %v, want a park", err)
	}
	approveViaRecordDecision(t, repo, parked.RequestID, parked.PlanHash, apNow.Add(time.Minute))

	// The second Run's context is the one the dispatcher cancels mid-dispatch.
	_, err = s.Run(ctx, p, Selector{}, mutateAct())
	if err == nil {
		t.Fatal("Run with a mid-dispatch cancellation: want an error")
	}
	if got := atomic.LoadInt32(&disp.runs); got != 1 {
		t.Fatalf("dispatcher runs = %d, want 1", got)
	}

	got, err := repo.Get(context.Background(), parked.RequestID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.JobID == "" {
		t.Fatal("Request has no bound Job — the claim was lost to the cancelled request ctx")
	}
	if lastJobID, _ := disp.lastJobID.Load().(string); got.JobID != lastJobID {
		t.Errorf("bound JobID = %q, want the reserved id %q the dispatcher actually ran with", got.JobID, lastJobID)
	}

	// A fresh, LIVE context re-drives and re-attaches rather than dispatching
	// again.
	res, err := s.Run(context.Background(), p, Selector{}, mutateAct())
	if err != nil {
		t.Fatalf("third Run (re-attach): %v", err)
	}
	if got2 := atomic.LoadInt32(&disp.runs); got2 != 1 {
		t.Errorf("dispatcher runs after re-attach = %d, want still 1", got2)
	}
	for _, r := range res {
		if r.JobID != got.JobID {
			t.Errorf("result JobID = %q, want %q", r.JobID, got.JobID)
		}
	}
}

// claimCancelingApprovalStore wraps a real ApprovalStore and cancels the
// caller's own context exactly when the release claim starts — modeling a
// client per-call timeout that fires in the narrow window between the
// plan-hash read (ByPlanHash, left untouched) and the transactional claim
// (BindJob) itself (#713 plan-review cycle-2 B1). Every other method is
// promoted straight through the embedded interface.
type claimCancelingApprovalStore struct {
	ApprovalStore
	cancel context.CancelFunc
}

func (w *claimCancelingApprovalStore) BindJob(ctx context.Context, id, jobID string, now time.Time) (approval.Request, error) {
	w.cancel()
	return w.ApprovalStore.BindJob(ctx, id, jobID, now)
}

// TestRun_CallCancelledBeforeTheClaimDispatchesNothingAndLeavesTheApprovalReleasable
// is #713 plan-review S3, retargeted in cycle 2 (B1): a ctx cancelled BEFORE
// Run even starts fails at checkApproval's own ByPlanHash read and never
// reaches BindJob at all, which proved nothing about the claim itself. Here
// the ctx stays live through ByPlanHash — so checkApproval finds the Request
// Satisfied and unbound, exactly the claim path — and is cancelled only when
// the release claim (BindJob) starts, using the real SQLite store so the
// failure is a genuine transaction failure, not a fake's shortcut. The claim
// must fail outright, never touch the dispatcher, and leave the approval
// releasable for the very next (live) re-drive.
func TestRun_CallCancelledBeforeTheClaimDispatchesNothingAndLeavesTheApprovalReleasable(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "relay.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	repo := st.Approvals()

	reg := registry.NewInMemory()
	if _, err := reg.Upsert(registry.Report{NodeID: "node-a"}); err != nil {
		t.Fatalf("seed: %v", err)
	}

	disp := &spyDispatcher{jobID: "job-1"}
	audit := &spyAuditSink{}
	cancelCtx, cancel := context.WithCancel(context.Background())
	wrapped := &claimCancelingApprovalStore{ApprovalStore: repo, cancel: cancel}
	s := build(t, seams{reg: reg,
		authz: &spyAuthorizer{}, cap: &spyCapChecker{},
		audit: audit, freeze: &fakeFreezeStore{},
		gate: gateEverything(t, 1), approvals: wrapped, approvalAuthz: &spyApprovalAuthorizer{},
		now: func() time.Time { return apNow },
	})
	s.disp = disp
	p := Principal{AccountID: "acct-g", Account: "gleipnir-prod"}

	_, err = s.Run(context.Background(), p, Selector{}, mutateAct())
	var parked *ParkedError
	if !errors.As(err, &parked) {
		t.Fatalf("first Run: err = %v, want a park", err)
	}
	approveViaRecordDecision(t, repo, parked.RequestID, parked.PlanHash, apNow.Add(time.Minute))

	_, err = s.Run(cancelCtx, p, Selector{}, mutateAct())
	if err == nil {
		t.Fatal("Run whose ctx is cancelled inside the claim: want an error")
	}
	if disp.called {
		t.Error("dispatcher was called even though the claim's transaction should never have committed")
	}
	if !hasAuditKind(audit.entries, AuditKindRefusal) {
		t.Error("want a RefusalInternal refusal audited when the claim's ctx is cancelled")
	}

	got, err := repo.Get(context.Background(), parked.RequestID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.JobID != "" {
		t.Fatalf("JobID = %q, want unbound — a cancelled claim must not spend the approval", got.JobID)
	}

	res, err := s.Run(context.Background(), p, Selector{}, mutateAct())
	if err != nil {
		t.Fatalf("live Run: %v", err)
	}
	if !disp.called {
		t.Fatal("dispatcher was never called on the live re-drive")
	}
	for _, r := range res {
		if r.JobID != "job-1" {
			t.Errorf("result JobID = %q, want job-1", r.JobID)
		}
	}
}

// laterNowOnBindJobApprovalStore wraps an ApprovalStore and substitutes now
// for whatever "now" Service.Run's claim actually passed to BindJob — C2-S4's
// simplification (#713 cycle-2 code review) of modeling "the deadline passed
// between checkApproval's read and the claim" without coupling a test to how
// many times Service happens to read its clock per Run. Every other method
// (including ByPlanHash, which stays reading the UNCHANGED clock so
// checkApproval still finds the Request Satisfied and commits to the claim
// path) is promoted straight through the embedded interface.
type laterNowOnBindJobApprovalStore struct {
	ApprovalStore
	now time.Time
}

func (w laterNowOnBindJobApprovalStore) BindJob(ctx context.Context, id, jobID string, _ time.Time) (approval.Request, error) {
	return w.ApprovalStore.BindJob(ctx, id, jobID, w.now)
}

// TestRun_ClaimThatFindsTheDeadlinePassedDispatchesNothing is #713
// plan-review cycle-2 B1's other fail-closed branch: checkApproval's own read
// finds the Request Satisfied (so it commits to the claim path, not a fresh
// park), but by the time BindJob evaluates the release the clock has ticked
// past ExpiresAt — a store-call boundary wide enough for a deadline to lapse
// in between. The domain refuses with ErrNotReleasable, and the claim must
// fail closed exactly like the cancelled-ctx case above: nothing dispatched,
// nothing bound, and the refusal audited. Unlike a genuinely expired approval
// (TestRun_ReleasedApprovalPastItsDeadlineParksAfresh), only the CLAIM's own
// evaluation overshoots the deadline — every other read, including the third
// Run's, still sees apNow, so the very next Run finds the same Request still
// Satisfied and releases it normally.
func TestRun_ClaimThatFindsTheDeadlinePassedDispatchesNothing(t *testing.T) {
	store := newMemApprovals()
	s, disp, audit := approvalFixtureWithAudit(t, []string{"node-a"}, gateEverything(t, 1), store, func() time.Time { return apNow })
	p := Principal{AccountID: "acct-g", Account: "gleipnir-prod"}

	_, err := s.Run(context.Background(), p, Selector{}, mutateAct())
	var parked *ParkedError
	if !errors.As(err, &parked) {
		t.Fatalf("first Run: err = %v, want a park", err)
	}
	store.approve(t, parked.RequestID, "acct-ana", "ana", apNow.Add(time.Minute))

	s.store = laterNowOnBindJobApprovalStore{ApprovalStore: store, now: apNow.Add(2 * time.Hour)}

	_, err = s.Run(context.Background(), p, Selector{}, mutateAct())
	if !errors.Is(err, approval.ErrNotReleasable) {
		t.Fatalf("err = %v, want it to wrap ErrNotReleasable", err)
	}
	if disp.called {
		t.Error("dispatcher was called even though the claim found the deadline had passed")
	}
	if !hasAuditKind(audit.entries, AuditKindRefusal) {
		t.Error("want a RefusalInternal refusal audited when the claim finds the deadline passed")
	}

	got, err := store.Get(context.Background(), parked.RequestID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.JobID != "" {
		t.Fatalf("JobID = %q, want unbound — a claim that finds the deadline passed must not spend the approval", got.JobID)
	}

	// Restore the plain store — the deadline-overshoot was only ever the
	// PREVIOUS Run's claim, not a lasting change to what "now" means.
	s.store = store
	res, err := s.Run(context.Background(), p, Selector{}, mutateAct())
	if err != nil {
		t.Fatalf("live Run: %v", err)
	}
	if !disp.called {
		t.Fatal("dispatcher was never called on the live re-drive")
	}
	for _, r := range res {
		if r.JobID != "job-1" {
			t.Errorf("result JobID = %q, want job-1", r.JobID)
		}
	}
}

// alwaysAlreadyReleasedNoJobIDApprovalStore forces BindJob to report
// ErrAlreadyReleased with no bound JobID — the store's own `n == 0` backstop
// (store/approvals.go), which BindJob's own belt-and-braces re-read makes
// unreachable there, but Service.Run's own guard against it must still be
// exercised directly (C2-S3, #713 code review): a loser must never re-attach
// to an empty Job ID.
type alwaysAlreadyReleasedNoJobIDApprovalStore struct {
	ApprovalStore
}

func (alwaysAlreadyReleasedNoJobIDApprovalStore) BindJob(context.Context, string, string, time.Time) (approval.Request, error) {
	return approval.Request{}, approval.ErrAlreadyReleased
}

// TestRun_ClaimAlreadyReleasedWithNoJobIDIsRefusedRatherThanReattachingToNothing
// is C2-S3: Run's claim switch has a case for ErrAlreadyReleased that
// reattaches to claimed.JobID, and a guard is needed for the case where that
// JobID is empty — nothing to reattach to. Exercised here directly, since the
// store itself can never produce it under SetMaxOpenConns(1).
func TestRun_ClaimAlreadyReleasedWithNoJobIDIsRefusedRatherThanReattachingToNothing(t *testing.T) {
	store := newMemApprovals()
	s, disp, audit := approvalFixtureWithAudit(t, []string{"node-a"}, gateEverything(t, 1), store, func() time.Time { return apNow })
	p := Principal{AccountID: "acct-g", Account: "gleipnir-prod"}

	_, err := s.Run(context.Background(), p, Selector{}, mutateAct())
	var parked *ParkedError
	if !errors.As(err, &parked) {
		t.Fatalf("first Run: err = %v, want a park", err)
	}
	store.approve(t, parked.RequestID, "acct-ana", "ana", apNow.Add(time.Minute))

	s.store = alwaysAlreadyReleasedNoJobIDApprovalStore{ApprovalStore: store}

	_, err = s.Run(context.Background(), p, Selector{}, mutateAct())
	if err == nil {
		t.Fatal("Run: want a refusal when the claim reports ErrAlreadyReleased with no JobID to reattach to")
	}
	if disp.called {
		t.Error("dispatcher ran despite an unreattachable claim result")
	}
	if !hasAuditKind(audit.entries, AuditKindRefusal) {
		t.Error("want a refusal audited")
	}
}

// reserveCountingDispatcher mints a unique reserved Job ID per call (an
// atomic counter, mirroring jobEngine.reserveJobID's uniqueness) and counts
// how many times run actually executes, sleeping briefly to widen the
// concurrent window.
type reserveCountingDispatcher struct {
	reserveCounter int64 // atomic
	runCount       int32 // atomic
}

func (d *reserveCountingDispatcher) reserveJobID() (string, error) {
	n := atomic.AddInt64(&d.reserveCounter, 1)
	return "job-r" + strconv.FormatInt(n, 10), nil
}

func (d *reserveCountingDispatcher) run(_ context.Context, disp dispatch) (dispatchResult, error) {
	atomic.AddInt32(&d.runCount, 1)
	time.Sleep(20 * time.Millisecond)
	results := make([]NodeResult, 0, len(disp.nodes))
	for _, n := range disp.nodes {
		results = append(results, NodeResult{NodeID: n.NodeID, JobID: disp.jobID})
	}
	return dispatchResult{jobID: disp.jobID, results: results}, nil
}

func (d *reserveCountingDispatcher) cancel(context.Context, string) error { return nil }
func (d *reserveCountingDispatcher) query(context.Context, dispatch) (planResult, error) {
	return planResult{}, nil
}

// TestRun_ConcurrentReDrivesDispatchExactlyOneJob is AP-77's headline
// concurrency proof (#713 plan review S3/Codex HIGH on PR #741): many
// goroutines racing to run the SAME approved plan at once must produce
// exactly one dispatch, and every goroutine — winner and losers alike — must
// come back with the same JobID and no error. Real SQLite, because the
// concurrency argument is SetMaxOpenConns(1) plus BindJob's transaction, not
// anything memApprovals' mutex can stand in for. Run with -race.
func TestRun_ConcurrentReDrivesDispatchExactlyOneJob(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "relay.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	repo := st.Approvals()

	reg := registry.NewInMemory()
	if _, err := reg.Upsert(registry.Report{NodeID: "node-a"}); err != nil {
		t.Fatalf("seed: %v", err)
	}

	disp := &reserveCountingDispatcher{}
	s := build(t, seams{reg: reg,
		authz: &spyAuthorizer{}, cap: &spyCapChecker{},
		audit: &spyAuditSink{}, freeze: &fakeFreezeStore{},
		gate: gateEverything(t, 1), approvals: repo, approvalAuthz: &spyApprovalAuthorizer{},
		now: func() time.Time { return apNow },
	})
	s.disp = disp
	p := Principal{AccountID: "acct-g", Account: "gleipnir-prod"}

	_, err = s.Run(context.Background(), p, Selector{}, mutateAct())
	var parked *ParkedError
	if !errors.As(err, &parked) {
		t.Fatalf("first Run: err = %v, want a park", err)
	}
	approveViaRecordDecision(t, repo, parked.RequestID, parked.PlanHash, apNow.Add(time.Minute))

	const n = 16
	start := make(chan struct{})
	var wg sync.WaitGroup
	results := make([][]NodeResult, n)
	errs := make([]error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			res, runErr := s.Run(context.Background(), p, Selector{}, mutateAct())
			results[i] = res
			errs[i] = runErr
		}(i)
	}
	close(start)
	wg.Wait()

	if got := atomic.LoadInt32(&disp.runCount); got != 1 {
		t.Fatalf("dispatcher run count = %d, want exactly 1", got)
	}

	stored, err := repo.Get(context.Background(), parked.RequestID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if stored.JobID == "" {
		t.Fatal("the released approval never bound a Job")
	}

	for i, runErr := range errs {
		if runErr != nil {
			t.Errorf("goroutine %d: err = %v, want nil — a loser must re-attach, not fail", i, runErr)
		}
		for _, r := range results[i] {
			if r.JobID != stored.JobID {
				t.Errorf("goroutine %d: result JobID = %q, want %q", i, r.JobID, stored.JobID)
			}
		}
	}
}

// Proves AP-84.
//
// TestApprovals_NoDispatchConsultsAGrant: the capability layer carries no
// approval-grant surface at all. Approvals has no grant method or field, the
// dispatch decision has no grant link, and an audit entry has no GrantID to set,
// so no dispatch can claim or record a grant.
func TestApprovals_NoDispatchConsultsAGrant(t *testing.T) {
	at := reflect.TypeOf(&Approvals{})
	for i := 0; i < at.NumMethod(); i++ {
		if name := at.Method(i).Name; strings.Contains(name, "Grant") {
			t.Errorf("Approvals has method %s; approval grants are removed", name)
		}
	}
	for _, c := range []struct {
		typ   reflect.Type
		field string
	}{
		{reflect.TypeOf(Approvals{}), "grants"},
		{reflect.TypeOf(approvalDecision{}), "grantID"},
		{reflect.TypeOf(AuditEntry{}), "GrantID"},
		{reflect.TypeOf(dispatch{}), "grantID"},
	} {
		if _, ok := c.typ.FieldByName(c.field); ok {
			t.Errorf("%s has field %s; approval grants are removed", c.typ.Name(), c.field)
		}
	}
}

// Proves AP-84.
//
// TestRun_EveryGatedDispatchParksOnItsOwn: approving one dispatch releases that
// dispatch only. A different dispatch by the same Account, of the same risk and
// fan-out, parks as its own Request and runs nothing.
func TestRun_EveryGatedDispatchParksOnItsOwn(t *testing.T) {
	store := newMemApprovals()
	s, disp := approvalFixture(t, []string{"node-a"}, gateEverything(t, 1), store, func() time.Time { return apNow })
	p := Principal{AccountID: "acct-g", Account: "gleipnir-prod"}

	var parkedA *ParkedError
	if _, err := s.Run(context.Background(), p, Selector{}, mutateAct()); !errors.As(err, &parkedA) {
		t.Fatalf("plan A: err = %v, want a park", err)
	}
	store.approve(t, parkedA.RequestID, "acct-ana", "ana", apNow.Add(time.Minute))

	if _, err := s.Run(context.Background(), p, Selector{}, mutateAct()); err != nil {
		t.Fatalf("approved plan A: %v", err)
	}
	if !disp.called {
		t.Fatal("the approved plan did not dispatch")
	}

	disp.called = false
	other := mutateAct()
	other.OperationArgs = map[string]string{"service": "redis"}
	var parkedB *ParkedError
	if _, err := s.Run(context.Background(), p, Selector{}, other); !errors.As(err, &parkedB) {
		t.Fatalf("plan B: err = %v, want its own park", err)
	}
	if parkedB.RequestID == parkedA.RequestID {
		t.Error("plan B parked under plan A's Request; the approval of A covers nothing else")
	}
	if disp.called {
		t.Error("plan B dispatched on plan A's approval")
	}
}
