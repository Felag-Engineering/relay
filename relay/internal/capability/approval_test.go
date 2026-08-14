package capability

import (
	"context"
	"errors"
	"sort"
	"testing"
	"time"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/approval"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/jobs"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/registry"
)

// memApprovals is an in-memory ApprovalStore for these tests. It is deliberately
// simple: the store's own behaviour is tested in internal/store, and what
// matters here is the capability layer's decision-making.
type memApprovals struct {
	byID   map[string]approval.Request
	byHash map[string]string // planHash -> id
	bound  map[string]string // id -> jobID
}

func newMemApprovals() *memApprovals {
	return &memApprovals{byID: map[string]approval.Request{}, byHash: map[string]string{}, bound: map[string]string{}}
}

func (m *memApprovals) Create(_ context.Context, r approval.Request) error {
	m.byID[r.ID] = r
	m.byHash[r.PlanHash] = r.ID
	return nil
}

func (m *memApprovals) ByPlanHash(_ context.Context, planHash string) (approval.Request, error) {
	id, ok := m.byHash[planHash]
	if !ok {
		return approval.Request{}, approval.ErrNotFound
	}
	return m.byID[id], nil
}

func (m *memApprovals) BindJob(_ context.Context, id, jobID string) error {
	if _, ok := m.byID[id]; !ok {
		return approval.ErrNotFound
	}
	m.bound[id] = jobID
	return nil
}

func (m *memApprovals) Get(_ context.Context, id string) (approval.Request, error) {
	r, ok := m.byID[id]
	if !ok {
		return approval.Request{}, approval.ErrNotFound
	}
	return r, nil
}

func (m *memApprovals) Pending(_ context.Context) ([]approval.Request, error) {
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
	r, ok := m.byID[id]
	if !ok {
		return approval.Request{}, approval.ErrNotFound
	}
	updated, err := r.Decide(d, now)
	if err != nil {
		return approval.Request{}, err
	}
	m.byID[id] = updated
	return updated, nil
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

func approvalFixture(t *testing.T, nodes []string, gate ApprovalGate, store ApprovalStore, now func() time.Time) (*Service, *spyDispatcher) {
	t.Helper()
	reg := registry.NewInMemory()
	for _, id := range nodes {
		if _, err := reg.Upsert(registry.Report{NodeID: id}); err != nil {
			t.Fatalf("seed registry: %v", err)
		}
	}
	disp := &spyDispatcher{jobID: "job-1"}
	s := New(reg,
		WithAuthorizer(&spyAuthorizer{}),
		WithCapChecker(&spyCapChecker{}),
		WithAuditSink(&spyAuditSink{}),
		WithFreeze(&fakeFreezeStore{}),
		WithApprovals(gate, store, &spyApprovalAuthorizer{}),
		WithClock(now),
	)
	s.disp = disp
	return s, disp
}

var apNow = time.Date(2026, 8, 14, 9, 0, 0, 0, time.UTC)

func mutateAct() jobs.Action {
	return jobs.Action{
		Kind: jobs.ActionOperation, OperationName: "service.restart",
		OperationArgs: map[string]string{"service": "nginx"}, RiskClass: jobs.RiskClassMutate,
	}
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
	s := New(reg,
		WithAuthorizer(&spyAuthorizer{}), WithCapChecker(&spyCapChecker{}),
		WithAuditSink(&spyAuditSink{}), WithFreeze(&fakeFreezeStore{}),
		WithApprovals(gateEverything(t, 1), store, &spyApprovalAuthorizer{}), WithClock(func() time.Time { return apNow }),
	)
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
	s := New(reg,
		WithAuthorizer(&spyAuthorizer{}), WithCapChecker(&spyCapChecker{}),
		WithAuditSink(&spyAuditSink{}), WithFreeze(&fakeFreezeStore{frozen: true}),
		WithApprovals(gateEverything(t, 1), store, &spyApprovalAuthorizer{}), WithClock(func() time.Time { return apNow }),
	)

	_, err := s.Run(context.Background(), Principal{Account: "gleipnir-prod"}, Selector{}, mutateAct())
	var frozen *FrozenError
	if !errors.As(err, &frozen) {
		t.Fatalf("err = %v, want a FrozenError", err)
	}
	if len(store.byID) != 0 {
		t.Error("a frozen Relay must not park work for later — the Freeze is a stop, not a queue")
	}
}
