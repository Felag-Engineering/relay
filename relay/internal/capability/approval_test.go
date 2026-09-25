package capability

import (
	"context"
	"errors"
	"sort"
	"strings"
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
	r, ok := m.byID[id]
	if !ok {
		return approval.ErrNotFound
	}
	m.bound[id] = jobID
	// Mirrors SQLite, where job_id is a column on the row: a caller reading
	// the Request back (Get, or RecordDecision's refusal return) sees the
	// bound Job, not just this fake's separate bound map.
	r.JobID = jobID
	m.byID[id] = r
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
// before an Approval grant is claimed or a Request is created.
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

// namespaceVaryingAudienceGate is a fake ApprovalGate whose answer depends on
// which namespace it is asked about: the "node" namespace's Requirement
// carries a blank audience entry, every other namespace's is unrestricted (no
// audience named at all).
//
// It exists to drive approval.RequirementForScope's namespace probing
// (grant.go): RequirementForScope calls Evaluate once per known namespace and
// merges the results with mergeStricter, which unions the audiences
// (unionAudience). Before #608 cycle 2's fix, unionAudience's "either side is
// empty means unrestricted" shortcut fired on ANY empty side, so merging the
// "node" probe's malformed Requirement with a later unrestricted probe threw
// the blank entry away and the merged Requirement read back unrestricted —
// defeating RequestGrant's own ValidateAudience backstop, which only ever
// sees the MERGED result. A single-call fake like blankAudienceGate cannot
// exercise this: the hazard is specifically in the merge across several
// Evaluate calls, which only RequirementForScope (and Gate.Evaluate, for a
// real Gate merging several matching rules) ever does.
type namespaceVaryingAudienceGate struct{}

func (namespaceVaryingAudienceGate) Evaluate(d approval.Dispatch) (approval.Requirement, []string, bool) {
	if len(d.Namespaces) > 0 && d.Namespaces[0] == "node" {
		return approval.Requirement{Count: 1, Audience: []string{""}, Channel: approval.ChannelOutOfBand, TTL: time.Hour},
			[]string{"node-rule"}, true
	}
	return approval.Requirement{Count: 1, Channel: approval.ChannelOutOfBand, TTL: time.Hour}, []string{"catch-all"}, true
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

// --- the shape key on the parked record (#415) ----------------------------

// shapeFixture is approvalFixture with the registry handed back, so a test can
// grow the fleet BETWEEN dispatches — which is the whole point of test
// TestSameShapeDifferentPlanStillParks.
func shapeFixture(t *testing.T, labelled map[string]map[string]string, gate ApprovalGate, store ApprovalStore) (*Service, *spyDispatcher, registry.Repository) {
	t.Helper()
	reg := registry.NewInMemory()
	for id, labels := range labelled {
		if _, err := reg.Upsert(registry.Report{NodeID: id}.WithNodeLabels(labels)); err != nil {
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
		WithClock(func() time.Time { return apNow }),
	)
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
	want := approval.HashPlanShape(act, shape)
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

	shape := approval.HashPlanShape(mutateAct(), approval.SelectorShape{
		Known: true,
		Terms: []approval.SelectorTerm{{Namespace: "node", Key: "role", Value: "web"}},
	})
	other := approval.HashPlanShape(mutateAct(), approval.SelectorShape{Known: true})

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
	s := New(registry.NewInMemory())
	if _, err := s.LastApprovedOfSameShape(context.Background(), approval.Request{ShapeKey: "abc"}); !errors.Is(err, ErrApprovalUnavailable) {
		t.Errorf("err = %v, want ErrApprovalUnavailable", err)
	}
}
