package capability

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/approval"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/jobs"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/registry"
)

// approval_decide_test.go covers #270's half of the callout: answering a parked
// dispatch through the capability layer.

// decideFixture builds a Service whose gate parks everything, with the given
// approval authorizer, and returns it alongside the store and audit spy.
func decideFixture(t *testing.T, count int, authorizer ApprovalAuthorizer) (*Service, *memApprovals, *spyAuditSink) {
	t.Helper()
	reg := registry.NewInMemory()
	for _, id := range []string{"node-a", "node-b"} {
		if _, err := reg.Upsert(registry.Report{NodeID: id}); err != nil {
			t.Fatalf("seed registry: %v", err)
		}
	}
	store := newMemApprovals()
	audit := &spyAuditSink{}
	s := New(reg,
		WithAuthorizer(&spyAuthorizer{}),
		WithCapChecker(&spyCapChecker{}),
		WithAuditSink(audit),
		WithFreeze(&fakeFreezeStore{}),
		WithApprovals(gateEverything(t, count), store, authorizer),
		WithClock(func() time.Time { return apNow }),
	)
	s.disp = &spyDispatcher{jobID: "job-1"}
	return s, store, audit
}

// park drives one gated dispatch and returns the resulting ParkedError.
func park(t *testing.T, s *Service, p Principal) *ParkedError {
	t.Helper()
	_, err := s.Run(context.Background(), p, Selector{}, mutateAct())
	var parked *ParkedError
	if !errors.As(err, &parked) {
		t.Fatalf("Run: err = %v, want a park", err)
	}
	return parked
}

func humanApprover(id, name string) Principal {
	return Principal{AccountID: id, Account: name, Role: "operator", Kind: PrincipalKindHuman}
}

var machineRequester = Principal{AccountID: "acct-g", Account: "gleipnir-prod", Role: "admin", Kind: "machine"}

// TestDecideApprovalRecordsAndAudits is the happy path: a human answers, the
// request reaches approved, and the answer is its own audit record.
func TestDecideApprovalRecordsAndAudits(t *testing.T) {
	s, _, audit := decideFixture(t, 1, &spyApprovalAuthorizer{})
	parked := park(t, s, machineRequester)

	updated, err := s.DecideApproval(context.Background(), humanApprover("acct-ana", "ana"), ApprovalDecision{
		RequestID: parked.RequestID,
		PlanHash:  parked.PlanHash,
		Approve:   true,
		Reason:    "checked the change ticket",
		Channel:   approval.ChannelOutOfBand,
	})
	if err != nil {
		t.Fatalf("DecideApproval: %v", err)
	}
	if updated.State != approval.StateApproved {
		t.Fatalf("State = %v, want approved", updated.State)
	}
	if !updated.Satisfied(apNow) {
		t.Error("a completed quorum must satisfy the requirement")
	}

	var decided *AuditEntry
	for i := range audit.entries {
		if audit.entries[i].Kind == AuditKindApprovalDecided {
			decided = &audit.entries[i]
		}
	}
	if decided == nil {
		t.Fatal("no AuditKindApprovalDecided entry — every decision is a first-class audit record (ADR-0027)")
	}
	if decided.ApprovalID != parked.RequestID || decided.PlanHash != parked.PlanHash {
		t.Errorf("audit entry = %+v, want it to name the request and the plan it answered", decided)
	}
	if decided.Principal.Account != "ana" {
		t.Errorf("audit principal = %q, want the DECIDER, not the requester", decided.Principal.Account)
	}
	if decided.JobID != "" || len(decided.Results) != 0 {
		t.Error("a decision runs nothing; its audit entry must carry no JobID and no Results")
	}
}

// TestDecideApprovalDoesNotDispatch is the property the whole design leans on:
// answering releases a Plan, it does not execute one. If deciding dispatched,
// registry drift between the answer and the run would have nothing to re-check.
func TestDecideApprovalDoesNotDispatch(t *testing.T) {
	s, _, _ := decideFixture(t, 1, &spyApprovalAuthorizer{})
	parked := park(t, s, machineRequester)

	if _, err := s.DecideApproval(context.Background(), humanApprover("acct-ana", "ana"), ApprovalDecision{
		RequestID: parked.RequestID, PlanHash: parked.PlanHash, Approve: true,
		Channel: approval.ChannelOutOfBand,
	}); err != nil {
		t.Fatalf("DecideApproval: %v", err)
	}

	disp := s.disp.(*spyDispatcher)
	if disp.called {
		t.Fatal("deciding an approval dispatched; a decision must never execute anything")
	}
}

// TestDecisionRoleFloorIsTheRequestFloor: the authorizer is consulted with the
// kind of Action being RELEASED, not with anything the decider supplied. This is
// what stops an operator releasing an admin's Raw Exec.
func TestDecisionRoleFloorUsesTheParkedActionKind(t *testing.T) {
	authorizer := &spyApprovalAuthorizer{}
	s, _, _ := decideFixture(t, 1, authorizer)
	parked := park(t, s, machineRequester)

	if _, err := s.DecideApproval(context.Background(), humanApprover("acct-ana", "ana"), ApprovalDecision{
		RequestID: parked.RequestID, PlanHash: parked.PlanHash, Approve: true,
		Channel: approval.ChannelOutOfBand,
	}); err != nil {
		t.Fatalf("DecideApproval: %v", err)
	}
	if authorizer.kind != jobs.ActionOperation {
		t.Errorf("authorizer saw kind %v, want the parked Action's own kind", authorizer.kind)
	}
}

// TestDecisionRefusedByRoleFloorRecordsNothing: a refused decision must leave
// no decision behind, or a quorum could be advanced by someone who was denied.
func TestDecisionRefusedByRoleFloorRecordsNothing(t *testing.T) {
	denied := errors.New("authz: unauthorized")
	s, store, _ := decideFixture(t, 1, &spyApprovalAuthorizer{err: denied})
	parked := park(t, s, machineRequester)

	if _, err := s.DecideApproval(context.Background(), humanApprover("acct-viewer", "vi"), ApprovalDecision{
		RequestID: parked.RequestID, PlanHash: parked.PlanHash, Approve: true,
		Channel: approval.ChannelOutOfBand,
	}); !errors.Is(err, denied) {
		t.Fatalf("err = %v, want the authorizer's refusal", err)
	}

	stored := store.byID[parked.RequestID]
	if len(stored.Decisions) != 0 {
		t.Errorf("stored %d decisions after a refusal, want 0", len(stored.Decisions))
	}
	if stored.State != approval.StatePending {
		t.Errorf("State = %v, want it still pending", stored.State)
	}
}

// TestMachineCannotDecideItsOwnRequestThroughTheLayer is the acceptance
// criterion "a machine Account can never satisfy its own gate on any channel",
// exercised end to end through the capability layer under the most permissive
// rule the config language can express (requester_allowed: true, and the
// requester holding the admin role).
func TestMachineCannotDecideItsOwnRequestThroughTheLayer(t *testing.T) {
	s, store, _ := decideFixture(t, 1, &spyApprovalAuthorizer{})
	parked := park(t, s, machineRequester)

	_, err := s.DecideApproval(context.Background(), machineRequester, ApprovalDecision{
		RequestID: parked.RequestID, PlanHash: parked.PlanHash, Approve: true,
		Channel: approval.ChannelOutOfBand,
	})
	if !errors.Is(err, approval.ErrMachineSelfDecision) {
		t.Fatalf("err = %v, want ErrMachineSelfDecision", err)
	}
	if store.byID[parked.RequestID].State != approval.StatePending {
		t.Error("the request must still be pending after a machine tried to answer itself")
	}
}

// TestDecisionKindComesFromThePrincipalNotTheCaller: a surface cannot claim its
// caller is human. The flag the domain sees is projected from the authenticated
// Account, so an unset Kind is a machine.
func TestDecisionKindComesFromThePrincipal(t *testing.T) {
	s, store, _ := decideFixture(t, 1, &spyApprovalAuthorizer{})
	parked := park(t, s, machineRequester)

	if _, err := s.DecideApproval(context.Background(),
		Principal{AccountID: "acct-ana", Account: "ana", Role: "operator", Kind: PrincipalKindHuman},
		ApprovalDecision{RequestID: parked.RequestID, PlanHash: parked.PlanHash, Approve: true, Channel: approval.ChannelOutOfBand},
	); err != nil {
		t.Fatalf("DecideApproval: %v", err)
	}
	got := store.byID[parked.RequestID].Decisions
	if len(got) != 1 || !got[0].DeciderHuman {
		t.Fatalf("decisions = %+v, want one recorded as human", got)
	}
}

// TestDenialIsTerminalAndAudited: deny beats approve, mirroring Policy's
// deny-beats-allow, and the denial is recorded even though nothing ran.
func TestDenialIsTerminalAndAudited(t *testing.T) {
	s, _, audit := decideFixture(t, 2, &spyApprovalAuthorizer{})
	parked := park(t, s, machineRequester)

	updated, err := s.DecideApproval(context.Background(), humanApprover("acct-ana", "ana"), ApprovalDecision{
		RequestID: parked.RequestID, PlanHash: parked.PlanHash, Approve: false,
		Reason: "wrong window", Channel: approval.ChannelOutOfBand,
	})
	if err != nil {
		t.Fatalf("DecideApproval: %v", err)
	}
	if updated.State != approval.StateDenied {
		t.Fatalf("State = %v, want denied", updated.State)
	}

	// A second approver cannot override the refusal.
	if _, err := s.DecideApproval(context.Background(), humanApprover("acct-bo", "bo"), ApprovalDecision{
		RequestID: parked.RequestID, PlanHash: parked.PlanHash, Approve: true,
		Channel: approval.ChannelOutOfBand,
	}); !errors.Is(err, approval.ErrNotPending) {
		t.Fatalf("second decision after a denial: err = %v, want ErrNotPending", err)
	}

	var denials int
	for _, e := range audit.entries {
		if e.Kind == AuditKindApprovalDecided {
			denials++
		}
	}
	if denials != 1 {
		t.Errorf("audited %d decisions, want exactly the denial", denials)
	}
}

// TestPlanHashMismatchIsRefused: an answer cannot be replayed onto a different
// Plan, which is what closes park-something-innocuous-then-mutate-the-world.
func TestPlanHashMismatchIsRefused(t *testing.T) {
	s, _, _ := decideFixture(t, 1, &spyApprovalAuthorizer{})
	parked := park(t, s, machineRequester)

	if _, err := s.DecideApproval(context.Background(), humanApprover("acct-ana", "ana"), ApprovalDecision{
		RequestID: parked.RequestID, PlanHash: "some-other-plan", Approve: true,
		Channel: approval.ChannelOutOfBand,
	}); !errors.Is(err, approval.ErrPlanChanged) {
		t.Fatalf("err = %v, want ErrPlanChanged", err)
	}
}

// TestPendingApprovalsHidesExpired: the queue must never advertise something
// undecidable, even between sweeper runs. Expiry is a clock fact, not a
// sweeper's opinion.
func TestPendingApprovalsHidesExpired(t *testing.T) {
	s, _, _ := decideFixture(t, 1, &spyApprovalAuthorizer{})
	parked := park(t, s, machineRequester)

	live, err := s.PendingApprovals(context.Background())
	if err != nil {
		t.Fatalf("PendingApprovals: %v", err)
	}
	if len(live) != 1 {
		t.Fatalf("pending = %d, want 1", len(live))
	}

	// Move the clock past the deadline without running any sweeper.
	s.now = func() time.Time { return parked.ExpiresAt.Add(time.Second) }
	after, err := s.PendingApprovals(context.Background())
	if err != nil {
		t.Fatalf("PendingApprovals: %v", err)
	}
	if len(after) != 0 {
		t.Errorf("pending = %d after the deadline, want 0 even with no sweeper run", len(after))
	}
}

// TestApprovalReadsTerminalRequests: a decider told "too late" must still be
// able to find out what became of the request.
func TestApprovalReadsTerminalRequests(t *testing.T) {
	s, _, _ := decideFixture(t, 1, &spyApprovalAuthorizer{})
	parked := park(t, s, machineRequester)

	if _, err := s.DecideApproval(context.Background(), humanApprover("acct-ana", "ana"), ApprovalDecision{
		RequestID: parked.RequestID, PlanHash: parked.PlanHash, Approve: false,
		Channel: approval.ChannelOutOfBand,
	}); err != nil {
		t.Fatalf("DecideApproval: %v", err)
	}

	got, err := s.Approval(context.Background(), parked.RequestID)
	if err != nil {
		t.Fatalf("Approval: %v", err)
	}
	if got.State != approval.StateDenied {
		t.Errorf("State = %v, want the terminal state to still be readable", got.State)
	}
}

func TestApprovalUnknownIDIsNotFound(t *testing.T) {
	s, _, _ := decideFixture(t, 1, &spyApprovalAuthorizer{})
	if _, err := s.Approval(context.Background(), "req-nope"); !errors.Is(err, approval.ErrNotFound) {
		t.Fatalf("err = %v, want approval.ErrNotFound unwrapped so a surface can map it to a 404", err)
	}
}

// TestNotifierFiresOncePerPark: an approval mechanism that pages on every retry
// is one operators mute, so a re-drive of an already-parked Plan must not
// re-notify.
func TestNotifierFiresOncePerPark(t *testing.T) {
	reg := registry.NewInMemory()
	if _, err := reg.Upsert(registry.Report{NodeID: "node-a"}); err != nil {
		t.Fatalf("seed registry: %v", err)
	}
	spy := &spyNotifier{}
	s := New(reg,
		WithAuthorizer(&spyAuthorizer{}),
		WithCapChecker(&spyCapChecker{}),
		WithAuditSink(&spyAuditSink{}),
		WithFreeze(&fakeFreezeStore{}),
		WithApprovals(gateEverything(t, 1), newMemApprovals(), &spyApprovalAuthorizer{}),
		WithApprovalNotifier(spy),
		WithClock(func() time.Time { return apNow }),
	)
	s.disp = &spyDispatcher{jobID: "job-1"}

	park(t, s, machineRequester)
	park(t, s, machineRequester)

	if len(spy.notices) != 1 {
		t.Fatalf("notified %d times for one parked Plan, want exactly 1", len(spy.notices))
	}
	n := spy.notices[0]
	if n.RequestID == "" || n.PlanHash == "" || n.Summary == "" {
		t.Errorf("notice = %+v, want it to carry what an approver needs to act", n)
	}
	if n.RequestedBy != machineRequester.Account {
		t.Errorf("RequestedBy = %q, want the verified requester", n.RequestedBy)
	}
}

// TestNotifierIsNotConsultedWhenNothingParks.
func TestNotifierSilentWhenNothingParks(t *testing.T) {
	reg := registry.NewInMemory()
	if _, err := reg.Upsert(registry.Report{NodeID: "node-a"}); err != nil {
		t.Fatalf("seed registry: %v", err)
	}
	empty, err := approval.NewGate(nil)
	if err != nil {
		t.Fatalf("NewGate: %v", err)
	}
	spy := &spyNotifier{}
	s := New(reg,
		WithAuthorizer(&spyAuthorizer{}),
		WithCapChecker(&spyCapChecker{}),
		WithAuditSink(&spyAuditSink{}),
		WithFreeze(&fakeFreezeStore{}),
		WithApprovals(empty, newMemApprovals(), &spyApprovalAuthorizer{}),
		WithApprovalNotifier(spy),
		WithClock(func() time.Time { return apNow }),
	)
	s.disp = &spyDispatcher{jobID: "job-1"}

	if _, err := s.Run(context.Background(), machineRequester, Selector{}, mutateAct()); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(spy.notices) != 0 {
		t.Errorf("notified %d times for an ungated dispatch, want 0", len(spy.notices))
	}
}

// TestWithApprovalsRequiresAnAuthorizer: wiring a store with no decision floor
// would let any authenticated caller release a parked dispatch. That is a
// composition-root bug, and it must fail loudly at construction rather than
// quietly at 3am.
func TestWithApprovalsRequiresAnAuthorizer(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("WithApprovals(gate, store, nil) must panic")
		}
	}()
	WithApprovals(gateEverything(t, 1), newMemApprovals(), nil)
}

type spyNotifier struct{ notices []ApprovalNotice }

func (s *spyNotifier) NotifyParked(_ context.Context, n ApprovalNotice) {
	s.notices = append(s.notices, n)
}

// --- batch/window grants (ADR-0027 decision 12) ---

// memGrants is an in-memory ApprovalGrantStore. Claim consumes a use, so the
// exhaustion behaviour under repeated dispatch is exercised for real.
type memGrants struct {
	grant  approval.Grant
	claims int
}

func (m *memGrants) ClaimGrant(_ context.Context, d approval.Dispatch, now time.Time) (approval.Grant, bool, error) {
	if !m.grant.Covers(d, now) {
		return approval.Grant{}, false, nil
	}
	m.grant.Uses++
	m.claims++
	return m.grant, true, nil
}

func grantFixture(t *testing.T, store *memGrants) (*Service, *spyDispatcher, *spyAuditSink) {
	t.Helper()
	reg := registry.NewInMemory()
	for _, id := range []string{"node-a", "node-b"} {
		if _, err := reg.Upsert(registry.Report{NodeID: id}); err != nil {
			t.Fatalf("seed registry: %v", err)
		}
	}
	audit := &spyAuditSink{}
	disp := &spyDispatcher{jobID: "job-1"}
	s := New(reg,
		WithAuthorizer(&spyAuthorizer{}),
		WithCapChecker(&spyCapChecker{}),
		WithAuditSink(audit),
		WithFreeze(&fakeFreezeStore{}),
		WithApprovals(gateEverything(t, 1), newMemApprovals(), &spyApprovalAuthorizer{}),
		WithApprovalGrants(store),
		WithClock(func() time.Time { return apNow }),
	)
	s.disp = disp
	return s, disp, audit
}

func coveringGrant() approval.Grant {
	return approval.Grant{
		ID: "grant-1", RequestID: "req-granted",
		Scope: approval.Scope{
			Account: "gleipnir-prod", RiskClass: jobs.RiskClassMutate,
			MaxFanOut: 10, Operations: []string{"service.restart"},
		},
		StartsAt: apNow.Add(-time.Minute), ExpiresAt: apNow.Add(time.Hour),
		MaxUses: 3, CreatedAt: apNow,
	}
}

// TestGrantReleasesAGatedDispatchWithoutParking is decision 12's whole point:
// the second, third, … dispatch inside a batch does not produce a second,
// third, … elicitation.
func TestGrantReleasesAGatedDispatchWithoutParking(t *testing.T) {
	store := &memGrants{grant: coveringGrant()}
	s, disp, audit := grantFixture(t, store)

	if _, err := s.Run(context.Background(), machineRequester, Selector{}, mutateAct()); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !disp.called {
		t.Fatal("a covered dispatch did not reach the dispatcher")
	}

	var dispatched *AuditEntry
	for i := range audit.entries {
		if audit.entries[i].Kind == AuditKindDispatch {
			dispatched = &audit.entries[i]
		}
	}
	if dispatched == nil {
		t.Fatal("no dispatch audit entry")
	}
	if dispatched.GrantID != "grant-1" {
		t.Errorf("GrantID = %q, want the grant that released it — a grant's blast radius must be one query", dispatched.GrantID)
	}
	if dispatched.ApprovalID != "req-granted" {
		t.Errorf("ApprovalID = %q, want the grant's authorizing request", dispatched.ApprovalID)
	}
}

// TestGrantIsConsultedOnlyAfterTheGate: a grant can never CREATE a requirement,
// and an ungated deployment must be unaffected by one entirely.
func TestGrantIsConsultedOnlyAfterTheGate(t *testing.T) {
	reg := registry.NewInMemory()
	if _, err := reg.Upsert(registry.Report{NodeID: "node-a"}); err != nil {
		t.Fatalf("seed registry: %v", err)
	}
	empty, err := approval.NewGate(nil)
	if err != nil {
		t.Fatalf("NewGate: %v", err)
	}
	store := &memGrants{grant: coveringGrant()}
	s := New(reg,
		WithAuthorizer(&spyAuthorizer{}), WithCapChecker(&spyCapChecker{}),
		WithAuditSink(&spyAuditSink{}), WithFreeze(&fakeFreezeStore{}),
		WithApprovals(empty, newMemApprovals(), &spyApprovalAuthorizer{}),
		WithApprovalGrants(store),
		WithClock(func() time.Time { return apNow }),
	)
	s.disp = &spyDispatcher{jobID: "job-1"}

	if _, err := s.Run(context.Background(), machineRequester, Selector{}, mutateAct()); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if store.claims != 0 {
		t.Errorf("claimed %d grants on an ungated dispatch, want 0 — a grant answers a requirement, it never creates one", store.claims)
	}
}

// TestUncoveredDispatchStillParks: the grant is a wall, not a switch. Anything
// outside it gets the normal callout.
func TestUncoveredDispatchStillParks(t *testing.T) {
	g := coveringGrant()
	g.Scope.MaxFanOut = 1 // the fixture resolves 2 Nodes
	store := &memGrants{grant: g}
	s, disp, _ := grantFixture(t, store)

	_, err := s.Run(context.Background(), machineRequester, Selector{}, mutateAct())
	var parked *ParkedError
	if !errors.As(err, &parked) {
		t.Fatalf("err = %v, want a park for a dispatch above the grant's fan-out ceiling", err)
	}
	if disp.called {
		t.Error("dispatcher was reached for an uncovered dispatch")
	}
}

// TestExhaustedGrantParksAgain: the use limit is real, and running out is a
// return to the normal callout rather than a failure.
func TestExhaustedGrantParksAgain(t *testing.T) {
	store := &memGrants{grant: coveringGrant()} // MaxUses 3
	s, _, _ := grantFixture(t, store)

	for i := 0; i < 3; i++ {
		if _, err := s.Run(context.Background(), machineRequester, Selector{}, mutateAct()); err != nil {
			t.Fatalf("run %d: %v", i+1, err)
		}
	}

	_, err := s.Run(context.Background(), machineRequester, Selector{}, mutateAct())
	var parked *ParkedError
	if !errors.As(err, &parked) {
		t.Fatalf("run 4: err = %v, want a park once the grant is exhausted", err)
	}
	if store.claims != 3 {
		t.Errorf("claims = %d, want exactly the grant's 3 uses", store.claims)
	}
}

// TestGrantNeverBypassesTheBlastCap: a grant substitutes for the HUMAN, never
// for the pipeline. The cap runs before the gate is even consulted, so a
// covered-but-over-cap dispatch is still refused.
func TestGrantNeverBypassesTheBlastCap(t *testing.T) {
	store := &memGrants{grant: coveringGrant()}
	reg := registry.NewInMemory()
	for _, id := range []string{"node-a", "node-b"} {
		if _, err := reg.Upsert(registry.Report{NodeID: id}); err != nil {
			t.Fatalf("seed registry: %v", err)
		}
	}
	capErr := &CapExceededError{Matched: 2, Cap: 1}
	s := New(reg,
		WithAuthorizer(&spyAuthorizer{}),
		WithCapChecker(&spyCapChecker{err: capErr}),
		WithAuditSink(&spyAuditSink{}), WithFreeze(&fakeFreezeStore{}),
		WithApprovals(gateEverything(t, 1), newMemApprovals(), &spyApprovalAuthorizer{}),
		WithApprovalGrants(store),
		WithClock(func() time.Time { return apNow }),
	)
	s.disp = &spyDispatcher{jobID: "job-1"}

	_, err := s.Run(context.Background(), machineRequester, Selector{}, mutateAct())
	if err == nil {
		t.Fatal("a grant released a dispatch over the blast cap")
	}
	var exceeded *CapExceededError
	if !errors.As(err, &exceeded) {
		t.Fatalf("err = %v, want the cap refusal", err)
	}
	if store.claims != 0 {
		t.Error("the grant was claimed for a dispatch the cap had already refused")
	}
}

// TestGrantDoesNotBindItsRequestToOneJob is the modelling rule the one-to-one
// binding cannot express.
//
// A Request carries a single job_id — correct when one approval releases one
// Job. A Grant releases many, so binding each in turn would leave the
// authorizing Request pointing at whichever Job ran last and silently lose the
// rest. The grant-to-Jobs join is the audit trail's GrantID instead.
func TestGrantDoesNotBindItsRequestToOneJob(t *testing.T) {
	store := &memGrants{grant: coveringGrant()}
	approvals := newMemApprovals()

	reg := registry.NewInMemory()
	if _, err := reg.Upsert(registry.Report{NodeID: "node-a"}); err != nil {
		t.Fatalf("seed registry: %v", err)
	}
	audit := &spyAuditSink{}
	s := New(reg,
		WithAuthorizer(&spyAuthorizer{}), WithCapChecker(&spyCapChecker{}),
		WithAuditSink(audit), WithFreeze(&fakeFreezeStore{}),
		WithApprovals(gateEverything(t, 1), approvals, &spyApprovalAuthorizer{}),
		WithApprovalGrants(store),
		WithClock(func() time.Time { return apNow }),
	)
	s.disp = &spyDispatcher{jobID: "job-1"}

	for i := 0; i < 2; i++ {
		if _, err := s.Run(context.Background(), machineRequester, Selector{}, mutateAct()); err != nil {
			t.Fatalf("run %d: %v", i+1, err)
		}
	}

	if len(approvals.bound) != 0 {
		t.Fatalf("grant-released dispatches bound %d Jobs onto the authorizing Request; the join is GrantID, not job_id", len(approvals.bound))
	}

	var withGrant int
	for _, e := range audit.entries {
		if e.Kind == AuditKindDispatch && e.GrantID == "grant-1" {
			withGrant++
		}
	}
	if withGrant != 2 {
		t.Errorf("%d dispatch entries carry the GrantID, want 2 — a grant's full blast radius must be one query", withGrant)
	}
}
