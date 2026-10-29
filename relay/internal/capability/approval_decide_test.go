package capability

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/Felag-Engineering/relay/relay/internal/approval"
	"github.com/Felag-Engineering/relay/relay/internal/jobs"
	"github.com/Felag-Engineering/relay/relay/internal/registry"
)

// approval_decide_test.go covers #270's half of the callout: answering a parked
// dispatch through the capability layer.

// decideFixture builds a Service whose gate parks everything, with the given
// approval authorizer, and returns it alongside the store and audit spy.
func decideFixture(t *testing.T, authorizer ApprovalAuthorizer) (*testSvc, *memApprovals, *spyAuditSink) {
	t.Helper()
	reg := registry.NewInMemory()
	for _, id := range []string{"node-a", "node-b"} {
		if _, err := reg.Upsert(registry.Report{NodeID: id}); err != nil {
			t.Fatalf("seed registry: %v", err)
		}
	}
	store := newMemApprovals()
	audit := &spyAuditSink{}
	s := build(t, seams{reg: reg,
		authz:  &spyAuthorizer{},
		cap:    &spyCapChecker{},
		audit:  audit,
		freeze: &fakeFreezeStore{},
		gate:   gateEverything(t), approvals: store, approvalAuthz: authorizer,
		now: func() time.Time { return apNow },
	})
	s.disp = &spyDispatcher{jobID: "job-1"}
	return s, store, audit
}

// decideFixtureWithRequirement is decideFixture, parameterised on the gate's
// Requirement instead of a fixed count, and on the store and the clock —
// matching approvalFixture's shape (nodes, gate/req, store, now) rather than
// inventing a third fixture shape — for tests that need to shape
// audience/channel/requester rules, substitute a failing store, or move time.
func decideFixtureWithRequirement(t *testing.T, req approval.Requirement, store ApprovalStore, authorizer ApprovalAuthorizer, now func() time.Time) (*testSvc, *spyAuditSink) {
	t.Helper()
	reg := registry.NewInMemory()
	for _, id := range []string{"node-a", "node-b"} {
		if _, err := reg.Upsert(registry.Report{NodeID: id}); err != nil {
			t.Fatalf("seed registry: %v", err)
		}
	}
	gate, err := approval.NewGate([]approval.Rule{{Name: "t", Require: req}})
	if err != nil {
		t.Fatalf("NewGate: %v", err)
	}
	audit := &spyAuditSink{}
	s := build(t, seams{reg: reg,
		authz:  &spyAuthorizer{},
		cap:    &spyCapChecker{},
		audit:  audit,
		freeze: &fakeFreezeStore{},
		gate:   gate, approvals: store, approvalAuthz: authorizer,
		now: now,
	})
	s.disp = &spyDispatcher{jobID: "job-1"}
	return s, audit
}

// failingApprovals wraps *memApprovals but fails RecordDecision with a
// non-domain error, standing in for a genuine store outage — as opposed to a
// domain refusal — on the "store failure" row of
// TestDecideApproval_OtherRefusalsAreUnchanged.
type failingApprovals struct {
	*memApprovals
	err error
}

func (f *failingApprovals) RecordDecision(context.Context, string, approval.Decision, time.Time) (approval.Request, error) {
	return approval.Request{}, f.err
}

// countApprovalDecided counts the AuditKindApprovalDecided entries audit has
// recorded so far, so a test can assert a refusal added none.
func countApprovalDecided(audit *spyAuditSink) int {
	n := 0
	for _, e := range audit.entries {
		if e.Kind == AuditKindApprovalDecided {
			n++
		}
	}
	return n
}

// park drives one gated dispatch and returns the resulting ParkedError.
func park(t *testing.T, s *testSvc, p Principal) *ParkedError {
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
	s, _, audit := decideFixture(t, &spyApprovalAuthorizer{})
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
		t.Error("an approved request must satisfy the requirement")
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
	s, _, _ := decideFixture(t, &spyApprovalAuthorizer{})
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
	s, _, _ := decideFixture(t, authorizer)
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
// no decision behind, or a request could be ended by someone who was denied.
func TestDecisionRefusedByRoleFloorRecordsNothing(t *testing.T) {
	denied := errors.New("authz: unauthorized")
	s, store, _ := decideFixture(t, &spyApprovalAuthorizer{err: denied})
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
// rule the config language can express (the requester holding the admin role).
func TestMachineCannotDecideItsOwnRequestThroughTheLayer(t *testing.T) {
	s, store, _ := decideFixture(t, &spyApprovalAuthorizer{})
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
	s, store, _ := decideFixture(t, &spyApprovalAuthorizer{})
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
	s, _, audit := decideFixture(t, &spyApprovalAuthorizer{})
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
	s, _, _ := decideFixture(t, &spyApprovalAuthorizer{})
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
	s, _, _ := decideFixture(t, &spyApprovalAuthorizer{})
	parked := park(t, s, machineRequester)

	live, err := s.PendingApprovals(context.Background())
	if err != nil {
		t.Fatalf("PendingApprovals: %v", err)
	}
	if len(live) != 1 {
		t.Fatalf("pending = %d, want 1", len(live))
	}

	// Move the clock past the deadline without running any sweeper.
	s.Approvals.now = func() time.Time { return parked.ExpiresAt.Add(time.Second) }
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
	s, _, _ := decideFixture(t, &spyApprovalAuthorizer{})
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
	s, _, _ := decideFixture(t, &spyApprovalAuthorizer{})
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
	s := build(t, seams{reg: reg,
		authz:  &spyAuthorizer{},
		cap:    &spyCapChecker{},
		audit:  &spyAuditSink{},
		freeze: &fakeFreezeStore{},
		gate:   gateEverything(t), approvals: newMemApprovals(), approvalAuthz: &spyApprovalAuthorizer{},
		approvalNotifier: spy,
		now:              func() time.Time { return apNow },
	})
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

// TestRedriveAuditsPendingObservedNotRequested (#379): approval_requested
// means a Request was CREATED. Re-driving the same Plan is how a caller polls
// while waiting, so N attempts at one parked Plan must leave exactly one
// approval_requested record — the polls land under approval_pending_observed,
// naming the same request, so an AI-agent hammering a parked request stays
// visible without inflating the count of asks.
func TestRedriveAuditsPendingObservedNotRequested(t *testing.T) {
	reg := registry.NewInMemory()
	if _, err := reg.Upsert(registry.Report{NodeID: "node-a"}); err != nil {
		t.Fatalf("seed registry: %v", err)
	}
	audit := &spyAuditSink{}
	s := build(t, seams{reg: reg,
		authz:  &spyAuthorizer{},
		cap:    &spyCapChecker{},
		audit:  audit,
		freeze: &fakeFreezeStore{},
		gate:   gateEverything(t), approvals: newMemApprovals(), approvalAuthz: &spyApprovalAuthorizer{},
		now: func() time.Time { return apNow },
	})
	s.disp = &spyDispatcher{jobID: "job-1"}

	first := park(t, s, machineRequester)
	park(t, s, machineRequester)
	park(t, s, machineRequester)

	var requested, observed []AuditEntry
	for _, e := range audit.entries {
		switch e.Kind {
		case AuditKindApprovalRequested:
			requested = append(requested, e)
		case AuditKindApprovalPendingObserved:
			observed = append(observed, e)
		}
	}
	if len(requested) != 1 {
		t.Fatalf("%d approval_requested entries for one logical request, want exactly 1", len(requested))
	}
	if len(observed) != 2 {
		t.Fatalf("%d approval_pending_observed entries, want 2 — each re-drive is on the record under its own kind", len(observed))
	}
	for _, e := range observed {
		if e.ApprovalID != first.RequestID || e.PlanHash != first.PlanHash {
			t.Errorf("observed entry ApprovalID/PlanHash = %q/%q, want %q/%q — a poll must name the request it bounced off",
				e.ApprovalID, e.PlanHash, first.RequestID, first.PlanHash)
		}
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
	s := build(t, seams{reg: reg,
		authz:  &spyAuthorizer{},
		cap:    &spyCapChecker{},
		audit:  &spyAuditSink{},
		freeze: &fakeFreezeStore{},
		gate:   empty, approvals: newMemApprovals(), approvalAuthz: &spyApprovalAuthorizer{},
		approvalNotifier: spy,
		now:              func() time.Time { return apNow },
	})
	s.disp = &spyDispatcher{jobID: "job-1"}

	if _, err := s.Run(context.Background(), machineRequester, Selector{}, mutateAct()); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(spy.notices) != 0 {
		t.Errorf("notified %d times for an ungated dispatch, want 0", len(spy.notices))
	}
}

// TestNewApprovalsRequiresAnAuthorizer: wiring a store with no decision floor
// would let any authenticated caller release a parked dispatch. That is a
// composition-root bug, and it must fail loudly at construction rather than
// quietly at 3am.
func TestNewApprovalsRequiresAnAuthorizer(t *testing.T) {
	rec := NewRecorder(&spyAuditSink{}, nil, nil)
	gate, store := gateEverything(t), newMemApprovals()
	defer func() {
		if recover() == nil {
			t.Fatal("NewApprovals with a gate and store but no approval authorizer must panic")
		}
	}()
	NewApprovals(rec, gate, store, nil, nil, nil)
}

type spyNotifier struct{ notices []ApprovalNotice }

func (s *spyNotifier) NotifyParked(_ context.Context, n ApprovalNotice) {
	s.notices = append(s.notices, n)
}

// TestDecideApprovalAuditEntryCarriesTheAnswerAndChannel (#545): DecideApproval's
// audit entry carries the structured answer and the Channel it arrived on —
// not just the prose Reason those facts used to live inside exclusively.
//
// DISTINCT Channels on the approve and deny cases is the point: an OutOfBand
// approval and an InBand denial are accepted in the same test (#545's plan).
func TestDecideApprovalAuditEntryCarriesTheAnswerAndChannel(t *testing.T) {
	reg := registry.NewInMemory()
	if _, err := reg.Upsert(registry.Report{NodeID: "node-a"}); err != nil {
		t.Fatalf("seed registry: %v", err)
	}
	gate, err := approval.NewGate([]approval.Rule{{
		Name:    "everything",
		Match:   approval.Match{},
		Require: approval.Requirement{TTL: time.Hour},
	}})
	if err != nil {
		t.Fatalf("NewGate: %v", err)
	}
	store := newMemApprovals()
	auditSink := &spyAuditSink{}
	s := build(t, seams{reg: reg,
		authz:  &spyAuthorizer{},
		cap:    &spyCapChecker{},
		audit:  auditSink,
		freeze: &fakeFreezeStore{},
		gate:   gate, approvals: store, approvalAuthz: &spyApprovalAuthorizer{},
		now: func() time.Time { return apNow },
	})
	s.disp = &spyDispatcher{jobID: "job-1"}

	// Two distinct Actions so the two dispatches park as two distinct
	// requests (checkApproval hashes the Plan; identical Actions would bounce
	// the second dispatch off the first's pending Request instead of parking
	// a second one).
	approveAct := jobs.Action{
		Kind: jobs.ActionOperation, OperationName: "service.restart",
		OperationArgs: map[string]string{"service": "nginx"},
	}
	denyAct := jobs.Action{
		Kind: jobs.ActionOperation, OperationName: "service.restart",
		OperationArgs: map[string]string{"service": "redis"},
	}

	parkOne := func(act jobs.Action) *ParkedError {
		t.Helper()
		_, err := s.Run(context.Background(), machineRequester, Selector{}, act)
		var parked *ParkedError
		if !errors.As(err, &parked) {
			t.Fatalf("Run: err = %v, want a park", err)
		}
		return parked
	}

	approveParked := parkOne(approveAct)
	denyParked := parkOne(denyAct)
	if approveParked.RequestID == denyParked.RequestID {
		t.Fatal("the two dispatches parked as the SAME request — they must be distinct plans " +
			"for this test to isolate the approve case from the deny case")
	}

	if _, err := s.DecideApproval(context.Background(), humanApprover("acct-ana", "ana"), ApprovalDecision{
		RequestID: approveParked.RequestID, PlanHash: approveParked.PlanHash, Approve: true,
		Channel: approval.ChannelOutOfBand,
	}); err != nil {
		t.Fatalf("DecideApproval(approve): %v", err)
	}
	if _, err := s.DecideApproval(context.Background(), humanApprover("acct-bo", "bo"), ApprovalDecision{
		RequestID: denyParked.RequestID, PlanHash: denyParked.PlanHash, Approve: false,
		Channel: approval.ChannelInBand,
	}); err != nil {
		t.Fatalf("DecideApproval(deny): %v", err)
	}

	var approveEntry, denyEntry *AuditEntry
	for i := range auditSink.entries {
		e := &auditSink.entries[i]
		if e.Kind != AuditKindApprovalDecided {
			continue
		}
		switch e.ApprovalID {
		case approveParked.RequestID:
			approveEntry = e
		case denyParked.RequestID:
			denyEntry = e
		}
	}
	if approveEntry == nil || denyEntry == nil {
		t.Fatalf("missing decision audit entries: approve=%v deny=%v", approveEntry, denyEntry)
	}

	if approveEntry.ApprovalAnswer != ApprovalAnswerApproved {
		t.Errorf("approve entry ApprovalAnswer = %q, want %q", approveEntry.ApprovalAnswer, ApprovalAnswerApproved)
	}
	if approveEntry.DecisionChannel != approval.ChannelOutOfBand {
		t.Errorf("approve entry DecisionChannel = %v, want %v", approveEntry.DecisionChannel, approval.ChannelOutOfBand)
	}
	if approveEntry.PlanHash != approveParked.PlanHash {
		t.Errorf("approve entry PlanHash = %q, want %q", approveEntry.PlanHash, approveParked.PlanHash)
	}

	// The denial case must not be left at the zero value: setting the answer
	// only on the happy path is exactly the bug this test guards against.
	if denyEntry.ApprovalAnswer == ApprovalAnswerUnrecorded {
		t.Fatal("deny entry ApprovalAnswer is Unrecorded — the answer is being set only on the approve path")
	}
	if denyEntry.ApprovalAnswer != ApprovalAnswerDenied {
		t.Errorf("deny entry ApprovalAnswer = %q, want %q", denyEntry.ApprovalAnswer, ApprovalAnswerDenied)
	}
	if denyEntry.DecisionChannel != approval.ChannelInBand {
		t.Errorf("deny entry DecisionChannel = %v, want %v", denyEntry.DecisionChannel, approval.ChannelInBand)
	}
	if denyEntry.PlanHash != denyParked.PlanHash {
		t.Errorf("deny entry PlanHash = %q, want %q", denyEntry.PlanHash, denyParked.PlanHash)
	}
}

// TestDecideApproval_InBandHumanWithNoAssertedApproverIsVerified is AP-79's
// domain half: proof that the domain ALREADY accepts an in-band decision by a
// human Account with nothing in the asserted lane as that Account's own
// self-confirmation, with no change to package approval or this file's
// DecideApproval — approval.Request.Decide's own carve-out
// (inBandSelfConfirmation) already reads `!d.DeciderHuman && ...`, so a human
// decider never needs the asserted branch at all. The capability layer's
// session rule (ElicitedResponderRule) is what restricts WHICH
// sessions may reach this path; this test is the domain's side of "and once
// there, it is treated exactly as a human's in-band self-confirmation always
// has been".
//
// Each subtest gets its own gate, per the plan review's isolation note.
func TestDecideApproval_InBandHumanWithNoAssertedApproverIsVerified(t *testing.T) {
	t.Run("in-band: recorded as this human's own decision", func(t *testing.T) {
		s, audit := decideFixtureWithRequirement(t,
			approval.Requirement{TTL: time.Hour},
			newMemApprovals(), &spyApprovalAuthorizer{}, func() time.Time { return apNow })

		p := humanApprover("acct-ana", "ana")
		parked := park(t, s, p)

		updated, err := s.DecideApproval(context.Background(), p, ApprovalDecision{
			RequestID: parked.RequestID, PlanHash: parked.PlanHash, Approve: true, Channel: approval.ChannelInBand,
		})
		if err != nil {
			t.Fatalf("DecideApproval: %v", err)
		}
		if updated.State != approval.StateApproved {
			t.Errorf("State = %v, want StateApproved", updated.State)
		}

		var entry *AuditEntry
		for i := range audit.entries {
			if audit.entries[i].Kind == AuditKindApprovalDecided && audit.entries[i].ApprovalID == parked.RequestID {
				entry = &audit.entries[i]
			}
		}
		if entry == nil {
			t.Fatal("no AuditKindApprovalDecided entry recorded")
		}
		if !reflect.DeepEqual(entry.Principal, p) {
			t.Errorf("audit entry Principal = %+v, want the human decider %+v", entry.Principal, p)
		}
		if entry.Asserted.OnBehalfOf != "" {
			t.Errorf("audit entry Asserted.OnBehalfOf = %q, want empty — nothing was asserted", entry.Asserted.OnBehalfOf)
		}
	})

	t.Run("machine Account, same shape otherwise: ErrMachineSelfDecision", func(t *testing.T) {
		s, _ := decideFixtureWithRequirement(t,
			approval.Requirement{TTL: time.Hour},
			newMemApprovals(), &spyApprovalAuthorizer{}, func() time.Time { return apNow })

		p := Principal{AccountID: "acct-mo", Account: "mo", Role: "operator", Kind: "machine"}
		parked := park(t, s, p)

		_, err := s.DecideApproval(context.Background(), p, ApprovalDecision{
			RequestID: parked.RequestID, PlanHash: parked.PlanHash, Approve: true, Channel: approval.ChannelInBand,
		})
		if !errors.Is(err, approval.ErrMachineSelfDecision) {
			t.Errorf("err = %v, want errors.Is(_, approval.ErrMachineSelfDecision) — a machine Account must never "+
				"be inferred human from anything about the session", err)
		}
	})
}

// --- #724: a refused decision reports what became of the request ----------

// TestDecideApproval_NotPendingReturnsTheCurrentRequest is the issue's first
// acceptance criterion: a decision refused because the Request is no longer
// pending — already approved, already denied, or lapsed but not yet swept —
// returns the Request as it now stands, not the zero value.
func TestDecideApproval_NotPendingReturnsTheCurrentRequest(t *testing.T) {
	t.Run("already approved with a bound Job", func(t *testing.T) {
		s, _, audit := decideFixture(t, &spyApprovalAuthorizer{})
		parked := park(t, s, machineRequester)

		if _, err := s.DecideApproval(context.Background(), humanApprover("acct-ana", "ana"), ApprovalDecision{
			RequestID: parked.RequestID, PlanHash: parked.PlanHash, Approve: true,
			Channel: approval.ChannelOutOfBand,
		}); err != nil {
			t.Fatalf("DecideApproval (approve): %v", err)
		}
		// The request is approved, so re-driving the same Plan dispatches and
		// binds the Job the approval released.
		if _, err := s.Run(context.Background(), machineRequester, Selector{}, mutateAct()); err != nil {
			t.Fatalf("Run after approval: %v", err)
		}

		before := countApprovalDecided(audit)
		got, err := s.DecideApproval(context.Background(), humanApprover("acct-bo", "bo"), ApprovalDecision{
			RequestID: parked.RequestID, PlanHash: parked.PlanHash, Approve: true,
			Channel: approval.ChannelOutOfBand,
		})
		if !errors.Is(err, approval.ErrNotPending) {
			t.Fatalf("err = %v, want ErrNotPending", err)
		}
		if got.ID != parked.RequestID {
			t.Errorf("ID = %q, want %q", got.ID, parked.RequestID)
		}
		if got.State != approval.StateApproved {
			t.Errorf("State = %v, want approved", got.State)
		}
		if got.JobID != "job-1" {
			t.Errorf("JobID = %q, want job-1 — the caller's next question after \"too late\" is what already ran", got.JobID)
		}
		if len(got.Decisions) != 1 {
			t.Errorf("Decisions = %d, want 1", len(got.Decisions))
		}
		if countApprovalDecided(audit) != before {
			t.Error("a refused decision must not add an audit entry")
		}
	})

	t.Run("already denied", func(t *testing.T) {
		s, _, audit := decideFixture(t, &spyApprovalAuthorizer{})
		parked := park(t, s, machineRequester)

		if _, err := s.DecideApproval(context.Background(), humanApprover("acct-ana", "ana"), ApprovalDecision{
			RequestID: parked.RequestID, PlanHash: parked.PlanHash, Approve: false,
			Reason: "wrong window", Channel: approval.ChannelOutOfBand,
		}); err != nil {
			t.Fatalf("DecideApproval (deny): %v", err)
		}

		before := countApprovalDecided(audit)
		got, err := s.DecideApproval(context.Background(), humanApprover("acct-bo", "bo"), ApprovalDecision{
			RequestID: parked.RequestID, PlanHash: parked.PlanHash, Approve: true,
			Channel: approval.ChannelOutOfBand,
		})
		if !errors.Is(err, approval.ErrNotPending) {
			t.Fatalf("err = %v, want ErrNotPending", err)
		}
		if got.State != approval.StateDenied {
			t.Errorf("State = %v, want denied", got.State)
		}
		if len(got.Decisions) != 1 || got.Decisions[0].Account != "ana" || got.Decisions[0].Approve {
			t.Errorf("Decisions = %+v, want exactly ana's denial", got.Decisions)
		}
		if countApprovalDecided(audit) != before {
			t.Error("a refused decision must not add an audit entry")
		}
	})

	t.Run("lapsed but not swept", func(t *testing.T) {
		clock := apNow
		req := approval.Requirement{TTL: time.Hour}
		store := newMemApprovals()
		s, audit := decideFixtureWithRequirement(t, req, store, &spyApprovalAuthorizer{}, func() time.Time { return clock })
		parked := park(t, s, machineRequester)

		// Move the clock past the deadline without running any sweeper — the
		// same technique TestPendingApprovalsHidesExpired uses.
		clock = parked.ExpiresAt.Add(time.Minute)

		before := countApprovalDecided(audit)
		got, err := s.DecideApproval(context.Background(), humanApprover("acct-ana", "ana"), ApprovalDecision{
			RequestID: parked.RequestID, PlanHash: parked.PlanHash, Approve: true,
			Channel: approval.ChannelOutOfBand,
		})
		if !errors.Is(err, approval.ErrNotPending) {
			t.Fatalf("err = %v, want ErrNotPending", err)
		}
		if !strings.Contains(err.Error(), "expired at") {
			t.Errorf("err = %q, want it to still carry \"expired at\" — the capability layer must not re-wrap the domain's error", err)
		}
		if got.ID != parked.RequestID {
			t.Errorf("ID = %q, want %q", got.ID, parked.RequestID)
		}
		if got.State != approval.StatePending {
			t.Errorf("State = %v, want StatePending — a lapsed Request the sweeper has not retired yet is stored as pending", got.State)
		}
		if !got.Expired(clock) {
			t.Error("Expired(clock) = false, want true")
		}
		if len(got.Decisions) != 0 {
			t.Errorf("Decisions = %d, want 0", len(got.Decisions))
		}
		if countApprovalDecided(audit) != before {
			t.Error("a refused decision must not add an audit entry")
		}
		if len(store.byID[parked.RequestID].Decisions) != 0 {
			t.Error("the store must still hold zero decisions after a refused decision")
		}
	})
}

// TestDecideApproval_SecondDecisionReturnsTheCurrentRequest: one Decision ends
// a request (AP-82), so a second one, even from the Account that decided first,
// is refused as not pending and returns the Request as it now stands.
//
// Proves AP-82.
func TestDecideApproval_SecondDecisionReturnsTheCurrentRequest(t *testing.T) {
	s, store, audit := decideFixture(t, &spyApprovalAuthorizer{})
	parked := park(t, s, machineRequester)

	if _, err := s.DecideApproval(context.Background(), humanApprover("acct-ana", "ana"), ApprovalDecision{
		RequestID: parked.RequestID, PlanHash: parked.PlanHash, Approve: true,
		Channel: approval.ChannelOutOfBand,
	}); err != nil {
		t.Fatalf("first decision: %v", err)
	}

	for _, p := range []Principal{humanApprover("acct-ana", "ana"), humanApprover("acct-bo", "bo")} {
		got, err := s.DecideApproval(context.Background(), p, ApprovalDecision{
			RequestID: parked.RequestID, PlanHash: parked.PlanHash, Approve: false,
			Channel: approval.ChannelOutOfBand,
		})
		if !errors.Is(err, approval.ErrNotPending) {
			t.Fatalf("second decision by %s: err = %v, want ErrNotPending", p.Account, err)
		}
		if got.State != approval.StateApproved {
			t.Errorf("State = %v, want it still approved", got.State)
		}
		if len(got.Decisions) != 1 || got.Decisions[0].AccountID != "acct-ana" {
			t.Errorf("Decisions = %+v, want exactly ana's first decision", got.Decisions)
		}
	}
	if n := countApprovalDecided(audit); n != 1 {
		t.Errorf("audited %d decisions, want exactly the first one: a refused decision is not its own audit record", n)
	}
	if len(store.byID[parked.RequestID].Decisions) != 1 {
		t.Errorf("stored %d decisions, want 1", len(store.byID[parked.RequestID].Decisions))
	}
}

// TestDecideApproval_OtherRefusalsAreUnchanged is the issue's third
// acceptance criterion: every refusal besides ErrNotPending returns exactly
// what it always has — the zero value —
// and records or audits nothing new.
func TestDecideApproval_OtherRefusalsAreUnchanged(t *testing.T) {
	errRoleFloorDenied := errors.New("authz: unauthorized")
	errStoreFailure := errors.New("disk on fire")

	cases := []struct {
		name       string
		wantErr    error  // checked with errors.Is when set
		wantErrSub string // checked with strings.Contains when wantErr is nil
		build      func(t *testing.T) (s *testSvc, p Principal, in ApprovalDecision, audit *spyAuditSink, checkStore func(t *testing.T))
	}{
		{
			name:    "role floor",
			wantErr: errRoleFloorDenied,
			build: func(t *testing.T) (*testSvc, Principal, ApprovalDecision, *spyAuditSink, func(t *testing.T)) {
				s, store, audit := decideFixture(t, &spyApprovalAuthorizer{err: errRoleFloorDenied})
				parked := park(t, s, machineRequester)
				return s, humanApprover("acct-viewer", "vi"), ApprovalDecision{
						RequestID: parked.RequestID, PlanHash: parked.PlanHash, Approve: true, Channel: approval.ChannelOutOfBand,
					}, audit, func(t *testing.T) {
						if got := store.byID[parked.RequestID]; len(got.Decisions) != 0 || got.State != approval.StatePending {
							t.Errorf("stored record changed: %+v", got)
						}
					}
			},
		},
		{
			name:    "machine self-decision",
			wantErr: approval.ErrMachineSelfDecision,
			build: func(t *testing.T) (*testSvc, Principal, ApprovalDecision, *spyAuditSink, func(t *testing.T)) {
				req := approval.Requirement{TTL: time.Hour}
				store := newMemApprovals()
				s, audit := decideFixtureWithRequirement(t, req, store, &spyApprovalAuthorizer{}, func() time.Time { return apNow })
				parked := park(t, s, machineRequester)
				return s, machineRequester, ApprovalDecision{
						RequestID: parked.RequestID, PlanHash: parked.PlanHash, Approve: true, Channel: approval.ChannelOutOfBand,
					}, audit, func(t *testing.T) {
						if got := store.byID[parked.RequestID]; len(got.Decisions) != 0 || got.State != approval.StatePending {
							t.Errorf("stored record changed: %+v", got)
						}
					}
			},
		},
		{
			name:    "plan hash",
			wantErr: approval.ErrPlanChanged,
			build: func(t *testing.T) (*testSvc, Principal, ApprovalDecision, *spyAuditSink, func(t *testing.T)) {
				s, store, audit := decideFixture(t, &spyApprovalAuthorizer{})
				parked := park(t, s, machineRequester)
				return s, humanApprover("acct-ana", "ana"), ApprovalDecision{
						RequestID: parked.RequestID, PlanHash: "some-other-plan", Approve: true, Channel: approval.ChannelOutOfBand,
					}, audit, func(t *testing.T) {
						if got := store.byID[parked.RequestID]; len(got.Decisions) != 0 || got.State != approval.StatePending {
							t.Errorf("stored record changed: %+v", got)
						}
					}
			},
		},
		{
			name:    "unavailable",
			wantErr: ErrApprovalUnavailable,
			build: func(t *testing.T) (*testSvc, Principal, ApprovalDecision, *spyAuditSink, func(t *testing.T)) {
				reg := registry.NewInMemory()
				audit := &spyAuditSink{}
				s := build(t, seams{reg: reg,
					authz:  &spyAuthorizer{},
					cap:    &spyCapChecker{},
					audit:  audit,
					freeze: &fakeFreezeStore{},
					now:    func() time.Time { return apNow },
				})
				return s, humanApprover("acct-ana", "ana"), ApprovalDecision{
					RequestID: "req-x", PlanHash: "hash", Approve: true, Channel: approval.ChannelOutOfBand,
				}, audit, func(t *testing.T) {}
			},
		},
		{
			name:       "missing ID",
			wantErrSub: "request id is required",
			build: func(t *testing.T) (*testSvc, Principal, ApprovalDecision, *spyAuditSink, func(t *testing.T)) {
				s, _, audit := decideFixture(t, &spyApprovalAuthorizer{})
				return s, humanApprover("acct-ana", "ana"), ApprovalDecision{
					RequestID: "", PlanHash: "hash", Approve: true, Channel: approval.ChannelOutOfBand,
				}, audit, func(t *testing.T) {}
			},
		},
		{
			name:    "not found",
			wantErr: approval.ErrNotFound,
			build: func(t *testing.T) (*testSvc, Principal, ApprovalDecision, *spyAuditSink, func(t *testing.T)) {
				s, _, audit := decideFixture(t, &spyApprovalAuthorizer{})
				return s, humanApprover("acct-ana", "ana"), ApprovalDecision{
					RequestID: "req-nope", PlanHash: "hash", Approve: true, Channel: approval.ChannelOutOfBand,
				}, audit, func(t *testing.T) {}
			},
		},
		{
			name:    "store failure",
			wantErr: errStoreFailure,
			build: func(t *testing.T) (*testSvc, Principal, ApprovalDecision, *spyAuditSink, func(t *testing.T)) {
				inner := newMemApprovals()
				failing := &failingApprovals{memApprovals: inner, err: errStoreFailure}
				req := approval.Requirement{TTL: time.Hour}
				s, audit := decideFixtureWithRequirement(t, req, failing, &spyApprovalAuthorizer{}, func() time.Time { return apNow })
				parked := park(t, s, machineRequester)
				return s, humanApprover("acct-ana", "ana"), ApprovalDecision{
						RequestID: parked.RequestID, PlanHash: parked.PlanHash, Approve: true, Channel: approval.ChannelOutOfBand,
					}, audit, func(t *testing.T) {
						if got := inner.byID[parked.RequestID]; len(got.Decisions) != 0 || got.State != approval.StatePending {
							t.Errorf("stored record changed: %+v", got)
						}
					}
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s, p, in, audit, checkStore := tc.build(t)
			before := countApprovalDecided(audit)

			got, err := s.DecideApproval(context.Background(), p, in)

			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("err = %v, want errors.Is(err, %v)", err, tc.wantErr)
				}
			} else if err == nil || !strings.Contains(err.Error(), tc.wantErrSub) {
				t.Fatalf("err = %v, want it to contain %q", err, tc.wantErrSub)
			}
			if !reflect.DeepEqual(got, approval.Request{}) {
				t.Errorf("Request = %+v, want the zero value", got)
			}
			if countApprovalDecided(audit) != before {
				t.Error("a refused decision must not add an audit entry")
			}
			checkStore(t)
		})
	}
}

// TestAnswerElicited_RecordsAnInBandDecision: the in-band entry point takes no
// channel and still records one, in the Decision and in the audit entry.
//
// Proves AP-12, AP-63.
func TestAnswerElicited_RecordsAnInBandDecision(t *testing.T) {
	req := approval.Requirement{TTL: time.Hour}
	store := newMemApprovals()
	s, auditSink := decideFixtureWithRequirement(t, req, store, &spyApprovalAuthorizer{}, func() time.Time { return apNow })
	parked := park(t, s, machineRequester)

	ctx := WithAssertions(context.Background(), Assertions{OnBehalfOf: "alice"})
	got, err := s.AnswerElicited(ctx, humanApprover("acct-ana", "ana"), parked.RequestID, parked.PlanHash, true)
	if err != nil {
		t.Fatalf("AnswerElicited: %v", err)
	}
	if got.State != approval.StateApproved {
		t.Errorf("state = %v, want approved", got.State)
	}
	if len(got.Decisions) != 1 {
		t.Fatalf("decisions = %d, want 1", len(got.Decisions))
	}
	d := got.Decisions[0]
	if d.Channel != approval.ChannelInBand {
		t.Errorf("recorded channel = %v, want in-band", d.Channel)
	}
	if d.OnBehalfOf != "alice" {
		t.Errorf("recorded on-behalf-of = %q, want alice", d.OnBehalfOf)
	}

	var entry *AuditEntry
	for i := range auditSink.entries {
		if auditSink.entries[i].Kind == AuditKindApprovalDecided {
			entry = &auditSink.entries[i]
		}
	}
	if entry == nil {
		t.Fatal("no approval-decided audit entry")
	}
	if entry.DecisionChannel != approval.ChannelInBand {
		t.Errorf("audit channel = %v, want in-band", entry.DecisionChannel)
	}
	if entry.ApprovalAnswer != ApprovalAnswerApproved {
		t.Errorf("audit answer = %v, want approved", entry.ApprovalAnswer)
	}
}

// TestAnswerElicited_RefusesExactlyAsDecideApproval: the entry point adds no
// refusal of its own and drops none of DecideApproval's.
func TestAnswerElicited_RefusesExactlyAsDecideApproval(t *testing.T) {
	cases := []struct {
		name     string
		planHash func(parked *ParkedError) string
		wantErr  error
	}{
		{"plan hash mismatch", func(*ParkedError) string { return "some-other-plan" }, approval.ErrPlanChanged},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := approval.Requirement{TTL: time.Hour}
			store := newMemApprovals()
			s, auditSink := decideFixtureWithRequirement(t, req, store, &spyApprovalAuthorizer{}, func() time.Time { return apNow })
			parked := park(t, s, machineRequester)

			// An API-token principal, so the session rule (AP-87) does not refuse
			// first and this test still isolates DecideApproval's refusals.
			p := humanApprover("acct-ana", "ana")
			p.AuthMethod = AuthMethodAPIToken
			_, err := s.AnswerElicited(context.Background(), p, parked.RequestID, tc.planHash(parked), true)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("err = %v, want errors.Is(_, %v)", err, tc.wantErr)
			}
			if got := store.byID[parked.RequestID]; len(got.Decisions) != 0 || got.State != approval.StatePending {
				t.Errorf("stored record changed: %+v", got)
			}
			if n := countApprovalDecided(auditSink); n != 0 {
				t.Errorf("approval-decided audit entries = %d, want 0", n)
			}
		})
	}
}
