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

// approval_grant_test.go covers the MANAGEMENT half of batch/window approvals
// (#378): asking for a Grant, listing, and revoking. The dispatch half — a
// Grant releasing work — lives in approval_decide_test.go.
//
// The property most of these tests exist to defend is that a Grant is not a
// cheaper way to get approved. Everything here that looks like paperwork (the
// derived requirement, the role floor, the scope hash, the validate-before-
// write ordering) is load-bearing for exactly that.

// grantMgmtFixture builds a Service with the given gate, plus both approval
// stores, and returns the pieces a management test needs to inspect.
func grantMgmtFixture(t *testing.T, gate ApprovalGate, authorizer ApprovalAuthorizer) (*Service, *memApprovals, *memGrants, *spyAuditSink) {
	t.Helper()
	reg := registry.NewInMemory()
	if _, err := reg.Upsert(registry.Report{NodeID: "node-a"}); err != nil {
		t.Fatalf("seed registry: %v", err)
	}
	approvals, grants, audit := newMemApprovals(), &memGrants{}, &spyAuditSink{}
	s := New(reg,
		WithAuthorizer(&spyAuthorizer{}),
		WithCapChecker(&spyCapChecker{}),
		WithAuditSink(audit),
		WithFreeze(&fakeFreezeStore{}),
		WithApprovals(gate, approvals, authorizer),
		WithApprovalGrants(grants),
		WithClock(func() time.Time { return apNow }),
	)
	s.disp = &spyDispatcher{jobID: "job-1"}
	return s, approvals, grants, audit
}

// scopeFixture is a small, fully bounded Scope: the shape a real request has.
func scopeFixture() approval.Scope {
	return approval.Scope{
		Account:    "gleipnir-prod",
		RiskClass:  jobs.RiskClassMutate,
		MaxFanOut:  3,
		Operations: []string{"service.restart"},
	}
}

func grantRequestFixture() GrantRequest {
	return GrantRequest{
		Scope:     scopeFixture(),
		ExpiresAt: apNow.Add(2 * time.Hour),
		MaxUses:   5,
	}
}

// TestRequestGrantCreatesAPendingRequest is the shape of the two-step flow:
// asking for a Grant does not grant it. The Grant row exists so the Request has
// something to point at, but the authorization it represents is still pending.
func TestRequestGrantCreatesAPendingRequest(t *testing.T) {
	s, approvals, grants, audit := grantMgmtFixture(t, gateEverything(t, 1), &spyApprovalAuthorizer{})

	grant, request, err := s.RequestGrant(context.Background(), machineRequester, grantRequestFixture())
	if err != nil {
		t.Fatalf("RequestGrant: %v", err)
	}

	if request.State != approval.StatePending {
		t.Fatalf("request State = %v, want pending — requesting a grant must never be the same act as being granted one", request.State)
	}
	if grant.RequestID != request.ID {
		t.Errorf("grant.RequestID = %q, request.ID = %q — a grant is never self-authorizing", grant.RequestID, request.ID)
	}
	if stored := approvals.byID[request.ID]; stored.ID == "" {
		t.Error("the approval request was not persisted")
	}
	if _, err := grants.GetGrant(context.Background(), grant.ID); err != nil {
		t.Errorf("GetGrant: %v", err)
	}

	// The requester never authors the prose an approver reads (ADR-0027): the
	// summary is the Relay's own rendering of the Scope.
	if request.Summary != grant.Summary || grant.Summary != approval.SummarizeScope(grant.Scope, grant.StartsAt, grant.ExpiresAt, grant.MaxUses) {
		t.Errorf("summary = %q, want the Relay-authored scope summary on both the grant and its request", grant.Summary)
	}
	if request.PlanHash != approval.HashScope(grant.Scope, grant.StartsAt, grant.ExpiresAt, grant.MaxUses) {
		t.Error("the request must bind to a hash over the SCOPE, so an answer cannot be replayed onto moved walls")
	}

	var requested *AuditEntry
	for i := range audit.entries {
		if audit.entries[i].Kind == AuditKindApprovalGrantRequested {
			requested = &audit.entries[i]
		}
	}
	if requested == nil {
		t.Fatal("no AuditKindApprovalGrantRequested entry for the grant request")
	}
	// #546: and emphatically NOT filed as an ordinary park. Asserted rather
	// than assumed, because the two were the same kind until this change and a
	// revert would otherwise only fail the positive check above.
	for i := range audit.entries {
		if audit.entries[i].Kind == AuditKindApprovalRequested {
			t.Errorf("the grant request was ALSO filed as an ordinary park (%+v) — a Grant is "+
				"an ask for standing authority, not one Plan waiting for one answer",
				audit.entries[i])
		}
	}
	if requested.GrantID != grant.ID || requested.ApprovalID != request.ID {
		t.Errorf("audit entry = %+v, want it to name both the grant and its authorizing request", requested)
	}
}

// TestRequestGrantDerivesTheStrictestRequirement is the central anti-escalation
// property: a Grant costs what the strictest dispatch it could release costs.
//
// The gate here asks for two people only at fan-out 10+. A Scope whose CEILING
// is 10 can release such a dispatch, so its own approval needs two people —
// even though most dispatches it covers would have needed only one.
func TestRequestGrantDerivesTheStrictestRequirement(t *testing.T) {
	gate, err := approval.NewGate([]approval.Rule{
		{Name: "any-mutate", Match: approval.Match{RiskClass: jobs.RiskClassMutate},
			Require: approval.Requirement{Count: 1, RequesterAllowed: true, Channel: approval.ChannelInBand, TTL: time.Hour}},
		{Name: "wide-mutate", Match: approval.Match{RiskClass: jobs.RiskClassMutate, MinFanOut: 10},
			Require: approval.Requirement{Count: 2, Channel: approval.ChannelOutOfBand, TTL: time.Hour}},
	})
	if err != nil {
		t.Fatalf("NewGate: %v", err)
	}
	s, _, _, _ := grantMgmtFixture(t, gate, &spyApprovalAuthorizer{})

	in := grantRequestFixture()
	in.Scope.MaxFanOut = 10
	_, wide, err := s.RequestGrant(context.Background(), machineRequester, in)
	if err != nil {
		t.Fatalf("RequestGrant: %v", err)
	}
	if wide.Require.Count != 2 {
		t.Errorf("Count = %d, want 2 — a grant must be at least as strictly approved as the widest dispatch it can release", wide.Require.Count)
	}
	if wide.Require.Channel != approval.ChannelOutOfBand {
		t.Errorf("Channel = %v, want out-of-band from the stricter matching rule", wide.Require.Channel)
	}
	if wide.Require.RequesterAllowed {
		t.Error("RequesterAllowed must be false — false is the stricter value and the strictest matching rule wins")
	}
	if len(wide.MatchedRules) != 2 {
		t.Errorf("MatchedRules = %v, want both rules named so the approver can see why", wide.MatchedRules)
	}

	// The same Scope with a ceiling below the rule's floor never reaches it.
	in.Scope.MaxFanOut = 3
	_, narrow, err := s.RequestGrant(context.Background(), machineRequester, in)
	if err != nil {
		t.Fatalf("RequestGrant (narrow): %v", err)
	}
	if narrow.Require.Count != 1 {
		t.Errorf("Count = %d, want 1 — a ceiling below the rule's floor cannot release a dispatch that rule would gate", narrow.Require.Count)
	}
}

// TestRequestGrantRefusesWhenNothingIsGated: a Grant covering only ungated work
// authorizes nothing, so creating one would leave a live authorization in the
// table for no reason — an object with reach and no purpose.
func TestRequestGrantRefusesWhenNothingIsGated(t *testing.T) {
	gate, err := approval.NewGate([]approval.Rule{{
		Name:    "raw-exec-only",
		Match:   approval.Match{RawExec: true},
		Require: approval.Requirement{Count: 1, Channel: approval.ChannelOutOfBand, TTL: time.Hour},
	}})
	if err != nil {
		t.Fatalf("NewGate: %v", err)
	}
	s, approvals, grants, _ := grantMgmtFixture(t, gate, &spyApprovalAuthorizer{})

	if _, _, err := s.RequestGrant(context.Background(), machineRequester, grantRequestFixture()); !errors.Is(err, ErrGrantCoversNothingGated) {
		t.Fatalf("err = %v, want ErrGrantCoversNothingGated", err)
	}
	if len(approvals.byID) != 0 || len(grants.byID) != 0 {
		t.Error("a refused grant request must leave nothing behind")
	}
}

// TestRequestGrantRoleFloorUsesTheScopeActionKind: a Scope covering Raw Exec is
// checked against the Raw Exec floor, so an operator cannot even ASK for a
// window over the broadest path in the system.
func TestRequestGrantRoleFloorUsesTheScopeActionKind(t *testing.T) {
	authorizer := &spyApprovalAuthorizer{}
	s, _, _, _ := grantMgmtFixture(t, gateEverything(t, 1), authorizer)

	in := grantRequestFixture()
	in.Scope.RawExec = true
	if _, _, err := s.RequestGrant(context.Background(), machineRequester, in); err != nil {
		t.Fatalf("RequestGrant: %v", err)
	}
	if authorizer.kind != jobs.ActionRawExec {
		t.Errorf("authorizer saw kind %v, want ActionRawExec — the floor is the floor for the most powerful thing the grant can release", authorizer.kind)
	}

	authorizer.kind = jobs.ActionKind(0)
	if _, _, err := s.RequestGrant(context.Background(), machineRequester, grantRequestFixture()); err != nil {
		t.Fatalf("RequestGrant (operation): %v", err)
	}
	if authorizer.kind != jobs.ActionOperation {
		t.Errorf("authorizer saw kind %v, want ActionOperation for a structured-only scope", authorizer.kind)
	}
}

// TestRequestGrantRefusedByRoleFloorWritesNothing: the refusal must land before
// any row exists, or a denied request leaves an orphan for someone to find and
// wonder about later.
func TestRequestGrantRefusedByRoleFloorWritesNothing(t *testing.T) {
	denied := errors.New("authz: unauthorized")
	s, approvals, grants, _ := grantMgmtFixture(t, gateEverything(t, 1), &spyApprovalAuthorizer{err: denied})

	if _, _, err := s.RequestGrant(context.Background(), machineRequester, grantRequestFixture()); !errors.Is(err, denied) {
		t.Fatalf("err = %v, want the authorizer's refusal", err)
	}
	if len(approvals.byID) != 0 || len(grants.byID) != 0 {
		t.Error("a role-floor refusal must leave neither a request nor a grant behind")
	}
}

// TestRequestGrantRefusesUnboundedScopes: the walls ARE the security argument
// for grants, so an unbounded one must be impossible to create — and, like the
// role floor, must leave no orphaned approval Request.
func TestRequestGrantRefusesUnboundedScopes(t *testing.T) {
	cases := map[string]func(*GrantRequest){
		"no operations and no raw exec": func(in *GrantRequest) { in.Scope.Operations = nil },
		"no fan-out ceiling":            func(in *GrantRequest) { in.Scope.MaxFanOut = 0 },
		"no risk class":                 func(in *GrantRequest) { in.Scope.RiskClass = jobs.RiskClassUnspecified },
		"no requesting account":         func(in *GrantRequest) { in.Scope.Account = "" },
		"no window":                     func(in *GrantRequest) { in.ExpiresAt = time.Time{} },
		"window beyond the maximum":     func(in *GrantRequest) { in.ExpiresAt = apNow.Add(approval.MaxGrantWindow + time.Minute) },
		"no use limit":                  func(in *GrantRequest) { in.MaxUses = 0 },
		"uses beyond the maximum":       func(in *GrantRequest) { in.MaxUses = approval.MaxGrantUses + 1 },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			s, approvals, grants, _ := grantMgmtFixture(t, gateEverything(t, 1), &spyApprovalAuthorizer{})
			in := grantRequestFixture()
			mutate(&in)

			if _, _, err := s.RequestGrant(context.Background(), machineRequester, in); err == nil {
				t.Fatal("RequestGrant accepted an unbounded grant")
			}
			if len(approvals.byID) != 0 || len(grants.byID) != 0 {
				t.Error("a refused grant request must leave nothing behind")
			}
		})
	}
}

// TestRequestGrantHashChangesWhenTheWallsMove is plan-hash binding applied to a
// Scope: widening any wall must produce a different hash, so an approval of the
// narrow grant is simply not an approval of the wide one.
func TestRequestGrantHashChangesWhenTheWallsMove(t *testing.T) {
	s, _, _, _ := grantMgmtFixture(t, gateEverything(t, 1), &spyApprovalAuthorizer{})

	_, base, err := s.RequestGrant(context.Background(), machineRequester, grantRequestFixture())
	if err != nil {
		t.Fatalf("RequestGrant: %v", err)
	}

	widenings := map[string]func(*GrantRequest){
		"fan-out ceiling": func(in *GrantRequest) { in.Scope.MaxFanOut = 50 },
		"extra operation": func(in *GrantRequest) { in.Scope.Operations = append(in.Scope.Operations, "service.stop") },
		"raw exec":        func(in *GrantRequest) { in.Scope.RawExec = true },
		"longer window":   func(in *GrantRequest) { in.ExpiresAt = apNow.Add(6 * time.Hour) },
		"more uses":       func(in *GrantRequest) { in.MaxUses = 500 },
	}
	for name, widen := range widenings {
		t.Run(name, func(t *testing.T) {
			in := grantRequestFixture()
			widen(&in)
			_, wider, err := s.RequestGrant(context.Background(), machineRequester, in)
			if err != nil {
				t.Fatalf("RequestGrant: %v", err)
			}
			if wider.PlanHash == base.PlanHash {
				t.Errorf("widening the %s did not change the hash; an old approval would carry over to a wider grant", name)
			}
		})
	}
}

// TestRequestGrantDefaultsStartToNow: an unset start means "now", never the
// zero time — a grant starting in 1970 would be one whose window a reader
// cannot reason about.
func TestRequestGrantDefaultsStartToNow(t *testing.T) {
	s, _, _, _ := grantMgmtFixture(t, gateEverything(t, 1), &spyApprovalAuthorizer{})

	grant, _, err := s.RequestGrant(context.Background(), machineRequester, grantRequestFixture())
	if err != nil {
		t.Fatalf("RequestGrant: %v", err)
	}
	if !grant.StartsAt.Equal(apNow) {
		t.Errorf("StartsAt = %v, want %v", grant.StartsAt, apNow)
	}
}

// TestGrantRequestNeverOutlivesItsGrant: the human has until the window closes
// and no longer. An approval landing after the Grant's own expiry authorizes
// nothing, so a Request that outlives its subject is a queue entry whose only
// possible outcome is a no-op.
func TestGrantRequestNeverOutlivesItsGrant(t *testing.T) {
	// The gate's TTL is an hour; the grant's window is fifteen minutes.
	s, _, _, _ := grantMgmtFixture(t, gateEverything(t, 1), &spyApprovalAuthorizer{})

	in := grantRequestFixture()
	in.ExpiresAt = apNow.Add(15 * time.Minute)
	grant, request, err := s.RequestGrant(context.Background(), machineRequester, in)
	if err != nil {
		t.Fatalf("RequestGrant: %v", err)
	}
	if request.ExpiresAt.After(grant.ExpiresAt) {
		t.Errorf("request expires at %v, after the grant's %v", request.ExpiresAt, grant.ExpiresAt)
	}
}

// TestActiveGrantsExcludesRevoked: the queue view answers "what is live right
// now", so a closed window must leave it immediately.
func TestActiveGrantsExcludesRevoked(t *testing.T) {
	s, _, _, _ := grantMgmtFixture(t, gateEverything(t, 1), &spyApprovalAuthorizer{})

	grant, _, err := s.RequestGrant(context.Background(), machineRequester, grantRequestFixture())
	if err != nil {
		t.Fatalf("RequestGrant: %v", err)
	}
	live, err := s.ActiveGrants(context.Background())
	if err != nil {
		t.Fatalf("ActiveGrants: %v", err)
	}
	if len(live) != 1 {
		t.Fatalf("ActiveGrants returned %d, want 1", len(live))
	}

	if _, err := s.RevokeGrant(context.Background(), humanApprover("acct-ana", "ana"), grant.ID, "incident"); err != nil {
		t.Fatalf("RevokeGrant: %v", err)
	}
	live, err = s.ActiveGrants(context.Background())
	if err != nil {
		t.Fatalf("ActiveGrants: %v", err)
	}
	if len(live) != 0 {
		t.Errorf("ActiveGrants returned %d after revocation, want 0", len(live))
	}
}

// TestRevokeGrantAttributesAndAudits: closing a window is an operational act
// with consequences for whoever is relying on it, so it is attributed and
// recorded like any other decision.
func TestRevokeGrantAttributesAndAudits(t *testing.T) {
	s, _, _, audit := grantMgmtFixture(t, gateEverything(t, 1), &spyApprovalAuthorizer{})

	grant, _, err := s.RequestGrant(context.Background(), machineRequester, grantRequestFixture())
	if err != nil {
		t.Fatalf("RequestGrant: %v", err)
	}

	revoked, err := s.RevokeGrant(context.Background(), humanApprover("acct-ana", "ana"), grant.ID, "incident 42")
	if err != nil {
		t.Fatalf("RevokeGrant: %v", err)
	}
	if !revoked.Revoked() || revoked.RevokedBy != "ana" || revoked.RevokeReason != "incident 42" {
		t.Errorf("revoked grant = %+v, want it attributed to ana with the reason", revoked)
	}

	var decided *AuditEntry
	for i := range audit.entries {
		if audit.entries[i].Kind == AuditKindApprovalDecided {
			decided = &audit.entries[i]
		}
	}
	if decided == nil {
		t.Fatal("no audit entry for the revocation")
	}
	if decided.GrantID != grant.ID || decided.Principal.Account != "ana" {
		t.Errorf("audit entry = %+v, want it to name the grant and the revoker", decided)
	}

	// Revoking twice is not a silent no-op: an operator reaching for this is
	// usually mid-incident and needs a truthful answer.
	if _, err := s.RevokeGrant(context.Background(), humanApprover("acct-ana", "ana"), grant.ID, "again"); !errors.Is(err, approval.ErrGrantNotActive) {
		t.Errorf("second revoke: err = %v, want ErrGrantNotActive", err)
	}
}

// TestRevokeGrantRefusedByRoleFloor: revocation carries the same floor as
// approving the grant would have, so it is not a side door for a role that
// could not have opened the window.
func TestRevokeGrantRefusedByRoleFloor(t *testing.T) {
	authorizer := &spyApprovalAuthorizer{}
	s, _, _, _ := grantMgmtFixture(t, gateEverything(t, 1), authorizer)

	grant, _, err := s.RequestGrant(context.Background(), machineRequester, grantRequestFixture())
	if err != nil {
		t.Fatalf("RequestGrant: %v", err)
	}

	denied := errors.New("authz: unauthorized")
	authorizer.err = denied
	if _, err := s.RevokeGrant(context.Background(), humanApprover("acct-viewer", "vi"), grant.ID, "nope"); !errors.Is(err, denied) {
		t.Fatalf("err = %v, want the authorizer's refusal", err)
	}

	authorizer.err = nil
	live, err := s.ActiveGrants(context.Background())
	if err != nil {
		t.Fatalf("ActiveGrants: %v", err)
	}
	if len(live) != 1 {
		t.Error("a refused revocation must leave the grant live")
	}
}

// TestGrantManagementUnavailableWithoutAStore: a surface offering grants against
// a Relay that has not wired them must fail loudly, not silently do nothing.
func TestGrantManagementUnavailableWithoutAStore(t *testing.T) {
	s, _, _ := decideFixture(t, 1, &spyApprovalAuthorizer{})

	if _, _, err := s.RequestGrant(context.Background(), machineRequester, grantRequestFixture()); !errors.Is(err, ErrApprovalUnavailable) {
		t.Errorf("RequestGrant: err = %v, want ErrApprovalUnavailable", err)
	}
	if _, err := s.ActiveGrants(context.Background()); !errors.Is(err, ErrApprovalUnavailable) {
		t.Errorf("ActiveGrants: err = %v, want ErrApprovalUnavailable", err)
	}
	if _, err := s.RevokeGrant(context.Background(), humanApprover("acct-ana", "ana"), "grant-1", "x"); !errors.Is(err, ErrApprovalUnavailable) {
		t.Errorf("RevokeGrant: err = %v, want ErrApprovalUnavailable", err)
	}
	if _, err := s.GrantForApproval(context.Background(), "req-1"); !errors.Is(err, ErrApprovalUnavailable) {
		t.Errorf("GrantForApproval: err = %v, want ErrApprovalUnavailable", err)
	}
}

// TestGrantForApprovalResolvesAGrantFromItsRequest: nothing on a Request marks
// it as a grant request, so this join is the only way a surface can tell that
// the thing a human is being asked to approve is a WINDOW rather than one Plan.
func TestGrantForApprovalResolvesAGrantFromItsRequest(t *testing.T) {
	s, _, _, _ := grantMgmtFixture(t, gateEverything(t, 1), &spyApprovalAuthorizer{})

	grant, request, err := s.RequestGrant(context.Background(), machineRequester, grantRequestFixture())
	if err != nil {
		t.Fatalf("RequestGrant: %v", err)
	}

	got, err := s.GrantForApproval(context.Background(), request.ID)
	if err != nil {
		t.Fatalf("GrantForApproval: %v", err)
	}
	if got.ID != grant.ID {
		t.Errorf("GrantForApproval returned grant %q, want %q", got.ID, grant.ID)
	}
	if got.Scope.MaxFanOut != grant.Scope.MaxFanOut || got.MaxUses != grant.MaxUses {
		t.Errorf("GrantForApproval returned a different Scope: %+v", got.Scope)
	}
}

// TestGrantForApprovalIsNotFoundForAPlainRequest pins the SENTINEL ITSELF
// rather than errors.Is: the documented contract is that
// approval.ErrGrantNotFound travels UNWRAPPED, so a surface can say "this is
// not a Grant request" without matching on text, and errors.Is would also pass
// on a %w wrap that broke that.
func TestGrantForApprovalIsNotFoundForAPlainRequest(t *testing.T) {
	s, _, _, _ := grantMgmtFixture(t, gateEverything(t, 1), &spyApprovalAuthorizer{})

	_, err := s.GrantForApproval(context.Background(), "req-that-is-a-plan")
	if err != approval.ErrGrantNotFound { //nolint:errorlint // the point is that it is UNWRAPPED
		t.Fatalf("err = %v, want the unwrapped approval.ErrGrantNotFound", err)
	}
}

// TestRevokeGrantAuditEntryRecordsNoAnswer (#545): a revocation is not a
// Decision — nobody answered a parked Job — so its audit entry must carry an
// Unrecorded answer and ChannelUnspecified, never something that reads as a
// denial. GrantID (already asserted by TestRevokeGrantAttributesAndAudits) is
// this entry's structural discriminator; this test pins that a revocation is
// not silently filed as a denial alongside it.
func TestRevokeGrantAuditEntryRecordsNoAnswer(t *testing.T) {
	s, _, _, audit := grantMgmtFixture(t, gateEverything(t, 1), &spyApprovalAuthorizer{})

	grant, _, err := s.RequestGrant(context.Background(), machineRequester, grantRequestFixture())
	if err != nil {
		t.Fatalf("RequestGrant: %v", err)
	}
	if _, err := s.RevokeGrant(context.Background(), humanApprover("acct-ana", "ana"), grant.ID, "incident 42"); err != nil {
		t.Fatalf("RevokeGrant: %v", err)
	}

	var revocation *AuditEntry
	for i := range audit.entries {
		if audit.entries[i].Kind == AuditKindApprovalDecided && audit.entries[i].GrantID == grant.ID {
			revocation = &audit.entries[i]
		}
	}
	if revocation == nil {
		t.Fatal("no audit entry for the revocation")
	}
	if revocation.ApprovalAnswer != ApprovalAnswerUnrecorded {
		t.Errorf("revocation ApprovalAnswer = %q, want Unrecorded — a revocation is not a Decision", revocation.ApprovalAnswer)
	}
	if revocation.DecisionChannel != approval.ChannelUnspecified {
		t.Errorf("revocation DecisionChannel = %v, want Unspecified — nobody answered a parked Job", revocation.DecisionChannel)
	}
}
