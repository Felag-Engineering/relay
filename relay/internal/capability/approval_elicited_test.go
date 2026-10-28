package capability

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/Felag-Engineering/relay/relay/internal/approval"
)

// tokenPrincipal is an API-token session of the given Account kind.
func tokenPrincipal(id, name string, kind string) Principal {
	return Principal{AccountID: id, Account: name, Role: "admin", Kind: kind, AuthMethod: AuthMethodAPIToken}
}

func elicitedFixture(t *testing.T, now func() time.Time) (*testSvc, *memApprovals, *spyAuditSink) {
	t.Helper()
	req := approval.Requirement{Count: 1, RequesterAllowed: true, Channel: approval.ChannelInBand, TTL: time.Hour}
	store := newMemApprovals()
	s, auditSink := decideFixtureWithRequirement(t, req, store, &spyApprovalAuthorizer{}, now)
	return s, store, auditSink
}

func lastApprovalReason(auditSink *spyAuditSink) string {
	reason := ""
	for _, e := range auditSink.entries {
		if e.Kind == AuditKindApprovalDecided {
			reason = e.Reason
		}
	}
	return reason
}

// TestElicitedResponderRule_TurnsOnTheSession: the session decides what a
// responder is for, once, in the capability layer.
//
// Proves AP-79, AP-87.
func TestElicitedResponderRule_TurnsOnTheSession(t *testing.T) {
	cases := []struct {
		name string
		p    Principal
		want ResponderRule
	}{
		{"oauth human", Principal{Kind: PrincipalKindHuman, AuthMethod: AuthMethodOAuth}, ResponderIgnored},
		{"oauth machine", Principal{Kind: "machine", AuthMethod: AuthMethodOAuth}, ResponderRequired},
		{"oauth unset kind", Principal{AuthMethod: AuthMethodOAuth}, ResponderRequired},
		{"console session", Principal{Kind: PrincipalKindHuman, AuthMethod: AuthMethodConsoleSession}, ResponderRequired},
		{"unspecified auth method", Principal{Kind: PrincipalKindHuman}, ResponderRequired},
		{"api token human", Principal{Kind: PrincipalKindHuman, AuthMethod: AuthMethodAPIToken}, ResponderRecorded},
		{"api token machine", Principal{Kind: "machine", AuthMethod: AuthMethodAPIToken}, ResponderRecorded},
		{"api token unset kind", Principal{AuthMethod: AuthMethodAPIToken}, ResponderRecorded},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := ElicitedResponderRule(tc.p); got != tc.want {
				t.Errorf("ElicitedResponderRule = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestAnswerElicited_HumanTokenSessionIsTheHumansTokenSessionDecision: an
// elicited answer on a human Account's API-token session counts as that
// Account's decision, with no responder.
//
// Proves AP-87, AP-88.
func TestAnswerElicited_HumanTokenSessionIsTheHumansTokenSessionDecision(t *testing.T) {
	s, _, _ := elicitedFixture(t, func() time.Time { return apNow })
	human := tokenPrincipal("acct-hana", "hana", PrincipalKindHuman)
	parked := park(t, s, human)

	got, err := s.AnswerElicited(context.Background(), human, parked.RequestID, parked.PlanHash, true)
	if err != nil {
		t.Fatalf("AnswerElicited: %v", err)
	}
	if got.State != approval.StateApproved || len(got.Decisions) != 1 {
		t.Fatalf("state = %v with %d decisions, want approved with 1", got.State, len(got.Decisions))
	}
	d := got.Decisions[0]
	if !d.DeciderHuman {
		t.Error("DeciderHuman = false, want true: the human is the decider")
	}
	if d.IdentifiedBy != approval.IdentifiedByAPITokenSession {
		t.Errorf("IdentifiedBy = %v, want api_token_session", d.IdentifiedBy)
	}
	if d.OnBehalfOf != "" {
		t.Errorf("OnBehalfOf = %q, want empty: no responder was sent", d.OnBehalfOf)
	}
}

// TestAnswerElicited_MachineTokenSessionIsMachineSelfConfirmation: a machine
// Account's token-session answer to its own request is accepted, and a
// responder, when sent, is recorded as asserted.
//
// Proves AP-87, AP-88.
func TestAnswerElicited_MachineTokenSessionIsMachineSelfConfirmation(t *testing.T) {
	machine := tokenPrincipal("acct-g", "gleipnir-prod", "machine")

	t.Run("no responder", func(t *testing.T) {
		s, _, _ := elicitedFixture(t, func() time.Time { return apNow })
		parked := park(t, s, machine)
		got, err := s.AnswerElicited(context.Background(), machine, parked.RequestID, parked.PlanHash, true)
		if err != nil {
			t.Fatalf("AnswerElicited: %v", err)
		}
		d := got.Decisions[0]
		if d.DeciderHuman || d.IdentifiedBy != approval.IdentifiedByAPITokenSession || d.OnBehalfOf != "" {
			t.Errorf("decision = %+v, want a machine api_token_session decision with no assertion", d)
		}
	})

	t.Run("with a responder", func(t *testing.T) {
		s, _, _ := elicitedFixture(t, func() time.Time { return apNow })
		parked := park(t, s, machine)
		ctx := WithAssertions(context.Background(), Assertions{OnBehalfOf: "alice"})
		got, err := s.AnswerElicited(ctx, machine, parked.RequestID, parked.PlanHash, true)
		if err != nil {
			t.Fatalf("AnswerElicited: %v", err)
		}
		d := got.Decisions[0]
		if d.OnBehalfOf != "alice" || d.IdentifiedBy != approval.IdentifiedByAPITokenSession {
			t.Errorf("decision = %+v, want OnBehalfOf alice recorded as asserted", d)
		}
	})
}

// TestAnswerElicited_OtherSessionNeedsAResponder: off an API-token session and
// off a human's OAuth session, an answer with no responder is a machine
// self-decision, and nothing is stored or audited.
//
// Proves AP-87.
func TestAnswerElicited_OtherSessionNeedsAResponder(t *testing.T) {
	cases := []struct {
		name string
		p    Principal
	}{
		{"oauth machine", Principal{AccountID: "acct-g", Account: "gleipnir-prod", Role: "admin", Kind: "machine", AuthMethod: AuthMethodOAuth}},
		{"unspecified auth method", Principal{AccountID: "acct-g", Account: "gleipnir-prod", Role: "admin", Kind: PrincipalKindHuman}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s, store, auditSink := elicitedFixture(t, func() time.Time { return apNow })
			parked := park(t, s, tc.p)
			_, err := s.AnswerElicited(context.Background(), tc.p, parked.RequestID, parked.PlanHash, true)
			if !errors.Is(err, approval.ErrMachineSelfDecision) {
				t.Fatalf("err = %v, want ErrMachineSelfDecision", err)
			}
			if got := store.byID[parked.RequestID]; len(got.Decisions) != 0 {
				t.Errorf("decisions stored = %d, want 0", len(got.Decisions))
			}
			if n := countApprovalDecided(auditSink); n != 0 {
				t.Errorf("approval-decided audit entries = %d, want 0", n)
			}
		})
	}
}

// TestAnswerElicited_OAuthHumanSessionClearsAnyAssertion: on a human's OAuth
// session the asserted approver is never recorded.
//
// Proves AP-79.
func TestAnswerElicited_OAuthHumanSessionClearsAnyAssertion(t *testing.T) {
	s, _, _ := elicitedFixture(t, func() time.Time { return apNow })
	human := Principal{AccountID: "acct-ana", Account: "ana", Role: "operator", Kind: PrincipalKindHuman, AuthMethod: AuthMethodOAuth}
	parked := park(t, s, machineRequester)

	ctx := WithAssertions(context.Background(), Assertions{OnBehalfOf: "mallory", SessionRef: "keep"})
	got, err := s.AnswerElicited(ctx, human, parked.RequestID, parked.PlanHash, true)
	if err != nil {
		t.Fatalf("AnswerElicited: %v", err)
	}
	d := got.Decisions[0]
	if d.OnBehalfOf != "" || d.IdentifiedBy != approval.IdentifiedByOAuthSession {
		t.Errorf("decision = %+v, want no asserted approver and oauth_session", d)
	}
}

// TestAnswerElicited_TokenSessionMeetsTheSameRefusals: the token-session
// carve-out relaxes only the responder requirement; pending and unexpired, the
// plan hash and the role floor still apply.
//
// Proves AP-42, AP-46, AP-48, AP-49.
func TestAnswerElicited_TokenSessionMeetsTheSameRefusals(t *testing.T) {
	human := tokenPrincipal("acct-hana", "hana", PrincipalKindHuman)

	t.Run("terminal", func(t *testing.T) {
		s, store, auditSink := elicitedFixture(t, func() time.Time { return apNow })
		parked := park(t, s, machineRequester)
		store.approve(t, parked.RequestID, "acct-other", "other", apNow)
		_, err := s.AnswerElicited(context.Background(), human, parked.RequestID, parked.PlanHash, true)
		if !errors.Is(err, approval.ErrNotPending) {
			t.Fatalf("err = %v, want ErrNotPending", err)
		}
		if n := countApprovalDecided(auditSink); n != 0 {
			t.Errorf("audit entries = %d, want 0", n)
		}
	})

	t.Run("expired", func(t *testing.T) {
		now := apNow
		s, _, auditSink := elicitedFixture(t, func() time.Time { return now })
		parked := park(t, s, machineRequester)
		now = apNow.Add(2 * time.Hour)
		_, err := s.AnswerElicited(context.Background(), human, parked.RequestID, parked.PlanHash, true)
		if !errors.Is(err, approval.ErrNotPending) {
			t.Fatalf("err = %v, want ErrNotPending", err)
		}
		if n := countApprovalDecided(auditSink); n != 0 {
			t.Errorf("audit entries = %d, want 0", n)
		}
	})

	t.Run("wrong plan hash", func(t *testing.T) {
		s, store, auditSink := elicitedFixture(t, func() time.Time { return apNow })
		parked := park(t, s, machineRequester)
		_, err := s.AnswerElicited(context.Background(), human, parked.RequestID, "some-other-plan", true)
		if !errors.Is(err, approval.ErrPlanChanged) {
			t.Fatalf("err = %v, want ErrPlanChanged", err)
		}
		if len(store.byID[parked.RequestID].Decisions) != 0 || countApprovalDecided(auditSink) != 0 {
			t.Error("a refused answer stored or audited something")
		}
	})

	t.Run("role floor", func(t *testing.T) {
		floor := errors.New("below the role floor")
		req := approval.Requirement{Count: 1, RequesterAllowed: true, Channel: approval.ChannelInBand, TTL: time.Hour}
		store := newMemApprovals()
		s, auditSink := decideFixtureWithRequirement(t, req, store, &spyApprovalAuthorizer{err: floor}, func() time.Time { return apNow })
		parked := park(t, s, machineRequester)
		_, err := s.AnswerElicited(context.Background(), human, parked.RequestID, parked.PlanHash, true)
		if !errors.Is(err, floor) {
			t.Fatalf("err = %v, want the authorizer's refusal", err)
		}
		if len(store.byID[parked.RequestID].Decisions) != 0 || countApprovalDecided(auditSink) != 0 {
			t.Error("a refused answer stored or audited something")
		}
	})
}

// TestDecideApproval_TokenCarveOutIsInBandOnly: a machine API-token principal
// deciding its own request out-of-band is a machine self-decision.
//
// Proves AP-11, AP-48.
func TestDecideApproval_TokenCarveOutIsInBandOnly(t *testing.T) {
	s, _, _ := elicitedFixture(t, func() time.Time { return apNow })
	machine := tokenPrincipal("acct-g", "gleipnir-prod", "machine")
	parked := park(t, s, machine)

	_, err := s.DecideApproval(context.Background(), machine, ApprovalDecision{
		RequestID: parked.RequestID, PlanHash: parked.PlanHash, Approve: true, Channel: approval.ChannelOutOfBand,
	})
	if !errors.Is(err, approval.ErrMachineSelfDecision) {
		t.Fatalf("err = %v, want ErrMachineSelfDecision", err)
	}
}

// TestAnswerElicited_RecordsHowTheDeciderWasIdentified: the identification is
// recorded on the Decision and in the audit Reason; an out-of-band decision
// records none.
//
// Proves AP-88.
func TestAnswerElicited_RecordsHowTheDeciderWasIdentified(t *testing.T) {
	cases := []struct {
		name      string
		p         Principal
		assertion string
		want      approval.IdentifiedBy
	}{
		{"oauth human", Principal{AccountID: "acct-ana", Account: "ana", Role: "operator", Kind: PrincipalKindHuman, AuthMethod: AuthMethodOAuth}, "", approval.IdentifiedByOAuthSession},
		{"human token", tokenPrincipal("acct-hana", "hana", PrincipalKindHuman), "", approval.IdentifiedByAPITokenSession},
		{"machine token", tokenPrincipal("acct-g2", "bot", "machine"), "", approval.IdentifiedByAPITokenSession},
		{"oauth machine with a responder", Principal{AccountID: "acct-g3", Account: "bot3", Role: "admin", Kind: "machine", AuthMethod: AuthMethodOAuth}, "alice", approval.IdentifiedByResponderAssertion},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s, _, auditSink := elicitedFixture(t, func() time.Time { return apNow })
			parked := park(t, s, tc.p)
			ctx := context.Background()
			if tc.assertion != "" {
				ctx = WithAssertions(ctx, Assertions{OnBehalfOf: tc.assertion})
			}
			got, err := s.AnswerElicited(ctx, tc.p, parked.RequestID, parked.PlanHash, true)
			if err != nil {
				t.Fatalf("AnswerElicited: %v", err)
			}
			if d := got.Decisions[0]; d.IdentifiedBy != tc.want {
				t.Errorf("IdentifiedBy = %v, want %v", d.IdentifiedBy, tc.want)
			}
			if reason := lastApprovalReason(auditSink); !strings.Contains(reason, "decider identified by "+tc.want.String()) {
				t.Errorf("audit reason %q does not name how the decider was identified", reason)
			}
		})
	}

	t.Run("out-of-band stays unrecorded", func(t *testing.T) {
		s, _, auditSink := elicitedFixture(t, func() time.Time { return apNow })
		parked := park(t, s, machineRequester)
		got, err := s.DecideApproval(context.Background(), humanApprover("acct-ana", "ana"), ApprovalDecision{
			RequestID: parked.RequestID, PlanHash: parked.PlanHash, Approve: true, Channel: approval.ChannelOutOfBand,
		})
		if err != nil {
			t.Fatalf("DecideApproval: %v", err)
		}
		if got.Decisions[0].IdentifiedBy != approval.IdentifiedByUnrecorded {
			t.Errorf("IdentifiedBy = %v, want unrecorded", got.Decisions[0].IdentifiedBy)
		}
		if reason := lastApprovalReason(auditSink); strings.Contains(reason, "decider identified by") {
			t.Errorf("audit reason %q names an identification for an out-of-band decision", reason)
		}
	})
}
