package capability

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/approval"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/registry"
)

// askable_test.go is #723's capability-layer half of the in-band MRTR
// question (docs/specs/approval.md AP-61, AP-62, AP-69): ParkedError.Askable.

// askCaller is the human requester every test in this file parks as, and the
// Account most of these Requirements are (or are not) written to admit.
var askCaller = Principal{AccountID: "acct-ana", Account: "ana", Role: "operator", Kind: PrincipalKindHuman}

// ruleGate wraps approval.NewGate, failing the test rather than the assertion
// on a malformed rule — every rule literal in this file is meant to load.
func ruleGate(t *testing.T, rules ...approval.Rule) ApprovalGate {
	t.Helper()
	g, err := approval.NewGate(rules)
	if err != nil {
		t.Fatalf("NewGate: %v", err)
	}
	return g
}

// askableFixture is approvalFixture's shape, fixed to one Node and apNow:
// every test here is about the gate's decision, not about fan-out or the
// clock.
func askableFixture(t *testing.T, gate ApprovalGate) (*testSvc, *memApprovals, *spyDispatcher) {
	t.Helper()
	reg := registry.NewInMemory()
	if _, err := reg.Upsert(registry.Report{NodeID: "node-a"}); err != nil {
		t.Fatalf("seed registry: %v", err)
	}
	store := newMemApprovals()
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
	return s, store, disp
}

// inBandRule is the askable baseline every negative test flips one term of:
// in-band, requester allowed, unrestricted audience.
func inBandRule(name string) approval.Rule {
	return approval.Rule{
		Name:  name,
		Match: approval.Match{},
		Require: approval.Requirement{
			Count: 1, RequesterAllowed: true, Channel: approval.ChannelInBand, TTL: time.Hour,
		},
	}
}

// TestParkIsAskableOnlyForAnInBandCreatedParkTheCallerCouldAnswer is AP-61's
// positive direction: every term holds, so the park is askable — and an
// askable park is still a park (AP-2 shape: no dispatch, one stored request).
func TestParkIsAskableOnlyForAnInBandCreatedParkTheCallerCouldAnswer(t *testing.T) {
	for _, tc := range []struct {
		name     string
		audience []string
	}{
		{"unrestricted audience", nil},
		{"audience admits the caller case-insensitively", []string{"ANA", "bob"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rule := inBandRule("askable")
			rule.Require.Audience = tc.audience

			s, store, disp := askableFixture(t, ruleGate(t, rule))
			parked := park(t, s, askCaller)

			if !parked.Askable {
				t.Error("Askable = false, want true")
			}
			if disp.called {
				t.Error("dispatcher was called; an askable park is still a park")
			}
			if len(store.byID) != 1 {
				t.Errorf("stored %d requests, want exactly 1", len(store.byID))
			}
		})
	}
}

// fixedRequirementGate is a minimal ApprovalGate returning req verbatim,
// gated — the one shape a real *approval.Gate can never produce (a rule's
// Channel is always normalized away from Unspecified before it is stored),
// used only to prove Askable fails closed if it ever saw one.
type fixedRequirementGate struct {
	req   approval.Requirement
	rules []string
}

func (g fixedRequirementGate) Evaluate(approval.Dispatch) (approval.Requirement, []string, bool) {
	return g.req, g.rules, true
}

// TestOutOfBandParkIsNeverAskable is AP-69: out-of-band evidence can never be
// satisfied by an in-band answer, so it is never offered as one.
func TestOutOfBandParkIsNeverAskable(t *testing.T) {
	rule := inBandRule("out-of-band")
	rule.Require.Channel = approval.ChannelOutOfBand

	s, _, _ := askableFixture(t, ruleGate(t, rule))
	parked := park(t, s, askCaller)
	if parked.Askable {
		t.Error("Askable = true for an out-of-band rule, want false (AP-69)")
	}

	t.Run("unspecified channel fails closed", func(t *testing.T) {
		gate := fixedRequirementGate{
			req: approval.Requirement{
				Count: 1, RequesterAllowed: true, Channel: approval.ChannelUnspecified, TTL: time.Hour,
			},
			rules: []string{"unspecified"},
		}
		s, _, _ := askableFixture(t, gate)
		parked := park(t, s, askCaller)
		if parked.Askable {
			t.Error("Askable = true for a Channel Unspecified Requirement, want false — normalization lands it out-of-band")
		}
	})

	t.Run("askableBy itself fails closed on an unspecified channel", func(t *testing.T) {
		// Direct unit-level check of the channel term, bypassing Service and
		// Gate.Evaluate's normalization entirely: a Request whose Require
		// somehow carries ChannelUnspecified — set here after construction,
		// since NewRequest itself normalizes it away — must still read as not
		// askable rather than as satisfiable.
		r := approval.NewRequest("req-1", "hash-1", askCaller.AccountID, askCaller.Account, mutateAct(),
			[]string{"node-a"}, approval.SelectorShape{}, []string{"rule"},
			approval.Requirement{Count: 1, RequesterAllowed: true, Channel: approval.ChannelInBand, TTL: time.Hour},
			apNow)
		r.Require.Channel = approval.ChannelUnspecified
		if askableBy(r, askCaller) {
			t.Error("askableBy = true for Channel Unspecified, want false")
		}
	})
}

// TestRequesterExcludedParkIsNotAskable is AP-61's requester-exclusion term:
// an in-band answer is authenticated as the requesting session's own Account,
// so a rule that refuses the requester unconditionally refuses an in-band
// answer too.
func TestRequesterExcludedParkIsNotAskable(t *testing.T) {
	rule := inBandRule("requester-excluded")
	rule.Require.RequesterAllowed = false

	s, _, _ := askableFixture(t, ruleGate(t, rule))
	parked := park(t, s, askCaller)
	if parked.Askable {
		t.Error("Askable = true for a requester-excluded rule, want false (AP-61)")
	}
}

// TestAudienceThatOmitsTheCallerIsNotAskable is AP-61's audience term.
func TestAudienceThatOmitsTheCallerIsNotAskable(t *testing.T) {
	rule := inBandRule("audience-excludes-caller")
	rule.Require.Audience = []string{"bob", "carol"}

	s, _, _ := askableFixture(t, ruleGate(t, rule))
	parked := park(t, s, askCaller)
	if parked.Askable {
		t.Error("Askable = true for an audience that omits the caller, want false (AP-61)")
	}
}

// TestRedriveOfAPendingRequestIsNotAskable is AP-62: a re-drive that bounces
// off a request already pending is not askable, even though every other term
// would hold for a fresh park.
func TestRedriveOfAPendingRequestIsNotAskable(t *testing.T) {
	s, store, _ := askableFixture(t, ruleGate(t, inBandRule("askable")))

	first := park(t, s, askCaller)
	if !first.Askable {
		t.Fatal("first park: Askable = false, want true")
	}

	second := park(t, s, askCaller)
	if second.RequestID != first.RequestID {
		t.Fatalf("second park created a new request (%q), want the same one (%q)", second.RequestID, first.RequestID)
	}
	if second.Askable {
		t.Error("second park: Askable = true for a re-drive of an already-pending request, want false (AP-62)")
	}
	if len(store.byID) != 1 {
		t.Errorf("stored %d requests after two drives of one Plan, want 1", len(store.byID))
	}
}

// TestPartialQuorumRedriveIsNotAskable is AP-62 under count:2 — a partial
// quorum still bounces off a pending request, and the boolean does not read
// as "askable" merely because a slot remains open.
func TestPartialQuorumRedriveIsNotAskable(t *testing.T) {
	rule := inBandRule("quorum-2")
	rule.Require.Count = 2

	s, _, _ := askableFixture(t, ruleGate(t, rule))

	first := park(t, s, askCaller)
	if !first.Askable {
		t.Fatal("first park: Askable = false, want true")
	}

	updated, err := s.DecideApproval(context.Background(), askCaller, ApprovalDecision{
		RequestID: first.RequestID, PlanHash: first.PlanHash, Approve: true, Channel: approval.ChannelInBand,
	})
	if err != nil {
		t.Fatalf("DecideApproval (self-confirmation, requester allowed): %v", err)
	}
	if updated.State != approval.StatePending {
		t.Fatalf("State = %v, want still pending after 1 of 2", updated.State)
	}
	if got := updated.Progress(); got != "1 of 2" {
		t.Fatalf("Progress = %q, want %q", got, "1 of 2")
	}

	second := park(t, s, askCaller)
	if second.RequestID != first.RequestID {
		t.Fatalf("re-drive created a new request (%q), want the same one (%q)", second.RequestID, first.RequestID)
	}
	if second.Askable {
		t.Error("re-drive after a partial quorum: Askable = true, want false")
	}
}

// TestParkWithAFailingAuditIsNotAskable is the plan-review adoption for #723:
// a park whose audit write failed must never report Askable. Service.Run
// returns errors.Join(ap.parked, auditErr) on this path — an unaudited (and
// therefore un-notified) park must not be rendered as a question a surface
// could ask about.
func TestParkWithAFailingAuditIsNotAskable(t *testing.T) {
	reg := registry.NewInMemory()
	if _, err := reg.Upsert(registry.Report{NodeID: "node-a"}); err != nil {
		t.Fatalf("seed registry: %v", err)
	}
	audit := &spyAuditSink{err: errors.New("audit store is down")}
	s := build(t, seams{reg: reg,
		authz:  &spyAuthorizer{},
		cap:    &spyCapChecker{},
		audit:  audit,
		freeze: &fakeFreezeStore{},
		gate:   ruleGate(t, inBandRule("askable")), approvals: newMemApprovals(), approvalAuthz: &spyApprovalAuthorizer{},
		now: func() time.Time { return apNow },
	})
	s.disp = &spyDispatcher{jobID: "job-1"}

	_, err := s.Run(context.Background(), askCaller, Selector{}, mutateAct())
	var parked *ParkedError
	if !errors.As(err, &parked) {
		t.Fatalf("Run: err = %v, want a *ParkedError joined with the audit-write failure", err)
	}
	if parked.Askable {
		t.Error("Askable = true for a park whose audit write failed, want false")
	}
}

// TestAskableReadsTheMergedRequirement proves the boolean is computed from
// the Requirement Gate.Evaluate returns AFTER merging every matching rule
// (mergeStricter), never from one rule in isolation — case c is askable
// although its first rule alone is not, because the audience UNION admits the
// caller.
func TestAskableReadsTheMergedRequirement(t *testing.T) {
	for _, tc := range []struct {
		name    string
		rules   []approval.Rule
		askable bool
	}{
		{
			name: "an out-of-band rule wins the merge",
			rules: []approval.Rule{
				inBandRule("rule-a"),
				func() approval.Rule {
					r := inBandRule("rule-b")
					r.Require.Channel = approval.ChannelOutOfBand
					return r
				}(),
			},
			askable: false,
		},
		{
			name: "a requester-excluded rule wins the merge",
			rules: []approval.Rule{
				inBandRule("rule-a"),
				func() approval.Rule { r := inBandRule("rule-b"); r.Require.RequesterAllowed = false; return r }(),
			},
			askable: false,
		},
		{
			name: "the union of two restricted audiences admits the caller",
			rules: []approval.Rule{
				func() approval.Rule { r := inBandRule("rule-a"); r.Require.Audience = []string{"bob"}; return r }(),
				func() approval.Rule { r := inBandRule("rule-b"); r.Require.Audience = []string{"ana"}; return r }(),
			},
			askable: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, _, _ := askableFixture(t, ruleGate(t, tc.rules...))
			parked := park(t, s, askCaller)
			if parked.Askable != tc.askable {
				t.Errorf("Askable = %v, want %v", parked.Askable, tc.askable)
			}
			if len(parked.Rules) != 2 {
				t.Errorf("Rules = %v, want both matched rules named", parked.Rules)
			}
		})
	}
}

// TestAskableAudienceReadsAsDecideDoes pins askableBy's audience mirror to the
// domain's own reading (Request.inAudience, exercised here through Decide):
// if a later change to inAudience's semantics is not mirrored here, this test
// is the one that fails.
func TestAskableAudienceReadsAsDecideDoes(t *testing.T) {
	newReq := func(audience []string) approval.Request {
		return approval.NewRequest("req-1", "hash-1", askCaller.AccountID, askCaller.Account, mutateAct(),
			[]string{"node-a"}, approval.SelectorShape{}, []string{"rule"},
			approval.Requirement{Count: 1, RequesterAllowed: true, Channel: approval.ChannelInBand, Audience: audience},
			apNow)
	}
	// AccountID "acct-other" keeps Decide's requester-exclusion branch out of
	// the way, so only the audience term is under test.
	decide := func(r approval.Request) error {
		_, err := r.Decide(approval.Decision{
			AccountID: "acct-other", Account: askCaller.Account, Approve: true,
			Channel: approval.ChannelInBand, PlanHash: r.PlanHash, DeciderHuman: true, At: apNow,
		}, apNow)
		return err
	}

	for _, audience := range [][]string{
		nil, {}, {"ana"}, {"ANA"}, {"bob"}, {"bob", "ana"},
		// " ana " is not blank (ValidateAudience trims before checking), so
		// it is a well-formed entry rather than a malformed one — but
		// EqualFold does not trim, so it does not match "ana" either. This
		// is the row that would catch a mirror that trimmed before comparing
		// where inAudience does not.
		{" ana "},
	} {
		t.Run(fmt.Sprintf("audience=%v", audience), func(t *testing.T) {
			r := newReq(audience)
			want := !errors.Is(decide(r), approval.ErrNotInAudience)
			if got := askableBy(r, askCaller); got != want {
				t.Errorf("askableBy = %v, want %v (Decide did NOT return ErrNotInAudience = %v)", got, want, want)
			}
		})
	}

	t.Run("a whitespace-padded entry is malformed and admits no one", func(t *testing.T) {
		r := newReq(nil)
		// NewGate refuses a blank entry (Rule.Validate), so it is set directly
		// here — a real *approval.Gate can never produce this, but a stored
		// row somehow carrying one must still fail closed (see
		// Requirement.AudienceMalformed).
		r.Require.Audience = []string{"ana", " "}
		if askableBy(r, askCaller) {
			t.Error("askableBy = true for a malformed audience, want false")
		}
		if err := decide(r); !errors.Is(err, approval.ErrNotInAudience) {
			t.Errorf("Decide err = %v, want ErrNotInAudience", err)
		}
	})
}
