package capability

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/Felag-Engineering/relay/relay/internal/approval"
	"github.com/Felag-Engineering/relay/relay/internal/registry"
)

// askable_test.go is the capability-layer half of the in-band MRTR question
// (docs/specs/approval.md AP-62, AP-81): ParkedError.Askable.

// askCaller is the human requester every test in this file parks as.
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

// gatingRule is a rule that matches every dispatch.
func gatingRule(name string) approval.Rule {
	return approval.Rule{
		Name:    name,
		Match:   approval.Match{},
		Require: approval.Requirement{TTL: time.Hour},
	}
}

// TestParkIsAskableOnlyWhenThisCallCreatedIt: a park this call created is
// askable whatever the rule, since no rule names a channel, an audience or a
// requester exclusion — and an askable park is still a park (AP-2 shape: no
// dispatch, one stored request).
//
// Proves AP-62, AP-81.
func TestParkIsAskableOnlyWhenThisCallCreatedIt(t *testing.T) {
	s, store, disp := askableFixture(t, ruleGate(t, gatingRule("askable")))
	parked := park(t, s, askCaller)

	if !parked.Askable {
		t.Error("Askable = false for a park this call created, want true")
	}
	if disp.called {
		t.Error("dispatcher was called; an askable park is still a park")
	}
	if len(store.byID) != 1 {
		t.Errorf("stored %d requests, want exactly 1", len(store.byID))
	}
}

// TestRedriveOfAPendingRequestIsNotAskable is AP-62: a re-drive that bounces
// off a request already pending is not askable, even though a fresh park is.
func TestRedriveOfAPendingRequestIsNotAskable(t *testing.T) {
	s, store, _ := askableFixture(t, ruleGate(t, gatingRule("askable")))

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

// TestParkWithAFailingAuditIsNotAskable: a park whose audit write failed must
// never report Askable. Service.Run returns errors.Join(ap.parked, auditErr) on
// this path — an unaudited (and therefore un-notified) park must not be
// rendered as a question a surface could ask about.
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
		gate:   ruleGate(t, gatingRule("askable")), approvals: newMemApprovals(), approvalAuthz: &spyApprovalAuthorizer{},
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

// TestAskableOverlappingRulesNameEveryMatch: overlapping rules park once, name
// every rule that matched, and the park is askable (AP-81).
func TestAskableOverlappingRulesNameEveryMatch(t *testing.T) {
	short := gatingRule("rule-a")
	short.Require.TTL = 30 * time.Minute
	s, _, _ := askableFixture(t, ruleGate(t, short, gatingRule("rule-b")))

	parked := park(t, s, askCaller)
	if !parked.Askable {
		t.Error("Askable = false, want true")
	}
	if len(parked.Rules) != 2 {
		t.Errorf("Rules = %v, want both matched rules named", parked.Rules)
	}
	if want := apNow.Add(30 * time.Minute); !parked.ExpiresAt.Equal(want) {
		t.Errorf("ExpiresAt = %v, want %v: the shortest ttl wins", parked.ExpiresAt, want)
	}
}
