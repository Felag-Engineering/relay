package approval

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/jobs"
)

var t0 = time.Date(2026, 8, 14, 12, 0, 0, 0, time.UTC)

func req(count int, requesterAllowed bool, audience ...string) Requirement {
	return Requirement{Count: count, RequesterAllowed: requesterAllowed, Audience: audience, Channel: ChannelOutOfBand, TTL: time.Hour}
}

func newTestRequest(t *testing.T, r Requirement) Request {
	t.Helper()
	return NewRequest("req-1", "hash-abc", "acct-mike", "mike", PlanSummary{}, []string{"rule"}, r, t0)
}

func approveBy(id, name string) Decision {
	return Decision{AccountID: id, Account: name, Approve: true, Channel: ChannelOutOfBand, PlanHash: "hash-abc", At: t0.Add(time.Minute)}
}

// --- the count:1 happy path, and that it is not satisfied before it is met ---

func TestSingleApprovalSatisfies(t *testing.T) {
	r := newTestRequest(t, req(1, true))
	if r.Satisfied(t0) {
		t.Fatal("a freshly parked Request must not be satisfied")
	}

	r, err := r.Decide(approveBy("acct-ana", "ana"), t0.Add(time.Minute))
	if err != nil {
		t.Fatalf("Decide: %v", err)
	}
	if r.State != StateApproved {
		t.Errorf("State = %v, want approved", r.State)
	}
	if !r.Satisfied(t0.Add(2 * time.Minute)) {
		t.Error("an approved, unexpired Request must be satisfied")
	}
}

// TestQuorumNeedsDistinctDeciders is the test that makes count:2 mean something.
// Without the duplicate-decider guard, one approver clicking twice satisfies a
// two-person rule, and the whole separation-of-duties tier is decoration.
func TestQuorumNeedsDistinctDeciders(t *testing.T) {
	r := newTestRequest(t, req(2, true))

	r, err := r.Decide(approveBy("acct-ana", "ana"), t0.Add(time.Minute))
	if err != nil {
		t.Fatalf("first approval: %v", err)
	}
	if r.State != StatePending {
		t.Fatalf("State = %v after 1 of 2, want pending", r.State)
	}
	if got := r.Progress(); got != "1 of 2" {
		t.Errorf("Progress() = %q, want %q", got, "1 of 2")
	}

	if _, err := r.Decide(approveBy("acct-ana", "ana"), t0.Add(2*time.Minute)); !errors.Is(err, ErrDuplicateDecider) {
		t.Fatalf("second approval by the SAME account: err = %v, want ErrDuplicateDecider", err)
	}

	r, err = r.Decide(approveBy("acct-bo", "bo"), t0.Add(3*time.Minute))
	if err != nil {
		t.Fatalf("second approval by a distinct account: %v", err)
	}
	if r.State != StateApproved {
		t.Errorf("State = %v after 2 of 2, want approved", r.State)
	}
}

// TestRequesterCannotApproveOwnRequest pins the two-person tier's whole point.
func TestRequesterCannotApproveOwnRequest(t *testing.T) {
	r := newTestRequest(t, req(1, false)) // requested by acct-mike

	_, err := r.Decide(approveBy("acct-mike", "mike"), t0.Add(time.Minute))
	if !errors.Is(err, ErrRequesterExcluded) {
		t.Fatalf("requester approving their own request: err = %v, want ErrRequesterExcluded", err)
	}

	if _, err := r.Decide(approveBy("acct-ana", "ana"), t0.Add(time.Minute)); err != nil {
		t.Fatalf("a different account must be able to approve: %v", err)
	}
}

// TestDenyIsTerminalAndBeatsApproval mirrors Policy's deny-beats-allow: a second
// approver must not be able to override a colleague's refusal.
func TestDenyIsTerminalAndBeatsApproval(t *testing.T) {
	r := newTestRequest(t, req(2, true))

	r, err := r.Decide(approveBy("acct-ana", "ana"), t0.Add(time.Minute))
	if err != nil {
		t.Fatalf("approve: %v", err)
	}
	deny := approveBy("acct-bo", "bo")
	deny.Approve = false
	r, err = r.Decide(deny, t0.Add(2*time.Minute))
	if err != nil {
		t.Fatalf("deny: %v", err)
	}
	if r.State != StateDenied {
		t.Fatalf("State = %v, want denied", r.State)
	}
	if r.Satisfied(t0.Add(3 * time.Minute)) {
		t.Error("a denied Request must never be satisfied")
	}
	if _, err := r.Decide(approveBy("acct-cy", "cy"), t0.Add(4*time.Minute)); !errors.Is(err, ErrNotPending) {
		t.Errorf("a third approver after a denial: err = %v, want ErrNotPending", err)
	}
}

// TestExpiredRequestIsNotDecidableOrSatisfiable covers the sweeper-outage case:
// a Request past its deadline must read as expired to EVERY caller, whether or
// not anything has updated its stored state.
func TestExpiredRequestIsNotDecidableOrSatisfiable(t *testing.T) {
	r := newTestRequest(t, req(1, true)) // TTL 1h

	late := t0.Add(2 * time.Hour)
	if !r.Expired(late) {
		t.Fatal("a Request past its deadline must report Expired")
	}
	if _, err := r.Decide(approveBy("acct-ana", "ana"), late); !errors.Is(err, ErrNotPending) {
		t.Errorf("deciding an expired Request: err = %v, want ErrNotPending", err)
	}

	// And an approval granted in time does not stay redeemable forever.
	fresh := newTestRequest(t, req(1, true))
	fresh, err := fresh.Decide(approveBy("acct-ana", "ana"), t0.Add(time.Minute))
	if err != nil {
		t.Fatalf("Decide: %v", err)
	}
	if !fresh.Satisfied(t0.Add(2 * time.Minute)) {
		t.Fatal("approved in-window must be satisfied")
	}
	if fresh.Satisfied(late) {
		t.Error("an approval must stop being redeemable after the deadline")
	}
}

// TestDecisionMustCiteTheRequestsPlanHash stops a decision being replayed onto
// a different Plan.
func TestDecisionMustCiteTheRequestsPlanHash(t *testing.T) {
	r := newTestRequest(t, req(1, true))
	d := approveBy("acct-ana", "ana")
	d.PlanHash = "hash-something-else"

	if _, err := r.Decide(d, t0.Add(time.Minute)); !errors.Is(err, ErrPlanChanged) {
		t.Fatalf("decision citing another Plan: err = %v, want ErrPlanChanged", err)
	}
}

func TestAudienceIsEnforced(t *testing.T) {
	r := newTestRequest(t, req(1, true, "ana", "bo"))

	if _, err := r.Decide(approveBy("acct-cy", "cy"), t0.Add(time.Minute)); !errors.Is(err, ErrNotInAudience) {
		t.Fatalf("out-of-audience decider: err = %v, want ErrNotInAudience", err)
	}
	if _, err := r.Decide(approveBy("acct-ana", "ANA"), t0.Add(time.Minute)); err != nil {
		t.Errorf("in-audience decider (case-insensitive): %v", err)
	}
}

// --- Requirement normalization: the fail-closed defaults ---

func TestUnstatedChannelDefaultsToOutOfBand(t *testing.T) {
	got := Requirement{Count: 1}.normalized()
	if got.Channel != ChannelOutOfBand {
		t.Errorf("Channel = %v, want out-of-band — an unstated channel must never silently mean 'trust the harness'", got.Channel)
	}
	if got.TTL != DefaultTTL {
		t.Errorf("TTL = %v, want DefaultTTL — every Request must expire", got.TTL)
	}
}

// --- Gate evaluation ---

func mutateDispatch(fanOut int) Dispatch {
	return Dispatch{RiskClass: jobs.RiskClassMutate, FanOut: fanOut, Namespaces: []string{"node"}, Account: "gleipnir-prod", Operation: "service.restart"}
}

func TestEmptyGateGatesNothing(t *testing.T) {
	g, err := NewGate(nil)
	if err != nil {
		t.Fatalf("NewGate: %v", err)
	}
	if _, _, gated := g.Evaluate(mutateDispatch(500)); gated {
		t.Error("an empty Gate must gate nothing — that is a deployment with no approval rules")
	}
	var nilGate *Gate
	if _, _, gated := nilGate.Evaluate(mutateDispatch(500)); gated {
		t.Error("a nil Gate must gate nothing rather than panic")
	}
}

func TestGateMatchesOnRiskClassAndFanOut(t *testing.T) {
	g, err := NewGate([]Rule{{
		Name:    "big-mutates",
		Match:   Match{RiskClass: jobs.RiskClassMutate, MinFanOut: 10},
		Require: req(1, true),
	}})
	if err != nil {
		t.Fatalf("NewGate: %v", err)
	}

	if _, _, gated := g.Evaluate(mutateDispatch(9)); gated {
		t.Error("fan-out 9 must not match MinFanOut 10")
	}
	_, rules, gated := g.Evaluate(mutateDispatch(10))
	if !gated {
		t.Fatal("fan-out 10 must match MinFanOut 10")
	}
	if len(rules) != 1 || rules[0] != "big-mutates" {
		t.Errorf("rules = %v, want [big-mutates] — a gate must be able to say which rule fired", rules)
	}

	read := mutateDispatch(50)
	read.RiskClass = jobs.RiskClassRead
	if _, _, gated := g.Evaluate(read); gated {
		t.Error("a read-class dispatch must not match a mutate-class rule")
	}
}

// TestOverlappingRulesMergeToTheStrictest is the property that makes rule
// authoring safe: adding a rule can only ever tighten the outcome, so an
// operator cannot accidentally weaken an existing rule by writing a broader one.
func TestOverlappingRulesMergeToTheStrictest(t *testing.T) {
	g, err := NewGate([]Rule{
		{
			Name:    "loose",
			Match:   Match{RiskClass: jobs.RiskClassMutate},
			Require: Requirement{Count: 1, RequesterAllowed: true, Channel: ChannelInBand, TTL: 8 * time.Hour},
		},
		{
			Name:    "strict",
			Match:   Match{MinFanOut: 10},
			Require: Requirement{Count: 2, RequesterAllowed: false, Channel: ChannelOutOfBand, TTL: time.Hour},
		},
	})
	if err != nil {
		t.Fatalf("NewGate: %v", err)
	}

	got, rules, gated := g.Evaluate(mutateDispatch(50))
	if !gated {
		t.Fatal("both rules match, so the dispatch must be gated")
	}
	if got.Count != 2 {
		t.Errorf("Count = %d, want 2 (the stricter)", got.Count)
	}
	if got.RequesterAllowed {
		t.Error("RequesterAllowed = true, want false (the stricter)")
	}
	if got.Channel != ChannelOutOfBand {
		t.Errorf("Channel = %v, want out-of-band (the stricter)", got.Channel)
	}
	if got.TTL != time.Hour {
		t.Errorf("TTL = %v, want 1h (the shorter window is the narrower one)", got.TTL)
	}
	if len(rules) != 2 {
		t.Errorf("rules = %v, want both named", rules)
	}
}

// TestRuleOrderDoesNotMatter is the corollary: unlike a firewall ruleset, a
// permissive rule listed first cannot shadow a strict one listed later.
func TestRuleOrderDoesNotMatter(t *testing.T) {
	loose := Rule{Name: "loose", Match: Match{RiskClass: jobs.RiskClassMutate}, Require: Requirement{Count: 1, RequesterAllowed: true, Channel: ChannelInBand, TTL: 8 * time.Hour}}
	strict := Rule{Name: "strict", Match: Match{MinFanOut: 10}, Require: Requirement{Count: 2, Channel: ChannelOutOfBand, TTL: time.Hour}}

	forward, err := NewGate([]Rule{loose, strict})
	if err != nil {
		t.Fatalf("NewGate: %v", err)
	}
	reverse, err := NewGate([]Rule{strict, loose})
	if err != nil {
		t.Fatalf("NewGate: %v", err)
	}

	a, _, _ := forward.Evaluate(mutateDispatch(50))
	b, _, _ := reverse.Evaluate(mutateDispatch(50))
	if a.Count != b.Count || a.RequesterAllowed != b.RequesterAllowed || a.Channel != b.Channel || a.TTL != b.TTL {
		t.Errorf("rule order changed the outcome: %+v vs %+v", a, b)
	}
}

func TestUnsatisfiableRuleIsRejectedAtLoad(t *testing.T) {
	_, err := NewGate([]Rule{{
		Name:    "impossible",
		Require: Requirement{Count: 2, Audience: []string{"only-ana"}},
	}})
	if err == nil {
		t.Fatal("count 2 with a single-member audience can never be satisfied and must be rejected at load")
	}
	if !strings.Contains(err.Error(), "distinct deciders") {
		t.Errorf("error = %q, want it to explain why", err)
	}
}

func TestDuplicateRuleNamesRejected(t *testing.T) {
	_, err := NewGate([]Rule{
		{Name: "dup", Require: req(1, true)},
		{Name: "DUP", Require: req(1, true)},
	})
	if err == nil {
		t.Fatal("duplicate rule names must be rejected — the name is how a park explains itself")
	}
}
