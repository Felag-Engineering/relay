package approval

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/jobs"
)

var t0 = time.Date(2026, 8, 14, 12, 0, 0, 0, time.UTC)

// testAction is the Action every fixture Request is built over: a structured
// Operation, so the stored ActionKind is a real one and the role floor these
// tests do not exercise still has something truthful to be computed from.
var testAction = jobs.Action{
	Kind:          jobs.ActionOperation,
	OperationName: "service.restart",
	OperationArgs: map[string]string{"service": "nginx"},
	RiskClass:     jobs.RiskClassMutate,
}

func req(count int, requesterAllowed bool, audience ...string) Requirement {
	return Requirement{Count: count, RequesterAllowed: requesterAllowed, Audience: audience, Channel: ChannelOutOfBand, TTL: time.Hour}
}

func newTestRequest(t *testing.T, r Requirement) Request {
	t.Helper()
	return NewRequest("req-1", "hash-abc", "acct-mike", "mike", testAction, []string{"node-a"}, SelectorShape{}, []string{"rule"}, r, t0)
}

func approveBy(id, name string) Decision {
	return Decision{AccountID: id, Account: name, Approve: true, Channel: ChannelOutOfBand, PlanHash: "hash-abc", DeciderHuman: true, At: t0.Add(time.Minute)}
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

// --- #270: the rules that make a decision trustworthy ---

// TestMachineCannotConfirmItself pins ADR-0027's ladder rung 2 as HUMAN-ONLY,
// and pins it against the strongest configuration an operator could write in
// the other direction: requester_allowed: true.
//
// If this ever passes for a machine, an AI-agent can approve its own dispatch
// and the entire callout is decoration — which is why the rule lives in the
// domain rather than in whichever surface happened to remember it.
func TestMachineCannotConfirmItself(t *testing.T) {
	r := newTestRequest(t, req(1, true)) // requester_allowed: true

	machine := Decision{
		AccountID: "acct-mike", Account: "mike", Approve: true,
		Channel: ChannelOutOfBand, PlanHash: "hash-abc", DeciderHuman: false,
		At: t0.Add(time.Minute),
	}
	if _, err := r.Decide(machine, t0.Add(time.Minute)); !errors.Is(err, ErrMachineSelfDecision) {
		t.Fatalf("err = %v, want ErrMachineSelfDecision — a machine may never satisfy its own gate", err)
	}

	// The same Account, same rule, as a human: rung 2 is open.
	human := machine
	human.DeciderHuman = true
	if _, err := r.Decide(human, t0.Add(time.Minute)); err != nil {
		t.Fatalf("human self-confirmation under requester_allowed: true = %v, want it permitted", err)
	}
}

// TestMachineMayDecideSomeoneElsesRequest: the restriction is on deciding your
// OWN request, not on machine Accounts generally. An approval bridge that holds
// its own credential is a legitimate deployment; what it can never do is answer
// for the Account that asked.
func TestMachineMayDecideSomeoneElsesRequest(t *testing.T) {
	r := newTestRequest(t, req(1, false))

	other := Decision{
		AccountID: "acct-bridge", Account: "bridge", Approve: true,
		Channel: ChannelOutOfBand, PlanHash: "hash-abc", DeciderHuman: false,
		At: t0.Add(time.Minute),
	}
	updated, err := r.Decide(other, t0.Add(time.Minute))
	if err != nil {
		t.Fatalf("Decide: %v", err)
	}
	if updated.State != StateApproved {
		t.Errorf("State = %v, want approved", updated.State)
	}
}

// TestWeakChannelIsRefused: an in-band answer cannot satisfy a rule that asked
// for out-of-band. In-band is an assumption about the client; out-of-band is
// evidence, and a rule that asked for evidence must not take an assumption.
func TestWeakChannelIsRefused(t *testing.T) {
	r := newTestRequest(t, req(1, false)) // req() uses ChannelOutOfBand

	inBand := Decision{
		AccountID: "acct-ana", Account: "ana", Approve: true,
		Channel: ChannelInBand, PlanHash: "hash-abc", DeciderHuman: true,
		At: t0.Add(time.Minute),
	}
	if _, err := r.Decide(inBand, t0.Add(time.Minute)); !errors.Is(err, ErrWeakChannel) {
		t.Fatalf("err = %v, want ErrWeakChannel", err)
	}
}

// TestUnspecifiedChannelIsRefused is the fail-closed corollary: a decision
// whose channel was never set is weaker than either real channel, so forgetting
// to stamp one refuses rather than defaults.
func TestUnspecifiedChannelIsRefused(t *testing.T) {
	r := newTestRequest(t, req(1, false))

	unstamped := Decision{
		AccountID: "acct-ana", Account: "ana", Approve: true,
		PlanHash: "hash-abc", DeciderHuman: true, At: t0.Add(time.Minute),
	}
	if _, err := r.Decide(unstamped, t0.Add(time.Minute)); !errors.Is(err, ErrWeakChannel) {
		t.Fatalf("err = %v, want ErrWeakChannel for an unstamped channel", err)
	}
}

// TestStrongChannelSatisfiesAWeakerRule: strength is a floor, not an equality
// check. An out-of-band answer to an in-band rule is more evidence than was
// asked for, and must be accepted.
func TestStrongChannelSatisfiesAWeakerRule(t *testing.T) {
	r := NewRequest("req-2", "hash-abc", "acct-mike", "mike", testAction, []string{"node-a"}, SelectorShape{}, []string{"rule"},
		Requirement{Count: 1, Channel: ChannelInBand, TTL: time.Hour}, t0)

	outOfBand := Decision{
		AccountID: "acct-ana", Account: "ana", Approve: true,
		Channel: ChannelOutOfBand, PlanHash: "hash-abc", DeciderHuman: true,
		At: t0.Add(time.Minute),
	}
	updated, err := r.Decide(outOfBand, t0.Add(time.Minute))
	if err != nil {
		t.Fatalf("Decide: %v", err)
	}
	if updated.State != StateApproved {
		t.Errorf("State = %v, want approved", updated.State)
	}
}

// TestWeakChannelIsRefusedForDenialsToo: a denial is TERMINAL, so accepting one
// over a channel the rule did not trust would let a compromised harness kill
// work it could not authorize.
func TestWeakChannelIsRefusedForDenialsToo(t *testing.T) {
	r := newTestRequest(t, req(1, false))

	deny := Decision{
		AccountID: "acct-ana", Account: "ana", Approve: false,
		Channel: ChannelInBand, PlanHash: "hash-abc", DeciderHuman: true,
		At: t0.Add(time.Minute),
	}
	if _, err := r.Decide(deny, t0.Add(time.Minute)); !errors.Is(err, ErrWeakChannel) {
		t.Fatalf("err = %v, want ErrWeakChannel — a weak-channel denial is still a decision the rule did not trust", err)
	}
}

// TestNewRequestRecordsTheActionKind: the role floor on a decision is computed
// from this field, so a Request that forgot it would be decidable by the wrong
// people (or, given authz's deny-by-default on an unknown kind, by nobody).
func TestNewRequestRecordsTheActionKind(t *testing.T) {
	rawExec := jobs.Action{
		Kind:        jobs.ActionRawExec,
		RawExecArgv: []string{"/usr/bin/systemctl", "restart", "nginx"},
		RiskClass:   jobs.RiskClassMutate,
	}
	r := NewRequest("req-3", "hash-x", "acct-g", "gleipnir", rawExec, []string{"node-a"}, SelectorShape{}, nil, req(1, false), t0)

	if r.ActionKind != jobs.ActionRawExec {
		t.Errorf("ActionKind = %v, want raw exec", r.ActionKind)
	}
	if r.RiskClass != jobs.RiskClassMutate {
		t.Errorf("RiskClass = %v, want mutate", r.RiskClass)
	}
	// The rendered summary and the structured kind must describe the same
	// thing: a decider reads one and the role floor is computed from the other.
	if !strings.Contains(r.Summary, "raw exec") {
		t.Errorf("Summary = %q, want it to describe the raw exec the ActionKind claims", r.Summary)
	}
}

// -----------------------------------------------------------------------
// ADR-0029: a machine may RELAY an in-band answer, and only relay it
// -----------------------------------------------------------------------

// TestMachineMayRelayAnAssertedInBandAnswer is the one case ADR-0029 opened.
//
// The machine is not confirming its own proposal — it is passing on an answer a
// human gave its client. Both facts must be present for that reading to be
// credible: the channel is in-band (so a client with a human in front of it was
// the surface) and an approver is named (so the trail records who).
func TestMachineMayRelayAnAssertedInBandAnswer(t *testing.T) {
	// The rule must ASK for in-band. An unstated channel normalizes to
	// out-of-band (the fail-closed default), so this carve-out is only ever
	// reachable where an operator configured it deliberately.
	rule := req(1, true) // requester_allowed: true
	rule.Channel = ChannelInBand
	r := newTestRequest(t, rule)

	relayed := Decision{
		AccountID: "acct-mike", Account: "mike", Approve: true,
		Channel: ChannelInBand, PlanHash: "hash-abc", DeciderHuman: false,
		OnBehalfOf: "alice@corp.example",
		At:         t0.Add(time.Minute),
	}
	got, err := r.Decide(relayed, t0.Add(time.Minute))
	if err != nil {
		t.Fatalf("Decide: %v — a machine relaying a named human's in-band answer is ADR-0029's one carve-out", err)
	}
	if got.State != StateApproved {
		t.Errorf("State = %v, want approved", got.State)
	}
	if got.Decisions[0].OnBehalfOf != "alice@corp.example" {
		t.Errorf("OnBehalfOf = %q, want the asserted approver preserved — it is the only record of who actually answered",
			got.Decisions[0].OnBehalfOf)
	}
	if got.Decisions[0].DeciderHuman {
		t.Error("DeciderHuman is true for a machine Account. The carve-out must not launder an assertion " +
			"into the verified lane — that distinction is the whole reason the asserted lane exists.")
	}
}

// TestMachineCannotRelayWithoutNamingAHuman closes the obvious hole in the
// carve-out: if in-band alone sufficed, any machine could self-approve simply by
// using the tool surface, and requester_allowed would mean nothing.
func TestMachineCannotRelayWithoutNamingAHuman(t *testing.T) {
	r := newTestRequest(t, req(1, true))

	anonymous := Decision{
		AccountID: "acct-mike", Account: "mike", Approve: true,
		Channel: ChannelInBand, PlanHash: "hash-abc", DeciderHuman: false,
		OnBehalfOf: "   ", // whitespace is not a human
		At:         t0.Add(time.Minute),
	}
	if _, err := r.Decide(anonymous, t0.Add(time.Minute)); !errors.Is(err, ErrMachineSelfDecision) {
		t.Fatalf("err = %v, want ErrMachineSelfDecision — an in-band answer naming nobody is a machine deciding", err)
	}
}

// TestAssertedApproverDoesNotWeakenAnOutOfBandRule is the guard that keeps
// ADR-0029 from quietly becoming a downgrade path.
//
// A rule demanding out-of-band strength is the two-person tier. Naming an
// approver must not buy passage through it: the asserted lane adds attribution,
// never authority.
func TestAssertedApproverDoesNotWeakenAnOutOfBandRule(t *testing.T) {
	rule := req(1, true)
	rule.Channel = ChannelOutOfBand
	r := newTestRequest(t, rule)

	relayed := Decision{
		AccountID: "acct-mike", Account: "mike", Approve: true,
		Channel: ChannelInBand, PlanHash: "hash-abc", DeciderHuman: false,
		OnBehalfOf: "alice@corp.example",
		At:         t0.Add(time.Minute),
	}
	_, err := r.Decide(relayed, t0.Add(time.Minute))
	if !errors.Is(err, ErrMachineSelfDecision) && !errors.Is(err, ErrWeakChannel) {
		t.Fatalf("err = %v, want a refusal — an in-band answer must never satisfy an out-of-band requirement", err)
	}
}

// TestRelayedAnswerStillCannotSatisfyTwoPersonRule pins the tier boundary.
//
// requester_allowed:false is the second-person rung. ADR-0029 relaxed the
// MACHINE check, not the REQUESTER check, and conflating the two would let one
// party satisfy a rule that exists precisely to require two.
func TestRelayedAnswerStillCannotSatisfyTwoPersonRule(t *testing.T) {
	r := newTestRequest(t, req(1, false)) // requester_allowed: false

	relayed := Decision{
		AccountID: "acct-mike", Account: "mike", Approve: true,
		Channel: ChannelInBand, PlanHash: "hash-abc", DeciderHuman: false,
		OnBehalfOf: "alice@corp.example",
		At:         t0.Add(time.Minute),
	}
	if _, err := r.Decide(relayed, t0.Add(time.Minute)); !errors.Is(err, ErrRequesterExcluded) {
		t.Fatalf("err = %v, want ErrRequesterExcluded — naming an approver does not turn one party into two", err)
	}
}

// --- #608: a blank audience entry must never widen to "unrestricted" ---

func TestValidateAudience(t *testing.T) {
	tests := []struct {
		name     string
		audience []string
		wantErr  bool
	}{
		{name: "nil", audience: nil},
		{name: "empty", audience: []string{}},
		{name: "named accounts", audience: []string{"ana", "bo"}},
		{name: "lone blank entry", audience: []string{""}, wantErr: true},
		{name: "lone whitespace entry", audience: []string{"  "}, wantErr: true},
		{name: "named account plus blank", audience: []string{"ana", ""}, wantErr: true},
		{name: "named account plus tab", audience: []string{"ana", "\t"}, wantErr: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			before := append([]string(nil), tc.audience...)
			err := ValidateAudience(tc.audience)
			if tc.wantErr && !errors.Is(err, ErrAudienceBlankEntry) {
				t.Fatalf("err = %v, want ErrAudienceBlankEntry", err)
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("err = %v, want nil", err)
			}
			// ValidateAudience must never trim, filter or rewrite: it only
			// reports.
			if len(tc.audience) != len(before) {
				t.Fatalf("ValidateAudience mutated the input slice: got %v, want %v", tc.audience, before)
			}
			for i := range before {
				if tc.audience[i] != before[i] {
					t.Fatalf("ValidateAudience mutated entry %d: got %q, want %q", i, tc.audience[i], before[i])
				}
			}
		})
	}
}

func TestBlankAudienceEntryRejectedAtLoad(t *testing.T) {
	tests := []struct {
		name     string
		audience []string
	}{
		{name: "lone blank", audience: []string{""}},
		{name: "lone whitespace", audience: []string{"  "}},
		{name: "named account plus blank", audience: []string{"ana", ""}},
		{name: "lone tab", audience: []string{"\t"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := NewGate([]Rule{{
				Name:    "blank-rule",
				Require: Requirement{Count: 1, Audience: tc.audience},
			}})
			if !errors.Is(err, ErrAudienceBlankEntry) {
				t.Fatalf("err = %v, want errors.Is(err, ErrAudienceBlankEntry)", err)
			}
			if !strings.Contains(err.Error(), "blank-rule") {
				t.Errorf("error = %q, want it to name the rule", err)
			}
		})
	}
}

// TestBlankAudienceEntryCannotPadPastQuorumCheck: Rule.Validate's "count N
// with an audience smaller than N cannot ever be satisfied" check counts
// len(Audience). A blank entry must not be allowed to pad that count into
// looking like a real second member — the blank check must run first.
//
// The Count 2 / Audience [""] case is the one that actually proves the
// ordering: len([""]) == 1 == Count-1, so were the blank check to run AFTER
// the quorum-size check, the quorum check would itself refuse it first (1 <
// 2) and the test would pass for the wrong reason without ever reaching the
// audience check at all. It must still be ErrAudienceBlankEntry, not the
// quorum-size error.
func TestBlankAudienceEntryCannotPadPastQuorumCheck(t *testing.T) {
	tests := []struct {
		name     string
		audience []string
	}{
		{name: "blank entry alone, one short of quorum", audience: []string{""}},
		{name: "blank entry padding a named account up to quorum size", audience: []string{"ana", ""}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := NewGate([]Rule{{
				Name:    "padded",
				Require: Requirement{Count: 2, Audience: tc.audience},
			}})
			if !errors.Is(err, ErrAudienceBlankEntry) {
				t.Fatalf("err = %v, want ErrAudienceBlankEntry — a blank entry must never be accepted as a distinct decider", err)
			}
		})
	}
}

// TestAudienceWithBlankEntryPermitsNoApprover is the domain-level regression:
// a Request that somehow carries a malformed audience (e.g. a legacy stored
// row) must admit NO decider, never fall back to "unrestricted".
func TestAudienceWithBlankEntryPermitsNoApprover(t *testing.T) {
	r := newTestRequest(t, req(1, true, "ana", ""))

	if !r.Require.AudienceMalformed() {
		t.Fatal("AudienceMalformed() = false, want true for an audience containing a blank entry")
	}

	if _, err := r.Decide(approveBy("acct-ana", "ana"), t0.Add(time.Minute)); !errors.Is(err, ErrNotInAudience) {
		t.Fatalf("approval by a NAMED account against a malformed audience: err = %v, want ErrNotInAudience", err)
	}

	deny := approveBy("acct-ana", "ana")
	deny.Approve = false
	if _, err := r.Decide(deny, t0.Add(time.Minute)); !errors.Is(err, ErrNotInAudience) {
		t.Fatalf("denial against a malformed audience: err = %v, want ErrNotInAudience", err)
	}

	whitespace := newTestRequest(t, req(1, true, " "))
	if _, err := whitespace.Decide(approveBy("acct-cy", "cy"), t0.Add(time.Minute)); !errors.Is(err, ErrNotInAudience) {
		t.Fatalf("a whitespace-only audience must refuse every decider: err = %v, want ErrNotInAudience", err)
	}

	// Contrast: the genuinely unrestricted case (no audience at all) is
	// unchanged by this fix.
	unrestricted := newTestRequest(t, req(1, true))
	if _, err := unrestricted.Decide(approveBy("acct-cy", "cy"), t0.Add(time.Minute)); err != nil {
		t.Fatalf("unrestricted audience refused a decider: %v", err)
	}
}

// --- unionAudience: an empty side must never absorb a malformed one ---
// (#608 cycle 2, security finding 1)

// TestUnionAudienceGenuineEmptyStillAbsorbsARestrictedSide pins the ADR-0027
// amendment-2026-09-16 behaviour this fix must NOT change: a genuinely empty
// (unrestricted) audience still absorbs a WELL-FORMED restricted one, in
// either order.
func TestUnionAudienceGenuineEmptyStillAbsorbsARestrictedSide(t *testing.T) {
	if got := unionAudience(nil, []string{"ana", "bo"}); got != nil {
		t.Errorf("unionAudience(nil, restricted) = %v, want nil (unrestricted absorbs)", got)
	}
	if got := unionAudience([]string{"ana", "bo"}, nil); got != nil {
		t.Errorf("unionAudience(restricted, nil) = %v, want nil (unrestricted absorbs)", got)
	}
}

// TestUnionAudienceNeverLetsAnEmptySideAbsorbAMalformedOne is the regression:
// before this fix, unionAudience's "either side is empty means unrestricted"
// shortcut fired on len(side) == 0 alone, so a malformed side merging with a
// genuinely empty (unrestricted) one — or with a well-formed restricted one,
// via the general dedup path missing the blank entry check entirely — could
// launder a blank entry away. The merged result must still be malformed,
// whichever side the blank entry started on.
func TestUnionAudienceNeverLetsAnEmptySideAbsorbAMalformedOne(t *testing.T) {
	tests := []struct {
		name string
		a, b []string
	}{
		{name: "malformed then empty", a: []string{""}, b: nil},
		{name: "empty then malformed", a: nil, b: []string{""}},
		{name: "malformed then well-formed restricted", a: []string{"ana", ""}, b: []string{"bo"}},
		{name: "well-formed restricted then malformed", a: []string{"bo"}, b: []string{"ana", ""}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := unionAudience(tc.a, tc.b)
			if err := ValidateAudience(got); !errors.Is(err, ErrAudienceBlankEntry) {
				t.Fatalf("unionAudience(%v, %v) = %v (err %v), want a result that is still malformed — a blank entry must survive the merge", tc.a, tc.b, got, err)
			}
		})
	}
}

// TestMergeStricterPreservesAMalformedAudience is the same property one level
// up: Gate.Evaluate and RequirementForScope both merge matching Requirements
// with mergeStricter, and a malformed audience on either side must make the
// MERGED Requirement malformed too, not just the unmerged inputs.
func TestMergeStricterPreservesAMalformedAudience(t *testing.T) {
	malformed := Requirement{Count: 1, Audience: []string{""}, Channel: ChannelOutOfBand, TTL: time.Hour}
	unrestricted := Requirement{Count: 1, Channel: ChannelOutOfBand, TTL: time.Hour}

	if merged := mergeStricter(malformed, unrestricted); !merged.AudienceMalformed() {
		t.Errorf("mergeStricter(malformed, unrestricted).Audience = %v, want it to stay malformed", merged.Audience)
	}
	if merged := mergeStricter(unrestricted, malformed); !merged.AudienceMalformed() {
		t.Errorf("mergeStricter(unrestricted, malformed).Audience = %v, want it to stay malformed", merged.Audience)
	}
}
