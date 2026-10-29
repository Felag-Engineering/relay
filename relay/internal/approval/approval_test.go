package approval

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/Felag-Engineering/relay/relay/internal/jobs"
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

func req() Requirement {
	return Requirement{TTL: time.Hour}
}

func newTestRequest(t *testing.T) Request {
	t.Helper()
	return NewRequest("req-1", "hash-abc", "acct-mike", "mike", testAction, []string{"node-a"}, []string{"rule"}, req(), t0)
}

func approveBy(id, name string) Decision {
	return Decision{AccountID: id, Account: name, Approve: true, Channel: ChannelOutOfBand, PlanHash: "hash-abc", DeciderHuman: true, At: t0.Add(time.Minute)}
}

func TestSingleApprovalSatisfies(t *testing.T) {
	r := newTestRequest(t)
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

// TestDecide_FirstDecisionEndsTheRequest: an approving Decision approves, a
// denying one denies, and a later Decision, from the same Account or another,
// is refused as not pending and never recorded.
//
// Proves AP-82.
func TestDecide_FirstDecisionEndsTheRequest(t *testing.T) {
	deny := approveBy("acct-ana", "ana")
	deny.Approve = false

	cases := []struct {
		name      string
		first     Decision
		wantState State
	}{
		{"approve", approveBy("acct-ana", "ana"), StateApproved},
		{"deny", deny, StateDenied},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r, err := newTestRequest(t).Decide(tc.first, t0.Add(time.Minute))
			if err != nil {
				t.Fatalf("first Decide: %v", err)
			}
			if r.State != tc.wantState {
				t.Fatalf("State = %v, want %v", r.State, tc.wantState)
			}
			if got := r.Satisfied(t0.Add(2 * time.Minute)); got != (tc.wantState == StateApproved) {
				t.Errorf("Satisfied = %v after %s", got, tc.name)
			}
			for _, later := range []Decision{approveBy("acct-bo", "bo"), approveBy("acct-ana", "ana"), deny} {
				if _, err := r.Decide(later, t0.Add(3*time.Minute)); !errors.Is(err, ErrNotPending) {
					t.Errorf("later Decision: err = %v, want ErrNotPending", err)
				}
			}
			if len(r.Decisions) != 1 {
				t.Errorf("Decisions = %d, want exactly the first", len(r.Decisions))
			}
		})
	}
}

// TestDecide_HumanRequesterMayConfirmOwnRequest: a human may confirm their own
// request, in-band or out-of-band.
//
// Proves AP-11.
func TestDecide_HumanRequesterMayConfirmOwnRequest(t *testing.T) {
	for _, ch := range []Channel{ChannelInBand, ChannelOutOfBand} {
		t.Run(ch.String(), func(t *testing.T) {
			d := approveBy("acct-mike", "mike") // the requester, DeciderHuman
			d.Channel = ch
			r, err := newTestRequest(t).Decide(d, t0.Add(time.Minute))
			if err != nil {
				t.Fatalf("Decide: %v", err)
			}
			if r.State != StateApproved {
				t.Errorf("State = %v, want approved", r.State)
			}
		})
	}
}

// TestDecide_MachineSelfDecisionOnlyInBandForms: a machine Account never
// decides its own request out-of-band; the in-band token-session and asserted
// forms are the only exceptions.
//
// Proves AP-48.
func TestDecide_MachineSelfDecisionOnlyInBandForms(t *testing.T) {
	machine := func(mut func(*Decision)) Decision {
		d := Decision{
			AccountID: "acct-mike", Account: "mike", Approve: true,
			Channel: ChannelInBand, PlanHash: "hash-abc", DeciderHuman: false,
			At: t0.Add(time.Minute),
		}
		mut(&d)
		return d
	}
	cases := []struct {
		name    string
		d       Decision
		wantErr error
	}{
		{"out-of-band", machine(func(d *Decision) { d.Channel = ChannelOutOfBand }), ErrMachineSelfDecision},
		{"out-of-band naming an approver", machine(func(d *Decision) { d.Channel = ChannelOutOfBand; d.OnBehalfOf = "alice@corp.example" }), ErrMachineSelfDecision},
		{"in-band naming nobody", machine(func(d *Decision) { d.OnBehalfOf = "   " }), ErrMachineSelfDecision},
		{"in-band asserted approver", machine(func(d *Decision) { d.OnBehalfOf = "alice@corp.example" }), nil},
		{"in-band API Token session", machine(func(d *Decision) { d.IdentifiedBy = IdentifiedByAPITokenSession }), nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := newTestRequest(t).Decide(tc.d, t0.Add(time.Minute))
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("err = %v, want %v", err, tc.wantErr)
			}
		})
	}
}

// TestMachineMayDecideSomeoneElsesRequest: the restriction is on deciding your
// OWN request, not on machine Accounts generally. An approval bridge that holds
// its own credential is a legitimate deployment; what it can never do is answer
// for the Account that asked.
func TestMachineMayDecideSomeoneElsesRequest(t *testing.T) {
	r := newTestRequest(t)

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

// TestMachineRelayKeepsTheAssertedLane: relaying a named human's in-band answer
// records the asserted approver and never launders it into the verified lane.
func TestMachineRelayKeepsTheAssertedLane(t *testing.T) {
	relayed := Decision{
		AccountID: "acct-mike", Account: "mike", Approve: true,
		Channel: ChannelInBand, PlanHash: "hash-abc", DeciderHuman: false,
		OnBehalfOf: "alice@corp.example",
		At:         t0.Add(time.Minute),
	}
	got, err := newTestRequest(t).Decide(relayed, t0.Add(time.Minute))
	if err != nil {
		t.Fatalf("Decide: %v", err)
	}
	if got.Decisions[0].OnBehalfOf != "alice@corp.example" {
		t.Errorf("OnBehalfOf = %q, want the asserted approver preserved", got.Decisions[0].OnBehalfOf)
	}
	if got.Decisions[0].DeciderHuman {
		t.Error("DeciderHuman is true for a machine Account; an assertion must not enter the verified lane")
	}
}

// TestExpiredRequestIsNotDecidableOrSatisfiable covers the sweeper-outage case:
// a Request past its deadline must read as expired to EVERY caller, whether or
// not anything has updated its stored state.
func TestExpiredRequestIsNotDecidableOrSatisfiable(t *testing.T) {
	r := newTestRequest(t) // TTL 1h

	late := t0.Add(2 * time.Hour)
	if !r.Expired(late) {
		t.Fatal("a Request past its deadline must report Expired")
	}
	if _, err := r.Decide(approveBy("acct-ana", "ana"), late); !errors.Is(err, ErrNotPending) {
		t.Errorf("deciding an expired Request: err = %v, want ErrNotPending", err)
	}

	// And an approval granted in time does not stay redeemable forever.
	fresh := newTestRequest(t)
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
	r := newTestRequest(t)
	d := approveBy("acct-ana", "ana")
	d.PlanHash = "hash-something-else"

	if _, err := r.Decide(d, t0.Add(time.Minute)); !errors.Is(err, ErrPlanChanged) {
		t.Fatalf("decision citing another Plan: err = %v, want ErrPlanChanged", err)
	}
}

func TestUnstatedTTLDefaultsToDefaultTTL(t *testing.T) {
	if got := (Requirement{}).normalized(); got.TTL != DefaultTTL {
		t.Errorf("TTL = %v, want DefaultTTL: every Request must expire", got.TTL)
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
		t.Error("an empty Gate must gate nothing: that is a deployment with no gate rules")
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
		Require: req(),
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
		t.Errorf("rules = %v, want [big-mutates]: a gate must be able to say which rule fired", rules)
	}

	read := mutateDispatch(50)
	read.RiskClass = jobs.RiskClassRead
	if _, _, gated := g.Evaluate(read); gated {
		t.Error("a read-class dispatch must not match a mutate-class rule")
	}
}

// TestGate_OverlappingRulesShortestTTLWins: when rules overlap, the shortest
// TTL wins, a rule naming no ttl counts as DefaultTTL, and rule order does not
// matter.
//
// Proves AP-81.
func TestGate_OverlappingRulesShortestTTLWins(t *testing.T) {
	long := Rule{Name: "long", Match: Match{RiskClass: jobs.RiskClassMutate}, Require: Requirement{TTL: 2 * time.Hour}}
	short := Rule{Name: "short", Match: Match{MinFanOut: 10}, Require: Requirement{TTL: 30 * time.Minute}}
	unset := Rule{Name: "unset", Match: Match{MinFanOut: 1}}

	for name, rules := range map[string][]Rule{"long first": {long, short}, "short first": {short, long}} {
		t.Run(name, func(t *testing.T) {
			g, err := NewGate(rules)
			if err != nil {
				t.Fatalf("NewGate: %v", err)
			}
			got, names, gated := g.Evaluate(mutateDispatch(50))
			if !gated {
				t.Fatal("both rules match, so the dispatch must be gated")
			}
			if got.TTL != 30*time.Minute {
				t.Errorf("TTL = %v, want 30m (the shortest)", got.TTL)
			}
			if len(names) != 2 {
				t.Errorf("rules = %v, want both named", names)
			}
		})
	}

	g, err := NewGate([]Rule{long, unset})
	if err != nil {
		t.Fatalf("NewGate: %v", err)
	}
	got, _, _ := g.Evaluate(mutateDispatch(50))
	if got.TTL != 2*time.Hour {
		t.Errorf("TTL = %v, want 2h: a rule with no ttl counts as DefaultTTL (4h), which is longer", got.TTL)
	}
	g, err = NewGate([]Rule{unset})
	if err != nil {
		t.Fatalf("NewGate: %v", err)
	}
	if got, _, _ := g.Evaluate(mutateDispatch(50)); got.TTL != DefaultTTL {
		t.Errorf("TTL = %v, want DefaultTTL", got.TTL)
	}
}

func TestDuplicateRuleNamesRejected(t *testing.T) {
	_, err := NewGate([]Rule{
		{Name: "dup", Require: req()},
		{Name: "DUP", Require: req()},
	})
	if err == nil {
		t.Fatal("duplicate rule names must be rejected: the name is how a park explains itself")
	}
}

// TestNewGate_RefusalNamesNoRuleNameOrValue: a refusal names the rule's
// position and never its name or a value, because it reaches logs (RC-18).
func TestNewGate_RefusalNamesNoRuleNameOrValue(t *testing.T) {
	cases := map[string][]Rule{
		"negative ttl":      {{Name: "ok"}, {Name: "CANARY", Require: Requirement{TTL: -time.Hour}}},
		"unknown namespace": {{Name: "ok"}, {Name: "x", Match: Match{SelectorNamespace: "CANARY"}}},
		"duplicate name":    {{Name: "CANARY"}, {Name: "CANARY"}},
	}
	for name, rules := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := NewGate(rules)
			if err == nil {
				t.Fatal("want a refusal")
			}
			if strings.Contains(err.Error(), "CANARY") {
				t.Errorf("error %q carries a rule name or value", err)
			}
		})
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
	r := NewRequest("req-3", "hash-x", "acct-g", "gleipnir", rawExec, []string{"node-a"}, nil, req(), t0)

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

// --- AP-77: an approval releases one execution ---

// TestRequest_ReleaseBindsOnce pins the release claim itself: the first
// Release wins, returns a copy rather than mutating the receiver, and a
// second attempt always learns the winner's Job ID rather than a stale
// "not satisfiable" answer.
func TestRequest_ReleaseBindsOnce(t *testing.T) {
	r := newTestRequest(t) // TTL 1h
	r, err := r.Decide(approveBy("acct-ana", "ana"), t0.Add(time.Minute))
	if err != nil {
		t.Fatalf("Decide: %v", err)
	}
	if !r.Satisfied(t0.Add(2 * time.Minute)) {
		t.Fatal("want a Satisfied Request before exercising Release")
	}
	if r.Released() {
		t.Fatal("a freshly satisfied Request must not already be Released")
	}

	bound, err := r.Release("job-1", t0.Add(2*time.Minute))
	if err != nil {
		t.Fatalf("Release: %v", err)
	}
	if bound.JobID != "job-1" {
		t.Errorf("JobID = %q, want job-1", bound.JobID)
	}
	if !bound.Released() {
		t.Error("Released() = false on the bound copy, want true")
	}
	if r.Released() {
		t.Error("Released() = true on the original, want false — Release must return a copy, not mutate the receiver")
	}

	// A second Release — even past the deadline — must still report
	// ErrAlreadyReleased and the FIRST Job ID: Released is checked before
	// Satisfied, so a caller who lost a concurrent claim always learns the
	// winner's Job ID rather than a stale "not satisfiable" answer.
	late := t0.Add(2 * time.Hour)
	again, err := bound.Release("job-2", late)
	if !errors.Is(err, ErrAlreadyReleased) {
		t.Fatalf("second Release: err = %v, want ErrAlreadyReleased", err)
	}
	if again.JobID != "job-1" {
		t.Errorf("JobID after a refused second Release = %q, want the original job-1", again.JobID)
	}

	if _, err := r.Release("", t0.Add(2*time.Minute)); !errors.Is(err, ErrNotReleasable) {
		t.Fatalf("Release(\"\"): err = %v, want ErrNotReleasable", err)
	}
}

// TestRequest_ReleaseRefusesAnUnsatisfiedRequest is the other half: Release
// must never bind a Job to a Request that is not Satisfied — pending,
// denied, or approved but past its deadline — and must leave it unchanged.
func TestRequest_ReleaseRefusesAnUnsatisfiedRequest(t *testing.T) {
	pending := newTestRequest(t)

	denied := newTestRequest(t)
	deny := approveBy("acct-ana", "ana")
	deny.Approve = false
	denied, err := denied.Decide(deny, t0.Add(time.Minute))
	if err != nil {
		t.Fatalf("Decide (deny): %v", err)
	}

	pastDeadline := newTestRequest(t)
	pastDeadline, err = pastDeadline.Decide(approveBy("acct-ana", "ana"), t0.Add(time.Minute))
	if err != nil {
		t.Fatalf("Decide (approve): %v", err)
	}

	tests := []struct {
		name string
		r    Request
		now  time.Time
	}{
		{name: "pending", r: pending, now: t0.Add(time.Minute)},
		{name: "denied", r: denied, now: t0.Add(2 * time.Minute)},
		{name: "approved but past its deadline", r: pastDeadline, now: t0.Add(2 * time.Hour)},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := tc.r.Release("job-1", tc.now)
			if !errors.Is(err, ErrNotReleasable) {
				t.Fatalf("Release: err = %v, want ErrNotReleasable", err)
			}
			if got.Released() {
				t.Error("Released() = true after a refused Release, want false")
			}
			if got.JobID != tc.r.JobID {
				t.Errorf("JobID = %q, want unchanged %q", got.JobID, tc.r.JobID)
			}
		})
	}
}

// TestGateRuleAcceptsExactlyTheKnownNamespaces pins that Rule.Validate accepts
// exactly knownNamespaces and nothing else. Rule.Validate consults
// knownNamespaces directly rather than a second hardcoded set (gate.go), so
// there is one vocabulary to drift.
func TestGateRuleAcceptsExactlyTheKnownNamespaces(t *testing.T) {
	for _, ns := range knownNamespaces {
		r := Rule{Name: "r", Match: Match{SelectorNamespace: ns}, Require: Requirement{TTL: time.Hour}}
		if err := r.Validate(); err != nil {
			t.Errorf("a gate rule matching selector_namespace %q did not validate: %v", ns, err)
		}
	}
	bad := Rule{Name: "r", Match: Match{SelectorNamespace: "tenant"}, Require: Requirement{TTL: time.Hour}}
	if err := bad.Validate(); err == nil {
		t.Error("a gate rule matching an unknown namespace validated; knownNamespaces has drifted from Rule.Validate's vocabulary")
	}
}
