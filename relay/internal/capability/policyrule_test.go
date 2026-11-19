package capability

import (
	"context"
	"reflect"
	"testing"

	"github.com/Felag-Engineering/relay/relay/internal/jobs"
)

func runDeniedMutate(t *testing.T, rule jobs.PolicyRuleRef) (dispatchResult, []NodeResult) {
	t.Helper()
	conduit := newFakeConduit(nil)
	for _, id := range []string{"node-1", "node-2"} {
		conduit.connected[id] = true
	}
	conduit.results["node-1"] = jobs.Result{Outcome: jobs.OutcomeDeniedByPolicy, ExitCode: -1, PolicyRule: rule}
	conduit.results["node-2"] = jobs.Result{Outcome: jobs.OutcomeSuccess}
	e, _ := newConcurrentEngine(t, conduit, 1)
	d := newDispatch(Principal{Account: "alice"}, Selector{}, nodeSet(2), mutateRawExec())
	dr, err := e.run(context.Background(), d)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	return dr, dr.results
}

// A denied Task's rule reference reaches the per-Node result the audit sink
// records, verbatim as the daemon reported it.
// Proves EX-70.
func TestDispatch_ADeniedTaskCarriesTheDaemonsRuleReferenceToItsOutcomeRecord(t *testing.T) {
	want := jobs.PolicyRuleRef{Pass: "deny", RuleSection: "raw_exec_deny", RuleIndex: 2, RuleLine: 14}
	_, results := runDeniedMutate(t, want)

	got := map[string]jobs.PolicyRuleRef{}
	for _, r := range results {
		got[r.NodeID] = r.PolicyRule
	}
	if got["node-1"] != want {
		t.Errorf("node-1 PolicyRule = %+v, want %+v", got["node-1"], want)
	}
	if !got["node-2"].IsZero() {
		t.Errorf("node-2 PolicyRule = %+v, want zero: it was not denied", got["node-2"])
	}
}

// No decision reads the rule reference: two Jobs whose results differ only in
// it, one contradicting its own outcome, resolve alike.
// Proves EX-70.
func TestDispatch_NoDecisionReadsThePolicyRule(t *testing.T) {
	plain, plainResults := runDeniedMutate(t, jobs.PolicyRuleRef{})
	odd, oddResults := runDeniedMutate(t, jobs.PolicyRuleRef{Pass: "allow", RuleSection: "operation", RuleIndex: 7, RuleLine: 999})

	// The whole halt: its Task, Node, Outcome and resolution are the halt reason.
	if plain.halt != odd.halt {
		t.Errorf("halt differs: %+v vs %+v", plain.halt, odd.halt)
	}
	if len(plainResults) != len(oddResults) {
		t.Fatalf("result counts differ: %d vs %d", len(plainResults), len(oddResults))
	}
	for i := range plainResults {
		a, b := plainResults[i], oddResults[i]
		a.JobID, b.JobID = "", ""
		a.PolicyRule, b.PolicyRule = jobs.PolicyRuleRef{}, jobs.PolicyRuleRef{}
		if !reflect.DeepEqual(a, b) {
			t.Errorf("result %d differs beyond PolicyRule: %+v vs %+v", i, a, b)
		}
	}
}
