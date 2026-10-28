package approval

import (
	"testing"

	"github.com/Felag-Engineering/relay/relay/internal/jobs"
)

func gatedDispatch() Dispatch {
	return Dispatch{
		RiskClass: jobs.RiskClassMutate,
		FanOut:    5,
		Account:   "gleipnir-prod",
		Operation: "service.restart",
	}
}

// TestSelectorNamespaceNarrows proves the selectors-and-labels row that a
// relay:-namespace Selector narrows at the approval gate: a rule matching
// Match.SelectorNamespace gates only dispatches whose Selector used it.
func TestSelectorNamespaceNarrows(t *testing.T) {
	gate, err := NewGate([]Rule{{
		Name:    "relay-lane",
		Match:   Match{SelectorNamespace: "relay"},
		Require: Requirement{Count: 1},
	}})
	if err != nil {
		t.Fatalf("NewGate: %v", err)
	}

	wrong := gatedDispatch()
	wrong.Namespaces = []string{"tag"}
	if _, _, gated := gate.Evaluate(wrong); gated {
		t.Error("a rule matching relay: gated a tag: Selector")
	}

	right := gatedDispatch()
	right.Namespaces = []string{"relay"}
	if _, _, gated := gate.Evaluate(right); !gated {
		t.Error("a rule matching relay: did not gate a relay: Selector")
	}

	both := gatedDispatch()
	both.Namespaces = []string{"relay", "node"}
	if _, _, gated := gate.Evaluate(both); !gated {
		t.Error("a rule matching relay: did not gate a dispatch whose Selector also used node:")
	}
}

// TestSelectorNamespaceState is the sibling for the state: namespace
// (ADR-0034): a gate Rule can match "state" and narrows the same way.
func TestSelectorNamespaceState(t *testing.T) {
	if err := (Rule{Name: "r", Match: Match{SelectorNamespace: "state"}, Require: Requirement{Count: 1}}).Validate(); err != nil {
		t.Fatalf("a rule matching selector_namespace \"state\" did not validate: %v", err)
	}

	gate, err := NewGate([]Rule{{
		Name:    "state-lane",
		Match:   Match{SelectorNamespace: "state"},
		Require: Requirement{Count: 1},
	}})
	if err != nil {
		t.Fatalf("NewGate: %v", err)
	}

	wrong := gatedDispatch()
	wrong.Namespaces = []string{"node"}
	if _, _, gated := gate.Evaluate(wrong); gated {
		t.Error("a rule matching state: gated a node: Selector")
	}

	right := gatedDispatch()
	right.Namespaces = []string{"state"}
	if _, _, gated := gate.Evaluate(right); !gated {
		t.Error("a rule matching state: did not gate a state: Selector")
	}
}
