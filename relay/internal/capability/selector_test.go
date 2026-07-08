package capability

import (
	"testing"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/registry"
)

func TestParseSelector(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    Selector
		wantErr bool
	}{
		{
			name:  "empty string matches all",
			input: "",
			want:  Selector{},
		},
		{
			name:  "whitespace-only matches all",
			input: "   ",
			want:  Selector{},
		},
		{
			name:  "single node term",
			input: "node:role=web",
			want:  Selector{Predicates: []Predicate{{Namespace: NamespaceNode, Key: "role", Value: "web"}}},
		},
		{
			name:  "single relay term",
			input: "relay:quarantine=on",
			want:  Selector{Predicates: []Predicate{{Namespace: NamespaceRelay, Key: "quarantine", Value: "on"}}},
		},
		{
			name:  "mixed namespaces with spacing",
			input: "node:role=web, relay:quarantine=on",
			want: Selector{Predicates: []Predicate{
				{Namespace: NamespaceNode, Key: "role", Value: "web"},
				{Namespace: NamespaceRelay, Key: "quarantine", Value: "on"},
			}},
		},
		{
			name:    "unprefixed term rejected",
			input:   "role=web",
			wantErr: true,
		},
		{
			name:    "malformed term missing =",
			input:   "node:role",
			wantErr: true,
		},
		{
			name:    "malformed term empty key",
			input:   "node:=web",
			wantErr: true,
		},
		{
			name:    "empty term between commas",
			input:   "node:role=web,,relay:quarantine=on",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseSelector(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("ParseSelector(%q) = %+v, want error", tt.input, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseSelector(%q) returned unexpected error: %v", tt.input, err)
			}
			if len(got.Predicates) != len(tt.want.Predicates) {
				t.Fatalf("ParseSelector(%q) = %+v, want %+v", tt.input, got, tt.want)
			}
			for i, p := range got.Predicates {
				if p != tt.want.Predicates[i] {
					t.Errorf("ParseSelector(%q) predicate[%d] = %+v, want %+v", tt.input, i, p, tt.want.Predicates[i])
				}
			}
		})
	}
}

// seedRegistry builds an InMemory registry with three Nodes exercising both
// label namespaces, including the deliberately-ambiguous "quarantine" key
// set in only one namespace per Node, to prove node: and relay: predicates
// are never conflated.
func seedRegistry(t *testing.T) registry.Repository {
	t.Helper()
	reg := registry.NewInMemory()

	if _, err := reg.Upsert(registry.Report{
		NodeID:     "node-1",
		NodeLabels: map[string]string{"role": "web", "env": "prod"},
	}); err != nil {
		t.Fatalf("Upsert(node-1): %v", err)
	}
	if err := reg.SetRelayLabels("node-1", map[string]string{"quarantine": "on"}); err != nil {
		t.Fatalf("SetRelayLabels(node-1): %v", err)
	}

	if _, err := reg.Upsert(registry.Report{
		NodeID:     "node-2",
		NodeLabels: map[string]string{"role": "db", "env": "prod"},
	}); err != nil {
		t.Fatalf("Upsert(node-2): %v", err)
	}

	// node-3 carries "quarantine=on" as a node-space label, not a relay-
	// space one. A relay:quarantine=on Selector must never match it.
	if _, err := reg.Upsert(registry.Report{
		NodeID:     "node-3",
		NodeLabels: map[string]string{"role": "web", "quarantine": "on"},
	}); err != nil {
		t.Fatalf("Upsert(node-3): %v", err)
	}

	return reg
}

func TestSelectorMatchesNamespacesNeverConflate(t *testing.T) {
	reg := seedRegistry(t)
	node1, _ := reg.Get("node-1")
	node3, _ := reg.Get("node-3")

	relayQuarantine := Selector{Predicates: []Predicate{{Namespace: NamespaceRelay, Key: "quarantine", Value: "on"}}}
	if !relayQuarantine.Matches(node1) {
		t.Error("relay:quarantine=on should match node-1 (has RelayLabels[quarantine]=on)")
	}
	if relayQuarantine.Matches(node3) {
		t.Error("relay:quarantine=on must NOT match node-3 — it only has a node-space quarantine label")
	}

	nodeQuarantine := Selector{Predicates: []Predicate{{Namespace: NamespaceNode, Key: "quarantine", Value: "on"}}}
	if !nodeQuarantine.Matches(node3) {
		t.Error("node:quarantine=on should match node-3 (has NodeLabels[quarantine]=on)")
	}
	if nodeQuarantine.Matches(node1) {
		t.Error("node:quarantine=on must NOT match node-1 — it only has a relay-space quarantine label")
	}
}

func TestSelectorMatchesUnspecifiedNamespaceNeverMatches(t *testing.T) {
	reg := seedRegistry(t)
	node1, _ := reg.Get("node-1")

	sel := Selector{Predicates: []Predicate{{Namespace: NamespaceUnspecified, Key: "role", Value: "web"}}}
	if sel.Matches(node1) {
		t.Error("a Predicate with the zero-value Namespace must never match (fail closed)")
	}
}

func TestSelectorMatchesConjunction(t *testing.T) {
	reg := seedRegistry(t)
	node1, _ := reg.Get("node-1")
	node2, _ := reg.Get("node-2")

	sel := Selector{Predicates: []Predicate{
		{Namespace: NamespaceNode, Key: "role", Value: "web"},
		{Namespace: NamespaceRelay, Key: "quarantine", Value: "on"},
	}}

	if !sel.Matches(node1) {
		t.Error("node-1 satisfies both predicates and should match")
	}
	if sel.Matches(node2) {
		t.Error("node-2 has neither predicate satisfied and should not match")
	}
}

func TestSelectorResolve(t *testing.T) {
	reg := seedRegistry(t)

	t.Run("empty selector matches all nodes", func(t *testing.T) {
		got := Selector{}.Resolve(reg)
		if len(got) != 3 {
			t.Fatalf("Resolve(empty selector) returned %d nodes, want 3", len(got))
		}
	})

	t.Run("node predicate narrows to matching nodes only", func(t *testing.T) {
		sel := Selector{Predicates: []Predicate{{Namespace: NamespaceNode, Key: "role", Value: "web"}}}
		got := sel.Resolve(reg)
		if len(got) != 2 {
			t.Fatalf("Resolve(node:role=web) returned %d nodes, want 2 (node-1, node-3)", len(got))
		}
		for _, n := range got {
			if n.NodeID != "node-1" && n.NodeID != "node-3" {
				t.Errorf("unexpected node %q matched node:role=web", n.NodeID)
			}
		}
	})

	t.Run("relay predicate narrows to matching nodes only", func(t *testing.T) {
		sel := Selector{Predicates: []Predicate{{Namespace: NamespaceRelay, Key: "quarantine", Value: "on"}}}
		got := sel.Resolve(reg)
		if len(got) != 1 || got[0].NodeID != "node-1" {
			t.Fatalf("Resolve(relay:quarantine=on) = %+v, want only node-1", got)
		}
	})
}
