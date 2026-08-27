package capability

import (
	"strings"
	"testing"
	"time"

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
		{
			name:  "single tag term",
			input: "tag:team=payments",
			want:  Selector{Predicates: []Predicate{{Namespace: NamespaceTag, Key: "team", Value: "payments"}}},
		},
		{
			name:  "state marker term",
			input: "state:offline",
			want:  Selector{Predicates: []Predicate{{Namespace: NamespaceState, Key: "offline"}}},
		},
		{
			name:  "state fact term",
			input: "state:daemon-version=1.4.2",
			want: Selector{Predicates: []Predicate{
				{Namespace: NamespaceState, Key: "daemon-version", Value: "1.4.2"},
			}},
		},
		{
			name:    "state term outside the closed vocabulary",
			input:   "state:bogus",
			wantErr: true,
		},
		{
			name:    "state marker with a value",
			input:   "state:offline=true",
			wantErr: true,
		},
		{
			name:    "state fact without a value",
			input:   "state:daemon-version",
			wantErr: true,
		},
		{
			name:    "state fact with an empty value",
			input:   "state:policy-fingerprint=",
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
	if !relayQuarantine.Matches(node1, StateEval{}) {
		t.Error("relay:quarantine=on should match node-1 (has RelayLabels[quarantine]=on)")
	}
	if relayQuarantine.Matches(node3, StateEval{}) {
		t.Error("relay:quarantine=on must NOT match node-3 — it only has a node-space quarantine label")
	}

	nodeQuarantine := Selector{Predicates: []Predicate{{Namespace: NamespaceNode, Key: "quarantine", Value: "on"}}}
	if !nodeQuarantine.Matches(node3, StateEval{}) {
		t.Error("node:quarantine=on should match node-3 (has NodeLabels[quarantine]=on)")
	}
	if nodeQuarantine.Matches(node1, StateEval{}) {
		t.Error("node:quarantine=on must NOT match node-1 — it only has a relay-space quarantine label")
	}
}

func TestSelectorMatchesUnspecifiedNamespaceNeverMatches(t *testing.T) {
	reg := seedRegistry(t)
	node1, _ := reg.Get("node-1")

	sel := Selector{Predicates: []Predicate{{Namespace: NamespaceUnspecified, Key: "role", Value: "web"}}}
	if sel.Matches(node1, StateEval{}) {
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

	if !sel.Matches(node1, StateEval{}) {
		t.Error("node-1 satisfies both predicates and should match")
	}
	if sel.Matches(node2, StateEval{}) {
		t.Error("node-2 has neither predicate satisfied and should not match")
	}
}

// TestSelectorMatchesStateNeverReadsForgedLabels is the read-side half of
// "nobody can write a state: label" (ADR-0034): a Node carrying a forged
// NodeLabels/RelayLabels "offline" key must not satisfy state:offline while
// it is actually connected. NamespaceState reads a nodestate.LabelSet, which
// never looks at either stored map.
func TestSelectorMatchesStateNeverReadsForgedLabels(t *testing.T) {
	reg := registry.NewInMemory()
	if _, err := reg.Upsert(registry.Report{
		NodeID:     "node-forged",
		NodeLabels: map[string]string{"offline": "true"},
	}); err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	if err := reg.SetRelayLabels("node-forged", map[string]string{"offline": "true"}); err != nil {
		t.Fatalf("SetRelayLabels: %v", err)
	}
	reg.SetConnected("node-forged", true)
	n, _ := reg.Get("node-forged")

	sel := Selector{Predicates: []Predicate{{Namespace: NamespaceState, Key: "offline"}}}
	if sel.Matches(n, StateEval{Now: time.Now()}) {
		t.Error("state:offline matched a connected Node carrying a forged node:/relay: offline label — " +
			"a stored label must never satisfy a state: term")
	}
}

// TestSelectorMatchesTagAlwaysFalse: tag-space has no storage on
// registry.Node until #430, so a tag: predicate must never match, even
// against a Node with no labels at all — "matches nothing" is the honest
// answer today, not a placeholder that happens to return false.
func TestSelectorMatchesTagAlwaysFalse(t *testing.T) {
	reg := seedRegistry(t)
	node1, _ := reg.Get("node-1")

	sel := Selector{Predicates: []Predicate{{Namespace: NamespaceTag, Key: "team", Value: "payments"}}}
	if sel.Matches(node1, StateEval{}) {
		t.Error("a tag: predicate matched — tag-space has no storage until #430")
	}
}

func TestSelectorString_StateRoundTrips(t *testing.T) {
	sel := Selector{Predicates: []Predicate{
		{Namespace: NamespaceState, Key: "offline"},
		{Namespace: NamespaceState, Key: "policy-fingerprint", Value: "4b18"},
	}}
	s := sel.String()
	if s != "state:offline, state:policy-fingerprint=4b18" {
		t.Fatalf("String() = %q, want %q", s, "state:offline, state:policy-fingerprint=4b18")
	}

	got, err := ParseSelector(s)
	if err != nil {
		t.Fatalf("ParseSelector(%q): %v", s, err)
	}
	if len(got.Predicates) != len(sel.Predicates) {
		t.Fatalf("round-trip predicate count = %d, want %d", len(got.Predicates), len(sel.Predicates))
	}
	for i, p := range got.Predicates {
		if p != sel.Predicates[i] {
			t.Errorf("round-trip predicate[%d] = %+v, want %+v", i, p, sel.Predicates[i])
		}
	}
}

func TestNamespaceNames_ReportsAllFourNamespaces(t *testing.T) {
	sel := Selector{Predicates: []Predicate{
		{Namespace: NamespaceNode, Key: "role", Value: "web"},
		{Namespace: NamespaceRelay, Key: "quarantine", Value: "on"},
		{Namespace: NamespaceTag, Key: "team", Value: "payments"},
		{Namespace: NamespaceState, Key: "offline"},
	}}
	names := sel.NamespaceNames()
	joined := strings.Join(names, ",")
	for _, want := range []string{"node", "relay", "tag", "state"} {
		if !strings.Contains(joined, want) {
			t.Errorf("NamespaceNames() = %v, missing %q", names, want)
		}
	}
	if len(names) != 4 {
		t.Errorf("NamespaceNames() = %v, want exactly 4 distinct names", names)
	}
}

func TestSelectorResolve(t *testing.T) {
	reg := seedRegistry(t)

	t.Run("empty selector matches all nodes", func(t *testing.T) {
		got := Selector{}.Resolve(reg, StateEval{})
		if len(got) != 3 {
			t.Fatalf("Resolve(empty selector) returned %d nodes, want 3", len(got))
		}
	})

	t.Run("node predicate narrows to matching nodes only", func(t *testing.T) {
		sel := Selector{Predicates: []Predicate{{Namespace: NamespaceNode, Key: "role", Value: "web"}}}
		got := sel.Resolve(reg, StateEval{})
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
		got := sel.Resolve(reg, StateEval{})
		if len(got) != 1 || got[0].NodeID != "node-1" {
			t.Fatalf("Resolve(relay:quarantine=on) = %+v, want only node-1", got)
		}
	})
}

// TestSelectorResolve_StateIsNodeLocal is acceptance 3 at the resolver level:
// a second Node's state (offline, outdated) must not change whether the
// first Node matches a state: Selector.
func TestSelectorResolve_StateIsNodeLocal(t *testing.T) {
	reg := registry.NewInMemory(registry.WithMinDaemonVersion("1.4.0"))
	if _, err := reg.Upsert(registry.Report{NodeID: "node-healthy", DaemonVersion: "1.5.0"}); err != nil {
		t.Fatalf("Upsert(node-healthy): %v", err)
	}
	reg.SetConnected("node-healthy", true)

	sel := Selector{Predicates: []Predicate{{Namespace: NamespaceState, Key: "offline"}}}
	ev := StateEval{Now: time.Now()}

	before := sel.Resolve(reg, ev)
	if len(before) != 0 {
		t.Fatalf("state:offline matched the healthy, connected Node: %+v", before)
	}

	// Add a second Node that IS offline and outdated.
	if _, err := reg.Upsert(registry.Report{NodeID: "node-sick", DaemonVersion: "1.0.0"}); err != nil {
		t.Fatalf("Upsert(node-sick): %v", err)
	}

	after := sel.Resolve(reg, ev)
	if len(after) != 1 || after[0].NodeID != "node-sick" {
		t.Fatalf("state:offline after adding node-sick = %+v, want only node-sick", after)
	}
	// The first Node's match result — false — is unchanged.
	for _, n := range after {
		if n.NodeID == "node-healthy" {
			t.Fatal("node-healthy started matching state:offline after an unrelated Node was added")
		}
	}
}
