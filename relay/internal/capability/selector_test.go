package capability

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/approval"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/jobs"
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
			// #560: tag: is refused, not parsed. The namespace is in the model
			// (invariant 7) but has no storage until #430, so parsing one would
			// hand back a Selector that matches nothing for an invisible
			// reason. TestParseSelectorTagRefusalIsASentinel pins the error
			// IDENTITY; these two cases only pin that it is refused at all.
			name:    "single tag term is refused until #430",
			input:   "tag:team=payments",
			wantErr: true,
		},
		{
			name:    "a tag term poisons an otherwise valid selector",
			input:   "node:role=web, tag:team=payments",
			wantErr: true,
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

// TestParseSelectorTagRefusalIsASentinel pins the error's IDENTITY, not just
// its existence.
//
// It matters because surfaces RECOGNISE this error rather than re-deciding the
// rule: the Console's parseFleetFilter renders its own sentence for it and the
// generic "every term needs a namespace prefix" lead for everything else. If
// the refusal stopped wrapping the sentinel, that errors.Is would silently
// fall through and the fleet filter would tell an operator their prefixed term
// has no prefix.
func TestParseSelectorTagRefusalIsASentinel(t *testing.T) {
	for _, in := range []string{
		"tag:team=payments",
		"node:role=web, tag:team=payments",
		"tag:team=payments, node:role=web",
	} {
		_, err := ParseSelector(in)
		if !errors.Is(err, ErrSelectorTagUnsupported) {
			t.Errorf("ParseSelector(%q) error = %v, want it to wrap ErrSelectorTagUnsupported", in, err)
		}
		// The offending term is named, so an operator can see WHICH term was
		// refused in a multi-term filter.
		if err != nil && !strings.Contains(err.Error(), "tag:team=payments") {
			t.Errorf("ParseSelector(%q) error does not name the offending term: %v", in, err)
		}
	}

	// A selector with no tag: term must NOT wrap it — otherwise the Console
	// would render the tag: sentence for an ordinary typo.
	_, err := ParseSelector("node:role")
	if err == nil {
		t.Fatal("ParseSelector(\"node:role\") = nil error, want a parse error")
	}
	if errors.Is(err, ErrSelectorTagUnsupported) {
		t.Errorf("a malformed node: term wrapped ErrSelectorTagUnsupported: %v", err)
	}
}

// TestParseSelectorUnprefixedErrorDoesNotOfferTag guards the OTHER half of
// #560, which the tag:-prefixed tests cannot see.
//
// Every surface renders this string verbatim -- the Console's fallback lead,
// MCP's "invalid selector" wrap, the Control API's problem detail -- so a
// stale namespace list here advertises tag: to the operator and the AI-agent for
// any ordinary typo, which is the exact false advertisement this issue exists
// to remove. It was stale in the first version of this change and no test saw
// it, because they all exercised the tag:-prefixed path.
func TestParseSelectorUnprefixedErrorDoesNotOfferTag(t *testing.T) {
	_, err := ParseSelector("bogus")
	if err == nil {
		t.Fatal("ParseSelector(\"bogus\") = nil error, want a parse error")
	}
	if strings.Contains(err.Error(), "tag:") {
		t.Errorf("the unprefixed-term error offers tag:, which is never accepted: %v", err)
	}
	// And it still names the three that DO work, so the message stays useful.
	for _, ns := range []string{"node:", "relay:", "state:"} {
		if !strings.Contains(err.Error(), ns) {
			t.Errorf("the unprefixed-term error does not name %s: %v", ns, err)
		}
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
		NodeID: "node-1",
	}.WithNodeLabels(map[string]string{"role": "web", "env": "prod"})); err != nil {
		t.Fatalf("Upsert(node-1): %v", err)
	}
	if err := reg.SetRelayLabels("node-1", map[string]string{"quarantine": "on"}); err != nil {
		t.Fatalf("SetRelayLabels(node-1): %v", err)
	}

	if _, err := reg.Upsert(registry.Report{
		NodeID: "node-2",
	}.WithNodeLabels(map[string]string{"role": "db", "env": "prod"})); err != nil {
		t.Fatalf("Upsert(node-2): %v", err)
	}

	// node-3 carries "quarantine=on" as a node-space label, not a relay-
	// space one. A relay:quarantine=on Selector must never match it.
	if _, err := reg.Upsert(registry.Report{
		NodeID: "node-3",
	}.WithNodeLabels(map[string]string{"role": "web", "quarantine": "on"})); err != nil {
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
		NodeID: "node-forged",
	}.WithNodeLabels(map[string]string{"offline": "true"})); err != nil {
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

// --- shape-key normalisation (#415) ---------------------------------------

// shapeKeyFor drives a real Selector string all the way through the production
// path — ParseSelector -> Shape -> approval.HashPlanShape — against a
// fixed Action, so what these cases compare is exactly what a parked Request
// stores.
func shapeKeyFor(t *testing.T, selector string) string {
	t.Helper()
	sel, err := ParseSelector(selector)
	if err != nil {
		t.Fatalf("ParseSelector(%q): %v", selector, err)
	}
	shape, err := sel.Shape()
	if err != nil {
		t.Fatalf("Shape(%q): %v", selector, err)
	}
	return approval.HashPlanShape(jobs.Action{
		Kind:          jobs.ActionOperation,
		OperationName: "service.restart",
		OperationArgs: map[string]string{"unit": "nginx"},
		RiskClass:     jobs.RiskClassMutate,
	}, shape)
}

// shapeKeyForSelector is shapeKeyFor for a Selector built as a STRUCT rather
// than parsed from a string.
//
// It exists because #560 made tag: unparseable, and the distinct-shapes table
// below needs tag: to stay covered: invariant 7's point is that the four
// namespaces target different Nodes, so a tag: predicate must not collide with
// a node: one carrying the same key and value. Losing that assertion because
// the parser stopped accepting the spelling would quietly narrow what this
// test proves.
func shapeKeyForSelector(t *testing.T, sel Selector) string {
	t.Helper()
	shape, err := sel.Shape()
	if err != nil {
		t.Fatalf("Shape(%+v): %v", sel, err)
	}
	return approval.HashPlanShape(jobs.Action{
		Kind:          jobs.ActionOperation,
		OperationName: "service.restart",
		OperationArgs: map[string]string{"unit": "nginx"},
		RiskClass:     jobs.RiskClassMutate,
	}, shape)
}

// TestShapeKey_SelectorNormalisation is the acceptance's table: which Selector
// spellings are the SAME shape, and which are emphatically not.
func TestShapeKey_SelectorNormalisation(t *testing.T) {
	same := []struct {
		name string
		a, b string
	}{
		{"term order", "node:role=web, node:env=prod", "node:env=prod, node:role=web"},
		{"whitespace around terms", "node:role=web,node:env=prod", "  node:role=web ,   node:env=prod  "},
		{"an exactly duplicated term", "node:role=web, node:role=web", "node:role=web"},
		{"state terms reordered", "state:offline, state:daemon-version=1.4.2", "state:daemon-version=1.4.2, state:offline"},
		{"an empty selector two ways", "", "   "},
	}
	for _, tt := range same {
		t.Run(tt.name, func(t *testing.T) {
			if shapeKeyFor(t, tt.a) != shapeKeyFor(t, tt.b) {
				t.Errorf("%q and %q are the same shape but hashed differently", tt.a, tt.b)
			}
		})
	}

	// Every one of these targets a DIFFERENT set of Nodes, so no two may share
	// a key. The namespace trio is invariant 7's half: the security lane must
	// never share a shape key with a routine one.
	distinct := map[string]string{
		"node":  "node:role=web",
		"relay": "relay:role=web",

		"state marker": "state:offline",
		"state fact":   "state:daemon-version=1.4.2",
		"empty":        "",
		"value case":   "node:role=Web",
		// node:role= parses cleanly to an EMPTY value (ParseSelector rejects
		// only an empty key), so it is a real term and its own shape.
		"empty value": "node:role=",
		"two terms":   "node:role=web, node:env=prod",
		"other value": "node:role=db",
	}
	seen := make(map[string]string, len(distinct))
	for name, selector := range distinct {
		key := shapeKeyFor(t, selector)
		if other, dup := seen[key]; dup {
			t.Errorf("%s (%q) and %s share a shape key", name, selector, other)
		}
		seen[key] = name
	}

	// tag: cannot be spelled any more (#560 refuses it at the parser), so it is
	// built as a struct to keep invariant 7's namespace separation asserted: a
	// tag: predicate must not share a shape key with the node: or relay: one
	// carrying the same key and value.
	tagKey := shapeKeyForSelector(t, Selector{Predicates: []Predicate{
		{Namespace: NamespaceTag, Key: "role", Value: "web"},
	}})
	if other, dup := seen[tagKey]; dup {
		t.Errorf("a tag: predicate shares a shape key with %s — the namespace "+
			"is not part of the shape", other)
	}

	// "Canonicalising namespace prefixes" must NOT have been implemented by
	// loosening the parser: an upper-case prefix is still not a namespace.
	if _, err := ParseSelector("NODE:role=web"); err == nil {
		t.Error("ParseSelector accepted NODE: — the parser was loosened in the name of canonicalisation")
	}
}

// TestNamespaceName_TotalAndDistinct: one mapping, used by both callers. A
// drift that mapped relay: to "node" would let a security-lane Selector share a
// shape key with a routine one.
func TestNamespaceName_TotalAndDistinct(t *testing.T) {
	want := map[Namespace]string{
		NamespaceNode:  "node",
		NamespaceRelay: "relay",
		NamespaceTag:   "tag",
		NamespaceState: "state",
	}
	seen := make(map[string]Namespace, len(want))
	for ns, token := range want {
		got := ns.Name()
		if got != token {
			t.Errorf("Namespace(%d).Name() = %q, want %q", ns, got, token)
		}
		if other, dup := seen[got]; dup {
			t.Errorf("namespaces %d and %d share the token %q", ns, other, got)
		}
		seen[got] = ns
	}
	if got := NamespaceUnspecified.Name(); got != "" {
		t.Errorf("NamespaceUnspecified.Name() = %q, want %q", got, "")
	}

	// NamespaceNames still returns the same tokens after the extraction.
	sel := Selector{Predicates: []Predicate{
		{Namespace: NamespaceNode, Key: "a", Value: "b"},
		{Namespace: NamespaceRelay, Key: "c", Value: "d"},
		{Namespace: NamespaceTag, Key: "e", Value: "f"},
		{Namespace: NamespaceState, Key: "offline"},
	}}
	if got := strings.Join(sel.NamespaceNames(), ","); got != "node,relay,tag,state" {
		t.Errorf("NamespaceNames() = %q, want %q", got, "node,relay,tag,state")
	}
}

// TestShape_RefusesUnspecifiedNamespace: a struct-literal Selector with no
// namespace fails closed rather than parking with a key that means nothing.
func TestShape_RefusesUnspecifiedNamespace(t *testing.T) {
	sel := Selector{Predicates: []Predicate{{Key: "role", Value: "web"}}}
	got, err := sel.Shape()
	if err == nil {
		t.Fatal("Shape accepted a Predicate with no namespace")
	}
	if got.Known {
		t.Error("a refused Selector came back marked Known; the error path must yield the zero value")
	}

	// The empty Selector is fine — it is a well-defined shape (the whole
	// fleet), not an error, and it is KNOWN.
	shape, err := Selector{}.Shape()
	if err != nil {
		t.Fatalf("Shape on an empty Selector: %v", err)
	}
	if !shape.Known {
		t.Error("the empty Selector came back unknown; it targets every Node, which is a fact, not an absence")
	}
	if len(shape.Terms) != 0 {
		t.Errorf("Shape on an empty Selector = %v, want no terms", shape.Terms)
	}
}
