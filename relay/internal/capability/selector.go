package capability

import (
	"fmt"
	"strings"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/registry"
)

// Namespace is the label namespace a Predicate is scoped to (ADR-0006,
// invariant 7). The zero value, NamespaceUnspecified, is deliberately
// invalid and never matches any Node — a Predicate must always name its
// namespace explicitly rather than fall back to "either".
type Namespace int

const (
	NamespaceUnspecified Namespace = iota
	NamespaceNode
	NamespaceRelay
)

// Predicate is a single "namespace:key=value" equality test. It is scoped to
// exactly one namespace; Matches never looks it up against the other one.
type Predicate struct {
	Namespace Namespace
	Key       string
	Value     string
}

// Selector is a label-based query that targets a set of Nodes (CONTEXT.md).
// A Node matches a Selector iff it matches every Predicate.
type Selector struct {
	Predicates []Predicate
}

// ParseSelector parses a comma-separated list of "node:key=value" and
// "relay:key=value" terms (e.g. "node:role=web, relay:quarantine=on").
// Every term MUST carry a node: or relay: prefix — an unprefixed term is a
// parse error. This is a fail-closed design: the parser never guesses which
// namespace a bare key belongs to (mirrors protoconv.ParseNodeLabel's
// prefix-stripping style, extended here to both namespaces).
//
// An empty (or all-whitespace) string parses to an empty Selector, which
// Resolve treats as matching every Node (see Resolve).
func ParseSelector(s string) (Selector, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return Selector{}, nil
	}

	terms := strings.Split(s, ",")
	predicates := make([]Predicate, 0, len(terms))
	for _, term := range terms {
		term = strings.TrimSpace(term)
		if term == "" {
			return Selector{}, fmt.Errorf("capability: empty selector term")
		}

		var ns Namespace
		var rest string
		switch {
		case strings.HasPrefix(term, "node:"):
			ns = NamespaceNode
			rest = strings.TrimPrefix(term, "node:")
		case strings.HasPrefix(term, "relay:"):
			ns = NamespaceRelay
			rest = strings.TrimPrefix(term, "relay:")
		default:
			return Selector{}, fmt.Errorf("capability: selector term %q has no node: or relay: prefix", term)
		}

		key, value, ok := strings.Cut(rest, "=")
		if !ok || key == "" {
			return Selector{}, fmt.Errorf("capability: malformed selector term %q, want namespace:key=value", term)
		}

		predicates = append(predicates, Predicate{Namespace: ns, Key: key, Value: value})
	}

	return Selector{Predicates: predicates}, nil
}

// Matches reports whether n satisfies every Predicate in sel. Each
// Predicate's lookup reads exactly one of n's two label maps — NamespaceNode
// reads only NodeLabels, NamespaceRelay reads only RelayLabels — so node:
// and relay: predicates can never be satisfied by the other namespace's
// labels. This mirrors the registry's structural two-disjoint-maps
// invariant (registry.go). A Predicate with the zero-value Namespace never
// matches (fail closed).
func (sel Selector) Matches(n registry.Node) bool {
	for _, p := range sel.Predicates {
		var labels map[string]string
		switch p.Namespace {
		case NamespaceNode:
			labels = n.NodeLabels
		case NamespaceRelay:
			labels = n.RelayLabels
		default:
			return false
		}
		if v, ok := labels[p.Key]; !ok || v != p.Value {
			return false
		}
	}
	return true
}

// Resolve returns every Node in reg that matches sel. A Selector with no
// Predicates matches every Node (inventory semantics — ADR-0003's
// list_nodes(selector?) is deliberately callable with no selector at all).
// Resolve itself never bounds the number of Nodes returned; guarding
// fan-out size against the blast-radius cap is the pipeline's job
// (Service.Run), not the resolver's.
func (sel Selector) Resolve(reg registry.Repository) []registry.Node {
	var matched []registry.Node
	for _, n := range reg.List() {
		if sel.Matches(n) {
			matched = append(matched, n)
		}
	}
	return matched
}
