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

// String renders sel back into the canonical "node:key=value, relay:key=value"
// form ParseSelector accepts — the true inverse of ParseSelector, used by the
// audit adapter to record "the Selector as written" (audit.Record.Selector).
// An empty Selector renders as "".
func (sel Selector) String() string {
	terms := make([]string, 0, len(sel.Predicates))
	for _, p := range sel.Predicates {
		var prefix string
		switch p.Namespace {
		case NamespaceNode:
			prefix = "node:"
		case NamespaceRelay:
			prefix = "relay:"
		default:
			prefix = ""
		}
		terms = append(terms, fmt.Sprintf("%s%s=%s", prefix, p.Key, p.Value))
	}
	return strings.Join(terms, ", ")
}

// Resolve returns every Node in reg that matches sel. A Selector with no
// Predicates matches every Node (inventory semantics — ADR-0003's
// list_nodes(selector?) is deliberately callable with no selector at all).
// Resolve itself never bounds the number of Nodes returned; guarding
// fan-out size against the blast-radius cap is the pipeline's job
// (Service.Run), not the resolver's.
// NamespaceNames returns the distinct label namespaces this Selector targets,
// as the lower-case names the approval-gate config uses ("node", "relay").
// It is how a gate rule expresses "anything targeting the security lane needs
// two people" (ADR-0027) without package approval knowing about Predicate.
//
// An empty Selector targets no namespace and matches every Node, so it returns
// nothing — a namespace-scoped rule must not fire on a match-everything
// Selector merely because that Selector also happens to reach `relay:`-labelled
// Nodes. Rules that should catch a match-everything dispatch are the fan-out
// ones (MinFanOut), which is the honest axis for that case.
func (sel Selector) NamespaceNames() []string {
	var out []string
	seen := make(map[Namespace]struct{}, len(sel.Predicates))
	for _, p := range sel.Predicates {
		if _, dup := seen[p.Namespace]; dup {
			continue
		}
		seen[p.Namespace] = struct{}{}
		switch p.Namespace {
		case NamespaceNode:
			out = append(out, "node")
		case NamespaceRelay:
			out = append(out, "relay")
		}
	}
	return out
}

func (sel Selector) Resolve(reg registry.Repository) []registry.Node {
	var matched []registry.Node
	for _, n := range reg.List() {
		if sel.Matches(n) {
			matched = append(matched, n)
		}
	}
	return matched
}
