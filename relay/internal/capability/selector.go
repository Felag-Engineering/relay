package capability

import (
	"fmt"
	"strings"
	"time"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/approval"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/nodestate"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/registry"
)

// Namespace is the label namespace a Predicate is scoped to (ADR-0006,
// ADR-0020, ADR-0034, invariant 7). The zero value, NamespaceUnspecified, is
// deliberately invalid and never matches any Node — a Predicate must always
// name its namespace explicitly rather than fall back to "either".
//
// Values are APPENDED, never renumbered: Namespace is compared in switches
// across capability, mcp, api and console, and a reordering would silently
// re-point every existing switch arm.
type Namespace int

const (
	NamespaceUnspecified Namespace = iota
	NamespaceNode
	NamespaceRelay
	NamespaceTag
	NamespaceState
)

// StateEval is the evaluation context a `state:` Predicate needs beyond the
// Node's own record: the instant this resolution is happening at, and the
// certificate-expiry warning window (file-only configuration, invariant 11).
//
// A zero StateEval means `state:cert-expiring` can never fire (a zero
// CertExpiringWithin — see nodestate.Input) — the composition root always
// sets a real one, and every surface that resolves a Selector (MCP, the
// Control API, the Console) is handed the SAME value, so a wiring test pins
// that a zero StateEval never reaches production.
type StateEval struct {
	Now                time.Time
	CertExpiringWithin time.Duration
}

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

// ParseSelector parses a comma-separated list of "node:key=value",
// "relay:key=value", "tag:key=value" and "state:key[=value]" terms (e.g.
// "node:role=web, relay:quarantine=on"). Every term MUST carry one of the
// four namespace prefixes — an unprefixed term is a parse error. This is a
// fail-closed design: the parser never guesses which namespace a bare key
// belongs to (mirrors protoconv.ParseNodeLabel's prefix-stripping style,
// extended here to all four namespaces).
//
// node:, relay: and tag: keep the same "key=value, value required" grammar.
// state: is different because it is closed-vocabulary and typed (ADR-0034):
// a boolean marker term carries no value ("state:offline") and a fact term
// requires a non-empty one ("state:daemon-version=1.4.2"). Both directions
// are parse errors rather than a silently-empty match: a marker written with
// a value, a fact written without one, an empty fact value, or any key
// outside the closed vocabulary (nodestate.KeyKind).
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
		case strings.HasPrefix(term, "tag:"):
			ns = NamespaceTag
			rest = strings.TrimPrefix(term, "tag:")
		case strings.HasPrefix(term, "state:"):
			p, err := parseStateTerm(term, strings.TrimPrefix(term, "state:"))
			if err != nil {
				return Selector{}, err
			}
			predicates = append(predicates, p)
			continue
		default:
			return Selector{}, fmt.Errorf(
				"capability: selector term %q has no node:, relay:, tag:, or state: prefix", term)
		}

		key, value, ok := strings.Cut(rest, "=")
		if !ok || key == "" {
			return Selector{}, fmt.Errorf("capability: malformed selector term %q, want namespace:key=value", term)
		}

		predicates = append(predicates, Predicate{Namespace: ns, Key: key, Value: value})
	}

	return Selector{Predicates: predicates}, nil
}

// parseStateTerm parses the part of a `state:` term after the prefix, against
// the closed vocabulary nodestate.KeyKind enumerates. term is the whole
// original term, kept only for error messages.
func parseStateTerm(term, rest string) (Predicate, error) {
	key, value, hasValue := strings.Cut(rest, "=")
	if key == "" {
		return Predicate{}, fmt.Errorf("capability: malformed selector term %q, want state:key or state:key=value", term)
	}

	switch kind := nodestate.KeyKind(key); kind {
	case nodestate.KindMarker:
		if hasValue {
			return Predicate{}, fmt.Errorf(
				"capability: %q is a boolean marker and takes no value (want state:%s)", term, key)
		}
		return Predicate{Namespace: NamespaceState, Key: key}, nil
	case nodestate.KindFact:
		if !hasValue || value == "" {
			// An empty fact value can never match — Facts omits it entirely
			// rather than emitting `state:key=` — so a term with one would
			// silently match nothing, which is exactly the failure mode a
			// closed vocabulary exists to turn into a parse error.
			return Predicate{}, fmt.Errorf(
				"capability: %q is a fact and requires a non-empty value (want state:%s=value)", term, key)
		}
		return Predicate{Namespace: NamespaceState, Key: key, Value: value}, nil
	default:
		return Predicate{}, fmt.Errorf(
			"capability: %q is not a state: label; the closed vocabulary is markers %v and facts %v",
			term, nodestate.MarkerKeys(), nodestate.FactKeys())
	}
}

// Matches reports whether n satisfies every Predicate in sel, evaluated at
// ev. Each Predicate's lookup reads exactly one namespace's map — NamespaceNode
// reads only NodeLabels, NamespaceRelay reads only RelayLabels, NamespaceState
// reads a nodestate.LabelSet computed for n — so a predicate in one namespace
// can never be satisfied by another namespace's labels. This mirrors the
// registry's structural disjoint-maps invariant (registry.go): a forged
// NodeLabels["offline"]="true" can never satisfy state:offline, because
// NamespaceState never looks at NodeLabels at all. A Predicate with the
// zero-value Namespace never matches (fail closed).
//
// state's map is computed at most once per call, not once per Predicate:
// Resolve runs Matches per Node over a registry that may hold 100k of them,
// and nodestate.Labels is not free.
func (sel Selector) Matches(n registry.Node, ev StateEval) bool {
	var states map[string]string
	for _, p := range sel.Predicates {
		if p.Namespace == NamespaceState {
			states = nodestate.LabelSet(nodestate.Input{
				Node: n, Now: ev.Now, CertExpiringWithin: ev.CertExpiringWithin,
			})
			break
		}
	}

	for _, p := range sel.Predicates {
		var labels map[string]string
		switch p.Namespace {
		case NamespaceNode:
			labels = n.NodeLabels
		case NamespaceRelay:
			labels = n.RelayLabels
		case NamespaceState:
			labels = states
		case NamespaceTag:
			// tag-space has no storage on registry.Node until the label-
			// management write path lands (#430), so no Node carries one —
			// "matches nothing" is the true answer today, not a placeholder.
			return false
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
// An empty Selector renders as "". A NamespaceState Predicate with an empty
// Value renders as "state:key" (a marker, no trailing "="); with a Value it
// renders as "state:key=value" (a fact) — the same asymmetry ParseSelector
// requires, so this round-trips through it exactly.
func (sel Selector) String() string {
	terms := make([]string, 0, len(sel.Predicates))
	for _, p := range sel.Predicates {
		switch p.Namespace {
		case NamespaceNode:
			terms = append(terms, fmt.Sprintf("node:%s=%s", p.Key, p.Value))
		case NamespaceRelay:
			terms = append(terms, fmt.Sprintf("relay:%s=%s", p.Key, p.Value))
		case NamespaceTag:
			terms = append(terms, fmt.Sprintf("tag:%s=%s", p.Key, p.Value))
		case NamespaceState:
			if p.Value == "" {
				terms = append(terms, "state:"+p.Key)
			} else {
				terms = append(terms, fmt.Sprintf("state:%s=%s", p.Key, p.Value))
			}
		default:
			terms = append(terms, fmt.Sprintf("%s=%s", p.Key, p.Value))
		}
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
// as the lower-case names the approval-gate config uses ("node", "relay",
// "tag", "state"). It is how a gate rule expresses "anything targeting the
// security lane needs two people" (ADR-0027) without package approval knowing
// about Predicate.
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
		if name := p.Namespace.Name(); name != "" {
			out = append(out, name)
		}
	}
	return out
}

// Name is the lower-case token for n ("node", "relay", "tag", "state"), or ""
// for NamespaceUnspecified.
//
// ONE mapping, used by NamespaceNames and by Shape. Two switches would be
// free to drift, and a drift that mapped relay: to "node" would let a
// security-lane Selector share an approval shape key with a routine one
// (invariant 7).
func (n Namespace) Name() string {
	switch n {
	case NamespaceNode:
		return "node"
	case NamespaceRelay:
		return "relay"
	case NamespaceTag:
		return "tag"
	case NamespaceState:
		return "state"
	default:
		return ""
	}
}

// Shape projects sel into the normalised form the approval shape key is
// computed over (#415, approval.HashPlanShape).
//
// It is built from the TYPED Predicate, never from Selector text: the namespace
// travels as its own length-prefixed field, so no key or value — however it is
// spelled — can forge a namespace boundary, and a `tag:` term can never
// normalise into anything a `relay:` term could collide with. Nothing is
// case-folded or trimmed here; whitespace-insensitivity comes from
// ParseSelector, which trims around terms, not from mangling a key or a value
// that Selector.Matches compares exactly.
//
// A Predicate with no namespace is an ERROR rather than a blank token, so a
// struct-literal Selector fails closed instead of parking with a key that means
// nothing.
//
// This is the only place approval.SelectorShape.Known is set: a Selector this
// method saw is a Selector that was known, INCLUDING the empty one, which
// targets the whole fleet rather than nothing.
func (sel Selector) Shape() (approval.SelectorShape, error) {
	terms := make([]approval.SelectorTerm, 0, len(sel.Predicates))
	for _, p := range sel.Predicates {
		name := p.Namespace.Name()
		if name == "" {
			return approval.SelectorShape{}, fmt.Errorf(
				"capability: selector predicate %q has no namespace; a shape key must name one of node, relay, tag, state", p.Key)
		}
		terms = append(terms, approval.SelectorTerm{Namespace: name, Key: p.Key, Value: p.Value})
	}
	return approval.SelectorShape{Known: true, Terms: terms}, nil
}

// Resolve returns every Node in reg that matches sel, evaluated at ev. A
// Selector with no Predicates matches every Node (inventory semantics —
// ADR-0003's list_nodes(selector?) is deliberately callable with no selector
// at all). Resolve itself never bounds the number of Nodes returned; guarding
// fan-out size against the blast-radius cap is the pipeline's job
// (Service.Run), not the resolver's.
//
// Every Node in one Resolve call is evaluated against the SAME ev — one
// instant, one cert-expiring window — so a single resolution is internally
// consistent: a Node cannot be `state:offline` for one Predicate and judged
// against a different clock reading for another.
func (sel Selector) Resolve(reg registry.Repository, ev StateEval) []registry.Node {
	var matched []registry.Node
	for _, n := range reg.List() {
		if sel.Matches(n, ev) {
			matched = append(matched, n)
		}
	}
	return matched
}
