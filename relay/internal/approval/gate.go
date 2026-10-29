package approval

import (
	"errors"
	"fmt"
	"strings"

	"github.com/Felag-Engineering/relay/relay/internal/jobs"
)

// Dispatch is what a Gate matches against: the facts about a resolved dispatch,
// in plain domain terms.
//
// It is a value rather than a reference to the capability layer's types on
// purpose — package approval must not import capability, because capability
// imports this. Passing the facts keeps the dependency one-directional and
// keeps this package testable without constructing a Service.
type Dispatch struct {
	RiskClass jobs.RiskClass

	// FanOut is the number of Nodes the Selector resolved to — the blast size
	// the approver will be told about, and the number a MinFanOut rule tests.
	FanOut int

	// Namespaces are the label namespaces the Selector used ("node", "relay",
	// "tag", "state"). A rule may match on one, which is how "anything
	// targeting the security lane needs two people" is expressed.
	Namespaces []string

	// Account is the requesting Account's name (verified lane).
	Account string

	// Operation is the structured Operation's name, empty for Raw Exec.
	Operation string

	// RawExec reports whether this is the Raw Exec path.
	RawExec bool
}

// Match is the "match" half of ADR-0027's rule grammar. Every field is
// optional; an omitted field matches anything. A Match with no fields set
// matches every dispatch, which is a legitimate way to say "everything needs
// approval".
type Match struct {
	// RiskClass matches read or mutate. RiskClassUnspecified matches any.
	RiskClass jobs.RiskClass

	// MinFanOut matches dispatches touching at least this many Nodes. Zero
	// matches any. Note this is >=, so MinFanOut:1 matches everything that
	// resolved to at least one Node.
	MinFanOut int

	// SelectorNamespace matches dispatches whose Selector used this namespace.
	// Empty matches any.
	SelectorNamespace string

	// Account matches this requesting Account by name. Empty matches any.
	Account string

	// Operation matches this Operation name. Empty matches any.
	Operation string

	// RawExec, when true, restricts the rule to the Raw Exec path. When false
	// the rule is not restricted (it is not "match only structured
	// Operations") — use Operation for that.
	RawExec bool
}

// matches reports whether d satisfies every set field of m.
func (m Match) matches(d Dispatch) bool {
	if m.RiskClass != jobs.RiskClassUnspecified && m.RiskClass != d.RiskClass {
		return false
	}
	if m.MinFanOut > 0 && d.FanOut < m.MinFanOut {
		return false
	}
	if m.SelectorNamespace != "" && !hasNamespace(d.Namespaces, m.SelectorNamespace) {
		return false
	}
	if m.Account != "" && !strings.EqualFold(m.Account, d.Account) {
		return false
	}
	if m.Operation != "" && !strings.EqualFold(m.Operation, d.Operation) {
		return false
	}
	if m.RawExec && !d.RawExec {
		return false
	}
	return true
}

func hasNamespace(have []string, want string) bool {
	for _, h := range have {
		if strings.EqualFold(h, want) {
			return true
		}
	}
	return false
}

// knownNamespaces is the namespace vocabulary a gate rule's selector_namespace
// may name (ADR-0006, ADR-0020, ADR-0034).
var knownNamespaces = []string{"node", "relay", "tag", "state"}

// IsKnownNamespace reports whether ns is exactly one of the selector
// namespaces a gate rule may name, case-sensitively. The configuration loader
// and Rule.Validate share it so both accept the same vocabulary.
func IsKnownNamespace(ns string) bool {
	for _, known := range knownNamespaces {
		if known == ns {
			return true
		}
	}
	return false
}

// Rule pairs a Match with the Requirement it imposes.
type Rule struct {
	// Name is an operator-chosen label, carried into the audit record so a
	// parked Job can say WHICH rule parked it. A gate that cannot explain
	// itself trains operators to disable it.
	Name string

	Match   Match
	Require Requirement
}

// Validate checks a Rule for the mistakes that would make it a silent no-op.
// Its messages are fixed text: they never carry the rule's name or a value
// (RC-18), because they reach logs and the startup error.
func (r Rule) Validate() error {
	if strings.TrimSpace(r.Name) == "" {
		return errors.New("rule has no name")
	}
	if r.Require.TTL < 0 {
		return errors.New("ttl must not be negative")
	}
	if r.Match.MinFanOut < 0 {
		return errors.New("min_fan_out must not be negative")
	}
	// The comparison is case-SENSITIVE, unlike hasNamespace's matching of a
	// dispatch's namespaces, because this validates a rule's own configuration
	// rather than something the Selector grammar has already normalized.
	if ns := r.Match.SelectorNamespace; ns != "" && !IsKnownNamespace(ns) {
		return errors.New("unknown selector namespace (want node, relay, tag, or state)")
	}
	return nil
}

// Gate is the evaluated approval-gate configuration: the configured rules
// deciding which dispatches must park (ADR-0027).
//
// The zero Gate has no rules and gates nothing, which is exactly the behaviour
// of a deployment that has not configured approvals. That is safe by
// construction rather than by accident: a Gate can only ever ADD a reason to
// stop, so an empty one leaves the pre-approval pipeline (Selector -> authz ->
// blast cap -> Policy) exactly as it was.
//
// What is NOT safe is an empty Gate that resulted from a configuration the
// Relay failed to read. The rules come from the configuration file's
// [[approval.rules]] sections: a file with none gates nothing, but one whose
// rules cannot be loaded is a startup error, never a silent zero.
type Gate struct {
	rules []Rule
}

// NewGate builds a Gate from rules, validating each. A refusal names the
// rule's 1-based position and never its name or a value (RC-18).
func NewGate(rules []Rule) (*Gate, error) {
	seen := make(map[string]struct{}, len(rules))
	for i, r := range rules {
		if err := r.Validate(); err != nil {
			return nil, fmt.Errorf("approval: rule %d: %w", i+1, err)
		}
		key := strings.ToLower(r.Name)
		if _, dup := seen[key]; dup {
			return nil, fmt.Errorf("approval: rule %d: repeats an earlier rule's name; names must be unique", i+1)
		}
		seen[key] = struct{}{}
	}
	out := make([]Rule, len(rules))
	copy(out, rules)
	return &Gate{rules: out}, nil
}

// Rules returns a copy of the configured rules, for rendering and tests.
func (g *Gate) Rules() []Rule {
	if g == nil {
		return nil
	}
	out := make([]Rule, len(g.rules))
	copy(out, g.rules)
	return out
}

// Evaluate reports whether d must be approved, and if so under what
// Requirement and which rules demanded it.
//
// Every matching rule applies, not the first: rule order is never
// security-relevant. When several match, the shortest TTL wins (AP-81), the
// narrower window being the more restrictive one.
func (g *Gate) Evaluate(d Dispatch) (Requirement, []string, bool) {
	if g == nil || len(g.rules) == 0 {
		return Requirement{}, nil, false
	}

	var (
		req   Requirement
		names []string
	)
	for _, r := range g.rules {
		if !r.Match.matches(d) {
			continue
		}
		ttl := r.Require.normalized().TTL
		if len(names) == 0 || ttl < req.TTL {
			req.TTL = ttl
		}
		names = append(names, r.Name)
	}
	if len(names) == 0 {
		return Requirement{}, nil, false
	}
	return req, names, true
}
