package approval

import (
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

// isKnownNamespace reports whether ns is exactly one of knownNamespaces
// (grant.go), case-sensitively. It is the single vocabulary check behind
// Rule.Validate's selector_namespace acceptance, so that list can never drift
// from what RequirementForScope prices a Grant over.
func isKnownNamespace(ns string) bool {
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

// Validate checks a Rule for the mistakes that would make it a silent no-op or
// an unsatisfiable park. It is called by the loader, so a bad rule fails at
// load rather than at 3am.
func (r Rule) Validate() error {
	if strings.TrimSpace(r.Name) == "" {
		return fmt.Errorf("approval: rule has no name")
	}
	if r.Require.Count < 1 {
		return fmt.Errorf("approval: rule %q: count must be at least 1", r.Name)
	}
	if r.Require.Count > MaxCount {
		return fmt.Errorf("approval: rule %q: count %d exceeds the v1 maximum of %d", r.Name, r.Require.Count, MaxCount)
	}
	if r.Require.TTL < 0 {
		return fmt.Errorf("approval: rule %q: ttl must not be negative", r.Name)
	}
	if err := ValidateAudience(r.Require.Audience); err != nil {
		return fmt.Errorf("approval: rule %q: require.audience: %w; an audience names the Accounts that may decide and a blank entry names none, so remove it or name an Account",
			r.Name, err)
	}
	// A rule that excludes the requester and has an audience of exactly the
	// requester can never be satisfied. We cannot know the requester at load
	// time, but we CAN catch the unconditional version: count 2 with a
	// single-member audience is unsatisfiable, because quorum needs distinct
	// deciders.
	if r.Require.Count > 1 && len(r.Require.Audience) > 0 && len(r.Require.Audience) < r.Require.Count {
		return fmt.Errorf(
			"approval: rule %q: count %d with an audience of %d cannot ever be satisfied — quorum needs distinct deciders",
			r.Name, r.Require.Count, len(r.Require.Audience))
	}
	if r.Match.MinFanOut < 0 {
		return fmt.Errorf("approval: rule %q: min_fan_out must not be negative", r.Name)
	}
	// Consults knownNamespaces (grant.go) rather than a second hardcoded list:
	// that is the one vocabulary a Grant is priced over, and a namespace added
	// there without being added here would let a Grant be priced below a rule
	// this Validate would happily accept. The accepted set and the error text
	// are unchanged — knownNamespaces is exactly {node, relay, tag, state} —
	// and the comparison stays case-SENSITIVE, unlike hasNamespace's matching
	// of a dispatch's namespaces, because this validates a rule's own
	// configuration rather than something the Selector grammar has already
	// normalized.
	if ns := r.Match.SelectorNamespace; ns != "" && !isKnownNamespace(ns) {
		return fmt.Errorf("approval: rule %q: unknown selector namespace %q (want node, relay, tag, or state)",
			r.Name, ns)
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
// What is NOT safe is an empty Gate that resulted from a config file the Relay
// failed to read. That distinction is the loader's job (see Load): a missing
// path means "no approvals configured", but an unreadable or invalid file is a
// startup error, never a silent zero.
type Gate struct {
	rules []Rule
}

// NewGate builds a Gate from rules, validating each.
func NewGate(rules []Rule) (*Gate, error) {
	seen := make(map[string]struct{}, len(rules))
	for _, r := range rules {
		if err := r.Validate(); err != nil {
			return nil, err
		}
		key := strings.ToLower(r.Name)
		if _, dup := seen[key]; dup {
			return nil, fmt.Errorf("approval: duplicate rule name %q — names identify which rule parked a Job, so they must be unique", r.Name)
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
// When several rules match, their Requirements merge to the STRICTEST
// (mergeStricter) rather than first-match-wins. First-match-wins would make
// rule order security-relevant and would let a broad permissive rule shadow a
// narrow strict one — the mistake that makes firewall rulesets dangerous. Here,
// adding a rule can only ever tighten the outcome.
func (g *Gate) Evaluate(d Dispatch) (Requirement, []string, bool) {
	if g == nil || len(g.rules) == 0 {
		return Requirement{}, nil, false
	}

	var (
		merged  Requirement
		names   []string
		matched bool
	)
	for _, r := range g.rules {
		if !r.Match.matches(d) {
			continue
		}
		req := r.Require.normalized()
		if !matched {
			merged, matched = req, true
		} else {
			merged = mergeStricter(merged, req)
		}
		names = append(names, r.Name)
	}
	if !matched {
		return Requirement{}, nil, false
	}
	return merged.normalized(), names, true
}
