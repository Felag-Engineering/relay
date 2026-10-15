// Action resolution (ADR-0012, ADR-0042): how every Action's risk
// class and a Template Operation's fan-out and argument names are decided
// before anything is dispatched.
//
// A Native Operation's risk class is a constant the Relay compiled in
// (opvocab, ADR-0012) and Raw Exec is always mutate; both come from
// fixedRiskClass (riskclass.go). A Template Operation's class is a value each
// Node reports about itself (nodevocab, ADR-0021), so it cannot be known until
// the Selector is resolved, and a Node is exactly the party whose compromise
// the rest of the system is built to survive. resolveAction is the one place
// that decides a class for any Action, and it is reached only from
// Execution.Run and Execution.Plan — never from an adapter, which builds an Action
// with no class at all (invariants 10 and 13). An Action that arrives with a
// class is refused.
//
// The rules, each from ADR-0042:
//
//   - A matched Node that does not report the Template — or that the Relay
//     holds no vocabulary report for — is EXCLUDED: never sent a Task,
//     reported unsupported, and not counted by the blast cap, the approval
//     gate or the plan hash.
//   - The class is read only if every remaining Node reports read; any other
//     report makes the whole dispatch mutate. A Node can make a dispatch
//     stricter, never looser than its peers.
//   - The call's argument names must be exactly the Template's slot names on
//     every remaining Node; Nodes that disagree about the slot set refuse the
//     call rather than receive it piecemeal. Names only — values are the
//     daemon's (invariant 12).
//   - Each Task records ITS OWN Node's reported class, and output retention
//     (ADR-0025) follows that per-Task class — not the dispatch's. Most-
//     restrictive is the safe direction for the cap and the approval gate but
//     the unsafe one for retention: one Node reporting mutate must not cause
//     every other Node's read output to be kept. A Node can only change the
//     retention of its own output.
//   - A cached report whose fingerprint differs from the template-set
//     fingerprint the Node's latest Hello carried is stale — the daemon has
//     restarted with a different set and its new report has not landed yet —
//     and counts as no report at all.
//
// resolveAction COMPUTES and never refuses: the caller authorizes first and
// only then acts on resolvedAction.refusal, so a caller who may not ask
// learns nothing about which Nodes carry which Templates.
package capability

import (
	"fmt"
	"sort"
	"strings"

	"github.com/Felag-Engineering/relay/relay/internal/jobs"
	"github.com/Felag-Engineering/relay/relay/internal/nodevocab"
	"github.com/Felag-Engineering/relay/relay/internal/opvocab"
	"github.com/Felag-Engineering/relay/relay/internal/registry"
)

// TemplateNotInVocabularyReason is the Relay-authored stderr of a Task whose
// Node was excluded from a Template dispatch because its reported vocabulary
// does not contain the Template (ADR-0042). A fixed string: it carries no
// Node- or caller-controlled bytes.
const TemplateNotInVocabularyReason = "not dispatched: this Node does not report this Template Operation, " +
	"so the Relay excluded it from the dispatch and sent it nothing (ADR-0042). " +
	"list_operations with this Node's ID shows what it does report."

// TemplateNotReportedReason is the Relay-authored stderr of a Task whose Node
// was excluded because the Relay holds no vocabulary report for it at all —
// typically a Node that has not reconnected since the Relay last started,
// since the vocabulary cache is in memory. Distinct from
// TemplateNotInVocabularyReason so a caller can tell "this Node does not have
// it" from "this Node has not told us" (ADR-0042).
const TemplateNotReportedReason = "not dispatched: the Relay holds no current Template vocabulary report for this " +
	"Node (none since the Relay started, or one older than the Node's latest connection), so the Relay cannot " +
	"see whether it has this Template and sent it nothing (ADR-0042)."

// excludedNode is one matched Node left out of a Template dispatch, with the
// Relay-authored reason recorded on its unsupported Task.
type excludedNode struct {
	node   registry.Node
	reason string
}

// resolvedAction is resolveAction's result: the Action with its class
// decided, the Nodes that will actually be dispatched, the Nodes excluded
// from it, and — if the dispatch must be refused — why. For a Native
// Operation or Raw Exec it is the input with its fixed class and every matched
// Node dispatched.
//
// nodeClass is each dispatched Node's OWN reported class for a Template
// (nil for a Native Operation or Raw Exec, whose class is the Action's): the
// class its Task is recorded under, which decides whether its output is
// retained.
type resolvedAction struct {
	act         jobs.Action
	nodes       []registry.Node
	nodeClass   map[string]jobs.RiskClass
	excluded    []excludedNode
	refusal     error
	refusalKind RefusalKind
}

// isTemplateAction reports whether act names an Operation outside the frozen
// Native vocabulary. Every such name is treated as a Template Operation and
// resolved against the Nodes' reports — including a name no Node has, which
// resolveAction refuses as an unknown operation.
func isTemplateAction(act jobs.Action) bool {
	if act.Kind != jobs.ActionOperation {
		return false
	}
	_, native := opvocab.Lookup(act.OperationName)
	return !native
}

// resolveAction decides an Action's class and, for a Template, its dispatch
// over matched; see this file's header for the rules. It never refuses on its own: a refusal is
// returned as data for the caller to act on after authorization.
func (s *Execution) resolveAction(act jobs.Action, matched []registry.Node) resolvedAction {
	if !isTemplateAction(act) {
		out := resolvedAction{act: act, nodes: matched}
		// Written even on the refusal path, so a refused Action never carries
		// an adapter-supplied class onward.
		out.act.RiskClass = fixedRiskClass(act)
		if act.RiskClass != jobs.RiskClassUnspecified {
			out.refusalKind = RefusalInternal
			out.refusal = &ClassPresetError{Kind: act.Kind, Operation: act.OperationName, Class: act.RiskClass}
		}
		return out
	}

	// An adapter never decides a Template's class (invariants 10 and 13). A
	// class already present means a surface tried to; refuse rather than trust
	// it. Unlike the branch above, the preset stays on the returned Action: a
	// Template's class is unknowable without the Nodes' reports, and a refusal
	// never reaches a cap check or a Task.
	if act.RiskClass != jobs.RiskClassUnspecified {
		return resolvedAction{act: act, nodes: matched, refusalKind: RefusalInternal,
			refusal: &TemplateClassPresetError{Operation: act.OperationName, Class: act.RiskClass}}
	}

	out := resolvedAction{act: act, nodeClass: map[string]jobs.RiskClass{}}
	var (
		supporting  []nodevocab.Template
		notReported int
	)
	for _, n := range matched {
		snap, ok := s.templateSnapshot(n.NodeID)
		if !ok || snap.Fingerprint != n.TemplateSetFingerprint {
			notReported++
			out.excluded = append(out.excluded, excludedNode{node: n, reason: TemplateNotReportedReason})
			continue
		}
		t, ok := findTemplate(snap, act.OperationName)
		if !ok {
			out.excluded = append(out.excluded, excludedNode{node: n, reason: TemplateNotInVocabularyReason})
			continue
		}
		out.nodes = append(out.nodes, n)
		out.nodeClass[n.NodeID] = reportedClass(t)
		supporting = append(supporting, t)
	}

	if len(out.nodes) == 0 {
		out.refusalKind = RefusalUnknownOperation
		out.refusal = &UnknownOperationError{Operation: act.OperationName, Matched: len(matched), NotReported: notReported}
		return out
	}

	out.act.RiskClass = mostRestrictiveClass(supporting)

	if err := checkSlotAgreement(act.OperationName, out.nodes, supporting); err != nil {
		out.refusalKind = RefusalMalformed
		out.refusal = err
		return out
	}
	if err := opvocab.ValidateArgNames(templateDescriptor(supporting[0]), act.OperationArgs); err != nil {
		out.refusalKind = RefusalMalformed
		out.refusal = &MalformedCallError{Operation: act.OperationName, Reason: err.Error()}
		return out
	}
	return out
}

// templateSnapshot reads one Node's reported Template vocabulary. An Execution
// with no vocabulary source wired holds no report for any Node, which
// excludes every Node rather than dispatching blind.
func (s *Execution) templateSnapshot(nodeID string) (nodevocab.Snapshot, bool) {
	if s.read.nodeVocab == nil {
		return nodevocab.Snapshot{}, false
	}
	return s.read.nodeVocab.Get(nodeID)
}

// findTemplate returns the Template named name in snap, if the Node reports it.
func findTemplate(snap nodevocab.Snapshot, name string) (nodevocab.Template, bool) {
	for _, t := range snap.Templates {
		if t.Name == name {
			return t, true
		}
	}
	return nodevocab.Template{}, false
}

// mostRestrictiveClass is ADR-0042's class rule: read only if every reporting
// Node reports read. Mutate, unspecified, and any value outside the enum all
// make the dispatch mutate — an unrecognised report is never read as the
// looser class.
func mostRestrictiveClass(templates []nodevocab.Template) jobs.RiskClass {
	for _, t := range templates {
		if reportedClass(t) != jobs.RiskClassRead {
			return jobs.RiskClassMutate
		}
	}
	return jobs.RiskClassRead
}

// reportedClass is one Node's report of t's class, read the safe way: read
// only if it says exactly read, and mutate for anything else, including an
// unspecified or out-of-range value.
func reportedClass(t nodevocab.Template) jobs.RiskClass {
	if jobs.RiskClass(t.RiskClass) == jobs.RiskClassRead {
		return jobs.RiskClassRead
	}
	return jobs.RiskClassMutate
}

// slotNames returns t's slot names, sorted, so two Templates are compared as
// sets of names rather than by declaration order.
func slotNames(t nodevocab.Template) []string {
	names := make([]string, 0, len(t.Slots))
	for _, sl := range t.Slots {
		names = append(names, sl.Name)
	}
	sort.Strings(names)
	return names
}

// checkSlotAgreement refuses a call whose remaining Nodes disagree about the
// Template's slot names: one call cannot be well-formed for both, and sending
// it to whichever Nodes it happens to fit would turn a vocabulary
// disagreement into per-Node failures (ADR-0042).
func checkSlotAgreement(name string, nodes []registry.Node, templates []nodevocab.Template) error {
	want := slotNames(templates[0])
	for i := 1; i < len(templates); i++ {
		got := slotNames(templates[i])
		if !equalStrings(want, got) {
			return &MalformedCallError{Operation: name, Reason: fmt.Sprintf(
				"the matched Nodes do not agree on this Template's arguments: Node %q declares %v and Node %q declares %v. "+
					"The Relay will not send one call to Nodes that disagree about its arguments; narrow the Selector "+
					"to Nodes carrying the same Template definition (see list_operations with a node_id)",
				nodes[0].NodeID, want, nodes[i].NodeID, got)}
		}
	}
	return nil
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// templateDescriptor presents a Template's slots in opvocab's ArgConstraints
// convention, so ValidateArgNames — the one definition of the argument-name
// check (ADR-0042) — serves Templates too rather than a second copy drifting
// from it. Every slot is required: the daemon's Template engine has no optional
// slots.
func templateDescriptor(t nodevocab.Template) opvocab.Descriptor {
	constraints := make(map[string]string, len(t.Slots))
	for _, sl := range t.Slots {
		constraints[sl.Name] = sl.Type + ", required."
	}
	return opvocab.Descriptor{Name: t.Name, ArgConstraints: constraints}
}

// UnknownOperationError is the refusal for an Operation name that is not
// Native and that no matched Node reports as a Template Operation (ADR-0042).
// Refused after authorization and before any Job exists. Exported and typed
// so a surface recognises it via errors.As (the NoNodesMatchedError
// precedent). NotReported counts matched Nodes the Relay holds no vocabulary
// report for, so the caller can tell a missing Template from a Relay that has
// not heard from its Nodes yet.
type UnknownOperationError struct {
	Operation   string
	Matched     int
	NotReported int
}

func (e *UnknownOperationError) Error() string {
	var b strings.Builder
	fmt.Fprintf(&b, "unknown operation %q: it is not a Native Operation, and none of the %d matched Node(s) "+
		"reports it as a Template Operation", e.Operation, e.Matched)
	if e.NotReported > 0 {
		fmt.Fprintf(&b, " (%d of them have no current Template vocabulary report: none since the Relay started, "+
			"or one older than the Node's latest connection)", e.NotReported)
	}
	b.WriteString(". See list_operations — with a node_id for that Node's Template Operations.")
	return b.String()
}

// MalformedCallError is the refusal for a Template call whose argument names
// do not match the Template's slots, or whose matched Nodes disagree about
// what those slots are (ADR-0042). Malformed, never a Policy verdict: the
// call is refused before any Node is asked.
type MalformedCallError struct {
	Operation string
	Reason    string
}

func (e *MalformedCallError) Error() string {
	return fmt.Sprintf("malformed call to %q: %s", e.Operation, e.Reason)
}

// TemplateClassPresetError is the refusal for a Template Action that reached
// the capability layer already carrying a risk class. Only this layer decides
// a Template's class (ADR-0042, invariant 10); an adapter that set one has a
// bug, and the dispatch fails closed rather than trusting it.
type TemplateClassPresetError struct {
	Operation string
	Class     jobs.RiskClass
}

func (e *TemplateClassPresetError) Error() string {
	return fmt.Sprintf("capability: refusing Template Operation %q: it arrived with risk class %q already set, "+
		"but only the capability layer decides a Template's class (ADR-0042, invariant 10)",
		e.Operation, jobs.RiskClassName(e.Class))
}
