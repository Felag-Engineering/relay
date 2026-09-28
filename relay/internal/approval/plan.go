package approval

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/jobs"
)

// HashPlan content-addresses what an approver is being asked to approve: the
// Action and the RESOLVED FAN-OUT, together.
//
// Including the fan-out is the whole point. An approval bound to "Job X" would
// let a requester park something innocuous, wait for the human, and have the
// registry drift underneath it so the approved Job lands on a different — and
// larger — set of Nodes than the one described to the approver. Binding to the
// resolved node set means that drift changes the hash, the hash no longer
// matches at dispatch, and the Job re-parks for re-approval (ADR-0027). It is
// the approval-flow analog of ADR-0011's plan-verdicts-match-execution property.
//
// The encoding is explicit and length-prefixed rather than "join with a
// separator", because a separator-joined encoding is ambiguous: an argument
// containing the separator could make two different Plans hash identically, and
// arguments here are caller-controlled. Every variable-length field is written
// as its byte length, a colon, then its bytes (encoding.go's writeField), and
// every repeated block is preceded by a decimal count (writeCount).
//
// Node IDs and argument keys are sorted, so the hash is a property of the Plan
// rather than of map iteration order or the registry's result ordering.
//
// # #494: the argument encoding used to be ambiguous
//
// Until #494, an Operation argument's KEY was folded into the field NAME
// (write("arg."+k, v)) instead of being written as its own field. Because the
// key is caller-controlled and unescaped inside the field name, the key/value
// boundary was not unique. Witness, executed against the old encoding:
//
//	{"a": "1=1:x"}   ->  arg.a=5:1=1:x\n
//	{"a=5:1": "x"}   ->  arg.a=5:1=1:x\n     byte-identical
//
// Two different Actions produced the same bytes and therefore the same
// PlanHash. Every argument is now written as TWO separate length-prefixed
// fields — its key under the literal field name "arg.k" and its value under
// the literal field name "arg.v" — matching HashPlanShape (shape.go). No
// caller-influenced byte occupies a field name anywhere in this function, so
// the key/value boundary cannot be forged: the decoder always knows a field's
// name ends at "=", because the name is a compile-time literal, and always
// knows where its value ends, because the value is length-prefixed.
//
// The reachable path for this was Template Operations (ADR-0021): native
// Operations are constrained to opvocab's declared argument names
// (opvocab.ValidateArgNames), which cannot carry the "="/":" needed to forge
// the split, but a Template Operation's argument keys are exactly the ones
// opvocab has never declared. The two ValidateArgNames call sites
// (mcp/tools_execution.go, api/execution.go) were the only thing holding the
// boundary shut — a validator on two surfaces, not a property of the hash.
//
// Changing this encoding changes every Plan's hash, including every value
// already stored in approval_requests.plan_hash. A stale row can never equal a
// freshly computed HashPlan again, so ByPlanHash (capability/approval.go)
// misses and the dispatch FAILS CLOSED: it re-parks for a fresh human
// decision instead of releasing against a hash nobody can recompute. Moving
// this encoding again is therefore a stored-record decision, not a refactor.
//
// What is deliberately NOT hashed: the requester, the timeout, and the Selector
// text. The requester is bound separately on the Request (RequestedByID) and is
// not part of what is being approved. The timeout does not change what runs
// where. The Selector is excluded because two different Selector spellings that
// resolve to the same Nodes describe the same blast radius — the resolved set
// is the truth, and hashing the text would re-park Jobs over a cosmetic
// rewrite while missing drift that kept the text identical.
func HashPlan(act jobs.Action, nodeIDs []string) string {
	h := sha256.New()

	writeField(h, "kind", ActionKindName(act.Kind))
	writeField(h, "risk", jobs.RiskClassName(act.RiskClass))

	switch act.Kind {
	case jobs.ActionOperation:
		writeField(h, "op", act.OperationName)
		keys := make([]string, 0, len(act.OperationArgs))
		for k := range act.OperationArgs {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		writeCount(h, "args", len(keys))
		for _, k := range keys {
			writeField(h, "arg.k", k)
			writeField(h, "arg.v", act.OperationArgs[k])
		}
	case jobs.ActionRawExec:
		// argv order is semantic — never sorted.
		writeCount(h, "argv", len(act.RawExecArgv))
		for _, a := range act.RawExecArgv {
			writeField(h, "argv.v", a)
		}
	}

	sorted := append([]string(nil), nodeIDs...)
	sort.Strings(sorted)
	writeCount(h, "nodes", len(sorted))
	for _, n := range sorted {
		writeField(h, "node", n)
	}

	return hex.EncodeToString(h.Sum(nil))
}

func ActionKindName(k jobs.ActionKind) string {
	switch k {
	case jobs.ActionOperation:
		return "operation"
	case jobs.ActionRawExec:
		return "raw_exec"
	default:
		return "unspecified"
	}
}

// ParseActionKind is ActionKindName's inverse, used by the store to read back a
// persisted Request.
//
// An unrecognized name maps to jobs.ActionUnspecified rather than to an error,
// and that is deliberately the SAFE direction rather than a lenient one:
// authz.RoleGate denies an unspecified Action kind for every role including
// admin, so a stored row this build cannot interpret becomes undecidable, not
// decidable by whichever floor happened to be weakest.
func ParseActionKind(s string) jobs.ActionKind {
	switch s {
	case "operation":
		return jobs.ActionOperation
	case "raw_exec":
		return jobs.ActionRawExec
	default:
		return jobs.ActionUnspecified
	}
}

// ParseRiskClassName is RiskClassName's inverse. Unlike ParseActionKind it is
// not a security boundary — risk class picks the blast cap at dispatch, and
// that decision is made from the live Action, never from this stored copy,
// which exists for rendering and filtering the queue.
func ParseRiskClassName(s string) jobs.RiskClass {
	switch s {
	case "read":
		return jobs.RiskClassRead
	case "mutate":
		return jobs.RiskClassMutate
	default:
		return jobs.RiskClassUnspecified
	}
}

// PlanSummary is the Relay-authored description of a parked dispatch — the text
// a human actually reads before deciding.
//
// It is built HERE, from the Relay's own resolved state, and never from
// anything the requesting AI-agent supplied as prose. That is the structural
// answer to the approval-view fidelity gap: the agent chooses the Action, but
// it does not get to choose the words describing the Action, so it cannot
// truncate, soften, or misrepresent what it is asking for (ADR-0027).
type PlanSummary struct {
	Action    string
	RiskClass string
	NodeCount int
	// SampleNodes is a bounded sample for legibility at fleet scale; NodeCount
	// is always the true total, so a summary can never understate blast radius.
	SampleNodes []string
	PlanHash    string
}

// SampleLimit bounds SampleNodes.
const SampleLimit = 10

// String renders the summary as the single line an approver reads. The node
// count is always the true total and is stated before the sample, so a
// truncated list can never be mistaken for the whole blast radius.
func (s PlanSummary) String() string {
	line := fmt.Sprintf("%s [%s] on %d node(s)", s.Action, s.RiskClass, s.NodeCount)
	if len(s.SampleNodes) > 0 {
		line += ": " + strings.Join(s.SampleNodes, ", ")
		if s.NodeCount > len(s.SampleNodes) {
			line += fmt.Sprintf(", and %d more", s.NodeCount-len(s.SampleNodes))
		}
	}
	return line
}

// Summarize renders act over nodeIDs into the approver-facing summary.
func Summarize(act jobs.Action, nodeIDs []string) PlanSummary {
	sorted := append([]string(nil), nodeIDs...)
	sort.Strings(sorted)

	sample := sorted
	if len(sample) > SampleLimit {
		sample = sample[:SampleLimit]
	}

	return PlanSummary{
		Action:      describeAction(act),
		RiskClass:   jobs.RiskClassName(act.RiskClass),
		NodeCount:   len(nodeIDs),
		SampleNodes: sample,
		PlanHash:    HashPlan(act, nodeIDs),
	}
}

// describeAction renders the Action in the same shape the Operation vocabulary
// uses, with arguments sorted so the same Action always reads the same way.
func describeAction(act jobs.Action) string {
	switch act.Kind {
	case jobs.ActionOperation:
		keys := make([]string, 0, len(act.OperationArgs))
		for k := range act.OperationArgs {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		parts := make([]string, 0, len(keys))
		for _, k := range keys {
			parts = append(parts, fmt.Sprintf("%s=%q", k, act.OperationArgs[k]))
		}
		if len(parts) == 0 {
			return act.OperationName
		}
		return act.OperationName + "(" + strings.Join(parts, ", ") + ")"
	case jobs.ActionRawExec:
		quoted := make([]string, 0, len(act.RawExecArgv))
		for _, a := range act.RawExecArgv {
			quoted = append(quoted, fmt.Sprintf("%q", a))
		}
		return "raw exec: [" + strings.Join(quoted, " ") + "]"
	default:
		return "unspecified action"
	}
}
