package capability

import "github.com/Felag-Engineering/gleipnir-relay/relay/internal/jobs"

// policyBoundaryExplanation is the one spelling of the Node-Policy boundary
// sentence, shared by the apply-path and plan-path constants below (they
// differ only in their lead clause). It exists because the demo's third act
// walks straight into it: a Node Policy deny is the only one of the four
// refusal walls whose boundary is not the Relay, so it is the one wall where
// naming the boundary — not just the deciding rule — actually changes what a
// caller does next.
//
// Five binding rules for anyone editing this text:
//
//  1. The mapping below takes an enum and nothing else. It is NEVER derived
//     from, conditioned on, or parsed out of the daemon's reason string
//     (invariant 12 / ADR-0011). Keeping the mapping functions' signature
//     func(enum) string is what makes this structural rather than a promise.
//  2. The text is surface-neutral — no tool name, no route, no file path —
//     so both adapters emit byte-identical bytes (ADR-0009/0010 parity,
//     invariant 10).
//  3. It is render-only: never written to a Task row, an audit record, a log
//     line or a wire field, so it cannot size an audit record.
//  4. Every clause must stay true of the code. Invariant 2 / ADR-0002 backs
//     the "no code path to write it" clause, proven by
//     relay/cmd/relay/policy_immutability_test.go; the caller-identity
//     clause is proven by TestWireCarriesNoCallerIdentity in that same file.
//     Do NOT say "root-owned" — daemon/src/policy.rs:483-495 accepts uid 0
//     OR the daemon's euid. Do NOT name a path or say "the Policy file"
//     singular — the fragment-directory direction in policy.md would
//     falsify it.
//  5. This text explains the ARCHITECTURE OF THE BOUNDARY. It never explains
//     the specific rule and never asserts why this particular deny happened.
//     denied_by_policy is a wider category than "a Policy rule said no": it
//     also covers ADR-0018 argument-form preconditions that deny before the
//     engine runs (dispatch.rs:533-543), the whitespace-in-argv refusal,
//     the post-open path re-check's IO-error path
//     (daemon/src/operations/file_read.rs:113-128), and the deny-all
//     fallback a Node runs when its Policy file is absent or misowned
//     (main.rs:775-793). On every one of those the deciding text belongs to
//     the daemon and lives in stderr; anything this constant asserted about
//     *why* would be wrong on at least one of them. This is why the clause
//     about widening Policy is written conditionally ("Where the answer is a
//     Policy rule"), and why there is no claim about retries at all: the
//     blanket "no retry changes this answer" is FALSE on an args-mismatch
//     deny — the daemon's own stderr on that same row says a different
//     argument would be allowed — and on the three other classes above. The
//     claim this text makes is scoped to the credential, which is what the
//     Relay can actually guarantee.
//
// One more rule, stated separately because it is a trap rather than a
// drafting constraint: on a denied_by_policy row, stderr is the Node's
// verbatim reason and PolicyDenyExplanation/PolicyDenyVerdictExplanation are
// the Relay's framing — two different authors on the same row. On a
// version_refused row the Relay authored both, so RefusalExplanation repeats
// stderr there. Never infer the two agree, and never infer they differ.
const policyBoundaryExplanation = "Policy is local to the Node: the relay-daemon loads " +
	"it from that Node's own disk, and the Relay has no code path to add, change or " +
	"relax a rule over the wire (ADR-0002). The Node is never told which Account or role " +
	"asked — the wire contract carries no caller identity — so the same request reaching " +
	"the Node gets the same answer whoever asks, and no credential this control plane can " +
	"issue changes it. Where the answer is a Policy rule, widening it is a deliberate " +
	"human change on the Node itself, delivered by your own config management, and never " +
	"something this control plane can do."

// PolicyDenyExplanation is the Relay-authored, caller-facing framing for an
// apply-path Task that resolved denied_by_policy: the Node refused it and
// nothing executed. See policyBoundaryExplanation's doc comment for the
// rules this text must keep obeying.
const PolicyDenyExplanation = "Refused by the Node, not by this control plane — a " +
	"refusal, not a failure: nothing executed. " + policyBoundaryExplanation

// PolicyDenyVerdictExplanation is the plan-mode counterpart of
// PolicyDenyExplanation: the Node reports it would refuse the Task, so
// nothing was ever dispatched.
const PolicyDenyVerdictExplanation = "The Node reports that it would refuse this; " +
	"nothing was dispatched. " + policyBoundaryExplanation

// RefusalExplanation returns the Relay's caller-facing framing for a
// resolved Task outcome, or "" when the outcome is not a named boundary
// refusal. Both the MCP and Control API adapters call this unconditionally
// (invariant 10: one decision, in the capability layer, not per interface)
// rather than each branching on the outcome themselves.
//
// OutcomeUnreachable, OutcomeUnsupported, OutcomeCancelled, OutcomeTimeout,
// OutcomeFailure and OutcomeSuccess deliberately return "": OutcomeUnreachable
// hit no boundary at all, OutcomeUnsupported is a vocabulary miss the
// daemon's own UNSUPPORTED_REASON already explains, and a cancel came from
// the caller, not from a boundary. If a future Outcome value is added, its
// case must be added here deliberately — refusal_legibility_test.go's mapping
// table is anchored to relayv1.Outcome_name's length, so a new /proto Outcome
// with no added case here fails that test.
//
// On the apply path, o is the Node's own self-reported outcome for the
// values a daemon may legitimately send (denied_by_policy, unsupported,
// timeout, cancelled, failure, success), so the lead clause this returns
// ("nothing executed", "the Task was never sent") is only as trustworthy as
// outcome/stderr already are on that same row — not a new trust boundary —
// whereas the shared boundary text's architecture clauses (no code path to
// write Policy, no caller identity on the wire) hold unconditionally
// regardless of what any Node reports. Unreachable and version_refused are
// NOT self-reported on any path: the wire boundary
// (dispatch.result()) refuses a daemon that reports either, so by the time
// o reaches this function it is always Relay-authored. A version_refused row
// persisted by a Relay that predates that boundary is not covered by this
// guarantee.
func RefusalExplanation(o jobs.Outcome) string {
	switch o {
	case jobs.OutcomeDeniedByPolicy:
		return PolicyDenyExplanation
	case jobs.OutcomeVersionRefused:
		return jobs.VersionRefusedMessage
	default:
		return ""
	}
}

// VerdictExplanation is the plan-mode counterpart of RefusalExplanation.
// VerdictUnsupported and VerdictUnknown deliberately return "": the former
// is a vocabulary miss explained by DecidingRule already, and the latter
// means "not yet known" (offline or a failed PolicyQuery), never a refusal.
func VerdictExplanation(v VerdictStatus) string {
	switch v {
	case VerdictDeny:
		return PolicyDenyVerdictExplanation
	default:
		return ""
	}
}
