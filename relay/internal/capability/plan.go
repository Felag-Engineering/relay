// Plan mode (ADR-0011): plan=true's Relay-side half. A Plan resolves
// the same Selector, runs the same authz/cap checks as Run, but never
// dispatches a Task — it asks each matched, connected daemon a read-only
// PolicyQuery and reports the per-Node PolicyVerdict instead of executing.
//
// The load-bearing distinctions from Run:
//   - Freeze is ADVISORY only, never a gate (ADR-0013): observation is
//     wanted during an incident, so PolicyQuery is exempt from the Freeze
//     check that refuses real dispatch.
//   - The blast cap is CHECKED but never ENFORCED as an error (ADR-0011): an
//     over-cap Plan reports would-be-rejected data (Matched/Cap/Class) with
//     err == nil, and — because real dispatch would touch nothing over-cap —
//     the query fan-out is skipped entirely rather than querying an
//     unbounded fleet.
//   - A matched-but-disconnected Node is unknown(offline), never a guess
//     from a cached PolicySnapshot (invariant 12): the Relay never computes
//     verdicts, only the daemon's live engine does.
//   - Authz still GATES (mirrors Run): a caller not authorized to ASK must
//     not learn per-Node deciding rules.
//   - A Plan creates no Job, no Stage, no Task, no dedup entry, and is
//     audited as a distinct AuditKindPlan (seams.go), never AuditKindDispatch.
//   - A Selector matching no Nodes is REPORTED (PlanResult.NoNodesMatched),
//     never refused, while Run refuses the same condition as
//     no_nodes_matched (ADR-0011).
package capability

import (
	"context"
	"errors"
	"fmt"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/jobs"
)

// VerdictStatus is one Node's Plan-mode verdict. The zero value,
// VerdictUnknown, is deliberately "not yet known" (a matched-but-
// disconnected Node, or a query that itself failed) rather than a fabricated
// allow — mirrors jobs.OutcomeUnspecified's zero-value discipline.
type VerdictStatus int

const (
	VerdictUnknown VerdictStatus = iota
	VerdictAllow
	VerdictDeny
	// VerdictUnsupported: the Node answered that the Operation is not in its
	// vocabulary, so its Policy was never asked (ADR-0021). Distinct from
	// VerdictDeny (the Node's Policy decided) and from VerdictUnknown (the
	// Relay could not ask). A real dispatch to this Node would report
	// OutcomeUnsupported — the plan/apply parity ADR-0011 requires.
	VerdictUnsupported
)

// NodeVerdict is one matched Node's Plan-mode result. DecidingRule is set on
// VerdictDeny (the daemon's PolicyVerdict.DecidingRule) and on
// VerdictUnsupported (where it explains the vocabulary miss instead of naming
// a rule); Reason is set only on VerdictUnknown (e.g. "offline",
// "query_failed") — never both a Reason and a DecidingRule,
// mirroring jobs.Result's per-Node discipline. Outdated is ADVISORY ONLY
// (ADR-0014): it never changes Status, which still comes solely from the
// daemon's live PolicyVerdict (invariant 12) — a real dispatch (Run) would
// refuse this Node with OutcomeVersionRefused regardless of what Status says
// here, and Outdated tells the caller that in advance so an apply is not
// surprised.
type NodeVerdict struct {
	NodeID       string
	Status       VerdictStatus
	DecidingRule string
	Reason       string
	Outdated     bool
}

// planResult is what dispatcher.query returns: just the per-Node verdicts.
// Unlike dispatchResult there is no jobID — a Plan creates no Job.
type planResult struct {
	verdicts []NodeVerdict
}

// PlanResult is Execution.Plan's exported surface. CapExceeded, when non-nil,
// carries the blast-cap rejection AS DATA (ADR-0011: a Plan never hard-fails
// on a guardrail) — Verdicts is empty in that case, since the query fan-out
// is skipped rather than probing an unbounded fleet. Frozen is advisory: it
// reports that real dispatch would currently be refused (ADR-0013), but the
// Plan still ran its queries — Frozen and a populated Verdicts are not
// mutually exclusive. NoNodesMatched is true when the Selector resolved to
// zero Nodes. A real Run would refuse that as no_nodes_matched, and a Policy
// preflight reports it as data instead (ADR-0011). Verdicts is then empty
// because there was no Node to ask. Like Frozen it is advisory, and it is
// never an error.
type PlanResult struct {
	Matched        int
	Frozen         bool
	CapExceeded    *CapExceededError
	NoNodesMatched bool
	Verdicts       []NodeVerdict
}

// query implements dispatcher: for each of d's matched Nodes, ask the
// daemon a read-only PolicyQuery if it is connected, else conclude
// unknown(offline) without ever touching the Conduit — the Relay never
// guesses a verdict from a cached PolicySnapshot (invariant 12). It persists
// nothing: no Job, no Stage, no Task, no MarkDispatched, so jobEngine
// satisfying dispatcher.query adds no new store dependency.
//
// Outdated (ADR-0014) is set on every NodeVerdict from the Node's registry
// flag, connected or not — plan mode never gates or skips the PolicyQuery for
// an outdated Node; the gate is a Run-only, dispatch-level concern (invariant
// 12: only the daemon's live engine decides Policy verdicts).
func (e *jobEngine) query(ctx context.Context, d dispatch) (planResult, error) {
	verdicts := make([]NodeVerdict, 0, len(d.nodes))
	for _, n := range d.nodes {
		if !e.conduit.Connected(n.NodeID) {
			verdicts = append(verdicts, NodeVerdict{NodeID: n.NodeID, Status: VerdictUnknown, Reason: "offline", Outdated: n.Outdated})
			continue
		}
		v, err := e.conduit.Query(ctx, n.NodeID, d.action)
		if err != nil {
			// Best-effort, never fabricated: a query that itself failed (e.g.
			// the Tunnel dropped mid-query) is unknown, not a guessed allow or
			// deny.
			verdicts = append(verdicts, NodeVerdict{NodeID: n.NodeID, Status: VerdictUnknown, Reason: "query_failed", Outdated: n.Outdated})
			continue
		}
		if v.Unsupported {
			// The Node has no such Operation — its Policy was never consulted,
			// so this is not a deny (ADR-0021).
			verdicts = append(verdicts, NodeVerdict{NodeID: n.NodeID, Status: VerdictUnsupported, DecidingRule: v.DecidingRule, Outdated: n.Outdated})
		} else if v.Allowed {
			verdicts = append(verdicts, NodeVerdict{NodeID: n.NodeID, Status: VerdictAllow, Outdated: n.Outdated})
		} else {
			verdicts = append(verdicts, NodeVerdict{NodeID: n.NodeID, Status: VerdictDeny, DecidingRule: v.DecidingRule, Outdated: n.Outdated})
		}
	}
	return planResult{verdicts: verdicts}, nil
}

// Plan resolves sel, authorizes p against act, and — unlike Run — checks the
// Freeze and blast cap only as ADVISORY data, never as a gate: a Plan always
// runs (once authorized) and always reports, rather than erroring, when real
// dispatch would currently be refused (ADR-0011/0013).
//
// Order mirrors Run except for the Freeze/cap treatment:
//  1. resolve the Selector — identical resolution to Run —
//     and, for a Template Operation, its class and fan-out (ADR-0042),
//     exactly as Run does.
//  2. authorize p against act/sel — GATES (returns an error, audited as a
//     refusal): a caller not permitted to ASK must not learn per-Node
//     deciding rules (invariant 3).
//  3. note whether the Selector matched no Nodes — advisory only, reported
//     as NoNodesMatched; Run refuses the same condition as no_nodes_matched,
//     after authorization, so a Policy preflight and a real run agree.
//     Otherwise refuse an unknown or malformed Template call, as Run does,
//     and report each Node excluded from a Template dispatch as
//     unsupported without querying it.
//  4. read Frozen — advisory only; a read error is swallowed (never fails
//     the Plan) since Frozen here is informational, not a guardrail.
//  5. check the blast cap — reported as CapExceeded data, not an error; the
//     query fan-out is skipped in that case (real dispatch would touch
//     nothing over-cap, so there is nothing useful to probe).
//  6. query every matched Node not excluded in step 3 through the sealed
//     dispatcher seam.
//  7. audit as AuditKindPlan — Principal/Selector/Action only, no
//     JobID/Results (no Job/Task rows were ever created).
func (s *Execution) Plan(ctx context.Context, p Principal, sel Selector, act jobs.Action) (PlanResult, error) {
	matched := sel.Resolve(s.read.reg, s.read.stateEval())

	// The same resolution Run makes, which fixes the class of every Action
	// kind (ADR-0042, invariant 13), so a preflight and a real run agree on
	// the class, the cap and which Nodes are excluded.
	ra := s.resolveAction(act, matched)
	act = ra.act
	nodes := ra.nodes

	if err := s.control.authz.Authorize(withoutAssertions(ctx), p, act, sel); err != nil {
		return PlanResult{}, s.recordRefusal(ctx, p, sel, act, RefusalUnauthorized, err)
	}

	noMatch := len(matched) == 0

	// An unknown or malformed Template call is not a guardrail to report but a
	// request that cannot be asked at all, so a preflight refuses it exactly
	// as a run would. With no Node matched there is nothing to resolve
	// against, and NoNodesMatched below says so instead.
	if !noMatch && ra.refusal != nil {
		return PlanResult{}, s.recordRefusal(ctx, p, sel, act, ra.refusalKind, ra.refusal)
	}

	// Excluded Nodes are reported unsupported — the outcome a run would give
	// them — and never queried.
	excluded := make([]NodeVerdict, 0, len(ra.excluded))
	for _, x := range ra.excluded {
		excluded = append(excluded, NodeVerdict{NodeID: x.node.NodeID, Status: VerdictUnsupported, DecidingRule: x.reason, Outdated: x.node.Outdated})
	}

	frozen, _ := s.control.freeze.Frozen(ctx)

	if capErr := s.cap.Check(act.RiskClass, len(nodes)); capErr != nil {
		var ce *CapExceededError
		errors.As(capErr, &ce)
		if err := s.recorder().audit.Record(ctx, AuditEntry{Kind: AuditKindPlan, Principal: p, Selector: sel, Action: act, Asserted: AssertionsFromContext(ctx)}); err != nil {
			return PlanResult{Matched: len(matched), Frozen: frozen, CapExceeded: ce, NoNodesMatched: noMatch},
				fmt.Errorf("capability: record audit entry: %w", err)
		}
		return PlanResult{Matched: len(matched), Frozen: frozen, CapExceeded: ce, NoNodesMatched: noMatch}, nil
	}

	pr, err := s.disp.query(ctx, newDispatch(p, sel, nodes, act))

	// The audit write is unconditional, even when query itself errored —
	// mirroring Run's own "a partially-executed dispatch must never go
	// unaudited" discipline (pipeline.go) — and a failed write is joined
	// into the returned error rather than silently swallowed.
	auditErr := s.recorder().audit.Record(ctx, AuditEntry{Kind: AuditKindPlan, Principal: p, Selector: sel, Action: act, Asserted: AssertionsFromContext(ctx)})
	if auditErr != nil {
		auditErr = fmt.Errorf("capability: record audit entry: %w", auditErr)
	}

	verdicts := append(pr.verdicts, excluded...)
	if joined := errors.Join(err, auditErr); joined != nil {
		return PlanResult{Matched: len(matched), Frozen: frozen, NoNodesMatched: noMatch, Verdicts: verdicts}, joined
	}
	return PlanResult{Matched: len(matched), Frozen: frozen, NoNodesMatched: noMatch, Verdicts: verdicts}, nil
}
