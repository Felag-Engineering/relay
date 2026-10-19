// Package dispatch is the Relay's v0.0.5 Task-dispatch transport: the
// proto-speaking adapter that sends a Task down a connected Node's Tunnel and
// correlates its Result, plus the restart-reconciliation loop that recovers
// in-flight Tasks after a crash (ADR-0004). capability.Conduit anticipates
// this package by design (execution.go's doc comment): capability stays
// domain-typed and proto-free (ADR-0009/0010's import lock), so the wire
// conversion and the live Tunnel send/receive live here instead.
//
// This package satisfies capability.Conduit structurally — Connected/
// Dispatch/Cancel on jobs.Task/jobs.Result — without importing capability, so
// there is no import cycle and the capability package's narrow allowlist
// (.golangci.yml's capability-imports rule) stays intact.
package dispatch

import (
	"github.com/Felag-Engineering/relay/relay/internal/jobs"
	relayv1 "github.com/Felag-Engineering/relay/relay/internal/relay/v1"
)

// taskRequest converts a persisted Task into the wire TaskRequest sent down
// the Node's Tunnel. RiskClass travels with it (ADR-0042): the class this
// Task was dispatched under — for a Template, the class this Node itself
// reported — so the daemon can refuse a Task dispatched as read whose action
// it now classifies as mutate. The class is the one the capability layer's
// resolveAction fixed (ADR-0012, ADR-0042, invariant 13); an adapter's value
// cannot reach here, because the capability layer refuses any Action that
// arrives with one. jobs.RiskClass mirrors relayv1.RiskClass value for value.
func taskRequest(t jobs.Task) *relayv1.TaskRequest {
	tr := &relayv1.TaskRequest{
		TaskId:         t.ID,
		TimeoutSeconds: t.TimeoutSeconds,
		RiskClass:      relayv1.RiskClass(t.Action.RiskClass), //nolint:gosec // G115: a closed enum that mirrors relayv1.RiskClass value for value
	}
	switch t.Action.Kind {
	case jobs.ActionOperation:
		tr.Action = &relayv1.TaskRequest_Operation{
			Operation: &relayv1.Operation{
				Name: t.Action.OperationName,
				Args: t.Action.OperationArgs,
			},
		}
	case jobs.ActionRawExec:
		tr.Action = &relayv1.TaskRequest_RawExec{
			RawExec: &relayv1.RawExec{Argv: t.Action.RawExecArgv},
		}
	case jobs.ActionUnspecified:
		// No Action set: leave tr.Action nil. jobEngine never mints a Task with
		// an unspecified Action, but taskRequest is a pure converter and must
		// not panic on it.
	}
	return tr
}

// policyQuery converts act into the wire PolicyQuery sent down the Node's
// Tunnel for a Plan (ADR-0011): the same argv-verbatim/no-shell oneof
// as taskRequest, but deliberately carrying no task_id — a PolicyQuery can
// never be mistaken for (or deduped alongside) a real Task. queryID is
// correlation-only (Router.Query mints it via crypto/rand, unrelated to any
// task_id).
func policyQuery(queryID string, act jobs.Action) *relayv1.PolicyQuery {
	pq := &relayv1.PolicyQuery{QueryId: queryID}
	switch act.Kind {
	case jobs.ActionOperation:
		pq.Action = &relayv1.PolicyQuery_Operation{
			Operation: &relayv1.Operation{
				Name: act.OperationName,
				Args: act.OperationArgs,
			},
		}
	case jobs.ActionRawExec:
		pq.Action = &relayv1.PolicyQuery_RawExec{
			RawExec: &relayv1.RawExec{Argv: act.RawExecArgv},
		}
	case jobs.ActionUnspecified:
		// No Action set: leave pq.Action nil, mirroring taskRequest's own
		// pure-converter discipline (never panics on an unset Action).
	}
	return pq
}

// verdict converts a wire PolicyVerdict into the domain jobs.Verdict that
// capability.Conduit.Query returns. Allowed and Unsupported are plain bools
// and DecidingRule a plain string, so every wire value maps unambiguously.
// The pass and rule reference are display data copied from the daemon, never
// an outcome: an unspecified or unrecognised pass or section maps to "", and
// a rule index and line are kept only alongside a section (invariant 12).
func verdict(pv *relayv1.PolicyVerdict) jobs.Verdict {
	v := jobs.Verdict{
		Allowed:      pv.GetAllowed(),
		DecidingRule: pv.GetDecidingRule(),
		Unsupported:  pv.GetUnsupported(),
		Pass:         passName(pv.GetPass()),
		MatchedOn:    pv.GetMatchedOn(),
	}
	if v.RuleSection = ruleSectionName(pv.GetRuleSection()); v.RuleSection != "" {
		v.RuleIndex = int(pv.GetRuleIndex())
		v.RuleLine = int(pv.GetRuleLine())
	}
	return v
}

// passName is the daemon's Pass display name for a wire PolicyPass, "" for
// the unspecified or an unrecognised value.
func passName(p relayv1.PolicyPass) string {
	switch p {
	case relayv1.PolicyPass_POLICY_PASS_PRECONDITION:
		return "precondition"
	case relayv1.PolicyPass_POLICY_PASS_DENY:
		return "deny"
	case relayv1.PolicyPass_POLICY_PASS_GUARD:
		return "guard"
	case relayv1.PolicyPass_POLICY_PASS_ALLOW:
		return "allow"
	case relayv1.PolicyPass_POLICY_PASS_DEFAULT:
		return "default"
	}
	return ""
}

// ruleSectionName names the Policy file section for a wire PolicyRuleSection,
// "" for the unspecified or an unrecognised value.
func ruleSectionName(s relayv1.PolicyRuleSection) string {
	switch s {
	case relayv1.PolicyRuleSection_POLICY_RULE_SECTION_OPERATION:
		return "operation"
	case relayv1.PolicyRuleSection_POLICY_RULE_SECTION_DENY:
		return "deny"
	case relayv1.PolicyRuleSection_POLICY_RULE_SECTION_RAW_EXEC_ALLOW:
		return "raw_exec_allow"
	case relayv1.PolicyRuleSection_POLICY_RULE_SECTION_RAW_EXEC_DENY:
		return "raw_exec_deny"
	}
	return ""
}

// relayOnlyOutcomes mirrors the wire Outcome values /proto marks
// Relay-synthesized — "a daemon never emits this" (proto/relay/v1/relay.proto,
// enum Outcome). A TaskResult carrying one is a protocol violation, never a
// result: an enrolled but compromised Node could otherwise report
// version_refused for a Task it received and executed, and every surface
// would then state the Task was never sent. This map is a MIRROR, not
// the source: /proto is (invariant 8), and wire_outcome_contract_test.go's G1
// fails if the two disagree in either direction, G2 if any enum value is
// unclassified.
var relayOnlyOutcomes = map[relayv1.Outcome]bool{
	relayv1.Outcome_OUTCOME_UNREACHABLE:     true,
	relayv1.Outcome_OUTCOME_VERSION_REFUSED: true,
}

// result converts a wire TaskResult into the domain jobs.Result that
// TaskRepository.Resolve persists, refusing at this single wire boundary
// every Outcome a relay-daemon is not permitted to report:
// relayOnlyOutcomes (the two /proto marks Relay-synthesized) and
// OUTCOME_UNSPECIFIED (the enum's own "not yet resolved" zero value — a
// finished Task's result may never carry it; see
// wire_outcome_contract_test.go's G2 for why unresolvedOutcomes classifies
// it there rather than here). The second return value is the zero
// jobs.ProtocolViolation when tr was one a daemon may legitimately send.
func result(tr *relayv1.TaskResult) (jobs.Result, jobs.ProtocolViolation) {
	o := tr.GetOutcome()

	rule := jobs.ViolationNone
	switch {
	case relayOnlyOutcomes[o]:
		rule = jobs.ViolationRelayOnlyOutcome
	case o == relayv1.Outcome_OUTCOME_UNSPECIFIED:
		rule = jobs.ViolationUnresolvedOutcome
	}

	if rule != jobs.ViolationNone {
		v := jobs.ProtocolViolation{Rule: rule, ReportedOutcome: relayv1.Outcome_name[int32(o)]}
		return jobs.Result{
			Outcome: jobs.OutcomeFailure,
			// ExitCode is the repo-wide no-exit-status sentinel (see
			// api/execution.go's perNodeResult.ExitCode and this package's
			// sibling doc comments): a 0 here would render as "exit 0" beside
			// a failure.
			ExitCode: -1,
			// The daemon's own Stdout/Stderr/Truncated are DISCARDED, not
			// carried alongside: this row is Relay-authored end to end, and
			// keeping a misbehaving Node's bytes next to the Relay's sentence
			// recreates the two-authors-on-one-row confusion
			// capability/refusal.go warns about. This is the one place
			// jobs.Result.Stderr carries Relay prose rather than Node bytes —
			// why jobs names the method Explanation(), not Stderr().
			Stderr: []byte(v.Explanation()),
		}, v
	}

	return jobs.Result{
		Outcome:   outcome(o),
		ExitCode:  tr.GetExitCode(),
		Stdout:    tr.GetStdout(),
		Stderr:    tr.GetStderr(),
		Truncated: tr.GetTruncated(),
	}, jobs.ProtocolViolation{}
}

// outcome converts a wire Outcome into its domain mirror. Called only for a
// value result() has already let through, so OUTCOME_UNSPECIFIED never
// reaches it from the wire path — result() refuses that value before this
// function runs (see the dispatch package doc). An unrecognized value
// (>= 9, e.g. a newer daemon under invariant 14: the Relay never pushes
// binaries, so version skew is the normal state) still maps to
// jobs.OutcomeUnspecified rather than panicking or guessing, preserving
// forward compatibility for a value this Relay predates. The
// OUTCOME_UNSPECIFIED case below remains only for non-wire callers of this
// function.
func outcome(o relayv1.Outcome) jobs.Outcome {
	switch o {
	case relayv1.Outcome_OUTCOME_SUCCESS:
		return jobs.OutcomeSuccess
	case relayv1.Outcome_OUTCOME_FAILURE:
		return jobs.OutcomeFailure
	case relayv1.Outcome_OUTCOME_TIMEOUT:
		return jobs.OutcomeTimeout
	case relayv1.Outcome_OUTCOME_DENIED_BY_POLICY:
		return jobs.OutcomeDeniedByPolicy
	case relayv1.Outcome_OUTCOME_CANCELLED:
		return jobs.OutcomeCancelled
	case relayv1.Outcome_OUTCOME_UNREACHABLE:
		return jobs.OutcomeUnreachable
	case relayv1.Outcome_OUTCOME_VERSION_REFUSED:
		return jobs.OutcomeVersionRefused
	case relayv1.Outcome_OUTCOME_UNSUPPORTED:
		return jobs.OutcomeUnsupported
	case relayv1.Outcome_OUTCOME_UNSPECIFIED:
		return jobs.OutcomeUnspecified
	default:
		return jobs.OutcomeUnspecified
	}
}
