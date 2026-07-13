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
// (TestCapabilityImportsOnlyRegistryAndJobs) stays intact.
package dispatch

import (
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/jobs"
	relayv1 "github.com/Felag-Engineering/gleipnir-relay/relay/internal/relay/v1"
)

// taskRequest converts a persisted Task into the wire TaskRequest sent down
// the Node's Tunnel. RiskClass is deliberately NOT sent: it is not a
// TaskRequest field on the wire — blast-radius classification is a Relay-side
// concern (ADR-0012), already spent by the time a Task reaches dispatch.
func taskRequest(t jobs.Task) *relayv1.TaskRequest {
	tr := &relayv1.TaskRequest{
		TaskId:         t.ID,
		TimeoutSeconds: t.TimeoutSeconds,
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
// Tunnel for a Plan (#119, ADR-0011): the same argv-verbatim/no-shell oneof
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
// capability.Conduit.Query returns. There is no "unrecognized" case to
// default here — Allowed is a plain bool and DecidingRule a plain string, so
// every wire value maps unambiguously.
func verdict(pv *relayv1.PolicyVerdict) jobs.Verdict {
	return jobs.Verdict{
		Allowed:      pv.GetAllowed(),
		DecidingRule: pv.GetDecidingRule(),
	}
}

// result converts a wire TaskResult into the domain jobs.Result that
// TaskRepository.Resolve persists.
func result(tr *relayv1.TaskResult) jobs.Result {
	return jobs.Result{
		Outcome:  outcome(tr.GetOutcome()),
		ExitCode: tr.GetExitCode(),
		Stdout:   tr.GetStdout(),
		Stderr:   tr.GetStderr(),
	}
}

// outcome converts a wire Outcome into its domain mirror. An unrecognized
// wire value (including OUTCOME_UNSPECIFIED) maps to jobs.OutcomeUnspecified
// rather than panicking or guessing — a Task with an unspecified Outcome is
// truthfully "not yet resolved" from the Relay's point of view.
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
	case relayv1.Outcome_OUTCOME_UNSPECIFIED:
		return jobs.OutcomeUnspecified
	default:
		return jobs.OutcomeUnspecified
	}
}
