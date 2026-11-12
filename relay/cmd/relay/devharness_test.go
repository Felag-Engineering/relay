//go:build devharness

package main

import (
	"context"
	"reflect"
	"testing"

	"github.com/Felag-Engineering/relay/relay/internal/jobs"
)

// The dev harness's request parsing and response rendering, pinned without a
// socket, a Router or an Execution: every case below returns before a handler
// touches harnessState, so a nil state is enough.

func TestDispatchHarnessRequestRefusesBeforeTouchingState(t *testing.T) {
	cases := []struct {
		req  harnessRequest
		want string
	}{
		{harnessRequest{Op: "no_such_op"}, `unknown op "no_such_op"`},
		{harnessRequest{Op: "dispatch", NodeID: "n1", TaskID: "t1"}, "dispatch: node_id, task_id, and operation are required"},
		{harnessRequest{Op: "get_node"}, "get_node: node_id is required"},
		{harnessRequest{Op: "cancel_job"}, "cancel_job: job_id is required"},
		{harnessRequest{Op: "query_job"}, "query_job: job_id is required"},
		{harnessRequest{Op: "run_job", Selector: "node:"}, `run_job: parse selector "node:": `},
		{harnessRequest{Op: "preflight_job", Selector: "node:"}, `preflight_job: parse selector "node:": `},
		{harnessRequest{Op: "run_job", Selector: "node:role=web"}, "run_job: operation or raw_exec is required"},
		{harnessRequest{Op: "preflight_job", Selector: "node:role=web"}, "preflight_job: operation or raw_exec is required"},
	}
	for _, tc := range cases {
		t.Run(tc.req.Op+"/"+tc.want, func(t *testing.T) {
			got := dispatchHarnessRequest(context.Background(), nil, tc.req)
			if len(got.Error) < len(tc.want) || got.Error[:len(tc.want)] != tc.want {
				t.Fatalf("Error = %q, want prefix %q", got.Error, tc.want)
			}
		})
	}
}

func TestHarnessRunJobAction(t *testing.T) {
	args := map[string]string{"unit": "nginx"}

	raw, err := harnessRunJobAction(harnessRequest{RawExec: []string{"/bin/true"}, Operation: "ignored", Args: args})
	if err != nil {
		t.Fatalf("raw exec: %v", err)
	}
	if want := (jobs.Action{Kind: jobs.ActionRawExec, RawExecArgv: []string{"/bin/true"}}); !reflect.DeepEqual(raw, want) {
		t.Fatalf("raw exec Action = %+v, want %+v", raw, want)
	}

	op, err := harnessRunJobAction(harnessRequest{Operation: "service_status", Args: args})
	if err != nil {
		t.Fatalf("operation: %v", err)
	}
	if want := (jobs.Action{Kind: jobs.ActionOperation, OperationName: "service_status", OperationArgs: args}); !reflect.DeepEqual(op, want) {
		t.Fatalf("operation Action = %+v, want %+v", op, want)
	}
	if op.RiskClass != raw.RiskClass || op.RiskClass != (jobs.Action{}).RiskClass {
		t.Fatal("the harness must leave the risk class unset: the capability layer derives it (invariant 13)")
	}

	if _, err := harnessRunJobAction(harnessRequest{}); err == nil {
		t.Fatal("an Action with neither operation nor raw_exec was accepted")
	}
}

func TestHarnessTaskInfos(t *testing.T) {
	tasks := []jobs.Task{{
		ID:      "t1",
		JobID:   "j1",
		NodeID:  "n1",
		State:   jobs.DispatchStateResolved,
		Outcome: jobs.OutcomeDeniedByPolicy,
		Stderr:  []byte("denied"),
	}}
	want := harnessTaskInfo{
		TaskID:  "t1",
		NodeID:  "n1",
		State:   "resolved",
		Outcome: "OUTCOME_DENIED_BY_POLICY",
		Stderr:  "denied",
	}

	// query_job's caller already holds the Job ID, so it is left off; only
	// list_inflight reports it.
	if got := harnessTaskInfos(tasks, false); !reflect.DeepEqual(got, []harnessTaskInfo{want}) {
		t.Fatalf("without Job ID = %+v, want %+v", got, want)
	}
	want.JobID = "j1"
	if got := harnessTaskInfos(tasks, true); !reflect.DeepEqual(got, []harnessTaskInfo{want}) {
		t.Fatalf("with Job ID = %+v, want %+v", got, want)
	}
	if got := harnessTaskInfos(nil, true); got == nil || len(got) != 0 {
		t.Fatalf("no Tasks = %#v, want an empty, non-nil slice", got)
	}
}

func TestOutcomeAndDispatchStateStrings(t *testing.T) {
	outcomes := map[jobs.Outcome]string{
		jobs.OutcomeSuccess:        "OUTCOME_SUCCESS",
		jobs.OutcomeFailure:        "OUTCOME_FAILURE",
		jobs.OutcomeTimeout:        "OUTCOME_TIMEOUT",
		jobs.OutcomeDeniedByPolicy: "OUTCOME_DENIED_BY_POLICY",
		jobs.OutcomeCancelled:      "OUTCOME_CANCELLED",
		jobs.OutcomeUnreachable:    "OUTCOME_UNREACHABLE",
		jobs.OutcomeVersionRefused: "OUTCOME_VERSION_REFUSED",
		jobs.OutcomeUnsupported:    "OUTCOME_UNSUPPORTED",
		jobs.Outcome(-1):           "OUTCOME_UNSPECIFIED",
	}
	for o, want := range outcomes {
		if got := outcomeString(o); got != want {
			t.Errorf("outcomeString(%d) = %q, want %q", o, got, want)
		}
	}

	states := map[jobs.DispatchState]string{
		jobs.DispatchStatePending:    "pending",
		jobs.DispatchStateDispatched: "dispatched",
		jobs.DispatchStateResolved:   "resolved",
		jobs.DispatchState(-1):       "unspecified",
	}
	for s, want := range states {
		if got := dispatchStateString(s); got != want {
			t.Errorf("dispatchStateString(%d) = %q, want %q", s, got, want)
		}
	}
}
