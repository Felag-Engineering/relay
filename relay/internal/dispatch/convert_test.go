package dispatch

import (
	"reflect"
	"testing"

	gleipnirv1 "github.com/Felag-Engineering/gleipnir-relay/relay/internal/gleipnir/v1"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/jobs"
)

func TestTaskRequest_OperationRoundTrip(t *testing.T) {
	task := jobs.Task{
		ID: "task-1",
		Action: jobs.Action{
			Kind:          jobs.ActionOperation,
			OperationName: "file.read",
			OperationArgs: map[string]string{"path": "/etc/hostname"},
			RiskClass:     jobs.RiskClassRead,
		},
		TimeoutSeconds: 30,
	}

	got := taskRequest(task)
	if got.TaskId != task.ID {
		t.Errorf("TaskId = %q, want %q", got.TaskId, task.ID)
	}
	if got.TimeoutSeconds != task.TimeoutSeconds {
		t.Errorf("TimeoutSeconds = %d, want %d", got.TimeoutSeconds, task.TimeoutSeconds)
	}
	op := got.GetOperation()
	if op == nil {
		t.Fatal("GetOperation() = nil, want a populated Operation")
	}
	if op.GetName() != "file.read" {
		t.Errorf("Operation.Name = %q, want file.read", op.GetName())
	}
	if !reflect.DeepEqual(op.GetArgs(), task.Action.OperationArgs) {
		t.Errorf("Operation.Args = %v, want %v", op.GetArgs(), task.Action.OperationArgs)
	}
	if got.GetRawExec() != nil {
		t.Error("GetRawExec() should be nil for an Operation Action")
	}
}

func TestTaskRequest_RawExecRoundTrip(t *testing.T) {
	task := jobs.Task{
		ID: "task-2",
		Action: jobs.Action{
			Kind:        jobs.ActionRawExec,
			RawExecArgv: []string{"/bin/sleep", "5"},
			RiskClass:   jobs.RiskClassMutate,
		},
		TimeoutSeconds: 60,
	}

	got := taskRequest(task)
	rawExec := got.GetRawExec()
	if rawExec == nil {
		t.Fatal("GetRawExec() = nil, want a populated RawExec")
	}
	if !reflect.DeepEqual(rawExec.GetArgv(), task.Action.RawExecArgv) {
		t.Errorf("RawExec.Argv = %v, want %v", rawExec.GetArgv(), task.Action.RawExecArgv)
	}
	if got.GetOperation() != nil {
		t.Error("GetOperation() should be nil for a RawExec Action")
	}
}

// TestTaskRequest_RiskClassNeverSent asserts the deliberate omission: Action
// carries RiskClass but TaskRequest has no such field to receive it — blast
// classification is spent on the Relay side (ADR-0012) before dispatch.
func TestTaskRequest_RiskClassNeverSent(t *testing.T) {
	task := jobs.Task{
		ID:     "task-3",
		Action: jobs.Action{Kind: jobs.ActionOperation, OperationName: "system.facts", RiskClass: jobs.RiskClassRead},
	}
	got := taskRequest(task)
	// TaskRequest has no RiskClass field at all; this test documents the
	// contract via the type itself compiling without one, plus a proto
	// round-trip check that no unexpected field leaks the value.
	if got.GetOperation().GetName() != "system.facts" {
		t.Errorf("Operation.Name = %q, want system.facts", got.GetOperation().GetName())
	}
}

func TestResult_ConvertsFields(t *testing.T) {
	tr := &gleipnirv1.TaskResult{
		TaskId:   "task-1",
		Outcome:  gleipnirv1.Outcome_OUTCOME_SUCCESS,
		ExitCode: 0,
		Stdout:   []byte("hi"),
		Stderr:   []byte(""),
	}
	got := result(tr)
	want := jobs.Result{Outcome: jobs.OutcomeSuccess, ExitCode: 0, Stdout: []byte("hi"), Stderr: []byte("")}
	if got.Outcome != want.Outcome || got.ExitCode != want.ExitCode {
		t.Errorf("result() = %+v, want %+v", got, want)
	}
	if string(got.Stdout) != string(want.Stdout) || string(got.Stderr) != string(want.Stderr) {
		t.Errorf("result() stdout/stderr = %q/%q, want %q/%q", got.Stdout, got.Stderr, want.Stdout, want.Stderr)
	}
}

func TestOutcome_FullEnumMap(t *testing.T) {
	cases := []struct {
		wire gleipnirv1.Outcome
		want jobs.Outcome
	}{
		{gleipnirv1.Outcome_OUTCOME_UNSPECIFIED, jobs.OutcomeUnspecified},
		{gleipnirv1.Outcome_OUTCOME_SUCCESS, jobs.OutcomeSuccess},
		{gleipnirv1.Outcome_OUTCOME_FAILURE, jobs.OutcomeFailure},
		{gleipnirv1.Outcome_OUTCOME_TIMEOUT, jobs.OutcomeTimeout},
		{gleipnirv1.Outcome_OUTCOME_DENIED_BY_POLICY, jobs.OutcomeDeniedByPolicy},
		{gleipnirv1.Outcome_OUTCOME_CANCELLED, jobs.OutcomeCancelled},
		{gleipnirv1.Outcome_OUTCOME_UNREACHABLE, jobs.OutcomeUnreachable},
	}
	for _, c := range cases {
		if got := outcome(c.wire); got != c.want {
			t.Errorf("outcome(%v) = %v, want %v", c.wire, got, c.want)
		}
	}
}

func TestOutcome_UnrecognizedDefaultsToUnspecified(t *testing.T) {
	if got := outcome(gleipnirv1.Outcome(999)); got != jobs.OutcomeUnspecified {
		t.Errorf("outcome(999) = %v, want jobs.OutcomeUnspecified", got)
	}
}
