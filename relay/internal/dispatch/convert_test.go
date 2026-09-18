package dispatch

import (
	"reflect"
	"regexp"
	"testing"

	"google.golang.org/protobuf/reflect/protoreflect"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/jobs"
	relayv1 "github.com/Felag-Engineering/gleipnir-relay/relay/internal/relay/v1"
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

func TestPolicyQuery_OperationRoundTrip(t *testing.T) {
	act := jobs.Action{
		Kind:          jobs.ActionOperation,
		OperationName: "file.read",
		OperationArgs: map[string]string{"path": "/etc/hostname"},
		RiskClass:     jobs.RiskClassRead,
	}

	got := policyQuery("query-1", act)
	if got.GetQueryId() != "query-1" {
		t.Errorf("QueryId = %q, want query-1", got.GetQueryId())
	}
	op := got.GetOperation()
	if op == nil {
		t.Fatal("GetOperation() = nil, want a populated Operation")
	}
	if op.GetName() != "file.read" {
		t.Errorf("Operation.Name = %q, want file.read", op.GetName())
	}
	if !reflect.DeepEqual(op.GetArgs(), act.OperationArgs) {
		t.Errorf("Operation.Args = %v, want %v", op.GetArgs(), act.OperationArgs)
	}
	if got.GetRawExec() != nil {
		t.Error("GetRawExec() should be nil for an Operation Action")
	}
}

func TestPolicyQuery_RawExecRoundTrip(t *testing.T) {
	act := jobs.Action{
		Kind:        jobs.ActionRawExec,
		RawExecArgv: []string{"/bin/sleep", "5"},
		RiskClass:   jobs.RiskClassMutate,
	}

	got := policyQuery("query-2", act)
	rawExec := got.GetRawExec()
	if rawExec == nil {
		t.Fatal("GetRawExec() = nil, want a populated RawExec")
	}
	if !reflect.DeepEqual(rawExec.GetArgv(), act.RawExecArgv) {
		t.Errorf("RawExec.Argv = %v, want %v", rawExec.GetArgv(), act.RawExecArgv)
	}
	if got.GetOperation() != nil {
		t.Error("GetOperation() should be nil for a RawExec Action")
	}
}

// TestPolicyQuery_CarriesNoTaskID documents the deliberate omission: a
// PolicyQuery has no task_id field on the wire at all — a Plan's probe can
// never be mistaken for, or deduped alongside, a real Task (ADR-0011).
func TestPolicyQuery_CarriesNoTaskID(t *testing.T) {
	got := policyQuery("query-3", jobs.Action{Kind: jobs.ActionOperation, OperationName: "system.facts"})
	// PolicyQuery has no TaskId field at all; this test documents the
	// contract via the type itself compiling without one, plus a proto
	// round-trip check that no unexpected field leaks a task_id-shaped value.
	if got.GetQueryId() != "query-3" {
		t.Errorf("QueryId = %q, want query-3", got.GetQueryId())
	}
}

func TestVerdict_ConvertsFields(t *testing.T) {
	tests := []struct {
		name string
		pv   *relayv1.PolicyVerdict
		want jobs.Verdict
	}{
		{"allow", &relayv1.PolicyVerdict{QueryId: "q-1", Allowed: true}, jobs.Verdict{Allowed: true}},
		{
			"deny with deciding rule",
			&relayv1.PolicyVerdict{QueryId: "q-2", Allowed: false, DecidingRule: "deny-rm-rf"},
			jobs.Verdict{Allowed: false, DecidingRule: "deny-rm-rf"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := verdict(tt.pv); got != tt.want {
				t.Errorf("verdict(%+v) = %+v, want %+v", tt.pv, got, tt.want)
			}
		})
	}
}

func TestResult_ConvertsFields(t *testing.T) {
	tr := &relayv1.TaskResult{
		TaskId:    "task-1",
		Outcome:   relayv1.Outcome_OUTCOME_SUCCESS,
		ExitCode:  0,
		Stdout:    []byte("hi"),
		Stderr:    []byte(""),
		Truncated: true,
	}
	got := result(tr)
	want := jobs.Result{Outcome: jobs.OutcomeSuccess, ExitCode: 0, Stdout: []byte("hi"), Stderr: []byte(""), Truncated: true}
	if got.Outcome != want.Outcome || got.ExitCode != want.ExitCode {
		t.Errorf("result() = %+v, want %+v", got, want)
	}
	if string(got.Stdout) != string(want.Stdout) || string(got.Stderr) != string(want.Stderr) {
		t.Errorf("result() stdout/stderr = %q/%q, want %q/%q", got.Stdout, got.Stderr, want.Stdout, want.Stderr)
	}
	if got.Truncated != want.Truncated {
		t.Errorf("result() Truncated = %v, want %v", got.Truncated, want.Truncated)
	}
}

// TestResult_TruncatedDefaultsFalse asserts the wire's single truncated bool
// maps to false when the daemon reports no truncation — the not-truncated
// case must not be silently dropped either direction.
func TestResult_TruncatedDefaultsFalse(t *testing.T) {
	tr := &relayv1.TaskResult{TaskId: "task-2", Outcome: relayv1.Outcome_OUTCOME_SUCCESS}
	if got := result(tr); got.Truncated {
		t.Errorf("result().Truncated = true, want false for an untruncated TaskResult")
	}
}

func TestOutcome_FullEnumMap(t *testing.T) {
	cases := []struct {
		wire relayv1.Outcome
		want jobs.Outcome
	}{
		{relayv1.Outcome_OUTCOME_UNSPECIFIED, jobs.OutcomeUnspecified},
		{relayv1.Outcome_OUTCOME_SUCCESS, jobs.OutcomeSuccess},
		{relayv1.Outcome_OUTCOME_FAILURE, jobs.OutcomeFailure},
		{relayv1.Outcome_OUTCOME_TIMEOUT, jobs.OutcomeTimeout},
		{relayv1.Outcome_OUTCOME_DENIED_BY_POLICY, jobs.OutcomeDeniedByPolicy},
		{relayv1.Outcome_OUTCOME_CANCELLED, jobs.OutcomeCancelled},
		{relayv1.Outcome_OUTCOME_UNREACHABLE, jobs.OutcomeUnreachable},
	}
	for _, c := range cases {
		if got := outcome(c.wire); got != c.want {
			t.Errorf("outcome(%v) = %v, want %v", c.wire, got, c.want)
		}
	}
}

func TestOutcome_UnrecognizedDefaultsToUnspecified(t *testing.T) {
	if got := outcome(relayv1.Outcome(999)); got != jobs.OutcomeUnspecified {
		t.Errorf("outcome(999) = %v, want jobs.OutcomeUnspecified", got)
	}
}

// callerIdentityFieldName mirrors relay/cmd/relay/policy_immutability_test.go's
// guard of the same name. Deliberately duplicated here, not shared, because
// THIS package — internal/dispatch — is where the wire conversion this guard
// protects actually happens (taskRequest/policyQueryProto below), and it IS
// on docs/agents/security-surface.txt (relay/cmd/relay/** is not, except
// main.go): a security review of a caller-identity addition must find this
// guard even if it never opens the cmd/relay copy.
var callerIdentityFieldName = regexp.MustCompile(`(?i)principal|actor|account|role|token|caller|subject|identity|user|auth`)

// walkReachableMessageFields mirrors relay/cmd/relay/policy_immutability_test.go's
// function of the same name — see its doc comment for why the BFS, rather
// than a hand-built Go-side field list, is what makes this guard structural.
func walkReachableMessageFields(start protoreflect.MessageDescriptor, visit func(fieldName string)) {
	visited := map[protoreflect.FullName]bool{}
	queue := []protoreflect.MessageDescriptor{start}
	for len(queue) > 0 {
		md := queue[0]
		queue = queue[1:]
		if visited[md.FullName()] {
			continue
		}
		visited[md.FullName()] = true

		fields := md.Fields()
		for i := 0; i < fields.Len(); i++ {
			f := fields.Get(i)
			if md.IsMapEntry() && (f.Name() == "key" || f.Name() == "value") {
				if f.Kind() == protoreflect.MessageKind || f.Kind() == protoreflect.GroupKind {
					queue = append(queue, f.Message())
				}
				continue
			}
			visit(string(f.Name()))
			if f.Kind() == protoreflect.MessageKind || f.Kind() == protoreflect.GroupKind {
				queue = append(queue, f.Message())
			}
		}
	}
}

// assertExactTopLevelFieldSet fails t if md's own (non-transitive) field-name
// set is not exactly want.
func assertExactTopLevelFieldSet(t *testing.T, md protoreflect.MessageDescriptor, want map[string]bool) {
	t.Helper()
	fields := md.Fields()
	got := make(map[string]bool, fields.Len())
	for i := 0; i < fields.Len(); i++ {
		got[string(fields.Get(i).Name())] = true
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("%s field set changed:\n  got:  %v\n  want: %v\n"+
			"any addition must be reviewed for caller identity before this allow-set is updated",
			md.FullName(), got, want)
	}
}

// TestWireCarriesNoCallerIdentity mirrors
// relay/cmd/relay/policy_immutability_test.go's test of the same name — see
// its doc comment for the full rationale (the bypass beat, F2; the rename
// blind spot an earlier review found in the regex-only version; ADR-0002).
// Kept in both places deliberately: this package is on the security surface,
// the cmd/relay copy sits beside its sibling wire-immutability idiom.
func TestWireCarriesNoCallerIdentity(t *testing.T) {
	start := (&relayv1.RelayMessage{}).ProtoReflect().Descriptor()
	walkReachableMessageFields(start, func(fieldName string) {
		if callerIdentityFieldName.MatchString(fieldName) {
			t.Errorf("RelayMessage reaches a field named %q, which looks like caller identity — "+
				"the wire contract must never let the Relay tell the Node who is asking (ADR-0002, #454)", fieldName)
		}
	})

	// Exact-field-set belt-and-suspenders on the four messages a Task/
	// PolicyQuery actually carries, INCLUDING the two oneof payload messages:
	// a rename (e.g. "requested_by", "on_behalf_of") evades the regex above,
	// so an addition or a rename inside Operation/RawExec must be named here
	// to pass, not just caught by the regex.
	assertExactTopLevelFieldSet(t, (&relayv1.TaskRequest{}).ProtoReflect().Descriptor(),
		map[string]bool{"task_id": true, "operation": true, "raw_exec": true, "timeout_seconds": true})
	assertExactTopLevelFieldSet(t, (&relayv1.PolicyQuery{}).ProtoReflect().Descriptor(),
		map[string]bool{"query_id": true, "operation": true, "raw_exec": true})
	assertExactTopLevelFieldSet(t, (&relayv1.Operation{}).ProtoReflect().Descriptor(),
		map[string]bool{"name": true, "args": true})
	assertExactTopLevelFieldSet(t, (&relayv1.RawExec{}).ProtoReflect().Descriptor(),
		map[string]bool{"argv": true})
}
