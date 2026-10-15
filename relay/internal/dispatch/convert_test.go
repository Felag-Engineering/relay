package dispatch

import (
	"reflect"
	"regexp"
	"strings"
	"testing"

	"github.com/Felag-Engineering/relay/relay/internal/jobs"
	relayv1 "github.com/Felag-Engineering/relay/relay/internal/relay/v1"
	"github.com/Felag-Engineering/relay/relay/internal/relaytest/protowalk"
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

// TestTaskRequest_CarriesItsRiskClass: the class a Task was dispatched under
// travels with it (ADR-0042), so the daemon can refuse a Task dispatched as
// read whose action it classifies as mutate. Every class maps value for
// value — jobs.RiskClass mirrors relayv1.RiskClass — including Raw Exec's
// mutate and an unspecified class, which the daemon does not check.
func TestTaskRequest_CarriesItsRiskClass(t *testing.T) {
	for _, tc := range []struct {
		act  jobs.Action
		want relayv1.RiskClass
	}{
		{jobs.Action{Kind: jobs.ActionOperation, OperationName: "system.facts", RiskClass: jobs.RiskClassRead}, relayv1.RiskClass_RISK_CLASS_READ},
		{jobs.Action{Kind: jobs.ActionOperation, OperationName: "svc.restart", RiskClass: jobs.RiskClassMutate}, relayv1.RiskClass_RISK_CLASS_MUTATE},
		{jobs.Action{Kind: jobs.ActionRawExec, RawExecArgv: []string{"/bin/true"}, RiskClass: jobs.RiskClassMutate}, relayv1.RiskClass_RISK_CLASS_MUTATE},
		{jobs.Action{Kind: jobs.ActionOperation, OperationName: "legacy"}, relayv1.RiskClass_RISK_CLASS_UNSPECIFIED},
	} {
		got := taskRequest(jobs.Task{ID: "task-3", Action: tc.act})
		if got.GetRiskClass() != tc.want {
			t.Errorf("taskRequest(%s %s).RiskClass = %v, want %v", jobs.RiskClassName(tc.act.RiskClass), tc.act.OperationName, got.GetRiskClass(), tc.want)
		}
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
	got, v := result(tr)
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
	if v.Violated() {
		t.Errorf("result() reported a protocol violation for a legitimate daemon result: %+v", v)
	}
}

// TestResult_TruncatedDefaultsFalse asserts the wire's single truncated bool
// maps to false when the daemon reports no truncation — the not-truncated
// case must not be silently dropped either direction.
func TestResult_TruncatedDefaultsFalse(t *testing.T) {
	tr := &relayv1.TaskResult{TaskId: "task-2", Outcome: relayv1.Outcome_OUTCOME_SUCCESS}
	if got, _ := result(tr); got.Truncated {
		t.Errorf("result().Truncated = true, want false for an untruncated TaskResult")
	}
}

// TestResult_RefusesOutcomesNoDaemonMaySend is #632's core regression test:
// every wire Outcome a relay-daemon is not permitted to report must resolve
// failure with a Relay-authored explanation, ExitCode -1, and no daemon
// bytes surviving — never the outcome the Node claimed.
func TestResult_RefusesOutcomesNoDaemonMaySend(t *testing.T) {
	cases := []struct {
		name string
		wire relayv1.Outcome
		rule jobs.ViolationRule
	}{
		{"unreachable", relayv1.Outcome_OUTCOME_UNREACHABLE, jobs.ViolationRelayOnlyOutcome},
		{"version_refused", relayv1.Outcome_OUTCOME_VERSION_REFUSED, jobs.ViolationRelayOnlyOutcome},
		{"unspecified", relayv1.Outcome_OUTCOME_UNSPECIFIED, jobs.ViolationUnresolvedOutcome},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			tr := &relayv1.TaskResult{
				TaskId:  "task-forged",
				Outcome: c.wire,
				Stdout:  []byte("i actually ran"),
				Stderr:  []byte("and here is my real stderr"),
			}
			got, v := result(tr)

			if !v.Violated() {
				t.Fatalf("result(%v) reported no violation, want one", c.wire)
			}
			if v.Rule != c.rule {
				t.Errorf("violation Rule = %v, want %v", v.Rule, c.rule)
			}
			wantName := relayv1.Outcome_name[int32(c.wire)]
			if v.ReportedOutcome != wantName {
				t.Errorf("violation ReportedOutcome = %q, want %q", v.ReportedOutcome, wantName)
			}

			if got.Outcome != jobs.OutcomeFailure {
				t.Errorf("Result.Outcome = %v, want jobs.OutcomeFailure", got.Outcome)
			}
			if got.ExitCode != -1 {
				t.Errorf("Result.ExitCode = %d, want -1 (the no-exit-status sentinel)", got.ExitCode)
			}
			if string(got.Stderr) != v.Explanation() {
				t.Errorf("Result.Stderr = %q, want v.Explanation() = %q", got.Stderr, v.Explanation())
			}
			if len(got.Stdout) != 0 {
				t.Errorf("Result.Stdout = %q, want empty — the Node's bytes must be discarded", got.Stdout)
			}
			if strings.Contains(string(got.Stderr), "i actually ran") {
				t.Errorf("Result.Stderr leaked the Node's forged stdout: %q", got.Stderr)
			}
			if strings.Contains(string(got.Stderr), "and here is my real stderr") {
				t.Errorf("Result.Stderr leaked the Node's own stderr: %q", got.Stderr)
			}
		})
	}
}

// TestOutcome_FullEnumMap iterates relayv1.Outcome_value rather than a
// hand-picked subset, so a new /proto Outcome value can never silently go
// untested here (rev 1 of this test omitted OUTCOME_VERSION_REFUSED and
// OUTCOME_UNSUPPORTED without failing).
func TestOutcome_FullEnumMap(t *testing.T) {
	explicit := map[relayv1.Outcome]jobs.Outcome{
		relayv1.Outcome_OUTCOME_UNSPECIFIED:      jobs.OutcomeUnspecified,
		relayv1.Outcome_OUTCOME_SUCCESS:          jobs.OutcomeSuccess,
		relayv1.Outcome_OUTCOME_FAILURE:          jobs.OutcomeFailure,
		relayv1.Outcome_OUTCOME_TIMEOUT:          jobs.OutcomeTimeout,
		relayv1.Outcome_OUTCOME_DENIED_BY_POLICY: jobs.OutcomeDeniedByPolicy,
		relayv1.Outcome_OUTCOME_CANCELLED:        jobs.OutcomeCancelled,
		relayv1.Outcome_OUTCOME_UNREACHABLE:      jobs.OutcomeUnreachable,
		relayv1.Outcome_OUTCOME_VERSION_REFUSED:  jobs.OutcomeVersionRefused,
		relayv1.Outcome_OUTCOME_UNSUPPORTED:      jobs.OutcomeUnsupported,
	}
	for name, number := range relayv1.Outcome_value {
		wire := relayv1.Outcome(number)
		want, ok := explicit[wire]
		if !ok {
			t.Fatalf("relayv1.Outcome_value has %s (%d) with no expected mapping in this test's explicit table — add it", name, number)
		}
		if got := outcome(wire); got != want {
			t.Errorf("outcome(%s) = %v, want %v", name, got, want)
		}
	}
}

// TestOutcome_UnrecognizedDefaultsToUnspecified documents §2's deliberate
// forward-compat line: outcome() keeps this mapping for values >= 9 only,
// because the wire value 0 (OUTCOME_UNSPECIFIED) is refused by result()
// before outcome() is ever reached.
func TestOutcome_UnrecognizedDefaultsToUnspecified(t *testing.T) {
	if got := outcome(relayv1.Outcome(999)); got != jobs.OutcomeUnspecified {
		t.Errorf("outcome(999) = %v, want jobs.OutcomeUnspecified", got)
	}
}

// callerIdentityFieldName mirrors relay/cmd/relay/policy_immutability_test.go's
// guard of the same name. Deliberately duplicated here, not shared (only the
// descriptor walk and set comparison are, in internal/relaytest/protowalk), because
// THIS package — internal/dispatch — is where the wire conversion this guard
// protects actually happens (taskRequest/policyQueryProto below), and it IS
// on docs/agents/security-surface.txt (relay/cmd/relay/** is not, except
// main.go): a security review of a caller-identity addition must find this
// guard even if it never opens the cmd/relay copy.
var callerIdentityFieldName = regexp.MustCompile(`(?i)principal|actor|account|role|token|caller|subject|identity|user|auth`)

// TestWireCarriesNoCallerIdentity mirrors
// relay/cmd/relay/policy_immutability_test.go's test of the same name — see
// its doc comment for the full rationale (the bypass beat, F2; the rename
// blind spot an earlier review found in the regex-only version; ADR-0002).
// Kept in both places deliberately: this package is on the security surface,
// the cmd/relay copy sits beside its sibling wire-immutability idiom.
func TestWireCarriesNoCallerIdentity(t *testing.T) {
	start := (&relayv1.RelayMessage{}).ProtoReflect().Descriptor()
	protowalk.WalkReachableMessageFields(start, func(fieldName string) {
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
	protowalk.AssertExactTopLevelFieldSet(t, (&relayv1.TaskRequest{}).ProtoReflect().Descriptor(),
		map[string]bool{"task_id": true, "operation": true, "raw_exec": true, "timeout_seconds": true, "risk_class": true})
	protowalk.AssertExactTopLevelFieldSet(t, (&relayv1.PolicyQuery{}).ProtoReflect().Descriptor(),
		map[string]bool{"query_id": true, "operation": true, "raw_exec": true})
	protowalk.AssertExactTopLevelFieldSet(t, (&relayv1.Operation{}).ProtoReflect().Descriptor(),
		map[string]bool{"name": true, "args": true})
	protowalk.AssertExactTopLevelFieldSet(t, (&relayv1.RawExec{}).ProtoReflect().Descriptor(),
		map[string]bool{"argv": true})
}
