package capability

import (
	"context"
	"errors"
	"fmt"
	"math"
	"strings"
	"testing"

	"github.com/Felag-Engineering/relay/relay/internal/jobs"
	"github.com/Felag-Engineering/relay/relay/internal/registry"
)

// queryCountingDispatcher counts the Nodes' queries a Plan makes, so a test can
// prove a refusal came before any Node was asked.
type queryCountingDispatcher struct {
	spyDispatcher
	queries int
}

func (d *queryCountingDispatcher) query(context.Context, dispatch) (planResult, error) {
	d.queries++
	return planResult{}, nil
}

var malformedNativeCalls = []struct {
	name string
	act  jobs.Action
	want string // the offending name the refusal must carry
}{
	{"unknown name (the #345 trap)", jobs.Action{Kind: jobs.ActionOperation, OperationName: "service.restart", OperationArgs: map[string]string{"unitt": "nginx"}}, "unitt"},
	{"an extra unknown name", jobs.Action{Kind: jobs.ActionOperation, OperationName: "file.read", OperationArgs: map[string]string{"path": "/etc/os-release", "bogus": "x"}}, "bogus"},
	{"missing required name", jobs.Action{Kind: jobs.ActionOperation, OperationName: "service.restart", OperationArgs: map[string]string{}}, "unit"},
	{"any name on a zero-arg Operation", jobs.Action{Kind: jobs.ActionOperation, OperationName: "system.facts", OperationArgs: map[string]string{"x": "y"}}, "x"},
}

var emptyRawExecCalls = []struct {
	name string
	argv []string
}{
	{"nil argv", nil},
	{"empty argv", []string{}},
}

// assertRefusedAudited checks the shared half of EX-64 and EX-67: a
// MalformedCallError, the malformed metric, one audited refusal that names
// want, no dispatch audit, and no Task sent to any Node.
func assertRefusedAudited(t *testing.T, f *startFx, m *recordingMetrics, err error, want string) {
	t.Helper()
	assertRefusedAuditedAs(t, f, m, err, isMalformedCall, want)
}

func isMalformedCall(err error) bool {
	var mal *MalformedCallError
	return errors.As(err, &mal)
}

func isTimeoutRefusal(err error) bool {
	var te *TimeoutError
	return errors.As(err, &te)
}

// assertRefusedAuditedAs is assertRefusedAudited for any call-shape refusal
// type, named by isRefusal.
func assertRefusedAuditedAs(t *testing.T, f *startFx, m *recordingMetrics, err error, isRefusal func(error) bool, want string) {
	t.Helper()
	if !isRefusal(err) {
		t.Fatalf("err = %v, want the call-shape refusal", err)
	}
	if !strings.Contains(err.Error(), want) {
		t.Errorf("error %q must name %q", err.Error(), want)
	}
	if len(m.refusals) != 1 || m.refusals[0] != RefusalMalformed {
		t.Errorf("refusal metrics = %v, want [RefusalMalformed]", m.refusals)
	}
	reasons := f.audit.refusalReasons()
	if len(reasons) != 1 || !strings.Contains(reasons[0], want) {
		t.Errorf("refusal audit reasons = %q, want exactly one naming %q", reasons, want)
	}
	if hasAuditKind(f.audit.entries, AuditKindDispatch) {
		t.Errorf("audit kinds = %v, want no dispatch record", f.audit.kinds())
	}
	for _, id := range startNode {
		if n := f.conduit.dispatched(id); n != 0 {
			t.Errorf("%s was sent %d Tasks, want 0", id, n)
		}
	}
}

// TestCallShape_MalformedNativeCallIsRefusedAuditedWithNoJob: a Native call
// whose argument names do not match opvocab's declaration is refused as
// malformed in the layer, audited, with no Job, through Run and Start.
//
// Proves EX-64.
func TestCallShape_MalformedNativeCallIsRefusedAuditedWithNoJob(t *testing.T) {
	for _, tc := range malformedNativeCalls {
		t.Run("Run/"+tc.name, func(t *testing.T) {
			m := &recordingMetrics{}
			f := newStartFx(t, func(s *seams) { s.metrics = m })
			_, err := f.svc.Run(context.Background(), alice, fleetSel, tc.act)
			assertRefusedAudited(t, f, m, err, tc.want)
		})
		t.Run("Start/"+tc.name, func(t *testing.T) {
			m := &recordingMetrics{}
			f := newStartFx(t, func(s *seams) { s.metrics = m })
			sj, err := f.svc.Start(context.Background(), alice, fleetSel, tc.act, StartOptions{})
			assertRefusedAudited(t, f, m, err, tc.want)
			if sj.JobID != "" {
				t.Errorf("JobID = %q, want none: a refused call creates no Job", sj.JobID)
			}
		})
	}
}

// TestCallShape_EmptyRawExecArgvIsRefusedAuditedWithNoJob: a Raw Exec call
// whose argv is nil or empty is refused the same way, through Run, Start and
// Plan, and a Plan refuses it whatever matched and before any Node is queried.
//
// Proves EX-67.
func TestCallShape_EmptyRawExecArgvIsRefusedAuditedWithNoJob(t *testing.T) {
	for _, tc := range emptyRawExecCalls {
		act := jobs.Action{Kind: jobs.ActionRawExec, RawExecArgv: tc.argv}
		t.Run("Run/"+tc.name, func(t *testing.T) {
			m := &recordingMetrics{}
			f := newStartFx(t, func(s *seams) { s.metrics = m })
			_, err := f.svc.Run(context.Background(), alice, fleetSel, act)
			assertRefusedAudited(t, f, m, err, "argv is empty")
		})
		t.Run("Start/"+tc.name, func(t *testing.T) {
			m := &recordingMetrics{}
			f := newStartFx(t, func(s *seams) { s.metrics = m })
			sj, err := f.svc.Start(context.Background(), alice, fleetSel, act, StartOptions{})
			assertRefusedAudited(t, f, m, err, "argv is empty")
			if sj.JobID != "" {
				t.Errorf("JobID = %q, want none: a refused call creates no Job", sj.JobID)
			}
		})
		for name, sel := range map[string]Selector{"Nodes matched": webSelector(), "none matched": dbSelector()} {
			t.Run("Plan/"+tc.name+"/"+name, func(t *testing.T) {
				assertPlanRefusesBeforeQuerying(t, sel, act, "argv is empty")
			})
		}
	}
}

func dbSelector() Selector {
	return Selector{Predicates: []Predicate{{Namespace: NamespaceNode, Key: "role", Value: "db"}}}
}

func assertPlanRefusesBeforeQuerying(t *testing.T, sel Selector, act jobs.Action, want string) {
	t.Helper()
	assertPlanRefusedBeforeQuerying(t, sel, act, nil, isMalformedCall, want)
}

// assertPlanRefusedBeforeQuerying runs Plan over a two-Node registry (vocab is
// what its Nodes reported, nil for none) and checks a call-shape refusal named
// by isRefusal, audited, with no Node queried.
func assertPlanRefusedBeforeQuerying(t *testing.T, sel Selector, act jobs.Action, vocab TemplateVocabularySource, isRefusal func(error) bool, want string) {
	t.Helper()
	audit := &spyAuditSink{}
	m := &recordingMetrics{}
	svc := build(t, seams{reg: seedNodes(t, 2), authz: &spyAuthorizer{}, cap: &spyCapChecker{}, audit: audit, metrics: m, nodeVocab: vocab})
	disp := &queryCountingDispatcher{}
	svc.disp = disp

	pr, err := svc.Plan(context.Background(), Principal{Account: "alice"}, sel, act)

	if !isRefusal(err) {
		t.Fatalf("Plan err = %v, want the call-shape refusal: a call that cannot be asked is refused, not reported", err)
	}
	if !strings.Contains(err.Error(), want) {
		t.Errorf("error %q must name %q", err.Error(), want)
	}
	if disp.queries != 0 {
		t.Errorf("Plan queried %d times, want 0: the refusal comes before any Node is asked", disp.queries)
	}
	if hasAuditKind(audit.entries, AuditKindPlan) || !hasAuditKind(audit.entries, AuditKindRefusal) {
		t.Errorf("audit kinds = %v, want a refusal and no plan record", audit.kinds())
	}
	if len(m.refusals) != 1 || m.refusals[0] != RefusalMalformed {
		t.Errorf("refusal metrics = %v, want [RefusalMalformed]", m.refusals)
	}
	if pr.NoNodesMatched || pr.Matched != 0 || len(pr.Verdicts) != 0 {
		t.Errorf("PlanResult = %+v, want the zero value: nothing is reported for a refused call", pr)
	}
}

// TestPlan_UndeclaredNativeArgumentIsRefusedBeforeAnyNodeIsQueried: a
// preflight refuses a Native call with an undeclared argument name whatever
// matched, with an audited refusal and no Node queried (PF-13).
//
// Proves PF-13, EX-64.
func TestPlan_UndeclaredNativeArgumentIsRefusedBeforeAnyNodeIsQueried(t *testing.T) {
	act := jobs.Action{Kind: jobs.ActionOperation, OperationName: "service.restart", OperationArgs: map[string]string{"unitt": "nginx"}}
	t.Run("Nodes matched", func(t *testing.T) {
		assertPlanRefusesBeforeQuerying(t, webSelector(), act, "unitt")
	})
	t.Run("none matched", func(t *testing.T) {
		assertPlanRefusesBeforeQuerying(t, dbSelector(), act, "unitt")
	})
}

// TestCallShape_MalformedNativeCallFromUnauthorizedCallerIsUnauthorized: a
// caller who may not ask learns nothing about the call's shape.
//
// Proves EX-64.
func TestCallShape_MalformedNativeCallFromUnauthorizedCallerIsUnauthorized(t *testing.T) {
	act := jobs.Action{Kind: jobs.ActionOperation, OperationName: "service.restart", OperationArgs: map[string]string{"unitt": "x"}}
	authzErr := errors.New("denied for test")

	check := func(t *testing.T, err error) {
		t.Helper()
		var mal *MalformedCallError
		if !errors.Is(err, authzErr) || errors.As(err, &mal) {
			t.Fatalf("err = %v, want the authorization refusal and not a malformed-call one", err)
		}
	}
	t.Run("Run", func(t *testing.T) {
		f := newStartFx(t)
		f.authz.err = authzErr
		_, err := f.svc.Run(context.Background(), alice, fleetSel, act)
		check(t, err)
	})
	t.Run("Start", func(t *testing.T) {
		f := newStartFx(t)
		f.authz.err = authzErr
		_, err := f.svc.Start(context.Background(), alice, fleetSel, act, StartOptions{})
		check(t, err)
	})
	t.Run("Plan", func(t *testing.T) {
		authz := &spyAuthorizer{err: authzErr}
		svc := build(t, seams{reg: seedNodes(t, 2), authz: authz, cap: &spyCapChecker{}, audit: &spyAuditSink{}})
		_, err := svc.Plan(context.Background(), Principal{Account: "alice"}, webSelector(), act)
		check(t, err)
	})
}

// TestStart_MalformedCallMatchingNoNodeIsRefusedAsNoNodesMatched: on a real
// dispatch the zero-match refusal comes first (EX-3), so a malformed call
// whose Selector matches nothing is no_nodes_matched.
//
// Proves EX-59, EX-64, EX-67.
func TestStart_MalformedCallMatchingNoNodeIsRefusedAsNoNodesMatched(t *testing.T) {
	calls := map[string]jobs.Action{
		"Native":               {Kind: jobs.ActionOperation, OperationName: "service.restart", OperationArgs: map[string]string{"unitt": "x"}},
		"Raw Exec":             {Kind: jobs.ActionRawExec},
		"Native timeout 301":   {Kind: jobs.ActionOperation, OperationName: "system.facts", TimeoutSeconds: 301},
		"Raw Exec timeout 301": {Kind: jobs.ActionRawExec, RawExecArgv: []string{"/usr/bin/true"}, TimeoutSeconds: 301},
		"Template timeout 301": {Kind: jobs.ActionOperation, OperationName: "svc.status", TimeoutSeconds: 301},
	}
	for name, act := range calls {
		t.Run(name, func(t *testing.T) {
			f := newStartFx(t)
			_, err := f.svc.Start(context.Background(), alice, dbSelector(), act, StartOptions{})
			var nnm *NoNodesMatchedError
			if !errors.As(err, &nnm) || isMalformedCall(err) || isTimeoutRefusal(err) {
				t.Fatalf("err = %v, want no_nodes_matched and not a call-shape refusal", err)
			}
		})
	}
}

// TestResolveAction_CallShapeIsComputedNeverRefused: resolveAction computes the
// call-shape refusal as data, leaves the Node-dependent refusal alone and still
// fixes the class.
func TestResolveAction_CallShapeIsComputedNeverRefused(t *testing.T) {
	s := &Execution{}
	tests := []struct {
		name        string
		act         jobs.Action
		wantRefusal bool
		wantClass   jobs.RiskClass
		// template marks a Template Operation, the only call whose Node-dependent
		// refusal may be set (here by an empty matched set).
		template bool
	}{
		{"malformed Native", malformedNativeCalls[0].act, true, jobs.RiskClassMutate, false},
		{"Raw Exec nil argv", jobs.Action{Kind: jobs.ActionRawExec}, true, jobs.RiskClassMutate, false},
		{"Raw Exec empty argv", jobs.Action{Kind: jobs.ActionRawExec, RawExecArgv: []string{}}, true, jobs.RiskClassMutate, false},
		{"valid Native", jobs.Action{Kind: jobs.ActionOperation, OperationName: "service.restart", OperationArgs: map[string]string{"unit": "nginx"}}, false, jobs.RiskClassMutate, false},
		{"Template name", jobs.Action{Kind: jobs.ActionOperation, OperationName: "svc.status"}, false, jobs.RiskClassUnspecified, true},
		{"Native timeout 301", jobs.Action{Kind: jobs.ActionOperation, OperationName: "service.restart", OperationArgs: map[string]string{"unit": "nginx"}, TimeoutSeconds: 301}, true, jobs.RiskClassMutate, false},
		{"Raw Exec timeout -1", jobs.Action{Kind: jobs.ActionRawExec, RawExecArgv: []string{"/usr/bin/true"}, TimeoutSeconds: -1}, true, jobs.RiskClassMutate, false},
		{"Template timeout 301", jobs.Action{Kind: jobs.ActionOperation, OperationName: "svc.status", TimeoutSeconds: 301}, true, jobs.RiskClassUnspecified, true},
		{"Native timeout 300", jobs.Action{Kind: jobs.ActionOperation, OperationName: "service.restart", OperationArgs: map[string]string{"unit": "nginx"}, TimeoutSeconds: 300}, false, jobs.RiskClassMutate, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ra := s.resolveAction(tt.act, nil)
			if (ra.callRefusal != nil) != tt.wantRefusal {
				t.Errorf("callRefusal = %v, want refusal=%v", ra.callRefusal, tt.wantRefusal)
			}
			if tt.wantRefusal && ra.callRefusalKind != RefusalMalformed {
				t.Errorf("callRefusalKind = %v, want RefusalMalformed", ra.callRefusalKind)
			}
			if !tt.template && ra.refusal != nil {
				t.Errorf("refusal = %v, want nil: the call-shape check is not a Node-dependent refusal", ra.refusal)
			}
			if ra.act.RiskClass != tt.wantClass {
				t.Errorf("class = %v, want %v", ra.act.RiskClass, tt.wantClass)
			}
		})
	}
}

// timeoutCall is one kind of call carrying a given timeout_seconds.
type timeoutCall struct {
	name string
	act  func(timeout int32) jobs.Action
	// vocab is what the Nodes reported: only a Template call needs one.
	vocab TemplateVocabularySource
}

func timeoutCalls() []timeoutCall {
	templates := func(ids ...string) TemplateVocabularySource {
		v := staticVocab{}
		for _, id := range ids {
			v[id] = reported(readTemplate("svc.status"))
		}
		return v
	}
	return []timeoutCall{
		{"Native", func(t int32) jobs.Action {
			return jobs.Action{Kind: jobs.ActionOperation, OperationName: "system.facts", TimeoutSeconds: t}
		}, nil},
		{"Raw Exec", func(t int32) jobs.Action {
			return jobs.Action{Kind: jobs.ActionRawExec, RawExecArgv: []string{"/usr/bin/true"}, TimeoutSeconds: t}
		}, nil},
		{"Template", func(t int32) jobs.Action {
			return jobs.Action{Kind: jobs.ActionOperation, OperationName: "svc.status", TimeoutSeconds: t}
		}, templates("node-a", "node-b", "node-0", "node-1")},
	}
}

// newTimeoutStartFx is a Start fixture whose Nodes have reported tc's vocabulary.
func newTimeoutStartFx(t *testing.T, tc timeoutCall, mods ...func(*seams)) *startFx {
	t.Helper()
	return newStartFx(t, append([]func(*seams){func(s *seams) {
		reg := registry.NewInMemory()
		for _, id := range startNode {
			if _, err := reg.Upsert(linuxReportWith(registry.Report{NodeID: id, TemplateSetFingerprint: reportedTemplateSet})); err != nil {
				t.Fatalf("seed registry: %v", err)
			}
		}
		s.reg = reg
		s.nodeVocab = tc.vocab
	}}, mods...)...)
}

// TestCallShape_TaskTimeoutOutsideTheCeilingIsRefusedAuditedWithNoJob: a
// timeout_seconds above 300 or below 0 is refused as malformed in the layer,
// for a Native, a Template and a Raw Exec call, audited, with no Job; a Plan
// refuses it whatever matched and before any Node is queried.
//
// Proves EX-59.
func TestCallShape_TaskTimeoutOutsideTheCeilingIsRefusedAuditedWithNoJob(t *testing.T) {
	for _, tc := range timeoutCalls() {
		for _, asked := range []int32{301, -1} {
			act := tc.act(asked)
			label := fmt.Sprintf("%s/%d", tc.name, asked)
			t.Run("Start/"+label, func(t *testing.T) {
				m := &recordingMetrics{}
				f := newTimeoutStartFx(t, tc, func(s *seams) { s.metrics = m })
				sj, err := f.svc.Start(context.Background(), alice, fleetSel, act, StartOptions{})
				assertRefusedAuditedAs(t, f, m, err, isTimeoutRefusal, "300")
				var te *TimeoutError
				if errors.As(err, &te) && te.Asked != asked {
					t.Errorf("Asked = %d, want %d", te.Asked, asked)
				}
				if !strings.Contains(err.Error(), "Nothing was dispatched") {
					t.Errorf("error %q must say nothing was dispatched", err.Error())
				}
				if sj.JobID != "" {
					t.Errorf("JobID = %q, want none: a refused call creates no Job", sj.JobID)
				}
			})
			for name, sel := range map[string]Selector{"Nodes matched": webSelector(), "none matched": dbSelector()} {
				t.Run("Plan/"+label+"/"+name, func(t *testing.T) {
					assertPlanRefusedBeforeQuerying(t, sel, act, tc.vocab, isTimeoutRefusal, "300")
				})
			}
		}
	}
}

// TestCallShape_TaskTimeoutAtTheCeilingPasses: 300 and 0 are not refused, for
// each kind, through Start and Plan.
//
// Proves EX-59.
func TestCallShape_TaskTimeoutAtTheCeilingPasses(t *testing.T) {
	for _, tc := range timeoutCalls() {
		for _, asked := range []int32{300, 0} {
			act := tc.act(asked)
			label := fmt.Sprintf("%s/%d", tc.name, asked)
			t.Run("Start/"+label, func(t *testing.T) {
				m := &recordingMetrics{}
				f := newTimeoutStartFx(t, tc, func(s *seams) { s.metrics = m })
				sj, err := f.svc.Start(context.Background(), alice, fleetSel, act, StartOptions{})
				if err != nil {
					t.Fatalf("Start err = %v, want none", err)
				}
				if sj.JobID == "" {
					t.Error("JobID is empty, want a Job")
				}
				if len(m.refusals) != 0 {
					t.Errorf("refusal metrics = %v, want none", m.refusals)
				}
			})
			t.Run("Plan/"+label, func(t *testing.T) {
				svc := build(t, seams{reg: seedNodes(t, 2), authz: &spyAuthorizer{}, cap: &spyCapChecker{}, audit: &spyAuditSink{}, nodeVocab: tc.vocab})
				disp := &queryCountingDispatcher{}
				svc.disp = disp
				if _, err := svc.Plan(context.Background(), Principal{Account: "alice"}, webSelector(), act); err != nil {
					t.Fatalf("Plan err = %v, want none", err)
				}
				if disp.queries == 0 {
					t.Error("Plan queried no Node, want it to ask the matched Nodes")
				}
			})
		}
	}
}

// TestCallShape_TaskTimeoutFromUnauthorizedCallerIsUnauthorized: a caller who
// may not ask learns nothing about the call's timeout.
//
// Proves EX-59.
func TestCallShape_TaskTimeoutFromUnauthorizedCallerIsUnauthorized(t *testing.T) {
	authzErr := errors.New("denied for test")
	for _, tc := range timeoutCalls() {
		act := tc.act(301)
		t.Run("Start/"+tc.name, func(t *testing.T) {
			f := newTimeoutStartFx(t, tc)
			f.authz.err = authzErr
			_, err := f.svc.Start(context.Background(), alice, fleetSel, act, StartOptions{})
			if !errors.Is(err, authzErr) || isTimeoutRefusal(err) {
				t.Fatalf("err = %v, want the authorization refusal and not a timeout one", err)
			}
		})
		t.Run("Plan/"+tc.name, func(t *testing.T) {
			authz := &spyAuthorizer{err: authzErr}
			svc := build(t, seams{reg: seedNodes(t, 2), authz: authz, cap: &spyCapChecker{}, audit: &spyAuditSink{}, nodeVocab: tc.vocab})
			_, err := svc.Plan(context.Background(), Principal{Account: "alice"}, webSelector(), act)
			if !errors.Is(err, authzErr) || isTimeoutRefusal(err) {
				t.Fatalf("err = %v, want the authorization refusal and not a timeout one", err)
			}
		})
	}
}

// TestCheckCallShape_TheTimeoutIsTheLastCheck: a malformed name or an empty
// argv wins over a timeout past the ceiling; a well-formed call is refused only
// outside 0-300.
//
// Proves EX-59.
func TestCheckCallShape_TheTimeoutIsTheLastCheck(t *testing.T) {
	malformed := []jobs.Action{
		{Kind: jobs.ActionOperation, OperationName: "service.restart", OperationArgs: map[string]string{"unitt": "x"}, TimeoutSeconds: 301},
		{Kind: jobs.ActionRawExec, TimeoutSeconds: 301},
	}
	for _, act := range malformed {
		_, err := checkCallShape(act)
		if !isMalformedCall(err) {
			t.Errorf("checkCallShape(%+v) err = %v, want the *MalformedCallError", act, err)
		}
	}

	valid := jobs.Action{Kind: jobs.ActionOperation, OperationName: "system.facts"}
	for _, asked := range []int32{301, -1, math.MaxInt32, math.MinInt32} {
		valid.TimeoutSeconds = asked
		kind, err := checkCallShape(valid)
		if !isTimeoutRefusal(err) || kind != RefusalMalformed {
			t.Errorf("timeout %d: (%v, %v), want a *TimeoutError and RefusalMalformed", asked, kind, err)
		}
	}
	for _, asked := range []int32{0, 1, MaxTaskTimeoutSeconds} {
		valid.TimeoutSeconds = asked
		if _, err := checkCallShape(valid); err != nil {
			t.Errorf("timeout %d: err = %v, want none", asked, err)
		}
	}
}

// TestTimeoutError_NamesTheCeilingAndSaysNothingWasDispatched: the text reads
// sensibly for a value above the ceiling and for a negative one.
//
// Proves EX-59.
func TestTimeoutError_NamesTheCeilingAndSaysNothingWasDispatched(t *testing.T) {
	for _, asked := range []int32{301, -1} {
		msg := (&TimeoutError{Asked: asked}).Error()
		for _, want := range []string{fmt.Sprint(asked), "300", "Nothing was dispatched"} {
			if !strings.Contains(msg, want) {
				t.Errorf("TimeoutError{%d} = %q, want it to contain %q", asked, msg, want)
			}
		}
	}
}
