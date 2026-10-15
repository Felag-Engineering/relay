package capability

import (
	"context"
	"errors"
	"testing"

	"github.com/Felag-Engineering/relay/relay/internal/jobs"
	"github.com/Felag-Engineering/relay/relay/internal/opvocab"
	"github.com/Felag-Engineering/relay/relay/internal/registry"
)

// These tests are the proof of invariant 13 for Native and Raw Exec Actions
// (#878, ADR-0012): only the capability layer decides the class, an adapter
// that presets one is refused, and Raw Exec is always mutate.

func twoNodes() []registry.Node {
	return []registry.Node{{NodeID: "node-0"}, {NodeID: "node-1"}}
}

func TestResolveAction_RefusesANativeActionThatArrivesWithAClass(t *testing.T) {
	s := buildRaw(t, seams{nodeVocab: staticVocab{}})
	for _, preset := range []jobs.RiskClass{jobs.RiskClassRead, jobs.RiskClassMutate} {
		act := jobs.Action{Kind: jobs.ActionOperation, OperationName: "service.restart",
			OperationArgs: map[string]string{"unit": "nginx"}, RiskClass: preset}
		ra := s.resolveAction(act, twoNodes())

		var presetErr *ClassPresetError
		if !errors.As(ra.refusal, &presetErr) {
			t.Fatalf("preset %q: refusal = %v, want a *ClassPresetError (even the correct class may not be set by a caller)",
				jobs.RiskClassName(preset), ra.refusal)
		}
		if ra.refusalKind != RefusalInternal {
			t.Errorf("preset %q: refusalKind = %v, want RefusalInternal", jobs.RiskClassName(preset), ra.refusalKind)
		}
		if ra.act.RiskClass != jobs.RiskClassMutate {
			t.Errorf("preset %q: resolved class = %q, want the derived mutate, never the adapter's",
				jobs.RiskClassName(preset), jobs.RiskClassName(ra.act.RiskClass))
		}
	}
}

func TestResolveAction_NativeWithNoClassResolvesToItsOpvocabClass(t *testing.T) {
	s := buildRaw(t, seams{nodeVocab: staticVocab{}})

	restart := s.resolveAction(jobs.Action{Kind: jobs.ActionOperation, OperationName: "service.restart",
		OperationArgs: map[string]string{"unit": "nginx"}}, twoNodes())
	if restart.refusal != nil || restart.act.RiskClass != jobs.RiskClassMutate {
		t.Errorf("service.restart = class %q, refusal %v; want mutate, no refusal",
			jobs.RiskClassName(restart.act.RiskClass), restart.refusal)
	}

	ops := opvocab.Operations()
	if len(ops) == 0 {
		t.Fatal("opvocab.Operations() is empty: the loop below would prove nothing")
	}
	for _, d := range ops {
		want := jobs.RiskClassMutate
		if d.Risk == jobs.RiskClassRead {
			want = jobs.RiskClassRead
		}
		ra := s.resolveAction(jobs.Action{Kind: jobs.ActionOperation, OperationName: d.Name}, twoNodes())
		if ra.refusal != nil {
			t.Errorf("%s: unexpected refusal %v", d.Name, ra.refusal)
		}
		if ra.act.RiskClass != want {
			t.Errorf("%s: class = %q, want %q", d.Name, jobs.RiskClassName(ra.act.RiskClass), jobs.RiskClassName(want))
		}
		if len(ra.nodes) != 2 {
			t.Errorf("%s: dispatched to %d Nodes, want every matched Node", d.Name, len(ra.nodes))
		}
	}
}

func TestResolveAction_RawExecIsMutateWhateverTheAdapterPassed(t *testing.T) {
	s := buildRaw(t, seams{nodeVocab: staticVocab{}})
	for _, preset := range []jobs.RiskClass{jobs.RiskClassUnspecified, jobs.RiskClassRead, jobs.RiskClassMutate} {
		act := jobs.Action{Kind: jobs.ActionRawExec, RawExecArgv: []string{"/bin/cat", "/etc/hostname"}, RiskClass: preset}
		ra := s.resolveAction(act, twoNodes())

		if ra.act.RiskClass != jobs.RiskClassMutate {
			t.Errorf("preset %q: Raw Exec class = %q, want mutate", jobs.RiskClassName(preset), jobs.RiskClassName(ra.act.RiskClass))
		}
		var presetErr *ClassPresetError
		refused := errors.As(ra.refusal, &presetErr)
		if wantRefused := preset != jobs.RiskClassUnspecified; refused != wantRefused {
			t.Errorf("preset %q: refused = %v, want %v (refusal %v)", jobs.RiskClassName(preset), refused, wantRefused, ra.refusal)
		}
	}
}

func TestRun_NativePresetClassIsRefusedAndAuditedBeforeAnyJob(t *testing.T) {
	reg := seedOneNode(t)
	authz := &spyAuthorizer{}
	capChecker := &spyCapChecker{}
	disp := &spyDispatcher{}
	audit := &spyAuditSink{}
	svc := buildRaw(t, seams{reg: reg, authz: authz, cap: capChecker, disp: disp, audit: audit, freeze: noopFreezeStore{}, metrics: noopMetricsSink{}})

	sel := Selector{Predicates: []Predicate{{Namespace: NamespaceNode, Key: "role", Value: "web"}}}
	act := jobs.Action{Kind: jobs.ActionOperation, OperationName: "service.restart",
		OperationArgs: map[string]string{"unit": "nginx"}, RiskClass: jobs.RiskClassRead}
	_, err := svc.Run(context.Background(), Principal{Account: "alice"}, sel, act)

	var presetErr *ClassPresetError
	if !errors.As(err, &presetErr) {
		t.Fatalf("Run() error = %v, want a *ClassPresetError", err)
	}
	if capChecker.called {
		t.Error("the blast cap was consulted for an Action whose class an adapter had set")
	}
	if disp.called {
		t.Error("the dispatcher was called for an Action whose class an adapter had set")
	}
	if !audit.called || audit.entry.Kind != AuditKindRefusal {
		t.Fatalf("audit = %+v, want one refusal entry", audit.entry)
	}
	if audit.entry.Action.RiskClass != jobs.RiskClassMutate {
		t.Errorf("refusal carried class %q, want the derived mutate", jobs.RiskClassName(audit.entry.Action.RiskClass))
	}
}

func TestRun_RawExecTakesTheMutateCap(t *testing.T) {
	reg := seedOneNode(t)
	capChecker := &spyCapChecker{}
	svc := buildRaw(t, seams{reg: reg, authz: &spyAuthorizer{}, cap: capChecker, disp: &spyDispatcher{jobID: "job-1"},
		audit: &spyAuditSink{}, freeze: noopFreezeStore{}, metrics: noopMetricsSink{}})

	sel := Selector{Predicates: []Predicate{{Namespace: NamespaceNode, Key: "role", Value: "web"}}}
	act := jobs.Action{Kind: jobs.ActionRawExec, RawExecArgv: []string{"/bin/cat", "/etc/hostname"}}
	if _, err := svc.Run(context.Background(), Principal{Account: "alice"}, sel, act); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !capChecker.called || capChecker.gotClass != jobs.RiskClassMutate {
		t.Errorf("cap checked = %v with class %q, want Raw Exec under the mutate cap",
			capChecker.called, jobs.RiskClassName(capChecker.gotClass))
	}
}

func TestPlan_NativeClassIsDerived(t *testing.T) {
	reg := seedNodes(t, 2)
	var log []string
	conduit := newFakeConduit(&log)
	for _, id := range []string{"node-0", "node-1"} {
		conduit.connected[id] = true
		conduit.verdicts[id] = jobs.Verdict{Allowed: true}
	}
	jobsRepo, tasksRepo := testEngineStore(t)
	capChecker := &spyCapChecker{}
	svc := build(t, seams{reg: reg,
		authz:    &spyAuthorizer{},
		cap:      capChecker,
		audit:    &spyAuditSink{},
		freeze:   &fakeFreezeStore{},
		jobsRepo: jobsRepo, tasksRepo: tasksRepo, conduit: conduit,
	})

	act := jobs.Action{Kind: jobs.ActionOperation, OperationName: "system.facts"}
	if _, err := svc.Plan(context.Background(), Principal{Account: "alice"}, webSelector(), act); err != nil {
		t.Fatalf("Plan: %v", err)
	}
	if !capChecker.called || capChecker.gotClass != jobs.RiskClassRead {
		t.Errorf("cap checked = %v with class %q, want system.facts under the read cap",
			capChecker.called, jobs.RiskClassName(capChecker.gotClass))
	}
}
