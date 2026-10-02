package capability

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/jobs"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/nodevocab"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/policyview"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/registry"
)

// staticVocab is a TemplateVocabularySource over a fixed map: a Node absent
// from the map has reported nothing (the nodevocab.Cache miss), which is
// different from a Node mapped to an empty Snapshot (it reported no
// Templates). Gets are recorded so a test can prove which Nodes were read.
type staticVocab map[string]nodevocab.Snapshot

func (v staticVocab) Get(nodeID string) (nodevocab.Snapshot, bool) {
	s, ok := v[nodeID]
	return s, ok
}

// countingVocab wraps a staticVocab and records every Get.
type countingVocab struct {
	staticVocab
	mu   sync.Mutex
	gets []string
}

func (c *countingVocab) Get(nodeID string) (nodevocab.Snapshot, bool) {
	c.mu.Lock()
	c.gets = append(c.gets, nodeID)
	c.mu.Unlock()
	return c.staticVocab.Get(nodeID)
}

func templateWithClass(name string, class jobs.RiskClass, slots ...string) nodevocab.Template {
	t := nodevocab.Template{Name: name, RiskClass: int32(class)}
	for _, s := range slots {
		t.Slots = append(t.Slots, nodevocab.Slot{Name: s, Type: "identifier"})
	}
	return t
}

func readTemplate(name string, slots ...string) nodevocab.Template {
	return templateWithClass(name, jobs.RiskClassRead, slots...)
}

func mutateTemplate(name string, slots ...string) nodevocab.Template {
	return templateWithClass(name, jobs.RiskClassMutate, slots...)
}

// capturingAuthorizer records the Action it was asked to authorize, so a
// test can prove authorization sees the RESOLVED class (ADR-0042's order).
type capturingAuthorizer struct {
	spyAuthorizer
	gotAct jobs.Action
}

func (c *capturingAuthorizer) Authorize(ctx context.Context, p Principal, act jobs.Action, sel Selector) error {
	c.mu.Lock()
	c.gotAct = act
	c.mu.Unlock()
	return c.spyAuthorizer.Authorize(ctx, p, act, sel)
}

// recordingMetrics records refusal kinds.
type recordingMetrics struct {
	mu       sync.Mutex
	refusals []RefusalKind
}

func (m *recordingMetrics) IncDispatch(jobs.Outcome) {}

func (m *recordingMetrics) IncRefusal(k RefusalKind) {
	m.mu.Lock()
	m.refusals = append(m.refusals, k)
	m.mu.Unlock()
}

type templateFixture struct {
	svc     *Service
	audit   *spyAuditSink
	authz   *capturingAuthorizer
	tasks   jobs.TaskRepository
	metrics *recordingMetrics
}

// newTemplateTestService wires a real jobEngine and a real SQLite store
// behind a Service with the given vocabulary source and cap checker.
func newTemplateTestService(t *testing.T, reg registry.Repository, conduit *fakeConduit, vocab TemplateVocabularySource, capc CapChecker) (*Service, *templateFixture) {
	t.Helper()
	jobsRepo, tasksRepo := testEngineStore(t)
	f := &templateFixture{audit: &spyAuditSink{}, authz: &capturingAuthorizer{}, tasks: tasksRepo, metrics: &recordingMetrics{}}
	opts := []Option{
		WithAuthorizer(f.authz),
		WithCapChecker(capc),
		WithAuditSink(f.audit),
		WithFreeze(&fakeFreezeStore{}),
		WithMetrics(f.metrics),
		WithExecution(jobsRepo, tasksRepo, conduit),
	}
	if vocab != nil {
		opts = append(opts, WithTemplateVocabulary(vocab))
	}
	f.svc = New(reg, opts...)
	return f.svc, f
}

func connectedConduit(log *[]string, nodes ...string) *fakeConduit {
	c := newFakeConduit(log)
	for _, n := range nodes {
		c.connected[n] = true
		c.results[n] = jobs.Result{Outcome: jobs.OutcomeSuccess}
		c.verdicts[n] = jobs.Verdict{Allowed: true}
	}
	return c
}

func templateAction(name string, args map[string]string) jobs.Action {
	return jobs.Action{Kind: jobs.ActionOperation, OperationName: name, OperationArgs: args}
}

// --- resolveAction: the rules, one at a time ------------------------------

func TestResolveAction_NativeAndRawExecPassThroughUnchanged(t *testing.T) {
	s := &Service{nodeVocab: staticVocab{}}
	nodes := []registry.Node{{NodeID: "node-0"}, {NodeID: "node-1"}}
	for _, act := range []jobs.Action{
		{Kind: jobs.ActionOperation, OperationName: "service.restart", OperationArgs: map[string]string{"unit": "nginx"}, RiskClass: jobs.RiskClassMutate},
		{Kind: jobs.ActionRawExec, RawExecArgv: []string{"/bin/true"}, RiskClass: jobs.RiskClassMutate},
	} {
		ra := s.resolveAction(act, nodes)
		if ra.refusal != nil || !reflect.DeepEqual(ra.act, act) || len(ra.nodes) != 2 || len(ra.excluded) != 0 {
			t.Errorf("resolveAction(%+v) = %+v, want the Action and every Node unchanged", act, ra)
		}
	}
}

func TestResolveAction_ClassIsMostRestrictiveOverReportingNodes(t *testing.T) {
	nodes := []registry.Node{{NodeID: "a"}, {NodeID: "b"}, {NodeID: "c"}}
	tests := []struct {
		name  string
		vocab staticVocab
		want  jobs.RiskClass
	}{
		{"every reporting Node says read", staticVocab{
			"a": {Templates: []nodevocab.Template{readTemplate("svc.status")}},
			"b": {Templates: []nodevocab.Template{readTemplate("svc.status")}},
			"c": {Templates: []nodevocab.Template{readTemplate("svc.status")}},
		}, jobs.RiskClassRead},
		{"one Node says mutate", staticVocab{
			"a": {Templates: []nodevocab.Template{readTemplate("svc.status")}},
			"b": {Templates: []nodevocab.Template{mutateTemplate("svc.status")}},
			"c": {Templates: []nodevocab.Template{readTemplate("svc.status")}},
		}, jobs.RiskClassMutate},
		{"one Node reports an unspecified class", staticVocab{
			"a": {Templates: []nodevocab.Template{readTemplate("svc.status")}},
			"b": {Templates: []nodevocab.Template{templateWithClass("svc.status", jobs.RiskClassUnspecified)}},
		}, jobs.RiskClassMutate},
		{"one Node reports a class outside the enum", staticVocab{
			"a": {Templates: []nodevocab.Template{readTemplate("svc.status")}},
			"b": {Templates: []nodevocab.Template{templateWithClass("svc.status", jobs.RiskClass(99))}},
		}, jobs.RiskClassMutate},
		{"the only mutate report is from a Node that does not report the Template", staticVocab{
			"a": {Templates: []nodevocab.Template{readTemplate("svc.status")}},
			"b": {Templates: []nodevocab.Template{mutateTemplate("other.thing")}},
		}, jobs.RiskClassRead},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &Service{nodeVocab: tt.vocab}
			ra := s.resolveAction(templateAction("svc.status", nil), nodes)
			if ra.refusal != nil {
				t.Fatalf("refusal = %v, want none", ra.refusal)
			}
			if ra.act.RiskClass != tt.want {
				t.Errorf("class = %s, want %s", jobs.RiskClassName(ra.act.RiskClass), jobs.RiskClassName(tt.want))
			}
		})
	}
}

func TestResolveAction_ExcludesNodesThatDoNotReportOrHaveNoReport(t *testing.T) {
	s := &Service{nodeVocab: staticVocab{
		"has":   {Templates: []nodevocab.Template{readTemplate("svc.status")}},
		"lacks": {Templates: []nodevocab.Template{readTemplate("other")}},
		"empty": {},
		// "silent" is deliberately absent: no report at all.
	}}
	nodes := []registry.Node{{NodeID: "has"}, {NodeID: "lacks"}, {NodeID: "empty"}, {NodeID: "silent"}}

	ra := s.resolveAction(templateAction("svc.status", nil), nodes)
	if ra.refusal != nil {
		t.Fatalf("refusal = %v, want none", ra.refusal)
	}
	if len(ra.nodes) != 1 || ra.nodes[0].NodeID != "has" {
		t.Errorf("dispatched = %v, want only [has]", ra.nodes)
	}
	reasons := map[string]string{}
	for _, x := range ra.excluded {
		reasons[x.node.NodeID] = x.reason
	}
	want := map[string]string{
		"lacks":  TemplateNotInVocabularyReason,
		"empty":  TemplateNotInVocabularyReason,
		"silent": TemplateNotReportedReason,
	}
	if !reflect.DeepEqual(reasons, want) {
		t.Errorf("excluded reasons = %v, want %v", reasons, want)
	}
}

func TestResolveAction_NoReportingNodeIsAnUnknownOperation(t *testing.T) {
	s := &Service{nodeVocab: staticVocab{"a": {}}}
	ra := s.resolveAction(templateAction("nope.notreal", nil), []registry.Node{{NodeID: "a"}, {NodeID: "b"}})
	var unk *UnknownOperationError
	if !errors.As(ra.refusal, &unk) || ra.refusalKind != RefusalUnknownOperation {
		t.Fatalf("refusal = %v (kind %v), want UnknownOperationError/RefusalUnknownOperation", ra.refusal, ra.refusalKind)
	}
	if unk.Matched != 2 || unk.NotReported != 1 {
		t.Errorf("UnknownOperationError = %+v, want Matched=2 NotReported=1", unk)
	}
	if !strings.Contains(unk.Error(), "unknown operation") || !strings.Contains(unk.Error(), "list_operations") {
		t.Errorf("error %q must say unknown operation and point at list_operations", unk.Error())
	}
}

func TestResolveAction_NoVocabularySourceDispatchesNothingBlind(t *testing.T) {
	s := &Service{}
	ra := s.resolveAction(templateAction("svc.status", nil), []registry.Node{{NodeID: "a"}})
	var unk *UnknownOperationError
	if !errors.As(ra.refusal, &unk) || len(ra.nodes) != 0 {
		t.Fatalf("with no vocabulary source wired: refusal=%v nodes=%v, want an unknown operation and nothing dispatched", ra.refusal, ra.nodes)
	}
}

// The structural half of invariant 10 for Templates: an adapter can never
// choose a Template's class, because the capability layer refuses one that
// arrives already set rather than trusting it.
func TestResolveAction_RefusesATemplateActionThatArrivesWithAClass(t *testing.T) {
	s := &Service{nodeVocab: staticVocab{"a": {Templates: []nodevocab.Template{mutateTemplate("svc.restart")}}}}
	for _, preset := range []jobs.RiskClass{jobs.RiskClassRead, jobs.RiskClassMutate} {
		act := templateAction("svc.restart", nil)
		act.RiskClass = preset
		ra := s.resolveAction(act, []registry.Node{{NodeID: "a"}})
		var pe *TemplateClassPresetError
		if !errors.As(ra.refusal, &pe) || ra.refusalKind != RefusalInternal {
			t.Errorf("preset %s: refusal = %v, want TemplateClassPresetError/RefusalInternal", jobs.RiskClassName(preset), ra.refusal)
		}
	}
}

func TestResolveAction_ArgumentNamesAreCheckedAgainstTheSlots(t *testing.T) {
	s := &Service{nodeVocab: staticVocab{
		"a": {Templates: []nodevocab.Template{readTemplate("log.tail", "unit")}},
		"b": {Templates: []nodevocab.Template{readTemplate("log.tail", "unit")}},
	}}
	nodes := []registry.Node{{NodeID: "a"}, {NodeID: "b"}}
	tests := []struct {
		name    string
		args    map[string]string
		wantSub string
	}{
		{"misspelled slot (#345)", map[string]string{"unitt": "nginx"}, "unitt"},
		{"missing slot", nil, "unit"},
		{"extra argument", map[string]string{"unit": "nginx", "bogus": "x"}, "bogus"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ra := s.resolveAction(templateAction("log.tail", tt.args), nodes)
			var mal *MalformedCallError
			if !errors.As(ra.refusal, &mal) || ra.refusalKind != RefusalMalformed {
				t.Fatalf("refusal = %v, want MalformedCallError/RefusalMalformed", ra.refusal)
			}
			if !strings.Contains(mal.Error(), tt.wantSub) {
				t.Errorf("error %q must name %q", mal.Error(), tt.wantSub)
			}
		})
	}
	if ra := s.resolveAction(templateAction("log.tail", map[string]string{"unit": "nginx"}), nodes); ra.refusal != nil {
		t.Errorf("a well-formed call was refused: %v", ra.refusal)
	}
}

func TestResolveAction_NodesThatDisagreeAboutSlotsRefuseTheCall(t *testing.T) {
	s := &Service{nodeVocab: staticVocab{
		"a": {Templates: []nodevocab.Template{readTemplate("log.tail", "unit")}},
		"b": {Templates: []nodevocab.Template{readTemplate("log.tail", "unit", "lines")}},
	}}
	ra := s.resolveAction(templateAction("log.tail", map[string]string{"unit": "nginx"}), []registry.Node{{NodeID: "a"}, {NodeID: "b"}})
	var mal *MalformedCallError
	if !errors.As(ra.refusal, &mal) {
		t.Fatalf("refusal = %v, want MalformedCallError for a slot disagreement", ra.refusal)
	}
	if !strings.Contains(mal.Error(), "do not agree") {
		t.Errorf("error %q must say the Nodes disagree", mal.Error())
	}

	// Declaration order is not a disagreement: slots are compared as names.
	s.nodeVocab = staticVocab{
		"a": {Templates: []nodevocab.Template{readTemplate("cp", "src", "dst")}},
		"b": {Templates: []nodevocab.Template{readTemplate("cp", "dst", "src")}},
	}
	if ra := s.resolveAction(templateAction("cp", map[string]string{"src": "x", "dst": "y"}), []registry.Node{{NodeID: "a"}, {NodeID: "b"}}); ra.refusal != nil {
		t.Errorf("same slot names in a different order were refused: %v", ra.refusal)
	}
}

// --- Service.Run ----------------------------------------------------------

func TestRun_TemplateExcludesNonReportingNodesAndNeverSendsThem(t *testing.T) {
	reg := seedNodes(t, 3)
	var log []string
	conduit := connectedConduit(&log, "node-0", "node-1", "node-2")
	capc := &spyCapChecker{}
	vocab := staticVocab{
		"node-0": {Templates: []nodevocab.Template{readTemplate("svc.status", "unit")}},
		"node-1": {Templates: []nodevocab.Template{readTemplate("svc.status", "unit")}},
		"node-2": {Templates: []nodevocab.Template{readTemplate("other")}},
	}
	svc, f := newTemplateTestService(t, reg, conduit, vocab, capc)

	results, err := svc.Run(context.Background(), Principal{Account: "alice"}, webSelector(), templateAction("svc.status", map[string]string{"unit": "nginx"}))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	byNode := map[string]NodeResult{}
	for _, r := range results {
		byNode[r.NodeID] = r
	}
	if len(byNode) != 3 {
		t.Fatalf("results = %+v, want one per matched Node (3)", results)
	}
	for _, n := range []string{"node-0", "node-1"} {
		if byNode[n].Outcome != jobs.OutcomeSuccess {
			t.Errorf("%s outcome = %v, want success", n, byNode[n].Outcome)
		}
	}
	if r := byNode["node-2"]; r.Outcome != jobs.OutcomeUnsupported || string(r.Stderr) != TemplateNotInVocabularyReason {
		t.Errorf("node-2 = %+v, want unsupported with the Relay's reason", r)
	}
	for _, entry := range log {
		if entry == "dispatch:node-2" {
			t.Error("node-2 was dispatched; a Node that does not report the Template is never sent anything")
		}
	}

	// The cap counted only the Nodes actually dispatched, under the resolved class.
	if capc.gotMatched != 2 || capc.gotClass != jobs.RiskClassRead {
		t.Errorf("cap saw (%s, %d), want (read, 2)", jobs.RiskClassName(capc.gotClass), capc.gotMatched)
	}
	// Authorization saw the resolved class, not the adapter's empty one.
	if f.authz.gotAct.RiskClass != jobs.RiskClassRead {
		t.Errorf("authorizer saw class %s, want read", jobs.RiskClassName(f.authz.gotAct.RiskClass))
	}
	// So did the audit trail.
	if f.audit.entry.Kind != AuditKindDispatch || f.audit.entry.Action.RiskClass != jobs.RiskClassRead {
		t.Errorf("audit entry = kind %v class %s, want a dispatch record with class read", f.audit.entry.Kind, jobs.RiskClassName(f.audit.entry.Action.RiskClass))
	}

	// The exclusion is a Task row, so get_job re-reads it like any outcome.
	tasks, err := f.tasks.ByJob(context.Background(), byNode["node-0"].JobID)
	if err != nil {
		t.Fatalf("ByJob: %v", err)
	}
	var sawExcluded bool
	for _, task := range tasks {
		if task.NodeID == "node-2" {
			sawExcluded = true
			if task.Outcome != jobs.OutcomeUnsupported || !task.DispatchedAt.IsZero() {
				t.Errorf("node-2 task = outcome %v dispatchedAt %v, want unsupported and never dispatched", task.Outcome, task.DispatchedAt)
			}
		}
	}
	if len(tasks) != 3 || !sawExcluded {
		t.Errorf("job has %d tasks (excluded present: %v), want 3 including node-2", len(tasks), sawExcluded)
	}
}

func TestRun_TemplateOneMutateReportTakesTheMutateCap(t *testing.T) {
	reg := seedNodes(t, 2)
	var log []string
	conduit := connectedConduit(&log, "node-0", "node-1")
	capc := &spyCapChecker{}
	vocab := staticVocab{
		"node-0": {Templates: []nodevocab.Template{readTemplate("svc.thing")}},
		"node-1": {Templates: []nodevocab.Template{mutateTemplate("svc.thing")}},
	}
	svc, _ := newTemplateTestService(t, reg, conduit, vocab, capc)

	if _, err := svc.Run(context.Background(), Principal{Account: "alice"}, webSelector(), templateAction("svc.thing", nil)); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if capc.gotClass != jobs.RiskClassMutate {
		t.Errorf("cap class = %s, want mutate (one Node reports mutate)", jobs.RiskClassName(capc.gotClass))
	}
}

func TestRun_UnknownTemplateIsRefusedAfterAuthorizationWithNoJob(t *testing.T) {
	reg := seedNodes(t, 2)
	var log []string
	conduit := connectedConduit(&log, "node-0", "node-1")
	vocab := staticVocab{"node-0": {}, "node-1": {}}

	// A caller who may not ask is told "unauthorized", never "unknown
	// operation": the vocabulary is not disclosed before authorization.
	svc, f := newTemplateTestService(t, reg, conduit, vocab, &spyCapChecker{})
	authzErr := errors.New("denied for test")
	f.authz.err = authzErr
	_, err := svc.Run(context.Background(), Principal{Account: "mallory"}, webSelector(), templateAction("nope.notreal", nil))
	var unk *UnknownOperationError
	if !errors.Is(err, authzErr) || errors.As(err, &unk) {
		t.Fatalf("unauthorized Run err = %v, want the authorization refusal and not an unknown operation", err)
	}

	svc, f = newTemplateTestService(t, reg, conduit, vocab, &spyCapChecker{})
	_, err = svc.Run(context.Background(), Principal{Account: "alice"}, webSelector(), templateAction("nope.notreal", nil))
	if !errors.As(err, &unk) {
		t.Fatalf("Run err = %v, want UnknownOperationError", err)
	}
	if f.audit.entry.Kind != AuditKindRefusal || !strings.Contains(f.audit.entry.Reason, "unknown operation") {
		t.Errorf("audit = %+v, want a refusal record naming the unknown operation", f.audit.entry)
	}
	if got := f.metrics.refusals; len(got) != 1 || got[0] != RefusalUnknownOperation {
		t.Errorf("refusal metrics = %v, want [RefusalUnknownOperation]", got)
	}
	for _, entry := range log {
		if strings.HasPrefix(entry, "dispatch:") {
			t.Errorf("an unknown operation dispatched: %s", entry)
		}
	}
}

func TestRun_ZeroMatchStillReportsNoNodesMatchedForATemplate(t *testing.T) {
	reg := seedNodes(t, 1)
	var log []string
	svc, _ := newTemplateTestService(t, reg, connectedConduit(&log), staticVocab{}, &spyCapChecker{})
	sel := Selector{Predicates: []Predicate{{Namespace: NamespaceNode, Key: "role", Value: "db"}}}
	_, err := svc.Run(context.Background(), Principal{Account: "alice"}, sel, templateAction("svc.status", nil))
	var nnm *NoNodesMatchedError
	if !errors.As(err, &nnm) {
		t.Fatalf("err = %v, want NoNodesMatchedError ahead of any Template refusal", err)
	}
}

func TestRun_MalformedTemplateCallIsRefusedBeforeDispatch(t *testing.T) {
	reg := seedNodes(t, 1)
	var log []string
	vocab := staticVocab{"node-0": {Templates: []nodevocab.Template{readTemplate("log.tail", "unit")}}}
	svc, f := newTemplateTestService(t, reg, connectedConduit(&log, "node-0"), vocab, &spyCapChecker{})

	_, err := svc.Run(context.Background(), Principal{Account: "alice"}, webSelector(), templateAction("log.tail", map[string]string{"unitt": "nginx"}))
	var mal *MalformedCallError
	if !errors.As(err, &mal) {
		t.Fatalf("err = %v, want MalformedCallError", err)
	}
	if got := f.metrics.refusals; len(got) != 1 || got[0] != RefusalMalformed {
		t.Errorf("refusal metrics = %v, want [RefusalMalformed]", got)
	}
	if len(log) != 0 {
		t.Errorf("conduit log = %v, want nothing dispatched or queried", log)
	}
}

// --- Service.Plan (Policy preflight) --------------------------------------

// TestPreflightTemplateExclusionNeverDecidesAVerdict proves amended PF-7 and
// PF-11 (ADR-0042) for a Template: the cached vocabulary decides which Nodes
// are excluded — they read unsupported with the Relay's reason and are never
// queried — while every queried Node's allow, deny or unsupported is the
// daemon's own answer, even where the cache says otherwise. The Policy view
// is never read at all.
func TestPreflightTemplateExclusionNeverDecidesAVerdict(t *testing.T) {
	reg := seedNodes(t, 4)
	var log []string
	conduit := connectedConduit(&log, "node-0", "node-1", "node-2", "node-3")
	conduit.verdicts["node-1"] = jobs.Verdict{Allowed: false, DecidingRule: "deny-from-daemon"}
	conduit.verdicts["node-2"] = jobs.Verdict{Unsupported: true, DecidingRule: "daemon says not in vocabulary"}

	vocab := &countingVocab{staticVocab: staticVocab{
		"node-0": {Templates: []nodevocab.Template{readTemplate("svc.status")}},
		"node-1": {Templates: []nodevocab.Template{readTemplate("svc.status")}},
		"node-2": {Templates: []nodevocab.Template{readTemplate("svc.status")}}, // stale: the daemon disagrees
		"node-3": {Templates: []nodevocab.Template{readTemplate("other")}},
	}}
	pv := &recordingPolicyView{snap: policyview.Snapshot{PolicyFingerprint: "cache-says-nothing-is-allowed"}}

	jobsRepo, tasksRepo := testEngineStore(t)
	svc := New(reg,
		WithAuthorizer(&spyAuthorizer{}),
		WithCapChecker(&spyCapChecker{}),
		WithAuditSink(&spyAuditSink{}),
		WithFreeze(&fakeFreezeStore{}),
		WithExecution(jobsRepo, tasksRepo, conduit),
		WithPolicyView(pv),
		WithTemplateVocabulary(vocab),
	)

	pr, err := svc.Plan(context.Background(), Principal{Account: "alice"}, webSelector(), templateAction("svc.status", nil))
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	got := map[string]NodeVerdict{}
	for _, v := range pr.Verdicts {
		got[v.NodeID] = v
	}
	if v := got["node-0"]; v.Status != VerdictAllow {
		t.Errorf("node-0 = %+v, want the daemon's allow", v)
	}
	if v := got["node-1"]; v.Status != VerdictDeny || v.DecidingRule != "deny-from-daemon" {
		t.Errorf("node-1 = %+v, want the daemon's deny and rule", v)
	}
	if v := got["node-2"]; v.Status != VerdictUnsupported || v.DecidingRule != "daemon says not in vocabulary" {
		t.Errorf("node-2 = %+v, want the daemon's own unsupported despite the cache listing the Template", v)
	}
	if v := got["node-3"]; v.Status != VerdictUnsupported || v.DecidingRule != TemplateNotInVocabularyReason {
		t.Errorf("node-3 = %+v, want the Relay's exclusion with the same reason a run records", v)
	}
	for _, entry := range log {
		if entry == "query:node-3" {
			t.Error("node-3 was queried; an excluded Node is never asked")
		}
	}
	if pr.Matched != 4 {
		t.Errorf("Matched = %d, want 4", pr.Matched)
	}
	if len(pv.gets) != 0 {
		t.Errorf("policyView.gets = %v during a preflight, want none — the Policy view never decides a verdict", pv.gets)
	}
	if len(vocab.gets) == 0 {
		t.Error("the vocabulary was never read — the exclusion above could not have come from it, so this test proves nothing")
	}
}

func TestPreflightRefusesAnUnknownTemplate(t *testing.T) {
	reg := seedNodes(t, 1)
	var log []string
	svc, _ := newTemplateTestService(t, reg, connectedConduit(&log, "node-0"), staticVocab{"node-0": {}}, &spyCapChecker{})
	_, err := svc.Plan(context.Background(), Principal{Account: "alice"}, webSelector(), templateAction("nope.notreal", nil))
	var unk *UnknownOperationError
	if !errors.As(err, &unk) {
		t.Fatalf("Plan err = %v, want UnknownOperationError", err)
	}
	if len(log) != 0 {
		t.Errorf("conduit log = %v, want no Node queried", log)
	}
}
