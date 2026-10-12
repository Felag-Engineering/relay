package capability

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/approval"
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
	svc     *testSvc
	audit   *spyAuditSink
	authz   *capturingAuthorizer
	tasks   jobs.TaskRepository
	metrics *recordingMetrics
}

// newTemplateTestService wires a real jobEngine and a real SQLite store
// behind a Service with the given vocabulary source and cap checker.
func newTemplateTestService(t *testing.T, reg registry.Repository, conduit *fakeConduit, vocab TemplateVocabularySource, capc CapChecker) (*testSvc, *templateFixture) {
	t.Helper()
	jobsRepo, tasksRepo := testEngineStore(t)
	f := &templateFixture{audit: &spyAuditSink{}, authz: &capturingAuthorizer{}, tasks: tasksRepo, metrics: &recordingMetrics{}}
	f.svc = build(t, seams{
		reg:       reg,
		authz:     f.authz,
		cap:       capc,
		audit:     f.audit,
		freeze:    &fakeFreezeStore{},
		metrics:   f.metrics,
		jobsRepo:  jobsRepo,
		tasksRepo: tasksRepo,
		conduit:   conduit,
		nodeVocab: vocab,
	})
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

func TestResolveAction_NativeAndRawExecTakeTheirFixedClass(t *testing.T) {
	s := buildRaw(t, seams{nodeVocab: staticVocab{}})
	nodes := []registry.Node{{NodeID: "node-0"}, {NodeID: "node-1"}}
	tests := []struct {
		act  jobs.Action
		want jobs.RiskClass
	}{
		{jobs.Action{Kind: jobs.ActionOperation, OperationName: "service.restart", OperationArgs: map[string]string{"unit": "nginx"}}, jobs.RiskClassMutate},
		{jobs.Action{Kind: jobs.ActionOperation, OperationName: "system.facts"}, jobs.RiskClassRead},
		{jobs.Action{Kind: jobs.ActionRawExec, RawExecArgv: []string{"/bin/true"}}, jobs.RiskClassMutate},
	}
	for _, tt := range tests {
		ra := s.resolveAction(tt.act, nodes)
		want := tt.act
		want.RiskClass = tt.want
		if ra.refusal != nil || !reflect.DeepEqual(ra.act, want) || len(ra.nodes) != 2 || len(ra.excluded) != 0 {
			t.Errorf("resolveAction(%+v) = %+v, want the Action with class %q and every Node unchanged",
				tt.act, ra, jobs.RiskClassName(tt.want))
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
			s := buildRaw(t, seams{nodeVocab: tt.vocab})
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
	s := buildRaw(t, seams{nodeVocab: staticVocab{
		"has":   {Templates: []nodevocab.Template{readTemplate("svc.status")}},
		"lacks": {Templates: []nodevocab.Template{readTemplate("other")}},
		"empty": {},
		// "silent" is deliberately absent: no report at all.
	}})
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
	s := buildRaw(t, seams{nodeVocab: staticVocab{"a": {}}})
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
	s := buildRaw(t, seams{})
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
	s := buildRaw(t, seams{nodeVocab: staticVocab{"a": {Templates: []nodevocab.Template{mutateTemplate("svc.restart")}}}})
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
	s := buildRaw(t, seams{nodeVocab: staticVocab{
		"a": {Templates: []nodevocab.Template{readTemplate("log.tail", "unit")}},
		"b": {Templates: []nodevocab.Template{readTemplate("log.tail", "unit")}},
	}})
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
	s := buildRaw(t, seams{nodeVocab: staticVocab{
		"a": {Templates: []nodevocab.Template{readTemplate("log.tail", "unit")}},
		"b": {Templates: []nodevocab.Template{readTemplate("log.tail", "unit", "lines")}},
	}})
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
	svc := build(t, seams{reg: reg,
		authz:    &spyAuthorizer{},
		cap:      &spyCapChecker{},
		audit:    &spyAuditSink{},
		freeze:   &fakeFreezeStore{},
		jobsRepo: jobsRepo, tasksRepo: tasksRepo, conduit: conduit,
		policyView: pv,
		nodeVocab:  vocab,
	})

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

// --- Review fixes: per-Node class, stale reports, ordering, approval -------

// Each Task is recorded under its OWN Node's reported class, while the cap
// sees the dispatch's most-restrictive one — so retention (ADR-0025) follows
// the Node that produced the output.
func TestRun_TemplateTasksRecordTheirOwnNodesClass(t *testing.T) {
	reg := seedNodes(t, 2)
	var log []string
	capc := &spyCapChecker{}
	vocab := staticVocab{
		"node-0": {Templates: []nodevocab.Template{readTemplate("proc.list")}},
		"node-1": {Templates: []nodevocab.Template{mutateTemplate("proc.list")}},
	}
	svc, f := newTemplateTestService(t, reg, connectedConduit(&log, "node-0", "node-1"), vocab, capc)

	results, err := svc.Run(context.Background(), Principal{Account: "alice"}, webSelector(), templateAction("proc.list", nil))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if capc.gotClass != jobs.RiskClassMutate {
		t.Errorf("cap class = %s, want mutate (most restrictive)", jobs.RiskClassName(capc.gotClass))
	}
	want := map[string]jobs.RiskClass{"node-0": jobs.RiskClassRead, "node-1": jobs.RiskClassMutate}
	for _, r := range results {
		if r.RiskClass != want[r.NodeID] {
			t.Errorf("result %s class = %s, want %s", r.NodeID, jobs.RiskClassName(r.RiskClass), jobs.RiskClassName(want[r.NodeID]))
		}
	}
	tasks, err := f.tasks.ByJob(context.Background(), results[0].JobID)
	if err != nil {
		t.Fatalf("ByJob: %v", err)
	}
	for _, task := range tasks {
		if task.Action.RiskClass != want[task.NodeID] {
			t.Errorf("task %s recorded class %s, want its own Node's %s", task.NodeID, jobs.RiskClassName(task.Action.RiskClass), jobs.RiskClassName(want[task.NodeID]))
		}
	}
}

// A cached report whose fingerprint differs from the Node's latest Hello is
// from before a daemon restart; until the new report lands it counts as no
// report, so a Template whose class changed across the restart cannot be
// dispatched under the old one.
func TestResolveAction_StaleReportCountsAsNotReported(t *testing.T) {
	s := buildRaw(t, seams{nodeVocab: staticVocab{
		"fresh": {Fingerprint: "fp-new", Templates: []nodevocab.Template{readTemplate("svc.status")}},
		"stale": {Fingerprint: "fp-old", Templates: []nodevocab.Template{readTemplate("svc.status")}},
	}})
	nodes := []registry.Node{
		{NodeID: "fresh", TemplateSetFingerprint: "fp-new"},
		{NodeID: "stale", TemplateSetFingerprint: "fp-new"},
	}
	ra := s.resolveAction(templateAction("svc.status", nil), nodes)
	if len(ra.nodes) != 1 || ra.nodes[0].NodeID != "fresh" {
		t.Fatalf("dispatched = %v, want only [fresh]", ra.nodes)
	}
	if len(ra.excluded) != 1 || ra.excluded[0].reason != TemplateNotReportedReason {
		t.Errorf("excluded = %+v, want the stale Node excluded as not reported", ra.excluded)
	}
}

// orderCheckingConduit fails the test if any excluded Task is still Pending
// when the first real Task is dispatched.
type orderCheckingConduit struct {
	*fakeConduit
	t        *testing.T
	tasks    jobs.TaskRepository
	excluded string
}

func (c *orderCheckingConduit) Dispatch(ctx context.Context, nodeID string, task jobs.Task) (jobs.Result, error) {
	all, err := c.tasks.ByJob(ctx, task.JobID)
	if err != nil {
		c.t.Errorf("ByJob during dispatch: %v", err)
	}
	for _, other := range all {
		if other.NodeID == c.excluded && other.State != jobs.DispatchStateResolved {
			c.t.Errorf("excluded Task for %s was %v when %s was dispatched; it must be resolved first", c.excluded, other.State, nodeID)
		}
	}
	return c.fakeConduit.Dispatch(ctx, nodeID, task)
}

func TestRun_ExcludedTasksAreResolvedBeforeAnyDispatch(t *testing.T) {
	reg := seedNodes(t, 2)
	var log []string
	jobsRepo, tasksRepo := testEngineStore(t)
	conduit := &orderCheckingConduit{fakeConduit: connectedConduit(&log, "node-0", "node-1"), t: t, tasks: tasksRepo, excluded: "node-1"}
	svc := build(t, seams{reg: reg,
		authz:    &spyAuthorizer{},
		cap:      &spyCapChecker{},
		audit:    &spyAuditSink{},
		freeze:   &fakeFreezeStore{},
		jobsRepo: jobsRepo, tasksRepo: tasksRepo, conduit: conduit,
		nodeVocab: staticVocab{"node-0": {Templates: []nodevocab.Template{readTemplate("svc.status")}}},
	})
	if _, err := svc.Run(context.Background(), Principal{Account: "alice"}, webSelector(), templateAction("svc.status", nil)); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(log) != 1 || log[0] != "dispatch:node-0" {
		t.Errorf("conduit log = %v, want exactly one dispatch to node-0", log)
	}
}

// templateApprovalFixture is approvalFixture with a Template vocabulary wired.
func templateApprovalFixture(t *testing.T, nodes []string, vocab TemplateVocabularySource, gate ApprovalGate, store ApprovalStore) (*testSvc, *spyDispatcher) {
	t.Helper()
	reg := registry.NewInMemory()
	for _, id := range nodes {
		if _, err := reg.Upsert(registry.Report{NodeID: id}); err != nil {
			t.Fatalf("seed registry: %v", err)
		}
	}
	disp := &spyDispatcher{jobID: "job-1"}
	s := build(t, seams{reg: reg,
		authz:  &spyAuthorizer{},
		cap:    &spyCapChecker{},
		audit:  &spyAuditSink{},
		freeze: &fakeFreezeStore{},
		gate:   gate, approvals: store, approvalAuthz: &spyApprovalAuthorizer{},
		nodeVocab: vocab,
		now:       func() time.Time { return apNow },
	})
	s.disp = disp
	return s, disp
}

// A mutate-keyed approval rule sees the RESOLVED class: an all-read Template
// dispatch is not gated, and the same dispatch parks as soon as one Node
// reports the Template mutate.
func TestRun_TemplateApprovalGateMatchesTheResolvedClass(t *testing.T) {
	gate, err := approval.NewGate([]approval.Rule{{
		Name:    "mutates-need-a-human",
		Match:   approval.Match{RiskClass: jobs.RiskClassMutate},
		Require: approval.Requirement{Count: 1, RequesterAllowed: true, Channel: approval.ChannelOutOfBand, TTL: time.Hour},
	}})
	if err != nil {
		t.Fatalf("NewGate: %v", err)
	}
	vocab := staticVocab{
		"node-a": {Templates: []nodevocab.Template{readTemplate("svc.thing")}},
		"node-b": {Templates: []nodevocab.Template{readTemplate("svc.thing")}},
	}
	s, disp := templateApprovalFixture(t, []string{"node-a", "node-b"}, vocab, gate, newMemApprovals())
	if _, err := s.Run(context.Background(), machineRequester, Selector{}, templateAction("svc.thing", nil)); err != nil {
		t.Fatalf("all-read Run: %v, want it to proceed ungated", err)
	}
	if !disp.called {
		t.Fatal("all-read Template dispatch did not reach the dispatcher")
	}

	vocab["node-b"] = nodevocab.Snapshot{Templates: []nodevocab.Template{mutateTemplate("svc.thing")}}
	disp.called = false
	_, err = s.Run(context.Background(), machineRequester, Selector{}, templateAction("svc.thing", nil))
	var parked *ParkedError
	if !errors.As(err, &parked) {
		t.Fatalf("mixed Run err = %v, want a park under the mutate rule", err)
	}
	if disp.called {
		t.Error("a parked dispatch reached the dispatcher")
	}
}

// An approval binds the resolved class and the Nodes that report the
// Template. If either changes before the re-drive, the plan hash differs and
// the dispatch parks again rather than releasing against an approval that
// described something else (ADR-0027's drift rule, ADR-0042).
func TestRun_TemplateApprovalReparksWhenTheReportingSetChanges(t *testing.T) {
	store := newMemApprovals()
	vocab := staticVocab{
		"node-a": {Templates: []nodevocab.Template{mutateTemplate("svc.restart")}},
		"node-b": {Templates: []nodevocab.Template{mutateTemplate("svc.restart")}},
	}
	s, disp := templateApprovalFixture(t, []string{"node-a", "node-b", "node-c"}, vocab, gateEverything(t, 1), store)

	_, err := s.Run(context.Background(), machineRequester, Selector{}, templateAction("svc.restart", nil))
	var first *ParkedError
	if !errors.As(err, &first) {
		t.Fatalf("first Run err = %v, want a park", err)
	}
	store.approve(t, first.RequestID, "acct-ana", "ana", apNow)

	// node-c starts reporting the Template: the remaining set changed.
	vocab["node-c"] = nodevocab.Snapshot{Templates: []nodevocab.Template{mutateTemplate("svc.restart")}}
	_, err = s.Run(context.Background(), machineRequester, Selector{}, templateAction("svc.restart", nil))
	var second *ParkedError
	if !errors.As(err, &second) || second.PlanHash == first.PlanHash {
		t.Fatalf("Run after the reporting set grew: err = %v, want a fresh park with a different plan hash", err)
	}
	if disp.called {
		t.Fatal("an approval for two Nodes released a dispatch to three")
	}

	// Back to the approved set: it releases.
	delete(vocab, "node-c")
	if _, err := s.Run(context.Background(), machineRequester, Selector{}, templateAction("svc.restart", nil)); err != nil {
		t.Fatalf("re-drive of the approved plan: %v", err)
	}
	if !disp.called {
		t.Error("the approved plan did not release")
	}
}

// --- Code-review gaps -------------------------------------------------------

// The class half of the drift rule: an approval given while every Node
// reported read does not release the dispatch once one Node reports mutate.
func TestRun_TemplateApprovalReparksWhenAReportedClassChanges(t *testing.T) {
	store := newMemApprovals()
	vocab := staticVocab{
		"node-a": {Templates: []nodevocab.Template{readTemplate("svc.thing")}},
		"node-b": {Templates: []nodevocab.Template{readTemplate("svc.thing")}},
	}
	s, disp := templateApprovalFixture(t, []string{"node-a", "node-b"}, vocab, gateEverything(t, 1), store)

	_, err := s.Run(context.Background(), machineRequester, Selector{}, templateAction("svc.thing", nil))
	var first *ParkedError
	if !errors.As(err, &first) {
		t.Fatalf("first Run err = %v, want a park", err)
	}
	store.approve(t, first.RequestID, "acct-ana", "ana", apNow)

	vocab["node-b"] = nodevocab.Snapshot{Templates: []nodevocab.Template{mutateTemplate("svc.thing")}}
	_, err = s.Run(context.Background(), machineRequester, Selector{}, templateAction("svc.thing", nil))
	var second *ParkedError
	if !errors.As(err, &second) || second.PlanHash == first.PlanHash {
		t.Fatalf("Run after node-b flipped to mutate: err = %v, want a fresh park with a different plan hash", err)
	}
	if disp.called {
		t.Fatal("an approval given under read released a dispatch that resolved to mutate")
	}
}

// A malformed Template call from a caller who may not ask is refused as
// unauthorized: its slots are not disclosed before authorization.
func TestRun_MalformedTemplateFromUnauthorizedCallerIsUnauthorized(t *testing.T) {
	reg := seedNodes(t, 1)
	var log []string
	vocab := staticVocab{"node-0": {Templates: []nodevocab.Template{readTemplate("log.tail", "unit")}}}
	svc, f := newTemplateTestService(t, reg, connectedConduit(&log, "node-0"), vocab, &spyCapChecker{})
	authzErr := errors.New("denied for test")
	f.authz.err = authzErr

	_, err := svc.Run(context.Background(), Principal{Account: "mallory"}, webSelector(), templateAction("log.tail", map[string]string{"unitt": "x"}))
	var mal *MalformedCallError
	if !errors.Is(err, authzErr) || errors.As(err, &mal) {
		t.Fatalf("err = %v, want the authorization refusal and not a malformed-call one", err)
	}
}

// A preflight's cap check counts only the Nodes a run would dispatch.
func TestPlan_TemplateCapCountsTheRemainingNodes(t *testing.T) {
	reg := seedNodes(t, 3)
	var log []string
	capc := &spyCapChecker{}
	vocab := staticVocab{
		"node-0": {Templates: []nodevocab.Template{readTemplate("svc.status")}},
		"node-1": {Templates: []nodevocab.Template{readTemplate("svc.status")}},
		"node-2": {},
	}
	svc, _ := newTemplateTestService(t, reg, connectedConduit(&log, "node-0", "node-1", "node-2"), vocab, capc)
	pr, err := svc.Plan(context.Background(), Principal{Account: "alice"}, webSelector(), templateAction("svc.status", nil))
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	if capc.gotMatched != 2 || capc.gotClass != jobs.RiskClassRead {
		t.Errorf("cap saw (%s, %d), want (read, 2)", jobs.RiskClassName(capc.gotClass), capc.gotMatched)
	}
	if pr.Matched != 3 {
		t.Errorf("Matched = %d, want all 3 matched Nodes reported", pr.Matched)
	}
}

// A Template preflight whose Selector matches nothing reports NoNodesMatched
// (PF-5), never an unknown operation.
func TestPlan_TemplateZeroMatchReportsNoNodesMatched(t *testing.T) {
	reg := seedNodes(t, 1)
	var log []string
	svc, _ := newTemplateTestService(t, reg, connectedConduit(&log), staticVocab{}, &spyCapChecker{})
	sel := Selector{Predicates: []Predicate{{Namespace: NamespaceNode, Key: "role", Value: "db"}}}
	pr, err := svc.Plan(context.Background(), Principal{Account: "alice"}, sel, templateAction("svc.status", nil))
	if err != nil {
		t.Fatalf("Plan err = %v, want NoNodesMatched reported as data", err)
	}
	if !pr.NoNodesMatched {
		t.Error("NoNodesMatched = false, want true")
	}
}

// Exclusion takes precedence over the version gate: an outdated Node that
// does not report the Template reads unsupported, not version_refused — it
// was never a dispatch target at all.
func TestRun_ExclusionTakesPrecedenceOverTheVersionGate(t *testing.T) {
	reg := registry.NewInMemory(registry.WithMinDaemonVersion("1.2.0"))
	for id, version := range map[string]string{"node-new": "1.2.0", "node-old": "1.0.0"} {
		if _, err := reg.Upsert(registry.Report{NodeID: id, DaemonVersion: version}.WithNodeLabels(map[string]string{"role": "web"})); err != nil {
			t.Fatalf("Upsert(%s): %v", id, err)
		}
	}
	var log []string
	vocab := staticVocab{"node-new": {Templates: []nodevocab.Template{readTemplate("svc.status")}}}
	svc, _ := newTemplateTestService(t, reg, connectedConduit(&log, "node-new", "node-old"), vocab, &spyCapChecker{})

	results, err := svc.Run(context.Background(), Principal{Account: "alice"}, webSelector(), templateAction("svc.status", nil))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	for _, r := range results {
		if r.NodeID == "node-old" && r.Outcome != jobs.OutcomeUnsupported {
			t.Errorf("node-old outcome = %v, want unsupported", r.Outcome)
		}
	}
}

// JobEvent counts every matched Node, excluded ones included: the Job has a
// Task for each.
func TestRun_TemplateJobEventsCountExcludedNodes(t *testing.T) {
	reg := seedNodes(t, 3)
	var log []string
	events := &spyJobEventSink{}
	jobsRepo, tasksRepo := testEngineStore(t)
	svc := build(t, seams{reg: reg,
		authz:    &spyAuthorizer{},
		cap:      &spyCapChecker{},
		audit:    &spyAuditSink{},
		freeze:   &fakeFreezeStore{},
		jobsRepo: jobsRepo, tasksRepo: tasksRepo, conduit: connectedConduit(&log, "node-0", "node-1", "node-2"),
		jobEvents: events,
		nodeVocab: staticVocab{"node-0": {Templates: []nodevocab.Template{readTemplate("svc.status")}}},
	})
	if _, err := svc.Run(context.Background(), Principal{Account: "alice"}, webSelector(), templateAction("svc.status", nil)); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(events.events) != 2 {
		t.Fatalf("job events = %d, want created + completed", len(events.events))
	}
	for _, ev := range events.events {
		if ev.Nodes != 3 {
			t.Errorf("%v event Nodes = %d, want 3 (one dispatched, two excluded)", ev.Transition, ev.Nodes)
		}
	}
	if got := events.events[1].Outcomes[jobs.OutcomeUnsupported]; got != 2 {
		t.Errorf("completed event counts %d unsupported, want 2", got)
	}
}
