package capability

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/jobs"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/registry"
)

// spyAuthorizer records whether it was called and returns a fixed error.
type spyAuthorizer struct {
	called bool
	err    error
}

func (s *spyAuthorizer) Authorize(context.Context, Principal, jobs.Action, Selector) error {
	s.called = true
	return s.err
}

// spyCapChecker records the arguments it was called with and returns a fixed error.
type spyCapChecker struct {
	called     bool
	gotClass   jobs.RiskClass
	gotMatched int
	err        error
}

func (s *spyCapChecker) Check(class jobs.RiskClass, matched int) error {
	s.called = true
	s.gotClass = class
	s.gotMatched = matched
	return s.err
}

// spyDispatcher records whether run was called and returns fixed results.
// It implements the unexported dispatcher interface, which only a file
// inside package capability can do — exactly the seal this test exploits to
// prove the pipeline's short-circuiting.
type spyDispatcher struct {
	called  bool
	jobID   string
	results []NodeResult
	err     error

	// cancelledJobID and cancelErr let the task-handle tests (#374) assert that
	// cancelling a task goes through the ORDINARY cancel path, and that a
	// failed cancel is reported rather than papered over.
	cancelledJobID string
	cancelErr      error
}

func (s *spyDispatcher) run(context.Context, dispatch) (dispatchResult, error) {
	s.called = true
	return dispatchResult{jobID: s.jobID, results: s.results}, s.err
}

// cancel satisfies the dispatcher interface's cancel method, recording the Job
// it was asked to cancel so a caller's delegation can be asserted.
func (s *spyDispatcher) cancel(_ context.Context, jobID string) error {
	if s.cancelErr != nil {
		return s.cancelErr
	}
	s.cancelledJobID = jobID
	return nil
}

// query satisfies the dispatcher interface's query method (#119); no test in
// this file exercises Plan, so it is a no-op returning no verdicts.
func (s *spyDispatcher) query(context.Context, dispatch) (planResult, error) {
	return planResult{}, nil
}

// spyAuditSink records the last AuditEntry/FreezeEvent it received.
type spyAuditSink struct {
	called bool
	entry  AuditEntry
	// entries accumulates every recorded AuditEntry. entry (the last one) is
	// kept for the tests that predate it; the approval decision tests need the
	// whole sequence, because a park and its decision are two entries from one
	// exchange and asserting on only the last would hide either.
	entries     []AuditEntry
	err         error
	freezeCalls []FreezeEvent
	cancelCalls []cancelCall
}

// cancelCall records one RecordCancel invocation's arguments.
type cancelCall struct {
	Principal Principal
	JobID     string
}

func (s *spyAuditSink) Record(_ context.Context, e AuditEntry) error {
	s.called = true
	s.entry = e
	s.entries = append(s.entries, e)
	return s.err
}

func (s *spyAuditSink) RecordFreeze(_ context.Context, e FreezeEvent) error {
	s.freezeCalls = append(s.freezeCalls, e)
	return s.err
}

func (s *spyAuditSink) RecordCancel(_ context.Context, p Principal, jobID string) error {
	s.cancelCalls = append(s.cancelCalls, cancelCall{Principal: p, JobID: jobID})
	return s.err
}

func seedOneNode(t *testing.T) registry.Repository {
	t.Helper()
	reg := registry.NewInMemory()
	if _, err := reg.Upsert(registry.Report{
		NodeID:     "node-1",
		NodeLabels: map[string]string{"role": "web"},
	}); err != nil {
		t.Fatalf("Upsert(node-1): %v", err)
	}
	return reg
}

func TestRunAuthorizeDeniedShortCircuits(t *testing.T) {
	reg := seedOneNode(t)
	authz := &spyAuthorizer{err: errors.New("denied")}
	capChecker := &spyCapChecker{}
	disp := &spyDispatcher{}
	audit := &spyAuditSink{}
	svc := &Service{reg: reg, authz: authz, cap: capChecker, disp: disp, audit: audit, freeze: noopFreezeStore{}, metrics: noopMetricsSink{}}

	sel := Selector{Predicates: []Predicate{{Namespace: NamespaceNode, Key: "role", Value: "web"}}}
	_, err := svc.Run(context.Background(), Principal{Account: "alice"}, sel, jobs.Action{RiskClass: jobs.RiskClassRead})
	if err == nil {
		t.Fatal("Run() with a denying Authorizer should return an error")
	}
	if !authz.called {
		t.Error("Authorizer was not called")
	}
	if capChecker.called {
		t.Error("CapChecker must not be called when Authorize fails")
	}
	if disp.called {
		t.Error("dispatcher must not be called when Authorize fails")
	}
	if !audit.called {
		t.Error("AuditSink must be called when Authorize fails — refusals are audited")
	}
	if audit.entry.Kind != AuditKindRefusal {
		t.Errorf("AuditEntry.Kind = %v, want AuditKindRefusal", audit.entry.Kind)
	}
	if audit.entry.Reason == "" {
		t.Error("AuditEntry.Reason is empty, want the Authorize error's message")
	}
}

func TestRunCapCheckDeniedShortCircuits(t *testing.T) {
	reg := seedOneNode(t)
	authz := &spyAuthorizer{}
	capChecker := &spyCapChecker{err: errors.New("blast radius exceeded")}
	disp := &spyDispatcher{}
	audit := &spyAuditSink{}
	svc := &Service{reg: reg, authz: authz, cap: capChecker, disp: disp, audit: audit, freeze: noopFreezeStore{}, metrics: noopMetricsSink{}}

	sel := Selector{Predicates: []Predicate{{Namespace: NamespaceNode, Key: "role", Value: "web"}}}
	act := jobs.Action{RiskClass: jobs.RiskClassMutate}
	_, err := svc.Run(context.Background(), Principal{Account: "alice"}, sel, act)
	if err == nil {
		t.Fatal("Run() with a rejecting CapChecker should return an error")
	}
	if !capChecker.called {
		t.Error("CapChecker was not called")
	}
	if capChecker.gotClass != jobs.RiskClassMutate {
		t.Errorf("CapChecker.Check got class %v, want RiskClassMutate", capChecker.gotClass)
	}
	if capChecker.gotMatched != 1 {
		t.Errorf("CapChecker.Check got matched=%d, want 1", capChecker.gotMatched)
	}
	if disp.called {
		t.Error("dispatcher must not be called when the cap check fails")
	}
	if !audit.called {
		t.Error("AuditSink must be called when the cap check fails — refusals are audited")
	}
	if audit.entry.Kind != AuditKindRefusal {
		t.Errorf("AuditEntry.Kind = %v, want AuditKindRefusal", audit.entry.Kind)
	}
	if audit.entry.Reason == "" {
		t.Error("AuditEntry.Reason is empty, want the CapChecker error's message")
	}
}

func TestRunThreadsPrincipalToAudit(t *testing.T) {
	reg := seedOneNode(t)
	authz := &spyAuthorizer{}
	capChecker := &spyCapChecker{}
	wantResults := []NodeResult{{NodeID: "node-1", Outcome: jobs.OutcomeSuccess}}
	disp := &spyDispatcher{jobID: "job-1", results: wantResults}
	audit := &spyAuditSink{}
	svc := &Service{reg: reg, authz: authz, cap: capChecker, disp: disp, audit: audit, freeze: noopFreezeStore{}, metrics: noopMetricsSink{}}

	principal := Principal{Account: "alice", Role: "operator"}
	sel := Selector{Predicates: []Predicate{{Namespace: NamespaceNode, Key: "role", Value: "web"}}}
	act := jobs.Action{Kind: jobs.ActionOperation, OperationName: "service.restart", RiskClass: jobs.RiskClassMutate}

	results, err := svc.Run(context.Background(), principal, sel, act)
	if err != nil {
		t.Fatalf("Run() returned unexpected error: %v", err)
	}
	if len(results) != 1 || !reflect.DeepEqual(results[0], wantResults[0]) {
		t.Errorf("Run() results = %+v, want %+v", results, wantResults)
	}

	if !audit.called {
		t.Fatal("AuditSink was not called")
	}
	if audit.entry.Kind != AuditKindDispatch {
		t.Errorf("AuditEntry.Kind = %v, want AuditKindDispatch", audit.entry.Kind)
	}
	if audit.entry.JobID != "job-1" {
		t.Errorf("AuditEntry.JobID = %q, want %q (threaded from the dispatcher)", audit.entry.JobID, "job-1")
	}
	if audit.entry.Principal != principal {
		t.Errorf("AuditEntry.Principal = %+v, want %+v", audit.entry.Principal, principal)
	}
	if audit.entry.Selector.Predicates[0] != sel.Predicates[0] {
		t.Errorf("AuditEntry.Selector = %+v, want %+v", audit.entry.Selector, sel)
	}
	if !reflect.DeepEqual(audit.entry.Action, act) {
		t.Errorf("AuditEntry.Action = %+v, want %+v", audit.entry.Action, act)
	}
	if len(audit.entry.Results) != 1 || !reflect.DeepEqual(audit.entry.Results[0], wantResults[0]) {
		t.Errorf("AuditEntry.Results = %+v, want %+v", audit.entry.Results, wantResults)
	}
}

func TestRunHappyPathDefaultsToNoopDispatcher(t *testing.T) {
	reg := seedOneNode(t)
	svc := New(reg)

	sel := Selector{Predicates: []Predicate{{Namespace: NamespaceNode, Key: "role", Value: "web"}}}
	results, err := svc.Run(context.Background(), Principal{Account: "alice"}, sel, jobs.Action{RiskClass: jobs.RiskClassRead})
	if err != nil {
		t.Fatalf("Run() with default seams returned unexpected error: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("Run() returned %d results, want 1", len(results))
	}
	if results[0].NodeID != "node-1" {
		t.Errorf("results[0].NodeID = %q, want node-1", results[0].NodeID)
	}
	if results[0].Outcome != jobs.OutcomeUnspecified {
		t.Errorf("results[0].Outcome = %v, want OutcomeUnspecified (noopDispatcher performs no execution)", results[0].Outcome)
	}
}

func TestRunAuditsPartialResultsOnDispatchError(t *testing.T) {
	reg := seedOneNode(t)
	authz := &spyAuthorizer{}
	capChecker := &spyCapChecker{}
	partialResults := []NodeResult{{NodeID: "node-1", Outcome: jobs.OutcomeFailure}}
	dispatchErr := errors.New("node-1: connection reset mid-dispatch")
	disp := &spyDispatcher{results: partialResults, err: dispatchErr}
	audit := &spyAuditSink{}
	svc := &Service{reg: reg, authz: authz, cap: capChecker, disp: disp, audit: audit, freeze: noopFreezeStore{}, metrics: noopMetricsSink{}}

	principal := Principal{Account: "alice"}
	sel := Selector{Predicates: []Predicate{{Namespace: NamespaceNode, Key: "role", Value: "web"}}}
	act := jobs.Action{Kind: jobs.ActionOperation, OperationName: "service.restart", RiskClass: jobs.RiskClassMutate}

	results, err := svc.Run(context.Background(), principal, sel, act)
	if err == nil {
		t.Fatal("Run() with an erroring dispatcher should return an error")
	}
	if !errors.Is(err, dispatchErr) {
		t.Errorf("Run() error = %v, want it to wrap the dispatch error %v", err, dispatchErr)
	}
	if len(results) != 1 || !reflect.DeepEqual(results[0], partialResults[0]) {
		t.Errorf("Run() results = %+v, want the dispatcher's partial results %+v", results, partialResults)
	}

	if !audit.called {
		t.Fatal("AuditSink was not called even though dispatch was attempted; a partially-executed dispatch must never go unaudited")
	}
	if audit.entry.Principal != principal {
		t.Errorf("AuditEntry.Principal = %+v, want %+v", audit.entry.Principal, principal)
	}
	if len(audit.entry.Results) != 1 || !reflect.DeepEqual(audit.entry.Results[0], partialResults[0]) {
		t.Errorf("AuditEntry.Results = %+v, want the dispatcher's partial results %+v", audit.entry.Results, partialResults)
	}
}

// TestWithOptionsPanicOnNilSeam asserts that WithAuthorizer, WithCapChecker,
// and WithAuditSink all panic on a nil seam at construction, matching
// WithExecution's own nil guard (execution.go): a nil seam here is a
// composition-root wiring bug, not a recoverable runtime condition, so every
// seam surface must fail identically rather than let a nil slip through to
// panic later (or not at all) inside Run.
func TestWithOptionsPanicOnNilSeam(t *testing.T) {
	tests := []struct {
		name string
		call func()
	}{
		{"WithAuthorizer", func() { WithAuthorizer(nil) }},
		{"WithCapChecker", func() { WithCapChecker(nil) }},
		{"WithAuditSink", func() { WithAuditSink(nil) }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			defer func() {
				if recover() == nil {
					t.Fatalf("%s(nil) should panic", tt.name)
				}
			}()
			tt.call()
		})
	}
}

func TestRunJoinsDispatchAndAuditErrors(t *testing.T) {
	reg := seedOneNode(t)
	authz := &spyAuthorizer{}
	capChecker := &spyCapChecker{}
	dispatchErr := errors.New("dispatch failed")
	auditWriteErr := errors.New("audit write failed")
	disp := &spyDispatcher{results: nil, err: dispatchErr}
	audit := &spyAuditSink{err: auditWriteErr}
	svc := &Service{reg: reg, authz: authz, cap: capChecker, disp: disp, audit: audit, freeze: noopFreezeStore{}, metrics: noopMetricsSink{}}

	sel := Selector{Predicates: []Predicate{{Namespace: NamespaceNode, Key: "role", Value: "web"}}}
	act := jobs.Action{RiskClass: jobs.RiskClassMutate}
	_, err := svc.Run(context.Background(), Principal{Account: "alice"}, sel, act)

	if !audit.called {
		t.Fatal("AuditSink was not called even though dispatch was attempted")
	}
	if !errors.Is(err, dispatchErr) {
		t.Errorf("Run() error = %v, want it to wrap the dispatch error %v", err, dispatchErr)
	}
	if !errors.Is(err, auditWriteErr) {
		t.Errorf("Run() error = %v, want it to wrap the audit-write error %v", err, auditWriteErr)
	}
}
