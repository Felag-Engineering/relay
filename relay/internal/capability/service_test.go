package capability

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/jobs"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/registry"
)

// spyAuthorizer records whether it was called and returns a fixed error.
type spyAuthorizer struct {
	called bool
	err    error

	// controlCalls records every ControlAction the Service asked about (#397),
	// and controlErr is what AuthorizeControl returns. Separate from
	// called/err so a test can assert that the administrative half was
	// consulted without an Action-shaped call being confused for it.
	controlCalls []ControlAction
	controlErr   error
}

func (s *spyAuthorizer) Authorize(context.Context, Principal, jobs.Action, Selector) error {
	s.called = true
	return s.err
}

func (s *spyAuthorizer) AuthorizeControl(_ context.Context, _ Principal, act ControlAction) error {
	s.controlCalls = append(s.controlCalls, act)
	return s.controlErr
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
	entries           []AuditEntry
	err               error
	freezeCalls       []FreezeEvent
	cancelCalls       []cancelCall
	readCalls         []readCall
	accountAdminCalls []accountAdminCall
}

// accountAdminCall records one RecordAccountAdmin invocation's arguments
// (#653).
type accountAdminCall struct {
	Principal Principal
	Event     AccountAdminEvent
}

// cancelCall records one RecordCancel invocation's arguments.
type cancelCall struct {
	Principal Principal
	JobID     string
}

// readCall records one RecordRead invocation's arguments (#441).
type readCall struct {
	Principal Principal
	Tool      string
	Selector  string
	NodeID    string
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

func (s *spyAuditSink) RecordRead(_ context.Context, p Principal, tool, selector, nodeID, jobID string) error {
	s.readCalls = append(s.readCalls, readCall{Principal: p, Tool: tool, Selector: selector, NodeID: nodeID, JobID: jobID})
	return s.err
}

func (s *spyAuditSink) RecordAccountAdmin(_ context.Context, p Principal, e AccountAdminEvent) error {
	s.accountAdminCalls = append(s.accountAdminCalls, accountAdminCall{Principal: p, Event: e})
	return s.err
}

func seedOneNode(t *testing.T) registry.Repository {
	t.Helper()
	reg := registry.NewInMemory()
	if _, err := reg.Upsert(registry.Report{
		NodeID: "node-1",
	}.WithNodeLabels(map[string]string{"role": "web"})); err != nil {
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

// TestRunZeroMatchRefusedBeforeAnyJob is #571's core acceptance line: a
// Selector resolving to zero Nodes is refused, once, in the capability layer
// — authorized but never dispatched, never capacity-checked — and audited as
// a refusal rather than a job-level dispatch row.
func TestRunZeroMatchRefusedBeforeAnyJob(t *testing.T) {
	reg := seedOneNode(t)
	authz := &spyAuthorizer{}
	capChecker := &spyCapChecker{}
	disp := &spyDispatcher{}
	audit := &spyAuditSink{}
	svc := &Service{reg: reg, authz: authz, cap: capChecker, disp: disp, audit: audit, freeze: noopFreezeStore{}, metrics: noopMetricsSink{}}

	principal := Principal{Account: "alice"}
	sel := Selector{Predicates: []Predicate{{Namespace: NamespaceNode, Key: "role", Value: "db"}}}
	act := jobs.Action{Kind: jobs.ActionOperation, OperationName: "system.facts", RiskClass: jobs.RiskClassRead}

	results, err := svc.Run(context.Background(), principal, sel, act)
	if results != nil {
		t.Errorf("Run() results = %+v, want nil", results)
	}
	var nnmErr *NoNodesMatchedError
	if !errors.As(err, &nnmErr) {
		t.Fatalf("Run() error = %v, want errors.As to find a *NoNodesMatchedError", err)
	}
	if nnmErr.Selector != "node:role=db" {
		t.Errorf("NoNodesMatchedError.Selector = %q, want %q", nnmErr.Selector, "node:role=db")
	}
	if !strings.Contains(err.Error(), "no_nodes_matched") {
		t.Errorf("Run() error = %q, want it to contain %q", err.Error(), "no_nodes_matched")
	}
	if !strings.Contains(err.Error(), "node:role=db") {
		t.Errorf("Run() error = %q, want it to contain the Selector %q", err.Error(), "node:role=db")
	}
	if !authz.called {
		t.Error("Authorizer was not called — the zero-match refusal must come AFTER authorization")
	}
	if capChecker.called {
		t.Error("CapChecker must not be called on a zero-match Selector")
	}
	if disp.called {
		t.Error("dispatcher must not be called on a zero-match Selector")
	}

	if len(audit.entries) != 1 {
		t.Fatalf("audit.entries = %+v, want exactly one entry", audit.entries)
	}
	entry := audit.entries[0]
	if entry.Kind != AuditKindRefusal {
		t.Errorf("AuditEntry.Kind = %v, want AuditKindRefusal", entry.Kind)
	}
	if entry.Principal != principal {
		t.Errorf("AuditEntry.Principal = %+v, want %+v", entry.Principal, principal)
	}
	if !reflect.DeepEqual(entry.Selector, sel) {
		t.Errorf("AuditEntry.Selector = %+v, want %+v", entry.Selector, sel)
	}
	if entry.Action.OperationName != act.OperationName {
		t.Errorf("AuditEntry.Action.OperationName = %q, want %q", entry.Action.OperationName, act.OperationName)
	}
	if entry.JobID != "" {
		t.Errorf("AuditEntry.JobID = %q, want empty (no Job was ever created)", entry.JobID)
	}
	if entry.Results != nil {
		t.Errorf("AuditEntry.Results = %+v, want nil", entry.Results)
	}
	if !strings.Contains(entry.Reason, "no_nodes_matched") {
		t.Errorf("AuditEntry.Reason = %q, want it to contain %q", entry.Reason, "no_nodes_matched")
	}
}

// TestRunZeroMatchCreatesNoJob proves the zero-match refusal happens before
// any Job exists: CreateJob is never reached, so a later GetJob for the id
// the (untouched) ID generator would have produced returns ErrJobNotFound,
// and the Conduit is never touched.
func TestRunZeroMatchCreatesNoJob(t *testing.T) {
	reg := seedOneNode(t)
	var log []string
	conduit := newFakeConduit(&log)

	jobsRepo, tasksRepo := testEngineStore(t)
	audit := &spyAuditSink{}
	svc := New(reg,
		WithAuthorizer(&spyAuthorizer{}),
		WithCapChecker(&spyCapChecker{}),
		WithAuditSink(audit),
		WithFreeze(&fakeFreezeStore{}),
		WithExecution(jobsRepo, tasksRepo, conduit, WithExecNewID(sequentialIDs("id-"))),
	)

	sel := Selector{Predicates: []Predicate{{Namespace: NamespaceNode, Key: "role", Value: "db"}}}
	act := jobs.Action{Kind: jobs.ActionOperation, OperationName: "system.facts", RiskClass: jobs.RiskClassRead}

	_, err := svc.Run(context.Background(), Principal{Account: "alice"}, sel, act)
	var nnmErr *NoNodesMatchedError
	if !errors.As(err, &nnmErr) {
		t.Fatalf("Run() error = %v, want errors.As to find a *NoNodesMatchedError", err)
	}

	if _, err := jobsRepo.GetJob(context.Background(), "id-1"); !errors.Is(err, jobs.ErrJobNotFound) {
		t.Errorf("jobsRepo.GetJob(id-1) error = %v, want ErrJobNotFound (CreateJob must never be called)", err)
	}
	if len(log) != 0 {
		t.Errorf("Conduit was touched (log = %v), want no Dispatch/Query calls on a zero-match Run", log)
	}
}

// TestRunZeroMatchUnauthorizedIsRefusedAsUnauthorized pins the ordering
// decision: an unauthorized caller gets "unauthorized" whatever the fleet
// holds, and never learns that its Selector matched no Node.
func TestRunZeroMatchUnauthorizedIsRefusedAsUnauthorized(t *testing.T) {
	reg := seedOneNode(t)
	authz := &spyAuthorizer{err: errors.New("denied")}
	capChecker := &spyCapChecker{}
	disp := &spyDispatcher{}
	audit := &spyAuditSink{}
	svc := &Service{reg: reg, authz: authz, cap: capChecker, disp: disp, audit: audit, freeze: noopFreezeStore{}, metrics: noopMetricsSink{}}

	sel := Selector{Predicates: []Predicate{{Namespace: NamespaceNode, Key: "role", Value: "db"}}}
	act := jobs.Action{Kind: jobs.ActionOperation, OperationName: "system.facts", RiskClass: jobs.RiskClassRead}

	_, err := svc.Run(context.Background(), Principal{Account: "alice"}, sel, act)
	var nnmErr *NoNodesMatchedError
	if errors.As(err, &nnmErr) {
		t.Fatalf("Run() error = %v, want errors.As NOT to find a *NoNodesMatchedError (authz must gate first)", err)
	}
	if len(audit.entries) != 1 {
		t.Fatalf("audit.entries = %+v, want exactly one entry", audit.entries)
	}
	if audit.entries[0].Reason != "denied" {
		t.Errorf("AuditEntry.Reason = %q, want %q", audit.entries[0].Reason, "denied")
	}
	if disp.called {
		t.Error("dispatcher must not be called when Authorize fails")
	}
}

// TestNoNodesMatchedErrorIsLegibleForAnEmptySelector checks both of
// NoNodesMatchedError.Error()'s branches: a non-empty Selector renders it
// verbatim, and an empty Selector (which matches every Node) gets its own
// legible sentence rather than a bare "".
func TestNoNodesMatchedErrorIsLegibleForAnEmptySelector(t *testing.T) {
	nonEmpty := &NoNodesMatchedError{Selector: "node:role=db"}
	if !strings.Contains(nonEmpty.Error(), "no_nodes_matched") {
		t.Errorf("Error() = %q, want it to contain %q", nonEmpty.Error(), "no_nodes_matched")
	}
	if !strings.Contains(nonEmpty.Error(), "node:role=db") {
		t.Errorf("Error() = %q, want it to contain the Selector", nonEmpty.Error())
	}

	empty := &NoNodesMatchedError{}
	if !strings.Contains(empty.Error(), "no_nodes_matched") {
		t.Errorf("Error() = %q, want it to contain %q", empty.Error(), "no_nodes_matched")
	}
	if !strings.Contains(empty.Error(), "empty Selector") {
		t.Errorf("Error() = %q, want it to explain the empty Selector rather than render a bare \"\"", empty.Error())
	}
	if strings.Contains(empty.Error(), `""`) {
		t.Errorf("Error() = %q, want no bare \"\" rendered for the empty Selector", empty.Error())
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
