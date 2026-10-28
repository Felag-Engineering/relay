package capability

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/Felag-Engineering/relay/relay/internal/jobs"
	"github.com/Felag-Engineering/relay/relay/internal/registry"
)

// spyAuthorizer records whether it was called and returns a fixed error.
//
// mu guards every field: the AP-77 concurrent-claim tests (#713) drive many
// goroutines through Run at once, and Authorize/AuthorizeControl run BEFORE
// the release claim's own serialisation kicks in, so this fake's bookkeeping
// must not race itself.
type spyAuthorizer struct {
	mu     sync.Mutex
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
	s.mu.Lock()
	defer s.mu.Unlock()
	s.called = true
	return s.err
}

func (s *spyAuthorizer) AuthorizeControl(_ context.Context, _ Principal, act ControlAction) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.controlCalls = append(s.controlCalls, act)
	return s.controlErr
}

// spyCapChecker records the arguments it was called with and returns a fixed
// error. mu guards it for the same reason spyAuthorizer's does (AP-77
// concurrent-claim tests, #713).
type spyCapChecker struct {
	mu         sync.Mutex
	called     bool
	gotClass   jobs.RiskClass
	gotMatched int
	err        error
}

func (s *spyCapChecker) Check(class jobs.RiskClass, matched int) error {
	s.mu.Lock()
	defer s.mu.Unlock()
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

	// ranWithJobID records the jobID a dispatch actually carried into run
	// (AP-77): a reserved, already-bound ID when Service.Run claimed an
	// approval's release, empty otherwise. Lets a test assert the dispatcher
	// ran with the SAME id the claim bound, rather than minting its own.
	ranWithJobID string

	// reserveErr lets a test force reserveJobID to fail, exercising Run's
	// RefusalInternal path when the dispatcher cannot mint a claim ID.
	reserveErr error

	// failWithNoJobID makes run report NO Job at all alongside err — the
	// jobEngine CreateJob-failure shape (dispatchResult{}), distinct from a
	// partial per-Task failure AFTER a Job was created (which still reports
	// jobID and partial results). Used by
	// TestRun_ClaimedReleaseThatFailsToDispatchStaysSpent to prove a claim
	// that wins and then never gets a real Job stays spent (AP-77).
	failWithNoJobID bool
}

func (s *spyDispatcher) run(_ context.Context, d dispatch) (dispatchResult, error) {
	s.called = true
	s.ranWithJobID = d.jobID
	if s.failWithNoJobID {
		return dispatchResult{results: s.results}, s.err
	}
	jobID := s.jobID
	if d.jobID != "" {
		jobID = d.jobID
	}
	return dispatchResult{jobID: jobID, results: s.results}, s.err
}

// reserveJobID implements dispatcher (AP-77). Defaults to "job-1" so tests
// that never set s.jobID still get a deterministic, non-empty reservation.
func (s *spyDispatcher) reserveJobID() (string, error) {
	if s.reserveErr != nil {
		return "", s.reserveErr
	}
	if s.jobID != "" {
		return s.jobID, nil
	}
	return "job-1", nil
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
//
// mu guards every recording method (AP-77, #713): the concurrent-claim tests
// drive RecordRead/Record from many goroutines at once (losing re-attaches
// racing the winning dispatch's audit write), and this fake's own slice
// appends must not race each other the way an unsynchronised test fixture
// would — the real AuditSink is backed by a single serialised SQLite
// connection and has no such hazard.
type spyAuditSink struct {
	mu     sync.Mutex
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
	s.mu.Lock()
	defer s.mu.Unlock()
	s.called = true
	s.entry = e
	s.entries = append(s.entries, e)
	return s.err
}

func (s *spyAuditSink) RecordFreeze(_ context.Context, e FreezeEvent) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.freezeCalls = append(s.freezeCalls, e)
	return s.err
}

func (s *spyAuditSink) RecordCancel(_ context.Context, p Principal, jobID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cancelCalls = append(s.cancelCalls, cancelCall{Principal: p, JobID: jobID})
	return s.err
}

func (s *spyAuditSink) RecordRead(_ context.Context, p Principal, tool, selector, nodeID, jobID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.readCalls = append(s.readCalls, readCall{Principal: p, Tool: tool, Selector: selector, NodeID: nodeID, JobID: jobID})
	return s.err
}

func (s *spyAuditSink) RecordAccountAdmin(_ context.Context, p Principal, e AccountAdminEvent) error {
	s.mu.Lock()
	defer s.mu.Unlock()
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
	svc := buildRaw(t, seams{reg: reg, authz: authz, cap: capChecker, disp: disp, audit: audit, freeze: noopFreezeStore{}, metrics: noopMetricsSink{}})

	sel := Selector{Predicates: []Predicate{{Namespace: NamespaceNode, Key: "role", Value: "web"}}}
	_, err := svc.Run(context.Background(), Principal{Account: "alice"}, sel, jobs.Action{})
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
	svc := buildRaw(t, seams{reg: reg, authz: authz, cap: capChecker, disp: disp, audit: audit, freeze: noopFreezeStore{}, metrics: noopMetricsSink{}})

	sel := Selector{Predicates: []Predicate{{Namespace: NamespaceNode, Key: "role", Value: "web"}}}
	act := jobs.Action{}
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
	svc := buildRaw(t, seams{reg: reg, authz: authz, cap: capChecker, disp: disp, audit: audit, freeze: noopFreezeStore{}, metrics: noopMetricsSink{}})

	principal := Principal{Account: "alice"}
	sel := Selector{Predicates: []Predicate{{Namespace: NamespaceNode, Key: "role", Value: "db"}}}
	act := jobs.Action{Kind: jobs.ActionOperation, OperationName: "system.facts"}

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
	svc := build(t, seams{reg: reg,
		authz:    &spyAuthorizer{},
		cap:      &spyCapChecker{},
		audit:    audit,
		freeze:   &fakeFreezeStore{},
		jobsRepo: jobsRepo, tasksRepo: tasksRepo, conduit: conduit, newID: sequentialIDs("id-"),
	})

	sel := Selector{Predicates: []Predicate{{Namespace: NamespaceNode, Key: "role", Value: "db"}}}
	act := jobs.Action{Kind: jobs.ActionOperation, OperationName: "system.facts"}

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
	svc := buildRaw(t, seams{reg: reg, authz: authz, cap: capChecker, disp: disp, audit: audit, freeze: noopFreezeStore{}, metrics: noopMetricsSink{}})

	sel := Selector{Predicates: []Predicate{{Namespace: NamespaceNode, Key: "role", Value: "db"}}}
	act := jobs.Action{Kind: jobs.ActionOperation, OperationName: "system.facts"}

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
	svc := buildRaw(t, seams{reg: reg, authz: authz, cap: capChecker, disp: disp, audit: audit, freeze: noopFreezeStore{}, metrics: noopMetricsSink{}})

	principal := Principal{Account: "alice", Role: "operator"}
	sel := Selector{Predicates: []Predicate{{Namespace: NamespaceNode, Key: "role", Value: "web"}}}
	act := jobs.Action{Kind: jobs.ActionOperation, OperationName: "service.restart"}

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
	wantAct := act
	wantAct.RiskClass = jobs.RiskClassMutate // derived by the capability layer (invariant 13)
	if !reflect.DeepEqual(audit.entry.Action, wantAct) {
		t.Errorf("AuditEntry.Action = %+v, want %+v", audit.entry.Action, wantAct)
	}
	if len(audit.entry.Results) != 1 || !reflect.DeepEqual(audit.entry.Results[0], wantResults[0]) {
		t.Errorf("AuditEntry.Results = %+v, want %+v", audit.entry.Results, wantResults)
	}
}

func TestRunHappyPathDefaultsToNoopDispatcher(t *testing.T) {
	reg := seedOneNode(t)
	svc := build(t, seams{reg: reg})

	sel := Selector{Predicates: []Predicate{{Namespace: NamespaceNode, Key: "role", Value: "web"}}}
	results, err := svc.Run(context.Background(), Principal{Account: "alice"}, sel, jobs.Action{})
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
	svc := buildRaw(t, seams{reg: reg, authz: authz, cap: capChecker, disp: disp, audit: audit, freeze: noopFreezeStore{}, metrics: noopMetricsSink{}})

	principal := Principal{Account: "alice"}
	sel := Selector{Predicates: []Predicate{{Namespace: NamespaceNode, Key: "role", Value: "web"}}}
	act := jobs.Action{Kind: jobs.ActionOperation, OperationName: "service.restart"}

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

// TestConstructorsPanicOnNilSeam asserts that every capability constructor
// panics on a nil required seam at construction: a nil seam here is a
// composition-root wiring bug, not a recoverable runtime condition, so every
// seam surface must fail identically rather than let a nil slip through to
// panic later (or not at all) inside Run. Each row asserts the panic names the
// constructor and the argument, so a runtime nil dereference — which is not a
// string — cannot satisfy it. The collaborators are built outside the recover
// scope, over one shared Recorder.
func TestConstructorsPanicOnNilSeam(t *testing.T) {
	rec := NewRecorder(&spyAuditSink{}, nil, nil)
	jr, tr := testEngineStore(t)
	conduit := newFakeConduit(nil)
	capc := &spyCapChecker{}
	reg := registry.NewInMemory()
	aq := &spyAuditQuery{}
	jq := &spyJobQuery{}
	authz := &permissiveControlAuthorizer{}
	freeze := &fakeFreezeStore{}
	store := &fakeAccountStore{}
	tokens := &fakeAPITokenStore{}
	ctl := NewControl(rec, authz, freeze)
	read := NewReadLane(rec, reg, aq, jq, nil, nil, testSettings, nil)
	gate := gateEverything(t, 1)
	astore := newMemApprovals()
	aauthz := &spyApprovalAuthorizer{}
	appr := NewApprovals(rec, gate, astore, aauthz, nil, nil, nil)

	tests := []struct {
		name string
		call func()
		want string
	}{
		{"NewRecorder", func() { NewRecorder(nil, nil, nil) }, "capability: NewRecorder: auditSink"},
		{"NewControl/recorder", func() { NewControl(nil, authz, freeze) }, "NewControl: recorder"},
		{"NewControl/authorizer", func() { NewControl(rec, nil, freeze) }, "NewControl: authorizer"},
		{"NewControl/freezeStore", func() { NewControl(rec, authz, nil) }, "NewControl: freezeStore"},
		{"NewAccountAdmin/control", func() { NewAccountAdmin(nil, store, tokens) }, "NewAccountAdmin: control"},
		{"NewAccountAdmin/account store", func() { NewAccountAdmin(ctl, nil, tokens) }, "NewAccountAdmin: account store"},
		{"NewAccountAdmin/API token store", func() { NewAccountAdmin(ctl, store, nil) }, "NewAccountAdmin: API token store"},
		{"NewReadLane/recorder", func() { NewReadLane(nil, reg, aq, jq, nil, nil, testSettings, nil) }, "NewReadLane: recorder"},
		{"NewReadLane/registry", func() { NewReadLane(rec, nil, aq, jq, nil, nil, testSettings, nil) }, "NewReadLane: registry"},
		{"NewReadLane/audit query seam", func() { NewReadLane(rec, reg, nil, jq, nil, nil, testSettings, nil) }, "NewReadLane: audit query seam"},
		{"NewReadLane/job query seam", func() { NewReadLane(rec, reg, aq, nil, nil, nil, testSettings, nil) }, "NewReadLane: job query seam"},
		{"NewReadLane/settings", func() { NewReadLane(rec, reg, aq, jq, nil, nil, nil, nil) }, "NewReadLane: settings"},
		{"NewApprovals/recorder", func() { NewApprovals(nil, gate, astore, aauthz, nil, nil, nil) }, "NewApprovals: recorder"},
		{"NewApprovals/gate", func() { NewApprovals(rec, nil, astore, aauthz, nil, nil, nil) }, "NewApprovals: gate"},
		{"NewApprovals/store", func() { NewApprovals(rec, gate, nil, aauthz, nil, nil, nil) }, "NewApprovals: store"},
		{"NewApprovals/approval authorizer", func() { NewApprovals(rec, gate, astore, nil, nil, nil, nil) }, "NewApprovals: approval authorizer"},
		{"NewExecution/control", func() {
			NewExecution(nil, read, appr, capc, nil, jr, tr, conduit, testSettings, nil, nil)
		}, "capability: NewExecution: control"},
		{"NewExecution/read lane", func() {
			NewExecution(ctl, nil, appr, capc, nil, jr, tr, conduit, testSettings, nil, nil)
		}, "capability: NewExecution: read lane"},
		{"NewExecution/approvals", func() {
			NewExecution(ctl, read, nil, capc, nil, jr, tr, conduit, testSettings, nil, nil)
		}, "capability: NewExecution: approvals"},
		// rec's AuditSink cannot record intent, so without this check the call
		// would panic anyway, but with the IntentRecorder text, not this one.
		{"NewExecution/capChecker", func() {
			NewExecution(ctl, read, appr, nil, nil, jr, tr, conduit, testSettings, nil, nil)
		}, "capability: NewExecution: capChecker"},
		{"NewExecution/settings", func() {
			NewExecution(ctl, read, appr, capc, nil, jr, tr, conduit, nil, nil, nil)
		}, "settings must not be nil"},
		{"NewExecution/jobsRepo", func() {
			NewExecution(ctl, read, appr, capc, nil, nil, tr, conduit, testSettings, nil, nil)
		}, "NewExecution: jobsRepo, tasksRepo, and conduit"},
		{"NewExecution/tasksRepo", func() {
			NewExecution(ctl, read, appr, capc, nil, jr, nil, conduit, testSettings, nil, nil)
		}, "NewExecution: jobsRepo, tasksRepo, and conduit"},
		{"NewExecution/conduit", func() {
			NewExecution(ctl, read, appr, capc, nil, jr, tr, nil, testSettings, nil, nil)
		}, "NewExecution: jobsRepo, tasksRepo, and conduit"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			defer func() {
				r := recover()
				if r == nil {
					t.Fatalf("%s(nil) should panic", tt.name)
				}
				if msg, _ := r.(string); !strings.Contains(msg, tt.want) {
					t.Fatalf("%s panic = %v, want a string containing %q", tt.name, r, tt.want)
				}
			}()
			tt.call()
		})
	}
}

// TestNewExecution_RefusesReadLaneOverADifferentRecorder: the Control and the
// read lane must share one Recorder, or the layer would hold two audit trails.
func TestNewExecution_RefusesReadLaneOverADifferentRecorder(t *testing.T) {
	jr, tr := testEngineStore(t)
	spy := &intentSpySink{&spyAuditSink{}, &nonAtomicIntents{tr: tr}}
	recA := NewRecorder(spy, nil, nil)
	recB := NewRecorder(spy, nil, nil)
	reg := registry.NewInMemory()
	ctl := NewControl(recA, &spyAuthorizer{}, &fakeFreezeStore{})
	other := newReadLane(recB, reg, nil, nil, nil, nil, testSettings, nil)
	same := newReadLane(recA, reg, nil, nil, nil, nil, testSettings, nil)
	appr := newApprovals(recA, noopApprovalGate{}, nil, nil, nil, noopApprovalNotifier{}, nil)

	if NewExecution(ctl, same, appr, &spyCapChecker{}, nil, jr, tr, newFakeConduit(nil), testSettings, nil, nil) == nil {
		t.Fatal("NewExecution over a read lane sharing the Control's Recorder returned nil")
	}

	defer func() {
		r := recover()
		if r == nil {
			t.Fatal("NewExecution over a read lane with a different Recorder should panic")
		}
		msg, _ := r.(string)
		if !strings.Contains(msg, "capability: NewExecution:") || !strings.Contains(msg, "share one Recorder") {
			t.Fatalf("panic = %v, want NewExecution's shared-Recorder refusal", r)
		}
	}()
	NewExecution(ctl, other, appr, &spyCapChecker{}, nil, jr, tr, newFakeConduit(nil), testSettings, nil, nil)
}

// TestNewExecution_RefusesApprovalsOverADifferentRecorder: the Control and the
// Approvals must share one Recorder, or the layer would hold two audit trails.
func TestNewExecution_RefusesApprovalsOverADifferentRecorder(t *testing.T) {
	jr, tr := testEngineStore(t)
	spy := &intentSpySink{&spyAuditSink{}, &nonAtomicIntents{tr: tr}}
	recA := NewRecorder(spy, nil, nil)
	recB := NewRecorder(spy, nil, nil)
	reg := registry.NewInMemory()
	ctl := NewControl(recA, &spyAuthorizer{}, &fakeFreezeStore{})
	same := newReadLane(recA, reg, nil, nil, nil, nil, testSettings, nil)
	apprA := newApprovals(recA, noopApprovalGate{}, nil, nil, nil, noopApprovalNotifier{}, nil)
	apprB := newApprovals(recB, noopApprovalGate{}, nil, nil, nil, noopApprovalNotifier{}, nil)

	if NewExecution(ctl, same, apprA, &spyCapChecker{}, nil, jr, tr, newFakeConduit(nil), testSettings, nil, nil) == nil {
		t.Fatal("NewExecution over an Approvals sharing the Control's Recorder returned nil")
	}

	defer func() {
		r := recover()
		if r == nil {
			t.Fatal("NewExecution over an Approvals with a different Recorder should panic")
		}
		msg, _ := r.(string)
		if !strings.Contains(msg, "capability: NewExecution:") || !strings.Contains(msg, "share one Recorder") || !strings.Contains(msg, "approvals") {
			t.Fatalf("panic = %v, want NewExecution's approvals shared-Recorder refusal", r)
		}
	}()
	NewExecution(ctl, same, apprB, &spyCapChecker{}, nil, jr, tr, newFakeConduit(nil), testSettings, nil, nil)
}

// TestNewApprovals_NilNotifierParksWithoutNotifying: production passes a nil
// notifier when no webhook is configured, and the park path calls NotifyParked
// with no nil check — so NewApprovals must map nil to the no-op.
func TestNewApprovals_NilNotifierParksWithoutNotifying(t *testing.T) {
	rec := NewRecorder(&spyAuditSink{}, nil, nil)
	appr := NewApprovals(rec, gateEverything(t, 1), newMemApprovals(), &spyApprovalAuthorizer{}, nil, nil, nil)
	ctl := NewControl(rec, &spyAuthorizer{}, &fakeFreezeStore{})
	read := newReadLane(rec, seedOneNode(t), nil, nil, nil, nil, testSettings, nil)
	svc := newExecution(ctl, read, appr, noopCapChecker{}, nil, noopDispatcher{}, nil)

	_, err := svc.Run(context.Background(), machineRequester, Selector{}, mutateAct())
	var parked *ParkedError
	if !errors.As(err, &parked) {
		t.Fatalf("Run: err = %v, want a park", err)
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
	svc := buildRaw(t, seams{reg: reg, authz: authz, cap: capChecker, disp: disp, audit: audit, freeze: noopFreezeStore{}, metrics: noopMetricsSink{}})

	sel := Selector{Predicates: []Predicate{{Namespace: NamespaceNode, Key: "role", Value: "web"}}}
	act := jobs.Action{}
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
