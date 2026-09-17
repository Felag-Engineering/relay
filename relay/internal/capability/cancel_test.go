package capability

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/jobs"
)

// TestCancelJobStopsPendingSendsCancelToDispatchedLeavesResolved is
// acceptance criteria 3/4: a Job with a Pending, a Dispatched, and an
// already-Resolved (success) Task. CancelJob marks the Pending Task
// cancelled without ever sending it, asks the Dispatched Task's Conduit to
// cancel without rewriting its state, and leaves the Resolved Task's
// truthful outcome untouched.
func TestCancelJobStopsPendingSendsCancelToDispatchedLeavesResolved(t *testing.T) {
	jobsRepo, tasksRepo := testEngineStore(t)
	ctx := context.Background()
	at := time.Date(2026, 7, 8, 0, 0, 0, 0, time.UTC)

	jobID := "job-1"
	if err := jobsRepo.CreateJob(ctx, jobs.Job{ID: jobID, CreatedAt: at}); err != nil {
		t.Fatalf("CreateJob: %v", err)
	}
	if err := jobsRepo.AddStage(ctx, jobs.Stage{ID: "stage-1", JobID: jobID, Index: 0}); err != nil {
		t.Fatalf("AddStage: %v", err)
	}

	pendingTask := jobs.Task{ID: "task-pending", JobID: jobID, StageID: "stage-1", NodeID: "node-pending",
		Action: jobs.Action{Kind: jobs.ActionOperation, OperationName: "system.facts", RiskClass: jobs.RiskClassRead}, CreatedAt: at}
	dispatchedTask := jobs.Task{ID: "task-dispatched", JobID: jobID, StageID: "stage-1", NodeID: "node-dispatched",
		Action: jobs.Action{Kind: jobs.ActionOperation, OperationName: "system.facts", RiskClass: jobs.RiskClassRead}, CreatedAt: at}
	resolvedTask := jobs.Task{ID: "task-resolved", JobID: jobID, StageID: "stage-1", NodeID: "node-resolved",
		Action: jobs.Action{Kind: jobs.ActionOperation, OperationName: "system.facts", RiskClass: jobs.RiskClassRead}, CreatedAt: at}

	for _, task := range []jobs.Task{pendingTask, dispatchedTask, resolvedTask} {
		if err := tasksRepo.CreateTask(ctx, task); err != nil {
			t.Fatalf("CreateTask(%s): %v", task.ID, err)
		}
	}
	if err := tasksRepo.MarkDispatched(ctx, dispatchedTask.ID, at); err != nil {
		t.Fatalf("MarkDispatched(dispatched): %v", err)
	}
	if err := tasksRepo.MarkDispatched(ctx, resolvedTask.ID, at); err != nil {
		t.Fatalf("MarkDispatched(resolved): %v", err)
	}
	if err := tasksRepo.Resolve(ctx, resolvedTask.ID, jobs.Result{Outcome: jobs.OutcomeSuccess}); err != nil {
		t.Fatalf("Resolve(resolved): %v", err)
	}

	var log []string
	conduit := newFakeConduit(&log)

	e := &jobEngine{
		jobsRepo:  jobsRepo,
		tasksRepo: tasksRepo,
		conduit:   conduit,
		newID:     sequentialIDs("id-"),
		now:       func() time.Time { return at },
	}
	audit := &spyAuditSink{}
	svc := &Service{disp: e, audit: audit, metrics: noopMetricsSink{}, authz: &spyAuthorizer{}}

	principal := Principal{Account: "alice", Role: "operator", Kind: PrincipalKindHuman}
	if err := svc.CancelJob(ctx, principal, jobID); err != nil {
		t.Fatalf("CancelJob: %v", err)
	}

	if len(audit.cancelCalls) != 1 {
		t.Fatalf("AuditSink.RecordCancel calls = %d, want 1", len(audit.cancelCalls))
	}
	if got := audit.cancelCalls[0]; got.Principal != principal || got.JobID != jobID {
		t.Errorf("RecordCancel call = %+v, want {%+v %q}", got, principal, jobID)
	}

	gotPending, err := tasksRepo.Get(ctx, pendingTask.ID)
	if err != nil {
		t.Fatalf("Get(pending): %v", err)
	}
	if gotPending.State != jobs.DispatchStateResolved {
		t.Errorf("pending Task state = %v, want DispatchStateResolved", gotPending.State)
	}
	if gotPending.Outcome != jobs.OutcomeCancelled {
		t.Errorf("pending Task outcome = %v, want OutcomeCancelled", gotPending.Outcome)
	}
	if !gotPending.DispatchedAt.IsZero() {
		t.Errorf("pending Task DispatchedAt = %v, want zero (never sent)", gotPending.DispatchedAt)
	}
	for _, entry := range log {
		if entry == "cancel:"+pendingTask.NodeID+":"+pendingTask.ID {
			t.Errorf("Conduit.Cancel was called for the Pending Task, which was never dispatched; log = %v", log)
		}
	}

	gotDispatched, err := tasksRepo.Get(ctx, dispatchedTask.ID)
	if err != nil {
		t.Fatalf("Get(dispatched): %v", err)
	}
	if gotDispatched.State != jobs.DispatchStateDispatched {
		t.Errorf("dispatched Task state = %v, want DispatchStateDispatched (no rewrite)", gotDispatched.State)
	}
	wantCancelLog := "cancel:" + dispatchedTask.NodeID + ":" + dispatchedTask.ID
	found := false
	for _, entry := range log {
		if entry == wantCancelLog {
			found = true
		}
	}
	if !found {
		t.Errorf("Conduit.Cancel was not called for the Dispatched Task; log = %v, want to contain %q", log, wantCancelLog)
	}

	gotResolved, err := tasksRepo.Get(ctx, resolvedTask.ID)
	if err != nil {
		t.Fatalf("Get(resolved): %v", err)
	}
	if gotResolved.Outcome != jobs.OutcomeSuccess {
		t.Errorf("resolved Task outcome = %v, want OutcomeSuccess (a cancelled Job's already-completed Tasks keep their truthful outcome)", gotResolved.Outcome)
	}
}

// TestCancelJobUnknownJobReturnsErrJobNotFound: CancelJob on a jobID that
// does not exist surfaces jobs.ErrJobNotFound.
func TestCancelJobUnknownJobReturnsErrJobNotFound(t *testing.T) {
	jobsRepo, tasksRepo := testEngineStore(t)
	e := &jobEngine{
		jobsRepo:  jobsRepo,
		tasksRepo: tasksRepo,
		conduit:   newFakeConduit(nil),
		newID:     sequentialIDs("id-"),
		now:       func() time.Time { return time.Now().UTC() },
	}
	audit := &spyAuditSink{}
	svc := &Service{disp: e, audit: audit, metrics: noopMetricsSink{}, authz: &spyAuthorizer{}}

	err := svc.CancelJob(context.Background(), Principal{Account: "alice", Role: "operator", Kind: PrincipalKindHuman}, "job-does-not-exist")
	if !errors.Is(err, jobs.ErrJobNotFound) {
		t.Errorf("CancelJob(unknown) error = %v, want jobs.ErrJobNotFound", err)
	}
	if len(audit.cancelCalls) != 0 {
		t.Errorf("RecordCancel calls = %d, want 0 (nothing true happened, so nothing is recorded)", len(audit.cancelCalls))
	}
}

// TestCancelJobRefusesBelowOperatorBeforeTouchingAnyTask: when the Authorizer
// refuses ControlCancelJob, CancelJob returns that refusal before disp.cancel
// is ever called — no Task changes state, RecordCancel is never called, and
// the refusal is recorded through refuseControl with the Principal and an
// empty JobID (the refusal precedes any existence check, so the id is
// caller-authored text — see CancelJob's doc comment).
func TestCancelJobRefusesBelowOperatorBeforeTouchingAnyTask(t *testing.T) {
	refusal := errors.New("cancelling a Job requires operator")
	authz := &spyAuthorizer{controlErr: refusal}
	audit := &spyAuditSink{}
	conduit := newFakeConduit(nil)
	e := &jobEngine{
		conduit: conduit,
		newID:   sequentialIDs("id-"),
		now:     func() time.Time { return time.Now().UTC() },
	}
	svc := &Service{disp: e, audit: audit, metrics: noopMetricsSink{}, authz: authz}

	principal := Principal{Account: "eve", Role: "viewer"}
	err := svc.CancelJob(context.Background(), principal, "job-1")
	if !errors.Is(err, refusal) {
		t.Fatalf("CancelJob error = %v, want it to wrap %v", err, refusal)
	}
	if got := authz.controlCalls; len(got) != 1 || got[0] != ControlCancelJob {
		t.Fatalf("controlCalls = %v, want exactly [ControlCancelJob]", got)
	}
	if len(audit.cancelCalls) != 0 {
		t.Errorf("RecordCancel calls = %d, want 0 — a refused cancel touches no Task", len(audit.cancelCalls))
	}
	if len(audit.entries) != 1 {
		t.Fatalf("audit entries = %d, want 1", len(audit.entries))
	}
	got := audit.entries[0]
	if got.Kind != AuditKindRefusal {
		t.Errorf("audit entry Kind = %v, want AuditKindRefusal", got.Kind)
	}
	if got.Principal != principal {
		t.Errorf("refusal Principal = %+v, want %+v", got.Principal, principal)
	}
	if got.JobID != "" {
		t.Errorf("refusal JobID = %q, want empty — the refusal precedes any existence check", got.JobID)
	}
}

// TestCancelJobRefusalDoesNotRevealWhetherTheJobExists: an unknown Job ID
// plus a refusing Authorizer returns the refusal, never jobs.ErrJobNotFound —
// a refused caller learns nothing about the Job.
func TestCancelJobRefusalDoesNotRevealWhetherTheJobExists(t *testing.T) {
	refusal := errors.New("cancelling a Job requires operator")
	authz := &spyAuthorizer{controlErr: refusal}
	jobsRepo, tasksRepo := testEngineStore(t)
	e := &jobEngine{
		jobsRepo:  jobsRepo,
		tasksRepo: tasksRepo,
		conduit:   newFakeConduit(nil),
		newID:     sequentialIDs("id-"),
		now:       func() time.Time { return time.Now().UTC() },
	}
	svc := &Service{disp: e, audit: &spyAuditSink{}, metrics: noopMetricsSink{}, authz: authz}

	err := svc.CancelJob(context.Background(), Principal{Account: "eve", Role: "viewer"}, "job-does-not-exist")
	if errors.Is(err, jobs.ErrJobNotFound) {
		t.Fatalf("CancelJob(unknown, refused) error = %v, must not reveal jobs.ErrJobNotFound", err)
	}
	if !errors.Is(err, refusal) {
		t.Fatalf("CancelJob error = %v, want it to wrap %v", err, refusal)
	}
}

// TestCancelJobAuthorizesWithoutAssertions: an authorization decision must
// never read caller-asserted attribution off the context (assertions.go), so
// AuthorizeControl must see none even when the caller set some.
func TestCancelJobAuthorizesWithoutAssertions(t *testing.T) {
	authz := &assertionSpyAuthorizer{}
	jobsRepo, tasksRepo := testEngineStore(t)
	at := time.Date(2026, 7, 8, 0, 0, 0, 0, time.UTC)
	jobID := "job-1"
	if err := jobsRepo.CreateJob(context.Background(), jobs.Job{ID: jobID, CreatedAt: at}); err != nil {
		t.Fatalf("CreateJob: %v", err)
	}
	e := &jobEngine{
		jobsRepo:  jobsRepo,
		tasksRepo: tasksRepo,
		conduit:   newFakeConduit(nil),
		newID:     sequentialIDs("id-"),
		now:       func() time.Time { return at },
	}
	svc := &Service{disp: e, audit: &spyAuditSink{}, metrics: noopMetricsSink{}, authz: authz}

	ctx := WithAssertions(context.Background(), Assertions{OnBehalfOf: "ops-team"})
	if err := svc.CancelJob(ctx, Principal{Account: "alice", Role: "operator", Kind: PrincipalKindHuman}, jobID); err != nil {
		t.Fatalf("CancelJob: %v", err)
	}
	if !authz.called {
		t.Fatal("the Authorizer was never called; this test proves nothing")
	}
	if !authz.sawAssertions.IsZero() {
		t.Errorf("AuthorizeControl saw caller-asserted attribution %+v — it must never be able to", authz.sawAssertions)
	}
}

// machineCancelFixture builds a *Service wired for CancelJob's
// machine-Account scoping tests below (owner decision 2026-09-17,
// execution.md §Cancellation, #614): a real Job in the engine store, an
// allow-all role-floor Authorizer (spyAuthorizer), and jobQ wired verbatim —
// a *spyJobQuery answering jobID's requester however the caller sets
// jobsResult/jobsErr, or a literal nil to exercise the "no job query wired"
// fail-closed case (authorizeMachineCancel's s.jobQ == nil branch): passing
// the JobQuery interface type, not *spyJobQuery, is what keeps a nil
// argument an actually-nil interface rather than a non-nil interface
// wrapping a nil *spyJobQuery, which would panic instead of exercising the
// branch. It mirrors the other CancelJob fixtures in this file rather than
// New(), so the test stays a white-box exercise of
// authorizeMachineCancel/refuseCancel without the rest of New's wiring
// guards.
func machineCancelFixture(t *testing.T, jobID string, jobQ JobQuery) (*Service, *spyAuditSink) {
	t.Helper()
	jobsRepo, tasksRepo := testEngineStore(t)
	at := time.Date(2026, 9, 17, 0, 0, 0, 0, time.UTC)
	if err := jobsRepo.CreateJob(context.Background(), jobs.Job{ID: jobID, CreatedAt: at}); err != nil {
		t.Fatalf("CreateJob: %v", err)
	}
	e := &jobEngine{
		jobsRepo:  jobsRepo,
		tasksRepo: tasksRepo,
		conduit:   newFakeConduit(nil),
		newID:     sequentialIDs("id-"),
		now:       func() time.Time { return at },
	}
	audit := &spyAuditSink{}
	svc := &Service{disp: e, audit: audit, metrics: noopMetricsSink{}, authz: &spyAuthorizer{}, jobQ: jobQ}
	return svc, audit
}

// TestCancelJobAllowsMachineCancellingItsOwnResolvedRequesterJob: a machine
// Account at operator+ may cancel a Job whose recorded requester (jobQ's
// join from the audit trail) is that very Account.
func TestCancelJobAllowsMachineCancellingItsOwnResolvedRequesterJob(t *testing.T) {
	const jobID = "job-owned"
	machine := Principal{AccountID: "acct-m", Account: "gleipnir-prod", Role: "operator", Kind: "machine"}
	jobQ := &spyJobQuery{jobsResult: JobPage{Jobs: []JobSummary{{JobID: jobID, RequesterAccountID: machine.AccountID}}}}
	svc, audit := machineCancelFixture(t, jobID, jobQ)

	if err := svc.CancelJob(context.Background(), machine, jobID); err != nil {
		t.Fatalf("CancelJob: %v", err)
	}
	if len(audit.cancelCalls) != 1 {
		t.Fatalf("RecordCancel calls = %d, want 1", len(audit.cancelCalls))
	}
	if !jobQ.jobsCalled {
		t.Error("the machine-scoping check never queried the Job's requester")
	}
	if jobQ.gotJobFilter.JobID != jobID {
		t.Errorf("queried JobID = %q, want %q", jobQ.gotJobFilter.JobID, jobID)
	}
}

// TestCancelJobRefusesMachineCancellingAnotherAccountsJob: a machine Account
// asking to cancel a Job whose recorded requester is a DIFFERENT Account is
// refused with ErrJobNotRequestedByCaller, and the reason never names the
// other Account.
func TestCancelJobRefusesMachineCancellingAnotherAccountsJob(t *testing.T) {
	const jobID = "job-not-mine"
	machine := Principal{AccountID: "acct-m", Account: "gleipnir-prod", Role: "operator", Kind: "machine"}
	jobQ := &spyJobQuery{jobsResult: JobPage{Jobs: []JobSummary{{JobID: jobID, RequesterAccountID: "acct-other"}}}}
	svc, audit := machineCancelFixture(t, jobID, jobQ)

	err := svc.CancelJob(context.Background(), machine, jobID)
	if !errors.Is(err, ErrJobNotRequestedByCaller) {
		t.Fatalf("CancelJob error = %v, want ErrJobNotRequestedByCaller", err)
	}
	if strings.Contains(err.Error(), "acct-other") {
		t.Errorf("refusal reason names another Account: %q", err.Error())
	}
	if len(audit.cancelCalls) != 0 {
		t.Errorf("RecordCancel calls = %d, want 0 — a refused cancel touches no Task", len(audit.cancelCalls))
	}
	if len(audit.entries) != 1 || audit.entries[0].Kind != AuditKindRefusal {
		t.Fatalf("audit entries = %+v, want exactly one AuditKindRefusal", audit.entries)
	}
	if audit.entries[0].JobID != jobID {
		t.Errorf("refusal JobID = %q, want %q — this refusal follows a real Job lookup", audit.entries[0].JobID, jobID)
	}
}

// TestCancelJobRefusesMachineCancellingAJobWithNoRecordedRequester: a Job
// whose requester has not yet been joined from the audit trail (a still
// in-flight Job, before #616) is refused exactly like one requested by
// somebody else — never inferred as the caller's own.
func TestCancelJobRefusesMachineCancellingAJobWithNoRecordedRequester(t *testing.T) {
	const jobID = "job-in-flight"
	machine := Principal{AccountID: "acct-m", Account: "gleipnir-prod", Role: "operator", Kind: "machine"}
	jobQ := &spyJobQuery{jobsResult: JobPage{Jobs: []JobSummary{{JobID: jobID, RequesterAccountID: ""}}}}
	svc, audit := machineCancelFixture(t, jobID, jobQ)

	err := svc.CancelJob(context.Background(), machine, jobID)
	if !errors.Is(err, ErrJobNotRequestedByCaller) {
		t.Fatalf("CancelJob error = %v, want ErrJobNotRequestedByCaller", err)
	}
	if len(audit.cancelCalls) != 0 {
		t.Errorf("RecordCancel calls = %d, want 0 — a refused cancel touches no Task", len(audit.cancelCalls))
	}
	if len(audit.entries) != 1 || audit.entries[0].JobID != jobID {
		t.Fatalf("refusal audit entries = %+v, want exactly one carrying JobID %q — the lookup found a real Job",
			audit.entries, jobID)
	}
}

// TestCancelJobRefusesMachineWithEmptyAccountIDAgainstEmptyRequester guards
// authorizeMachineCancel's `requester == ""` check specifically: an empty
// AccountID (a Principal built without one — see Principal.AccountID's doc
// comment) must never be treated as matching an unresolved, equally-empty
// RequesterAccountID. A `requester != accountID` comparison ALONE would let
// "" == "" authorize this by accident; the explicit empty check is what
// closes it.
func TestCancelJobRefusesMachineWithEmptyAccountIDAgainstEmptyRequester(t *testing.T) {
	const jobID = "job-empty-both"
	machine := Principal{AccountID: "", Account: "gleipnir-nightly", Role: "operator", Kind: "machine"}
	jobQ := &spyJobQuery{jobsResult: JobPage{Jobs: []JobSummary{{JobID: jobID, RequesterAccountID: ""}}}}
	svc, audit := machineCancelFixture(t, jobID, jobQ)

	err := svc.CancelJob(context.Background(), machine, jobID)
	if !errors.Is(err, ErrJobNotRequestedByCaller) {
		t.Fatalf("CancelJob error = %v, want ErrJobNotRequestedByCaller", err)
	}
	if len(audit.cancelCalls) != 0 {
		t.Errorf("RecordCancel calls = %d, want 0 — a refused cancel touches no Task", len(audit.cancelCalls))
	}
}

// TestCancelJobFailsClosedWhenTheRequesterCannotBeResolved is a table test
// over authorizeMachineCancel's three "the lookup never confirmed a real
// Job" cases: a query error, no job query wired at all, and jobID matching
// no Job. Every case refuses with the SAME caller-visible
// ErrJobNotRequestedByCaller, is audited as a refusal, and — because none of
// them resolved jobID to a real Job — the refusal's audit JobID is empty,
// exactly like a role-floor refusal (see refuseCancel/authorizeMachineCancel).
func TestCancelJobFailsClosedWhenTheRequesterCannotBeResolved(t *testing.T) {
	const jobID = "job-unresolvable"
	machine := Principal{AccountID: "acct-m", Account: "gleipnir-prod", Role: "operator", Kind: "machine"}

	cases := []struct {
		name string
		jobQ JobQuery // nil means no job query wired at all
	}{
		{"query error", &spyJobQuery{jobsErr: errors.New("store: unavailable")}},
		{"no job query wired", nil},
		{"unknown Job ID", &spyJobQuery{jobsResult: JobPage{}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			svc, audit := machineCancelFixture(t, jobID, tc.jobQ)

			err := svc.CancelJob(context.Background(), machine, jobID)
			if !errors.Is(err, ErrJobNotRequestedByCaller) {
				t.Fatalf("CancelJob error = %v, want ErrJobNotRequestedByCaller", err)
			}
			if len(audit.cancelCalls) != 0 {
				t.Errorf("RecordCancel calls = %d, want 0 — a refused cancel touches no Task", len(audit.cancelCalls))
			}
			if len(audit.entries) != 1 || audit.entries[0].Kind != AuditKindRefusal {
				t.Fatalf("audit entries = %+v, want exactly one AuditKindRefusal", audit.entries)
			}
			if audit.entries[0].JobID != "" {
				t.Errorf("refusal JobID = %q, want empty — the lookup never resolved a real Job", audit.entries[0].JobID)
			}
		})
	}
}

// TestCancelJobAllowsHumanOperatorCancellingAMachinesJob: the machine-Account
// scoping is Kind-specific — a human Account at operator+ may still cancel
// ANY Job, including one a machine Account requested, and the scoping check
// is never even consulted for one.
func TestCancelJobAllowsHumanOperatorCancellingAMachinesJob(t *testing.T) {
	const jobID = "job-machine-owned"
	human := Principal{AccountID: "acct-ops", Account: "ana", Role: "operator", Kind: PrincipalKindHuman}
	jobQ := &spyJobQuery{jobsResult: JobPage{Jobs: []JobSummary{{JobID: jobID, RequesterAccountID: "acct-m"}}}}
	svc, audit := machineCancelFixture(t, jobID, jobQ)

	if err := svc.CancelJob(context.Background(), human, jobID); err != nil {
		t.Fatalf("CancelJob: %v", err)
	}
	if len(audit.cancelCalls) != 1 {
		t.Fatalf("RecordCancel calls = %d, want 1", len(audit.cancelCalls))
	}
	if jobQ.jobsCalled {
		t.Error("a human Account's cancel must never query the Job's requester — the scoping check is machine-only")
	}
}
