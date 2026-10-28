package capability

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Felag-Engineering/relay/relay/internal/audit"
	"github.com/Felag-Engineering/relay/relay/internal/jobs"
	"github.com/Felag-Engineering/relay/relay/internal/registry"
	"github.com/Felag-Engineering/relay/relay/internal/store"
)

// postdispatch_test.go proves the reserved-path fix pass on Service.Run's
// POST-dispatch accounting (the KindDispatch audit record): once a Job's
// release claim has committed, a client that drops mid-dispatch must not
// leave that Job's accounting stranded on a ctx the same
// drop already cancelled — see the acctCtx block in Run (pipeline.go).

// ctxSensitiveAuditSink is a minimal capability.AuditSink over a REAL
// audit.Repository (SQLite, store.Open) rather than a spy that always
// succeeds (spyAuditSink, service_test.go). It exists only so the tests below
// can tell "the write ran on a live context" from "it ran on the request ctx
// the dispatcher itself cancelled" — a spy that cannot fail could not
// distinguish the two, which would make a passing test equally consistent
// with the pre-fix defect. Record's ctx reaches the repo's real
// db.ExecContext (relay/internal/store/audit.go), so a cancelled ctx fails
// exactly the way it would through the production sink (internal/auditsink),
// which this package cannot import directly — auditsink imports capability,
// so doing so from a non-test file would be a cycle; this file is a _test.go
// file, exempt from .golangci.yml's capability-imports rule, so importing audit/store here is not that cycle.
type ctxSensitiveAuditSink struct {
	repo  audit.Repository
	newID idGen
	now   func() time.Time
}

func (s *ctxSensitiveAuditSink) Record(ctx context.Context, e AuditEntry) error {
	id, err := s.newID()
	if err != nil {
		return err
	}
	return s.repo.Append(ctx, audit.Record{
		ID:        id,
		Timestamp: s.now(),
		Kind:      ctxSensitiveAuditKind(e.Kind),
		Principal: e.Principal.Account,
		JobID:     e.JobID,
	})
}

func (s *ctxSensitiveAuditSink) RecordFreeze(context.Context, FreezeEvent) error { return nil }
func (s *ctxSensitiveAuditSink) RecordCancel(context.Context, Principal, string) error {
	return nil
}
func (s *ctxSensitiveAuditSink) RecordRead(context.Context, Principal, string, string, string, string) error {
	return nil
}
func (s *ctxSensitiveAuditSink) RecordAccountAdmin(context.Context, Principal, AccountAdminEvent) error {
	return nil
}

// ctxSensitiveAuditKind maps the handful of AuditKind values the tests below
// actually produce onto the real audit.Kind* string constants, mirroring the
// small slice of internal/auditsink's own mapping these tests exercise.
func ctxSensitiveAuditKind(k AuditKind) string {
	switch k {
	case AuditKindDispatch:
		return audit.KindDispatch
	case AuditKindApprovalRequested:
		return audit.KindApprovalRequested
	case AuditKindApprovalPendingObserved:
		return audit.KindApprovalPendingObserved
	default:
		return audit.KindRefusal
	}
}

// TestCtxSensitiveAuditSinkRejectsACancelledContext is the negative control
// for TestRun_ReservedDispatchIsAuditedAndBoundWhenTheClientDropsMidDispatch
// below: it proves ctxSensitiveAuditSink is not a spy that always succeeds —
// the fixture the positive test relies on to tell a live, detached ctx from a
// cancelled request ctx actually rejects the latter, over the real store,
// exactly the property that makes the positive test meaningful.
func TestCtxSensitiveAuditSinkRejectsACancelledContext(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "relay.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	sink := &ctxSensitiveAuditSink{repo: st.Audit(), newID: defaultID, now: func() time.Time { return apNow }}

	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := sink.Record(cancelled, AuditEntry{Kind: AuditKindDispatch, JobID: "job-x"}); err == nil {
		t.Fatal("Record on a cancelled context: want an error — the fixture must be able to detect a post-dispatch write that ran on a cancelled ctx")
	}

	if err := sink.Record(context.Background(), AuditEntry{Kind: AuditKindDispatch, JobID: "job-x"}); err != nil {
		t.Fatalf("Record on a live context: %v, want success", err)
	}
	recs, err := st.Audit().ByJob(context.Background(), "job-x")
	if err != nil {
		t.Fatalf("ByJob: %v", err)
	}
	if len(recs) != 1 {
		t.Fatalf("ByJob(job-x) = %d records, want exactly 1 (only the live-ctx write should have landed)", len(recs))
	}
}

// cancelOnDispatchConduit is a Conduit whose Dispatch call cancels the
// caller-supplied context.CancelFunc before returning a canned Result —
// modeling a client per-call timeout or a dropped connection firing WHILE
// jobEngine.run is sending the (already-persisted) Task, on the request ctx
// Service.Run itself was called with. Since jobEngine.run's own
// persist-then-dispatch pipeline for a reserved id already runs on a context
// detached from this one (runCtx, execution.go), cancelling here never stops
// the Job from completing — it only leaves the ORIGINAL ctx cancelled by the
// time s.disp.run returns to Service.Run, which is exactly the state Run's
// post-dispatch accounting must survive.
type cancelOnDispatchConduit struct {
	cancel context.CancelFunc
	result jobs.Result
}

func (c *cancelOnDispatchConduit) Connected(string) bool { return true }

func (c *cancelOnDispatchConduit) Dispatch(context.Context, string, jobs.Task) (jobs.Result, error) {
	c.cancel()
	return c.result, nil
}

func (c *cancelOnDispatchConduit) Cancel(context.Context, string, string) error { return nil }

func (c *cancelOnDispatchConduit) Query(context.Context, string, jobs.Action) (jobs.Verdict, error) {
	return jobs.Verdict{}, nil
}

// TestRun_ReservedDispatchIsAuditedWhenTheClientDropsMidDispatch: a client
// that drops mid-dispatch on the RESERVED (approval-released) path must not
// leave the Job it already committed to with no durable dispatch audit
// record. Real SQLite for the approval claim (whose atomicity is the store's
// contract, matching TestRun_ReleasedJobStaysBoundWhenTheCallIsCancelledMidDispatch)
// and the Job engine, and the ctx-sensitive sink above for the audit write: a
// spy that cannot fail would prove nothing about which ctx Run actually used.
func TestRun_ReservedDispatchIsAuditedWhenTheClientDropsMidDispatch(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "relay.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	approvalsRepo := st.Approvals()

	reg := registry.NewInMemory()
	if _, err := reg.Upsert(registry.Report{NodeID: "node-a"}); err != nil {
		t.Fatalf("seed: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	conduit := &cancelOnDispatchConduit{cancel: cancel, result: jobs.Result{Outcome: jobs.OutcomeSuccess}}
	auditSink := &ctxSensitiveAuditSink{repo: st.Audit(), newID: defaultID, now: func() time.Time { return apNow }}

	s := build(t, seams{reg: reg,
		authz: &spyAuthorizer{}, cap: &spyCapChecker{},
		audit: auditSink, freeze: &fakeFreezeStore{},
		gate: gateEverything(t, 1), approvals: approvalsRepo, approvalAuthz: &spyApprovalAuthorizer{},
		jobsRepo: st.Jobs(), tasksRepo: st.Tasks(), conduit: conduit,
		now: func() time.Time { return apNow },
	})
	p := Principal{AccountID: "acct-g", Account: "gleipnir-prod"}

	_, err = s.Run(ctx, p, Selector{}, mutateAct())
	var parked *ParkedError
	if !errors.As(err, &parked) {
		t.Fatalf("first Run: err = %v, want a park", err)
	}
	approveViaRecordDecision(t, approvalsRepo, parked.RequestID, parked.PlanHash, apNow.Add(time.Minute))

	// The second Run's ctx is the one cancelOnDispatchConduit cancels from
	// inside the (already-detached) dispatch pipeline — mid-dispatch, exactly
	// like a client timeout or a dropped connection.
	res, err := s.Run(ctx, p, Selector{}, mutateAct())
	if err != nil {
		t.Fatalf("release Run: %v — a client drop mid-dispatch must not surface as an error once the Job and its accounting both completed", err)
	}
	if len(res) != 1 || res[0].Outcome != jobs.OutcomeSuccess {
		t.Fatalf("release Run results = %+v, want one successful result", res)
	}
	jobID := res[0].JobID
	if jobID == "" {
		t.Fatal("release Run: want a Job ID on the result")
	}

	// (1) The Job completed: a Resolved, successful Task.
	gotTasks, err := st.Tasks().ByJob(context.Background(), jobID)
	if err != nil {
		t.Fatalf("ByJob(%s): %v", jobID, err)
	}
	if len(gotTasks) != 1 || gotTasks[0].State != jobs.DispatchStateResolved || gotTasks[0].Outcome != jobs.OutcomeSuccess {
		t.Fatalf("task state/outcome = %+v, want exactly one Resolved/Success Task", gotTasks)
	}

	// (2) The KindDispatch audit record was written — durably, over the real
	// store — even though the request ctx was cancelled by the time Run's
	// post-dispatch accounting ran.
	auditRecs, err := st.Audit().ByJob(context.Background(), jobID)
	if err != nil {
		t.Fatalf("Audit ByJob(%s): %v", jobID, err)
	}
	found := false
	for _, r := range auditRecs {
		if r.Kind == audit.KindDispatch {
			found = true
		}
	}
	if !found {
		t.Fatalf("no %s audit record for job %s — the client drop stranded the reserved-path dispatch accounting", audit.KindDispatch, jobID)
	}
}

// captureDefaultLog swaps slog's default logger for one that writes JSON
// lines to a buffer, restoring the previous default on test cleanup, and
// returns the buffer — mirroring dispatch/router_test.go's
// captureDefaultLog/TestNewRouter_NilViolationRecorderWarnsAtConstruction
// idiom, which is what proves a package-level slog call happened rather than
// merely that a function returned successfully.
func captureDefaultLog(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&buf, nil)))
	t.Cleanup(func() { slog.SetDefault(prev) })
	return &buf
}

// TestRun_ReservedDispatchAuditWriteFailureIsLoggedForAnOperator is the fix
// pass's third requirement: on the reserved path, an audit-write failure
// (for any reason, not just a cancelled ctx) must surface somewhere an
// operator is actually watching, because the caller Run would otherwise
// return the error to may already be the same client that dropped the
// connection. spyAuditSink here always fails, regardless of ctx — the point
// of THIS test is the operator-visible signal, not ctx-sensitivity, which
// the tests above already cover.
func TestRun_ReservedDispatchAuditWriteFailureIsLoggedForAnOperator(t *testing.T) {
	store := newMemApprovals()
	reg := registry.NewInMemory()
	if _, err := reg.Upsert(registry.Report{NodeID: "node-a"}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	disp := &spyDispatcher{jobID: "job-audit-fail"}
	auditSink := &spyAuditSink{err: errors.New("boom: audit store unavailable")}
	s := build(t, seams{reg: reg,
		authz: &spyAuthorizer{}, cap: &spyCapChecker{},
		audit: auditSink, freeze: &fakeFreezeStore{},
		gate: gateEverything(t, 1), approvals: store, approvalAuthz: &spyApprovalAuthorizer{},
		now: func() time.Time { return apNow },
	})
	s.disp = disp
	p := Principal{AccountID: "acct-g", Account: "gleipnir-prod"}

	_, err := s.Run(context.Background(), p, Selector{}, mutateAct())
	var parked *ParkedError
	if !errors.As(err, &parked) {
		t.Fatalf("first Run: err = %v, want a park", err)
	}
	store.approve(t, parked.RequestID, "acct-ana", "ana", apNow.Add(time.Minute))

	buf := captureDefaultLog(t)
	_, err = s.Run(context.Background(), p, Selector{}, mutateAct())
	if err == nil {
		t.Fatal("release Run with a failing audit sink: want an error")
	}
	if !disp.called {
		t.Fatal("dispatcher was never called on release")
	}
	logged := buf.String()
	if !strings.Contains(logged, "reserved-path dispatch audit write failed") || !strings.Contains(logged, "incomplete or missing audit record") {
		t.Errorf("operator log did not record the reserved-path audit write failure; log:\n%s", logged)
	}
	if !strings.Contains(logged, "job-audit-fail") {
		t.Errorf("operator log did not name the Job the failed audit write was for; log:\n%s", logged)
	}
}
