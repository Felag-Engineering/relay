package capability

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/Felag-Engineering/relay/relay/internal/jobs"
)

// failKindSink forwards every record to the spy and fails the ones of one Kind,
// as a store that can write a dispatch's intent but not its outcome would.
type failKindSink struct {
	*spyAuditSink
	fail AuditKind
}

func (s failKindSink) Record(ctx context.Context, e AuditEntry) error {
	err := s.spyAuditSink.Record(ctx, e)
	if e.Kind == s.fail {
		return errors.New("audit store down")
	}
	return err
}

// recordOutcomeAuditFailureFails is a JobRepository whose
// RecordOutcomeAuditFailure always errors.
type recordOutcomeAuditFailureFails struct {
	jobs.JobRepository
	err error
}

func (r recordOutcomeAuditFailureFails) RecordOutcomeAuditFailure(context.Context, string, time.Time) error {
	return r.err
}

func getJob(t *testing.T, repo jobs.JobRepository, jobID string) jobs.Job {
	t.Helper()
	job, err := repo.GetJob(context.Background(), jobID)
	if err != nil {
		t.Fatalf("GetJob: %v", err)
	}
	return job
}

// haltingFx builds two Nodes that both fail a mutate Raw Exec at concurrency 1,
// so the Job halts, over an audit sink failing the given Kind.
func haltingFx(t *testing.T, audit AuditSink) (*testSvc, jobs.JobRepository) {
	t.Helper()
	jobsRepo, tasksRepo := testEngineStore(t)
	var log []string
	conduit := connectedConduit(&log, "node-0", "node-1")
	for _, n := range []string{"node-0", "node-1"} {
		conduit.results[n] = jobs.Result{Outcome: jobs.OutcomeFailure}
	}
	svc := build(t, seams{
		reg: seedNodes(t, 2), authz: &spyAuthorizer{}, cap: &spyCapChecker{}, audit: audit, freeze: &fakeFreezeStore{},
		jobsRepo: jobsRepo, tasksRepo: tasksRepo, conduit: conduit, settings: concurrencyOf(1),
	})
	return svc, jobsRepo
}

// Proves EX-66.
func TestStart_AFailedDispatchRecordIsRecordedOnTheJobBeforeDoneCloses(t *testing.T) {
	f := newStartFx(t, func(s *seams) {
		s.audit = failKindSink{spyAuditSink: &spyAuditSink{}, fail: AuditKindDispatch}
	})

	sj, err := f.svc.Start(context.Background(), alice, fleetSel, factsAct, StartOptions{})
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	waitClosed(t, sj.Done, "Done")

	if got := getJob(t, f.st.Jobs(), sj.JobID).OutcomeAuditFailedAt; got.IsZero() {
		t.Error("OutcomeAuditFailedAt is zero when Done closed, want the failure recorded")
	}
}

// Proves EX-66.
func TestRun_AFailedDispatchRecordIsRecordedOnTheJob(t *testing.T) {
	f := newStartFx(t, func(s *seams) {
		s.audit = failKindSink{spyAuditSink: &spyAuditSink{}, fail: AuditKindDispatch}
	})

	results, err := f.svc.Run(context.Background(), alice, fleetSel, factsAct)
	if err == nil || !strings.Contains(err.Error(), "record audit entry") {
		t.Fatalf("Run error = %v, want the audit failure beside the results", err)
	}
	if len(results) == 0 {
		t.Fatal("Run returned no results")
	}
	if got := getJob(t, f.st.Jobs(), results[0].JobID).OutcomeAuditFailedAt; got.IsZero() {
		t.Error("OutcomeAuditFailedAt is zero when Run returned, want the failure recorded")
	}
}

// Proves EX-66.
func TestStart_AFailedHaltRecordIsRecordedOnTheJobBeforeDoneCloses(t *testing.T) {
	spy := &spyAuditSink{}
	svc, jobsRepo := haltingFx(t, failKindSink{spyAuditSink: spy, fail: AuditKindJobHalt})
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := svc.Drain(ctx); err != nil {
			t.Errorf("background Jobs did not drain before the store closed: %v", err)
		}
	})

	sj, err := svc.Start(context.Background(), alice, webSelector(), rawExecTrue(), StartOptions{})
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	waitClosed(t, sj.Done, "Done")

	job := getJob(t, jobsRepo, sj.JobID)
	if !job.Halt.Halted() {
		t.Fatalf("Job.Halt = %+v, want a halted Job", job.Halt)
	}
	if job.OutcomeAuditFailedAt.IsZero() {
		t.Error("OutcomeAuditFailedAt is zero when Done closed, want the halt audit failure recorded")
	}
	if kinds := spy.kinds(); len(kinds) != 2 || kinds[0] != AuditKindDispatch {
		t.Errorf("audit kinds = %v, want the dispatch record written before the failing halt record", kinds)
	}
}

// Proves EX-66.
func TestRun_AFailedHaltRecordIsRecordedOnTheJob(t *testing.T) {
	spy := &spyAuditSink{}
	svc, jobsRepo := haltingFx(t, failKindSink{spyAuditSink: spy, fail: AuditKindJobHalt})

	results, err := svc.Run(context.Background(), alice, webSelector(), rawExecTrue())
	if err == nil || !strings.Contains(err.Error(), "job halt audit entry") {
		t.Fatalf("Run error = %v, want the halt audit failure", err)
	}
	job := getJob(t, jobsRepo, results[0].JobID)
	if !job.Halt.Halted() {
		t.Fatalf("Job.Halt = %+v, want a halted Job", job.Halt)
	}
	if job.OutcomeAuditFailedAt.IsZero() {
		t.Error("OutcomeAuditFailedAt is zero, want the halt audit failure recorded")
	}
	if kinds := spy.kinds(); len(kinds) != 2 || kinds[0] != AuditKindDispatch {
		t.Errorf("audit kinds = %v, want the dispatch record written before the failing halt record", kinds)
	}
}

func TestExecution_ASuccessfulOutcomeWriteRecordsNoFailure(t *testing.T) {
	f := newStartFx(t)

	results, err := f.svc.Run(context.Background(), alice, fleetSel, factsAct)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if got := getJob(t, f.st.Jobs(), results[0].JobID).OutcomeAuditFailedAt; !got.IsZero() {
		t.Errorf("OutcomeAuditFailedAt = %v, want zero when the outcome was audited", got)
	}
}

func TestExecution_AFailedFailureRecordLogsBothFailuresWithTheJobID(t *testing.T) {
	logBuf := captureDefaultLog(t)
	const argvToken = "/bin/secret-argv-token"
	jobsRepo, tasksRepo := testEngineStore(t)
	var log []string
	conduit := connectedConduit(&log, "node-0")
	svc := build(t, seams{
		reg: seedNodes(t, 1), authz: &spyAuthorizer{}, cap: &spyCapChecker{}, freeze: &fakeFreezeStore{},
		audit:     failKindSink{spyAuditSink: &spyAuditSink{}, fail: AuditKindDispatch},
		jobsRepo:  recordOutcomeAuditFailureFails{JobRepository: jobsRepo, err: errors.New("jobs store wedged")},
		tasksRepo: tasksRepo, conduit: conduit,
	})

	results, err := svc.Run(context.Background(), alice, webSelector(),
		jobs.Action{Kind: jobs.ActionRawExec, RawExecArgv: []string{argvToken}})
	if err == nil {
		t.Fatal("Run error = nil, want the audit failure")
	}
	out := logBuf.String()
	for _, want := range []string{results[0].JobID, "audit store down", "jobs store wedged", "job_id"} {
		if !strings.Contains(out, want) {
			t.Errorf("log lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, argvToken) {
		t.Errorf("log carries the Raw Exec argv:\n%s", out)
	}
}

// A dispatcher with no Job store has nowhere to record a failure: the audit error is still returned.
func TestExecution_ADispatcherWithoutAJobStoreStillReturnsTheAuditError(t *testing.T) {
	svc := build(t, seams{audit: failKindSink{spyAuditSink: &spyAuditSink{}, fail: AuditKindDispatch}})

	_, err := svc.account(context.Background(), alice, Selector{}, prep{act: factsAct},
		dispatchResult{jobID: "job-1"}, nil, false)
	if err == nil || !strings.Contains(err.Error(), "record audit entry") {
		t.Errorf("account error = %v, want the audit failure", err)
	}
}

// rawExecTrue is a Raw Exec as a caller submits it: the capability layer, not the
// caller, sets its risk class.
func rawExecTrue() jobs.Action {
	return jobs.Action{Kind: jobs.ActionRawExec, RawExecArgv: []string{"/bin/true"}}
}
