package capability

import (
	"context"
	"errors"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/jobs"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/registry"
)

// spyAuditQuery is a spy capability.AuditQuery, in the style of
// service_test.go's spyAuditSink.
type spyAuditQuery struct {
	queryCalled bool
	gotFilter   AuditFilter
	gotPage     PageRequest
	queryResult AuditPage
	queryErr    error

	countsCalled bool
	gotBucket    time.Duration
	countsResult []PrincipalBucket
	countsErr    error

	reachCalled bool
	reachResult Reach
	reachErr    error
}

func (s *spyAuditQuery) QueryAudit(_ context.Context, f AuditFilter, page PageRequest) (AuditPage, error) {
	s.queryCalled = true
	s.gotFilter = f
	s.gotPage = page
	return s.queryResult, s.queryErr
}

func (s *spyAuditQuery) AuditCounts(_ context.Context, f AuditFilter, bucket time.Duration) ([]PrincipalBucket, error) {
	s.countsCalled = true
	s.gotFilter = f
	s.gotBucket = bucket
	return s.countsResult, s.countsErr
}

func (s *spyAuditQuery) AuditReach(_ context.Context, f AuditFilter) (Reach, error) {
	s.reachCalled = true
	s.gotFilter = f
	return s.reachResult, s.reachErr
}

// spyJobQuery is a spy capability.JobQuery.
type spyJobQuery struct {
	jobsCalled   bool
	gotJobFilter JobFilter
	gotJobPage   PageRequest
	jobsResult   JobPage
	jobsErr      error

	tasksCalled   bool
	gotTaskFilter TaskFilter
	gotTaskPage   PageRequest
	tasksResult   TaskPage
	tasksErr      error
}

func (s *spyJobQuery) QueryJobs(_ context.Context, f JobFilter, page PageRequest) (JobPage, error) {
	s.jobsCalled = true
	s.gotJobFilter = f
	s.gotJobPage = page
	return s.jobsResult, s.jobsErr
}

func (s *spyJobQuery) QueryTasks(_ context.Context, f TaskFilter, page PageRequest) (TaskPage, error) {
	s.tasksCalled = true
	s.gotTaskFilter = f
	s.gotTaskPage = page
	return s.tasksResult, s.tasksErr
}

// readLaneFixture builds a Service wired with spy read-lane seams and a spy
// AuditSink, for the tests below.
func readLaneFixture(t *testing.T) (*testSvc, *spyAuditQuery, *spyJobQuery, *spyAuditSink) {
	t.Helper()
	reg := registry.NewInMemory()
	auditQ := &spyAuditQuery{}
	jobQ := &spyJobQuery{}
	audit := &spyAuditSink{}
	svc := build(t, seams{reg: reg, auditQ: auditQ, jobQ: jobQ, audit: audit})
	return svc, auditQ, jobQ, audit
}

var testPrincipal = Principal{AccountID: "acct-1", Account: "gleipnir", Role: "operator"}

// validAggWindow is a bounded Since/Until pair satisfying AuditFilter.
// validateWindow (F1, #441 cycle-2 security review): AuditCounts and
// AuditReach reject AuditFilter{} outright now, so every test exercising
// them for reasons OTHER than that specific rejection needs a filter that
// clears it.
var validAggWindow = AuditFilter{
	Since: time.Date(2026, 8, 20, 11, 0, 0, 0, time.UTC),
	Until: time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC),
}

// TestReadLane_RecordsReadBeforeQuerying is acceptance line 23 (ADR-0025
// fail-closed): every read-lane method records exactly one RecordRead with
// the right tool name, and does so BEFORE the underlying query seam is
// reached — proven by making RecordRead fail and asserting the query spy was
// never called.
func TestReadLane_RecordsReadBeforeQuerying(t *testing.T) {
	cases := []struct {
		name string
		tool string
		call func(svc *testSvc) error
		spy  func(auditQ *spyAuditQuery, jobQ *spyJobQuery) bool // returns whether the underlying seam was called
	}{
		{
			"QueryAudit", toolQueryAudit,
			func(svc *testSvc) error {
				_, err := svc.QueryAudit(context.Background(), testPrincipal, AuditFilter{}, PageRequest{})
				return err
			},
			func(auditQ *spyAuditQuery, _ *spyJobQuery) bool { return auditQ.queryCalled },
		},
		{
			"AuditCounts", toolAuditCounts,
			func(svc *testSvc) error {
				_, err := svc.AuditCounts(context.Background(), testPrincipal, validAggWindow, time.Hour)
				return err
			},
			func(auditQ *spyAuditQuery, _ *spyJobQuery) bool { return auditQ.countsCalled },
		},
		{
			"AuditReach", toolAuditReach,
			func(svc *testSvc) error {
				_, err := svc.AuditReach(context.Background(), testPrincipal, validAggWindow)
				return err
			},
			func(auditQ *spyAuditQuery, _ *spyJobQuery) bool { return auditQ.reachCalled },
		},
		{
			"QueryJobs", toolQueryJobs,
			func(svc *testSvc) error {
				_, err := svc.QueryJobs(context.Background(), testPrincipal, JobFilter{}, PageRequest{})
				return err
			},
			func(_ *spyAuditQuery, jobQ *spyJobQuery) bool { return jobQ.jobsCalled },
		},
		{
			"QueryTasks", toolQueryTasks,
			func(svc *testSvc) error {
				_, err := svc.QueryTasks(context.Background(), testPrincipal, TaskFilter{JobID: "job-1"}, PageRequest{})
				return err
			},
			func(_ *spyAuditQuery, jobQ *spyJobQuery) bool { return jobQ.tasksCalled },
		},
	}

	for _, c := range cases {
		t.Run(c.name+"/success", func(t *testing.T) {
			svc, auditQ, jobQ, audit := readLaneFixture(t)
			if err := c.call(svc); err != nil {
				t.Fatalf("%s: %v", c.name, err)
			}
			if len(audit.readCalls) != 1 {
				t.Fatalf("RecordRead called %d times, want 1", len(audit.readCalls))
			}
			if got := audit.readCalls[0].Tool; got != c.tool {
				t.Errorf("tool = %q, want %q", got, c.tool)
			}
			if audit.readCalls[0].Principal != testPrincipal {
				t.Errorf("RecordRead principal = %+v, want %+v", audit.readCalls[0].Principal, testPrincipal)
			}
			if !c.spy(auditQ, jobQ) {
				t.Errorf("%s: underlying query seam was never called", c.name)
			}
		})

		t.Run(c.name+"/failClosedOnUnauditableRead", func(t *testing.T) {
			svc, auditQ, jobQ, audit := readLaneFixture(t)
			audit.err = errors.New("audit write failed")
			if err := c.call(svc); err == nil {
				t.Fatalf("%s: err = nil, want the audit write failure to propagate", c.name)
			}
			if len(audit.readCalls) != 1 {
				t.Fatalf("RecordRead called %d times, want 1 (attempted even though it failed)", len(audit.readCalls))
			}
			if c.spy(auditQ, jobQ) {
				t.Errorf("%s: underlying query seam was called despite RecordRead failing — not fail-closed", c.name)
			}
		})
	}
}

// TestReadLane_FilterValidation covers Until-before-Since on every filter
// type, and TaskFilter's required JobID.
func TestReadLane_FilterValidation(t *testing.T) {
	svc, _, _, _ := readLaneFixture(t)
	ctx := context.Background()
	since := time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)
	until := since.Add(-time.Hour)

	if _, err := svc.QueryAudit(ctx, testPrincipal, AuditFilter{Since: since, Until: until}, PageRequest{}); !errors.Is(err, ErrInvalidFilter) {
		t.Errorf("QueryAudit with Until before Since: err = %v, want ErrInvalidFilter", err)
	}
	if _, err := svc.AuditCounts(ctx, testPrincipal, AuditFilter{Since: since, Until: until}, time.Hour); !errors.Is(err, ErrInvalidFilter) {
		t.Errorf("AuditCounts with Until before Since: err = %v, want ErrInvalidFilter", err)
	}
	if _, err := svc.AuditReach(ctx, testPrincipal, AuditFilter{Since: since, Until: until}); !errors.Is(err, ErrInvalidFilter) {
		t.Errorf("AuditReach with Until before Since: err = %v, want ErrInvalidFilter", err)
	}
	if _, err := svc.QueryJobs(ctx, testPrincipal, JobFilter{Since: since, Until: until}, PageRequest{}); !errors.Is(err, ErrInvalidFilter) {
		t.Errorf("QueryJobs with Until before Since: err = %v, want ErrInvalidFilter", err)
	}
	if _, err := svc.QueryTasks(ctx, testPrincipal, TaskFilter{}, PageRequest{}); !errors.Is(err, ErrInvalidFilter) {
		t.Errorf("QueryTasks with no JobID: err = %v, want ErrInvalidFilter", err)
	}

	// A valid filter with an arg prefix but no arg key is refused too.
	if _, err := svc.QueryAudit(ctx, testPrincipal, AuditFilter{ArgValuePrefix: "/etc"}, PageRequest{}); !errors.Is(err, ErrInvalidFilter) {
		t.Errorf("QueryAudit with ArgValuePrefix but no ArgKey: err = %v, want ErrInvalidFilter", err)
	}
}

// TestReadLane_LimitClamping covers 0 -> DefaultPageSize, over-max ->
// clamped, and Page.Limit reporting the effective value.
func TestReadLane_LimitClamping(t *testing.T) {
	svc, auditQ, jobQ, _ := readLaneFixture(t)
	ctx := context.Background()

	cases := []struct {
		name  string
		limit int
		want  int
	}{
		{"zero", 0, DefaultPageSize},
		{"negative", -5, DefaultPageSize},
		{"underMax", 10, 10},
		{"overMax", MaxPageSize + 100, MaxPageSize},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, err := svc.QueryAudit(ctx, testPrincipal, AuditFilter{}, PageRequest{Limit: c.limit}); err != nil {
				t.Fatalf("QueryAudit: %v", err)
			}
			if auditQ.gotPage.Limit != c.want {
				t.Errorf("QueryAudit effective limit = %d, want %d", auditQ.gotPage.Limit, c.want)
			}

			if _, err := svc.QueryJobs(ctx, testPrincipal, JobFilter{}, PageRequest{Limit: c.limit}); err != nil {
				t.Fatalf("QueryJobs: %v", err)
			}
			if jobQ.gotJobPage.Limit != c.want {
				t.Errorf("QueryJobs effective limit = %d, want %d", jobQ.gotJobPage.Limit, c.want)
			}
		})
	}
}

// TestReadLane_QueryTasksStripsReadClassOutput covers D3: TaskRow output is
// blanked for every Task EXCEPT one whose RiskClass is explicitly
// jobs.RiskClassMutate, and preserved for that one — including
// RiskClassUnspecified, which F3 (#441 cycle-2 security review) requires to
// strip rather than retain. Before the fix, the condition was
// "== RiskClassRead", which left RiskClassUnspecified's output untouched; a
// build that regresses to that condition fails the "unspecified" case below.
func TestReadLane_QueryTasksStripsReadClassOutput(t *testing.T) {
	svc, _, jobQ, _ := readLaneFixture(t)
	jobQ.tasksResult = TaskPage{Tasks: []TaskRow{
		{TaskID: "t-read", RiskClass: jobs.RiskClassRead, Stdout: []byte("secret output"), Stderr: []byte("secret err")},
		{TaskID: "t-mutate", RiskClass: jobs.RiskClassMutate, Stdout: []byte("mutate out"), Stderr: []byte("mutate err")},
		{TaskID: "t-unspecified", RiskClass: jobs.RiskClassUnspecified, Stdout: []byte("unspecified output"), Stderr: []byte("unspecified err")},
	}}

	page, err := svc.QueryTasks(context.Background(), testPrincipal, TaskFilter{JobID: "job-1"}, PageRequest{})
	if err != nil {
		t.Fatalf("QueryTasks: %v", err)
	}
	if len(page.Tasks) != 3 {
		t.Fatalf("Tasks = %d, want 3", len(page.Tasks))
	}
	for _, row := range page.Tasks {
		switch row.TaskID {
		case "t-read", "t-unspecified":
			if row.Stdout != nil || row.Stderr != nil {
				t.Errorf("non-mutate-class Task %s kept output: stdout=%q stderr=%q", row.TaskID, row.Stdout, row.Stderr)
			}
		case "t-mutate":
			if string(row.Stdout) != "mutate out" || string(row.Stderr) != "mutate err" {
				t.Errorf("mutate-class Task %s output altered: stdout=%q stderr=%q", row.TaskID, row.Stdout, row.Stderr)
			}
		}
	}
}

// TestReadLane_NilSeamReturnsError asserts a Service built without
// WithQueries returns ErrQueriesUnavailable — never an empty page, which
// would be a claim ("there is nothing here") rather than an absence.
func TestReadLane_NilSeamReturnsError(t *testing.T) {
	svc := build(t, seams{reg: registry.NewInMemory()})
	ctx := context.Background()

	if _, err := svc.QueryAudit(ctx, testPrincipal, AuditFilter{}, PageRequest{}); !errors.Is(err, ErrQueriesUnavailable) {
		t.Errorf("QueryAudit: err = %v, want ErrQueriesUnavailable", err)
	}
	if _, err := svc.AuditCounts(ctx, testPrincipal, AuditFilter{}, time.Hour); !errors.Is(err, ErrQueriesUnavailable) {
		t.Errorf("AuditCounts: err = %v, want ErrQueriesUnavailable", err)
	}
	if _, err := svc.AuditReach(ctx, testPrincipal, AuditFilter{}); !errors.Is(err, ErrQueriesUnavailable) {
		t.Errorf("AuditReach: err = %v, want ErrQueriesUnavailable", err)
	}
	if _, err := svc.QueryJobs(ctx, testPrincipal, JobFilter{}, PageRequest{}); !errors.Is(err, ErrQueriesUnavailable) {
		t.Errorf("QueryJobs: err = %v, want ErrQueriesUnavailable", err)
	}
	if _, err := svc.QueryTasks(ctx, testPrincipal, TaskFilter{JobID: "job-1"}, PageRequest{}); !errors.Is(err, ErrQueriesUnavailable) {
		t.Errorf("QueryTasks: err = %v, want ErrQueriesUnavailable", err)
	}
}

// TestReadLane_QueryJobsPassesOrderAndCountThrough (#795): the direction and
// the count request reach the seam untouched, and they ride the ONE read the
// lane records — the count is part of that read, not a second.
func TestReadLane_QueryJobsPassesOrderAndCountThrough(t *testing.T) {
	svc, _, jobQ, audit := readLaneFixture(t)
	jobQ.jobsResult = JobPage{Matching: 12}
	running := jobs.JobStateRunning
	f := JobFilter{State: &running, Order: jobs.JobOrderOldestFirst, CountMatching: true}

	page, err := svc.QueryJobs(context.Background(), testPrincipal, f, PageRequest{Limit: 5})
	if err != nil {
		t.Fatalf("QueryJobs: %v", err)
	}
	if jobQ.gotJobFilter.Order != jobs.JobOrderOldestFirst || !jobQ.gotJobFilter.CountMatching {
		t.Errorf("the seam was handed %+v, want Order and CountMatching unchanged", jobQ.gotJobFilter)
	}
	if page.Matching != 12 {
		t.Errorf("Matching = %d, want the seam's 12 passed back", page.Matching)
	}
	if len(audit.readCalls) != 1 || audit.readCalls[0].Tool != toolQueryJobs {
		t.Errorf("RecordRead calls = %+v, want exactly one query_jobs", audit.readCalls)
	}
}

func TestJobFilter_RefusesAnUnknownOrder(t *testing.T) {
	svc, _, jobQ, audit := readLaneFixture(t)

	_, err := svc.QueryJobs(context.Background(), testPrincipal, JobFilter{Order: jobs.JobOrder(99)}, PageRequest{})
	if !errors.Is(err, ErrInvalidFilter) {
		t.Fatalf("an unknown order: err = %v, want ErrInvalidFilter", err)
	}
	if jobQ.jobsCalled || len(audit.readCalls) != 0 {
		t.Errorf("a refused filter reached the seam (%v) or was recorded (%d)", jobQ.jobsCalled, len(audit.readCalls))
	}
}

// The read record says what was asked. A filter that asks for neither the
// order nor the count records exactly what it did before #795.
func TestJobFilter_SummaryRecordsOrderAndCountOnlyWhenAsked(t *testing.T) {
	running := jobs.JobStateRunning
	if got := (JobFilter{State: &running, RequesterAccountID: "acct-1"}).summary(); got != "state=running;requester=acct-1" {
		t.Errorf("a default filter's summary = %q, want it unchanged by #795", got)
	}
	got := JobFilter{State: &running, Order: jobs.JobOrderOldestFirst, CountMatching: true}.summary()
	if got != "state=running;order=oldest_first;count=matching" {
		t.Errorf("summary = %q, want the order and count named", got)
	}
}

// TestReadLane_AuditCounts_RejectsUnboundedFilter is F1's headline case
// (#441 cycle-2 security review): AuditFilter{} — a legal match-everything
// filter for QueryAudit — must be refused by AuditCounts before it ever
// reaches the seam or gets recorded as an attempted read, since AuditCounts
// has no LIMIT to fall back on.
func TestReadLane_AuditCounts_RejectsUnboundedFilter(t *testing.T) {
	svc, auditQ, _, audit := readLaneFixture(t)

	_, err := svc.AuditCounts(context.Background(), testPrincipal, AuditFilter{}, time.Hour)
	if !errors.Is(err, ErrInvalidFilter) {
		t.Fatalf("AuditCounts(AuditFilter{}): err = %v, want ErrInvalidFilter", err)
	}
	if auditQ.countsCalled {
		t.Error("AuditCounts: underlying seam was called for an unbounded filter")
	}
	if len(audit.readCalls) != 0 {
		t.Errorf("AuditCounts: RecordRead called %d times for a refused filter, want 0", len(audit.readCalls))
	}
}

// TestReadLane_AuditReach_RejectsUnboundedFilter is AuditCounts' sibling
// case: AuditReach has no LIMIT either (F1/F6, #441 cycle-2 security
// review), so it is bound by the same required window.
func TestReadLane_AuditReach_RejectsUnboundedFilter(t *testing.T) {
	svc, auditQ, _, audit := readLaneFixture(t)

	_, err := svc.AuditReach(context.Background(), testPrincipal, AuditFilter{})
	if !errors.Is(err, ErrInvalidFilter) {
		t.Fatalf("AuditReach(AuditFilter{}): err = %v, want ErrInvalidFilter", err)
	}
	if auditQ.reachCalled {
		t.Error("AuditReach: underlying seam was called for an unbounded filter")
	}
	if len(audit.readCalls) != 0 {
		t.Errorf("AuditReach: RecordRead called %d times for a refused filter, want 0", len(audit.readCalls))
	}
}

// TestReadLane_AuditCounts_ClampsBucket is F1: a caller-chosen bucket below
// MinAuditBucket reaches the seam floored to MinAuditBucket rather than
// being refused — the same "clamp, don't reject" convention as Limit.
func TestReadLane_AuditCounts_ClampsBucket(t *testing.T) {
	svc, auditQ, _, _ := readLaneFixture(t)

	if _, err := svc.AuditCounts(context.Background(), testPrincipal, validAggWindow, time.Second); err != nil {
		t.Fatalf("AuditCounts: %v", err)
	}
	if !auditQ.countsCalled {
		t.Fatal("AuditCounts: underlying seam was never called")
	}
	if auditQ.gotBucket != MinAuditBucket {
		t.Errorf("bucket reaching the seam = %s, want MinAuditBucket (%s)", auditQ.gotBucket, MinAuditBucket)
	}

	// A bucket already at or above the floor passes through unchanged.
	if _, err := svc.AuditCounts(context.Background(), testPrincipal, validAggWindow, time.Hour); err != nil {
		t.Fatalf("AuditCounts: %v", err)
	}
	if auditQ.gotBucket != time.Hour {
		t.Errorf("bucket reaching the seam = %s, want 1h (unchanged)", auditQ.gotBucket)
	}
}

// TestWithQueriesRefusesNoopAuditSink is F5 (#441 cycle-2 security review):
// a Service built with WithQueries but no WithAuditSink must panic at
// construction, the same class of composition-root guard
// TestWithExecutionRefusesDefaultSeams asserts for a real dispatcher —
// otherwise every trail query is answered while recording nothing, exactly
// the "unauditable read succeeded" state ADR-0025 forbids.
func TestWithQueriesRefusesNoopAuditSink(t *testing.T) {
	reg := registry.NewInMemory()
	auditQ := &spyAuditQuery{}
	jobQ := &spyJobQuery{}

	defer func() {
		if recover() == nil {
			t.Fatal("New(reg, WithQueries(...)) without a real AuditSink should panic")
		}
	}()
	New(reg, WithQueries(auditQ, jobQ))
}

// TestWithQueriesAcceptsRealAuditSink is the positive twin of
// TestWithQueriesRefusesNoopAuditSink: WithQueries plus a real (spy)
// AuditSink constructs successfully regardless of the two Options' order.
func TestWithQueriesAcceptsRealAuditSink(t *testing.T) {
	reg := registry.NewInMemory()
	auditQ := &spyAuditQuery{}
	jobQ := &spyJobQuery{}
	audit := &spyAuditSink{}

	// WithAuditSink BEFORE WithQueries.
	New(reg, WithAuditSink(audit), WithQueries(auditQ, jobQ))
	// WithAuditSink AFTER WithQueries — the guard must not depend on order.
	New(reg, WithQueries(auditQ, jobQ), WithAuditSink(audit))
}

// TestReadLane_JobFilterCarriesOneJob is the Job-detail screen's read (#423):
// the filter reaches the seam intact, and the read record it writes names the
// Job on its own column — so "who looked at this Job" is answerable by the
// same lookup every other Job question uses, not by parsing a summary string.
func TestReadLane_JobFilterCarriesOneJob(t *testing.T) {
	svc, _, jobQ, sink := readLaneFixture(t)

	if _, err := svc.QueryJobs(context.Background(), testPrincipal, JobFilter{JobID: "job-1"}, PageRequest{Limit: 1}); err != nil {
		t.Fatalf("QueryJobs: %v", err)
	}
	if jobQ.gotJobFilter.JobID != "job-1" {
		t.Errorf("the seam got JobID %q, want job-1", jobQ.gotJobFilter.JobID)
	}
	if len(sink.readCalls) != 1 {
		t.Fatalf("got %d read records, want 1", len(sink.readCalls))
	}
	if got := sink.readCalls[0].JobID; got != "job-1" {
		t.Errorf("the read record's JobID = %q, want job-1", got)
	}
	if got := sink.readCalls[0].Selector; got != "job=job-1" {
		t.Errorf("the read record's selector = %q, want job=job-1", got)
	}
}

// TestReadLane_OverLongJobIDIsRefused bounds a caller-controlled value that
// lands in the append-only trail, on both Job filters — the same reasoning
// AuditFilter.validate bounds Kinds and Operations on.
func TestReadLane_OverLongJobIDIsRefused(t *testing.T) {
	svc, _, jobQ, _ := readLaneFixture(t)
	long := strings.Repeat("a", maxJobIDBytes+1)

	if _, err := svc.QueryJobs(context.Background(), testPrincipal, JobFilter{JobID: long}, PageRequest{}); !errors.Is(err, ErrInvalidFilter) {
		t.Errorf("QueryJobs with a %d-byte job id = %v, want ErrInvalidFilter", len(long), err)
	}
	if _, err := svc.QueryTasks(context.Background(), testPrincipal, TaskFilter{JobID: long}, PageRequest{}); !errors.Is(err, ErrInvalidFilter) {
		t.Errorf("QueryTasks with a %d-byte job id = %v, want ErrInvalidFilter", len(long), err)
	}
	if jobQ.jobsCalled || jobQ.tasksCalled {
		t.Error("a refused filter still reached the query seam")
	}
}

// TestReadLane_EmptyJobFilterIsEveryJob pins the shape the Job-detail screen
// depends on NOT having: an empty JobID must remain "every Job" (the Job
// list's own query), so a screen that means "one Job" has to say so. The
// guard is against the reverse reading — a future validate() that treated ""
// as a match-nothing sentinel would silently empty the Job list.
func TestReadLane_EmptyJobFilterIsEveryJob(t *testing.T) {
	svc, _, jobQ, _ := readLaneFixture(t)
	if _, err := svc.QueryJobs(context.Background(), testPrincipal, JobFilter{}, PageRequest{}); err != nil {
		t.Fatalf("QueryJobs: %v", err)
	}
	if !jobQ.jobsCalled || jobQ.gotJobFilter.JobID != "" {
		t.Errorf("an unfiltered Job query reached the seam as %+v", jobQ.gotJobFilter)
	}
}

// TestReadLane_FilterSummaryCannotForgeItsOwnStructure — the read record's
// selector is evidence, and a caller-controlled field that can write ';' and
// '=' into it forges a filter no human reading the trail could tell from a
// real one. stripControl removes control characters and nothing else, so the
// separators are escaped here.
func TestReadLane_FilterSummaryCannotForgeItsOwnStructure(t *testing.T) {
	svc, _, _, sink := readLaneFixture(t)
	forged := "x;requester=admin;op=raw_exec"

	if _, err := svc.QueryJobs(context.Background(), testPrincipal, JobFilter{JobID: forged}, PageRequest{}); err != nil {
		t.Fatalf("QueryJobs: %v", err)
	}
	got := sink.readCalls[0].Selector
	if strings.Contains(got, ";requester=") {
		t.Errorf("the recorded selector %q reads as a multi-field filter the caller never asked for", got)
	}
	if want := `job=x\;requester\=admin\;op\=raw_exec`; got != want {
		t.Errorf("selector = %q, want %q", got, want)
	}
}

// TestReadLane_AuditFilterJobIDIsBoundedToo — all three filters that carry a
// Job ID reach the append-only trail with it, this one in the read record's
// job_id COLUMN. A bound applied to two of the three is a bound on its way
// out.
func TestReadLane_AuditFilterJobIDIsBoundedToo(t *testing.T) {
	svc, auditQ, _, _ := readLaneFixture(t)
	long := strings.Repeat("a", maxJobIDBytes+1)

	if _, err := svc.QueryAudit(context.Background(), testPrincipal, AuditFilter{JobID: long}, PageRequest{}); !errors.Is(err, ErrInvalidFilter) {
		t.Errorf("QueryAudit with a %d-byte job id = %v, want ErrInvalidFilter", len(long), err)
	}
	if auditQ.queryCalled {
		t.Error("a refused filter still reached the trail seam")
	}
}

// ---------------------------------------------------------------------------
// RecordEventSubscription (#539). A1-A6 below, over readLaneFixture's real
// *Service and spyAuditSink — the lane half of the mutation matrix;
// console/events_audit_test.go's B1-B7 are the route half.
// ---------------------------------------------------------------------------

// A1: the record names the right tool, the right selector, and an EMPTY
// aim — a subscription targets no Node and no Job.
//
// MUT change toolWatchEvents's value -> the tool assertion goes red.
// MUT pass a nodeID through to recordQueryRead -> the aim assertion goes red.
func TestRecordEventSubscription_NamesToolSelectorAndEmptyAim(t *testing.T) {
	svc, _, _, sink := readLaneFixture(t)

	names, err := svc.RecordEventSubscription(context.Background(), testPrincipal, []string{"job"}, false)
	if err != nil {
		t.Fatalf("RecordEventSubscription: %v", err)
	}
	if len(names) != 1 || names[0] != "job" {
		t.Errorf("returned names = %v, want [\"job\"] — the caller (console/events.go) builds "+
			"Subscribe's argument from exactly this return value", names)
	}
	if len(sink.readCalls) != 1 {
		t.Fatalf("wrote %d read calls, want 1", len(sink.readCalls))
	}
	got := sink.readCalls[0]
	// A literal, not toolWatchEvents: the tool name lands in the append-only
	// trail forever, so this test pins the STRING, not whatever the constant
	// happens to hold — comparing against the constant would make a
	// mutation of its value invisible to this test.
	if got.Tool != "watch_events" {
		t.Errorf("Tool = %q, want %q", got.Tool, "watch_events")
	}
	if got.Selector != "kinds=job" {
		t.Errorf("Selector = %q, want %q", got.Selector, "kinds=job")
	}
	if got.NodeID != "" || got.JobID != "" {
		t.Errorf("NodeID = %q, JobID = %q, want both empty — a subscription targets no Node and "+
			"no Job", got.NodeID, got.JobID)
	}
}

// A2: three orderings and a duplicate all record the identical selector —
// canonicalisation (sort + dedup) is what makes the trail groupable by
// subscription shape.
//
// MUT delete the sort in canonicalEventKinds -> this test goes red for the
// reordered cases. MUT delete the dedup -> it goes red for the duplicated
// one, and its selector would additionally exceed what a deduped one should.
func TestRecordEventSubscription_CanonicalFormIsOrderAndDuplicateInsensitive(t *testing.T) {
	for _, kinds := range [][]string{
		{"job", "enrollment"},
		{"enrollment", "job"},
		{"job", "job", "enrollment", "job"},
	} {
		svc, _, _, sink := readLaneFixture(t)
		names, err := svc.RecordEventSubscription(context.Background(), testPrincipal, kinds, false)
		if err != nil {
			t.Fatalf("RecordEventSubscription(%v): %v", kinds, err)
		}
		if got := sink.readCalls[0].Selector; got != "kinds=enrollment,job" {
			t.Errorf("RecordEventSubscription(%v) recorded %q, want %q", kinds, got, "kinds=enrollment,job")
		}
		if want := []string{"enrollment", "job"}; !slices.Equal(names, want) {
			t.Errorf("RecordEventSubscription(%v) returned %v, want %v — the canonical form, so a "+
				"caller building Subscribe's argument from it cannot see the caller's own order or "+
				"duplicates", kinds, names, want)
		}
	}
}

// A3: a resumed subscription's selector carries resume=yes, and ONLY a
// resumed one does.
//
// MUT drop the resume field from eventSubscriptionSummary -> this test goes
// red; no other A-test asserts on the resume field.
func TestRecordEventSubscription_ResumedRecordsTheResumeField(t *testing.T) {
	svc, _, _, sink := readLaneFixture(t)

	if _, err := svc.RecordEventSubscription(context.Background(), testPrincipal, []string{"job"}, true); err != nil {
		t.Fatalf("RecordEventSubscription: %v", err)
	}
	if got := sink.readCalls[0].Selector; got != "kinds=job;resume=yes" {
		t.Errorf("Selector = %q, want %q", got, "kinds=job;resume=yes")
	}
}

// A4: the bound is on the DISTINCT, canonicalised set, not on the raw
// caller-supplied slice — bounding the raw slice first would turn
// ?kinds=job,job,... into a refusal for a request this route accepts today.
//
// MUT remove the count/length bound entirely -> the first half (33 names,
// a 65-byte name) goes red, because both would now be accepted and
// recorded.
// MUT bound the raw slice's LENGTH before dedup, instead of the deduped
// count -> the second half (5,000 copies of "job") goes red, because a
// pre-dedup bound of 32 would refuse 5,000 raw entries that canonicalise to
// exactly one distinct name.
func TestRecordEventSubscription_BoundsTheCanonicalSetNotTheRawSlice(t *testing.T) {
	svc, _, _, sink := readLaneFixture(t)

	tooManyDistinct := make([]string, 0, maxEventKinds+1)
	for i := 0; i <= maxEventKinds; i++ {
		tooManyDistinct = append(tooManyDistinct, "kind-"+strconv.Itoa(i))
	}
	if _, err := svc.RecordEventSubscription(context.Background(), testPrincipal, tooManyDistinct, false); !errors.Is(err, ErrInvalidFilter) {
		t.Errorf("%d distinct kinds = %v, want ErrInvalidFilter", len(tooManyDistinct), err)
	}

	tooLong := []string{strings.Repeat("k", maxEventKindBytes+1)}
	if _, err := svc.RecordEventSubscription(context.Background(), testPrincipal, tooLong, false); !errors.Is(err, ErrInvalidFilter) {
		t.Errorf("a %d-byte kind name = %v, want ErrInvalidFilter", len(tooLong[0]), err)
	}
	if len(sink.readCalls) != 0 {
		t.Fatalf("a refused subscription still wrote %d read records, want 0", len(sink.readCalls))
	}

	repeated := make([]string, 5000)
	for i := range repeated {
		repeated[i] = "job"
	}
	names, err := svc.RecordEventSubscription(context.Background(), testPrincipal, repeated, false)
	if err != nil {
		t.Fatalf("5,000 copies of one legal kind = %v, want it accepted — the allowlist bounds the "+
			"ALPHABET, not repetition of a legal name", err)
	}
	if len(sink.readCalls) != 1 || sink.readCalls[0].Selector != "kinds=job" {
		t.Fatalf("5,000 copies of \"job\" recorded %+v, want one record of kinds=job", sink.readCalls)
	}
	if !slices.Equal(names, []string{"job"}) {
		t.Errorf("5,000 copies of \"job\" returned %v, want [\"job\"]", names)
	}
}

// A4b: bounds that are each individually legal do not compose into a
// selector filterSummary.String would silently truncate — #539 fix round,
// Finding 2. canonicalEventKinds sorts, so a silent truncation would drop
// whatever sorts LAST, which is exactly where a name like "tool_call" would
// land relative to "enrollment" and "job".
//
// MUT delete the wouldTruncate check in canonicalEventKinds -> this test
// goes red, because the call would then succeed and record a selector
// filterSummary.String had already shortened without saying so.
func TestRecordEventSubscription_RefusesASelectorThatWouldTruncate(t *testing.T) {
	svc, _, _, sink := readLaneFixture(t)

	// Five names, each individually legal (<= maxEventKindBytes), five
	// distinct names (<= maxEventKinds) — but joined, comfortably over
	// maxFilterSummaryBytes (256).
	kinds := make([]string, 5)
	for i := range kinds {
		kinds[i] = strings.Repeat(string(rune('a'+i)), maxEventKindBytes)
	}
	if _, err := svc.RecordEventSubscription(context.Background(), testPrincipal, kinds, false); !errors.Is(err, ErrInvalidFilter) {
		t.Fatalf("a selector that would exceed %d bytes = %v, want ErrInvalidFilter", maxFilterSummaryBytes, err)
	}
	if len(sink.readCalls) != 0 {
		t.Fatalf("a refused subscription still wrote %d read records, want 0", len(sink.readCalls))
	}
}

// A5: a sink that refuses to write refuses the subscription, and the
// original cause is still reachable underneath ErrReadUnaudited — the same
// two-sentinel shape every other read-lane method uses.
//
// MUT swallow the sink's error and return nil -> this test goes red.
func TestRecordEventSubscription_FailsClosedOnASinkError(t *testing.T) {
	reg := registry.NewInMemory()
	sinkErr := errors.New("trail is down")
	sink := &spyAuditSink{err: sinkErr}
	svc := build(t, seams{reg: reg, auditQ: &spyAuditQuery{}, jobQ: &spyJobQuery{}, audit: sink})

	names, err := svc.RecordEventSubscription(context.Background(), testPrincipal, []string{"job"}, false)
	if !errors.Is(err, ErrReadUnaudited) {
		t.Fatalf("err = %v, want ErrReadUnaudited", err)
	}
	if !errors.Is(err, sinkErr) {
		t.Errorf("err = %v, want the sink's own error still reachable underneath it", err)
	}
	if names != nil {
		t.Errorf("names = %v on a failed call, want nil — a caller must not have a kind list to "+
			"subscribe with when the record it goes with was never written", names)
	}
}

// A6: a Service with no real audit sink refuses rather than "recording"
// through noopAuditSink, which unconditionally returns nil — the exact
// unaudited-stream state this ticket exists to prevent. New(reg) alone (no
// WithQueries, no WithAuditSink) is the shape a caller could reach this
// method on: New's own fail-open guards trip on WithExecution or
// WithQueries, not on a bare event-subscription lane.
//
// MUT delete auditSinkPresent() from RecordEventSubscription -> this test
// goes red, because canonicalEventKinds would then run to completion and
// recordQueryRead would call noopAuditSink.RecordRead, which returns nil —
// RecordEventSubscription would report success on a Service that recorded
// nothing at all.
func TestRecordEventSubscription_RefusesOnTheNoopSink(t *testing.T) {
	reg := registry.NewInMemory()
	svc := build(t, seams{reg: reg})

	_, err := svc.RecordEventSubscription(context.Background(), testPrincipal, []string{"job"}, false)
	if !errors.Is(err, ErrReadUnaudited) {
		t.Fatalf("err = %v, want ErrReadUnaudited — a Service on the no-op sink must refuse rather "+
			"than silently open an unaudited stream", err)
	}
}
