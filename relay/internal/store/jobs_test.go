package store

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"testing"
	"time"

	"github.com/Felag-Engineering/relay/relay/internal/accounts"
	"github.com/Felag-Engineering/relay/relay/internal/jobs"
)

// TestSingleStage_CodeGuard is acceptance #3's code-guard half: a second
// AddStage on the same Job returns jobs.ErrSingleStageOnly, even though the
// caller supplies a distinct stage_index — the code guard rejects a second
// Stage outright, it does not merely rely on the index being taken.
func TestSingleStage_CodeGuard(t *testing.T) {
	st, _ := openTestStore(t)
	ctx := context.Background()
	jobRepo := st.Jobs()

	if err := jobRepo.CreateJob(ctx, jobs.Job{ID: "job-1", CreatedAt: time.Now().UTC()}); err != nil {
		t.Fatalf("CreateJob: %v", err)
	}
	if err := jobRepo.AddStage(ctx, jobs.Stage{ID: "stage-1", JobID: "job-1", Index: 0}); err != nil {
		t.Fatalf("first AddStage: %v", err)
	}

	err := jobRepo.AddStage(ctx, jobs.Stage{ID: "stage-2", JobID: "job-1", Index: 0})
	if !errors.Is(err, jobs.ErrSingleStageOnly) {
		t.Errorf("second AddStage: want ErrSingleStageOnly, got %v", err)
	}

	stages, err := jobRepo.Stages(ctx, "job-1")
	if err != nil {
		t.Fatalf("Stages: %v", err)
	}
	if len(stages) != 1 || stages[0].ID != "stage-1" {
		t.Errorf("Stages after rejected second AddStage: got %#v, want [stage-1]", stages)
	}
}

// TestSingleStage_SchemaBackstop is acceptance #3's schema half: even
// bypassing the code guard with a raw second-stage INSERT (a distinct
// stage_id, but the same job_id and stage_index=0) must fail against the
// UNIQUE(job_id, stage_index) constraint. This proves the schema, not just
// the code, enforces one stage per Job.
func TestSingleStage_SchemaBackstop(t *testing.T) {
	st, _ := openTestStore(t)
	ctx := context.Background()
	jobRepo := st.Jobs()

	if err := jobRepo.CreateJob(ctx, jobs.Job{ID: "job-1", CreatedAt: time.Now().UTC()}); err != nil {
		t.Fatalf("CreateJob: %v", err)
	}
	if err := jobRepo.AddStage(ctx, jobs.Stage{ID: "stage-1", JobID: "job-1", Index: 0}); err != nil {
		t.Fatalf("first AddStage: %v", err)
	}

	_, err := st.db.ExecContext(ctx,
		`INSERT INTO stages (stage_id, job_id, stage_index) VALUES (?, ?, ?)`,
		"stage-2", "job-1", 0)
	if err == nil {
		t.Fatal("raw second-stage INSERT: want a UNIQUE constraint violation, got nil error")
	}
}

// TestSingleStage_SchemaCheckRejectsNonZeroIndex proves the CHECK half of the
// schema backstop: stage_index must be 0, even for a Job's only Stage.
func TestSingleStage_SchemaCheckRejectsNonZeroIndex(t *testing.T) {
	st, _ := openTestStore(t)
	ctx := context.Background()
	jobRepo := st.Jobs()

	if err := jobRepo.CreateJob(ctx, jobs.Job{ID: "job-1", CreatedAt: time.Now().UTC()}); err != nil {
		t.Fatalf("CreateJob: %v", err)
	}

	_, err := st.db.ExecContext(ctx,
		`INSERT INTO stages (stage_id, job_id, stage_index) VALUES (?, ?, ?)`,
		"stage-1", "job-1", 1)
	if err == nil {
		t.Fatal("raw INSERT with stage_index=1: want a CHECK constraint violation, got nil error")
	}
}

func TestGetJob_NotFound(t *testing.T) {
	st, _ := openTestStore(t)
	ctx := context.Background()
	jobRepo := st.Jobs()

	_, err := jobRepo.GetJob(ctx, "does-not-exist")
	if !errors.Is(err, jobs.ErrJobNotFound) {
		t.Errorf("GetJob not found: want ErrJobNotFound, got %v", err)
	}
}

// TestCreateJob_RoundTripsRequester (#616) proves CreateJob's requester
// columns round-trip through GetJob unchanged.
func TestCreateJob_RoundTripsRequester(t *testing.T) {
	st, _ := openTestStore(t)
	ctx := context.Background()
	jobRepo := st.Jobs()

	req := jobs.Requester{AccountID: "acct-1", AccountName: "agent-1", Kind: "machine"}
	if err := jobRepo.CreateJob(ctx, jobs.Job{ID: "job-1", CreatedAt: time.Now().UTC(), Requester: req}); err != nil {
		t.Fatalf("CreateJob: %v", err)
	}

	got, err := jobRepo.GetJob(ctx, "job-1")
	if err != nil {
		t.Fatalf("GetJob: %v", err)
	}
	if got.Requester != req {
		t.Errorf("GetJob Requester = %#v, want %#v", got.Requester, req)
	}
}

// TestCreateJob_ZeroRequesterStoresNull (#616) proves a Job created with no
// Requester stores NULL in all three columns — the "no requester recorded"
// state, never a name-only or empty-string sentinel.
func TestCreateJob_ZeroRequesterStoresNull(t *testing.T) {
	st, _ := openTestStore(t)
	ctx := context.Background()
	jobRepo := st.Jobs()

	if err := jobRepo.CreateJob(ctx, jobs.Job{ID: "job-1", CreatedAt: time.Now().UTC()}); err != nil {
		t.Fatalf("CreateJob: %v", err)
	}

	var id, name, kind interface{}
	err := st.db.QueryRowContext(ctx,
		`SELECT requester_account_id, requester_account_name, requester_kind FROM jobs WHERE job_id = ?`, "job-1").
		Scan(&id, &name, &kind)
	if err != nil {
		t.Fatalf("query raw job row: %v", err)
	}
	if id != nil || name != nil || kind != nil {
		t.Errorf("requester columns = (%v, %v, %v), want all NULL", id, name, kind)
	}
}

// TestCreateJob_RejectsRequesterKindOutsideHumanOrMachine (#616) proves
// CreateJob validates Kind in Go before the INSERT ever runs.
func TestCreateJob_RejectsRequesterKindOutsideHumanOrMachine(t *testing.T) {
	st, _ := openTestStore(t)
	ctx := context.Background()
	jobRepo := st.Jobs()

	req := jobs.Requester{AccountID: "acct-1", Kind: "robot"}
	err := jobRepo.CreateJob(ctx, jobs.Job{ID: "job-1", CreatedAt: time.Now().UTC(), Requester: req})
	if err == nil {
		t.Fatal("CreateJob with kind \"robot\": want an error, got nil")
	}

	if _, getErr := jobRepo.GetJob(ctx, "job-1"); !errors.Is(getErr, jobs.ErrJobNotFound) {
		t.Errorf("GetJob after rejected CreateJob: want ErrJobNotFound, got %v", getErr)
	}
}

// TestCreateJob_RejectsNameOrKindWithoutAccountID (#616) proves CreateJob
// refuses a name-only or kind-only Requester rather than silently dropping
// the orphaned field — a name or kind without an AccountID could be
// mistaken for a verified owner.
func TestCreateJob_RejectsNameOrKindWithoutAccountID(t *testing.T) {
	st, _ := openTestStore(t)
	ctx := context.Background()
	jobRepo := st.Jobs()

	cases := []struct {
		name string
		req  jobs.Requester
	}{
		{"name only", jobs.Requester{AccountName: "agent-1"}},
		{"kind only", jobs.Requester{Kind: "machine"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := jobRepo.CreateJob(ctx, jobs.Job{ID: "job-" + tc.name, CreatedAt: time.Now().UTC(), Requester: tc.req})
			if err == nil {
				t.Fatalf("CreateJob with %#v: want an error, got nil", tc.req)
			}
		})
	}
}

// TestCreateJob_AcceptsEveryAccountsKind (#616) pins the jobs mirror to
// accounts.Kind's wire values: every valid accounts.Kind must round-trip.
func TestCreateJob_AcceptsEveryAccountsKind(t *testing.T) {
	st, _ := openTestStore(t)
	ctx := context.Background()
	jobRepo := st.Jobs()

	for _, k := range []accounts.Kind{accounts.KindHuman, accounts.KindMachine} {
		t.Run(string(k), func(t *testing.T) {
			req := jobs.Requester{AccountID: "acct-" + string(k), Kind: string(k)}
			id := "job-" + string(k)
			if err := jobRepo.CreateJob(ctx, jobs.Job{ID: id, CreatedAt: time.Now().UTC(), Requester: req}); err != nil {
				t.Fatalf("CreateJob with kind %q: %v", k, err)
			}
			got, err := jobRepo.GetJob(ctx, id)
			if err != nil {
				t.Fatalf("GetJob: %v", err)
			}
			if got.Requester.Kind != string(k) {
				t.Errorf("Requester.Kind = %q, want %q", got.Requester.Kind, k)
			}
		})
	}
}

// seedHaltFixture creates job-h with a Dispatched Task on node-1 and returns
// the Task's ID.
func seedHaltFixture(t *testing.T, st *Store) string {
	t.Helper()
	ctx := context.Background()
	seedJobAndStage(t, st, "job-h", "stage-h")
	task := jobs.Task{ID: "task-h1", JobID: "job-h", StageID: "stage-h", NodeID: "node-1", Action: testAction(), CreatedAt: time.Now().UTC()}
	if err := st.Tasks().CreateTask(ctx, task); err != nil {
		t.Fatalf("CreateTask: %v", err)
	}
	if err := st.Tasks().MarkDispatched(ctx, task.ID, time.Now().UTC()); err != nil {
		t.Fatalf("MarkDispatched: %v", err)
	}
	return task.ID
}

func resolveHaltFixture(t *testing.T, st *Store, taskID string, o jobs.Outcome) {
	t.Helper()
	if err := st.Tasks().Resolve(context.Background(), taskID, jobs.Result{Outcome: o}); err != nil {
		t.Fatalf("Resolve: %v", err)
	}
}

// TestGetJob_NeverHaltedJobHasNoHalt: #1150, a Job that never halted (and every
// Job older than the halt columns) reads a zero Halt.
func TestGetJob_NeverHaltedJobHasNoHalt(t *testing.T) {
	st, _ := openTestStore(t)
	seedJobAndStage(t, st, "job-1", "stage-1")
	job, err := st.Jobs().GetJob(context.Background(), "job-1")
	if err != nil {
		t.Fatalf("GetJob: %v", err)
	}
	if job.Halt.Halted() || job.Halt != (jobs.Halt{}) {
		t.Errorf("Halt = %+v, want the zero Halt", job.Halt)
	}
}

// TestRecordHalt_ReadBackByGetJob: both a resolved and an unresolved halt
// round-trip.
func TestRecordHalt_ReadBackByGetJob(t *testing.T) {
	for _, resolved := range []bool{true, false} {
		t.Run(fmt.Sprintf("resolved=%v", resolved), func(t *testing.T) {
			st, _ := openTestStore(t)
			ctx := context.Background()
			taskID := seedHaltFixture(t, st)
			outcome := jobs.OutcomeTimeout
			if resolved {
				resolveHaltFixture(t, st, taskID, outcome)
			}
			at := time.Date(2026, 10, 26, 12, 0, 0, 123, time.UTC)
			h := jobs.Halt{TaskID: taskID, NodeID: "node-1", Outcome: outcome, Resolved: resolved, At: at}
			if err := st.Jobs().RecordHalt(ctx, "job-h", h); err != nil {
				t.Fatalf("RecordHalt: %v", err)
			}
			job, err := st.Jobs().GetJob(ctx, "job-h")
			if err != nil {
				t.Fatalf("GetJob: %v", err)
			}
			if job.Halt.TaskID != h.TaskID || job.Halt.NodeID != h.NodeID || job.Halt.Outcome != h.Outcome ||
				job.Halt.Resolved != resolved || !job.Halt.At.Equal(at) {
				t.Errorf("Halt = %+v, want %+v", job.Halt, h)
			}
		})
	}
}

func TestRecordHalt_OnlyOnce(t *testing.T) {
	st, _ := openTestStore(t)
	ctx := context.Background()
	taskID := seedHaltFixture(t, st)
	h := jobs.Halt{TaskID: taskID, NodeID: "node-1", Outcome: jobs.OutcomeFailure, At: time.Now().UTC()}
	if err := st.Jobs().RecordHalt(ctx, "job-h", h); err != nil {
		t.Fatalf("first RecordHalt: %v", err)
	}
	if err := st.Jobs().RecordHalt(ctx, "job-h", h); !errors.Is(err, jobs.ErrJobAlreadyHalted) {
		t.Errorf("second RecordHalt = %v, want ErrJobAlreadyHalted", err)
	}
}

// TestUnsettledTasksOfHaltedJobs_ListsOnlyUnsettledTasksOfHaltedJobs: what a
// restart settles is the Pending and Dispatched Tasks of a Job that carries a
// halt, and nothing of a Job that does not.
func TestUnsettledTasksOfHaltedJobs_ListsOnlyUnsettledTasksOfHaltedJobs(t *testing.T) {
	st, _ := openTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC()
	haltingID := seedHaltFixture(t, st)
	resolveHaltFixture(t, st, haltingID, jobs.OutcomeFailure)
	addTask := func(jobID, stageID, taskID, nodeID string, dispatch, resolve bool) {
		task := jobs.Task{ID: taskID, JobID: jobID, StageID: stageID, NodeID: nodeID, Action: testAction(), CreatedAt: now}
		if err := st.Tasks().CreateTask(ctx, task); err != nil {
			t.Fatalf("CreateTask(%s): %v", taskID, err)
		}
		if dispatch {
			if err := st.Tasks().MarkDispatched(ctx, taskID, now); err != nil {
				t.Fatalf("MarkDispatched(%s): %v", taskID, err)
			}
		}
		if resolve {
			resolveHaltFixture(t, st, taskID, jobs.OutcomeSuccess)
		}
	}
	addTask("job-h", "stage-h", "task-h2-pending", "node-2", false, false)
	addTask("job-h", "stage-h", "task-h3-dispatched", "node-3", true, false)
	addTask("job-h", "stage-h", "task-h4-resolved", "node-4", true, true)
	if err := st.Jobs().RecordHalt(ctx, "job-h", jobs.Halt{TaskID: haltingID, NodeID: "node-1", Outcome: jobs.OutcomeFailure, Resolved: true, At: now}); err != nil {
		t.Fatalf("RecordHalt: %v", err)
	}
	seedJobAndStage(t, st, "job-p", "stage-p")
	addTask("job-p", "stage-p", "task-p1-pending", "node-2", false, false)
	addTask("job-p", "stage-p", "task-p2-dispatched", "node-3", true, false)

	got, err := st.HaltedJobs().UnsettledTasksOfHaltedJobs(ctx)
	if err != nil {
		t.Fatalf("UnsettledTasksOfHaltedJobs: %v", err)
	}
	var ids []string
	for _, task := range got {
		ids = append(ids, task.ID)
	}
	want := []string{"task-h2-pending", "task-h3-dispatched"}
	if !slices.Equal(ids, want) {
		t.Errorf("UnsettledTasksOfHaltedJobs = %v, want %v", ids, want)
	}
}

func TestRecordHalt_UnknownJob(t *testing.T) {
	st, _ := openTestStore(t)
	h := jobs.Halt{TaskID: "task-x", NodeID: "node-1", Outcome: jobs.OutcomeFailure, At: time.Now().UTC()}
	if err := st.Jobs().RecordHalt(context.Background(), "no-such-job", h); !errors.Is(err, jobs.ErrJobNotFound) {
		t.Errorf("RecordHalt on an unknown Job = %v, want ErrJobNotFound", err)
	}
}

func TestRecordHalt_RefusesATaskOfAnotherJobOrNode(t *testing.T) {
	st, _ := openTestStore(t)
	ctx := context.Background()
	taskID := seedHaltFixture(t, st)
	seedJobAndStage(t, st, "job-other", "stage-other")
	for name, tc := range map[string]struct {
		jobID string
		h     jobs.Halt
	}{
		"a Task of another Job":  {"job-other", jobs.Halt{TaskID: taskID, NodeID: "node-1", Outcome: jobs.OutcomeFailure}},
		"another Node":           {"job-h", jobs.Halt{TaskID: taskID, NodeID: "node-2", Outcome: jobs.OutcomeFailure}},
		"a Task that is unknown": {"job-h", jobs.Halt{TaskID: "task-none", NodeID: "node-1", Outcome: jobs.OutcomeFailure}},
	} {
		t.Run(name, func(t *testing.T) {
			tc.h.At = time.Now().UTC()
			err := st.Jobs().RecordHalt(ctx, tc.jobID, tc.h)
			if err == nil || errors.Is(err, jobs.ErrJobAlreadyHalted) || errors.Is(err, jobs.ErrJobNotFound) {
				t.Fatalf("RecordHalt = %v, want a refusal of the halting Task", err)
			}
			job, _ := st.Jobs().GetJob(ctx, tc.jobID)
			if job.Halt.Halted() {
				t.Errorf("Halt = %+v, want none after a refusal", job.Halt)
			}
		})
	}
}

func TestRecordHalt_RefusesANonHaltingOutcomeOrNoTask(t *testing.T) {
	st, _ := openTestStore(t)
	ctx := context.Background()
	taskID := seedHaltFixture(t, st)
	for name, h := range map[string]jobs.Halt{
		"success":          {TaskID: taskID, NodeID: "node-1", Outcome: jobs.OutcomeSuccess},
		"unreachable":      {TaskID: taskID, NodeID: "node-1", Outcome: jobs.OutcomeUnreachable},
		"unspecified":      {TaskID: taskID, NodeID: "node-1"},
		"no Task":          {NodeID: "node-1", Outcome: jobs.OutcomeFailure},
		"no Node":          {TaskID: taskID, Outcome: jobs.OutcomeFailure},
		"denied_by_policy": {TaskID: taskID, NodeID: "node-1", Outcome: jobs.OutcomeDeniedByPolicy},
	} {
		t.Run(name, func(t *testing.T) {
			h.At = time.Now().UTC()
			if err := st.Jobs().RecordHalt(ctx, "job-h", h); err == nil {
				t.Errorf("RecordHalt(%+v) = nil, want a refusal", h)
			}
		})
	}
}

// TestRecordHalt_RefusesAResolvedHaltTheTaskDoesNotHold: the store makes
// "resolved: true" impossible to record for a Task that did not resolve with
// that outcome, while the same halt with resolved false is recorded.
func TestRecordHalt_RefusesAResolvedHaltTheTaskDoesNotHold(t *testing.T) {
	ctx := context.Background()
	tests := []struct {
		name  string
		setup func(t *testing.T, st *Store, taskID string)
	}{
		{"the Task is still Dispatched", func(*testing.T, *Store, string) {}},
		{"the Task resolved another outcome", func(t *testing.T, st *Store, taskID string) {
			resolveHaltFixture(t, st, taskID, jobs.OutcomeSuccess)
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			st, _ := openTestStore(t)
			taskID := seedHaltFixture(t, st)
			tt.setup(t, st, taskID)
			h := jobs.Halt{TaskID: taskID, NodeID: "node-1", Outcome: jobs.OutcomeFailure, Resolved: true, At: time.Now().UTC()}
			if err := st.Jobs().RecordHalt(ctx, "job-h", h); err == nil {
				t.Fatal("RecordHalt(resolved: true) = nil, want a refusal: the Task does not hold failure")
			}
			job, _ := st.Jobs().GetJob(ctx, "job-h")
			if job.Halt.Halted() {
				t.Errorf("Halt = %+v, want none after a refusal", job.Halt)
			}
			h.Resolved = false
			if err := st.Jobs().RecordHalt(ctx, "job-h", h); err != nil {
				t.Errorf("RecordHalt(resolved: false) = %v, want it recorded: it claims less", err)
			}
		})
	}
}
