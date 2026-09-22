package store

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/accounts"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/jobs"
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
