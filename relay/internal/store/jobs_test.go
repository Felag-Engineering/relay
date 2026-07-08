package store

import (
	"context"
	"errors"
	"testing"
	"time"

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
