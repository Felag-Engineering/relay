package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/jobs"
)

// sqliteJobs implements jobs.JobRepository against the jobs/stages tables.
type sqliteJobs struct {
	db *sql.DB
}

var _ jobs.JobRepository = (*sqliteJobs)(nil)

// CreateJob persists a new Job.
func (j *sqliteJobs) CreateJob(ctx context.Context, job jobs.Job) error {
	_, err := j.db.ExecContext(ctx, `INSERT INTO jobs (job_id, created_at) VALUES (?, ?)`,
		job.ID, formatTime(roundTripTime(job.CreatedAt)))
	if err != nil {
		return fmt.Errorf("insert job: %w", err)
	}
	return nil
}

// AddStage adds a Stage to a Job. Returns jobs.ErrSingleStageOnly if the Job
// already has a Stage — the code guard for v1's one-stage-per-Job constraint.
// The stages table's CHECK(stage_index = 0)+UNIQUE(job_id, stage_index) is
// defense-in-depth, not the primary enforcement.
func (j *sqliteJobs) AddStage(ctx context.Context, stage jobs.Stage) error {
	tx, err := j.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck

	var count int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM stages WHERE job_id = ?`, stage.JobID).Scan(&count); err != nil {
		return fmt.Errorf("count stages for job %q: %w", stage.JobID, err)
	}
	if count > 0 {
		return jobs.ErrSingleStageOnly
	}

	if _, err := tx.ExecContext(ctx, `INSERT INTO stages (stage_id, job_id, stage_index) VALUES (?, ?, ?)`,
		stage.ID, stage.JobID, stage.Index); err != nil {
		return fmt.Errorf("insert stage: %w", err)
	}
	return tx.Commit()
}

// GetJob returns the Job with the given ID, or jobs.ErrJobNotFound.
func (j *sqliteJobs) GetJob(ctx context.Context, id string) (jobs.Job, error) {
	var createdAt string
	err := j.db.QueryRowContext(ctx, `SELECT created_at FROM jobs WHERE job_id = ?`, id).Scan(&createdAt)
	if errors.Is(err, sql.ErrNoRows) {
		return jobs.Job{}, jobs.ErrJobNotFound
	}
	if err != nil {
		return jobs.Job{}, fmt.Errorf("query job %q: %w", id, err)
	}
	t, err := parseTime(sql.NullString{String: createdAt, Valid: true})
	if err != nil {
		return jobs.Job{}, fmt.Errorf("parse created_at for job %q: %w", id, err)
	}
	return jobs.Job{ID: id, CreatedAt: t}, nil
}

// Stages returns all Stages for jobID, ordered by Index (at most one, in v1).
func (j *sqliteJobs) Stages(ctx context.Context, jobID string) ([]jobs.Stage, error) {
	rows, err := j.db.QueryContext(ctx, `SELECT stage_id, stage_index FROM stages WHERE job_id = ? ORDER BY stage_index`, jobID)
	if err != nil {
		return nil, fmt.Errorf("query stages for job %q: %w", jobID, err)
	}
	defer rows.Close()

	var out []jobs.Stage
	for rows.Next() {
		var s jobs.Stage
		if err := rows.Scan(&s.ID, &s.Index); err != nil {
			return nil, fmt.Errorf("scan stage row: %w", err)
		}
		s.JobID = jobID
		out = append(out, s)
	}
	return out, rows.Err()
}
