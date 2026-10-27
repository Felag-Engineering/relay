package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/Felag-Engineering/relay/relay/internal/accounts"
	"github.com/Felag-Engineering/relay/relay/internal/jobs"
)

// sqliteJobs implements jobs.JobRepository against the jobs/stages tables.
type sqliteJobs struct {
	db *sql.DB
}

var _ jobs.JobRepository = (*sqliteJobs)(nil)
var _ jobs.HaltedJobRepository = (*sqliteJobs)(nil)

// CreateJob persists a new Job, including its Requester, in one write.
//
// The requester is validated BEFORE the INSERT: an AccountID-less
// name or kind, or a kind outside human/machine, is rejected here rather
// than silently dropped or left to the schema's CHECK constraint, which is
// only the backstop.
func (j *sqliteJobs) CreateJob(ctx context.Context, job jobs.Job) error {
	req := job.Requester
	if !req.Recorded() && (req.AccountName != "" || req.Kind != "") {
		return fmt.Errorf("store: job %q requester has a name or kind but no account id", job.ID)
	}
	if req.Kind != "" && !accounts.Kind(req.Kind).Valid() {
		return fmt.Errorf("store: job %q requester kind %q is not human or machine", job.ID, req.Kind)
	}

	_, err := j.db.ExecContext(ctx,
		`INSERT INTO jobs (job_id, created_at, requester_account_id, requester_account_name, requester_kind) VALUES (?, ?, ?, ?, ?)`,
		job.ID, formatTime(roundTripTime(job.CreatedAt)),
		nullIfEmpty(req.AccountID), nullIfEmpty(req.AccountName), nullIfEmpty(req.Kind))
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
	var requesterID, requesterName, requesterKind sql.NullString
	var haltTaskID, haltNodeID, haltedAt sql.NullString
	var haltOutcome sql.NullInt64
	var haltResolved int64
	err := j.db.QueryRowContext(ctx,
		`SELECT created_at, requester_account_id, requester_account_name, requester_kind,
			halt_task_id, halt_node_id, halt_outcome, halt_resolved, halted_at
		FROM jobs WHERE job_id = ?`, id).
		Scan(&createdAt, &requesterID, &requesterName, &requesterKind,
			&haltTaskID, &haltNodeID, &haltOutcome, &haltResolved, &haltedAt)
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
	job := jobs.Job{
		ID:        id,
		CreatedAt: t,
		Requester: jobs.Requester{
			AccountID:   requesterID.String,
			AccountName: requesterName.String,
			Kind:        requesterKind.String,
		},
	}
	if haltTaskID.Valid {
		at, err := parseTime(haltedAt)
		if err != nil {
			return jobs.Job{}, fmt.Errorf("parse halted_at for job %q: %w", id, err)
		}
		job.Halt = jobs.Halt{
			TaskID:   haltTaskID.String,
			NodeID:   haltNodeID.String,
			Outcome:  jobs.Outcome(haltOutcome.Int64),
			Resolved: haltResolved != 0,
			At:       at,
		}
	}
	return job, nil
}

// RecordHalt records h on jobID once, in one statement. The WHERE clause makes
// the store the check on the halt's honesty: the halting Task must be a Task of
// the Job on h.NodeID, and a Resolved halt is recorded only for a Task the
// store holds Resolved with h.Outcome (Resolved is terminal, so the check
// cannot go stale). It returns jobs.ErrJobNotFound for an unknown Job and
// jobs.ErrJobAlreadyHalted when the Job already carries a halt.
func (j *sqliteJobs) RecordHalt(ctx context.Context, jobID string, h jobs.Halt) error {
	if !h.Halted() || h.NodeID == "" {
		return fmt.Errorf("store: halt of job %q names no Task or Node", jobID)
	}
	if h.Outcome != jobs.OutcomeFailure && h.Outcome != jobs.OutcomeTimeout {
		return fmt.Errorf("store: halt of job %q has outcome %q; only failure or timeout halts a Job",
			jobID, jobs.OutcomeName(h.Outcome))
	}
	resolved := 0
	if h.Resolved {
		resolved = 1
	}
	res, err := j.db.ExecContext(ctx, `
		UPDATE jobs SET halt_task_id = ?, halt_node_id = ?, halt_outcome = ?, halt_resolved = ?, halted_at = ?
		WHERE job_id = ? AND halt_task_id IS NULL
		AND EXISTS (SELECT 1 FROM tasks WHERE task_id = ? AND job_id = ? AND node_id = ?
			AND (? = 0 OR (state = 'resolved' AND outcome = ?)))`,
		h.TaskID, h.NodeID, int(h.Outcome), resolved, formatTime(roundTripTime(h.At)),
		jobID,
		h.TaskID, jobID, h.NodeID, resolved, int(h.Outcome))
	if err != nil {
		return fmt.Errorf("record halt of job %q: %w", jobID, err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("record halt of job %q: rows affected: %w", jobID, err)
	}
	if n > 0 {
		return nil
	}

	var existing sql.NullString
	err = j.db.QueryRowContext(ctx, `SELECT halt_task_id FROM jobs WHERE job_id = ?`, jobID).Scan(&existing)
	if errors.Is(err, sql.ErrNoRows) {
		return jobs.ErrJobNotFound
	}
	if err != nil {
		return fmt.Errorf("record halt of job %q: %w", jobID, err)
	}
	if existing.Valid {
		return jobs.ErrJobAlreadyHalted
	}
	return fmt.Errorf("store: task %q on node %q is not a Task of job %q holding the halt's recorded outcome",
		h.TaskID, h.NodeID, jobID)
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

// UnsettledTasksOfHaltedJobs returns every Pending or Dispatched Task whose Job
// carries a halt, ordered by Job then Task ID. A NULL halt_task_id means the
// Job never halted.
func (j *sqliteJobs) UnsettledTasksOfHaltedJobs(ctx context.Context) ([]jobs.Task, error) {
	return queryTasks(ctx, j.db,
		`WHERE state IN ('pending', 'dispatched')
		   AND job_id IN (SELECT job_id FROM jobs WHERE halt_task_id IS NOT NULL)
		 ORDER BY job_id, task_id`)
}
