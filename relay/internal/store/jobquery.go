package store

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/jobs"
)

// jobquery.go implements jobs.QueryRepository: the Job/Task read lane (#441).
// It reads the SAME jobs/stages/tasks tables sqliteJobs/sqliteTasks write,
// plus the audit trail for the requester/selector that a Job carries nowhere
// of its own (jobs.Job's doc comment: "Selector and principal provenance
// live in audit for now").

// sqliteJobQueries implements jobs.QueryRepository.
type sqliteJobQueries struct {
	db *sql.DB
}

var _ jobs.QueryRepository = (*sqliteJobQueries)(nil)

// jobOutcomeOrder fixes the per-outcome SUM(CASE...) order, mirroring
// auditsink's outcomeOrder. jobs.OutcomeUnspecified is excluded: a RESOLVED
// Task's Outcome is never Unspecified in practice (jobs.Outcome's doc
// comment: Unspecified means "not yet resolved"), so summing it would only
// ever contribute zero.
var jobOutcomeOrder = []jobs.Outcome{
	jobs.OutcomeSuccess,
	jobs.OutcomeFailure,
	jobs.OutcomeTimeout,
	jobs.OutcomeDeniedByPolicy,
	jobs.OutcomeCancelled,
	jobs.OutcomeUnreachable,
	jobs.OutcomeVersionRefused,
	jobs.OutcomeUnsupported,
}

// jobOutcomeSumColumns renders one "SUM(CASE WHEN outcome = n THEN 1 ELSE 0
// END) AS on" per jobOutcomeOrder entry. The outcome literal is an internal
// constant (jobs.Outcome), never caller input, so interpolating it directly
// is safe — nothing here is bound from a request.
func jobOutcomeSumColumns() []string {
	cols := make([]string, len(jobOutcomeOrder))
	for i, o := range jobOutcomeOrder {
		cols[i] = fmt.Sprintf("SUM(CASE WHEN outcome = %d THEN 1 ELSE 0 END) AS o%d", int(o), i)
	}
	return cols
}

// jobQuerySelect is the QueryJobs SELECT: one row per Job, LEFT JOINed to a
// per-Job Task aggregate and a per-Job audit aggregate.
//
// Both joins are LEFT, deliberately: a zero-Task Job (fan-out matched
// nothing) has no row in the tasks aggregate, and an IN-FLIGHT Job has no
// audit row yet at all — capability/service.go's dispatcher writes the audit
// record only after disp.run returns (capability/service.go:409's
// AuditSink.Record call happens after dispatch, not before). An INNER JOIN
// would make either kind of Job disappear from a query the instant it was
// created, which is exactly the race a Job list must not have: Job state and
// risk class come from the tasks table, never from the trail, so they are
// correct from the moment CreateTask commits.
var jobQuerySelect = `SELECT j.job_id, j.created_at,
	COALESCE(t.total, 0), COALESCE(t.unresolved, 0),
	t.action_kind, t.operation_name, t.risk_class,
	` + strings.Join(jobOutcomeColumnRefs(), ", ") + `,
	a.selector, a.account_id, a.account_name
FROM jobs j
LEFT JOIN (
	SELECT job_id,
		COUNT(*) AS total,
		SUM(CASE WHEN state != 'resolved' THEN 1 ELSE 0 END) AS unresolved,
		MIN(action_kind) AS action_kind,
		MIN(operation_name) AS operation_name,
		MIN(risk_class) AS risk_class,
		` + strings.Join(jobOutcomeSumColumns(), ",\n\t\t") + `
	FROM tasks
	GROUP BY job_id
) t ON t.job_id = j.job_id
LEFT JOIN (
	SELECT job_id, MIN(selector) AS selector, MIN(account_id) AS account_id, MIN(account_name) AS account_name
	FROM audit
	WHERE kind = 'dispatch'
	GROUP BY job_id
) a ON a.job_id = j.job_id`

// jobOutcomeColumnRefs renders "COALESCE(t.o0, 0), COALESCE(t.o1, 0), ..."
// for the outer SELECT — the inner aggregate's SUM is NULL only when a Job
// has no matching tasks row at all (the zero-Task case), which COALESCE
// turns into a truthful zero rather than a NULL Outcome count.
func jobOutcomeColumnRefs() []string {
	refs := make([]string, len(jobOutcomeOrder))
	for i := range jobOutcomeOrder {
		refs[i] = fmt.Sprintf("COALESCE(t.o%d, 0)", i)
	}
	return refs
}

// QueryJobs implements jobs.QueryRepository: one page of JobSummary rows
// matching filter, newest (CreatedAt) first, keyset-paginated on
// (created_at, job_id) exactly as auditquery.go's Query is on (ts, audit_id).
func (q *sqliteJobQueries) QueryJobs(ctx context.Context, filter jobs.JobQuery, limit int, cursor string) (jobs.JobPage, error) {
	limit = clampPageSize(limit)

	conds, args := buildJobWhere(filter)
	if cursor != "" {
		lastCreatedAt, lastJobID, err := decodeCursor2(cursor, jobs.ErrInvalidCursor)
		if err != nil {
			return jobs.JobPage{}, err
		}
		conds = append(conds, `(j.created_at < ? OR (j.created_at = ? AND j.job_id < ?))`)
		args = append(args, lastCreatedAt, lastCreatedAt, lastJobID)
	}

	stmt := jobQuerySelect
	if len(conds) > 0 {
		stmt += ` WHERE ` + strings.Join(conds, " AND ")
	}
	stmt += ` ORDER BY j.created_at DESC, j.job_id DESC LIMIT ?`
	args = append(args, limit+1)

	rows, err := q.db.QueryContext(ctx, stmt, args...)
	if err != nil {
		return jobs.JobPage{}, fmt.Errorf("query jobs: %w", err)
	}
	defer rows.Close()

	type scannedJob struct {
		summary   jobs.JobSummary
		createdAt string // raw stored text, for the cursor
	}
	var fetched []scannedJob
	for rows.Next() {
		summary, createdAt, err := scanJobSummary(rows)
		if err != nil {
			return jobs.JobPage{}, err
		}
		fetched = append(fetched, scannedJob{summary, createdAt})
	}
	if err := rows.Err(); err != nil {
		return jobs.JobPage{}, fmt.Errorf("iterate jobs: %w", err)
	}

	page := jobs.JobPage{Limit: limit}
	hasMore := len(fetched) > limit
	if hasMore {
		fetched = fetched[:limit]
	}
	page.Jobs = make([]jobs.JobSummary, len(fetched))
	for i, s := range fetched {
		page.Jobs[i] = s.summary
	}
	if hasMore && len(fetched) > 0 {
		last := fetched[len(fetched)-1]
		page.Next = encodeCursor2(last.createdAt, last.summary.JobID)
	}
	return page, nil
}

// buildJobWhere translates a jobs.JobQuery into parameterised SQL conditions
// (ANDed by the caller, referencing the jobQuerySelect aliases j/t/a) and
// their bound arguments.
func buildJobWhere(filter jobs.JobQuery) (conds []string, args []any) {
	if filter.State != nil {
		switch *filter.State {
		case jobs.JobStateRunning:
			conds = append(conds, `(COALESCE(t.total, 0) > 0 AND COALESCE(t.unresolved, 0) > 0)`)
		default: // JobStateComplete: zero Tasks, or every Task resolved.
			conds = append(conds, `(COALESCE(t.total, 0) = 0 OR COALESCE(t.unresolved, 0) = 0)`)
		}
	}
	if filter.RequesterAccountID != "" {
		conds = append(conds, `a.account_id = ?`)
		args = append(args, filter.RequesterAccountID)
	}
	if filter.Operation != "" {
		conds = append(conds, `t.operation_name = ?`)
		args = append(args, filter.Operation)
	}
	if filter.RiskClass != nil {
		conds = append(conds, `t.risk_class = ?`)
		args = append(args, riskClassToString(*filter.RiskClass))
	}
	if !filter.Since.IsZero() {
		conds = append(conds, `j.created_at >= ?`)
		args = append(args, secondPrefix(filter.Since))
	}
	if !filter.Until.IsZero() {
		conds = append(conds, `j.created_at < ?`)
		args = append(args, secondPrefix(filter.Until.Add(time.Second)))
	}
	return conds, args
}

// scanJobSummary scans one jobQuerySelect row, also returning the raw stored
// created_at text (needed for the cursor, on auditquery.go's precedent).
func scanJobSummary(row rowScanner) (jobs.JobSummary, string, error) {
	var (
		jobID, createdAt                     string
		total, unresolved                    int
		actionKind, operationName, riskClass sql.NullString
		outcomeCounts                        = make([]int, len(jobOutcomeOrder))
		selector, accountID, accountName     sql.NullString
	)

	dest := []any{&jobID, &createdAt, &total, &unresolved, &actionKind, &operationName, &riskClass}
	for i := range outcomeCounts {
		dest = append(dest, &outcomeCounts[i])
	}
	dest = append(dest, &selector, &accountID, &accountName)

	if err := row.Scan(dest...); err != nil {
		return jobs.JobSummary{}, "", fmt.Errorf("scan job summary row: %w", err)
	}

	createdAtTime, err := parseTime(sql.NullString{String: createdAt, Valid: true})
	if err != nil {
		return jobs.JobSummary{}, "", fmt.Errorf("parse created_at for job %q: %w", jobID, err)
	}

	state := jobs.JobStateComplete
	if total > 0 && unresolved > 0 {
		state = jobs.JobStateRunning
	}

	kind := jobs.ActionUnspecified
	if actionKind.Valid {
		if kind, err = actionKindFromString(actionKind.String); err != nil {
			return jobs.JobSummary{}, "", fmt.Errorf("job %q: %w", jobID, err)
		}
	}

	counts := make(map[jobs.Outcome]int, len(jobOutcomeOrder))
	for i, o := range jobOutcomeOrder {
		if outcomeCounts[i] > 0 {
			counts[o] = outcomeCounts[i]
		}
	}

	return jobs.JobSummary{
		JobID:              jobID,
		CreatedAt:          createdAtTime,
		State:              state,
		ActionKind:         kind,
		OperationName:      operationName.String,
		RiskClass:          riskClassFromString(riskClass.String),
		Selector:           selector.String,
		Requester:          accountName.String,
		RequesterAccountID: accountID.String,
		Total:              total,
		Counts:             counts,
		Unresolved:         unresolved,
	}, createdAt, nil
}

// QueryTasks implements jobs.QueryRepository: one page of TaskSummary rows
// for filter.JobID, optionally restricted to filter.Outcome, in ascending
// task_id order (see jobs.TaskPage's doc comment for why that is not
// creation order but IS a stable one). Reuses queryTasks/scanTask
// (tasks.go) rather than a second column list, so the two cannot drift.
func (q *sqliteJobQueries) QueryTasks(ctx context.Context, filter jobs.TaskQuery, limit int, cursor string) (jobs.TaskPage, error) {
	limit = clampPageSize(limit)

	conds := []string{`job_id = ?`}
	args := []any{filter.JobID}
	if filter.Outcome != nil {
		conds = append(conds, `outcome = ?`)
		args = append(args, int(*filter.Outcome))
	}
	if cursor != "" {
		lastID, err := decodeCursor1(cursor, jobs.ErrInvalidCursor)
		if err != nil {
			return jobs.TaskPage{}, err
		}
		conds = append(conds, `task_id > ?`)
		args = append(args, lastID)
	}

	whereClause := `WHERE ` + strings.Join(conds, " AND ") + ` ORDER BY task_id ASC LIMIT ?`
	args = append(args, limit+1)

	tasks, err := queryTasks(ctx, q.db, whereClause, args...)
	if err != nil {
		return jobs.TaskPage{}, err
	}

	page := jobs.TaskPage{Limit: limit}
	hasMore := len(tasks) > limit
	if hasMore {
		tasks = tasks[:limit]
	}
	page.Tasks = make([]jobs.TaskSummary, len(tasks))
	for i, t := range tasks {
		page.Tasks[i] = taskSummaryFromTask(t)
	}
	if hasMore && len(tasks) > 0 {
		page.Next = encodeCursor1(tasks[len(tasks)-1].ID)
	}
	return page, nil
}

// taskSummaryFromTask projects a full jobs.Task (scanTask's shape) onto the
// narrower jobs.TaskSummary the query lane returns. See TaskSummary's doc
// comment for what is deliberately absent (Truncated) and why.
func taskSummaryFromTask(t jobs.Task) jobs.TaskSummary {
	return jobs.TaskSummary{
		TaskID:       t.ID,
		NodeID:       t.NodeID,
		State:        t.State,
		Outcome:      t.Outcome,
		ExitCode:     t.ExitCode,
		RiskClass:    t.Action.RiskClass,
		Stdout:       t.Stdout,
		Stderr:       t.Stderr,
		CreatedAt:    t.CreatedAt,
		DispatchedAt: t.DispatchedAt,
		ResolvedAt:   t.ResolvedAt,
	}
}
