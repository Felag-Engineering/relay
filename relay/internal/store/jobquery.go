package store

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/jobs"
)

// jobquery.go implements jobs.QueryRepository: the Job/Task read lane.
// It reads the SAME jobs/stages/tasks tables sqliteJobs/sqliteTasks write.
// The requester now comes from the jobs row itself; the audit trail
// still supplies the selector, on-behalf-of, approval, grant and args a Job
// carries nowhere of its own.

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

// runningJobIDs selects the job_id of every unresolved Task. Given tasks.state
// is NOT NULL with CHECK (state IN ('pending','dispatched','resolved')) in
// 0001_init, this is exactly the set where the Task aggregate's
// `state != 'resolved'` holds, so it must change together with that
// expression (and jobHasNoUnresolvedTask) if a Task state is ever added. It is
// spelled as IN rather than != so SQLite plans a covering SEARCH on
// idx_tasks_state_job (migration 0027) instead of an index scan. It binds no
// arguments, so embedding it changes no argument order. The literals are
// internal constants, never caller input, the same reasoning as
// jobOutcomeSumColumns.
const runningJobIDs = `SELECT job_id FROM tasks WHERE state IN ('pending', 'dispatched')`

// jobHasNoUnresolvedTask holds for a Job with no Task, or with every Task
// resolved: the complete state. It is runningJobIDs' complement as a
// per-Job predicate, and exact for the same reason (tasks.state is NOT NULL
// with a CHECK in 0001_init), so the two change together with
// scanJobSummary's derivation if a Task state is ever added. NOT EXISTS
// rather than NOT IN so a NULL can never make it unknown; it plans a covering
// SEARCH on idx_tasks_state_job. The literals are internal constants.
const jobHasNoUnresolvedTask = `NOT EXISTS (SELECT 1 FROM tasks WHERE job_id = j.job_id AND state IN ('pending', 'dispatched'))`

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

// jobOrderBy renders the ORDER BY clause (no LIMIT) for order. It is used
// twice by jobPageQuery, inside the page and on the outer SELECT, which works
// verbatim because the outer query names the page `j`.
func jobOrderBy(order jobs.JobOrder) (string, error) {
	switch order {
	case jobs.JobOrderNewestFirst:
		return ` ORDER BY j.created_at DESC, j.job_id DESC`, nil
	case jobs.JobOrderOldestFirst:
		return ` ORDER BY ` + jobCreatedAtFixedWidth + ` ASC, j.job_id ASC`, nil
	default:
		return "", fmt.Errorf("query jobs: unknown order %d", order)
	}
}

// jobPageQuery renders the QueryJobs page statement for filter: one row per
// Job, LEFT JOINed to a per-Job Task aggregate and two per-Job audit
// aggregates, all computed only for the page's Jobs. limit is the already-clamped page
// size; the statement fetches limit+1 rows so the caller can tell whether
// another page exists. It returns the arguments in text order, all bound
// inside the page. A bad order or cursor is refused here, the order first.
//
// All three joins are LEFT, deliberately: a zero-Task Job (a historical row, from
// when a zero-match dispatch still created one) has no row in
// the tasks aggregate, and an IN-FLIGHT Job has only its dispatch_intent row,
// which the dispatch-only aggregate `a` deliberately ignores; its
// outcome rows are written after disp.run returns. An INNER JOIN would make either kind of Job disappear
// from a query the instant it was created, which is exactly the race a Job
// list must not have: Job state and risk class come from the tasks table,
// never from the trail, so they are correct from the moment CreateTask
// commits.
//
// # Page first
//
// SQLite cannot flatten an aggregate subquery, and it does not push an outer
// WHERE into the right operand of a LEFT JOIN, so an aggregate joined to jobs
// is a GROUP BY over every row of tasks and every dispatch row of audit no
// matter how few Jobs the page keeps. So the page's job_ids are
// chosen first, from jobs alone (filters, cursor, ORDER BY, LIMIT; see
// buildJobWhere for how each filter reads only j or a correlated lookup), and
// both aggregates are restricted to them with `job_id IN (SELECT job_id FROM
// page)`, which plans as an index SEARCH per Job. MATERIALIZED makes the page
// computed once for its four readers. The outer ORDER BY is required: a join
// does not preserve the page's order. `+kind` is not a typo: it disqualifies
// idx_audit_kind_ts, which SQLite would otherwise pick for `kind = 'dispatch'`
// and so read every dispatch row, instead of idx_audit_job_ts.
// TestJobQuery_PageFirstReadsOnlyThePage pins the plan and
// TestJobQuery_PageFirstMatchesTheAggregateFirstShape pins the results.
//
// kind = 'dispatch' is load-bearing: capability's CancelJob writes
// job_id-carrying KindRefusal and KindJobCancel audit rows too, and the
// Selector, on-behalf-of and approval columns must come from the dispatch
// record, not from a refusal or cancel row. See
// TestJobQuery_RequesterIsNeverTakenFromTheAuditTrail.
//
// # Recording
//
// The third join counts the Job's dispatch_intent and dispatch rows, which
// scanJobSummary compares with the Task total to say how much of the Job's
// dispatch record exists (jobs.JobRecording). The count is exact because run
// returns one result per persisted Task and Execution.Run appends one dispatch
// row per result. `+kind IN (...)` keeps the planner off idx_audit_kind_ts in
// the same way `a` does.
//
// # What the audit aggregate projects, and why MIN is exact
//
// Every dispatch record within one Job is written from one base record
// (internal/auditsink's fan-out loop mutates only the Node, the outcome and
// the captured output), so MIN over a Job's dispatch rows returns the single
// value they all carry rather than an arbitrary sample. See jobs.JobSummary's
// doc comment for the caller invariant that rests on.
//
// It does NOT project stdout, stderr or truncated, ever (ADR-0025): no BLOB
// column is named here, so paginating a Job list can never become a path to
// captured output.
func jobPageQuery(filter jobs.JobQuery, limit int, cursor string) (stmt string, args []any, err error) {
	orderBy, err := jobOrderBy(filter.Order)
	if err != nil {
		return "", nil, err
	}
	conds, args := buildJobWhere(filter)

	if cursor != "" {
		switch filter.Order {
		case jobs.JobOrderNewestFirst:
			lastCreatedAt, lastJobID, err := decodeCursor2(cursor, jobs.ErrInvalidCursor)
			if err != nil {
				return "", nil, err
			}
			conds = append(conds, `(j.created_at < ? OR (j.created_at = ? AND j.job_id < ?))`)
			args = append(args, lastCreatedAt, lastCreatedAt, lastJobID)
		case jobs.JobOrderOldestFirst:
			tag, lastCreatedAt, lastJobID, err := decodeCursor3(cursor, jobs.ErrInvalidCursor)
			if err != nil {
				return "", nil, err
			}
			if tag != jobCursorOldestTag {
				return "", nil, jobs.ErrInvalidCursor
			}
			lastKey, err := normalizeAuditTimeText(lastCreatedAt)
			if err != nil {
				return "", nil, fmt.Errorf("%w: %v", jobs.ErrInvalidCursor, err)
			}
			conds = append(conds, `(`+jobCreatedAtFixedWidth+` > ? OR (`+jobCreatedAtFixedWidth+` = ? AND j.job_id > ?))`)
			args = append(args, lastKey, lastKey, lastJobID)
		}
	}
	where := ""
	if len(conds) > 0 {
		where = ` WHERE ` + strings.Join(conds, " AND ")
	}
	args = append(args, limit+1)

	stmt = `WITH page AS MATERIALIZED (
	SELECT j.job_id, j.created_at, j.requester_account_id, j.requester_account_name, j.requester_kind
	FROM jobs j` + where + orderBy + ` LIMIT ?
)
SELECT j.job_id, j.created_at,
	COALESCE(t.total, 0), COALESCE(t.unresolved, 0),
	t.action_kind, t.operation_name, t.risk_class,
	` + strings.Join(jobOutcomeColumnRefs(), ", ") + `,
	a.selector, j.requester_account_id, j.requester_account_name, j.requester_kind,
	a.on_behalf_of, a.approval_id, a.grant_id, a.args, a.raw_exec_argv,
	COALESCE(r.intents, 0), COALESCE(r.outcomes, 0)
FROM page j
LEFT JOIN (
	SELECT job_id,
		COUNT(*) AS total,
		SUM(CASE WHEN state != 'resolved' THEN 1 ELSE 0 END) AS unresolved,
		MIN(action_kind) AS action_kind,
		MIN(operation_name) AS operation_name,
		MIN(risk_class) AS risk_class,
		` + strings.Join(jobOutcomeSumColumns(), ",\n\t\t") + `
	FROM tasks WHERE job_id IN (SELECT job_id FROM page)
	GROUP BY job_id
) t ON t.job_id = j.job_id
LEFT JOIN (
	SELECT job_id, MIN(selector) AS selector,
		MIN(asserted_on_behalf_of) AS on_behalf_of, MIN(approval_id) AS approval_id, MIN(grant_id) AS grant_id,
		MIN(args) AS args, MIN(raw_exec_argv) AS raw_exec_argv
	FROM audit WHERE +kind = 'dispatch' AND job_id IN (SELECT job_id FROM page)
	GROUP BY job_id
) a ON a.job_id = j.job_id
LEFT JOIN (
	SELECT job_id,
		SUM(CASE WHEN kind = 'dispatch_intent' THEN 1 ELSE 0 END) AS intents,
		SUM(CASE WHEN kind = 'dispatch' THEN 1 ELSE 0 END) AS outcomes
	FROM audit WHERE +kind IN ('dispatch', 'dispatch_intent') AND job_id IN (SELECT job_id FROM page)
	GROUP BY job_id
) r ON r.job_id = j.job_id` + orderBy
	return stmt, args, nil
}

// jobQueryCount renders the COUNT(*) over exactly the Jobs jobPageQuery would
// return for filter, before paging. It shares buildJobWhere with the page, so
// the two cannot describe different filters, and it joins no aggregate: every
// condition is a column of jobs or a per-Job lookup. It cannot be bounded by
// the page, a count of matching Jobs being O(matching Jobs) by definition.
func jobQueryCount(filter jobs.JobQuery) (stmt string, args []any) {
	conds, args := buildJobWhere(filter)
	stmt = `SELECT COUNT(*) FROM jobs j`
	if len(conds) > 0 {
		stmt += ` WHERE ` + strings.Join(conds, " AND ")
	}
	return stmt, args
}

// jobOutcomeColumnRefs renders "COALESCE(t.o0, 0), COALESCE(t.o1, 0), ..."
// for the outer SELECT — the inner aggregate's SUM is NULL only when a Job
// has no matching tasks row at all (the zero-Task case, a historical row),
// which COALESCE turns into a truthful zero rather than a
// NULL Outcome count.
func jobOutcomeColumnRefs() []string {
	refs := make([]string, len(jobOutcomeOrder))
	for i := range jobOutcomeOrder {
		refs[i] = fmt.Sprintf("COALESCE(t.o%d, 0)", i)
	}
	return refs
}

// jobCursorOldestTag marks an oldest-first cursor. Such a cursor is
// three-part (tag, created_at, job_id) while a newest-first one is two-part,
// so a cursor minted in one direction is refused in the other rather than
// silently walking the wrong way.
const jobCursorOldestTag = "asc"

// jobCreatedAtFixedWidth is a SQL expression rendering j.created_at as
// auditTimeLayout text: nine fractional digits, always 30 bytes, so a byte
// comparison of it is a chronological one.
//
// It exists because jobs.created_at is stored as time.RFC3339Nano, which
// trims trailing zeros ("...:01Z" sorts after "...:01.5Z"). Only formatTime
// writes the column, always in UTC with a "Z" suffix, so the stored spellings
// are exactly: seconds only, or seconds plus 1-9 fractional digits. Characters
// 1-19 are the seconds; the rest is "Z" or ".digitsZ", stripped to its digits
// and right-padded with zeros. Oldest-first only: newest-first keeps ordering
// by the raw column (the same latent defect, tracked separately).
const jobCreatedAtFixedWidth = `(substr(j.created_at, 1, 19) || '.' || ` +
	`substr(replace(replace(substr(j.created_at, 20), 'Z', ''), '.', '') || '000000000', 1, 9) || 'Z')`

// QueryJobs implements jobs.QueryRepository: one page of JobSummary rows
// matching filter, in filter.Order's direction (newest (CreatedAt) first by
// default), keyset-paginated on (created_at, job_id) exactly as
// auditquery.go's Query is on (ts, audit_id).
//
// Oldest-first is chronological even though created_at is trimmed
// RFC3339Nano text: it orders and pages on jobCreatedAtFixedWidth, and its
// cursor carries that fixed-width key. Newest-first still orders the raw text
// and so still inverts within a second (the defect audittime.go names,
// tracked separately); its SQL and cursor are unchanged.
//
// With filter.CountMatching the page and the count of matching Jobs are read
// in one transaction, so they describe one snapshot; otherwise no
// transaction is opened.
func (q *sqliteJobQueries) QueryJobs(ctx context.Context, filter jobs.JobQuery, limit int, cursor string) (jobs.JobPage, error) {
	limit = clampPageSize(limit)

	// Both statements are built, and a bad order or cursor refused, before a
	// transaction is opened.
	stmt, args, err := jobPageQuery(filter, limit, cursor)
	if err != nil {
		return jobs.JobPage{}, err
	}
	// The total ignores paging, so it never sees the cursor condition.
	countStmt, countArgs := jobQueryCount(filter)

	var (
		db       queryer = q.db
		matching int
	)
	if filter.CountMatching {
		// A snapshot read: it must not take the write lock now that write
		// transactions begin IMMEDIATE (sqliteDSN).
		tx, err := q.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
		if err != nil {
			return jobs.JobPage{}, fmt.Errorf("query jobs: begin: %w", err)
		}
		defer tx.Rollback() //nolint:errcheck
		db = tx
		if err := db.QueryRowContext(ctx, countStmt, countArgs...).Scan(&matching); err != nil {
			return jobs.JobPage{}, fmt.Errorf("count jobs: %w", err)
		}
	}

	rows, err := db.QueryContext(ctx, stmt, args...)
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

	page := jobs.JobPage{Limit: limit, Matching: matching}
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
		if filter.Order == jobs.JobOrderOldestFirst {
			key, err := normalizeAuditTimeText(last.createdAt)
			if err != nil {
				return jobs.JobPage{}, fmt.Errorf("cursor for job %q: %w", last.summary.JobID, err)
			}
			page.Next = encodeCursor3(jobCursorOldestTag, key, last.summary.JobID)
		} else {
			page.Next = encodeCursor2(last.createdAt, last.summary.JobID)
		}
	}
	return page, nil
}

// buildJobWhere translates a jobs.JobQuery into parameterised SQL conditions
// (ANDed by the caller) and their bound arguments. Every condition names only
// columns of `j` (a jobs row, or the page's projection of one) or a
// correlated lookup keyed on j.job_id, because it runs where no aggregate
// exists: inside the page and in the count. Each lookup is the SAME
// MIN, over the same rows, that the page's aggregate projects, so a filter
// selects exactly the Jobs whose summary shows the value; a Job with no such
// rows yields NULL, which fails `= ?` as the old LEFT JOIN's NULL did.
func buildJobWhere(filter jobs.JobQuery) (conds []string, args []any) {
	if filter.JobID != "" {
		conds = append(conds, `j.job_id = ?`)
		args = append(args, filter.JobID)
	}
	if filter.State != nil {
		switch *filter.State {
		case jobs.JobStateRunning:
			// Exact: tasks.state is NOT NULL with a CHECK (0001_init), so "has
			// an unresolved Task" is total > 0 AND unresolved > 0, which is
			// scanJobSummary's running derivation. Changes together with it.
			conds = append(conds, `j.job_id IN (`+runningJobIDs+`)`)
		default: // JobStateComplete: zero Tasks, or every Task resolved.
			conds = append(conds, jobHasNoUnresolvedTask)
		}
	}
	if filter.RequesterAccountID != "" {
		// A plain column predicate on the jobs row itself — no join,
		// no aggregate, and idx_jobs_requester_created_at (migration 0026)
		// serves it directly.
		conds = append(conds, `j.requester_account_id = ?`)
		args = append(args, filter.RequesterAccountID)
	}
	if filter.OnBehalfOf != "" {
		// The caller-asserted lane has no home on the jobs row, so it reads
		// the Job's dispatch rows. `+kind` keeps the planner on
		// idx_audit_job_ts (see jobPageQuery); and only dispatch rows count,
		// as a refusal or cancel row may assert something else.
		conds = append(conds, `(SELECT MIN(asserted_on_behalf_of) FROM audit WHERE +kind = 'dispatch' AND job_id = j.job_id) = ?`)
		args = append(args, filter.OnBehalfOf)
	}
	if filter.Operation != "" {
		conds = append(conds, `(SELECT MIN(operation_name) FROM tasks WHERE job_id = j.job_id) = ?`)
		args = append(args, filter.Operation)
	}
	if filter.RiskClass != nil {
		conds = append(conds, `(SELECT MIN(risk_class) FROM tasks WHERE job_id = j.job_id) = ?`)
		args = append(args, jobs.RiskClassName(*filter.RiskClass))
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

// jobRecording says how much of a Job's dispatch record the trail holds, from
// the Job's Task total and its dispatch_intent and dispatch row counts.
func jobRecording(total, intents, outcomes int) jobs.JobRecording {
	switch {
	case outcomes > 0 && outcomes >= total:
		return jobs.JobRecordingOutcome
	case outcomes > 0:
		return jobs.JobRecordingOutcomePartial
	case intents > 0:
		return jobs.JobRecordingIntentOnly
	default:
		return jobs.JobRecordingNone
	}
}

// scanJobSummary scans one jobPageQuery row, also returning the raw stored
// created_at text (needed for the cursor, on auditquery.go's precedent).
func scanJobSummary(row rowScanner) (jobs.JobSummary, string, error) {
	var (
		jobID, createdAt                     string
		total, unresolved                    int
		actionKind, operationName, riskClass sql.NullString
		outcomeCounts                        = make([]int, len(jobOutcomeOrder))
		selector, requesterID, requesterName sql.NullString
		requesterKind                        sql.NullString
		onBehalfOf, approvalID, grantID      sql.NullString
		argsJSON, argvJSON                   sql.NullString
		intents, outcomes                    int
	)

	dest := []any{&jobID, &createdAt, &total, &unresolved, &actionKind, &operationName, &riskClass}
	for i := range outcomeCounts {
		dest = append(dest, &outcomeCounts[i])
	}
	dest = append(dest, &selector, &requesterID, &requesterName, &requesterKind,
		&onBehalfOf, &approvalID, &grantID, &argsJSON, &argvJSON,
		&intents, &outcomes)

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

	// A decode failure FAILS THE SCAN rather than yielding nil. A Job row that
	// silently drops the argv it was dispatched with is worse than an error:
	// the row still renders, and it renders as a Raw Exec with no command.
	dispatchArgs, err := decodeStringMap(argsJSON)
	if err != nil {
		return jobs.JobSummary{}, "", fmt.Errorf("job %q: %w", jobID, err)
	}
	rawExecArgv, err := decodeStringSlice(argvJSON)
	if err != nil {
		return jobs.JobSummary{}, "", fmt.Errorf("job %q: %w", jobID, err)
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
		Requester:          requesterName.String,
		RequesterAccountID: requesterID.String,
		RequesterKind:      requesterKind.String,
		OnBehalfOf:         onBehalfOf.String,
		ApprovalID:         approvalID.String,
		GrantID:            grantID.String,
		Args:               dispatchArgs,
		RawExecArgv:        rawExecArgv,
		Total:              total,
		Counts:             counts,
		Unresolved:         unresolved,
		Recording:          jobRecording(total, intents, outcomes),
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
