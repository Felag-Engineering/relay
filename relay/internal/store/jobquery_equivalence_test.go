package store

import (
	"context"
	"database/sql"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/audit"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/jobs"
)

// Everything from here to the first test is a FROZEN, verbatim copy of the
// aggregate-first QueryJobs (the post-#816 shape: a GROUP BY over tasks and
// over the dispatch audit rows, filtered after the join), renamed legacy*. It
// is the reference #919's page-first shape is proven against, so it must never
// be "fixed" or tidied to follow jobquery.go. Delete or regenerate it only
// when the Job summary's projection changes on purpose.

func legacyJobQuerySelect(filter jobs.JobQuery) (stmt string, args []any) {
	from, args := legacyJobQueryFrom(filter, true)
	stmt = `SELECT j.job_id, j.created_at,
	COALESCE(t.total, 0), COALESCE(t.unresolved, 0),
	t.action_kind, t.operation_name, t.risk_class,
	` + strings.Join(jobOutcomeColumnRefs(), ", ") + `,
	a.selector, j.requester_account_id, j.requester_account_name, j.requester_kind,
	a.on_behalf_of, a.approval_id, a.grant_id, a.args, a.raw_exec_argv,
		COALESCE(r.intents, 0), COALESCE(r.outcomes, 0)
` + from
	return stmt, args
}

func legacyJobQueryCount(filter jobs.JobQuery) (stmt string, args []any) {
	from, args := legacyJobQueryFrom(filter, legacyJobWhereUsesAudit(filter))
	conds, whereArgs := legacyBuildJobWhere(filter)
	stmt = `SELECT COUNT(*) ` + from
	if len(conds) > 0 {
		stmt += ` WHERE ` + strings.Join(conds, " AND ")
	}
	return stmt, append(args, whereArgs...)
}

func legacyJobQueryFrom(filter jobs.JobQuery, withAudit bool) (from string, args []any) {
	// kind = 'dispatch' is still load-bearing, even though the requester no
	// longer comes from this join (#616): capability's CancelJob writes
	// job_id-carrying KindRefusal and KindJobCancel audit rows too, and the
	// Selector, on-behalf-of and approval columns below must come from the
	// dispatch record, not from a refusal or cancel row. See
	// TestJobQuery_RequesterIsNeverTakenFromTheAuditTrail.
	auditWhere := "\n\tWHERE kind = 'dispatch'"
	recordingWhere := "\n\tWHERE kind IN ('dispatch', 'dispatch_intent')"
	var taskConds []string
	if filter.JobID != "" {
		taskConds = append(taskConds, "job_id = ?")
		auditWhere += "\n\t\tAND job_id = ?"
		recordingWhere += "\n\t\tAND job_id = ?"
		args = []any{filter.JobID}
		if withAudit {
			args = append(args, filter.JobID, filter.JobID)
		}
	}
	if filter.State != nil && *filter.State == jobs.JobStateRunning {
		taskConds = append(taskConds, "job_id IN ("+runningJobIDs+")")
	}
	taskWhere := ""
	if len(taskConds) > 0 {
		taskWhere = "\n\tWHERE " + strings.Join(taskConds, "\n\t\tAND ")
	}
	from = `FROM jobs j
LEFT JOIN (
	SELECT job_id,
		COUNT(*) AS total,
		SUM(CASE WHEN state != 'resolved' THEN 1 ELSE 0 END) AS unresolved,
		MIN(action_kind) AS action_kind,
		MIN(operation_name) AS operation_name,
		MIN(risk_class) AS risk_class,
		` + strings.Join(jobOutcomeSumColumns(), ",\n\t\t") + `
	FROM tasks` + taskWhere + `
	GROUP BY job_id
) t ON t.job_id = j.job_id`
	if withAudit {
		from += `
LEFT JOIN (
	SELECT job_id, MIN(selector) AS selector,
		MIN(asserted_on_behalf_of) AS on_behalf_of, MIN(approval_id) AS approval_id, MIN(grant_id) AS grant_id,
		MIN(args) AS args, MIN(raw_exec_argv) AS raw_exec_argv
	FROM audit` + auditWhere + `
	GROUP BY job_id
) a ON a.job_id = j.job_id
LEFT JOIN (
	SELECT job_id,
		SUM(CASE WHEN kind = 'dispatch_intent' THEN 1 ELSE 0 END) AS intents,
		SUM(CASE WHEN kind = 'dispatch' THEN 1 ELSE 0 END) AS outcomes
	FROM audit` + recordingWhere + `
	GROUP BY job_id
) r ON r.job_id = j.job_id`
	}
	return from, args
}

func (q *sqliteJobQueries) legacyQueryJobs(ctx context.Context, filter jobs.JobQuery, limit int, cursor string) (jobs.JobPage, error) {
	limit = clampPageSize(limit)

	stmt, args := legacyJobQuerySelect(filter)
	conds, whereArgs := legacyBuildJobWhere(filter)
	args = append(args, whereArgs...)

	// The total ignores paging, so it never sees the cursor condition.
	countStmt, countArgs := legacyJobQueryCount(filter)

	var orderBy string
	switch filter.Order {
	case jobs.JobOrderNewestFirst:
		orderBy = ` ORDER BY j.created_at DESC, j.job_id DESC LIMIT ?`
		if cursor != "" {
			lastCreatedAt, lastJobID, err := decodeCursor2(cursor, jobs.ErrInvalidCursor)
			if err != nil {
				return jobs.JobPage{}, err
			}
			conds = append(conds, `(j.created_at < ? OR (j.created_at = ? AND j.job_id < ?))`)
			args = append(args, lastCreatedAt, lastCreatedAt, lastJobID)
		}
	case jobs.JobOrderOldestFirst:
		orderBy = ` ORDER BY ` + jobCreatedAtFixedWidth + ` ASC, j.job_id ASC LIMIT ?`
		if cursor != "" {
			tag, lastCreatedAt, lastJobID, err := decodeCursor3(cursor, jobs.ErrInvalidCursor)
			if err != nil {
				return jobs.JobPage{}, err
			}
			if tag != jobCursorOldestTag {
				return jobs.JobPage{}, jobs.ErrInvalidCursor
			}
			lastKey, err := normalizeAuditTimeText(lastCreatedAt)
			if err != nil {
				return jobs.JobPage{}, fmt.Errorf("%w: %v", jobs.ErrInvalidCursor, err)
			}
			conds = append(conds, `(`+jobCreatedAtFixedWidth+` > ? OR (`+jobCreatedAtFixedWidth+` = ? AND j.job_id > ?))`)
			args = append(args, lastKey, lastKey, lastJobID)
		}
	default:
		return jobs.JobPage{}, fmt.Errorf("query jobs: unknown order %d", filter.Order)
	}

	if len(conds) > 0 {
		stmt += ` WHERE ` + strings.Join(conds, " AND ")
	}
	stmt += orderBy
	args = append(args, limit+1)

	var (
		db       queryer = q.db
		matching int
	)
	if filter.CountMatching {
		// A snapshot read: it must not take the write lock now that write
		// transactions begin IMMEDIATE (sqliteDSN, #833).
		tx, err := q.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
		if err != nil {
			return jobs.JobPage{}, fmt.Errorf("query jobs: begin: %w", err)
		}
		defer tx.Rollback()
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

func legacyJobWhereUsesAudit(filter jobs.JobQuery) bool {
	return filter.OnBehalfOf != ""
}

func legacyBuildJobWhere(filter jobs.JobQuery) (conds []string, args []any) {
	if filter.JobID != "" {
		// Also pushed into both derived tables by legacyJobQuerySelect — see there
		// for why one predicate in three places is the point rather than a
		// duplication.
		conds = append(conds, `j.job_id = ?`)
		args = append(args, filter.JobID)
	}
	if filter.State != nil {
		switch *filter.State {
		case jobs.JobStateRunning:
			// legacyJobQueryFrom pushes the same IN into the Task aggregate (#816);
			// here it lets SQLite SEARCH jobs by key. The COALESCE
			// predicate is redundant with it but keeps the derivation
			// identical to scanJobSummary's.
			conds = append(conds, `j.job_id IN (`+runningJobIDs+`) AND (COALESCE(t.total, 0) > 0 AND COALESCE(t.unresolved, 0) > 0)`)
		default: // JobStateComplete: zero Tasks, or every Task resolved.
			conds = append(conds, `(COALESCE(t.total, 0) = 0 OR COALESCE(t.unresolved, 0) = 0)`)
		}
	}
	if filter.RequesterAccountID != "" {
		// A plain column predicate on the jobs row itself (#616) — no join,
		// no aggregate, and idx_jobs_requester_created_at (migration 0026)
		// serves it directly.
		conds = append(conds, `j.requester_account_id = ?`)
		args = append(args, filter.RequesterAccountID)
	}
	if filter.OnBehalfOf != "" {
		// The derived table's ALIAS, not the raw column: asserted_on_behalf_of
		// is inside the aggregate, and the outer WHERE can only see what the
		// aggregate projected.
		//
		// This predicate lands in the OUTER WHERE and SQLite will not push it
		// into the right operand of a LEFT JOIN (see legacyJobQuerySelect's doc
		// comment), so the aggregate still reads every dispatch row in the
		// trail. Unlike RequesterAccountID above, OnBehalfOf stays
		// audit-joined: it is the caller-asserted lane, which has no home on
		// the jobs row.
		conds = append(conds, `a.on_behalf_of = ?`)
		args = append(args, filter.OnBehalfOf)
	}
	if filter.Operation != "" {
		conds = append(conds, `t.operation_name = ?`)
		args = append(args, filter.Operation)
	}
	if filter.RiskClass != nil {
		conds = append(conds, `t.risk_class = ?`)
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

// appendAssertedAudit writes an audit row of the given kind for jobID that
// asserts onBehalfOf. dispatchAuditRecordFull hardcodes agent-7, so the
// fixture's differing assertions need their own record.
func appendAssertedAudit(t *testing.T, st *Store, id string, kind, jobID, onBehalfOf string, ts time.Time) {
	t.Helper()
	if err := st.Audit().Append(context.Background(), audit.Record{
		ID: id, Timestamp: ts, Kind: kind, Principal: "p",
		Attribution: audit.Attribution{Asserted: audit.Asserted{OnBehalfOf: onBehalfOf}},
		Selector:    "role=" + onBehalfOf, JobID: jobID, NodeID: "n", ActionKind: "operation",
	}); err != nil {
		t.Fatalf("append audit %s: %v", id, err)
	}
}

// TestJobQuery_PageFirstMatchesTheAggregateFirstShape is #919's evidence that
// the page-first statement is a pure reshape: over a heterogeneous fixture,
// every filter, both orders and several page sizes, QueryJobs returns the
// same pages, cursors (compared as strings; each side follows its own Next)
// and totals as the frozen legacyQueryJobs.
//
// The fixture is built to separate a filter that is exactly the aggregate's
// MIN from the plausible rewrites: Jobs whose Tasks differ in operation or
// risk class (a Job is selected only by the lowest, as before), a Raw Exec
// Task (NULL operation) beside an Operation Task, Jobs with two dispatch rows
// asserting different on-behalf-ofs, and Jobs whose refusal or cancel row
// asserts the filtered on-behalf-of while the dispatch row asserts another.
func TestJobQuery_PageFirstMatchesTheAggregateFirstShape(t *testing.T) {
	st, _ := openTestStore(t)
	ctx := context.Background()
	base := time.Date(2026, 8, 20, 0, 0, 0, 0, time.UTC)
	ann := jobs.Requester{AccountID: "acct-ann", AccountName: "ann", Kind: "human"}
	bob := jobs.Requester{AccountID: "acct-bob", AccountName: "bob", Kind: "human"}
	read, mutate := jobs.RiskClassRead, jobs.RiskClassMutate
	op := func(name string, r jobs.RiskClass) jobs.Action {
		return jobs.Action{Kind: jobs.ActionOperation, OperationName: name, RiskClass: r}
	}
	raw := jobs.Action{Kind: jobs.ActionRawExec, RawExecArgv: []string{"/bin/true"}, RiskClass: mutate}
	type task struct {
		action  jobs.Action
		state   jobs.DispatchState
		outcome jobs.Outcome
	}
	fixture := []struct {
		id    string
		who   jobs.Requester
		at    time.Time
		tasks []task
	}{
		{"a", ann, base, []task{{op("system.facts", read), jobs.DispatchStatePending, 0}}},
		// Two operations and two risk classes in one Job.
		{"b", bob, base, []task{{op("system.facts", read), jobs.DispatchStateResolved, jobs.OutcomeSuccess}, {op("service.restart", mutate), jobs.DispatchStateResolved, jobs.OutcomeFailure}}},
		// Raw Exec (NULL operation) mixed with an Operation Task.
		{"c", ann, base.Add(500 * time.Millisecond), []task{{raw, jobs.DispatchStateDispatched, 0}, {op("service.restart", read), jobs.DispatchStateResolved, jobs.OutcomeTimeout}}},
		{"d", jobs.Requester{}, base.Add(time.Second), []task{{raw, jobs.DispatchStateResolved, jobs.OutcomeSuccess}}},
		// No Task at all, tied on created_at with d.
		{"e", bob, base.Add(time.Second), nil},
		{"f", ann, base.Add(1100 * time.Millisecond), []task{{op("service.restart", mutate), jobs.DispatchStatePending, 0}, {op("service.restart", mutate), jobs.DispatchStateResolved, jobs.OutcomeSuccess}}},
		{"g", bob, base.Add(2 * time.Second), []task{{op("system.facts", mutate), jobs.DispatchStateResolved, jobs.OutcomeCancelled}}},
		{"h", ann, base.Add(2*time.Second + 250*time.Millisecond), []task{{op("system.facts", read), jobs.DispatchStateResolved, jobs.OutcomeSuccess}, {op("system.facts", read), jobs.DispatchStateResolved, jobs.OutcomeUnreachable}}},
	}
	for _, f := range fixture {
		var tasks []jobs.Task
		for i, x := range f.tasks {
			tasks = append(tasks, jobs.Task{ID: fmt.Sprintf("%s-t%d", f.id, i), NodeID: "n", Action: x.action, State: x.state, Outcome: x.outcome})
		}
		createJobFixtureBy(t, ctx, st, f.id, f.who, f.at, tasks)
	}

	// a: one dispatch asserting agent-7. b: two dispatch rows asserting
	// different on-behalf-ofs. c: a refusal asserting agent-7 beside a
	// dispatch asserting agent-9. f: a cancel asserting agent-7 and no
	// dispatch row. g: full attribution. h: full attribution, three Nodes.
	appendAssertedAudit(t, st, "x1", audit.KindDispatch, "a", "agent-7", base)
	appendAssertedAudit(t, st, "x2", audit.KindDispatch, "b", "agent-7", base)
	appendAssertedAudit(t, st, "x3", audit.KindDispatch, "b", "agent-1", base)
	appendAssertedAudit(t, st, "x4", audit.KindRefusal, "c", "agent-7", base)
	appendAssertedAudit(t, st, "x5", audit.KindDispatch, "c", "agent-9", base)
	appendAssertedAudit(t, st, "x6", audit.KindJobCancel, "f", "agent-7", base)
	dispatchAuditRecordFull(t, ctx, st, "x7", "g", "n1", jobs.OutcomeCancelled, base)
	for i, n := range []string{"n1", "n2", "n3"} {
		dispatchAuditRecordFull(t, ctx, st, fmt.Sprintf("x8-%d", i), "h", n, jobs.OutcomeSuccess, base.Add(time.Duration(i)*time.Second))
	}

	running, complete := jobs.JobStateRunning, jobs.JobStateComplete
	filters := []jobs.JobQuery{
		{}, {State: &running}, {State: &complete}, {RequesterAccountID: "acct-bob"},
		{Operation: "service.restart"}, {Operation: "system.facts"}, {Operation: "no.such.op"},
		{RiskClass: &mutate}, {RiskClass: &read},
		{OnBehalfOf: "agent-7"}, {OnBehalfOf: "agent-1"}, {OnBehalfOf: "agent-9"},
		{State: &complete, Operation: "system.facts"}, {RiskClass: &mutate, OnBehalfOf: "agent-7"},
		{State: &running, RequesterAccountID: "acct-ann", Since: base},
		{Since: base.Add(time.Second)}, {Until: base}, {JobID: "c"}, {JobID: "e", State: &complete},
		{Operation: "service.restart", RiskClass: &read, OnBehalfOf: "agent-9"},
	}
	q := &sqliteJobQueries{db: st.db}
	for fi, f := range filters {
		for _, order := range []jobs.JobOrder{jobs.JobOrderNewestFirst, jobs.JobOrderOldestFirst} {
			for _, limit := range []int{1, 2, 3, 50} {
				f.Order, f.CountMatching = order, true
				oldCursor, newCursor := "", ""
				for pageNo := 0; ; pageNo++ {
					want, err := q.legacyQueryJobs(ctx, f, limit, oldCursor)
					if err != nil {
						t.Fatalf("filter %d legacy: %v", fi, err)
					}
					got, err := q.QueryJobs(ctx, f, limit, newCursor)
					if err != nil {
						t.Fatalf("filter %d: %v", fi, err)
					}
					if !reflect.DeepEqual(got, want) {
						t.Fatalf("filter %d (%+v) order %d limit %d page %d:\nlegacy %+v\n   new %+v", fi, f, order, limit, pageNo, want, got)
					}
					if want.Next == "" {
						break
					}
					oldCursor, newCursor = want.Next, got.Next
				}
			}
		}
	}

	// The refusals are the same too: an unknown order, and a cursor from the
	// other direction or malformed.
	for _, c := range []struct {
		name   string
		filter jobs.JobQuery
		cursor string
	}{
		{"unknown order", jobs.JobQuery{Order: jobs.JobOrder(99)}, ""},
		{"unknown order with a cursor", jobs.JobQuery{Order: jobs.JobOrder(99)}, "!!"},
		{"malformed newest cursor", jobs.JobQuery{}, "!!"},
		{"malformed oldest cursor", jobs.JobQuery{Order: jobs.JobOrderOldestFirst}, "!!"},
		{"newest cursor on oldest", jobs.JobQuery{Order: jobs.JobOrderOldestFirst}, encodeCursor2("2026-08-20T00:00:00Z", "a")},
		{"oldest cursor on newest", jobs.JobQuery{}, encodeCursor3(jobCursorOldestTag, "2026-08-20T00:00:00.000000000Z", "a")},
		{"oldest cursor, bad time", jobs.JobQuery{Order: jobs.JobOrderOldestFirst}, encodeCursor3(jobCursorOldestTag, "not a time", "a")},
		{"oldest cursor, wrong tag", jobs.JobQuery{Order: jobs.JobOrderOldestFirst}, encodeCursor3("zzz", "2026-08-20T00:00:00.000000000Z", "a")},
	} {
		_, wantErr := q.legacyQueryJobs(ctx, c.filter, 5, c.cursor)
		_, gotErr := q.QueryJobs(ctx, c.filter, 5, c.cursor)
		if wantErr == nil || gotErr == nil {
			t.Errorf("%s: legacy err %v, new err %v; both must refuse", c.name, wantErr, gotErr)
			continue
		}
		if wantErr.Error() != gotErr.Error() {
			t.Errorf("%s: error %q, legacy %q", c.name, gotErr, wantErr)
		}
	}
}
