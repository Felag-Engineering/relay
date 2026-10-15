package store

import (
	"context"
	"database/sql"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/Felag-Engineering/relay/relay/internal/audit"
	"github.com/Felag-Engineering/relay/relay/internal/jobs"
)

// auditquery.go is *sqliteAudit's other interface: audit.QueryRepository, the
// trail's filtered/paginated/aggregating read lane. audit.go's
// Repository (Append + the by-key readers) is unchanged; this file adds
// nothing to it and nothing here can Append.

var _ audit.QueryRepository = (*sqliteAudit)(nil)

// auditQueryColumns is every column audit.Row carries, in scan order. It is
// audit.go's SELECT list (audit.go:96-99) MINUS stdout, stderr, truncated —
// the read lane never selects those, which is what makes D2's acceptance
// criterion ("the seam has no field for it") true of the SQL, not just the
// Go struct, and what keeps paginating the trail cheap: no BLOB ever crosses
// this path.
const auditQueryColumns = `audit_id, ts, kind, principal, selector, job_id, node_id, action_kind, operation_name, args, raw_exec_argv, outcome, reason,
	account_id, account_name, account_role, token_id, auth_method, verified_source,
	asserted_on_behalf_of, asserted_traceparent, asserted_session_ref, asserted_change_ref,
	approval_id, grant_id, approval_answer, decision_channel, plan_hash`

// auditOrderDesc is the read lane's newest-first order, and the exact mirror
// of audit.go's auditOrderAsc.
//
// The ", audit_id DESC" half is not decoration: Query's keyset predicate
// below is "ts < ? OR (ts = ? AND audit_id < ?)", which presumes the rows
// arrive in descending audit_id within a timestamp. Spelling this clause any
// other way — a bare "ORDER BY ts", or the mixed "ORDER BY ts DESC, audit_id"
// — makes the paged walk skip or repeat every row that shares a timestamp
// with a page boundary. TestAuditSQL_EveryOrderByTsCarriesTheTieBreak
// requires this exact text, or auditOrderAsc's, and nothing else.
const auditOrderDesc = `ORDER BY ts DESC, audit_id DESC`

// auditArgKeyPattern bounds Query.ArgKey before it reaches
// json_extract(args, '$.' || ?): defense in depth alongside
// capability.AuditFilter.validate — this store package trusts no
// caller, including one inside the same binary.
var auditArgKeyPattern = regexp.MustCompile(`^[a-z][a-z0-9_]*$`)

// clampPageSize applies audit.DefaultPageSize/MaxPageSize: n <= 0
// becomes the default, and anything above the max is clamped rather than
// refused, so a caller sees the effective limit on the returned Page.
func clampPageSize(n int) int {
	switch {
	case n <= 0:
		return audit.DefaultPageSize
	case n > audit.MaxPageSize:
		return audit.MaxPageSize
	default:
		return n
	}
}

// checkBucketCount is CountsByPrincipal's bucket-count guard, factored
// out so it is testable against a
// synthetic groupCount without materialising audit.MaxCountBuckets+1 rows in
// a real SQLite database. groupCount exceeding the limit is
// audit.ErrInvalidFilter, never a silent truncation.
func checkBucketCount(groupCount int64) error {
	if groupCount > audit.MaxCountBuckets {
		return fmt.Errorf("%w: query would produce %d buckets, exceeding the %d limit; narrow the window or widen the bucket",
			audit.ErrInvalidFilter, groupCount, audit.MaxCountBuckets)
	}
	return nil
}

// Query implements audit.QueryRepository: one page of Rows matching q,
// newest first.
//
// Pagination is keyset, not OFFSET: the cursor is the opaque encoding of the
// last row's (ts, audit_id), and the next page's WHERE adds
// "ts < ? OR (ts = ? AND audit_id < ?)" — the same order the ORDER BY uses,
// which is what makes it stable under concurrent appends (a row inserted
// after a cursor was issued sorts newer, so it appears on an EARLIER page the
// caller already turned, never inside the one they are about to fetch).
//
// The "ts < ?" and "ts = ?" comparisons are TEXT comparisons, and they are
// exact only because every stored ts is the same fixed width (migration
// 0024). decodeAuditCursor's normalisation is what extends that exactness to
// a cursor issued by an older binary, whose ts came back from the driver in
// the trimmed rendering.
//
// LIMIT is requested as limit+1 so Next can be computed from this one round
// trip: a limit+1'th row means there is a next page, and its cursor is drawn
// from the limit'th (the last row actually returned), not the extra one.
func (a *sqliteAudit) Query(ctx context.Context, q audit.Query, limit int, cursor string) (audit.Page, error) {
	limit = clampPageSize(limit)

	conds, args, err := buildAuditWhere(q)
	if err != nil {
		return audit.Page{}, err
	}
	if cursor != "" {
		cts, cid, err := decodeAuditCursor(cursor)
		if err != nil {
			return audit.Page{}, err
		}
		conds = append(conds, `(ts < ? OR (ts = ? AND audit_id < ?))`)
		args = append(args, cts, cts, cid)
	}

	stmt := `SELECT ` + auditQueryColumns + ` FROM audit`
	if len(conds) > 0 {
		stmt += ` WHERE ` + strings.Join(conds, " AND ") //nolint:gosec // G202: conds are buildAuditWhere's fixed fragments; every value is a ? placeholder
	}
	stmt += " " + auditOrderDesc + " LIMIT ?"
	args = append(args, limit+1)

	rows, err := a.db.QueryContext(ctx, stmt, args...)
	if err != nil {
		return audit.Page{}, fmt.Errorf("query audit trail: %w", err)
	}
	defer rows.Close()

	var fetched []audit.Row
	for rows.Next() {
		row, err := scanAuditQueryRow(rows)
		if err != nil {
			return audit.Page{}, err
		}
		fetched = append(fetched, row)
	}
	if err := rows.Err(); err != nil {
		return audit.Page{}, fmt.Errorf("iterate audit trail: %w", err)
	}

	page := audit.Page{Limit: limit}
	hasMore := len(fetched) > limit
	if hasMore {
		fetched = fetched[:limit]
	}
	page.Rows = make([]audit.Row, len(fetched))
	copy(page.Rows, fetched)
	if hasMore && len(fetched) > 0 {
		// The cursor carries the STORED rendering of the last row's ts,
		// re-derived from its parsed Timestamp — never the string that came
		// back from the scan. modernc.org/sqlite reads the ts column's
		// TIMESTAMP decltype and parses the text into a time.Time, and
		// database/sql then renders that into a Go string as trimmed
		// RFC3339Nano. So a scanned ts of a 30-character stored row is 20
		// characters, and a cursor built from it compares unequal to the
		// column it is compared against — which would return the same row
		// forever.
		last := fetched[len(fetched)-1]
		page.Next = encodeAuditCursor(last.Timestamp.UTC().Format(auditTimeLayout), last.ID)
	}
	return page, nil
}

// CountsByPrincipal implements audit.QueryRepository: q's matching Records,
// grouped by verified Account and by a fixed-width time bucket, ascending.
func (a *sqliteAudit) CountsByPrincipal(ctx context.Context, q audit.Query, bucket time.Duration) ([]audit.Bucket, error) {
	conds, args, err := buildAuditWhere(q)
	if err != nil {
		return nil, err
	}
	bucketSeconds := int64(bucket / time.Second)
	if bucketSeconds <= 0 {
		bucketSeconds = 1
	}

	whereClause := ""
	if len(conds) > 0 {
		whereClause = ` WHERE ` + strings.Join(conds, " AND ")
	}

	// Bucket-count guard: count the
	// (account, bucket) groups BEFORE materialising a Bucket struct per
	// group, and ERROR rather than silently truncate. This runs even when a
	// caller's window/bucket combination is otherwise legal — it is the
	// store's own defense-in-depth (audit.MaxCountBuckets' doc comment),
	// independent of capability.MaxAggregateWindow/MinAuditBucket. The
	// counting query itself is cheap regardless of table size: SQLite
	// aggregates COUNT(*) over the grouped subquery in its own engine
	// without handing a row back to Go per group.
	countStmt := `SELECT COUNT(*) FROM (SELECT 1 FROM audit` + whereClause +
		` GROUP BY account_id, (CAST(strftime('%s', ts) AS INTEGER) / ?))`
	countArgs := append(append([]any{}, args...), bucketSeconds)
	var groupCount int64
	if err := a.db.QueryRowContext(ctx, countStmt, countArgs...).Scan(&groupCount); err != nil {
		return nil, fmt.Errorf("count audit principal buckets: %w", err)
	}
	if err := checkBucketCount(groupCount); err != nil {
		return nil, err
	}

	// strftime('%s', ts) parses ts back into a Unix timestamp regardless of
	// how many fractional digits it carries — pinned by
	// TestAuditQuery_CountsByPrincipal_ParsesFractionalTimestamps against a
	// 9-fractional-digit value, since a driver that could not parse RFC3339Nano
	// text here would mis-bucket silently rather than fail loudly.
	//
	// GROUP BY/ORDER BY reference the bucket_start alias rather than
	// repeating the expression: SQLite resolves an alias against the SELECT
	// list in both clauses, so the bucket width is bound as a parameter
	// exactly once.
	stmt := `SELECT account_id, account_name, (CAST(strftime('%s', ts) AS INTEGER) / ?) * ? AS bucket_start, COUNT(*)
		FROM audit` + whereClause + `
		GROUP BY account_id, account_name, bucket_start
		ORDER BY bucket_start ASC`

	fullArgs := append([]any{bucketSeconds, bucketSeconds}, args...)

	rows, err := a.db.QueryContext(ctx, stmt, fullArgs...)
	if err != nil {
		return nil, fmt.Errorf("count audit records by principal: %w", err)
	}
	defer rows.Close()

	var out []audit.Bucket
	for rows.Next() {
		var accountID, accountName sql.NullString
		var bucketStart int64
		var count int
		if err := rows.Scan(&accountID, &accountName, &bucketStart, &count); err != nil {
			return nil, fmt.Errorf("scan audit principal bucket: %w", err)
		}
		out = append(out, audit.Bucket{
			AccountID:   accountID.String,
			AccountName: accountName.String,
			Start:       time.Unix(bucketStart, 0).UTC(),
			Count:       count,
		})
	}
	return out, rows.Err()
}

// reachTargetExpr builds the COALESCE chain that names WHAT a Record's
// Args touched, in audit.TargetArgKeys' precedence order. Built FROM
// TargetArgKeys, rather than hand-written and separately pinned, so the SQL
// cannot drift from the one Go definition.
//
// audit.TargetArgKeys is a package-level `var`, not a const — it is the ONE
// value interpolated directly into SQL by fmt.Sprintf below rather than
// bound as a parameter. Nothing assigns
// to it today, so this is not attacker-reachable, but each key is validated
// against auditArgKeyPattern before it reaches the query string, exactly as
// Query.ArgKey is re-validated above — defense in depth so a future
// assignment to the var cannot become the lane's one var-to-SQL string path.
func reachTargetExpr() (string, error) {
	parts := make([]string, len(audit.TargetArgKeys))
	for i, key := range audit.TargetArgKeys {
		if !auditArgKeyPattern.MatchString(key) {
			return "", fmt.Errorf("audit: TargetArgKeys[%d] %q is not a valid identifier (^[a-z][a-z0-9_]*$)", i, key)
		}
		parts[i] = fmt.Sprintf("json_extract(args, '$.%s')", key)
	}
	return "COALESCE(" + strings.Join(parts, ", ") + ", '')", nil
}

// ReachCounts implements audit.QueryRepository: q's call count, distinct
// targets, and distinct Nodes: how far its matching Records reached.
// NULL/empty node_id is excluded from the distinct-Node count via the CASE,
// matching COUNT(DISTINCT ...)'s own NULL-skipping so an unset Node never
// counts as one.
//
// Residual: this evaluates a 4-way
// json_extract COALESCE per row with no index and no LIMIT, so even a filter
// that looks narrow to the caller is a full scan of the largest table.
// capability.AuditFilter's required, bounded Since/Until window on this
// path (F1's validateWindow) is what bounds the scan; indexing JSON is out
// of scope here (SQLite refuses date functions in indexed expressions, and
// this migration is additive-index-only).
func (a *sqliteAudit) ReachCounts(ctx context.Context, q audit.Query) (audit.Reach, error) {
	conds, args, err := buildAuditWhere(q)
	if err != nil {
		return audit.Reach{}, err
	}
	targetExpr, err := reachTargetExpr()
	if err != nil {
		return audit.Reach{}, err
	}

	//nolint:gosec // G201: targetExpr is built from audit.TargetArgKeys, each checked against ^[a-z][a-z0-9_]*$
	stmt := fmt.Sprintf(`SELECT COUNT(*),
		COUNT(DISTINCT operation_name || ' ' || %s),
		COUNT(DISTINCT CASE WHEN node_id IS NOT NULL AND node_id != '' THEN node_id END)
		FROM audit`, targetExpr)
	if len(conds) > 0 {
		stmt += ` WHERE ` + strings.Join(conds, " AND ")
	}

	var reach audit.Reach
	row := a.db.QueryRowContext(ctx, stmt, args...)
	if err := row.Scan(&reach.Calls, &reach.DistinctTargets, &reach.DistinctNodes); err != nil {
		return audit.Reach{}, fmt.Errorf("count audit reach: %w", err)
	}
	return reach, nil
}

// buildAuditWhere translates an audit.Query into parameterised SQL
// conditions (ANDed by the caller) and their bound arguments, in the same
// order as the returned slice — never string-interpolated, including
// ArgKey (re-validated here even though capability.AuditFilter.validate
// already checked it: this package trusts no caller).
func buildAuditWhere(q audit.Query) (conds []string, args []any, err error) {
	if len(q.Kinds) > 0 {
		placeholders := make([]string, len(q.Kinds))
		for i, k := range q.Kinds {
			placeholders[i] = "?"
			args = append(args, k)
		}
		conds = append(conds, "kind IN ("+strings.Join(placeholders, ", ")+")")
	}
	if q.AccountID != "" {
		conds = append(conds, "account_id = ?")
		args = append(args, q.AccountID)
	}
	if q.OnBehalfOf != "" {
		// Exact match only, never LIKE — mirrors audit.go's ByOnBehalfOf: the
		// value is caller-controlled.
		conds = append(conds, "asserted_on_behalf_of = ?")
		args = append(args, q.OnBehalfOf)
	}
	if len(q.Operations) > 0 {
		placeholders := make([]string, len(q.Operations))
		for i, op := range q.Operations {
			placeholders[i] = "?"
			args = append(args, op)
		}
		conds = append(conds, "operation_name IN ("+strings.Join(placeholders, ", ")+")")
	}
	if q.NodeID != "" {
		conds = append(conds, "node_id = ?")
		args = append(args, q.NodeID)
	}
	if q.JobID != "" {
		conds = append(conds, "job_id = ?")
		args = append(args, q.JobID)
	}
	if q.ApprovalID != "" {
		conds = append(conds, "approval_id = ?")
		args = append(args, q.ApprovalID)
	}
	if q.GrantID != "" {
		conds = append(conds, "grant_id = ?")
		args = append(args, q.GrantID)
	}
	if q.Outcome != nil {
		conds = append(conds, "outcome = ?")
		args = append(args, int(*q.Outcome))
	}
	if !q.Since.IsZero() {
		conds = append(conds, "ts >= ?")
		args = append(args, secondPrefix(q.Since))
	}
	if !q.Until.IsZero() {
		// Widening (D4): the exclusive bound is the START OF THE SECOND AFTER
		// Until, so Until's own second is included whole even though ts text
		// only orders correctly at second granularity — see secondPrefix.
		conds = append(conds, "ts < ?")
		args = append(args, secondPrefix(q.Until.Add(time.Second)))
	}
	if q.ArgValuePrefix != "" {
		if !auditArgKeyPattern.MatchString(q.ArgKey) {
			return nil, nil, fmt.Errorf("%w: arg key %q is not a valid identifier", audit.ErrInvalidFilter, q.ArgKey)
		}
		conds = append(conds, `json_extract(args, '$.' || ?) LIKE ? ESCAPE '\'`)
		args = append(args, q.ArgKey, escapeLikePrefix(q.ArgValuePrefix)+"%")
	}
	return conds, args, nil
}

// secondPrefix formats t, floored to the whole second, and returns its
// 19-character date/time prefix ("2006-01-02T15:04:05").
//
// It is NOT a workaround for the text format: the whole stored string
// orders correctly as TEXT, because migration 0024 made every ts
// fixed-width.
//
// It stays because the WIDENING it produces on Until is a deliberate filter
// semantic (D4): buildAuditWhere passes secondPrefix(Until + 1s) as an
// exclusive bound, so Until's own second is included whole. Narrowing that to
// nanosecond precision would change results for every caller of the read
// lane, which is a different decision from this one.
func secondPrefix(t time.Time) string {
	s := t.UTC().Truncate(time.Second).Format(timeLayout)
	if len(s) > 19 {
		s = s[:19]
	}
	return s
}

// escapeLikePrefix escapes the LIKE metacharacters (and the escape character
// itself) in a caller-supplied prefix, so it matches literally rather than as
// a pattern, then the caller appends the trailing "%" that turns it into a
// prefix match.
func escapeLikePrefix(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch r {
		case '\\', '%', '_':
			b.WriteByte('\\')
		}
		b.WriteRune(r)
	}
	return b.String()
}

// encodeAuditCursor is the opaque cursor Query returns as Page.Next: the
// (ts, audit_id) of the last row emitted, with ts in the STORED rendering
// (auditTimeLayout) so it compares byte-exactly against the column — see
// querycursor.go and Query's comment at the call site.
func encodeAuditCursor(ts, id string) string {
	return encodeCursor2(ts, id)
}

// decodeAuditCursor is encodeAuditCursor's inverse. Strict: a cursor that
// does not decode to base64, does not split into exactly two non-empty parts,
// or whose ts part is not RFC3339, is audit.ErrInvalidCursor — never a silent
// reset to page one, which would loop a paging client forever.
//
// The ts part is NORMALISED to the stored rendering. A cursor issued
// before migration 0024 and one issued after are byte-identical — both are
// the driver's trimmed RFC3339Nano re-rendering of the column — so "reject
// stale cursors" is not implementable: there is nothing to detect. Normalising
// is what makes both map to exactly the text the migrated row holds, so a
// pre-0024 cursor neither skips a row nor repeats one.
func decodeAuditCursor(cursor string) (ts, id string, err error) {
	ts, id, err = decodeCursor2(cursor, audit.ErrInvalidCursor)
	if err != nil {
		return "", "", err
	}
	stored, err := normalizeAuditTimeText(ts)
	if err != nil {
		return "", "", fmt.Errorf("%w: cursor timestamp %q is not RFC3339", audit.ErrInvalidCursor, ts)
	}
	return stored, id, nil
}

// scanAuditQueryRow scans one row of auditQueryColumns into an audit.Row.
//
// It does not hand back a "raw stored ts text" for the cursor: there is no
// such thing on this path. The driver parses the TIMESTAMP-declared column
// into a time.Time and database/sql re-renders it as trimmed RFC3339Nano, so
// the scanned string is not the stored bytes and never was. Query
// builds the cursor from Timestamp instead.
func scanAuditQueryRow(row rowScanner) (audit.Row, error) {
	var (
		id, ts, kind, principal, selector, jobID, actionKind string
		nodeID                                               sql.NullString
		operationName                                        sql.NullString
		argsJSON, argvJSON                                   sql.NullString
		outcome                                              int
		reason                                               sql.NullString
		accountID, accountName, accountRole, tokenID         sql.NullString
		authMethod, verifiedSource                           sql.NullString
		onBehalfOf, traceparent, sessionRef, changeRef       sql.NullString
		approvalID, grantID                                  sql.NullString
		approvalAnswer, decisionChannel, planHash            sql.NullString
	)
	if err := row.Scan(&id, &ts, &kind, &principal, &selector, &jobID, &nodeID, &actionKind,
		&operationName, &argsJSON, &argvJSON, &outcome, &reason,
		&accountID, &accountName, &accountRole, &tokenID, &authMethod, &verifiedSource,
		&onBehalfOf, &traceparent, &sessionRef, &changeRef,
		&approvalID, &grantID, &approvalAnswer, &decisionChannel, &planHash); err != nil {
		return audit.Row{}, fmt.Errorf("scan audit query row: %w", err)
	}

	tsTime, err := parseTime(sql.NullString{String: ts, Valid: true})
	if err != nil {
		return audit.Row{}, fmt.Errorf("parse ts for audit record %q: %w", id, err)
	}
	argsMap, err := decodeStringMap(argsJSON)
	if err != nil {
		return audit.Row{}, err
	}
	argv, err := decodeStringSlice(argvJSON)
	if err != nil {
		return audit.Row{}, err
	}

	return audit.Row{
		ID:        id,
		Timestamp: tsTime,
		Kind:      kind,
		Principal: principal,
		Attribution: audit.Attribution{
			Verified: audit.Verified{
				AccountID:   accountID.String,
				AccountName: accountName.String,
				Role:        accountRole.String,
				TokenID:     tokenID.String,
				Method:      authMethod.String,
				Source:      verifiedSource.String,
			},
			Asserted: audit.Asserted{
				OnBehalfOf:  onBehalfOf.String,
				Traceparent: traceparent.String,
				SessionRef:  sessionRef.String,
				ChangeRef:   changeRef.String,
			},
		},
		Selector:        selector,
		JobID:           jobID,
		NodeID:          nodeID.String,
		ActionKind:      actionKind,
		OperationName:   operationName.String,
		Args:            argsMap,
		RawExecArgv:     argv,
		Outcome:         jobs.Outcome(outcome),
		Reason:          reason.String,
		ApprovalID:      approvalID.String,
		GrantID:         grantID.String,
		ApprovalAnswer:  approvalAnswer.String,
		DecisionChannel: decisionChannel.String,
		PlanHash:        planHash.String,
	}, nil
}
