package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/approval"
)

// sqliteApprovals implements approval.Repository against the
// approval_requests / approval_decisions tables (migration 0012).
type sqliteApprovals struct {
	db *sql.DB
}

var _ approval.Repository = (*sqliteApprovals)(nil)

// Create persists a new pending Request.
func (a *sqliteApprovals) Create(ctx context.Context, r approval.Request) error {
	_, err := a.db.ExecContext(ctx, `
		INSERT INTO approval_requests (
			request_id, job_id, plan_hash, requested_by_id, requested_by,
			plan_summary, matched_rules, action_kind, risk_class,
			require_count, require_audience, requester_allowed, require_channel, require_ttl_ns,
			state, created_at, expires_at, resolved_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		r.ID, nullString(r.JobID), r.PlanHash, r.RequestedByID, r.RequestedBy,
		r.Summary, strings.Join(r.MatchedRules, ","),
		approval.ActionKindName(r.ActionKind), approval.RiskClassName(r.RiskClass),
		r.Require.Count, strings.Join(r.Require.Audience, ","), boolToInt(r.Require.RequesterAllowed),
		int(r.Require.Channel), int64(r.Require.TTL),
		int(r.State), formatTime(roundTripTime(r.CreatedAt)), formatTime(roundTripTime(r.ExpiresAt)),
		formatTime(roundTripTime(r.ResolvedAt)),
	)
	if err != nil {
		return fmt.Errorf("insert approval request: %w", err)
	}
	return nil
}

const approvalSelect = `
	SELECT request_id, job_id, plan_hash, requested_by_id, requested_by,
	       plan_summary, matched_rules, action_kind, risk_class,
	       require_count, require_audience, requester_allowed, require_channel, require_ttl_ns,
	       state, created_at, expires_at, resolved_at
	  FROM approval_requests`

// Get returns the Request with the given ID.
func (a *sqliteApprovals) Get(ctx context.Context, id string) (approval.Request, error) {
	return a.getWith(ctx, a.db, approvalSelect+` WHERE request_id = ?`, id)
}

// ByJob returns the Request bound to jobID.
func (a *sqliteApprovals) ByJob(ctx context.Context, jobID string) (approval.Request, error) {
	if jobID == "" {
		return approval.Request{}, approval.ErrNotFound
	}
	return a.getWith(ctx, a.db, approvalSelect+` WHERE job_id = ?`, jobID)
}

// ByPlanHash returns the most recent Request for planHash.
func (a *sqliteApprovals) ByPlanHash(ctx context.Context, planHash string) (approval.Request, error) {
	if planHash == "" {
		return approval.Request{}, approval.ErrNotFound
	}
	return a.getWith(ctx, a.db,
		approvalSelect+` WHERE plan_hash = ? ORDER BY created_at DESC, request_id DESC LIMIT 1`, planHash)
}

// querier is the shared surface of *sql.DB and *sql.Tx this file needs, so the
// scan helpers work identically inside and outside a transaction.
type querier interface {
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
}

func (a *sqliteApprovals) getWith(ctx context.Context, q querier, query string, args ...any) (approval.Request, error) {
	row := q.QueryRowContext(ctx, query, args...)
	r, err := scanApproval(row.Scan)
	if errors.Is(err, sql.ErrNoRows) {
		return approval.Request{}, approval.ErrNotFound
	}
	if err != nil {
		return approval.Request{}, err
	}
	decisions, err := a.decisionsFor(ctx, q, r.ID)
	if err != nil {
		return approval.Request{}, err
	}
	r.Decisions = decisions
	return r, nil
}

// scanApproval reads one approval_requests row through the given scan func,
// which is *sql.Row.Scan or *sql.Rows.Scan.
func scanApproval(scan func(dest ...any) error) (approval.Request, error) {
	var (
		r          approval.Request
		jobID      sql.NullString
		audience   string
		matched    string
		actionKind string
		riskClass  string
		reqAllowed int
		channel    int
		ttlNS      int64
		state      int
		created    sql.NullString
		expires    sql.NullString
		resolved   sql.NullString
	)
	if err := scan(
		&r.ID, &jobID, &r.PlanHash, &r.RequestedByID, &r.RequestedBy,
		&r.Summary, &matched, &actionKind, &riskClass,
		&r.Require.Count, &audience, &reqAllowed, &channel, &ttlNS,
		&state, &created, &expires, &resolved,
	); err != nil {
		return approval.Request{}, err
	}

	r.JobID = jobID.String
	r.MatchedRules = splitList(matched)
	// An unrecognized stored name reads back as the UNSPECIFIED value rather
	// than erroring, and that is the fail-closed direction here: authz denies
	// an unspecified Action kind for every role, so a row this build cannot
	// interpret becomes undecidable instead of decidable by the weakest floor.
	r.ActionKind = approval.ParseActionKind(actionKind)
	r.RiskClass = approval.ParseRiskClassName(riskClass)
	r.Require.Audience = splitList(audience)
	r.Require.RequesterAllowed = reqAllowed != 0
	r.Require.Channel = approval.Channel(channel)
	r.Require.TTL = time.Duration(ttlNS)
	r.State = approval.State(state)

	var err error
	if r.CreatedAt, err = parseTime(created); err != nil {
		return approval.Request{}, fmt.Errorf("parse approval created_at: %w", err)
	}
	if r.ExpiresAt, err = parseTime(expires); err != nil {
		return approval.Request{}, fmt.Errorf("parse approval expires_at: %w", err)
	}
	if r.ResolvedAt, err = parseTime(resolved); err != nil {
		return approval.Request{}, fmt.Errorf("parse approval resolved_at: %w", err)
	}
	return r, nil
}

func (a *sqliteApprovals) decisionsFor(ctx context.Context, q querier, requestID string) ([]approval.Decision, error) {
	rows, err := q.QueryContext(ctx, `
		SELECT account_id, account, approve, reason, channel, plan_hash, decider_human, on_behalf_of, decided_at
		  FROM approval_decisions WHERE request_id = ? ORDER BY decision_id`, requestID)
	if err != nil {
		return nil, fmt.Errorf("select approval decisions: %w", err)
	}
	defer rows.Close() //nolint:errcheck

	var out []approval.Decision
	for rows.Next() {
		var (
			d       approval.Decision
			approve int
			channel int
			human   int
			// NULL for every out-of-band decision and for every row written
			// before ADR-0029, so it must be scanned as nullable — a plain
			// string would fail the scan on existing data.
			onBehalf sql.NullString
			at       sql.NullString
		)
		if err := rows.Scan(&d.AccountID, &d.Account, &approve, &d.Reason, &channel, &d.PlanHash, &human, &onBehalf, &at); err != nil {
			return nil, fmt.Errorf("scan approval decision: %w", err)
		}
		d.Approve = approve != 0
		d.Channel = approval.Channel(channel)
		d.DeciderHuman = human != 0
		d.OnBehalfOf = onBehalf.String
		var err error
		if d.At, err = parseTime(at); err != nil {
			return nil, fmt.Errorf("parse approval decided_at: %w", err)
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// Pending returns every still-pending Request, oldest deadline first.
func (a *sqliteApprovals) Pending(ctx context.Context) ([]approval.Request, error) {
	return a.listWith(ctx, a.db,
		approvalSelect+` WHERE state = ? ORDER BY expires_at, request_id`, int(approval.StatePending))
}

func (a *sqliteApprovals) listWith(ctx context.Context, q querier, query string, args ...any) ([]approval.Request, error) {
	rows, err := q.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("select approval requests: %w", err)
	}
	defer rows.Close() //nolint:errcheck

	var out []approval.Request
	for rows.Next() {
		r, err := scanApproval(rows.Scan)
		if err != nil {
			return nil, fmt.Errorf("scan approval request: %w", err)
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	// Decisions are loaded after the rows cursor is drained: SQLite allows one
	// active statement per connection in this driver's configuration, and
	// querying inside the loop would deadlock against the open cursor.
	for i := range out {
		d, err := a.decisionsFor(ctx, q, out[i].ID)
		if err != nil {
			return nil, err
		}
		out[i].Decisions = d
	}
	return out, nil
}

// RecordDecision appends d and persists the resulting transition atomically.
//
// The whole read-modify-write runs in one transaction. Without it, two
// approvers answering a count:2 Request at the same moment could each read
// "0 approvals recorded" and each append one, leaving a Request that never
// reaches StateApproved — or, with a different interleaving, one that reaches
// it while a decision row is lost. Quorum arithmetic done outside a
// transaction is quorum theatre.
func (a *sqliteApprovals) RecordDecision(ctx context.Context, id string, d approval.Decision, now time.Time) (approval.Request, error) {
	tx, err := a.db.BeginTx(ctx, nil)
	if err != nil {
		return approval.Request{}, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck

	cur, err := a.getWith(ctx, tx, approvalSelect+` WHERE request_id = ?`, id)
	if err != nil {
		return approval.Request{}, err
	}

	// The domain type owns every eligibility rule; the store only persists the
	// result. Duplicating the checks here would be a second implementation of
	// the security-relevant logic, which is exactly how the two drift.
	updated, err := cur.Decide(d, now)
	if err != nil {
		return approval.Request{}, err
	}

	if _, err := tx.ExecContext(ctx, `
		INSERT INTO approval_decisions (request_id, account_id, account, approve, reason, channel, plan_hash, decider_human, on_behalf_of, decided_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		id, d.AccountID, d.Account, boolToInt(d.Approve), d.Reason, int(d.Channel), d.PlanHash,
		boolToInt(d.DeciderHuman), nullIfEmpty(d.OnBehalfOf), formatTime(roundTripTime(d.At)),
	); err != nil {
		return approval.Request{}, fmt.Errorf("insert approval decision: %w", err)
	}

	if _, err := tx.ExecContext(ctx, `
		UPDATE approval_requests SET state = ?, resolved_at = ? WHERE request_id = ?`,
		int(updated.State), formatTime(roundTripTime(updated.ResolvedAt)), id,
	); err != nil {
		return approval.Request{}, fmt.Errorf("update approval request state: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return approval.Request{}, fmt.Errorf("commit approval decision: %w", err)
	}
	return updated, nil
}

// BindJob records the Job created for an approved Request.
func (a *sqliteApprovals) BindJob(ctx context.Context, id, jobID string) error {
	res, err := a.db.ExecContext(ctx,
		`UPDATE approval_requests SET job_id = ? WHERE request_id = ?`, jobID, id)
	if err != nil {
		return fmt.Errorf("bind job to approval request: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("bind job to approval request: rows affected: %w", err)
	}
	if n == 0 {
		return approval.ErrNotFound
	}
	return nil
}

// ExpirePending moves lapsed pending Requests to StateExpired.
//
// The scan and the update run in one transaction so the returned set is exactly
// the set that changed — the caller emits one audit record per element, and a
// double-run must not produce duplicate expiry records.
func (a *sqliteApprovals) ExpirePending(ctx context.Context, now time.Time) ([]approval.Request, error) {
	tx, err := a.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck

	stamp := roundTripTime(now)
	due, err := a.listWith(ctx, tx,
		approvalSelect+` WHERE state = ? AND expires_at <= ? ORDER BY expires_at, request_id`,
		int(approval.StatePending), formatTime(stamp))
	if err != nil {
		return nil, err
	}
	if len(due) == 0 {
		return nil, nil
	}

	out := make([]approval.Request, 0, len(due))
	for _, r := range due {
		expired, err := r.Expire(stamp)
		if err != nil {
			// Unreachable: the query filtered to StatePending.
			return nil, fmt.Errorf("expire approval request %q: %w", r.ID, err)
		}
		if _, err := tx.ExecContext(ctx,
			`UPDATE approval_requests SET state = ?, resolved_at = ? WHERE request_id = ? AND state = ?`,
			int(expired.State), formatTime(expired.ResolvedAt), r.ID, int(approval.StatePending),
		); err != nil {
			return nil, fmt.Errorf("update expired approval request %q: %w", r.ID, err)
		}
		out = append(out, expired)
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit approval expiry: %w", err)
	}
	return out, nil
}

func nullString(s string) any {
	if s == "" {
		return nil
	}
	return s
}

// splitList is the inverse of strings.Join for the comma-separated list
// columns. An empty column is an empty slice, never []string{""}.
func splitList(s string) []string {
	if s == "" {
		return nil
	}
	return strings.Split(s, ",")
}
