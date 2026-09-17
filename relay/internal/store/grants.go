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

// sqliteGrants implements approval.GrantRepository against the approval_grants
// table (migration 0014).
//
// # The matcher lives in the domain, never in SQL
//
// The one design rule this file follows above all others: **SQL narrows the
// candidate set, the domain decides.** ClaimGrant's query filters by requester,
// class, and window — cheap, exact, indexable — and then calls
// approval.Grant.Covers on each candidate to decide.
//
// Expressing Covers in SQL would be a second implementation of a security
// predicate. The fan-out ceiling, the Operations allow-list semantics (empty
// covers nothing), the Raw Exec opt-in, and the half-open window would each
// have to be re-derived in a dialect with different NULL and case-folding
// rules, and the two copies would drift the first time either changed. One of
// them would then be wrong, and the wrong one would be the one that decides
// whether a fleet action needs a human.
type sqliteGrants struct {
	db *sql.DB
}

var _ approval.GrantRepository = (*sqliteGrants)(nil)

const grantSelect = `
	SELECT grant_id, request_id,
	       scope_account, scope_risk_class, scope_max_fan_out, scope_operations,
	       scope_raw_exec, scope_selector_namespace,
	       starts_at, expires_at, max_uses, uses, summary, created_at,
	       revoked_at, revoked_by, revoke_reason
	  FROM approval_grants`

// CreateGrant persists a validated Grant.
//
// Validate runs HERE as well as at the caller, deliberately. An unbounded grant
// must be impossible to STORE, not merely impossible to create through today's
// API — a future surface, a migration script, or a test helper that skipped the
// caller-side check must still not be able to write a standing authorization
// into the table.
func (g *sqliteGrants) CreateGrant(ctx context.Context, gr approval.Grant) error {
	if err := gr.Validate(); err != nil {
		return err
	}
	_, err := g.db.ExecContext(ctx, `
		INSERT INTO approval_grants (
			grant_id, request_id,
			scope_account, scope_risk_class, scope_max_fan_out, scope_operations,
			scope_raw_exec, scope_selector_namespace,
			starts_at, expires_at, max_uses, uses, summary, created_at,
			revoked_at, revoked_by, revoke_reason
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		gr.ID, gr.RequestID,
		gr.Scope.Account, approval.RiskClassName(gr.Scope.RiskClass), gr.Scope.MaxFanOut,
		strings.Join(gr.Scope.Operations, ","), boolToInt(gr.Scope.RawExec),
		// Always empty: no Grant created after #482 is pinned. Validate refuses
		// LegacyNamespacePin, and this literal means no field can reintroduce a
		// pin.
		"",
		formatTime(roundTripTime(gr.StartsAt)), formatTime(roundTripTime(gr.ExpiresAt)),
		gr.MaxUses, gr.Uses, gr.Summary, formatTime(roundTripTime(gr.CreatedAt)),
		nullTime(gr.RevokedAt), gr.RevokedBy, gr.RevokeReason,
	)
	if err != nil {
		return fmt.Errorf("insert approval grant: %w", err)
	}
	return nil
}

// GetGrant returns one Grant by ID.
func (g *sqliteGrants) GetGrant(ctx context.Context, id string) (approval.Grant, error) {
	row := g.db.QueryRowContext(ctx, grantSelect+` WHERE grant_id = ?`, id)
	gr, err := scanGrant(row.Scan)
	if errors.Is(err, sql.ErrNoRows) {
		return approval.Grant{}, approval.ErrGrantNotFound
	}
	if err != nil {
		return approval.Grant{}, err
	}
	return gr, nil
}

// GrantByRequest returns the Grant an approval Request authorized, in whatever
// state it is in.
//
// NO Active(now) filter and no `revoked_at IS NULL` guard, which is the mistake
// a copy of ClaimGrant's query would make: this read exists precisely to return
// the revoked, expired and exhausted ones. It releases nothing — the claim path
// is ClaimGrant, and it is the only query here that writes.
//
// request_id is indexed (migration 0014) but NOT unique, so the ordering is
// load-bearing rather than tidy: without it a duplicate would make this return
// an arbitrary row. Today RequestGrant mints one Request per Grant, so the
// newest is the only one.
func (g *sqliteGrants) GrantByRequest(ctx context.Context, requestID string) (approval.Grant, error) {
	row := g.db.QueryRowContext(ctx,
		grantSelect+` WHERE request_id = ? ORDER BY created_at DESC, grant_id DESC LIMIT 1`, requestID)
	gr, err := scanGrant(row.Scan)
	if errors.Is(err, sql.ErrNoRows) {
		return approval.Grant{}, approval.ErrGrantNotFound
	}
	if err != nil {
		return approval.Grant{}, err
	}
	return gr, nil
}

// ActiveGrants returns every Grant that could still cover something at now.
//
// The clock filter is applied by the DOMAIN (Grant.Active), not by the query,
// for the same reason Covers is: one implementation of "is this still live",
// used by the queue view and the claim path alike.
func (g *sqliteGrants) ActiveGrants(ctx context.Context, now time.Time) ([]approval.Grant, error) {
	rows, err := g.db.QueryContext(ctx, grantSelect+` ORDER BY created_at DESC, grant_id DESC`)
	if err != nil {
		return nil, fmt.Errorf("select approval grants: %w", err)
	}
	defer rows.Close() //nolint:errcheck

	var out []approval.Grant
	for rows.Next() {
		gr, err := scanGrant(rows.Scan)
		if err != nil {
			return nil, fmt.Errorf("scan approval grant: %w", err)
		}
		if gr.Active(now) {
			out = append(out, gr)
		}
	}
	return out, rows.Err()
}

// ClaimGrant atomically finds a Grant covering d and consumes one use.
//
// The whole find-and-consume runs in ONE transaction, and the UPDATE carries
// its own `uses < max_uses` guard. Both matter, and for different reasons:
//
//   - The transaction stops two concurrent dispatches from both reading the
//     same remaining use.
//   - The conditional UPDATE means that even if a candidate went stale between
//     the SELECT and the UPDATE, the write affects zero rows and this falls
//     through to the next candidate rather than over-spending the grant.
//
// A grant bounded at 20 releasing 21 dispatches would not be a counting bug; it
// would be a human's stated limit being wrong, which is the one thing the
// mechanism promises.
func (g *sqliteGrants) ClaimGrant(ctx context.Context, d approval.Dispatch, now time.Time) (approval.Grant, bool, error) {
	tx, err := g.db.BeginTx(ctx, nil)
	if err != nil {
		return approval.Grant{}, false, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck

	// Narrow cheaply on the exact-match, indexed columns. This is an
	// OPTIMIZATION and nothing more: every candidate it returns is still put to
	// Grant.Covers below, so a query that over-selects is merely slower, never
	// more permissive.
	//
	// The EXISTS clause is the AUTHORIZATION LINK, and it is the one predicate
	// here that is not merely a narrowing: a Grant is claimable only while its
	// authorizing approval Request is in the approved state. A grant row exists
	// from the moment one is requested, so without this a pending — or denied —
	// grant request would be live the instant it was written.
	//
	// It tests the request's STATE rather than Satisfied(now). Satisfied also
	// asks the clock, and the two deadlines answer different questions: the
	// Request's TTL bounds how long an unanswered ask stays redeemable, while
	// the Grant's own window bounds how long the answer stays good. Requiring
	// both would silently cap every grant at the request TTL (4h by default),
	// which is not what the approver was shown.
	rows, err := tx.QueryContext(ctx,
		grantSelect+` WHERE scope_account = ? AND scope_risk_class = ? AND revoked_at IS NULL
		              AND EXISTS (
		                  SELECT 1 FROM approval_requests r
		                   WHERE r.request_id = approval_grants.request_id
		                     AND r.state = ?
		              )
		              ORDER BY expires_at ASC, grant_id ASC`,
		d.Account, approval.RiskClassName(d.RiskClass), int(approval.StateApproved))
	if err != nil {
		return approval.Grant{}, false, fmt.Errorf("select candidate grants: %w", err)
	}

	var candidates []approval.Grant
	for rows.Next() {
		gr, err := scanGrant(rows.Scan)
		if err != nil {
			rows.Close() //nolint:errcheck
			return approval.Grant{}, false, fmt.Errorf("scan candidate grant: %w", err)
		}
		candidates = append(candidates, gr)
	}
	if err := rows.Err(); err != nil {
		rows.Close() //nolint:errcheck
		return approval.Grant{}, false, err
	}
	// Drained before any write: this driver allows one active statement per
	// connection, so writing inside the loop would deadlock against the cursor
	// (the same constraint approvals.go's listWith documents).
	rows.Close() //nolint:errcheck

	// Soonest-expiring first, so a grant about to lapse is spent before one
	// with room left — the operator's earlier, narrower window is used up
	// rather than stranded.
	for _, gr := range candidates {
		if !gr.Covers(d, now) {
			continue
		}
		res, err := tx.ExecContext(ctx,
			`UPDATE approval_grants SET uses = uses + 1
			  WHERE grant_id = ? AND uses < max_uses AND revoked_at IS NULL`, gr.ID)
		if err != nil {
			return approval.Grant{}, false, fmt.Errorf("consume approval grant: %w", err)
		}
		n, err := res.RowsAffected()
		if err != nil {
			return approval.Grant{}, false, fmt.Errorf("consume approval grant: rows affected: %w", err)
		}
		if n == 0 {
			// Raced or revoked between SELECT and UPDATE. Try the next one.
			continue
		}
		if err := tx.Commit(); err != nil {
			return approval.Grant{}, false, fmt.Errorf("commit grant claim: %w", err)
		}
		gr.Uses++
		return gr, true, nil
	}

	return approval.Grant{}, false, nil
}

// RevokeGrant ends a Grant early.
//
// Revoking one that is already revoked or already lapsed returns
// ErrGrantNotActive rather than succeeding quietly. An operator reaching for
// this is usually mid-incident and needs to know whether they actually closed
// the window or were looking at a stale queue.
func (g *sqliteGrants) RevokeGrant(ctx context.Context, id, revokedBy, reason string, now time.Time) (approval.Grant, error) {
	tx, err := g.db.BeginTx(ctx, nil)
	if err != nil {
		return approval.Grant{}, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck

	row := tx.QueryRowContext(ctx, grantSelect+` WHERE grant_id = ?`, id)
	gr, err := scanGrant(row.Scan)
	if errors.Is(err, sql.ErrNoRows) {
		return approval.Grant{}, approval.ErrGrantNotFound
	}
	if err != nil {
		return approval.Grant{}, err
	}
	if gr.Revoked() || !now.Before(gr.ExpiresAt) {
		return approval.Grant{}, approval.ErrGrantNotActive
	}

	stamp := roundTripTime(now)
	if _, err := tx.ExecContext(ctx,
		`UPDATE approval_grants SET revoked_at = ?, revoked_by = ?, revoke_reason = ?
		  WHERE grant_id = ? AND revoked_at IS NULL`,
		formatTime(stamp), revokedBy, reason, id,
	); err != nil {
		return approval.Grant{}, fmt.Errorf("revoke approval grant: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return approval.Grant{}, fmt.Errorf("commit grant revocation: %w", err)
	}

	gr.RevokedAt = stamp
	gr.RevokedBy = revokedBy
	gr.RevokeReason = reason
	return gr, nil
}

// scanGrant reads one approval_grants row through *sql.Row.Scan or
// *sql.Rows.Scan.
func scanGrant(scan func(dest ...any) error) (approval.Grant, error) {
	var (
		gr        approval.Grant
		riskClass string
		ops       string
		rawExec   int
		starts    sql.NullString
		expires   sql.NullString
		created   sql.NullString
		revoked   sql.NullString
	)
	if err := scan(
		&gr.ID, &gr.RequestID,
		&gr.Scope.Account, &riskClass, &gr.Scope.MaxFanOut, &ops,
		&rawExec, &gr.LegacyNamespacePin,
		&starts, &expires, &gr.MaxUses, &gr.Uses, &gr.Summary, &created,
		&revoked, &gr.RevokedBy, &gr.RevokeReason,
	); err != nil {
		return approval.Grant{}, err
	}

	gr.Scope.RiskClass = approval.ParseRiskClassName(riskClass)
	gr.Scope.Operations = splitList(ops)
	gr.Scope.RawExec = rawExec != 0

	var err error
	if gr.StartsAt, err = parseTime(starts); err != nil {
		return approval.Grant{}, fmt.Errorf("parse grant starts_at: %w", err)
	}
	if gr.ExpiresAt, err = parseTime(expires); err != nil {
		return approval.Grant{}, fmt.Errorf("parse grant expires_at: %w", err)
	}
	if gr.CreatedAt, err = parseTime(created); err != nil {
		return approval.Grant{}, fmt.Errorf("parse grant created_at: %w", err)
	}
	if gr.RevokedAt, err = parseTime(revoked); err != nil {
		return approval.Grant{}, fmt.Errorf("parse grant revoked_at: %w", err)
	}
	return gr, nil
}

// nullTime renders the zero time as SQL NULL, so "never revoked" is an absent
// value rather than year 1 — which the revoked_at IS NULL guards depend on.
func nullTime(t time.Time) any {
	if t.IsZero() {
		return nil
	}
	return formatTime(roundTripTime(t))
}
