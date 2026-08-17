package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/mcptask"
)

// sqliteMCPTasks implements mcptask.Repository against the mcp_task_handles
// table (migration 0016).
//
// Note what this file does NOT contain: any computation of a handle's status.
// The status a client is told is derived at read time from the approval Request
// (mcptask.Handle.Status), and last_status here is only the record of what was
// last reported. A SQL expression that decided status would be a second
// implementation of that rule, in a dialect with different NULL semantics,
// drifting from the first the moment either changed.
type sqliteMCPTasks struct {
	db *sql.DB
}

var _ mcptask.Repository = (*sqliteMCPTasks)(nil)

const mcpTaskSelect = `
	SELECT task_id, approval_request_id, job_id, account_id, account_name,
	       last_status, created_at, last_updated_at, expires_at, cancelled_at
	  FROM mcp_task_handles`

// Create persists a validated handle.
//
// Validate runs HERE as well as at the caller, on the same reasoning as
// grants: a handle with no owner must be impossible to STORE, not merely
// impossible to mint through today's code path. An unowned row would be one no
// ownership check could ever fail.
func (m *sqliteMCPTasks) Create(ctx context.Context, h mcptask.Handle) error {
	if err := h.Validate(); err != nil {
		return err
	}
	_, err := m.db.ExecContext(ctx, `
		INSERT INTO mcp_task_handles (
			task_id, approval_request_id, job_id, account_id, account_name,
			last_status, created_at, last_updated_at, expires_at, cancelled_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		h.ID, h.ApprovalRequestID, nullIfEmpty(h.JobID), h.AccountID, h.Account,
		h.LastStatus.String(),
		formatTime(roundTripTime(h.CreatedAt)), formatTime(roundTripTime(h.LastUpdatedAt)),
		formatTime(roundTripTime(h.ExpiresAt)), nullTime(h.CancelledAt),
	)
	if err != nil {
		return fmt.Errorf("insert mcp task handle: %w", err)
	}
	return nil
}

// Get returns a handle by ID for the Account resolving it.
//
// The ownership check is in the WHERE clause rather than applied after the read
// for a reason worth stating: a check the caller performs is a check a caller
// can forget, and this one is the whole reason a task handle is not a bearer
// token. Filtering in SQL means the not-yours case and the no-such-handle case
// produce literally the same result — no row — so the indistinguishability
// mcptask.ErrNotFound documents is structural rather than remembered.
func (m *sqliteMCPTasks) Get(ctx context.Context, id, accountID string) (mcptask.Handle, error) {
	if accountID == "" {
		return mcptask.Handle{}, mcptask.ErrNotFound
	}
	row := m.db.QueryRowContext(ctx,
		mcpTaskSelect+` WHERE task_id = ? AND account_id = ?`, id, accountID)
	return scanMCPTask(row.Scan)
}

// ByApprovalRequest returns the handle minted for an approval Request.
//
// Deliberately NOT owner-scoped, and that is not an omission. Its caller is the
// mint path asking "does a handle already exist for this parked dispatch?", so
// that a re-drive re-attaches instead of minting a second handle for one wait.
// The answer never reaches a client — it is compared, not returned to the
// wire — and the unique index means there is at most one row to find.
func (m *sqliteMCPTasks) ByApprovalRequest(ctx context.Context, approvalRequestID string) (mcptask.Handle, error) {
	row := m.db.QueryRowContext(ctx,
		mcpTaskSelect+` WHERE approval_request_id = ?`, approvalRequestID)
	return scanMCPTask(row.Scan)
}

// BindJob records the Job a released dispatch created.
func (m *sqliteMCPTasks) BindJob(ctx context.Context, id, jobID string, status mcptask.Status, now time.Time) error {
	res, err := m.db.ExecContext(ctx, `
		UPDATE mcp_task_handles
		   SET job_id = ?, last_status = ?, last_updated_at = ?
		 WHERE task_id = ?`,
		jobID, status.String(), formatTime(roundTripTime(now)), id)
	if err != nil {
		return fmt.Errorf("bind job to mcp task handle: %w", err)
	}
	return affectedOrNotFound(res)
}

// RecordStatus updates what the client was last told.
func (m *sqliteMCPTasks) RecordStatus(ctx context.Context, id string, status mcptask.Status, now time.Time) error {
	res, err := m.db.ExecContext(ctx, `
		UPDATE mcp_task_handles
		   SET last_status = ?, last_updated_at = ?
		 WHERE task_id = ?`,
		status.String(), formatTime(roundTripTime(now)), id)
	if err != nil {
		return fmt.Errorf("record mcp task handle status: %w", err)
	}
	return affectedOrNotFound(res)
}

// Cancel ends the client's polling contract.
//
// It touches this table and nothing else — no approval Request is read, let
// alone written. ADR-0028 is explicit: a cancel arrives over the MCP session,
// which is the AI's own channel, and if it could act on the approval object the
// requesting session would hold a lever over a decision reserved for
// out-of-band humans. An agent must not be able to withdraw a request the
// moment it senses a denial coming, erasing the evidence a human was about to
// rule on.
//
// Cancelling twice is a no-op returning the existing row: a client retrying a
// cancel it already sent is not making a mistake worth an error.
func (m *sqliteMCPTasks) Cancel(ctx context.Context, id, accountID string, now time.Time) (mcptask.Handle, error) {
	if accountID == "" {
		return mcptask.Handle{}, mcptask.ErrNotFound
	}
	if _, err := m.db.ExecContext(ctx, `
		UPDATE mcp_task_handles
		   SET cancelled_at = ?, last_status = ?, last_updated_at = ?
		 WHERE task_id = ? AND account_id = ? AND cancelled_at IS NULL`,
		formatTime(roundTripTime(now)), mcptask.StatusCancelled.String(),
		formatTime(roundTripTime(now)), id, accountID); err != nil {
		return mcptask.Handle{}, fmt.Errorf("cancel mcp task handle: %w", err)
	}
	// Re-read rather than trusting rows-affected: zero rows means either "not
	// yours / no such handle" or "already cancelled", and those need different
	// answers.
	return m.Get(ctx, id, accountID)
}

// DeleteExpired sweeps handles past their deadline.
func (m *sqliteMCPTasks) DeleteExpired(ctx context.Context, now time.Time) (int, error) {
	res, err := m.db.ExecContext(ctx,
		`DELETE FROM mcp_task_handles WHERE expires_at <= ?`,
		formatTime(roundTripTime(now)))
	if err != nil {
		return 0, fmt.Errorf("sweep expired mcp task handles: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("sweep expired mcp task handles: %w", err)
	}
	return int(n), nil
}

// affectedOrNotFound maps a zero-row update onto ErrNotFound, so a write
// against a handle that has been swept or never existed is reported rather
// than passing silently.
func affectedOrNotFound(res sql.Result) error {
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("mcp task handle rows affected: %w", err)
	}
	if n == 0 {
		return mcptask.ErrNotFound
	}
	return nil
}

func scanMCPTask(scan func(...any) error) (mcptask.Handle, error) {
	var (
		id, approvalRequestID, accountID, accountName, status string
		jobID                                                 sql.NullString
		createdAt, lastUpdatedAt, expiresAt                   string
		cancelledAt                                           sql.NullString
	)
	if err := scan(&id, &approvalRequestID, &jobID, &accountID, &accountName,
		&status, &createdAt, &lastUpdatedAt, &expiresAt, &cancelledAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return mcptask.Handle{}, mcptask.ErrNotFound
		}
		return mcptask.Handle{}, fmt.Errorf("scan mcp task handle: %w", err)
	}

	created, err := parseTime(sql.NullString{String: createdAt, Valid: true})
	if err != nil {
		return mcptask.Handle{}, fmt.Errorf("parse created_at for mcp task handle %q: %w", id, err)
	}
	updated, err := parseTime(sql.NullString{String: lastUpdatedAt, Valid: true})
	if err != nil {
		return mcptask.Handle{}, fmt.Errorf("parse last_updated_at for mcp task handle %q: %w", id, err)
	}
	expires, err := parseTime(sql.NullString{String: expiresAt, Valid: true})
	if err != nil {
		return mcptask.Handle{}, fmt.Errorf("parse expires_at for mcp task handle %q: %w", id, err)
	}
	cancelled, err := parseTime(cancelledAt)
	if err != nil {
		return mcptask.Handle{}, fmt.Errorf("parse cancelled_at for mcp task handle %q: %w", id, err)
	}

	return mcptask.Handle{
		ID:                id,
		ApprovalRequestID: approvalRequestID,
		JobID:             jobID.String,
		AccountID:         accountID,
		Account:           accountName,
		// An unrecognized stored name reads as StatusUnspecified rather than
		// as a guess. It is a cache, so a bad value is a curiosity and never a
		// decision — the real status is recomputed from the approval Request.
		LastStatus:    mcptask.ParseStatus(status),
		CreatedAt:     created,
		LastUpdatedAt: updated,
		ExpiresAt:     expires,
		CancelledAt:   cancelled,
	}, nil
}
