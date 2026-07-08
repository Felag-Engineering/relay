package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/freeze"
)

// sqliteFreeze implements freeze.Repository against the single-row freeze
// table.
type sqliteFreeze struct {
	db *sql.DB
}

var _ freeze.Repository = (*sqliteFreeze)(nil)

// Frozen reports whether the Freeze is currently engaged. No row (a fresh
// Relay that has never had its Freeze touched) means not-frozen, not an
// error.
func (f *sqliteFreeze) Frozen(ctx context.Context) (bool, error) {
	var engaged bool
	err := f.db.QueryRowContext(ctx, `SELECT engaged FROM freeze WHERE id = 1`).Scan(&engaged)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("query freeze state: %w", err)
	}
	return engaged, nil
}

// Engage sets the Freeze, recording principal.
func (f *sqliteFreeze) Engage(ctx context.Context, principal string) error {
	return f.set(ctx, true, principal, "")
}

// Release clears the Freeze, recording principal and reason.
func (f *sqliteFreeze) Release(ctx context.Context, principal, reason string) error {
	return f.set(ctx, false, principal, reason)
}

// set idempotently UPSERTs the single freeze row.
func (f *sqliteFreeze) set(ctx context.Context, engaged bool, principal, reason string) error {
	_, err := f.db.ExecContext(ctx, `
		INSERT INTO freeze (id, engaged, principal, reason, updated_at)
		VALUES (1, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET
			engaged = excluded.engaged,
			principal = excluded.principal,
			reason = excluded.reason,
			updated_at = excluded.updated_at`,
		engaged, principal, nullIfEmpty(reason), formatTime(roundTripTime(time.Now().UTC())),
	)
	if err != nil {
		return fmt.Errorf("upsert freeze state: %w", err)
	}
	return nil
}
