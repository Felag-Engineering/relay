package store

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/Felag-Engineering/relay/relay/internal/approval"
)

// backfillShapeKeys fills approval_requests.shape_key for the rows migration
// 0022 leaves empty.
//
// It is idempotent by construction — it only ever touches rows whose
// shape_key is still empty — and deterministic, because every value it writes
// is a pure function of data already in the row. Running it on every Open,
// which is what happens, therefore converges once and then does nothing.
//
// It lives in Go rather than in migration SQL because it binds
// approval.LegacyShapePrefix, so the constant and the statement cannot drift.
func backfillShapeKeys(ctx context.Context, db *sql.DB) error {
	// Steady state is the common case by far: after the first Open every row
	// has a key, and this probe is all the backfill costs.
	var pending int
	if err := db.QueryRowContext(ctx,
		`SELECT EXISTS(SELECT 1 FROM approval_requests WHERE shape_key = '')`,
	).Scan(&pending); err != nil {
		return fmt.Errorf("check for approval requests without a shape key: %w", err)
	}
	if pending == 0 {
		return nil
	}

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin shape key backfill: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck

	// Every row is marked as UNCOMPARABLE. A record's true shape cannot be
	// recomputed: approval_requests never stored the Selector
	// or the arguments (migration 0012), and D10 rules out reconstructing one
	// ("normalising a Selector after the fact is guesswork, and the approval
	// trail is exactly the data you least want to guess about").
	//
	// A per-row unique legacy key is deterministic, re-runnable, and
	// structurally unable to collide with a real key (64 hex characters, no
	// prefix) or with another legacy row (request_id is the primary key). Each
	// legacy record is therefore ITS OWN SHAPE, and the read seams refuse the
	// prefix outright — so the diff callout can never tell a human "you
	// approved this Tuesday" about a record whose shape nobody knows.
	// A grant request left with an empty key (a database upgraded from before
	// migration 0022) is stamped the same way: it becomes its own shape and is
	// never a lookup match, the fail-safe direction.
	//
	// The prefix is BOUND, not written into the SQL literal, so the constant
	// and the statement cannot drift apart.
	if _, err := tx.ExecContext(ctx,
		`UPDATE approval_requests SET shape_key = ? || request_id WHERE shape_key = ''`,
		approval.LegacyShapePrefix,
	); err != nil {
		return fmt.Errorf("stamp legacy shape keys: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit shape key backfill: %w", err)
	}
	return nil
}
