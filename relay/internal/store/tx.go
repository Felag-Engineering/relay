package store

import (
	"context"
	"database/sql"
	"fmt"
)

// inTx runs fn in one write transaction on db and commits it when fn returns
// nil. Any error from fn rolls the transaction back and is returned unchanged,
// so callers keep matching sentinel errors with errors.Is.
//
// beginMsg and commitMsg name the operation in the wrapped begin and commit
// errors ("begin <beginMsg>", "commit <commitMsg>"). Validation that needs no
// transaction belongs before the call, so a malformed request never opens one.
func inTx(ctx context.Context, db *sql.DB, beginMsg, commitMsg string, fn func(tx *sql.Tx) error) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin %s: %w", beginMsg, err)
	}
	defer tx.Rollback() //nolint:errcheck // a no-op after Commit; the error that matters is fn's

	if err := fn(tx); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit %s: %w", commitMsg, err)
	}
	return nil
}
