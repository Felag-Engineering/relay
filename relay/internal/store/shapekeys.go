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
// shape_key is still empty — and
// deterministic, because every value it writes is a pure function of data
// already in the row. Running it on every Open, which is what happens,
// therefore converges once and then does nothing.
//
// It lives in Go rather than in migration SQL for two reasons. The ordering
// between the two passes matters (see below), and computing a SHA-256 in SQL
// would be a SECOND IMPLEMENTATION of the hash the write path uses — the one
// failure mode that would make "recomputing a key yields the same key" false.
// Pass A calls exactly the function approval.NewGrantRequest calls.
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

	// PASS A — grant requests, RECOMPUTED EXACTLY. A Grant's Scope is fully
	// stored, so its shape key is not guesswork: it is the same
	// approval.HashGrantShape over the same Scope the write path hashes.
	//
	// The read goes through grantSelect and scanGrant — the read path's own
	// column list and its own Scope reconstruction (risk-class parse,
	// comma-split, raw-exec flag) — rather than a second hand-written Scope
	// read. A second read would drift the first time a scope_* column is added,
	// and it would then hash a stale Scope, which is the same class of mistake
	// as a second hash implementation.
	//
	// Ordered by request_id, grant_id so the pathological case of two grants
	// naming one request resolves deterministically to the first.
	//
	// Reusing scanGrant means the backfill also parses four timestamp columns
	// it has no use for, so one unparseable revoked_at on a legacy grant row
	// aborts store.Open and the Relay refuses to start. That is the accepted
	// trade: an approval record this build cannot read is not a record to shrug
	// past at boot, and one read path is worth more than a narrower one that
	// could hash a Scope the real reader would have rejected.
	rows, err := tx.QueryContext(ctx, grantSelect+`
		 WHERE request_id IN (SELECT request_id FROM approval_requests WHERE shape_key = '')
		 ORDER BY request_id, grant_id`)
	if err != nil {
		return fmt.Errorf("read grants for shape key backfill: %w", err)
	}
	// The cursor is drained FULLY before anything is written: this driver
	// allows one active statement per connection (store.Open pins
	// SetMaxOpenConns(1)), the same constraint listWith and ClaimGrant work
	// under.
	keys := make(map[string]string)
	for rows.Next() {
		gr, err := scanGrant(rows.Scan)
		if err != nil {
			rows.Close()
			return fmt.Errorf("scan grant for shape key backfill: %w", err)
		}
		if _, seen := keys[gr.RequestID]; seen {
			continue
		}
		keys[gr.RequestID] = gr.ShapeKey()
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return fmt.Errorf("read grants for shape key backfill: %w", err)
	}
	if err := rows.Close(); err != nil {
		return fmt.Errorf("close grant cursor for shape key backfill: %w", err)
	}

	for requestID, key := range keys {
		if _, err := tx.ExecContext(ctx,
			`UPDATE approval_requests SET shape_key = ? WHERE request_id = ? AND shape_key = ''`,
			key, requestID,
		); err != nil {
			return fmt.Errorf("write recomputed grant shape key for %q: %w", requestID, err)
		}
	}

	// PASS B — everything else, marked as UNCOMPARABLE. A Plan record's true
	// shape cannot be recomputed: approval_requests never stored the Selector
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
	//
	// This MUST run after Pass A, which is why neither pass lives in the
	// migration: a legacy fill applied first would consume the very rows that
	// CAN be recomputed.
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
