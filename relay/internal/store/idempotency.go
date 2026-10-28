package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/Felag-Engineering/relay/relay/internal/jobs"
)

// sqliteIdempotency implements jobs.IdempotencyRepository against the
// dispatch_idempotency_keys table (migration 0029). Times are Unix
// nanoseconds, so every comparison is exact.
type sqliteIdempotency struct {
	db *sql.DB
}

var _ jobs.IdempotencyRepository = (*sqliteIdempotency)(nil)

const idempotencySelect = `
	SELECT account_id, idem_key, request_digest, job_id, created_at_ns
	  FROM dispatch_idempotency_keys`

func (i *sqliteIdempotency) Claim(ctx context.Context, rec jobs.IdempotencyRecord, notBefore time.Time) (jobs.IdempotencyRecord, bool, error) {
	tx, err := i.db.BeginTx(ctx, nil)
	if err != nil {
		return jobs.IdempotencyRecord{}, false, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck

	// The sweep bounds the table: a client that sends a fresh key per run
	// would otherwise add a row forever.
	if _, err := tx.ExecContext(ctx,
		`DELETE FROM dispatch_idempotency_keys WHERE created_at_ns < ?`, notBefore.UTC().UnixNano()); err != nil {
		return jobs.IdempotencyRecord{}, false, fmt.Errorf("sweep expired idempotency keys: %w", err)
	}
	res, err := tx.ExecContext(ctx, `
		INSERT INTO dispatch_idempotency_keys (account_id, idem_key, request_digest, job_id, created_at_ns)
		VALUES (?, ?, ?, ?, ?)
		ON CONFLICT(account_id, idem_key) DO NOTHING`,
		rec.AccountID, rec.Key, rec.RequestDigest, rec.JobID, rec.CreatedAt.UTC().UnixNano())
	if err != nil {
		return jobs.IdempotencyRecord{}, false, fmt.Errorf("claim idempotency key: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return jobs.IdempotencyRecord{}, false, fmt.Errorf("claim idempotency key: rows affected: %w", err)
	}
	claimed := n == 1
	out := rec
	if !claimed {
		existing, ok, err := scanIdempotency(tx.QueryRowContext(ctx,
			idempotencySelect+` WHERE account_id = ? AND idem_key = ?`, rec.AccountID, rec.Key))
		if err != nil {
			return jobs.IdempotencyRecord{}, false, err
		}
		if !ok {
			return jobs.IdempotencyRecord{}, false, errors.New("claim idempotency key: conflicting row vanished")
		}
		out = existing
	}
	if err := tx.Commit(); err != nil {
		return jobs.IdempotencyRecord{}, false, fmt.Errorf("commit idempotency claim: %w", err)
	}
	return out, claimed, nil
}

func (i *sqliteIdempotency) Lookup(ctx context.Context, accountID, key string, notBefore time.Time) (jobs.IdempotencyRecord, bool, error) {
	return scanIdempotency(i.db.QueryRowContext(ctx,
		idempotencySelect+` WHERE account_id = ? AND idem_key = ? AND created_at_ns >= ?`,
		accountID, key, notBefore.UTC().UnixNano()))
}

func (i *sqliteIdempotency) Rebind(ctx context.Context, accountID, key, fromJobID, toJobID string) error {
	if _, err := i.db.ExecContext(ctx,
		`UPDATE dispatch_idempotency_keys SET job_id = ? WHERE account_id = ? AND idem_key = ? AND job_id = ?`,
		toJobID, accountID, key, fromJobID); err != nil {
		return fmt.Errorf("rebind idempotency key: %w", err)
	}
	return nil
}

func (i *sqliteIdempotency) Release(ctx context.Context, accountID, key, jobID string) error {
	if _, err := i.db.ExecContext(ctx,
		`DELETE FROM dispatch_idempotency_keys WHERE account_id = ? AND idem_key = ? AND job_id = ?`,
		accountID, key, jobID); err != nil {
		return fmt.Errorf("release idempotency key: %w", err)
	}
	return nil
}

func scanIdempotency(row *sql.Row) (jobs.IdempotencyRecord, bool, error) {
	var (
		rec jobs.IdempotencyRecord
		ns  int64
	)
	if err := row.Scan(&rec.AccountID, &rec.Key, &rec.RequestDigest, &rec.JobID, &ns); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return jobs.IdempotencyRecord{}, false, nil
		}
		return jobs.IdempotencyRecord{}, false, fmt.Errorf("read idempotency key: %w", err)
	}
	rec.CreatedAt = time.Unix(0, ns).UTC()
	return rec, true, nil
}
