package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/audit"
)

// The audit chain's store half. internal/audit defines the encoding and
// the verifier's state machine; this file is every piece that touches SQL:
// the migration 28 back-fill, the single chained insert, the head read, and
// the read-only walk relay-audit-verify runs.

// The two triggers migration 28 installs. They block UPDATE and DELETE only,
// never INSERT: a Relay binary older than the chain keeps writing rows with no
// chain position, and blocking its INSERT would stop it dispatching — the
// reasoning auditshape.go records for rejecting an aborting trigger. The
// verifier reports such rows instead (exit 3).
//
// A guardrail, not a security boundary: anyone holding the file can DROP
// TRIGGER. The hash chain is what makes that visible.
const (
	auditNoUpdateTriggerSQL = `CREATE TRIGGER audit_append_only_no_update BEFORE UPDATE ON audit BEGIN SELECT RAISE(ABORT, 'audit is append-only: UPDATE refused'); END`
	auditNoDeleteTriggerSQL = `CREATE TRIGGER audit_append_only_no_delete BEFORE DELETE ON audit BEGIN SELECT RAISE(ABORT, 'audit is append-only: DELETE refused'); END`
)

// auditTSCanonicaliseSQL is migration 0024's conversion UPDATE, verbatim. It
// is not advice to an operator — audit refuses UPDATE — but
// the first step of migration 28, the last moment the table can be rewritten.
// TestAuditTSCanonicalise_MatchesMigration0024 pins it against the migration
// so the two cannot drift.
const auditTSCanonicaliseSQL = `UPDATE audit
SET ts = substr(ts, 1, 19) || '.' ||
         substr(CASE WHEN substr(ts, 20, 1) = '.'
                     THEN substr(ts, 21, length(ts) - 21)
                     ELSE '' END || '000000000', 1, 9) || 'Z'
WHERE ts NOT GLOB '` + auditTSCanonicalGlob + `'
  AND ts GLOB '` + auditTSShapeGlob + `'`

// auditChainBackfillBatch is how many rows the back-fill holds in memory at
// once. Small because a row can carry two 1 MiB output blobs.
const auditChainBackfillBatch = 64

// chainAuditTrail is migration 28's Go step. It runs inside the migration's
// transaction, so the whole of it — canonicalised timestamps, every chained
// row, both triggers — commits or rolls back with the version row.
//
// Chaining happens exactly once, here. There is deliberately no re-chaining on
// Open: that would bless any row inserted outside the chain.
func chainAuditTrail(ctx context.Context, tx *sql.Tx) error {
	// Before chaining, while the table can still be rewritten. The hash is over
	// the decoded instant, so this changes no hash.
	if _, err := tx.ExecContext(ctx, auditTSCanonicaliseSQL); err != nil {
		return fmt.Errorf("canonicalise audit timestamps: %w", err)
	}

	head, err := readChainHead(ctx, tx)
	if err != nil {
		return err
	}

	var after int64
	for {
		batch, err := readBackfillBatch(ctx, tx, after)
		if err != nil {
			return err
		}
		if len(batch) == 0 {
			break
		}
		for _, row := range batch {
			seq := head.Seq + 1
			hash := audit.ComputeChainHash(seq, head.Hash, row.rec)
			if _, err := tx.ExecContext(ctx,
				`UPDATE audit SET seq = ?, prev_hash = ?, hash = ? WHERE rowid = ?`,
				int64(seq), head.Hash.Hex(), hash.Hex(), row.rowid); err != nil { //nolint:gosec // G115: seq counts rows, nowhere near 2^63
				return fmt.Errorf("chain audit record %q: %w", row.rec.ID, err)
			}
			head = audit.ChainHead{Seq: seq, Hash: hash}
			after = row.rowid
		}
	}

	for _, ddl := range []string{auditNoUpdateTriggerSQL, auditNoDeleteTriggerSQL} {
		if _, err := tx.ExecContext(ctx, ddl); err != nil {
			return fmt.Errorf("create audit append-only trigger: %w", err)
		}
	}
	return nil
}

type backfillRow struct {
	rowid int64
	rec   audit.Record
}

// readBackfillBatch reads the next unchained rows after rowid `after`, in
// insertion order. It fully reads and closes its Rows before returning: the
// caller then writes on the same transaction.
func readBackfillBatch(ctx context.Context, tx *sql.Tx, after int64) ([]backfillRow, error) {
	rows, err := tx.QueryContext(ctx,
		`SELECT rowid, `+auditRecordColumns+` FROM audit WHERE seq IS NULL AND rowid > ? ORDER BY rowid LIMIT ?`,
		after, auditChainBackfillBatch)
	if err != nil {
		return nil, fmt.Errorf("read audit rows to chain: %w", err)
	}
	defer rows.Close() //nolint:errcheck

	var batch []backfillRow
	for rows.Next() {
		var rowid int64
		rec, err := scanAuditRecord(rows, &rowid)
		if err != nil {
			return nil, fmt.Errorf("chain audit trail: %w", err)
		}
		batch = append(batch, backfillRow{rowid: rowid, rec: rec})
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("read audit rows to chain: %w", err)
	}
	return batch, nil
}

// auditChainExecer is what insertChained needs of a write transaction. Callers
// pass a *sql.Tx, never a *sql.DB: the head read and the inserts must be one
// write transaction.
type auditChainExecer interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

// preparedAudit is a Record ready to be chained: its insert arguments, and the
// view of it the verifier will re-derive on read.
type preparedAudit struct {
	args  []any
	canon audit.Record
}

// prepareAudit encodes r for insertion and computes the Record the reader
// will decode back from what is stored.
//
// The hash is over that read-back view, not over r, because the two differ:
// JSON encoding replaces invalid UTF-8 in args and argv with U+FFFD (two keys
// differing only in invalid bytes collapse into one), and an empty string is
// stored as NULL and read back as "". Running the real encode and decode here,
// not simulating them, is what keeps the writer's hash and the verifier's
// equal.
func prepareAudit(r audit.Record) (preparedAudit, error) {
	args, err := auditInsertArgs(r)
	if err != nil {
		return preparedAudit{}, err
	}
	canon := r
	argsJSON, err := encodeStringMap(r.Args)
	if err != nil {
		return preparedAudit{}, err
	}
	if canon.Args, err = decodeStringMap(nullString(argsJSON)); err != nil {
		return preparedAudit{}, err
	}
	argvJSON, err := encodeStringSlice(r.RawExecArgv)
	if err != nil {
		return preparedAudit{}, err
	}
	if canon.RawExecArgv, err = decodeStringSlice(nullString(argvJSON)); err != nil {
		return preparedAudit{}, err
	}
	canon.Timestamp = r.Timestamp.UTC()
	return preparedAudit{args: args, canon: canon}, nil
}

// nullString adapts an encode result (nil or a string) to what decode takes.
func nullString(v any) sql.NullString {
	s, ok := v.(string)
	return sql.NullString{String: s, Valid: ok}
}

// readChainHead returns the newest chained row's position, or the empty
// trail's {0, genesis}. A head that cannot be parsed is an error, so appends
// fail closed rather than chain onto garbage.
func readChainHead(ctx context.Context, q interface {
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}) (audit.ChainHead, error) {
	var seq int64
	var hash sql.NullString
	err := q.QueryRowContext(ctx,
		`SELECT seq, hash FROM audit WHERE seq IS NOT NULL ORDER BY seq DESC LIMIT 1`).Scan(&seq, &hash)
	if errors.Is(err, sql.ErrNoRows) {
		return audit.ChainHead{Hash: audit.GenesisPrevHash}, nil
	}
	if err != nil {
		return audit.ChainHead{}, fmt.Errorf("read audit chain head: %w", err)
	}
	if seq <= 0 {
		return audit.ChainHead{}, fmt.Errorf("audit chain head has seq %d", seq)
	}
	h, err := audit.ParseChainHash(hash.String)
	if err != nil {
		return audit.ChainHead{}, fmt.Errorf("audit chain head (seq %d): %w", seq, err)
	}
	return audit.ChainHead{Seq: uint64(seq), Hash: h}, nil
}

// insertChained appends ps to the audit chain, each row at the next seq with
// the hash of the one before. It is the ONLY function that may reference
// insertAuditSQL; TestInsertAuditSQL_OnlyReferencedByInsertChained enforces it.
//
// q must be a write transaction (the store's DSN makes every transaction
// BEGIN IMMEDIATE), so the head is read under the cross-process write lock and
// two appenders cannot chain onto the same head. idx_audit_seq is the backstop.
// It is the seam for a caller that needs the audit row committed in its own
// transaction: pass that transaction.
func insertChained(ctx context.Context, q auditChainExecer, ps []preparedAudit) error {
	head, err := readChainHead(ctx, q)
	if err != nil {
		return err
	}
	for i, p := range ps {
		seq := head.Seq + 1
		hash := audit.ComputeChainHash(seq, head.Hash, p.canon)
		args := make([]any, 0, len(p.args)+3)
		args = append(args, p.args...)
		args = append(args, int64(seq), head.Hash.Hex(), hash.Hex()) //nolint:gosec // G115: seq counts rows, nowhere near 2^63
		if _, err := q.ExecContext(ctx, insertAuditSQL, args...); err != nil {
			return fmt.Errorf("insert audit record %d of %d: %w", i+1, len(ps), err)
		}
		head = audit.ChainHead{Seq: seq, Hash: hash}
	}
	return nil
}

// ChainHead returns the newest chained row's position.
func (a *sqliteAudit) ChainHead(ctx context.Context) (audit.ChainHead, error) {
	return readChainHead(ctx, a.db)
}

var _ audit.ChainHeadReader = (*sqliteAudit)(nil)

// sqliteReadOnlyDSN is sqliteDSN for the verifier: read-only at both the
// SQLite open and the connection, and without _txlock=immediate, which would
// make a read-only transaction ask for the write lock.
func sqliteReadOnlyDSN(path string) (string, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", fmt.Errorf("resolve store path %q: %w", path, err)
	}
	q := url.Values{}
	q.Set("mode", "ro")
	q.Add("_pragma", "query_only(1)")
	q.Add("_pragma", fmt.Sprintf("busy_timeout(%d)", busyTimeoutMillis))
	u := url.URL{Path: abs}
	return "file:" + u.EscapedPath() + "?" + q.Encode(), nil
}

// VerifyAuditChain walks the audit chain of the database at path and returns
// the verdict. It never writes, creates or migrates: a missing file is an
// error and a database that predates migration 28 is refused. anchors are
// checked as well (see audit.ChainVerifier).
//
// The whole walk, and the count of rows with no chain position, run in one
// read transaction so a Relay appending in WAL mode cannot move the snapshot
// between them.
func VerifyAuditChain(ctx context.Context, path string, anchors []audit.ChainAnchor) (audit.ChainVerdict, error) {
	var verdict audit.ChainVerdict
	if _, err := os.Stat(path); err != nil {
		return verdict, fmt.Errorf("audit store: %w", err)
	}
	verifier, err := audit.NewChainVerifier(anchors...)
	if err != nil {
		return verdict, err
	}
	dsn, err := sqliteReadOnlyDSN(path)
	if err != nil {
		return verdict, err
	}
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return verdict, fmt.Errorf("open %q read-only: %w", path, err)
	}
	defer db.Close() //nolint:errcheck
	db.SetMaxOpenConns(1)

	tx, err := db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return verdict, fmt.Errorf("begin read-only transaction on %q: %w", path, err)
	}
	defer tx.Rollback() //nolint:errcheck

	var hasHash int
	if err := tx.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM pragma_table_info('audit') WHERE name = 'hash'`).Scan(&hasHash); err != nil {
		return verdict, fmt.Errorf("inspect audit schema: %w", err)
	}
	if hasHash == 0 {
		return verdict, errors.New("store predates the audit chain (migration 28 not applied)")
	}

	brk, err := walkAuditChain(ctx, tx, verifier)
	if err != nil {
		return verdict, err
	}
	if brk == nil {
		brk = verifier.Finish()
	}

	// Rows with no chain position. A binary older than the chain writes them with all
	// three chain columns NULL; a row with NULL seq but a hash column set cannot
	// come from any legitimate path, so it is a break, not a rollback artefact.
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM audit WHERE seq IS NULL`).Scan(&verdict.Unchained); err != nil {
		return verdict, fmt.Errorf("count unchained audit rows: %w", err)
	}
	if verdict.Unchained > 0 {
		if err := tx.QueryRowContext(ctx,
			`SELECT audit_id FROM audit WHERE seq IS NULL ORDER BY rowid LIMIT 1`).Scan(&verdict.FirstUnchainedID); err != nil {
			return verdict, fmt.Errorf("read first unchained audit row: %w", err)
		}
		if brk == nil {
			var id string
			err := tx.QueryRowContext(ctx,
				`SELECT audit_id FROM audit WHERE seq IS NULL AND (prev_hash IS NOT NULL OR hash IS NOT NULL) ORDER BY rowid LIMIT 1`).Scan(&id)
			switch {
			case err == nil:
				brk = &audit.ChainBreak{AuditID: id, Reason: audit.BreakMalformed,
					Detail: "row has a chain hash but no seq: no legitimate writer produces that"}
			case !errors.Is(err, sql.ErrNoRows):
				return verdict, fmt.Errorf("inspect unchained audit rows: %w", err)
			}
		}
	}

	verdict.Rows = verifier.Rows()
	verdict.Head = verifier.Head()
	verdict.AnchorsChecked = verifier.AnchorsChecked()
	verdict.Break = brk
	return verdict, nil
}

// walkAuditChain streams the chained rows in seq order through verifier and
// stops at the first break.
func walkAuditChain(ctx context.Context, tx *sql.Tx, verifier *audit.ChainVerifier) (*audit.ChainBreak, error) {
	rows, err := tx.QueryContext(ctx,
		`SELECT seq, prev_hash, hash, `+auditRecordColumns+` FROM audit WHERE seq IS NOT NULL ORDER BY seq`)
	if err != nil {
		return nil, fmt.Errorf("read audit chain: %w", err)
	}
	defer rows.Close() //nolint:errcheck

	for rows.Next() {
		var seq int64
		var prev, hash sql.NullString
		rec, err := scanAuditRecord(rows, &seq, &prev, &hash)
		if err != nil {
			if ctxErr := ctx.Err(); ctxErr != nil {
				return nil, ctxErr
			}
			// A row that does not decode (edited args, say) is damage to the
			// trail, not a failure of the verifier.
			// seq and the ID are set when the failure came after the scan.
			brkSeq := uint64(verifier.Head().Seq + 1)
			if seq > 0 {
				brkSeq = uint64(seq)
			}
			return &audit.ChainBreak{Seq: brkSeq, AuditID: rec.ID, Reason: audit.BreakMalformed,
				Detail: fmt.Sprintf("row at seq %d cannot be decoded: %v", brkSeq, err)}, nil
		}
		if seq <= 0 {
			return &audit.ChainBreak{AuditID: rec.ID, Reason: audit.BreakMalformed,
				Detail: fmt.Sprintf("seq %d is not positive", seq)}, nil
		}
		if brk := verifier.Check(uint64(seq), prev.String, hash.String, rec); brk != nil {
			return brk, nil
		}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("read audit chain: %w", err)
	}
	return nil, nil
}
