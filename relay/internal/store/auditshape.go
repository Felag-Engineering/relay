package store

import (
	"context"
	"database/sql"
	"errors"
	"log/slog"
	"time"
)

// auditTSCanonicalGlob matches exactly the fixed-width ts migration 0024
// produces and formatAuditTime writes: 30 characters, UTC "Z", nine
// fractional digits. One spelling of "already converted", shared by the
// migration's skip gate, this detector, and
// TestAudit_StoredTimestampIsFixedWidth, so the writer and the migration
// cannot disagree about it.
//
// GLOB is a whole-string match in SQLite and "." is a literal in GLOB syntax,
// so this is the exact canonical form and not an approximation of it —
// unlike length(ts) = 30, which "2026-01-01T00:00:01.1234+05:30" also
// satisfies.
const auditTSCanonicalGlob = `[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9]Z`

// auditTSShapeGlob matches every shape the writer could ever have produced:
// a UTC RFC3339 value, with or without a fraction. A value outside it is left
// alone rather than mangled by substr arithmetic on a negative length.
const auditTSShapeGlob = `[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9]*Z`

// auditTSRepairSQL is migration 0024's conversion UPDATE, verbatim — the
// statement an operator runs to repair rows a rolled-back binary wrote in the
// old format.
//
// It is a second copy on purpose: an operator reading a log line has a binary
// and a database, not this repository, so "see migrations/0024" is not a
// remedy. TestAuditTSRepair_MatchesMigration0024 pins the two copies against
// each other so they cannot drift.
const auditTSRepairSQL = `UPDATE audit
SET ts = substr(ts, 1, 19) || '.' ||
         substr(CASE WHEN substr(ts, 20, 1) = '.'
                     THEN substr(ts, 21, length(ts) - 21)
                     ELSE '' END || '000000000', 1, 9) || 'Z'
WHERE ts NOT GLOB '` + auditTSCanonicalGlob + `'
  AND ts GLOB '` + auditTSShapeGlob + `'`

// auditShapeCheckRows is how many of the most recently inserted rows the
// window reads.
const auditShapeCheckRows = 100

// legacyTSWarnMsg is the one message both warning paths use, so an operator
// grepping for it finds the first boot that saw the problem and every boot
// since.
const legacyTSWarnMsg = "audit trail holds pre-0024 timestamps — rows written by a Relay older than #656 sort out of order against migrated rows, and a pagination cursor landing on one can skip or repeat rows. If running the repair does not clear this warning, the offending rows are outside the statement's shape (no Relay binary can write such a value, so they were introduced by hand) and need manual inspection"

// auditShapeCheckFailedMsg is logged when the detector itself cannot run. It
// is never an error the caller sees: see warnOnLegacyAuditTimestamps.
const auditShapeCheckFailedMsg = "could not check the audit trail's timestamp shape"

// legacyTSObservation is what the window saw: how many rows it read, how many
// of them were not canonical, and one of them to look at.
type legacyTSObservation struct {
	checked  int
	bad      int
	sampleID string
	sampleTS string
}

// auditShapeAlert is the persisted memory of an earlier observation — the
// audit_shape_alert row (migration 0025).
type auditShapeAlert struct {
	observedAt string
	sampleID   string
	sampleTS   string
}

// warnOnLegacyAuditTimestamps logs, at Warn, if the audit table holds
// pre-0024 timestamps — the binary-rollback case.
//
// WHY IT EXISTS: migrate deliberately tolerates a database newer than the
// binary (#492), so an operator can roll a Relay back onto a converted table,
// and that older Relay writes trimmed ts values into it. Those rows sort to
// the end of their second instead of their right place, a pagination cursor
// landing on one mis-seeks, and a paged read over the mixed table silently
// DROPS rows (TestAuditQuery_MixedFormatRowsAreSkipped pins that).
//
// ROLL-FORWARD DOES NOT SELF-HEAL. Version 24 is already recorded in
// schema_migrations and migrate selects by PRESENCE, so upgrading again
// re-runs nothing. Without this the symptom is entirely silent: no error, no
// failed query, just an audit trail that is quietly in two formats. This
// function is what turns it into a log line carrying the repair statement.
//
// THREE STEPS, AND THE MIDDLE ONE IS WHY THERE IS A TABLE FOR IT (0025):
//
//  1. If no alert is recorded, read the most recently INSERTED rows —
//     auditShapeCheckRows of them — and check their stored shape. Rows a
//     rolled-back binary wrote are by construction the ones most recently
//     inserted, so this window sees them without any assumption about clocks:
//     it is ORDER BY rowid DESC, not ORDER BY ts DESC, because a backwards
//     clock step around the rollback would push those rows below a hundred
//     canonical ones in ts order and out of a ts-ordered window. Measured at
//     0.2 ms on a 10-million-row table (the LIMIT bounds it, not the table).
//     If it sees any, warn and RECORD the alert.
//
//  2. If an alert IS recorded, the window is no longer trustworthy — it
//     scrolls, and ordinary traffic buries the offending rows within a
//     hundred appends, which is how the windowed-only version of this
//     detector went permanently silent while the damage stayed. So ask the
//     exact question instead: does ANY row fail the canonical GLOB.
//
//  3. If the exact question says no, the operator has run the repair: clear
//     the alert and say so at Info. A detector that kept warning after the
//     remedy is one an operator learns to ignore.
//
// The exact question is only asked at step 2 because it cannot use an index —
// nonconforming values are interleaved with canonical ones rather than
// forming a range — so on a clean table it scans the whole index to conclude
// "none": measured 0.62 s at 1 million rows and 6.4 s at 10 million, against
// 0.2 ms for the window. A flagged database pays that once per boot until it
// is repaired, which is the right place for it; a healthy one never pays it.
//
// NEVER A STARTUP GATE. It returns nothing. Every failure — the read, the
// scan, the alert write, the alert clear — is logged at Warn and Open carries
// on. Refusing to start over a DIAGNOSTIC would invert #492's
// tolerate-a-newer-database posture, and is the same reasoning that rejected
// a CHECK constraint or an aborting trigger here: a Relay that cannot write
// an audit record cannot dispatch, so bricking the control plane on rollback
// would be worse than the ordering defect. Unlike backfillShapeKeys, this
// repairs no audit row and asserts nothing; the only thing it writes is its
// own alert.
func warnOnLegacyAuditTimestamps(ctx context.Context, db *sql.DB, logger *slog.Logger) {
	alert, err := readAuditShapeAlert(ctx, db)
	if err != nil {
		logger.Warn(auditShapeCheckFailedMsg, "error", err)
		return
	}

	if alert == nil {
		observed, err := windowHoldsLegacyTimestamps(ctx, db)
		if err != nil {
			logger.Warn(auditShapeCheckFailedMsg, "error", err)
			return
		}
		if observed.bad == 0 {
			return
		}
		if err := raiseAuditShapeAlert(ctx, db, observed); err != nil {
			// Worth its own line: the warning below still fires on this
			// boot, but without the alert row it would not fire on the next
			// one once these rows leave the window.
			logger.Warn("could not record the audit timestamp alert, so this warning may not survive the next hundred appends", "error", err)
		}
		logger.Warn(legacyTSWarnMsg,
			"checked_rows", observed.checked,
			"nonconforming_rows", observed.bad,
			"sample_audit_id", observed.sampleID,
			"sample_ts", observed.sampleTS,
			"repair", auditTSRepairSQL,
		)
		return
	}

	stillLegacy, err := anyLegacyAuditTimestamp(ctx, db)
	if err != nil {
		logger.Warn(auditShapeCheckFailedMsg, "error", err)
		return
	}
	if stillLegacy {
		logger.Warn(legacyTSWarnMsg,
			"first_observed_at", alert.observedAt,
			"sample_audit_id", alert.sampleID,
			"sample_ts", alert.sampleTS,
			"repair", auditTSRepairSQL,
		)
		return
	}

	if err := clearAuditShapeAlert(ctx, db); err != nil {
		logger.Warn("could not clear the audit timestamp alert", "error", err)
		return
	}
	logger.Info("audit trail timestamps are canonical again — the pre-0024 rows first seen earlier are gone, so the alert is cleared",
		"first_observed_at", alert.observedAt,
	)
}

// windowHoldsLegacyTimestamps reads the most recently inserted rows and
// reports how many of them are not in the canonical shape.
func windowHoldsLegacyTimestamps(ctx context.Context, db *sql.DB) (legacyTSObservation, error) {
	var obs legacyTSObservation

	// THE SHAPE IS DECIDED IN SQL, NOT IN GO, and that is not a style choice.
	// ts is declared TIMESTAMP, so modernc.org/sqlite parses the column's
	// text into a time.Time on scan and database/sql re-renders it into a Go
	// string as TRIMMED RFC3339Nano: a canonical 30-character stored value
	// arrives here as the 20-character "2026-01-01T00:00:01Z". A detector
	// that measured THAT would report every row of a perfectly converted
	// table as nonconforming. The GLOB runs inside SQLite against the stored
	// bytes, and CAST(ts AS TEXT) is an expression rather than a column
	// reference, so it carries no decltype for the driver to act on — which
	// is how the sample in the log line is the operator's actual bytes. Same
	// driver behaviour that broke the pagination cursor (#656).
	//
	// ORDER BY rowid DESC is INSERTION order, which is exactly "what was
	// written most recently" — the rows a rolled-back binary just wrote — and
	// unlike ts DESC it assumes nothing about the clock. It reads
	// auditShapeCheckRows table rows in reverse and decodes two columns of
	// each, never the retained output blobs.
	//
	// THE PREMISE, stated because it is not a property of rowid in general:
	// this holds because `audit` is append-only. Nothing in this repo deletes
	// from it, VACUUMs it, or names a rowid on insert, so rowids are assigned
	// in ascending order and never reused. SQLite reuses the highest rowid
	// after the highest row is deleted, which would put a NEWER row below
	// older ones and hide it from this window. Retention (#677) is the
	// obvious future violator: deleting oldest-first stays safe, deleting
	// newest or emptying the table does not. Anything that starts removing
	// audit rows must re-check this window.
	rows, err := db.QueryContext(ctx,
		`SELECT audit_id, CAST(ts AS TEXT), ts GLOB ? FROM audit ORDER BY rowid DESC LIMIT ?`,
		auditTSCanonicalGlob, auditShapeCheckRows)
	if err != nil {
		return obs, err
	}
	defer rows.Close() //nolint:errcheck

	for rows.Next() {
		var id, ts string
		var canonical int
		if err := rows.Scan(&id, &ts, &canonical); err != nil {
			return obs, err
		}
		obs.checked++
		if canonical == 0 {
			obs.bad++
			if obs.sampleID == "" {
				obs.sampleID, obs.sampleTS = id, ts
			}
		}
	}
	return obs, rows.Err()
}

// anyLegacyAuditTimestamp is the exact question, asked of the whole table:
// does any row fail the canonical GLOB. See warnOnLegacyAuditTimestamps for
// what it costs and why only a database already known to have been mixed
// pays it.
func anyLegacyAuditTimestamp(ctx context.Context, db *sql.DB) (bool, error) {
	var exists int
	if err := db.QueryRowContext(ctx,
		`SELECT EXISTS(SELECT 1 FROM audit WHERE ts NOT GLOB ?)`, auditTSCanonicalGlob).Scan(&exists); err != nil {
		return false, err
	}
	return exists == 1, nil
}

// readAuditShapeAlert returns the recorded alert, or nil when none is
// recorded — the state every healthy database is in.
func readAuditShapeAlert(ctx context.Context, db *sql.DB) (*auditShapeAlert, error) {
	var a auditShapeAlert
	// observed_at is read through CAST for the same reason the ts sample is:
	// the column is declared TIMESTAMP, and a plain scan would hand back the
	// driver's re-rendering rather than what was written.
	err := db.QueryRowContext(ctx,
		`SELECT CAST(observed_at AS TEXT), sample_audit_id, sample_ts FROM audit_shape_alert WHERE id = 1`).
		Scan(&a.observedAt, &a.sampleID, &a.sampleTS)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &a, nil
}

// raiseAuditShapeAlert records that pre-0024 rows were observed, so the
// warning survives the window that saw them.
func raiseAuditShapeAlert(ctx context.Context, db *sql.DB, obs legacyTSObservation) error {
	_, err := db.ExecContext(ctx,
		`INSERT INTO audit_shape_alert (id, observed_at, sample_audit_id, sample_ts) VALUES (1, ?, ?, ?)
		 ON CONFLICT (id) DO UPDATE SET observed_at = excluded.observed_at, sample_audit_id = excluded.sample_audit_id, sample_ts = excluded.sample_ts`,
		formatTime(time.Now()), obs.sampleID, obs.sampleTS)
	return err
}

// clearAuditShapeAlert forgets the alert, which only anyLegacyAuditTimestamp
// answering "no" may cause.
func clearAuditShapeAlert(ctx context.Context, db *sql.DB) error {
	_, err := db.ExecContext(ctx, `DELETE FROM audit_shape_alert WHERE id = 1`)
	return err
}
