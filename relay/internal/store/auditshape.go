package store

import (
	"context"
	"database/sql"
	"log/slog"
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

// auditShapeCheckRows is how many of the newest rows the detector reads.
const auditShapeCheckRows = 100

// warnOnLegacyAuditTimestamps logs once, at Warn, if the newest rows of the
// audit table hold pre-0024 timestamps — the binary-rollback case.
//
// WHY IT EXISTS: migrate deliberately tolerates a database newer than the
// binary (#492), so an operator can roll a Relay back onto a converted table,
// and that older Relay writes trimmed ts values into it. Those rows sort to
// the end of their second instead of their right place, and a pagination
// cursor landing on one mis-seeks.
//
// ROLL-FORWARD DOES NOT SELF-HEAL. Version 24 is already recorded in
// schema_migrations and migrate selects by PRESENCE, so upgrading again
// re-runs nothing. Without this the symptom is entirely silent: no error, no
// failed query, just an audit trail that is quietly in two formats. This
// function is what turns it into a log line carrying the repair statement.
//
// WHY THE NEWEST N IS THE RIGHT WINDOW, AND WHY IT IS CHEAP: a rolled-back
// binary's rows are by construction the newest, and the 19-character
// date/time prefix dominates the text comparison, so a trimmed row written
// later still sorts to the top of a DESC scan. (Within one second a trimmed
// value also sorts at or above its padded twin: "Z" is 0x5A, above both "."
// 0x2E and every digit.) The scan is satisfied by idx_audit_ts (ts,
// audit_id) — no temp B-tree, no table read.
//
// NEVER A STARTUP GATE. It returns nothing, and a query failure is logged at
// Warn while Open carries on. Refusing to start over a DIAGNOSTIC READ would
// invert #492's tolerate-a-newer-database posture, and is the same reasoning
// that rejected a CHECK constraint or an aborting trigger here: a Relay that
// cannot write an audit record cannot dispatch, so bricking the control plane
// on rollback would be worse than the ordering defect. Unlike
// backfillShapeKeys, this repairs nothing and asserts nothing.
func warnOnLegacyAuditTimestamps(ctx context.Context, db *sql.DB, logger *slog.Logger) {
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
	// Newest-first, which is what makes reading only auditShapeCheckRows a
	// sufficient window. Spelled as a literal rather than built from
	// auditOrderDesc so this file is itself covered by
	// TestAuditSQL_EveryOrderByTsCarriesTheTieBreak, the guard that exists
	// because a new by-key reader in a new file is the clause most likely to
	// be spelled wrong.
	rows, err := db.QueryContext(ctx,
		`SELECT audit_id, CAST(ts AS TEXT), ts GLOB ? FROM audit ORDER BY ts DESC, audit_id DESC LIMIT ?`,
		auditTSCanonicalGlob, auditShapeCheckRows)
	if err != nil {
		logger.Warn("could not check the audit trail's timestamp shape", "error", err)
		return
	}
	defer rows.Close() //nolint:errcheck

	checked, bad := 0, 0
	sampleID, sampleTS := "", ""
	for rows.Next() {
		var id, ts string
		var canonical int
		if err := rows.Scan(&id, &ts, &canonical); err != nil {
			logger.Warn("could not check the audit trail's timestamp shape", "error", err)
			return
		}
		checked++
		if canonical == 0 {
			bad++
			if sampleID == "" {
				sampleID, sampleTS = id, ts
			}
		}
	}
	if err := rows.Err(); err != nil {
		logger.Warn("could not check the audit trail's timestamp shape", "error", err)
		return
	}
	if bad == 0 {
		return
	}

	logger.Warn("audit trail holds pre-0024 timestamps — rows written by a Relay older than #656 sort out of order against migrated rows, and a pagination cursor landing on one can skip or repeat rows",
		"checked_rows", checked,
		"nonconforming_rows", bad,
		"sample_audit_id", sampleID,
		"sample_ts", sampleTS,
		"repair", auditTSRepairSQL,
	)
}
