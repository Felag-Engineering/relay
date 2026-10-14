package store

import "time"

// auditTimeLayout is the audit table's ts rendering: RFC3339 in UTC with
// exactly nine fractional digits, always 30 characters.
//
// The property it buys: ts is a TEXT column, so
// ORDER BY on it is a byte comparison, and a byte comparison over a
// FIXED-WIDTH rendering is chronological order. time.RFC3339Nano trims
// trailing zeros in the fraction, so under it "…:01Z" sorts AFTER "…:01.5Z"
// and "…:01.15Z" sorts after "…:01.1Z" — a systematic inversion, not a rare
// one, for anything written on a whole-second boundary. Migration 0024
// converts every stored row to this layout, and formatAuditTime is the only
// thing that writes it.
//
// AUDIT-ONLY, deliberately. timeLayout/formatTime (registry.go) stay
// RFC3339Nano for the other eleven tables. jobs.created_at has the same
// latent defect, and jobquery.go's cursor is built from the driver's
// re-rendering of that column exactly as auditquery.go's was — so moving the
// global layout would silently break Jobs pagination the same way this change
// had to fix for the trail. That is its own migration and its own issue.
const auditTimeLayout = "2006-01-02T15:04:05.000000000Z"

// formatAuditTime returns the value to store in the audit table's ts column:
// NULL for the zero value, else the fixed-width text.
//
// The NULL half mirrors formatTime rather than inventing a zero-time
// encoding: ts is NOT NULL, so a zero Timestamp fails the INSERT loudly
// instead of being recorded as a plausible-looking instant in year 1.
func formatAuditTime(t time.Time) any {
	if t.IsZero() {
		return nil
	}
	return t.UTC().Format(auditTimeLayout)
}

// normalizeAuditTimeText re-renders any RFC3339Nano spelling of an instant as
// the bytes migration 0024 stores for it.
//
// One implementation of "whatever rendering this instant arrived in, map it to
// the stored text". decodeAuditCursor is the caller: a keyset cursor compares
// its ts as TEXT against the column, so a cursor carrying a trimmed rendering
// ("…:01Z") would compare unequal to the stored "…:01.000000000Z" and
// mis-seek. An unparseable value is an error, never a best-effort guess.
func normalizeAuditTimeText(s string) (string, error) {
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		return "", err
	}
	return t.UTC().Format(auditTimeLayout), nil
}
