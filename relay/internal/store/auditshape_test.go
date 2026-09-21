package store

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"testing"
	"time"
)

const legacyTSWarning = "audit trail holds pre-0024 timestamps"

// reopenWithLogger closes st and reopens the same database with a buffered
// logger, so a test can assert on what Open itself logs — and hands back the
// reopened Store, since the detector's durability is a property ACROSS boots.
func reopenWithLogger(t *testing.T, st *Store, path string) (*Store, *bytes.Buffer) {
	t.Helper()
	if err := st.Close(); err != nil {
		t.Fatalf("close store: %v", err)
	}
	var logBuf bytes.Buffer
	reopened, err := Open(path, WithLogger(slog.New(slog.NewJSONHandler(&logBuf, nil))))
	if err != nil {
		t.Fatalf("reopen store: %v", err)
	}
	t.Cleanup(func() { _ = reopened.Close() })
	return reopened, &logBuf
}

// auditShapeAlertRows reports how many rows audit_shape_alert holds: 0 on
// every database that has never been seen mixed, 1 once it has.
func auditShapeAlertRows(t *testing.T, st *Store) int {
	t.Helper()
	var n int
	if err := st.db.QueryRowContext(context.Background(), `SELECT count(*) FROM audit_shape_alert`).Scan(&n); err != nil {
		t.Fatalf("count audit_shape_alert: %v", err)
	}
	return n
}

// appendCanonicalRows writes n rows through the real writer, which is what
// scrolls the detector's window past whatever came before them.
func appendCanonicalRows(t *testing.T, st *Store, n int, base time.Time) {
	t.Helper()
	ctx := context.Background()
	for i := 0; i < n; i++ {
		id := fmt.Sprintf("scroll-%03d", i)
		if err := st.Audit().Append(ctx, orderRecord(id, base.Add(time.Duration(i)*time.Millisecond))); err != nil {
			t.Fatalf("append %s: %v", id, err)
		}
	}
}

// linesContaining returns the log lines whose text carries msg.
func linesContaining(logBuf *bytes.Buffer, msg string) []string {
	var out []string
	for _, line := range strings.Split(strings.TrimRight(logBuf.String(), "\n"), "\n") {
		if strings.Contains(line, msg) {
			out = append(out, line)
		}
	}
	return out
}

// TestWarnOnLegacyAuditTimestamps_WarnsOnARolledBackRow is the #656 residual
// R1 made visible: an operator who rolls a binary back onto a converted table
// gets pre-0024 rows written into it, and upgrading again fixes nothing
// because migrate selects by presence and 24 is already recorded. Without
// this line the symptom is completely silent.
func TestWarnOnLegacyAuditTimestamps_WarnsOnARolledBackRow(t *testing.T) {
	st, path := openTestStore(t)
	ctx := context.Background()

	base := time.Date(2026, 9, 21, 12, 0, 0, 0, time.UTC)
	for i, id := range []string{"canon-1", "canon-2", "canon-3"} {
		if err := st.Audit().Append(ctx, orderRecord(id, base.Add(time.Duration(i)*time.Second))); err != nil {
			t.Fatalf("append %s: %v", id, err)
		}
	}
	// The rollback shape: a trimmed ts, written AFTER every converted row —
	// which is what makes reading only the most recently inserted rows a
	// sufficient window for the first observation.
	insertLegacyAuditRow(t, st.db, "rolled-back", "2026-09-21T12:01:00Z")

	_, logBuf := reopenWithLogger(t, st, path)

	lines := linesContaining(logBuf, legacyTSWarning)
	if len(lines) != 1 {
		t.Fatalf("Open logged %d warnings for a trimmed ts row, want 1 — a binary rollback after 0024 re-introduces the pre-0024 format silently, and roll-forward does not self-heal because migrate selects by presence (#656); log:\n%s", len(lines), logBuf.String())
	}

	var entry struct {
		Level             string `json:"level"`
		CheckedRows       int    `json:"checked_rows"`
		NonconformingRows int    `json:"nonconforming_rows"`
		SampleAuditID     string `json:"sample_audit_id"`
		SampleTS          string `json:"sample_ts"`
		Repair            string `json:"repair"`
	}
	if err := json.Unmarshal([]byte(lines[0]), &entry); err != nil {
		t.Fatalf("unmarshal warning %q: %v", lines[0], err)
	}
	if entry.Level != "WARN" {
		t.Errorf("log level = %q, want WARN", entry.Level)
	}
	if entry.NonconformingRows != 1 || entry.CheckedRows != 4 {
		t.Errorf("nonconforming_rows/checked_rows = %d/%d, want 1/4", entry.NonconformingRows, entry.CheckedRows)
	}
	if entry.SampleAuditID != "rolled-back" {
		t.Errorf("sample_audit_id = %q, want rolled-back — the sample must name a row the operator can look at", entry.SampleAuditID)
	}
	if entry.SampleTS != "2026-09-21T12:01:00Z" {
		t.Errorf("sample_ts = %q, want the STORED bytes \"2026-09-21T12:01:00Z\" — the driver re-renders a scanned TIMESTAMP column, so a sample read that way would not be what is in the file", entry.SampleTS)
	}
	if entry.Repair != auditTSRepairSQL {
		t.Errorf("repair = %q, want the 0024 conversion UPDATE — an operator reading this line has a binary and a database, not the repository, so a file reference is not a remedy", entry.Repair)
	}
}

func TestWarnOnLegacyAuditTimestamps_SilentOnACleanTable(t *testing.T) {
	st, path := openTestStore(t)
	ctx := context.Background()

	base := time.Date(2026, 9, 21, 12, 0, 0, 0, time.UTC)
	// Every fractional width the writer can produce, including the
	// whole-second case the driver re-renders to 20 characters on scan — the
	// exact value a detector that measured the SCANNED string would
	// mis-report.
	for i, offset := range []time.Duration{0, 1, 123456789, 999999999} {
		id := "clean-" + string(rune('a'+i))
		if err := st.Audit().Append(ctx, orderRecord(id, base.Add(time.Duration(i)*time.Second+offset))); err != nil {
			t.Fatalf("append %s: %v", id, err)
		}
	}

	reopened, logBuf := reopenWithLogger(t, st, path)

	if lines := linesContaining(logBuf, legacyTSWarning); len(lines) != 0 {
		t.Errorf("Open warned about legacy audit timestamps on a fully converted table: %q — a detector that cries wolf on every boot is one an operator learns to ignore", lines)
	}
	// No alert row means the exact whole-table scan was never reached, which
	// is the property that keeps this check at 0.2 ms instead of the 6.4 s
	// that scan costs at ten million rows.
	if n := auditShapeAlertRows(t, reopened); n != 0 {
		t.Errorf("audit_shape_alert holds %d rows after a clean boot, want 0 — a clean database must never be flagged, and a flagged one pays a whole-index scan on every boot until it is repaired", n)
	}
}

// TestWarnOnLegacyAuditTimestamps_KeepsWarningAfterTheWindowScrolls is the
// #656 cycle-1 security finding, executable: the windowed-only detector
// warned once and then went PERMANENTLY silent as ordinary traffic buried the
// offending rows, while the damage — a silently skipped row in a paged read,
// see TestAuditQuery_MixedFormatRowsAreSkipped — stayed forever.
func TestWarnOnLegacyAuditTimestamps_KeepsWarningAfterTheWindowScrolls(t *testing.T) {
	st, path := openTestStore(t)

	base := time.Date(2026, 9, 21, 12, 0, 0, 0, time.UTC)
	insertLegacyAuditRow(t, st.db, "rolled-back", "2026-09-21T12:01:00Z")

	reopened, logBuf := reopenWithLogger(t, st, path)
	if lines := linesContaining(logBuf, legacyTSWarning); len(lines) != 1 {
		t.Fatalf("the first Open after the rollback logged %d warnings, want 1; log:\n%s", len(lines), logBuf.String())
	}

	// Ordinary traffic: more canonical rows than the window reads, so the
	// window alone would now see nothing wrong.
	appendCanonicalRows(t, reopened, auditShapeCheckRows+50, base.Add(2*time.Minute))

	reopenedAgain, logBuf := reopenWithLogger(t, reopened, path)
	lines := linesContaining(logBuf, legacyTSWarning)
	if len(lines) != 1 {
		t.Fatalf("Open logged %d warnings once %d canonical rows had scrolled the window past the mixed rows, want 1 — the mixed rows are still there and roll-forward does not self-heal, so the warning must outlive the window that observed it (#656); log:\n%s", len(lines), auditShapeCheckRows+50, logBuf.String())
	}

	var entry struct {
		Level           string `json:"level"`
		FirstObservedAt string `json:"first_observed_at"`
		SampleAuditID   string `json:"sample_audit_id"`
		Repair          string `json:"repair"`
	}
	if err := json.Unmarshal([]byte(lines[0]), &entry); err != nil {
		t.Fatalf("unmarshal warning %q: %v", lines[0], err)
	}
	if entry.Level != "WARN" {
		t.Errorf("log level = %q, want WARN", entry.Level)
	}
	if entry.SampleAuditID != "rolled-back" {
		t.Errorf("sample_audit_id = %q, want rolled-back — the sample is carried from the observation precisely because the row is now far outside the window", entry.SampleAuditID)
	}
	if entry.FirstObservedAt == "" {
		t.Errorf("first_observed_at is empty — a warning on a later boot must say when the problem was first seen")
	}
	if entry.Repair != auditTSRepairSQL {
		t.Errorf("repair = %q, want the 0024 conversion UPDATE — every boot's warning must carry the remedy, not just the first", entry.Repair)
	}
	if n := auditShapeAlertRows(t, reopenedAgain); n != 1 {
		t.Errorf("audit_shape_alert holds %d rows, want 1 — the alert is what makes the warning durable", n)
	}
}

// TestWarnOnLegacyAuditTimestamps_ClearsTheAlertAfterTheRepair is the other
// half of durability: a warning that cannot stop is one an operator learns to
// ignore. Running the statement the log line carries must end it.
func TestWarnOnLegacyAuditTimestamps_ClearsTheAlertAfterTheRepair(t *testing.T) {
	st, path := openTestStore(t)

	insertLegacyAuditRow(t, st.db, "rolled-back", "2026-09-21T12:01:00Z")
	reopened, logBuf := reopenWithLogger(t, st, path)
	if lines := linesContaining(logBuf, legacyTSWarning); len(lines) != 1 {
		t.Fatalf("the first Open after the rollback logged %d warnings, want 1; log:\n%s", len(lines), logBuf.String())
	}

	// Exactly what the operator is told to run — the log line's own string.
	if _, err := reopened.db.ExecContext(context.Background(), auditTSRepairSQL); err != nil {
		t.Fatalf("run the repair the warning carries: %v", err)
	}

	repaired, logBuf := reopenWithLogger(t, reopened, path)
	if lines := linesContaining(logBuf, legacyTSWarning); len(lines) != 0 {
		t.Errorf("Open still warned after the repair ran: %q — the alert must clear when the exact check says the table is canonical again", lines)
	}
	if lines := linesContaining(logBuf, "audit trail timestamps are canonical again"); len(lines) != 1 {
		t.Errorf("Open logged %d all-clear lines after the repair, want 1 — an operator who acts on a warning is owed the confirmation; log:\n%s", len(lines), logBuf.String())
	}
	if n := auditShapeAlertRows(t, repaired); n != 0 {
		t.Errorf("audit_shape_alert holds %d rows after the repair, want 0 — a stale alert would make every later boot pay the whole-table scan for nothing", n)
	}
	if got := storedTS(t, repaired.db, "rolled-back"); got != "2026-09-21T12:01:00.000000000Z" {
		t.Errorf("the repaired row holds %q — the statement in the log line must be the one that converts it", got)
	}
}

// TestWarnOnLegacyAuditTimestamps_FirstObservationIsWindowed pins the limit
// of the detector, honestly: the WINDOW is what observes, and it reads only
// the most recently inserted auditShapeCheckRows rows. A legacy row that was
// already buried when this binary first booted is not found — the alert makes
// an observation permanent, it does not make the first observation exact.
//
// The exact question is affordable only on a database already known to be
// mixed: measured 6.4 s at ten million rows, against 0.2 ms for the window.
//
// IF THIS GOES RED because the detector now finds the buried row, that is an
// improvement and this test should be rewritten to assert it — not deleted
// quietly.
func TestWarnOnLegacyAuditTimestamps_FirstObservationIsWindowed(t *testing.T) {
	st, path := openTestStore(t)

	base := time.Date(2026, 9, 21, 12, 0, 0, 0, time.UTC)
	insertLegacyAuditRow(t, st.db, "buried", "2026-09-21T12:00:00Z")
	appendCanonicalRows(t, st, auditShapeCheckRows+10, base.Add(time.Minute))

	reopened, logBuf := reopenWithLogger(t, st, path)
	if lines := linesContaining(logBuf, legacyTSWarning); len(lines) != 0 {
		t.Errorf("Open warned about a legacy row buried under %d later inserts: %q — if the window got wider or exact, say so here", auditShapeCheckRows+10, lines)
	}
	if n := auditShapeAlertRows(t, reopened); n != 0 {
		t.Errorf("audit_shape_alert holds %d rows, want 0 — nothing was observed, so nothing may be remembered", n)
	}
}

// TestWarnOnLegacyAuditTimestamps_SurvivesAQueryError pins that the detector
// is a diagnostic and never a gate: a failing handle produces a log line and
// a normal return, never a panic and never an error the caller could
// mistake for a reason to refuse startup.
func TestWarnOnLegacyAuditTimestamps_SurvivesAQueryError(t *testing.T) {
	st, _ := openTestStore(t)
	db := st.db
	if err := st.Close(); err != nil {
		t.Fatalf("close store: %v", err)
	}

	var logBuf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logBuf, nil))

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("warnOnLegacyAuditTimestamps panicked (%v) — it is a diagnostic and must never gate startup, per #492's tolerate-a-newer-database posture", r)
		}
	}()
	warnOnLegacyAuditTimestamps(context.Background(), db, logger)

	if !strings.Contains(logBuf.String(), "could not check the audit trail's timestamp shape") {
		t.Errorf("a failing query logged %q — the failure must be visible, and visible ONLY as a log line", logBuf.String())
	}
}

// TestAuditTSRepair_MatchesMigration0024 pins the two copies of the
// conversion UPDATE against each other. They are two copies on purpose — the
// log line has to carry a runnable statement — and two copies drift.
func TestAuditTSRepair_MatchesMigration0024(t *testing.T) {
	collapse := func(s string) string { return strings.Join(strings.Fields(s), " ") }

	migrationSQL := collapse(stripLineComments(migration0024(t).sql))
	repair := collapse(auditTSRepairSQL)

	if !strings.Contains(migrationSQL, repair) {
		t.Errorf("auditTSRepairSQL is not present in 0024_audit_ts_sortable.sql — the statement an operator is told to run must be the statement the migration runs, byte for byte modulo whitespace (#656).\nrepair:    %s\nmigration: %s", repair, migrationSQL)
	}
}
