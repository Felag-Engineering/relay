package store

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"
	"time"
)

const legacyTSWarning = "audit trail holds pre-0024 timestamps"

// reopenWithLogger closes st and reopens the same database with a buffered
// logger, so a test can assert on what Open itself logs.
func reopenWithLogger(t *testing.T, st *Store, path string) *bytes.Buffer {
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
	return &logBuf
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
	// The rollback shape: a trimmed ts, at a LATER instant than every
	// converted row — which is what makes reading only the newest rows a
	// sufficient window.
	insertLegacyAuditRow(t, st.db, "rolled-back", "2026-09-21T12:01:00Z")

	logBuf := reopenWithLogger(t, st, path)

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

	logBuf := reopenWithLogger(t, st, path)

	if lines := linesContaining(logBuf, legacyTSWarning); len(lines) != 0 {
		t.Errorf("Open warned about legacy audit timestamps on a fully converted table: %q — a detector that cries wolf on every boot is one an operator learns to ignore", lines)
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
