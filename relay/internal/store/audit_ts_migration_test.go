package store

import (
	"context"
	"database/sql"
	"strings"
	"testing"

	"github.com/Felag-Engineering/relay/relay/internal/audit"
	"github.com/Felag-Engineering/relay/relay/internal/jobs"
)

// migrationByVersion returns the shipped migration with that version, so
// these tests exercise the statements an operator actually runs rather than a
// copy of them that could drift.
func migrationByVersion(t *testing.T, version int) migration {
	t.Helper()
	migrations, err := loadMigrations()
	if err != nil {
		t.Fatalf("loadMigrations: %v", err)
	}
	for _, m := range migrations {
		if m.version == version {
			return m
		}
	}
	t.Fatalf("migration %d is not embedded", version)
	return migration{}
}

// migration0024 is the audit ts conversion (#656).
func migration0024(t *testing.T) migration {
	t.Helper()
	return migrationByVersion(t, 24)
}

// auditIndexDefinitions maps each idx_audit_* index a migration creates to
// its definition from ON onwards, whitespace-collapsed and with IF NOT EXISTS
// removed — so two files creating the same index are directly comparable.
func auditIndexDefinitions(t *testing.T, m migration) map[string]string {
	t.Helper()
	defs := map[string]string{}
	for _, stmt := range splitStatements(m.sql) {
		norm := strings.Join(strings.Fields(stmt), " ")
		rest, isCreate := strings.CutPrefix(norm, "CREATE INDEX ")
		if !isCreate {
			continue
		}
		rest = strings.TrimPrefix(rest, "IF NOT EXISTS ")
		name, def, ok := strings.Cut(rest, " ")
		if !ok || !strings.HasPrefix(name, "idx_audit_") {
			continue
		}
		defs[name] = def
	}
	return defs
}

// TestAuditIndexDefinitions_0021MatchesMigration0024 pins the five audit
// index definitions in 0021 against the ones 0024 recreates.
//
// This became load-bearing the moment 0021's creates gained IF NOT EXISTS
// (#656): on #492's repair path — a database that skipped 0021 and later
// applied 0024 — 0021 runs against a table where 0024 has already created
// these indexes, and IF NOT EXISTS then SKIPS each one. If the two files ever
// disagree, the repair silently keeps 0024's definition and never applies
// 0021's, with no error anywhere. Two copies of a definition, so: pinned,
// exactly as auditTSCanonicaliseSQL is pinned against the migration it quotes.
func TestAuditIndexDefinitions_0021MatchesMigration0024(t *testing.T) {
	in21 := auditIndexDefinitions(t, migrationByVersion(t, 21))
	in24 := auditIndexDefinitions(t, migration0024(t))

	for _, name := range []string{"idx_audit_ts", "idx_audit_kind_ts", "idx_audit_account_ts", "idx_audit_node_ts", "idx_audit_job_ts"} {
		def21, ok21 := in21[name]
		def24, ok24 := in24[name]
		switch {
		case !ok21:
			t.Errorf("%s is not created by 0021 — the five audit indexes live in 0021 and are recreated by 0024; if one moved, this pin must move with it (#656)", name)
		case !ok24:
			t.Errorf("%s is not created by 0024 — 0024 drops all five audit indexes around its row rewrite and must recreate every one (#656)", name)
		case def21 != def24:
			t.Errorf("%s is created differently by the two migrations:\n  0021: %s\n  0024: %s\nThey must be byte-identical modulo whitespace: 0021 creates it with IF NOT EXISTS, so on #492's repair path a drifted definition is SILENTLY SKIPPED rather than applied (#656).", name, def21, def24)
		}
	}
}

// runMigration0024 re-executes the shipped statements against a store where
// 0024 has ALREADY run (openTestStore applies every migration).
//
// That works only because the file leads with DROP INDEX IF EXISTS: a plain
// DROP INDEX, or a CREATE INDEX without IF EXISTS in front of it, would make
// every test below fail for a reason that has nothing to do with what it
// asserts.
//
// Since #896 the audit table refuses UPDATE, so the statements run with the
// append-only triggers lifted (withoutAppendOnlyTriggers) — the test-only
// equivalent of an operator restoring a database from before migration 28.
func runMigration0024(t *testing.T, db *sql.DB) {
	t.Helper()
	withoutAppendOnlyTriggers(t, db, func() {
		for _, stmt := range splitStatements(migration0024(t).sql) {
			if _, err := db.ExecContext(context.Background(), stmt); err != nil {
				t.Fatalf("exec 0024 statement %q: %v", stmt, err)
			}
		}
	})
}

// insertLegacyAuditRow writes a row with a hand-supplied ts TEXT, bypassing
// the Go writer — the only way to produce the pre-0024 shapes the migration
// exists to convert.
func insertLegacyAuditRow(t *testing.T, db *sql.DB, id, ts string) {
	t.Helper()
	if _, err := db.ExecContext(context.Background(), `
		INSERT INTO audit (audit_id, ts, kind, principal, selector, job_id, action_kind, outcome)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		id, ts, audit.KindDispatch, "gleipnir:operator", "relay:env=prod", "job-1", "operation", int(jobs.OutcomeSuccess),
	); err != nil {
		t.Fatalf("insert legacy audit row %s: %v", id, err)
	}
}

// storedTS reads the ts column's ACTUAL BYTES. A direct scan would not: ts is
// declared TIMESTAMP, so the driver parses it into a time.Time and
// database/sql re-renders it as trimmed RFC3339Nano (#656 finding 4).
func storedTS(t *testing.T, db *sql.DB, id string) string {
	t.Helper()
	var ts string
	if err := db.QueryRowContext(context.Background(),
		`SELECT CAST(ts AS TEXT) FROM audit WHERE audit_id = ?`, id).Scan(&ts); err != nil {
		t.Fatalf("read stored ts for %s: %v", id, err)
	}
	return ts
}

func TestMigration0024_ConvertsLegacyTimestampShapes(t *testing.T) {
	st, _ := openTestStore(t)

	cases := []struct {
		id, legacy, want string
	}{
		{"whole-second", "2026-01-01T00:00:01Z", "2026-01-01T00:00:01.000000000Z"},
		{"one-digit", "2026-01-01T00:00:01.5Z", "2026-01-01T00:00:01.500000000Z"},
		{"four-digits", "2026-01-01T00:00:01.5001Z", "2026-01-01T00:00:01.500100000Z"},
		{"nine-digits", "2026-01-01T00:00:01.123456789Z", "2026-01-01T00:00:01.123456789Z"},
		{"trailing-nano", "2026-01-01T00:00:01.000000001Z", "2026-01-01T00:00:01.000000001Z"},
		{"epoch", "1970-01-01T00:00:00Z", "1970-01-01T00:00:00.000000000Z"},
	}
	for _, c := range cases {
		insertLegacyAuditRow(t, st.db, c.id, c.legacy)
	}

	runMigration0024(t, st.db)

	for _, c := range cases {
		if got := storedTS(t, st.db, c.id); got != c.want {
			t.Errorf("migration 0024 left ts = %q for %s, want %q — a row written before 0024 must convert to the fixed-width form or the table sorts as two formats at once (#656)", got, c.id, c.want)
		}
	}
}

func TestMigration0024_IsIdempotent(t *testing.T) {
	st, _ := openTestStore(t)

	insertLegacyAuditRow(t, st.db, "legacy", "2026-01-01T00:00:01.5Z")
	runMigration0024(t, st.db)
	first := storedTS(t, st.db, "legacy")

	runMigration0024(t, st.db)
	second := storedTS(t, st.db, "legacy")

	if first != second {
		t.Errorf("re-running 0024 changed %q to %q — the conversion must be idempotent so an operator can re-run it after a binary rollback", first, second)
	}
}

// TestMigration0024_SkipGateIsThePositiveShape pins the gate's SPELLING and
// its outcome, and is careful about which of the two each assertion proves.
//
// The outcome half — an already-canonical row and a 30-character
// non-canonical one both survive untouched — is what must be true, and it is
// true under either spelling. The gate was changed from length(ts) <> 30 to
// "NOT GLOB the canonical pattern" for clarity, not to fix a corruption:
// a 30-character value in the wrong shape was skipped by the length gate and
// is skipped by the shape GLOB, so both spellings behave identically on
// everything reachable. Claiming otherwise in a test message would be the
// same over-claiming this issue is about.
//
// So the spelling itself is asserted against the shipped SQL directly. That
// is the part that actually changed, and the only way to make it falsifiable.
func TestMigration0024_SkipGateIsThePositiveShape(t *testing.T) {
	st, _ := openTestStore(t)

	// Comments stripped first: the prose explains WHY the gate is not a length
	// comparison, and naming the rejected spelling there must not read as
	// using it.
	sqlText := stripLineComments(migration0024(t).sql)
	if !strings.Contains(sqlText, "ts NOT GLOB '"+auditTSCanonicalGlob+"'") {
		t.Errorf("0024's skip gate is not \"ts NOT GLOB '<canonical>'\" — it must say what it means, and it must be the SAME pattern auditTSCanonicalGlob holds, so the writer, the migration and the rollback detector cannot disagree about what \"already converted\" means (#656)")
	}
	if strings.Contains(sqlText, "length(ts) <> 30") {
		t.Errorf("0024's skip gate is a length comparison — \"2026-01-01T00:00:01.1234+05:30\" is also exactly 30 characters, so the length is an approximation of the shape rather than the shape itself")
	}

	const (
		canonical = "2026-01-01T00:00:01.000000000Z"
		// Exactly 30 characters, and not the canonical form: a non-UTC offset.
		// Unreachable through the Go writer, which always converts to UTC.
		offsetForm = "2026-01-01T00:00:01.1234+05:30"
	)
	if len(offsetForm) != 30 {
		t.Fatalf("fixture %q is %d characters, the test needs exactly 30", offsetForm, len(offsetForm))
	}
	insertLegacyAuditRow(t, st.db, "canonical", canonical)
	insertLegacyAuditRow(t, st.db, "offset-form", offsetForm)

	runMigration0024(t, st.db)

	for _, c := range []struct{ id, want string }{
		{"canonical", canonical},
		{"offset-form", offsetForm},
	} {
		if got := storedTS(t, st.db, c.id); got != c.want {
			t.Errorf("0024 changed %q to %q — an already-canonical row and a 30-character non-canonical one must both survive: the first is skipped by the canonical gate, the second by the shape GLOB, and neither may be rewritten", c.want, got)
		}
	}
}

func TestMigration0024_LeavesUnrecognisedTextAlone(t *testing.T) {
	st, _ := openTestStore(t)

	for _, junk := range []string{"not-a-timestamp", "", "2026-01-01", "10000-01-01T00:00:01Z"} {
		insertLegacyAuditRow(t, st.db, "junk-"+junk, junk)
	}

	runMigration0024(t, st.db)

	for _, junk := range []string{"not-a-timestamp", "", "2026-01-01", "10000-01-01T00:00:01Z"} {
		if got := storedTS(t, st.db, "junk-"+junk); got != junk {
			t.Errorf("0024 changed %q to %q — the shape GLOB exists so a value this code could never have written is left alone rather than mangled by substr arithmetic", junk, got)
		}
	}
}

// TestMigration0024_IndexesCarryTheTieBreak pins the index decision in both
// directions, because it is a decision and not an oversight.
//
// The four indexes that order BY ts carry audit_id, so the new ORDER BY is
// index-satisfied. idx_audit_job_ts deliberately does NOT: widening it to
// (job_id, ts, audit_id) was measured, and SQLite then stops choosing it for
// jobquery.go's per-Job audit aggregate, switching to idx_audit_kind_ts and
// reading every dispatch row ever written on each Job-detail page view —
// exactly what TestJobQuery_SingleJobDoesNotScanEveryTask forbids. ByJob
// sorting its tie-break in a temp B-tree over one Job's rows is the cheaper
// half of that trade.
func TestMigration0024_IndexesCarryTheTieBreak(t *testing.T) {
	st, _ := openTestStore(t)

	rows, err := st.db.QueryContext(context.Background(),
		`SELECT name, sql FROM sqlite_master WHERE type = 'index' AND name LIKE 'idx_audit_%'`)
	if err != nil {
		t.Fatalf("read index definitions: %v", err)
	}
	defer rows.Close()

	defs := map[string]string{}
	for rows.Next() {
		var name string
		var def sql.NullString
		if err := rows.Scan(&name, &def); err != nil {
			t.Fatalf("scan index definition: %v", err)
		}
		defs[name] = def.String
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate index definitions: %v", err)
	}

	for _, name := range []string{"idx_audit_ts", "idx_audit_kind_ts", "idx_audit_account_ts", "idx_audit_node_ts"} {
		def, ok := defs[name]
		if !ok {
			t.Errorf("%s is missing — migration 0024 drops all five audit indexes and must recreate every one", name)
			continue
		}
		if !strings.Contains(def, "audit_id") {
			t.Errorf("%s = %q — every audit index ordered by ts must carry audit_id, or the new ORDER BY falls back to a temp B-tree sort (#656)", name, def)
		}
	}

	jobDef, ok := defs["idx_audit_job_ts"]
	if !ok {
		t.Fatal("idx_audit_job_ts is missing — migration 0024 drops all five audit indexes and must recreate every one")
	}
	if strings.Contains(jobDef, "audit_id") {
		t.Errorf("idx_audit_job_ts = %q — it must stay (job_id, ts). Widening it flips SQLite's choice for jobquery.go's per-Job audit aggregate onto idx_audit_kind_ts, which reads every dispatch row in the trail on every Job-detail page view (#656, and TestJobQuery_SingleJobDoesNotScanEveryTask)", jobDef)
	}
}
