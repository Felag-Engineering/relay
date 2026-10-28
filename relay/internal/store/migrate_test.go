package store

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"io"
	"log/slog"
	"path/filepath"
	"reflect"
	"sort"
	"testing"
	"time"
)

// discardLogger is the logger a test hands applyMigration when it asserts
// nothing about what the migration logs.
func discardLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// The regression this exists for: a semicolon inside a migration comment used
// to split the file mid-sentence, handing the remaining prose to SQLite as a
// statement. It failed with a syntax error pointing at an English word, which
// is a long way from "your comment has a semicolon in it".
//
// Migration comments are where the reasoning for a schema change lives, so
// they are precisely where ordinary punctuation turns up.
func TestSplitStatements_SemicolonInACommentIsNotAStatement(t *testing.T) {
	sql := `
-- Two lanes, kept distinct in the schema; blurring them is how an audit trail
-- becomes fiction.
ALTER TABLE audit ADD COLUMN account_id TEXT;

-- A second comment; also with a semicolon.
ALTER TABLE audit ADD COLUMN token_id TEXT;
`
	want := []string{
		"ALTER TABLE audit ADD COLUMN account_id TEXT",
		"ALTER TABLE audit ADD COLUMN token_id TEXT",
	}
	if got := splitStatements(sql); !reflect.DeepEqual(got, want) {
		t.Errorf("splitStatements =\n  %q\nwant\n  %q", got, want)
	}
}

func TestSplitStatements_OrdinaryCases(t *testing.T) {
	cases := []struct {
		label string
		sql   string
		want  []string
	}{
		{"empty", "", nil},
		{"comments only", "-- nothing but prose;\n-- more prose\n", nil},
		{"no trailing semicolon", "SELECT 1", []string{"SELECT 1"}},
		{"blank statements collapse", "SELECT 1;;;\n\n;SELECT 2;", []string{"SELECT 1", "SELECT 2"}},
		{
			"indented comment",
			"    -- indented; still a comment\nSELECT 1;",
			[]string{"SELECT 1"},
		},
		{
			"multi-line statement keeps its shape",
			"CREATE INDEX idx\n    ON audit (account_id) WHERE account_id IS NOT NULL;",
			[]string{"CREATE INDEX idx\n    ON audit (account_id) WHERE account_id IS NOT NULL"},
		},
	}
	for _, c := range cases {
		got := splitStatements(c.sql)
		if len(got) == 0 && len(c.want) == 0 {
			continue
		}
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("[%s] splitStatements = %q, want %q", c.label, got, c.want)
		}
	}
}

// The documented remaining limitation, pinned so it stays a known constraint
// rather than becoming a surprise: a trailing comment on the same line as SQL
// is NOT stripped, because telling it apart from a "--" inside a string
// literal needs a tokenizer. Dropping a line that is unambiguously a comment
// cannot corrupt a statement; guessing at one that might be a literal can.
func TestSplitStatements_TrailingCommentsAreNotStripped(t *testing.T) {
	got := splitStatements("SELECT 1; -- a trailing note\n")
	want := []string{"SELECT 1", "-- a trailing note"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("splitStatements = %q, want %q — the trailing-comment limitation is documented on splitStatements", got, want)
	}
}

// Every shipped migration must still split into statements SQLite accepts.
// openTestStore runs the whole set, so this is really an assertion that the
// stripping did not eat anything load-bearing.
func TestMigrations_AllApplyCleanly(t *testing.T) {
	st, _ := openTestStore(t)
	if st == nil {
		t.Fatal("openTestStore returned nil")
	}
}

// TestMigrations_VersionsAreContiguousFromOne is the option-3 deliverable
// (#492): under presence-based selection, a gap or a duplicate in the
// embedded set is no longer caught by comparing against MAX(version) at
// runtime, so it must be caught here instead. It rides the repo's normal
// test gate (make test-relay / make test-relay-race / make verify) as a
// unit-level invariant of this one package — it does not have its own named
// Makefile target or CI job the way openapi-check and opschema-check do,
// because those check drift between artifacts and this checks one package's
// internal numbering.
func TestMigrations_VersionsAreContiguousFromOne(t *testing.T) {
	migrations, err := loadMigrations()
	if err != nil {
		t.Fatalf("loadMigrations: %v", err)
	}

	versions := make([]int, 0, len(migrations))
	seenBy := make(map[int]string, len(migrations))
	for _, m := range migrations {
		if other, dup := seenBy[m.version]; dup {
			t.Fatalf("migration version %d is used twice: %q and %q — every embedded migration version must be unique", m.version, other, m.name)
		}
		seenBy[m.version] = m.name
		versions = append(versions, m.version)
	}
	sort.Ints(versions)

	for i, v := range versions {
		if want := i + 1; v != want {
			t.Fatalf(
				"embedded migration versions are not contiguous from 1: got %v.\n"+
					"Renumber the OFFENDING NEW file to max+1 (%d) BEFORE merging.\n"+
					"Do NOT renumber a migration that has already shipped: under presence-based "+
					"selection (#492) a migration is applied whenever its version is absent from "+
					"schema_migrations, so giving a shipped migration a new number makes an "+
					"already-migrated database apply it a second time.",
				versions, len(versions)+1,
			)
		}
	}
}

// TestPendingMigrations_ReappliesAnAbsentLowerVersion is the regression this
// issue is about, and the exact scenario #492 reported: embedded versions
// 1, 2, 22, 23 with 23 recorded as applied and 22 absent. Under the old
// MAX(version) comparison this would silently and permanently skip 22;
// under presence-based selection it must be pending. There is no 0023 file
// in this repo and adding one is out of scope, which is exactly why
// pendingMigrations is a pure function independent of the embedded FS.
func TestPendingMigrations_ReappliesAnAbsentLowerVersion(t *testing.T) {
	migrations := []migration{
		{version: 1, name: "0001_a.sql"},
		{version: 2, name: "0002_b.sql"},
		{version: 22, name: "0022_c.sql"},
		{version: 23, name: "0023_d.sql"},
	}
	applied := map[int]struct{}{1: {}, 2: {}, 23: {}}

	pending, unknown := pendingMigrations(migrations, applied)

	if len(unknown) != 0 {
		t.Errorf("unknown = %v, want none", unknown)
	}
	if len(pending) != 1 || pending[0].version != 22 {
		t.Fatalf("pending = %v, want exactly version 22 — 23 already being recorded must not suppress the still-absent 22", pending)
	}
}

// TestPendingMigrations_FreshDatabase: an empty applied set (schema_migrations
// not created yet) yields every embedded migration, in ascending order —
// the 0001_init.sql precondition.
func TestPendingMigrations_FreshDatabase(t *testing.T) {
	migrations := []migration{
		{version: 1, name: "0001_a.sql"},
		{version: 2, name: "0002_b.sql"},
		{version: 3, name: "0003_c.sql"},
	}

	pending, unknown := pendingMigrations(migrations, map[int]struct{}{})

	if len(unknown) != 0 {
		t.Errorf("unknown = %v, want none", unknown)
	}
	if !reflect.DeepEqual(pending, migrations) {
		t.Errorf("pending = %v, want every migration in ascending order %v", pending, migrations)
	}
}

// TestPendingMigrations_UpToDateIsNoOp: an applied set that is a superset of
// the embedded migrations yields no pending work — re-running migrate on an
// up-to-date (or newer-than-this-binary) database must not reapply anything.
func TestPendingMigrations_UpToDateIsNoOp(t *testing.T) {
	migrations := []migration{
		{version: 1, name: "0001_a.sql"},
		{version: 2, name: "0002_b.sql"},
	}
	applied := map[int]struct{}{1: {}, 2: {}, 3: {}}

	pending, _ := pendingMigrations(migrations, applied)

	if len(pending) != 0 {
		t.Errorf("pending = %v, want none", pending)
	}
}

// TestPendingMigrations_UnknownAppliedVersionIsReportedNotDropped: an applied
// version with no embedded file (a database newer than this binary) must
// come back in unknown, not simply vanish.
func TestPendingMigrations_UnknownAppliedVersionIsReportedNotDropped(t *testing.T) {
	migrations := []migration{
		{version: 1, name: "0001_a.sql"},
		{version: 2, name: "0002_b.sql"},
	}
	applied := map[int]struct{}{1: {}, 2: {}, 99: {}}

	pending, unknown := pendingMigrations(migrations, applied)

	if len(pending) != 0 {
		t.Errorf("pending = %v, want none", pending)
	}
	if !reflect.DeepEqual(unknown, []int{99}) {
		t.Errorf("unknown = %v, want [99]", unknown)
	}
}

// TestAppliedVersions_TableAbsentIsEmptyNotAnError is the 0001_init.sql
// precondition: appliedVersions must not error on a database that has never
// been migrated, and must hand back a non-nil empty map so pendingMigrations
// needs no special case for it.
func TestAppliedVersions_TableAbsentIsEmptyNotAnError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fresh.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	defer db.Close()

	applied, err := appliedVersions(context.Background(), db)
	if err != nil {
		t.Fatalf("appliedVersions: %v", err)
	}
	if applied == nil {
		t.Fatal("appliedVersions returned a nil map on a table-absent database, want non-nil empty")
	}
	if len(applied) != 0 {
		t.Errorf("applied = %v, want empty", applied)
	}
}

// TestAppliedVersions_ReadsEveryRowNotJustTheMax is the direct regression
// test for the bug this issue reports at the query layer: appliedVersions
// must return every recorded version, not MAX(version).
func TestAppliedVersions_ReadsEveryRowNotJustTheMax(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "versions.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)

	migrations, err := loadMigrations()
	if err != nil {
		t.Fatalf("loadMigrations: %v", err)
	}
	for _, m := range migrations {
		if m.version > 2 {
			continue
		}
		if err := applyMigration(ctx, db, m, discardLogger()); err != nil {
			t.Fatalf("apply %s: %v", m.name, err)
		}
	}

	// A higher version, hand-inserted rather than applied through a migration
	// file this test does not have — standing in for a version recorded by a
	// binary newer than the one running this test.
	if _, err := db.ExecContext(ctx,
		`INSERT INTO schema_migrations (version, applied_at) VALUES (?, ?)`,
		9999, time.Now().UTC().Format(timeLayout),
	); err != nil {
		t.Fatalf("insert version 9999: %v", err)
	}

	applied, err := appliedVersions(ctx, db)
	if err != nil {
		t.Fatalf("appliedVersions: %v", err)
	}
	want := map[int]struct{}{1: {}, 2: {}, 9999: {}}
	if !reflect.DeepEqual(applied, want) {
		t.Errorf("applied = %v, want %v — appliedVersions must return every row, not MAX(version)", applied, want)
	}
}

// seedMigrations applies every embedded migration through applyMigration
// EXCEPT those in skip, over a raw *sql.DB, to build a database at a known,
// non-current schema state. Called with no skip versions, it seeds the full
// embedded set.
func seedMigrations(t *testing.T, db *sql.DB, skip ...int) (migrations []migration, seeded int) {
	t.Helper()
	skipped := make(map[int]struct{}, len(skip))
	for _, v := range skip {
		skipped[v] = struct{}{}
	}

	migrations, err := loadMigrations()
	if err != nil {
		t.Fatalf("loadMigrations: %v", err)
	}
	for _, m := range migrations {
		if _, ok := skipped[m.version]; ok {
			continue
		}
		if err := applyMigration(context.Background(), db, m, discardLogger()); err != nil {
			t.Fatalf("seed %s: %v", m.name, err)
		}
		seeded++
	}
	return migrations, seeded
}

// TestMigrate_RepairsASkippedMigration builds a database with every embedded
// migration applied EXCEPT 21, so a lower version is absent while every
// higher version — including 22 — is already recorded. That state is
// reachable in reality because 21 (audit/jobs/tasks indexes only) and 22
// (an ALTER on approval_requests) are mutually independent: neither's SQL
// depends on the other having run, so nothing about applying 22 first would
// have failed. Running migrate must apply 21, and its actual effect — not
// just its schema_migrations row — must be present afterward.
func TestMigrate_RepairsASkippedMigration(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "skipped21.db")

	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	db.SetMaxOpenConns(1)
	migrations, seeded := seedMigrations(t, db, 21)
	if want := len(migrations) - 1; seeded != want {
		t.Fatalf("seeded %d migrations, want %d (every embedded migration except 21)", seeded, want)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("close seed db: %v", err)
	}

	st, err := Open(path)
	if err != nil {
		t.Fatalf("Open on a database missing migration 21: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	applied, err := appliedVersions(ctx, st.db)
	if err != nil {
		t.Fatalf("appliedVersions: %v", err)
	}
	if len(applied) != len(migrations) {
		t.Errorf("applied = %d versions, want %d (every embedded migration)", len(applied), len(migrations))
	}
	for _, m := range migrations {
		if _, ok := applied[m.version]; !ok {
			t.Errorf("migration %d (%s) was not applied after repair", m.version, m.name)
		}
	}

	// 21's actual work landed, not just its schema_migrations row: it
	// creates idx_audit_ts among others.
	var name string
	err = st.db.QueryRowContext(ctx,
		`SELECT name FROM sqlite_master WHERE type = 'index' AND name = 'idx_audit_ts'`,
	).Scan(&name)
	if err != nil {
		t.Fatalf("idx_audit_ts (created by migration 21) not found after repair: %v", err)
	}
}

// TestMigrate_IsIdempotent: a second migrate on an already-repaired,
// up-to-date database is a no-op — no error, and schema_migrations gains no
// rows.
func TestMigrate_IsIdempotent(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "idempotent.db")

	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	db.SetMaxOpenConns(1)
	defer db.Close()
	migrations, _ := seedMigrations(t, db, 21)

	if err := migrate(ctx, db, slog.Default()); err != nil {
		t.Fatalf("first migrate (repair): %v", err)
	}
	var rowsAfterRepair int
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM schema_migrations`).Scan(&rowsAfterRepair); err != nil {
		t.Fatalf("count after repair: %v", err)
	}
	if rowsAfterRepair != len(migrations) {
		t.Fatalf("rows after repair = %d, want %d (every embedded migration)", rowsAfterRepair, len(migrations))
	}

	if err := migrate(ctx, db, slog.Default()); err != nil {
		t.Fatalf("second migrate: %v", err)
	}
	var rowsAfterSecondRun int
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM schema_migrations`).Scan(&rowsAfterSecondRun); err != nil {
		t.Fatalf("count after second run: %v", err)
	}
	if rowsAfterSecondRun != rowsAfterRepair {
		t.Errorf("schema_migrations row count changed on a no-op re-run: %d -> %d", rowsAfterRepair, rowsAfterSecondRun)
	}
}

// TestMigrate_UnknownAppliedVersionDoesNotBlockStartup pins the
// tolerate-don't-refuse decision (#492): a schema_migrations row recorded by
// a binary newer than this one must not stop Open from succeeding, must not
// be touched, and — because "logged and tolerated, never silent" is the
// whole point of that decision — must actually produce a warning carrying
// the unknown version and a count, not merely leave Open returning nil.
func TestMigrate_UnknownAppliedVersionDoesNotBlockStartup(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "newer-than-binary.db")

	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	db.SetMaxOpenConns(1)
	migrations, _ := seedMigrations(t, db)

	// Simulate a database written by a newer binary that shipped a
	// migration this binary does not embed (e.g. after a binary rollback,
	// since migrations here are forward-only).
	if _, err := db.ExecContext(ctx,
		`INSERT INTO schema_migrations (version, applied_at) VALUES (?, ?)`,
		9999, time.Now().UTC().Format(timeLayout),
	); err != nil {
		t.Fatalf("insert version 9999: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("close seed db: %v", err)
	}

	var logBuf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logBuf, nil))

	st, err := Open(path, WithLogger(logger))
	if err != nil {
		t.Fatalf("Open on a database newer than this binary: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	applied, err := appliedVersions(context.Background(), st.db)
	if err != nil {
		t.Fatalf("appliedVersions: %v", err)
	}
	if len(applied) != len(migrations)+1 {
		t.Errorf("applied = %d versions, want %d (every embedded version, plus the untouched 9999)", len(applied), len(migrations)+1)
	}
	if _, ok := applied[9999]; !ok {
		t.Error("the unrecognised version 9999 row was removed; migrate must leave it alone")
	}

	var entry struct {
		Level           string `json:"level"`
		Msg             string `json:"msg"`
		UnknownVersions []int  `json:"unknown_versions"`
		Count           int    `json:"count"`
	}
	if err := json.Unmarshal(logBuf.Bytes(), &entry); err != nil {
		t.Fatalf("unmarshal warning log line %q: %v", logBuf.String(), err)
	}
	if entry.Level != "WARN" {
		t.Errorf("log level = %q, want WARN", entry.Level)
	}
	if entry.Msg == "" {
		t.Error("warning message is empty")
	}
	if !reflect.DeepEqual(entry.UnknownVersions, []int{9999}) {
		t.Errorf("unknown_versions = %v, want [9999]", entry.UnknownVersions)
	}
	if entry.Count != 1 {
		t.Errorf("count = %d, want 1", entry.Count)
	}
}

// TestLogMigrationApplied_InfoOnlyPastTheSlowThreshold pins the level the
// per-migration line is logged at, in both directions.
//
// It matters twice. A fresh Open applies two dozen migrations in microseconds
// each: at Info they bury the one line an operator is meant to see, which is
// why everything below migrationSlowThreshold is Debug. And 0024 rewrites
// every audit row — minutes on a large trail — which is the line that must
// not be invisible.
//
// The durations here are ABSOLUTE rather than expressed relative to
// migrationSlowThreshold on purpose: a test written as
// "migrationSlowThreshold - 1ns must be Debug" passes even if the threshold
// is set to zero, which is exactly the regression it would exist to catch.
func TestLogMigrationApplied_InfoOnlyPastTheSlowThreshold(t *testing.T) {
	cases := []struct {
		name    string
		elapsed time.Duration
		want    string
	}{
		{"instant, as a schema-only migration is", 0, "DEBUG"},
		{"a typical fresh-database migration", 50 * time.Microsecond, "DEBUG"},
		{"slow, but not slow enough to notice", 999 * time.Millisecond, "DEBUG"},
		{"one second", time.Second, "INFO"},
		{"0024 on a large trail", 14 * time.Minute, "INFO"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var logBuf bytes.Buffer
			logger := slog.New(slog.NewJSONHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelDebug}))

			logMigrationApplied(logger, "0024_audit_ts_sortable.sql", c.elapsed)

			var entry struct {
				Level    string `json:"level"`
				Msg      string `json:"msg"`
				Name     string `json:"name"`
				Duration int64  `json:"duration"`
			}
			if err := json.Unmarshal(logBuf.Bytes(), &entry); err != nil {
				t.Fatalf("unmarshal %q: %v", logBuf.String(), err)
			}
			if entry.Level != c.want {
				t.Errorf("a migration taking %s logged at %s, want %s — below %s the line is noise that buries the one that matters, at or above it the operator is entitled to know which migration they are waiting on",
					c.elapsed, entry.Level, c.want, migrationSlowThreshold)
			}
			if entry.Msg != "applied schema migration" || entry.Name != "0024_audit_ts_sortable.sql" {
				t.Errorf("line = %q — both levels must carry the same message and the migration's name", logBuf.String())
			}
			if entry.Duration != int64(c.elapsed) {
				t.Errorf("duration = %d, want %d — the number is the whole point of the line", entry.Duration, int64(c.elapsed))
			}
		})
	}
}
