package store

import (
	"context"
	"database/sql"
	"embed"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"strconv"
	"strings"
	"time"
)

//go:embed migrations/*.sql
var migrationFiles embed.FS

// migration is one embedded migration file, parsed for its version number.
type migration struct {
	version int
	name    string
	sql     string
}

// loadMigrations reads every embedded migration file, parses its version from
// the numeric filename prefix (e.g. "0001_init.sql" -> 1), and returns them
// sorted by version.
func loadMigrations() ([]migration, error) {
	entries, err := migrationFiles.ReadDir("migrations")
	if err != nil {
		return nil, fmt.Errorf("read embedded migrations: %w", err)
	}

	migrations := make([]migration, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		prefix, _, ok := strings.Cut(e.Name(), "_")
		if !ok {
			return nil, fmt.Errorf("migration file %q missing version prefix", e.Name())
		}
		version, err := strconv.Atoi(prefix)
		if err != nil {
			return nil, fmt.Errorf("migration file %q has non-numeric version prefix: %w", e.Name(), err)
		}
		contents, err := migrationFiles.ReadFile("migrations/" + e.Name())
		if err != nil {
			return nil, fmt.Errorf("read migration file %q: %w", e.Name(), err)
		}
		migrations = append(migrations, migration{version: version, name: e.Name(), sql: string(contents)})
	}

	sort.Slice(migrations, func(i, j int) bool {
		return migrations[i].version < migrations[j].version
	})
	return migrations, nil
}

// migrationSlowThreshold is the duration past which a single migration is
// logged at Info rather than Debug. One second: below it an operator would not
// notice the pause anyway, and above it they are entitled to know which
// migration they are waiting on.
const migrationSlowThreshold = time.Second

// migrate applies every embedded migration whose version is ABSENT from
// schema_migrations, each in its own transaction, recording the applied
// version as it goes. This is selection by per-version presence, not by
// comparison against the highest version recorded: a version that is
// missing gets applied regardless of how many higher versions already are.
// schema_migrations itself is created by 0001_init.sql, so before
// that has run the applied set is simply empty.
//
// One consequence of presence-based selection: repairing a database that
// already skipped a lower-numbered migration runs that migration AFTER the
// higher-numbered ones that are already applied. That is inherent to
// repairing an existing database, not a bug — the alternative is the
// permanent silent skip this change replaces.
//
// Another: schema_migrations can hold a version with no corresponding
// embedded file — a database that is newer than this binary (for example
// after a binary rollback, since migrations here are forward-only). That is
// logged once, at Warn, to logger — the caller's seam so a test can assert
// it actually fired — and tolerated rather than treated as fatal: refusing
// to start would leave an operator who just rolled back a bad deploy with no
// in-band remedy, and there is no down-migration mechanism to undo a
// refusal. See pendingMigrations' unknown return value.
func migrate(ctx context.Context, db *sql.DB, logger *slog.Logger) error {
	applied, err := appliedVersions(ctx, db)
	if err != nil {
		return err
	}

	migrations, err := loadMigrations()
	if err != nil {
		return err
	}

	pending, unknown := pendingMigrations(migrations, applied)
	if len(unknown) > 0 {
		logger.Warn("database schema is newer than this relay binary",
			"unknown_versions", unknown,
			"count", len(unknown),
		)
	}

	// Timed because 0024 is the first migration whose cost is proportional to
	// the size of a table rather than to the schema — it rewrites every audit
	// row, at roughly 16 seconds per GB — so a boot can take minutes, and the
	// operator is owed the reason. 0028 is the
	// second: it chains every existing audit row.
	//
	// Info only past migrationSlowThreshold, Debug otherwise. A fresh database
	// applies two dozen migrations in microseconds each; logging all of them at
	// Info buries the one line that matters under the ones that never do. The
	// threshold is what makes a slow migration self-announcing rather than
	// something to go looking for.
	//
	// Said plainly because the line cannot do more than this: it reports a
	// migration's cost AFTER that migration returns. It is not a progress
	// signal — an operator watching a boot still inside a 14-minute 0024 sees
	// nothing from here until it finishes.
	for _, m := range pending {
		start := time.Now()
		if err := applyMigration(ctx, db, m); err != nil {
			return fmt.Errorf("apply migration %s: %w", m.name, err)
		}
		logMigrationApplied(logger, m.name, time.Since(start))
	}
	return nil
}

// logMigrationApplied records that one migration finished: at Info if it took
// at least migrationSlowThreshold, at Debug otherwise.
//
// A function rather than two lines inline so the choice of level is directly
// testable — TestLogMigrationApplied_InfoOnlyPastTheSlowThreshold pins both
// branches without spending a second of test time to reach the slow one.
func logMigrationApplied(logger *slog.Logger, name string, elapsed time.Duration) {
	if elapsed >= migrationSlowThreshold {
		logger.Info("applied schema migration", "name", name, "duration", elapsed)
		return
	}
	logger.Debug("applied schema migration", "name", name, "duration", elapsed)
}

// schemaMigrationsExists reports whether the schema_migrations table has
// been created yet. False, nil means a brand-new database — before
// 0001_init.sql has run, which is what creates that table.
func schemaMigrationsExists(ctx context.Context, db *sql.DB) (bool, error) {
	var exists int
	err := db.QueryRowContext(ctx,
		`SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'schema_migrations'`,
	).Scan(&exists)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return false, nil
		}
		return false, fmt.Errorf("check schema_migrations exists: %w", err)
	}
	return true, nil
}

// appliedVersions returns every version recorded in schema_migrations. On a
// brand-new database (schema_migrations not yet created) it returns a
// non-nil empty map and a nil error, rather than an error — the fresh-database
// case is not a failure, and pendingMigrations relies on this being a total
// function with no special case for "no table yet".
//
// CRITICAL: this must fully scan and close its *sql.Rows before returning.
// Open (store.go) sets db.SetMaxOpenConns(1), so a single connection serves
// the whole Store; a Rows left open here would still be holding that one
// connection when applyMigration's BeginTx tries to acquire it. migrate is
// called with context.Background() (store.go), which has no deadline, and
// PRAGMA busy_timeout only bounds SQLite's own lock contention — it does not
// bound database/sql's pool wait. Getting the ordering wrong here hangs
// Relay startup FOREVER, not for a few seconds.
func appliedVersions(ctx context.Context, db *sql.DB) (map[int]struct{}, error) {
	exists, err := schemaMigrationsExists(ctx, db)
	if err != nil {
		return nil, err
	}
	if !exists {
		return map[int]struct{}{}, nil
	}

	rows, err := db.QueryContext(ctx, `SELECT version FROM schema_migrations`)
	if err != nil {
		return nil, fmt.Errorf("read schema_migrations versions: %w", err)
	}
	defer rows.Close()

	applied := map[int]struct{}{}
	for rows.Next() {
		var version int
		if err := rows.Scan(&version); err != nil {
			return nil, fmt.Errorf("scan schema_migrations version: %w", err)
		}
		applied[version] = struct{}{}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate schema_migrations versions: %w", err)
	}
	return applied, nil
}

// pendingMigrations splits migrations (already in ascending version order,
// per loadMigrations) against applied: pending is every migration whose
// version is absent from applied, in that same ascending order; unknown is
// every applied version with no corresponding embedded migration, sorted
// ascending. A pure function — no ctx, no db — so the skipped-migration
// scenario (embedded 1, 2, 22, 23 with applied {1, 2, 23}, expecting pending
// [22]) is testable without a real database or an embedded file that does
// not exist in this repo.
func pendingMigrations(migrations []migration, applied map[int]struct{}) (pending []migration, unknown []int) {
	embedded := make(map[int]struct{}, len(migrations))
	for _, m := range migrations {
		embedded[m.version] = struct{}{}
		if _, ok := applied[m.version]; !ok {
			pending = append(pending, m)
		}
	}

	for v := range applied {
		if _, ok := embedded[v]; !ok {
			unknown = append(unknown, v)
		}
	}
	sort.Ints(unknown)

	return pending, unknown
}

// migrationGoSteps holds the migrations that need Go after their SQL: work SQL
// cannot do (SHA-256) or splitStatements cannot split (a trigger body). A step
// runs inside the migration's transaction, after the SQL statements and before
// the version is recorded, so it commits or rolls back with them.
var migrationGoSteps = map[int]func(context.Context, *sql.Tx) error{
	28: chainAuditTrail,
}

// applyMigration runs one migration's SQL and its Go step, if any, and records
// its version, in a single transaction. 0001_init.sql itself creates
// schema_migrations.
func applyMigration(ctx context.Context, db *sql.DB, m migration) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck

	for _, stmt := range splitStatements(m.sql) {
		if _, err := tx.ExecContext(ctx, stmt); err != nil {
			return fmt.Errorf("exec statement: %w", err)
		}
	}

	if step, ok := migrationGoSteps[m.version]; ok {
		if err := step(ctx, tx); err != nil {
			return fmt.Errorf("go step: %w", err)
		}
	}

	if _, err := tx.ExecContext(ctx,
		`INSERT INTO schema_migrations (version, applied_at) VALUES (?, ?)`,
		m.version, time.Now().UTC().Format(timeLayout),
	); err != nil {
		return fmt.Errorf("record migration version: %w", err)
	}

	return tx.Commit()
}

// splitStatements splits a migration file's SQL text into individual
// statements on ";" so each can be executed separately.
//
// Whole-line "--" comments are stripped BEFORE the split. Without that, a
// semicolon inside a comment splits the file mid-sentence and the remaining
// prose is handed to SQLite as a statement — which fails the migration with a
// syntax error pointing at an English word, and takes a while to recognise for
// what it is. Migration comments are where the reasoning for a schema change
// lives, so they are exactly the place ordinary punctuation appears.
//
// Remaining constraint, unchanged: a ";" inside a string literal, or inside a
// trailing comment on the same line as SQL, still splits. Stripping those would
// need a real tokenizer to tell a literal from a comment, and hand-written
// schema migrations have no need of either.
func splitStatements(sqlText string) []string {
	parts := strings.Split(stripLineComments(sqlText), ";")
	stmts := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		stmts = append(stmts, p)
	}
	return stmts
}

// stripLineComments removes lines whose first non-whitespace characters are
// "--", leaving every other line byte-for-byte intact.
//
// Deliberately only whole-line comments: a trailing "-- note" after SQL on the
// same line is left alone, because distinguishing it from a "--" inside a
// string literal needs a tokenizer, and guessing wrong would silently corrupt a
// statement. Dropping a line that is unambiguously a comment cannot.
func stripLineComments(sqlText string) string {
	lines := strings.Split(sqlText, "\n")
	kept := lines[:0]
	for _, line := range lines {
		if strings.HasPrefix(strings.TrimSpace(line), "--") {
			continue
		}
		kept = append(kept, line)
	}
	return strings.Join(kept, "\n")
}
