package store

import (
	"context"
	"database/sql"
	"embed"
	"errors"
	"fmt"
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

// migrate applies every embedded migration whose version is greater than the
// highest version already recorded in schema_migrations, each in its own
// transaction, recording the applied version as it goes. schema_migrations
// itself is created by 0001_init.sql; before that has run, maxVersion is 0.
func migrate(ctx context.Context, db *sql.DB) error {
	maxVersion, err := currentSchemaVersion(ctx, db)
	if err != nil {
		return err
	}

	migrations, err := loadMigrations()
	if err != nil {
		return err
	}

	for _, m := range migrations {
		if m.version <= maxVersion {
			continue
		}
		if err := applyMigration(ctx, db, m); err != nil {
			return fmt.Errorf("apply migration %s: %w", m.name, err)
		}
	}
	return nil
}

// currentSchemaVersion returns the highest version recorded in
// schema_migrations, or 0 if that table does not exist yet (a brand-new
// database, before 0001_init.sql has run).
func currentSchemaVersion(ctx context.Context, db *sql.DB) (int, error) {
	var exists int
	err := db.QueryRowContext(ctx,
		`SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'schema_migrations'`,
	).Scan(&exists)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return 0, nil
		}
		return 0, fmt.Errorf("check schema_migrations exists: %w", err)
	}

	var maxVersion int
	row := db.QueryRowContext(ctx, `SELECT COALESCE(MAX(version), 0) FROM schema_migrations`)
	if err := row.Scan(&maxVersion); err != nil {
		return 0, fmt.Errorf("read schema_migrations max version: %w", err)
	}
	return maxVersion, nil
}

// applyMigration runs one migration's SQL and records its version, in a
// single transaction. 0001_init.sql itself creates schema_migrations.
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

	if _, err := tx.ExecContext(ctx,
		`INSERT INTO schema_migrations (version, applied_at) VALUES (?, ?)`,
		m.version, time.Now().UTC().Format(timeLayout),
	); err != nil {
		return fmt.Errorf("record migration version: %w", err)
	}

	return tx.Commit()
}

// splitStatements splits a migration file's SQL text into individual
// statements on ";" so each can be executed separately. Migration files must
// not use ";" inside string literals or comments in a way that would defeat
// this — a reasonable constraint for hand-written schema migrations.
func splitStatements(sqlText string) []string {
	parts := strings.Split(sqlText, ";")
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
