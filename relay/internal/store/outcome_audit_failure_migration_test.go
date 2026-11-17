package store

import (
	"context"
	"database/sql"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestMigration0037_PreExistingJobsReadNoOutcomeAuditFailure drives the real
// upgrade path: a Job written before migration 37 has no outcome_audit_failed_at
// and reads as having no recorded failure (no backfill).
func TestMigration0037_PreExistingJobsReadNoOutcomeAuditFailure(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "schema36.db")

	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	db.SetMaxOpenConns(1)
	seedMigrations(t, db, 37)
	if name := migrationByVersion(t, 37).name; !strings.Contains(name, "outcome_audit_failure") {
		t.Fatalf("migration 37 is %q, want the outcome audit failure migration", name)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO jobs (job_id, created_at) VALUES ('job-old', ?)`,
		formatTime(time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC))); err != nil {
		t.Fatalf("insert job: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("close seed db: %v", err)
	}

	st, err := Open(path)
	if err != nil {
		t.Fatalf("Open on a pre-0037 database: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	job, err := st.Jobs().GetJob(ctx, "job-old")
	if err != nil {
		t.Fatalf("GetJob: %v", err)
	}
	if !job.OutcomeAuditFailedAt.IsZero() {
		t.Errorf("OutcomeAuditFailedAt = %v, want zero for a pre-existing Job", job.OutcomeAuditFailedAt)
	}
}
