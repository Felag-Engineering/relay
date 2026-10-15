package store

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"
	"time"

	"github.com/Felag-Engineering/relay/relay/internal/jobs"
)

// TestMigration0026_LegacyJobsReadBackWithNoRequester (#616, AC3) drives the
// real upgrade path: a database seeded at schema 0025 — the highest version
// before this change — holds a Job written the OLD way, with no requester
// column at all and its attribution living only in an audit dispatch row.
// Reopening it through today's Open applies migration 0026 and must NOT
// backfill that Job's requester from the audit row it already has: NULL
// means "no requester recorded", never "unknown, go look in audit".
func TestMigration0026_LegacyJobsReadBackWithNoRequester(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "schema25.db")

	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	db.SetMaxOpenConns(1)
	// seedMigrations skips exactly migration 26 by version number rather than
	// stopping after 25: if a later migration is ever added, this line would
	// still need updating to name it, or this seed would apply a migration
	// past 0026 without 0026 itself.
	seedMigrations(t, db, 26)

	at := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	createdAt := formatTime(at)
	auditTS := formatAuditTime(at)
	if _, err := db.ExecContext(ctx,
		`INSERT INTO jobs (job_id, created_at) VALUES (?, ?)`, "job-legacy", createdAt); err != nil {
		t.Fatalf("insert legacy job: %v", err)
	}
	if _, err := db.ExecContext(ctx,
		`INSERT INTO stages (stage_id, job_id, stage_index) VALUES (?, ?, 0)`, "job-legacy-stage", "job-legacy"); err != nil {
		t.Fatalf("insert legacy stage: %v", err)
	}
	if _, err := db.ExecContext(ctx, `
		INSERT INTO tasks (task_id, job_id, stage_id, node_id, action_kind, operation_name, risk_class, state, outcome, created_at, dispatched_at, resolved_at)
		VALUES (?, ?, ?, ?, 'operation', 'system.facts', 'read', 'resolved', ?, ?, ?, ?)`,
		"job-legacy-t1", "job-legacy", "job-legacy-stage", "node-1", int(jobs.OutcomeSuccess), createdAt, createdAt, createdAt,
	); err != nil {
		t.Fatalf("insert legacy task: %v", err)
	}
	if _, err := db.ExecContext(ctx, `
		INSERT INTO audit (audit_id, ts, principal, selector, job_id, action_kind, operation_name, outcome, kind, account_id, account_name)
		VALUES (?, ?, 'legacy-machine:operator', 'relay:env=prod', ?, 'operation', 'system.facts', ?, 'dispatch', ?, ?)`,
		"audit-legacy", auditTS, "job-legacy", int(jobs.OutcomeSuccess), "acct-legacy", "legacy-machine",
	); err != nil {
		t.Fatalf("insert legacy audit row: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("close seed db: %v", err)
	}

	st, err := Open(path)
	if err != nil {
		t.Fatalf("Open on a schema-0025 database: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	// QueryJobs returns an empty Requester/RequesterAccountID/RequesterKind,
	// even though the audit trail names "acct-legacy" — never inferred.
	page, err := st.JobQueries().QueryJobs(ctx, jobs.JobQuery{JobID: "job-legacy"}, 0, "")
	if err != nil {
		t.Fatalf("QueryJobs: %v", err)
	}
	if len(page.Jobs) != 1 {
		t.Fatalf("QueryJobs = %+v, want exactly one row", page.Jobs)
	}
	got := page.Jobs[0]
	if got.Requester != "" || got.RequesterAccountID != "" || got.RequesterKind != "" {
		t.Errorf("legacy job requester = %+v, want all empty (no backfill from the audit trail)", got)
	}
	// Selector still comes from the audit trail, unaffected by 0026.
	if got.Selector != "relay:env=prod" {
		t.Errorf("legacy job Selector = %q, want relay:env=prod (audit-joined, unaffected by 0026)", got.Selector)
	}

	// GetJob returns a zero Requester.
	job, err := st.Jobs().GetJob(ctx, "job-legacy")
	if err != nil {
		t.Fatalf("GetJob: %v", err)
	}
	if job.Requester != (jobs.Requester{}) {
		t.Errorf("GetJob(job-legacy).Requester = %+v, want the zero value", job.Requester)
	}

	// A RequesterAccountID filter for the audit row's account returns
	// nothing: the audit trail's attribution must never leak into the
	// requester filter for a Job that recorded none.
	filtered, err := st.JobQueries().QueryJobs(ctx, jobs.JobQuery{RequesterAccountID: "acct-legacy"}, 0, "")
	if err != nil {
		t.Fatalf("QueryJobs(RequesterAccountID): %v", err)
	}
	if len(filtered.Jobs) != 0 {
		t.Errorf("QueryJobs(RequesterAccountID=acct-legacy) = %+v, want none", filtered.Jobs)
	}

	// The partial index migration 0026 adds exists.
	var name string
	err = st.db.QueryRowContext(ctx,
		`SELECT name FROM sqlite_master WHERE type = 'index' AND name = 'idx_jobs_requester_created_at'`,
	).Scan(&name)
	if err != nil {
		t.Fatalf("idx_jobs_requester_created_at (created by migration 26) not found: %v", err)
	}
}
