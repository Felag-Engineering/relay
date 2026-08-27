-- #441: index the trail and Jobs/Tasks for the capability layer's read lane.
--
-- Index-only. No column is added, no row is backfilled, and no write path
-- changes -- this migration exists purely so the new filtered/paginated
-- queries (internal/store/auditquery.go, internal/store/jobquery.go) do not
-- run as full scans against an append-only table that only grows.
--
-- idx_audit_account_id (migration 0010) is DROPPED: idx_audit_account_ts below
-- is a strict prefix superset of it (account_id, ...) and answers every query
-- the old index did plus the new ORDER BY ts DESC pagination. Keeping both
-- would cost write amplification on every appended row for an index nothing
-- reads through anymore -- the same write-amplification reasoning 0010's own
-- comment used to justify going partial in the first place, which is also why
-- the replacement below stays partial rather than reintroducing that cost.
--
-- idx_audit_account_ts and idx_audit_node_ts are PARTIAL (WHERE ... IS NOT
-- NULL), matching 0010's convention: the large majority of rows carry no
-- account_id or no node_id (a Plan, a Freeze event, a refusal before
-- attribution existed), and indexing those NULLs would grow the index without
-- ever being read through -- nothing queries "account_id IS NULL" by walking
-- this index.
--
-- idx_audit_job_ts is new: no job_id index exists today, so ByJob and the Job
-- list's audit-attribution join (jobquery.go) are both full scans.
--
-- idx_jobs_created_at and idx_tasks_job_outcome serve QueryJobs' ORDER BY
-- created_at DESC and QueryTasks' WHERE job_id = ? AND outcome = ? .
--
-- NOTE: keep semicolons out of these comments. splitStatements
-- (store/migrate.go) splits the file on that character without stripping
-- comments first, so one inside a comment is executed as SQL.

DROP INDEX IF EXISTS idx_audit_account_id;

CREATE INDEX idx_audit_ts ON audit (ts, audit_id);

CREATE INDEX idx_audit_kind_ts ON audit (kind, ts, audit_id);

CREATE INDEX idx_audit_account_ts ON audit (account_id, ts, audit_id) WHERE account_id IS NOT NULL;

CREATE INDEX idx_audit_node_ts ON audit (node_id, ts, audit_id) WHERE node_id IS NOT NULL;

CREATE INDEX idx_audit_job_ts ON audit (job_id, ts);

CREATE INDEX idx_jobs_created_at ON jobs (created_at, job_id);

CREATE INDEX idx_tasks_job_outcome ON tasks (job_id, outcome, task_id);
