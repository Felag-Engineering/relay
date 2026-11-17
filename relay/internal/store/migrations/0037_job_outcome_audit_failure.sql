-- A Job whose outcome audit write failed after its Tasks ran records when, on its own
-- row (execution.md, EX-66). It is written once, by the Job engine; the store's error
-- text is never stored.
--
-- NO BACKFILL. NULL means no failure is recorded, which covers every pre-existing row.
ALTER TABLE jobs ADD COLUMN outcome_audit_failed_at TEXT;
