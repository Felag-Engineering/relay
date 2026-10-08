-- #896: make the audit trail tamper-evident. Every row gets seq, prev_hash and
-- hash, and the table refuses UPDATE and DELETE.
--
-- The columns and the unique index are plain SQL below. Everything else is the
-- Go step migrationGoSteps[28] (store/auditchain.go), which runs in THIS
-- transaction after these statements. It is Go because SQLite cannot compute
-- SHA-256 and because splitStatements cannot split a trigger body that
-- contains semicolons. In order, the step:
--
--   1. Re-runs 0024's timestamp conversion, so any row a rolled-back binary
--      left in the old trimmed spelling is canonical before the table becomes
--      unrewritable. The hash is over the decoded instant, so this changes no
--      hash.
--   2. Chains every existing row in insertion (rowid) order, from seq 1.
--   3. Creates the two triggers that refuse UPDATE and DELETE.
--
-- Triggers never block INSERT. A Relay binary older than this change keeps
-- writing rows with no chain position, so blocking INSERT would stop it
-- dispatching. relay-audit-verify reports such rows instead.
--
-- COST, IN 0024'S CLASS. The back-fill rewrites every audit row, so the upgrade
-- boot scales with the size of the table and needs free disk of roughly 100
-- percent of the database size for the -wal, because the whole migration is one
-- transaction. Running out of disk rolls back and the Relay refuses to start
-- with the trail untouched. Free space and restart.
--
-- 0024 ADVISED RUNNING ITS UPDATE VERBATIM TO REPAIR ROWS A ROLLED-BACK BINARY
-- WROTE. That no longer works, because audit now refuses UPDATE. Step 1 above
-- is the last chance to convert, and it runs for every row that exists when
-- this migration does. A row written afterwards by an older binary cannot be
-- rewritten in place.
--
-- THE #492 EDGE: a database that has 28 applied but is missing 24 would hit
-- the trigger when 0024's UPDATE runs, and Open fails loudly. That state needs
-- an operator to look at it, not a silent bypass.
--
-- NOTE: keep semicolons out of these comments. See 0024's note.

ALTER TABLE audit ADD COLUMN seq INTEGER;

ALTER TABLE audit ADD COLUMN prev_hash TEXT;

ALTER TABLE audit ADD COLUMN hash TEXT;

CREATE UNIQUE INDEX idx_audit_seq ON audit (seq);
