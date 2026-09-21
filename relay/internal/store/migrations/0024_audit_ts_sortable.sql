-- #656: give the audit trail one total order that matches the order things
-- happened.
--
-- ts is a TEXT column and ORDER BY on TEXT is a byte comparison, but every
-- row until now was written in RFC3339Nano, which TRIMS trailing zeros in the
-- fractional part. So a whole-second row sorts AFTER the .5 row in the same
-- second, and ".15" sorts after ".1" -- a systematic inversion, not a rare
-- one. This migration rewrites every ts into the fixed-width rendering
-- (store/audittime.go's auditTimeLayout, always 30 characters, always UTC Z,
-- always nine fractional digits), under which the byte order IS the
-- chronological order -- including for an operator running
-- sqlite3 relay.db "SELECT ... ORDER BY ts" during an incident, which is how
-- this table is actually read under pressure.
--
-- The five indexes are dropped and recreated around the UPDATE, each with
-- EXACTLY the definition 0021 gave it -- pinned by
-- TestAuditIndexDefinitions_0021MatchesMigration0024, because since #656 0021
-- creates them with IF NOT EXISTS, and a drifted definition there would be
-- silently skipped on #492's repair path rather than failing. Rebuilding a
-- whole index is far cheaper than maintaining it row by row through a full
-- table rewrite.
--
-- WHICH READERS THE NEW ORDER BY ts, audit_id COSTS NOTHING, read off
-- EXPLAIN QUERY PLAN rather than assumed:
--
--   List        SCAN audit USING INDEX idx_audit_ts
--   read lane   SCAN audit USING INDEX idx_audit_ts           (the DESC mirror)
--   ByNode      SEARCH audit USING INDEX idx_audit_node_ts (node_id=?)
--   ByAccount   SEARCH audit USING INDEX idx_audit_account_ts (account_id=?)
--
-- Those indexes carry (key, ts, audit_id), so the order comes out of the
-- index with no sorting step at all. The other three readers each sort, and
-- each for a different reason -- both stated below, because "it has an index"
-- and "its ORDER BY is satisfied" are not the same claim.
--
-- idx_audit_job_ts DELIBERATELY STAYS (job_id, ts), two columns, and is NOT
-- widened to carry audit_id. ByJob therefore plans as SEARCH audit USING
-- INDEX idx_audit_job_ts (job_id=?) plus USE TEMP B-TREE FOR LAST TERM OF
-- ORDER BY -- the index orders ts and only the audit_id tie-break is sorted.
-- Widening it was tried and measured, and it makes things worse where it
-- matters most: with three columns SQLite stops choosing it for
-- jobquery.go's per-Job audit aggregate and switches to
-- idx_audit_kind_ts (kind=?) instead, which materialises an aggregate over
-- EVERY dispatch row ever written on every Job-detail page view. That is the
-- exact unboundedness TestJobQuery_SingleJobDoesNotScanEveryTask exists to
-- forbid, and it caught the change. The price of keeping it narrow is that
-- ByJob sorts the tie-break in a temp B-tree -- over one Job's audit rows,
-- which the blast cap bounds, against a scan that grows with the whole trail.
-- Not a close call. The planner picks the narrower index only because it is
-- narrower, so this is recorded here rather than left to be rediscovered.
--
-- ByApproval/ByGrant/ByOnBehalfOf DO each have an index -- idx_audit_approval
-- and idx_audit_grant from 0015, idx_audit_asserted_on_behalf_of from 0010 --
-- and the planner SEARCHes all three. What they pay is USE TEMP B-TREE FOR
-- ORDER BY, the WHOLE order rather than just its last term, because those
-- indexes are single-column: they constrain the key and carry neither ts nor
-- audit_id. Deliberately left that way. The decision is about WIDENING three
-- existing indexes to (key, ts, audit_id), not about creating three missing
-- ones, and widening them is write amplification on every appended row for
-- queries nobody has complained about -- with the idx_audit_job_ts result
-- above standing as the warning that a wider index also changes which index
-- the planner picks somewhere else.
--
-- THE SKIP GATE IS THE POSITIVE SHAPE. The first WHERE clause is "not already
-- canonical", spelled as the exact 30-character GLOB rather than
-- length(ts) <> 30 -- "2026-01-01T00:00:01.1234+05:30" is also exactly 30
-- characters. GLOB is a whole-string match in SQLite and "." is a literal in
-- GLOB syntax, so the pattern matches exactly the canonical form. It is the
-- same pattern store/auditshape.go's auditTSCanonicalGlob holds and
-- TestAudit_StoredTimestampIsFixedWidth asserts of the writer, so the writer
-- and this migration cannot disagree about what "already converted" means.
--
-- The second WHERE clause is the shape gate. It matches exactly what the
-- writer could ever have produced (a UTC RFC3339 value with or without a
-- fraction), so a value this code could never have written is LEFT ALONE
-- rather than mangled by substr arithmetic on a negative length. Measured
-- against Go's own Format over 2015 values: four disagreements, all four of
-- them skips under this gate, zero corruptions.
--
-- Re-running this file is a no-op: after conversion every row matches the
-- canonical GLOB and the UPDATE matches nothing. An operator whose binary was
-- rolled back to a pre-#656 Relay, and so re-introduced trimmed rows, can run
-- the UPDATE below verbatim to repair them. They need telling, because
-- roll-forward does NOT self-heal -- this version is already recorded in
-- schema_migrations and migrate selects by presence, so it never runs again.
-- store/auditshape.go is what tells them: it sees such rows at Open, logs
-- this statement with the warning, and remembers in audit_shape_alert (0025)
-- so the warning outlives the window that saw them.
--
-- COST, MEASURED, BECAUSE AN OPERATOR PAYS IT ON THE UPGRADE BOOT.
--
-- (a) It scales with stored BYTES, not rows. The UPDATE rewrites each whole
-- record including the retained stdout/stderr blobs, and the sink retains
-- both streams for every non-read Operation with a 1 MiB per-stream daemon
-- cap, so a mutate-heavy trail is the expensive case. Measured on pure-Go
-- SQLite in WAL mode with one connection, 100 000 rows and all five indexes:
-- 61 MB / no blobs took 2.88 s, 124 MB / 512 B per row took 1.97 s with the
-- drop-and-recreate above, and 503 MB / 4 KB per row took 4.20 s. As a rule
-- an operator can apply to their own file: roughly 16 SECONDS PER GB of audit
-- table, with a floor of roughly 20 seconds per million rows, whichever is
-- larger. At 10 million rows of 4 KB that is a roughly 49 GB table and
-- ROUGHLY 14 MINUTES -- not the 3.5 minutes a row-only estimate suggests.
-- Paid once, before store.Open returns, with no listener up yet.
--
-- (b) It needs FREE DISK OF ROUGHLY 100 PERCENT OF THE DATABASE SIZE.
-- applyMigration wraps the whole file in one transaction, so the rewrite
-- lives in the -wal, which cannot checkpoint past an open write transaction.
-- Peak -wal measured at roughly 100 percent of the database in all three
-- shapes above. At 10 million times 4 KB that is a roughly 49 GB -wal at
-- boot. THIS IS THE SAME FREE-SPACE REQUIREMENT VACUUM WAS REJECTED FOR --
-- the single-transaction approach did not avoid that cost, it accepted it in
-- exchange for the audit table never being observably half-converted. VACUUM
-- stays rejected on the two grounds that actually separate it: it cannot run
-- inside this transaction, so it could not be atomic with the rewrite, and it
-- buys nothing the ordering fix needs.
--
-- (c) Running out of disk is SAFE AND LOUD. SQLITE_FULL rolls the transaction
-- back, applyMigration returns an error, migrate returns, store.Open returns
-- an error, and THE RELAY REFUSES TO START -- with the trail intact,
-- un-migrated, and this version never recorded in schema_migrations. Free the
-- space, restart, and it retries cleanly. A refusing Relay is a visible,
-- recoverable failure. A half-converted audit trail would not be.
--
-- NOTE: keep semicolons out of these comments. See 0023's corrected note --
-- splitStatements strips whole-line comments first, but a semicolon in a
-- trailing comment on a line that also carries SQL still splits a statement
-- in half, and the failure surfaces as a syntax error pointing at an English
-- word.

DROP INDEX IF EXISTS idx_audit_ts;

DROP INDEX IF EXISTS idx_audit_kind_ts;

DROP INDEX IF EXISTS idx_audit_account_ts;

DROP INDEX IF EXISTS idx_audit_node_ts;

DROP INDEX IF EXISTS idx_audit_job_ts;

UPDATE audit
SET ts = substr(ts, 1, 19) || '.' ||
         substr(CASE WHEN substr(ts, 20, 1) = '.'
                     THEN substr(ts, 21, length(ts) - 21)
                     ELSE '' END || '000000000', 1, 9) || 'Z'
WHERE ts NOT GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9]Z'
  AND ts GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9]*Z';

CREATE INDEX idx_audit_ts ON audit (ts, audit_id);

CREATE INDEX idx_audit_kind_ts ON audit (kind, ts, audit_id);

CREATE INDEX idx_audit_account_ts ON audit (account_id, ts, audit_id) WHERE account_id IS NOT NULL;

CREATE INDEX idx_audit_node_ts ON audit (node_id, ts, audit_id) WHERE node_id IS NOT NULL;

CREATE INDEX idx_audit_job_ts ON audit (job_id, ts);
