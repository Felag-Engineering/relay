-- #656: audit_shape_alert remembers that the audit table was observed holding
-- pre-0024 timestamps, so the warning about it outlives the window that
-- observed it.
--
-- WHAT IT IS FOR. store/auditshape.go detects the binary-rollback case -- an
-- older Relay writing trimmed ts values into a table 0024 already converted --
-- by reading the most recently inserted rows at every Open. That window is
-- what makes the check cost a fifth of a millisecond rather than a scan of the
-- trail. But a window scrolls: once ordinary traffic appends a hundred
-- canonical rows the newest rows are all canonical and the detector goes
-- silent, while the mixed rows stay forever, because roll-forward does not
-- self-heal -- 24 is already recorded in schema_migrations and migrate selects
-- by presence. A mixed table silently DROPS ROWS from a paged read, so a
-- detector that can go permanently silent about it is the wrong residual for
-- the artifact incidents are reconstructed from.
--
-- WHY NOT ASK THE TABLE ITSELF ON EVERY BOOT. The exact question --
-- SELECT EXISTS(SELECT 1 FROM audit WHERE ts NOT GLOB '<canonical>') -- has no
-- usable index term, because nonconforming values are interleaved with
-- canonical ones rather than forming a range. So on a CLEAN table, which is
-- every healthy database, it must scan the whole index before it can answer
-- "none". Measured on pure-Go SQLite in WAL mode with one connection, three
-- runs each: 0.62 s at 1 million rows, 6.4 s at 10 million, against 0.2 ms for
-- the windowed read at both sizes. That is boot latency every Relay would pay
-- forever, growing with the trail, to answer a question that is "no" on every
-- healthy database.
--
-- So the cheap window OBSERVES, this table REMEMBERS, and the exact scan runs
-- only on a database already known to have been mixed -- where it is also what
-- decides the alert may be cleared, which is what keeps the warning from
-- crying wolf after an operator has run the repair.
--
-- Single-row, exactly like freeze (0003): id is always 1, and no row is
-- seeded, so "no row" means "never observed" and a fresh database needs no
-- seed value. The sample columns hold the audit_id and the STORED ts bytes of
-- one offending row, captured at the moment of observation -- by the time an
-- operator reads a later boot's warning that row may be far outside the
-- window, and a warning with nothing to look at is a warning nobody can act
-- on.
CREATE TABLE audit_shape_alert (
    id              INTEGER PRIMARY KEY CHECK (id = 1),
    observed_at     TIMESTAMP NOT NULL,
    sample_audit_id TEXT NOT NULL,
    sample_ts       TEXT NOT NULL
);
