-- Extend audit with full-output-always (#122): the Relay persists complete
-- per-Task stdout/stderr and the daemon-side truncated flag on every dispatch
-- audit Record, not just the Task row. Additive only: pre-0006 rows keep
-- NULL stdout/stderr and truncated=0, which is a truthful default — those
-- rows predate this retention posture and never carried output.
ALTER TABLE audit ADD COLUMN stdout    BLOB;
ALTER TABLE audit ADD COLUMN stderr    BLOB;
ALTER TABLE audit ADD COLUMN truncated INTEGER NOT NULL DEFAULT 0;
