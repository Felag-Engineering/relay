-- Extend audit with Kind (dispatch | refusal | freeze_engage | freeze_release),
-- NodeID (per-Node "which Node" accountability, ADR-0004), and Reason (why a
-- refusal/freeze happened). Additive only: existing rows are pre-release data
-- and get a well-formed default Kind.
ALTER TABLE audit ADD COLUMN kind    TEXT NOT NULL DEFAULT 'dispatch';
ALTER TABLE audit ADD COLUMN node_id TEXT;
ALTER TABLE audit ADD COLUMN reason  TEXT;
