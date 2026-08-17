-- #378 (ADR-0027): join a dispatch to the approval that authorized it.
--
-- Until now the approval callout reached the trail only through `reason` prose
-- on the park and decision rows. That is enough to READ, and not enough to
-- QUERY -- and the acceptance criterion for batch/window grants is exactly a
-- query: "every covered Job auditing to the same approval ID". A grant covers
-- many dispatches, so "what did that window actually release" is a question
-- somebody will ask under time pressure, and it must be a WHERE clause rather
-- than a grep over free text.
--
-- Two columns, because they answer different questions:
--
--   approval_id -- the approval Request that authorized this record. Set on a
--                  park, on a decision, and on every dispatch released by
--                  either a single approval or a grant. For a grant this is the
--                  grant's OWN authorizing Request, which is what makes every
--                  covered Job share one approval ID.
--
--   grant_id    -- set only when a batch/window Grant released the dispatch. Its
--                  presence is the distinction between "a human approved THIS
--                  plan" and "a human approved a window this plan fell inside",
--                  which an auditor needs and cannot recover from approval_id
--                  alone.
--
-- Both are NULL for every row written before this migration and for every
-- record with no approval in its history -- the overwhelming majority. NULL
-- here means "no approval was involved", never "unknown".
--
-- Deliberately not foreign keys, on the same reasoning as approval_grants:
-- cross-table constraints would make a retention policy or a partial restore
-- fail in surprising ways, and the audit trail is the one table that must
-- outlive everything it references.
--
-- NOTE: keep semicolons out of these comments. splitStatements
-- (store/migrate.go) splits the file on that character without stripping
-- comments first, so one inside a comment is executed as SQL.

ALTER TABLE audit ADD COLUMN approval_id TEXT;
ALTER TABLE audit ADD COLUMN grant_id TEXT;

-- "Which Jobs did this grant release" and "what happened under this approval"
-- are both point lookups on a highly selective value.
CREATE INDEX idx_audit_approval ON audit (approval_id);
CREATE INDEX idx_audit_grant ON audit (grant_id);
