-- #415 (D10): the shape key on the approval record.
--
-- shape_key content-addresses WHAT an approval is for rather than how much of
-- it: the Action, its risk class, its shape arguments, and the normalised
-- Selector, deliberately WITHOUT the resolved fan-out (approval.HashPlanShape).
-- It exists so the approval object can find "the last approved action of the
-- same shape" as a lookup rather than a scan.
--
-- It is a GROUPING key and never a release lookup. Only plan_hash releases a
-- dispatch, and that separation is enforced in code, not here.
--
-- The DEFAULT '' means "written before #415". It is impossible for a new row:
-- the key is computed in approval.NewRequest, which every writer goes through.
--
-- The VALUES are filled by the Go backfill in store/shapekeys.go, not by this
-- file, for two reasons. First, the ordering between recomputing a grant
-- request's key and stamping everything else as legacy matters, and a DEFAULT
-- fill here would consume the grant rows before they could be recomputed.
-- Second, computing a SHA-256 in SQL would be a SECOND IMPLEMENTATION OF THE
-- SAME HASH -- the one failure mode that would make "recomputing a key yields
-- the same key" false.
--
-- There is deliberately NO shape_key column on approval_grants: every input to
-- a Grant's key is already a scope_* column there, so Grant.ShapeKey() derives
-- it and it can never go stale against the Scope it describes.
--
-- NOTE: keep semicolons out of these comments. splitStatements
-- (store/migrate.go) strips whole-line comments before splitting, but a
-- semicolon in a trailing same-line comment still splits the file.

ALTER TABLE approval_requests ADD COLUMN shape_key TEXT NOT NULL DEFAULT '';

-- The anti-fatigue read: newest APPROVED record with this key. state and
-- resolved_at are in the index because the query filters on the first and
-- orders by the second.
CREATE INDEX idx_approval_requests_shape ON approval_requests (shape_key, state, resolved_at);
