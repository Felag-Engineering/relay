-- #270 (ADR-0027): the structured facts a decision surface needs.
--
-- 0012 stored what the approver READS (plan_summary, a rendered line). Deciding
-- also needs what the approver is being asked to RELEASE, structurally:
--
--   * action_kind drives the role floor on a decision. The floor for deciding a
--     request is the same floor that Action would have needed to be requested
--     (authz.RoleGate), so an operator can never approve a Raw Exec they could
--     not have asked for. Reading that out of the rendered summary would make a
--     security boundary depend on string formatting.
--   * risk_class lets the queue be filtered and rendered without re-parsing
--     prose.
--
-- Both default to the unspecified value, which is what pre-0013 rows carry.
-- That is the fail-closed direction for action_kind: authz.RoleGate denies an
-- unrecognized kind for EVERY role including admin, so a request parked before
-- this migration cannot be decided at all rather than being decidable by
-- whoever the weakest floor would have admitted. In practice there are no such
-- rows outside a development store -- the approval callout ships whole in
-- v0.5.0 -- and a request that predates the column would in any case have
-- expired long before an upgrade lands.
--
-- decider_human records whether the deciding Account was a human one. It is the
-- verified fact behind ADR-0027's ladder rung 2 being human-only, and it is
-- recorded rather than recomputed at read time because an Account's kind is
-- mutable state and "who was allowed to answer this, then" is a fact about the
-- past.
--
-- NOTE: keep semicolons out of these comments. splitStatements
-- (store/migrate.go) splits the file on that character without stripping
-- comments first, so one inside a comment is executed as SQL.

ALTER TABLE approval_requests ADD COLUMN action_kind TEXT NOT NULL DEFAULT 'unspecified';
ALTER TABLE approval_requests ADD COLUMN risk_class TEXT NOT NULL DEFAULT 'unspecified';
ALTER TABLE approval_decisions ADD COLUMN decider_human INTEGER NOT NULL DEFAULT 0;
