-- #300: verified/asserted attribution lanes on the audit trail.
--
-- Two lanes, kept structurally distinct in the schema itself. The verified
-- columns are facts the Relay established at the authentication boundary. The
-- asserted_* columns are caller-claimed strings stored verbatim.
--
-- The `asserted_` prefix is the mechanism, not decoration: it makes the lane
-- visible in every SELECT, every index name, and every ad-hoc query an
-- operator types at 3am. A schema where the two lanes look alike is one where
-- a query eventually treats a claim as a fact.
--
-- All columns are nullable with no default: rows written before this migration
-- carry NULL, which reads correctly as "not recorded" rather than as an empty
-- assertion. The existing `principal` TEXT column is untouched — it stays as
-- the human-readable rendering.
--
-- NOTE: whole-line comments like these are stripped before the statement split
-- (store/migrate.go), so ordinary punctuation is safe here. A trailing comment
-- on the same line as SQL still is not -- see splitStatements.

-- Verified lane: established by the Relay, unforgeable by a caller.
ALTER TABLE audit ADD COLUMN account_id TEXT;
ALTER TABLE audit ADD COLUMN account_name TEXT;
ALTER TABLE audit ADD COLUMN account_role TEXT;
ALTER TABLE audit ADD COLUMN token_id TEXT;

-- Asserted lane: caller-claimed, bounded at the boundary, stored verbatim.
ALTER TABLE audit ADD COLUMN asserted_on_behalf_of TEXT;
ALTER TABLE audit ADD COLUMN asserted_traceparent TEXT;
ALTER TABLE audit ADD COLUMN asserted_session_ref TEXT;
ALTER TABLE audit ADD COLUMN asserted_change_ref TEXT;

-- The two accountability queries #300 requires. Partial indexes: the vast
-- majority of rows carry no assertion, and indexing those NULLs would cost
-- write amplification on an append-only hot path for nothing.
CREATE INDEX IF NOT EXISTS idx_audit_account_id
    ON audit (account_id) WHERE account_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_audit_asserted_on_behalf_of
    ON audit (asserted_on_behalf_of) WHERE asserted_on_behalf_of IS NOT NULL;
