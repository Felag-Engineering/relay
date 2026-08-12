-- #299: record HOW a verified identity was established.
--
-- The verified lane (migration 0010) already records WHO acted. With OAuth
-- sessions alongside static API Tokens there are now two ways to become that
-- identity, and #299 requires them to be distinguishable in audit -- a
-- compromised static credential and a compromised IdP account call for
-- different responses.
--
-- Values: "api_token", "oauth", or NULL for a record written outside an
-- authentication boundary (a local signal on the Relay host) or before this
-- migration. No CHECK constraint, matching the `kind` column's precedent, so
-- a future method needs no migration.
--
-- NOTE: keep semicolons out of these comments. splitStatements
-- (store/migrate.go) splits the file on that character without stripping
-- comments first, so one inside a comment is executed as SQL.

ALTER TABLE audit ADD COLUMN auth_method TEXT;
