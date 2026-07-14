-- daemon_version is the node-self-reported relay-daemon version, refreshed on
-- each Hello Upsert (ADR-0014). It is report-only, like policy_fingerprint.
-- The derived `outdated` flag is NOT stored here: it depends on the Relay's
-- configured min_daemon_version, which can change between restarts, so it is
-- computed at read time instead. Additive: pre-existing rows default to ''.
ALTER TABLE nodes ADD COLUMN daemon_version TEXT NOT NULL DEFAULT '';
