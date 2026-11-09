-- Observations of a Node's connections: the Raw Exec state its last
-- PolicySnapshot reported, when it first connected, and the clock skew the
-- Relay measured on its last heartbeat. The Relay writes every column;
-- reported_raw_exec is the Node's self-report, recorded as evidence only, and
-- the other two are the Relay's own. registry.Report has no field for any of
-- them (invariant 9). Each is nullable because NULL is the honest answer: not
-- reported, never connected, not measured.
--
-- reported_raw_exec: NULL not reported, 0 disabled, 1 enabled.
-- clock_skew_ms: milliseconds, positive when the Node's clock is ahead.
ALTER TABLE nodes ADD COLUMN reported_raw_exec INTEGER;
ALTER TABLE nodes ADD COLUMN first_connected_at TIMESTAMP;
ALTER TABLE nodes ADD COLUMN clock_skew_ms INTEGER;
ALTER TABLE nodes ADD COLUMN clock_skew_measured_at TIMESTAMP;

-- Backfill: only a connect's Upsert writes a daemon version or a Policy
-- fingerprint (enrollment's report carries neither), so either one proves the
-- Node connected earlier. last_seen is the latest contact, so the copied value
-- is an upper bound: the Node connected at or before it.
--
-- Gap: a Node with neither value stored is treated as first on its next
-- connect, at most once.
UPDATE nodes SET first_connected_at = last_seen
 WHERE daemon_version <> '' OR policy_fingerprint <> '';
