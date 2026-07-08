-- freeze is the persisted Relay-wide emergency stop (ADR-0013). It is a
-- single-row table (id is always 1) that engage/release UPSERT into, so a
-- Freeze survives a Relay restart. No row is seeded: Frozen() treats "no
-- row" as not-frozen, so a fresh Relay starts unfrozen without needing a
-- CURRENT_TIMESTAMP-vs-application-clock seed value.
CREATE TABLE freeze (
    id         INTEGER PRIMARY KEY CHECK (id = 1),
    engaged    INTEGER NOT NULL DEFAULT 0 CHECK (engaged IN (0, 1)),
    principal  TEXT NOT NULL DEFAULT '',
    reason     TEXT,
    updated_at TIMESTAMP NOT NULL
);
