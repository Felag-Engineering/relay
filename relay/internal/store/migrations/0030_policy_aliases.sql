-- A Policy alias is a display name the Relay holds for a Policy fingerprint.
-- No column names a Node, Label or Selector, and there is no foreign key to
-- nodes: an alias outlives every Node that reports its fingerprint.
CREATE TABLE policy_aliases (
    fingerprint TEXT NOT NULL PRIMARY KEY,
    alias       TEXT NOT NULL UNIQUE CHECK (alias <> ''),
    updated_at  TEXT NOT NULL
);
