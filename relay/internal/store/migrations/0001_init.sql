-- schema_migrations tracks which migration files have been applied.
CREATE TABLE schema_migrations (
    version    INTEGER PRIMARY KEY,
    applied_at TIMESTAMP NOT NULL
);

-- nodes is the Node registry: identity, Facts, last-seen, Policy fingerprint,
-- and revocation state. node: and relay: labels live in the two disjoint
-- tables below, not here.
CREATE TABLE nodes (
    node_id            TEXT PRIMARY KEY,
    cert_fingerprint   TEXT NOT NULL,
    hostname           TEXT NOT NULL,
    os                 TEXT NOT NULL,
    kernel             TEXT NOT NULL,
    arch               TEXT NOT NULL,
    ip_addresses       TEXT, -- JSON array, NULL = Facts.IPAddresses is nil (not empty)
    enrolling_token_id TEXT NOT NULL,
    policy_fingerprint TEXT NOT NULL,
    last_seen          TIMESTAMP NOT NULL,
    revoked_at         TIMESTAMP -- NULL = active, the persisted revocation state
);

-- node_labels and relay_labels are two DISJOINT tables mirroring the two
-- disjoint maps on registry.Node: no single write path spans both, so the
-- node:/relay: namespace boundary (ADR-0006, invariant 7) is structural here
-- too, not just in application code.
CREATE TABLE node_labels (
    node_id TEXT NOT NULL REFERENCES nodes (node_id) ON DELETE CASCADE,
    key     TEXT NOT NULL,
    value   TEXT NOT NULL,
    PRIMARY KEY (node_id, key)
);

CREATE TABLE relay_labels (
    node_id TEXT NOT NULL REFERENCES nodes (node_id) ON DELETE CASCADE,
    key     TEXT NOT NULL,
    value   TEXT NOT NULL,
    PRIMARY KEY (node_id, key)
);

-- jobs is the unit of audit and blast-radius control: one Job comprises one
-- Task per matched Node, grouped into Stages.
CREATE TABLE jobs (
    job_id     TEXT PRIMARY KEY,
    created_at TIMESTAMP NOT NULL
);

-- stages models a Job as stages of Task batches. The CHECK pins every stage
-- to index 0 and the UNIQUE makes it the only stage per Job: together they
-- are the SCHEMA half of the one-stage-per-Job constraint in v1 (the code
-- guard in internal/jobs.AddStage is the primary enforcement). Modeling
-- Job -> Stage -> Task lets a post-1.0 staged rollout land without a data
-- migration.
CREATE TABLE stages (
    stage_id    TEXT PRIMARY KEY,
    job_id      TEXT NOT NULL REFERENCES jobs (job_id) ON DELETE CASCADE,
    stage_index INTEGER NOT NULL CHECK (stage_index = 0),
    UNIQUE (job_id, stage_index)
);

-- tasks is the execution of one Action on a single Node. task_id is unique —
-- the at-most-once execution key (ADR-0004). In-flight dispatch state is
-- state = 'dispatched' AND resolved_at IS NULL: what a Relay restart must
-- recover to decide whether re-dispatch is safe.
CREATE TABLE tasks (
    task_id         TEXT PRIMARY KEY,
    job_id          TEXT NOT NULL REFERENCES jobs (job_id) ON DELETE CASCADE,
    stage_id        TEXT NOT NULL REFERENCES stages (stage_id) ON DELETE CASCADE,
    node_id         TEXT NOT NULL,
    action_kind     TEXT NOT NULL, -- 'operation' | 'raw_exec'
    operation_name  TEXT,
    operation_args  TEXT, -- JSON map
    raw_exec_argv   TEXT, -- JSON array
    risk_class      TEXT NOT NULL,
    timeout_seconds INTEGER NOT NULL DEFAULT 0,
    state           TEXT NOT NULL DEFAULT 'pending'
                    CHECK (state IN ('pending', 'dispatched', 'resolved')),
    outcome         INTEGER, -- NULL until resolved
    exit_code       INTEGER,
    stdout          BLOB,
    stderr          BLOB,
    created_at      TIMESTAMP NOT NULL,
    dispatched_at   TIMESTAMP,
    resolved_at     TIMESTAMP
);

CREATE INDEX idx_tasks_state ON tasks (state);
CREATE INDEX idx_tasks_job_id ON tasks (job_id);

-- audit is the append-only Task-dispatch trail.
CREATE TABLE audit (
    audit_id       TEXT PRIMARY KEY,
    ts             TIMESTAMP NOT NULL,
    principal      TEXT NOT NULL,
    selector       TEXT NOT NULL,
    job_id         TEXT NOT NULL,
    action_kind    TEXT NOT NULL,
    operation_name TEXT,
    args           TEXT, -- JSON map
    raw_exec_argv  TEXT, -- JSON array
    outcome        INTEGER
);
