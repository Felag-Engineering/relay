-- #269 (ADR-0027): the approval callout's durable state.
--
-- A gated dispatch parks BEFORE any Task is sent. The Job and its Tasks are
-- not created at park time -- parking happens after Selector resolution, authz,
-- and the blast-cap check but before the Job engine runs -- so an
-- approval_requests row is the only trace a parked dispatch leaves until it is
-- approved. That is deliberate: an unapproved dispatch must never leave a
-- Pending Task lying in the store that a restart reconciler could mistake for
-- work to resume.
--
-- Two tables rather than an "approved" flag on jobs, because ADR-0027 fixes the
-- stored shape as requirement-vs-set-of-decisions from day one. v1 config only
-- exposes count 1 or 2, but N-of-M, richer audiences, and per-decision channel
-- recording then arrive as a config change with NO data migration -- the same
-- discipline the Job engine used for stages.
--
-- NOTE: keep semicolons out of these comments. splitStatements
-- (store/migrate.go) splits the file on that character without stripping
-- comments first, so one inside a comment is executed as SQL.

CREATE TABLE approval_requests (
    request_id        TEXT PRIMARY KEY,

    -- job_id is the Job this approval releases. It is NOT a foreign key into
    -- jobs: the Job does not exist yet while the request is pending, and is
    -- created only once the requirement is satisfied.
    job_id            TEXT,

    -- plan_hash content-addresses the Operation, its arguments, and the
    -- RESOLVED FAN-OUT (approval.HashPlan). The approval binds to this, never
    -- to the Job in the abstract, so registry drift between approval and
    -- dispatch re-parks instead of silently running against a different fleet.
    plan_hash         TEXT NOT NULL,

    -- The verified requester. Stored here as well as in audit because
    -- requester_allowed is evaluated against it at decision time.
    requested_by_id   TEXT NOT NULL DEFAULT '',
    requested_by      TEXT NOT NULL DEFAULT '',

    -- A rendered, Relay-authored description of what is being approved. Stored
    -- rather than recomputed so the approval queue and the audit trail show
    -- exactly what the approver was shown, even after the fleet has moved on.
    plan_summary      TEXT NOT NULL DEFAULT '',

    -- Which gate rules parked this dispatch, comma-separated. A gate that
    -- cannot say why it fired trains operators to switch it off.
    matched_rules     TEXT NOT NULL DEFAULT '',

    -- The merged requirement (strictest of every matching rule).
    require_count     INTEGER NOT NULL,
    require_audience  TEXT NOT NULL DEFAULT '',
    requester_allowed INTEGER NOT NULL DEFAULT 0,
    require_channel   INTEGER NOT NULL,
    require_ttl_ns    INTEGER NOT NULL,

    -- 0 pending, 1 approved, 2 denied, 3 expired. No CHECK constraint, matching
    -- the audit table's precedent, so a future state needs no migration.
    state             INTEGER NOT NULL DEFAULT 0,

    created_at        TIMESTAMP NOT NULL,
    expires_at        TIMESTAMP NOT NULL,
    resolved_at       TIMESTAMP
);

-- The sweeper and the approval queue both scan by state, and the sweeper
-- additionally orders by deadline.
CREATE INDEX idx_approval_requests_state ON approval_requests (state, expires_at);

CREATE TABLE approval_decisions (
    decision_id  INTEGER PRIMARY KEY AUTOINCREMENT,
    request_id   TEXT NOT NULL REFERENCES approval_requests (request_id) ON DELETE CASCADE,

    -- The verified decider.
    account_id   TEXT NOT NULL DEFAULT '',
    account      TEXT NOT NULL DEFAULT '',

    approve      INTEGER NOT NULL,
    reason       TEXT NOT NULL DEFAULT '',

    -- How the decision arrived (1 in-band, 2 out-of-band). Recorded rather than
    -- assumed, so an auditor can tell whether an approval was evidence or an
    -- assumption about the harness.
    channel      INTEGER NOT NULL,

    -- The Plan this decision was made against, so a decision cannot be replayed
    -- onto a different Plan.
    plan_hash    TEXT NOT NULL,

    decided_at   TIMESTAMP NOT NULL,

    -- Quorum means DISTINCT deciders. The code guard in approval.Request.Decide
    -- is the primary enforcement -- this UNIQUE is defense-in-depth, mirroring
    -- how the stages table backs the one-stage-per-Job rule.
    UNIQUE (request_id, account_id)
);

CREATE INDEX idx_approval_decisions_request ON approval_decisions (request_id);
