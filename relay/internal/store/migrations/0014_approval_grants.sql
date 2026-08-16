-- #378 (ADR-0027 decision 12): batch/window approval grants.
--
-- One row is one human decision covering a BOUNDED SET of future dispatches,
-- rather than one Plan. Every column below that bounds something is NOT NULL
-- with no default, because the bounds are the entire security argument for
-- grants: a normal approval is bound by its plan hash, and a grant is bound by
-- nothing except these walls.
--
-- request_id is the approval_requests row that authorized this grant. It is not
-- a foreign key for the same reason approval_requests.job_id is not one -- the
-- store deliberately avoids cross-table constraints that would make a retention
-- policy or a partial restore fail in surprising ways -- but the join is the
-- whole audit story: requirement, decisions, and approvers all live there, so
-- quorum is evaluated in exactly one place.
--
-- NOTE the uses/max_uses pair. Claiming a grant increments uses inside a
-- transaction with a conditional UPDATE (see store/grants.go ClaimGrant): a
-- bound enforced outside a transaction is not a bound, because two concurrent
-- dispatches could both read the last remaining use.
--
-- NOTE: keep semicolons out of these comments. splitStatements
-- (store/migrate.go) splits the file on that character without stripping
-- comments first, so one inside a comment is executed as SQL.

CREATE TABLE approval_grants (
    grant_id                 TEXT PRIMARY KEY,

    -- The authorizing approval Request. A grant is never self-authorizing.
    request_id               TEXT NOT NULL,

    -- The Scope: every one of these is a wall, and none may be absent.
    -- scope_operations is a comma-separated allow-list, empty ONLY when
    -- scope_raw_exec is set. An empty list covers nothing, never everything --
    -- approval.Scope.Validate refuses the ambiguous case before it is stored,
    -- and rejects commas inside an operation name so this encoding stays
    -- unambiguous.
    scope_account            TEXT NOT NULL,
    scope_risk_class         TEXT NOT NULL,
    scope_max_fan_out        INTEGER NOT NULL,
    scope_operations         TEXT NOT NULL,
    scope_raw_exec           INTEGER NOT NULL,
    scope_selector_namespace TEXT NOT NULL DEFAULT '',

    -- The window. Half-open [starts_at, expires_at).
    starts_at                TEXT NOT NULL,
    expires_at               TEXT NOT NULL,

    -- The use counter.
    max_uses                 INTEGER NOT NULL,
    uses                     INTEGER NOT NULL DEFAULT 0,

    -- The Relay-authored description the approver actually read. Stored rather
    -- than recomputed, for the same reason approval_requests.plan_summary is:
    -- what a human was shown is a fact about the past, and re-rendering it from
    -- today's state would quietly rewrite history.
    summary                  TEXT NOT NULL,

    created_at               TEXT NOT NULL,

    -- Early revocation. A window is a period of reduced friction, and reduced
    -- friction against a compromised requester is exactly when someone needs to
    -- close it without reaching for the fleet-wide Freeze.
    revoked_at               TEXT,
    revoked_by               TEXT NOT NULL DEFAULT '',
    revoke_reason            TEXT NOT NULL DEFAULT ''
);

-- The claim path's candidate query narrows by requester and class before the
-- domain predicate decides. Both are exact-match and highly selective.
CREATE INDEX idx_approval_grants_claim
    ON approval_grants (scope_account, scope_risk_class, expires_at);

-- "Which Jobs did this grant release" is answered from the audit trail's
-- grant_id, not from here -- a grant releases many Jobs, so there is
-- deliberately no job_id column to overwrite.
CREATE INDEX idx_approval_grants_request ON approval_grants (request_id);
