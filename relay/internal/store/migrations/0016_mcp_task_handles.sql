-- v0.5.1 (#373, ADR-0028, SEP-2663): MCP task handles.
--
-- One row is one client-polled reference to one parked dispatch. This is the
-- MCP protocol's "task", NOT a Relay Task -- a Relay Task is one Operation on
-- one Node (ADR-0004), and the two are unrelated. The table is named in full
-- for that reason.
--
-- WHY TWO NULLABLE BINDINGS RATHER THAN ONE ID
--
-- SEP-2663 wants a task id in the tools/call RESPONSE, which is the instant the
-- dispatch parks. But a parked dispatch deliberately creates no Job (#269:
-- parking leaves behind no Job and no Pending Tasks, or a restart reconciler
-- mistakes them for interrupted work). So at mint time there is an approval
-- Request and nothing else, and a Job arrives later or never. Overloading one
-- column to mean "approval id now, job id later" would make every reader guess
-- which era a row is in.
--
-- WHY status IS NOT AUTHORITATIVE
--
-- last_status records what a client was most recently TOLD. It is deliberately
-- not the answer to "what is this handle's status" -- that is computed from the
-- approval Request at read time (mcptask.Handle.Status). The underlying facts
-- change without this table being told: a decision lands on the Control API, a
-- sweeper expires a Request. A handle reporting "working" for an approval
-- denied an hour ago would be the approval-view fidelity gap in a new place.
-- The column is kept because what a client was told is a fact about the past.
--
-- account_id is NOT NULL because a handle is not a bearer capability. Holding
-- the id is not permission to resolve it: reads are owner-checked, and once
-- [4/6] lands, resolving a handle can re-drive the stored call through the
-- capability layer -- so an unowned handle would be a way to run somebody
-- else's dispatch under their authority.
--
-- Handles are swept, not kept (see DeleteExpired). They are a bounded-life
-- client convenience -- the durable record of what happened is the audit trail,
-- which outlives them.
--
-- NOTE: keep semicolons out of these comments. splitStatements
-- (store/migrate.go) splits the file on that character without stripping
-- comments first, so one inside a comment is executed as SQL.

CREATE TABLE mcp_task_handles (
    task_id             TEXT PRIMARY KEY,

    -- The parked dispatch this handle refers to. Set at mint time, never
    -- changed: re-pointing a handle would let a client's stored id silently
    -- start reporting on a different dispatch.
    approval_request_id TEXT NOT NULL,

    -- Set once an approved dispatch actually ran. NULL means "not yet, or
    -- never".
    job_id              TEXT,

    -- The minting Account. Ownership is checked against the ID rather than the
    -- name, so a rename never hands a handle to whoever inherits the name.
    account_id          TEXT NOT NULL,
    account_name        TEXT NOT NULL DEFAULT '',

    -- What the client was last told. See the note above: a cache and an audit
    -- record, never the source of truth.
    last_status         TEXT NOT NULL,

    created_at          TEXT NOT NULL,
    last_updated_at     TEXT NOT NULL,

    -- Always at or before the approval Request's own expiry. A handle that
    -- outlived its subject could only report on something no longer decidable.
    expires_at          TEXT NOT NULL,

    -- tasks/cancel. It ends the CLIENT'S polling contract and nothing else --
    -- the approval Request stays pending until a human decides it or it
    -- expires (ADR-0028). A cancel arrives over the AI's own session, and a
    -- lever there over an out-of-band decision is exactly what the approval
    -- callout exists to prevent.
    cancelled_at        TEXT
);

-- One handle per parked dispatch: a re-drive re-attaches rather than minting a
-- second handle for the same wait. UNIQUE rather than an ordinary index so the
-- one-to-one mapping is the schema's rule and not a convention a later caller
-- can quietly break.
CREATE UNIQUE INDEX idx_mcp_task_handles_request
    ON mcp_task_handles (approval_request_id);

-- The sweeper's scan, and the owner-scoped listing.
CREATE INDEX idx_mcp_task_handles_expiry ON mcp_task_handles (expires_at);
CREATE INDEX idx_mcp_task_handles_account ON mcp_task_handles (account_id);
