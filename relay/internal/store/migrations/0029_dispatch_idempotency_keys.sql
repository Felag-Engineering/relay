-- #895: client idempotency keys for dispatch. A key binds an Account's
-- run_operation / raw_exec call to the Job it created, so a call re-issued
-- after a lost response is answered with that Job instead of dispatching again.
--
-- account_id is the verified AccountID, never a display name: a key is scoped
-- to the Account that sent it. job_id is a Job ID reserved BEFORE the Job row
-- exists (like approval_requests.job_id, AP-77), so it carries no foreign key.
--
-- There is no backfill: no earlier dispatch carried a key.
--
-- created_at_ns is an INTEGER of Unix nanoseconds, not the RFC3339Nano TEXT the
-- other tables use: the window and abandon comparisons run in SQL, and an
-- integer compares exactly where trimmed fractional seconds sort wrongly (#656).
-- Nothing else reads this table.
CREATE TABLE dispatch_idempotency_keys (
    account_id     TEXT    NOT NULL,
    idem_key       TEXT    NOT NULL,
    request_digest TEXT    NOT NULL,
    job_id         TEXT    NOT NULL,
    created_at_ns  INTEGER NOT NULL,
    PRIMARY KEY (account_id, idem_key)
);

CREATE INDEX dispatch_idempotency_keys_created ON dispatch_idempotency_keys(created_at_ns);
