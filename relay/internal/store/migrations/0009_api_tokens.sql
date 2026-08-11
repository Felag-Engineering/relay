-- API Tokens are the credentials machine Accounts (and scripted humans)
-- authenticate with (ADR-0010, roadmap v0.3.0). Distinct from Enrollment
-- Tokens (table `tokens`), which join Nodes to the fleet and can never call
-- the control plane.
--
-- secret_hash holds ONLY the SHA-256 of the secret component: the plaintext is
-- returned once at mint and never stored, so a database dump, a backup, or a
-- compromised read replica yields no usable credential.
--
-- A token carries NO role. Authorization reads the Account's role at
-- verification time, which is what makes "a token inherits role changes of its
-- Account" true by construction rather than by a sync step.
--
-- revoked_at is a timestamp rather than a flag so an incident review can ask
-- "when was this cut off", and ON DELETE CASCADE means deleting an Account can
-- never leave orphaned credentials behind that still hash-match.
CREATE TABLE api_tokens (
    id           TEXT PRIMARY KEY,
    account_id   TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    name         TEXT NOT NULL,
    secret_hash  BLOB NOT NULL,
    created_at   TEXT NOT NULL,
    expires_at   TEXT,
    last_used_at TEXT,
    revoked_at   TEXT
);

CREATE INDEX api_tokens_account_idx ON api_tokens (account_id);
