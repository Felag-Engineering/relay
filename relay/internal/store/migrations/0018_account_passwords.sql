-- Local password credentials for human Accounts signing in to the Console
-- (#418, docs/design/console/12-login.md).
--
-- A SEPARATE TABLE rather than a column on `accounts`, for the same reason
-- accounts.PasswordRepository is a separate seam from accounts.Repository:
-- every surface reads Accounts, and a hash that lived on that row would
-- eventually be selected into an API response or a Console template by
-- someone adding a field. Here, reading a hash takes a deliberate join that
-- exactly one component performs.
--
-- password_hash holds an argon2id PHC string — a memory-hard KDF, not the
-- SHA-256 used for api_tokens. The difference is the entropy of the input:
-- 256 random bits need no work factor, a human-chosen password needs all it
-- can get. The cost parameters travel inside the string so raising them later
-- re-verifies old credentials at their original cost instead of locking
-- everyone out.
--
-- ON DELETE CASCADE mirrors api_tokens: deleting an Account can never leave a
-- credential behind that still verifies.
CREATE TABLE account_passwords (
    account_id    TEXT PRIMARY KEY REFERENCES accounts(id) ON DELETE CASCADE,
    password_hash TEXT NOT NULL,
    updated_at    TEXT NOT NULL
);
