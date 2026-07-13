-- tokens is the persisted Enrollment Token store (ADR-0006). It mirrors the
-- fields of enroll.Token. Persisting it (rather than keeping tokens in memory)
-- is what makes revocation survive a Relay restart: a revoked token can never
-- mint a new identity after the process restarts (issue #133). The plaintext
-- secret is never stored — only the SHA-256 hash of the secret part.
CREATE TABLE tokens (
    token_id     TEXT PRIMARY KEY,
    secret_hash  BLOB NOT NULL,               -- sha256 of the secret part only, never the plaintext
    scope        TEXT NOT NULL,               -- JSON array of relay: Labels
    expires_at   TIMESTAMP NOT NULL,
    revoked      INTEGER NOT NULL DEFAULT 0,  -- 0 = active, 1 = revoked
    max_uses     INTEGER NOT NULL DEFAULT 0,  -- 0 = unlimited
    uses         INTEGER NOT NULL DEFAULT 0,
    created_at   TIMESTAMP NOT NULL,
    created_by   TEXT NOT NULL DEFAULT ''
);
