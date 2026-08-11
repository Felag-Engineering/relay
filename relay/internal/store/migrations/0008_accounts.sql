-- Accounts are the control plane's identity substrate (ADR-0010, roadmap
-- v0.3.0): every action on every surface attributes to exactly one Account,
-- and every authorization question is answered from its role.
--
-- name_normalized is the uniqueness key (lowercased, trimmed) so "Alice" and
-- "alice" cannot both exist and be confused for one another in an audit trail;
-- name keeps the operator's original casing for display.
--
-- enabled is the durable off-switch, deliberately distinct from revoking a
-- credential (tokens arrive in #296): disabling the identity and revoking one
-- of its tokens are different acts with different blast radii.
--
-- No credential material lives here. Tokens are their own table, hashed at
-- rest, bound to an account_id (#296).
CREATE TABLE accounts (
    id              TEXT PRIMARY KEY,
    name            TEXT NOT NULL,
    name_normalized TEXT NOT NULL UNIQUE,
    kind            TEXT NOT NULL CHECK (kind IN ('human','machine')),
    role            TEXT NOT NULL CHECK (role IN ('viewer','operator','admin')),
    enabled         INTEGER NOT NULL DEFAULT 1,
    created_at      TEXT NOT NULL,
    last_seen_at    TEXT
);

CREATE INDEX accounts_role_idx ON accounts (role);
