# Control-plane credentials

The Relay's control-plane listener (MCP + `/api/v1`, ADR-0009/0010) accepts exactly one kind
of credential: an **API Token** bound to an **Account**. There is no shared secret, and no
credential in Relay configuration — the Relay's config file cannot grant control-plane
access at all (ADR-0023).

Every token:

- carries the `glp_` prefix, so a leak is greppable and secret scanners recognize it;
- is stored only as a SHA-256 hash, so it cannot be recovered from the store, a dump, or a
  backup;
- inherits its Account's role at every request, so a demotion or a disable takes effect on
  the next call — no restart, no waiting for expiry;
- can be revoked individually, without disturbing any other caller.

> **Upgrading from a Relay that used the seeded credential?** See
> [Migrating from the seeded credential](#migrating-from-the-seeded-credential) at the
> bottom. The `-control-credential-hash-file` flag, the
> `RELAY_CONTROL_CREDENTIAL_HASH_FILE` environment variable, and the
> `relay hash-credential` subcommand are all gone; a Relay started with the old flag will
> refuse the unknown argument.

## Bootstrapping the first credential

Minting an Account's token requires authenticating, and authenticating requires a token.
`relay bootstrap-token` breaks that cycle from outside the wire, the same way Node Policy
is rooted locally rather than pushed (ADR-0002): it writes directly to the Relay's own
store file, which is root-owned.

```console
# On the Relay host, as root:
$ relay bootstrap-token -store-path /var/lib/relay/store/relay.db -ttl 24h
Minted API Token 7f3c… for account founding-admin (acct-…).
This token expires at 2026-08-12T09:00:00Z. Revoke it once your real Accounts have tokens:
  DELETE /api/v1/api-tokens/7f3c…
The credential below is shown once and cannot be recovered.
glp_7f3c….g7Kx…_Q
```

Diagnostics go to stderr and **the credential alone goes to stdout**, so you can capture it
straight into a secret store without parsing:

```console
$ relay bootstrap-token -store-path /var/lib/relay/store/relay.db -ttl 24h \
    | vault kv put secret/relay/bootstrap token=-
```

Prefer that to letting the plaintext sit in your scrollback or a CI log.

Flags:

| Flag | Default | Meaning |
|---|---|---|
| `-store-path` | *(required)* | The Relay's store path — the same value the Relay runs with. |
| `-name` | `bootstrap` | Operator-facing label, shown when listing the Account's tokens. |
| `-ttl` | `0` (no expiry) | Token lifetime, e.g. `24h`. A bootstrap credential you intend to revoke promptly is better served by a short TTL. |

Notes:

- **It is safe to run while the Relay is running.** The store is WAL-mode with a busy
  timeout, so a second writer does not disturb the server.
- **It is additive.** Each run mints a *new* token and never revokes an existing one, so
  recovering from a lost plaintext cannot silently break a credential still in use. Revoke
  the old one deliberately.
- **It refuses a disabled founding admin.** Disabling that Account retires its authority on
  purpose; minting it a fresh credential would reverse that decision silently. Re-enable it
  explicitly (as another admin) if that is what you want.

## The intended flow

The bootstrap credential is a *starting point*, not a service account. Use it once to
establish real identities, then retire it:

```console
# 1. Create the Account your orchestrator will be.
$ curl -sS --cacert ca.pem -H "Authorization: Bearer $BOOTSTRAP" \
    -H 'Content-Type: application/json' \
    -d '{"name":"gleipnir","kind":"machine","role":"operator"}' \
    https://relay.example:9443/api/v1/accounts

# 2. Mint it a credential. ttl_seconds is required; 0 means no expiry.
$ curl -sS --cacert ca.pem -H "Authorization: Bearer $BOOTSTRAP" \
    -H 'Content-Type: application/json' \
    -d '{"name":"gleipnir-prod","ttl_seconds":2592000}' \
    https://relay.example:9443/api/v1/accounts/$ACCOUNT_ID/tokens

# 3. Revoke the bootstrap credential.
$ curl -sS -X DELETE --cacert ca.pem -H "Authorization: Bearer $BOOTSTRAP" \
    https://relay.example:9443/api/v1/api-tokens/$BOOTSTRAP_TOKEN_ID
```

Give each caller its own Account, and give it the **lowest role that does its job**:

| Role | Can |
|---|---|
| `viewer` | Read: list Nodes, describe them, read Jobs and audit. Dispatches nothing. |
| `operator` | …and run structured Operations (the typed path). |
| `admin` | …and use Raw Exec, and administer Accounts, tokens, enrollment, and the Freeze. |

Raw Exec is admin-only and enforced centrally, so an `operator` token cannot reach the
arbitrary-command path from any surface. That is the point of separating the roles: most
orchestration is Operations, and only Operations.

## Rotation, revocation, and recovery

- **Rotate** a caller: mint it a second token, switch the caller over, revoke the first. No
  restart, and no other caller is affected — which is exactly what a shared credential
  could never offer.
- **Revoke** immediately: `DELETE /api/v1/api-tokens/{id}`. It takes effect on the next
  request. Revoking twice is a no-op; revoking an unknown id is a 404.
- **Cut off an identity entirely**: `POST /api/v1/accounts/{id}/disable`. That refuses every
  one of its tokens at once *without revoking any of them*, so re-enabling restores access.
  Disabling the Account and revoking a token are deliberately different acts with different
  blast radii.
- **Lost the plaintext?** There is no recovery, by design — only a hash is stored. Mint a
  replacement and revoke the old one.
- **Locked out entirely** (no working admin token, founding admin disabled): recovery
  requires local root on the Relay host, which is the same access `bootstrap-token` already
  assumes. There is deliberately no `-force` flag; see ADR-0023's residual note.

## Why SHA-256, not a password KDF

API Tokens are high-entropy, machine-generated bearer material — the same shape as an
Enrollment Token secret (`relay/internal/enroll/token.go`) — not low-entropy human
passwords. A fast cryptographic hash compared in constant time
(`crypto/subtle.ConstantTimeCompare`) is the correct, standard choice for that shape of
secret; slow KDFs like bcrypt/argon2 exist to defend against brute-forcing low-entropy human
secrets and are not needed here. The Relay's human-login credential model (Admin Console,
v0.6.0) is a separate, future concern and may make a different choice.

## Migrating from the seeded credential

1. Upgrade the Relay binary.
2. Remove `-control-credential-hash-file` / `RELAY_CONTROL_CREDENTIAL_HASH_FILE` from your
   unit file, IaC, and any wrapper scripts. The Relay will not start with the flag present.
3. Start the Relay. It seeds the founding admin Account automatically, as it already did.
4. Run `relay bootstrap-token` and switch your callers to the printed credential.
5. Create per-caller Accounts, mint their tokens, and revoke the bootstrap one.
6. Delete the old credential-hash file and the plaintext from your vault. Nothing reads
   them any more.

Step 5 is the one worth not skipping. The migration is only finished when each caller has
its own identity — until then you have replaced one shared secret with another, and the
audit trail still cannot tell you who did what.
