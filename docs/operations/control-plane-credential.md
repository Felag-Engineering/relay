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
$ relay bootstrap-token -store-path /var/lib/relay/relay.db -ttl 24h
Minted API Token 7f3c… for account founding-admin (acct-…).
This token expires at 2026-08-12T09:00:00Z. Revoke it once your real Accounts have tokens:
  DELETE /api/v1/api-tokens/7f3c…
The credential below is shown once and cannot be recovered.
glp_7f3c….g7Kx…_Q
```

Diagnostics go to stderr and **the credential alone goes to stdout**, so you can capture it
straight into a secret store without parsing:

```console
$ relay bootstrap-token -store-path /var/lib/relay/relay.db -ttl 24h \
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

The administrative acts in that last row are enforced centrally too, from the same role
ladder (#397). Concretely:

| Act | Floor |
|---|---|
| Mint or revoke an Enrollment Token | `admin` |
| Revoke a Node | `admin` |
| **Engage** the Freeze | `operator`, **and a human Account** |
| **Release** the Freeze | `admin`, with a non-empty reason |

The one rule that is not a role: **a machine Account can never engage the Freeze**, at any
role including `admin`. Halting the whole fleet is a fire alarm for people to pull; an
AI-agent stopping the plane that supervises it is a denial of service wearing a safety
feature's clothes. Automation that legitimately needs to stop the fleet does it on the
Relay host (`SIGUSR1`), where the authority is root on the box rather than a credential
someone could steal. Releasing is *not* human-only — an incident must have an automated
way back.

Every one of those refusals is written to the audit trail as a `refusal`, with the Account
and its role, so "who tried" is answerable and not only "who succeeded".

## Human sessions: OAuth 2.1 through your IdP

API Tokens are the right credential for headless drivers. For a **person** connecting
their own MCP harness (Claude, or any off-the-shelf client), the Relay speaks MCP's
standard OAuth 2.1 authorization layer, so the session runs under their identity rather
than a shared machine credential.

**The Relay is a protected resource, never an authorization server** (ADR-0024). It
validates tokens your IdP issued; it has no login page, no consent screen, and no token
endpoint, and it will not grow them without a new ADR. You keep one identity system.

### Configuring it

```console
relay \
  -control-enabled -control-addr :9443 \
  -oauth-issuer https://idp.example.com \
  -oauth-audience https://relay.example.internal:9443/mcp \
  -oauth-public-url https://relay.example.internal:9443 \
  -oauth-account-claim email \
  -oauth-required-scope relay.fleet
```

| Flag | Env | Meaning |
|---|---|---|
| `-oauth-issuer` | `RELAY_OAUTH_ISSUER` | Your IdP's issuer URL. Empty disables OAuth entirely. |
| `-oauth-audience` | `RELAY_OAUTH_AUDIENCE` | **Required.** This Relay's resource identifier, checked against every token's `aud`. |
| `-oauth-public-url` | `RELAY_OAUTH_PUBLIC_URL` | **Required.** The base URL clients actually dial — used to advertise metadata. |
| `-oauth-account-claim` | `RELAY_OAUTH_ACCOUNT_CLAIM` | Claim naming the Account a session resolves to. Default `email`. |
| `-oauth-required-scope` | `RELAY_OAUTH_REQUIRED_SCOPE` | Scope every token must carry. Empty requires none. |

Discovery happens once, at startup, so a wrong issuer fails the boot instead of every
request.

> **`-oauth-audience` is not optional, and not a formality.** It is the RFC 8707 binding
> that stops a token minted for some *other* service in the same IdP from driving your
> fleet. Without it, every application sharing your IdP becomes a confused deputy. The
> Relay refuses to start if you set an issuer without one.

### Onboarding a human

Their Account must exist first — **the Relay never auto-creates one from a token claim**.
Whoever administers the IdP would otherwise be able to mint identities on your control
plane, and Account creation is an audited admin act.

```console
# The name must match what the configured claim will carry.
$ curl -sS --cacert ca.pem -H "Authorization: Bearer $ADMIN" \
    -H 'Content-Type: application/json' \
    -d '{"name":"mike","kind":"human","role":"operator"}' \
    https://relay.example.internal:9443/api/v1/accounts
```

Then they point their harness at `https://relay.example.internal:9443/mcp` and complete
the flow. The harness discovers everything it needs on its own: an unauthenticated request
gets a `WWW-Authenticate` challenge pointing at
`/.well-known/oauth-protected-resource`, which names your IdP.

That metadata document is the **one** unauthenticated route on the control plane. It has
to be — it is what tells a client how to obtain a credential. It discloses an issuer URL
and a resource identifier, both public by definition.

### What an OAuth session does and does not buy

It buys **attribution and revocation**: audit records the human's Account and marks the
session `oauth` rather than `api_token`, and disabling their Account or their IdP user cuts
them off.

It does **not** buy trust. An OAuth session proves a human authorized the *session* — not
that a human intended each *call*. The calls are still generated by a model that may have
read attacker-controlled content. So MCP-originated calls stay agent-grade for approval
gating regardless of who authorized the session, and authority is still the role of the
Account the session resolves to: a human authenticating through your IdP gets `operator`
if their Account is an operator, and Raw Exec still requires `admin`.

An IdP outage affects OAuth sessions only. API Tokens and the bootstrap credential are
verified entirely locally, so you are never locked out of your own control plane by
someone else's downtime.

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
secrets and are not needed here. The Relay's human-login credential — the Admin Console
password a human Account signs in with — is exactly that other shape, and does make the
other choice: it is stored as an argon2id hash (`relay/internal/accounts`), verified by the
Console's session layer (`relay/internal/consoleauth`), and set on the Relay host with
`relay console-password` ([relay-install.md](relay-install.md)). The two credential kinds
never substitute for one another: a password cannot call the API, and an API Token cannot
sign in to the Console.

## Migrating from the seeded credential

1. Upgrade the Relay binary.
2. Remove `-control-credential-hash-file` / `RELAY_CONTROL_CREDENTIAL_HASH_FILE` from your
   unit file, IaC, and any wrapper scripts. The Relay will not start with the flag present.
3. Start the Relay. It seeds the founding admin Account automatically, as it already did.
4. Run `relay bootstrap-token -store-path <path>` — the same store path the Relay runs with —
   and switch your callers to the printed credential.
5. Create per-caller Accounts, mint their tokens, and revoke the bootstrap one.
6. Delete the old credential-hash file and the plaintext from your vault. Nothing reads
   them any more.

Step 5 is the one worth not skipping. The migration is only finished when each caller has
its own identity — until then you have replaced one shared secret with another, and the
audit trail still cannot tell you who did what.
