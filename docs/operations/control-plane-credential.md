# Control-plane credentials

The Relay's control-plane listener (MCP + `/api/v1`, ADR-0009/0010) accepts one kind of
credential: an **API Token** bound to an **Account**. There is no shared secret, and the
Relay's configuration file cannot grant control-plane access at all (ADR-0023).

Every token:

- carries the `glp_` prefix, so a leak is greppable and secret scanners recognize it;
- is stored only as a SHA-256 hash, so it cannot be recovered from the store, a dump, or a
  backup;
- inherits its Account's role at every request, so a demotion or a disable takes effect on the
  next call;
- can be revoked individually, without disturbing any other caller.

## Bootstrapping the first credential

Minting a token requires authenticating, and authenticating requires a token. `relay init`
breaks that cycle from outside the wire, the same way Node Policy is rooted locally
(ADR-0002): it writes directly to the Relay's own store, as the Relay's own account
(ADR-0030).

Start the Relay once first: it creates its CA and store at first start, and `init` acts only on
that store. Then, on the Relay host:

```console
$ sudo -u relay relay init --admin alice
Console password for alice (not echoed):
Again:
Created alice (acct-…), a human admin, with its Console password and its first API Token 7f3c….
Recorded on the audit trail as account_create, password_set and api_token_mint, attributed to local-host.
Now the first Enrollment Token, for the Nodes that join first.
If you abandon this prompt, the admin already exists: relay init --recover alice mints its API Token again.
How many Nodes is it for? (1 to 256): 3
It expires after (default 2h):
The API Token below is shown once and cannot be recovered; a lost one is replaced with relay init --recover.
Keep the Console password safe: no surface resets it, and relay init --recover does not.
glp_7f3c….g7Kx…_Q
…
glp_join_…
```

In a terminal, `init` asks for the first Enrollment Token's count and expiry and shows its join
string after the API Token ([enrollment.md](enrollment.md)). Piped, as in the vault example
below, stdout is not a terminal, so it mints none and stdout carries the API Token alone.
When init mints, do not redirect or capture its output: the join string would land in the
capture. To pipe init's output, give it a non-terminal stdin, and then it mints nothing.

The name is yours to choose; no Account name is reserved. `init` reads `/etc/relay/relay.toml`
(or `--config <path>`) through the same start-time check as the Relay, so it refuses to run as
root, and it creates neither the CA nor the store.

Diagnostics go to stderr and **only the credential goes to stdout**, so you can capture it
straight into a secret store rather than leave it in scrollback or a CI log:

```console
$ sudo -u relay relay init --admin alice | vault kv put secret/relay/alice token=-
```

When stdin is not a terminal, the password is its first line; no flag takes it.

- **It creates the first admin once.** On a Relay that already has any human Account, `init`
  creates nothing, prints no credential, and reports the human admins that exist. Every further
  Account is created through the Control API or the Console.
- **It is safe to run while the Relay is running.** The store is WAL-mode with a busy timeout.
- **Recovery is an explicit request.** `relay init --recover <name>` mints a new API Token for
  an enabled human `admin` who has lost theirs, recorded as `api_token_mint` attributed to
  `local-host`. It never revokes an existing token: revoke the old one deliberately.
- **Recovery refuses a disabled, non-admin or machine Account.** Minting a disabled Account a
  fresh credential would silently reverse the decision to disable it. Re-enable it explicitly
  (as another admin) if that is what you want.
- **Token lifetime.** `--ttl <duration>` (e.g. `24h`) sets the lifetime of the token either
  form mints. Without it the token lives seven days (`168h`); `--ttl 0` means no expiry. Use the
  token to create the Accounts your callers need, then mint yourself a longer-lived token if you
  want one and revoke this one, as below.
- **A Console password is never reset.** `--recover` never touches one, and no surface sets a
  password a human has set. The password `--admin` sets is the first admin's; the admin changes
  it under "Your account" in the Console, proving the current one. A forgotten Console
  password is not recoverable: an admin disables the Account and creates a new one. Other
  human Accounts get a temporary password from an admin in the Console, which they change at
  first sign-in (ADR-0045); a human created through `POST /api/v1/accounts` has none until
  an admin issues one from its Account page in the Console.

## The intended flow

The first admin's credential (`$BOOTSTRAP` below) is a *starting point*, not a service
account. Use it to establish real identities, then retire it once the admin holds a token with
a lifetime:

```console
# 1. Create the Account your orchestrator will be.
$ curl -sS --cacert ca.pem -H "Authorization: Bearer $BOOTSTRAP" \
    -H 'Content-Type: application/json' \
    -d '{"name":"gleipnir","kind":"machine","role":"operator"}' \
    https://relay.example:9443/api/v1/accounts

# 2. Mint it a credential. ttl_seconds may be omitted for a human Account (seven days)
#    and is required for a machine Account; 0 means no expiry.
$ curl -sS --cacert ca.pem -H "Authorization: Bearer $BOOTSTRAP" \
    -H 'Content-Type: application/json' \
    -d '{"name":"gleipnir-prod","ttl_seconds":2592000}' \
    https://relay.example:9443/api/v1/accounts/$ACCOUNT_ID/tokens

# 3. Revoke the bootstrap credential.
$ curl -sS -X DELETE --cacert ca.pem -H "Authorization: Bearer $BOOTSTRAP" \
    https://relay.example:9443/api/v1/api-tokens/$BOOTSTRAP_TOKEN_ID
```

Give each caller its own Account, with the **lowest role that does its job**:

| Role | Can |
|---|---|
| `viewer` | Read: list Nodes, describe them, read Jobs and audit. Dispatches nothing. |
| `operator` | …and run structured Operations (the typed path). |
| `admin` | …and use Raw Exec, and administer Accounts, tokens, enrollment, and the Freeze. |

Raw Exec is admin-only and enforced centrally, so an `operator` token cannot reach the
arbitrary-command path from any surface. Most orchestration is Operations, and only
Operations.

The administrative acts are enforced from the same role ladder:

| Act | Floor |
|---|---|
| Mint or revoke an Enrollment Token | `admin` |
| Revoke a Node | `admin` |
| **Engage** the Freeze | `operator`, **and a human Account** |
| **Release** the Freeze | `admin`, with a non-empty reason |

The one rule that is not a role: **a machine Account can never engage the Freeze**, at any
role including `admin`. Halting the fleet is a fire alarm for people to pull; an AI-agent
stopping the plane that supervises it is a denial of service. Automation that legitimately
needs to stop the fleet does it on the Relay host (`SIGUSR1`), where the authority is root on
the box rather than a stealable credential. Releasing is *not* human-only: an incident must
have an automated way back.

Every one of these refusals is audited as a `refusal`, with the Account and its role, so "who
tried" is answerable as well as "who succeeded".

## Human sessions: OAuth 2.1 through your IdP

API Tokens suit headless drivers. For a **person** connecting their own MCP harness (Claude,
or any off-the-shelf client), the Relay speaks MCP's standard OAuth 2.1 authorization layer,
so the session runs under their identity rather than a shared machine credential.

**The Relay is a protected resource, never an authorization server** (ADR-0024). It validates
tokens your IdP issued; it has no login page, no consent screen, and no token endpoint, and
will not grow them without a new ADR.

### Configuring it

In `relay.toml` (OAuth is served on the control plane, so `control_plane.enabled = true`):

```toml
[oauth]
issuer = "https://idp.example.com"
audience = "https://relay.example.internal:9443/mcp"
public_url = "https://relay.example.internal:9443"
account_claim = "email"
required_scope = "relay.fleet"
```

| Key | Meaning |
|---|---|
| `issuer` | Your IdP's issuer URL. Unset disables OAuth entirely; every other key needs it. |
| `audience` | **Required with `issuer`.** This Relay's resource identifier, checked against every token's `aud`. |
| `public_url` | **Required with `issuer`.** The base URL clients actually dial, used to advertise metadata. |
| `account_claim` | Claim naming the Account a session resolves to. Default `email`. |
| `required_scope` | One scope every token must carry. Unset requires none. |

Discovery happens once, at startup, so a wrong issuer fails the boot instead of every request.
The `[oauth]` section is read only at start: a change needs a restart, not a SIGHUP.

> **`audience` is not a formality.** It is the RFC 8707 binding that stops a token minted for
> some *other* service in the same IdP from driving your fleet. Without it, every application
> sharing your IdP becomes a confused deputy. The Relay refuses to start with an issuer and no
> audience.

### Onboarding a human

Their Account must exist first: **the Relay never auto-creates one from a token claim**.
Otherwise whoever administers the IdP could mint identities on your control plane, and Account
creation is an audited admin act.

```console
# The name must match what the configured claim will carry.
$ curl -sS --cacert ca.pem -H "Authorization: Bearer $ADMIN" \
    -H 'Content-Type: application/json' \
    -d '{"name":"mike","kind":"human","role":"operator"}' \
    https://relay.example.internal:9443/api/v1/accounts
```

They then point their harness at `https://relay.example.internal:9443/mcp` and complete the
flow. The harness discovers the rest: an unauthenticated request gets a `WWW-Authenticate`
challenge pointing at `/.well-known/oauth-protected-resource`, which names your IdP.

That metadata document and the health endpoint (`GET /healthz`, which answers only serving or
not serving) are the routes on the control plane that answer without a credential. The
metadata is unauthenticated because it tells a client how to obtain a credential. It discloses
an issuer URL and a resource identifier, both public by definition.

### What an OAuth session does and does not buy

It buys **attribution and revocation**: audit records the human's Account and marks the
session `oauth` rather than `api_token`, and disabling their Account or their IdP user cuts
them off.

It does **not** buy trust. An OAuth session proves a human authorized the *session*, not that
a human intended each *call*: the calls are generated by a model that may have read
attacker-controlled content. So MCP-originated calls stay agent-grade for approval gating
whoever authorized the session, and authority is still the role of the Account the session
resolves to. Raw Exec still requires `admin`.

An IdP outage affects OAuth sessions only. API Tokens, the first admin's included, are
verified locally, so someone else's downtime never locks you out of your own control plane.

## Rotation, revocation, and recovery

- **Rotate** a caller: mint it a second token, switch the caller over, revoke the first. No
  restart, and no other caller is affected.
- **Revoke** immediately: `DELETE /api/v1/api-tokens/{id}`, effective on the next request.
  Revoking twice is a no-op; revoking an unknown id is a 404.
- **Cut off an identity entirely**: `POST /api/v1/accounts/{id}/disable`. That refuses every
  one of its tokens at once *without revoking any*, so re-enabling restores access. Disabling
  and revoking are deliberately different acts with different blast radii.
- **Lost the plaintext?** There is no recovery: only a hash is stored. Mint a replacement and
  revoke the old one.
- **Locked out entirely** (no working admin token): `relay init --recover <name>` on the Relay
  host re-mints an API Token for any enabled human admin; it does not reset a Console
  password, which nothing does. With no enabled human admin left, an enabled admin of any kind
  re-enables one through the Control API; with none, recovery requires local root on the Relay
  host acting on the store directly. There is deliberately no `--force` flag; see ADR-0023's
  residual note.

## Why SHA-256, not a password KDF

API Tokens are high-entropy, machine-generated bearer material, the same shape as an
Enrollment Token secret (`relay/internal/enroll/token.go`). A fast cryptographic hash compared
in constant time (`crypto/subtle.ConstantTimeCompare`) is the standard choice for that shape;
slow KDFs like bcrypt/argon2 defend low-entropy human secrets. The Admin Console password is
that other shape and makes the other choice: an argon2id hash (`relay/internal/accounts`),
verified by the Console's session layer (`relay/internal/consoleauth`), and set for the first
admin by `relay init` ([relay-install.md](relay-install.md)). The two never substitute for one
another: a password cannot call the API, and an API Token cannot sign in to the Console.
