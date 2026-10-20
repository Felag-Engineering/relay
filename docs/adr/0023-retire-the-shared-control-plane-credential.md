# Retire the shared control-plane credential; bootstrap the first Account token locally

**Status:** Accepted.

The control plane (MCP + `/api/v1`) was protected by a single **config-seeded bearer
credential**: its SHA-256 hash in a root-owned file, its plaintext in the operator's vault,
and every caller presenting the same string. That was the right staged choice while there
were no Accounts to authenticate as (ADR-0010's staged authz). With Accounts (#295), API
Tokens (#296), and both on the wire (#297), this ADR retires the shared credential and records
the bootstrap path that replaces it.

## Why the shared credential has to go, not just be deprecated

A shared secret is not a weaker per-Account credential; it quietly defeats three properties
the rest of the system now provides.

- **It cannot attribute.** Every caller presenting it is the same principal. "Which
  orchestrator ran this?" has no answer, and the audit trail's attribution — the thing
  ADR-0004 and ADR-0010 build on — is honest only as far as the credential is unshared.
- **It cannot be revoked in isolation.** Cutting off one caller means rotating the secret
  and restarting the Relay, which cuts off *everyone*. During an incident that is exactly
  backwards: the compromised caller and the responders lose access together.
- **It cannot be scoped.** With #298's role ladder, authority is a property of an Account.
  A credential that resolves to one hardcoded admin identity can only ever be admin, so
  every caller holding it gets Raw Exec whether it needs it or not.

Keeping it alongside Account tokens would keep all three problems and add a second
authentication path — and the weaker path is the one an attacker chooses.

## Decisions

- **The control plane accepts exactly one kind of credential: a per-Account API Token.**
  `controlplane.Authenticator` holds no digest and no secret material of any kind; it
  delegates to a `TokenVerifier` and nothing else. There is no fallback path, no
  compatibility mode, and no configuration that re-enables the old behaviour.
- **The credential leaves Relay configuration entirely.** `-control-credential-hash-file`
  / `RELAY_CONTROL_CREDENTIAL_HASH_FILE` and the `relay hash-credential` subcommand are
  removed. Invariant 11 said the API may never reach Relay configuration; this makes the
  weaker statement true as well — there is no longer a credential *in* configuration for
  anything to reach.
- **The first credential is rooted locally, not over the wire.** `relay bootstrap-token`
  mints an API Token for the founding admin Account by writing to the Relay's own store
  file, and prints the plaintext to stdout exactly once.
- **`bootstrap-token` refuses a disabled founding admin.** An operator who disabled that
  Account retired its authority deliberately; minting it a fresh credential would reverse a
  security decision at the moment nobody is watching. Re-enabling is an explicit act,
  through the API, by another admin.
- **Every `bootstrap-token` run is additive.** It mints a new token and never revokes an
  existing one, so recovering from a lost plaintext cannot silently break a credential that
  is still in use. Revocation stays a deliberate act.

## Why local root is the right trust root for bootstrap

Minting an Account's token requires authenticating, and authenticating requires a token.
Something has to break the cycle from outside the wire protocol.

ADR-0002 answers the same shape for Node Policy: **root the authority locally.**
`bootstrap-token` requires read/write access to the Relay's
store file, which is root-owned. Anyone who can run it can already edit that SQLite file
directly — insert an Account, set a role, write a token hash. The subcommand therefore
grants **no authority local root did not already have**; it makes the intended path a
documented one-liner instead of a hand-rolled SQL edit — the difference between an operator
doing the safe thing and improvising.

It is safe to run while the Relay is serving: the store is opened WAL-mode with a busy
timeout, so a second process writes without stopping the first.

## Alternatives considered

- **Keep the seeded credential as a bootstrap-only fallback.** Rejected: it leaves the
  weaker authentication path permanently in place, and "bootstrap-only" is a convention, not
  a mechanism — nothing would stop it becoming the credential everyone uses, as it was while
  it was the only option.
- **Seed a *token* from config instead of a credential** (the hash of an API Token in the
  config file). Rejected: it reproduces the shared secret with extra steps. The token would
  still live in configuration, still be un-revocable without a config change and restart,
  and still be presented by whoever holds the file.
- **Print a one-time bootstrap token to the log on first start.** Rejected: it writes a
  live credential into the log stream — the one place we have worked hardest to keep
  secrets out of (`docs/security/secret-handling-audit.md`) — and it is unavailable on
  demand, so a lost plaintext means recreating the store.
- **A network bootstrap endpoint, unauthenticated on first run.** Rejected: an
  unauthenticated write path on the control plane, however briefly open, is exactly the
  surface this system exists to avoid. "Only until first use" is a race, not a boundary.

## Consequences

- **This is a breaking operator change.** An existing deployment must run
  `relay bootstrap-token` and switch its callers to the printed credential; the
  credential-hash file and its flag are gone, and a Relay started with the old flag will
  refuse the unknown argument. `docs/operations/control-plane-credential.md` is rewritten
  around the new path.
- **Bootstrap credentials are real credentials.** The printed token is an admin credential
  with no expiry unless `-ttl` says otherwise. The documented flow is: bootstrap → create
  your real Accounts and mint their tokens → revoke the bootstrap token.
- **Residual: total lockout is possible, and deliberately not papered over.** Disable the
  founding admin, revoke every other admin's token, and there is no in-band way back —
  `bootstrap-token` will refuse, by design. Recovery requires local root and a direct store
  edit, which is the same access the bootstrap path already assumes. We prefer that to a
  `-force` flag that would make "the off-switch can be flipped back on by anyone with a
  shell" a supported, discoverable feature.
- **The plaintext reaches the operator's terminal or their IaC run.** Same exposure as an
  Enrollment Token mint. The docs tell operators to capture it directly into their secret
  store rather than let it sit in scrollback or a CI log.
