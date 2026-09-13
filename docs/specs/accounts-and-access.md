# Accounts and access

**Status:** proposed draft, assessed against the code on `2026-09-13`; it is not
authoritative until a human explicitly approves it.

## Purpose

Accounts and access identify a caller of the Relay, establish its credentials, and
apply its authority consistently across the Control API, MCP, and Admin Console.
An **Account** is the durable identity and authorization unit: a human operator or
a machine Account used by an AI-agent, CI job, or other headless driver. Credentials
are revocable ways to authenticate as that Account; they are not authority in their
own right.

This capability makes attribution meaningful. A security-sensitive action can name
the verified Account and, where applicable, the API Token or authentication method
that established it. It does not make a caller's identity a substitute for Node
Policy, approval, or the blast-radius cap.

## Surfaces

| Surface | Current access to the capability |
|---|---|
| **Control API** | Admin-only Account lifecycle endpoints under `/api/v1/accounts`, API Token mint/list under `/api/v1/accounts/{id}/tokens`, and API Token revocation under `/api/v1/api-tokens/{token_id}`. Bearer API Tokens authenticate this surface. |
| **MCP** | A per-Account API Token authenticates a headless caller. When configured, the endpoint is also an OAuth 2.1 protected resource: it publishes protected-resource metadata and accepts a verified external-IdP token that resolves to an existing Account. MCP does not expose Account or API Token administration. |
| **Admin Console** | Human Accounts can sign in with a local password, establish a Console-only session, and sign out. Existing Console routes receive that session and its Account role. The Accounts and API Tokens administration screen described in `docs/design/console/15-accounts-and-tokens.md` is v0.7.0 work (#433), not current behaviour. |
| **Local operator** | `relay bootstrap-token` creates an API Token for the stored founding admin using local access to the Relay store. It is the bootstrap escape from the authentication cycle and is not a network surface. |

## Behaviour

### Accounts and roles

An Account has a unique normalized name, a kind (`human` or `machine`), one of the
closed roles `viewer`, `operator`, or `admin`, an enabled state, and non-secret
timestamps. The Account's current role is the authority for every credential that
resolves to it. A role change therefore takes effect on existing API Tokens without
reissuing them; disabling an Account cuts off its live API Tokens and Console
sessions on their next use.

The roles are coarse and fixed: `viewer` is read authority, `operator` can request
Operations and lifecycle work, and `admin` additionally has Raw Exec and Account
administration authority. A role grants no permission beyond the relevant capability
gate, and never overrides the relay-daemon's live Policy decision.

The Control API creates, lists, reads, re-roles, enables, and disables Accounts.
Those endpoints currently require an authenticated `admin`; their successful writes
record the acting principal in the audit trail. The API refuses an Account changing
its own role or disabling itself. The founding-admin name is reserved and cannot be
created through the API.

### API Tokens

An API Token belongs to exactly one Account and has a non-secret ID, name, creation
time, optional expiry, last-use time, and revocation state. At mint, the caller must
explicitly choose a TTL; zero means no expiry. The plaintext `glp_…` credential is
returned in the mint response exactly once. Relay stores and subsequently exposes
neither its plaintext nor its hash.

At authentication, a valid, unexpired, unrevoked API Token resolves to its enabled
Account and current role. API Token verification updates the token's last-use time
without changing its authority. Revocation is idempotent and takes effect before the
next request authenticated with that token. Listing Tokens provides only their
redacted lifecycle data. An `admin` may revoke its own Token.

The local `bootstrap-token` command follows the same reveal-once model. It creates
an additive Token for the founding admin, refusing if that Account is disabled; it
does not silently replace a working credential.

### OAuth and MCP attribution

Relay is an OAuth 2.1 protected resource, never an authorization server. When OAuth
is configured locally, Relay verifies an external IdP token's signature, issuer,
audience, expiry, configured subject claim, and optional required scope. The verified
claim must map to an already-existing enabled Account; Relay does not auto-provision
an Account from an IdP claim. The Account's role remains the authorization authority.

OAuth and API Token inputs are routed by credential kind rather than being tried as
alternative interpretations of the same input. An OAuth-authenticated principal is
marked as OAuth in the verified audit lane and has no API Token ID. API Tokens remain
locally verifiable when an IdP is unavailable.

An OAuth session on MCP proves that a human authorized that *session*. MCP calls
remain agent-grade for approval: OAuth attribution does not prove a human intended
an individual model-generated call and does not raise its approval channel.

### Console authentication and step-up

The Console's current local sign-in accepts only an enabled human Account with a
local password. Successful sign-in retires any presented session identifier, creates
a new Console-only session, and records the verified Account, method, and source.
The session cookie is host-only, Secure, HttpOnly, SameSite=Strict, and accompanied
by a session-bound CSRF secret for unsafe Console requests. Console sessions do not
authenticate `/api/v1` or MCP; Bearer credentials do not become Console sessions.

Unknown Account, disabled Account, machine Account, absent password, corrupt stored
password hash, and wrong password have one indistinguishable sign-in refusal. Login
and step-up throttling are recorded without naming a verified Account. Sign-out ends
the server-side session; disabling an Account also makes an already-issued Console
session unusable.

The Console authentication service can perform password step-up and records success,
failure, and throttling separately from sign-in. Its freshness window is root-owned
Relay configuration. **No current Accounts administration route consumes that
step-up capability.** The proposal for #433 is that creating an Account, changing a
role, minting a Token, and re-enabling an Account require step-up and audit; that is
designed behaviour requiring human approval and implementation, not a claim about
today's Control API.

## Refusals

| Refusal | Current behaviour |
|---|---|
| Missing, malformed, expired, revoked, disabled, or otherwise invalid API Token | Authentication fails with one generic unauthorized response, without identifying the failing check. |
| Non-admin Account lifecycle request | The Control API returns an admin-required refusal. |
| Invalid Account name, kind, or role; duplicate or reserved Account name | The create or update request is refused; names remain unique and the founding admin cannot be shadowed. |
| Self role change or self-disable | The Control API refuses the mutation to avoid the direct self-lockout path. |
| Token mint for a disabled or missing Account, missing TTL, invalid TTL, or invalid Token request | The Control API refuses minting and does not issue a credential. |
| Unknown API Token at revocation | The Control API reports that the Token was not found; an already-revoked Token is accepted as the requested end state. |
| OAuth token failing any Relay check, unknown subject, disabled Account, absent required scope, or OAuth not configured | The MCP authentication path refuses without revealing which check failed; an unconfigured Relay publishes no OAuth metadata. |
| Console sign-in failure | The Console returns the same credential failure for all identity or password failures; a throttle says when another attempt may be made. |
| Machine Account attempting Console local-password sign-in | It is refused as the same indistinguishable Console credential failure. |

## Governing ADRs and invariants

- **ADR-0010** — defines the unified Account model, fixed role ladder, credential-to-Account
  binding, and the rule that credentials do not override Node Policy.
- **ADR-0023** — retires the shared control-plane credential: the accepted network
  credential is a per-Account API Token, while local root performs bootstrap.
- **ADR-0024** — makes Relay an OAuth protected resource only, requires existing-Account
  mapping, and preserves API Token authentication for headless callers.
- **ADR-0009** and **ADR-0026** — bind the Console to the shared capability layer and
  require step-up for Console privilege grants and mutate applies respectively. #433 has
  not yet made its Account administration behaviour current.
- **ADR-0027** — OAuth/MCP session attribution does not make individual MCP calls
  human-grade for approval.
- **ADR-0028** — MCP is stateless; a machine Account has recent activity, never a
  durable connected session to terminate.
- **ADR-0035** — account suspension is deferred and imposes no current state or route.
- **Invariant 10** — surface adapters must not create a parallel authorization or
  dispatch path; durable Account authority must remain consistent across surfaces.
- **Invariant 11** — OAuth issuer, audience, scope, and Console step-up freshness are
  root-owned Relay configuration, never API-managed runtime objects.

## Seams and proof

The Accounts domain and Token service own Account/Token state and verification. The
control-plane authenticator resolves a credential to a principal; adapters consume
that principal and their route roles. Console session and step-up state is separate
from bearer-token authentication. The Account administration Console will need to
call the same lifecycle capability rather than reproduce its own role or audit logic.

`make verify` is sufficient for a documentation-only change. Changes to authentication,
OAuth configuration, Console sessions, or Account lifecycle are security-sensitive and
should also exercise their focused tests; integration verification is appropriate if
composition-root configuration changes.

### What proves each claim

| Behaviour | Proven by | Seam |
|---|---|---|
| An admin can create an Account and mint its Token end to end | `TestIdentityAPI_AdminCreatesAccountAndMintsTokenEndToEnd` | API |
| Non-admin callers cannot use Account lifecycle endpoints | `TestIdentityAPI_NonAdminIsRefusedEveryIdentityEndpoint` | API |
| A Token plaintext occurs only in its mint response | `TestIdentityAPI_PlaintextAppearsOnlyInTheMintResponse` | API |
| Token revocation cuts access and Account disablement cuts tokens off | `TestIdentityAPI_AccountTokenAuthenticatesAndRevocationCutsAccess` | API |
| Self-disable and self-re-role are refused | `TestIdentityAPI_SelfDisableAndSelfRoleAreRefused` | API |
| A Token inherits Account role and enablement | `TestAPIToken_InheritsAccountRoleAndDisablement` | capability |
| OAuth resolves only a valid token to an existing Account and uses that Account's role | `TestOAuth_ValidTokenResolvesToItsAccount` and `TestOAuth_AuthorityIsTheAccountsRole` | MCP |
| OAuth rejections are indistinguishable and never auto-provision an Account | `TestOAuth_EveryRejectionIsIndistinguishable` and `TestOAuth_UnknownSubjectIsNotProvisioned` | MCP |
| Credential kinds are routed rather than tried in turn | `TestOAuth_CredentialKindsAreRoutedNotTried` | MCP |
| Console sign-in establishes a secure session and does not enumerate Accounts | `TestConsole_SignInIssuesASessionAndLands` and `TestConsole_SignInIsIndistinguishableAcrossFailures` | Console |
| A disabled Account's Console session stops working | `TestConsole_DisablingAnAccountEndsItsConsoleSession` | Console |
| Step-up requires a credential and is audited independently | `TestStepUp_RefreshesPresenceOnlyWithACredential` and `TestStepUp_SucceedsUnderItsOwnAuditKind` | Console |

### Performance

| Characteristic | Contract | Measured by |
|---|---|---|
| API Token verification | Credential checks remain local to Relay and do not depend on IdP availability. | *(none)* |
| OAuth verification | Uses cached/discovered IdP verification material; no latency contract is specified. | *(none)* |
| Account and Token listing | No pagination or scale contract is currently specified. | *(none)* |

## Out of scope

- Relay is not an OAuth authorization server: no Relay token issuer, consent screen,
  authorization endpoint, client registration, or refresh-token service.
- Group/team federation and per-Token scopes are not current behaviour. A future Grant
  may narrow permissions, but it cannot widen Node Policy.
- Account suspension is deferred; revoking API Tokens, disabling an Account, and Freeze
  are distinct existing controls with different effects.
- API-managed identity-provider, role-ladder, step-up-window, listener, TLS, or other
  Relay configuration is forbidden by invariant 11.
- Node identity and enrollment credentials belong to enrollment, not Accounts and access.

## Open questions

| Question | Classification | What forces the call |
|---|---|---|
| Does Account lifecycle authorization already satisfy invariant 10's single capability-layer requirement, or must #433 first introduce a shared lifecycle authorization seam? | Blocks #433 design | An architect needs a surface-parity design for the Console without treating the Control API's route gate as the lasting source of truth. |
| Which actions beyond the four named in the Console design are privilege-granting and must demand step-up (disablement, Token revocation, password management, bootstrap recovery)? | Blocks #433 implementation | The human-approved Account administration spec must define the complete mutation matrix before decomposition. |
| What Console OIDC browser flow, if any, joins the existing local-password session flow? | Follow-up | A human chooses whether external browser identity is needed; `console_oidc` is reserved but not implemented. |
| What limits, pagination, and audit-query disclosure apply to Account and Token listings? | Follow-up | Expected fleet/operator scale or an audit/read-lane specification requires a caller-visible contract. |
| Is preventing removal or demotion of the final enabled admin required, beyond the current self-target guard? | Blocks destructive Account lifecycle expansion | A human must choose the recovery and local-root model; current code permits another admin to make that state. |

## History

- `2026-09-13` — proposed draft assembled from current contracts, code, ADRs, Console design,
  and #433; awaiting explicit human approval.
