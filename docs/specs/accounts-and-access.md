# Accounts and access

**Status:** aspirational — worked through with the owner, last confirmed `2026-09-19`. Describes
intended behaviour, not the code (see the establishing phase in `README.md`). Migration to the
claim format was deferred until #655 landed; it landed as #662 on 2026-09-20 (the Accounts write
routes, step-up, reveal-once token mint), so this spec is ready to migrate and is sixth in
#587's order.

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

| Surface | Access to the capability |
|---|---|
| **Control API** | Admin-only Account lifecycle endpoints under `/api/v1/accounts`, API Token mint/list under `/api/v1/accounts/{id}/tokens`, and API Token revocation under `/api/v1/api-tokens/{token_id}`. Bearer API Tokens authenticate this surface. |
| **MCP** | A per-Account API Token authenticates a headless caller. When configured, the endpoint is also an OAuth 2.1 protected resource: it publishes protected-resource metadata and accepts a verified external-IdP token that resolves to an existing Account. MCP does not expose Account or API Token administration. |
| **Admin Console** | Human Accounts sign in with a local password, establish a Console-only session, and sign out. Console routes receive that session and its Account role. The Accounts and API Tokens administration screen is built: the read half in #660, the write routes with step-up and the reveal-once token mint in #662; its step-up matrix is settled below and the migration session maps each row to its test. That screen is `admin`-only: a `viewer` is not shown it and cannot reach it. |
| **Local operator** | `relay bootstrap-token` creates an API Token for the stored founding admin using local access to the Relay store. It is the bootstrap escape from the authentication cycle, and the recovery path when no enabled `admin` can act. It is not a network surface. Designed for v0.6.5: `relay init` replaces it, recovery role included, as an explicit request naming an enabled human `admin`; the first admin is then the Account the operator names at `init` on an empty store, and no name is reserved (`relay-configuration.md`, RC-28; ADR-0030, amended 2026-10-16). |

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

**The role is the only Relay-side limit on an Account in the first pass.** An `operator`
machine Account may request any Operation against any Node its role allows, bounded by Freeze,
the blast-radius cap, approval and Node Policy — and by nothing narrower. Narrowing an Account
below its role is Future work.

### What each role may do elsewhere

Other capabilities decide these, each in the capability layer; they are gathered here so a
role's reach can be read in one place.

| Act | Floor | Settled in |
|---|---|---|
| Read the registry, vocabulary and audit metadata | `viewer` | `query.md`, `audit-and-read-lane.md` |
| Request an Operation | `operator` | `execution.md` |
| Request Raw Exec | `admin` | `execution.md` |
| Cancel any Job, not only one's own | `operator`, **human Account only** | `execution.md` |
| Cancel a Job it requested | `operator`, machine Account | `execution.md` |
| Add and remove `tag:` labels, on every surface including MCP | `operator` | `selectors-and-labels.md` |
| Engage a Freeze over the Control API | `operator`, **human Account only** | `freeze.md` |
| Release a Freeze over the Control API | `admin`, with a reason | `freeze.md` |
| Decide an approval | the role floor the Action required | `approval.md` |
| Issue an approval grant | second-person, out-of-band approval | `approval.md` |
| Mint an Enrollment Token | `admin` | `enrollment.md` |
| Administer Accounts and API Tokens | `admin` | this spec |

### Account administration

The Control API creates, lists, reads, re-roles, enables, and disables Accounts.
Those acts require an authenticated `admin`; their successful writes record the acting
principal in the audit trail. An Account may not change its own role or disable itself.
That refusal is decided in the capability layer, because deciding it needs the acting principal's
identity, which the Accounts repository never sees.
The founding-admin name is reserved and cannot be created through any surface. The reservation
ends when `relay init` lands: the first admin is then named by the operator and nothing is
reserved against any creation path (ADR-0030, amended 2026-10-16; `relay-configuration.md`, RC-28).

**The last enabled `admin` cannot be disabled or demoted,** by itself or by another Account.
The Relay always keeps at least one enabled `admin`; if none can act, recovery is
`relay bootstrap-token` on the Relay host. This refusal is enforced atomically by the Accounts
repository, and the capability layer reports it rather than re-deriving it: the rule is a count
over every Account, so a check made above the repository races a concurrent writer, and two
Accounts demoting each other can both read "another admin exists" and both succeed.

What it guarantees is one enabled `admin` **record**, which is not the same as one `admin` that
can authenticate: revoking that Account's last Token locks the control plane out just as
effectively. Recovery is then `relay bootstrap-token` only while the founding admin is enabled —
otherwise it is local root on the store (ADR-0023), which that ADR accepts on the record rather
than papering over.

**Account administration is authorized in the capability layer,** once, for every surface
(invariant 10). No Control API route reaches Account or Token state except through that
capability, so a route added later cannot reach it ungated. Account administration cannot be
wired at all without a real authorizer and a real audit trail: a Relay assembled without either
refuses to start rather than serving the surface unfloored.

### API Tokens

An API Token belongs to exactly one Account and has a non-secret ID, name, creation
time, optional expiry, last-use time, and revocation state. At mint, the caller must
explicitly choose a TTL; zero means no expiry, so a configured AI-agent can stay connected
without routine human re-authentication. The plaintext `glp_…` credential is
returned in the mint response exactly once. Relay stores a hash of the secret
component and never the plaintext, and exposes neither afterwards: no read, list, or
audit surface returns the plaintext or the hash.

At authentication, a valid, unexpired, unrevoked API Token resolves to its enabled
Account and current role. API Token verification updates the token's last-use time
without changing its authority. Revocation is idempotent and takes effect before the
next request authenticated with that token. Listing Tokens provides only their
redacted lifecycle data. Revoking a Token requires an authenticated `admin` and no step-up: it
only reduces privilege, and an incident instrument that costs a password is one people route
around. An `admin` may revoke its own Token.

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

### Console authentication

The Console's local sign-in accepts only an enabled human Account with a
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

### Console step-up

The Console authentication service performs password step-up and records success, failure, and
throttling separately from sign-in. Its freshness window is root-owned Relay configuration.

**Privilege-granting Account administration in the Console requires a fresh step-up**, and each
is audited:

- creating an `admin` Account;
- raising an Account's role;
- re-enabling a disabled Account;
- minting an API Token for another Account;
- resetting another human Account's Console password.

**Only an `admin` may reset another Account's password.** In the first pass the admin sets the new
password directly; an emailed self-service reset link is Future work. Setting another person's
password is an Account-takeover path, which is why it sits in this matrix.

Acts that only reduce privilege — disabling an Account, lowering a role, revoking a Token — do not
require step-up. This is the matrix #655 implements.

## Refusals

| Refusal | Behaviour |
|---|---|
| Missing, malformed, expired, revoked, disabled, or otherwise invalid API Token | Authentication fails with one generic unauthorized response, without identifying the failing check. |
| Non-admin Account administration request | Refused as admin-required, on every surface. |
| Invalid Account name, kind, or role; duplicate or reserved Account name | The create or update request is refused; names remain unique and the founding admin cannot be shadowed. |
| Self role change or self-disable | Refused, to avoid the direct self-lockout path. |
| Disabling or demoting the last enabled `admin` | Refused; the Relay always keeps one enabled `admin`. |
| Privilege-granting Console act without a fresh step-up | Refused until the Account steps up. |
| Token mint for a disabled or missing Account, missing TTL, invalid TTL, or invalid Token request | Minting is refused and no credential is issued. |
| Unknown API Token at revocation | Reported as not found; an already-revoked Token is accepted as the requested end state. |
| OAuth token failing any Relay check, unknown subject, disabled Account, absent required scope, or OAuth not configured | The MCP authentication path refuses without revealing which check failed; an unconfigured Relay publishes no OAuth metadata. |
| Console sign-in failure | The same credential failure for all identity or password failures; a throttle says when another attempt may be made. |
| Machine Account attempting Console local-password sign-in | Refused as the same indistinguishable Console credential failure. |

## Governing ADRs and invariants

- **ADR-0010** — defines the unified Account model, fixed role ladder, credential-to-Account
  binding, and the rule that credentials do not override Node Policy.
- **ADR-0023** — retires the shared control-plane credential: the accepted network
  credential is a per-Account API Token, while local root performs bootstrap.
- **ADR-0024** — makes Relay an OAuth protected resource only, requires existing-Account
  mapping, and preserves API Token authentication for headless callers.
- **ADR-0009** and **ADR-0026** — bind the Console to the shared capability layer and require
  step-up for Console privilege grants and mutate applies respectively. The step-up matrix above
  is what the privilege-grant half means for Account administration.
- **ADR-0027** — OAuth/MCP session attribution does not make individual MCP calls
  human-grade for approval.
- **ADR-0028** — MCP is stateless; a machine Account has recent activity, never a
  durable connected session to terminate.
- **ADR-0013** — a Freeze is engaged over the API only by a human Account.
- **ADR-0035** — account suspension is deferred and imposes no state or route.
- **Invariant 10** — Account administration is authorized once in the capability layer, as the
  invariant requires of every decision. Where a surface exposes Account administration, it adapts
  that one decision and reproduces no part of it.
- **Invariant 11** — OAuth issuer, audience, scope, and Console step-up freshness are
  root-owned Relay configuration, never API-managed runtime objects.

## Seams and proof

The Accounts domain and Token service own Account/Token state and verification. The
control-plane authenticator resolves a credential to a principal; adapters consume
that principal. Console session and step-up state is separate from bearer-token
authentication. Account administration authorization belongs in the capability layer, so the Control API and the
Console screen (#654, #655) call the same lifecycle capability rather than reproducing role or
audit logic.

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
| Self-disable and self-re-role are refused | `TestIdentityAPI_SelfDisableAndSelfRoleAreRefused`, and at the shared seam `TestAccountAdmin_SelfRoleChangeIsRefused` and `TestAccountAdmin_SelfDisableIsRefused` | API, capability |
| Account administration is authorized in the capability layer, and no surface re-derives it | `TestRoleGate_AccountAdministrationRequiresAdmin` and `TestCapabilityFlooredRoutesDoNotReachASurfaceGate` | capability, API |
| The last enabled `admin` cannot be disabled or demoted | `TestRepositoryConformance` (both Repository implementations), `TestSQLiteAccounts_LastAdminGuardIsASingleStatement`, `TestSQLiteAccounts_ConcurrentDemotionsLeaveOneEnabledAdmin`, and `TestAccountAdmin_LastAdminRefusalSurvivesTheRealStore` | store, capability |
| Account administration cannot be wired without a real authorizer and a real audit sink | `TestNewRefusesAccountAdminWithoutARealAuthorizer` | composition |
| A Token inherits Account role and enablement | `TestAPIToken_InheritsAccountRoleAndDisablement` | capability |
| OAuth resolves only a valid token to an existing Account and uses that Account's role | `TestOAuth_ValidTokenResolvesToItsAccount` and `TestOAuth_AuthorityIsTheAccountsRole` | MCP |
| OAuth rejections are indistinguishable and never auto-provision an Account | `TestOAuth_EveryRejectionIsIndistinguishable` and `TestOAuth_UnknownSubjectIsNotProvisioned` | MCP |
| Credential kinds are routed rather than tried in turn | `TestOAuth_CredentialKindsAreRoutedNotTried` | MCP |
| Console sign-in establishes a secure session and does not enumerate Accounts | `TestConsole_SignInIssuesASessionAndLands` and `TestConsole_SignInIsIndistinguishableAcrossFailures` | Console |
| A disabled Account's Console session stops working | `TestConsole_DisablingAnAccountEndsItsConsoleSession` | Console |
| Step-up requires a credential and is audited independently | `TestStepUp_RefreshesPresenceOnlyWithACredential` and `TestStepUp_SucceedsUnderItsOwnAuditKind` | Console |

Claims above with **no row**, and so nothing checking them:

- That an Account's authority is applied consistently across the Control API, MCP, and the
  Console. Each surface proves its own gate; no cross-surface authorization-parity test
  asserts that they agree — the same gap `query.md` records for the read floor.
- That the four privilege-granting Console acts require a fresh step-up, and that
  privilege-reducing acts do not. Not built; the Console write routes are #655. The step-up
  machinery itself exists and is exercised, but no route consults the step-up freshness window.
- That the founding-admin name is reserved against every creation path, rather than the
  Control API route alone.
- That `relay bootstrap-token` is additive and refuses a disabled founding admin. The
  command implements both; no named test is cited here for either.
- That the role floors gathered in *What each role may do elsewhere* hold. Each is owned, and
  proven or listed as unproven, by the spec named in that table.

### Performance

| Characteristic | Contract | Measured by |
|---|---|---|
| API Token verification | Credential checks remain local to Relay and do not depend on IdP availability. | *(none)* |
| OAuth verification | Uses cached/discovered IdP verification material; no latency contract is specified. | *(none)* |
| Account and Token listing | No pagination or scale contract is specified. | *(none)* |

## Out of scope

- Relay is not an OAuth authorization server: no Relay token issuer, consent screen,
  authorization endpoint, client registration, or refresh-token service.
- Group/team federation and per-Token scopes are not first-pass behaviour (Future work). A
  narrowing mechanism may narrow permissions; it can never widen Node Policy.
- Account suspension is deferred; revoking API Tokens, disabling an Account, and Freeze
  are distinct controls with different effects.
- API-managed identity-provider, role-ladder, step-up-window, listener, TLS, or other
  Relay configuration is forbidden by invariant 11.
- Node identity and enrollment credentials belong to `enrollment.md`.
- What each role floor *does* inside another capability — cancellation, tagging, Freeze,
  approval — is owned by that capability's spec.

## Accepted residual risk

- **An Account's role is its whole Relay-side authority.** A machine Account at `operator` may
  request any Operation against any Node its role allows; only Freeze, the blast-radius cap,
  approval and Node Policy bound it.
- **A no-expiry API Token is a standing bearer credential.** Chosen so a configured AI-agent stays
  connected; a stolen one is live until it is revoked or its Account is disabled.
- **Total lockout remains possible.** The last-admin refusal keeps one enabled `admin` record, not
  one `admin` that can authenticate; disabling the founding admin and revoking every other admin's
  Token leaves no in-band way back, and `relay bootstrap-token` refuses by design. Accepted by the
  owner in ADR-0023 §Consequences, which declines to paper it over; the compensating control is
  local root on the Relay host.

## Future work

Wanted, deliberately not in the first pass. Named so each is neither re-litigated nor lost;
none is a commitment to an order.

- **Narrowing an Account below its role (research, #578).** Per-Token scope, authorization Grants
  over Operations × Selectors, and machine authentication stronger than a long-lived bearer API
  Token — and on which engine (#285 proposes Cedar, evaluated jointly with the approval-rule
  grammar). Any answer must keep a configured AI-agent connected without routine human
  re-authentication, and a Grant used as a security boundary is narrows-only and `relay:`-scoped
  (`docs/deferred.md`). Unrelated to an approval grant despite the name.
- **Console OIDC sign-in.** An external browser identity flow beside local passwords;
  `console_oidc` is reserved and unimplemented.
- **Emailed password reset.** A reset link sent to the Account holder instead of an admin setting
  the password directly.
- **Per-Account rate limits (#279).** Bounding a runaway AI-agent loop in time as well as in blast
  radius.
- **IdP group claims for approval audiences** and `on_behalf_of`, joined to the existing-Account
  OAuth mapping. `docs/deferred.md` names IdP-federated teams as the direction and rules out a
  native Relay org chart.

## Open questions

| Question | Classification | What forces the call |
|---|---|---|
| What limits, pagination, and audit-query disclosure apply to Account and Token listings? | Follow-up | Expected operator scale, or #654's screen needing a caller-visible contract. |
