# Accounts and access

**Status:** aspirational — worked through with the owner, last confirmed `2026-09-19`. Describes
intended behaviour, not the code (see the establishing phase in `README.md`). Ready to migrate
to the claim format.

## Purpose

Accounts and access identify a caller of the Relay, establish its credentials, and apply its
authority consistently across the Control API, MCP, and Admin Console. An **Account** is the
durable identity and authorization unit: a human operator, or a machine Account used by an
AI-agent, CI job, or other headless driver. Credentials are revocable ways to authenticate as
an Account, not authority in their own right.

This makes attribution meaningful: a security-sensitive action names the verified Account and,
where applicable, the API Token or authentication method behind it. A caller's identity is
never a substitute for Node Policy, approval, or the blast-radius cap.

## Surfaces

| Surface | Access to the capability |
|---|---|
| **Control API** | Admin-only Account lifecycle endpoints under `/api/v1/accounts`, API Token mint/list under `/api/v1/accounts/{id}/tokens`, and API Token revocation under `/api/v1/api-tokens/{token_id}`. Bearer API Tokens authenticate this surface. |
| **MCP** | A per-Account API Token authenticates a headless caller. When configured, the endpoint is also an OAuth 2.1 protected resource: it publishes protected-resource metadata and accepts a verified external-IdP token that resolves to an existing Account. MCP does not expose Account or API Token administration. |
| **Admin Console** | Human Accounts sign in with a local password, establish a Console-only session, and sign out. Console routes receive that session and its Account role. The Accounts and API Tokens administration screen, with step-up and the reveal-once token mint, is `admin`-only: a `viewer` is not shown it and cannot reach it. |
| **Local operator** | `relay init --admin <name>`, on a store with no human Account, creates the first human `admin` with that name, its Console password and its first API Token; no name is reserved. `relay init --recover <name>` mints a new API Token for an enabled human `admin` who has lost every Token. It is the bootstrap escape from the authentication cycle and the recovery path, using local access to the Relay store; it is not a network surface (`relay-configuration.md`, RC-28; ADR-0030, amended 2026-10-16). |

## Behaviour

### Accounts and roles

An Account has a unique normalized name, a kind (`human` or `machine`), one of the closed roles
`viewer`, `operator`, or `admin`, an enabled state, and non-secret timestamps. Its current role
is the authority for every credential that resolves to it, so a role change takes effect on
existing API Tokens without reissuing them, and disabling an Account cuts off its live API
Tokens and Console sessions on their next use.

The roles are coarse and fixed: `viewer` reads, `operator` can also request Operations and
lifecycle work, and `admin` additionally has Raw Exec and Account administration. A role grants
nothing beyond the relevant capability gate and never overrides the relay-daemon's live Policy
decision.

**The role is the only Relay-side limit on an Account in the first pass.** An `operator`
machine Account may request any Operation against any Node its role allows, bounded by Freeze,
the blast-radius cap, approval and Node Policy — and by nothing narrower. Narrowing an Account
below its role is Future work.

### What each role may do elsewhere

Other capabilities decide these, each in the capability layer; they are gathered here so a
role's reach reads in one place.

| Act | Floor | Settled in |
|---|---|---|
| Read the registry, vocabulary and audit metadata | `viewer` | `query.md`, `audit-and-read-lane.md` |
| Request an Operation, over MCP or the Control API | `operator` | `execution.md` |
| Request Raw Exec | `admin` | `execution.md` |
| Cancel any Job, not only one's own | `operator`, **human Account only** | `execution.md` |
| Cancel a Job it requested | `operator`, machine Account | `execution.md` |
| Add and remove `tag:` labels, on the Console and the Control API | `operator`, **human Account only** | `selectors-and-labels.md` |
| Engage a Freeze over the Control API | `operator`, **human Account only** | `freeze.md` |
| Release a Freeze over the Control API | `admin`, with a reason | `freeze.md` |
| Decide an approval | the role floor the Action required | `approval.md` |
| Issue an approval grant | second-person, out-of-band approval | `approval.md` |
| Mint an Enrollment Token | `admin` | `enrollment.md` |
| Set, rename or clear a Policy alias (designed, not built) | `admin`, **human Account only** | `query.md` |
| Administer Accounts and API Tokens | `admin` | this spec |

The Console requests no Operation and no Raw Exec: it watches and does not execute (ADR-0052).

**Tag writes are a human act** (ADR-0050). A human Account at `operator` or above adds and
removes `tag:` labels on the Console and the Control API. A machine Account may not, whatever
its role, and no MCP tool writes a tag. The capability layer decides this once for both
surfaces (invariant 10).

### Account administration

The Control API creates, lists, reads, re-roles, enables, and disables Accounts. Those acts
require an authenticated `admin`, and each successful write records the acting principal in the
audit trail. An Account may not change its own role or disable itself; the capability layer
decides that, because it needs the acting principal's identity, which the Accounts repository
never sees. No Account name is reserved against any creation path (ADR-0030, amended
2026-10-16).

**The last enabled `admin` cannot be disabled or demoted,** by itself or by another Account.
If none can act, recovery is `relay init --recover` on the Relay host. The Accounts repository
enforces this refusal atomically and the capability layer reports it rather than re-deriving
it: the rule is a count over every Account, so a check above the repository races a concurrent
writer — two Accounts demoting each other could both read "another admin exists" and both
succeed.

It guarantees one enabled `admin` **record**, not one `admin` that can authenticate: revoking
that Account's last Token locks the control plane out just as effectively. Recovery is then
`relay init --recover`, which needs an enabled human `admin`; without one it is local root on
the store, which ADR-0023 accepts on the record.

**Account administration is authorized in the capability layer,** once, for every surface
(invariant 10). No Control API route reaches Account or Token state except through that
capability, so a route added later cannot reach it ungated. A Relay assembled without a real
authorizer and a real audit trail for Account administration refuses to start.

### API Tokens

An API Token belongs to exactly one Account and has a non-secret ID, name, creation time,
optional expiry, last-use time, and revocation state. At mint the caller must choose a TTL
explicitly; zero means no expiry, so a configured AI-agent can stay connected without routine
human re-authentication. Designed for the MVP: for a human Account the Console's mint form
offers seven days as its default, because an approval answered on a human's token session counts
as that human (ADR-0047, amended 2026-10-23), and a copied interactive token should stop working
on its own. The plaintext `glp_…` credential is returned in the mint response
exactly once. Relay stores a hash of the secret component and never the plaintext, and no
read, list, or audit surface returns either.

At authentication, a valid, unexpired, unrevoked API Token resolves to its enabled Account and
current role, and its last-use time is updated. Revocation is idempotent and takes effect
before the next request with that Token. Listing Tokens returns only redacted lifecycle data.
Revoking a Token requires an authenticated `admin` and no step-up: it only reduces privilege,
and an incident instrument that costs a password is one people route around. An `admin` may
revoke its own Token.

`relay init` follows the same reveal-once model. `--recover` mints an additional Token for an
enabled human `admin`, refusing a disabled, machine or non-admin Account; it does not replace
a working credential.

### OAuth and MCP attribution

Relay is an OAuth 2.1 protected resource, never an authorization server. When OAuth is
configured locally, Relay verifies an external IdP token's signature, issuer, audience, expiry,
configured subject claim, and optional required scope. The verified claim must map to an
existing enabled Account; Relay never auto-provisions one. The Account's role remains the
authority.

OAuth and API Token inputs are routed by credential kind, never tried as alternative readings
of the same input. An OAuth principal is marked as OAuth in the verified audit lane and has no
API Token ID. API Tokens stay locally verifiable when an IdP is unavailable.

An OAuth session on MCP proves a human authorized that *session*, not any individual
model-generated call, so MCP calls stay agent-grade for approval. Who an elicited approval
answer is recorded as, on an OAuth or an API-token session, is `approval.md`'s (ADR-0047,
amended 2026-10-23).

### Console authentication

The Console's local sign-in accepts only an enabled human Account with a local password.
Successful sign-in retires any presented session identifier, creates a new Console-only
session, and records the verified Account, method, and source. The session cookie is
host-only, Secure, HttpOnly, SameSite=Strict, with a session-bound CSRF secret for unsafe
Console requests. Console sessions do not authenticate `/api/v1` or MCP, and Bearer credentials
do not become Console sessions.

Unknown Account, disabled Account, machine Account, absent password, corrupt stored password
hash, and wrong password share one indistinguishable sign-in refusal. Login and step-up
throttling are recorded without naming a verified Account. Sign-out ends the server-side
session; disabling an Account also makes an issued Console session unusable.

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
password directly; an emailed reset link is Future work. No surface does this yet: the only
Console password set today is the first admin's, by `relay init`, and `relay init --recover`
re-mints an API Token without touching it. Setting another person's password is
an Account-takeover path, which is why it sits in this matrix.

> **Superseded on 2026-10-22 by
> [ADR-0045](../adr/0045-console-passwords-temporary-at-creation-and-self-service-change.md).**
> The owner rejected an admin reset (#1107). An `admin` issues a temporary password only at a
> human Account's creation, and re-issues one only while its human has never set their own; a
> signed-in human changes only their own password, proving the current one. The admin-reset
> text above and its step-up bullet are left as they were for the migration of this spec to
> reconcile (`/spec-author --migrate`); where they disagree with ADR-0045, the ADR binds.

Acts that only reduce privilege — disabling an Account, lowering a role, revoking a Token — do not
require step-up.

## Refusals

| Refusal | Behaviour |
|---|---|
| Missing, malformed, expired, revoked, disabled, or otherwise invalid API Token | Authentication fails with one generic unauthorized response, without identifying the failing check. |
| Non-admin Account administration request | Refused as admin-required, on every surface. |
| Invalid Account name, kind, or role; duplicate Account name | The create or update request is refused; names remain unique. |
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
- **ADR-0023** — retires the shared control-plane credential: the network credential is a
  per-Account API Token, and local root performs bootstrap.
- **ADR-0024** — makes Relay an OAuth protected resource only, requires existing-Account
  mapping, and preserves API Token authentication for headless callers.
- **ADR-0009** and **ADR-0026** — bind the Console to the shared capability layer and require
  step-up for Console privilege grants. The step-up matrix above is what that means for Account
  administration.
- **ADR-0050** — only a human Account at `operator` or above writes a tag, on the Console and
  the Control API; no MCP tool writes one.
- **ADR-0052** — the Console watches and does not execute, so no role reaches a dispatch through
  it.
- **ADR-0027** — OAuth/MCP session attribution does not make individual MCP calls
  human-grade for approval.
- **ADR-0028** — MCP is stateless; a machine Account has recent activity, never a
  durable connected session to terminate.
- **ADR-0013** — a Freeze is engaged over the API only by a human Account.
- **ADR-0035** — account suspension is deferred and imposes no state or route.
- **Invariant 10** — Account administration is authorized once in the capability layer; a
  surface that exposes it adapts that one decision and reproduces no part of it.
- **Invariant 11** — OAuth issuer, audience, scope, and Console step-up freshness are
  root-owned Relay configuration, never API-managed runtime objects.

## Seams and proof

The Accounts domain and Token service own Account and Token state and verification. The
control-plane authenticator resolves a credential to a principal, which adapters consume.
Console session and step-up state is separate from bearer-token authentication. The Control
API and the Console screen call the same lifecycle capability rather than reproducing role or
audit logic.

`make verify` suffices for a documentation-only change. Changes to authentication, OAuth
configuration, Console sessions, or Account lifecycle are security-sensitive and should also
run their focused tests, plus `make test-integration` if composition-root configuration
changes.

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
- That the privilege-granting Console acts require a fresh step-up, and privilege-reducing acts
  do not. The Console write routes consult the step-up window and have tests; no row cites
  them yet.
- That `relay init --recover` is additive and refuses a disabled, machine or non-admin
  Account. `relay-configuration.md` (RC-28) owns `relay init`.
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
- Account suspension is deferred (ADR-0035); revoking API Tokens, disabling an Account, and
  Freeze are distinct controls with different effects.
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
  one `admin` that can authenticate. If no enabled human `admin` remains and every remaining
  admin's Token is revoked, there is no in-band way back, and `relay init --recover` refuses by
  design. Accepted by the owner in ADR-0023 §Consequences; the compensating control is local
  root on the Relay host.

## Future work

Wanted, deliberately not in the first pass, and in no committed order.

- **Narrowing an Account below its role (research, #578).** Per-Token scope, authorization Grants
  over Operations × Selectors, and machine authentication stronger than a long-lived bearer API
  Token — and on which engine (#285 proposes Cedar, evaluated jointly with the approval-rule
  grammar). Any answer must keep a configured AI-agent connected without routine human
  re-authentication, and a Grant used as a security boundary is narrows-only and `relay:`-scoped
  (`roadmap: relay/multi-principal-rbac-and-grants`). Unrelated to an approval grant despite the name.
- **Console OIDC sign-in.** An external browser identity flow beside local passwords;
  `console_oidc` is reserved and unimplemented.
- **Emailed password reset.** A reset link sent to the Account holder instead of an admin setting
  the password directly.
- **Per-Account rate limits (#279).** Bounding a runaway AI-agent loop in time as well as in blast
  radius.
- **OAuth tested against common identity providers** —
  `roadmap: relay/oauth-against-common-providers`.
- **IdP group claims for approval audiences** and `on_behalf_of`, joined to the existing-Account
  OAuth mapping. The roadmap (`roadmap: relay/idp-federated-teams-and-audiences`) names IdP-federated teams as the direction and rules out a
  native Relay org chart.

## Open questions

| Question | Classification | What forces the call |
|---|---|---|
| What limits, pagination, and audit-query disclosure apply to Account and Token listings? | Follow-up | Expected operator scale, or #654's screen needing a caller-visible contract. |
