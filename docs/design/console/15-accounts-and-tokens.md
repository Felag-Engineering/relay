# 15 — Accounts and API tokens

**No artboard.** Human and machine identities, roles, and the credentials that carry them.
**Milestone v0.7.0.**

**Governing:** ADR-0009, ADR-0010, ADR-0023, ADR-0024, invariants #10, #11.
**Backend:** the Account model; API Token mint and revoke; step-up; audit.

## What this screen is for

Every principal in the system: the humans who log in, and the **machine Accounts the AI-agents
authenticate as**. It is the screen ADR-0009 warned about most directly.

It lists every Account and its credentials, and it creates an Account, sets a role, enables or
disables one, and mints or revokes an API Token. Each write goes through the same capability-layer
method the Control API calls: the admin floor, the self-target refusal, the last-enabled-admin
refusal and every audit row are decided there, never on this screen. The step-up matrix:

| Act | Step-up |
|---|---|
| Create an Account (any role, any kind) | yes |
| **Raise** a role | yes |
| Re-enable a disabled Account | yes |
| Mint an API Token | yes |
| Disable an Account | no |
| **Lower** a role | no |
| Revoke an API Token | no |

Owner decision, `2026-09-19`; the principle is under *The warning, restated*. A human Account
created here cannot sign in until a password is set, and only `relay init --admin` on the host sets
one, for the first admin. No capability seam can set one, and the screen says so.

## The warning, restated

> Once the Console manages Accounts and roles, a hijacked admin session can *indirectly* reach
> execution by elevating a machine Account it controls.

So **every action on this screen that could increase what a principal may do requires step-up**,
and every action is audited. An act that can only *reduce* what a principal may do (disabling an
Account, **lowering** a role, revoking a Token) takes no step-up, because an emergency brake that
costs a password is one people route around. This is the mitigation ADR-0009 named for a
consequence class it could not otherwise close, not a UI convention.

Step-up is a password on the granting form itself, consulting the recent-auth window (owner
decision `2026-10-05`): one password covers granting acts until the window lapses. A submitted
password is always verified in the request, and a successful step-up rotates the session.

## Rows

Accounts listed with kind (**human** or **machine**), role (`viewer` / `operator` / `admin`),
state, last authentication, and — for machine Accounts — the time of its last tool call, linking to
Activity scoped to that Account ([04](04-activity.md), `?account=`). Its sign-ins and the changes
made to it are on [20 — Access](20-access.md). There is no "connected" state: the MCP transport is
stateless (ADR-0028), so an Account is *active recently* or not.

The list is read-only. **Order on the page** (D32): the selected Account's panel first; then the
list; then the create form behind a **New account** button — a native `<details>`, closed by
default and open when re-rendered with a refusal — so creating an Account is a deliberate step,
never what an admin who came to change one sees first. An Account's panel holds its role and state
controls above its API Tokens, following the form-control rule in `00-foundations.md`. A role change is split by what it does to authority: **Raise role** (the roles
above the current one, with the password, filled) and **Lower role** (the roles below it, no
password, in the danger style). Each select shows the Account's current role, preselected and not
submittable, so nothing changes without an explicit choice; the server refuses a missing or
unchanged role. The **Lower role** button is never drawn dimmed or disabled while the current role
is selected: a hint beside it says "choose a lower role", and pressing it with the current role
selected is refused with the same words. **Disable** takes the danger style; the password and
**Enable** are filled. Granting buttons sit beside the password they spend.

**Disable**, **Lower role** and **Revoke** take the danger style — outlined in the muted red — and
each asks a confirmation naming its target and consequence before it acts (`00-foundations.md`,
"Form controls"; D24). For example:

| Act | Confirmation |
|---|---|
| Revoke an API Token | "Revoke token `dev-fleet-approver`? Anything using it fails immediately; this cannot be undone." |
| Disable an Account | "Disable `ci-agent`? It can no longer sign in or call the Relay; re-enabling takes a password." |
| Lower a role | "Lower `ci-agent` from `admin` to `operator`? Its API Tokens carry the lower role from their next request." |

The confirmation is a server-rendered step with no script; it changes nothing about who may act or
whether step-up applies. Every control keeps its visible label.

Machine Accounts are first-class. On a fleet driven by an AI-agent the busiest principal is a
machine Account, and treating it as an edge case is how it ends up over-privileged.

## Roles

`viewer` / `operator` / `admin`, defined in ADR-0010 and **decided by the capability layer's
`RoleGate`**. This screen assigns a role; it never interprets one. A Console that computed its own
answer to "may this Account do X" would be a second control path, and the first to be forgotten.

Never claim a role can do something Policy might still deny — **the ceiling is always what the
fleet's own Policy permits.** The screen draws no per-role lines: it states that Policy ceiling in
one visible sentence beside the role controls. What each role may do is defined in ADR-0010 and
GLOSSARY.md (*Account*).

## API tokens

Minted per Account, listed with name, creation, last use and expiry. **There is no scope:** an API
Token carries no authority of its own — authorization reads the Account's role at verification
time, which is what makes "a token inherits its Account's role changes" true by construction
(`accounts.APIToken`). **The plaintext is shown once at mint and never again** — the same
reveal-once discipline as spec 09, for the same reason.

The mint is the one write on this screen that does **not** post-redirect-get: a plaintext must
never enter a URL, a `Location` header or a browser history entry, so it renders in the response
body, once, with `Cache-Control: no-store`. A lifetime is a closed choice with no default — a
forgotten field must never silently mint an immortal credential.

Revocation is immediate and audited. ADR-0023 retired the shared control-plane credential; nothing
on this screen may reintroduce one, and there is no such thing as a token not bound to an Account.

## Stopping one actor

There is no suspension rung: ADR-0035 is **deferred, not adopted** (#443). The instruments are
**revoking the Account's API Tokens** here — immediate, audited, `admin`, deliberately **without**
step-up — or Freeze (spec 16). Disabling an Account (`Enabled`) is the durable off-switch: it
authenticates nowhere; re-enabling is privilege-granting and takes step-up.

## Must not appear

- A role or permission editor of any kind. Roles are the three from ADR-0010; a custom-permission
  builder is a second authorization model.
- Any Relay configuration, including which gates or caps apply to an Account.
- A token value after its mint response.
- Any way to grant an Account something Node Policy would not permit — that is not expressible, and
  the UI must not imply it is.

## States

- **Self** — an Account cannot change its own role or disable itself. On the signed-in Account's
  own panel no role or state control is offered: the panel states the role and state and says why
  in place of the controls, never omitting them silently. The capability layer refuses a self role
  change or self-disable, and would refuse a hand-built request too. Its API Tokens stay
  manageable.
- **Last admin** — refuse to remove the final `admin`, explicitly.
- **`viewer`** — does not see this screen (owner decision, `2026-09-19`). The route is not
  mounted below `admin`, so it answers the same 404 as any unmounted path — a 403 would disclose
  that the screen exists.

## Acceptance

- [ ] Every privilege-granting action demands step-up and is audited with the actor.
- [ ] An API token's plaintext appears in exactly one response and is never retrievable again.
- [ ] Roles are enforced by the capability layer; this package contains no role interpretation.
- [ ] An Account cannot elevate itself.
- [ ] The final `admin` cannot be removed or demoted.
- [ ] Revoking a token is immediate: the next request carrying it is refused and audited.
- [ ] Disable, Lower role and Revoke are drawn in the danger style, and each acts only from a
      confirmation that names its target and consequence; none gains a step-up by it.
- [ ] The selected Account's panel is above the list, and the create form is behind New account.
