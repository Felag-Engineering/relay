# 15 — Accounts and API tokens

**No artboard.** Human and machine identities, roles, and the credentials that carry them.
**Milestone v0.7.0.**

**Governing:** ADR-0009, ADR-0010, ADR-0023, ADR-0024, invariants #10, #11.
**Backend:** the Account model; API Token mint and revoke; step-up; audit.

## What this screen is for

Every principal in the system: the humans who log in, and the **machine Accounts the AI-agents
authenticate as**. It is also the screen ADR-0009 warned about most directly.

## The warning, restated

> Once the Console manages Accounts and roles, a hijacked admin session can *indirectly* reach
> execution by elevating a machine Account it controls.

So **every privilege-granting action on this screen requires step-up**, and every one is audited:
creating an Account, changing a role, minting an API Token, re-enabling a disabled Account. This is
not a UI convention — it is the mitigation ADR-0009 named for a consequence class it could not
otherwise close.

## Rows

Accounts listed with kind (**human** or **machine**), role (`viewer` / `operator` / `admin`),
state, last authentication, and — for machine Accounts — whether a session is connected right now,
linking to the agent stream (spec 03).

Machine Accounts are first-class, not a footnote. On a fleet driven by an AI-agent, the busiest
principal in the system is a machine Account, and treating it as an edge case is how it ends up
over-privileged.

## Roles

`viewer` / `operator` / `admin`, defined in ADR-0010 and **decided by the capability layer's
`RoleGate`**. This screen assigns a role; it never interprets one. A Console that computed its own
answer to "may this Account do X" would be a second control path, and the first to be forgotten.

Show what a role means in terms of the boundary, not in terms of screens: `operator` may run
Operations, `admin` may additionally use Raw Exec and set `relay:` labels. Never claim a role can do
something Policy might still deny — **the ceiling is always what the fleet's own Policy permits.**

## API tokens

Minted per Account, listed with scope, creation, last use and expiry. **The plaintext is shown once
at mint and never again** — the same reveal-once discipline as spec 09, for the same reason.

Revocation is immediate and audited. ADR-0023 retired the shared control-plane credential; nothing
on this screen may reintroduce one, and there is no such thing as a token not bound to an Account.

## Suspension

The incident-ladder rung from D2 lives here as well as on the agent stream: **`operator`+ to
suspend, `admin` + step-up with a reason to lift.** Suspension is not revocation — tokens survive
it, which is what makes it reversible and therefore usable in a hurry.

## Must not appear

- A role or permission editor of any kind. Roles are the three from ADR-0010; a custom-permission
  builder is a second authorization model.
- Any Relay configuration, including which gates or caps apply to an Account.
- A token value after its mint response.
- Any way to grant an Account something Node Policy would not permit — that is not expressible, and
  the UI must not imply it is.

## States

- **Self** — an Account cannot change its own role or delete itself. Say why; do not hide it.
- **Last admin** — refuse to remove the final `admin`, explicitly.
- **`viewer`** — sees the list, changes nothing.

## Acceptance

- [ ] Every privilege-granting action demands step-up and is audited with the actor.
- [ ] An API token's plaintext appears in exactly one response and is never retrievable again.
- [ ] Roles are enforced by the capability layer; this package contains no role interpretation.
- [ ] An Account cannot elevate itself.
- [ ] The final `admin` cannot be removed or demoted.
- [ ] Suspending requires `operator`+; lifting requires `admin` + step-up + a reason.
