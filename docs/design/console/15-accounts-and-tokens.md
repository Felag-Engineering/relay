# 15 — Accounts and API tokens

**No artboard.** Human and machine identities, roles, and the credentials that carry them.
**Milestone v0.7.0.**

**Governing:** ADR-0009, ADR-0010, ADR-0023, ADR-0024, ADR-0026, ADR-0045, invariants #10, #11.
**Backend:** the Account model; API Token mint and revoke; step-up; audit.

## What this screen is for

Every principal in the system: the humans who log in, and the **machine Accounts the AI-agents
authenticate as**. It is the screen ADR-0009 warned about most directly.

It lists every Account, and from that list an `admin` creates an Account, sets a role, enables or
disables one, and mints or revokes an API Token. Each write goes through the same capability-layer
method the Control API calls: the admin floor, the self-target refusal, the last-enabled-admin
refusal and every audit row are decided there, never on this screen. The step-up matrix:

| Act | Step-up |
|---|---|
| Create an Account (any role, any kind) | yes |
| Re-issue a temporary password | yes |
| **Raise** a role | yes |
| Re-enable a disabled Account | yes |
| Mint an API Token | yes |
| Disable an Account | no |
| **Lower** a role | no |
| Revoke an API Token | no |

Owner decision, `2026-09-19`; the principle is under *The warning, restated*. Creating a human
Account issues it a **temporary password**, and the create's step-up covers it; re-issuing one is
the same granting act (ADR-0045). Changing your own password is not on this screen and not in this
matrix: it proves the current password on every change, and the recent-auth window never stands in
for it ([Your own password](#your-own-password)).

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

## Layout

The Accounts screen is **one list**, and every act on an Account is reached from its row (D35).
There is no selected-Account panel stacked above the list.

```
Accounts                                                            [New account]
┌──────────────┬─────────┬──────────┬──────────┬─────────────────┬────────────────┬──────────────────┐
│ Name         │ Kind    │ Role     │ Status   │ Last auth       │ Last tool call │                  │
├──────────────┼─────────┼──────────┼──────────┼─────────────────┼────────────────┼──────────────────┤
│ mike         │ HUMAN   │ admin    │ enabled  │ 4 min ago       │                │ [Edit]           │
│ ci-agent     │ MACHINE │ operator │ enabled  │ 12s ago         │ 12s ago →      │ [Edit] [Disable] │
│ old-runner   │ MACHINE │ viewer   │ disabled │ 41 days ago     │ 41 days ago →  │ [Edit] [Enable]  │
└──────────────┴─────────┴──────────┴──────────┴─────────────────┴────────────────┴──────────────────┘
```

## The list

One bordered table, one row per Account: **Name | Kind | Role | Status | Last authentication |
Last tool call | actions**.

- **Name** is the Account's name, verbatim (`00-foundations.md`, "Identifiers render verbatim").
- **Kind** is the kind label, `human` or `machine`, in its one treatment (`00-foundations.md`,
  "Kind label"), read from the registry's current kind because this screen describes Accounts as
  they are now.
- **Role** is `viewer`, `operator` or `admin`; **Status** is `enabled` or `disabled`.
- **Last authentication** is relative, with the absolute UTC instant in its `title`.
- **Last tool call** is drawn for machine Accounts only: the time of its last tool call, linking to
  Activity scoped to that Account ([04](04-activity.md), `?account=`, by Account ID). A human row
  leaves the cell empty. An Account's sign-ins and the changes made to it are on
  [20 — Access](20-access.md).
- **Actions** sit right-aligned in the row: **Edit**, and **Disable** on an enabled Account or
  **Enable** on a disabled one. Disable is a destructive act and leads to its named confirmation
  (below). Enable grants authority, so it opens the Account's edit view at its state section, where
  the step-up password sits beside the Enable button; it never acts from the row.

There is no "connected" state: the MCP transport is stateless (ADR-0028), so an Account is *active
recently* or not. Below 600px the table reflows to cards, each cell carrying its column name
(`00-foundations.md`, "Narrow width").

**Open: badge colours.** The Gleipnir model (#1109) draws role and status as tinted badges, a hue
per role and status green for enabled and red for disabled. The colour budget
(`00-foundations.md`; D5, D24) reserves green for "reachable, and it worked" and red for failure and
the destructive button, and has no per-role hue. Until the owner settles which gives way, Role and
Status are drawn as words in the quiet treatment, with no new hue.

Machine Accounts are first-class. On a fleet driven by an AI-agent the busiest principal is a
machine Account, and treating it as an edge case is how it ends up over-privileged.

## New account

A primary **New account** button in the page header opens a modal (D35; the modal convention is
[11](11-console-shell.md), "Modals"). The form holds:

- **Name**, a text input.
- **Kind**, radios: `human`, `machine`.
- **Role**, radios: `viewer`, `operator`, `admin`, with nothing preselected, so a forgotten choice
  is refused rather than defaulted.
- **What this role may do**, a panel beside the role radios that lists, for the role selected, what
  an Account with it may ask of the Relay. See [Roles](#roles) for where its words come from.
- **Your password**, the step-up field, beside the primary **Create account** button that spends it
  (`00-foundations.md`, "Form controls").

There is no password field for the new Account. **Creating a human Account issues it a temporary
password**, which the Relay generates (ADR-0045 decision 1): the admin takes the act and never
chooses the value. A machine Account gets none.

The create of a human Account is, like a token mint, a write that does **not** post-redirect-get:
its response shows the Account and its temporary password **once**, in the response body, with
`Cache-Control: no-store`, never in a URL, a `Location` header or a browser history entry (see
[API tokens](#api-tokens)). The only words beside the revealed value are **"Shown once."** and its
expiry, drawn as data — "expires in 72 hours", the absolute UTC instant in the `title` — not as a
note (D34). A machine Account's create redirects as before. The admin passes it to the person out of band. The person's first sign-in with it is
forced to set their own password before anything else ([12](12-login.md), "Temporary password"),
so the admin never knows the password the person keeps.

A refused create keeps the modal open with the operator's input, except the password: a **banner
above the modal's footer** gives the capability layer's refusal, and a field the refusal names is
marked invalid, its message tied to the field by `aria-describedby`. These are situational messages
and stay visible (`00-foundations.md`).

**Without JavaScript**, New account is a link to a page holding the same form, with **Back to
Accounts**. Its path cannot collide with an Account's page: an Account may be named `new`.

## Editing an Account

**Edit** opens the same modal in edit mode (D35), headed by the Account's name and kind label. The
modal is the Account's view: there is no separate detail screen to work in. It holds three
sections, and a fourth on a human Account that has not yet set its own password, following the
form-control rule in `00-foundations.md`.

**Role.** A role change is split by what it does to authority: **Raise role** (the roles above the
current one, with the step-up password on the form, filled) and **Lower role** (the roles below it,
no password, in the danger style). Each select shows the Account's current role, preselected and not
submittable, so nothing changes without an explicit choice; the server refuses a missing or
unchanged role. The **Lower role** button is never drawn dimmed or disabled while the current role
is selected: a hint beside it says "choose a lower role", and pressing it with the current role
selected is refused with the same words. Granting buttons sit beside the password they spend.

**State.** **Disable** takes the danger style; **Enable**, on a disabled Account, is filled and sits
beside the step-up password.

**API Tokens.** The Account's tokens, each with name, creation, last use and expiry and a
**Revoke** button in the danger style; and a mint form — token name, lifetime, the step-up
password, and a filled **Mint token** button ([API tokens](#api-tokens)).

**Temporary password**, on a human Account **whose human has never set their own password**
only. It says whether the temporary password is live, with its expiry, or has expired, and offers
**Issue new temporary password** beside the step-up password, filled (ADR-0045 decision 4). The
response reveals the new value once, exactly as at creation, and the previous one stops being
accepted. Once the Account's human has set a password, the section is not drawn: no control on any
screen sets it again.

**Without JavaScript**, Edit is a link to the Account's page, `/console/accounts/<name>`, which
holds the same sections and a **Back to Accounts** link. The name in the path only locates
the page; every form on it posts by Account ID, as the Control API does, so a renamed or reused
name never redirects an act.

### Destructive acts confirm by name

**Disable**, **Lower role** and **Revoke** take the danger style — outlined in the muted red — and
each asks a confirmation naming its target and consequence before it acts (`00-foundations.md`,
"Form controls"; D24). From the modal or the Account's page alike, the button leads to the
server-rendered confirmation page, which works with scripts off; the modal never stands in for it.
For example:

| Act | Confirmation |
|---|---|
| Revoke an API Token | "Revoke token `dev-fleet-approver`? Anything using it fails immediately; this cannot be undone." |
| Disable an Account | "Disable `ci-agent`? It can no longer sign in or call the Relay; re-enabling takes a password." |
| Lower a role | "Lower `ci-agent` from `admin` to `operator`? Its API Tokens carry the lower role from their next request." |

The confirmation changes nothing about who may act or whether step-up applies. Every control keeps
its visible label.

### What a modal changes, and what it does not

A modal is presentation. Every act in it is the same **POST with its CSRF token** to the same route
as without it; nothing is posted by script, and the capability layer decides each act exactly as
before. Step-up, the refusal of a self role change or self-disable, the last-admin refusal, and the
named confirmation are unchanged. A successful act returns to the screen it was made from, with a
one-line result.

## Roles

`viewer` / `operator` / `admin`, defined in ADR-0010 and **decided by the capability layer's
`RoleGate`**. This screen assigns a role; it never interprets one. A Console that computed its own
answer to "may this Account do X" would be a second control path, and the first to be forgotten.

**The "What this role may do" panel** shows a description of each role; it never decides one. Its
lines come from the one description of the roles that the capability layer and the docs share
(ADR-0010, GLOSSARY.md *Account*) — never authored in the Console, never computed for a particular
Account, and never consulted to allow or refuse anything. With JavaScript it shows the selected
role's lines; without it, all three roles' lines are drawn, each under its role's name.

Never claim a role can do something Policy might still deny — **the ceiling is always what the
fleet's own Policy permits.** The panel's lines say what an Account may *ask the Relay for*, never
what will run on a Node. No sentence beside the role controls restates the Policy ceiling (D34): the
panel's wording carries it, and the docs explain it.

## API tokens

Minted per Account, listed with name, creation, last use and expiry. **There is no scope:** an API
Token carries no authority of its own — authorization reads the Account's role at verification
time, which is what makes "a token inherits its Account's role changes" true by construction
(`accounts.APIToken`). **The plaintext is shown once at mint and never again** — the same
reveal-once discipline as spec 09, for the same reason. The only prose beside the revealed value is
**"Shown once."** (D34). Beneath it the same response renders the harness setup as labelled data:
the CA certificate, then one block each for Claude Code, `.mcp.json`, Gleipnir (a
machine Account's token only) and a connection check. Every block but the CA certificate carries
the plaintext, in this response and no other.

The mint, and a temporary password's issue (at a human Account's create or by re-issue), are the
writes on this screen that do **not** post-redirect-get: a plaintext must never enter a URL, a `Location` header or a browser history entry, so it renders in the response
body, once, with `Cache-Control: no-store`. A mint made from the modal is an ordinary form post, so
its response is that page; no script carries the value, and the modal is never re-opened onto it
from a URL. A lifetime is a closed choice with no default — a forgotten field must never silently
mint an immortal credential.

Revocation is immediate and audited. ADR-0023 retired the shared control-plane credential; nothing
on this screen may reintroduce one, and there is no such thing as a token not bound to an Account.

## Your own password

**Built** ([ADR-0045](../../adr/0045-console-passwords-temporary-at-creation-and-self-service-change.md),
owner decisions `2026-10-21` and `2026-10-22`, #1107).

**A signed-in human Account changes only its own password.** There is no admin reset: no role, on
this screen or any other, sets another Account's password, beyond the temporary password issued
at creation and re-issued while it is unredeemed ([New account](#new-account),
[Editing an Account](#editing-an-account)).

- **Where.** A **your account** surface, reached from the signed-in block of the shell
  ([11](11-console-shell.md)), not from the Accounts list, so it is not an `admin`-only act. Any
  signed-in human Account reaches it; a machine Account cannot hold a Console session.
- **The form.** Current password, new password, and confirm new password, with a filled **Change
  password** button, and a hidden username field carrying the signed-in Account's name so password
  managers file the change against the right entry. A refusal is a banner above the button and an
  inline message on the field it names, as in [New account](#new-account).
- **The current password is the step-up, every time.** It is verified in the request on every
  change and the recent-auth window never satisfies it: inside the window a hijacked session could
  otherwise take the Account from its owner with no password at all. It is throttled and recorded
  as a step-up (`step_up`, `step_up_failed`, `step_up_throttled`), with the same progressive delay
  and no hard lockout ([12](12-login.md)).
- **The new password** is 12 to 4096 bytes, differs from the current one, and matches its
  confirmation. There are no composition rules.
- **On success** this session's identifier rotates and **every other Console session of the
  Account ends**. API Tokens are untouched. The screen returns with a one-line result.
- **The forced change** is this same form. A sign-in with a temporary password opens a restricted
  session that reaches only this form and sign-out ([12](12-login.md), "Temporary password"); the
  current password it proves is the temporary one, and the change leaves an ordinary session.
- **Recorded** on [20 — Access](20-access.md) as `password_change` — time, Account, source address,
  whether it redeemed a temporary password — and never the password or its hash.

## Stopping one actor

There is no suspension rung: ADR-0035 is **deferred, not adopted** (#443). The instruments are
**revoking the Account's API Tokens** here — immediate, audited, `admin`, deliberately **without**
step-up — or Freeze (`docs/specs/freeze.md`). Disabling an Account (`Enabled`) is the durable off-switch: it
authenticates nowhere; re-enabling is privilege-granting and takes step-up.

## Must not appear

- A role or permission editor of any kind. Roles are the three from ADR-0010; a custom-permission
  builder is a second authorization model.
- Any Relay configuration, including which gates or caps apply to an Account.
- A token value after its mint response.
- Any way to grant an Account something Node Policy would not permit — that is not expressible, and
  the UI must not imply it is.
- A control that sets another Account's password, other than issuing a temporary password to a
  human Account that has never set its own (ADR-0045).
- A temporary password, or an API Token's value, after the response that reveals it.
- A standing note restating the Policy ceiling, or explaining temporary passwords (D34).
- Inline script, or any act a script performs instead of a form post ([11](11-console-shell.md)).

## States

- **Self** — an Account cannot change its own role or disable itself. Its row offers no Disable,
  and in its edit view no role or state control is offered: the view states the role and state and
  says why in place of the controls, never omitting them silently. That sentence is situational —
  it is about this caller — and stays. The capability layer refuses a self role change or
  self-disable, and would refuse a hand-built request too. Its API Tokens stay manageable.
- **Last admin** — refuse to remove the final `admin`, explicitly.
- **`viewer`** — does not see this screen (owner decision, `2026-09-19`). The route is not
  mounted below `admin`, so it answers the same 404 as any unmounted path — a 403 would disclose
  that the screen exists. The same holds for each Account's page.
- **No JavaScript** — New account and Edit are links to pages holding the same forms, each with
  Back to Accounts; every act works.

## Acceptance

- [ ] Every privilege-granting action demands step-up and is audited with the actor.
- [ ] An API token's plaintext appears in exactly one response and is never retrievable again.
- [ ] Roles are enforced by the capability layer; this package contains no role interpretation, and
      the "What this role may do" panel decides nothing.
- [ ] An Account cannot elevate itself.
- [ ] The final `admin` cannot be removed or demoted.
- [ ] Revoking a token is immediate: the next request carrying it is refused and audited.
- [ ] Disable, Lower role and Revoke are drawn in the danger style, and each acts only from a
      confirmation that names its target and consequence; none gains a step-up by it.
- [ ] The screen is one list; New account and Edit open native `<dialog>` modals driven only by
      the Console's external script, and every act in them is a CSRF-bearing POST.
- [ ] With scripts off, New account and Edit reach pages that hold the same forms and a Back to
      Accounts link, and every act still works.
- [x] No control on any screen sets another Account's password, except issuing a temporary
      password to a human Account that has never set its own; that act takes step-up.
- [x] A temporary password is generated by the Relay, appears in exactly one response, expires
      72 hours after issue, and stops being accepted when it is redeemed or re-issued.
- [x] A human changes their own password only by proving the current one in the same request; the
      recent-auth window never satisfies it, and a change ends the Account's other sessions.
- [x] Every temporary-password issue and every change is a row on Access, carrying neither the
      password nor its hash.
