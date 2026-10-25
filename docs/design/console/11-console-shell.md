# 11 — The Console shell

**No artboard.** The skeleton every screen mounts into. **Build this first** — every other spec
assumes it exists. **Milestone v0.6.0.**

**Governing:** ADR-0009, ADR-0010, ADR-0026, ADR-0052, invariants #10, #11.
**Backend:** the Account model (sessions, roles, step-up state); the SSE seam with its four
publishers (D9, #416).

## Why this has its own spec

ADR-0026 puts browser security **on the critical path**: CSP and CSRF are controls on an
administrative surface, because a forged click would counterfeit a human Account's own act:
minting an Enrollment Token, granting a role, retagging Nodes. The Console runs no command
(ADR-0052), but what it administers decides who can. This is the one part of the Console an
implementer must not improvise.

## Layout template

One template, three regions.

```
┌ nav (184px) ─┬ control-plane banner slot (conditional) ──────────────────┐
│ Relay        ├ topbar: page title · page controls · account chip ────────┤
│              │                                                            │
│ OBSERVE      │ content                                                    │
│  Fleet       │                                                            │
│  Activity    │                                                            │
│ ADMINISTER   │                                                            │
│  Add Nodes   │                                                            │
│  Accounts    │                                                            │
│  Access      │                                                            │
│              │                                                            │
│ signed in as │                                                            │
└──────────────┴────────────────────────────────────────────────────────────┘
```

The banner slot sits **above** the topbar and is empty in the common case. See
`00-foundations.md` for its three conditions.

The **signed-in block** names the Account and its role, and links to the **your account**
surface, where a signed-in human changes their own password ([15](15-accounts-and-tokens.md),
"Your own password"; ADR-0045, designed, not built). In a session opened with a temporary
password the shell draws no nav; the change-password form and sign-out are all it reaches
([12](12-login.md), "Temporary password").

At 800px and below the nav and the signed-in block fold behind a **Menu** toggle, closed by
default (`00-foundations.md`, "Narrow width"). The toggle is a checkbox and label, because the CSP
admits no inline script.

## The nav is built from what is actually mounted

**Do not render a nav item and then refuse the route.** The nav is generated from the routes this
process mounted for this Account's role:

- A `viewer` gets a **structurally smaller** nav — Add Nodes, Accounts and Access simply are not
  there. Access is `admin`-only ([20](20-access.md)), so an `operator` does not see it either.
- There is no Run item for any role and no execution route to mount: the Console watches and
  does not execute (ADR-0052), and the dormant `console_execution` gate and the run placeholder
  are deleted.

**Absent beats forbidden** (ADR-0026). A greyed-out control gives the property away.

## HTMX conventions

- **Fragment boundaries are named regions**, not ad-hoc selectors. Every swappable region has a
  stable `id`; every `hx-target` names one.
- **`hx-swap` is explicit** on every request. Never rely on the default.
- **Out-of-band swaps** carry cross-cutting updates — the banner slot — so a screen-level request
  does not have to know about them. The nav carries no approvals destination or pending count
  (ADR-0044).
- **`hx-on:` is banned.** It is inline script and the CSP will block it. Behaviour that needs
  JavaScript lives in an external file served from the Console's own origin.
- **Every mutating request is POST/PUT/DELETE**, never GET. A GET that mutates is a CSRF hole
  regardless of tokens.

## Modals

Where a screen opens a modal (D35; [15](15-accounts-and-tokens.md) is the first), it is built one
way:

- **A native `<dialog>`**, opened with `showModal()` by the Console's external same-origin script.
  No inline script, no `hx-on:`, no inline event handler (CSP, below).
- **Every trigger is a real link** to a page holding the same form. Without JavaScript, following it
  opens that page, which carries a **Back** link to the screen it came from; with JavaScript the
  script opens the dialog instead. A modal is never the only way to an act.
- **Every act is a form POST with its CSRF token**, exactly as on the page. The script opens and
  closes dialogs; it never posts, never carries a secret, and never decides anything.
- **Closing** — a × button, Esc, Cancel, or a click on the backdrop. Focus moves into the dialog on
  open and returns to the trigger on close; the dialog is labelled by its heading.
- **Errors** — a refusal re-renders the form with a banner above the dialog's footer and inline
  field messages tied by `aria-describedby`.
- **A destructive act inside a modal still goes to its named confirmation page**
  (`00-foundations.md`, "Form controls"); a modal never replaces it with a `confirm()` or a script.

## CSP

Strict, and **no inline script**. HTMX itself is an external file from the Console's own origin;
`hx-*` attributes are not script, which is why `hx-on:`, which *is* script, is banned.

No inline styles where a nonce would be required; ship a stylesheet. A CSP violation in this
product is a security event, not a rendering glitch, and should be reported.

**Reporting is deferred**: `99-open-decisions.md` D15 gives the four reasons and what would close
it. No `report-to` naming a group with no endpoint behind it ships.

## CSRF

A token on **every** mutating route, verified server-side, rotated per session.

Without inline script: `hx-headers` on the body element carries the token on every HTMX request;
plain form posts carry it as a hidden field. Reject a mutating request lacking a valid token with a
refusal the UI can render, not a bare 403 — a user whose session rotated mid-action needs to know
what happened.

## Sessions and step-up

- Session cookie: `HttpOnly`, `Secure`, `SameSite=Strict`, host-only, with an absolute lifetime
  **and** an idle timeout.
- **Step-up is a recent-auth window on the session**, not a separate credential. Re-authenticating
  stamps the session; actions requiring step-up check the stamp's age against a configured window
  and demand re-auth when it is stale.
- The window is a fixed constant, five minutes, and the absolute session lifetime is twelve
  hours (`docs/specs/relay-configuration.md`). Neither is a setting, and no Account of any role
  can extend either — an admin who could widen their own step-up window has removed the
  control (invariant #11).
- A step-up prompt must state **what it is authorising**, not merely ask for a password. "Confirm
  it is you" with no object is how people are trained to type passwords into anything.

## SSE

- One connection per Console session, multiplexing all event kinds; screens subscribe to the kinds
  they render.
- **Reconnect with jittered backoff** and resume from the last event id. A fleet's worth of
  Consoles reconnecting in lockstep after a Relay restart is a self-inflicted thundering herd.
- **Degrade visibly.** When the stream is down, say so in the affected region rather than showing
  stale data as if it were live.
- **Honour `gap`.** When the seam reports the client fell behind its buffer, reload the affected
  region rather than splicing; continuity that was not real must not look real.
- **Live but stable** (foundations rule 6) is enforced *here*, not per screen: incoming events for
  a region a user is reading queue behind an explicit control. Build it once.

## Internal-only exposure

Not internet-facing by default; served on an internal, VPN- or bastion-reachable interface.
Enrolling Nodes never reach it. This is ADR-0009, kept by ADR-0026 as one of the stacked
mitigations on a session-authenticated administrative surface.

## The structural guard

The `no_dispatch` guard covers the Console package (`00-foundations.md`, "Technical frame"): a
Console file that holds any concrete capability service, calls its constructors, or reaches
capability's internal dispatch **must fail to compile the test suite**.

## Acceptance

- [ ] A `viewer` session's rendered nav contains no Add Nodes, Accounts or Access item, and those
      routes are not mounted.
- [ ] No session, at any role, has a Run item or a mounted execution route (ADR-0052).
- [ ] No inline `<script>`, no `hx-on:` attribute, and no inline event handler survives in any
      rendered page — assert it in a test over the templates.
- [ ] Every mutating route rejects a request with a missing or stale CSRF token.
- [ ] No mutating action is reachable by GET.
- [ ] A step-up prompt names the action it authorises.
- [ ] Killing the SSE endpoint mid-session degrades visibly and reconnects with backoff.
- [ ] A Console file that reaches the capability layer's dispatch does not compile.
