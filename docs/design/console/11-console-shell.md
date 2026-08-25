# 11 — The Console shell

**No artboard.** The skeleton every screen mounts into. **Build this first** — every other spec
assumes it exists. **Milestone v0.6.0.**

**Governing:** ADR-0009, ADR-0010, ADR-0026, invariants #10, #11.
**Backend:** the Account model (sessions, roles, step-up state); the SSE seam with its four
publishers (D9, #416).

## Why this has its own spec

ADR-0026 moved browser security **onto the critical path**: CSP and CSRF are no longer hygiene,
they are controls with a fleet-RCE blast radius, because a forged click would counterfeit the
strongest credential in the system. This is the one part of the Console an implementer must not
improvise.

## Layout template

One template, three regions.

```
┌ nav (184px) ─┬ control-plane banner slot (conditional) ──────────────────┐
│ Relay        ├ topbar: page title · page controls · account chip ────────┤
│              │                                                            │
│ OBSERVE      │ content                                                    │
│  Fleet       │                                                            │
│  Agents      │                                                            │
│  Activity    │                                                            │
│ ACT          │                                                            │
│  Run         │                                                            │
│  Policy      │                                                            │
│  Approvals   │                                                            │
│ ADMINISTER   │                                                            │
│  Add Nodes   │                                                            │
│  Accounts    │                                                            │
│  Incident    │                                                            │
│              │                                                            │
│ signed in as │                                                            │
└──────────────┴────────────────────────────────────────────────────────────┘
```

The banner slot sits **above** the topbar and is empty in the common case. See
`00-foundations.md` for its three conditions.

## The nav is built from what is actually mounted

**Do not render a nav item and then refuse the route.** The nav is generated from the routes this
process actually mounted for this Account's role. Consequences:

- A `viewer` gets a **structurally smaller** nav — Run, Policy, Add Nodes, Accounts and Incident
  simply are not there.
- With `console_execution = off` (v0.7.0, spec 05), Run is absent because the route was never
  mounted, not because a check refused it. The flag itself arrives with the composer; in v0.6.0
  there is no execution route for it to gate.

ADR-0026's insight is that **absent beats forbidden**. An implementation that ships a greyed-out
composer has given the property away, and the acceptance criterion in spec 05 exists to catch it.

## HTMX conventions

- **Fragment boundaries are named regions**, not ad-hoc selectors. Every swappable region has a
  stable `id`; every `hx-target` names one.
- **`hx-swap` is explicit** on every request. Never rely on the default.
- **Out-of-band swaps** carry cross-cutting updates — the banner slot, the Approvals count in the
  nav — so a screen-level request does not have to know about them.
- **`hx-on:` is banned.** It is inline script and the CSP will block it. Behaviour that needs
  JavaScript lives in an external file served from the Console's own origin.
- **Every mutating request is POST/PUT/DELETE**, never GET. A GET that mutates is a CSRF hole
  regardless of tokens.

## CSP

Strict, and **no inline script**. HTMX itself is an external file from the Console's own origin;
`hx-*` attributes are attributes, not script, so they are unaffected — which is precisely why
`hx-on:` must be banned, since that one *is* script.

No inline styles either where a nonce would otherwise be required; ship a stylesheet. Report
violations rather than silently dropping them, because a CSP violation in this product is a
security event, not a rendering glitch.

## CSRF

A token on **every** mutating route, verified server-side, rotated per session.

Injecting it without inline script: put `hx-headers` on the body element with the token, so every
HTMX request carries it as a header. Plain form posts carry it as a hidden field. Reject any
mutating request lacking a valid token with a refusal the UI can render, not a bare 403 page — a
user whose session rotated mid-action needs to know what happened.

## Sessions and step-up

- Session cookie: `HttpOnly`, `Secure`, `SameSite=Strict`, host-only, with an absolute lifetime
  **and** an idle timeout.
- **Step-up is a recent-auth window on the session**, not a separate credential. Re-authenticating
  stamps the session; actions requiring step-up check the stamp's age against a configured window
  and demand re-auth when it is stale.
- The window is Relay configuration (file-only, invariant #11). No Account of any role can extend
  it — an admin who could widen their own step-up window has removed the control.
- A step-up prompt must state **what it is authorising**, not merely ask for a password. "Confirm
  it is you" with no object is how people are trained to type passwords into anything.

## SSE

- One connection per Console session, multiplexing all event kinds; screens subscribe to the kinds
  they render.
- **Reconnect with jittered backoff** and resume from the last event id. A fleet's worth of
  Consoles reconnecting in lockstep after a Relay restart is a self-inflicted thundering herd.
- **Degrade visibly.** When the stream is down, say so in the affected region rather than showing
  stale data as if it were live. A monitoring surface that silently freezes is worse than one that
  admits it is blind.
- **Honour `gap`.** When the seam reports the client fell behind its buffer, reload the affected
  region rather than splicing; continuity that was not real must not look real.
- **Live but stable** (foundations rule 6) is enforced *here*, not per screen: incoming events for
  a region a user is reading queue behind an explicit control. Build it once.

## Internal-only exposure

Not internet-facing by default; served on an internal, VPN- or bastion-reachable interface.
Enrolling Nodes never reach it. This is ADR-0009 and it is unchanged by ADR-0026 — it is one of the
stacked mitigations that made the execution surface acceptable.

## The structural guard

The `no_dispatch`-style test extends to the Console package: a Console file that holds a
`*capability.Service`, calls `capability.New`, or reaches capability's internal dispatch **must
fail to compile the test suite**. Extend the guard when the package is created, not when the
composer is.

## Acceptance

- [ ] A `viewer` session's rendered nav contains no Run, Policy, Add Nodes, Accounts or Incident
      item, and those routes are not mounted.
- [ ] No inline `<script>`, no `hx-on:` attribute, and no inline event handler survives in any
      rendered page — assert it in a test over the templates.
- [ ] Every mutating route rejects a request with a missing or stale CSRF token.
- [ ] No mutating action is reachable by GET.
- [ ] A step-up prompt names the action it authorises.
- [ ] Killing the SSE endpoint mid-session degrades visibly and reconnects with backoff.
- [ ] A Console file that reaches the capability layer's dispatch does not compile.
