# 09 — Add Nodes

**Artboard 7.** Mint an Enrollment Token for a number of Nodes and show its join string once.

**Governing:** ADR-0006, ADR-0030, ADR-0031, ADR-0032, ADR-0048, ADR-0050, invariants #7, #10, #11.
**Behaviour:** `enrollment.md` EN-36, EN-47; designed: EN-46's 256-Node cap.
**Backend:** the capability layer's Enrollment Token mint, the same action (`ControlMintEnrollmentToken`)
and `admin` floor as `POST /api/v1/enrollment-tokens`.

## What this screen is for

Getting the first Node — and the next fifty — into the fleet. On a fresh install it is the second
screen a new operator sees (spec 10 is the first).

## The constraint that shapes everything

**The Enrollment Token's plaintext is returned exactly once.** The Relay stores only its hash, so
the join string that carries it can be shown only at the moment of minting, and never again, by
anyone.

Consequences for this screen, all mandatory:

- **Everything the mint needs is on the form**, chosen before minting: how many Nodes, the
  expiry, initial tags and the password.
- The result behaves like a **secret reveal**: shown once, prominently marked as such, not a
  document to return to.
- **There is no showing it again.** Losing the string means minting another token and revoking
  the first. That is cheap and correct; a "show again" control would be a lie.

## Layout

**Left — the mint form.** How many Nodes the token is for (EN-46 caps it at 256, once built), the expiry (two
hours by default), optional initial tags (ADR-0050), and the Account's password. Then "Mint".

**Right — the reveal.** A once-only banner, the command `sudo relay-daemon join`, and apart from
it the join string to paste at that command's prompt, each with copy (ADR-0048). Below, "what
happens on each machine".

## Initial tags, not the security lane

The labels a token names are written as each joining Node's first `tag:` labels, as the minting
`admin`'s act, and are ordinary tags afterwards (ADR-0050). They are not `relay:` labels: `relay:`
holds only keys a Relay action defines, and enrollment writes `relay:node-id` and nothing else.
Minting is still a privilege-granting act, because it admits Nodes to the fleet, which is why it
requires `admin` (ADR-0032 decision 5).

## What happens on each machine

Three steps, stated on screen because they are the trust story:

1. The daemon verifies the certificate the Relay presents against the **fingerprint pinned inside
   the join string**, before anything else. Wrong fingerprint and it exits — there is no fallback.
2. It presents the token once, receives its own identity certificate, and the Relay writes
   `relay:node-id` and the token's initial tags on it.
3. It loads its Policy and comes up **read-only** per ADR-0022 — interrogable, unable to change
   anything, until the operator widens Policy themselves.

## Must not appear

- A control that shows a token's join string again, in any form.
- The token plaintext anywhere outside the one-time reveal — not in a list, not in an audit view,
  not in a log.
- Any Relay configuration. The address a Node dials appears only inside the opaque join string
  ADR-0048 requires the reveal to show, never decoded or shown on its own.

## Routes and step-up

**The routes are `GET /console/add-nodes` and `POST /console/add-nodes/tokens`.** `Register`
mounts a method pattern plus a bare path for every route that constrains reach, so
`GET /console/nodes/add` would panic at registration against `GET /console/nodes/{node_id}`, and
a constrained `GET` and `POST` on one path register the bare path twice.

**The step-up is the Account's password on every mint, inline on the form**, never the
recent-sign-in window (owner decisions 2026-09-20 and 2026-10-29). A window lets one password
buy a burst of fleet-admitting credentials; a window also invites refuse, prompt, replay, which
would carry a pending mint across a request boundary; and an adapter may be stricter than the
capability layer, never looser (invariant 10). The 2026-10-05 window decision covers only the
four Account acts.

## Acceptance

- [x] Minting requires `admin`; a `viewer` and an `operator` are refused.
- [x] Exactly one audit event per mint.
- [x] Navigating away from the reveal and back does not show the join string again.
- [x] The token plaintext appears in exactly one response and is never persisted.
- [x] A daemon given a wrong CA fingerprint refuses enrollment and exits without falling back
  (the daemon's own test, EN-27).
