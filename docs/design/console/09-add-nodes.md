# 09 — Add Nodes

**Artboard 7.** Mint an Enrollment Token and render what the machines need, in one act.
**Milestone v0.7.0.**

**Governing:** ADR-0006, ADR-0030, ADR-0031, ADR-0032, ADR-0033, invariants #7, #11.
**Backend:** `POST /api/v1/enrollment-tokens` with the `render` field and `renderings` response
(ADR-0032); the pure renderer; **`admin` gating, which does not exist yet — issue #397 is a
prerequisite.**

## What this screen is for

Getting the first Node — and the next fifty — into the fleet. It is also, on a fresh install, the
second screen a new operator ever sees (spec 10 is the first).

## The constraint that shapes everything

**The Enrollment Token's plaintext is returned exactly once.** The Relay stores only its hash. So
an artifact that *contains* a token — a playbook, a shell one-liner, a join string — can only be
produced at the moment of minting, and can never be reproduced afterwards by anyone, including the
Relay.

Consequences for this screen, all mandatory:

- **Rendering format is chosen before minting**, not after. There is no "render this existing
  token" affordance, because that endpoint cannot work.
- The result behaves like a **secret reveal**: shown once, prominently marked as such, not a
  document to return to.
- **There is no re-render.** Losing the artifact means minting another token and revoking the
  first. That is cheap and correct; a re-render button would be a lie.

## Layout

**Left — the mint form.** The `relay:` labels this token will stamp, max uses, expiry, and the
render formats. Then "Mint and render". Below it, the outstanding-token inventory with revoke.

**Right — the reveal.** A once-only banner, then the rendered artifacts in tabs (`ansible`, `join`,
env file), each with copy and download. Below, "what happens on each machine".

## Scope is the security lane

The labels a token stamps are `relay:` labels — Relay-set, Node-immutable, and the only valid
target for quarantine and secret-distribution Selectors. A token that stamps `relay:env=prod` is
therefore a privilege-granting act, which is why minting requires `admin`.

**#397 established by probe that this gate does not exist today**: `POST
/api/v1/enrollment-tokens` authenticates the caller and never checks their role, so a `viewer` can
mint a token that stamps `relay:` labels. Building this screen on an ungated mint would wrap a
privilege escalation in a convenience. Fix #397 first.

## The renderings

Three formats at beta, all renderings of the same three fields (join string, scope, expiry), so a
fourth is a template rather than an architectural change.

- **`ansible`** — a playbook that installs the pinned daemon version by digest (`get_url` +
  `checksum`, so verify-then-install survives), writes the env file at mode `0600`, and enables the
  unit. Carries the token inline, and its expiry in a header comment.
- **`join`** — the bare `glp_join_…` string: one opaque, `glp_`-prefixed token that is greppable by
  secret scanners and safe unquoted in a shell.
- **env file** — `RELAY_JOIN` plus `RELAY_NODE_LABELS`, the two lines a Node needs.

## What happens on each machine

Three steps, stated on screen because they are the trust story:

1. The daemon verifies the certificate the Relay presents against the **fingerprint pinned inside
   the join string**, before anything else. Wrong fingerprint and it exits — there is no fallback.
2. It presents the token once, receives its own identity certificate, and the Relay stamps the
   `relay:` labels on it.
3. It loads its Policy and comes up **read-only** per ADR-0022 — interrogable, unable to change
   anything, until the operator widens Policy themselves.

## Must not appear

- A re-render control, in any form, for any token.
- The token plaintext anywhere outside the one-time reveal — not in a list, not in an audit view,
  not in a log.
- Any Relay configuration.

## Acceptance

- [ ] Minting requires `admin`; a `viewer` and an `operator` are refused (and #397 is closed).
- [ ] Exactly one audit event per mint, recording what was rendered.
- [ ] The renderer has **no store dependency** — assert it structurally.
- [ ] Navigating away from the reveal and back does not show the artifacts again.
- [ ] The token plaintext appears in exactly one response and is never persisted.
- [ ] A daemon given a wrong CA fingerprint refuses enrollment and exits without falling back.
