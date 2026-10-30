# 10 — Day one

**Artboard 8.** The Console with zero Nodes. **Milestone v0.6.0.**

**Governing:** ADR-0030, ADR-0031, ADR-0033.
**Backend:** registry (empty); the SSE seam's enrollment-attempt publisher (D9's fourth, #416);
the CA and server-leaf fingerprints from startup.

## What this screen is for

After `relay init --admin`, a brand-new Relay has **no Nodes**, and every other screen is designed
for thousands. This is the first thing a new operator sees, and it decides whether they continue.
It is not an error state and not a decorated blank.

## Contents

1. **A plain statement.** "Nothing has joined yet." Then what *is* true: the Relay is running, its
   CA is issued, and the first Account exists (the one signed in).
2. **One path forward** — Add your first Nodes — plus a quickstart link. One primary action; no
   competing calls.
3. **A live watch.** "Watching for enrollments", with a live indicator and the honest current
   state ("no enrollment attempts in the last hour"). It makes the empty state worth leaving open
   while a playbook runs: the fastest feedback loop for the product's most failure-prone step.
4. **What a machine needs in order to trust this Relay** — the reachable address, the **CA
   fingerprint** and the **server certificate fingerprint**. Both are printed on the Relay's
   console at first boot; comparing them before handing a join string to anything is the only
   thing standing between a fleet and a Relay that merely claims to be this one.

## What this screen is not

- Not a tutorial. Do not embed the quickstart; link it.
- Not a feature tour. Do not describe screens that have no data.
- Not a checklist of setup steps the Console cannot verify.
- Not a settings page. The fingerprints and address are shown because a machine needs them to
  join, in context — not as an inventory of configuration (invariant #11).

## Failure feedback

The watch panel is the place for **rejected** enrollment attempts, which are more valuable than
successes. It shows what the Relay can honestly attribute — **Relay-side rejections**: an expired,
revoked or unknown token, a token past `max_uses`, a malformed join string. Each carries the
attempt's source, the token ID (never plaintext) and the reason. Otherwise that failure class
surfaces as journald lines on N machines after the fact.

**A wrong CA fingerprint is rejected on the daemon**, before it sends anything (ADR-0031): the Relay
sees at most a TLS handshake aborted by the peer — a source address and no token. Surfacing that as
"a connection from *addr* aborted the handshake before enrolling — usually a fingerprint mismatch"
needs a listener hook (#444). Until then the quickstart carries the check, and the screen must not
claim to see what it cannot.

## Transition

The moment the first Node enrolls, this screen is replaced by the fleet view (spec 01). No
"getting started" panel survives it.

## Acceptance

- [ ] With zero Nodes, no screen renders an empty table or a zeroed statistic.
- [ ] Both fingerprints are shown and are the same values the Relay printed at first boot.
- [ ] A Relay-side enrollment rejection appears here with its reason, live; the screen never
      claims to see daemon-side rejections.
- [ ] The first successful enrollment moves the operator to the fleet view without a reload.
- [ ] Nothing on this screen exposes a token, a private key, or any Relay configuration value.

## Deviations from this document, as built (#427)

Five, each this specification's honesty rule beating its own illustrative prose.

**No reachable address.** Contents item 4 asks for one; acceptance criterion 5 forbids exposing
"any Relay configuration value", and a listen address is one — operator-set and unreachable from
any API (invariant #11). The Console holds no address, and the seam it reads the fingerprints
through (`console/seams.go`) states that absence as a property. A Node gets the address it dials
from its join string, or from `RELAY_ADDRESS` (`daemon/src/config.rs`). The checkbox is authoritative
over the prose.

**The server certificate is labelled as rotating, not as a boot-time constant.** Criterion 2 asks
for "the same values the Relay printed at first boot", but ADR-0031 has the leaf re-issued about
daily, so an exception pinned to it breaks at every rotation. The CA fingerprint is rendered first
as the value to compare; the server leaf beside it says in words that it is not what you
pin. The Relay logs the CA fingerprint at startup (`relay certificate authority`), which makes the
criterion checkable. One certificate serves both listeners (ADR-0031 decision 1), so the leaf
shown is the one the browser is talking to.

**The quickstart is named, not linked.** `docs/quickstart.md` is a file in the repository, which the
Relay does not serve, so the screen renders its path in mono, as a placeholder screen names its
specification, rather than as a link that would 404. A broken link on the first screen a new
operator sees is worse than a path they can look for.

**The CA fingerprint is described as a value to compare, not as a value anything pins.** ADR-0031
decision 3 makes it the number a daemon pins, through a join string. The screen's copy says only
that a daemon trusts this Relay because it was installed with the CA bundle (relay-transport
`tunnel`), and says what the value is for without naming the pin.

**The watch states ten minutes, not "the last hour".** The event seam retains 1,000 events or 10
minutes, whichever comes first, and the screen renders what the seam reports through
`EventReader.RetentionWindow`, not a constant of its own. Quoting a wider window would claim to see
what it cannot.
