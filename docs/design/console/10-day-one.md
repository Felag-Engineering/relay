# 10 — Day one

**Artboard 8.** The Console with zero Nodes. **Milestone v0.6.0.**

**Governing:** ADR-0030, ADR-0031, ADR-0033.
**Backend:** registry (empty); the SSE seam's enrollment-attempt publisher (D9's fourth, #416);
the CA and server-leaf fingerprints from startup.

## What this screen is for

After `relay init`, a brand-new Relay has **no Nodes**, and every other screen in this set is
designed for thousands. This is the first thing a new operator ever sees and it decides whether
they continue. It is not an error state and it is not a decorated blank.

## Contents

1. **A plain statement.** "Nothing has joined yet." Then what *is* true: the Relay is running, its
   CA is issued, the founding admin Account exists.
2. **One path forward** — Add your first Nodes — plus a quickstart link. One primary action; no
   competing calls.
3. **A live watch.** "Watching for enrollments", with a live indicator and the honest current
   state ("no enrollment attempts in the last hour"). This turns the empty state into something
   worth leaving open while a playbook runs, and it is the fastest possible feedback loop for the
   most failure-prone step in the product.
4. **What a machine needs in order to trust this Relay** — the reachable address, the **CA
   fingerprint** and the **server certificate fingerprint**. Both are printed on the Relay's
   console at first boot, and comparing them there before handing a join string to anything is the
   only thing standing between a fleet and a Relay that merely claims to be this one.

## What this screen is not

- Not a tutorial. Do not embed the quickstart; link it.
- Not a feature tour. Do not describe screens that have no data.
- Not a checklist of setup steps the Console cannot verify.
- Not a settings page. The fingerprints and address are shown because a machine needs them to
  join, in context — not as an inventory of configuration (invariant #11).

## Failure feedback

The watch panel is the right place for **rejected** enrollment attempts, and they are more valuable
than successes. It shows what the Relay can honestly attribute — **Relay-side rejections**: an
expired, revoked or unknown token, a token past `max_uses`, a malformed join string. Each carries
the attempt's source, the token ID (never plaintext) and the reason. Otherwise that whole failure
class surfaces as journald lines on N machines after the fact.

**A wrong CA fingerprint is rejected on the daemon**, before it sends anything (ADR-0031): the Relay
sees at most a TLS handshake aborted by the peer — a source address and no token. Surfacing that as
"a connection from *addr* aborted the handshake before enrolling — usually a fingerprint mismatch"
needs a listener hook and is a follow-up (#444), not v0.6.0 scope. Until then the quickstart carries
the check, and the screen must not claim to see what it cannot.

## Transition

The moment the first Node enrolls, this screen is replaced by the fleet view (spec 01). Do not
keep a "getting started" panel around afterwards; the empty state's job is finished.

## Acceptance

- [ ] With zero Nodes, no screen renders an empty table or a zeroed statistic.
- [ ] Both fingerprints are shown and are the same values the Relay printed at first boot.
- [ ] A Relay-side enrollment rejection appears here with its reason, live; the screen never
      claims to see daemon-side rejections.
- [ ] The first successful enrollment moves the operator to the fleet view without a reload.
- [ ] Nothing on this screen exposes a token, a private key, or any Relay configuration value.

## Deviations from this document, as built (#427)

Five, each of them this specification's own honesty rule beating its own illustrative prose.

**No reachable address.** Contents item 4 asks for one; acceptance criterion 5 forbids exposing
"any Relay configuration value", and a listen address is exactly that — operator-set at startup and
unreachable from any API (invariant #11). The Console holds no address of any kind, and the seam it
reads the fingerprints through (`console/seams.go`) states that absence as a property. The address a
Node dials is delivered today by whatever installs the daemon (`RELAY_ADDR`,
`daemon/src/config.rs`), and ADR-0031's join string will carry it once that lands. The checkbox is
authoritative over the prose.

**The server certificate is labelled as rotating, not as a boot-time constant.** Criterion 2 asks
for "the same values the Relay printed at first boot", and ADR-0031 decides the opposite for the
leaf: it is re-issued about daily, so an exception pinned to it breaks at every rotation. The CA
fingerprint is rendered first as the value to compare; the control-plane leaf is rendered beside it
and says in words that it is not what you pin. The Relay logs the CA fingerprint at
startup (`relay certificate authority`), which is what makes the criterion checkable. ADR-0031
decision 1 (one certificate for both listeners) is not implemented, so "the server certificate" is
still listener-scoped and the screen names which listener it means.

**The quickstart is named, not linked.** "One path forward — Add your first Nodes — plus a
quickstart link." `docs/quickstart.md` does not exist (#402, `v0.1.0-beta`), so the screen renders
the document's path in mono the way a placeholder screen names its specification. A link that 404s
on the first screen a new operator sees is worse than a path they can look for.

**The CA fingerprint is described as a value to compare, not as a value anything pins.** ADR-0031
decision 3 makes it the number a daemon pins, through a join string; neither is built — nothing in
`relay/`, `daemon/` or `proto/` carries a CA fingerprint, and a daemon trusts this Relay because it
was installed with the CA bundle (`daemon/src/tunnel.rs`). The copy says what the value is for
without asserting a mechanism the tree does not have.

**The watch states ten minutes, not "the last hour".** The event seam retains 1,000 events or
10 minutes, whichever comes first, and the screen renders whatever the seam reports through
`EventReader.RetentionWindow` rather than a constant of its own. A screen quoting a window wider than
its buffer would be claiming to see what it cannot, which is what the failure-feedback section
above forbids.
