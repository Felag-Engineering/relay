# 10 — Day one

**Artboard 8.** The Console with zero Nodes. **Milestone v0.6.0.**

**Governing:** ADR-0030, ADR-0031, ADR-0033.
**Backend:** registry (empty); the enrollment-attempt event stream; the CA and server-leaf
fingerprints from startup.

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

The watch panel is the right place for **rejected** enrollment attempts, and they are more
valuable than successes: a wrong fingerprint, an expired token, a token past `max_uses`, a
malformed join string. Each is a failure an operator would otherwise discover as journald lines on
N machines after the fact. Show the attempt, its source, and the reason.

## Transition

The moment the first Node enrolls, this screen is replaced by the fleet view (spec 01). Do not
keep a "getting started" panel around afterwards; the empty state's job is finished.

## Acceptance

- [ ] With zero Nodes, no screen renders an empty table or a zeroed statistic.
- [ ] Both fingerprints are shown and are the same values the Relay printed at first boot.
- [ ] A failed enrollment attempt appears here with its reason, live.
- [ ] The first successful enrollment moves the operator to the fleet view without a reload.
- [ ] Nothing on this screen exposes a token, a private key, or any Relay configuration value.
