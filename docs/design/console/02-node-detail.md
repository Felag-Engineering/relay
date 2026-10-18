# 02 — Node detail

**Artboard 2.** Reached from a fleet row or a pixel-wall cell. **Milestone v0.6.0** (read-only);
`relay:` and `tag:` writes arrive in v0.7.0.

**Governing:** ADR-0002, ADR-0006, ADR-0011, ADR-0020, ADR-0021, invariants #2, #7, #12.
**Backend:** registry read seams; `policyview` for the effective-Policy render (ADR-0011);
Task history from the store; label writes via the capability layer + Control API (v0.7.0).

## What this screen is for

Everything Relay knows about one machine, and the one place **Facts** live. It is also where the
incident ladder's first rung sits: setting or removing `relay:quarantine`.

## Layout

```
Fleet / prod / web-0442 ┄self-reported┄   node id 4e05a1c9-…(full ID, never truncated)   ● online, last seen 12s      [▷ Run here] [Pin to compare]
─────────────────────────────────────────────────────────────────────────────────────────
[relay:quarantine] [node:env=prod] [node:role=web] [tag:pci] [state:outdated]      
                                          [Edit tag: labels] [Remove quarantine · admin+step-up]
─────────────────────────────────────────────────────────────────────────────────────────
┌ Identity & enrollment ─┐  ┌ Effective Policy ───────────────────────────────────────┐
│ node id, cert sha256,  │  │ answered by this Node's own engine, 12s ago             │
│ issued/expires,        │  │ [read-only, structurally]                                │
│ renewals, enrolled via │  │   <verbatim policy.toml>                                 │
│ token, daemon version  │  └──────────────────────────────────────────────────────────┘
├ Fingerprints ──────────┤  ┌ Recent Tasks ────────────────────────────────────────────┐
│ policy (alias + hash,  │
│  [Edit alias] · admin),│
│ template set           │  │ when · operation · outcome · job                         │
├ Facts ─────────────────┤  └──────────────────────────────────────────────────────────┘
│ this page only         │
└────────────────────────┘
```

## Data

**Identity & enrollment** — `node_id`, certificate SHA-256, issued and expiry, renewal count and
last renewal (and `state:cert-expiring` when the warning window is crossed), the Enrollment Token it joined with and when, daemon version. Provenance is the
point: renewal is cert-authenticated and preserves `node_id`, so the chain back to enrollment is
unbroken. None of the certificate fields are persisted today — `registry.Node` carries only the
fingerprint — so this panel depends on #440 landing first.

**Heading** — the H1 is the Node's hostname, marked self-reported, with the verified node id
beneath it in mono. With no usable hostname (including one shaped like a Node ID) the H1 is the full Node ID, never a truncated one, and
it is not repeated beneath. (D20; D22 extends the same order to every place a Node is shown.)

**Fingerprints** — Policy and template-set, each with how many Nodes in the fleet share it. That
comparison is the whole value: confirming a rollout landed is string equality, not trust. The
Policy fingerprint is drawn in full with its Policy alias beside it, or the neutral per-render
letter where none is set (`00-foundations.md`, "Policy fingerprint"), and for a human `admin` an
**Edit alias** control that sets, renames or clears it, exactly as on the Fleet view (spec 01,
"Policy aliases"; D23). The alias names the fingerprint on this Relay; it is not this Node's
Policy, and the panel's "no path to this Node's Policy" note stays true. Template
set may read the literal `unloadable`, which means the Node's local template set failed to load
and its template vocabulary is empty (fail closed).

**Facts** — OS, kernel, arch, hostname, IP, package count. Self-reported. **In full on this page only.**
The hostname alone also names the Node, as the heading here and on a fleet row, marked
self-reported beside the verified Node ID (D20), and as Compare's column heading. No Fact is in a
facet, filterable or targetable. Label the panel so an implementer does not "helpfully" surface the
others elsewhere.

**Package count is not on the wire.** `registry.Facts` mirrors `relayv1.Facts` and neither carries
one, so adding it is a `/proto` change plus a daemon change — contract-first and escalated, not a
Console one. The panel renders the five Facts that exist.

**Effective Policy** — rendered from `policyview`, queried live from the Node's own engine, with
the query timestamp shown. Read-only *structurally*, not by permission: there is no code path from
this screen to a Node's Policy, and the panel says so. Offer "ask a what-if" (a `PolicyQuery`)
and a link to the Policy Catalog (spec 06). The catalog is not seeded from this Node: it
arranges first-party fragments, never a Node's own file.

**What shipped (#421):** the panel carries the instant the RELAY received the report, stamped
inside `policyview.Cache.Set` from the Relay's own clock and un-injectable by a caller. That is a
receipt time, not a query time — a snapshot is captured when a Node connects — and the panel says
which, because "queried 12s ago" would be a claim nothing supports. **Not implemented: "ask a
what-if".** A `PolicyQuery` is a live request through the capability layer's dispatch path, which
v0.6.0's "zero mutating routes" excludes; it belongs with the composer (spec 05) in v0.7.0. The
Policy Catalog link is role-gated to `operator` today; it follows PC-8 (`viewer`) when spec 06
lands. Where no snapshot has been received since the Relay last started, the panel says so in one
sentence and renders nothing else: an answer remembered from before a restart could be out of date
without saying so, and operators read this panel before deciding a Task is safe (#849).

**Recent Tasks** — time, Operation with arguments, outcome chip, Job link. Include denies; they
are the most informative rows here. Read-class rows say "output not retained" (ADR-0025).

## Labels

All four namespaces on one row, visually distinct per `00-foundations.md`, with a one-line
explainer of who sets each namespace a chip can carry here (`node:`, `relay:`, `state:`); `tag:` is
not named while no `tag:` label can exist (#849). Two actions, both v0.7.0:

- **Add and remove `tag:` labels on this Node** — `operator`, standard auth, no step-up, audited.
  The bulk form is on the Fleet view (spec 01).
- **Quarantine this Node** — `operator`+, with a reason; lifting is a human `admin` with step-up.
  The rules are spec 16's. No control on this screen writes a `relay:` label directly, because no
  Account may (invariant 7, amended 2026-09-16); `relay:quarantine=on` is only ever the side effect
  of engaging a quarantine.

`node:` labels are read-only here and everywhere. `state:` labels are derived and settable by
nobody, including admins — render them, never an edit affordance. The fingerprint rows in the
Fingerprints panel are the readable form of `state:policy-fingerprint=` and
`state:template-fingerprint=`; offer a link that targets the same value as a Selector.

## Pin to compare

Select 2–3 Nodes for a side-by-side diff of Facts and effective Policy. This is the "why did only
this one deny" flow in a single screen, and it is the reason Facts earn a detail page at all. Nodes
are pinned from this page's header or from any Fleet row (spec 01).

The pin bar appears on Fleet, Node detail and Compare. Off the Compare screen it always shows
"Compare these Nodes", disabled with "Pin 1 more to compare" below two pins, so one pin is never a
dead end. On a Node's own page its chip reads "this Node" and is not a link to the page already
open. Every other pin chip names its Node by hostname, marked self-reported, with the Node ID
secondary beside it (`00-foundations.md`, "Self-reported names"; D22); the chip's link and the pin
set in the query string carry the Node ID.

**Compare's column headings** lead with each Node's hostname, marked self-reported, with the
verified Node ID secondary beneath it in full (D22). The Policy fingerprint row draws each hash with
its alias or per-render letter, and the letters are assigned once per page, so the same fingerprint
carries the same letter in every column.

**Differences only** (owner decision, 2026-10-18, D28). Compare shows only the rows that differ by
default. A "Show differences only" checkbox, checked by default, sits in a GET form beside the pin
bar and carries the pin set; unchecking it and applying shows every row. The choice is a GET
parameter, so the view is linkable and needs no script. When nothing differs, the
screen says so in words — "These Nodes reported the same Policy and fingerprints." — rather than
drawing an empty table. A differing row is emphasised by **weight and a border**, with no new hue,
and the emphasis marks the **row**, never a cell: Compare says these differ and never which one is
right (QRY-9). A column that has not reported still marks its row as differing, and is never read
as agreement.

**Not implemented: the Facts half.** No Fact but the hostname appears off Node detail, and the hostname only as a name (the v0.6.0
acceptance criterion below), and a second screen diffing hostname/os/kernel/arch/ip would be the
second page they live on whatever it was called. `/console/compare` diffs fingerprints and reported
Policy — what is comparable ACROSS Nodes for a divergence question — and
`TestCompare_RendersNoFact` is the guard that keeps the promise true. The hostname appears only as
the heading naming each column, as it does on a fleet row; nothing else self-reported is on the
screen and nothing self-reported is compared. The pin set travels in the query string, so pinning
is a link here and a GET form on Fleet; neither writes anything, and no screen has a mutating route
for it.

## Must not appear

- Any Policy edit control. (The Edit alias control names a fingerprint on the Relay; it writes
  nothing a Node reads.)
- Any `node:` label edit control.
- Any `state:` label edit control.
- Host metrics of any kind.
- Daemon upgrade actions.

## States

- **Offline Node** — everything renders from the last known registry state, clearly stamped with
  last-seen. The effective-Policy panel cannot be refreshed and must say so rather than showing a
  stale answer as if it were live.
- **Revoked Node** — reachable by link from audit; renders its final state and the revocation
  record, including the REASON the operator gave. The endpoint requires one as of #487, which is
  what ADR-0020's incident ladder wanted for its middle and irreversible rung. A record predating
  that change has an attribution and a blank reason because there was nowhere to put one; the page
  says so explicitly rather than showing an empty field, because "no reason was given" and "this
  Relay could not ask for one" are different facts. The CAUSATIVE record is shown, not the latest:
  revoke is idempotent, so a later re-revoke must not relabel why the Node was revoked. A Node
  revoked by a token cascade now shows the derived cause instead of falling through to the "no
  revocation record" branch (#557); the causative-record rule is unchanged, and a Node already
  revoked when the cascade reaches it keeps its original record.
- **Unreported Node** — the same predicate as the fleet view: no recorded daemon version, or no
  recorded Policy fingerprint. When a Policy snapshot was captured on the tunnel anyway, the panel
  still renders it, as the Node's daemon-reported Policy, and states the facts: the snapshot's own
  fingerprint, and which recorded field the Relay lacks. When the fingerprint is missing it adds
  that the snapshot cannot be cross-checked against the fingerprint the fleet is compared by; when
  only the daemon version is missing it makes no cross-check claim. Either way it says the Console
  does not count the Node as current or permitted. The Fingerprints panel keeps saying "not
  reported".
- **`viewer`** — no label actions, no "Run here".
- **`console_execution = off`** — "Run here" is absent.

## Acceptance

- [x] The effective-Policy panel is rendered from a daemon-evaluated query, never from a
      Relay-side reimplementation of Policy (invariant #12).
      **Qualified (#421), the same way box 2 is.** It is a daemon-evaluated REPORT, not a live
      query: the daemon's own engine produced it and the Relay only stores and renders it
      (`policyview`), but the Relay does not ask — the snapshot arrives when the Node connects.
      The half invariant #12 is about holds absolutely: nothing on the Relay evaluates Policy.
- [x] The panel carries the timestamp of the query and cannot be mistaken for Relay-held state.
      **Qualified (#421).** What is shown is the RELAY's receipt time for a snapshot the Node
      reported on connection, stamped inside `policyview.Cache.Set` so no caller — and therefore no
      Node — can supply it. It is not a query timestamp, because nothing re-asks the Node: the live
      half is `PolicyQuery`, deferred to v0.7.0 with the composer. The panel says "received", never
      "queried", and an offline Node's panel says it cannot be refreshed.
- [ ] Setting `relay:quarantine` demands `admin` + step-up and is audited with a reason.
      **Not implemented (v0.7.0).** Label writes go through the capability layer with #430; v0.6.0
      is read-only, so there is no set/remove control on this screen at any role.
- [ ] Editing a `tag:` label demands `operator` and no step-up.
      **Not implemented (#430).** `tag:` has no storage on `registry.Node` yet, so no chip renders
      and no control exists. The label explainer does not name it: no `tag:` chip can render, and a key
      for a namespace that cannot appear is copy without data (#849).
- [x] No surface anywhere writes a `node:` or `state:` label.
- [x] Facts appear on this page and no other. **Two qualifications.** First, the hostname is the
      self-reported visual primary of a fleet row and of this page's heading, always beside the
      verified Node ID and never filterable or targetable (D20). Second, `/console/compare` diffs no
      Fact — os, kernel, arch and ip are absent from it entirely, and `TestCompare_RendersNoFact`
      asserts that, including that none is a row key. It does render each Node's HOSTNAME as the
      heading identifying its column, which is the use a fleet row already makes of one
      (`newFleetNode`); it is self-reported like every Fact, it is never diffed and never
      targetable, and the screen says so where an operator reads it.
