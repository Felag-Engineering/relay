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
last renewal (and `state:cert-expiring` when the warning window is crossed), the Enrollment Token
it joined with and when, daemon version. Provenance is the point: renewal is cert-authenticated
and preserves `node_id`, so the chain back to enrollment is unbroken.

**Heading** — the H1 is the Node's hostname, marked self-reported, with the verified Node ID
beneath it in mono. With no usable hostname (including one shaped like a Node ID) the H1 is the
full Node ID, not repeated beneath (D20, D22).

**Fingerprints** — Policy and template-set, each with how many Nodes in the fleet share it. That
comparison is the whole value: confirming a rollout landed is string equality, not trust. The
Policy fingerprint follows `00-foundations.md` ("Policy fingerprint"), with the same **Edit alias**
control for a human `admin` as the Fleet view (spec 01, "Policy aliases"; D23). The alias names the
fingerprint on this Relay; it is not this Node's Policy. Template set may read the literal
`unloadable`: the Node's local template set failed to load and its template vocabulary is empty
(fail closed).

**Facts** — OS, kernel, arch, hostname, IP, package count. Self-reported. **In full on this page only.**
The hostname alone also names the Node — the heading here, a fleet row, Compare's column heading —
marked self-reported beside the verified Node ID. No Fact is in a facet, filterable or targetable.
Label the panel so an implementer does not "helpfully" surface the others elsewhere.

**Package count is not on the wire.** `registry.Facts` mirrors `relayv1.Facts` and neither carries
one; adding it is a `/proto` and daemon change, contract-first and escalated. The panel renders the
five Facts that exist.

**Effective Policy** — rendered from `policyview`: the Node's own engine's report. Read-only
*structurally*: there is no code path from this screen to a Node's Policy, and the panel says so.
It links to the Policy Catalog (spec 06), which arranges first-party fragments and is never seeded
from a Node's own file.

The panel carries the instant the Relay **received** the report, stamped inside
`policyview.Cache.Set` from the Relay's own clock, which no caller can inject. It is a receipt time,
not a query time — a snapshot is captured when a Node connects — and the panel says "received",
never "queried". **Not implemented: "ask a what-if".** A `PolicyQuery` is a live request through the
capability layer's dispatch path, so it belongs with the composer (spec 05, v0.7.0). The Policy
Catalog link is role-gated to `operator`; it follows PC-8 (`viewer`) when spec 06 lands. Where no
snapshot has been received since the Relay last started, the panel says so in one sentence and
renders nothing else: an answer remembered from before a restart could be out of date without
saying so, and operators read this panel before deciding a Task is safe.

**Recent Tasks** — time, Operation with arguments, outcome chip, Job link. Include denies; they
are the most informative rows here. Read-class rows say "output not retained" (ADR-0025).

## Labels

All four namespaces on one row, visually distinct per `00-foundations.md`, with a one-line
explainer of who sets each namespace a chip can carry here (`node:`, `relay:`, `state:`); `tag:` is
not named while no `tag:` label can exist. Two actions, both v0.7.0:

- **Add and remove `tag:` labels on this Node** — `operator`, standard auth, no step-up, audited.
  The bulk form is on the Fleet view (spec 01).
- **Quarantine this Node** — `operator`+, with a reason; lifting is a human `admin` with step-up.
  The rules are spec 16's. No control writes a `relay:` label directly, because no Account may
  (invariant 7); `relay:quarantine=on` is only ever the side effect of engaging a quarantine.

`node:` labels are read-only here and everywhere. `state:` labels are derived and settable by
nobody, including admins — render them, never an edit affordance. The fingerprint rows in the
Fingerprints panel are the readable form of `state:policy-fingerprint=` and
`state:template-fingerprint=`; offer a link that targets the same value as a Selector.

## Pin to compare

Select 2–3 Nodes for a side-by-side diff — the "why did only this one deny" flow in a single
screen. Nodes are pinned from this page's header or from any Fleet row (spec 01).

The pin bar appears on Fleet, Node detail and Compare. Off Compare it always shows "Compare these
Nodes", disabled with "Pin 1 more to compare" below two pins, so one pin is never a dead end. On a
Node's own page its chip reads "this Node" and is not a link. Every other pin chip names its Node
per `00-foundations.md` ("Self-reported names"); the chip's link and the query string carry the
Node ID.

**Compare's column headings** lead with each Node's hostname, marked self-reported, with the
verified Node ID beneath it in full. The Policy fingerprint row draws each hash with its alias or
per-render letter, assigned once per page, so a fingerprint carries the same letter in every
column.

**Differences only** (D28). By default Compare shows only rows that differ. A "Show differences
only" checkbox, checked by default, sits in a GET form beside the pin bar and carries the pin set;
unchecking it shows every row. It is a GET parameter, so the view is linkable and needs no script.
When nothing differs, the screen says so in words — "These Nodes reported the same Policy and fingerprints." — rather than
drawing an empty table. A differing row is emphasised by **weight and a border**, with no new hue,
and the emphasis marks the **row**, never a cell: Compare says these differ and never which one is
right (QRY-9). A column that has not reported still marks its row as differing, and is never read
as agreement.

**Not implemented: the Facts half.** No Fact but the hostname appears off Node detail, and the
hostname only as a name (acceptance below); a screen diffing os/kernel/arch/ip would be a second
page Facts live on. `/console/compare` diffs fingerprints and reported Policy, and
`TestCompare_RendersNoFact` keeps it that way. The hostname appears only as each column's heading;
nothing else self-reported is on the screen and nothing self-reported is compared. Pinning is a
link here and a GET form on Fleet; neither writes anything.

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
  record, including the reason the operator gave (required, ADR-0020). An older record with a blank
  reason says so explicitly, because "no reason was given" and "this Relay could not ask for one"
  are different facts. The **causative** record is shown, not the latest: revoke is idempotent, so
  a later re-revoke must not relabel why. A Node revoked by a token cascade shows the derived cause;
  a Node already revoked when the cascade reaches it keeps its original record.
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
      **Qualified, as box 2 is.** It is a daemon-evaluated report, not a live query: the snapshot
      arrives when the Node connects, and the Relay only stores and renders it (`policyview`).
      Invariant #12 holds absolutely: nothing on the Relay evaluates Policy.
- [x] The panel carries the timestamp of the query and cannot be mistaken for Relay-held state.
      **Qualified.** It is the Relay's receipt time, stamped inside `policyview.Cache.Set` so no
      caller or Node can supply it, not a query time: the live half is `PolicyQuery`, v0.7.0 with
      the composer. The panel says "received", never "queried", and an offline Node's panel says it
      cannot be refreshed.
- [ ] Setting `relay:quarantine` demands `admin` + step-up and is audited with a reason.
      **Not implemented (v0.7.0).** Label writes go through the capability layer with #430; v0.6.0
      is read-only, so there is no set/remove control on this screen at any role.
- [ ] Editing a `tag:` label demands `operator` and no step-up.
      **Not implemented (#430).** `tag:` has no storage on `registry.Node`, so no chip renders and
      no control exists, and the label explainer does not name it.
- [x] No surface anywhere writes a `node:` or `state:` label.
- [x] Facts appear on this page and no other. **Qualified:** the hostname names a fleet row, this
      page's heading and each Compare column, always beside the verified Node ID, never diffed,
      filterable or targetable. `TestCompare_RendersNoFact` asserts that os, kernel, arch and ip
      are absent from Compare, including as row keys.
