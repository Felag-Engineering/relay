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
Fleet / prod / web-0442        ● online, last seen 12s      [▷ Run here] [Pin to compare]
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
│ policy, template set   │  │ when · operation · outcome · job                         │
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

**Fingerprints** — Policy and template-set, each with how many Nodes in the fleet share it. That
comparison is the whole value: confirming a rollout landed is string equality, not trust. Template
set may read the literal `unloadable`, which means the Node's local template set failed to load
and its template vocabulary is empty (fail closed).

**Facts** — OS, kernel, arch, hostname, IP, package count. Self-reported. **This page only:** not
on a fleet row, not in a facet, never targetable. Label the panel so an implementer does not
"helpfully" surface them elsewhere.

**Package count is not on the wire.** `registry.Facts` mirrors `relayv1.Facts` and neither carries
one, so adding it is a `/proto` change plus a daemon change — contract-first and escalated, not a
Console one. The panel renders the five Facts that exist.

**Effective Policy** — rendered from `policyview`, queried live from the Node's own engine, with
the query timestamp shown. Read-only *structurally*, not by permission: there is no code path from
this screen to a Node's Policy, and the panel says so. Offer "ask a what-if" (a `PolicyQuery`)
and a link into the Policy Author (spec 06) seeded from this file.

**What shipped (#421):** the panel carries the instant the RELAY received the report, stamped
inside `policyview.Cache.Set` from the Relay's own clock and un-injectable by a caller. That is a
receipt time, not a query time — a snapshot is captured when a Node connects — and the panel says
which, because "queried 12s ago" would be a claim nothing supports. **Not implemented: "ask a
what-if".** A `PolicyQuery` is a live request through the capability layer's dispatch path, which
v0.6.0's "zero mutating routes" excludes; it belongs with the composer (spec 05) in v0.7.0. The
Policy Author LINK ships, role-gated to `operator`.

**Recent Tasks** — time, Operation with arguments, outcome chip, Job link. Include denies; they
are the most informative rows here. Read-class rows say "output not retained" (ADR-0025).

## Labels

All four namespaces on one row, visually distinct per `00-foundations.md`, with a one-line
explainer of who sets each. Two actions, both v0.7.0:

- **Edit `tag:` labels** — `operator`, standard auth, no step-up.
- **Set/remove `relay:` labels** — `admin` **plus step-up**. This is the quarantine lever, and it
  sits at the bottom of the incident ladder: quarantine < revoke < Freeze.

`node:` labels are read-only here and everywhere. `state:` labels are derived and settable by
nobody, including admins — render them, never an edit affordance. The fingerprint rows in the
Fingerprints panel are the readable form of `state:policy-fingerprint=` and
`state:template-fingerprint=`; offer a link that targets the same value as a Selector.

## Pin to compare

Select 2–3 Nodes for a side-by-side diff of Facts and effective Policy. This is the "why did only
this one deny" flow in a single screen, and it is the reason Facts earn a detail page at all.

**Not implemented: the Facts half.** Facts appear on Node detail and nowhere else (the v0.6.0
acceptance criterion below), and a second screen diffing hostname/os/kernel/arch/ip would be the
second page they live on whatever it was called. `/console/compare` diffs fingerprints and reported
Policy — what is comparable ACROSS Nodes for a divergence question — and
`TestCompare_RendersNoFact` is the guard that keeps the promise true. The hostname appears only as
the heading naming each column, as it does on a fleet row; nothing else self-reported is on the
screen and nothing self-reported is compared. The pin set travels in the query string, so pinning
is a link and this screen has no mutating route.

## Must not appear

- Any Policy edit control.
- Any `node:` label edit control.
- Any `state:` label edit control.
- Host metrics of any kind.
- Daemon upgrade actions.

## States

- **Offline Node** — everything renders from the last known registry state, clearly stamped with
  last-seen. The effective-Policy panel cannot be refreshed and must say so rather than showing a
  stale answer as if it were live.
- **Revoked Node** — reachable by link from audit; renders its final state and the revocation
  record. The trail attributes the revoke; it records no REASON, because
  `POST /api/v1/nodes/{id}/revoke` does not accept one (`api/nodes.go` passes `""`). The page says
  that rather than showing an empty field — follow-up: give the endpoint a reason, as ADR-0020's
  incident ladder arguably requires for its middle and irreversible rung.
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
      and no control exists. The label explainer says so rather than leaving the namespace unnamed.
- [x] No surface anywhere writes a `node:` or `state:` label.
- [x] Facts appear on this page and no other. **One qualification.** `/console/compare` diffs no
      Fact — os, kernel, arch and ip are absent from it entirely, and `TestCompare_RendersNoFact`
      asserts that, including that none is a row key. It does render each Node's HOSTNAME as the
      heading identifying its column, which is the use a fleet row already makes of one
      (`newFleetNode`); it is self-reported like every Fact, it is never diffed and never
      targetable, and the screen says so where an operator reads it.
