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
[relay:quarantine] [node:env=prod] [node:role=web] [tag:pci] [state:template-drift]
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
unbroken.

**Fingerprints** — Policy and template-set, each with how many Nodes in the fleet share it. That
comparison is the whole value: confirming a rollout landed is string equality, not trust. Template
set may read the literal `unloadable`, which means the Node's local template set failed to load
and its template vocabulary is empty (fail closed).

**Facts** — OS, kernel, arch, hostname, IP, package count. Self-reported. **This page only:** not
on a fleet row, not in a facet, never targetable. Label the panel so an implementer does not
"helpfully" surface them elsewhere.

**Effective Policy** — rendered from `policyview`, queried live from the Node's own engine, with
the query timestamp shown. Read-only *structurally*, not by permission: there is no code path from
this screen to a Node's Policy, and the panel says so. Offer "ask a what-if" (a `PolicyQuery`)
and a link into the Policy Author (spec 06) seeded from this file.

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
  record.
- **`viewer`** — no label actions, no "Run here".
- **`console_execution = off`** — "Run here" is absent.

## Acceptance

- [ ] The effective-Policy panel is rendered from a daemon-evaluated query, never from a
      Relay-side reimplementation of Policy (invariant #12).
- [ ] The panel carries the timestamp of the query and cannot be mistaken for Relay-held state.
- [ ] Setting `relay:quarantine` demands `admin` + step-up and is audited with a reason.
- [ ] Editing a `tag:` label demands `operator` and no step-up.
- [ ] No surface anywhere writes a `node:` or `state:` label.
- [ ] Facts appear on this page and no other.
