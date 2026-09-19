# Policy Catalog

**Status:** designed, not built, as of `2026-09-19`.
**Claim prefix:** `PC`

## Purpose

Giving a Node a little more permission — let it restart nginx — should be a one-line change in
the customer's config management, not an afternoon of hand-editing a Policy file. The Policy
Catalog makes that true by publishing **catalog fragments**: first-party, pre-made Policy
fragments an operator selects by name, arranges into cohorts that match their config-management
groups, and hands to config management to install.

It is a planning aid that ends at the operator's clipboard. The Relay never applies Policy to a
Node, and nothing here changes that: the catalog makes the *authoring* half of Policy cheap while
leaving the *delivery* half exactly where invariant 2 puts it. Widening what a Node will ever do
stays a deliberate local act; the catalog only makes it a short one.

The shipped default Policy is not part of the catalog. It keeps its own rules (ADR-0022,
ADR-0033): installed once if absent, the operator's file from then on. Catalog fragments are
additions beside it, each opt-in.

## Surfaces

| Surface | What it does |
|---|---|
| **Console** | Where built (PC-8 to PC-16), the Policy Catalog screen: browse catalog fragments, arrange them into cohorts, add narrowing deny rules, export. It writes nothing |
| **Release artifacts** | Where built (PC-2), the catalog is published with each release under the release `SHA256SUMS`, beside the daemon binary |
| **The customer's config management** | The only installer. It runs the exported install task, which places selected fragments in a Node's Policy directory (`daemon-installation.md`) |
| **MCP, Control API** | Nothing. Catalog fragments are published release content; an AI-agent that needs one reads the release. A Policy change an AI-agent proposes ends as a proposal a human ships through config management (`policy.md`) |

## Behaviour

Nothing yet. The catalog is unbuilt; everything it will do is under *Designed, not built*. The
one statement true of `main` today is the refusal below, which the catalog must never make
untrue.

## Refusals

- **PC-1** No Relay surface — MCP, the Control API or the Console — writes, transmits, signs or
  applies Policy content to a Node, and no message on the Node connection carries Policy content
  towards the daemon.

## Governing ADRs and invariants

- **Invariant 2 / ADR-0002** — the catalog's whole shape. Output ends at download or clipboard;
  delivery is the customer's config management. Distributing Policy through the Relay is Future
  work in `policy.md`, admissible only if it adds no path by which the Relay can widen what a Node
  permits, and would need its own ADR; the catalog does not approach it.
- **Invariant 3 / ADR-0002** — deny-by-default is untouched: a catalog fragment not in a Node's
  Policy directory permits nothing. The screen's own authoring emits deny rules only.
- **Invariant 12 / ADR-0011** — the screen describes what a fragment grants; it never computes
  whether a given Task would be allowed. Verdicts come from the daemon's engine.
- **Invariant 9 / ADR-0008** — the Relay stores no cohort arrangement, so it holds no description
  of what any Node's Policy *should* be.
- **Invariant 10** — the Console screen is an adapter. The capability layer decides who may open
  it and serves the Node counts it shows, through the read lane.
- **Invariant 13 / ADR-0012** — each catalog fragment declares its highest risk class, and the
  screen groups by it.
- **Invariant 14 / ADR-0014** — a fragment's required daemon release is advisory to the operator;
  the Relay never upgrades a daemon to meet it.
- **Invariant 1 / ADR-0001** — no catalog fragment enables Raw Exec.
- **ADR-0021** — Templates load from template files beside the Policy, not from Policy
  fragments; the Templates-in-Policy model in `policy.md` is not ratified. So no catalog fragment
  defines a Template of any class. A first-party `mutate` Template would be a further decision.
- **ADR-0022, ADR-0033** — the shipped default Policy stays outside the catalog and keeps its
  place-if-absent, operator-owned rules.
- **ADR-0026** — Console security; the screen mounts no write route.

## Seams and proof

Once built, the catalog's content is proven where it is published: CI runs the daemon's own
`policy check` against every catalog fragment and compares each against its previous release, so
a fragment the daemon cannot load, or one widened in place, fails the build rather than a fleet.
The screen is proven at the Console's handler seam; PC-1 by the structural guard that no adapter
reaches a Node except through dispatch. `make verify` is sufficient; nothing here needs the dev
fleet.

### What proves each claim

| Claim | Proven by | Seam |
|---|---|---|

No row yet: PC-1.

### Performance

| Characteristic | Contract | Measured by |
|---|---|---|
| Catalog size | Every catalog fragment renders on one screen; no pagination contract | *(none)* |

## Designed, not built

Every row depends on the daemon loading a Policy directory beside the Policy file, specified in
`daemon-installation.md` and delivered by #648 in the same milestone.

| Claim | Statement | Milestone |
|---|---|---|
| PC-2 | The catalog is one first-party set of catalog fragments, maintained in the repository and versioned with the release. It is published as a release artifact under the release `SHA256SUMS`, and the Relay embeds byte-identical copies; no surface adds to, edits or removes a catalog fragment. | v0.7.0 — Admin Console: Administration & Execution |
| PC-3 | Every catalog fragment declares a name, a one-line purpose, its highest risk class, the Operations it permits, and its required daemon release — the earliest relay-daemon release that can load it. | v0.7.0 — Admin Console: Administration & Execution |
| PC-4 | Every catalog fragment is opt-in and permits only Native Operations, with every argument scoped to named values — for example `service.restart` of the unit `nginx`. No catalog fragment defines a Template, enables Raw Exec, or replaces the shipped default Policy. | v0.7.0 — Admin Console: Administration & Execution |
| PC-5 | Every catalog fragment is accepted by the daemon's `policy check --strict` alone, beside the shipped default Policy, and composed with every other catalog fragment; CI fails the build otherwise. | v0.7.0 — Admin Console: Administration & Execution |
| PC-6 | A catalog fragment never permits, in a later release, anything it did not permit in an earlier one under the same name. A fragment that permits more ships under a new name that someone must choose. CI fails a release that widens a fragment in place. | v0.7.0 — Admin Console: Administration & Execution |
| PC-7 | A catalog fragment is live on a Node only once config management places it in that Node's Policy directory. Nothing in a release, and nothing on the Relay, places one there. | v0.7.0 — Admin Console: Administration & Execution |
| PC-8 | The Console's Policy Catalog screen is available to every role from `viewer` up, decided by the capability layer. It lists every catalog fragment with its declared fields and its full text. | v0.7.0 — Admin Console: Administration & Execution |
| PC-9 | On the screen an operator arranges catalog fragments into named cohorts. The arrangement lives in the page address and in the export; the Relay stores nothing about it. | v0.7.0 — Admin Console: Administration & Execution |
| PC-10 | Pasting an exported group-variables block into the screen reopens the arrangement it describes. Parsing it records nothing. | v0.7.0 — Admin Console: Administration & Execution |
| PC-11 | Per cohort, the operator may add deny rules; the screen emits them as one operator-owned deny fragment. The screen never emits an allow rule. | v0.7.0 — Admin Console: Administration & Execution |
| PC-12 | Per cohort, the screen exports: the selected catalog fragments and the cohort's deny fragment as files; a group-variables block naming them; and an install task that validates each file with the daemon's `policy check`, places it in the Policy directory, and restarts the unit. There is no single-file export for daemons that predate the Policy directory. | v0.7.0 — Admin Console: Administration & Execution |
| PC-13 | The screen states in plain language what each catalog fragment grants, and never states whether a particular Task would be allowed; it points to `policy check --would-allow` and Policy preflight for that. | v0.7.0 — Admin Console: Administration & Execution |
| PC-14 | Where a catalog fragment's required daemon release is newer than a Node's daemon, the screen says how many Nodes that is and what happens on each: on a daemon that predates the Policy directory, the fragment is silently not loaded; on a later daemon that cannot load it, the whole Policy is invalid and the Node refuses every Task. The count is an audited registry read, refused when it cannot be recorded (`query.md`). | v0.7.0 — Admin Console: Administration & Execution |
| PC-15 | The Policy Catalog screen has no control that writes, pushes, distributes or applies Policy, and no route beneath it accepts a write. The screen says, on the screen, that it applies nothing. | v0.7.0 — Admin Console: Administration & Execution |
| PC-16 | Every exported catalog fragment is shown with its SHA-256, and the exported install task refuses to place a catalog fragment whose digest does not match the release `SHA256SUMS` the operator obtained from the release — never a digest supplied only by the Relay. | v0.7.0 — Admin Console: Administration & Execution |

## Out of scope

- **Writing allow rules.** An allow the catalog does not cover is written in the customer's IaC
  repo, or produced one rule at a time from a denial by Console screen spec 07. The catalog
  screen emits deny rules only (PC-11).
- **The shipped default Policy**: `daemon-installation.md` and ADR-0022.
- **Customer-authored catalog entries.** The catalog is first-party. A customer's own fragments
  live in their IaC repo, never in the Relay.
- **Saved, shared or compared cohorts.** Storing what a cohort should run, or comparing Nodes
  against it, is a desired-state description (invariant 9) and needs an ADR.
- **A first-party Ansible role and OS packages** carrying the catalog: Future work in
  `daemon-installation.md`. The exported install task stands alone.
- **Delivering fragments and restarting the daemon**: `daemon-installation.md`, through config
  management.
- **What a fragment may contain and how it is evaluated**: `policy.md`. Hypothetical evaluation:
  `policy-preflight.md`.
- **Displaying a Node's current Policy**: `query.md`.

## Future work

- **Catalog fragments that define Templates** — for example nginx config test and reload, or
  journal vacuum. Needs a decision that first-party `mutate` Templates are admissible (a new ADR
  or an ADR-0021 amendment), #626 so a Template can be dispatched at all, and `policy.md`'s
  Templates-in-Policy model to be ratified.
- **Which catalog fragments a Node runs** — the daemon reporting each loaded fragment's name and
  digest, so the Fleet view can say which Nodes run which catalog fragments without the Relay
  storing an arrangement.

## Open questions

1. **How is "never widens" (PC-6) checked mechanically?** Comparing rule structure between
   releases, or asking the daemon's engine about the old fragment's permitted set. Forced at
   `/design`.
2. **Can the Relay-rendered parts of the export be verified mechanically?** PC-16 makes catalog
   fragments checkable against the release, but two exported artifacts have no release digest:
   the cohort deny fragment and the install task itself, which performs PC-16's check. A
   compromised Relay or hijacked Console session could serve allow entries in a file presented as
   a deny fragment, or an install task with the check removed. As designed, the only control is
   that both are shown in full and land in the customer's IaC repo through their review — the task
   once, when first committed. A deny-only mode in `policy check` would
   let the install task refuse the deny fragment; nothing mechanical covers the task. Forced at
   `/design`: either such checks, or the owner accepts the risk on the record with a threat-model
   row naming both artifacts.

## History

- `2026-09-19` — revised with the owner after `/spec-check` returned BLOCKED on ADR-0021,
  ADR-0022 and ADR-0033: the shipped default Policy leaves the catalog; catalog fragments are
  Native-only and define no Templates; the catalog is a release artifact, not a package or role;
  a Policy directory applied by restart, not reload; exported fragments carry release digests
  (PC-16).
- `2026-09-18` — created with the owner: first-party read-only catalog, arrange-and-narrow,
  nothing stored on the Relay, fragments never widen in place, `viewer` access, all of it in
  v0.7.0. Replaces Console screen spec 06's Policy Author (#436).
