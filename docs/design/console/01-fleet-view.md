# 01 — Fleet view

**Artboard 1.** The landing screen. **Milestone v0.6.0** (read-only); the one action arrives in
v0.7.0.

**Governing:** ADR-0006, ADR-0014, ADR-0020, invariants #7, #9, #11.
**Backend:** registry read seams (`relay/internal/registry`, already consumed by MCP
`list_nodes`/`describe_node`); the SSE seam; per-Account view persistence. Group-by itself is a
pure read over existing labels.

## What this screen is for

The operator's first question is not "how is my Relay doing" but **"can I act on my fleet right
now, and what is in the way?"** Everything in the way is Relay-status truth expressed about the
fleet: unreachable Nodes, Nodes that will refuse work, Nodes whose Policy will deny, Nodes
deliberately fenced.

Scope is the four questions in `00-foundations.md`. No collected metrics.

## Layout

```
[nav] │ Fleet                                  4,960 Nodes enrolled        [mike · admin]
      ├──────────────────────────────────────────────────────────────────────────────────
      │ [My slice ▾]  [ node:env=prod                            ]  [Group by env ▾]
      ├──────────────────────────────────────────────────────────────────────────────────
      │ Since you last looked (2h)  2 enrolled · 1 offline · 3 changed Policy fingerprint
      │                                    [Tag these 4,012]  [▷ Run against these 4,012]
      ├──────────────────────────────────────────────────────────────────────────────────
      │ ┌ prod   4,012 nodes · 3 offline · 2 outdated · 12 on an older Policy fingerprint · 1 quarantined
      │ │  [pixel wall — one cell per Node]
      │ │  ┌────────────┬──────────────────────────────────────────────┐
      │ │  │ facet rail │ deviation table, anomaly-first                │
      │ │  └────────────┴──────────────────────────────────────────────┘
      │ ├ staging  612 nodes · no deviations                    (collapsed)
      │ ├ dev      240 nodes · 2 offline                        (collapsed)
      │ └ edge      96 nodes · 96 outdated                 (collapsed)
```

## Regions

**View controls.** A saved-views switcher (landing is the signed-in Account's default view — their
filter and grouping, not the global registry). A filter box that speaks **Selector syntax** —
literally the language that targets commands, because browsing trains targeting and "what would
this Job hit?" is then answered by the filter already on screen. A group-by control accepting any
label key.

**Delta lane**, scoped to the current view: "since you last looked" — enrolled, went offline,
gained a `state:` label. The operator's daily question is what changed, not what everything is.

**Rollup cards**, one per value of the grouping key, headlined with the customer's own name for
it. Healthy groups compress to a single line. Only deviating groups show detail.

**Pixel wall**, inside an opened group: one tiny cell per Node. Four buckets only — normal, drift,
needs attention, quarantined — because preattentive vision handles about four, and the table names
which. Click a cell to open that Node.

**Facet rail**, showing value distributions as counts. The facets *are* the summary statistics.
Ordered: `state:`, daemon version, Policy fingerprint, template set, `node:role`.

**Deviation table**, sorted **anomaly-first by rarity, never alphabetically**. The weird Node is
row one. Columns: liveness dot + name · **State** · Labels · Policy fingerprint · Last seen.
Below it, the ladder: "*N* more deviate the same way — expand", then the mode as one calm line
("3,993 Nodes carry no `state:` label at all — reachable, current, permitted").

## Filtering and targeting

**Filter and group freely on anything; target only on labels.** After this session's decisions
those are the same set, which is the point: everything filterable is a label in one of four
namespaces, so the contextual "Run against these" can never be handed a set it cannot express.

Facts (OS, kernel, hostname, IP, packages) are **not** filterable and **not** on the row. If an
operator wants to target on OS, their config management stamps `node:os=ubuntu`. The discriminator
is the ROADMAP scope rule: *what Ansible could check in check-mode is out of realm*.

## Deviation states

Rendered in the State column and counted on the rollup card.

| State | Meaning | Colour |
|---|---|---|
| `state:offline` | not connected right now | amber |
| `state:outdated` | daemon below the dispatch minimum; every dispatch returns `version_refused` | amber |
| `state:template-unloadable` | template set failed to load; vocabulary empty, fail closed | grey |
| `state:cert-expiring` | identity certificate near expiry and not renewed; the Node drops off silently if ignored | amber |
| `relay:quarantine` | deliberately fenced; a declared label, not derived | indigo |

**Drift is not among them** and deliberately so — see `99-open-decisions.md` D1. A fingerprint
"behind the fleet" is fleet-relative and would invert mid-rollout. Drift is shown two ways
instead: as a count on the rollup card ("12 on a different Policy fingerprint" — an observation),
and as the fingerprint distribution in the facet rail. Acting on it means targeting the value:
`state:policy-fingerprint=4b18…c02`. Clicking the facet fills that into the filter, which is the
whole interaction.

A Node with no state chip is normal. That is most of them, and the column being empty is the
calmest thing on the screen.

## Upgrades

ADR-0014: **the registry is the upgrade dashboard.** The daemon-version facet is that dashboard.
The Console shows the distribution and offers **nothing** — no push, no copyable inventory, no
`pkg.install` shortcut. The Relay never pushes binaries; upgrades flow through the customer's
config management.

## Must not appear

- CPU, memory, disk, load, latency, application health, uptime graphs.
- Desired-vs-actual affordances. A group card never grows "expected 40, found 39, reconcile" —
  Relay does not auto-reconcile, ever (invariant #9). Groups are observations.
- Blast caps, listeners, or any Relay configuration as an editable value.
- Any way to edit `node:` labels or Policy.
- Any upgrade action.

## States

- **Empty fleet** → the day-one screen, spec 10. Do not render an empty table.
- **Frozen** → the control-plane banner above content; the screen is otherwise unchanged (reads still work).
- **Relay or CA certificate near expiry** → the same banner slot, per `00-foundations.md`.
- **`viewer`** → identical, minus the two action buttons.
- **Single-Node and small fleets** → the pixel wall becomes a short strip, group cards collapse to
  one row, and the deviation table simply is the fleet. Nothing special-cased.

## Acceptance

- [ ] An operator lands on their saved view, not the global registry.
- [ ] The filter box accepts Selector syntax across all four namespaces and the resulting match
      count is the same number the composer would resolve.
- [ ] A fleet of 10,000 Nodes renders without a scrollable list of rows: one segmented summary,
      one pixel wall, and the deviating rows.
- [ ] The single quarantined Node in a 4,000-Node group is findable without reading any text.
- [ ] No Fact appears on a row or in a facet.
- [ ] No route on this screen mutates anything in v0.6.0.

## Open

- Whether `state:cert-expiring` earns a fifth state. See `99-open-decisions.md`.
- Bulk `tag:` from the current filter (v0.7.0, `operator`, no step-up) is the fleet view's one and
  only action. Confirm nothing else creeps in.
