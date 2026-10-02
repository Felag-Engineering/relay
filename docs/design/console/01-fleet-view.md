# 01 — Fleet view

**Artboard 1.** The landing screen. **Milestone v0.6.0** (read-only); the one action arrives in
v0.7.0.

**Governing:** ADR-0006, ADR-0014, ADR-0020, invariants #7, #9, #11.
**Backend:** registry read seams (`relay/internal/registry`, already consumed by MCP
`list_nodes`/`describe_node`); the SSE seam; per-Account view persistence (#442 — a preference,
not a runtime object). Group-by itself is a pure read over existing labels.

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

**Pixel wall**, inside an opened group: one tiny cell per Node. Four colour buckets only — normal,
drift, needs attention, quarantined — because preattentive vision handles about four, and the table
names which. A Node with no recorded Hello (no daemon version or no Policy fingerprint) is a
**hollow "not reported" cell**: an outline with no fill, on the fill-versus-outline channel rather
than a fifth hue, so the four-hue argument survives. Without it such a Node would be drawn as a
filled "normal" cell, which is false reassurance. A cell takes the first bucket that applies:
quarantined, then needs attention, then not reported, then drift, then normal. An offline or
cert-expiring Node therefore stays amber even when it is also unreported. Click a cell to open that
Node.

**Facet rail**, showing value distributions as counts. The facets *are* the summary statistics.
Ordered: `state:`, daemon version, Policy fingerprint, template set, `node:role`. The daemon
version and Policy fingerprint facets each carry an explicit "not reported" row, so every value
facet sums to the group's Node count. That row is not a link: absence is not a label.

**Deviation table**, sorted **anomaly-first by rarity, never alphabetically**. The weird Node is
row one. Columns: liveness dot + name · **State** · Labels · Policy fingerprint · Last seen.
The State column is omitted from a group's table when no row in it draws a state (revoked,
quarantined, not reported, or a `state:` label).
Below it, the ladder: "*N* more deviate the same way — expand", then the mode as one calm line
("3,993 Nodes carry no `state:` label at all — reachable, current, permitted"). The mode line never
counts a "not reported" Node as reachable, current or permitted: it says how many Nodes have not
reported and that they are not counted, and uses "other Nodes" for the rest. The card header shows
the count in a neutral style ("1 not reported"), not amber.

## Filtering and targeting

**Filter and group freely on anything; target only on labels.** After this session's decisions
those are the same set, which is the point: everything filterable is a label in one of four
namespaces, so the contextual "Run against these" can never be handed a set it cannot express.

Facts (OS, kernel, hostname, IP, packages) are **not** filterable and **not** on the row. If an
operator wants to target on OS, their config management stamps `node:os=ubuntu`. The discriminator
is the configuration-management scope rule (AGENTS.md, *Out of realm*): *what Ansible could check in check-mode is out of realm*.

### Tagging a selection (v0.7.0)

From a filtered view an `operator` can **add or remove one `tag:` label on every Node in the current
selection** — the bulk form of Node detail's per-Node tag control (spec 02). This is what makes a
tag-based quarantine fast mid-incident: filter, tag `incident=4412`, then engage by that tag from
spec 16.

- The Console resolves the filter to Node IDs and sends **the IDs, never the filter**, so the set
  tagged is the set on screen even if labels change between render and click.
- The confirm step names the count and the tag; the result lists the Nodes changed. Audited per
  Node, with actor.
- Standard auth, no step-up (ADR-0020). A `node:` or `state:` label has no edit affordance, here or
  anywhere.

## Deviation states

Rendered in the State column and counted on the rollup card.

| State | Meaning | Colour |
|---|---|---|
| `state:offline` | not connected right now | amber |
| `state:outdated` | daemon below the dispatch minimum; every dispatch returns `version_refused` | amber |
| `state:template-unloadable` | template set failed to load; vocabulary empty, fail closed | grey |
| `state:cert-expiring` | identity certificate near expiry and not renewed; the Node drops off silently if ignored | amber |
| `relay:quarantine` | deliberately fenced; a declared label, not derived | indigo |
| not reported | no recorded Hello: no daemon version or no Policy fingerprint. A Console presentation bucket, not a `state:` label, and not targetable (owner decision on #833) | hollow cell, neutral chip |

**Drift is not among them** and deliberately so — see `99-open-decisions.md` D1. A fingerprint
"behind the fleet" is fleet-relative and would invert mid-rollout. Drift is shown two ways
instead: as a count on the rollup card ("12 on a different Policy fingerprint" — an observation,
counted only over Nodes that reported a fingerprint),
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
      **Partially met.** Proven on the rendered HTML by `TestFleet_TenThousandNodesRenderWithoutAList`,
      which bounds the page by `groupCards` and `deviationRows` rather than by a number, and by an
      absolute literal beside each derived bound. The box stays unticked because the ladder those two
      constants describe permits 40 cards of 25 deviating rows — 1,040 table rows — which is a
      scrollable list by any ordinary reading of this box. Whether that is the intended reading is an
      open question for the owner; changing either constant is out of scope for a test-coverage issue.
- [ ] The single quarantined Node in a 4,000-Node group is findable without reading any text.
- [ ] No Fact appears on a row or in a facet.
- [ ] No route on this screen mutates anything in v0.6.0.

## Open

- Bulk `tag:` from the current filter (v0.7.0, `operator`, no step-up) is the fleet view's one and
  only action. Confirm nothing else creeps in.
