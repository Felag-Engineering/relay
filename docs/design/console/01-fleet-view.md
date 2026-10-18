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
      │ 4,012 of 4,960 Nodes                       rendered 40s ago · [Refresh]
      ├──────────────────────────────────────────────────────────────────────────────────
      │ System state   4,009 of 4,012 reachable · 2 Policy fingerprints:
      │                web-hardened ‹full fingerprint› 4,000 · B ‹full fingerprint› 12
      │ [pixel wall, the whole matched set]                       [key: 4 buckets, counts]
      ├──────────────────────────────────────────────────────────────────────────────────
      │ Since you last looked (2h)  2 enrolled · 1 offline · 3 changed Policy fingerprint
      │                                    [Tag these 4,012]  [▷ Run against these 4,012]
      ├──────────────────────────────────────────────────────────────────────────────────
      │ ┌ prod   4,012 nodes · 3 offline · 2 outdated · 12 on Policy fingerprint B · 1 quarantined
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

**System state — the headline** (owner decision, 2026-10-18, D26). The first thing under the view
controls, and the screen's summary: it states, in the largest type on the page after the heading,
**how many of the matched Nodes are reachable** ("4,009 of 4,012 reachable") and **how many Policy
fingerprints they report**, each drawn in full beside its Policy alias or per-render letter, with
its count (`00-foundations.md`, "Policy fingerprint"; never the alias alone, QRY-33),
and a "not reported" count where there is one. It answers questions 1 and 3 of the four and nothing
else: no approvals count, no Job count, no figure about the Relay itself. The fleet-wide pixel wall
and its four-bucket key sit beneath it. Every figure in it is counted over the matched set, so it
changes with the filter.

**Delta lane**, scoped to the current view: "since you last looked" — enrolled, went offline,
gained a `state:` label. The operator's daily question is what changed, not what everything is.

**Rollup cards**, one per value of the grouping key, headlined with the customer's own name for
it. Healthy groups compress to a single line. Only deviating groups show detail. Each card is a
native `<details>`, open when its group deviates and closed when it does not, so collapsing and
expanding needs no script.

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
Ordered: `state:`, daemon version, Policy fingerprint, template set, `node:role`. Each Policy
fingerprint value carries its alias or per-render letter beside the hash; the link it makes still
targets the hash. For a human `admin`, each value also carries an **Edit alias** control, which
sets, renames or clears the alias of that fingerprint (below, "Policy aliases"). The daemon
version and Policy fingerprint facets each carry an explicit "not reported" row, so every value
facet sums to the group's Node count. That row is not a link: absence is not a label.

**Deviation table**, sorted **anomaly-first by rarity, never alphabetically**. The weird Node is
row one. Columns: liveness dot + name · **State** · Labels · Policy fingerprint · Last seen · Pin.
The State column is omitted from a group's table when no row in it draws a state (revoked,
quarantined, not reported, or a `state:` label). The Node column names each Node by its hostname,
marked self-reported, with the verified Node ID secondary beside it (`00-foundations.md`,
"Self-reported names"). The Policy fingerprint column draws the hash with its Policy alias or
per-render letter (`00-foundations.md`, "Policy fingerprint").
Below it, the ladder: "*N* more deviate the same way — expand", then the mode as one calm line
("3,993 Nodes carry no `state:` label at all — reachable, current, permitted"). The mode line never
counts a "not reported" Node as reachable, current or permitted: it says how many Nodes have not
reported and that they are not counted, and uses "other Nodes" for the rest. The card header shows
the count in a neutral style ("1 not reported"), not amber.

**Pin to compare.** Every listed row carries a Pin toggle that adds or removes that Node from the
pin set (2-3 Nodes, spec 02). It is a button in a GET form, keyboard reachable and needing no script,
and it keeps the current filter, grouping and pin set. It is pressed when the Node is pinned. Once
three are pinned the buttons of unpinned rows are disabled, which takes them out of the tab order;
the pin bar's "three is the maximum" sentence carries the reason. The pin bar always offers
Compare, disabled with "Pin 1 more to compare" until two are pinned. Pinning writes nothing: the set
lives in the query string. Below 600px the toggle is a labelled cell in the row's card.

## Filtering and targeting

**Filter and group freely on anything; target only on labels.** After this session's decisions
those are the same set, which is the point: everything filterable is a label in one of four
namespaces, so the contextual "Run against these" can never be handed a set it cannot express.

Facts (OS, kernel, hostname, IP, packages) are **not** filterable, and none is on the
row except the hostname. The hostname names the Node as the row's self-reported visual primary,
with the verified Node ID secondary beside it (`00-foundations.md`, "Self-reported names"; D20,
D21). The row links by Node
ID, and the hostname is never filterable or targetable. If an
operator wants to target on OS, their config management stamps `node:os=ubuntu`. The discriminator
is the configuration-management scope rule (AGENTS.md, *Out of realm*): *what Ansible could check in check-mode is out of realm*.

### A refused filter

A filter the Selector parser refuses — an unprefixed term, a `tag:` term, a malformed one — is
said where it was typed (owner decision, 2026-10-18, D25):

- **The count reads "filter not applied"**, never "*N* of *M* Nodes": a count beside a filter that
  was not applied reads as that filter's result.
- **The refusal sits directly under the filter field**, which is marked invalid (`aria-invalid` and
  the field's own error styling, tied to the message by `aria-describedby`), in the parser's own
  words.
- **The results below still show the whole fleet, visibly de-emphasised** — dimmed, under a one-line
  note that they are unfiltered — so they cannot be mistaken for the filter's matches. They are not
  blanked: an empty page makes a typo feel like an outage.

Validation happens **on submit, on the server**, by the one Selector parser the capability layer
uses (`docs/specs/selectors-and-labels.md`). The Console parses no Selector in the browser: a second
parser would be a second answer to "what does this filter match?", and invariant 10 allows one.

A filter that parses and matches nothing is not refused; it is the empty state ("No Nodes match
this Selector", with a link that clears it).

### Policy aliases

A Policy fingerprint is a hash, and nobody says a hash aloud. A human `admin` may give a
fingerprint a **Policy alias** — "web-hardened" — from its facet value here or from the
Fingerprints panel on Node detail (spec 02). Owner decision, 2026-10-18 (D22); the capability is
`docs/specs/query.md`.

- **Edit alias** opens a small server-rendered form — the alias, a Save, and a Clear where one is
  set — posted with the CSRF token. It is offered only to a human `admin`; for every other role it
  is absent, not disabled. No step-up: an alias gates nothing.
- The write goes through the capability layer, which decides who may make it and records it on the
  audit trail with the old and the new value; the Console decides nothing.
- An alias is display only: the hash is always drawn beside it, every filter and link still carries
  the hash, and nothing about a Node, its Policy or what may run on it changes. It is metadata the
  Relay holds about a fingerprint, never Policy (invariant 2).

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
- Any way to edit `node:` labels or Policy. (A Policy alias names a fingerprint on this Relay; it is
  not Policy and reaches no Node.)
- Any upgrade action.

## States

- **Empty fleet** → the day-one screen, spec 10. Do not render an empty table.
- **Refreshing** → a **Refresh** link beside the count reloads the screen with its filter, grouping
  and pin set preserved, and is an audited read like the page load (`00-foundations.md`,
  "Refreshing a screen"). Beside it, the page says how old it is — "rendered 40s ago", the absolute
  UTC time in its `title` — and an old page says so in words and weight, never in amber
  (D29). The screen never reloads on a timer.
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
- [ ] No route on this screen mutates anything in v0.6.0 except the Policy alias write (D22), which
      reaches the capability layer's alias write and nothing that reaches a Node or a label.
- [ ] A refused filter shows "filter not applied", its refusal under the field, and the whole
      fleet de-emphasised beneath; nothing parses the filter in the browser.
- [ ] Every Policy fingerprint drawn on this screen shows its full hash beside its alias or letter.

## Open

- Bulk `tag:` from the current filter (v0.7.0, `operator`, no step-up) is the fleet view's one and
  only action. Confirm nothing else creeps in.
