# 01 — Fleet view

**Artboard 1.** The landing screen. **Milestone v0.6.0** (read-only); the one action, bulk tag
editing, arrives in the MVP (ADR-0050).

**Governing:** ADR-0006, ADR-0014, ADR-0020, ADR-0050, ADR-0052, invariants #7, #9, #11.
**Backend:** registry read seams (`relay/internal/registry`, already consumed by MCP
`list_nodes`/`describe_node`); the SSE seam; per-Account view persistence (#442 — a preference,
not a runtime object). Group-by itself is a pure read over existing labels.

## What this screen is for

The operator's first question is not "how is my Relay doing" but **"can I act on my fleet right
now, and what is in the way?"** Everything in the way is Relay-status truth expressed about the
fleet: unreachable Nodes, Nodes that will refuse work, Nodes whose Policy will deny.

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
      │                                                            [Tag these 4,012]
      ├──────────────────────────────────────────────────────────────────────────────────
      │ ┌ prod   4,012 nodes · 3 offline · 2 outdated · 12 on Policy fingerprint B
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

**System state — the headline** (D27). The first thing under the view controls, in the largest
type after the heading: **how many matched Nodes are reachable** ("4,009 of 4,012 reachable") and
**how many Policy fingerprints they report**, each drawn in full beside its alias or per-render
letter, with its count (`00-foundations.md`, "Policy fingerprint"; never the alias alone, QRY-33),
plus a "not reported" count where there is one. It answers questions 1 and 3 and nothing else: no
approvals count, no Job count, no figure about the Relay. The fleet-wide pixel wall and its
four-bucket key sit beneath it. Every figure counts the matched set, so it changes with the filter.

**Delta lane**, scoped to the current view: "since you last looked" — enrolled, went offline,
gained a `state:` label. The operator's daily question is what changed, not what everything is.

**Rollup cards**, one per value of the grouping key, headlined with the customer's own name for
it. Healthy groups compress to a single line. Only deviating groups show detail. Each card is a
native `<details>`, open when its group deviates and closed when it does not, so collapsing and
expanding needs no script.

**Pixel wall**, inside an opened group: one tiny cell per Node. Three colour buckets only — normal,
drift, needs attention — because preattentive vision handles about four. (A fourth,
quarantined, waits with quarantine: roadmap: relay/quarantine.) A Node with
no recorded Hello (no daemon version or no Policy fingerprint) is a **hollow "not reported" cell**:
an outline with no fill, on the fill-versus-outline channel rather than a fifth hue. Drawing it as
a filled "normal" cell would be false reassurance. A cell takes the first bucket that applies:
needs attention, not reported, drift, normal — so an offline or cert-expiring Node
stays amber even when also unreported. Click a cell to open that Node.

**Facet rail**, showing value distributions as counts. The facets *are* the summary statistics.
Ordered: `state:`, daemon version, Policy fingerprint, template set, `node:role`. Each Policy
fingerprint value carries its alias or per-render letter beside the hash; the link it makes still
targets the hash. For a human `admin`, each value also carries an **Edit alias** control, which
sets, renames or clears the alias of that fingerprint (below, "Policy aliases"). The daemon
version and Policy fingerprint facets each carry an explicit "not reported" row, so every value
facet sums to the group's Node count. That row is not a link: absence is not a label.

**Deviation table**, sorted **anomaly-first by rarity, never alphabetically**. The weird Node is
row one. Columns: liveness dot + name · **State** · Labels · Policy fingerprint · Last seen · Pin.
The State column is omitted when no row in the group draws a state (revoked, not
reported, or a `state:` label). Names and fingerprints follow `00-foundations.md` ("Self-reported
names", "Policy fingerprint"). The table's caption ("Every Node in `web`, oddest first") is
**visually hidden** — present for screen readers, not drawn (D34): the sort order is visible in the
rows. Below it, the ladder: "*N* more deviate the same way — expand", then the mode as one calm line
("3,993 Nodes carry no `state:` label at all — reachable, current, permitted"). The mode line never
counts a "not reported" Node as reachable, current or permitted: it says how many Nodes have not
reported and that they are not counted, and uses "other Nodes" for the rest. The card header shows
the count in a neutral style ("1 not reported"), not amber. **A group with no deviation draws no
mode sentence** (D34): its one-line header ("612 nodes · no deviations") already says it, and a
sentence restating that every Node is reachable, current and permitted is deleted.

**Pin to compare.** Every listed row carries a Pin toggle that adds or removes that Node from the
pin set (2–3 Nodes, spec 02): a button in a GET form, needing no script, that keeps the current
filter, grouping and pin set, and shows pressed when the Node is pinned. Once three are pinned,
unpinned rows' buttons are disabled (and leave the tab order); the pin bar's "three is the
maximum" sentence says why. The pin bar always offers Compare, disabled with "Pin 1 more to
compare" until two are pinned. Pinning writes nothing: the set lives in the query string. Below
600px the toggle is a labelled cell in the row's card.

## Filtering and targeting

**Filter and group freely on anything; target only on labels.** Those are the same set: everything
filterable is a label in one of four namespaces, so the filter on screen is always a Selector an
AI-agent or the Control API could target. The Console itself runs nothing (ADR-0052).

Facts (OS, kernel, hostname, IP, packages) are **not** filterable, and none is on the row except
the hostname, drawn as the self-reported primary name (`00-foundations.md`, "Self-reported names").
The row links by Node ID. The hostname Fact is not filterable, but the daemon declares the
hostname, OS and architecture as the `node:hostname`, `node:os` and `node:arch` labels, which
filter and target like any declared label. A distribution is targeted with a label config
management declares, such as `node:distro=ubuntu`. The discriminator is the
configuration-management scope rule (AGENTS.md, *Out of realm*): *what Ansible could check in
check-mode is out of realm*.

### A refused filter

A filter the Selector parser refuses — an unprefixed term, a malformed one — is
said where it was typed (D26):

- **The count reads "filter not applied"**, never "*N* of *M* Nodes": a count beside a filter that
  was not applied reads as that filter's result.
- **The refusal sits directly under the filter field**, which is marked invalid (`aria-invalid` and
  the field's own error styling, tied to the message by `aria-describedby`), in the parser's own
  words.
- **The results below still show the whole fleet, visibly de-emphasised** — dimmed, under a one-line
  note that they are unfiltered. They are not blanked: an empty page makes a typo feel like an
  outage.

Validation happens **on submit, on the server**, by the capability layer's one Selector parser
(`docs/specs/selectors-and-labels.md`). The Console parses no Selector in the browser: a second
parser would be a second answer to "what does this filter match?" (invariant 10).

A filter that parses and matches nothing is not refused; it is the empty state ("No Nodes match
this Selector", with a link that clears it).

### Policy aliases

Nobody says a hash aloud. A human `admin` may give a fingerprint a **Policy alias** —
"web-hardened" — from its facet value here or from the Fingerprints panel on Node detail (spec 02).
D23; the capability is `docs/specs/query.md`.

- **Edit alias** opens a small server-rendered form — the alias, a Save, and a Clear where one is
  set — posted with the CSRF token. It is offered only to a human `admin`; for every other role it
  is absent, not disabled. No step-up: an alias gates nothing.
- The write goes through the capability layer, which decides who may make it and records it on the
  audit trail with the old and the new value; the Console decides nothing.
- An alias is display only: the hash is always drawn beside it, every filter and link still carries
  the hash, and nothing about a Node, its Policy or what may run on it changes. It is metadata the
  Relay holds about a fingerprint, never Policy (invariant 2).

### Tagging a selection (MVP)

From a filtered view a human Account at `operator` or above can **add or remove one `tag:` label
on every Node the current Selector matches**, the bulk form of Node detail's per-Node tag control
(spec 02). ADR-0050 is the decision; `docs/specs/selectors-and-labels.md` holds the behaviour.

- The confirm step lists the matched Nodes, names the count and the tag, and writes nothing until
  confirmed. The Console resolves the filter to Node IDs and sends **the IDs, never the filter**,
  so the set tagged is the set confirmed even if labels change between render and click. The
  result lists the Nodes changed.
- One bulk act covers at most **256 Nodes**. The cap is the capability layer's, so the Control API
  holds it too; a filter matching more is refused on the confirm step with "Tag at most 256 Nodes
  at once; narrow the filter."
- Each change is one audit record with the Account, the Node and the old and new values.
- Standard auth, no step-up (ADR-0020, ADR-0050): a tag gates nothing. A machine Account is
  refused. A `node:`, `relay:` or `state:` label has no edit affordance, here or anywhere.

## Deviation states

Rendered in the State column and counted on the rollup card.

| State | Meaning | Colour |
|---|---|---|
| `state:offline` | not connected right now | amber |
| `state:outdated` | daemon below the dispatch minimum; every dispatch returns `version_refused` | amber |
| `state:template-unloadable` | template set failed to load; vocabulary empty, fail closed | grey |
| `state:cert-expiring` | identity certificate near expiry and not renewed; the Node drops off silently if ignored | amber |
| not reported | no recorded Hello: no daemon version or no Policy fingerprint. A Console presentation bucket, not a `state:` label, and not targetable (owner decision on #833) | hollow cell, neutral chip |

**Drift is not among them** (`99-open-decisions.md` D1): "behind the fleet" is fleet-relative and
would invert mid-rollout. Drift is shown as a count on the rollup card ("12 on a different Policy
fingerprint", counted only over Nodes that reported one) and as the fingerprint distribution in
the facet rail. Acting on it means targeting the value, `state:policy-fingerprint=4b18…c02`;
clicking the facet fills that into the filter.

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
  "Refreshing a screen"); no sentence beside it says so (D34). Beside it, the page says how old it
  is — "rendered 40s ago", the absolute UTC time in its `title` — and an old page says so in words
  and weight, never in amber (D30). The screen never reloads on a timer.
- **Frozen** → the control-plane banner above content; the screen is otherwise unchanged (reads still work).
- **Relay or CA certificate near expiry** → the same banner slot, per `00-foundations.md`.
- **`viewer`** → identical, minus the tag action and the alias control.
- **Single-Node and small fleets** → the pixel wall becomes a short strip, group cards collapse to
  one row, and the deviation table simply is the fleet. Nothing special-cased.

## Acceptance

- [ ] An operator lands on their saved view, not the global registry.
- [ ] The filter box accepts Selector syntax across all four namespaces and the resulting match
      count is the same number a dispatch to that Selector would resolve.
- [ ] A fleet of 10,000 Nodes renders without a scrollable list of rows: one segmented summary,
      one pixel wall, and the deviating rows.
      **Partially met.** `TestFleet_TenThousandNodesRenderWithoutAList` bounds the rendered page by
      `groupCards` and `deviationRows`, with an absolute literal beside each derived bound. The box
      stays unticked: those constants permit 40 cards of 25 deviating rows — 1,040 table rows — a
      scrollable list by any ordinary reading. Whether that is intended is an open owner question.
- [ ] The single offline Node in a 4,000-Node group is findable without reading any text.
- [ ] No Fact appears on a row or in a facet.
- [x] No route on this screen mutates anything except the Policy alias write (D23) and the bulk
      tag write (MVP, ADR-0050). Neither reaches a Node; neither writes a `node:`, `relay:` or
      `state:` label.
      **Qualified:** the alias write is not built, so the bulk tag write is the screen's one
      mutation. It writes only `tag:` labels (`TestConsole_NoScreenOffersAnEditForANodeRelayOrStateLabel`).
- [x] The bulk tag confirmation lists the matched Nodes before anything is written, and a machine
      Account is refused.
      **Built.** The confirm page writes nothing and lists every matched Node, up to the 256-Node
      cap (`TestTags_ConfirmListsTheMatchedNodesAndWritesNothing`,
      `TestTags_TheConfirmPageAndItsPostAgreeAtTheCountBound`). A machine Account is refused by
      the capability layer, which the Console renders (`TestTags_RefusalsRenderTheCapabilityLayersAnswer`).
- [ ] A refused filter shows "filter not applied", its refusal under the field, and the whole
      fleet de-emphasised beneath; nothing parses the filter in the browser.
- [ ] Every Policy fingerprint drawn on this screen shows its full hash beside its alias or letter.

## Open

- Bulk `tag:` from the current filter (MVP, human `operator`+, no step-up) is the fleet view's one
  action beside the alias write. Confirm nothing else creeps in.
