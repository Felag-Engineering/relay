# Admin Console — wireframe brief (four key screens)

> **Expanded by [docs/design/console/](console/) (2026-09-20).** The per-screen specifications
> there are the live description of each Console screen and win where they differ. This brief
> is kept as the designer-facing origin of the design language, in its 2026-08-07 wording.
>
> **"Plan" below usually means the Policy preflight.** The owner ruled (#575, D16 in
> [docs/design/console/99-open-decisions.md](console/99-open-decisions.md)) that the
> Console's composer says **Preflight**, after ADR-0038 gave "Plan" to an approved route of
> execution. D16 keeps the word where it means the approved route — *the approval object, the
> Job's Plan block and every "plan hash" keep the word, and the shared Plan renderer keeps its
> name* — and the wire option is still spelled `plan`. Read a "Plan" that means the composer's
> no-execution preview as **preflight**, and leave the rest.
>
> **A screen prompt pasted into a mockup tool travels without this header:** substitute
> "Preflight" for "Plan" in the prompt text first, and never ask for a button labelled
> "Plan" (Screen 4's primary button predates the ruling).

**Status:** designer-facing brief, 2026-08-07. Derived from `ui-advisory.md` and
ADR-0009/ADR-0020, written as paste-able prompts for mockup generation: prepend the global
section to each screen prompt (ui-advisory deliverable #2).

The product: a fleet-administration control plane. The Console's job: **make the security
boundary legible** to a skeptical operator who watches the fleet, probes what's allowed and
reads *why* something was denied before trusting the system.

---

## Global design language (prepend to every screen prompt)

Design a screen for an internal operations web console. Aesthetic: plain, fast, unbranded,
desktop-first. Server-rendered feel — no flashy transitions. Calm, quiet, high-legibility;
think "well-typeset technical document," not "dashboard product."

Rules that override normal dashboard instincts:

1. **Calm by default.** Neutral palette (near-white / near-black surfaces, one restrained
   accent for interactive elements). Color is *semantic and scarce*: amber means *attention
   now* (the control-plane banner, `state:offline`, `state:outdated`, `state:cert-expiring`,
   over-cap notes); indigo is the security lane (`relay:` labels, quarantine); one muted red
   exists, on `failure` and `timeout` and on the button of an act that lowers authority (D5
   and D24 in `console/99-open-decisions.md`). A **denied** result is NOT an error — render
   it neutral/informative (slate chip, not red), because a deny is the product working
   correctly.
2. **The UI computes what is interesting; the human only ever reads exceptions.** Fleets
   run 100–10,000 Nodes. A list is a bug: render the *mode* (the normal state) as one
   compressed calm line and spend pixels on deviations. Grouped counts with
   expand-on-demand ("10 allow · 1 deny · 1 offline") are the standard pattern; the
   disclosure ladder is count → segmented bar → groups → sampled members → full list only
   on explicit demand.
3. **The user's taxonomy is the organizing axis.** Screens organize first by the customer's
   own labels (`env=prod`, `role=web`, `team=payments`). Server machinery (enrollment state,
   certificate fingerprints, tokens) is data on the row and an available grouping, never the
   default frame. Show only what the server truthfully knows (connectivity, versions, config
   drift, command history — no CPU/latency/app-health; this is not a monitoring product), and
   render groups as *observations*, never desired-vs-actual (no "expected 40, found 39, fix
   it" affordances).
4. **One decision per screen.** Decision surfaces (approval, execution) contain exactly one
   primary action and nothing competing with it. No sidebars of stats, no secondary CTAs.
5. **Two-lane identity grammar, used everywhere identically:** a **solid chip** = identity
   verified by the server; an **outlined chip** = caller-asserted, unverified. These must
   never look equally authoritative.
6. **Three label namespaces, visually distinct everywhere:** `node:` labels (set on the
   machine) and `tag:` labels (set by operators) are ordinary quiet chips, subtly
   differentiated; `relay:` labels are the security lane — visually weightier (filled,
   distinct hue, small lock glyph). A viewer must sense `relay:` means business.
7. **Live but stable.** Counters and lists may update live; anything a human is reading to
   make a decision (an open approval card, a rendered plan) is pinned and never reflows.
8. Layout skeleton: slim left nav (Fleet, Jobs, Approvals, Audit, Tokens, Accounts,
   Lifecycle), full-width content, and a slot above content for the global Freeze banner
   (amber, unmissable, present on every screen when the fleet freeze is engaged).
9. **No settings pages exist, ever.** Server configuration (blast caps, listeners, gates)
   appears only as *effects in context* — a cap shown inside a plan line, an `outdated`
   flag on a row — never as an inventory of editable values. *(Superseded: invariant 11 now
   lets a human `admin` change reach-bounding settings with step-up; see
   [console/18-settings.md](console/18-settings.md) and
   [console/19-approval-rules.md](console/19-approval-rules.md). The security floor is
   still never editable.)*

---

## Screen 1 — Fleet view (the landing screen)

The user's whole fleet, organized by *their* names — group-by-first, not a raw registry
table. Eyes-only in phase one: no action buttons on rows (phase two adds exactly one
action: bulk-apply a `tag:` label to the current filter result).

- **Top bar: view controls.** A search box whose query language is the Selector syntax used
  to target commands (browsing trains targeting) · a **"Group by"** control accepting any
  label key (`env`, `role`, `team`…) · a **saved-views** switcher. Landing is the signed-in
  user's default saved view ("my slice"); the global everything-view is just another view.
- **Grouped state (the default): rollup cards.** One calm card per value of the grouping
  key, headlined with the user's own name for it: "**prod** · 4,012 nodes · 3 offline ·
  12 outdated". Healthy groups compress to a single line; only deviating groups show
  detail. Opening a card reveals the layers below, scoped to that group. "Group by
  nothing" degrades to the flat machinery view.
- **Inside a group (or ungrouped): the pixel wall.** The group's Nodes as a grid of tiny
  colored cells — 10,000 fit on one screen; the lone amber cell is findable with zero
  reading. Click a cell to jump to that Node.
- **Below it: facets + the deviation table.** A slim facet rail (OS, daemon version,
  labels, liveness) showing value distributions as counts ("1.4.2 — 9,990 · 1.3.9 — 10");
  clicking filters. The table: compact rows (~40px), sorted **anomaly-first** (by
  rarity/deviation, never alphabetical — the weird Node is row one). Columns: liveness
  dot + name · label chips (three namespaces per rule 6) · facts summary · Policy
  fingerprint (short mono hash) with an `outdated` tag when stale · last seen.
- A quiet "since you last looked" delta line under the top bar, **scoped to the current
  view**: "2 enrolled · 1 went offline · 3 became outdated."
- Node detail (linked from a row): facts panel, cert/enrollment info, effective-Policy
  viewer (read-only), recent Tasks, and pin-to-compare (2–3 Nodes side-by-side diff of
  facts/Policy).
- **Forward socket:** design the rollup card so a future named, shared, described group
  (a "Service" from the post-1.0 semantic model) is the same card with a richer source —
  a data upgrade, not a redesign.

## Screen 2 — Job detail (grouped outcomes)

The record of one command run against many Nodes. Must be legible at 3 Nodes and at 10k.

- Header: Operation name + a **risk-class badge** (`read` = quiet, `mutate` = amber-tinted)
  · requester identity chips (solid verified chip; if run on behalf of someone, an outlined
  asserted chip beside it) · timestamps · job state.
- Plan block (shared component, see Screen 4): "matched 12 nodes · mutate-cap 100 ✓" +
  plan hash in mono.
- Results: a horizontal **segmented count bar** summarizing outcomes (success / denied /
  unreachable / unsupported / cancelled / timeout), then one collapsible group per
  outcome, headed by count. Within the success group, identical outputs are clustered:
  "9,797 identical (view one) · 3 differ," the 3 expanded by default. "Show all" always
  sits behind one more click.
- The **denied** group is the showpiece: expanding it shows the policy rule that fired,
  verbatim, in a mono block, with a link "view this node's effective policy." Styled
  informative-neutral, never as failure.

## Screen 3 — Approval object (the highest-stakes screen)

> **Retired.** The Console decides no approvals (ADR-0044); see
> [console/08-approval-object.md](console/08-approval-object.md). Kept as the origin of the
> card's design language.

One pending action awaiting human sign-off. A single centered card, generous whitespace,
**mobile-first** (approvers arrive from a phone link). Nothing else on the page competes.

Card contents, top to bottom:
- Requester line: solid verified chip for the requesting account (often the AI agent's
  machine account) + outlined asserted chip for "on behalf of" when present.
- The plan summary, server-authored: operation + risk badge, target selector, fan-out
  ("matches 12 nodes · cap 100 ✓"), grouped predicted verdicts, plan hash (mono — this
  hash is what's being approved).
- A **diff-against-last-approval callout**, visually distinct (left-border accent block):
  "Same as the action you approved Tue 14:02, except: fan-out 3 → 12." This one element
  is the anti-fatigue mechanism — make it the most eye-catching text on the card.
- Quorum + expiry line: "1 of 2 approvals — mike, 2h ago" + a quiet TTL countdown.
- If a batch: one card, "Batch · 14 actions," member list collapsed; approving requires
  expanding it at least once.
- Footer: **Approve and Deny buttons of equal size, weight, and color emphasis** — no
  primary/secondary split, no default focus. Below them, an inline step-up field
  (re-enter password) that must be completed to submit either decision.

## Screen 4 — Composer with Plan (execution surface)

Where an operator composes a command and sees exactly what would happen before it can run.
Two-column layout; the mutating path is deliberately slower than the reading path.

- Left column — the form: Operation picker (searchable; each entry shows its risk badge);
  beneath it, schema-driven argument fields showing their constraints inline as quiet
  helper text (enum choices, patterns) *before* submission; a Selector input with a live
  match feedback line beneath it: "matches 12 nodes · mutate-cap 100 ✓" (turns to an
  amber "exceeds cap" note when over — informative, not an error state). A Raw Exec tab
  exists but is visible only to admins.
- Primary button: **"Plan"** — not "Run." There is no run button yet.
- Right column — empty until planned, then renders the Plan (same component as Screens
  2 & 3): fan-out summary, risk badge, grouped per-node verdicts ("10 allow · 1 deny
  (rule shown verbatim) · 1 unknown — offline"), plan hash. Once rendered, the plan is
  pinned (no live reflow).
- Only after the Plan renders does an **"Apply"** button appear beneath it, and clicking
  it opens the step-up re-auth modal. The visual rhythm to convey: compose → see the
  truth → confirm identity → run.

---

Shared components to keep consistent across all four: the Plan renderer (screens 2, 3, 4),
the segmented outcome bar + groups (2, 4), verified/asserted chips (all), the three-tier
label chips (all), the deny block (2, 3, 4), the step-up modal (3, 4), the Freeze banner
(all).
