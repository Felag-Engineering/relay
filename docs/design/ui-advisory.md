# Admin Console — UI advisory (design brief)

> **Superseded (2026-09-20).** The Console execution surface this brief argued for is decided in
> [ADR-0026](../adr/0026-admin-console-execution-surface.md), and the live per-screen
> specification is [docs/design/console/](console/), cited from source. This file is kept as the
> pre-ADR design intent, in its 2026-08-07 wording.
>
> **"Plan" below usually means the Policy preflight.** The owner ruled (#575, D16 in
> [docs/design/console/99-open-decisions.md](console/99-open-decisions.md)) that the Console's
> composer says **Preflight**, after ADR-0038 gave "Plan" to an approved route of execution.
> D16 keeps the word where it means the approved route — *the approval object, the Job's Plan
> block and every "plan hash" keep the word, and the shared Plan renderer keeps its name* — and
> the wire option is still spelled `plan`. Read a "Plan" that means the composer's
> no-execution preview as **preflight**, and leave the rest.
>
> **The Console decides no approvals**
> ([ADR-0044](../adr/0044-the-console-does-not-decide-approvals.md)). The approval queue, the
> approval object and the Approver journey below are retired; see
> [console/08-approval-object.md](console/08-approval-object.md).

**Status:** draft from the 2026-08-07 planning session. **Amended 2026-08-24:** `outdated`
means ADR-0014's below-the-dispatch-minimum (ADR-0034); Policy-fingerprint drift is an
observation, not a flag. This is the design plan #264 references. Companions:
`console-backend-coverage.md` (what backend each screen needs),
`approval-and-attribution.md` (the identity/approval model the screens render),
`console-wireframe-brief.md` (designer-facing prompts for the four key screens).

## Design intent

The Console is the **trust-building wedge**: a skeptical operator probes the boundary
themselves — composer → Plan → deny with the rule that fired — and *then* hands the keys
to the AI-agent. The wall is the same wall. Every design decision serves one goal: **make the
boundary legible**, in the interface rather than in the README.

Two consequences run through every screen:

1. **A deny is not an error.** It is the product working. Denies render calm and
   informative — the rule that fired, verbatim, linked to the Node's effective-Policy
   view — never as a red failure state.
2. **Plan before apply, everywhere.** No mutating action without its Plan rendered first; it
   *is* the confirmation ladder's self-confirmation rung.

## Technical frame (ADR-0009, unchanged)

Server-rendered Go + HTMX, internal-only, SSE for liveness. No SPA, no client build
pipeline. Strict CSP (no inline script), CSRF tokens on every mutating route, SameSite
session cookies. The execution phase (v0.7.0) inherits this hardening from the monitoring
phase (v0.6.0), so it is built once, first.

## Journeys

- **Skeptical operator** (trust journey): watch the fleet live → probe the boundary in
  the composer → read the deny → widen Policy deliberately in their IaC → eventually
  delegate to the AI-agent. The Console's success metric is this journey completing.
- **Approver** ("Mike") *(retired, ADR-0044)*: notification → one approval object read in
  under a minute → decide with step-up.
- **Auditor**: "who asked / for whom / who approved / what happened" in one query, with
  the verified/asserted distinction visible at a glance.
- **Admin**: enrollment tokens, Node revocation, Accounts/tokens, Freeze — every
  privilege-granting act a small ceremony (step-up).

## Screen inventory

**v0.6.0 — Monitoring (eyes only; zero mutating routes)**
- Login (password; OIDC later).
- Fleet view: live registry, **group-by-first** (see Organizing principle) — group by any
  label key with rollup cards; per-Account saved views (landing = the operator's slice);
  view-scoped delta lane; liveness, facts summary, `node:`/`tag:`/`relay:` labels (the
  three namespaces visually distinct — `node:` and `tag:` quiet, `relay:` the security
  lane), Policy + template-set fingerprints, `state:` labels (ADR-0034 — `outdated` means
  below the dispatch minimum, never fingerprint divergence).
- Node detail: facts, effective Policy (rendered from `policyview`), template
  vocabulary, cert/enrollment info, recent Tasks.
- Jobs: list + detail — per-Node outcomes with the full outcome vocabulary
  (`success / denied(rule) / unreachable / unsupported / cancelled / timeout`) grouped,
  not listed; list filterable to "Jobs that touched my current fleet view".
- Audit trail: filterable; verified/asserted lanes distinct (below).
- Approval queue, read-only *(retired, ADR-0044)*.
- Enrollment Token inventory, CA/cert lifecycle, Freeze state (global banner on every
  screen when engaged).

**v0.7.0 — Administration & Execution**
- Approval queue, deciding *(retired, ADR-0044)*.
- Composer: Operation picker driven by `list_operations` schemas (risk-class badge,
  argument constraints legible before submission — the ADR-0001 legibility bar applies
  to humans too), Selector input with live match-count vs blast cap, Plan rendering,
  apply with step-up.
- Accounts & tokens: create/disable Accounts (human + machine), roles, token
  mint/revoke — all step-up.
- Lifecycle: token mint/revoke, Node revoke, Freeze engage/release.
- Labels (ADR-0020): bulk tag-from-filter in the fleet view (`tag:`, `operator`, no
  step-up — the fleet view's one action); quarantine on Node detail (`admin` + step-up),
  beside Revoke and Freeze as the incident ladder quarantine < revoke < Freeze. Who writes
  `relay:` is invariant 7 as amended: only the quarantine act itself
  (`docs/specs/quarantine-node.md`).

## Key screen requirements

**Plan rendering** (composer and Job detail share one component): fan-out summary
("matches 12 Nodes, mutate-cap 100 ✓"), risk-class badge, per-Node verdicts *grouped*
("10 allow · 1 deny(rule R) · 1 unknown(offline)") with expansion, the plan hash visible.

**Deny legibility:** the failing rule verbatim + link to the Node's effective-Policy
view. The operator must be able to go from "denied" to "I understand exactly why, and
what file to change in my IaC" without leaving the Console.

**The approval object** *(retired, ADR-0044)*. Its requirements shaped the approval-record
schema: verified requester and asserted `on_behalf_of` visually distinct; a Relay-authored
Plan summary; a **diff against the last approved similar action** ("same as Tuesday, except:
fan-out grew 3 → 12"), the anti-fatigue mechanism; quorum state and TTL; a batch as one card;
Approve and Deny equally prominent, with no dark patterns.

**Audit lanes:** one visual grammar for verified vs asserted everywhere (solid chip =
Relay-verified, outlined chip = caller-asserted). An asserted "ops-team" must never render
with the same authority as a verified Account.

**Scale-ready results:** Job results must be legible at 3 Nodes and at 10k. Until the
v0.9.0 aggregation primitive lands, group-by-outcome with counts + sampled expansion;
the layout anticipates histogram-by-output so v0.9.0 slots into the same component.

**Live-but-stable:** SSE updates must never reflow content under a cursor mid-decision.
Rendered Plans are pinned once open; liveness is for lists and counters, not for the thing
being read.

## Organizing principle: Relay-centric data, user-centric organization

The Console shows the operator *their* fleet, not Relay's bookkeeping. The facts on
screen are Relay's — liveness, versions, Policy drift, Job history — but the *structure* of
every screen comes from the customer's own taxonomy: their `node:` labels (written in their
IaC) and their `tag:` labels (ADR-0020). Concretely:

- **Group-by-first fleet view**: group by any label key; the user's names (`prod`,
  `payments`, `web`) become the headline structure as rollup cards ("prod · 4,012 nodes ·
  3 offline · 12 on an older Policy fingerprint"); Relay's machinery view is just "group by
  nothing".
- **Saved views per Account**: landing is the operator's slice (filter + grouping), not
  the global registry; the "since you last looked" delta lane scopes to the current view.
- **Jobs mirror it**: the Jobs list filters to "Jobs that touched my view".
- **System Model socket**: the rollup card is designed so a post-1.0 Service (ADR-0008,
  v1.1.0) is just a named, shared group with provenance — a data upgrade, not a redesign.

Two boundaries keep this honest. (1) **No health theater**: rollups say
offline/outdated/quarantined — truth Relay actually knows — never CPU, latency or app
health. (2) **Observations, never desired state**: a group card never grows "expected N /
found M / reconcile" affordances — Relay does not auto-reconcile (invariant 9).

## Fleet-scale display patterns (legible at 10 and at 10,000 Nodes)

The governing rule: **the UI computes what is interesting; the human only ever reads
exceptions.** At fleet scale a list is a bug: every screen renders the *mode* (the normal
state) as one calm line and spends its pixels on deviations.

- **Histogram-by-output** (the v0.9.0 aggregation primitive; grouped outcomes with counts
  until then): cluster identical outputs — "9,797 Nodes: identical output (view one) · 3
  differ," outliers expanded by default. Same for facts and versions ("9,990 on daemon 1.4.2
  · 10 on 1.3.9").
- **The pixel wall**: fleet liveness as a grid of tiny colored cells, one per Node —
  10,000 fit on one screen and the single amber cell is found with zero reading. Click a
  cell to drill.
- **Faceted filtering with counts**: a slim rail of facets (OS, daemon version, labels,
  liveness), each showing its value distribution as counts; clicking one filters.
- **Selector-as-search**: the fleet view's filter box is the Selector language used for
  targeting, so browsing trains targeting and "what would this Job hit?" is already on
  screen.
- **Anomaly-first ordering**: default sort is by deviation/rarity, never alphabetical.
- **Deltas, not states**: the SSE seam feeds a "what changed" lane — since last look:
  2 enrolled, 1 offline, 3 changed Policy fingerprint.
- **Progressive-disclosure ladder, uniformly**: count → segmented bar → groups → sampled
  members → full list only on explicit demand. Never skip a rung.
- **Pin-and-compare**: select 2–3 Nodes for a side-by-side diff of facts / effective
  Policy — the "why did only this one deny" flow in one screen.

If the default render of 10,000 Nodes is one segmented bar, a pixel wall and three
interesting rows, the screen cannot get busy.

## What the Console never shows

The security floor (listeners, `console_execution` and the rest of invariant 11's list) as
anything but read-only; reach-bounding settings such as blast caps and gate rules are
`admin`-editable with step-up (`console/18-settings.md`, `console/19-approval-rules.md`).
Policy editing — view/query only. `node:` label editing. With `console_execution = off`,
the composer and every execution route are absent, not disabled: the strict tier is a
smaller Console, not a greyed-out one.

## Open design questions

- OIDC login UX and IdP-group display (when federated teams land).

Settled since: visual identity (#282 closed; `docs/brand/`), and approvals on a phone
(the Console decides none, ADR-0044).

## Deliverable order

1. This brief.
2. HTML wireframes of the four key screens — fleet view, Job detail, approval object,
   composer-with-Plan — iterated before any HTMX is written.
3. The #264 ADR — **written: [ADR-0026](../adr/0026-admin-console-execution-surface.md)**
   (supersedes ADR-0009's execution clause, amends invariant 10).
4. v0.6.0 build per `console-backend-coverage.md` sequencing.
