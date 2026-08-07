# Admin Console — UI advisory (design brief)

**Status:** draft from the 2026-08-07 planning session, for owner ratification. This is the
design plan #264 references; it feeds the #264 ADR (Console execution surface), the
v0.5.0 approval-record schema, and the v0.6.0/v0.7.0 Console milestones. Companions:
`console-backend-coverage.md` (what backend each screen needs),
`approval-and-attribution.md` (the identity/approval model the screens render).

## Design intent

The Console is the **trust-building wedge**: a skeptical operator probes the boundary
themselves — composer → Plan → deny with the rule that fired — and *then* hands the keys
to the AI. The wall is the same wall. Every design decision serves one goal: **make the
boundary legible.** The product's pitch ("distrust is the architecture") must be visible
in the interface, not asserted in the README.

Two consequences run through every screen:

1. **A deny is not an error.** It is the product working. Denies render calm and
   informative — the rule that fired, verbatim, linked to the Node's effective-Policy
   view — never as a red failure state.
2. **Plan before apply, everywhere.** No mutating action without its Plan rendered first
   (mirrors the CLI's `--apply` discipline; it *is* the confirmation ladder's
   self-confirmation rung).

## Technical frame (ADR-0009, unchanged)

Server-rendered Go + HTMX, internal-only, SSE for liveness. No SPA, no client build
pipeline. Strict CSP (no inline script), CSRF tokens on every mutating route, SameSite
session cookies — the execution phase (v0.7.0) inherits this hardening from the
monitoring phase (v0.6.0), so it is built once, first.

## Journeys

- **Skeptical operator** (trust journey): watch the fleet live → probe the boundary in
  the composer → read the deny → widen Policy deliberately in their IaC → eventually
  delegate to the AI-agent. The Console's success metric is this journey completing.
- **Approver** ("Mike"): notification (elicitation/webhook/link) → approval queue → one
  approval object read in under a minute → decide with step-up. Fatigue-resistant by
  design (see Approval object below).
- **Auditor**: "who asked / for whom / who approved / what happened" in one query, with
  the verified/asserted distinction visible at a glance.
- **Admin**: enrollment tokens, Node revocation, Accounts/tokens, Freeze — every
  privilege-granting act a small ceremony (step-up).

## Screen inventory

**v0.6.0 — Monitoring (eyes only; zero mutating routes)**
- Login (password; OIDC later).
- Fleet view: live registry — liveness, facts summary, `node:`/`relay:` labels
  (namespaces visually distinct — `relay:` is the security lane and must read as such),
  Policy + template-set fingerprints, `outdated` flags.
- Node detail: facts, effective Policy (rendered from `policyview`), template
  vocabulary, cert/enrollment info, recent Tasks.
- Jobs: list + detail — per-Node outcomes with the full outcome vocabulary
  (`success / denied(rule) / unreachable / unsupported / cancelled / timeout`) grouped,
  not listed.
- Audit trail: filterable; verified/asserted lanes distinct (below).
- Approval queue, **read-only**: pending approvals with their Plans and quorum state.
- Enrollment Token inventory, CA/cert lifecycle, Freeze state (global banner on every
  screen when engaged).

**v0.7.0 — Administration & Execution**
- Approval queue, deciding: approve/deny with step-up; batch expansion; partial-quorum
  display.
- Composer: Operation picker driven by `list_operations` schemas (risk-class badge,
  argument constraints legible before submission — the ADR-0001 legibility bar applies
  to humans too), Selector input with live match-count vs blast cap, Plan rendering,
  apply with step-up.
- Accounts & tokens: create/disable Accounts (human + machine), roles, token
  mint/revoke — all step-up.
- Lifecycle: token mint/revoke, Node revoke, Freeze engage/release.

## Key screen requirements (these shape backend schemas — read before v0.5.0 lands)

**Plan rendering** (composer, approval queue, Job detail share one component):
fan-out summary ("matches 12 Nodes, mutate-cap 100 ✓"), risk-class badge, per-Node
verdicts *grouped* ("10 allow · 1 deny(rule R) · 1 unknown(offline)") with expansion,
the plan-hash visible (it is what gets approved).

**Deny legibility:** the failing rule verbatim + link to the Node's effective-Policy
view. The operator must be able to go from "denied" to "I understand exactly why, and
what file to change in my IaC" without leaving the Console.

**The approval object** — the highest-stakes rendering in the system; the v0.5.0
approval-record schema must store what this needs:
- Requester (verified) and `on_behalf_of` (asserted) — visually distinct trust levels.
- The Plan summary (above) — Relay-authored, never the agent's phrasing.
- **Diff against the last approved similar action** (same op/selector shape): "same as
  what you approved Tuesday, except: fan-out grew 3 → 12." Fatigue dies here or nowhere.
- Quorum state ("1 of 2 — mike signed, 2h ago") and TTL countdown.
- Batch grouping: a declared batch renders as one card with member expansion, one
  decision; never forty cards.
- Approve and Deny equally prominent; no default-focused Approve; batch approval
  requires expanding the batch at least once. No dark patterns on the approval path —
  the guarantee is only as good as the attention the UI extracts.

**Audit lanes:** one consistent visual grammar for verified vs asserted everywhere
(e.g. solid chip = Relay-verified, outlined chip = caller-asserted). An asserted
"ops-team" must never render with the same authority as a verified Account. This grammar
is also the approval object's requester line.

**Scale-ready results:** Job results must be legible at 3 Nodes and at 10k. Until the
v0.9.0 aggregation primitive lands, group-by-outcome with counts + sampled expansion;
the layout anticipates histogram-by-output so v0.9.0 slots into the same component.

**Live-but-stable:** SSE updates must never reflow content under a cursor mid-decision.
Approval cards and rendered Plans are pinned once open; liveness is for lists and
counters, not for the thing being read.

## What the Console never shows

Relay config (blast caps, listeners, gate rules, `console_execution`) — no settings
pages, per invariant #11. Policy editing — view/query only. `node:` label editing.
With `console_execution = off`: the composer and every execution route are absent, not
disabled — the strict tier is a smaller Console, not a greyed-out one.

## Open design questions

- Visual identity: parked behind #282 (naming diligence) — ship the phases on a plain,
  fast, unbranded look; do not spend on identity yet.
- **Approvals on a phone**: approvers arrive from links (elicitation/webhook). The
  decision pages (approval object + step-up) must be responsive and self-contained even
  though the Console is otherwise desktop-internal; on-call approval is a primary flow,
  not an afterthought. Step-up mechanism on mobile (passkey?) needs a decision in the
  v0.5.0/v0.7.0 seam.
- OIDC login UX and IdP-group display (when federated teams land).

## Deliverable order

1. This brief (owner ratifies / edits).
2. HTML wireframes of the four key screens — fleet view, Job detail, approval object,
   composer-with-Plan — iterated before any HTMX is written.
3. The #264 ADR (separate PR — supersedes ADR-0009's execution clause, amends
   invariant #10).
4. v0.6.0 build per `console-backend-coverage.md` sequencing.
