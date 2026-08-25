# Admin Console — screen specifications

**Status:** wireframe-backed specifications, 2026-08-24. Written from a design session with the
owner, against low-fidelity wireframes that exist as a design canvas (link below). These expand
[`../console-wireframe-brief.md`](../console-wireframe-brief.md) — deliverable #2 of
[`../ui-advisory.md`](../ui-advisory.md) — into per-screen, implementable units.

**Wireframes:** <https://claude.ai/code/artifact/0048ba58-2686-4f1a-992c-ca2d47aa44a4> — eleven
artboards plus a shared-grammar sheet. Each screen spec names its artboard.

## How to use these

One spec, one implementable unit, roughly one issue. Read in this order:

1. [`00-foundations.md`](00-foundations.md) — the design language, the shared components, and the
   rules that override normal dashboard instincts. **Every screen spec assumes it.** Read it once
   before touching any screen.
2. The screen spec you are implementing.
3. [`99-open-decisions.md`](99-open-decisions.md) — **before you write code.** Several things
   these specs describe are not yet decided and must not be settled by an implementation.
   Building past an open decision is how a wireframe becomes an accidental architecture.

## Build order

Numbers are identifiers, not sequence. Build in this order:

1. **[11 — Console shell](11-console-shell.md)** and **[12 — Login](12-login.md)**. Everything
   mounts into the shell, and the shell's CSP/CSRF/session work is security-critical per ADR-0026.
2. The v0.6.0 read surfaces: [01](01-fleet-view.md), [02](02-node-detail.md),
   [04](04-activity.md), [13](13-job-detail.md), [03](03-agent-sessions.md) (stream only),
   [14](14-approval-queue.md) (read only), [08](08-approval-object.md) (read only),
   [10](10-day-one.md), [17](17-read-egress.md).
3. The v0.7.0 mutating surfaces, once step-up exists:
   [15](15-accounts-and-tokens.md), [09](09-add-nodes.md), [16](16-incident-ladder.md),
   [06](06-policy-author.md), [07](07-policy-fix-from-deny.md), then
   [05](05-composer-and-plan.md) — the composer last, behind the step-up and approval machinery it
   depends on.

**Two defects gate all of it:** [#397](99-open-decisions.md) (the enrollment mint has no role gate)
and E2a (the Relay's server certificate never rotates, and the Console's TLS rides on it). See
`99-open-decisions.md` D8 and D13.

## Screens

| # | Spec | Milestone | Mutating? |
|---|---|---|---|
| 11 | [Console shell](11-console-shell.md) | v0.6.0 | — |
| 12 | [Login](12-login.md) | v0.6.0 | — |
| 1 | [Fleet view](01-fleet-view.md) | v0.6.0 | no (tagging is v0.7.0) |
| 2 | [Node detail](02-node-detail.md) | v0.6.0 | no (`relay:` writes are v0.7.0) |
| 3 | [Agent sessions](03-agent-sessions.md) | v0.6.0 stream / v0.7.0 controls | mixed |
| 4 | [Activity](04-activity.md) | v0.6.0 | no |
| 13 | [Job detail](13-job-detail.md) | v0.6.0 | cancel only |
| 17 | [Read egress](17-read-egress.md) | v0.6.0 | no |
| 10 | [Day one](10-day-one.md) | v0.6.0 | no |
| 14 | [Approval queue](14-approval-queue.md) | v0.6.0 read / v0.7.0 decide | mixed |
| 8 | [Approval object](08-approval-object.md) | v0.6.0 read / v0.7.0 decide | mixed |
| 15 | [Accounts and API tokens](15-accounts-and-tokens.md) | v0.7.0 | yes |
| 9 | [Add Nodes](09-add-nodes.md) | v0.7.0 | yes |
| 16 | [Incident](16-incident-ladder.md) | v0.7.0 | yes |
| 6 | [Policy Author](06-policy-author.md) | v0.7.0 | **no — generate-and-copy only** |
| 7 | [Policy fix, from a deny](07-policy-fix-from-deny.md) | v0.7.0 | **no — generate-and-copy only** |
| 5 | [Composer and Plan](05-composer-and-plan.md) | v0.7.0 | yes |

Specs 11–17 have no artboard; the wireframes cover 1–10 plus the shared-grammar sheet.

## Sequencing

`../console-backend-coverage.md` holds the dependency map and it still governs: **Accounts →
Approval Callout backend → Console monitoring (with the SSE seam) → Console admin (step-up) →
Console execution composer.** Nothing here reorders that. The specs are written screen-first
because that is how they are built, not because that is the order they land.

## Decisions taken in the session that produced these

Recorded so an implementer knows which parts are settled and which are inherited. None of these
are ADRs yet; several need to be — see [`99-open-decisions.md`](99-open-decisions.md).

| Decision | Where it bites |
|---|---|
| A fourth Label namespace, **`state:`** — Relay-derived, nobody sets it, targetable, never a security-lane target | 01, 02, 05, 00 |
| **Facts are detail-view only** — not on a row, not in a facet, never targetable | 01, 02 |
| The fleet view answers **four questions** and nothing else; no collected metrics, ever | 01 |
| **No scheduled or repeated reads.** Every read is a deliberate, audited act | 03, 04, 01 |
| Upgrade handling is **progress only** — the Console never offers to push a daemon upgrade | 01 |
| The composer is reachable **from the nav and contextually** from a filtered fleet view | 01, 05 |
| Live stream and audit trail are **one surface** (Activity), Job-grained | 04 |
| Agent sessions are a **separate, call-grained surface** with different retention | 03 |
| **No hold-before-dispatch timer.** Interruption is cancellation (ADR-0013) | 03 |
| **Plan editing resets quorum**; approvers do not amend | 05, 08 |
| Policy authoring is **generate-and-copy**; the Relay never transmits Policy | 06, 07 |
| `state:` labels are **Node-local and objective**; drift is an observation, not a label | 01, 02, 00 |
| **`outdated`** matches the MCP wire field; `version-gated` was a synonym and is retired | all |
| Stopping one agent is **Account suspension**, not a session kill | 03, 15, 16 |
| The Freeze slot generalises to **control-plane conditions** | 00, all |
| **No `Jobs` nav destination** — Activity filtered to dispatch | 00, 04 |
| The SSE seam has **three publishers**, and never carries read output | 00, 03, 11 |
| The approval record carries a **shape key**, decided in v0.5.0 | 08, 14 |
