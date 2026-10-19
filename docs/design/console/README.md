# Admin Console — screen specifications

**Status:** wireframe-backed specifications, 2026-08-24. Written from a design session with the
owner, against low-fidelity wireframes drawn in a private design canvas (see below). These expand
[`../console-wireframe-brief.md`](../console-wireframe-brief.md) — deliverable #2 of
[`../ui-advisory.md`](../ui-advisory.md) — into per-screen, implementable units.

**Wireframes:** eleven artboards plus a shared-grammar sheet, in a private design canvas that
is not published with this repository. Each screen spec names its artboard.

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
   [04](04-activity.md), [13](13-job-detail.md),
   [10](10-day-one.md), [20](20-access.md) (admin only).
3. The v0.7.0 mutating surfaces, once step-up exists:
   [15](15-accounts-and-tokens.md), [09](09-add-nodes.md), [16](16-incident-ladder.md),
   [06](06-policy-author.md), [07](07-policy-fix-from-deny.md), then
   [05](05-composer-and-preflight.md) — the composer last, behind the step-up and the approval
   gate it depends on.
   [18](18-settings.md) and [19](19-approval-rules.md) follow step-up and store-backed settings
   (#590); neither mounts until its backend exists.

**Two defects gate all of it, and both are already tracked — neither needs a specification:**

- **[#397](https://github.com/Felag-Engineering/relay/issues/397)** — enrollment-token
  mint, Node revoke and Freeze engage/release have **no role gate**, so a `viewer` can do all
  three. Blocks specs [09](09-add-nodes.md) and [16](16-incident-ladder.md), whose controls state
  role requirements the API does not enforce.
- **[#403](https://github.com/Felag-Engineering/relay/issues/403)** — the Relay's server
  certificate never rotates. Both listeners share it (ADR-0031), so the Console's own TLS rides on
  the defect and breaks for every user fourteen days after the process starts.

Their fixes are settled in ADR-0032 §5, ADR-0013 and ADR-0031 §5 respectively. See
`99-open-decisions.md` D8 and D13. Both carry the `blocking` label and no milestone: they are
landed by hand, ahead of the loop.

## Screens

| # | Spec | Milestone | Mutating? |
|---|---|---|---|
| 11 | [Console shell](11-console-shell.md) | v0.6.0 | — |
| 12 | [Login](12-login.md) | v0.6.0 | — |
| 1 | [Fleet view](01-fleet-view.md) | v0.6.0 | no (tagging is v0.7.0) |
| 2 | [Node detail](02-node-detail.md) | v0.6.0 | no (`relay:` writes are v0.7.0) |
| 4 | [Activity](04-activity.md) | v0.6.0 stream / v0.7.0 Cancel | Cancel only (v0.7.0) |
| 13 | [Job detail](13-job-detail.md) | v0.6.0 record / v0.7.0 Cancel | Cancel only (v0.7.0) |
| 20 | [Access](20-access.md) | v0.6.0 | no — `admin` only |
| 10 | [Day one](10-day-one.md) | v0.6.0 | no |
| 15 | [Accounts and API tokens](15-accounts-and-tokens.md) | v0.7.0 | yes |
| 9 | [Add Nodes](09-add-nodes.md) | v0.7.0 | yes |
| 16 | [Incident](16-incident-ladder.md) | v0.7.0 | yes |
| 6 | [Policy Catalog](06-policy-author.md) | v0.7.0 | **no — generate-and-copy only** |
| 7 | [Policy fix, from a deny](07-policy-fix-from-deny.md) | v0.7.0 | **no — generate-and-copy only** |
| 5 | [Composer and Preflight](05-composer-and-preflight.md) | v0.7.0 | yes |

[03](03-agent-sessions.md) is retired: it was folded into 04 on 2026-09-29 (D17).
[14](14-approval-queue.md) and [08](08-approval-object.md) are retired: on 2026-10-18 the owner
removed approval from the Console entirely (ADR-0044, D21). Both screens were removed from the
code (`docs/specs/approval.md` AP-80).
[17](17-read-egress.md) is retired: dropped on 2026-10-01 (owner decision, D11); Activity (04)
carries read-class calls. Specs 11–20 have
no artboard; the wireframes cover 1–10 plus the shared-grammar sheet.

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
| **Facts are detail-view only** — not in a facet, never targetable; the hostname alone names a Node wherever one is shown, marked self-reported, with the verified ID secondary beside it (D20, widened by D22) | 01, 02, 00 |
| The fleet view answers **four questions** and nothing else; no collected metrics, ever | 01 |
| **No scheduled or repeated reads.** Every read is a deliberate, audited act | 03, 04, 01 |
| Upgrade handling is **progress only** — the Console never offers to push a daemon upgrade | 01 |
| The composer is reachable **from the nav and contextually** from a filtered fleet view | 01, 05 |
| Live stream and audit trail are **one surface** (Activity), call-grained, where a dispatching call's row is its Job (D17, 2026-09-29) | 04 |
| ~~Agent activity is a separate, call-grained, per-Account surface~~ — folded into Activity (D17); there are still no sessions (ADR-0028) | 04 |
| Sign-ins, step-up, Account changes and API Tokens are **Access**, `admin` only in the Console (D17) | 20 |
| **No hold-before-dispatch timer.** Interruption is cancellation (ADR-0013) | 03 |
| **Plan editing resets quorum**; approvers do not amend | 05 |
| Policy authoring is **generate-and-copy**; the Relay never transmits Policy. Since 2026-09-18, 06 arranges first-party catalog fragments (`docs/specs/policy-catalog.md`) and emits no allow rule | 06, 07 |
| `state:` labels are **Node-local and objective**; drift is an observation, not a label | 01, 02, 00 |
| **`outdated`** matches the MCP wire field; `version-gated` was a synonym and is retired | all |
| Stopping one agent: suspension **deferred** (ADR-0035 not adopted, #443); the instruments are token revoke and Freeze. There are no agent sessions to end — MCP is stateless | 03, 15, 16 |
| The Freeze slot generalises to **control-plane conditions** | 00, all |
| **No `Jobs` nav destination** — Activity filtered to dispatch | 00, 04 |
| The SSE seam has **four publishers** (registry, Jobs, MCP tool calls, enrollment attempts), resumable from a bounded buffer, and never carries read output | 00, 03, 10, 11 |
| The approval record carries a **shape key** (retrofit, #415); a batch is a **Grant** over a Scope | — (08 and 14 retired) |
| **The Console has no approval surface** — approvals are answered in-band or on the Control API (ADR-0044, 2026-10-18) | 00, 04, 05, 11, 19 |
| v0.6.0 **mutating** means reaching the capability layer's write or dispatch path; **Cancel is v0.7.0** | 03, 13 |
| `console_execution` lands with the composer (v0.7.0), not the shell | 05, 11 |
| Owner review of the running Console, 2026-10-18 (D22–D33): hostname first everywhere, **Policy aliases**, destructive acts drawn red behind a named confirmation, no "About this screen" disclosure | 00, 01, 02, 04, 15, 20 |
