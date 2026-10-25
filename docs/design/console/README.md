# Admin Console — screen specifications

**Status:** wireframe-backed specifications, 2026-08-24, from a design session with the owner.
They expand [`../console-wireframe-brief.md`](../console-wireframe-brief.md) — deliverable #2 of
[`../ui-advisory.md`](../ui-advisory.md) — into per-screen, implementable units.

**Wireframes:** eleven artboards plus a shared-grammar sheet, in a private design canvas not
published with this repository. Each screen spec names its artboard.

## How to use these

One spec, one implementable unit, roughly one issue. Read in this order:

1. [`00-foundations.md`](00-foundations.md) — the design language, the shared components, and the
   rules that override normal dashboard instincts. **Every screen spec assumes it.**
2. The screen spec you are implementing.
3. [`99-open-decisions.md`](99-open-decisions.md) — **before you write code.** Some things these
   specs describe are not decided and must not be settled by an implementation.

## Build order

Numbers are identifiers, not sequence. Build in this order:

1. **[11 — Console shell](11-console-shell.md)** and **[12 — Login](12-login.md)**. Everything
   mounts into the shell, and the shell's CSP/CSRF/session work is security-critical per ADR-0026.
2. The v0.6.0 read surfaces: [01](01-fleet-view.md), [02](02-node-detail.md),
   [04](04-activity.md), [13](13-job-detail.md),
   [10](10-day-one.md), [20](20-access.md) (admin only).
3. The mutating surfaces, once step-up exists: [15](15-accounts-and-tokens.md),
   [09](09-add-nodes.md), and tag editing on [02](02-node-detail.md) and in bulk from
   [01](01-fleet-view.md) (ADR-0050).

The Console watches; it does not execute (ADR-0052). It has no composer, no approval queue
(ADR-0047), no settings screens (the configuration file is the one source for the MVP), no
Policy author and no incident screen. Those pages were cut from the MVP on 2026-10-23 and moved
to the private roadmap: roadmap: relay/console-execution-for-skills (05),
roadmap: relay/policy-catalog-and-live-reload (06, 07), roadmap: relay/quarantine (16),
roadmap: relay/settings-in-the-console (18, 19). Policy aliases stay, edited in the Console.

## Screens

| # | Spec | Milestone | Mutating? |
|---|---|---|---|
| 11 | [Console shell](11-console-shell.md) | v0.6.0 | — |
| 12 | [Login](12-login.md) | v0.6.0 | — |
| 1 | [Fleet view](01-fleet-view.md) | v0.6.0 / MVP bulk tags | bulk tag edit only (MVP, ADR-0050) |
| 2 | [Node detail](02-node-detail.md) | v0.6.0 / MVP tags | tag edit only (MVP, ADR-0050) |
| 4 | [Activity](04-activity.md) | v0.6.0 stream / v0.7.0 Cancel | Cancel only (v0.7.0) |
| 13 | [Job detail](13-job-detail.md) | v0.6.0 record / v0.7.0 Cancel | Cancel only (v0.7.0) |
| 20 | [Access](20-access.md) | v0.6.0 | no — `admin` only |
| 10 | [Day one](10-day-one.md) | v0.6.0 | no |
| 15 | [Accounts and API tokens](15-accounts-and-tokens.md) | v0.7.0 | yes |
| 9 | [Add Nodes](09-add-nodes.md) | v0.7.0 | yes |

Retired: [03](03-agent-sessions.md), folded into 04 (D17);
[08](08-approval-object.md) and 14 (approval queue), removed with the Console's approval
surface (ADR-0044, D21; `docs/specs/approval.md` AP-80); 14 is now in the private roadmap;
[17](17-read-egress.md), dropped (D11). Activity carries read-class calls.
Cut from the MVP on 2026-10-23 and moved to the private roadmap: 05, 06, 07, 16, 18, 19. Specs 11–20 have no artboard; the wireframes cover 1–10 plus the
shared-grammar sheet.

## Sequencing

`../console-backend-coverage.md` holds the dependency map, and it governs: **Accounts → Approval
Callout backend → Console monitoring (with the SSE seam) → Console admin (step-up).** The
Console execution composer that once ended this chain is cut (ADR-0052). The specs are written screen-first because that is how they are built, not
the order they land.

## Decisions taken in the session that produced these

So an implementer knows which parts are settled. Where one has become an ADR, or is still open,
[`99-open-decisions.md`](99-open-decisions.md) says so.

| Decision | Where it bites |
|---|---|
| A fourth Label namespace, **`state:`** — Relay-derived, nobody sets it, targetable, never a security-lane target | 01, 02, 00 |
| **Facts are detail-view only** — not in a facet, never targetable; the hostname alone names a Node wherever one is shown, marked self-reported, with the verified ID secondary beside it (D20, widened by D22) | 01, 02, 00 |
| The fleet view answers **four questions** and nothing else; no collected metrics, ever | 01 |
| **No scheduled or repeated reads.** Every read is a deliberate, audited act | 03, 04, 01 |
| Upgrade handling is **progress only** — the Console never offers to push a daemon upgrade | 01 |
| Live stream and audit trail are **one surface** (Activity), call-grained, where a dispatching call's row is its Job (D17, 2026-09-29) | 04 |
| ~~Agent activity is a separate, call-grained, per-Account surface~~ — folded into Activity (D17); there are still no sessions (ADR-0028) | 04 |
| Sign-ins, step-up, Account changes and API Tokens are **Access**, `admin` only in the Console (D17) | 20 |
| **No hold-before-dispatch timer.** Interruption is cancellation (ADR-0013) | 03 |
| The Relay never transmits Policy (invariant 2). The Console's Policy author was cut from the MVP (roadmap: relay/policy-catalog-and-live-reload) | — |
| `state:` labels are **Node-local and objective**; drift is an observation, not a label | 01, 02, 00 |
| **`outdated`** matches the MCP wire field; `version-gated` was a synonym and is retired | all |
| Stopping one agent: suspension **deferred** (ADR-0035 not adopted, #443); the instruments are token revoke and Freeze. There are no agent sessions to end — MCP is stateless | 03, 15 |
| The Freeze slot generalises to **control-plane conditions** | 00, all |
| **No `Jobs` nav destination** — Activity filtered to dispatch | 00, 04 |
| The SSE seam has **four publishers** (registry, Jobs, MCP tool calls, enrollment attempts), resumable from a bounded buffer, and never carries read output | 00, 03, 10, 11 |
| ~~The approval record carries a **shape key**; a batch is a **Grant** over a Scope~~ — both cut by ADR-0047 | — (08 and 14 retired) |
| **The Console has no approval surface** — an approval is one in-band answer (ADR-0044, ADR-0047) | 00, 04, 11 |
| v0.6.0 **mutating** means reaching the capability layer's write or dispatch path; **Cancel is v0.7.0** | 03, 13 |
| **The Console watches; it does not execute** (ADR-0052, 2026-10-23). No composer, no run placeholder, no execution flag | 00, 11 |
| **Tags are the operator's labels** (ADR-0050, 2026-10-23): edited on Node detail and in bulk over a Selector's matched Nodes from the Fleet view, with a confirmation that shows them | 01, 02 |
| Owner review of the running Console, 2026-10-18 (D22–D33): hostname first everywhere, **Policy aliases**, destructive acts drawn red behind a named confirmation, no "About this screen" disclosure | 00, 01, 02, 04, 15, 20 |
| Owner review, 2026-10-21 (D34–D36): **show, don't tell** — a standing note is deleted unless the screen would be wrong without it, Node detail's invariant-2 note included; Accounts is **one list with modals**; an Account changes only its **own password** | 00, 01, 02, 04, 11, 15, 20 |
| Console passwords, 2026-10-22 (D37, ADR-0045): a human Account created in the Console gets a **temporary password**, a first sign-in with it is **forced to change it**, and a human changes **only their own** password, proving the current one | 11, 12, 15, 20 |
