# Admin Console — backend coverage & sequencing

> **Frozen snapshot (2026-08-07), superseded.** The Status column is mostly as of that date and is
> wrong in places: Accounts, Console sessions and step-up re-authentication are built
> (ADR-0023). What each Console screen needs and has is in [docs/design/console/](console/)
> and the capability specs in [docs/specs/](../specs/). This file is kept for the sequencing
> rationale.
>
> **Cut from the MVP (2026-10-23).** The Console watches and does not execute (ADR-0052): the
> execution composer, its step-up apply and `console_execution` are gone, so the last step of
> the build order below no longer exists. There is no approval queue (ADR-0047). Quarantine is
> cut (roadmap: relay/quarantine); `tag:` grouping is built for the MVP, written by a human
> Account at `operator` or above (ADR-0050). The configuration file is the one source of
> settings for the MVP (roadmap: relay/settings-in-the-console).

**Status:** planning-session output (owner + AI-agent, 2026-08-07), pre-ADR. It maps each
Console surface to the backend it needs, so Console milestones are sequenced by real
dependencies.

## Surface → backend matrix

| Console surface | Backend needed | Status (2026-08-07) |
|---|---|---|
| Node registry view (facts, labels, liveness, Policy fingerprint, `outdated`) | registry read seams | ✅ `relay/internal/registry`, consumed by MCP `list_nodes`/`describe_node`; liveness and certificate validity not yet on the record (#440) |
| Effective-Policy viewer per Node | daemon-evaluated Policy queries | ✅ `policyview` (ADR-0011) |
| Jobs/Tasks, results, audit trail | store + audit queries | ✅ the capability layer's read lane (#441), exposed to the Console as `console.QueryReader`, never a Console→store call (invariant 10) |
| Freeze, Enrollment Token mint/revoke, Node revoke | capability layer + API | ✅ `/api/v1` slice (v0.0.6) |
| Execution composer (`list_operations` schemas, plan, run, raw_exec, cancel) | capability layer | ✅ MCP-only; the Console adapts the same layer in-process |
| **Login, roles, sessions** | Account model | ❌ single seeded shared credential; no identity |
| **Step-up re-auth** on mutate apply / privilege grants | session "recent-auth" concept | ❌ depends on Accounts |
| **Live updates (SSE)** | event seam with **four publishers** — registry transitions, Job transitions, MCP tool calls (arguments, never read results), enrollment attempts — bounded ring buffer, `Last-Event-ID` resume, `gap` event | ✅ seam: `internal/events` + `internal/eventsink` (#416); the SSE route over it is #422 |
| **Approval queue** | pending-approval Job state + decision endpoint | ❌ = the Approval Callout milestone ([2/6], [3/6]) |
| **Browser security** (CSRF tokens, CSP, cookie sessions) | new middleware | ❌ bearer-token-only; #264 puts XSS/CSRF on the most dangerous path |
| Large-fleet result rendering | aggregation/histogram primitive | ❌ deferred; paginate short-term |
| Saved views + group-by fleet view (`ui-advisory.md` Organizing principle) | per-Account view persistence | ❌ #442; group-by itself is a pure read over registry labels |
| Label management: `relay:` quarantine lane + `tag:` grouping (ADR-0020) | capability + API endpoints | ❌ labels set only via token scope at enrollment |

## Planning consequences

1. **Accounts is the critical path for every Console phase.** Login, role gating, step-up
   re-auth and per-human audit attribution all sit on it. Cookie/session auth is structurally
   different from a bearer token, and retrofitting attribution is painful.
2. **Design the approval-record schema for the queue that renders it** — Plan-shaped approval
   objects, diffs against the last approved state, batching (see the #268 scope comment).
   Which surface decides an approval is settled since: ADR-0040 and ADR-0044 (the Console
   does not decide approvals).
3. **Build order:** Accounts → Approval Callout backend → Console monitoring (with the SSE
   seam) → Console admin (step-up) → Console execution composer. The aggregation primitive
   slots in wherever fleet sizes demand it.
4. **Label management** is settled since: who writes each namespace is invariant 7 (ADR-0020,
   ADR-0034). No Account writes a `relay:` label directly.

## What must never appear in the UI

- **The security floor** (listeners, CA and TLS material, auth bootstrap, the identity
  provider, session and step-up windows, `console_execution` itself): set in the root-owned
  `relay.toml`, never on a settings page (invariant 11, ADR-0043). Reach-bounding
  configuration — blast caps, approval-gate rules — may be a runtime object a human Account
  changes with step-up.
- **Policy**: view and query only (`policyview`), never editable. Policy authoring stays in
  the customer's IaC (ADR-0002), backed by the daemon-side kernel protections (`ProtectSystem`,
  `ReadOnlyPaths=/etc/relay-daemon`, #246).
- **`node:` labels**: read-only (ADR-0006).

## Structural guard

Settled: the Console package has its own `no_dispatch` structural test, alongside the MCP and
Control API ones (invariant 10).

## Intent-binding note

The Console's step-up apply is the strongest per-action human-intent binding in the system
(`approval-and-attribution.md`). That justifies giving the Console an execution surface at all,
and makes its browser-security work security-critical, not cosmetic.
