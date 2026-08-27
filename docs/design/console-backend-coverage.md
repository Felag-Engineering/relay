# Admin Console — backend coverage & sequencing

**Status:** planning-session output (owner + AI-agent, 2026-08-07), pre-ADR. Companion to
the Console execution-surface decision (#264) and the approval/attribution design note
(`approval-and-attribution.md`). Maps every Console surface to the backend it needs, so
Console milestones are sequenced by real dependencies rather than optimism.

## Surface → backend matrix

| Console surface | Backend needed | Status (2026-08-07) |
|---|---|---|
| Node registry view (facts, labels, liveness, Policy fingerprint, `outdated`) | registry read seams | ✅ `relay/internal/registry`, consumed by MCP `list_nodes`/`describe_node` — **but** liveness and certificate validity are not on the record; #440 (v0.6.0) adds them for `state:` and Node detail |
| Effective-Policy viewer per Node | daemon-evaluated Policy queries | ✅ `policyview` (ADR-0011) |
| Jobs/Tasks, results, audit trail | store + audit queries | ✅ #441 landed the capability layer's read lane — `capability.{QueryAudit,AuditCounts,AuditReach,QueryJobs,QueryTasks}` (`internal/auditquery` adapts `store/auditquery.go`+`store/jobquery.go`), exposed to the Console as `console.QueryReader` (invariant #10, never a Console→store call); the screens that consume it (#422/#423/#424/#425) are separate issues |
| Freeze, Enrollment Token mint/revoke, Node revoke | capability layer + API | ✅ `/api/v1` slice (v0.0.6) |
| Execution composer (`list_operations` schemas, plan, run, raw_exec, cancel) | capability layer | ✅ `capability/{execution,plan,cancel}`, `opvocab` golden schema — MCP-only today; Console adapts the same layer in-process |
| **Login, roles, sessions** | Account model | ❌ single seeded shared credential; no identity |
| **Step-up re-auth** on mutate apply / privilege grants | session "recent-auth" concept | ❌ depends on Accounts |
| **Live updates (SSE)** | event seam with **four publishers** — registry transitions, Job transitions, MCP tool calls (arguments, never read results), enrollment attempts — bounded ring buffer, `Last-Event-ID` resume, `gap` event | ✅ seam landed: `internal/events` + `internal/eventsink`, wired into the composition root (#416, v0.6.0) — the SSE HTTP route over it is still outstanding, #422 |
| **Approval queue** | pending-approval Job state + decision endpoint | ❌ = the Approval Callout milestone ([2/6], [3/6]) |
| **Browser security** (CSRF tokens, CSP, cookie sessions) | new middleware | ❌ bearer-token-only today; #264 puts XSS/CSRF on the most dangerous path |
| Large-fleet result rendering | aggregation/histogram primitive | ❌ deferred (read-lane milestone); paginate short-term |
| Saved views + group-by fleet view (`ui-advisory.md` Organizing principle) | per-Account view persistence (small preference store keyed to Accounts) | ❌ #442 (v0.6.0); group-by itself is a pure read over existing registry labels |
| Label management: `relay:` quarantine lane + `tag:` grouping (ADR-0020) | capability + API endpoints — one mechanism, two authz tiers (`admin`+step-up / `operator`) | ❌ labels set only via token scope at enrollment; scheduled v0.7.0 |

## Planning consequences

1. **Accounts is the critical path for all Console phases.** Login, role gating
   (`viewer`/`operator`/`admin` on the composer), step-up re-auth, and per-human audit
   attribution all sit on it. Do not ship any Console phase on the shared credential —
   cookie/session auth is structurally different from a bearer token, and retrofitting
   attribution is painful.
2. **The Approval Callout backend doubles as Console backend.** The pending-approval
   state and decision endpoint are exactly what the approval queue renders — and the
   Console is likely the best decision surface. Design the approval-record schema with
   the UI's fatigue mitigations in mind *now* (Plan-shaped approval objects, diffs
   against last approved state, batching — see the #268 scope comment), so the backend
   stores what the queue needs to render.
3. **Suggested build order:** Accounts → Approval Callout backend → Console monitoring
   (with the SSE seam) → Console admin (step-up) → Console execution composer; the
   aggregation primitive slots in wherever fleet sizes demand it.
4. **Label management ships as one mechanism with two tiers** (ADR-0020): the same
   capability/API endpoints serve `tag:` writes (`operator`, standard auth) and `relay:`
   writes (`admin` + step-up). The Console surfaces are bulk tag-from-filter in the fleet
   view and `relay:` set/remove on Node detail — both v0.7.0, since they mutate.

## What must never appear in the UI

- **Relay config** (blast caps, listeners, approval-gate rules, `console_execution`
  itself): file-only per invariant #11 — no settings page, ever. The Console renders
  runtime objects; it does not manage the Relay.
- **Policy**: view/query only (`policyview`), never editable — Policy authoring stays in
  the customer's IaC (ADR-0002), and the daemon-side kernel protections
  (`ProtectSystem`, see #246 comment re `ReadOnlyPaths=/etc/relay-daemon`) back that up.
- **`node:` labels**: read-only (ADR-0006 — node-rooted, Relay-immutable).

## Structural guard

The `no_dispatch`-style structural test (today proving the MCP package cannot construct a
dispatch outside the capability layer — `controlplane/mcp/no_dispatch_test.go`) needs a
Console-package twin per #264: the execution composer must provably route through the one
capability chokepoint, verified by compilation/structural test rather than review
discipline — the v0.0.5 precedent.

## Intent-binding note

Per the approval/attribution design note: the Console's step-up apply is the strongest
per-action human-intent binding in the system (rung 2 of the confirmation ladder, fused
into the request surface). This is both the justification for giving the Console an
execution surface at all and the reason its browser-security work is security-critical,
not cosmetic.
