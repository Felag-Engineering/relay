# Relay status

What the code on `main` does today, capability by capability. Read from each capability
specification and from the surface code on 2026-10-06 at `main` `9950ec0`.

This page is a dated reading, not a source of truth. Behaviour lives in
[the capability specifications](specs/), what is in flight lives in the GitHub milestones, and
what must always hold lives in the invariants in [AGENTS.md](../AGENTS.md). A cell below
describes what `main` registers, never milestone progress. A spec's Status banner says how far
that spec has migrated to the claim format, not how much of the capability is built. Each cell
reports what the code on `main` registers; where a spec says otherwise, Notes records the
disagreement and this page never resolves it. A disagreement between a spec and the code is
resolved by a human ([AGENTS.md](../AGENTS.md#when-documents-and-the-code-disagree)).

## Capability matrix

Legend:

- **built** — the surface registers what the spec's Surfaces row says it does today.
- **partial** — the surface registers some of what its Surfaces row names; Notes says which part
  is missing.
- **designed** — the spec describes it on this surface (Behaviour, Surfaces, or a "Designed, not
  built" row) and the surface code does not register it.
- **deferred** — the spec places it under Future work or the first-pass exclusions,
  [docs/deferred.md](deferred.md) lists it, or an ADR shelved it.
- **n/a** — the spec says this surface deliberately does not expose the capability: an absence
  that is the design (invariants 2 and 14, or an adapter offering less under invariant 10).

A cell is `partial` as well when a "Designed, not built" item on that surface is unbuilt.

Where a read-only view is all the capability has on a surface, the cell says **built (read-only)**.

| Capability | Spec | MCP | Control API | Admin Console | Notes |
|---|---|---|---|---|---|
| Execution | [execution.md](specs/execution.md) | partial | partial | partial | MCP `run_operation`, `raw_exec`, `get_job`, `cancel_job`. MCP dispatch returns the Job once its Tasks are persisted (`job_status` `running`; poll `get_job`, or pass `wait_seconds` up to 300 to block); the idempotency key is implemented on MCP (`idempotency_key`, 24h per Account) and not on the Control API, whose `Idempotency-Key` and non-blocking return are not built. Console has Job cancel; the execution composer is designed (v0.7.0) and `/console/run` is a placeholder behind a flag the composition root keeps off (invariant 10 gap). |
| Operations and Templates | [operations-and-templates.md](specs/operations-and-templates.md) | partial | built | designed | MCP `list_operations` takes one optional `node_id`, not a Selector (QRY-25, designed), and `run_operation`; Control API dispatches by name and has no vocabulary-listing route. Console dispatch is the same composer as above. Daemon: Native executors, Template renderer, `relay-daemon policy check`. |
| Selectors and Labels | [selectors-and-labels.md](specs/selectors-and-labels.md) | partial | partial | partial | Selectors resolve on MCP execution tools, the Control API execution routes and the Console fleet filter; Control API Node routes do not take a Selector. `tag:` writes are designed and a `tag:` term is refused at parse (invariant 7 gap). Spec says `tag:` is writable on every surface. |
| Policy preflight | [policy-preflight.md](specs/policy-preflight.md) | built | built | partial | `plan: true` on `run_operation` and `raw_exec`; `"plan": true` on `POST /api/v1/operations` and `/raw-exec`. Console renders preflight audit records only; its own preflight (PF-21) is designed. |
| Plan | [plan.md](specs/plan.md) | designed | designed | designed | No Plan tool, route or screen is registered. |
| Approval | [approval.md](specs/approval.md) | built | built | partial | MCP `approve_request` and the MRTR elicitation envelope. Control API approvals list, read and decision, plus approval-grant create, list, read and revoke. Console queue, request detail and decision under step-up; approval grants have no Console screen; bulk decisions (AP-59) and gate rules edited in the Admin Console (AP-72) are designed. |
| Approval assurance | [approval-assurance.md](specs/approval-assurance.md) | deferred | deferred | deferred | A stub, shelved by ADR-0040. |
| Freeze | [freeze.md](specs/freeze.md) | n/a (exception) | built | deferred | Control API `freeze/engage` and `freeze/release`. The spec names no MCP surface and no Freeze tool is registered; `n/a` here is the one cell that is not a stated design absence, and records an unnamed surface. Relay host: `SIGUSR1` engages, `SIGUSR2` releases. |
| Quarantine a Node | [quarantine-node.md](specs/quarantine-node.md) | designed | designed | designed | No engage or lift is registered anywhere (invariant 7 gap). |
| Query | [query.md](specs/query.md) | built | built | built | MCP `list_nodes`, `describe_node`, `list_operations` (one optional `node_id`; a Selector is QRY-25, designed). The Control API exposes only the single-Node read `GET /api/v1/nodes/{node_id}`, by design (QRY-1); enumeration, the Policy view and the vocabulary are MCP and Console only. Console Fleet, Node detail and Compare read the registry; the Template vocabulary on Node detail is Future work (QRY-14). |
| Audit and the read lane | [audit-and-read-lane.md](specs/audit-and-read-lane.md) | built | built | partial | Control API reads `GET /api/v1/nodes/{node_id}` and `GET /api/v1/jobs/{id}` through the lane; there is no general audit-query endpoint. Console: Activity, Job detail and the event stream. The spec also names a Console read-egress screen; it was retired deliberately on 2026-10-01 and is not mounted, so the spec is stale there. |
| Enrollment | [enrollment.md](specs/enrollment.md) | n/a | built | built | Control API mints and revokes Enrollment Tokens. Console shows enrollment attempts and Node provenance; minting from the Console is deferred. Node plane: `Enrollment.Enroll` and `Renew`; the relay-daemon enrolls on first start. |
| Accounts and access | [accounts-and-access.md](specs/accounts-and-access.md) | built | built | built | MCP authenticates by API Token or OAuth and offers no administration. Control API administers Accounts and API Tokens. Console: login, Accounts, Access. Local operator: `relay bootstrap-token`. |
| Policy Catalog | [policy-catalog.md](specs/policy-catalog.md) | n/a | n/a | designed | No catalog screen is registered (PC-8 to PC-16). Release artifacts and config management are the other surfaces. |
| Policy | [policy.md](specs/policy.md) | built (read-only) | partial (read-only) | built (read-only) | The evaluated Policy and its fingerprint are shown through `describe_node` and the Console Node detail; the Control API Node read carries the Policy fingerprint only, and the Policy view is MCP and Console only (QRY-1, query.md). policy.md (aspirational) says the Control API shows it too; that disagrees with the migrated query.md and is left for a human. No surface writes Policy (invariant 2). The relay-daemon reads one local Policy file (`RELAY_POLICY_PATH`, default `/etc/relay-daemon/policy.toml`), written by the customer's config management and validated offline by `relay-daemon policy check`; the spec's fragment directory is not built. |
| Node connection | [node-connection.md](specs/node-connection.md) | n/a | n/a | n/a | Node plane only. Connection state reads appear in the Query row. |
| Relay configuration | [relay-configuration.md](specs/relay-configuration.md) | designed | designed | designed | No settings tool, route or screen is registered; the security floor is the host's `RELAY_*` environment. `relay bootstrap-token` and `relay console-password` exist. The Control API will have no write route. |
| Daemon installation | [daemon-installation.md](specs/daemon-installation.md) | n/a | n/a | n/a | Release artifacts and the customer's config management (invariant 14). Offline `relay-daemon` subcommands: `--version`, `policy check`, `dump-operation-schema`. |
| Observability | [observability.md](specs/observability.md) | n/a | n/a | n/a | A Prometheus `/metrics` endpoint is mounted on the control-plane listener. The spec's separate metrics listener and unauthenticated health endpoint are not registered. |
| System Model | [system-model.md](specs/system-model.md) | deferred | deferred | deferred | A stub, deferred by the owner on 2026-09-14 and not in the first pass; unbuilt, scheduled for v1.1.0 (ADR-0008). |

There is no row for `console.md`: the specs index lists it as not yet written.

## v0.0.9 and real hardware

`v0.0.9`, tagged 2026-08-09, is the only tagged version, and no GitHub Release with artifacts is
published for it. `main` has moved well past it: Templates, Accounts and access, the approval
callout, Control API execution and the whole Admin Console landed after the tag. The tag
contains the mTLS Node plane with enrollment by token; the MCP tools `run_operation`,
`raw_exec`, `get_job`, `cancel_job`, `list_nodes`, `describe_node` and `list_operations`,
including the Policy preflight (`plan: true`) on the two dispatch tools; the Control API's
Enrollment Token mint and revoke, Node revoke, and Freeze engage and release; a Prometheus
`/metrics` endpoint; and the relay-daemon's local deny-by-default Policy and Native executors. It
has no Template engine, no Admin Console and no approval. No real-hardware run is recorded for any
version: the sign-off table in [beta-hardware-validation.md](operations/beta-hardware-validation.md)
is unfilled, so everything here is proven by the automated suites and the Docker dev fleet only.

## Known deviations

Mirrors AGENTS.md's gap table as read on 2026-10-15.

| Invariant | Clause | Issue |
|---|---|---|
| 7 | `tag:`'s writer, and `relay:`'s | [#430](https://github.com/Felag-Engineering/gleipnir-relay/issues/430) |
| 10 | Console execution | [#438](https://github.com/Felag-Engineering/gleipnir-relay/issues/438) |
| 11 | Secret files readable only by the Relay, writable only by root (or the Relay, for what it generates) | [#864](https://github.com/Felag-Engineering/gleipnir-relay/issues/864) |
| 11 | The floor's source is writable only by a root-equivalent human | hardening review (issue to file) |

What each gap means is in
[AGENTS.md — Known gaps between these invariants and the code](../AGENTS.md#known-gaps-between-these-invariants-and-the-code);
believe that table over this one.
