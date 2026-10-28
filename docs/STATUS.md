# Relay status

What the code on `main` does today, capability by capability. Read from each capability
specification and from the surface code on 2026-10-06 at `main` `9950ec0`; the Accounts and
Relay configuration rows re-read on 2026-10-20. Aligned with the owner's MVP decisions of
2026-10-23: the rows for the System Model, quarantine and the Policy Catalog are removed, and
Notes name the ADRs that change a cell once their code lands. Cells still report the code.

This page is a dated reading, not a source of truth. Behaviour lives in
[the capability specifications](specs/), what is in flight in the GitHub milestones, and what
must always hold in the invariants in [AGENTS.md](../AGENTS.md). Each cell reports what `main`
registers, never milestone progress. A spec's Status banner says how far that spec has migrated
to the claim format, not how much of the capability is built. Where a spec disagrees with the
code, Notes records it and a human resolves it
([AGENTS.md](../AGENTS.md#when-documents-and-the-code-disagree)).

## Capability matrix

Legend:

- **built** — the surface registers what the spec's Surfaces row says it does today.
- **partial** — the surface registers some of what its Surfaces row names; Notes says which part
  is missing.
- **designed** — the spec describes it on this surface (Behaviour, Surfaces, or a "Designed, not
  built" row) and the surface code does not register it.
- **deferred** — the spec places it under Future work or the first-pass exclusions, a
  proposal in the private roadmap holds it, or an ADR shelved it.
- **n/a** — the spec says this surface deliberately does not expose the capability: an absence
  that is the design (invariants 2 and 14, or an adapter offering less under invariant 10).

A cell is also `partial` when a "Designed, not built" item on that surface is unbuilt, and
**built (read-only)** when a read-only view is all the capability has there.

| Capability | Spec | MCP | Control API | Admin Console | Notes |
|---|---|---|---|---|---|
| Execution | [execution.md](specs/execution.md) | partial | partial | partial | MCP `run_operation`, `raw_exec`, `get_job`, `cancel_job`. MCP dispatch returns the Job once its Tasks are persisted (`job_status` `running`; poll `get_job`, or pass `wait_seconds` up to 300 to block); the idempotency key is implemented on MCP (`idempotency_key`, 24h per Account) and not on the Control API, whose `Idempotency-Key` and non-blocking return are not built. Console has Job cancel and executes nothing: the Console watches and does not execute (ADR-0052). |
| Operations and Templates | [operations-and-templates.md](specs/operations-and-templates.md) | partial | built | n/a | MCP `list_operations` takes one optional `node_id`, not a Selector (QRY-25, designed), and `run_operation`; Control API dispatches by name and has no vocabulary-listing route. The Console dispatches nothing (ADR-0052). Daemon: Native executors, Template renderer, `relay-daemon policy check`. |
| Selectors and Labels | [selectors-and-labels.md](specs/selectors-and-labels.md) | partial | partial | partial | Selectors resolve on MCP execution tools, the Control API execution routes and the Console fleet filter; Control API Node routes do not take a Selector. `tag:` terms resolve on every surface. Tags are written by a human Account at `operator` or above (ADR-0050): built on the Control API, one Node or a list of Node IDs; the Console adds and removes them on Node detail and, in bulk, over a filtered Fleet view's resolved Node IDs, through the same capability call; no MCP tool writes one. |
| Policy preflight | [policy-preflight.md](specs/policy-preflight.md) | built | built | partial | `plan: true` on `run_operation` and `raw_exec`; `"plan": true` on `POST /api/v1/operations` and `/raw-exec`. Console renders preflight audit records only; it sends no preflight of its own, because the Console does not execute (ADR-0052). |
| Approval | [approval.md](specs/approval.md) | built | built | built (read-only) | MCP `approve_request` and the MRTR elicitation envelope. Control API approvals list, read and decision. Approval grants are removed (ADR-0047; `approval.md` AP-84), and so are the MCP task handle and the shape key (ADR-0047; `approval.md` AP-85, AP-92). ADR-0047 retires `approve_request` and makes gate rules a section of `relay.toml`; the code still registers `approve_request`. The Console has no approval surface (ADR-0044, ADR-0047); approval records render in Activity and Job detail. Gate rules are never edited in the Console for the MVP (roadmap: relay/settings-in-the-console). |
| Freeze | [freeze.md](specs/freeze.md) | n/a (exception) | built | deferred | Control API `freeze/engage` and `freeze/release`. The spec names no MCP surface and no Freeze tool is registered; `n/a` here is the one cell that is not a stated design absence, and records an unnamed surface. Relay host: `SIGUSR1` engages, `SIGUSR2` releases. |
| Query | [query.md](specs/query.md) | built | built | built | MCP `list_nodes`, `describe_node`, `list_operations` (one optional `node_id`; a Selector is QRY-25, designed). The Control API exposes only the single-Node read `GET /api/v1/nodes/{node_id}`, by design (QRY-1); enumeration, the Policy view and the vocabulary are MCP and Console only. Console Fleet, Node detail and Compare read the registry; the Template vocabulary on Node detail is Future work (QRY-14). |
| Audit and the read lane | [audit-and-read-lane.md](specs/audit-and-read-lane.md) | built | built | partial | Control API reads `GET /api/v1/nodes/{node_id}` and `GET /api/v1/jobs/{id}` through the lane; there is no general audit-query endpoint. Console: Activity, Job detail and the event stream. The spec also names a Console read-egress screen; it was retired deliberately on 2026-10-01 and is not mounted, so the spec is stale there. |
| Enrollment | [enrollment.md](specs/enrollment.md) | n/a | built | built | Control API mints and revokes Enrollment Tokens. Console shows enrollment attempts and Node provenance; minting from the Console is deferred. Node plane: `Enrollment.Enroll` and `Renew`. Joining is `sudo relay-daemon join` with the join string pasted at its prompt (ADR-0048); a token's labels become initial tags (ADR-0050, designed). |
| Accounts and access | [accounts-and-access.md](specs/accounts-and-access.md) | built | built | built | MCP authenticates by API Token or OAuth and offers no administration. Control API administers Accounts and API Tokens. Console: login, Accounts, Access. Local operator: `relay init --admin` / `--recover` creates the first admin and its first token. |
| Policy | [policy.md](specs/policy.md) | built (read-only) | partial (read-only) | built (read-only) | The evaluated Policy and its fingerprint are shown through `describe_node` and the Console Node detail; the Control API Node read carries the Policy fingerprint only, and the Policy view is MCP and Console only (QRY-1, query.md). policy.md (aspirational) says the Control API shows it too; that disagrees with the migrated query.md and is left for a human. No surface writes Policy (invariant 2). The relay-daemon reads one local Policy file (`RELAY_POLICY_PATH`, default `/etc/relay-daemon/policy.toml`), written by the customer's config management and validated offline by `relay-daemon policy check`; the spec's fragment directory is not built. |
| Node connection | [node-connection.md](specs/node-connection.md) | n/a | n/a | n/a | Node plane only. Connection state reads appear in the Query row. |
| Relay configuration | [relay-configuration.md](specs/relay-configuration.md) | n/a | n/a | deferred | No settings tool, route or screen is registered. For the MVP the configuration file is the one source of settings; settings in the Console wait in roadmap: relay/settings-in-the-console. The security floor is the root-owned `relay.toml` (ADR-0043), reloaded all-or-nothing on SIGHUP; the Relay refuses to start if a retired `RELAY_*` setting is in its environment. The Control API will have no write route. |
| Daemon installation | [daemon-installation.md](specs/daemon-installation.md) | n/a | n/a | n/a | Release artifacts and the customer's config management (invariant 14). Offline `relay-daemon` subcommands: `--version`, `policy check`, `dump-operation-schema`. |
| Observability | [observability.md](specs/observability.md) | n/a | n/a | n/a | A Prometheus `/metrics` endpoint is mounted on the control-plane listener. `GET /healthz` answers serving or not serving without a credential, and `/metrics` carries certificate expiry, failed authentications and approvals waiting; a separate listener waits in roadmap: relay/opentelemetry. |
There is no row for `console.md`: the specs index lists it as not yet written.

Removed on 2026-10-23, cut from the MVP, with their specs: the System Model (ADR-0051;
roadmap: relay/fleet-topology and roadmap: runtime/fleet-memory), quarantine
(roadmap: relay/quarantine) and the Policy Catalog
(roadmap: relay/policy-catalog-and-live-reload). None was built on any surface.

## Releases and real hardware

No version is tagged: the earlier `v0.0.9` tag was retired on 2026-10-21 so that delivery tags
start fresh, and it never had a published GitHub Release. `main` is prepared for 0.1.0, the
first alpha. No real-hardware run is
recorded for any version: the sign-off table in
[beta-hardware-validation.md](operations/beta-hardware-validation.md) is unfilled, so
everything here is proven by the automated suites and the Docker dev fleet only.

## Known deviations

Mirrors AGENTS.md's gap table as read on 2026-10-24. ADR-0050 closes row 7's `tag:` half
once its code lands.

| Invariant | Clause | Issue |
|---|---|---|
| 7 | Legacy `relay:` scope labels on upgraded Relays | [#1201](https://github.com/Felag-Engineering/relay/issues/1201) |

What each gap means is in
[AGENTS.md — Known gaps between these invariants and the code](../AGENTS.md#known-gaps-between-these-invariants-and-the-code);
believe that table over this one.
