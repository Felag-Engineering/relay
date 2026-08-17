# Manual validation — `v0.5.1` (MCP Tasks Extension)

> **Run waived for the v0.5.1 close — 2026-08-17.** Written but not executed, and the
> sign-off table below is empty by that decision rather than by oversight
> ([README.md](README.md) rule 7).
>
> **The reason is specific to this milestone, and is the finding itself: there was no
> client to run it with.** SEP-2663 reached Final and, as of this close, no available MCP
> client implemented it — not the Go SDK
> ([go-sdk#626](https://github.com/modelcontextprotocol/go-sdk/issues/626), open,
> unassigned), and not the TypeScript or Python SDKs. Steps 1–4 below need a genuinely
> Tasks-capable client and cannot be discharged with one that does not exist. They were
> exercised instead by a **raw JSON-RPC harness** that speaks the extension by hand
> (`relay/cmd/relay/mcp_tasks_e2e_test.go`), which is real wire traffic against the real
> stateless handler — but a hand-written client asserting against a hand-written server is
> not independent verification, and this script should not pretend otherwise.
>
> **What a real run would cover that CI cannot:** whether an *independent* implementation
> agrees with Relay's reading of SEP-2663 — field names, the flat result shape, `resultType:
> "task"`, and whether a client that receives the handle actually knows how to poll it.
> Relay's goldens pin what it *emits*; nothing in this repo can confirm that is what the
> spec *asks for*. That is the one thing this waiver leaves genuinely unproven, and it is
> stated here so it is discovered by reading rather than by a customer.
>
> Steps 5–8 need no Tasks-capable client and are the ones to run first when a fleet is
> available.

Delta script on top of [validate-v0.2.0.md](validate-v0.2.0.md) and the v0.5.0 approval
surface. It validates what v0.5.1 added: the MCP task handle as a delivery envelope for an
approval that was already possible without it.

**The property to keep in mind throughout:** every step below is about *how a caller waits*.
None of it changes *who may decide*. If any step appears to let an MCP client answer an
approval, stop — that is a finding, not a feature.

## Prerequisites

- A Relay with `--approval-gate-config` pointing at a file that parks mutates, at least one
  enrolled Node, and two Accounts: a machine requester and a human approver
  (`relay bootstrap-token`, then `POST /api/v1/accounts`).
- An MCP client that advertises `io.modelcontextprotocol/tasks` in its per-request
  `_meta` client capabilities. **If none exists, stop and record the waiver above.**

---

## 1. A gated dispatch returns a task handle, not a tool result

Drive `run_operation` for a gated mutate from the Tasks-capable client.

**Expect:** the `tools/call` response's `result` carries `"resultType": "task"` with
`taskId`, `status: "working"`, `createdAt`, `lastUpdatedAt`, `ttlMs`, and
`pollIntervalMs`. It does **not** carry `content` or `structuredContent`.

**Also confirm nothing ran:** `GET /api/v1/jobs` shows no new Job, and the approval queue
(`GET /api/v1/approvals`) shows one pending request.

_Discharges:_ v0.5.1 acceptance 1 (first half); ADR-0028 scope (parked dispatches only).

## 2. Polling is not a dispatch attempt

Call `tasks/get` with the handle three or four times, waiting `pollIntervalMs` between.

**Expect:** `status: "working"` each time, and `statusMessage` carrying the
**Relay-authored** plan summary verbatim — the same text the approver will read.

**The point of this step is what does NOT appear.** Check the audit trail: those polls must
produce **no** `approval_requested` and **no** `approval_pending_observed` entries. Polling
by re-driving produced one audit record per poll; `tasks/get` produces none, because it is
a read rather than a dispatch attempt.

_Discharges:_ ADR-0028 consequences (polling stops being a dispatch attempt).

## 3. A human approves out-of-band, and the same handle reports the result

As the **approver** Account, `POST /api/v1/approvals/{id}/decision` with `approve: true`
and the `plan_hash` from the queue. Then re-drive the original `run_operation` (the
approval releases a Plan; it does not itself dispatch), and poll `tasks/get` again.

**Expect:** `status: "completed"`, with `result` carrying the per-Node results.

**Compare against `get_job` for the same `job_id`.** The two must tell the same story — the
same outcomes, exit codes, and output. A Job that reads differently through a task handle
than through `get_job` is an approval-view fidelity finding.

_Discharges:_ v0.5.1 acceptance 1 (second half).

## 4. The decision never travelled over the MCP session

Review the audit trail for the exchange.

**Expect:** the `approval_decided` record is attributed to the **approver's** Account and
its `auth_method`/token, never to the requesting machine Account. The requesting session
made a `tools/call` and some `tasks/get` calls, and nothing else.

**Then try to break it:** from the Tasks-capable client, attempt `tasks/update` with any
payload.

**Expect:** the method is not served. Relay emits no `inputRequests`, so there is nothing
to answer, and no handler exists to receive one. A response other than a method error is a
finding — it would mean an approval decision channel had opened on the AI's own session.

_Discharges:_ ADR-0028 (`tasks/update` out of scope as a boundary); ADR-0027 decision 4.

---

The remaining steps need **no** Tasks-capable client. Run these first.

## 5. A client without the extension is unaffected

Drive the same gated `run_operation` from an ordinary MCP client (one that does not
advertise Tasks) — for example an SDK-default client.

**Expect:** a `pending_approval` tool **result** exactly as in v0.5.0: `status`,
`request_id`, `plan_hash`, `summary`, `matched_rules`, `progress`, `expires_at`,
`decision_path`, `next_step`. Approve out-of-band and re-drive: the dispatch runs.

**This is the step that matters most if you only run one.** The universal path is the
guarantee; Tasks is a convenience layered on it. If this regresses, the milestone has
broken something it promised not to touch.

_Discharges:_ v0.5.1 acceptance 2; ADR-0027 decision 2.

## 6. Cancelling a handle does not withdraw the approval

Park a dispatch, then call `tasks/cancel` on its handle. (A raw JSON-RPC call is fine here —
this step is about the server's behaviour, not the client's.)

**Expect:** `status: "cancelled"`. Then check `GET /api/v1/approvals`: the request is
**still pending, still listed, still decidable**. Approve it and re-drive the original
call — it runs.

**Why this matters:** a cancel arrives over the AI's own session. If it could withdraw a
pending request, an agent could pull one back the moment it sensed a denial coming and
erase the evidence a human was about to rule on.

_Discharges:_ v0.5.1 acceptance 3.

## 7. A handle is not a bearer token

As a **different** Account — including an `admin` one — call `tasks/get` with a handle
minted by the first Account. Then call it with an id that was never minted.

**Expect:** both refused, with the **same** message. A distinct "not yours" would confirm
that a guessed id is real, and existence alone discloses that some Account has a fleet
action waiting on a human. An admin is no exception: resolving a handle is not a read,
because it is the entry point that re-drives the stored call under the owner's authority.

_Discharges:_ v0.5.1 acceptance 4.

## 8. An unresolvable handle does not kill the session

Call `tasks/get` with a nonsense id, then make an ordinary call on the **same** MCP session.

**Expect:** the first fails legibly; the second succeeds. Polling a lapsed handle is
ordinary — handles expire by design — and losing the whole session for it would be a
defect. See `renderTaskError` for why the error code is chosen the way it is.

_Discharges:_ ADR-0028 amendment (#376), the error-code trade-off.

## 9. Is anyone using the extension?

Grep the Relay's logs for `mcp task result issued`.

**Expect:** one line per task result issued, carrying the task id and the `go-sdk#626`
removal condition — and **nothing else about the Plan**. If the log is silent over a
representative period, no Tasks-capable client is driving gated dispatches through this
Relay, and the shim can be deleted the moment the SDK ships Tasks natively.

_Discharges:_ #376 (usage signal); ADR-0028 removal condition.

---

## Sign-off

| Field | Value |
|---|---|
| Date | _(waived — see header)_ |
| `relay --version` | |
| `relay-daemon --version` | |
| Steps passed | |
| Steps skipped, and why | _All — no Tasks-capable MCP client existed at the v0.5.1 close._ |
| Operator | |

**Re-run trigger:** run steps 1–4 as soon as any MCP client ships SEP-2663 support. That is
the first opportunity to find out whether an independent implementation agrees with Relay's
reading of the spec — the one thing this waiver leaves unproven.
