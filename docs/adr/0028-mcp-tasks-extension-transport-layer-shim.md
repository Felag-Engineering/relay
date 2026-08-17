# Relay implements the MCP Tasks extension as a transport-layer shim

A parked dispatch is today rendered as a `pending_approval` tool *result* (#371): honest,
poll-by-re-driving, and universal. The MCP Tasks extension
([SEP-2663](https://github.com/modelcontextprotocol/modelcontextprotocol/blob/main/seps/2663-tasks-extension.md),
**Final**) is the protocol-native shape for the same wait — a `tools/call` returns a task
handle, the client polls `tasks/get`, and polling stops being a dispatch attempt at all
(#379's audit distinction, made structural). ADR-0027 named the MCP task handle as the
premium delivery envelope; this ADR decides how Relay acquires the capability when its SDK
does not have it.

The obstacle: `modelcontextprotocol/go-sdk` v1.7.0 does not implement Tasks, and
[go-sdk#626](https://github.com/modelcontextprotocol/go-sdk/issues/626) is open,
unassigned, with no timeline. The target spec is Final, so building against it is safe;
waiting for the SDK is unbounded.

## Decision

**Relay implements SEP-2663 itself, as a shim around the SDK — never a fork of it.**

Three options were on the table:

- **Wait for go-sdk#626.** Rejected: unbounded, and it holds v0.5.1 (and #272's
  elicitation path) hostage to an unassigned upstream issue.
- **Fork the SDK.** Rejected: the SDK is a security-critical protocol library sitting on
  the control plane's auth and transport path. Forking it makes us its maintainer —
  every upstream security fix becomes a merge, forever. That is the expensive direction
  of the polyglot bet (ADR-0007) with none of its payoff.
- **Shim around it.** Chosen. The SDK stays a pristine dependency; the shim is a bounded
  amount of our own code with a written removal condition. A shim is deletable; a fork is
  a marriage.

### The boundary, exactly

The SDK keeps ownership of everything it owns today: `tools/call` semantics, tool
registration and schemas, protocol negotiation, auth, and the streamable-HTTP transport.

The shim owns **only the task envelope**, in two pieces:

1. **The result rewrite**: when a dispatch parks *and* the client advertised the Tasks
   capability, the shim rewrites the outgoing parked tool result into a
   `CreateTaskResult` carrying an MCP task handle.
2. **The task methods**: `tasks/get` and `tasks/cancel`, served as custom methods beside
   the SDK's own dispatch table.

The shim never re-implements Selector parsing, Action construction, authz, or dispatch.
Resolving a handle either reports the park's current state or hands the original,
stored call back through the **same capability-layer path the original tool call took** —
so invariant 10 holds: the shim adds no control path to a Node, and the `no_dispatch`
structural guard extends over it unchanged ([5/6]).

### Why a transport-layer rewrite is tractable *here*

Rewriting wire JSON below an SDK is normally a losing game. Two facts about this
deployment make it a bounded one:

- The SDK **rejects JSON-RPC batching** for protocol ≥ 2025-06-18
  (`streamable.go:1447` in v1.7.0), and
- Relay runs the handler with **`JSONResponse: true, Stateless: true`** (#267)
  — every response is one JSON object, never an SSE stream or a batch.

So every request is exactly one JSON-RPC message and every reply exactly one JSON
object, and the shim is a **single-message response transformer**, not a protocol
reimplementation. A pre-2025-06-18 client could still send a batch — but such a client
cannot have advertised the Tasks capability, so the shim never touches its traffic.

**If either fact changes — the SDK starts accepting batches on our protocol versions, or
the handler stops running stateless/JSON — the shim's design assumption is void** and
this ADR must be revisited before the shim is trusted again. [5/6]'s wire-conformance
tests pin both facts so the change announces itself as a build failure, not a surprise.

### Scope

- **Parked dispatches only.** A task handle is minted for a dispatch that *parks* —
  never for ordinary long-running calls. General async dispatch would mean making
  `Service.Run` asynchronous, a Job-engine change this milestone does not make.
- **Capability negotiation is mandatory.** SEP-2663: servers **must not** return task
  results to clients that did not advertise `io.modelcontextprotocol/tasks`. Clients
  that did not keep receiving the `pending_approval` result (#371) — which is also
  ADR-0027 decision 2 ("never hard-depend on an envelope") expressed at the protocol
  level. The universal path remains fully functional with the shim deleted.
- **One MCP task handle ↔ one parked dispatch**, at Job granularity (the
  `1 tool call → 1 handle → 1 Job → N Relay Tasks` mapping from the research note). The
  handle store ([2/6]) is durable, matching the stateless handler: any instance can
  resolve any handle, the same property Job IDs already have (#139).

### `tasks/update` is out of scope — a boundary, not an omission

`tasks/update` is how a client answers an `inputRequests` elicitation. That is the
**in-band decision channel**, and whether an in-band answer can ever be a valid approval
is precisely the open rung-2 question on #272: the Relay can only verify the *session's*
Account, so an answer routed to a human by the harness would be recorded as the agent's.
Until #272 settles that question, Relay emits no `inputRequests`, and therefore no client
has any reason to call `tasks/update`.

This is stated as a boundary because the failure mode is someone later "completing the
extension" and thereby opening a decision channel on the AI's own session by accident.
`no_decision_test.go` — the structural guard that package `mcp` cannot accept an
approval decision — is extended to cover the shim ([5/6]). Implementing `tasks/update`
requires amending **both** this ADR and that guard, in front of a human.

### `tasks/cancel` cancels the client's interest, not the approval

`tasks/cancel` marks the handle cancelled and stops the client's polling contract.
It does **not** withdraw, expire, or decide the underlying approval Request. Two reasons:

- **Security.** The cancel arrives over the MCP session — the AI's channel. If it could
  act on the approval object, the requesting session would hold a lever over a decision
  reserved for out-of-band humans (ADR-0027). An agent must not be able to yank a request
  back the moment it senses a denial coming, erasing the evidence a human was about to
  rule on.
- **Honesty.** SEP-2663 makes cancel best-effort, and Relay's cancel semantics have been
  honest since ADR-0013: a thing that already happened is never retroactively
  un-happened. The Request stays pending until decided or expired, remains visible in
  the approval queue and audit, and a re-drive of the same Plan re-attaches to it.

## Removal condition

**When go-sdk#626 ships Tasks natively, the shim is deleted** and `tasks/*` re-points at
the SDK's implementation. [6/6] opens the tracking issue and its deletion checklist. The
expected survivors: the handle store ([2/6]) and the capability-layer semantics; the
wire-JSON rewriting ([4/6]) is the part that exists only because the SDK could not
express it, and it goes first. A temporary shim with no written removal condition is a
permanent shim; this one's condition is written down and tracked.

## Naming

An **MCP task handle** is not a Relay **Task** (per-Node execution unit, ADR-0004). The
term is always written in full — CONTEXT.md already carries both entries and the
disambiguation; no domain language shifts with this ADR.

## Consequences

- v0.5.1 [2/6]–[6/6] build against this boundary: handle store, `tasks/get`/`tasks/cancel`
  custom methods, the `CreateTaskResult` rewrite gated on client capability, structural
  guards + wire conformance, docs + validation + the removal tracking issue.
- Tasks-capable clients stop polling by re-driving: a poll becomes `tasks/get`, which is
  not a dispatch attempt and never touches the approval gate — the interaction #379
  could only make audit-truthful becomes structurally free of the problem.
- Clients without the capability are untouched, byte for byte: the shim inspects the
  negotiated capability before rewriting anything.
- Relay carries its own SEP-2663 conformance burden until go-sdk#626 lands ([5/6]'s
  golden wire tests), and the manual-validation script must find a genuinely
  Tasks-capable client or record a waiver ([6/6]).
