# Relay implements the MCP Tasks extension as a transport-layer shim

**Status:** Superseded by ADR-0047 (2026-10-22): the shim is removed. A return of MCP Tasks for
long-running Jobs is `docs/proposals/mcp-tasks-for-long-running-jobs.md`.

A parked dispatch is rendered as a `pending_approval` tool *result* (#371): honest,
poll-by-re-driving, and universal. The MCP Tasks extension
([SEP-2663](https://github.com/modelcontextprotocol/modelcontextprotocol/blob/main/seps/2663-tasks-extension.md),
**Final**) is the protocol-native shape for the same wait — a `tools/call` returns a task
handle, the client polls `tasks/get`, and polling stops being a dispatch attempt at all
(#379's audit distinction, made structural). ADR-0027 named the MCP task handle as the
premium delivery envelope; this ADR decides how Relay gets the capability when its SDK lacks
it.

The obstacle: `modelcontextprotocol/go-sdk` v1.7.0 does not implement Tasks, and
[go-sdk#626](https://github.com/modelcontextprotocol/go-sdk/issues/626) is open, unassigned,
with no timeline. The target spec is Final, so building against it is safe; waiting for the
SDK is unbounded.

## Decision

**Relay implements SEP-2663 itself, as a shim around the SDK — never a fork of it.**

- **Wait for go-sdk#626.** Rejected: unbounded, and it holds v0.5.1 (and #272's elicitation
  path) hostage to an unassigned upstream issue.
- **Fork the SDK.** Rejected: the SDK is a security-critical protocol library on the control
  plane's auth and transport path. Forking it makes us its maintainer — every upstream
  security fix becomes a merge, forever. That is the expensive direction of the polyglot bet
  (ADR-0007) with none of its payoff.
- **Shim around it.** Chosen. The SDK stays a pristine dependency; the shim is a bounded
  amount of our own code with a written removal condition. A shim is deletable; a fork is a
  marriage.

### The boundary, exactly

The SDK keeps everything it owns today: `tools/call` semantics, tool registration and
schemas, protocol negotiation, auth, and the streamable-HTTP transport.

The shim owns **only the task envelope**, in two pieces:

1. **The result rewrite**: when a dispatch parks *and* the client advertised the Tasks
   capability, the shim rewrites the outgoing parked tool result into a `CreateTaskResult`
   carrying an MCP task handle. *(Amended 2026-09-24: and the park did not emit an
   answerable approval question — see the amendment of that date.)*
2. **The task methods**: `tasks/get` and `tasks/cancel`, served as custom methods beside the
   SDK's own dispatch table.

The shim never re-implements Selector parsing, Action construction, authz, or dispatch.
Resolving a handle either reports the park's current state or hands the stored call back
through the **same capability-layer path the original tool call took** — so invariant 10
holds: the shim adds no control path to a Node, and the `no_dispatch` structural guard
extends over it unchanged ([5/6]).

### Why a transport-layer rewrite is tractable *here*

Rewriting wire JSON below an SDK is normally a losing game. Two facts make it bounded here:

- The SDK **rejects JSON-RPC batching** for protocol ≥ 2025-06-18 (`streamable.go:1447` in
  v1.7.0), and
- Relay runs the handler with **`JSONResponse: true, Stateless: true`** (#267) — every
  response is one JSON object, never an SSE stream or a batch.

So every request is one JSON-RPC message and every reply one JSON object, and the shim is a
**single-message response transformer**, not a protocol reimplementation. A
pre-2025-06-18 client could still send a batch, but it cannot have advertised the Tasks
capability, so the shim never touches its traffic.

**If either fact changes — the SDK accepts batches on our protocol versions, or the handler
stops running stateless/JSON — the shim's design assumption is void** and this ADR must be
revisited before the shim is trusted again. [5/6]'s wire-conformance tests pin both facts so
the change is a build failure, not a surprise.

### Scope

- **Parked dispatches only.** A task handle is minted for a dispatch that *parks*, never for
  ordinary long-running calls. General async dispatch would mean making `Service.Run`
  asynchronous, a Job-engine change this milestone does not make.
- **Capability negotiation is mandatory.** SEP-2663: servers **must not** return task
  results to clients that did not advertise `io.modelcontextprotocol/tasks`. Those clients
  keep receiving the `pending_approval` result (#371) — ADR-0027 decision 2 ("never
  hard-depend on an envelope") at the protocol level. The universal path works fully with
  the shim deleted.
- **One MCP task handle ↔ one parked dispatch**, at Job granularity (the
  `1 tool call → 1 handle → 1 Job → N Relay Tasks` mapping from the research note). The
  handle store ([2/6]) is durable, matching the stateless handler: any instance can resolve
  any handle, as with Job IDs (#139).

### `tasks/update` is out of scope — a boundary, not an omission

`tasks/update` is how a client answers an `inputRequests` elicitation. That is the
**in-band decision channel**, and whether an in-band answer can ever be a valid approval is
the open rung-2 question on #272: the Relay can only verify the *session's* Account, so an
answer routed to a human by the harness would be recorded as the agent's. Until #272 settles
that, Relay emits no `inputRequests`, so no client has a reason to call `tasks/update`.
*(Amended 2026-09-24: ADR-0029 settled the question, and #646 makes Relay emit them, so this
premise is void as a premise — the boundary now rests on a different one. See the amendment
of that date.)*

It is stated as a boundary because the failure mode is someone later "completing the
extension" and so opening a decision channel on the AI's own session by accident.
`no_decision_test.go` — the structural guard that package `mcp` cannot accept an approval
decision — is extended to cover the shim ([5/6]). Implementing `tasks/update` requires
amending **both** this ADR and that guard, in front of a human.

### `tasks/cancel` cancels the client's interest, not the approval

`tasks/cancel` marks the handle cancelled and ends the client's polling contract. It does
**not** withdraw, expire, or decide the underlying approval Request:

- **Security.** The cancel arrives over the MCP session — the AI's channel. If it could act
  on the approval object, the requesting session would hold a lever over a decision reserved
  for out-of-band humans (ADR-0027). An agent must not be able to yank a request back the
  moment it senses a denial coming, erasing the evidence a human was about to rule on.
- **Honesty.** SEP-2663 makes cancel best-effort, and since ADR-0013 Relay never
  retroactively un-happens what happened. The Request stays pending until decided or
  expired, remains visible in the approval queue and audit, and a re-drive of the same Plan
  re-attaches to it.

## Removal condition

**When go-sdk#626 ships Tasks natively, the shim is deleted** and `tasks/*` re-points at the
SDK's implementation. **Tracked, and left open deliberately, as
[#385](https://github.com/Felag-Engineering/relay/issues/385)**, which carries the deletion
checklist: what goes, what survives, what re-points, and the two things to re-check on the
way out. Expected survivors are the handle store ([2/6]) and the capability-layer semantics;
the wire-JSON rewriting ([4/6]) exists only because the SDK could not express it, and goes
first. A temporary shim with no written removal condition is a permanent shim.

## Naming

An **MCP task handle** is not a Relay **Task** (per-Node execution unit, ADR-0004). The term
is always written in full; GLOSSARY.md carries both entries and the disambiguation.

## Consequences

- v0.5.1 [2/6]–[6/6] build against this boundary: handle store, `tasks/get`/`tasks/cancel`
  custom methods, the `CreateTaskResult` rewrite gated on client capability, structural
  guards and wire conformance, docs, validation, and the removal tracking issue.
- Tasks-capable clients stop polling by re-driving: a poll becomes `tasks/get`, which is not
  a dispatch attempt and never touches the approval gate — the interaction #379 could only
  make audit-truthful becomes structurally free of the problem.
- Clients without the capability are untouched, byte for byte: the shim checks the
  negotiated capability before rewriting anything.
- Relay carries its own SEP-2663 conformance burden until go-sdk#626 lands ([5/6]'s golden
  wire tests), and the manual-validation script must find a genuinely Tasks-capable client
  or record a waiver ([6/6]).

## Amendment, 2026-08-17 — what the handle store settled (#373)

Building [2/6] settled one security boundary this ADR left open.

**A task handle is owner-only, and a handle you do not own is indistinguishable from one
that does not exist.**

Role-gating, so an admin could resolve anyone's handle, was rejected. Resolving a handle is
not a read: [4/6] hands the stored call back through the capability layer, so a second
Account resolving someone's handle would re-drive *their* dispatch under *their* authority —
an escalation wearing a read's clothes. Admins who need to see a waiting fleet action have
the approval queue and the audit trail, which show it without the power to advance it.

"Not yours" and "no such handle" are the same answer for the same reason. A distinct error
would confirm that a guessed or scraped ID is real, and existence alone discloses that some
Account has a fleet action waiting on a human. The check lives in the SQL `WHERE` clause
rather than a caller-side comparison, so both cases produce literally the same result — no
row — and the property is structural rather than remembered.

Two smaller things the store settled:

- **The handle carries two nullable bindings, not one overloaded ID.** SEP-2663 wants a task
  id in the `tools/call` response, the instant the dispatch parks — but parking creates no
  Job (#269), so at mint time there is only an approval Request. One field meaning "approval
  now, Job later" would make every reader guess which era a row was in.
- **The stored status is a record of what a client was told, never the answer.** Status is
  recomputed from the approval Request on every read, because what changes it — a decision
  on the Control API, the expiry sweeper — does not know handles exist. A handle reporting
  `working` for an approval denied an hour ago would be the approval-view fidelity gap in a
  new place. A handle also expires at or before its Request, under a hard 24-hour ceiling,
  so a lenient gate rule cannot mint week-long poll tokens carrying somebody's plan summary.

## Amendment, 2026-08-17 — what the shim settled (#375)

The shim is built. Three things this ADR left implicit turned out to be decisions, and one
premise is now verified.

**The premise holds.** `AddReceivingCustomMethod` merges `tasks/get` and `tasks/cancel` into
the SDK's own `receiveMethods` map, proven over the real transport with a real client
([3/6]). The response rewrite is a single-message transform: the SDK emits one JSON object
carrying `"resultType": "complete"` at the result's top level, so producing a task result is
replacing that object. `input_required`, the SDK's own second result type, is likewise flat
(`inputRequests` sits beside `resultType`), which fixes the task result's shape as flat too.

1. **The shim is a no-op object for everything that is not a candidate.** A request that is
   not a Tasks-capable `tools/call` never enters the buffering path and reaches the SDK
   handler holding the *original* `ResponseWriter`. Non-`tools/call` methods, error
   responses, plans, ordinary runs, and every non-advertising client are never processed,
   not merely "passed through". On a surface that sees every request to an RCE endpoint,
   "cannot be affected by a bug in this file" beats "is handled correctly by this file".

2. **The shim is a STRICT read file under the existing `no_dispatch` guard.** It may not name
   a capability identifier at all, so it cannot resolve a Selector, build an Action, or
   reach the Job engine — enforced by AST, not review. This is stronger than [5/6]
   anticipated, and is why the shim needed no new guard of its own.

3. **`ttlMs` is sent by the Relay, never derived by the shim.** The parked result carries
   `task_expires_at` — the *handle's* expiry, distinct from the approval's `expires_at`,
   because the handle is capped independently (`mcptask.MaxTTL`). A shim that computed a
   lifetime would be a second copy of that cap, and the two would drift. As with the status
   derivation in [2/6], the shim formats; it does not decide.

Identification is by the structured `pending_approval.status` field. Matching on the
Relay-authored summary would make the wire contract depend on wording; a test asserts that a
*completed* run whose captured Node output contains "pending_approval" and "task_id" is left
alone.

**Conformance is still owed.** The task result's field names follow SEP-2663 as read through
the issue and the SDK's flat `input_required` precedent; no genuinely Tasks-capable client has
yet spoken to this server. [6/6]'s validation script must find one or record a waiver, and
[5/6]'s golden wire tests pin the shape either way.

## Amendment, 2026-08-17 — conformance, and one finding (#376)

Both preconditions this ADR named are now **asserted by tests** that fail loudly if either
stops holding: the SDK refuses a JSON-RPC batch on the versions Relay speaks, and
`JSONResponse: true` yields exactly one JSON object per reply. If either fails after a
dependency bump, do not update the test — revisit this ADR before the shim is trusted again.

Conformance took option (1) from [5/6]: **byte-exact golden wire tests in-repo**, covering
create (capable and non-capable), poll non-terminal, poll terminal with results, cancel,
terminal-failed, and the unresolvable handle. They run through the real handler with fake
collaborators and a fixed clock, so only the wire varies.

Goldens rather than functional assertions because of how this fails. The shim's rule is
"when in doubt, pass through", so an SDK upgrade that changed the response shape would
degrade it into a silent no-op — every functional test green, Tasks-capable clients quietly
back on the universal path. Only an exact-JSON comparison makes that a failure.

The third structural guard [5/6] asked for is available in a stronger form than "must not
originate a result": **the shim does not import the MCP SDK at all.** A file that cannot name
the SDK cannot register a tool, add a method, or construct a result. `no_decision_test.go`
also covers `internal/mcptask` and forbids the literal `"tasks/update"` outright — serving it
requires naming it, so naming it fails the build. Both guards have a companion test that
plants a violation and asserts it is caught: a structural test nobody has seen fail is
indistinguishable from one that scans nothing.

### The finding: a JSON-RPC error code cannot be chosen on semantics alone

The goldens showed task errors going out with **code 0**, which is not a valid JSON-RPC
code. The obvious correction is wrong.

`CodeInvalidParams` is the right semantic fit for an unknown `taskId`. But the SDK's
streamable transport maps it — and `CodeMethodNotFound` — onto a **non-200 HTTP status**, and
the SDK's own client treats a non-200 as **fatal for the entire session**. Polling a lapsed
handle is ordinary; handles expire by design. The precise code would cost a correctly-behaving
client its whole MCP session and everything else in flight.

Task errors therefore use `CodeInternalError`, which maps to 200 and leaves the session
usable, and an e2e test pins it: a failed poll, then a working call on the same connection.
This trades code precision for session survival deliberately. If a real Tasks-capable client
wants a specific code, the fix belongs upstream in the SDK's code-to-status mapping.

Shim usage is logged once per rewrite (`msg="mcp task result issued"`, carrying the task id
and the `go-sdk#626` removal condition, never anything about the Plan). Silence means no
Tasks-capable client has driven a gated dispatch through this Relay, and the shim can go.

**Still owed, unchanged:** no genuinely Tasks-capable client has spoken to this server. The
goldens pin what Relay emits; they cannot confirm it is what SEP-2663 asks for. That remains
[6/6]'s to settle or waive.

## Amendment, 2026-09-24 — MRTR elicitation: a new premise for the `tasks/update` boundary, and one carve-out (#646)

ADR-0029 settled the question this ADR was waiting on, and #646 builds its decision 6: a
gated `tools/call` may answer with an MRTR input-required result carrying a Relay-authored
approval question, and the client retries the call carrying the answer. That makes two things
above wrong — an expired premise and a rule with a missing case. Both are this ADR's to
correct.

### 1. The `tasks/update` boundary keeps its position and loses its reason

The boundary said: *"Until #272 settles that question, Relay emits no `inputRequests`, and
therefore no client has any reason to call `tasks/update`."* **The question is settled, and
not there.** ADR-0029 decided that an in-band answer can be a valid approval, recorded as an
assertion rather than a verified human; #272 was closed as *not planned*, and what shipped
was deliberately narrower. So the premise is void **as a premise**: the condition it waited
on has been decided, the other way. #646 is what makes Relay emit `inputRequests`
(`approval.md` AP-60), and a boundary may not rest on a premise a decided change will
falsify.

**The boundary itself is unchanged and not weakened.** `tasks/update` remains out of scope,
the `no_decision_test.go` literal-string ban on `"tasks/update"` stands, and an in-band answer
arrives on a retried `tools/call`, never on a task method. Replacing the argument matters: an
edit that only deleted the stale fact would leave a security boundary standing on nothing,
which is how a boundary gets "completed" by someone who cannot find its reason.

**The replacement premise is the precedence decision below.** A park that emits an
answerable question emits no task envelope, so **there is no task to update**. A client never
holds a handle and a question for the same park at once, and the two answer channels cannot
race or disagree, because only one is ever open. This is stronger than the old premise, which
was a fact about what Relay had not built yet; this one is a property of the mechanism.

The rest of the original reasoning still holds: an answer arriving with no human anywhere in
the path is what the guard exists to prevent, and ADR-0029 decision 5 keeps that whole hole in
one auditable file. Implementing `tasks/update` still requires amending **both** this ADR and
that guard, in front of a human.

### 2. Precedence: an emitted question wins over the task envelope

*The boundary, exactly* says the shim rewrites a parked result into a `CreateTaskResult`
"when a dispatch parks *and* the client advertised the Tasks capability". That rule has no
case for a park already rendered as a question, so a client advertising both would receive a
handle for a park it was simultaneously being asked to answer.

**Decided: elicitation wins.** A park that emits an answerable approval question emits **no**
MCP task envelope; the rewrite condition gains "and no question was emitted". Everything else
is unchanged: a client that did not advertise the capability is untouched byte for byte, and
a park that emits *no* question — an `out-of-band` rule, an audience that excludes the caller
— is rewritten as before.

The question wins because it can be *answered*. A handle is a polling contract over a wait
somebody else must end; a question ends the wait on the same call. Giving a Tasks-capable
client the weaker envelope, when Relay has already decided this caller's answer would be
accepted, would make capability negotiation a downgrade.

**What this does not decide.** Which envelope a Tasks-capable client should get for a park
that *cannot* be asked stays as it is — such a park is still rewritten into a handle. That
belongs with #644 and `execution.md`'s migration, and is an Open question in
`docs/specs/approval.md`.

### Consequences

- **SEP-2663 conformance is unaffected.** A server must not return task results to clients
  that did not advertise the capability; it need not make every eligible result one.
  Declining to mint a handle is always conformant.
- **The universal path is still universal.** A client that can be asked gets a question; one
  that cannot gets `pending_approval` or a handle, as before. ADR-0027 decision 2's "never
  hard-depend on an envelope" holds across all three.
- **The removal condition is unchanged** (#385): when go-sdk#626 lands, the carve-out moves
  with the rewrite it qualifies.
- `docs/specs/approval.md` carries this as claims AP-60 and AP-71; GLOSSARY *MCP task handle*
  is corrected in the same change, since it said Relay mints one handle per parked dispatch.
