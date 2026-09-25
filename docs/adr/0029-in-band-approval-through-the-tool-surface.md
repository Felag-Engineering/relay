# In-band approval through the tool surface

**Status:** Accepted.

ADR-0027 decided *notify via MCP, decide out-of-band*, and named channel strength as
per-rule configuration: `in-band` ("the elicitation answer *is* the decision") and
`out-of-band` ("the decision must land on the authenticated decision endpoint"). The
`in-band` rung was designed, spelled in the config grammar, and given a comparison
operator — and then never made reachable. No surface could produce a `ChannelInBand`
decision, so a rule configured `channel: "in-band"` behaved identically to `out-of-band`.

Meanwhile ADR-0028 and `no_decision_test.go` hardened the opposite position: **no file in
package `mcp` or `mcptask` may name a decision identifier at all**, enforced by parsing the
package's own AST. That guard was correct for what it was written against — `tasks/update`,
an answer arriving with no human anywhere in the path.

The two positions were never reconciled. The result is a product that ships a
two-person-only approval mechanism, an inert config value, and a ROADMAP promising an
elicitation channel that cannot be emitted.

## Context that changed

**The harness assumption was wrong in one direction.** ADR-0027 treated an in-band answer as
"only as trustworthy as the harness" and stopped there. But the harnesses Relay is actually
driven by do not hand tool calls to the model to answer: Claude Code and Codex surface a
tool call to the operator and block on their confirmation, and Gleipnir's HIL router
intercepts and never exposes the decision to the LLM at all. The failure mode ADR-0027
guarded against — the model answering its own approval — is not what these clients do.

**The two-person tier is not the only tier that matters.** ADR-0027's own confirmation
ladder has three rungs, and rung 2 is self-confirmation: "are you sure", answered by the
person already present. Forcing rung 2 through an out-of-band endpoint makes the cheap case
as expensive as the expensive one, which is the fatigue failure ADR-0027 named as a
security property in its own right.

**MRTR arrived and changed nothing about who may decide.** MCP 2026-07-28 removed
server-initiated requests and replaced them with Multi Round-Trip Requests (SEP-2322); a
server answers `tools/call` with an `InputRequiredResult` and the client retries. It is
stateless-compatible, and go-sdk v1.7.0 implements both halves. But no client Relay is
driven by negotiates 2026-07-28 yet — Claude Code 2.1.234 negotiates `2025-11-25` and
refuses a 2026-07-28 server outright. MRTR is therefore buildable and testable but not yet
usable.

## Decision

**1. An in-band approval is accepted, and it is a tool call.**

A new MCP tool, `approve_request`, records a decision against a parked request. It takes the
`request_id`, the `plan_hash` it is answering, the approve/deny verdict, an asserted
`approver` identity, and an optional reason. It is an ordinary tool call, so every client
that exists today can make it and every client's tool-confirmation UX puts a human in front
of it.

This is deliberately *not* elicitation. Delivery envelopes come and go with protocol
revisions; a tool is the one surface every MCP client has had since 2024-11-05.

**2. Attribution stays honest: verified requester, asserted approver.**

Relay cannot verify that a human answered — only that the client says one did. So the
decision is recorded in the attribution triple ADR-0027 already defined, using the
`Assertions` lane that already exists end to end (`X-Relay-On-Behalf-Of`,
`asserted_on_behalf_of`, `ByOnBehalfOf`):

- `approved_by` — the **verified** Account whose credential made the call.
- `on_behalf_of` — the **asserted** approver identity supplied by the client.
- `channel` — `in-band`, recorded as the fact it is.

An auditor can always separate "a human authenticated to Relay and approved this" from "a
client told us a human approved this". That distinction is the point; collapsing it would
buy simplicity by making the audit trail claim more than Relay knows.

**3. `ErrMachineSelfDecision` is relaxed for in-band answers carrying an asserted approver
— and only there.**

The domain currently refuses a self-decision from a machine Account: *"A machine confirming
its own proposal is the same actor answering twice."* That reasoning holds when the machine
is genuinely answering. It does not hold when the machine is **relaying** an answer it did
not author. The relaxation is therefore conditioned on both facts together: the channel is
`in-band` **and** an asserted approver is present. A machine self-decision with no asserted
approver stays refused.

**4. Channel strength remains the operator's dial, and out-of-band still means out-of-band.**

`ErrWeakChannel` is unchanged: an in-band decision cannot satisfy a rule requiring
`out-of-band`. Deployments that want the two-person tier configure `channel: "out-of-band"`
and are entirely unaffected by this ADR. What changes is that `in-band` stops being inert.

**5. The structural guard is narrowed, not removed.**

`no_decision_test.go` continues to scan both packages and fail on every decision identifier
— except inside the single file implementing this tool. Every other file in `mcp` and
`mcptask` remains guarded, so a second decision path cannot appear by accident, and the
whole of this hole is auditable by opening one file.

**6. MRTR is the second envelope, later, over the same decision path.**

When a client Relay is driven by negotiates 2026-07-28 and implements SEP-2322, Relay may
additionally return an `InputRequiredResult` carrying the approval elicitation. It must
route to the **same** decision path this ADR establishes, with the same attribution and the
same channel semantics. One decision model, two delivery envelopes — not two mechanisms.

## Consequences

- Rung 2 becomes usable, on today's clients, with no protocol dependency.
- A deployment that wants the old posture changes nothing: leave rules `out-of-band`.
- **The guarantee for `in-band` rules is now explicitly a client-integrity assumption.** A
  compromised or naive client can approve rung-2 requests. This is stated rather than
  implied, and it is why rung 3 exists and why `out-of-band` remains the default for it.
  *(Note, 2026-09-24: no decision in this ADR changes, but the scope of this consequence does.
  [ADR-0040](0040-the-surface-that-created-a-request-answers-it.md) shelves out-of-band as a rule
  requirement for now and settles that an MCP-originated request is answered over MCP. Rung 3 and
  its default both stand wherever a rule sets one; no shipped or seeded rule does, so for
  agent-originated work the client-integrity assumption is no longer one posture among several —
  it is the posture. Explicitly interim, pending the permissions rework.)*
- Gleipnir's HIL router becomes load-bearing for in-band rules: ADR-0027's requirement that
  it be *"a deterministic path to the assigned human"* is no longer advice.
- The audit trail gains a class of record whose approver is asserted. Queries that need
  verified approvers must filter on channel.
- ROADMAP v0.5.0's "elicitation is the primary, first-class channel" is retired; the primary
  in-band channel is the tool surface.

## Alternatives considered

**Keep out-of-band only.** The status quo. Rejected: it makes rung 2 unreachable, which
makes the confirmation ladder two rungs, and it drives approval fatigue that ADR-0027
itself names as a security property.

**MRTR elicitation first.** Spec-native and testable in CI via the SDK's MRTR client, but
unusable from every client Relay is currently driven by. Building a surface nothing can call
is the trap v0.5.1 already fell into with Tasks; deferred to decision 6 rather than led with.

**Server-initiated `elicitation/create` over SSE.** Would work with today's clients, but it
implements a pattern 2026-07-28 explicitly removed, and requires abandoning
`JSONResponse: true` — a per-handler option — costing the stateless property for *every*
call to serve one rung. Rejected.

**Treat an in-band answer as a fully verified human decision.** Simpler, and rejected: the
audit trail would answer "who approved this?" identically whether a human really did or a
client merely said so.
