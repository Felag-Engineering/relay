# In-band approval through the tool surface

**Status:** Accepted; amended by ADR-0044.

ADR-0027 decided *notify via MCP, decide out-of-band*, and made channel strength per-rule
configuration: `in-band` ("the elicitation answer *is* the decision") and `out-of-band` ("the
decision must land on the authenticated decision endpoint"). The `in-band` rung was designed,
spelled in the config grammar, and given a comparison operator — and never made reachable. No
surface could produce a `ChannelInBand` decision, so a rule configured `channel: "in-band"`
behaved identically to `out-of-band`.

Meanwhile ADR-0028 and `no_decision_test.go` hardened the opposite position: **no file in
package `mcp` or `mcptask` may name a decision identifier at all**, enforced by parsing the
package's own AST. That guard was correct for what it was written against — `tasks/update`, an
answer arriving with no human anywhere in the path.

The two positions were never reconciled. The product shipped a two-person-only approval
mechanism, an inert config value, and a milestone plan (then in ROADMAP.md, retired
2026-09-12) promising an elicitation channel that could not be emitted.

## Context that changed

**The harness assumption was wrong in one direction.** ADR-0027 treated an in-band answer as
"only as trustworthy as the harness" and stopped there. But the harnesses that drive Relay do
not hand tool calls to the model to answer: Claude Code and Codex surface a tool call to the
operator and block on their confirmation, and Gleipnir's HIL router intercepts and never
exposes the decision to the LLM. The failure ADR-0027 guarded against — the model answering its
own approval — is not what these clients do.

**The two-person tier is not the only tier that matters.** ADR-0027's ladder has three rungs,
and rung 2 is self-confirmation: "are you sure", answered by the person already present. Forcing
rung 2 through an out-of-band endpoint makes the cheap case as expensive as the expensive one —
the fatigue failure ADR-0027 named as a security property.

**MRTR arrived and changed nothing about who may decide.** MCP 2026-07-28 removed
server-initiated requests and replaced them with Multi Round-Trip Requests (SEP-2322): a server
answers `tools/call` with an `InputRequiredResult` and the client retries. It is
stateless-compatible, and go-sdk v1.7.0 implements both halves. But no client that drives Relay
negotiates 2026-07-28 yet — Claude Code 2.1.234 negotiates `2025-11-25` and refuses a
2026-07-28 server outright. MRTR is buildable and testable but not yet usable.

## Decision

**1. An in-band approval is accepted, and it is a tool call.**

A new MCP tool, `approve_request`, records a decision against a parked request. It takes the
`request_id`, the `plan_hash` it is answering, the approve/deny verdict, an asserted `approver`
identity, and an optional reason. It is an ordinary tool call, so every existing client can make
it, and every client's tool-confirmation UX puts a human in front of it.

This is deliberately *not* elicitation. Delivery envelopes come and go with protocol revisions;
a tool is the one surface every MCP client has had since 2024-11-05.

**2. Attribution stays honest: verified requester, asserted approver.**

Relay cannot verify that a human answered — only that the client says one did. So the decision
is recorded in ADR-0027's attribution triple, using the `Assertions` lane that already exists end
to end (`X-Relay-On-Behalf-Of`, `asserted_on_behalf_of`, `ByOnBehalfOf`):

- `approved_by` — the **verified** Account whose credential made the call.
- `on_behalf_of` — the **asserted** approver identity supplied by the client.
- `channel` — `in-band`, recorded as the fact it is.

An auditor can always separate "a human authenticated to Relay and approved this" from "a
client told us a human approved this". Collapsing that would make the audit trail claim more
than Relay knows.

**3. `ErrMachineSelfDecision` is relaxed for in-band answers carrying an asserted approver —
and only there.**

The domain refuses a self-decision from a machine Account: *"A machine confirming its own
proposal is the same actor answering twice."* That holds when the machine is genuinely
answering, not when it is **relaying** an answer it did not author. The relaxation requires both
facts: the channel is `in-band` **and** an asserted approver is present. A machine
self-decision with no asserted approver stays refused.

**4. Channel strength remains the operator's dial, and out-of-band still means out-of-band.**

`ErrWeakChannel` is unchanged: an in-band decision cannot satisfy a rule requiring
`out-of-band`. Deployments that want the two-person tier configure `channel: "out-of-band"` and
are unaffected. What changes is that `in-band` stops being inert.

**5. The structural guard is narrowed, not removed.**

`no_decision_test.go` still scans both packages and fails on every decision identifier — except
inside the single file implementing this tool. Every other file in `mcp` and `mcptask` stays
guarded, so a second decision path cannot appear by accident, and the whole hole is auditable
by opening one file.

**6. MRTR is the second envelope, later, over the same decision path.**

When a client that drives Relay negotiates 2026-07-28 and implements SEP-2322, Relay may also
return an `InputRequiredResult` carrying the approval elicitation. It must route to the **same**
decision path, with the same attribution and channel semantics. One decision model, two
delivery envelopes — not two mechanisms.

## Consequences

- Rung 2 becomes usable, on today's clients, with no protocol dependency.
- A deployment that wants the old posture changes nothing: leave rules `out-of-band`.
- **The guarantee for `in-band` rules is now explicitly a client-integrity assumption.** A
  compromised or naive client can approve rung-2 requests. This is stated rather than implied,
  and it is why rung 3 exists and why `out-of-band` remains the default for it.
  *(Note, 2026-09-24: no decision in this ADR changes, but the scope of this consequence does.
  [ADR-0040](0040-the-surface-that-created-a-request-answers-it.md) shelves out-of-band as a
  rule requirement for now and settles that an MCP-originated request is answered over MCP. Rung
  3 and its default both stand wherever a rule sets one; no shipped or seeded rule does, so for
  agent-originated work the client-integrity assumption is no longer one posture among several —
  it is the posture. Explicitly interim, pending the permissions rework.)*
  *(Corrected 2026-09-25: ADR-0040's amendment of that date withdrew the answered-over-MCP
  separation. The client-integrity assumption is the **relied-on** posture for agent-originated
  work — MCP is the approved pathway — but not the only one reachable: the Console and the
  Control API still decide any request, not relied on.)*
  *(Amended 2026-10-18 by ADR-0044: the Console no longer decides approvals. The Control API
  decision endpoint is the one out-of-band path still reachable, and still not relied on.)*
- Gleipnir's HIL router becomes load-bearing for in-band rules: ADR-0027's requirement that it
  be *"a deterministic path to the assigned human"* is no longer advice.
- The audit trail gains a class of record whose approver is asserted. Queries that need verified
  approvers must filter on channel.
- The v0.5.0 milestone plan's (then in ROADMAP.md, retired 2026-09-12) "elicitation is the
  primary, first-class channel" is retired; the primary in-band channel is the tool surface.

## Alternatives considered

**Keep out-of-band only.** Rejected: it makes rung 2 unreachable, shrinking the ladder to two
rungs, and drives the approval fatigue ADR-0027 names as a security property.

**MRTR elicitation first.** Spec-native and testable in CI via the SDK's MRTR client, but
unusable from every client that currently drives Relay. Building a surface nothing can call is
the trap v0.5.1 fell into with Tasks; deferred to decision 6.

**Server-initiated `elicitation/create` over SSE.** Works with today's clients, but implements a
pattern 2026-07-28 explicitly removed, and requires abandoning `JSONResponse: true` — a
per-handler option — costing the stateless property for *every* call to serve one rung.
Rejected.

**Treat an in-band answer as a fully verified human decision.** Rejected: the audit trail would
answer "who approved this?" identically whether a human did or a client merely said so.

## Amendment (2026-09-28): an MRTR answer on a human's own OAuth session is that human's verified decision

An owner decision of 2026-09-28, recorded as a note; decisions 2 and 3 keep their text. Decision
2 records every in-band answer as a verified *relaying* Account beside an *asserted* approver,
and decision 3 relaxes the machine self-decision refusal only where an approver is asserted. Both
assume the Account that made the call is not the human who answered. One designed case breaks
that assumption, and for it the owner decided:

**An in-band MRTR answer arriving on an OAuth session of a human Account is that human's own
verified decision.** The verified lane holds the human as the approver, no asserted approver is
needed, and none is written in its place. Today the one client this applies to is Claude Code
(`docs/specs/approval.md` AP-78 and AP-79, designed and not built); on any other session — an
API Token, or a machine Account — Claude Code is not asked at all. This is not the alternative
rejected above: the answer is verified not because a client says a human gave it, but because
the credential that carried it is the human's own, which Relay authenticated.

It stands in tension with ADR-0027's statement that **MCP-originated calls are agent-grade
regardless of whose OAuth identity authorizes the session**. The owner resolved it: the
*request* stays agent-grade — rung selection is unchanged — while the *answer*, given in the
client's own UI which the model never sees, counts as the human's. The caveat is accepted, not
solved: a configured Claude Code **hook** can answer an elicitation with no human present, so a
verified approver here proves who owns the session, not that a human read this question. It
replaces a decision of 2026-09-27, never built, to accept a Claude Code answer as an *unnamed
confirmation* in the asserted lane — which anyone could forge by typing the same string into
`approve_request`. The owner also set a constraint: any unnamed form ever reintroduced is its
own structural field in the decision and audit record, never an asserted string. OAuth has
never run live (#351), so until it does nothing in the shipped posture reaches this case. See
ADR-0027's note of the same date.

## Amendment (2026-09-29): the signed-in identity decides, not the client's name; now built

A further owner decision, recorded as a note; decisions 2 and 3 keep their text, and the
2026-09-28 note stands as the record of that date. The case it describes is now **built**
(`docs/specs/approval.md` AP-78 and AP-79, PR #765), and generalised in one respect: **on a
signed-in human session, the signed-in identity decides, not the client's declared name.** Any
in-band MRTR answer arriving on an OAuth session of a human Account is that human's own verified
decision, whatever the client calls itself. If such an answer also carries an
`io.gleipnir/responder` assertion, the verified human still wins and nothing is written to the
asserted lane. The declared client name decides only whether Relay asks: `gleipnir` wherever the
rule allows, `claude-code` only on such a session.

Review of #765 found that tying the verified form to the `claude-code` name contradicted the
spec twice — the name chose how an answer was recorded, and a `claude-code` answer carrying
Gleipnir's responder key wrote an asserted approver. The trust was always the authenticated
OAuth session's, never the self-reported name's, so tying acceptance to the session fixes both
and weakens nothing. The caveats are unchanged: a Claude Code hook can answer with no human
present, anything holding the human's OAuth token answers as that human, and OAuth has never run
live against a real identity provider (#351). See ADR-0027's note of the same date.

## Amendment (2026-10-18): amended by ADR-0044 — one out-of-band path, the Control API

A note, not a change to any decision here.
[ADR-0044](0044-the-console-does-not-decide-approvals.md) removes the Admin Console's approval
surface and keeps the Control API decision endpoint. Every decision in this ADR stands; the
correction of 2026-09-25 in *Consequences*, which named "the Console and the Control API" as
reachable out-of-band paths, now names the Control API only.
