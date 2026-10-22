# Approval is answered in the requesting client

**Status:** shaping (`2026-10-22`). Origin: owner review of the ADR-0027 rewrite (#1138).

## Problem

ADR-0027's thesis is "notify via MCP, decide out-of-band": the guarantee never depends on the
AI-agent's own session. In practice the approval path in use is elicitation, the MCP question
the harness puts to a human. ADR-0040 already calls MCP the approved path, but only as an
interim posture. Meanwhile `approve_request` lets the AI-agent itself send a decision with an
approver name it typed, gated only by the harness's tool-confirmation prompt.

## Proposal

An approval is answered by a human, in the requesting client, through MCP elicitation: Relay
writes the question, the harness routes it to a person and never to the model, and the answer
returns on the retried call. That is the product's approval path, permanently. The
`approve_request` tool is retired: an approval the AI-agent can send is not an approval. The
Control API decision endpoint stays, built and specified, as the recovery path for an operator
who reaches Relay directly; the getting-started material does not feature it. Out-of-band as a
rule requirement, the second-person out-of-band default and the out-of-band floor on grant
issuance leave ADR-0027 and become future work.

## Changes

- **ADR-0027** is superseded in its channel decisions (2 and 4, and the out-of-band half of 12)
  by a new ADR; its title thesis no longer holds. Gate position, plan-hash binding, expiry,
  quorum, attribution lanes and grants are unchanged.
- **ADR-0029** decision 1, the `approve_request` tool, is withdrawn. Its MRTR decisions stand.
- **ADR-0040** stops being interim: the surface that created a request answers it, as policy.
- **`approval.md`**: AP-15 and AP-70's `approve_request` clause retire; AP-14's default channel
  for a rule that names none becomes `in-band`, since elicitation can never meet `out-of-band`.
  `approval-assurance.md` keeps the shelved out-of-band material.
- **Threat model**: R21 (an in-band approval is only as honest as the client) becomes the
  permanent accepted risk of the approval path, and loses its `approve_request` half.
- **Docs**: the README tool table, `approval-gates.md`, `demo-fleet.md`, `dev-fleet.md`.
- **Invariant 11** names "the approval notification path" as security floor; see objection 4.

## Objections

1. **Retire `approve_request`?** — Yes. A tool-call approval is insecure: the model composes
   the call, picks the verdict and types the approver. Owner ruling 2026-10-22.
2. **What do clients Relay does not ask lose?** Any client but Gleipnir, and Claude Code on an
   API token, gets `pending_approval` and has no in-band answer. — Accepted: the Control API is
   their recovery path. Owner ruling 2026-10-22.
3. **Is the Control API endpoint hidden?** — No. It is specified like every surface, because an
   undocumented path that decides approvals is what an auditor finds and distrusts. It is the
   documented recovery path, absent from the getting-started material. Owner ruling 2026-10-22.
4. **The webhook.** Invariant 11 makes its URL, secret and timeout security floor. Keep it as a
   best-effort notice, or retire it and amend the invariant's wording? — Keep it, unfeatured:
   specified, absent from the getting-started material, no invariant change. Its payload
   carries Operation arguments to whatever endpoint root configures, and signing is optional;
   neither is in the threat model's register yet, and both should be. Owner ruling 2026-10-22.
5. **Does Gleipnir call `approve_request` anywhere?** — No: Gleipnir relies on elicitation.
   Owner ruling 2026-10-22.

Grill, 2026-10-22 (`proposal-grill`); open until the owner answers.

6. **Elicitation is not stronger than the tool against a fully compromised orchestrator.** A
   client that declares `gleipnir` is asked anywhere, and its responder assertion is a
   self-report of the same strength as `approve_request`'s approver. Retiring the tool removes
   a prompt-injected model inside an honest harness, not a harness the attacker controls. Only
   an answer on a human's OAuth session names a verified approver. — open.
7. **Machine self-confirmation.** The seeded default works for Gleipnir only through ADR-0029's
   relaxation, an in-band answer with an asserted approver counted as self-confirmation. Keep
   it for elicitation, or drop it and send every seeded mutation to rung 3? — open.
8. **Second-person, `count: 2` and grants cannot be answered over MCP.** The requester and the
   second person arrive as one Account, and a grant has no tool call to elicit on. All of them
   land on the Control API, which then carries far more than recovery. — open.
9. **Flipping AP-14's default to `in-band`** silently weakens rules operators already wrote,
   with no human act or audit; the flip is not needed, since out-of-band is met on the Control
   API. — open; recommendation: drop it.
10. **Prior rejections.** ADR-0044 rejected MCP as the only path until R27 is closed and a
    verified approver exists over MCP; ADR-0040 calls itself interim pending the permissions
    rework (ADR-0041). Declaring the posture permanent re-argues both. — open.
11. **Scope.** This is three decisions: retire the tool, make ADR-0040 permanent, shelve
    out-of-band. The smaller alternative is the first alone, by an ADR-0029 amendment. — open.
12. **Unnamed consumers:** ADR-0026, 0028, 0044; R25, R26, R27; `GLOSSARY.md`, `plan.md`,
    `how-relay-works.md`, `approval-assurance.md`, `approval-gates.md`, the test fleet's gate
    rules, `STATUS.md`.

