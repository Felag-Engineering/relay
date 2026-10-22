# Approval is one in-band answer

**Status:** Accepted (owner decision 2026-10-22). Supersedes ADR-0027 decisions 4, 7 and 12 and
the second-person rung of its decision 5; supersedes ADR-0029 decisions 1 and 5 in part.

Reasoning and objections: `docs/proposals/approval-answered-in-the-requesting-client.md`.
Behaviour: `docs/specs/approval.md`.

## Decision

Approval is as simple as it can be and still be honest. A gate rule says only which dispatches
wait for a human and how long a parked request lives. One answer releases or denies it. Over
MCP that answer comes only through elicitation: Relay writes the question, the harness puts it
to a person, and the answer returns on the retried call. The `approve_request` tool, which let
the AI-agent send a decision itself, is retired. Two-person approval, a Relay-held list of who
may approve, out-of-band channel requirements and approval grants are cut from the product and
its code; each waits in a proposal until it is designed. Who to ask is the client's routing.

## The decisions

1. **A rule gates, and nothing more.** A gate rule names what it matches and how long a parked
   request lives. It names no count, no audience, no requester exclusion and no channel; a rule
   file naming any of them is refused at load, by field, so no existing rule changes meaning
   silently. The ladder has two rungs: no gate, and confirmation.
2. **One decision ends a request.** The first decision that clears the remaining refusals
   (pending and unexpired, the cited plan hash, the role floor of the request) releases it or
   denies it. A denial is terminal.
3. **Over MCP, the answer is elicited.** A gated call from a client Relay recognises returns a
   Relay-written question, and the answer rides the retried call (ADR-0029's MRTR decisions,
   unchanged). An answer on a human Account's OAuth session is that human's verified decision;
   elsewhere it carries a responder assertion, recorded as asserted. A machine requester's own
   request may be confirmed this way, which keeps Gleipnir's mutations answerable.
4. **`approve_request` is retired.** A tool call is the model's own output, and harnesses often
   allow tools without asking, so an approval sent that way can be the AI-agent approving
   itself. A client Relay does not ask gets `pending_approval`.
5. **The Control API decision endpoint is the recovery path.** It decides any parked request on
   a verified Account, for a client that cannot be asked or a question stranded by a restart.
   It is specified and kept out of the getting-started material. Its decisions record the
   surface they came from, as every decision does; no rule demands one surface over another.
6. **No approval grants.** Every gated dispatch parks and is answered on its own. A window
   needs someone other than its requester to open it, which is n-party approval, so grants
   wait with it.
7. **Unchanged:** the gate's position before dispatch, the Relay-written content, the plan-hash
   binding and re-park on drift, expiry, one approval releasing one Job, the two attribution
   lanes, first-class audit records, and the webhook as an unfeatured best-effort notice (R43).

## Why

The product's users answer approvals through Gleipnir, which already routes a question to the
right person and the right channel, including Slack. Relay holding a second copy of who should
answer, and enforcing quorums and channels no surface lets a human meet, was machinery with no
workflow behind it: a rule that left those fields out silently demanded a second person on a
path nobody was told to use. Cutting it leaves a small mechanism whose every part is reachable.

Elicitation is not proof against everything. A client that controls the harness, or holds a
stolen machine credential, can declare itself Gleipnir and answer its own question; only an
answer on a human's own OAuth session names a verified approver. That residual is R21, narrowed
here by removing the tool, the likeliest way a prompt-injected model approves its own work.

## What changes

- **Cut from code:** the `approve_request` tool; a rule's count, audience, requester exclusion
  and channel; channel-strength checks; approval grants and their API.
- **Proposals:** `n-party-approval.md` (more than one approver, a Relay-held audience, grants, a
  Slack approval with two presses) and `out-of-band-approval.md` (a channel requirement Relay
  verifies, and the shelved assurance in `approval-assurance.md`).
- **Threat model:** R18 (audience union) and R25 (grant bounds) close with the code; R21 loses
  its `approve_request` half and its "raise the rule to out-of-band" mitigation; R27 loses the
  `approve_request` workaround.
- **Docs:** the README tool table, the approval and demo-fleet runbooks, the glossary, `plan.md`,
  `how-relay-works.md`, and the test fleet's gate rules.

## Alternatives

- **Keep the mechanisms, unfeatured.** Enforcement nobody can satisfy is a trap, and dead paths
  in an approval system are what an auditor distrusts first.
- **Keep the tool for clients Relay cannot ask.** Those are the clients with no human-routing
  standard behind them.
- **Make elicitation the only path permanently, and drop the Control API.** Deferred to the
  identity work (ADR-0041): a verified approver over MCP does not exist yet in the shipped
  posture, which ADR-0044 named as the condition.
