# Approval is one in-band answer

**Status:** Accepted (owner decision 2026-10-22).

Reasoning and objections: `docs/proposals/approval-answered-in-the-requesting-client.md`.
Behaviour: `docs/specs/approval.md`. This ADR supersedes ADR-0027 decisions 4 (in part), 7 and
12, the second-person rung of decision 5, and decision 6's count, audience, requester exclusion,
channel, audience union, store-backed rules and seeded default; ADR-0010's 2026-09-15 amendment
where it makes gate rules a store-backed, Console-edited setting; ADR-0028, ADR-0040 and ADR-0044 in full, keeping what still holds of the last two as decisions
5 and 9; ADR-0029 decisions 1, 4 and 5; and ADR-0026 decision 7's second-person option.

## Decision

Relay's approval is cut to one answer per request. A gate rule says only which dispatches wait
for a human and how long a parked request lives. One answer releases or denies it. Over MCP that
answer comes only through elicitation: Relay writes the question, the requesting client puts it
to a person, and the answer returns with the retried call. The `approve_request` tool, which let
the AI-agent send a decision itself, is retired. Relay does not decide who is asked; the client
routes the question. Multi-person approval, approver lists, channel requirements and standing
approval windows are cut until each is designed. Gate rules are a section of the Relay's
configuration file, and the package ships one that gates mutations.

## The decisions

1. **A rule gates, and nothing more.** A gate rule names what it matches and how long a parked
   request lives. It names no count, audience, requester exclusion or channel, and a rule that
   names one is refused rather than reinterpreted. The ladder has two rungs: no gate, and
   self-confirmation.
2. **One decision ends a request.** The first decision that clears the remaining refusals
   releases or denies it; a denial is terminal. Those refusals are: the request is pending and
   unexpired, the cited plan hash is the request's, the decider clears the request's role floor,
   and a machine Account deciding its own request does so only through decision 3's form.
3. **Over MCP, the answer is elicited**, under ADR-0029's MRTR decisions, which stand. A machine
   requester's own request may be confirmed by an elicited answer carrying a responder
   assertion, recorded as asserted; that keeps Gleipnir's mutations answerable. Gleipnir is the
   first-party AI-agent system that drives Relay.
4. **`approve_request` is retired**, and so is ADR-0029 decision 5's exception that let its one
   file in the MCP package name a decision identifier. A tool call is the model's own output,
   and harnesses often allow tools without asking, so an approval sent that way can be the
   AI-agent approving itself.
5. **The Control API decision endpoint is the rescue.** It decides any parked request on a
   verified Account, for a client that cannot be asked or a question a restart stranded. It is
   specified, and kept out of the getting-started material. Every decision records the surface
   it came from; no rule demands one surface over another. It stays until a question a restart
   stranded can be answered another way, because it is what makes that risk tolerable (R27).
6. **No approval grants.** Every gated dispatch parks and is answered on its own. An approval
   window needs someone other than its requester to open it, which is multi-person approval, so
   approval grants wait with it.
7. **Gate rules are a section of the Relay configuration file**, read at startup and on every
   successful reload, so whoever administers the Relay's host sets them and nothing on the wire
   can (invariant 11 allows a runtime object; the file is the simpler and stricter choice). The
   package ships a section that gates `mutate` and Raw Exec, so a fresh install is gated.
   Editing rules in the Console, and seeding a store, wait in a proposal.
8. **No MCP task handle, and no shape key.** ADR-0028's shim existed to give a parked request a
   handle; elicitation answers parks, and a client that cannot be asked gets `pending_approval`.
   The shape key existed for a diff shown to approvers, which is a proposal.
9. **The Console decides no approval.** It has no queue, request screen or decide action, and
   renders only what an approval left on another record, such as a Job's approver. A dispatch
   from the Console's execution surface is confirmed by its own step-up apply (ADR-0026), which
   is that dispatch's self-confirmation; nothing asks a second time.

ADR-0027's other decisions stand.

## Why

People answer Relay's approvals through Gleipnir, which already routes a question to the right
person on the right channel, Slack included. Relay holding its own copy of who should answer,
and enforcing quorums and channels that no surface lets a person meet, was machinery with no
workflow behind it: a rule that left those fields out silently demanded a second person on a
path nobody was told to use. What remains is small, and every part of it is reachable.

Elicitation is not proof against a client that controls its own harness. That residual is R21,
narrowed here by removing the tool.

## What changes

- **Cut from code:** the `approve_request` tool; a rule's count, audience, requester exclusion
  and channel; channel-strength checks; approval grants and their API; the MCP Tasks shim; the
  shape key. The separate gate-rule file becomes a section of `relay.toml`.
- **Future work** waits in the private roadmap, under `roadmap: relay/`: more than one approver,
  a Relay-held audience and approval grants; a channel Relay verifies; rules edited in the
  Console; MCP Tasks for long-running Jobs; asking more clients and always-on agents; a diff
  against the last similar approval.
- **Threat model:** R18 and R25 close with the code; R21 and R27 lose `approve_request`.
- **The approval spec** is rewritten in the two-layer shape (ADR-0046) in the same change as
  the code cut, so it never describes a system that does not exist.

## Alternatives

- **Keep the mechanisms, unfeatured.** Enforcement nobody can satisfy is a trap, and dead paths
  in an approval system are what an auditor distrusts first.
- **Keep the tool for clients Relay cannot ask.** Those are the clients with no human-routing
  standard behind them.
- **Make elicitation the only path and drop the Control API.** Not until an MCP answer can name
  a verified approver on every client, which is the identity work (ADR-0041).

## Amendment (2026-10-23): an answer on an API-token session is that session's Account's

Owner decision in the MVP review. The MVP needs Claude Code, ChatGPT and other ordinary clients to
answer approvals without the customer first connecting an identity provider, so decision 3 widens.

- **Any client that advertises elicitation is asked**, not only clients Relay recognises by name
  (ADR-0029's client list). A client that cannot be asked still gets `pending_approval`.
- **An elicited answer on an API-token session is accepted as that session's Account's decision**,
  without the responder assertion decision 3 required. On a human Account's token the human is
  recorded as the decider, marked as a token session, distinct from an OAuth session's verified
  lane. On a machine Account's token the decision is recorded as machine self-confirmation, with
  any responder assertion recorded as asserted, as Gleipnir sends it.
- **A human Account's API token defaults to a short life**, seven days, so an interactive token
  copied into a script stops working on its own.

What this gives up, recorded in the threat model: an AI-agent that can read its session's API
token can call Relay itself and answer its own question as that Account; and a machine Account's
answer proves no person saw the question. The stronger paths wait in the private roadmap: an
approval page the person signs in to, which the AI-agent cannot answer
(`roadmap: relay/approval-by-link`), and OAuth tested against the common identity providers
(`roadmap: relay/oauth-against-common-providers`).
