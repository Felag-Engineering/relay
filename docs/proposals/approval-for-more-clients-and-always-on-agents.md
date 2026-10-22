# Approval for more clients, and for always-on agents

**Status:** idea (`2026-10-22`). Origin: owner review of the approval spec's client list
(`approval.md` AP-78).

## Problem

Relay asks an approval question only of clients it recognises by name: Gleipnir on any session,
and Claude Code on a human's OAuth session. Every other client gets `pending_approval` and has
no way to answer except the Control API. Codex, the ChatGPT desktop app and the new always-on
agents, such as Claude Duet and OpenAI Dots, act while nobody watches the screen, so a question
has to find a person somewhere else, later.

## Proposal

Two pieces of work, researched before anything is built.

1. **Interactive clients.** Replace "recognised by name" with a test a client must pass before
   Relay asks it: it speaks the 2026-07-28 MCP revision's MRTR round trip; its question is shown
   to a person and never to the model; and, ideally, the person answers on their own OAuth
   session, which makes the answer verified rather than asserted (AP-79). Codex and the ChatGPT
   desktop app are the first candidates. A client's declared name stays self-reported, so the
   test decides which names Relay asks, never how an answer is accepted.
2. **Always-on agents.** Work out how a question reaches a person when the agent runs in the
   background: whether these agents carry MCP elicitation to the person at all, whether a phone
   notification or a Slack message is the channel, and what Relay must change for an answer that
   arrives hours later. Expiry (four hours by default), a restart stranding a question (R27) and
   the webhook (R43) all matter here; so do `n-party-approval.md` and `out-of-band-approval.md`,
   which may turn out to be the same design.

## Research so far (2026-10-22)

- **Codex.** Earlier releases advertised elicitation and declined every request
  (openai/codex#6992). A change enabling elicitation for custom MCP servers merged in April 2026
  (openai/codex#17043); which release ships it is unconfirmed.
- **ChatGPT desktop.** Supports remote MCP servers over streamable HTTP. No source confirms or
  denies elicitation; MCPJam keeps a per-client support matrix worth checking.
- **MRTR.** Final in the 2026-07-28 revision (SEP-2322). The official Go and C# SDKs implement the
  client side, retrying the call with the answer.
- **Claude Duet.** Research preview from 2026-10-21; asks a human before sending messages,
  payments, signatures and deletions. No source shows MCP in its approval flow.
- **OpenAI Dots.** Announced 2026-09-29 as an always-on assistant inside Slack and Teams. No
  approval-policy details found.

## Changes

`approval.md` (AP-78's client list becomes a test; perhaps a claim for late answers); ADR-0029
(which clients are asked); the threat model (R21, R27, R43); likely an ADR if always-on agents
need a channel other than the requesting client.

## Objections

1. **A test that a client hides the question from its model cannot be run by Relay at call time;
   it is a release-by-release judgement.** Who makes it, and how often is it rechecked? — open.
2. **An always-on agent's "human" may be a policy, not a person.** Duet asks before some actions
   and blocks others outright. Does an answer from such a policy count as a human decision? — open.
