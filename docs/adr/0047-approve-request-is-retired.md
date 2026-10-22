# The `approve_request` tool is retired

**Status:** Accepted (owner decision 2026-10-22). Supersedes ADR-0029 decisions 1 and 5 in part.

Reasoning and objections: `docs/proposals/approval-answered-in-the-requesting-client.md`.

## Decision

An approval may never be something the AI-agent can send. The `approve_request` MCP tool lets
the model compose a decision, choose approve or deny, and type the approver's name, with only
the harness's tool-confirmation prompt in the way, so it is retired. Over MCP, a parked request
is answered only through elicitation: Relay writes the question, the harness puts it to a
person, and the answer returns on the retried call. The Control API decision endpoint stays as
the recovery path and is unchanged. Nothing else about how approval is gated, bound, expired or
recorded changes.

## Why

Elicitation and the tool differ in who holds the answer. An elicited question is answered in
the client's own interface, which the model is not meant to see; a tool call is the model's own
output. A prompt-injected model inside an honest harness can call a tool, and harnesses are
often set to allow tools without asking. It cannot answer an elicited question. Removing the
tool closes the likeliest way an AI-agent approves its own work.

It does not close every way. A client that controls the harness, or holds a stolen machine
credential, can declare itself Gleipnir, receive the question and answer it with a self-reported
responder; only an answer on a human's own OAuth session names a verified approver. That residual
is threat-model R21, which this ADR narrows and does not remove. Gleipnir relies on elicitation
and never called the tool.

## What changes

- **ADR-0029.** Decision 1 (an in-band approval is a tool call) is withdrawn, and so is decision
  5's exception that let one file in the MCP package name a decision identifier for the tool.
  Its MRTR decisions stand. Its decision 3 stands for elicitation: an in-band answer carrying an
  asserted responder is accepted as self-confirmation for a machine requester, so Gleipnir's own
  mutations remain answerable under the seeded default.
- **Clients Relay does not ask** (any client other than Gleipnir, and Claude Code on an API token)
  get `pending_approval` and have no in-band answer. The Control API is their path.
- **R27**, a restart stranding an in-flight elicitation, loses the `approve_request` workaround;
  the Control API is the remaining one.
- **`approval.md`** retires AP-15 and `approve_request`'s clause in AP-70; the README, the
  approval and demo-fleet runbooks, the glossary and `plan.md` stop naming the tool.

## Alternatives

- **Keep the tool, behind a rule flag.** A path that exists gets used, and the flag would be set
  wherever elicitation is inconvenient, which is wherever the protection matters.
- **Keep the tool for clients Relay cannot ask.** Those clients are exactly the ones with no
  human-routing standard behind them.
- **Make elicitation the only path, permanently, and shelve out-of-band now.** Deferred: it
  re-argues ADR-0040 and ADR-0044 before a verified approver exists over MCP, which belongs with
  the identity work (ADR-0041).
