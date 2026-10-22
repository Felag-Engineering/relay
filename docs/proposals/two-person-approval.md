# Two-person approval, answered where the approvers already are

**Status:** idea (`2026-10-22`). Origin: owner review of the approval path
(`approval-answered-in-the-requesting-client.md`, objection 8).

## Problem

Some work should need two people to say yes. Over MCP that cannot be done honestly: the
requester and the would-be second approver arrive as the same Account, and the only answer
Relay verifies is a human on their own OAuth session. Today the mechanism exists (a rule's
`count: 2` and a requester-excluding audience), but the only surface that can satisfy it is
the Control API, which no approver is expected to use.

## Proposal

Two-person approval is not supported today and is not featured. The intended shape is an
approval posted where the approvers already work, such as a Slack message with Approve and Deny
buttons, that releases the request once two people from the rule's audience have pressed
Approve. How that is built needs a design. The constraints it must meet:

- **Each press is a verified person.** A button press only counts if Relay can tie it to one
  of its own Accounts: a chat identity mapped to a Relay Account, never a display name.
- **Relay never holds the chat credential.** ADR-0027 rejected Relay pushing to Slack because
  of the routing and credential burden. A bridge that receives the webhook, posts the message,
  and turns each press into a per-person Control API decision keeps that burden outside Relay,
  and keeps the decision on Relay's existing decision path.
- **The message is Relay's words.** It shows the Relay-authored summary and is bound to the
  plan hash, so the second approver approves exactly what the first saw.
- **Distinct people, both in the audience,** and the requester never one of them.

## Changes

`approval.md` (the quorum and audience claims, and what a decider is shown); ADR-0027
(decisions 2 and 7, and its Slack alternative); the webhook payload; the threat model, for a
new decider surface. Likely a new ADR for the bridge.

## Objections

1. **A Slack workspace's identities are not Relay's.** How is a Slack user mapped to a Relay
   Account, and who may change the mapping? — open.
2. **A bridge holds a credential that can post decisions.** If it decides as one service
   Account, two presses become one verified approver and the quorum is fiction. — open; each
   press must decide as its own person.
3. **Does this reopen ADR-0027's rejection of chat integrations?** — Only if Relay itself talks
   to Slack. A bridge outside Relay does not. — open.
