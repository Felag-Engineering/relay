# N-party approval, answered where the approvers already are

**Status:** idea (`2026-10-22`). Origin: owner review of the approval path; cut from the
product by ADR-0047.

## Problem

Some work should need more than one person to say yes, from a set of people Relay can name.
Relay has no honest way to do that today: over MCP the requester and any second approver arrive
as one Account, and the only other route is a Control API call nobody is told to make. ADR-0047
cut the count, the audience, the requester exclusion and approval grants for that reason.

## Proposal

Design n-party approval end to end before building any of it. The intended shape is an approval
posted where the approvers already work, such as a Slack message with Approve and Deny buttons,
that releases the request once enough people from a named audience have pressed Approve.
Constraints a design must meet:

- **Each press is a verified person**, tied to one of Relay's own Accounts, never a display name.
- **Relay never holds the chat credential.** ADR-0027 rejected Relay pushing to Slack for its
  credential burden. A bridge receiving the webhook can post the message and turn each press
  into a per-person decision on Relay's own decision path.
- **The message is Relay's words**, bound to the plan hash, so every approver approves what the
  first one saw.
- **Distinct people from the audience, never the requester.** Gleipnir already routes by
  audience and channel; whether Relay holds its own audience, or verifies Gleipnir's, is the
  first decision, and the owner's direction is that Relay states who may approve and refuses an
  answer from anyone else, the guiding human and the AI-agent included.
- **Approval grants come back with it.** A window someone other than its requester opens is an
  n-party approval of a Scope.

## Changes

`approval.md` (quorum, audience and grant claims); ADR-0027's decisions 7 and 12 return in a new
ADR; the webhook payload; the threat model, for a new decider surface; likely an ADR for the
bridge.

## Objections

1. **A chat workspace's identities are not Relay's.** How is a Slack user mapped to a Relay
   Account, and who may change the mapping? — open.
2. **A bridge that decides as one service Account makes the quorum fiction.** — open; each press
   must decide as its own person.
3. **Does this reopen ADR-0027's rejection of chat integrations?** — Only if Relay itself talks
   to Slack; a bridge outside Relay does not. — open.
