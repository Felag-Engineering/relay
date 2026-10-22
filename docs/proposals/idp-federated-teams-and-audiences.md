# IdP-federated teams and approval audiences

**Status:** shaping (`2026-10-22`). Origin: the approval audience work; direction settled in
ADR-0041 (Proposed).

## Problem

Approval audiences and `on_behalf_of` attribution need to name groups of people, and Relay
has no notion of a team. Growing a native org chart inside Relay would duplicate the
customer's identity provider and drift from it.

## Proposal

Resolve audiences and `on_behalf_of` from OIDC group claims. Gleipnir is the directory and
Relay pulls a signed copy; a team is a grouping of principals; the approver's own identity
reaches Relay verified rather than asserted. Relay never grows an org chart of its own. Not
started before the demo; no milestone yet.

## Changes

`accounts-and-access.md` and `approval.md`; ADR-0027 (approval) and ADR-0041, which becomes
Accepted when the milestone opens; the OAuth mapping in ADR-0010.

## Objections

1. **A signed copy of the directory is a credential-shaped input; does it fall under the
   security floor (invariant 11)?** — The copy is data the Relay reads; the key that verifies
   it is floor. Recorded in ADR-0041.
2. **What happens to an open approval when its audience's group membership changes?** — open.
