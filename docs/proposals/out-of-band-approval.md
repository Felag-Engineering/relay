# Out-of-band approval: evidence instead of an assertion

**Status:** idea (`2026-10-22`). Origin: shelved by ADR-0040, cut from the product by ADR-0047.

## Problem

An in-band answer is only as honest as the client that carries it: Relay cannot tell a person's
answer from a harness that answered by itself (threat-model R21). A customer who needs evidence
that a named human approved, not a client's word for it, has no rule they can write today.

## Proposal

A gate rule may demand that its answer arrive on a channel Relay verifies, on a credential the
requesting session does not hold, and be satisfied by nothing weaker. ADR-0047 cut the channel
field and its enforcement because no surface lets an approver meet it in practice: the Control
API endpoint exists, but nothing routes a human there. A design has to supply that route first,
most likely together with n-party approval's chat bridge, where each press is a verified person.

The full argument, the properties it would restore and what would bring each back are in
`docs/specs/approval-assurance.md`, which this proposal absorbs when the design starts.

## Changes

`approval.md` (a channel claim and its refusal return); a new ADR superseding ADR-0047 decision 1
in part; the threat model's R21, which would regain the mitigation ADR-0047 removed.

## Objections

1. **An out-of-band requirement nobody can reach is a trap, which is why it was cut.** — Agreed;
   it returns only with a reachable route. Owner ruling 2026-10-22.
2. **Does a verified OAuth answer in the client already give the evidence?** It names who owns
   the session, not that they read the question. — open.
