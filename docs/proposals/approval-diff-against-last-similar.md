# Show the approver a diff against the last similar approval

**Status:** idea (`2026-10-22`). Origin: ADR-0027 decision 12, left open when batch and window
approvals were built (#378).

## Problem

An approver asked the fortieth time about the same kind of work stops reading and approves.
Batch and window grants cut the number of questions; they do not make each question easier to
judge, and a rubber-stamped approval manufactures evidence of consideration that never happened.

## Proposal

Each approval question carries a Relay-authored diff against the last approved action of the
same shape: "same as Tuesday, except fan-out grew from 3 to 12". It changes what an approver is
shown, never what an approval covers or how it is decided.

Finding "the last approved action of the same shape" needs an address for *what* an approval is
for that leaves out the fan-out, so it is stable across runs. Relay built one, the shape key, and
ADR-0047 cut it because nothing used it; the code is in git history. It must never authorize or
release anything: only a matching plan hash does.

## Changes

`approval.md` (what a decider is given, and the shape key's return); the shared rendering
contract in ADR-0027 decision 8,
which every rendering of a request must keep. No ADR change unless "similar" needs a decision.

## Objections

1. **What counts as similar, and can a requester shape a request to match an innocuous
   predecessor?** — open.
