# The Console does not decide approvals; the Control API is the out-of-band path

**Status:** Superseded by ADR-0047 (2026-10-22).

What still holds, that the Console decides no approval and a Console dispatch is confirmed by
its step-up apply, is ADR-0047 decision 9; the Control API endpoint is ADR-0047 decision 5.

## What it decided

The Admin Console lost its approval surface: the Approvals queue, the approval request screen
and the approve and deny action, by owner decision on 2026-10-18. The Control API decision
endpoint was kept as the one out-of-band path. This ADR amends ADR-0026, ADR-0029, ADR-0038 and
ADR-0040.

## Where to read now

ADR-0047 for the decision in force; `docs/specs/approval.md` for the behaviour. The full text
of this ADR is in git:
`git show 3694f23:docs/adr/0044-the-console-does-not-decide-approvals.md`.
