# Plan is an approved route of execution; Policy preflight is its own capability

**Status:** Superseded by ADR-0049 (2026-10-22).

The Plan is withdrawn unbuilt: sequencing belongs to the harness. The rename of plan mode to Policy
preflight stands, carried by ADR-0049 decision 3.

## What it decided

A Plan would be a Relay-held, ordered route of fixed steps, proposed as one object, answered by
one Approval, and executed and audited as one unit. The no-execution check ADR-0011 had called
plan mode was renamed Policy preflight and made its own capability. This ADR amends ADR-0011,
ADR-0013 and ADR-0027; those amendments stand as renames only. It was amended by ADR-0044.

## Where to read now

ADR-0049 for the decision in force; `docs/specs/policy-preflight.md` for the behaviour. The
design waits in the private roadmap (`roadmap: runtime/plans-in-the-harness`). The full text
of this ADR is in git:
`git show 3694f23:docs/adr/0038-plan-is-an-approved-route-of-execution.md`.
