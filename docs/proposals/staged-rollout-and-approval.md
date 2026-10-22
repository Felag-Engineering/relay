# Staged rollout with an approval gate between stages

**Status:** idea (`2026-10-22`). Origin: the Job schema's Stages and the approval-requirement
schema, which already anticipate it; ADR-0038 names it as a different axis from a Plan.

## Problem

A mutate across a large Selector is all-or-nothing within the blast cap. An operator who wants
to touch a canary first, look, and then continue has to issue two dispatches and carry the
judgement between them by hand.

## Proposal

A rollout spec on a Job: a canary stage, then a gate of `all-success` or `manual-approval`
reusing the approval mechanism, then the remainder, executed and audited as one Job. The
rollout ADR is written before 1.0; execution may land after it.

## Changes

`execution.md` and `plan.md` (a Stage is an axis a Plan's steps compose with, not a step);
`approval.md` for the gate; ADR-0004 (the Job model) and ADR-0027 (approval) amended or
superseded by the rollout ADR.

## Objections

1. **Is a staged Job still one Job under the blast cap, or does the cap apply per stage?** —
   open.
2. **Does `all-success` as a gate reintroduce desired-state reconciliation by the back door
   (invariant 9)?** — open; the gate must only continue a Job the human already issued, never
   re-plan one.
