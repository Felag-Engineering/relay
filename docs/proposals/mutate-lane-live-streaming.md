# Live streaming on the mutate lane

**Status:** idea (`2026-10-22`). Origin: the ADR-0004 caveat; read-lane streaming is
milestone v0.9.0.

## Problem

A long-running mutate reports nothing until it finishes. The read lane will stream output
live under v0.9.0; the mutate lane will not, so the Operations whose progress an operator most
wants to watch are the ones they cannot.

## Proposal

Extend live streaming to the mutate lane once the read lane has proven the mechanism, keeping
at-most-once delivery (invariant 4) and the dedup markers intact: a lost stream must never
re-execute a mutate, which #392 records as the open hazard today.

## Changes

`execution.md` and `audit-and-read-lane.md`; ADR-0004.

## Objections

1. **A reconnect mid-stream on a mutate is exactly the #392 re-execution hazard.** — open;
   this proposal does not start until #392 is closed.
