# Per-Account rate limits on Job creation

**Status:** idea (`2026-10-22`). Origin: #279, which decides the scheduling.

## Problem

The blast cap bounds how many Nodes one call reaches. Nothing bounds how many calls an Account
makes, so a runaway AI-agent loop is bounded in space and not in time.

## Proposal

Throttle Job creation per Account, as a reach-bounding runtime object under invariant 11:
changed by a human with step-up, audited, never part of the security floor. A throttled call
is refused with a reason the agent can read, like every other refusal.

## Changes

`execution.md` (a refusal claim); `accounts-and-access.md`; `relay-configuration.md` for the
default. No ADR unless the limit's shape is a trade-off worth recording.

## Objections

1. **Does a per-Account limit also need a per-fleet one, or is the blast cap that?** — open.
