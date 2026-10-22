# Expectations: scheduled read-class health checks

**Status:** idea (`2026-10-22`). Origin: the ADR-0008 notes; fits after v0.9.0 and v1.1.0.

## Problem

Relay only acts when asked. An operator who wants to know that a Service is still healthy has
to ask an AI-agent to look, every time, or run a second tool.

## Proposal

Advisory, scheduled *read-class* checks. A finding may *propose* a remediation Job routed
through the approval mechanism; nothing auto-executes (ADR-0008, invariant 9). The scheduler
can construct read-class dispatches only, enforced by type, so no schedule can ever carry a
mutate.

## Changes

`system-model.md` and `execution.md`; ADR-0008 and ADR-0012 (risk classes); the scheduler is
a new reach-bounding runtime object under invariant 11.

## Objections

1. **A scheduler that proposes remediation is one approval away from desired-state
   reconciliation, which is out of realm.** — The line is that a finding never becomes a Job
   without a human's approval, and the scheduler's dispatch type cannot express a mutate. Open
   until the type-level enforcement is designed.
