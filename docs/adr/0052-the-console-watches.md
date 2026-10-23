# The Console watches; it does not run commands

**Status:** Accepted (owner decision 2026-10-23).

This ADR supersedes in part ADR-0026, where the Console gains an execution surface behind the
root-owned `console_execution` flag, and amends AGENTS.md invariants 10 and 11. The later idea
waits in the private roadmap: `roadmap: relay/console-execution-for-skills`.

## Decision

The Admin Console shows the fleet, Jobs, results, approvals' records and the audit trail, and
administers Accounts, tokens, tags and Policy aliases. It runs no command on any Node. People
run commands through their AI-agent client over MCP, or through the Control API. The dormant
execution gate and the placeholder run page are deleted, so no code an auditor finds asks what
turns it on. If the Console ever executes, it is to test skills people write for the AI-agent,
and that is a new decision.

## The decisions

1. **No Console route dispatches.** The Console has no composer, preview or apply, and the
   structural `no_dispatch` guard covers it like every adapter.
2. **The `console_execution` flag and the `/console/run` placeholder are deleted.** They gated a
   surface that was never built; ADR-0026's design waits in the roadmap.
3. **Invariant 10 keeps its constraint.** Where the Console executes, it does so with preflight
   by default, step-up re-authentication on a `mutate` apply, role gating by the capability
   layer, and behind a host-set switch. The flag's name leaves the invariant.
4. **Invariant 11's security floor drops `console_execution`.** If Console execution returns, its
   host-set switch returns to the floor with it.

## Why

A surface that is built, tested and switched off is the first thing an auditor asks about, and
it carried a second session-based path to the fleet with its own CSRF and step-up surface. The
AI-agent clients already execute, with approval answered in-band.

## What changes

- AGENTS.md invariants 10 and 11 as decisions 3 and 4; the gap row for invariant 10 closes when
  the code lands.
- `execution.md`, `accounts-and-access.md` and the Console's design pages stop describing Console
  execution; the threat model's Console rows follow.

## Alternatives

- **Keep the dormant gate.** No work now; the invariants keep describing a switch nothing can set.
- **Build Console execution for the MVP.** Large, and the AI-agent clients already cover it.
