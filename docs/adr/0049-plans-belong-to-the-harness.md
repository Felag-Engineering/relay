# Plans belong to the harness, not Relay

**Status:** Accepted (owner decision 2026-10-22).

This ADR supersedes ADR-0038 in full. It keeps the one part of it that is built: the name Policy
preflight. Behaviour: `docs/specs/policy-preflight.md` and `docs/specs/execution.md`. The
reasoning, and ADR-0038's design as the harness's starting point, wait in the private roadmap
(`roadmap: runtime/plans-in-the-harness`).

## Decision

Relay runs one dispatch at a time and has no notion of a multi-step plan. Sequencing several
actions, deciding what comes next, and showing a person the whole route first are the harness's
job, because the harness can combine Relay actions with others, branch on what it sees, and talk
to the person directly. Every step it takes reaches Relay as an ordinary dispatch, meeting the
Selector, authorization, the blast cap, the gate and each Node's Policy on its own. The Plan
capability ADR-0038 designed, never built, is withdrawn. Its renaming of plan mode to Policy
preflight stands.

## The decisions

1. **No Plan, no step cursor, no route on the Relay.** Relay stores no ordered list of steps and
   offers no tool, route or screen to propose, approve or advance one. A Job stays one dispatch of
   one Operation or Raw Exec, and `Stage` keeps its reserved meaning for batches within one Job.
2. **The harness sequences.** It proposes the steps, shows the person the route, and issues each
   step as a dispatch. Relay cannot tell that two dispatches belong to one route, and enforces
   nothing about their order: each is decided alone.
3. **Policy preflight keeps its name and every ADR-0011 decision.** It is the no-execution
   preview of one dispatch: the daemon's live engine answers a hypothetical, an offline Node is
   `unknown(offline)`, and a preflight reports guardrails rather than failing on them. "Plan mode"
   and "dry run" stay refused names for it.
4. **A plan hash addresses one dispatch.** The approval of a gated dispatch binds to the hash of
   that dispatch's rendered preflight, its Operation, arguments and resolved fan-out (ADR-0027
   decision 8). The term no longer has a multi-step reading.

## Why

A route held by Relay, with a payload-free cursor, was the strongest way to make an approved
sequence the sequence that runs. It was also a second execution model inside Relay, with its own
storage, lifecycle, half-finished state and Console screens, built for a harness that is better
placed to plan: it sees the whole task, including the parts Relay never touches. Relay's job is
to make each action safe; the harness's is to choose the actions.

## What changes

- `docs/specs/plan.md` is removed; its design waits in the roadmap. `execution.md`,
  `policy-preflight.md`, `approval.md`, `freeze.md` and `quarantine-node.md` stop citing it.
- `GLOSSARY.md`: *Plan* is retired as a Relay term; *Policy preflight* and *Plan hash* are
  reworded for one dispatch.
- The threat model: R14, nothing evaluates a sequence as a whole, now describes the harness's
  routes; the jailbroken-agent narrative no longer points at a Relay Plan.
- ADR-0038 carries a note pointing here.

## Alternatives

- **Build ADR-0038's Plan.** Strongest enforcement of an approved route, at the cost of a second
  execution model in Relay for work the harness plans better.
- **Keep a thin route on the Relay for audit only.** A grouping field on each dispatch, recorded as
  an assertion, gives an auditor the grouping without Relay owning the route; it waits in the
  roadmap proposal if it is wanted.
