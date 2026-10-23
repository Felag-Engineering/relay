# The fleet model is split: facts in Relay, beliefs in the agent

**Status:** Accepted (owner decision 2026-10-23).

This ADR supersedes ADR-0008 in full and amends AGENTS.md invariant 9. The later work waits in the
private roadmap: `roadmap: relay/fleet-topology` and `roadmap: runtime/fleet-memory`.

## Decision

ADR-0008's System Model, a shared map of the fleet any AI-agent could rewrite, is withdrawn
unbuilt, and nothing replaces it in the MVP. It held three kinds of knowledge that belong in
different places. What the daemons observe, such as which Node talks to which and what each one
serves, and what people declare about it, such as "primary" or "critical", are Relay's to keep
later. What an AI-agent believes, such as "restarting X fixed Y last week", is that agent's
memory. Whatever Relay keeps, it stays advisory and never becomes a desired state.

## The decisions

1. **No System Model in the MVP.** No Services, Dependencies or Annotations, no model tools or
   resources, no git-backed file. `docs/specs/system-model.md` is removed.
2. **Observed topology and declared meaning are Relay's, later.** Facts reported by daemons
   through read Operations, under Policy and audit, and meaning written by people through the
   capability layer. Designed in the roadmap, not here.
3. **An AI-agent's beliefs are agent memory**, kept by the harness, never a store every Relay
   consumer reads as fact. One agent's guess must never become the next agent's ground truth.
4. **Invariant 9 is a constraint on any fleet model Relay keeps.** Where Relay keeps one, it is
   advisory and never a desired-state spec: Relay never reconciles. What Relay observed is
   always distinguishable from what anyone wrote. No AI-agent writes its grounding facts: Nodes,
   their identity and `relay:` labels. It never bypasses Selectors, Policy or the blast cap.

## Why

ADR-0008 let any AI-agent rewrite a map every other AI-agent trusted, which made it a route for
one compromised session to steer the next. The parts worth sharing are facts Relay can observe
first-hand and meaning people write; the rest is reasoning, which the agent keeps better. Nothing
was built, so withdrawing it costs only documents.

## What changes

- AGENTS.md invariant 9 is reworded as decision 4; its number is kept.
- `GLOSSARY.md`: *System Model*, *Service*, *Dependency* and *Annotation* are retired.
- The threat model's invariant map and the specs that cited ADR-0008 follow.

## Alternatives

- **Move it all to Gleipnir.** Loses the facts only Relay's daemons can observe, and a shared,
  audited record every consumer sees.
- **Keep ADR-0008.** A shared AI-writable map is the poisoning route this ADR exists to close.
