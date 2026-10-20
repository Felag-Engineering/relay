# Domain Docs

How agent skills should consume this repo's domain documentation when exploring the codebase.

## Before exploring, read these

- **`AGENTS.md`**: how to work here, and the fourteen architecture invariants. Each names
  the ADR that governs it; use them as the index into `docs/adr/`.
- **`GLOSSARY.md`**: the canonical glossary. This is a single-context repo; there is no
  `CONTEXT-MAP.md` and there should not be one.
- **`docs/specs/<capability>.md`**: the capability specification for your area, if one
  exists: what it does today, across every surface. Absence means unwritten, not undefined.
- **`docs/adr/`**: the ADRs that touch your area, the record of *why*.

These files always exist here and are load-bearing. Their absence is a bug, not a signal to
proceed silently.

## Use the glossary's vocabulary

Most `GLOSSARY.md` terms carry an `_Avoid_` line of rejected synonyms. Use the canonical term
in code, comments, commits, issue titles, test names and prose. The load-bearing ones:

- **relay-daemon**, never "agent". The daemon is not an AI.
- **AI-agent** is the only thing called "agent", and always qualified.
- **Relay**, never "hub", "master", or "server".
- Internal identifiers say `Relay`/`RELAY_`, never "gleipnir" (ADR-0016).

If the concept you need isn't in the glossary, either you're inventing language the project
doesn't use (reconsider), or there's a real gap, which is added to `GLOSSARY.md` **in the same
change** that introduces the term.

## ADR conflicts are a hard stop, not a flag

Elsewhere, contradicting an ADR means surfacing it and proceeding. Not here: the invariants
in `AGENTS.md` govern remote code execution on a customer's fleet. If your output would
violate one (Policy evaluation, the execution path, transport, mTLS, auth, the `/proto`
contract, blast-radius caps, label authority), **stop and escalate to a human.** It needs a new
ADR, not a workaround.

State the conflict plainly:

> _This requires the Relay to evaluate Policy locally, which ADR-0011 forbids (Policy is
> evaluated only by the daemon's live engine). Escalating rather than proceeding._

For everything outside that surface, normal engineering judgement applies.

## Writing an ADR

When to write one, and the style to match: `AGENTS.md`, *How to work here*, step 7.
