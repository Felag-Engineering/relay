# Domain Docs

How agent skills should consume this repo's domain documentation when exploring the codebase.

## Before exploring, read these

- **`AGENTS.md`** at the repo root — how to work here, plus the fourteen architecture
  invariants. Each invariant names the ADR that governs it; use the list as the index into
  `docs/adr/`, which is faster than reading every ADR.
- **`GLOSSARY.md`** at the repo root — the canonical glossary. Single-context repo; there is
  no `CONTEXT-MAP.md` and there should not be one.
- **`docs/specs/<capability>.md`** — the capability specification for the area you're working
  in, if one exists: what that capability does today, across every surface. Durable and
  canonical for behaviour. It does not yet cover every capability; absence means unwritten,
  not undefined.
- **`docs/adr/`** — read the ADRs that touch the area you're about to work in. They are
  numbered sequentially and are the record of *why*.

Unlike most repos, these files always exist here and are load-bearing. Their absence would
be a bug, not a signal to proceed silently.

## Use the glossary's vocabulary

`GLOSSARY.md` is opinionated: most terms carry an `_Avoid_` line listing synonyms the project
has deliberately rejected. Use the canonical term in code, comments, commits, issue titles,
test names, and prose. Do not drift to an `_Avoid_` synonym.

The load-bearing ones, because getting them wrong causes real confusion:

- **relay-daemon**, never "agent". The daemon is not an AI.
- **AI-agent** is the only thing called "agent", and always qualified.
- **Relay**, never "hub", "master", or "server".
- Internal identifiers say `Relay`/`RELAY_`, never "gleipnir" — the repo name is historical
  (ADR-0016).

If the concept you need isn't in the glossary, that's a signal: either you're inventing
language the project doesn't use (reconsider), or there's a real gap. A real gap gets added
to `GLOSSARY.md` **in the same change** that introduces the term.

## ADR conflicts are a hard stop, not a flag

In most repos, contradicting an ADR means surfacing it and proceeding. Here it does not.

The invariants enumerated in `AGENTS.md` govern remote code execution on a customer's fleet.
If your output would violate one — Policy evaluation, the execution path, transport, mTLS,
auth, the `/proto` contract, blast-radius caps, label authority — **stop and escalate to a
human.** It needs a new ADR, not a workaround, and the ADR lands in front of a person.

State the conflict plainly:

> _This requires the Relay to evaluate Policy locally, which ADR-0011 forbids (Policy is
> evaluated only by the daemon's live engine). Escalating rather than proceeding._

For everything outside that surface, normal engineering judgement applies.

## Writing an ADR

When to write one, and the style to match: `AGENTS.md`, *How to work here*, step 7.
