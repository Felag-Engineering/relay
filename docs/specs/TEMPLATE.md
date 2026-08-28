# <Feature name>

**Milestone:** `vX.Y.Z` · **Tracking issue:** #NNN · **Status:** draft | approved | shipped

## Problem Statement

The problem, from the user's perspective. Who is stuck, and on what. Not a solution in
disguise.

## Solution

The solution, from the user's perspective. What becomes possible that wasn't.

## Governing ADRs and invariants

The ADRs that constrain this work, and the numbered `CLAUDE.md` invariants it touches. If the
feature would contradict one, stop — that is a new ADR in front of a human, not a spec
decision. If it touches nothing, say so explicitly; that is a useful claim to have reviewed.

## User Stories

A long, numbered list, in the form *As an `<actor>`, I want `<feature>`, so that `<benefit>`*.
Be extensive — cover the unhappy paths, the roles that must be refused, and the operator as
well as the AI-agent.

1. As a …, I want …, so that …

## Seams

Where this gets tested. Prefer an existing seam to a new one, and the highest seam available —
the fewer seams across the codebase, the better. Name new ones explicitly and justify them.

## Implementation Decisions

The modules built or modified, the interfaces that change, schema and contract changes, and
the specific interactions. Decisions, not a task list.

For anything crossing the wire: `/proto` first, then regenerate, then both sides.
For any new Operation: state its risk class (`read` | `mutate`) — it is security-relevant
contract, and Raw Exec always takes the mutate cap.

**Promote before you ship:** any decision here that is hard to reverse, surprising without
context, and a real trade-off belongs in `docs/adr/`. Cite the number here instead.

## Testing Decisions

What makes a good test for this feature — external behaviour, never implementation details.
Which modules are covered, and the prior art in the codebase to follow. Note whether
`make verify` is sufficient or the change needs `make test-integration` or the dev fleet.

## Out of Scope

What this deliberately does not do. Be specific: this is the section that stops scope creep in
the tickets, and the one a reviewer checks the diff against.

## Further Notes

Open questions, prior art, links to the shaping conversation, anything that did not fit above.
