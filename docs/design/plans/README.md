# Design plans

A design plan is the bridge between a capability specification and the issues that implement
it: **which modules, contracts, seams and tests deliver a named set of spec claims, in what
order.** `/design` writes one; a human merges it; `/decompose` reads it into issues;
`/milestone-close` deletes it.

## Lifecycle

- **Milestone-scoped.** One plan per milestone, named `<milestone-slug>.md`. It opens with the
  milestone and is **deleted by the PR that closes the milestone.** A plan that outlives its
  milestone is a second, staler statement of what the spec already says.
- **Disposable by design.** `AGENTS.md` forbids file paths and code snippets in specs and
  tickets because they go stale within a sprint. A plan is *allowed* them for exactly that
  sprint, which is why it must not survive it. Anything in a plan that outlives the milestone —
  a behaviour, a decision, a term — is promoted to the spec, an ADR or `GLOSSARY.md` before
  the plan is deleted, never left here.
- **Reviewed before it exists.** `/design` runs the Claude design reviewer and the Codex
  reviewer on the draft; the plan PR carries both verdicts. The merge is the human sign-off,
  after which decomposition may run without one.

## Shape

```
# <Milestone title>

**Spec:** `docs/specs/<capability>.md` — claims <PREFIX>-n, <PREFIX>-m, …
**Milestone:** <title>   **Opened:** <date>

## Intent            what these claims add, in two or three sentences
## Shape             modules and contracts touched, and the seams that stay fixed
## Sequence          ordered steps, each naming the claims it makes true and what blocks it
## Tests             the seam each claim is proven at, per docs/specs/TEMPLATE.md
## Constraints       the invariants and ADRs that bind, and how the design stays inside them
## Rejected          alternatives considered, one line each, so decompose does not reopen them
## Open              what decompose or the loop must still decide, and what forces the call
```

A plan is small. If it needs more than a screen or two per section, the spec change was a
milestone's worth of milestones and should be split.
