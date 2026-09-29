---
description: "Close out a milestone: verify every Designed claim it tagged was promoted, delete its design plan, move the spec's Status, and open one PR for a human to merge. Refuses if anything is still open or unproven."
argument-hint: "<milestone title>"
allowed-tools: Bash(*), Read, Edit, Grep, Glob, Agent, AskUserQuestion
---

# Milestone close

The last link of the chain: the design plan dies, the spec says `current`, and nothing that
outlived the milestone is left only in a closed issue. See `docs/agents/workflow.md` and
`docs/design/plans/README.md`. Interactive.

Milestone: **$ARGUMENTS**.

## Stage 0 — Is it done?

```bash
gh issue list --milestone "<title>" --state open --json number,title
```

Open issues → stop and list them. A milestone closes when its issues are merged, not before.

## Stage 1 — Did the spec follow?

For every spec that any issue in the milestone cited (`Spec:` lines in the bodies):

- No *Designed, not built* row may still carry this milestone. One that does was never
  promoted: either its PR shipped without a test (the spec-proof stage reports this), or the
  claim was dropped. List them; the human decides — a test issue, or retiring the claim in
  `/spec-author`. Do not promote or delete anything yourself.
- Run `/spec-drift <spec>` on the claims the milestone promoted and confirm every one is
  `built` with a proof row. A promoted claim that drifted is a finding, not a fix.
- `make docs-check` passes.

Any finding → report and stop. Closing with a stale spec is the failure this command exists
to prevent.

## Stage 2 — Promote what outlives the plan

Read `docs/design/plans/<slug>.md` one last time against `AGENTS.md` "Promote before the issue
closes": a decision that meets the ADR test, a term the glossary lacks, a behaviour the spec
does not state. List each with where it should go. The human decides; anything they want kept
is drafted in `/spec-author`, not here.

## Stage 3 — The close PR

Branch `close/<slug>`. Delete `docs/design/plans/<slug>.md`. If the spec's Designed section is
now empty and its Status still says `designed`, set `current as of <today>`. Commit, push, open the PR with the verification results in
the body, and end with the attribution lines the session requires.

Close the GitHub milestone only after the human merges — say so, do not close it yourself.

## Never

- Promote, reword or delete a claim.
- Delete a plan whose milestone has open issues.
- Close the milestone.
