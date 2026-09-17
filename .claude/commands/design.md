---
description: "Write a milestone-scoped design plan from a spec's Designed claims, review it adversarially with Claude and Codex, and open the design PR for a human to merge. Exits 'no design needed' for one-issue changes."
argument-hint: "<docs/specs/<capability>.md> --milestone \"<title>\" [--claims EX-4,EX-5]"
allowed-tools: Bash(*), Read, Edit, Write, Grep, Glob, Agent, AskUserQuestion
---

# Design

Turn a merged spec change into a design plan the loop can decompose. Interactive: you are
present to answer the architect's questions, and you merge the result. See
`docs/agents/workflow.md` and `docs/design/plans/README.md`.

Arguments: **$ARGUMENTS** — the spec, the milestone title, optionally the claim IDs (default:
every *Designed, not built* row tagged with that milestone).

## Stage 0 — Preconditions

- Clean tree on `main`, up to date: `git fetch origin && git status --short`.
- The spec is migrated (Status `current` or `designed`) and `make docs-check` passes. A legacy
  spec cannot be designed from: its claims have no IDs. Stop and point at `/spec-author --migrate`.
- The milestone exists: `gh api repos/{owner}/{repo}/milestones --jq '.[].title'`. If not,
  ask whether to create it; create it only on a yes.
- The claims exist in the spec's Designed table. If `.spec-check/claims-diff.md` exists from a
  recent `/spec-check`, hand it to the architect too.

## Stage 1 — Architect

Branch: `design/<milestone-slug>`. **Use the `design-architect` agent.** Pass it the spec path,
the milestone, the claim IDs, and the claims diff if present. Write its output to
`docs/design/plans/<milestone-slug>.md`.

- `NO DESIGN NEEDED` → skip to Stage 4 with the single issue it describes.
- `BLOCKED` → print why, delete the branch, stop. The owner takes it to `/spec-author`.

## Stage 2 — Adversarial review, two vendors

In parallel:

- **Use the `design-reviewer` agent** on the plan file.
- `scripts/codex-review.sh design docs/design/plans/<slug>.md` (exit 3 means Codex is absent;
  record the gate as single-reviewer).

Merge the two reports. Deduplicate. For each BLOCKING item: run `design-architect` again with
the item and the current plan; overwrite the plan. **Max 2 revision cycles.** A BLOCKED verdict
from either reviewer ends the run as in Stage 1. If a blocking item stands after two cycles,
put it under **Unresolved** in the PR body and label the PR `loop:needs-human`.

## Stage 3 — Open the design PR

```bash
git add docs/design/plans/<slug>.md
git commit -m "design(<capability>): <milestone title>"
git push -u origin design/<slug>
gh pr create --title "design(<capability>): <milestone title>" --body-file <body>
```

Body: the spec and claim IDs; both reviewers' verdicts (or "Codex: absent"); revision cycles;
**Unresolved** if any; a line saying a human merges and `/decompose` runs after the merge.
End the commit message and the PR body with the attribution lines the session requires.

## Stage 4 — `NO DESIGN NEEDED`

No branch, no plan file. Print the issue the architect described and ask whether to create it
now as `loop:proposed` via the `/decompose` conventions (title, claims, acceptance, milestone).
Create it only on a yes.

## Never

- Merge. Design plans are permanent until the milestone closes; a human signs them off.
- Edit the spec. If the architect finds the spec wrong, that is a `BLOCKED` exit.
- Run unattended.
