---
description: "Decompose a merged design plan into GitHub issues, one per reviewable step plus the capability's testing issue, created as loop:proposed with blocking edges and claim references. A human flips each to loop:ready."
argument-hint: "<milestone title | docs/design/plans/<slug>.md> [--dry-run]"
allowed-tools: Bash(*), Read, Write, Grep, Glob, Agent, AskUserQuestion
---

# Decompose

Issues are the only artifact the loop implements from, so this is where a design becomes work.
Interactive, because creating issues is outward-facing and a wrong plan makes twenty wrong
issues; the gate after it is cheap (a label flip) but the creation is yours to approve. See
`docs/agents/workflow.md`, `docs/agents/issue-tracker.md`, `docs/agents/triage-labels.md`.

Argument: **$ARGUMENTS**.

## Stage 0 — Preconditions

- The plan is on `main` (merged). `git fetch origin && git show origin/main:docs/design/plans/<slug>.md`.
  A plan on a branch is unreviewed; stop.
- The milestone exists and is open. Existing issues in it: list them, so you do not duplicate.

## Stage 1 — Decompose

**Use the `decomposer` agent.** Pass it the plan path and a scratch directory
`.decompose/` (transient, never committed). It writes one file per issue and a summary.

## Stage 2 — Show, then create

Print the summary and the title, claims, and `Blocked by` line of every issue. Ask once:
create these? (`--dry-run` stops here.)

On yes, create in the order the summary gives, so blocking edges can cite real numbers:

```bash
gh issue create --title "<Title>" --body-file <file> --milestone "<milestone>" \
  --label loop:proposed [--label security] [--label bug]
```

After each creation, rewrite `#<step-k>` placeholders in the remaining files with the real
number. Then edit the created issues' bodies once more so every `Blocked by:` line names real
issues (`gh issue edit <n> --body-file`). Where a `Needs decision:` line is present, add
`loop:needs-human` instead of leaving it for the queue to find.

## Stage 3 — Report

```
DECOMPOSED  <milestone>
Created: #a #b #c … (+ testing #t)   Order: #a → #b → #c
loop:proposed: <n>   needs decision: <list or none>
Next: flip each to loop:ready when you are satisfied; the queue takes them lowest-number-first,
      skipping any whose Blocked by is still open.
```

## Never

- Create with `loop:ready`. That flip is GATE 3 and it is the human's.
- Create issues for claims outside the plan. Report them.
- Run unattended.
