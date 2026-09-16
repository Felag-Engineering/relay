---
description: "Drain the loop:ready queue one issue per tick, independent of merges. Built for unattended cloud routines: pick the next ready issue with no open PR, run the dev-loop pipeline on it, open a PR, stop. Never merges, never waits for a human."
argument-hint: "[--max-open-prs N] [--dry-run]"
allowed-tools: Bash(*), Read, Grep, Glob, Agent, Skill
---

# Dev-loop queue drainer (routine-driven)

One tick, one issue, no waiting. Unlike `/dev-loop-drive`, this **never gates on a merge** —
it is built for a scheduled cloud routine running while nobody is available to review.

It still **never merges.** Every tick ends at an open PR. The human remains the sole merge
authority (see "Routines & merge authority" in `AGENTS.md`).

`--max-open-prs N` overrides the default cap of **8**. `--dry-run` reports the decision and
stops before creating a branch.

## Stage 0 — Halt check (always first)

```bash
gh issue list --label loop:halt --state open --limit 1 --json number -q 'length'
```

**Non-zero → stop immediately.** Print `halted: loop:halt is set on #N` and end the tick. Do
not pick an issue, do not create a branch, do not comment.

This is the remote kill switch: one label, settable from a phone, stopping every future tick
without touching the routine's configuration. Never remove the `loop:halt` label yourself —
only a human clears it.

## Stage 1 — Capacity check

```bash
gh pr list --state open --json number,headRefName \
  -q '[.[] | select(.headRefName | test("^(loop|agent)/")) | .number] | length'
```

At or above the cap → stop. Print `at capacity: N open loop PRs (cap M)` and end the tick.

The cap exists because unmerged PRs accumulate while you are away, and each new branch is cut
from a `main` that does not contain any of them. Past a point, more PRs means more conflicts
and a review queue nobody can face. Stopping is the correct outcome, not a failure.

## Stage 2 — Pick the next issue

Eligible: open, labelled `loop:ready`, and **not** labelled `loop:in-progress`,
`loop:blocked`, `loop:needs-human`, `decision`, or `idea`.

```bash
gh issue list --label loop:ready --state open --limit 50 \
  --json number,title,labels,milestone \
  -q '[.[] | select([.labels[].name] | any(. == "loop:in-progress" or . == "loop:blocked"
        or . == "loop:needs-human" or . == "decision" or . == "idea") | not)]
      | sort_by(.number)'
```

Then drop any issue that already has a branch or an open PR:

```bash
gh pr list --state open --json headRefName -q '[.[].headRefName]'
git ls-remote --heads origin 'loop/*'
```

An issue with `loop/<number>` on either list has been started — **skip it.** `/dev-loop` has no
duplicate-PR guard of its own, so this is the only thing standing between an hourly routine and
two PRs for the same issue.

Take the **lowest-numbered** survivor. None left → print `queue empty` and end the tick
successfully. An empty queue is not an error; it means a human needs to triage more work.

## Stage 3 — Claim before working

```bash
gh issue edit <n> --add-label loop:in-progress
```

Claim **before** creating the branch. Two ticks that overlap will then collide on the label
rather than on the branch. This is advisory, not a lock — GitHub gives no compare-and-swap —
but it makes the accidental double-tick harmless.

`--dry-run` stops here, reporting the issue it would have taken, without claiming.

## Stage 4 — Run the pipeline

```
/dev-loop <n> --non-interactive
```

Unattended mode is mandatory. It never calls `AskUserQuestion`; where a stage would need a
human decision it comments on the issue and stops. Do not pass `--non-interactive` conditionally
and do not "helpfully" answer on the human's behalf.

Let the pipeline own its own stages, including `make verify`. Do not re-run or second-guess them.

## Stage 5 — Release the claim

Exactly one of these, every time, including on failure:

- **PR opened** → `gh issue edit <n> --remove-label loop:in-progress`. Leave `loop:ready` in
  place; the issue is done when the PR merges, which is not this tick's business.
- **Pipeline stopped and commented** (underspecified, invariant touched, escalation) →
  remove `loop:in-progress`, add `loop:needs-human`, remove `loop:ready`. The issue must leave
  the eligible set, or the next tick picks it up again and stops again, forever.
- **Crashed or ran out of context** → remove `loop:in-progress` and add `loop:needs-human` with
  a comment saying what happened. A claim left set silently removes the issue from the queue for
  good.

Never leave `loop:in-progress` set at the end of a tick.

## Stage 6 — Report

One short summary: the issue taken, the PR number, whether `make verify` was fully green, and
**explicitly whether any gate was skipped.** In a cloud environment `buf` may be absent, which
skips the proto-drift and proto-breaking checks with a notice — a skipped gate is not a passed
gate, and the human reading this in three weeks needs it stated, not implied.

## Never

- Never merge. Never `gh pr merge`, on any PR, for any reason.
- Never clear `loop:halt`.
- Never move an issue to `loop:ready` yourself. Triage is a human act.
- Never take more than one issue per tick — capacity control depends on it.
- Never design around an architecture invariant. `/dev-loop` stops and escalates; let it.
