---
description: "Address human review comments on open loop PRs: fix what was asked, re-verify, re-review, push, and reply per thread. Escalates questions and spec conflicts instead of answering them. Runs unattended on a schedule or interactively on one PR."
argument-hint: "[<pr-number>] [--non-interactive]"
allowed-tools: Bash(*), Read, Edit, Write, Grep, Glob, Agent
---

# PR respond

Human review is GATE 4. This command does the mechanical half of the cycle after it: turn each
change request into a fix, prove the fix, and hand the PR back. It never merges, never argues
with the reviewer in the thread, and never decides what the reviewer left open. See
`docs/agents/workflow.md`.

Arguments: **$ARGUMENTS**. With a PR number, work that PR. Without, pick the oldest open PR on
a `loop/`, `design/` or `close/` branch that has unaddressed human review since the last
push. `--non-interactive` is implied on a routine and means: never ask; escalate.

## Stage 0 — Halt and pick

`gh issue list --label loop:halt --state open --limit 1 --json number -q length` non-zero →
stop. Then:

```bash
gh pr list --state open --json number,headRefName,reviewDecision,updatedAt \
  -q '[.[] | select(.headRefName | test("^(loop|design|close)/"))]'
gh pr view <n> --json reviews,comments,commits
gh api repos/{owner}/{repo}/pulls/<n>/comments      # review-thread comments with paths and lines
```

A PR is **actionable** if it has a `CHANGES_REQUESTED` review or any review-thread comment
authored by a human after the branch's last commit, and does not carry `loop:needs-human`. None
→ print `nothing to respond to` and stop.

## Stage 1 — Classify every comment

For each human comment newer than the last push, one of:

- **Change request** — asks for something concrete in the diff. Actionable.
- **Question** — asks why, or asks for information. Answer it in the thread from the code and
  the plan, do not change code for it, and if the answer implies a decision, label the PR
  `loop:needs-human`.
- **Spec conflict** — asks for behaviour that would make a migrated spec claim untrue, or asks
  to change a claim. Reply naming the claim ID and that the spec must change first via
  `/spec-author`; label `loop:needs-human`; stop on this PR.
- **Out of scope** — asks for work beyond the issue. Reply proposing a follow-up issue; do not
  do it; do not create the issue unattended.

## Stage 2 — Fix

Check out the branch, `git pull`. Write the change requests to `.dev-loop/review-feedback.md`
under `## Human review — <date>` with path, line, and the request verbatim. **Use the
`devloop-developer` agent** with that file, the plan from the PR body's `<details>` block, and
the issue. It edits; it never commits.

## Stage 3 — Verify and re-review

`make verify` (full gate; **max 2 fix attempts** via the developer, then escalate). Then
**use the `devloop-code-reviewer` agent** on the new diff, and `scripts/codex-review.sh diff`;
if `scripts/security-surface.sh` matches (**exit 2 = the check could not run — treat it
as a failed gate and escalate, never as clean**), also the `devloop-security-reviewer` and
`scripts/codex-review.sh security`. Blocking findings go back to Stage 2 once; a second
failure escalates.

## Stage 4 — Push and reply

Commit with a message naming the review (`fix(<area>): address review — <one line>`), push.
Reply in **each** thread you acted on, one or two sentences: what changed and the commit. Reply
to questions with the answer. Do not resolve threads; the reviewer does.

Append to the PR body under **Review responses**: the date, what was fixed, the gate that
passed and every lane it covered, both reviewers' verdicts, and anything escalated.

## Stage 5 — Escalate, or finish

Anything classified as question-with-decision, spec conflict, out of scope, or a failed gate →
`gh pr edit <n> --add-label loop:needs-human` with a PR comment listing exactly what a human
must decide. Otherwise print `responded: PR #<n>, <k> threads` and stop. One PR per run.

## Never

- Merge, approve, or resolve a thread.
- Change a spec, an ADR, `AGENTS.md` or `GLOSSARY.md`.
- Answer a design question the reviewer asked the author. Escalate it.
- Push without a green `make verify` on the new tree.
