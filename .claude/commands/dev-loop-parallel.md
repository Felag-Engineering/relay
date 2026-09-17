---
description: "Implement up to three ready issues at once: pick non-conflicting loop:ready issues, claim them, run one dev-loop-runner subagent per issue in its own worktree, then release every claim and report. Interactive; never merges."
argument-hint: "[--count N (default 3)] [--max-open-prs N (default 8)] [--dry-run] [issue numbers…]"
allowed-tools: Bash(*), Read, Grep, Glob, Agent
---

# Dev loop, in parallel

Run `/dev-loop` on several issues at once. Each issue gets a **`dev-loop-runner` subagent in its
own git worktree**, which runs the full pipeline — planner, reviewers, verify, Codex, PR — exactly
as `/dev-loop --non-interactive` does. You are the coordinator: you pick, claim, launch, wait,
release and report. You never implement, review or merge. See `docs/agents/workflow.md`.

**Interactive only.** Launched subagents report back to this session, and an unattended one-shot
session can end before they do; scheduled runs keep using `/dev-loop-queue`.

Arguments: **$ARGUMENTS**. Explicit issue numbers skip Stage 2's picking but not its checks.

## Stage 0 — Halt and preflight

- `gh issue list --label loop:halt --state open --limit 1 --json number -q length` non-zero → stop.
- `gh auth status`; `go`, `cargo`, `buf`, `protoc-gen-go`, `protoc-gen-go-grpc` (the runners inherit this environment,
  and each will refuse to run half a gate). Missing → stop and say which.
- Warn once about cost: each runner builds the Go and Rust trees and runs `make verify` in its own
  worktree, so N runners use roughly N times the CPU, memory and disk of one.

## Stage 1 — Capacity

Open loop PRs, as in `/dev-loop-queue` Stage 1. Slots = min(`--count`, cap − open). Zero → stop.

## Stage 2 — Pick

Eligible exactly as `/dev-loop-queue` Stage 2: open, `loop:ready`, none of `loop:in-progress`,
`loop:blocked`, `loop:needs-human`, `loop:proposed`, `decision`, `idea`; no `Blocked by: #k` still
open; no existing `loop/issue-<n>-` branch or open PR.

Then, because these run **at the same time** and each is cut from the same `main`:

- **Never pick an issue that another eligible pick blocks.** If A says `Blocked by: #B`, they cannot
  run together, whatever B's state.
- **Avoid overlap.** For each candidate, read the paths and modules its body names (and its
  `Security surface:` line). Skip a candidate that names the same file, or the same package
  directory, as one already picked; note it as deferred for overlap. Two PRs editing one file will
  conflict on merge, and the second PR's author cannot see the first.
- **At most one `/proto`-touching issue per batch.** Regenerated code conflicts wholesale.

Take the lowest-numbered survivors up to the slot count. Print the picks and the skipped-for-overlap
list. `--dry-run` stops here.

## Stage 3 — Claim

`gh issue edit <n> --add-label loop:in-progress` for every pick, before launching anything.

## Stage 4 — Launch, all at once

In **one message**, one `Agent` call per pick:

- `subagent_type: "dev-loop-runner"`, `isolation: "worktree"`
- prompt: `Issue #<n>. RELAY_SMOKE_PORT=<20000 + n>. Execute your instructions and end with the RUNNER REPORT.`

Then wait. Each runner notifies when it finishes; do not poll, and do not start another pick while
any runs. Print one line per runner as its report arrives.

## Stage 5 — Release, for every pick, including failures

From each `RUNNER REPORT`, exactly one of:

- **PR_OPENED** → remove `loop:in-progress`. If the report lists escalations or unresolved findings
  and the PR lacks `loop:needs-human`, add it to the PR.
- **ESCALATED** → remove `loop:in-progress` and `loop:ready`, add `loop:needs-human`. The runner has
  already commented why.
- **NO_CHANGES** → remove `loop:in-progress`; comment the runner's reason; leave `loop:ready` off and
  add `loop:needs-human` so a human closes or rescopes it.
- **FAILED, or no report** (a crash, a context limit) → remove `loop:in-progress`, add
  `loop:needs-human`, comment what is known.

**Never leave `loop:in-progress` set.**

Worktrees: each runner's path comes back with its completion notice. For a **PR_OPENED** runner,
remove it only once both hold — `git -C <path> status --porcelain` is empty and
`git -C <path> rev-parse HEAD` equals `git -C <path> rev-parse @{u}` (everything is pushed) — with
`git worktree remove --force --force <path>` (the double force clears the lock a finished agent can
leave behind). Keep every other runner's worktree, and list those paths in the report: that is where
unpushed work lives.

## Stage 6 — Report

A table: issue, outcome, PR, verify (and any skipped lane), review verdicts, escalations. Then the
skipped-for-overlap list, so the next batch knows what is waiting. State plainly if any gate was
skipped or single-reviewer — a skipped gate is not a passed gate.

## Never

- Merge, approve, or run `gh pr merge`.
- Run a pipeline stage yourself instead of a runner.
- Launch two runners on overlapping files, or on issues where one blocks another.
- Clear `loop:halt`.
