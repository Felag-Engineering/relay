# Routines

How this repo is driven by scheduled Claude Code cloud routines while nobody is at a keyboard.

## What a routine runs

Two routines, both from `docs/agents/workflow.md`'s unattended set — nothing above GATE 3 ever
runs on a schedule.

```
/dev-loop-queue
```

One tick takes one `loop:ready` issue, runs the full `/dev-loop` pipeline on it unattended, and
opens a PR. It never merges and never waits for one, which is what makes it safe to fire on a
schedule for weeks.

```
/pr-respond --non-interactive
```

One tick takes the oldest open loop PR with unaddressed human review comments, fixes what was
asked, re-runs the full gate, Claude's reviewers and at most one Codex run, pushes, and replies
per thread. Questions and anything that would change a spec claim are escalated with
`loop:needs-human`, never answered on your behalf. A sensible cadence is every hour while you
are reviewing and twice a day otherwise; it exits in seconds when there is nothing to respond
to.

Both need the Codex CLI, and now node too, on the environment for the second reviewer. Without
either, every review gate runs single-vendor and the PR body says so — degraded, and stated,
never silent. `RELAY_CODEX_MODEL` overrides the default model (`gpt-5.6-terra`) per run.

## Environment

Cloud sessions run Ubuntu 24.04 on 4 vCPU / 16 GB RAM / 30 GB disk, with a fresh clone per run.
**Go, Rust (rustc + cargo), Docker, and `gh` are pre-installed**; `gh` picks up
`GH_TOKEN` automatically and its traffic bypasses the network allowlist. Whether node is
pre-installed on the image is not something this file can confirm — but node is now
load-bearing, not merely useful, whether or not it ships by default: `scripts/codex-review.sh`
runs the Codex companion and classifies its output with node, and `make test-codex-review`
FAILS without it rather than skipping — before #694 a node-less host merely degraded the Codex
gate to absent. Confirm node is present on the image; if it is missing, an unattended
`make verify` now goes red on this gate rather than degrading it.

One thing is missing, and it matters here:

```bash
# Setup script — configured in the environment dialog at claude.ai/code
make proto-tools
```

`buf` is not pre-installed. Without it, `verify-proto` **skips** the proto-drift and
proto-breaking gates with a notice — so a routine touching `/proto` would report a green
`make verify` that never checked the contract. Setup scripts run once and the filesystem is
snapshotted, so this costs nothing per run.

Network access: **Trusted** is sufficient. It covers crates.io, the Go module proxy, and GitHub.

## The kill switch

Label any open issue **`loop:halt`**. Every tick checks this first and stops before doing
anything else.

It is deliberately a label rather than a file: it takes five seconds from a phone, needs no
commit, no PR, and no laptop. Removing it is a human act — the routine will never clear it.

To stop permanently rather than temporarily, disable the routine at claude.ai/code.

## Caps, and why

- **8 open loop PRs** (`--max-open-prs`). Every branch is cut from a `main` that contains none
  of the others, so unmerged PRs compound into conflicts. Past a point, more PRs means less
  delivered work and a review queue nobody can face. Hitting the cap is the correct outcome.
- **One issue per tick.** Capacity control depends on it.
- **Plan limits.** Routines are capped per day by subscription tier and the minimum schedule
  interval is one hour. A daily or twice-daily cadence is usually right; hourly mostly buys
  "at capacity" messages.

## Before a long absence

1. **Merge the workflow to `main`.** Cloud sessions see only what is committed. A skill sitting
   on a branch does not exist.
2. **Flip `loop:proposed` to `loop:ready`** for the issues you have read. `loop:ready` is the
   entire queue; three issues is one day, not three weeks. Order matters less than it looks:
   the queue skips anything whose `Blocked by:` is still open.
3. **Prefer independent issues** when triaging. Work that depends on an unmerged PR cannot be
   done by a loop that never merges.
4. **Check the environment's setup script** actually installs `buf`.
5. **Confirm `loop:halt` is clear.**

## What you come back to

A stack of open PRs, each with a `make verify` result and an explicit statement of any skipped
gate. Some will conflict — they were all cut from the same `main`; rebasing them is a human's
call, made PR by PR, and `/pr-respond` picks up whatever review comments follow.

Issues labelled `loop:needs-human` are where the pipeline stopped rather than guessed:
underspecified work, or a change that would have touched an architecture invariant. Those are
the interesting ones. Read them first.
