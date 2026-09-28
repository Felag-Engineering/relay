---
description: "Drive a whole milestone in strict waves, designed to run under /loop: each tick either opens the next wave of PRs (one per ready issue, dependency-ordered, via the dev-loop pipeline) or verifies CI on the open wave (auto-fixing red PRs, capped at 2 attempts) — and a new wave starts only once every open loop PR has been merged or closed by a human. Never merges."
argument-hint: "[milestone] [--serial] [--max-parallel N] [--track <issue#>] [--max-issues N] [--max-open-prs N] [--max-wait H] [--dry-run]"
allowed-tools: Bash(*), Read, Grep, Glob, Agent, AskUserQuestion, Skill
---

# Dev-loop driver (strict waves, /loop-driven)

You orchestrate the per-issue `dev-loop` pipeline across a milestone. You select what to
work, order it by dependency, open one PR per issue, and then **verify each PR's CI**
until the human has resolved the whole wave. You do **not** merge anything — the human's
merges are the only thing that advances the frontier. The per-issue work itself is the
`dev-loop` command/skill; this command is the scheduler and verifier around it.

## The two constraints that shape everything

1. **Nothing merges without a human.** A dependent issue cannot be worked until its
   predecessor's PR is merged — its code isn't on the default branch yet. Work therefore
   happens in **waves** of issues that are all actionable right now.
2. **Strict wave barrier.** A new wave may start **only when zero pipeline PRs are open**.
   A *pipeline PR* is any open PR whose head branch starts with `loop/` or `agent/`
   (both prefixes the per-issue pipeline has used — manual `/dev-loop` PRs hold the
   barrier too). Merging a PR resolves it forward; closing it unmerged also resolves it,
   returning its issue to the pool (it will be re-worked in a later wave — to retire an
   issue instead, close the issue or drop its `loop:ready` label). Until every open
   pipeline PR is resolved, ticks only verify and fix — they **never** start new issues.

## Tick model — designed for `/loop`

This command is **single-tick**: each invocation does one unit of work and ends. There is
no internal sleeping or polling — `/loop` re-invokes it with fresh context, and all
durable state lives in GitHub: the open PRs, the issues, and a tracking issue that is
both the live dashboard and the state record.

Tick decision (after Setup):

| Condition | Tick type |
|---|---|
| Any open pipeline PR | **VERIFY** — check CI on every open PR, auto-fix red ones (capped), ping when the wave settles. Never start new issues. |
| No open PRs; actionable ready issues exist | **WAVE** — select, plan, and run the next wave; open PRs. |
| No open PRs; no ready issues left in milestone | **DONE** — final rollup, stop the loop. |
| No open PRs; ready issues exist but none actionable | **STUCK** — everything is blocked on non-loop issues or stopped needing the human. Notify, stop the loop. |

**Pacing (when driven by dynamic `/loop`):** after a WAVE tick or a CI-fix push →
short wakeup (~5 min, CI needs to run); VERIFY with checks still pending → ~5–10 min;
wave settled / waiting only on human merges → 20–30 min; DONE / STUCK / budget / stall →
**stop the loop** (ScheduleWakeup `stop: true` in dynamic mode; in fixed-interval mode,
state plainly in the final message that the loop should be stopped). Ticks never overlap:
turns in a session run serially, so a fixed-interval firing that lands mid-tick just
queues and runs after — harmless, since ticks are idempotent — but dynamic pacing avoids
the pileup entirely, which is why it's the recommended invocation.

### How to run it

```
/loop /dev-loop-drive <milestone>          ← recommended: self-paced ticks
/loop 15m /dev-loop-drive <milestone>      fixed cadence
/dev-loop-drive <milestone>                one-shot = exactly one tick
/dev-loop-drive <milestone> --dry-run      print the full projected wave plan, run nothing
```

## Flags

Parse `$ARGUMENTS`:
- optional milestone name (else the open GitHub milestone due soonest that still has open
  `loop:ready` issues — `gh api 'repos/{owner}/{repo}/milestones?state=open&sort=due_on'` —
  or fall back to "all open `loop:ready` issues"). GitHub milestones are the authority on
  what is in flight; never infer the target from a file.
- `--serial` — never parallelize; one issue at a time in dependency order.
- `--max-parallel N` — cap concurrent issues within a wave (default 3). `--serial` ==
  `--max-parallel 1`.
- `--track <issue#>` — the tracking issue to use as dashboard + state + ping channel.
  If omitted, reuse an open issue titled `🤖 drive: <milestone>` or create one
  (skipped entirely under `--dry-run`).
- `--max-issues N` — process at most N issues across the **whole loop** (persisted in
  the state record; default unlimited). A budget cap so a mislabel or bad dependency
  guess can't churn the backlog unattended.
- `--max-open-prs N` — a wave opens at most N PRs (default 5). If the frontier is
  larger, run the highest-priority subset (most transitive dependents; ties → lowest
  issue number) and defer the rest to a later wave. Bounds the review flood.
- `--max-wait H` — stall guard: if nothing has progressed (no merge/close, no new PR,
  no fix push) for H hours, notify and stop the loop (default 48).
- `--dry-run` — build and print the full projected plan (every wave) and **stop**,
  running nothing and creating nothing.

## Setup (every tick)

1. Verify `gh auth status` succeeds; if not, stop and tell the user.
2. Resolve the milestone and `GH_USER=$(gh api user --jq .login)`.
3. Resolve **TRACK** (per `--track` / reuse-or-create above). On create:
   ```bash
   gh issue create --title "🤖 drive: <milestone>" \
     --body "Starting the drive loop — live status will appear here. I'll @-mention you when a wave is verified and ready to merge, or when I need you. Merge PRs (e.g. from GitHub Mobile) to advance to the next wave."
   ```
4. Read the state record from the first line of TRACK's body — an HTML comment:
   ```
   <!-- drive-state {"wave":3,"processed":11,"last_progress":"2026-07-30T18:00:00Z","pinged":"wave3-settled","open_prs":[123,124],"lease":""} -->
   ```
   Missing or unparsable → defaults (`wave=0, processed=0, last_progress=now,
   pinged="", open_prs=[], lease=""`).
5. **Advisory lease — one driver at a time.** If the state's `lease` is a timestamp
   still in the future, another driver invocation is likely mid-tick (two `/loop`s, two
   sessions) — say so and **end this tick doing nothing**. Before any mutating work
   (running a wave, pushing a CI fix), rewrite the state with `lease = now + 60m`;
   clear it when the tick ends. Issue-body writes have no compare-and-swap, so this is
   advisory — it makes the accidental double-driver harmless, it is not a mutex; never
   run two drivers on the same repo deliberately.
6. List open pipeline PRs:
   ```bash
   gh pr list --state open --json number,headRefName \
     -q '[.[] | select(.headRefName | test("^(loop|agent)/")) | .number]'
   ```
   Compare against the state record's `open_prs`: any difference (a merge, a close, a
   new PR) is **progress** — update `last_progress`. Then pick the tick type from the
   table above.

## The tracking issue — dashboard, state, ping discipline

Every tick **rewrites the body** (editing a body does NOT ping — safe to do every tick):
the state comment on line 1, then the dashboard:

```bash
gh issue edit "$TRACK" --body "$(cat <<EOF
<!-- drive-state {...updated JSON...} -->
## 🤖 drive: <milestone> — live status
_tick at <UTC now> · <WAVE|VERIFY|DONE|STUCK> · wave <k>_

**Progress:** <merged>/<total> issues merged · <open> PRs open · <processed> processed
**✅ Ready to merge:** #a (✅ CI) → unblocks #x; #b (✅ local gate)
**⚠️ Review carefully (security surface):** #d — review on a real screen, do NOT quick-merge
**🔧 Being fixed (CI red, attempt k/2):** #c
**⏳ CI running:** #e
**🛑 Needs you (fix attempts exhausted / unverified):** #f
**🙋 Blocked on you (stopped/underspecified):** #g — see its issue comments
**⏸ Next wave (waiting on the barrier):** #h, #i
EOF
)"
```

**Ping** (an @-mention *comment* — fires a mobile notification) only when there is
something for the human to do, and only once per event: compute the tick's ping tag —
`wave<k>-settled`, `done`, `stuck`, `budget`, or `stall` — and comment **only if it
differs from the state record's `pinged`**, then store it. Interim ticks (CI still
running, fixes in flight) update the dashboard silently.

```bash
gh issue comment "$TRACK" --body "@$GH_USER Wave <k> is verified — merge to continue: #a #b. ⚠️ #d is security-surface — review carefully. 🛑 #f needs a human fix. Full status in the issue body."
```

## VERIFY tick — CI verification and auto-fix

Helpers:

```bash
ci_status() { # -> ✅ | ⏳ | ❌ | —(no CI)
  local out rc; out=$(gh pr checks "$1" 2>&1); rc=$?
  if echo "$out" | grep -qi 'no checks reported'; then echo "—(no CI)"
  elif [ $rc -eq 0 ]; then echo "✅"; elif [ $rc -eq 8 ]; then echo "⏳"; else echo "❌"; fi; }
sec_flag()  { gh pr view "$1" --json body -q '.body' | grep -qi 'security surface' \
  && echo "⚠️security-surface" || echo ""; }
local_ok()  { gh pr view "$1" --json body -q '.body' \
  | grep -qiE '✅ .*local verification|local verification.*✅' && echo yes || echo no; }
fix_attempts() { gh pr view "$1" --json comments \
  -q '[.comments[].body | select(startswith("🤖 ci-fix attempt"))] | length'; }
```

Classify every open pipeline PR. **Verification** is CI when present, else the local
full-gate pass the dev-loop records in the PR body (with CI quota exhausted, that local
pass **is** the merge signal):

- **✅ Ready to merge** — CI `✅`, or no-CI + local gate `yes`. Security-surface PRs go
  in the **Review carefully** bucket instead (still verified, never quick-merge).
- **⏳ CI running** — leave it; short wakeup and re-check next tick.
- **❌ Red** — enter the auto-fix flow below.
- **🛑 Unverified** — no CI **and** no local gate on record. Never advertise as
  mergeable; needs the human.

### Flake screen (before any fix attempt)

CI failures on loaded shared runners are sometimes flakes, and a fix attempt is
expensive (checkout, investigation, agent, commit, push) and can "fix" the wrong thing.
So the first response to a newly red PR is one cheap retry:

- If the PR has **no** `🤖 ci-rerun` marker comment yet: find the red run's id
  (`gh run list --branch <branch> --limit 1 --json databaseId`), run
  `gh run rerun <run-id> --failed`, post the marker
  (`gh pr comment <p> --body "🤖 ci-rerun — re-running failed jobs once to screen for a flake"`),
  and leave the PR in the **⏳** bucket this tick. A rerun is **not** a fix attempt.
- Green after the rerun → it was a flake; nothing to fix. Note the flaky check in the
  dashboard — a check that flakes repeatedly deserves its own issue.
- Red again (a `🤖 ci-rerun` marker already exists) → the failure is real; enter the
  fix flow below.

### Auto-fix flow (red PRs, max 2 attempts per PR)

Attempts are counted by marker comments on the PR itself (`fix_attempts` above), so the
cap survives fresh-context ticks. If `fix_attempts ≥ 2` → bucket **🛑 Needs you**, no
further touches. Otherwise, fix PRs one at a time (clean tree between them, back on the
default branch after):

1. `gh pr checkout <p>`, then pull the failure: `gh pr checks <p>` to find the failing
   check, `gh run list --branch <branch> --limit 5` + `gh run view <id> --log-failed`
   for the output.
2. **Use the `devloop-developer` agent** to fix it. Pass the failure output inline,
   instruct it to fix the **root cause** — never skip, disable, or relax tests to get
   green — and remind it not to run `git commit`/`git push`.
3. You (the coordinator) commit — the commit hook re-runs the local gate; a hook failure
   consumes the attempt — and push to the PR branch.
4. Post the marker: `gh pr comment <p> --body "🤖 ci-fix attempt <k>/2 — <failing check>: <one-line root cause and fix>"`.
5. A fix push is progress (reset the stall clock). At most one fix push per PR per tick —
   CI needs a chance to run; the next tick re-checks.

### Settle and stall

The wave is **settled** when no PR is ⏳ and no fix was pushed this tick — every open PR
is either verified-green or needs-you. On settle, ping `wave<k>-settled` listing the
merge-ready PRs (with what each unblocks), the review-carefully PRs, and the needs-you
PRs. From then on, ticks wait silently for the human's merges (long wakeups).

**Stall guard:** if `now − last_progress > --max-wait` hours, ping
`⏰ No progress in <H>h — pausing the drive. Merge/close/fix, then restart the loop.`
(tag `stall`) and stop the loop.

## WAVE tick — select, plan, execute

### Stage A — Select the candidate set

```bash
gh issue list --state open --label loop:ready --json number,title,body,labels,milestone --limit 100
```

Filter to the target milestone. Call this set **R**. Exclude issues that are **blocked
on the human**: an issue whose most recent activity is the pipeline's own stop/needs-human
comment (no later human comment or body edit) is never re-selected — re-working it would
just stop again. List these in the dashboard's 🙋 bucket instead. If **R** (after
exclusion) is empty → **DONE**; if only human-blocked issues remain → **STUCK**.

### Stage B — Build the dependency graph

For each candidate:

1. **Explicit** deps — scan the body for `depends on #N`, `blocked by #N`, `after #N`,
   and task-list references. Authoritative.
2. **Implicit** — do NOT assume numeric order means dependency. Infer cautiously from
   titles/bodies (e.g. "add X" before "use X"). When genuinely unsure whether two issues
   are independent, treat them as **dependent (serialize)** — correctness beats speed.

A dependency is **satisfied** if its issue is closed (`gh issue view N --json state`).
Build the **reverse map** (issue → dependents) for prioritization and unblock reporting.
Compute the **actionable frontier** (all deps satisfied) and **blocked** (note which #,
and whether it is a loop issue that will resolve or a human issue that won't).

**`--dry-run`:** compute the full topological layering of all candidates (Layer 0 = no
unsatisfied dep among candidates; Layer k = deps all in earlier layers), print each layer
as a projected wave (marking which are actionable *now*), and **stop**.

### Stage C — Plan the wave

The wave = the top `--max-open-prs` of the frontier (priority: most transitive
dependents, ties → lowest number); defer the rest to a later wave. Within the wave, two
issues run **in parallel** only if **both** hold:

1. **Graph-independent** — neither depends on the other.
2. **Likely file-disjoint** — from the issue text (and a quick `Glob`/`Grep` of areas
   they name), they touch different parts of the tree. If unsure, serialize.

Group into a parallel batch (up to `--max-parallel`) + a serial remainder. **Print the
wave plan**: order, what runs in parallel, what is deferred, what is blocked. In an
interactive one-shot run, let the user veto/adjust with `AskUserQuestion`; under `/loop`
or any non-interactive context, proceed without asking.

### Stage D — Execute the wave

**Crash-residue cleanup (before running anything):** a tick killed mid-wave leaves
worktrees and local branches behind with **no open PR** — invisible to the barrier, and
they would collide with `git worktree add` / `checkout -b` on the re-run. Run
`git worktree prune`, force-remove any leftover `../$(basename "$PWD")-issue-<n>`
worktrees, and delete any local `loop/`- or `agent/`-prefixed branch that has no open PR
(`git branch -D`; delete its remote branch too if one was pushed).

Budget check per issue before starting: if `processed ≥ --max-issues`, stop, ping
`budget` ("Budget of N issues reached — restart the loop to continue."), and stop the
loop. Increment `processed` per issue attempted (persisted in the state record).

Each issue runs the **`dev-loop` skill in `--non-interactive` mode** (an underspecified
or invariant-touching issue self-comments on its issue and stops without sinking the
wave).

**Serial issues:** one at a time, in dependency order, on the default branch; clean tree
between issues.

**Parallel batch:** isolate each issue in its own git worktree, spawn one agent per
issue (in a single message, so they run concurrently), each instructed to `cd` into its
worktree, run the `dev-loop` pipeline for its issue in `--non-interactive` mode, and
report the PR URL (or why it stopped). Then remove the worktrees:

```bash
git worktree add ../$(basename "$PWD")-issue-<n> origin/<default-branch>
# ...after all agents return:
git worktree remove ../$(basename "$PWD")-issue-<n>
```

If the **Workflow** tool is available and the batch is large, prefer it (worktree
isolation, concurrency cap, resumability for free).

Collect outcomes (`PR opened` / `stopped` / `failed`), take an initial `ci_status`
snapshot of the new PRs, bump `wave`, update `last_progress` and `open_prs`, rewrite the
dashboard, and **end the tick** (short wakeup — verification is the next ticks' job).
No ping yet: the wave pings when it *settles*, verified.

## Terminal ticks

- **DONE** — set the dashboard to a final rollup (issues completed, PRs merged, waves,
  fix cycles, anything that needed the human), ping `✅ Milestone <milestone> complete —
  everything merged. Stopping.` (tag `done`), `gh issue close "$TRACK"`, stop the loop.
- **STUCK** — ping `⚠️ Stuck: nothing a merge can advance. Needs you: <human-blocked
  issues / stopped issues>. Stopping — address them and restart the loop.` (tag `stuck`),
  stop the loop. **Do not spin.**
- **Budget / stall** — as described above; ping once, stop the loop.

## Rules

1. **Never merge.** Never run `gh pr merge`. The human's merges are the only frontier
   advance.
2. **Strict barrier.** Never start a new issue while any pipeline PR (`loop/` or
   `agent/` head branch) is open — verify and fix only.
3. **The merge must stay an informed decision.** Only advertise a PR as mergeable when
   it is verified green (CI ✅, or no-CI + recorded local gate); a red PR is "being
   fixed" or "needs you," never "merge"; security-surface PRs are always flagged
   "review carefully — don't quick-merge."
4. **Fix root causes, capped.** Max 2 ci-fix attempts per PR, counted via marker
   comments; never skip, disable, or relax tests to get green.
5. **Honor the caps.** `--max-open-prs` bounds each wave, `--max-issues` bounds the
   loop, `--max-wait` bounds silence; stop and report when hit.
6. **Correctness over parallelism.** When unsure whether two issues are independent and
   disjoint, serialize them.
7. **Isolate parallel work in worktrees.** Never run two pipelines in the same tree.
8. **Each per-issue run is the `dev-loop` skill in `--non-interactive` mode** — don't
   reimplement the pipeline here.
9. **Single tick, then end.** No internal sleeping or polling — `/loop` owns the
   cadence; terminal classes stop the loop rather than spinning.
10. **Report honestly.** The dashboard must show what was deferred, stopped, capped, or
    blocked; never imply a wave covered issues it skipped.
