# Autonomous dev-loop

A self-driving development loop for Gleipnir Relay. It turns roadmap milestones
into GitHub issues, implements them one at a time, verifies and adversarially
reviews each change, and **auto-merges the safe ones while escalating anything
that touches the security surface to a human.**

This product is remote-code-execution-as-a-service. The loop is built so that
autonomy can never quietly erode the architecture invariants in
[`../../CLAUDE.md`](../../CLAUDE.md): the merge decision is made by deterministic
code, not by a model that can be argued with.

## The pipeline

```
select → claim → implement → verify → review → GATE → merge | escalate
```

| Step | Who | Cost |
|---|---|---|
| select / claim | `tick.sh` (bash + `gh`) | free |
| implement | sandboxed `claude -p` on a throwaway branch | model: `$CLAUDE_IMPL_MODEL` (sonnet) |
| verify | `make build/test/lint` | free |
| review | `claude -p` → strict-JSON verdict | model: `$CLAUDE_REVIEW_MODEL` (haiku) |
| **gate** | **`gate.sh` — deterministic, no LLM** | free |
| merge / escalate | `tick.sh` (the *only* thing that can merge) | free |

The implement/review subprocesses can edit files and run the build. They **cannot
commit, push, or merge** — the driver owns all git history, and `gate.sh` decides
what is allowed to land.

## The gate (why this is safe without branch protection)

This repo is private on a free plan, so server-side branch protection isn't
available. The gate therefore lives entirely in [`gate.sh`](gate.sh), which a
model never executes. A change is **escalated to a human** (not auto-merged) if
*any* of these hold — deny-beats-allow, mirroring the daemon's own Policy model:

- build/test/lint did not pass;
- any changed file matches a `SECURITY_GLOBS` pattern in [`config.sh`](config.sh)
  — `proto/`, `docs/adr/`, Policy/exec/transport/mTLS/auth code, `CLAUDE.md`,
  `CONTEXT.md`, the `Makefile`, CI, **or the loop's own scripts**;
- the adversarial review reported a high-severity finding;
- the diff is larger than `MAX_AUTO_MERGE_LINES`;
- the implementer left a `DECISION_NEEDED.md` (an architecture call it wouldn't
  make alone).

Everything else — plumbing, registry CRUD, logging, tests — flows through
untouched.

## Cost & billing

On a machine authenticated with a **Claude subscription** (OAuth — no
`ANTHROPIC_API_KEY`), `claude -p` draws from your **plan**, not metered API
billing. There is no per-token dollar charge and no overflow billing path. What
it *does* consume is your plan's **rate-limit budget**, which competes with your
interactive use — so:

- the automated steps use **cheap models** (sonnet/haiku); Opus is reserved for
  you. Override with `CLAUDE_IMPL_MODEL` / `CLAUDE_REVIEW_MODEL`.
- the loop runs **serial, one issue per invocation** (`MAX_TICKS=1`). You set the
  pace via how often the scheduler fires (a nightly cron keeps budget impact low).
- if an `ANTHROPIC_API_KEY` is ever present, the loop **refuses to run** (so it
  can't silently meter you) unless you set `LOOP_ALLOW_API_BILLING=1`.

## Where the human steps in — three seams

1. **Per milestone — approve the issue breakdown.** `decompose.sh` drafts issues
   from the roadmap; you review/edit, then `--apply`. Nothing is created until you
   say so.
2. **Per escalated PR.** You only review PRs the gate flagged `loop:needs-human`
   (security surface, ADR-worthy decisions, failed review). Routine PRs merge
   themselves.
3. **Milestone acceptance.** When the ready queue drains, the loop stops and asks
   for a human acceptance review — several roadmap criteria require *real
   hardware* and can't be self-certified. Then you bump `ACTIVE_MILESTONE` and
   decompose the next one.

## Usage

```bash
# one-time: create loop:* labels and milestones
scripts/dev-loop/bootstrap.sh                 # make loop-bootstrap

# human seam #1: draft issues for the active milestone, review, then apply
scripts/dev-loop/decompose.sh v0.0.1          # make loop-decompose  (draft only)
scripts/dev-loop/decompose.sh v0.0.1 --apply  # create them on GitHub

# run one issue end-to-end (safe to watch); DRY_RUN skips push/merge/relabel
DRY_RUN=1 scripts/dev-loop/loop.sh            # make loop-dry
scripts/dev-loop/loop.sh                       # make loop  (for real)
```

## Kill switch

- Stop new work: remove `loop:ready` from open issues, or just don't fire the
  scheduler. The loop only ever picks up `loop:ready` issues in `ACTIVE_MILESTONE`.
- Stop a scheduled run: delete the cron/routine that calls `loop.sh`.
- A crashed mid-flight tick leaves a `loop:in-progress` label; the next tick
  refuses to start until a human clears it (no double-work on the shared contract).

## Files

| File | Role |
|---|---|
| `config.sh` | all tunables (milestone, security globs, models, caps) |
| `lib.sh` | logging, `gh`/`claude` wrappers, billing guard, `verify` |
| `gate.sh` | **the deterministic merge gate** (unit-testable, no LLM) |
| `tick.sh` | one full iteration; the sole merge authority |
| `loop.sh` | run N serial ticks; the scheduler entry point |
| `bootstrap.sh` | create labels + milestones (idempotent) |
| `decompose.sh` | milestone → draft issues (human-approved) |
| `prompts/` | implement / review / decompose templates |
