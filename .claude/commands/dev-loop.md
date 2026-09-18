---
description: "Implement one GitHub issue end to end: plan, adversarial plan review (Claude + Codex), implement, full verify, code review (Claude + Codex), security review when the surface is touched, spec proof update, and open a PR for a human to merge. Never merges."
argument-hint: "<issue-number> [--non-interactive]"
allowed-tools: Bash(*), Read, Edit, Write, Grep, Glob, LSP, Agent
---

# Dev loop

You are the coordinator for one issue: **#$ARGUMENTS**. The stages, the gates and what you may
touch are in `docs/agents/workflow.md`; this file is the order of operations. It **never
merges** — a human is the sole merge authority — and it never edits a spec's claims, an ADR,
`AGENTS.md` or `GLOSSARY.md`.

## Flags

`--non-interactive` (`-y`): unattended. Where a stage would need a human, **comment on the
issue, label it `loop:needs-human`, and STOP.** Interactive mode differs in one way only: it
prints the escalation to you instead of commenting, so you can fix the issue and rerun. The
loop never asks questions in either mode — an issue that needs shaping goes back through
`/decompose` or a hand edit, not through a conversation mid-pipeline.

## Repo context

!git remote get-url origin 2>/dev/null || echo "no remote"
!git branch --show-current
!git status --short

## Shared state

`.dev-loop/` at the repo root: created at the start, **removed at the end, never committed**.
Agents read these files; do not paste their contents into prompts.

- `issue.md` — title, body, and comments (decisions land in comments)
- `plan.md` — the implementation plan
- `review-feedback.md` — every reviewer's findings, per cycle, with what was done about each
- `verify.log` — the last full gate's output

---

## Stage 0 — Setup

`gh auth status` must succeed. `rm -rf .dev-loop && mkdir -p .dev-loop`. Tree clean, `git fetch
origin` done. Dirty tree → stop. On the default branch, or — when a `dev-loop-runner` runs this in
its own worktree — on that worktree's throwaway branch; Stage 2 branches from `origin/<default>`
either way.

**Duplicate guard.** If `git ls-remote --heads origin 'loop/issue-<n>-*'` or
`gh pr list --state open --search "head:loop/issue-<n>-"` returns anything, print
`already started: <ref>` and stop. The queue relies on this.

**Toolchain preflight.** `go`, `cargo`, `buf`, `protoc-gen-go`, `protoc-gen-go-grpc` on `PATH` or in `$(go env GOPATH)/bin` (`make proto-tools` installs
`buf`). Missing → in interactive mode stop and say which lane cannot be verified; unattended,
comment and stop. **Never silently run half the gate.**

## Stage 1 — Fetch

`gh issue view <n> --json title,body,labels,milestone,comments` → `.dev-loop/issue.md` as
`# <title>`, the body, then `## Comments` with each comment dated. Parse and print:

- `Spec:` line and `claims <IDs>` if present; the spec's Status line (`current`/`designed` =
  binding, `aspirational`/`stub` = context only, none = bug or chore);
- `Design:` line if present; `Blocked by:` — any listed issue still open → stop
  (`blocked by #k`); unattended, label `loop:blocked` and stop.

## Stage 1.5 — Triage

Underspecified if **two or more** hold: no acceptance criteria; ambiguous scope ("improve",
"rework"); no trigger or input; no error or edge cases; body under ~50 words. An issue that
promotes claims but names none (`Spec:` without IDs, on a migrated spec) is underspecified on
its own.

Well-specified → Stage 2. Underspecified → list the gaps (comment + `loop:needs-human`
unattended; print them interactively) and stop. The fix is a better issue, not a conversation.

## Stage 2 — Branch

`git checkout -b loop/issue-<n>-<slug> origin/<default>` — under 60 chars, lowercase, hyphens.

## Stage 2.5 — Scope gate

Skip Stages 3 and 4 only if **all** hold: well-specified; the issue names ≤ 2 files; the change
is one function, component or config value; **`scripts/security-surface.sh -` over those paths
exits 1** (exit 2 means the check could not run — a missing glob list — and is a skipped gate,
not a skip-eligible one: escalate as in Stage 3); the issue names no spec claims. On skip, write
a minimal `plan.md` (title, acceptance criteria, files, `Note: scope-gate skip`) and go to
Stage 5.

## Stage 3 — Plan

**Use the `devloop-architect` agent**: read `issue.md`, follow its output format. Write to `plan.md`. A plan beginning `ESCALATE:` → the issue cannot be done
without making a bound claim, an invariant or an ADR untrue: interactive, surface it and stop;
unattended, comment with the claim ID, label `loop:needs-human`, delete the branch, stop.

## Stage 4 — Plan review

**Use the `devloop-plan-reviewer` agent** on `issue.md` + `plan.md`. Record its findings in
`review-feedback.md` under `## Plan review`. (One vendor here: a bad plan is caught again at
code review, where both run, and a Codex pass per plan is cost without coverage.)

Any BLOCKING → `devloop-architect` again with the findings; overwrite `plan.md`. **Max 2
cycles.** A BLOCKING item still standing → escalate as in Stage 3.

## Stage 5 — Implement

**Use the `devloop-developer` agent**: read `issue.md`, `plan.md`, and on a revision cycle
`review-feedback.md`. It never commits, pushes, opens PRs, or edits `docs/specs/`, `docs/adr/`,
`AGENTS.md`, `GLOSSARY.md`. `No changes needed` → print why, delete the branch, stop.

Append its summary to `review-feedback.md` under `## Cycle <c> — Implementation` (`c` starts
at 1).

## Stage 5.5 — Verify: the full gate

```bash
make verify 2>&1 | tee .dev-loop/verify.log     # RELAY_SMOKE_PORT=<port> when running in parallel
```

This mirrors CI gate for gate. If the diff touches `proto/`, `verify-proto` must not have
skipped: grep the log for `skip` notices. **A skipped gate is reported as skipped, never as
passed**, and a proto change with a skipped proto gate is a stop.

Failure → `devloop-developer` with the failure output (fix the root cause; never skip, disable
or relax a test or lint). **Max 2 attempts**, then escalate (interactive: surface; unattended:
comment, label `loop:needs-human`, push the branch as-is with `[WIP]` so the work is not lost,
stop).

Record in `review-feedback.md` under `## Verify`: the command, every lane it covered, and any
lane that skipped.

## Stage 6 — Code review, two vendors

In parallel: **the `devloop-code-reviewer` agent** (reads issue, plan, `review-feedback.md`,
`git diff origin/<default>...HEAD`) and `scripts/codex-review.sh diff`. Merge, deduplicate,
append under `## Cycle <c> — Code review`.

- All clear → Stage 6.5.
- Blocking findings → increment `c`, back to Stage 5 with the findings. **Max 2 review
  cycles.** After cycle 2, every finding neither fixed nor justified in writing goes under
  **Unresolved** in the PR body, and the PR gets `loop:needs-human`. Never proceed silently.
- A reviewer verdict containing `ESCALATE` → escalate as in Stage 3 (the PR still opens, as
  `[WIP]`, so the human sees the diff).

## Stage 6.5 — Security review, when the surface is touched

`scripts/security-surface.sh origin/<default>` prints the matching paths, or nothing.

**Exit 1** (nothing printed) → print `Stage 6.5: no security-surface paths` and continue.
**Exit 2 means the check could not run** — it says why on stderr (a missing glob list, a base
ref that does not resolve, one that cannot be diffed). That is a skipped gate, not a clean
surface: escalate as in Stage 3.

Otherwise, in parallel: **the `devloop-security-reviewer` agent** and
`scripts/codex-review.sh security`. PASS from both → carry the summaries into the PR body.
CONCERNS fixable in scope → Stage 5 once (counts as a review cycle). FAIL, or anything that
would need an invariant or ADR to change → escalate as in Stage 3; the PR opens as `[WIP]`.
The PR body gets a **Security surface** section listing the paths and why each changed.

## Stage 6.6 — Spec proof

If the plan's `Spec:` line names a spec: **use the `spec-proof-updater` agent** with the spec
path, the issue, the claim IDs, and the diff. It adds proof rows, promotes only the named claims
the diff tests (same ID, same words), appends History, moves Status, and runs `make docs-check`.
Its **Findings** go into the PR body. A claim it did not promote for lack of a test is a
finding, not a failure — the human decides whether the PR is complete.

If the diff shifts the domain language or a convention `AGENTS.md` records, do not edit
`GLOSSARY.md` or `AGENTS.md`: note it under **Escalations** in the PR body. READMEs the diff
makes stale may be updated.

If a spec changed, re-run `make docs-check`; if any buildable file changed since Stage 5.5,
re-run `make verify`.

## Stage 7 — Commit and open the PR

Stage the files the plan and Stage 6.6 touched by name — never `git add -A`, never `.dev-loop/`.

```
<type>(<area>): <issue title>

<two lines: what became true, which claims>

Closes #<n>
<the attribution line the session requires>
```

`git push -u origin <branch>` then `gh pr create`, title `<type>(<area>): <issue title>`, body:

- `Closes #<n>`; **Spec** and **Claims** (promoted; not promoted and why); **Design** step
- **Verification**: the exact gate, every lane, every skipped lane, and whether CI was relied on
- **Reviews**: plan (Claude), code and security (both vendors) — verdicts, cycles used, or
  "Codex: absent"
- **Security surface** section, if Stage 6.5 ran
- **Unresolved** and **Escalations**, if any (and the `loop:needs-human` label)
- the plan in a `<details>` block; a line that this was produced by the dev-loop and **must be
  merged by a human**; the attribution line the session requires.

`rm -rf .dev-loop`. Print: issue, PR URL, cycles, skipped lanes, security surface yes/no,
escalations.

## Rules

1. **Never merge.** 2. **Do not skip stages** except the scope gate and the two early exits.
3. **Use the named agents**; do not do their work yourself. 4. **Pass context by file.**
5. **Only the coordinator touches git.** 6. **Respect scope**: only files the plan names.
7. **Stop on errors** rather than improvise. 8. **A spec's claims, an ADR, an invariant, the
glossary: never yours to change.** Escalate with the ID.
