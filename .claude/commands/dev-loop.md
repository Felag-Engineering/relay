---
description: "Pull a GitHub issue, architect a solution, review the plan adversarially, implement it, build/lint/test, security- and code-review it, and open a PR for a human to merge."
argument-hint: "<issue-number> [--non-interactive]"
allowed-tools: Bash(*), Read, Edit, Write, Grep, Glob, LSP, Agent, AskUserQuestion
---

# Agentic Development Loop

You are a development pipeline coordinator. Execute the following pipeline for
GitHub issue **#$ARGUMENTS**.

This loop **never merges.** It always ends by opening a PR for a human to review
and merge — the human is the sole merge authority. Do not run `gh pr merge`.

## Flags

Parse `$ARGUMENTS` for the issue number and optional flags:

- `--non-interactive` (or `-y`) — **unattended mode.** Never call `AskUserQuestion`
  or otherwise block on the user. If a stage would need a human decision (an
  underspecified issue in triage, an architecture invariant that would be violated),
  **post a comment on the issue explaining what's needed and STOP** instead of
  asking. This is the mode for `/loop /dev-loop <n> --non-interactive` and for the
  driver command running you in parallel.

## Current repo context

!git remote get-url origin 2>/dev/null || echo "no remote"
!git branch --show-current
!git status --short

---

## Shared state

All pipeline artifacts go in `.dev-loop/` at the repo root. It is created at the
start and **removed at the end**, and is **never committed** (Stage 7 stages
specific files only). If the repo does not already ignore it, that is fine — it is
transient scratch.

- `.dev-loop/issue.md` — the canonical issue body (Stage 1, maybe rewritten in 1.5)
- `.dev-loop/context.md` — codebase exploration notes (Stage 1.5, reused by the architect)
- `.dev-loop/plan.md` — the architecture plan (Stage 3, maybe revised in Stage 4)
- `.dev-loop/review-feedback.md` — accumulated review feedback across cycles
- `.dev-loop/refined-spec.md` — refined issue spec from brainstorming (1.5, if triggered)

These files are the source of truth for passing context between agents. When a stage
says "pass the plan", tell the agent to **read `.dev-loop/plan.md`** — do not paste
file contents into agent prompts.

---

## Pipeline

Execute these stages **in order**. Report a clear status line after each one.

### Stage 0 — Setup

Verify `gh auth status` succeeds. If not, stop immediately and tell the user.

Then reset the workspace and confirm a clean tree on the default branch:

```bash
rm -rf .dev-loop && mkdir -p .dev-loop
git status --short    # must be clean apart from intentional local files; if dirty, stop and ask
```

### Stage 1 — Fetch issue

`gh issue view <issue-number> --json title,body,labels,assignees`. Parse the issue
number from `$ARGUMENTS` (ignore trailing flags). Write the issue to
`.dev-loop/issue.md`:

```
# <title>

<body>
```

All later stages read the issue from this file. Print the title and a short summary.

### Stage 1.5 — Issue triage

An issue is **underspecified** if **2 or more** of these hold:

1. No acceptance criteria (no bullets/checkboxes/"should" statements for the done-state)
2. Ambiguous scope ("improve", "better", "rework" without concrete changes)
3. Missing trigger/input (doesn't say what drives the behavior)
4. No error/edge-case consideration
5. Single-sentence body (under ~50 words excluding boilerplate)

Print which criteria matched and your verdict (`well-specified` / `underspecified`).

**Well-specified** → Stage 2.

**Underspecified + `--non-interactive`** → do **not** brainstorm. Post a comment on
the issue listing the matched gaps and what's needed to make it actionable, then
STOP the pipeline (no branch, no PR). An unattended run must never block on a
question.

**Underspecified (interactive)** → brainstorm, then Stage 2:

1. **Explore the codebase first** (read `AGENTS.md`/`GLOSSARY.md` and related files)
   so your questions are informed. Persist findings to `.dev-loop/context.md`.
2. Summarize what's clear.
3. Ask clarifying questions **one at a time** with `AskUserQuestion` (max 5; stop
   when the spec is clear). Prefer multiple-choice.
4. Propose a refined spec: summary, acceptance-criteria checklist, scope boundaries
   (in/out), error/edge cases. Write it to `.dev-loop/refined-spec.md`.
5. Get user approval.
6. Update the issue: `gh issue edit <issue-number> --body-file .dev-loop/refined-spec.md`
7. `cp .dev-loop/refined-spec.md .dev-loop/issue.md`

### Stage 2 — Create branch

```bash
git fetch origin
DEFAULT=$(git symbolic-ref --short refs/remotes/origin/HEAD 2>/dev/null | sed 's#origin/##' || echo main)
git checkout -b loop/issue-<issue-number>-<slugified-title> origin/$DEFAULT
```

Keep the branch name under 60 chars, lowercase, hyphens only.

### Stage 2.5 — Scope gate (skip architect + plan-reviewer on trivial issues)

Skip Stages 3 and 4 and go to Stage 5 only if **all** hold:

1. Triage returned `well-specified`.
2. The issue names the file(s) to modify (≤ 2 files).
3. The change is localized (one function/component/config value) — not cross-cutting,
   not a new feature, and **does not touch the security surface** (see Stage 6.7).

On skip, write a minimal `.dev-loop/plan.md`:

```
IMPLEMENTATION PLAN
===================
Issue: <title>
Summary: <copy the acceptance criteria>
Affected files: <paths from the issue>
Note: scope-gate skip — no architect pass.
```

Print: `✅ Stage 2.5: scope gate matched, skipping architect/plan-reviewer.`
Otherwise proceed to Stage 3.

### Stage 3 — Architect

**Use the `devloop-architect` agent.** Pass it: read the issue from
`.dev-loop/issue.md`; if `.dev-loop/context.md` exists, read it as a starting point;
follow its output format exactly. Do not restate AGENTS.md — the agent reads it
itself. Write its output to `.dev-loop/plan.md`.

### Stage 4 — Plan review (adversarial)

**Use the `devloop-plan-reviewer` agent.** Pass it: read the issue and
`.dev-loop/plan.md`; verify claims against the codebase (prefer LSP).

- **APPROVE** → Stage 5.
- **REVISE** → run `devloop-architect` again (read issue + current plan + the
  reviewer's corrections; produce a revised plan). Overwrite `.dev-loop/plan.md`,
  then Stage 5.

### Stage 5 — Implement

**Use the `devloop-developer` agent.** Pass it: read the issue from
`.dev-loop/issue.md`; read the plan from `.dev-loop/plan.md`; on a revision cycle,
read `.dev-loop/review-feedback.md`. Emphasize: code is written for humans; obey the
repo's AGENTS.md/GLOSSARY.md invariants and ubiquitous language; **do not run
`git commit`/`git push`/`gh pr create`**; end with a `## Implementation Summary`.

If the developer returns `No changes needed`, stop the pipeline, print the
explanation, and exit — no branch commit or PR.

Append the implementation summary to `.dev-loop/review-feedback.md` under
`## Cycle <cycle> — Implementation` (initialize `cycle = 1` on first entry here).

### Stage 5.5 — Verify locally (the full gate — this is now the merge gate)

Reviewers must read **green** code — and since CI may be unavailable (quota/offline),
this local run is the *only* thing verifying the PR before a human merges it. So run the
**full** suite CI would run, not a subset.

1. **Toolchain preflight.** Confirm the toolchains the full gate needs are on `PATH` —
   derive the list from the gate itself (the `verify` target's lanes, or the CI
   workflow jobs; e.g. for Gleipnir: `go`, `node`/`npm`, `sqlc`, `buf`). If a required
   one is missing, **stop** and tell the user which lane can't be verified. Never
   silently skip half the suite and call it green.

2. **Run the repo's full pre-merge gate:**
   ```bash
   make verify
   ```
   `verify` mirrors the PR CI jobs (build + lint/format + race tests + daemon tests +
   integration + cross-binary). **If the repo has no such aggregate target,** enumerate
   what its CI actually runs from `.github/workflows/*.yml` and run every one of those
   `make`/toolchain commands locally — do **not** settle for `make test` if CI also runs
   race / integration / cross-binary / lint jobs. Only if there is no CI workflow to
   mirror, fall back to `make build && make lint && make test`.

3. **Proto drift (conditional):** if the diff touches `/proto`, also run
   `make proto-tools && make proto-check` (needs `protoc`; if it's missing, **stop** and
   say so — a proto change must not go out unverified).

If any step fails, **use the `devloop-developer` agent** to fix the root cause (pass the
failure output inline; do not skip/disable/relax tests or lints; do not commit). Re-run
the gate. **Max 2 fix attempts**; if it still fails, stop and surface it to the user (or,
in `--non-interactive` mode, comment on the issue and stop).

Record in `.dev-loop/review-feedback.md` **exactly which gate ran and that it passed** —
the command and the lanes it covered (e.g. "`make verify` ✅ — build, lint, race,
daemon, integration, cross-binary"). Stage 7 copies this into the PR body as the
local-verification signal the human merges on.

### Stage 6 — Code review

**Use the `devloop-code-reviewer` agent.** Pass it: read the issue, the plan, and
`.dev-loop/review-feedback.md`; start from `git diff`; verify each planned change;
verify the repo's declared invariants; readability is the top priority.

- **APPROVE** → Stage 6.5.
- **CHANGES_REQUESTED** → append feedback under `## Cycle <cycle> — Review Feedback`,
  increment `cycle`, go back to Stage 5.
- **Max 2 review cycles.** If cycle 2 still requests changes, log a warning and
  proceed to Stage 6.5 anyway.

### Stage 6.5 — Docs freshness

Check whether the change shifts anything the project docs must track. Update in the
same PR if so:

- **`GLOSSARY.md`** — if the domain/ubiquitous language shifted (new or changed term).
- **`AGENTS.md`** — if conventions, layout, commands, or settled decisions changed.
- Any area-specific docs the repo keeps current (READMEs, ADR back-references).

**`docs/specs/` is different — never edit a capability specification.** They are human-authored,
deliberately and interactively (`docs/specs/README.md`); the loop reads them and complies with
them. If this change makes any statement in the governing spec untrue, do **not** update the
spec and do **not** proceed quietly: name the false statement under Escalations in the PR body
and stop. A human updates the spec first, and the code follows.

If nothing needs updating, print: `Stage 6.5: project docs are current; capability spec still
true.`

### Stage 6.6 — Security review (when the security surface is touched)

Run `git diff --name-only`. If the change touches the repo's security/architecture
surface (for this project: `proto/`, `docs/adr/`, Policy/exec/transport/mTLS/auth
code, `AGENTS.md`, `GLOSSARY.md`, the `Makefile`, or CI/workflow config), **use the
`devloop-security-reviewer` agent** for a dedicated adversarial pass focused on the
repo's declared security invariants. Pass it: read the issue, the plan, and
`AGENTS.md`/`GLOSSARY.md`/relevant ADRs; start from `git diff`; assume the change is
unsafe until proven otherwise.

- **PASS** → proceed; carry its summary into the PR body.
- **CONCERNS / FAIL** → if the finding is fixable in scope, loop back to Stage 5 with
  the findings (counts as a review cycle). If it would require violating or amending a
  declared invariant, **stop and surface it to the user** (interactive) or **comment
  on the issue and stop** (`--non-interactive`) — never design around an invariant.

If the diff does not touch the security surface, print:
`Stage 6.6: no security-surface changes — skipping security review.`
(Optionally still run a lightweight pass for execution-adjacent changes.)

### Stage 6.7 — Security-surface check

Inspect `git diff --name-only`. If the change touches the repo's security/architecture
surface — for this project that means any of: `proto/`, `docs/adr/`, Policy/exec/
transport/mTLS/auth code, `AGENTS.md`, `GLOSSARY.md`, the `Makefile`, or CI/workflow
config — then:

- Do **not** treat the PR as routine. Add a prominent **⚠️ Security surface** section
  to the PR body listing exactly which sensitive paths changed and why.
- If the change would alter a declared architecture invariant, you should already have
  stopped earlier; if it surfaced only now, halt and surface it to the user before
  opening the PR.

This loop never auto-merges regardless; this step ensures the human reviewer's
attention is aimed at the sensitive parts.

### Stage 7 — Commit and open the PR

1. **Re-verify only if code changed after Stage 5.5** (a review/security loop-back, or
   doc edits that touch buildable files). If anything changed since the last green
   gate, re-run the **full gate** (`make verify`, per Stage 5.5) and fix via the
   `devloop-developer` agent (max 2 attempts) before committing. If nothing changed
   since Stage 5.5, the tree is already green — proceed.

2. **Commit** (stage specific files, never `git add -A`, never stage `.dev-loop/`):

   ```bash
   git add <file1> <file2> ...
   git commit -m "feat: <issue-title> (#<issue-number>)

   Implemented via the agentic dev-loop.

   Closes #<issue-number>
   Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
   ```

3. **Push and open the PR (do not merge):**

   ```bash
   git push -u origin <branch-name>
   gh pr create --title "feat: <issue-title>" --body "<pr-body>"
   ```

   PR body includes: `Closes #<issue-number>`; a brief summary; the plan in a
   `<details>` block; review cycles used; whether docs were updated; a
   **✅ Local verification** line naming the exact gate that passed and the lanes it
   covered (e.g. "`make verify` — build, lint, race, daemon, integration,
   cross-binary") and noting whether CI was relied on — this is the signal a human
   merges on when CI is unavailable; the security review verdict (Stage 6.6) if it ran;
   the **⚠️ Security surface** section from Stage 6.7 if it applies; and a note that this
   was generated by the dev-loop and **must be merged by a human**.

4. **Clean up:** `rm -rf .dev-loop`.

Print a final summary: issue number, PR URL, review cycles used, whether
brainstorming fired, and whether the change touches the security surface.

## Rules

1. **Never merge.** Open the PR; a human merges. Do not run `gh pr merge`.
2. **Do not skip stages** except where explicitly allowed (Stage 2.5 scope gate,
   Stage 5 "no changes needed" exit). No other shortcuts.
3. **Use the named agents** (`devloop-architect`, `devloop-plan-reviewer`,
   `devloop-developer`, `devloop-code-reviewer`). Don't do their work yourself.
4. **Report progress** after each stage (e.g. `✅ Stage 3 complete: plan produced`).
5. **Stop on errors** — `gh` unauthenticated, dirty tree, build catastrophically
   failing, git failures: stop and tell the user.
6. **Respect scope.** Only change files the plan identifies. No unrelated refactors.
7. **Pass context by file, not by pasting.** Agents read `.dev-loop/*.md`.
8. **Only the coordinator touches git.** The developer agent never commits, pushes,
   or opens PRs.
9. **Honor the repo's AGENTS.md/GLOSSARY.md and architecture invariants** at every
   stage. When a change would touch a declared invariant, stop and flag a human
   rather than design around it.
