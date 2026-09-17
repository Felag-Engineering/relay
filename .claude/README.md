# Agent workflow

The minimum a **scheduled cloud routine** needs, committed because a routine gets a fresh clone
and sees only what is in the tree. Anything living in `~/.claude` does not exist as far as an
unattended run is concerned.

```
commands/dev-loop-queue.md   routine: one loop:ready issue per tick, no merge waiting
commands/pr-respond.md       routine: address human review comments on an open loop PR
commands/dev-loop.md         the pipeline the queue invokes, in --non-interactive mode
commands/spec-author.md      interactive: co-author a spec, ADR, glossary entry or invariant
commands/spec-check.md       interactive: docs-only conflict check for a changed spec
commands/spec-drift.md       interactive: classify a spec's claims as built or unbuilt
commands/design.md           interactive: design plan from Designed claims, two-vendor reviewed
commands/decompose.md        interactive: merged plan → loop:proposed issues
commands/milestone-close.md  interactive: delete the plan, flip the spec's Status
agents/devloop-*.md          the five subagents dev-loop and pr-respond dispatch to
agents/design-*.md           the design architect and its adversarial reviewer
agents/decomposer.md, spec-conflict-reviewer.md, spec-proof-updater.md
```

The chain these form, and who may touch what, is `docs/agents/workflow.md`.

`worktrees/` and `settings.local.json` stay ignored: local state, not product.

## What is vendored, and why

Everything on the chain in `docs/agents/workflow.md` lives here, because a cloud routine sees
only the tree. The two unattended commands (`dev-loop-queue`, `pr-respond`) grant no `Skill`
tool and no `AskUserQuestion`; the interactive ones (`spec-author`, `design`, `decompose`,
`milestone-close`) do, and are never scheduled. Subagents get the narrowest tool set their job
needs — reviewers cannot edit, the developer cannot commit, the proof updater can edit only a
spec's evidence rows.

Codex is the second reviewer on the design, code and security gates, reached through
`scripts/codex-review.sh`, read-only. When the plugin is absent the gate runs single-vendor and
says so.

## Repo-specific configuration

Configuration lives in `docs/agents/`, not here — `routines.md` for how a scheduled run operates
(environment, caps, the `loop:halt` kill switch), `triage-labels.md` for the label vocabulary
`dev-loop-queue` depends on, plus the issue-tracker and domain-doc rules.

## Operating rule

Nothing here merges. Every tick ends at an open PR, and `loop:halt` on any open issue stops the
next tick before it takes work.
