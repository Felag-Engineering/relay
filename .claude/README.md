# Agent workflow

The minimum a **scheduled cloud routine** needs, committed because a routine gets a fresh clone
and sees only what is in the tree. Anything living in `~/.claude` does not exist as far as an
unattended run is concerned.

```
commands/dev-loop-queue.md   what a routine runs: one loop:ready issue per tick, no merge waiting
commands/dev-loop.md         the pipeline it invokes, in --non-interactive mode
agents/devloop-*.md          the five subagents dev-loop dispatches to
```

`worktrees/` and `settings.local.json` stay ignored: local state, not product.

## Deliberately minimal

This directory holds only what is reachable from a scheduled run. `/dev-loop` grants no `Skill`
tool and names no skill, and the subagents get `Read, Grep, Glob, Bash, LSP` only — so an
authoring skill in the tree would be unreachable weight an unattended agent still reads. In a
repo that ships remote code execution, fewer instruction files on the agent's path is the safer
default.

Two things are therefore **not** vendored:

- **`/dev-loop-drive`** — the wave driver. It gates each wave on human merges and stalls when
  nobody is there, which is the whole reason `dev-loop-queue` exists. Interactive use only.
- **The authoring skills** (`to-spec`, `to-tickets`, `grill-with-docs`, `tdd`, `triage`, …) from
  [`mattpocock/skills`](https://github.com/mattpocock/skills). Shaping and specifying are
  interactive acts that need a human to interrogate; they run at your desk, from your own
  install. Add them here only if you intend to start ad-hoc cloud sessions that use them.

## Repo-specific configuration

Configuration lives in `docs/agents/`, not here — `routines.md` for how a scheduled run operates
(environment, caps, the `loop:halt` kill switch), `triage-labels.md` for the label vocabulary
`dev-loop-queue` depends on, plus the issue-tracker and domain-doc rules.

## Operating rule

Nothing here merges. Every tick ends at an open PR, and `loop:halt` on any open issue stops the
next tick before it takes work.
