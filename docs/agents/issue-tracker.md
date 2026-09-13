# Issue tracker: GitHub

Issues and specs for this repo live in GitHub Issues on
[`Felag-Engineering/gleipnir-relay`](https://github.com/Felag-Engineering/gleipnir-relay),
driven through the `gh` CLI.

## Conventions

- **GitHub milestones are the planning spine.** They are human-owned, and they are the
  authority on what is in flight. Issues decompose a milestone; they never redefine one. Don't
  pull future milestones forward. A milestone's acceptance criteria live on its issues; durable
  behaviour lives in the capability specification for that capability.
- **Capability specs are files; implementation specs are issues.** A *capability
  specification* lives at `docs/specs/<capability>.md`, is durable, and is canonical for what
  that capability does across every surface. An *implementation specification* **is** the
  issue, and is disposable — it dies with its PR. The file holds behaviour; the issue holds
  this one change. If a comment on the issue changes a decision, fold it back into the file.
  See `docs/specs/README.md`.
- **Promote before the issue closes.** A closed issue is not a record. Behaviour that is now
  true → the capability spec; a hard-to-reverse, surprising, real-trade-off decision → an ADR;
  a language shift → `GLOSSARY.md`; a change to an architecture invariant → `CLAUDE.md` plus an
  ADR amendment, which is a conversation with a human.
- **Tickets** are one issue each, published in dependency order so blocking edges can
  reference real issue numbers. Use GitHub's native sub-issue relationship where it fits;
  otherwise put a `Blocked by: #NNN` line in the body.

## When a skill says "publish to the issue tracker"

```
gh issue create --title "<title>" --body-file <path> --label <triage-label> [--milestone <milestone>]
```

Apply the triage label from `triage-labels.md`. Set the milestone whenever the work belongs
to one — an issue with no milestone is invisible to milestone-driving skills.

**For a capability specification**, write the file first, then open a short tracking issue
whose body links to it rather than duplicating it:

```
# write docs/specs/<capability>.md from docs/specs/TEMPLATE.md, then:
gh issue create --title "spec: <capability>" \
  --body "Capability spec: [\`docs/specs/<capability>.md\`](docs/specs/<capability>.md) on \`<branch>\`" \
  --milestone "<milestone>"
```

Two documents saying the same thing is how they drift. The link is the point.

**For an implementation specification**, the issue body *is* the spec — write it there. Say
which capability spec it changes, and what it will leave true when it merges.

## Decomposition: which skill

Both of these are **interactive skills run from your own install** — they are not vendored into
this repo, because decomposition needs a human to approve the breakdown. Don't run both on the
same work.

- **`epic-decompose`** — a milestone whose shape is already understood. Milestone →
  self-contained, ~10-minute-reviewable issues. No spec needed.
- **`to-tickets`** — one approved spec → tracer-bullet vertical slices with blocking edges.
  Use this when the work needed shaping, which is why a spec exists at all.

Rule of thumb: if you can write the acceptance criteria without arguing with yourself, use
`epic-decompose`. If you can't, it needed a spec.

## When a skill says "fetch the relevant ticket"

```
gh issue view <number> --json title,body,labels,milestone,comments
```

Read the full body **and** the comments; decisions frequently land in comments rather than
in the original body.

## Merge authority

**No skill, agent, or routine merges anything.** The pipeline always ends by opening a PR
for a human. This is not a style preference — see "How this repo is developed" in
`CLAUDE.md` and the escalation list there. An agent that believes it should merge has
misread its instructions.

## PRs as a request surface

**Off.** External pull requests are not part of the triage queue. Flip this section on if
that changes.
