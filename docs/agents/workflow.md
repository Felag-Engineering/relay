# The workflow

How a change moves from an idea to `main` in this repo, and who may touch what at each step.
Every command in `.claude/commands/` and every agent in `.claude/agents/` cites this file rather
than restating it. If a command and this file disagree, this file wins and the command is the bug.

The premise is spec-driven development: **a capability specification says what Relay does,
code follows it, and the loop that writes the code may never rewrite the sentence it is
implementing.** The rest of this file is the machinery that makes that hold when most of the
work is done by agents.

## The chain

```
you edit a spec (co-authored, human-driven)      /spec-author
  └─ /spec-check <spec>       docs-only conflict check; a claims diff
  └─ spec PR ───────────────────────────────────► GATE 1  you merge
/design <spec>                                   design doc, adversarially reviewed
  └─ design PR ─────────────────────────────────► GATE 2  you merge; the milestone opens
/decompose <milestone>                           issues, created as loop:proposed
  └─ label flip ────────────────────────────────► GATE 3  you set loop:ready
/dev-loop-queue ► /dev-loop <n>                  unattended: plan, review, implement, verify,
  or /dev-loop-parallel (interactive: up to 3 issues at once, one runner per worktree)
  or /dev-loop-drive (interactive, under /loop: a milestone in waves; never merges)
                                                 review, proof-row update, PR
  └─ PR ────────────────────────────────────────► GATE 4  you review and comment
/pr-respond                                      unattended: address comments, re-verify, push
  └─ merge ─────────────────────────────────────► you merge
/milestone-close <milestone>                     delete the design doc, promote claims, flip
                                                 status; one PR ───────────────► GATE 5  you merge
```

Every gate is a human merge or a human label, because every artifact behind a gate is
permanent. Nothing between gates needs a human, and nothing between gates may act as one.

Two entries skip the top of the chain:

- **A bug** is an issue, written by hand or by triage, and enters at `/dev-loop`. Bugs never
  get specs (`AGENTS.md`). If the spec described the broken behaviour as correct, that is a
  spec problem and re-enters at the top.
- **A spec found wrong by the loop** — an issue that cannot be implemented without making a
  bound claim untrue — stops the loop, labels the issue `loop:needs-human`, and re-enters at
  `/spec-author`. The loop never resolves it in either direction.

## Claims and claim IDs

A spec is a set of **claims**: single statements a test can be pointed at. Each carries a
stable ID, `<PREFIX>-<n>`, where the prefix is declared once in the spec's header and `n` is
never reused. IDs are how the chain stays mechanical: a design says which claims it delivers,
an issue names the claims it implements, a PR's proof rows cite them, and `check-docs` verifies
the whole set. The format is in `docs/specs/TEMPLATE.md`; the rules `check-docs` enforces are
in `scripts/check-docs.sh`.

A claim lives in one of two places:

| Section | Means | Who moves a claim in or out |
|---|---|---|
| **Behaviour** / **Refusals** | True of `main` today | You, via `/spec-author`; the loop, only by promoting from Designed |
| **Designed, not built** | Decided, tagged with its milestone, not yet true | You put it there; the loop promotes it when the implementing PR lands |

A spec's `**Status:**` follows from that: `current as of <date>` when its Designed section is
empty and Behaviour was checked against the code on that date; `designed, not built, as of
<date>` when the Designed section has rows. Both bind the loop. The two legacy states,
`aspirational` and `stub`, mark a spec that has not been migrated: it is intent only, and the
loop treats it as context rather than as a requirement. The establishing phase ends per spec,
when its status leaves those two states, and ends for the repo when none remain.

## Authority

| Artifact | Written by | The loop may |
|---|---|---|
| An invariant, an ADR, `GLOSSARY.md` | You, co-authored in `/spec-author` | Never touch; escalate |
| Spec: Behaviour, Refusals, Designed, Out of scope, Open questions | You, co-authored in `/spec-author` | Never edit claim text; promote a claim from Designed to Behaviour when its PR lands |
| Spec: proof rows, Performance rows, History, the Status line | The loop, in the implementing PR | Add and update; never delete a row without a History line |
| Design doc (`docs/design/plans/`) | `/design`, by PR | Read; `/milestone-close` deletes it |
| Issue | `/decompose`; bugs by hand | Comment, label, branch |
| Code and tests | `/dev-loop`, `/pr-respond` | Everything, on a branch, never on `main` |
| PR | `/dev-loop`, `/pr-respond` | Open, push, reply to comments; never merge |

"Co-authored, human-driven" means what the spec README says: an agent may draft, argue, and
revise, in an interactive session with you present and deciding. An unattended run never
writes any artifact in the first two rows, and stops rather than guessing.

## Reviewers

Two vendors sit where a second model pays for itself, because it has different blind spots and
the value of a review is in what the author did not see — and because the Codex allowance is
plan quota rather than API spend, not every gate, every cycle: Codex is spent once per issue,
on the finished change.

| Gate | Claude | Codex |
|---|---|---|
| Spec conflicts | `spec-conflict-reviewer` | — |
| Design | `design-reviewer` | `scripts/codex-review.sh design` — once per plan |
| Issue plan | `devloop-plan-reviewer` | — |
| Code | `devloop-code-reviewer` | — (Claude alone, every cycle) |
| Security surface | `devloop-security-reviewer` | — (Claude alone, every cycle) |
| Final diff, once per issue | — | `scripts/codex-review.sh diff`, or `security` when the surface is touched |

Five or six Codex runs per issue — the plan review, each code-review cycle, the security
review, and `/pr-respond`'s re-review — exhausted the ChatGPT-plan quota in one night (#694).
Claude alone does the plan review and every fix cycle. Codex runs ONCE per issue, on the final
diff, BEFORE the commit: its review scope is the uncommitted working tree, so a run after the
commit would review an empty diff. A blocking finding buys one fix cycle and one further Codex
run, then the issue escalates. `/pr-respond` gets at most one Codex run after its fixes. Model
`gpt-5.6-terra` by default, overridable per run with `RELAY_CODEX_MODEL`.

Claude's findings are worked to a close first; Codex's single review arrives afterwards, at its
own stage, and its findings are merged into the same record. The developer fixes or justifies
each one; a finding neither fixed nor justified goes into the PR body under **Unresolved**, and
the PR is labelled `loop:needs-human`. Codex is a reviewer only. It never implements, and
because it now sits on only one gate per issue, its absence leaves the WHOLE ISSUE
single-vendor, not one gate of several — the PR body must say so.

Absence is anything that is not a structured verdict — an exhausted usage quota and a rejected
credential both land there — decided on the parsed payload, never on message text:
`scripts/codex-review.sh` exits 3 for all of them. Exit 2 (the script refused before ever
invoking Codex) and exit 1 (a killed run, or a failed classifier) are failures: escalate, never
record as a single-reviewer gate. A recorded absence must carry the script's structural reason
token and the model (`Codex: absent (reason=<token>, model <slug>)`): the token NARROWS the
cause without fully distinguishing it — `reason=no-result` covers both a transient quota
exhaustion and a permanent misconfiguration such as a rejected model slug, and only the
script's own stderr replay, never quoted into anything durable, says which. A blocking Codex
finding is severity `critical` or `high` in the plugin's output schema.

## The security surface

`docs/agents/security-surface.txt` is the one list of path globs that count as the security
and architecture surface. `scripts/security-surface.sh` reads it. A diff that touches it gets
the security review, a **Security surface** section in the PR body, and never the scope-gate
shortcut. Amend the list, never a copy of it.

## Unattended

Only `/dev-loop-queue` (which runs `/dev-loop --non-interactive`) and `/pr-respond` run on a
schedule. Everything above GATE 3 needs you present. `docs/agents/routines.md` has the
environment, the caps and the `loop:halt` kill switch; both routines check it first.

Unattended stops, in every case by labelling the issue or PR `loop:needs-human` with a comment
saying why:

- an issue that is underspecified, or that cites a spec without naming the claims it promotes;
- a change that would make a bound claim, an invariant or an ADR untrue;
- a failed gate after the fix budget;
- a reviewer finding neither fixed nor justified;
- a PR comment that asks a question rather than requests a change;
- a required toolchain missing, or a gate that skipped.

A skipped gate is reported as skipped, never as passed.

## Labels

The `loop:*` lanes in `docs/agents/triage-labels.md`, plus `loop:proposed`: created by
`/decompose`, invisible to the queue until you flip it to `loop:ready`. That flip is GATE 3.
