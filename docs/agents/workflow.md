# The workflow

How a change moves from an idea to `main` in this repo, and who may touch what at each step.
Every command in `.claude/commands/` and every agent in `.claude/agents/` cites this file rather
than restating it. If a command and this file disagree, this file wins and the command is the bug.

The premise is spec-driven development: **a capability specification says what Relay does,
code follows it, and the loop that writes the code may never rewrite the sentence it is
implementing.** The rest of this file is the machinery that keeps that true when agents do
most of the work.

## The chain

```
an idea (an issue labelled idea, or a sentence)  /propose
  └─ grill, refine, validate; a proposal in the private roadmap
  └─ you accept or reject ──────────────────────► GATE 0  you decide
you edit a spec (co-authored, human-driven)      /spec-author
  └─ /spec-check <spec>       docs-only conflict check; a claims diff; the reader review
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

GATE 0 is optional: a change the owner has already decided enters at `/spec-author`. It is
there for an idea that touches an invariant, an ADR or more than one spec, so the argument is
had once, on the record, and the ADR that follows can be one page (ADR-0046).

Two entries skip the top of the chain:

- **A bug** is an issue, written by hand or by triage, and enters at `/dev-loop`. Bugs never
  get specs (`AGENTS.md`). If the spec described the broken behaviour as correct, that is a
  spec problem and re-enters at the top.
- **A spec found wrong by the loop** — an issue that cannot be implemented without making a
  bound claim untrue — stops the loop, labels the issue `loop:needs-human`, and re-enters at
  `/spec-author`. The loop never resolves it in either direction.

## How to work here

1. **Read before writing.** `GLOSSARY.md`, the capability specification for what you touch,
   then the ADRs governing it. `docs/agents/domain.md` carries the consumer rules; the
   invariants in `AGENTS.md` are the index into `docs/adr/`.
2. **Shape before you spec.** Resolve ambiguity by interrogation, not guessing, and stress-test
   the idea against the codebase and the ADRs first.
3. **Spec, design, decompose, implement**, in the order of the chain above. A capability
   specification is durable, maintained as the capability evolves. An implementation
   specification is a GitHub issue and is disposable: it dies with its PR. Specs and issues name
   modules and contracts, never file paths or code snippets. Bugs never get specs: diagnose and
   fix; if the spec described the broken behaviour as correct, that is an escalation.
4. **Work the current milestone.** GitHub milestones are the authority on what is in flight:
   read them with `gh`. A milestone's acceptance criteria live on its issues; durable behaviour
   lives in the capability specification, never in a planning document. Issues decompose a
   milestone and never redefine one. Do not pull a
   future milestone forward, and do not self-assign one gated on something an agent cannot
   supply.
5. **Contract-first.** Wire or Operation changes start in `/proto`, then regenerate, then
   implement both sides.
6. **Verify before you open a PR.** `make verify` is the gate (`CONTRIBUTING.md`). A skipped
   gate is not a passed gate: say so in the PR body.
7. **Write an ADR** when a decision is hard to reverse, surprising without context, *and* the
   result of a real trade-off: all three. It opens with a `## Decision` of at most 120 words,
   then *Why*, *What changes* and *Alternatives*, at most 150 lines, and links the proposal
   that holds the argument (ADR-0046). It is amended at most once; the next change rewrites it.
   **Promote before the issue closes:** behaviour now true → the spec; a decision → an ADR; the
   reasoning behind it → the decided proposal in `docs/proposals/`; language → `GLOSSARY.md`; a
   change to what must always be true → an invariant, which is a conversation with a human.
   Work agreed in principle but not decided is a proposal in the private roadmap
   (`roadmap: relay/<slug>`) or an issue labelled `idea`; an open question is an issue labelled
   `decision`.
8. **Update `GLOSSARY.md`** in the same change whenever the domain language shifts.
9. **Security posture** is the rule in `AGENTS.md`, *How to work here*.

## Claims and claim IDs

A spec is a set of **claims**: single statements a test can be pointed at. Each carries a
stable ID, `<PREFIX>-<n>`; the prefix is declared once in the spec's header and `n` is never
reused. A design says which claims it delivers, an issue names the claims it implements, a
test names the claim it proves in the comment above it, and `check-docs` verifies the set.
The format is in `docs/specs/TEMPLATE.md`; the rules are in `scripts/check-docs.sh`.

A spec has two layers (ADR-0046): a *Purpose* a stranger can read, and the claims that bind.
Its *Proof* block is generated by `make spec-proof` from the tests that cite its claims, and
ends with the claims nothing proves and the Designed claims a test already cites. Specs still
in the earlier shape are listed in `docs/agents/docs-ratchet.txt`; the PR that next touches
one migrates it and drops its line.

A claim lives in one of two places:

| Section | Means | Who moves a claim in or out |
|---|---|---|
| **Behaviour** / **Refusals** | True of `main` today | You, via `/spec-author`; the loop, only by promoting from Designed |
| **Designed, not built** | Decided, tagged with its milestone, not yet true | You put it there; the loop promotes it when the implementing PR lands |

A spec's `**Status:**` follows: `current as of <date>` when its Designed section is empty and
Behaviour was checked against the code that day; `designed, not built, as of <date>` when the
Designed section has rows. Both bind the loop. The legacy states `aspirational` and `stub` mark
an unmigrated spec: intent only, which the loop treats as context, not a requirement. The
establishing phase ends per spec when its status leaves those states, and for the repo when
none remain. `scripts/spec-coverage.sh --summary` prints the numbers (legacy specs, proof
rows); without the flag it also lists code surfaces no spec names, each a missing claim or
dead weight for a human to decide. It reports and never fails.

## Authority

| Artifact | Written by | The loop may |
|---|---|---|
| An invariant, an ADR, `GLOSSARY.md` | You, co-authored in `/spec-author` | Never touch; escalate |
| A proposal (private roadmap; decided ones copied to `docs/proposals/`) | You, co-authored in `/propose` | Read as context; never cite as authority, never edit |
| Spec: Purpose, Surfaces, Behaviour, Refusals, Designed, Out of scope, Retired | You, co-authored in `/spec-author` | Never edit claim text; promote a claim from Designed to Behaviour when its PR lands; retire exactly the claims its issue's `Retires:` line names |
| Spec: the Proof block, the Status line | The loop, in the implementing PR | Regenerate the block with `make spec-proof`; move the Status date. In a spec still in the earlier shape, add proof rows and never delete one |
| Design doc (`docs/design/plans/`) | `/design`, by PR | Read; `/milestone-close` deletes it |
| Issue | `/decompose`; bugs by hand | Comment, label, branch |
| Code and tests | `/dev-loop`, `/pr-respond` | Everything, on a branch, never on `main` |
| PR | `/dev-loop`, `/pr-respond` | Open, push, reply to comments; never merge |

"Co-authored, human-driven" means what the spec README says: an agent may draft, argue, and
revise, in an interactive session with you present and deciding. An unattended run never
writes any artifact in the first two rows, and stops rather than guessing.

**Retirement decided in advance.** A Designed claim that replaces a Behaviour claim leaves the
old one untrue the moment it is promoted, so the retirement is decided before the work starts:
the issue carries `Retires: <IDs>`, which you approve when you flip it to `loop:ready`. The PR
that promotes the replacement retires exactly those claims, in the same change, and drops the
replacement's "Replaces X when promoted". A replaced claim the line does not name is still an
escalation.

## Reviewers

A second vendor has different blind spots, and a review's value is in what the author did not
see. The Codex allowance is plan quota, not API spend, so Codex is spent once per issue, on the
finished change, not at every gate.

| Gate | Claude | Codex |
|---|---|---|
| Proposal | `proposal-grill`, then `spec-conflict-reviewer` and `reader-reviewer` | — |
| Spec conflicts | `spec-conflict-reviewer`, `reader-reviewer` | — |
| An ADR | `reader-reviewer`, in the `/spec-author` session | — |
| Design | `design-reviewer` | `scripts/codex-review.sh design` — once per plan |
| Issue plan | `devloop-plan-reviewer` | — |
| Code | `devloop-code-reviewer` | — (Claude alone, every cycle) |
| Security surface | `devloop-security-reviewer` | — (Claude alone, every cycle) |
| Final diff, once per issue | — | `scripts/codex-review.sh diff`, or `security` when the surface is touched |

Claude alone does the plan review and every fix cycle; Codex at every gate exhausted the plan
quota in one night (#694). Codex runs ONCE per issue, on the final diff, BEFORE the commit: it
reviews the uncommitted working tree, so a run after the commit would review an empty diff. A
blocking finding buys one fix cycle and one further Codex run, then the issue escalates.
`/pr-respond` gets at most one Codex run after its fixes. The model is `gpt-5.6-terra` by
default, overridable per run with `RELAY_CODEX_MODEL`.

Claude's findings are worked to a close first; Codex's findings are then merged into the same
record. The developer fixes or justifies each one; a finding neither fixed nor justified goes
into the PR body under **Unresolved**, and the PR is labelled `loop:needs-human`. Codex only
reviews, never implements. Because it sits on one gate per issue, its absence leaves the WHOLE
ISSUE single-vendor, and the PR body must say so.

Absence is anything that is not a structured verdict (an exhausted quota, a rejected
credential), decided on the parsed payload, never on message text: `scripts/codex-review.sh`
exits 3 for all of them. Exit 2 (refused before invoking Codex) and exit 1 (a killed run, or a
failed classifier) are failures: escalate, never record as a single-reviewer gate. A recorded
absence carries the script's reason token and the model
(`Codex: absent (reason=<token>, model <slug>)`). The token narrows the cause without settling
it: `reason=no-result` covers both a transient quota exhaustion and a permanent
misconfiguration such as a rejected model slug; only the script's stderr replay, never quoted
into anything durable, says which. A blocking Codex finding is severity `critical` or `high`
in the plugin's output schema.

## The security surface

`docs/agents/security-surface.txt` is the one list of path globs that count as the security
and architecture surface. `scripts/security-surface.sh` reads it. A diff that touches it gets
the security review, a **Security surface** section in the PR body, and never the scope-gate
shortcut. Amend the list, never a copy of it.

## Unattended

Only `/dev-loop-queue` (which runs `/dev-loop --non-interactive`) and `/pr-respond` run on a
schedule. Everything above GATE 3 needs you present. `docs/agents/routines.md` has the
environment, the caps and the `loop:halt` kill switch; both routines check it first.

An unattended run stops, labelling the issue or PR `loop:needs-human` with a comment saying
why, on:

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
