---
description: "Shape an idea into a decision with the owner: grill a proposal in the private roadmap against the invariants, ADRs and threat model, record each objection and the owner's answer, validate the text with the conflict and reader reviewers, and hand an accepted proposal to /spec-author. Interactive only."
argument-hint: "<roadmap proposal path | #issue | \"<the idea in a sentence>\">"
allowed-tools: Bash(*), Read, Edit, Write, Grep, Glob, Agent, AskUserQuestion
---

# Propose

**Interactive only.** This session moves an idea from `idea` to `accepted` or `rejected` by
arguing it with the owner. You draft the proposal, run the grill, put each objection to the
owner, record the answers, and validate the text. **The owner decides.** If you find yourself
without a human answering, stop. See `docs/proposals/README.md` and `docs/agents/workflow.md`.

**Where proposals live.** An undecided proposal lives in Felag Engineering's private roadmap
repository, never in this public one (ADR-0046, amended 2026-10-22): Relay's are in its `relay/`
folder, normally checked out beside this repository at `../roadmap`. If it is not there, ask the
owner for the path and stop if there is none. A decided proposal is copied into `docs/proposals/`
in the same PR as its ADR.

Target: **$ARGUMENTS**: a proposal file, an issue labelled `idea`, or the idea in a sentence.

## Read first

`docs/how-relay-works.md`, the roadmap's `README.md`, `TEMPLATE.md` and `relay/README.md`,
`AGENTS.md` (invariants, gap table, out-of-realm), `docs/adr/README.md`, the other proposals in
the roadmap's `relay/proposals/`, and the decision records in `docs/proposals/`, so an idea
already decided is not re-argued. Keep the code out of your context; when a question
needs the code answered, delegate one narrow `Explore` probe and take back only the verdict.

## Steps

1. **Draft or load.** If the target is a sentence or an issue, write the proposal in the
   roadmap's `relay/proposals/`, list it in `relay/README.md`, and follow the roadmap's template: Problem in three sentences, Proposal in a paragraph, Changes by name, Objections
   empty, status `shaping`. If it is a file, set its status to `shaping`. Read it back to the
   owner in five lines and confirm it is the idea they meant before anything else.
2. **Grill.** Run the `proposal-grill` agent on the file. It reads only docs and returns
   numbered objections. If it finds an out-of-realm collision, put that to the owner first
   and alone: a yes ends the session with status `rejected` and the list as the authority.
3. **Refine.** Put each objection to the owner, one at a time, `AskUserQuestion` where the
   answer is a choice. Record every answer under *Objections* against the grill's number, in
   the owner's terms, or `open` if they defer it. Revise Problem, Proposal and Changes as the
   answers move them. Where an answer needs an ADR amended, an invariant amended or a
   gap-table issue, say so the moment it appears and add it to *Changes*.
4. **Grill again** if the proposal changed shape. One more round; a proposal that needs a
   third has become two proposals, so split it.
5. **Validate.** Run the `spec-conflict-reviewer` on the proposal (it reads it as a document
   that must agree with the specs and ADRs it names) and the `reader-reviewer`. Fix what they
   find; a reader verdict of `REVISE` is fixed before the owner decides.
6. **Decide.** Ask the owner: accept, reject, or leave `shaping`. Accepted: add *Outcome*
   naming the milestone if one exists, set the status, and hand off to `/spec-author` for the
   ADR and the Designed claims; the ADR links this file and the *Outcome* is updated with the
   ADR number when it lands, and the decided proposal is copied into this repository's
   `docs/proposals/` in the ADR's PR. Rejected: add *Outcome* with who decided and why; copy it
   here only if the rejection is worth explaining publicly. Run the roadmap's
   `scripts/check.sh`, and `make docs-check` here when a decision record was copied.
7. **Hand off.** Summarise: the decision, the objections still open, the ADRs and specs
   `/spec-author` will touch, and the branches. The owner commits in both repositories and
   opens the PR. You do not.

## Never

- Decide an objection the owner has not answered. Record it as `open`.
- Write a spec claim or an ADR here. That is `/spec-author`, after the decision.
- Put an undecided proposal, or research behind one, in this public repository.
- Reopen an item on the out-of-realm list or a `rejected` proposal without the owner saying
  so in this session, and then only by recording why the authority no longer holds.
- Read the code into this context. Delegate probes.
- Commit, push, or open the PR. The owner does.
- Run unattended.
