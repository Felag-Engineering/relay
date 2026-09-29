---
description: "Co-author a capability specification, ADR, glossary entry or invariant amendment with the owner in an interactive session. Interrogates, drafts, argues, revises; the human decides. Ends by running /spec-check. Also migrates a legacy spec to the claim format (--migrate)."
argument-hint: "<docs/specs/<capability>.md | adr | glossary | invariant <n>> [--migrate]"
allowed-tools: Bash(*), Read, Edit, Write, Grep, Glob, Agent, AskUserQuestion
---

# Spec authoring session

**Interactive only.** This session co-authors the artifacts that outrank the code:
capability specifications, ADRs, `GLOSSARY.md` entries and invariant amendments. You draft,
argue and revise; **the human decides every claim**, and nothing here is ever run unattended.
If you find yourself without a human answering, stop. See `docs/agents/workflow.md`.

Target: **$ARGUMENTS**.

## Read first

`docs/agents/workflow.md`, `docs/specs/README.md`, `docs/specs/TEMPLATE.md`, `AGENTS.md`
(invariants, gap table, out-of-realm, "Writing or amending an invariant"), `GLOSSARY.md`, and
the target file if it exists. Keep the code out of your context: this session is about intent.
When a question needs the code answered — *is this built? where?* — delegate it to an `Explore`
subagent with a narrow brief and take back only the verdict.

## For a capability spec

1. **Orient.** Read the spec, every spec it names under Out of scope, and the ADRs under
   Governing ADRs. Summarise in ten lines what it says today and what its Open questions are.
2. **Interrogate.** One question at a time, `AskUserQuestion`, multiple-choice where you can.
   Start from the Open questions and from what the owner said they want changed. For each
   answer, say what it changes elsewhere — which other spec, which ADR, which invariant — before
   moving on. A decision that would contradict an invariant or ADR is named as such the moment
   it appears: the amendment lands first, and this session can draft it.
3. **Draft, as claims.** Every behavioural statement is a bullet with the next free ID under the
   spec's prefix. Behaviour and Refusals hold only what is true of `main` today; decided-but-
   unbuilt goes under *Designed, not built* with the milestone the owner names. Never write an
   unbuilt behaviour in the present tense in Behaviour. Never reuse an ID; a retired claim gets
   a line under *Retired*.
4. **Argue.** After the draft, read it back adversarially: the two or three places you think it
   is wrong, over-reaching or inconsistent. Then revise with the owner.
5. **Check.** Run `/spec-check <spec>` and work through its findings with the owner until it
   returns CLEAN. Then `make docs-check`.
6. **Hand off.** Summarise: claims added, changed, moved to Designed, retired; ADRs or
   invariants that must land first; the branch and the suggested PR title. The owner commits
   and opens the PR. You do not.

## `--migrate` — a legacy spec to the claim format

The spec is `aspirational` or `stub`. The job is to sort its statements into today and
designed, give every one an ID, and leave the owner with a spec `check-docs` accepts.

1. Run `/spec-drift <spec>` and read its table: each claim marked built, unbuilt, or unclear.
2. Choose a prefix with the owner (two or three capitals, unused — `grep -h 'Claim prefix' docs/specs/*.md`).
3. Walk the Behaviour and Refusals sections claim by claim. Built → stays, gets an ID. Unbuilt →
   moves to *Designed, not built* with an ID and the milestone the owner names, or to *Future
   work* if there is no milestone. Unclear → ask, or delegate one narrow `Explore` probe.
   Rewrite any "aligned with" or "decided with the owner" trailer into the body; the body is
   the truth and there is no override section.
4. Rebuild the proof table keyed by ID from the existing rows; list the claims with no row.
5. Set Status to `current as of <today>` or `designed, not built, as of <today>`, add the
   prefix line, and run `make docs-check` until it passes.
6. `/spec-check`, then hand off as above.

## For an ADR

Match the surrounding style (`docs/adr/` — long-form, encoding constraints agents check
themselves against). Number sequentially. An amendment is a dated `## Amendment` section in the
existing ADR, never an edit to its Decision. Write the constraint, not the mechanism; write
"where X happens, it happens thus", never "X happens". If the ADR amends an invariant, draft the
`AGENTS.md` edit in the same session, keep the number, and list every consumer the invariant
section names — the threat model, the specs that cite it, `GLOSSARY.md` — as a checklist for the
owner. Never renumber or drop an invariant.

## For a glossary entry

One canonical term, its definition, and the `_Avoid_` line listing rejected synonyms. Grep the
repo for the synonyms and list the files the owner should sweep.

## Never

- Decide a claim the owner has not answered. Draft it as an Open question instead.
- Read the code into this context. Delegate probes.
- Commit, push, or open the PR. The owner does.
- Run unattended.
