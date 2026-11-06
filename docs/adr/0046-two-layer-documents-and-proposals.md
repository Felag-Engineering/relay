# Two-layer documents: a plain top, a bound body, and proposals for the reasoning

**Status:** Accepted (owner decision 2026-10-22); rewritten 2026-11-05. Governs how every ADR,
capability specification, proposal and reference document is written. Amends no earlier ADR.

## Decision

Every ADR, capability specification and proposal has two layers. The top is plain prose that a
customer's auditor can read without the glossary: an ADR's *Decision*, a spec's *Purpose*, a
proposal's *Problem*. The body below it is what binds the loop: claims with IDs, refusals,
constraints. Each fact has one home, and every other document links to it rather than
restating it. An ADR is amended at most once; the next change rewrites it to say what is true
now, and git keeps the history. Reasoning and objections live in decided proposals; undecided
ideas live in the private roadmap. Length is a lint.

## Why

On 2026-10-22 the documentation was 218,000 words against 120,000 lines of product code.
Forty-five ADRs ran to 6,857 lines; fifteen carried two or more amendments, and ADR-0027 had
eleven, so its current decision could only be learned by replaying 570 lines of history. The
spec template had twelve sections, of which the claims, the part the loop and the tests use,
were about a third of each file. Every rule that produced this was reasonable alone: amend
rather than rewrite, update every consumer, keep residual risk beside the behaviour, record
future work where it was noticed. Together they made one fact live in five files and rewarded
each agent run for adding to all five.

The documents serve three readers. The loop needs text it can check: claim IDs, refusals,
invariants. The owner needs to understand a decision well enough to make it. A customer who
audits the repository needs to find the reasoning in one hop and judge it sound. The corpus
had been optimised for the first reader at the cost of the other two, and an auditor reads
amendment chains and five-way duplication as churn, not care.

Relay's repository is public, and its proposals had become a readable roadmap, including
research into competitors, so only decided proposals stay in it.

## What changes

- **Shape.** An ADR opens with `## Decision`, at most 120 words, then *Why*, *What changes*
  and *Alternatives*, at most 150 lines. A spec opens with a *Purpose* of at most 120 words and
  a `**Governed by:**` line, then Surfaces, Behaviour, Refusals, Designed (when any), Out of
  scope, a generated Proof block and a one-line-per-ID Retired list, at most 250 lines beyond
  the Proof block. A proposal stays under 120 lines. `docs/specs/TEMPLATE.md` and
  `docs/proposals/TEMPLATE.md` are the shapes; `scripts/check-docs.sh` enforces them.
- **One home per fact.** Behaviour lives in the spec. Residual risk lives in the threat
  model's register, which the spec cites by row. Reasoning, rejected alternatives and
  objections live in the proposal the decision came from, which the ADR links. Open questions
  are issues labelled `decision`; future work is a roadmap proposal or an issue labelled
  `idea`. Domain language lives in `GLOSSARY.md`. The rule in `AGENTS.md` that an invariant
  amendment updates its consumers stands: the invariants are a public interface and the threat
  model maps them. Nothing else is mirrored.
- **Proposals.** Ideas not yet decided, and the research behind them, live in Felag
  Engineering's private roadmap repository. The public `docs/proposals/` keeps decision
  records only, status `accepted` or `rejected`. A public document refers to a private proposal
  as plain text, `roadmap: <project>/<slug>`, never as a link. `/propose` grills an idea in the
  roadmap; the decided proposal is copied here in the same PR as its ADR.
- **Amend once, then rewrite.** A second change to an ADR rewrites it as one text that says
  what is true now, keeping its number and title. A rewrite is a PR a human merges, the same
  sign-off the original had. A changed decision is never slipped into a rewrite: it is the one
  amendment, or a superseding ADR.
- **Status is status, not provenance.** A Status line says Accepted, Proposed, Deferred or
  Superseded, and nothing about which ADRs amended it. Who amends whom lives in the generated
  index, computed from each amending ADR's own "amends ADR-NNNN". Git keeps the history.
- **Proof is generated.** A test cites the claim it proves in its leading comment. The spec's
  Proof block is produced by `scripts/spec-proof.sh`, `make docs-check` fails on drift, and
  the block lists the claims nothing proves.
- **The ratchet.** Every document outside these rules when a rule is adopted is listed in
  `docs/agents/docs-ratchet.txt` with the rule it fails. The PR that touches a listed document
  brings it into shape and removes its line. The list is the visible backlog, and a document
  not listed and not in shape fails the lint.
- **A shaping pipeline.** `/propose` grills an idea against the invariants, the ADRs, the
  out-of-realm list and the threat model, and validates the text with the conflict reviewer
  and a reader reviewer. Accepted proposals enter the chain at `/spec-author`. The reader
  reviewer also runs on every spec and ADR change.

## Alternatives

- **Keep amending in place.** One file holds the whole history and no sign-off is ever
  overwritten. Rejected: the reader has to replay it, and the lint cannot tell a live clause
  from a reversed one.
- **A separate human summary beside each ADR and spec.** Rejected: two sources of truth,
  and the summary drifts the day the body changes.
- **Drop claim IDs and the mechanical checks.** Rejected: the IDs are the machine interface
  the loop, the issues and the tests are built on.
- **A big-bang rewrite of every document.** Rejected for the ratchet: it would land one
  unreviewable PR, and the rules would regrow the corpus in two months without the lint.

## Amendment (2026-11-05): reference documents have budgets, and no history

Owner decision. The two-layer rule covered ADRs, specs and proposals and left the reference
documents alone; they grew the same way. `AGENTS.md`, loaded into every agent session, was 478
lines; the threat-model register averaged 1,500 characters a row; glossary entries argued their
own history. From this date:

- `AGENTS.md` holds what every session needs, at most 260 lines; procedure lives in
  `docs/agents/` and `CONTRIBUTING.md`.
- A register row in `docs/security/threat-model.md` is at most 900 characters: the risk, who
  accepted it and when, the control, and references.
- A glossary definition is at most 5 lines before its `_Avoid_` line.
- **No history in a reference body.** In `AGENTS.md`, `GLOSSARY.md`, the register and every
  migrated spec, the text says what is true, never when it changed: no amendment dates, no
  "formerly", "no longer" or "previously", and no issue numbers except where a document points
  at open work (the gap table's Tracked column, a register row's references, a spec's Out of
  scope and Retired list). An ADR's Status and Amendment heading keep their dates.

`scripts/check-docs.sh` enforces each budget and the history rule; the ratchet waives a rule
for a document not yet in shape.
