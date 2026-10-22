# Two-layer documents: a plain top, a bound body, and proposals for the reasoning

**Status:** Accepted (owner decision 2026-10-22). Governs how every ADR, capability
specification and proposal is written from this date. Amends no earlier ADR.

## Decision

Every ADR, capability specification and proposal has two layers. The top is plain prose that a
customer's auditor can read without the glossary: an ADR's *Decision*, a spec's *Purpose*, a
proposal's *Problem*. The body below it is what binds the loop: claims with IDs, refusals,
constraints. Each fact has one home, and every other document links to it rather than
restating it. An ADR is amended at most once; the next change rewrites it to say what is true
now, and git keeps the history. Reasoning, objections and future work live in
`docs/proposals/`, which never binds anything. Length is a lint: an ADR stays under 150
lines, a spec under 250 beyond its generated proof table, a proposal under 120.

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

## What changes

- **Shape.** An ADR opens with `## Decision`, at most 120 words, then *Why*, *What changes*
  and *Alternatives*. A spec opens with a *Purpose* of at most 120 words and a `**Governed
  by:**` line, then Surfaces, Behaviour, Refusals, Designed (when any), Out of scope, a
  generated Proof block and a one-line-per-ID Retired list. `docs/specs/TEMPLATE.md` and
  `docs/proposals/TEMPLATE.md` are the shapes; `scripts/check-docs.sh` enforces them.
- **One home per fact.** Behaviour lives in the spec. Residual risk lives in the threat
  model's register, which the spec cites by row. Reasoning, rejected alternatives and
  objections live in the proposal the decision came from, which the ADR links. Open questions
  are issues labelled `decision`; future work is a proposal or an issue labelled `idea`.
  Domain language lives in `GLOSSARY.md`, trimmed to terms that carry a distinction the
  product depends on. The rule in `AGENTS.md` that an invariant amendment updates its
  consumers stands: the invariants are a public interface and the threat model maps them.
  Nothing else is mirrored.
- **Amend once, then rewrite.** A second change to an ADR rewrites it as one text that says
  what is true now, keeping its number and title and noting the rewrite date in its Status
  line. A rewrite is a PR a human merges, the same sign-off the original had. A changed
  decision is never slipped into a rewrite: it is the one amendment, or a superseding ADR.
- **Proof is generated.** A test cites the claim it proves in its leading comment. The spec's
  Proof block is produced by `scripts/spec-proof.sh`, `make docs-check` fails on drift, and
  the block lists the claims nothing proves, so nobody maintains that list by hand.
- **The ratchet.** Every document outside these rules on this date is listed in
  `docs/agents/docs-ratchet.txt` with the rule it fails. The PR that touches a listed document
  brings it into shape and removes its line, the rule the invariant gap table already uses.
  The list is the visible backlog, and a document not listed and not in shape fails the lint.
- **A shaping pipeline.** `/propose` grills an idea against the invariants, the ADRs, the
  out-of-realm list and the threat model, records the objections and their answers in the
  proposal, and validates the text with the conflict reviewer and a reader reviewer whose
  only question is whether a human can follow it. Accepted proposals enter the existing chain
  at `/spec-author`. The reader reviewer also runs on every spec and ADR change.

## Alternatives

- **Keep amending in place.** One file holds the whole history and no sign-off is ever
  overwritten. Rejected: the reader has to replay it, and the lint cannot tell a live clause
  from a reversed one.
- **A separate human summary beside each ADR and spec.** Rejected: two sources of truth,
  and the summary drifts the day the body changes. The plain top is part of the document and
  the lint holds its length.
- **Drop claim IDs and the mechanical checks.** The documents would read as prose. Rejected:
  the IDs are the machine interface the loop, the issues and the tests are built on.
- **A big-bang rewrite of every document.** Rejected for the ratchet: it would land one
  unreviewable PR, and the rules would regrow the corpus in two months without the lint.
