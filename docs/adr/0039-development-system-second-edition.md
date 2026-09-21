# The development system, second edition

**Status:** Proposed — 2026-09-21. Supersedes the process half of `docs/agents/workflow.md`,
the invariants block and gap table in `AGENTS.md`, and the establishing-phase rules in
`docs/specs/README.md` once accepted. Amends nothing; it replaces.

## Context

Relay is built by one owner and an agentic loop. The first-edition system put five human
gates between a spec edit and a merge, kept fourteen prose invariants with a rule that every
amendment updates every consumer by hand, appended amendments to ADRs instead of superseding
them, and traced spec claims to tests through hand-maintained tables. The 2026-09-20 audit
found what that produces: five ADR back-links missing, a threat model two ADRs behind, an
invariant citing the wrong issue, eighteen of nineteen specs non-binding, and a queue with
zero issues ready because every gate waits on the same person. The machinery was designed
for a team with a compliance function. The cost falls on the owner and the benefit does not.

## Decision

1. **Two human gates.** The owner merges ADRs and merges PRs. Nothing else needs a human.
   A spec, a design plan and an issue are agent-drafted and are approved when their PR
   merges. The `loop:proposed` → `loop:ready` flip is retired; an issue an agent opens is
   ready unless labelled `loop:needs-human`.

2. **A claim is a tagged test.** A capability spec still states claims with stable IDs, but
   the binding artifact is the test that carries the ID in its name or a `// claim: QRY-7`
   comment. Traceability is generated from the tree, never hand-written: a claim with no
   tagged test is listed by the generator, not by a person. A failing tagged test is a spec
   conflict and stops the loop; the loop may edit a claim only in the PR that changes its
   test, and the PR says so. The proof tables, the `spec-proof-updater` agent and the
   "loop may never edit a claim" rule are retired.

3. **ADRs are immutable and short.** Every ADR carries a `Status:` header — `Accepted`,
   `Proposed`, `Not adopted`, or `Superseded by ADR-N` — and a body of one page: context,
   decision as bullets, consequences as bullets. A decision changes only by a new ADR that
   supersedes the old one's header. Amendment sections are never appended again. The index
   and the supersession graph are generated. The existing thirty-eight are consolidated into
   about twelve superseding ADRs and moved to `docs/adr/superseded/` with their numbers, so
   every citation still resolves.

4. **Invariants become Principles plus fitness tests.** The fourteen numbered invariants
   keep their numbers and move into `docs/architecture.md` as a Principles section of one
   sentence each. Every Principle a test can enforce has one — the `no_dispatch` guards are
   the model — and the test's name carries the number. The gap table is retired: a Principle
   without its test, or with a failing one, is the gap, and the generator lists it. The
   "amending is not finished until its consumers are updated" rule is retired with it.

5. **Five living documents.** `docs/architecture.md` (context, containers, the three
   surfaces, the security model, the Principles); the ADR log; `docs/specs/`; `GLOSSARY.md`;
   and the threat register (the R-rows of today's threat model, kept; the boundary map is
   folded into the architecture document). `docs/design/*` retires — the console screens into
   the console spec, the rest to history. `docs/deferred.md` becomes issues. `AGENTS.md`
   shrinks to orientation, language, out-of-realm and the merge rule.

6. **One loop command, one reviewer per gate.** `/dev-loop` takes flags for queue, parallel
   and drive; the three commands merge. Two vendors review only a diff that touches the
   security surface. A docs-only change runs the docs gates only, locally as CI already does.

7. **Where a decision lives.** Anything that touches `/proto`, Policy, authentication,
   transport, labels or the security floor is an ADR first and a spec second. Everything
   else is spec-only. This rule heads `docs/specs/TEMPLATE.md`.

## Consequences

- A wrong spec claim can reach code before the owner reads it. The tagged test is the check:
  the PR that lands it shows the claim and the test together, and the owner reviews both at
  the one gate that remains.
- The invariants' authority does not change; their enforcement moves from prose to tests,
  which is stronger for the eleven that are testable and unchanged for the three that are not
  (9, 14, and the Principle half of 11), which stay prose in the architecture document.
- Migration cost: two agent-days of tooling, one owner session for the Principles text, one
  agent PR per consolidated ADR, and a rewrite of `.claude/commands/` and `docs/agents/`.
  The two specs already migrated convert by tagging their cited tests.
- Ordering: tooling (2) before consolidation (3) before the commands (6), so nothing is
  rewritten twice.
- Reversibility: high. Every retired document stays in git history and in `superseded/`.
