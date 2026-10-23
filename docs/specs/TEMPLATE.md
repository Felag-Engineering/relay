# <Capability name>

**Status:** current as of `<YYYY-MM-DD>`.
**Claim prefix:** `XX`
**Governed by:** ADR-NNNN, ADR-NNNN; invariants n, m.

The Status date says when this spec was last checked against the code, not when it was last
edited. The prefix is two or three capital letters, unique across `docs/specs/`; every claim is
`**XX-n**` and `n` is never reused. *Governed by* lists the ADRs and numbered `AGENTS.md`
invariants that bind this capability, by number only: a change that would contradict one is a
new ADR in front of a human, not a spec edit.

A spec has two layers (ADR-0046). *Purpose* is for a reader with no context: an owner deciding,
or a customer auditing. Everything below it binds the loop. `scripts/check-docs.sh` holds the
shape: the sections below, in this order, nothing else; Purpose at most 120 words; the whole
file at most 250 lines outside the generated Proof block.

## Purpose

What this capability is for, in the user's terms, in at most 120 words. Who reaches for it,
what becomes possible, and what it refuses to be. Plain prose a customer's auditor can read
without the glossary. Not a solution in disguise, and not a description of the code.

## Surfaces

How the capability is reached, per surface: tool names, API operations, Console screens. Name
them; never file paths. If a surface deliberately does not expose it, say so and say why: an
absence a reader cannot distinguish from an oversight will get "fixed".

## Behaviour

What this capability does **today**, on `main`, as **claims**: one statement per bullet that a
test could be pointed at, each with its ID. Say *where* each thing is enforced, because
Relay-side authorization, the blast-radius cap before dispatch and the daemon's live Policy
engine are three different places, and conflating them is how invariant 12 gets violated.
Prose between claims may orient; the claim is the unit.

- **XX-1** <a single statement about what the system does today>
- **XX-2** <another>

If a claim here is not true of the code, one of the two is a bug. A claim *decided but not yet
true* belongs under *Designed, not built*; the loop promotes it when the PR that makes it true
lands.

## Refusals

What this capability refuses, to whom, and what the caller is told. Cover the unhappy paths,
the roles that must be turned away, and every wall a jailbroken AI-agent would hit. A refusal
that does not explain itself sends an agent looking for Raw Exec. Refusals are claims too, with
IDs from the same sequence.

- **XX-3** <what is refused, to whom, and what they are told>

## Designed, not built

Decided, and not yet true of the code. Each row is a claim with an ID from the same sequence
and the milestone that delivers it, so `/decompose` can find it. When the implementing PR
lands, the loop moves the claim into Behaviour or Refusals, same ID and same words, and the
Proof block picks up its test. Omit the section when it has no rows; Status is
`designed, not built, as of <date>` while it has rows and `current as of <date>` once it is
empty.

| Claim | Statement | Milestone |
|---|---|---|
| XX-4 | <what will be true> | <milestone title> |

## Out of scope

What this capability deliberately does not do, and where that work lives instead: another
spec, a proposal in the private roadmap (named as `roadmap: relay/<slug>`), or an issue. A reviewer checks a diff against this
section, and it stops an issue quietly widening the capability. Residual risk is not recorded
here: it lives in the register in `docs/security/threat-model.md`, cited by row where a claim
depends on it.

## Proof

Generated. A test proves a claim by naming the claim's ID in the comment block directly above
the test function (`// Proves XX-1.` in Go; `/// Proves XX-1.` or `// Proves XX-1.` in Rust).
`make spec-proof` rewrites the block below from the tests; `make docs-check` fails while it is
stale. The block ends with the claims nothing proves, which are the testing issue's backlog, and
with any Designed claim a test already cites, which is the loop's cue to promote it. Naming
tests is the one exception to the no-file-paths rule: a test name is stable and verifiable.

<!-- proof:begin -->
| Claim | Proven by | Seam |
|---|---|---|
<!-- proof:end -->

## Retired

Every claim ID that no longer exists, one line each, so a gap in the sequence is explained.
`make docs-check` fails on a gap not listed here. `None.` when nothing has been retired.

- **XX-n** — `<YYYY-MM-DD>` — <replaced by XX-m | dropped, why> (#NNN)
