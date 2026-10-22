---
description: "Docs-only conflict check for a changed capability specification: template shape, glossary, invariants and ADRs, the other specs, the threat model. Emits a claims diff. Never reads the code."
argument-hint: "<docs/specs/<capability>.md> [--base <ref>]"
allowed-tools: Bash(*), Read, Grep, Glob, Agent
---

# Spec check

Verify that a changed capability specification agrees with itself and with every document that
outranks or neighbours it, **without loading the codebase.** Whether the code agrees is
`/spec-drift`'s job. See `docs/agents/workflow.md`.

Target: **$ARGUMENTS** (a spec path; `--base <ref>` defaults to `origin/main`).

## Stage 1 — Mechanical

```bash
make docs-check
```

Failures here are reported verbatim and fixed by the owner before anything else; do not proceed
past a red mechanical gate.

## Stage 2 — Claims diff

Against the base ref, list every claim ID that is **added**, **changed** (same ID, different
words), **moved** (Behaviour ↔ Designed), or **removed**. Use `git diff <base> -- <spec>` and
the ID pattern `**<PREFIX>-<n>**` / table rows `| <PREFIX>-<n> |`. For a legacy spec with no
IDs, list changed statements instead and say the spec is unmigrated.

Write the diff to `.spec-check/claims-diff.md` (transient, never committed) in this shape —
`/design` reads it:

```
CLAIMS DIFF  <spec>  <base>..HEAD
Added:    <ID> — <statement>
Changed:  <ID> — <before> → <after>
Moved:    <ID> — Designed → Behaviour | Behaviour → Designed
Removed:  <ID> — <statement>
```

## Stage 3 — Semantic

**Use the `spec-conflict-reviewer` agent.** Pass it the spec path and the base ref. It reads
only docs; it must never open `relay/`, `daemon/` or `proto/`. Take its report as-is.

**Then the `reader-reviewer` agent**, same inputs, in parallel with the first. It reads the
spec as the human it is for and says whether the plain top can be followed, whether a fact is
restated that has a home elsewhere, and whether the file is inside its budget (ADR-0046).

## Stage 4 — Report

```
SPEC CHECK  <spec>
Mechanical: pass | fail (<n> findings)
Claims diff: +<a> ~<c> ↔<m> −<r>   (.spec-check/claims-diff.md)
Semantic:  CLEAN | REVISE | BLOCKED
Reader:    READS | REVISE
<the reviewers' reports>
```

A reader verdict of `REVISE` is `REVISE` for the whole check.

`BLOCKED` means an invariant, ADR or gap-table issue must land first. Say which, and stop; the
owner takes it to `/spec-author`. `REVISE` lists what to fix in the spec. `CLEAN` means the
owner may open the PR.

## Never

- Read the code. If the reviewer or you want to know whether a claim is built, that is
  `/spec-drift`.
- Edit the spec. Report; the owner edits (with `/spec-author`).
- Resolve a conflict with an ADR or invariant in either direction.
