---
description: "Classify each claim of a capability spec as built, unbuilt or unclear by probing the code through narrow Explore subagents, so the coordinator's context stays small. Used to migrate legacy specs and before /design."
argument-hint: "<docs/specs/<capability>.md>"
allowed-tools: Bash(*), Read, Grep, Glob, Agent
---

# Spec drift

For every claim in the spec, answer one question: **is this true of the code on this branch
today?** The answer comes from `Explore` subagents given one narrow brief each; you read only
their verdicts, never the code. See `docs/agents/workflow.md`.

Target: **$ARGUMENTS**.

## Steps

1. Read the spec. Extract every claim from Behaviour, Refusals and *Designed, not built* (or,
   for a legacy spec, every behavioural sentence in those sections — number them `L1, L2 …` for
   this run). Note the proof row each already has, if any.
2. Group the claims into batches of five to eight by surface or mechanism. For each batch,
   launch one `Explore` agent in parallel with this brief:

   > For each claim below, say **built**, **unbuilt** or **unclear**, with one line of evidence:
   > the symbol or test that implements or asserts it, or the absence you looked for. Search
   > `relay/` and `daemon/` and the existing test names cited. Do not read more than you need;
   > do not review or judge the design. Claims: <the batch, with IDs>.

3. Where a claim already cites a test, ask the agent to confirm the test asserts *that* claim
   and not a neighbour.
4. Assemble the table. Do not resolve *unclear* yourself; list what would settle it.

## Output

```
SPEC DRIFT  <spec>   built <n> · unbuilt <m> · unclear <k>
| Claim | Verdict | Evidence |
|---|---|---|
| EX-12 | built | `TestDispatch_RefusesOverCap` asserts it |
| EX-13 | unbuilt | no caller of … ; nothing under approval/ reads gate rules from the store |
| EX-14 | unclear | <what would settle it> |

Proof rows that do not prove their claim: <IDs, or none>
```

Write it to `.spec-check/drift.md` (transient) and print it. This is input to
`/spec-author --migrate` and `/design`; it edits nothing.
