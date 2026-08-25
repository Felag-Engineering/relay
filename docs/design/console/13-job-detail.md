# 13 — Job detail

**No artboard** (the Plan renderer and outcome bar are on artboard 9). One command run against many
Nodes. **Milestone v0.6.0.**

**Governing:** ADR-0004, ADR-0012, ADR-0013, ADR-0025, invariants #4, #5, #13.
**Backend:** store queries for a Job and its Tasks, paginated and filterable by outcome; cancel
through the capability layer.

## What this screen is for

The record of one dispatch. **It must be legible at 3 Nodes and at 10,000** — that is the whole
design problem, and it is why the outcome bar and the disclosure ladder exist.

## Layout

**Header.** Operation name with its **risk-class badge**; requester identity — solid verified chip,
plus a dashed asserted chip when run on behalf of someone; approver chip when it was parked;
timestamps; Job state.

**Plan block.** The shared Plan renderer (`00-foundations.md`): fan-out with cap arithmetic, and
the plan hash in mono. This is the Plan the Job was dispatched against, not a fresh one.

**Results.** A segmented outcome bar across the full vocabulary, then one collapsible group per
outcome, headed by count. Ordered by interest, not alphabetically: denied first, then the failures,
then the never-rans, then success last — success is the mode and the mode is the least
informative thing on the screen.

## Clustering identical output

Within the success group, cluster identical output: **"9,797 identical (view one) · 3 differ"**,
with the 3 expanded by default. "Show all" is always one more click away, never the default.

This is the pre-aggregation stand-in for the v0.9.0 histogram primitive. **Lay it out so that
primitive slots into the same component** rather than replacing it — the shape of the answer does
not change, only how it is computed.

## The denied group is the showpiece

Expanding it shows **the Policy rule that fired, verbatim**, in mono, with a link to that Node's
effective Policy and a link into the Policy fix screen (spec 07). When every denial in the group
shares a reason, show the rule once and say so; when they differ, group by rule.

Styled informative-neutral — slate, never red. A deny is the product working.

## Live and terminal states

A running Job updates live: counts fill in, the bar grows. **The Plan block never reflows** — it is
what was agreed, not a live query.

**Cancel** is available while Tasks are in flight and is honest about what it does: it kills the
process group on Nodes still working; a Task that already finished reports its real outcome rather
than a retroactive cancel; the cancelled Task ID stays deduped, so at-most-once still holds.

## Read-class Jobs

Show outcomes and timings. **No output at any age** — the Task row may carry it while the Job
lives, but nothing here promises to retain it, and a read-class Job that has been garbage-collected
shows its audited metadata only (ADR-0025).

## Must not appear

- A flat list of Tasks as the default render.
- Retained read output presented as durable.
- A re-run button that skips Plan. Re-running is composing again (spec 05), with a fresh Plan and a
  fresh hash.

## Acceptance

- [ ] A Job over 10,000 Nodes renders in one screen with no list until explicitly requested.
- [ ] All eight outcomes render, with the three "did not run" kinds visually distinct.
- [ ] The denied group shows the rule verbatim and links to the Node's effective Policy.
- [ ] Cancel is offered only while Tasks are in flight, and its effect is described accurately.
- [ ] The Plan block does not change while the Job runs.
- [ ] A three-Node Job is as legible as a ten-thousand-Node one.
