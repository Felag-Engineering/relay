# 13 — Job detail

**No artboard** (the Plan renderer and outcome bar are on artboard 9). One command run against many
Nodes. **Milestone v0.6.0** for the record; **v0.7.0** for Cancel.

**Governing:** ADR-0004, ADR-0012, ADR-0013, ADR-0025, invariants #4, #5, #13.
**Backend:** store queries for a Job and its Tasks, paginated and filterable by outcome; Cancel
through the capability layer (v0.7.0 — in v0.6.0 no route on this page reaches the capability
layer's write or dispatch path).

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

**Cancel** (v0.7.0) is available while Tasks are in flight and is honest about what it does: it kills the
process group on Nodes still working; a Task that already finished reports its real outcome rather
than a retroactive cancel; the cancelled Task ID stays deduped, so at-most-once still holds.

## Read-class Jobs

Show outcomes and timings. **No output at any age** — the Task row may carry it while the Job
lives, but nothing here promises to retain it, and a read-class Job that has been garbage-collected
shows its audited metadata only (ADR-0025).

## Must not appear

- A flat list of Tasks as the default render.
- Retained read output presented as durable.
- A re-run button that skips the Preflight. Re-running is composing again (spec 05), with a fresh
  Preflight and a fresh plan hash.

## Acceptance

- [x] A Job over 10,000 Nodes renders in one screen with no list until explicitly requested.
      The counts come from ONE aggregate row (`capability.QueryJobs` filtered to the Job), so
      they are exact without a Task being materialised; rows come from at most one bounded page
      per outcome, and the success group fetches none at all above 50 Tasks.
      Proven on the rendered page, and structurally through the read lane, by
      `TestJob_TenThousandNodesRenderWithoutAList`.
- [x] All eight outcomes render, with the three "did not run" kinds visually distinct.
- [x] The denied group shows the rule verbatim and links to the Node's effective Policy.
      The link lands on the Node page; an anchor to its effective-Policy panel waits on #421.
      The second link the layout calls for — into the Policy fix screen (spec 07) — is NOT
      rendered, because spec 07 is not built in v0.6.0 and a link to a screen that does not
      exist is worse than no link.
- [x] Cancel (v0.7.0) is offered only while Tasks are in flight, and its effect is described
      accurately; in v0.6.0 no control on this page reaches the capability layer.
      **Built (#595).** Cancel renders for `operator` and above while any Task is unresolved,
      decided by the capability layer's `AuthorizeControl(ControlCancelJob)` — this page only
      narrows what is drawn to what the route table would let the session reach, and decides
      nothing itself. No step-up: Cancel only ever asks, never a mutate apply, and it is not
      behind `console_execution` (that flag scopes the composer and dispatch, and Cancel cannot
      run anything). The result block reads the Job's `job_cancel` audit record — never a
      query-string flash — and says which cancelled Tasks never left the Relay and which were
      stopped after being sent, qualifies the still-in-flight count as best-effort ("where its
      Node is connected"), and leaves every already-resolved Task's real outcome untouched.
- [ ] The Plan block does not change while the Job runs.
      **Partially met.** Everything the block renders is fixed at dispatch — risk class,
      fan-out (every Task is created before the first one runs), and the plan hash the bound
      approval committed to — except the Selector, which a Job carries nowhere of its own: it
      lives in the dispatch audit record, and the Job engine writes that record only AFTER the
      dispatch returns. So a running Job has no Selector to render. The block's STRUCTURE does
      not reflow — the Selector's own slot holds a note saying where the value comes from, and
      resolves in place at completion — but that one slot does change. Closing this properly
      means putting the Selector on the Job itself (`jobs.Job`'s doc comment already names the
      follow-up); `approval.Request` cannot serve as the earlier source, because it carries a
      plan hash and no Selector.
- [x] A three-Node Job is as legible as a ten-thousand-Node one.
      At or below 50 Tasks every group lists everything, success included.

**Attribution (#455).** The header now renders the approver chip(s) this Layout section already
called for, in the lane their own Account attribution earns — never hard-coded verified — plus
each decision's time, channel, the gate rule that parked the Job, the quorum it met, the
approval's own requester when it differs from the Job's, and the stored Relay-authored summary
the approver was shown, all on the Job screen itself. A visible lane key explains the
verified/asserted distinction in text, not only in a chip's hover title. A Grant-released Job
shows the Grant's approvers with the window caveat ("these approvers approved a Grant... not this
plan") and renders no plan hash, because the Grant's own hash is over its Scope, not this Job's
Plan. All of it is rendered from the one `Approval()` read the page already made for the plan
hash — no new read, no new audit record.

### Not delivered by this build

**Live updates.** "A running Job updates live: counts fill in, the bar grows" is prose in this
spec rather than an acceptance checkbox, and it is not built: the Console has no SSE client and
loads no JavaScript at all. (The layout does emit `hx-headers` attributes and the CSP admits a
same-origin event stream, but the HTMX script is not loaded, so nothing acts on them.) The page
renders per request; a running Job updates when it is reloaded. Building a transport for one
screen is not in v0.6.0's scope.

**Exact clustering above 50 Tasks.** "9,797 identical (view one) · 3 differ" is exact only when
the page listed the whole group. Above that the success group fetches nothing by default and at
most 100 rows under `?show=`, so the page says what it actually computed — "N of the M listed" —
rather than printing a cluster count over rows it never saw. The exact answer is one
`GROUP BY hash(stdout||stderr)` aggregate away, which is precisely the v0.9.0 histogram
primitive this component was laid out for: it replaces what computes the counts and nothing
about the shape of the answer.
