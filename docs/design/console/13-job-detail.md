# 13 — Job detail

**No artboard** (the Plan renderer and outcome bar are on artboard 9). One command run against many
Nodes. **Milestone v0.6.0** for the record; **v0.7.0** for Cancel.

**Governing:** ADR-0004, ADR-0012, ADR-0013, ADR-0025, invariants #4, #5, #13.
**Backend:** store queries for a Job and its Tasks, paginated and filterable by outcome; Cancel
through the capability layer (v0.7.0).

## What this screen is for

The record of one dispatch. **It must be legible at 3 Nodes and at 10,000** — the whole design
problem, and why the outcome bar and the disclosure ladder exist.

## Layout

**Header.** Operation name with its **risk-class badge**; requester identity — solid verified chip,
plus a dashed asserted chip when run on behalf of someone; approver chip when it was parked;
timestamps; Job state.

**Kind beside the requester and each approver.** The requester's verified chip is followed by a
kind label, `human` or `machine` (`00-foundations.md`). **Where Job detail shows its requester's
kind, it is read from the kind the Job row recorded for its requester when the Job was created,
and from nothing else** — never from the registry ([04](04-activity.md), "Kind is never read from
the registry"). A Job that recorded no kind shows no label — including one whose requester comes
from its dispatch audit record, which carries no kind either. In the approval section, **each
approving decider's chip is followed by a kind label read from that Decision's own record** of
whether its decider was human: `human` when it records a human decider, `machine` otherwise (an
unknown kind is recorded as not human, the restrictive default). A kind label is drawn only beside
a verified chip: a requester or decider rendered dashed, with no recorded Account ID, gets none.
The lane key under the header says in words what the label means, including that on a decision
`machine` means "not recorded as human". The Account that parked the approval, when not the Job's
requester, shows no kind: the approval record carries none. Nothing on this screen says how an
actor authenticated.

**Plan block.** The shared Plan renderer (`00-foundations.md`): fan-out with cap arithmetic, and
the plan hash in mono. This is the Plan the Job was dispatched against, not a fresh one.

**Results.** A segmented outcome bar across the full vocabulary, then one collapsible group per
outcome, headed by count. Ordered by interest: denied, then failures, then the never-rans, then
success last — the mode is the least informative thing on the screen.

## Clustering identical output

Within the success group, cluster identical output: **"9,797 identical (view one) · 3 differ"**,
with the 3 expanded by default. "Show all" is always one more click away, never the default.

This stands in for the v0.9.0 histogram primitive. **Lay it out so that primitive slots into the
same component**: the shape of the answer does not change, only how it is computed.

## The denied group is the showpiece

Expanding it shows **the Policy rule that fired, verbatim**, in mono, with a link to that Node's
effective Policy. When every denial in the group
shares a reason, show the rule once and say so; when they differ, group by rule.

Styled informative-neutral — slate, never red. A deny is the product working.

## Live and terminal states

A running Job updates live: counts fill in, the bar grows. **The Plan block never reflows** — it is
what was agreed, not a live query.

**Cancel** (v0.7.0) is available while Tasks are in flight and is honest about what it does: it
kills the process group on Nodes still working; a Task that already finished reports its real
outcome; the cancelled Task ID stays deduped, so at-most-once still holds.

## Read-class Jobs

Show outcomes and timings. **No output at any age** — the Task row may carry it while the Job
lives, but nothing here promises to retain it, and a read-class Job that has been garbage-collected
shows its audited metadata only (ADR-0025).

## Must not appear

- A flat list of Tasks as the default render.
- Retained read output presented as durable.
- A re-run button of any kind. The Console does not execute (ADR-0052); re-running is a new call
  from an AI-agent or the Control API, with a fresh Preflight and a fresh plan hash.

## Acceptance

- [x] A Job over 10,000 Nodes renders in one screen with no list until explicitly requested.
      The counts come from one aggregate row (`capability.QueryJobs` filtered to the Job), so
      they are exact without materialising a Task; rows come from at most one bounded page per
      outcome, and the success group fetches none above 50 Tasks. Proven by
      `TestJob_TenThousandNodesRenderWithoutAList`.
- [x] All eight outcomes render, with the three "did not run" kinds visually distinct.
- [x] The denied group shows the rule verbatim and links to the Node's effective Policy.
      The link lands on the Node page, without an anchor to its effective-Policy panel. There is
      no Policy fix screen: it is cut (roadmap: relay/policy-catalog-and-live-reload).
- [x] Cancel (v0.7.0) is offered only while Tasks are in flight, and its effect is described
      accurately; in v0.6.0 no control on this page reaches the capability layer.
      **Built.** Cancel renders for `operator` and above while any Task is unresolved, decided
      by the capability layer's `AuthorizeControl(ControlCancelJob)`; this page only narrows
      what is drawn. No step-up: Cancel cannot run anything, so it stays in a Console
      that does not execute (ADR-0052). The result block reads the Job's `job_cancel` audit record — never a
      query-string flash — says which cancelled Tasks never left the Relay and which were
      stopped after being sent, qualifies the still-in-flight count as best-effort ("if its
      Node is connected"), and leaves every already-resolved Task's real outcome untouched.
- [ ] The Plan block does not change while the Job runs.
      **Partially met.** Everything the block renders is fixed at dispatch — risk class,
      fan-out (every Task is created before the first runs), and the plan hash the bound
      approval committed to — except the Selector. A Job does not carry it: it lives in the
      dispatch audit record, written only after the dispatch returns. The block's structure
      does not reflow — the Selector's slot holds a note and resolves in place at completion —
      but that one slot changes. Closing it means putting the Selector on the Job itself
      (`jobs.Job`'s doc comment names the follow-up); `approval.Request` carries no Selector.
- [x] A three-Node Job is as legible as a ten-thousand-Node one.
      At or below 50 Tasks every group lists everything, success included.

**Attribution.** The header renders the approver chips in the lane their own Account attribution
earns — never hard-coded verified — with the decision's time and surface, the gate rule that
parked the Job, the approval's own requester when it differs from the Job's,
and the stored Relay-authored summary the approver was shown. A visible lane key explains the
verified/asserted distinction in text, not only in a hover title. An approval is one answer
(ADR-0047): there is no quorum to show, and approval Grants are cut, so no Job is Grant-released.
All of it comes
from the one `Approval()` read the page already makes — no new read, no new audit record.

### Not delivered by this build

**Live updates.** "A running Job updates live: counts fill in, the bar grows" is not built: Job
detail loads no script and has no SSE client, and the HTMX script is not loaded, so the layout's
`hx-headers` attributes are inert. A running Job updates when the page is reloaded.

**Exact clustering above 50 Tasks.** "9,797 identical (view one) · 3 differ" is exact only when
the page listed the whole group. Above that the success group fetches nothing by default and at
most 100 rows under `?show=`, so the page says what it computed — "N of the M listed" — rather than
a cluster count over rows it never saw. The exact answer is one `GROUP BY hash(stdout||stderr)`
aggregate away: the v0.9.0 histogram primitive this component was laid out for.
