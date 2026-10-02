# 14 — Approval queue

**No artboard** (the single card is artboard 6). The list of what is waiting. **Milestone v0.6.0**
shipped it read-only; **#453** (pulled forward from v0.7.0) added deciding on the object — this
screen stays structurally read-only, unchanged.

**Governing:** ADR-0027, ADR-0029, invariants #13.
**Backend:** pending-approval Job state; the decision endpoint; the shape key (D10).

## What this screen is for

Spec 08 is one decision read carefully. This is the **queue**, and its job is the opposite:
help a human decide **what to open**, and make it obvious when something is about to expire
unreviewed.

## Rows

One row per pending approval, ordered by **urgency, not arrival**: nearest expiry first, then
largest fan-out. An approval that lapses because it sat below the fold is a failure of this screen.

Each row carries the Operation with its risk badge, the requester as a verified chip (plus an
asserted chip when present), the fan-out, quorum state, and a **TTL countdown**. Nothing else — the
detail is one click away and the row exists to triage.

**A Grant renders as one row** (spec 08: a batch is a Grant over a Scope). A Grant that fragments
into one row per Job it could release has defeated the mechanism before anyone opens it.

## What the queue must convey that a single card cannot

- **Volume as a signal.** A queue that is suddenly forty deep is itself information — an agent in a
  loop, or a gate configured too tightly. Show the count plainly.
- **Repetition.** When several pending approvals share a shape key (D10), say so: "3 pending with
  the same shape". Approving them one at a time without noticing they are identical is exactly the
  fatigue failure.
- **Expiry pressure.** Anything inside its final window is visually distinct — this is the one
  place in the Console where a countdown earns its keep.

## Deciding from the queue

**One request is decided on its approval object** (spec 08), which carries the Plan, the diff
callout and step-up. There is no one-click Approve on a row: a row-level button would let someone
approve without seeing what they approved.

**Several requests may be decided in one bulk act** (`docs/specs/approval.md`, owner decision of
2026-09-18): select pending rows, then approve or deny them together. Before submitting, a
confirmation lists every selected request with its **Relay-authored** summary and fan-out, and
**one step-up re-authentication covers the whole act**. Raw Exec may be included. Approval grant
requests cannot be bulk-approved — each needs its Scope expanded on its own card. Each request is
still answered against its own plan hash and audited as its own Decision; a request the decision
checks refuse is reported by name and does not stop the others. Bulk deny still requires a
reason.

Deciding many requests at once is the approval-fatigue pattern this screen otherwise works
against; it is an accepted residual risk (`approval.md`, threat model R22), not an oversight.

## Filtering

By requester, Operation, risk class, quorum state, and whether this Account is an eligible
approver. Default to "waiting on me" when that is determinable — an approver arriving from a link
should not have to find their own item in someone else's list.

## Must not appear

- A one-click Approve control on a row — a bulk approve always passes through the confirmation
  listing what it approves.
- A default sort by arrival time.
- Grants split into per-Job rows.

## Refreshing

A request parked by a gate rule must be one click away without the operator hunting for the
browser's reload button. The queue offers a **Refresh** control, under the rules in
[`00-foundations.md`](00-foundations.md) ("Refreshing a screen"), in every state the queue renders
once it is wired — the empty state above all, since that is the state someone watches while waiting
for a request to arrive. It carries the current filter. Nothing reloads the queue on a timer.

**Reloading the queue is not an audited read — a known gap, tracked in #779 — and the screen says
so.** Unlike the screens on the read lane, the queue reads the pending Requests and the live
Approval grants through the capability layer's approval methods, which write no read record, so
neither a page load nor a Refresh of this queue puts anything on the audit trail. Because that
limits a security property, one plain sentence beside the Refresh control says it, and the
"About this screen" disclosure restates it in one sentence, as `00-foundations.md` ("Refreshing a
screen") requires. Opening one request is audited:
the approval object reads its park record through the read lane.

## States

- **Empty** — say so plainly. An empty approval queue is good news, not a blank screen.
- **`viewer`** — reads the queue, opens cards, decides nothing.
- **Requester excluded** — when `requester_allowed: false`, the requester sees their own item and
  cannot act on it; say why rather than hiding the control.

## Acceptance

- [x] Default order is nearest-expiry-first.
      The sort key is the `time.Duration`, never the rendered string — "10m left" sorts before
      "5m left" lexicographically, which put the most urgent request in the middle of the queue.
      A **lapsed** request sorts **last**, reversing what this screen first did: an undecidable
      row at the top pushes the decidable ones under it. The spec's "then largest fan-out"
      tiebreak is **not** implemented and cannot be — the approval record carries no fan-out and
      a park creates no Job to count Tasks on (#462, blocked on #469). The tiebreak is creation
      time and then id, which is arbitrary but stable.
- [ ] Bulk approve and bulk deny from the queue: a selection, a confirmation listing each
      request's Relay-authored summary, one step-up for the act, per-request results, no Approval
      grant request approvable in bulk. **Not built** (owner decision of 2026-09-18); until it is,
      the criterion below describes the queue.
- [x] No decision is possible without opening the approval object, except bulk deny with step-up.
      Still true after #453 added deciding, now enforced two ways rather than one: **the queue
      itself carries no control of any kind** — the Console's approval seam (`ApprovalReader`) has
      no decision method, no `RequestGrant` and no `RevokeGrant` on it, a fact about the interface
      — and the decision ROUTE, `POST /console/approvals/{approval_id}/decision`, exists only on
      the object's path and matches no queue row. Every filter is still an anchor. Bulk deny stays
      v0.7.0.
- [x] A Grant occupies exactly one row.
      Structural: the queue lists Requests and there is exactly one Request per Grant. The Jobs a
      Grant has released are listed on the card, never as rows.
- [x] Pending approvals sharing a shape key are visibly grouped.
      Grouped by the stored shape key (#415) and rendered as a **per-render ordinal** — "2 pending
      of the same shape (group A)". The key itself is an unexported field, so `html/template`
      cannot render it, and no route or query parameter accepts one: an unsalted SHA-256 over a
      small preimage (for Raw Exec, every argv element) would be an offline-confirmation oracle.
- [x] "Waiting on me" is the default filter when eligibility is determinable.
      With two rules that matter. It **excludes only what is definitely not the caller's** — a
      named audience that does not include them — so a Request with no audience is shown rather
      than hidden, because who may decide is the capability layer's answer and this screen never
      second-guesses it. And it is **not applied when it would empty a queue that has entries in
      it**: the screen renders everything and says the filter was not applied, because a defaulted
      filter that turns a full queue into "nothing is waiting" is the worst thing it could say.

### Not delivered by this build

**The per-row fan-out.** Spec 14 asks each row to carry it. Nothing stores it: the resolved fan-out
is not on the approval record, and a park creates no Job, so there is no Task and no result to
count. The row carries the Relay-authored summary, which names the node count as prose — and this
screen never reads a number back out of prose. #469 is the change that would make it available.
