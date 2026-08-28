# 14 — Approval queue

**No artboard** (the single card is artboard 6). The list of what is waiting. **Milestone v0.6.0**
read-only; **v0.7.0** to decide.

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

**Do not.** Decisions happen on the approval object (spec 08), which carries the Plan, the diff
callout and step-up. A row-level Approve button would let someone approve without seeing what they
approved, which is the whole thing the design is built to prevent.

The queue may offer **bulk deny** — refusing without reading is safe in a way that approving
without reading is not. Even then it requires step-up and a reason.

## Filtering

By requester, Operation, risk class, quorum state, and whether this Account is an eligible
approver. Default to "waiting on me" when that is determinable — an approver arriving from a link
should not have to find their own item in someone else's list.

## Must not appear

- An Approve control on a row.
- A default sort by arrival time.
- Grants split into per-Job rows.

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
- [x] No decision is possible without opening the approval object, except bulk deny with step-up.
      Stronger than asked in v0.6.0: **no control of any kind exists on either screen**, and the
      Console's approval seam has no decision method, no `RequestGrant` and no `RevokeGrant` on
      it — the criterion is a fact about the interface. Every filter is an anchor. Bulk deny is
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
