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

- [ ] Default order is nearest-expiry-first.
- [ ] No decision is possible without opening the approval object, except bulk deny with step-up.
- [ ] A Grant occupies exactly one row.
- [ ] Pending approvals sharing a shape key are visibly grouped.
- [ ] "Waiting on me" is the default filter when eligibility is determinable.
