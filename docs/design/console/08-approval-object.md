# 08 — Approval object

**Artboard 6.** One pending action awaiting human sign-off. The highest-stakes rendering in the
system. **Milestone v0.6.0** read-only; **v0.7.0** to decide.

**Governing:** ADR-0027, ADR-0029, `approval-and-attribution.md`, invariants #13.
**Backend:** pending-approval Job state and the decision endpoint (the Approval Callout
milestone); step-up re-auth; the approval-record schema, which must store what this screen renders.

## What this screen is for

A human decides whether an action runs. Approvers arrive from a link — an elicitation, a webhook,
a notification — often on a phone, often mid-something-else. **Mobile-first and self-contained:**
no nav, nothing competing, one card.

## The fatigue problem

An approval gate is worth exactly as much attention as the UI extracts. A screen that trains
people to click Approve has not added a control; it has added a rubber stamp with an audit trail.
Everything below is aimed at that.

## Card contents, top to bottom

1. **Requester line.** A solid verified chip for the requesting Account — often the AI-agent's
   machine Account — plus dashed asserted chips for `on_behalf_of` and any ticket or change
   reference. One line explaining the difference, because this may be the reader's first
   encounter with it.
2. **The action.** Operation in mono with its risk badge, then arguments, Selector, fan-out with
   cap arithmetic, grouped verdicts as a segmented bar plus counts, and the **plan hash**. The
   hash is what is being approved.
3. **The diff against the last approved similar action.** See below.
4. **Quorum and expiry.** "1 of 2 approvals · mike signed 2h ago", plus a TTL countdown. If the
   deployment sets `requester_allowed: false`, say that the requester is excluded and a second
   person must sign.
5. **Step-up.** An inline field that must be completed to submit **either** decision.
6. **Approve and Deny**, equal in size, weight and colour, with nothing focused by default.

## The diff callout — the anti-fatigue mechanism

> Same as what you approved Tue 14:02 — **except the fan-out grew 1,180 → 2,214.**

This is the single most valuable element on the screen and it must be **the most eye-catching text
on the card**. Fatigue dies here or nowhere: a reader who has approved this shape before needs to
see what is *different*, not re-read what is the same.

It requires a **shape key** on the approval record: a hash over the Operation and the normalised
Selector, excluding fan-out and any argument expected to vary (D10). Finding the prior approval is
then a lookup. This is a **v0.5.0 schema decision** — v0.5.0 lands well before the Console, and a
shape key cannot be recomputed for existing records because normalising a Selector after the fact
is guesswork.

When there is no comparable prior approval, say so plainly. Do not manufacture a diff.

## Batches

A declared batch renders as **one card** — "Batch · 14 actions" — with the member list collapsed
and one decision. Never forty cards. **Approving a batch requires expanding it at least once.**
That is a deliberate cost, and it is the only dark-pattern-shaped thing on the screen: it exists to
buy attention, not to sell it.

## No editing here

An approver who wants changes sends it back. Editing would produce a new plan hash and reset
quorum, and an approver who amends then approves has quietly become the requester, collapsing
`requester_allowed: false`. The amend affordance lives in the composer (spec 05).

## In-band decisions

Per ADR-0029, the approval may be answered through the tool surface: the Relay returns
`input_required` carrying the elicitation and the answer *is* the decision. This screen is the
human-facing rendering of the same object, not a second decision path. Both land on one record,
and Activity (spec 04) shows either.

## Must not appear

- A default-focused or visually dominant Approve.
- Approve enabled before step-up is satisfied.
- The requester's own phrasing of what the action does. The Plan summary is **Relay-authored** —
  an agent-supplied description of its own request is exactly the thing not to trust.
- Anything else on the page.

## States

- **Expired** — the decision controls are gone and the card says the TTL lapsed and what happens
  next.
- **Already decided** — shows the decision, who made it, and when.
- **Partial quorum** — shows who has signed and who is still needed.
- **`viewer`** — reads the card, cannot decide.

## Acceptance

- [ ] Renders legibly at 390px wide with no horizontal scroll and 44px minimum hit targets.
- [ ] Approve and Deny are visually identical in weight; neither is focused on load.
- [ ] Neither decision submits without step-up.
- [ ] A batch cannot be approved without its member list having been expanded.
- [ ] The diff callout is present whenever a comparable prior approval exists, and its absence is
      stated when one does not.
- [ ] The decision is bound to the plan hash; a plan that changed is not approvable.
