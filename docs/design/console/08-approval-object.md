# 08 — Approval object

**Artboard 6.** One pending action awaiting human sign-off. The highest-stakes rendering in the
system. **Milestone v0.6.0** shipped it read-only; **#453** (pulled forward from v0.7.0) added
deciding — approve/deny behind step-up, for a Plan only, never a Grant.

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
   encounter with it. **Where the requester line shows the requester's kind, it is read from
   what the approval record recorded at request time**, never from the Account registry's
   current kind (`00-foundations.md`, "Kind label"; #540). The approval record carries no
   requester kind today, so the requester line shows none.
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
then a lookup. It is a retrofit onto the v0.5.0 schema (#415): `v0.1.0-beta` has not started and
no production approval records exist, so the migration is over test data. For a Grant the key
hashes the Scope.

When there is no comparable prior approval, say so plainly. Do not manufacture a diff.

## Batches are Grants

A "batch" is what ADR-0027's #378 amendment built: a **Grant** — an ordinary approval Request whose
subject is a **Scope** (Operation allow-list, fan-out ceiling, window, `max_uses`; no namespace pin since 2026-09-16, ADR-0027)
rather than one Plan. It renders as **one card** — "Grant · `service.restart` on `tag:web` · ≤ 200
Nodes · next 2h · 20 uses" — carrying the Scope, its *derived worst-case Requirement*, and, once
approved, the Jobs it has released so far (audit `grant_id`). Never one card per released Job.
**Approving a Grant requires expanding its Scope at least once.** That is a deliberate cost, and
the only dark-pattern-shaped thing on the screen: it exists to buy attention, not to sell it.

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

## Decisions, and who made them

Every recorded Decision is listed: the decider's chip, the answer, when, the channel and the
note. **Each decider's chip is followed by a kind label, `human` or `machine`, read from that
Decision's own record of whether its decider was human** — the same fact the Control API renders
as `human` on each decision — and never from the Account registry. A Decision records an unknown
kind as not human (the restrictive default), so `machine` there means "not recorded as human".
A human decider is labelled as plainly as a machine one; neither is the unmarked case. Nothing on
the card says how a decider authenticated (owner decision, 2026-09-29). Job detail's approval
section (spec 13) draws the same label from the same record.

## States

- **Expired** — the decision controls are gone and the card says the TTL lapsed and what happens
  next.
- **Already decided** — shows the decision, who made it, and when.
- **Partial quorum** — shows who has signed and who is still needed.
- **`viewer`** — reads the card, cannot decide.

## Acceptance

- [x] Renders legibly at 390px wide with no horizontal scroll and 44px minimum hit targets.
      The card is chromeless — no nav rail, one column — and the rules ship: a 480px breakpoint
      that stacks the queue row and collapses the key/value grid, and a plan hash whose CONTAINER
      scrolls so the identifier is never broken across lines (the `.tablescroll` rule).
      **Which targets the 44px minimum covers, precisely:** the queue's rows, this card's back
      link, and the Job links a Grant's released list renders. It does **not** cover the
      prior-approval link inside the diff callout — that one sits mid-sentence, where a 44px inline
      box breaks the line rhythm of the paragraph the whole card is built around. **Stated limit:**
      all of this is asserted from the stylesheet, not from a browser. The 390px rendering and the
      one in-sentence link both still need the manual pass.
- [x] Approve and Deny are visually identical in weight; neither is focused on load.
      **(#453.)** One class, `.decideanswer`, renders both buttons; the stylesheet carries no rule
      keyed on `value="approve"`/`value="deny"` to diverge them, and neither button carries
      `autofocus`. Asserted from the markup and the stylesheet
      (`TestDecide_ApproveAndDenyAreVisuallyIdentical`), the same stated limit as the 390px
      criterion above: a browser has not painted the two pixel-for-pixel identical.
- [x] Neither decision submits without step-up. **(#453.)** A password field is inline on the
      decision form itself and `POST /console/approvals/{id}/decision` verifies it, in the same
      request, immediately before calling `capability.Service.DecideApproval` — never a separate
      re-auth round trip. **Deviation from the window model this criterion implies:** step-up is
      demanded on **every** decision rather than consulting the five-minute recent-auth window
      (`StepUpFresh`/`ErrStepUpRequired` stay uncalled) — approving three requests costs three
      passwords. Stricter than the window, which invariant 10 permits (an adapter may offer less,
      never more), and it is what kills the one-click rubber stamp this whole screen exists to
      prevent. **The one exception is a bulk act from the queue** (spec 14): there, one step-up
      covers every Decision in the act (`docs/specs/approval.md`, owner decision of 2026-09-18,
      threat model R22). A decision made on this card still costs its own password.
- [ ] A Grant cannot be approved without its Scope having been expanded.
      **(Deferred beyond #453.)** v0.6.0 shipped the closed `<details>` disclosure; #453 added the
      decision control for a Plan but deliberately **refuses to decide a Grant at all** rather than
      deciding one without the expansion gate — the card renders no form for a Grant-shaped
      Request, and a POST against one is refused (409, "this Console does not enforce that yet").
      Answering a Grant still goes through the Control API. The enforcement itself — requiring the
      expansion before a decision is accepted — remains unbuilt.
- [x] The diff callout is present whenever a comparable prior approval exists, and its absence is
      stated when one does not.
      It renders **only what is genuinely stored**: for a Grant, the real numbers (the fan-out
      ceiling, the window, the use limit — the three `HashGrantShape` excludes, all of them
      columns); for a Plan, shape identity plus a scale-argument diff read from each park's own
      audit record, plus plan-hash equality. The **fan-out is named as uncomparable** rather than
      inferred: a park creates no Job, so no Task and no result exists for the record being
      rendered. All three absences are stated — no prior of this shape, a shape that was never
      computed, and inputs missing from the audit trail. Nothing is ever parsed out of the
      summary.
- [x] The decision is bound to the plan hash; a plan that changed is not approvable.
      **(#453.)** The hidden `plan_hash` field is what the surface submits (never re-derived from
      the record), and `DecideApproval` refuses a hash that does not match with
      `approval.ErrPlanChanged`, rendered as "the Plan moved since this page was rendered; reload
      and read it again — your answer was not recorded."

### Deviation from the card order above

The **diff callout renders first**, above the requester line and the action. This spec asks for it
third and also calls it "the most eye-catching text on the card"; those cannot both hold. Recorded
in [99-open-decisions](99-open-decisions.md) under D10.
