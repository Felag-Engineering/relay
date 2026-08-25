# 04 — Activity

**Artboard 3.** The live stream and the audit trail, deliberately **one surface**.
**Milestone v0.6.0.**

**Governing:** ADR-0004, ADR-0013, ADR-0025, ADR-0027, `approval-and-attribution.md`.
**Backend:** the audit and Job query seams — kind, principal, time range, Node, Operation,
outcome, cursor pagination — exposed through the **capability layer's read lane** (#441, never
Console→store); the SSE seam's registry, Job and enrollment publishers.

## What this screen is for

What happened **to the fleet**, whether that was a second ago or last Tuesday. Live tail on is
"what is happening"; scroll back or filter and it is the audit trail. Same rows, same chips, one
renderer — two screens would mean two renderers of the same events that drift apart.

## Grain

**Job-grained, not Task-grained.** One `mutate` across 2,214 Nodes emits 2,214 Task events; a
naive tail becomes unreadable exactly when something important is happening. One row per Job,
filling in live, expanding to Tasks on demand.

Non-dispatch events are first-class rows too: approvals, label changes, token mints, enrollments,
Freeze transitions, logins.

## Row kinds

| Kind | Carries |
|---|---|
| `dispatch` | Operation + args, risk badge, requester chips, Selector, fan-out, plan hash, live outcome counts, Job link |
| `approval` | what is parked, quorum state, TTL, a link to decide |
| `label` | who set which label on which Node, with the step-up record and reason |
| `token` | who minted or revoked an Enrollment Token, its scope, uses and expiry |
| `enroll` | which Nodes joined, via which token, with which `relay:` labels stamped |
| `freeze` | engage or release, by whom, held for how long, with the reason |
| `auth` | sign-in, source address, method |

## Identity on every row

The verified/asserted grammar from `00-foundations.md`, without exception. `requested_by` is
verified — the Relay authenticated it. `on_behalf_of` is asserted — the caller claimed it and
nothing checked. `approved_by` is verified. Blurring the two is how audit trails become fiction: a
jailbroken agent can assert anything, but it cannot forge the verified fields.

## Live but stable

New events **queue behind an explicit click** ("3 new events — show") rather than pushing in.
Nothing moves under what someone is reading. This is rule 6 of the foundations and it is not
negotiable on a screen whose whole job is careful reading.

## Read rows

A read-class dispatch shows its metadata and says the output is not retained. Do not build a
detail view that promises to show it later.

## Filtering and export

One filter box over principal, Operation, Selector, outcome and Node — the same box that filters
the live tail filters history. Time controls: live tail, a relative window, an explicit range.
Export for an auditor.

## Must not appear

- Task-grained rows in the default view.
- Retained read output.
- Any row the Relay cannot attribute — if attribution is missing, that is a bug to surface, not a
  blank to render.

## Acceptance

- [ ] A Job touching 4,000 Nodes occupies one row that fills in live.
- [ ] An auditor answers "who asked, for whom, who approved, what happened" from this screen in
      one query, with the verified/asserted distinction visible without hovering.
- [ ] Live updates never reflow a row the user is reading.
- [ ] Live tail and historical query use the same renderer.
- [ ] A read row carries no output at any age.

## Jobs

There is no separate Jobs destination (D6, resolved). This screen filtered to `dispatch` **is** the
Jobs list, and the filter must be a first-class, linkable state rather than something a user has to
reconstruct. Job detail remains its own page, reached from any dispatch row here.
