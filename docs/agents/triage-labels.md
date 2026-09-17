# Triage Labels

Agent skills speak in terms of five canonical triage roles. This file maps those roles to the
label strings actually used in this repo's tracker.

| Canonical role    | Label in our tracker | Meaning                                            |
| ----------------- | -------------------- | -------------------------------------------------- |
| `needs-triage`    | *(no `loop:*` label)* | Not yet triaged. See the note below.               |
| `needs-info`      | `question`           | Waiting on the reporter for more information        |
| `ready-for-agent` | `loop:ready`         | Fully specified, eligible for the dev-loop to pick up |
| `ready-for-human` | `loop:needs-human`   | Escalated — a human must implement, review, or decide |
| `wontfix`         | `wontfix`            | Will not be actioned                                |

When a skill mentions a role ("apply the AFK-ready triage label"), use the label string from
the right-hand column.

## The `needs-triage` gap

There is no `needs-triage` label. Untriaged today means "carries no `loop:*` label", which is
indistinguishable from an issue that was triaged and deliberately parked. If triage becomes a
real lane, add an explicit `needs-triage` label rather than continuing to infer it from absence.

## Additional lanes this repo uses

These have no canonical equivalent; skills should preserve them rather than overwrite:

- `loop:proposed` — created by `/decompose` from a merged design plan. Not eligible until a
  human flips it to `loop:ready`; that flip is a gate (`docs/agents/workflow.md`).
- `loop:in-progress` — currently being worked. Do not pick up.
- `loop:blocked` — waiting on a dependency. Not eligible even though it may look ready.
- `loop:done` — merged.
- `blocking` — gates a milestone; landed by hand ahead of the loop.
- `decision` — a product/architecture decision to make. **Human-owned, never loop work.**
  An agent must not resolve one of these by implementing its preferred answer.
- `idea` — captured, no commitment yet. Promote or close at triage; never implement directly.
- `security-scan` — nightly vulnerability scan findings.

`decision` and `idea` are the two an eager agent is most likely to misread as actionable.
They are not.
