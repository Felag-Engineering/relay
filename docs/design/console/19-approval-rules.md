# 19 — Approval rules

**No artboard.** The approval-gate rules: which dispatches park, and what releases them.
**Milestone v0.7.0.**

**Governing:** ADR-0027 (amended 2026-09-15 and 2026-09-16), ADR-0029, invariants #5, #10, #11.
Behaviour: `docs/specs/approval.md`, `docs/specs/relay-configuration.md`.
**Backend:** store-backed gate rules, seeded on first boot (#590); step-up (#428); audit.

Decided with the owner, 2026-09-16: its own page beside Approvals; the confirm step shows old →
new and nothing more; no change history. *(2026-10-18: the Approvals page is gone — ADR-0044
removed the Console's approval surface — so this page sits in **Act** on its own. Whether the
owner's "cut approvals out of the UI completely" reaches this page too is not settled; see D21.)*

## What this screen is for

Deciding where human attention is spent. This is where the rule that parks a dispatch lives; the
parked request itself waits on the Control API or in the requesting client, never in the Console
(ADR-0044).

## Navigation

**Act › Approval rules**, after Policy. `admin` sees and edits. Other roles: absent — the rules
decide what an AI-agent may do unattended, and reading them is a map of what does not park.

## The list

Rules in evaluation order, each as one row in plain words, not JSON:

> **mutate across 2 or more Nodes** → 1 approval from `dev-approver`, out-of-band, not the
> requester, window 1h

Columns: name, match (risk class, fan-out, Selector namespace, principal, operation — only the
terms the rule sets), requirement (count, audience, requester allowed, channel, window). A rule
seeded on first boot says **shipped default** until it is edited.

Above the list, one line: *"A rule can only require approval. It never permits what a Node's
Policy refuses, and never raises a blast cap."* (ADR-0027: narrows only.)

## Editing

Add, edit, remove and reorder. The editor exposes exactly ADR-0027's v1 configuration surface —
`count` 1 or 2, audience, `requester_allowed`, channel, window — and no field the stored schema
has that the configuration language does not yet expose.

Every save: **confirm step showing the rule old → new** (or added / removed), then **step-up**.
Removing the last rule is allowed and says, on the confirm step, that nothing will park — the
residual accepted as R15.

## Must not appear

- The approval webhook URL, secret or timeout as editable — they are security floor (spec 18
  renders them read-only).
- Any control from which an approval is *decided* — the Console decides none (ADR-0044).
- A history of past rule sets.
- The page, for any role but `admin`.

## Acceptance

- Only `admin` reaches the route; every save requires a fresh step-up.
- Each add, edit, remove and reorder is one audit record with the rule before and after.
- The rendered sentence for a rule is derived from the same parsed rule the gate evaluates, so the
  screen cannot describe a rule differently from how it behaves (a table test over rule shapes).
- No MCP tool or Control API route writes a gate rule (structural test, per ADR-0027's amendment).
