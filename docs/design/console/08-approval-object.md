# 08 — Approval object (retired)

**Retired 2026-10-18 (owner decision, [ADR-0044](../../adr/0044-the-console-does-not-decide-approvals.md)).**
The Console renders no approval request and decides none — no approve, no deny, no step-up for
one. `/console/approvals/{id}` and its decision route are not mounted and answer the Console's
ordinary 404. A parked request is answered in-band through the requesting client, or out-of-band
on the Control API (`GET /api/v1/approvals/{id}`, `POST /api/v1/approvals/{id}/decision`).

The file keeps its name so existing links hold. Where a citation names a section of this file:

| Cited section | Now |
|---|---|
| Trust-lane chips, the Plan renderer, the deny block | [00-foundations.md](00-foundations.md) |
| Approver chips | [13-job-detail.md](13-job-detail.md) |
| The anti-fatigue diff | [docs/specs/approval.md](../../specs/approval.md), Open questions ("What the shape key is for once the Console has no queue") |

The previous text is in the repository history.
