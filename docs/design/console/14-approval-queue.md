# 14 — Approval queue (retired)

**Retired 2026-10-18 (owner decision, [ADR-0044](../../adr/0044-the-console-does-not-decide-approvals.md)).**
The Console has no approval surface: `/console/approvals` is not mounted and answers the
Console's ordinary 404, there is no Approvals destination in the navigation, and there is no
pending count. `GET /api/v1/approvals` on the Control API is the listing; a parked request is
answered in-band through the requesting client, or out-of-band on the Control API
(`POST /api/v1/approvals/{id}/decision`).

The file keeps its name so existing links hold. Where a citation names a section of this file:

| Cited section | Now |
|---|---|
| Partial quorum | The Control API's read of a request ([docs/specs/approval.md](../../specs/approval.md), AP-73 and AP-80) |
| The queue's unaudited read | Gone with the screen |

The previous text is in the repository history.
