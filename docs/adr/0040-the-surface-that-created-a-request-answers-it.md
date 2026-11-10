# The surface that created a request is the surface that answers it

**Status:** Superseded by ADR-0047 (2026-10-22).

What still held, that MCP is the approval path and the Control API decides any parked request
without being featured, is ADR-0047 decisions 3 and 5; the restart risk it recorded is
threat-model R27.

## What it decided

An approval request would be answered only on the surface that created it. The owner narrowed
that one day later: MCP is the approved pathway for a request an AI-agent created, and the
out-of-band paths keep deciding any parked request without being relied on. A requirement that
a rule be answered out-of-band stayed shelved. This ADR amends ADR-0027. It was amended by
ADR-0044.

## Where to read now

ADR-0047 for the decision in force; `docs/specs/approval.md` for the behaviour. The full text
of this ADR, with both of its amendments, is in git:
`git show 3694f23:docs/adr/0040-the-surface-that-created-a-request-answers-it.md`.
