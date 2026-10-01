# 17 — Read egress (retired)

**Retired 2026-10-01 (owner decision).** The Read egress screen is dropped. Activity
([04 — Activity](04-activity.md)) is the single log of what went through the control plane:
read-class calls already appear there as `read` rows (the `read` kind chip) and as read-class
`dispatch` rows. A second screen over the same records is not wanted. The route `/console/reads`
is no longer mounted and answers the Console's ordinary 404.

The file keeps its name so existing links hold. Where a citation names a section of this file:

| Cited section | Now |
|---|---|
| "What the audit trail can and cannot say" (ADR-0025) | [04](04-activity.md), "Reads" |
| Read records left out of the default feed | [04](04-activity.md), "Reads" |

The previous text is in git history.
