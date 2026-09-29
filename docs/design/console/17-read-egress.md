# 17 — Read egress

**No artboard** — specified without one, deliberately. What has been read, by whom, from where.
**Milestone v0.6.0** (the data already exists).

**Governing:** ADR-0021, ADR-0022, ADR-0025, invariant #13.
**Backend:** existing audit and Task records — `KindRead` rows for the four non-dispatching tools
(`list_nodes`, `describe_node`, `list_operations`, `get_job`), read-class `KindDispatch` rows for
`file.read`, `log.tail` and the rest of the catalog, and per-Task outcomes for deny-list refusals
(`denied_by_policy` is a daemon verdict on a Task, not an audit kind). **No new collection is
required.** The query seams — kind, principal, time range, path/arg, outcome, per-principal counts
by time bucket — are #441, in the capability layer's read lane.

## What this screen is for

The product's own architecture says reading is the exposure that matters:

- ADR-0021 governs data egress and establishes that **reading is exfiltration by construction** — a
  read result flows to the model provider.
- ADR-0022 builds a 25-path confidentiality deny-list around exactly that.
- ADR-0025 makes every read auditable and **fails the read closed** if the audit write fails.

All of that machinery exists, and **nothing in the Console surfaces any of it.** Nobody can
currently answer *"what has this agent read this week, and from where?"* — the question the
architecture itself says is the important one. This screen answers it.

## What the audit trail can and cannot say

ADR-0025 is explicit: the audit trail can say **a read happened, by whom, of what, and when — but
not what it contained.** Read output is not retained, at any age, deliberately.

**Two statements stay visible on this screen, each as one plain sentence in the note style**
(`00-foundations.md`, "Standing notes and situational messages"):

- Beneath the lede: the audit trail never keeps read output, what a daemon sent stays on the
  Job's Task rows until the Job is collected and is readable through the Job read, and this page
  will never show it (ADR-0025). It is a property the Console is visibly bound by, so it is never
  collapsed.
- Where the page says its figures are exact over the window, the same sentence says what they
  cannot count: a read-class Job created just before the window whose records land inside it is
  missing from the Node-read and refusal figures, because the read vocabulary comes from Jobs
  created in the window and the figures from records timestamped in it. The visible claim is never
  stronger than the truth. The longer explanation of both stays in the disclosure.

So this screen is a map of **exposure surface**, not a data browser. That is a feature: it is
useful for the question being asked and structurally incapable of becoming a second copy of the
fleet's secrets.

## Layout

**Summary first, at the top.** Reads in the window, by principal, with the verified/asserted
grammar. The headline is a count of *distinct paths and Nodes touched*, not a count of calls — one
`file.read` across 4,000 Nodes is one path and four thousand exposures, and the number that matters
depends on which question is being asked. Show both, labelled.

**By principal.** Which Accounts read, how much, and the trend against their own baseline. A
machine Account whose read volume jumped tenfold this week is the single most useful row this
screen can produce.

**By target.** Which paths, which Operations, which Nodes. Group aggressively — the disclosure
ladder applies here as everywhere: count, then bar, then groups, then sampled members, then the
full list only on demand.

**Deny-list activity.** Reads that were **refused** by the confidentiality deny-list. These are the
highest-signal rows in the product: something asked for `/etc/shadow` and Policy said no. Render
them informative-neutral like every other deny — but do not bury them, because a rising count is
either a misconfigured agent or a compromised one.

## Operations in scope

The read catalog, all of it — not just `file.read`. `log.tail` deserves particular prominence:
`policy.default.toml` names it the widest egress surface in the catalog, because a journal carries
whatever a service chooses to log. `file.checksum` too — a digest is a content oracle that confirms
a guessed file byte-for-byte, which is why ADR-0022's deny-list covers it exactly as it covers
`file.read`.

## Filtering

By principal, Operation, path or path prefix, Node, Selector, outcome and time range. Export, for
the auditor who has to answer this question to someone else.

## Must not appear

- Read output. Not a preview, not a sample, not "the first 200 bytes". It does not exist and the
  screen must not imply it could.
- Any suggestion that this is monitoring. It is an audit view over an existing trail.
- A rendering that treats a refused read as a failure. It is Policy working.

## Acceptance

- [ ] Answers "what has this principal read in this window, and from where" in one query.
- [ ] Distinguishes distinct paths from total exposures and labels both.
- [ ] Surfaces deny-list refusals prominently, styled informative-neutral.
- [ ] Contains no read output at any age or aggregation.
- [ ] Covers the whole read catalog, not only `file.read`.
- [ ] Requires no new collection: every row derives from an existing audit or Task record
      (`KindRead`, read-class `KindDispatch`, Task outcomes).
