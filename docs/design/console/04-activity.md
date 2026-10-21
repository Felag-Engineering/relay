# 04 — Activity

**Artboards 3 and 11.** Every call made to the control plane, and what it did to the fleet: the
live stream and the audit trail, deliberately **one surface**.
**Milestone v0.6.0** for the stream; **v0.7.0** for Cancel.

**Governing:** ADR-0003, ADR-0004, ADR-0013, ADR-0021, ADR-0025, ADR-0027, ADR-0028, ADR-0029,
invariants #10, #13, `approval-and-attribution.md`.
**Backend:** the audit and Job query seams — kind, principal, time range, Node, Operation,
outcome, cursor pagination — exposed through the **capability layer's read lane** (#441, never
Console→store); the SSE seam's MCP tool-call, Job, registry and enrollment publishers (D9, #416),
which carry arguments but **never** read results; Cancel through the capability layer (v0.7.0).

Activity absorbed the Agents screen ([03](03-agent-sessions.md), D17). The line between it and
[20 — Access](20-access.md) is the reader's question: Activity answers "what was asked of the
control plane, and what did it do to the fleet?"; Access answers "who got in, and who changed who
can get in?". Activity is a log of tool calls and nothing else (owner decision, 2026-10-01).

## What this screen is for

An operator earns trust in an AI-driven control plane by **watching it work**. This surface shows
the actual requests — an AI-agent's, and a person's through MCP or the Control API — beside their
fleet-side effects, a second ago or last Tuesday. Live, it shows what is happening; scrolled back
or filtered, it is the audit trail. One renderer serves both, so the two cannot drift apart.

**What it can honestly show is the request, not the reasoning.** The Relay sees tool calls; it
does not see the model's intent, and it must never pretend to. A verified record of what was asked
beats a narrated account of why, which an agent under prompt injection would happily fabricate.
The screen has **no lede** (D34): the heading and the rows say what it is. Nothing on it says
"every call an AI-agent makes" — it lists calls that reached the Relay, and it cannot tell an
AI-agent from a person using the same surface.

## Grain

**One row per audited call.** A `run_operation`, a `raw_exec`, a Preflight, a refusal, a Cancel
and an approval decision are each one row. A dispatching call creates exactly one Job, so **its
row is that Job**: it fills in live and expands to Tasks on demand. One `mutate` across 2,214 Nodes
is one row; a Task-grained tail would become unreadable exactly when something important happens.

**Only tool calls are rows.** Freeze transitions, Node revokes, Enrollment Token mints and revokes,
and every other record kind that is not a tool call (a Node's `protocol_violation`, or a kind this
screen does not yet classify) are not on this screen; they remain on the audit trail. Sign-ins,
step-up, Account changes and API Token mints and revokes are on [20 — Access](20-access.md).

## Row kinds

| Kind | Carries |
|---|---|
| `dispatch` | Operation + args, risk badge, requester chips, Selector with resolved fan-out, plan hash, approver if it was parked, live outcome counts, Job link; while running, a running marker linking to its entry in [Running now](#running-now), which holds Cancel |
| `plan` | a Preflight: the arguments, the grouped verdicts and `would_be_rejected`, and a line saying nothing executed and each Node's own engine answered. Its badge is distinct, because it is the trust-critical case |
| `approval` | what is parked, quorum state, TTL — and no link to decide, because the Console decides no approval (ADR-0044); an in-band elicitation (ADR-0029) with the deciding identity as a verified chip once decided |
| `refusal` | the capability layer's refusal, rendered slate and informative, never as an error — the role gate refusing `raw_exec` to a non-`admin`, for one |
| `read` | the arguments and a metadata-only result line; no output, and no per-row sentence saying the output is not retained (D34) |
| `cancel` | which Job, by whom |

A record kind no family above claims is not drawn here; it stays on the audit trail.

The tool surface is eight tools: `list_nodes`, `describe_node`, `list_operations`, `get_job`,
`run_operation`, `raw_exec`, `cancel_job`, `approve_request`. A Preflight is `plan: true` on
`run_operation` / `raw_exec` (the wire keeps that spelling; GLOSSARY.md), not a separate tool.

**A running Job before its dispatch is recorded.** A running Job with no dispatch audit row yet
shows as a **Running** row, sourced only from the Job row: requester, Operation, risk class and
resolved/total. Selector, arguments and approver are audit-joined and appear once the dispatch
record is written. Its Cancel is in [Running now](#running-now).

## Running now

A section above the stream lists the Jobs still running, **longest-running first**, five at a
time, so a running Job is never out of sight: in the time-ordered stream, a Job that has run for
hours sits pages down.

- **Each entry** carries the Operation (with the Raw Exec tier drawn exactly as on the stream),
  the verified requester, how long it has been running, resolved/total, a link to Job detail, and
  **Cancel**.
- **Cancel lives here and only here.** A running Job appears twice on the page — here and in the
  stream — and the page draws exactly one Cancel per Job, so this section owns it. The stream's row
  says the Job is running and links up to its entry. Cancel is gated by `cancelOffered` exactly as
  on Job detail ([13](13-job-detail.md)); viewers see the section but are never offered Cancel.
- **It pages on its own.** Its cursor (`?rc=`) is independent of the stream's, and it always says
  how many are running in all ("12 running · 1–5").
- **It follows `?account=` and nothing else.** Kind chips and the time window narrow the stream,
  never this section: no window may hide an old running Job.
- **It does not reorder under the reader.** A Job that finishes is marked finished in place and
  its Cancel hidden, without reflow; Jobs that start later arrive through Refresh and the "new
  events" control ("Live but stable" below).
- **One audited read.** The section is one running-only Job read through the capability layer's
  read lane (ADR-0025).
- **Empty is said plainly.** With nothing running it says "Nothing is running" (under `?account=`,
  that Account has nothing running) — except on a trail with no calls other than reads recorded yet, where it folds
  into the one explanatory block below ("Nothing recorded yet").

## Identity on every row

The verified/asserted grammar from `00-foundations.md`, without exception. `requested_by` and
`approved_by` are verified — the Relay authenticated them. `on_behalf_of` is asserted — the caller
claimed it and nothing checked. Blurring the two is how audit trails become fiction: a jailbroken
AI-agent can assert anything, but it cannot forge the verified fields.

**Person or machine Account.** On a `dispatch` row the requester's verified chip is followed by a
kind label, `human` or `machine` (`00-foundations.md`). **Where a dispatch row shows its
requester's kind, it is read from the kind the Job row recorded for its requester when the Job was
created, and from nothing else.** A Job that recorded no kind shows no label, and none is inferred.
The label is drawn only beside a verified chip; a requester with no recorded Account ID renders
dashed and gets none. Other rows show no kind: their audit records carry none. Nothing beside an
actor says how it authenticated.

### Kind is never read from the registry

Owner decision, 2026-09-08. A registry read would report the Account's **current** kind, so a
machine Account later converted to human would relabel its own history, and the screen would lie
about the past. It would also widen what this screen can see beyond the audited lane's own rows.
The security-relevant distinction — verified versus claimed identity — is already on every row, as
the trust chip. `00-foundations.md`, [13](13-job-detail.md) and [15](15-accounts-and-tokens.md)
cite this section.

## There are no sessions

**There are no sessions.** The MCP transport is stateless (ADR-0028; `Stateless: true`, no
`Mcp-Session-Id` — a Job ID is the durable handle). Every tool call is an independent,
authenticated request: no connect time, no idle state, nothing to disconnect. Stopping one actor
is revoking its API Tokens ([15](15-accounts-and-tokens.md)) or Freeze
([16](16-incident-ladder.md)); suspension is deferred (ADR-0035, not adopted; #443). There is no
list of active Accounts; `?account=` scopes the stream (Filtering and export).

## Reads

**With no kind filter, read records are left out.** Enumeration and polling — every Account's
`list_nodes`, `describe_node` and `get_job` calls, and every read of the trail — would otherwise
bury the calls that change something. While no kind filter is set, one plain sentence under the
kind chips says read records are left out and links to them, reads made from this Console included (the `read` chip with `?console=show`,
keeping the other filters), so following it never hides the reads this screen's own loads made. Activity is the only screen over these records ([17](17-read-egress.md) is retired).

Read **calls** are audited — who, which tool, what they asked for, when — and an unauditable read
fails closed (ADR-0025). Read **output** is never retained. A read row shows none and does not say
so on every row (D34) — the property is the docs'; no detail view promises to show it later.

### Reads made from this Console

Most Console screens read through the capability layer's audited read lane, so most pages an
operator opens — every reload of this one included — are calls on the trail, attributed to their
own Account. Shown, they would bury everything else within minutes.

**Where this screen lists read records, a record is left out by default only when it says BOTH
that its identity was established by a Console session AND that it was a read.**

- **"Made from this Console" is read from the record as written**: the authentication method on
  the verified lane (`console_session`). It means a Console session cookie authenticated the call,
  not that a person was at the keyboard. The rule never reads the Account registry or a kind.
- **"A read" is read from the row itself**: its record kind is `read` AND the risk class the row
  renders is `read`. Where the row does not carry enough to tell, it is treated as not a read and
  stays listed.
- **Everything that is not a read stays listed whatever its method**: a mutate-class call, an
  approval decision, a Cancel, a refusal, a Preflight, including those made from a Console session.
- **The residual, stated plainly.** Reads made with a stolen Console session cookie, or by
  software driving an operator's browser, carry the same record as the operator's own page loads.
  They are left out by default, counted in the visible sentence, and one click away.
- **The exclusion is never silent.** Where it is in force, one plain sentence says that reads made
  from this Console are left out and how many — of the calls on this page, or, where `?account=` is
  set, of that Account's calls on this page — and links to the same view with them shown
  (`?console=show`). With that parameter set, the screen lists and counts exactly as it would
  without this rule, and the sentence offers the way back.
- **It composes with every other filter.** Every link the screen draws — Older, Newest,
  "Show every Account" and Refresh — carries `?account=` and `?console=` as it found them.
- **It is presentation over the fetched page.** No read is added or widened. The sentence's count
  keeps the arithmetic visible.
- **The method decides what is listed and is never displayed.**
- **Empty states stay true.** Where the feed is empty only because every call on the
  page was a read made from this Console, it says that, rather than that nobody called. An empty page reached by Older says only that nothing is older
  than that point.

## Polling

Consecutive calls that would render **identically** apart from their timestamp collapse into one
row carrying their count. Equivalence is the whole rendered row: a poll of a different Job, a
different outcome or risk class never joins a run, and a `raw_exec` between two runs of `get_job`
polls stays its own row. Runs must be **consecutive**: collapsing non-adjacent calls would reorder
the trail, which on an audit screen is worse than the crowding. Collapsing is presentation over the
fetched page and never crosses a page boundary.

**A collapsed run is a `×N` chip on its row** (D34), whose tooltip (`title`) gives the run's time
range, first call to last. No sentence on the row or the page says how many calls were collapsed
into how many rows, or that each call is still on the audit trail.

## Live but stable

New events **queue behind an explicit click** rather than pushing in. Nothing moves under what
someone is reading (foundations rule 6, not negotiable here).

**Where events have queued, the live region becomes the control: "Live · 3 new"** (D34) — a
button, not small text, that reloads the page at its newest page with the current filter
preserved. No sentence beside it explains the number; its tooltip (`title`) says what it counts:
events on the stream, not rows that will appear, from a stream this page's filter does not narrow,
where one Job announces itself more than once. It is a Refresh in the sense of `00-foundations.md`
("Refreshing a screen"), never a timer, and like every Refresh it carries no sentence saying it is
an audited read. The kind chips' sentence still says the default leaves reads made from this
Console out (Reads made from this Console, above).

The live region states its condition in words alone — "Live", "Live · N new", "Not connected",
and the rest — with no pulsing dot or other animation.

## Filtering and export

Kind chips, one per row kind above, a mutate-only toggle, a hide-polling toggle, and one filter
box over principal, Operation, arguments, Selector, outcome, Node and plan hash. The same filters
apply to the live tail and to history. Time controls: live tail, a relative window, an explicit
range. Export for an auditor. The export carries the same tool-call rows as the screen, so Freeze
transitions, Node revokes, Enrollment Token mints and revokes, `protocol_violation` and revoked
Node dials are not in it; they remain on the audit trail.

`?account=` scopes the stream and Running now to one Account. It names the **verified Account
ID**, never a name: a name can later belong to a different Account. The Accounts screen's
last-call link uses it ([15](15-accounts-and-tokens.md)). The Principal box takes the Account's ID,
and its placeholder says so. Lookup by name waits for an audited Account-read path (#659).

What follows is recorded here rather than on the screen (D31, D34); no page-size sentence is drawn.
A page holds up to a fixed number of dispatches and, separately, of other events, merged by time;
the two lanes page separately, so a page does not end at a single moment, and Older continues each
lane from where it stopped (a filter that reads only one lane does end at a single moment). The
filter box offers no Selector and no Node field yet: the Job query has a field for neither, a Job
spans its Selector's whole fan-out and so has no single Node, and a Node filter that narrowed only
the other events would silently drop every dispatch row. The export is the fetched rows, not the
screen: it includes reads made from this Console and never collapses consecutive calls. The kind
chips carry no counts: counting each family across the whole trail would take one query per
family, and each query appends its own read record. The messages a request provokes stay visible
where they render: a part of the URL that could not be read, an unknown row kind, what an outcome
filter does to the page, and the read sentences above.

## Nothing recorded yet

On a Relay where nothing has been recorded and no filter is applied (D29), the screen draws **one
explanatory block** in place of an empty feed and an empty Running now — "When an AI-agent or an
operator dispatches a Task, or calls any tool, it appears here." — with the live region's state
beside it, because whether the stream is connected is what someone watching an empty screen needs
to know. The filters sit in a closed native `<details>` below: there is nothing yet to narrow.

The heading names what the default leaves out because a trail with nothing on it is never what
someone looking at it sees: every load of this screen is itself an audited read ("Reads made from
this Console"). With no kind filter the feed leaves reads out, so the heading is true whenever it
is drawn, and the read-records sentence beside the kind chips leads to the reads. An unfiltered
first page with an empty feed says the same sentence wherever the block is not drawn. No read is
added to tell an empty trail from one holding only reads.

The condition is **no filter applied** — no kind chip, toggle, filter text, window or `?account=`
other than the defaults. Where any filter is applied and nothing matches, the filters stay open and
the screen says that nothing matches this filter, not that nothing has happened: those are
different facts, and "Empty states stay true" above governs both.

## Interruption

**There is no hold-before-dispatch timer.** Interruption is **cancellation**: `TaskCancel` kills the process group, the daemon reports
`OUTCOME_CANCELLED`, a Task that already finished reports its real outcome rather than a
retroactive cancel, and the cancelled Task ID stays deduped so at-most-once still holds
(ADR-0013, invariant #4).

Cancel sits in [Running now](#running-now), one per Job per page. Token revocation is
[15](15-accounts-and-tokens.md); Freeze is [16](16-incident-ladder.md).

## Must not appear

- Task-grained rows in the default view.
- Retained read output, anywhere, at any age.
- Sign-ins, step-up, Account changes, or API Token mints and revokes — those are
  [20 — Access](20-access.md).
- Any row the Relay cannot attribute — if attribution is missing, that is a bug to surface, not a
  blank to render.
- Any claim about what the model was thinking, planning, or intending; prompt text, system
  prompts, or conversation content — the Relay does not have them and must not invent a place for
  them.
- A scheduled or automatic replay of any call.
- Rows for fleet events that are not tool calls (freeze transitions, Node revokes, Enrollment
  Token mints and revokes, protocol_violation), or a kind chip for one. They are on the audit
  trail.
- A pulsing or animated live indicator. The live region says its state in words.
- A Disconnect, End session, or Suspend control, or the word "connected" — nothing they would act
  on exists.

## Acceptance

- [ ] A Job touching 4,000 Nodes occupies one row that fills in live.
- [x] Every one of the eight tools renders with a request line and a result line.
- [ ] An auditor answers "who asked, for whom, who approved, what happened" from this screen in
      one query, with the verified/asserted distinction visible without hovering.
- [ ] Live updates never reflow a row the user is reading.
- [ ] Live tail and historical query use the same renderer.
- [ ] A read row carries no output at any age, and no per-row sentence about it.
- [x] Polling collapses; an Account making 200 `get_job` calls does not push everything else off.
- [x] A `raw_exec` refused by the role gate renders informative-neutral, not as an error.
- [x] Only tool-call rows appear: no freeze, Node revoke, Enrollment Token or other row, and no
      chip for one.
- [x] There is no Who-is-active strip; ?account= still scopes the stream and Running now.
- [x] The live region carries no pulsing dot; its text states its condition.
- [ ] No sign-in, step-up, Account or API Token row appears here, for any role.
- [x] An in-flight dispatch is cancellable from this screen (v0.7.0) and the cancellation is
      audited, from Running now.
- [x] A running Job of any age is visible on the first page, in Running now, longest-running
      first, whatever the time window or kind filter.
- [x] Each running Job draws exactly one Cancel on the page, in Running now; its stream row links
      to it.
- [x] Paging Running now never moves the stream, and paging the stream never moves Running now.
- [x] A Job that finishes while the page is open is marked finished in place; the section never
      reorders under the reader.

## Jobs

There is no Jobs destination (D6). This screen filtered to `dispatch` **is** the Jobs list, and
the filter must be a first-class, linkable state. Job detail is its own page, reached from any
dispatch row here.
