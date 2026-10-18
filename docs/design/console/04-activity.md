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

*(Owner decision, 2026-09-29: this screen absorbed the Agents screen, formerly
[03](03-agent-sessions.md), and gave up sign-ins and Account changes to
[20 — Access](20-access.md). The line between the two is the reader's question. Activity answers
"what was asked of the control plane, and what did it do to the fleet?". Access answers "who got
in, and who changed who can get in?")*

*(Owner decision, 2026-10-01, #829: Activity is a log of the tool calls that went through the
control plane, and nothing else. The "Who is active" strip, the rows for fleet events that are not
tool calls (freeze transitions, Node revokes, Enrollment Token mints and revokes, and any other
record kind), their kind chips, and the live region's pulsing dot were removed. Those events stay
on the audit trail. Giving them a home is a follow-up, not this screen.)*

## What this screen is for

An operator earns trust in an AI-driven control plane by **watching it work**. This is the surface
that shows the actual requests — an AI-agent's, and a person's through MCP or the Control API —
beside their fleet-side effects, whether that was a second ago or last Tuesday. With live updates
on, it shows what is happening. Scroll back or filter, and it is the audit trail. The same rows,
chips and renderer serve both, because two screens would mean two renderers of the same events
that drift apart.

**What it can honestly show is the request, not the reasoning.** The Relay sees tool calls; it
does not see the model's intent, and it must never pretend to. A verified record of what was asked
beats a narrated account of why, which an agent under prompt injection would happily fabricate.
The lede says the screen lists calls that reached the Relay, and never "every call an AI-agent
makes": the screen cannot tell an AI-agent from a person using the same surface.

## Grain

**One row per audited call.** A `run_operation`, a `raw_exec`, a Preflight, a refusal, a Cancel
and an approval decision are each one row. A dispatching call creates exactly one Job, so **its
row is that Job**: it fills in live and expands to Tasks on demand. One `mutate` across 2,214 Nodes
therefore still occupies one row, not 2,214. A naive Task-grained tail would become unreadable
exactly when something important is happening.

**Only tool calls are rows.** Freeze transitions, Node revokes, Enrollment Token mints and
revokes, and every record kind that is not a tool call (a Node's protocol_violation, and any kind
added to the trail before this screen classifies it) are not on this screen. They remain on the
audit trail, and surfacing them is follow-up work. Sign-ins, step-up, Account changes and API Token mints and
revokes are **not** on this screen. They are on [20 — Access](20-access.md).

## Row kinds

| Kind | Carries |
|---|---|
| `dispatch` | Operation + args, risk badge, requester chips, Selector with resolved fan-out, plan hash, approver if it was parked, live outcome counts, Job link; while running, a running marker linking to its entry in [Running now](#running-now), which holds Cancel |
| `plan` | a Preflight: the arguments, the grouped verdicts and `would_be_rejected`, and a line saying nothing executed and each Node's own engine answered. Its badge is distinct, because it is the trust-critical case |
| `approval` | what is parked, quorum state, TTL — and no link to decide, because the Console decides no approval (ADR-0044); an in-band elicitation (ADR-0029) with the deciding identity as a verified chip once decided |
| `refusal` | the capability layer's refusal, rendered slate and informative, never as an error — the role gate refusing `raw_exec` to a non-`admin`, for one |
| `read` | the arguments and a metadata-only result line that explicitly says the output is not retained |
| `cancel` | which Job, by whom |

A record kind no family above claims is not drawn here. It stays on the audit trail (owner
decision, 2026-10-01, which reverses D18 point 4's other row).

The tool surface is eight tools: `list_nodes`, `describe_node`, `list_operations`, `get_job`,
`run_operation`, `raw_exec`, `cancel_job`, `approve_request`. A Preflight is `plan: true` on
`run_operation` / `raw_exec` — the option keeps its old spelling on the wire until the code
follows (GLOSSARY.md) — not a separate tool.

**A running Job before its dispatch is recorded (#617).** A Job still running with no dispatch
audit row yet shows as a **Running** row, sourced only from the Job row: requester, Operation,
risk class and resolved/total. Selector, arguments and approver appear once the dispatch record is
written, because they are audit-joined. Its Cancel is in [Running now](#running-now), like every
running Job's.

## Running now

A section above the stream lists the Jobs still running, **longest-running first**, five at a
time. It exists so that a running Job is never out of sight, however far back in the history it
started: the stream is ordered by time, so a Job that has run for hours sits pages down it.

- **Each entry** carries the Operation (with the Raw Exec tier drawn exactly as on the stream),
  the verified requester, how long it has been running, resolved/total, a link to Job detail, and
  **Cancel**.
- **Cancel lives here and only here.** A running Job appears twice on the page — once here and
  once in the stream at its own time — and spec 04 draws exactly one Cancel per Job per page, so
  the section owns it. The stream's row says the Job is running and links up to its entry. Cancel
  is gated by `cancelOffered` exactly as Job detail's is ([13](13-job-detail.md)); viewers see the
  section but are never offered Cancel.
- **It pages on its own.** Its cursor (`?rc=`) is independent of the stream's, so paging one never
  moves the other, and it always says how many are running in all ("12 running · 1–5").
- **It follows `?account=` and nothing else.** The kind chips and the time window narrow the
  stream, never this section: an old running Job is the reason the section exists, so no window
  may hide one.
- **It does not reorder under the reader.** For one page load the section holds the same entries.
  A Job that finishes is marked finished in place and its Cancel is hidden, without reflowing
  anything; Jobs that start later arrive through Refresh and the "new events" control, per "Live
  but stable" below.
- **One audited read.** The section is one running-only Job read through the capability layer's
  read lane (ADR-0025) — the read the Agents screen made before it was retired, not a new kind of
  read.
- **Empty is said plainly.** With nothing running, the section says "Nothing is running", and
  under `?account=` it says that Account has nothing running — except on a trail with nothing
  recorded yet, where the section folds into the one explanatory block below ("Nothing recorded
  yet").

## Identity on every row

The verified/asserted grammar from `00-foundations.md`, without exception. `requested_by` is
verified — the Relay authenticated it. `on_behalf_of` is asserted — the caller claimed it and
nothing checked. `approved_by` is verified. Blurring the two is how audit trails become fiction: a
jailbroken agent can assert anything, but it cannot forge the verified fields.

**Whether the requester is a person or an AI-agent's machine Account.** On a `dispatch` row the
requester's verified chip is followed by a kind label, `human` or `machine` (the treatment is in
`00-foundations.md`). **Where a dispatch row shows its requester's kind, it is read from the kind
the Job row recorded for its requester when the Job was created, and from nothing else.** It is
never read from the Account registry's current kind. A Job that recorded no kind — one created
before the Job row carried its requester — shows no label, and the screen does not infer one from
the trail or anywhere else. The label is drawn only beside a verified chip; a requester with no
recorded Account ID renders dashed and gets none. Rows other than `dispatch` show no kind: their
audit records carry none. Nothing beside an actor says how it authenticated (owner decision,
2026-09-29).

### Kind is never read from the registry

Owner decision, 2026-09-08, #540. An Account-registry reader would report the Account's
**current** kind, so a machine Account later converted to human would retroactively relabel its
own history, and the screen would lie about the past. It would also widen what this screen can
see, against #542's direction of narrowing it to the audited lane's own rows. The
security-relevant distinction — verified authentication versus a claimed identity — is already on
every row, as the trust chip. `00-foundations.md`, [13](13-job-detail.md) and
[15](15-accounts-and-tokens.md) cite this decision here.

## There are no sessions

**There are no sessions.** The MCP transport is stateless (ADR-0028; `Stateless: true`, no
`Mcp-Session-Id` — a Job ID is the durable handle). Every tool call is an independent,
authenticated request. There is no connect time, no idle state, and nothing to disconnect.
Stopping one actor today is revoking its API Tokens ([15](15-accounts-and-tokens.md)) or Freeze
([16](16-incident-ladder.md)); suspension is deferred (ADR-0035, not adopted; #443).

(The "Who is active" strip that stood here, which listed Accounts with a call in the last 15
minutes, was removed by owner decision, 2026-10-01, #829. `?account=` scoping stays: see
Filtering and export.)

## Reads

**With no kind filter, read records are left out.** Enumeration and polling — every Account's
`list_nodes`, `describe_node` and `get_job` calls, and every read of the trail — would otherwise
bury the calls that change something. One plain sentence under the kind chips, drawn while no kind
filter is set, says read records are left out, and links to them (the `read` chip, keeping the
other filters). Activity is the only screen over these records; the Read egress screen
([17](17-read-egress.md)) was retired on 2026-10-01. Where a kind filter is set, no
sentence is drawn. The reasoning is this section; the screen states only that sentence and its
link (#849).

Read **calls** are audited — who, which tool, what they asked for, when — and an unauditable read
fails closed (ADR-0025). Read **output** is never retained. A read row says so, and no detail view
promises to show it later.

### Reads made from this Console

Most screens this Console renders read through the capability layer's audited read lane (the
built Approvals queue does not, #779; it is retired with the Console's approval surface,
ADR-0044). So most pages an operator opens are
themselves calls on the trail, attributed to their own Account, and every reload of this screen is
one. Where read records are shown, they would bury everything else within minutes of use.

**Where this screen lists read records, a record is left out by default only when it says BOTH
that its identity was established by a Console session AND that it was a read.**

- **"Made from this Console" is read from the record as written**: the authentication method on
  the verified lane (`console_session`), recorded when the call was made. It means the call was
  authenticated by a Console session cookie, not that a person was at the keyboard. The rule never
  reads the Account registry or an Account's kind.
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
- **It is presentation over the fetched page.** The lane is asked for the same page with the same
  filter it always was; no read is added or widened. The page note says what the page holds, not
  what the feed shows, and the sentence's count keeps the arithmetic visible.
- **The method decides what is listed and is never displayed.**
- **Empty states stay true.** Where the feed is empty only because every call on the
  page was a read made from this Console, it says that, rather than that nobody called.

## Polling

Consecutive calls that would render **identically** apart from their timestamp collapse into one
row carrying the count of calls it stands for (#541). Equivalence is the whole rendered row, not
just Account and tool: a poll of a different Job, a different outcome or a different risk class
never joins a run, and a `raw_exec` between two runs of `get_job` polls stays its own row. Runs
must be **consecutive**: collapsing non-adjacent calls would reorder the trail, which on an
audit-facing screen is worse than the crowding it fixes. A collapsed row carries its own count. The page note says how much was
collapsed. This is presentation over the fetched page only: it does not reach back past the page
boundary.

## Live but stable

New events **queue behind an explicit click** ("3 new events — show") rather than pushing in.
Nothing moves under what someone is reading. This is rule 6 of the foundations and it is not
negotiable on a screen whose whole job is careful reading.

**Where events have queued, the click is an obvious control**: drawn as a button, not as a line of
small text, and it reloads the page with the current filter preserved, at its newest page. Beside
it, one sentence says what the number counts, in plain lower-case words: events on the stream, not
rows that will appear, from a stream this page's filter does not narrow, where one Job announces
itself more than once. The control is a Refresh in the sense of `00-foundations.md` ("Refreshing a
screen"): a deliberate click, never a timer. One visible sentence beside the Refresh control says
that every reload is an audited read made from this Console; the kind chips' own visible note says
the default above leaves such reads out.

The live region states its condition in words alone ("Live.", "The live stream is not
connected.", and the rest). It draws no pulsing dot or other animated indicator (owner decision,
2026-10-01).

## Filtering and export

Kind chips, one per row kind above, a mutate-only toggle, a hide-polling toggle, and one filter box over principal,
Operation, arguments, Selector, outcome, Node and plan hash. The same filters apply to the live
tail and to history. Time controls: live tail, a relative window, an explicit range. Export for an
auditor. The export carries the same tool-call rows as the screen, so Freeze transitions, Node revokes,
Enrollment Token mints and revokes, `protocol_violation` and revoked Node dials are not in it; they remain on the audit trail
(owner decision, 2026-10-01, #829), and a home for them is follow-up work.

`?account=` scopes the stream and Running now to one Account. It names the **verified Account
ID**, never a name, because a name can later belong to a different Account and an ID never does.
The Accounts screen's last-call link uses it ([15](15-accounts-and-tokens.md)).
The Principal box takes the Account's ID, and its placeholder says so. Looking an Account up by name
is deferred until an audited Account-read path exists (#659): the registry read it needs is one no
audit record covers.

The screen carries no "About this screen" disclosure (owner decision, 2026-10-18, D30;
`00-foundations.md`). That every Refresh is an audited read made from this Console is said in one
visible sentence beside the Refresh control; how a page is bounded is the page note's; which events
are on the audit trail rather than here, like everything below, is recorded here and not repeated
on the screen (#849).
A page holds up to a fixed number of dispatches and, separately, of other events, merged by time;
the two lanes page separately, so a page does not end at a single moment, and Older continues each
lane from where it stopped (a filter that reads only one lane does end at a single moment). The
filter box offers no Selector and no Node field yet: the Job query has a field for neither, a Job
spans its Selector's whole fan-out and so has no single Node, and a Node filter that narrowed only
the other events would silently drop every dispatch row. The export is the fetched rows, not the
screen: it includes reads made from this Console and never collapses consecutive calls. The kind
chips carry no counts: counting each family across the whole trail would take one query per family,
and each query appends its own read record to the trail. Why the screen shows the request and never
the reasoning is stated above; why read records are left out is under Reads; that there are no
sessions is its own section. The messages a
request provokes stay visible where they render: a part of the URL that could not be read, an
unknown row kind, what an outcome filter does to the page, and the read sentences above.

## Nothing recorded yet

On a Relay where nothing has been recorded and no filter is applied (owner decision, 2026-10-18,
D28), the screen does not draw an empty feed and an empty Running now one above the other. It
draws **one explanatory block** in their place, saying what will appear here and how — "When an
AI-agent or an operator dispatches a Task, or calls any tool, it appears here." — and keeps the
live region's sentence ("Live." and the rest) beside it, because whether the stream is connected is
exactly what someone watching an empty screen needs to know. The filters sit in a native
`<details>`, closed, below the block: there is nothing yet to narrow.

The condition is **no filter applied** — no kind chip, toggle, filter text, window or `?account=`
other than the defaults. Where any filter is applied and nothing matches, the filters stay open and
the screen says that nothing matches this filter, not that nothing has happened: those are
different facts, and "Empty states stay true" above governs both.

## Interruption

**There is no hold-before-dispatch timer.** It was considered and dropped. Interruption is
**cancellation**, which already exists: `TaskCancel` kills the process group, the daemon reports
`OUTCOME_CANCELLED`, a Task that already finished reports its real outcome rather than a
retroactive cancel, and the cancelled Task ID stays deduped so at-most-once still holds
(ADR-0013, invariant #4).

Cancel sits in [Running now](#running-now) (v0.7.0), gated by `cancelOffered` exactly as Job
detail's is ([13](13-job-detail.md)), and a Job draws exactly one on the page wherever else it
appears. Viewers see running Jobs but are never offered Cancel. Token revocation is
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
- [ ] A read row carries no output at any age, and states that.
- [x] Polling collapses; an Account making 200 `get_job` calls does not push everything else off.
- [x] A `raw_exec` refused by the role gate renders informative-neutral, not as an error.
- [x] Only tool-call rows appear: no freeze, Node revoke, Enrollment Token or other row, and no
      chip for one.
- [x] There is no Who-is-active strip; ?account= still scopes the stream and Running now.
- [x] The live region carries no pulsing dot; its text states its condition.
- [ ] No sign-in, step-up, Account or API Token row appears here, for any role.
- [x] An in-flight dispatch is cancellable from this screen (v0.7.0) and the cancellation is
      audited. **Met on Activity (#786)**; the control moves into Running now with that section.
- [x] A running Job of any age is visible on the first page, in Running now, longest-running
      first, whatever the time window or kind filter.
- [x] Each running Job draws exactly one Cancel on the page, in Running now; its stream row links
      to it.
- [x] Paging Running now never moves the stream, and paging the stream never moves Running now.
- [x] A Job that finishes while the page is open is marked finished in place; the section never
      reorders under the reader.

## Jobs

There is no separate Jobs destination (D6). This screen filtered to `dispatch` **is** the Jobs
list, and the filter must be a first-class, linkable state rather than something a user has to
reconstruct. Job detail remains its own page, reached from any dispatch row here.
