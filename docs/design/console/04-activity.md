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

Fleet events that are not tool calls are rows too: freeze transitions, Node revokes, and
Enrollment Token mints and revokes. Sign-ins, step-up, Account changes and API Token mints and
revokes are **not** on this screen. They are on [20 — Access](20-access.md).

## Row kinds

| Kind | Carries |
|---|---|
| `dispatch` | Operation + args, risk badge, requester chips, Selector with resolved fan-out, plan hash, approver if it was parked, live outcome counts, Job link, Cancel while running (v0.7.0) |
| `plan` | a Preflight: the arguments, the grouped verdicts and `would_be_rejected`, and a line saying nothing executed and each Node's own engine answered. Its badge is distinct, because it is the trust-critical case |
| `approval` | what is parked, quorum state, TTL, a link to decide; an in-band elicitation (ADR-0029) with the deciding identity as a verified chip once decided |
| `refusal` | the capability layer's refusal, rendered slate and informative, never as an error — the role gate refusing `raw_exec` to a non-`admin`, for one |
| `read` | the arguments and a metadata-only result line that explicitly says the output is not retained |
| `cancel` | which Job, by whom |
| `freeze` | engage or release, by whom, held for how long, with the reason |
| `node` | a Node revoked, by whom |
| `token` | an Enrollment Token minted or revoked: by whom, its scope, uses and expiry |

The tool surface is eight tools: `list_nodes`, `describe_node`, `list_operations`, `get_job`,
`run_operation`, `raw_exec`, `cancel_job`, `approve_request`. A Preflight is `plan: true` on
`run_operation` / `raw_exec` — the option keeps its old spelling on the wire until the code
follows (GLOSSARY.md) — not a separate tool.

**A running Job before its dispatch is recorded (#617).** A Job still running with no dispatch
audit row yet shows as a **Running** row, sourced only from the Job row: requester, Operation,
risk class, resolved/total and Cancel. Selector, arguments and approver appear once the dispatch
record is written, because they are audit-joined.

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

## Who is active

A strip above the stream lists each Account with a call in the last **15 minutes**: name, role,
first and last call, call count, mutate count. Selecting one scopes the stream to it (`?account=`).
It is how an operator sees who is driving right now.

**There are no sessions.** The MCP transport is stateless (ADR-0028; `Stateless: true`, no
`Mcp-Session-Id` — a Job ID is the durable handle). Every tool call is an independent,
authenticated request. *Active* means "has made a call within 15 minutes", never "connected".
There is no connect time, no idle state, and nothing to disconnect. Stopping one actor today is
revoking its API Tokens ([15](15-accounts-and-tokens.md)) or Freeze
([16](16-incident-ladder.md)); suspension is deferred (ADR-0035, not adopted; #443).

**The strip is scoped twice, and says so.** Membership is the 15 minutes: an Account not seen in
that long is not listed. The numbers beside a listed Account are counted over the fetched
**page**, the same page the stream renders, so every entry is verifiable by scrolling to its rows.
The stream itself is never filtered by the 15 minutes: it is the history. An Account whose most
recent call on the page is older than 15 minutes drops off the strip, and the strip says how many
dropped. On this screen "window" means the 15 minutes and nothing else; the page is called the
page, never the window.

**Running rows do not count on the strip (#617).** They are read from the Job row, not from an
audited call, so the strip's fields stay call-grained. A Job joins the strip once its dispatch is
recorded. An otherwise empty strip over a page showing only running Jobs says so, rather than
saying nobody has called.

## Reads

**With no kind filter, read records are left out.** Enumeration and polling — every Account's
`list_nodes`, `describe_node` and `get_job` calls, and every read of the trail — would otherwise
bury the calls that change something. One plain sentence under the kind chips, drawn while no kind
filter is set, says read records are left out, and links to them (the `read` chip, keeping the
other filters) and to [17 — Read egress](17-read-egress.md). Where a kind filter is set, no
sentence is drawn. The reasoning stays in the disclosure.

Read **calls** are audited — who, which tool, what they asked for, when — and an unauditable read
fails closed (ADR-0025). Read **output** is never retained. A read row says so, and no detail view
promises to show it later.

### Reads made from this Console

Most screens this Console renders read through the capability layer's audited read lane (the
Approvals queue does not; that is a known gap, #779). So most pages an operator opens are
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
- **It composes with every other filter.** Every link the screen draws — the strip, Older, Newest,
  "Show every Account" and Refresh — carries `?account=` and `?console=` as it found them.
- **It is presentation over the fetched page.** The lane is asked for the same page with the same
  filter it always was; no read is added or widened. The page note says what the page holds, not
  what the feed shows, and the sentence's count keeps the arithmetic visible.
- **The method decides what is listed and is never displayed.**
- **Empty states stay true.** Where the strip or the feed is empty only because every call on the
  page was a read made from this Console, it says that, rather than that nobody called.

## Polling

Consecutive calls that would render **identically** apart from their timestamp collapse into one
row carrying the count of calls it stands for (#541). Equivalence is the whole rendered row, not
just Account and tool: a poll of a different Job, a different outcome or a different risk class
never joins a run, and a `raw_exec` between two runs of `get_job` polls stays its own row. Runs
must be **consecutive**: collapsing non-adjacent calls would reorder the trail, which on an
audit-facing screen is worse than the crowding it fixes. The strip keeps counting calls, never
rendered rows, and a collapsed row carries its own count. The page note says how much was
collapsed. This is presentation over the fetched page only: it does not reach back past the page
boundary.

## Live but stable

New events **queue behind an explicit click** ("3 new events — show") rather than pushing in.
Nothing moves under what someone is reading. This is rule 6 of the foundations and it is not
negotiable on a screen whose whole job is careful reading.

**Where events have queued, the click is an obvious control**: drawn as a button, not as a line of
small text, and it reloads the page with the current filter preserved, at its newest page. Beside
it, one sentence says what the number counts, in plain lower-case words: events on the stream,
not rows that will appear, from a stream this page's filter does not narrow, where one Job
announces itself more than once. The control is a Refresh in the sense of `00-foundations.md`
("Refreshing a screen"): a deliberate click, never a timer. The "About this screen" disclosure
says that every reload is an audited read, and that those reads are reads made from this Console,
so the default above leaves them out.

## Filtering and export

Kind chips, a mutate-only toggle, a hide-polling toggle, and one filter box over principal,
Operation, arguments, Selector, outcome, Node and plan hash. The same filters apply to the live
tail and to history. Time controls: live tail, a relative window, an explicit range. Export for an
auditor.

The screen's standing notes — how a page is bounded, the reasoning behind leaving read records
out, the row kinds and filter fields it cannot offer yet, why the kind chips carry no counts — sit
in the closed "About this screen" disclosure at its foot (`00-foundations.md`). The messages a
request provokes stay visible where they render: a part of the URL that could not be read, an
unknown row kind, what an outcome filter does to the page, and the read sentences above.

## Interruption

**There is no hold-before-dispatch timer.** It was considered and dropped. Interruption is
**cancellation**, which already exists: `TaskCancel` kills the process group, the daemon reports
`OUTCOME_CANCELLED`, a Task that already finished reports its real outcome rather than a
retroactive cancel, and the cancelled Task ID stays deduped so at-most-once still holds
(ADR-0013, invariant #4).

Cancel sits on a running dispatch row (v0.7.0), gated by `cancelOffered` exactly as Job detail's
is ([13](13-job-detail.md)). A Job with several dispatch rows on the page still draws exactly one.
Viewers see running Jobs but are never offered Cancel. Token revocation is
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
- [ ] Polling collapses; an Account making 200 `get_job` calls does not push everything else off.
- [x] A `raw_exec` refused by the role gate renders informative-neutral, not as an error.
- [ ] With no Account active in the 15 minutes, the strip says so plainly and does not fabricate
      activity.
- [ ] No sign-in, step-up, Account or API Token row appears here, for any role.
- [x] An in-flight dispatch is cancellable from this screen (v0.7.0) and the cancellation is
      audited. **Met on Activity (#786)**.

## Jobs

There is no separate Jobs destination (D6). This screen filtered to `dispatch` **is** the Jobs
list, and the filter must be a first-class, linkable state rather than something a user has to
reconstruct. Job detail remains its own page, reached from any dispatch row here.
