# 03 — Agent activity

**Artboard 11.** The live trust surface: every call an AI-agent makes, as it makes it.
**Milestone v0.6.0** for the read-only stream; **v0.7.0** for Cancel.

*(The file keeps its `03-agent-sessions.md` name so existing links hold. The screen is not about
sessions — see "There are no sessions" below.)*

**Governing:** ADR-0003, ADR-0013, ADR-0021, ADR-0025, ADR-0028, ADR-0029, invariants #10, #13.
**Backend:** the v0.6.0 SSE seam's MCP tool-call publisher (D9, #416), which carries arguments
but **never** read results; `KindRead` audit records and the audit query seams (#441) for history;
Cancel through the capability layer (v0.7.0).

## What this screen is for

An operator earns trust in an AI-driven control plane by **watching it work**. This is the only
surface that shows the agent's actual requests rather than their fleet-side effects.

**What it can honestly show is the request, not the reasoning.** The Relay sees tool calls; it
does not see the model's intent, and it must never pretend to. That limitation is a feature: a
verified record of what was asked beats a narrated account of why, which an agent under prompt
injection would happily fabricate.

**The lede claims no more than the screen lists.** It says the screen lists calls that reached the
Relay from outside this Console — which is where an AI-agent's calls arrive, and where a person's
arrive too when they call through MCP or the Control API — and it keeps the warning that the Relay
sees the request and never the reasoning. It does not say "every call an AI-agent makes": the
screen cannot tell an AI-agent from a person using the same surface, and by default it leaves out
reads made from this Console (below).

## There are no sessions

The MCP transport is **stateless** (ADR-0028; `Stateless: true`, no `Mcp-Session-Id` — a Job ID
is the durable handle). Every tool call is an independent, authenticated request. There is no
connection to show as "connected", no connect time, no idle state, and nothing to disconnect.

So the unit here is the **Account**, and *active* means "has made a call within the activity
window" — **15 minutes**. An earlier draft had a sessions rail with Disconnect and Suspend
controls; Disconnect had no object, and suspension is deferred (ADR-0035, not adopted; #443).
Stopping one actor today is revoking its API Tokens (spec 15) or Freeze (spec 16).

## Grain and retention — and why this is not Activity

| | Agent activity (this) | Activity (spec 04) |
|---|---|---|
| Grain | one MCP tool call | one Job |
| Scope | the Accounts active in the window | the whole control plane |
| Retention | payloads in flight only | durable audit |
| A `list_nodes` call | appears | never appears |

Keeping them apart is what lets each be honest about retention. Read **calls** are audited — who,
which tool, what they asked for, when — and an unauditable read *fails closed* (ADR-0025). Read
**output** is never retained. So this view has payloads while they are in flight and the scrollback
does not, and the screen says so rather than hiding it.

## Layout

```
[nav] │ Agents              every call an AI-agent makes, as it makes it     [mike · admin]
      ├────────────────┬─────────────────────────────────────────────────────────────────
      │ Active (15m)   │ [all] [run_operation] [raw_exec] [list_nodes] …  [mutate only]
      │ ● gleipnir-prod│ [ filter by argument, Selector, Node, plan hash            ]
      │   47 calls     │ ┌──────────────────────────────────────────────────────────┐
      │   3 mutate     │ │ → run_operation  [mutate]  plan=false     ● dispatching   │
      │   last 4s ago  │ │   args, selector, plan hash, approved-by                  │
      │ ○ gleipnir-stag│ │ ← job_9d41 · [====progress====] · [Cancel]                │
      │   last 12m ago │ └──────────────────────────────────────────────────────────┘
      │                │ … one card per call, newest first
      │ ● mike@desktop │
```

## The stream

One card per call, pairing **request and result**. The tool surface is eight tools:
`list_nodes`, `describe_node`, `list_operations`, `get_job`, `run_operation`, `raw_exec`,
`cancel_job`, `approve_request`. A Preflight is `plan: true` on `run_operation` / `raw_exec` — the
option keeps its old spelling on the wire until the code follows (GLOSSARY.md) — not a separate
tool; render it as a distinct badge because it is the trust-critical case.

Card contents by kind:

- **Dispatch in flight** — args, Selector with resolved fan-out, plan hash, who approved it if it
  was parked, then a live progress bar and per-outcome counts, with **Cancel** (v0.7.0). A Job
  still running with no dispatch audit row yet (#617) shows as a **Running** card instead,
  sourced only from the Job row: requester, Operation, risk class, resolved/total and Cancel.
  Selector, arguments and approver appear once the dispatch record is written, because they are
  audit-joined.
- **Preflight** — the arguments, then the grouped verdicts and `would_be_rejected`, and a line
  saying nothing executed and each Node's own engine answered.
- **Elicitation** (ADR-0029) — the Relay answered a call with `input_required` carrying an
  approval elicitation; the agent is blocked. Show the plan hash, quorum and TTL, then the
  `approve_request` decision when it arrives, with the deciding identity as a verified chip. The
  elicitation answer *is* the decision and it travels on the tool surface, not a side channel.
- **Refusal** — the role gate refusing `raw_exec` to a non-`admin`, rendered slate and
  informative. The capability layer decided; this screen renders it.
- **Read** — the arguments and a metadata-only result line, explicitly saying the result is not
  retained.
- **Polling** — consecutive calls that would render IDENTICALLY apart from their timestamp
  collapse into one row carrying the count of calls it stands for (#541). Equivalence is the
  WHOLE rendered row, not just Account+tool: a poll of a different Job, a different outcome or a
  different risk class never joins a run — a `raw_exec` that happened between two runs of
  `get_job` polls stays its own row, never swallowed into either. Runs must be CONSECUTIVE:
  collapsing non-adjacent calls would reorder the trail, which on an audit-facing screen is worse
  than the crowding it fixes. The rail keeps counting CALLS, never rendered rows, and a collapsed
  row carries its own count — so a rail entry stays verifiable by scrolling and adding up. The
  page note says how much was collapsed in every position, including the one where it would
  otherwise say nothing at all. This is presentation over the fetched PAGE only: it does not reach
  back past the page boundary, so 200 `get_job` calls spread across two pages still crowd out
  whatever the second page's Older link has to offer.

## Filtering

Tool-name chips, a mutate-only toggle, a hide-polling toggle, and a free-text filter over
arguments, Selector, Node and plan hash. Filters apply to the live tail and to an Account's
history (through #441) identically.

## Accounts rail

Each Account with a call in the last 15 minutes: name, role, first and last call, call count,
mutate count. Selecting one scopes the stream. An Account whose most recent call on the page is
older than 15 minutes drops off the rail and the rail says how many dropped; its calls stay in
the stream below, and its history stays reachable through the filter and through spec 15.

**The rail is scoped twice, and says so.** Membership is the 15 minutes: an Account not seen in
that long is not listed, full stop. The numbers beside a listed Account — call count, mutate
count, first and last call — are counted over the fetched PAGE, the same page the stream renders,
so any rail entry is verifiable by scrolling to its rows. The stream is never filtered by the
window: it is the history, and a page reached by following Older will USUALLY list no active
Account — usually, not always, since an Account making enough calls fast enough (200 `get_job`
polling calls, for instance) can fill a whole page from inside the window. On this screen "window"
means the 15 minutes and nothing else; the page is called the page, never the window.

**Kind (machine or human) is not on the rail.** Considered and dropped (owner decision, 2026-09-08,
#540) because the audited record does not carry it: an Account-registry reader would report the
Account's CURRENT kind, so a machine Account later converted to human would retroactively relabel
its own history — the rail would lie about the past — and it would widen what this screen can see,
against #542's direction of narrowing this screen to the audited lane's own rows. Carrying kind on
the verified attribution lane instead is an append-only schema change with a store migration, for a
descriptive rail label. The security-relevant distinction — verified authentication versus a claimed
identity — is already on the rail, as the trust chip beside the name.

**No controls live here.** Cancel sits on the in-flight dispatch card (v0.7.0); token revocation
is spec 15; Freeze is spec 16.

**A running Job's card does not count on the rail (#617).** It is read from the Job row, not from
an audited call, so it is not a call this screen's rail can count — the rail's Calls/Mutates/
Denied fields stay call-grained. It joins the rail once its dispatch is recorded. An otherwise
empty rail says so instead of "No Account has called a control surface yet.", since a page
showing only running Jobs is not truthfully an empty one.

## Reads made from this Console

Most screens this Console renders read through the capability layer's audited read lane (the
Approvals queue does not; that is a known gap, #779), so most pages the signed-in operator opens are
themselves calls on the trail (`query_audit`, `list_nodes`, `query_jobs`, …, attributed to their
own Account). Listed as they are, they fill the feed and the rail within minutes of use and bury
the AI-agent's calls this screen exists to show. Those page loads are reads, so reads are what this
rule leaves out.

**Where the Agents screen lists calls and counts them on the rail, a call is left out by default
only when its audit record says BOTH that its identity was established by a Console session AND
that it was a read.** The rule is proposed in this change and awaits a human's review of it.

- **"Made from this Console" is read from the record as written**: the authentication method on
  the verified lane (`console_session`), recorded when the call was made. It means the call was
  authenticated by a Console session cookie — not that a person was at the keyboard. The rule
  never reads the Account registry and never reads an Account's kind: the owner decision under
  "Kind (machine or human) is not on the rail" above (2026-09-08, #540) stands unchanged, and this
  rule does not depend on it.
- **"A read" is read from the row itself**: its record kind is the non-dispatching read kind
  (`read`) AND the risk class the row already renders is `read`. Where the row does not carry
  enough to tell, it is treated as not a read and stays listed. Nothing else is consulted.
- **Everything that is not a read stays listed whatever its method**: a mutate-class call, an
  approval decision, a Cancel, a refusal, a Preflight — including those made from a Console
  session.
- **The residual, stated plainly.** Reads made with a stolen Console session cookie, or by
  software driving an operator's browser, carry the same record as the operator's own page loads.
  They are left out of this screen by default, are counted in the visible sentence, and are one
  click away.
- **The exclusion is never silent.** Where it is in force, one plain sentence beside the feed says
  that reads made from this Console are left out and how many — of the calls on this page, or,
  where `?account=` is set, of that Account's calls on this page — and links to the same view with
  them shown (`?console=show`). Where that parameter is set, the screen lists and counts exactly as
  it would without this rule, and the sentence offers the way back.
- **`?account=` composes with it.** An Account filter narrows what the default leaves; with
  `?console=show` it narrows everything. Every link the screen draws — the rail, Older, Newest,
  "Show every Account" and Refresh — carries both parameters as it found them.
- **It is presentation over the fetched page**, like the polling collapse: the lane is asked for
  the same page with the same filter it always was, and no read is added or widened. The page is
  still bounded by the most recent 200 audited calls counted *before* the exclusion, so a page can
  list fewer than 200, and a page of nothing but Console reads lists none while still offering
  Older. The page note therefore says what the page holds, not what the feed shows, and the
  sentence's count keeps the arithmetic visible.
- **The method decides what is listed and is never displayed.** Nothing on this screen says how an
  actor authenticated.
- **The Running section is unaffected.** It is read from the Job row, which records no method.
- **Empty states stay true.** Where the rail, or the feed, is empty because every call on the page
  — or every call by the filtered Account — was a read made from this Console, it says that,
  rather than that nobody called.

## Refreshing

The Agents screen offers a **Refresh** control, under the rules in
[`00-foundations.md`](00-foundations.md) ("Refreshing a screen"): it reloads the screen with
`?account=` and `?console=` preserved, and nothing reloads it on a timer. The "About this screen"
disclosure says that every Refresh is an audited read, and that those reads are reads made from
this Console, so the default above leaves them out of this screen.

## Interruption

**There is no hold-before-dispatch timer.** It was considered and dropped. Interruption is
**cancellation**, which already exists: `TaskCancel` kills the process group, the daemon reports
`OUTCOME_CANCELLED`, a Task that already finished reports its real outcome rather than a
retroactive cancel, and the cancelled Task ID stays deduped so at-most-once still holds
(ADR-0013, invariant #4). No new architecture.

## Must not appear

- Any claim about what the model was thinking, planning, or intending.
- Retained read output, anywhere, at any age.
- A scheduled or automatic replay of any call.
- Prompt text, system prompts, or conversation content — the Relay does not have them and must not
  invent a place for them.
- A Disconnect, End session, or Suspend control — nothing they would act on exists.
- The word "connected", or any claim that a connection exists.

## Acceptance

- [ ] Every one of the eight tools renders with a request line and a result line.
- [ ] A read card states that output is not retained, and the scrollback genuinely has none.
- [x] An in-flight dispatch is cancellable from this screen (v0.7.0) and the cancellation is
      audited; in v0.6.0 no control here reaches the capability layer.
      **Met (#595, #617).** A running Job appears on the newest page from its Job row's recorded
      requester (#616, #617), through the same single `QueryJobs{State: Running}` lane read that
      has backed Cancel since #595. That read is now made for every role on the newest page,
      viewers included, because a viewer is shown running Jobs too (though never offered Cancel).
      The Job is marked running until it resolves, and Cancel is drawn where the capability
      layer's cancel route is reachable for the role — gated by `cancelOffered` exactly as Job
      detail's is (13-job-detail.md). A dispatch row of a still-running Job is marked running too,
      and its newest row carries the control, so a Job with several dispatch rows on the page
      still draws exactly one. Running cards are not counted on the rail until their dispatch is
      recorded — see the Accounts rail section below.
- [ ] Polling collapses; an Account doing 200 `get_job` calls does not push everything else off.
- [ ] A `raw_exec` refused by the role gate renders informative-neutral, not as an error.
- [ ] With no Account active in the window the screen says so plainly and does not fabricate
      activity.
- [ ] Nothing on this screen claims a connection exists or offers to end one.
