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
`cancel_job`, `approve_request`. Plan mode is `plan: true` on `run_operation` / `raw_exec`, not a
separate tool — render it as a distinct badge because it is the trust-critical case.

Card contents by kind:

- **Dispatch in flight** — args, Selector with resolved fan-out, plan hash, who approved it if it
  was parked, then a live progress bar and per-outcome counts, with **Cancel** (v0.7.0).
- **Plan** — the arguments, then the grouped verdicts and `would_be_rejected`, and a line saying
  nothing executed and each Node's own engine answered.
- **Elicitation** (ADR-0029) — the Relay answered a call with `input_required` carrying an
  approval elicitation; the agent is blocked. Show the plan hash, quorum and TTL, then the
  `approve_request` decision when it arrives, with the deciding identity as a verified chip. The
  elicitation answer *is* the decision and it travels on the tool surface, not a side channel.
- **Refusal** — the role gate refusing `raw_exec` to a non-`admin`, rendered slate and
  informative. The capability layer decided; this screen renders it.
- **Read** — the arguments and a metadata-only result line, explicitly saying the result is not
  retained.
- **Polling** — consecutive `get_job` calls collapse to one row with a count. Do not let polling
  drown the lane.

## Filtering

Tool-name chips, a mutate-only toggle, a hide-polling toggle, and a free-text filter over
arguments, Selector, Node and plan hash. Filters apply to the live tail and to an Account's
history (through #441) identically.

## Accounts rail

Each Account active in the window: name, kind (machine or human), role, first and last call in
the window, call count, mutate count. Selecting one scopes the stream. An Account outside the
window drops off the rail; its history stays reachable through the filter and through spec 15.

**No controls live here.** Cancel sits on the in-flight dispatch card (v0.7.0); token revocation
is spec 15; Freeze is spec 16.

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
- [ ] An in-flight dispatch is cancellable from this screen (v0.7.0) and the cancellation is
      audited; in v0.6.0 no control here reaches the capability layer.
- [ ] Polling collapses; an Account doing 200 `get_job` calls does not push everything else off.
- [ ] A `raw_exec` refused by the role gate renders informative-neutral, not as an error.
- [ ] With no Account active in the window the screen says so plainly and does not fabricate
      activity.
- [ ] Nothing on this screen claims a connection exists or offers to end one.
