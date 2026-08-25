# 03 — Agent sessions

**Artboard 11.** The live trust surface: every call an AI-agent makes, as it makes it.
**Milestone v0.6.0** for the read-only stream; **v0.7.0** for Disconnect and Suspend.

**Governing:** ADR-0003, ADR-0013, ADR-0021, ADR-0025, ADR-0028, ADR-0029, invariants #10, #13.
**Backend:** the v0.6.0 SSE seam, **widened to three publishers** — registry transitions, Job
transitions and MCP tool calls (D9). The tool-call publisher carries arguments but **never** read
results; `KindRead` audit records; session state on the MCP
server; Account suspension state on the Account model, and connection termination, both v0.7.0.

## What this screen is for

An operator earns trust in an AI-driven control plane by **watching it work**. This is the only
surface that shows the agent's actual requests rather than their fleet-side effects.

**What it can honestly show is the request, not the reasoning.** The Relay sees tool calls; it
does not see the model's intent, and it must never pretend to. That limitation is a feature: a
verified record of what was asked beats a narrated account of why, which an agent under prompt
injection would happily fabricate.

## Grain and retention — and why this is not Activity

| | Agent sessions (this) | Activity (spec 04) |
|---|---|---|
| Grain | one MCP tool call | one Job |
| Scope | a connected session | the whole control plane |
| Retention | payloads in flight only | durable audit |
| A `list_nodes` call | appears | never appears |

Keeping them apart is what lets each be honest about retention. Read **calls** are audited — who,
which tool, what they asked for, when — and an unauditable read *fails closed* (ADR-0025). Read
**output** is never retained. So this view has payloads while they are in flight and the scrollback
does not, and the screen says so rather than hiding it.

## Layout

```
[nav] │ Agent sessions        every call an AI-agent makes, as it makes it     [mike · admin]
      ├────────────────┬─────────────────────────────────────────────────────────────────
      │ Connected      │ [all] [run_operation] [raw_exec] [list_nodes] …  [mutate only]
      │ ● gleipnir-prod│ [ filter by argument, Selector, Node, plan hash            ]
      │   47 calls     │ ┌──────────────────────────────────────────────────────────┐
      │   [Disconnect] │ │ → run_operation  [mutate]  plan=false     ● dispatching   │
      │   [Suspend]    │ │   args, selector, plan hash, approved-by                  │
      │ ○ gleipnir-stag│ │ ← job_9d41 · [====progress====] · [Cancel]                │
      │                │ └──────────────────────────────────────────────────────────┘
      │ ● mike@desktop │ … one card per call, newest first
      │                │
```

## The stream

One card per call, pairing **request and result**. The tool surface is eight tools:
`list_nodes`, `describe_node`, `list_operations`, `get_job`, `run_operation`, `raw_exec`,
`cancel_job`, `approve_request`. Plan mode is `plan: true` on `run_operation` / `raw_exec`, not a
separate tool — render it as a distinct badge because it is the trust-critical case.

Card contents by kind:

- **Dispatch in flight** — args, Selector with resolved fan-out, plan hash, who approved it if it
  was parked, then a live progress bar and per-outcome counts, with **Cancel**.
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
arguments, Selector, Node and plan hash. Filters apply to the live tail and the session's history
identically.

## Sessions rail

Each connected session: Account (with its kind — machine or human — and role), connect time, call
count, mutate count, idle state. Selecting one scopes the stream.

Two controls, deliberately different in weight and intent (both v0.7.0):

**Disconnect** drops the connection with no state change. For an agent stuck in a loop that needs
its context broken. **It may reconnect immediately** — the UI must say so plainly. This is a
convenience, not a security control, and must never be presented as a rung on the incident ladder.

**Suspend** is the durable brake, and it is **Account-scoped, not session-scoped**: a session is
authenticated by a bearer token, so killing a connection buys seconds while the client reconnects
with the same credential. A suspended Account may still connect and **every call it makes is
refused** — not merely dispatch, because the actor is suspended for being untrusted and reading is
exfiltration by construction. Refused calls are still audited, so a suspended agent stays
observable through what it attempts. In-flight Tasks keep running; Cancel handles those.

**`operator`+ to engage; `admin` + step-up with an audited reason to lift** — Freeze's asymmetry,
for Freeze's reasons: no friction on the emergency path, a deliberate ceremony to remove
protection.

This completes the incident ladder. Quarantine fences one Node, revoke removes one Node, Freeze
stops the whole fleet — **suspend fences one actor**, which nothing else could do without
collateral damage. See `99-open-decisions.md` D2.

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

## Acceptance

- [ ] Every one of the eight tools renders with a request line and a result line.
- [ ] A read card states that output is not retained, and the scrollback genuinely has none.
- [ ] An in-flight dispatch is cancellable from this screen and the cancellation is audited.
- [ ] Polling collapses; a session doing 200 `get_job` calls does not push everything else off.
- [ ] A `raw_exec` refused by the role gate renders informative-neutral, not as an error.
- [ ] With no sessions connected the screen says so plainly and does not fabricate activity.
- [ ] Disconnect is labelled as reconnectable and is not presented as a security control.
- [ ] A suspended Account's every call is refused and each refusal is audited.
- [ ] Lifting a suspension demands `admin` + step-up and records a reason; engaging it does not.
