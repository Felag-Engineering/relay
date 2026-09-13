# Plan

**Status:** designed, **not built**, as of `2026-09-12`. ADR-0038 decides the shape; this
specifies the first cut of it. Nothing described here exists in code yet, and every claim below
is in the testing backlog rather than proven — see *Seams and proof*.

## Purpose

A Plan is **an approved route of execution**: an ordered list of steps that an AI-agent proposes,
a human approves once, and the agent then walks one step at a time.

It exists because diagnosis and remedy have different shapes. An AI-agent investigating an
incident reads freely — reads are cheap and ungated — and arrives at a conclusion of the form
*"six things need to happen to this host, in this order."* Relay's approval gate is built to
answer one dispatch at a time, so that conclusion costs six human decisions. A gate asked six
times is a gate answered without reading, and `approval.md` is explicit that fatigue is a
security failure rather than a UX complaint.

Relay already has one answer: the **Approval grant**, a *described* scope with walls around it —
an Operation allow-list, a fan-out ceiling, a window. A Plan is the *enumerated* answer. A grant
is a blank cheque with a spending limit; a Plan is an itemised invoice. Where a grant must be
walled because nobody can enumerate what it covers, a Plan needs no walls around its content,
because it has no room inside it.

## The first cut, and why each cut is safe

This specification describes **one Node at a time, linear, agent-driven**. Every reduction below
is a constant or a refusal, never a different design — widening each one later changes a value
or deletes a check, and re-specifies nothing.

| Reduced to | Widened later by | Why the cut is safe rather than merely small |
|---|---|---|
| A fan-out ceiling of **1** | Raising the ceiling | The ceiling mechanism ADR-0038 decides is present and enforced; it is pinned at 1. At 1 the resolved Node set is trivially pinnable, so the hardest open problem in the design — a fan-out that moves between approval and step 5 — does not arise yet. |
| **One Selector for the whole Plan**, not one per step | Per-step Selectors | The real case is "do these six things to this host", which one Selector expresses exactly, and which still expresses "do these six things to these forty hosts" when the ceiling rises. Per-step Selectors are cross-Node orchestration — a larger capability, not a wider one. |
| **Linear**, no branches | See *Out of scope* | An agent that can halt, read more, and decline to continue already has most of what a branch offers. A branch buys latency, not capability. |
| **Any failed step is terminal** | Per-step failure policy | If a step failed, the world is not what the approver assumed it was. Halting is the answer that cannot be wrong. |
| **Agent-driven only** | A Relay-internal driver | Both call the same advance path (ADR-0038); an internal driver is a caller, not a second execution path. |
| **No new approval surface** | — | A Plan parks through the existing Approval, exactly as an Approval grant does. |

## Surfaces

| Surface | How it is reached | Status |
|---|---|---|
| **MCP** | `propose_plan`, `get_plan`, `advance_plan`, `abandon_plan`. Approval is **not** a Plan surface — a gated Plan parks and is answered through `approve_request` like any other Approval. | Not built |
| **Control API** | `GET /api/v1/plans`, `GET /api/v1/plans/{id}`, `POST /api/v1/plans/{id}/abandon`. Decisions land on the existing `/api/v1/approvals` routes. | Not built |
| **Admin Console** | Renders a Plan in the approval queue and on a detail screen. **Composes nothing** — proposing a route is an agent act. | Not built |

Proposing is deliberately MCP-only in this cut. That is an adapter offering **less** than the
capability layer allows, which invariant 10 permits; it is never the layer deciding differently
per surface.

## Behaviour

### What a Plan is

An ordered list of **steps**, each one Operation or Raw Exec with fixed arguments, plus **one
Selector** the whole Plan runs against, plus an agent-supplied **rationale**. Steps are numbered
from 1 and the order is part of the Plan.

**A Plan sits above Jobs: one step is one Job** (ADR-0038). A Job is one Operation by definition,
so a Plan cannot be one Job; it is the object above, and each advance creates an ordinary Job
bound to the Plan's ID. A Plan step is **not** a Stage, and the two are never merged: `Stage` is
reserved for ordered batches within a *single* Operation's fan-out.

### The ceiling is 1, enforced at proposal and again at every advance

At proposal the Selector is resolved. If it matches anything other than **exactly one connected
Node**, the Plan is refused — with the matched count, so the refusal teaches. That refusal *is*
the fan-out ceiling of ADR-0038, set to 1.

At 1, the resolved set is pinned: the Plan hash binds the route **and** the single resolved Node.
Every advance re-resolves and must yield that same Node. A Selector that now resolves elsewhere,
to more than one Node, or to none, **re-parks the Plan for re-approval** rather than dispatching
— which is ADR-0038's drift rule at a ceiling of 1.

### Relay holds the route; the agent holds only a cursor

The approved Plan and a monotonic **step cursor** live on the Relay. The agent advances by naming
the Plan and the step index it believes is next, **and nothing else** — no Operation, no
arguments, no Selector. Relay looks up that step of the approved route, dispatches what the human
approved, and moves the cursor.

This is the security core of the capability and the reason it is worth building. The obvious
alternative — the agent holding the approved step list and dispatching each step itself — makes
the approval bind nothing, because a hijacked or confused agent can reorder, skip, replay or
substitute, and every dispatch arrives looking like any other. Here there is nothing in the
advance call to tamper with, **because the call contains no description of the work.**

> The agent decides **whether** and **when** to continue. Relay decides **what** runs.

The declared step index is not redundancy. It is an optimistic-concurrency check: a retried
advance arriving after the cursor has moved is refused rather than re-running a step, which is
how invariant 4's at-most-once reaches from Tasks up to steps.

### What the gate costs is derived from the strictest step

Gate rules are evaluated against **every** step. The strictest requirement any step triggers
governs the whole Plan, and a Plan with no gated step requires no approval and is not a way to
manufacture one. A single Raw Exec step therefore prices the entire Plan at Raw Exec's floor.

This mirrors how an Approval grant's cost is derived at its Scope's widest admissible dispatch,
and for the same reason: what a route costs to approve must never be something its requester gets
to say.

### An approved, incomplete Plan is grant-shaped

A Plan sitting at step 3 of 6 is standing authorization to dispatch steps 4–6 with no further
human involvement — an Approval grant whose scope happens to be enumerated. It takes the same
walls, and every one of them is mandatory:

- **A window.** Root-owned Relay configuration (invariant 11), inside ADR-0027's 24-hour ceiling
  and expected to be far shorter.
- **Revocable**, closing mid-route immediately.
- **Expiry is terminal and never resumable.** An expired Plan stays where it stopped; the
  remaining steps need a new Plan and a new Approval.
- **Abandonment is an explicit recorded act.** An abandonment indistinguishable from a crashed
  session is an absence in the trail rather than an answer.
- **The Freeze bites every advance.** An advance is new dispatch, so ADR-0013 applies with no new
  rule: a Freeze at step 3 stops step 4 and leaves step 3's in-flight Task running. A Plan is
  never a way around a Freeze because it was approved earlier.

### A Plan composes nothing, and the Node never learns one exists

Invariant 1 forbids anything on the wire from composing or escalating a command, and a sequence
of commands is superficially what a Plan is. It is not. Each step is an independent dispatch that
the Node's own Policy engine evaluates on its own terms, under its own blast cap, exactly as if a
human had typed it. **This capability adds nothing to the node plane** — a step arrives as an
ordinary Task, and nothing about a Node's threat surface moves.

The corollary that matters for review: a Plan can never cause a Node to run something that Node's
Policy would refuse. Approval narrows; it never widens (ADR-0027).

### The rationale is asserted; Relay authors the step list

The diagnosis that produced a route is what makes the route reviewable, so a Plan carries it. But
it is agent-authored prose placed in front of a human about to authorize mutations, which is a
first-class injection surface — a compromised agent's real lever is making six dangerous steps
read as routine.

So it lives in the **asserted** attribution lane beside `on_behalf_of`: bounded, stored verbatim,
rendered as a marked claim, and never interleaved with the steps. The step list an approver reads
is rendered by Relay from the stored Plan.

### Every step is preflighted at proposal

Proposing a Plan runs a Policy preflight across all of its steps against the resolved Node, and
the verdicts are part of what the approver sees. Policy cannot move underneath a Plan — invariant
2 means neither Relay nor the Plan can write it — but a Node can go offline, and its Policy can
be re-authored by the customer's own config management. Verdicts are therefore point-in-time and
are presented as **as-of-proposal**, never as current. A forecast presented as a fact is the
failure ADR-0011 exists to prevent, one layer up.

### Lifecycle

```
                     ┌──> denied (terminal)
pending-approval ────┤
                     └──> approved ──> completed | failed | abandoned (terminal)
                                 │
                                 └──> expired | revoked (terminal)
```

An ungated Plan is created `approved` with the cursor at 0. `failed` is reached by any step whose
Job does not fully succeed. No terminal state is resumable; a Plan is retained after it ends, and
per ADR-0025 the record holds steps, decisions and outcomes — **never read output**.

## Refusals

| Refusal | Cause |
|---|---|
| Empty plan | A Plan with no steps |
| Too many steps | Over the configured per-Plan step bound (Relay configuration, invariant 11) |
| Fan-out over ceiling | The Selector matched more than one Node — reported with the count |
| No Node matched | The Selector matched nothing, or its only match is not connected |
| Unauthorized to propose | Below the role floor of the strictest step |
| Not approved | An advance against a Plan still pending, denied, or terminal |
| Cursor mismatch | The declared step index is not the cursor's — a replay, a reorder, or a skip |
| Not the proposer | An Account other than the Plan's advancing it |
| Expired / revoked | The window closed, or a human closed it |
| Frozen | An advance while the Relay is frozen (ADR-0013) |
| Node drifted | The Selector no longer resolves to the approved Node — the Plan re-parks |

A **step's own** refusal — a Policy deny, an outdated daemon, a cap rejection — is not in this
table. It is the step's Job refusing, reported as that Job's outcome, and it halts the Plan.

## Governing ADRs and invariants

- **ADR-0038** — the whole shape: Plan as an approved route, the cursor and the payload-free
  advance, a step is a Job, the derived requirement, the grant-shaped walls, and the rename of
  plan mode to Policy preflight.
- **ADR-0027** — the Approval a gated Plan parks through, the plan hash it binds, channel
  strength, and the 24-hour ceiling a Plan's window sits inside.
- **ADR-0011** — the preflight that runs at proposal; the daemon's live engine answers, and the
  Relay never computes a verdict (**invariant 12**).
- **ADR-0013** — the Freeze, which halts every advance and does not kill an in-flight step.
- **ADR-0025** — read output is audited, never retained; a Plan record holds outcomes, not output.
- **Invariant 1** — a Plan composes nothing; each step is an independently evaluated dispatch.
- **Invariant 4** — at-most-once, extended from Tasks to steps by the cursor.
- **Invariant 5** — the cap is checked at every step. At a ceiling of 1 it is trivially satisfied
  and is still never skipped.
- **Invariant 10** — the Plan lives in the capability layer; every surface is an adapter that
  narrows only.
- **Invariant 11** — the step bound and the window are root-owned Relay configuration, unreachable
  from any API.
- **Invariant 13** — each step's risk class is declared contract and selects its cap and its gate
  rule.

## Seams and proof

The Plan is a capability-layer object beside dispatch and approval. It owns the route, the
cursor, and the lifecycle; each advance hands an ordinary dispatch to the execution path and
holds none of its own. Nothing about it reaches `/proto`'s node plane.

### What proves each claim

**Nothing yet — the capability is unbuilt, and this entire list is the backlog for its testing
issue.** Per `CLAUDE.md`, one issue per capability is its testing issue, and a spec's "no row"
list is that issue's scope. No test is named here, because naming one that does not exist is
worse than naming none.

- A Plan with a Selector matching more than one Node is refused, with the count
- A Plan's approved route is unchanged by anything the advance call carries
- An advance with a stale step index is refused and re-runs nothing
- An advance cannot skip or reorder a step
- An ungated Plan runs without an Approval; one gated step parks the whole Plan
- A Plan's requirement is the strictest step's, and a Raw Exec step prices the whole Plan
- A Plan that drifts to a different Node re-parks instead of dispatching
- A Freeze stops the next advance and leaves the in-flight step running
- An expired or revoked Plan cannot be advanced, and cannot be resumed
- A failed step halts the Plan terminally
- Abandonment is recorded, and is distinguishable from expiry and from silence
- An Account other than the proposer cannot advance a Plan
- Preflight verdicts are carried as-of-proposal and are not re-presented as current
- The rationale is stored verbatim in the asserted lane and never merged into the step list
- Each step's Job is independently Policy-evaluated, capped, and audited under the Plan's ID
- A Plan record survives completion and holds no read output

### Performance

| Characteristic | Contract | Measured by |
|---|---|---|
| Proposal | One Selector resolution plus one preflight per step, against one Node | *(none)* |
| Advance | One dispatch — the same cost as an ungated single-Node run | *(none)* |
| Retained Plans | Bounded by the step bound and the window; swept on expiry | *(none)* |

There are no benchmarks in this repository.

## Out of scope

Each of these is a deliberate reduction in *The first cut* above, recorded here so it is picked
up as a decision rather than rediscovered as a gap.

- **Multi-Node Plans.** Raising the fan-out ceiling above 1. The hard part is not the ceiling but
  what replaces pinning: with more than one Node the resolved set moves between approval and a
  later step, and ADR-0038 decides the answer — re-resolve against an approved ceiling, re-park
  past it — which this cut does not have to exercise.
- **Per-step Selectors**, and with them cross-Node orchestration ("drain A, then restart B"). A
  larger capability than a wider one; it wants its own ADR.
- **Branches.** A candidate idea, not a commitment, and it does not exist. Two constraints are
  recorded in ADR-0038 so they are not rediscovered: a predicate may read only Relay-observable
  outcomes and never Node-supplied content, and **a step's arguments may never be derived from a
  prior step's output** — that path lets a compromised Node write a command for the Relay to
  dispatch. And because a human can only approve what they can see, every reachable step must be
  enumerable at approval time. That, not effort, is what bounds branching.
- **Continue-on-failure**, and any per-step failure policy. Whatever it becomes, it is part of
  what the human approved and therefore part of the hash.
- **Resuming a failed or expired Plan.** Both are terminal here. Resumption means re-approval,
  which means a new Plan.
- **A Relay-internal driver** for unattended routes. Same advance path, no new privilege.
- **Composing a Plan from the Console.** Console execution is behind the root-owned
  `console_execution` flag and unbuilt (#438).
- **Staged rollout.** `Stage` is a different axis (`docs/deferred.md`) and the two compose rather
  than compete.
- **Policy preflight itself** — the verdicts, the four values, and the query that obtains them.
  See `policy-preflight.md`, renamed from `plan-mode.md` by ADR-0038.
- **The Approval a Plan parks through** — gate rules, channels, quorum, grants: `approval.md`.

## Open questions

- **One decision now releases N dispatches, and nothing bounds N's blast in aggregate.**
  Invariant 5's cap is per-dispatch and stays so. At a ceiling of 1 the step bound is an adequate
  aggregate control, because a Plan can touch at most one Node. It stops being adequate the moment
  the ceiling rises, and that is the question to answer **before** multi-Node lands, not after.
- **How short should a Plan's window be?** ADR-0027's 24-hour ceiling is the outer bound, but a
  route held open is standing authority and the honest default is probably closer to an hour.
  Unlike a grant, a Plan has a natural clock: the incident that motivated it.
- **Is `advance` the right granularity, or should an agent be able to advance several steps at
  once?** Per-step is the conservative answer and the one specified. A batched advance would be a
  convenience that reintroduces the question of what the agent is allowed to decide.
- **What does an approver see for step 4 that reads a file step 3 created?** The preflight verdict
  is honest but unhelpful — `unsupported` or a Policy deny may simply reflect a world that has not
  happened yet. Nothing here is wrong; the presentation may be.

## History

- `2026-09-12` — First written, from ADR-0038, specifying the one-Node cut. Nothing built.
