# Plan

**Status:** aspirational — designed, **not built**; worked through with the owner on `2026-09-14`,
awaiting their review of this draft. ADR-0038 decides the shape, amended by the decisions below;
this specifies the first cut of it. Nothing described here exists in code yet, and every claim
below is in the testing backlog rather than proven — see *Seams and proof*.

## Purpose

A Plan is **an approved route of execution**: an ordered list of steps that an AI-agent proposes,
a human approves as a route, and the agent then walks one step at a time — with each `mutate` step
released by its own approval, made against the route the approver already saw.

Diagnosis and remedy have different shapes. An AI-agent investigating an incident reads freely
and concludes *"six things need to happen to this host, in this order."* The approval gate
answers one dispatch at a time, so that arrives as six unrelated requests, and a gate asked six
times with no context is answered without reading (`approval.md`: fatigue is a security
failure). A Plan keeps the per-mutation decision, but gives each one the route as context, fixes
what each step is, and lets the reads in between run without asking.

The **Approval grant** is the *described* answer: a scope walled by an Operation allow-list, a
fan-out ceiling and a window — a blank cheque with a spending limit. A Plan is the *enumerated*
answer, an itemised invoice: it needs no walls around its content because it has no room inside
it.

## The first cut, and why each cut is safe

This specification describes **one Node at a time, linear, agent-driven**. Each reduction says
what widening it costs, and the costs differ: **the whole cut is not a config change.**

| Reduced to | Cost to widen | Why the cut is safe rather than merely small |
|---|---|---|
| Fan-out bounded to **one Node** | **Design work.** ADR-0038 binds the approved Node set by identity and re-parks on any addition. At one Node that check is node-equality; at N it is set-membership over a set that may legitimately shrink. A predicate to generalise, not a number to raise. | The binding is the same property — the approver's set is the set — so widening changes how the check is written, never what it guarantees. At one Node the check is trivially exact. |
| **One Selector for the whole Plan**, not one per step | **Its own ADR.** Per-step Selectors are cross-Node orchestration — a larger capability, not a wider one. | The real case is "do these six things to this host", which one Selector expresses exactly, and which still expresses "to these forty hosts" when the bound rises. Cross-Node sequencing is a different capability that this one does not block. |
| **Linear**, no branches | **Its own design pass**, under the constraints in *Out of scope*. | An agent that can halt, read more, and decline to continue already has most of what a branch offers. A branch buys latency, not capability. |
| **Any failed step is terminal** | A declared per-step failure policy — additive, and part of the hash. | If a step failed, the world is not what the approver assumed it was. Halting is the answer that cannot be wrong. |
| **Agent-driven only** | **A new caller.** Both drive through the same advance path (ADR-0038). | An internal driver is a caller, not a second execution path, and gains no privilege by being internal. |
| **No new approval surface** | — | A Plan, and each of its `mutate` steps, parks through the existing Approval, exactly as an Approval grant does. |
| **One step per advance** | A batched advance — a convenience that reopens what the agent may decide. | Per-step is the conservative answer; each advance is one decision point for the agent and, for a `mutate` step, for a human. |

## Surfaces

| Surface | How it is reached | Status |
|---|---|---|
| **MCP** | `propose_plan`, `get_plan`, `advance_plan`, `abandon_plan`. Approval is **not** a Plan surface — a gated Plan parks and is answered through `approve_request` like any other Approval. | Not built |
| **Control API** | `GET /api/v1/plans`, `GET /api/v1/plans/{id}`, `POST /api/v1/plans/{id}/abandon`. Decisions land on the existing `/api/v1/approvals` routes. | Not built |
| **Admin Console** | Renders a Plan on a detail screen. **Composes nothing** — proposing a route is an agent act — and **decides nothing**: the Console has no approval surface (ADR-0044). | Not built |

Proposing is MCP-only in this cut; the Console and Control API view and abandon a Plan, and the
Control API decides on it through approvals. That is an adapter offering **less** than the
capability layer allows, which invariant 10 permits, never the layer deciding differently per
surface.

## Behaviour

### What a Plan is

An ordered list of **steps**, each one Operation or Raw Exec with fixed arguments, plus **one
Selector** the whole Plan runs against, plus an agent-supplied **rationale**. Steps are numbered
from 1 and the order is part of the Plan.

**A Plan sits above Jobs: one step is one Job** (ADR-0038). A Job is one Operation, so each
advance creates an ordinary Job bound to the Plan's ID. A Plan step is **not** a Stage: `Stage` is
reserved for ordered batches within a *single* Operation's fan-out.

### The ceiling is 1, enforced at proposal and again at every advance

At proposal the Selector is resolved. If it matches anything but **exactly one connected Node**,
the Plan is refused with the matched count. That refusal *is* ADR-0038's fan-out ceiling, set to
1.

The Plan hash binds the route **and** the resolved Node — by identity, never by count (ADR-0038).
Every advance re-resolves and must yield that same Node. A Selector that now resolves to a
*different* Node, or to more than one, **re-parks the Plan for re-approval** rather than
dispatching. Resolving to none is shrinkage rather than drift: there is nothing left to run on,
so the step dispatches to nobody and is recorded, exactly as a fan-out that lost every Node would
be.

Binding identity rather than a count stops a compromised Node **forging its own `node:` labels**
(invariant 7) to elect itself into a route approved for a different host; the attack can only
cause a re-park.

### Relay holds the route; the agent holds only a cursor

The approved Plan and a monotonic **step cursor** live on the Relay. The agent advances by naming
the Plan and the step index it believes is next, **and nothing else** — no Operation, no
arguments, no Selector. Relay looks up that step of the approved route and moves the cursor. A `read`
step then dispatches what the human approved. **A `mutate` step parks for its own approval, bound
to the Plan hash and that step**, and dispatches only once released — so the cursor still carries
no description of the work, and a step approval can release only the step the route already
names.

This is the security core of the capability. If the agent held the approved step list and
dispatched each step itself, the approval would bind nothing: a hijacked or confused agent could
reorder, skip, replay or substitute, and every dispatch would look like any other. Here there is
nothing in the advance call to tamper with, **because it contains no description of the work.**

> The agent decides **whether** and **when** to continue. Relay decides **what** runs.

The declared step index is an optimistic-concurrency check: a retried advance arriving after the
cursor has moved is refused rather than re-running a step. That is how invariant 4's at-most-once
reaches from Tasks up to steps.

**The compare-and-advance is transactional, or it is not a bound** — the rule `approval.md`
states for a Grant's use limit. The cursor moves to an in-flight marker **before** the step
dispatches, in one transaction with the step's Job creation, like the Task-level
mark-dispatched-before-dispatch in `execution.md`. Otherwise two advances carrying the *same,
still-current* index — an ordinary client retry on a timeout — both dispatch. Task-level dedup
does not cover this: each advance mints a new Job with new Task IDs.

### What the gate costs is derived from the strictest step, then again per step

Gate rules are evaluated against **every** step at proposal. The strictest requirement any step
triggers governs the Plan's own approval, and a Plan with no gated step requires no approval and is
not a way to manufacture one. A single Raw Exec step therefore prices the route's approval at Raw
Exec's floor.

At advance, each `mutate` step is gated again **on its own**: its approval is priced by that step's
gate rule at the approved Node, and bound to the Plan hash and the step. A `read` step is not
re-gated.

This mirrors how an Approval grant's cost is derived at its Scope's widest admissible dispatch:
what a route costs to approve is never its requester's to say.

### Every `mutate` step is approved at its own advance

Approving a Plan approves the route — its steps, their order and its Node — as the context every
later decision is made in. **It does not by itself release a mutation.** When the cursor reaches a
`mutate` step, that step parks for its own approval, bound to the Plan hash and the step index,
and dispatches only when released. The step approval uses the ordinary approval path, channels
and audiences (`approval.md`); under the shipped in-band default it is a low-friction confirmation
in the client.

The reason for the rule: **a stolen proposer credential can run no mutation a human did not
release at that step.** It can walk an approved route's `read` steps, in order, on that one Node,
until the window closes, and nothing more. Proposer-identity-only advance and per-step step-up
re-authentication were weighed and declined.

### An approved, incomplete Plan is grant-shaped for its reads

A Plan at step 3 of 6 is standing authorization to dispatch the remaining **`read`** steps with
no further human involvement — an Approval grant whose scope is enumerated — while each remaining
`mutate` step waits for its own approval. It takes a grant's walls, all mandatory:

- **A window.** A Relay operator setting (`relay-configuration.md`; reach-bounding under
  invariant 11, so it may be store-backed): **1 hour by default, capped at 4 hours**, matching
  approval grants.
- **Revocable**, closing mid-route immediately.
- **Expiry is terminal and never resumable.** An expired Plan stays where it stopped; the
  remaining steps need a new Plan and a new Approval.
- **Abandonment is an explicit recorded act.** An abandonment indistinguishable from a crashed
  session is an absence in the trail rather than an answer.
- **The Freeze bites every advance.** An advance is new dispatch, so ADR-0013 applies unchanged:
  a Freeze at step 3 stops step 4 and leaves step 3's in-flight Task running.

### An Approval grant may not release a Plan

A Grant is consulted **only after** the gate has decided approval is required (`approval.md`), so
without this rule a gated Plan could consult one. It cannot: **a Grant covers dispatches, never
routes.** A Grant is *described*, and its walls are its whole security argument; a Plan is
*enumerated*. Letting one release the other would make one Grant use release N dispatches,
amplifying the Grant's central bound, and **no human would ever see the route** — the one control
threat model R14 depends on. A Plan parks, or it does not run.

### A Plan composes nothing, and the Node never learns one exists

A sequence of commands looks like what invariant 1 forbids composing. It is not: each step is
an independent dispatch the Node's own Policy engine evaluates, under its own blast cap, exactly
as if a human had typed it. **This capability adds nothing to the node plane** — a step arrives as
an ordinary Task. So a Plan can never make a Node run something its Policy would refuse: approval
narrows, never widens (ADR-0027).

### The rationale is asserted; Relay authors the step list

The diagnosis behind a route makes it reviewable, so a Plan carries it. But it is agent-authored
prose in front of a human about to authorize mutations, a first-class injection surface: a
compromised agent's real lever is making dangerous steps read as routine. So it lives in the
**asserted** attribution lane beside `on_behalf_of`: bounded, stored verbatim, rendered as a
marked claim, never interleaved with the steps. Relay renders the step list from the stored
Plan.

### Every step is preflighted at proposal

Proposing a Plan runs a Policy preflight of every step against the resolved Node, and the
approver sees the verdicts. Neither Relay nor the Plan can write Policy (invariant 2), but a Node
can go offline and the customer's config management can re-author its Policy, so verdicts are
presented as **as-of-proposal**, never as current. A forecast presented as a fact is the failure
ADR-0011 exists to prevent.

Verdicts for steps **after the first `mutate` step** are additionally labelled as **possibly
depending on earlier steps**: an `unsupported` or a Policy deny there may only reflect a world
steps 1–N have not yet produced.

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
| Too many steps | Over the configured per-Plan step bound (a Relay operator setting, `relay-configuration.md`) |
| Fan-out over bound | The Selector matched more than one Node — reported with the count |
| No Node matched | The Selector matched nothing, or its only match is not connected |
| Unauthorized to propose | Below the role floor of the strictest step |
| Not approved | An advance against a Plan still pending, denied, or terminal |
| Step awaiting approval | An advance at a `mutate` step that has no released step approval — the step parks; this is a park, not a refusal |
| Cursor mismatch | The declared step index is not the cursor's — a replay, a reorder, or a skip |
| Step already in flight | An advance at the current index while that step is mid-dispatch — refused by the claim transaction, never queued |
| Not the proposer | An Account other than the Plan's advancing it |
| Expired / revoked | The window closed, or a human closed it |
| Frozen | An advance while the Relay is frozen (ADR-0013) |
| Node drifted | The Selector resolves to a *different* Node, or to more than one — the Plan re-parks. Resolving to none is shrinkage, not drift: recorded, not refused |

A **step's own** refusal — a Policy deny, an outdated daemon, a cap rejection — is not in this
table. It is the step's Job refusing, reported as that Job's outcome, and it halts the Plan.

## Governing ADRs and invariants

- **ADR-0038 — needs amending.** The whole shape: Plan as an approved route, the cursor and the
  payload-free advance, a step is a Job, the derived requirement, the grant-shaped walls, and the
  rename of plan mode to Policy preflight. Its `2026-09-24` amendment records the 4-hour window
  ceiling; it still needs amending for per-step approval of every `mutate` step.
- **ADR-0027** — the Approval a gated Plan and each of its `mutate` steps parks through, the plan
  hash it binds, and channel strength. Its grant window, now 4 hours, is the ceiling a Plan's
  window matches.
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
- **Invariant 11** — the step bound and the window bound reach, and are operator settings: never
  reachable from an API Token or an MCP tool, editable (where store-backed) only by a human
  `admin` with step-up, audited. Both must appear among `relay-configuration.md`'s operator
  settings when this capability is designed.
- **Invariant 13** (ADR-0042) — each step's risk class is security-relevant contract and selects
  its cap and its gate rule; a Template step takes the most restrictive class the Nodes it reaches
  report (amended 2026-10-02).

## Seams and proof

The Plan is a capability-layer object beside dispatch and approval. It owns the route, the
cursor, and the lifecycle; each advance hands an ordinary dispatch to the execution path and
holds none of its own. Nothing about it reaches `/proto`'s node plane.

### What proves each claim

**Nothing yet: the capability is unbuilt, and this list is its testing issue's backlog.**

- A Plan with a Selector matching more than one Node is refused, with the count
- A Plan's approved route is unchanged by anything the advance call carries
- An advance with a stale step index is refused and re-runs nothing
- An advance cannot skip or reorder a step
- An ungated Plan runs without an Approval; one gated step parks the whole Plan
- **Every `mutate` step parks at advance for its own approval, bound to the Plan hash and step,
  and a `read` step does not**
- A step approval cannot release any step but the one it is bound to
- A Plan's window defaults to 1 hour and cannot be configured above 4 hours
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
- **Two concurrent advances at the same still-current index dispatch the step exactly once** —
  the claim transaction, not the index comparison, is what makes this true
- **A Selector resolving to a different Node re-parks rather than dispatching**, and resolving to
  none is recorded as shrinkage rather than refused
- An Approval grant does not release a Plan, at any granularity

### Performance

| Characteristic | Contract | Measured by |
|---|---|---|
| Proposal | One Selector resolution plus one preflight per step, against one Node | *(none)* |
| Advance | One dispatch — the same cost as an ungated single-Node run — plus, for a `mutate` step, one park and one decision | *(none)* |
| Retained Plans | Bounded by the step bound and the window; swept on expiry | *(none)* |

There are no benchmarks in this repository.

## Out of scope

Each is a deliberate reduction in *The first cut*, recorded so it is picked up as a decision
rather than rediscovered as a gap.

- **Multi-Node Plans.** Raising the fan-out ceiling above 1. The hard part is not the ceiling but
  what replaces pinning: with more than one Node the resolved set moves between approval and a
  later step, and ADR-0038 decides the answer — re-resolve against an approved ceiling, re-park
  past it — which this cut does not have to exercise.
- **Per-step Selectors**, and with them cross-Node orchestration ("drain A, then restart B"). A
  larger capability than a wider one; it wants its own ADR.
- **Branches.** A candidate idea, not a commitment. ADR-0038 records two constraints: a predicate
  may read only Relay-observable outcomes, never Node-supplied content, and **a step's arguments
  may never be derived from a prior step's output** — that path lets a compromised Node write a
  command for the Relay to dispatch. And a human can only approve what they can see, so every
  reachable step must be enumerable at approval time. That, not effort, bounds branching.
- **Continue-on-failure**, and any per-step failure policy. Whatever it becomes, it is part of
  what the human approved and therefore part of the hash.
- **Resuming a failed or expired Plan.** Both are terminal here. Resumption means re-approval,
  which means a new Plan.
- **A Relay-internal driver** for unattended routes. Same advance path, no new privilege.
- **Composing a Plan from the Console.** Console execution is behind the root-owned
  `console_execution` flag and unbuilt (#438).
- **Staged rollout.** `Stage` is a different axis (`docs/deferred.md`) and the two compose rather
  than compete.
- **Policy preflight itself** — the verdicts, the four values, and the query that obtains them:
  `policy-preflight.md`.
- **The Approval a Plan parks through** — gate rules, channels, quorum, grants: `approval.md`.

## Accepted residual risk

- **A stolen proposer credential can walk a route's reads.** Until the window closes it can advance
  every `read` step of an approved Plan, in order, on its one Node. It cannot release a mutation.
- **The rationale is the agent's lever.** It is stored and rendered as an assertion, but a human
  approving a route still reads it; a compromised agent's best move is making dangerous steps read
  as routine.
- **Later-step verdicts are least informative where they matter most.** Diagnose-then-remediate
  routes depend on earlier steps, so their later verdicts are labelled rather than solved.

## Future work

Named, not decided, and in no order.

- **Evidence-linked Plans.** A proposed Plan carries references to the audited read Jobs that
  observed the fault it addresses, so an approver checks the claims against what Relay actually
  saw rather than against the AI-agent's prose. ADR-0038 decided the route and left the evidence
  out.
- **Multi-Node Plans — answer aggregate blast first.** One decision releases N dispatches, and
  invariant 5's cap is per dispatch. At one Node the step bound is an adequate aggregate control;
  it stops being adequate the moment the fan-out bound rises, and an aggregate bound must be
  decided **before** multi-Node lands, not after.
- **Better presentation of dependent later steps** — so an approver judging step 4, which reads a
  file step 3 creates, is not left with a screen of misleading verdicts and the agent-authored
  rationale as the only guide.

## Open questions

None.
