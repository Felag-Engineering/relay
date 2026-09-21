# Plan is an approved route of execution; Policy preflight is its own capability

"Plan" has meant two things since ADR-0011, and the collision is visible in that ADR's own
opening: it describes the capability as "`terraform plan` / Ansible check-mode for the fleet".
Those are not the same thing. Ansible's check-mode is a rehearsal. Terraform's plan is a saved
artifact you later apply — the noun, not the rehearsal.

ADR-0011 built the rehearsal and took the noun's name for it. The noun then took itself back:
ADR-0027 defines **Plan hash** as "the content address of a Plan — a hash over the Operation, its
arguments, and the *resolved fan-out*", and binds a human approval to it. A content address over
a preview is meaningless. What that hash actually addresses is **the act the caller intends to
perform**, which is the Terraform meaning, arriving through the approval domain because that is
where the concept was genuinely needed.

Meanwhile the capability the product needs has no name at all. An AI-agent diagnoses an incident
with a series of reads, concludes that six things must happen in a particular order, and needs
**one** human decision over the whole route rather than six. Relay's existing answer is the
Approval grant: a *described* scope with walls around it — an Operation allow-list, a fan-out
ceiling, a window. This ADR adds the *enumerated* alternative. A grant is a blank cheque with a
spending limit; a Plan is an itemised invoice.

## Decisions

- **A Plan is an approved route of execution.** An ordered sequence of steps, each one a fixed
  Operation or Raw Exec with fixed arguments and a fixed Selector, proposed as one object,
  answered by one Approval, and executed and audited as one unit. **v1 is linear** — see the
  branching decision below.

- **Today's plan mode is renamed Policy preflight.** Every decision in ADR-0011 stands unchanged
  and is re-affirmed here: the daemon's live engine evaluates the hypothetical, the wire carries a
  distinct `PolicyQuery`/`PolicyVerdict` pair rather than a `dry_run` flag, an offline Node yields
  `unknown(offline)` and never a guess, and a preflight reports guardrails instead of failing on
  them. Only the **name** and the check-mode framing were wrong. The tool and API option `plan`
  becomes `preflight`.

  It is deliberately **not** renamed "dry run". A preflight never touches an executor; it asks
  each Node's Policy engine a question. A caller told "the dry run passed" would reasonably
  believe Relay had exercised the command, when all Relay did was confirm the doorman would not
  stop it. GLOSSARY.md already refuses that word for this capability, and freeing up "Plan" does
  not make it honest.

- **A Plan sits above Jobs: one step is one Job.** A Job is "a single dispatch of an Operation or
  Raw Exec across the Nodes matched by a Selector" — one Operation, by definition. A Plan carries
  several. Modelling a Plan as one multi-Operation Job would redefine the repo's unit of audit and
  blast-radius control; instead the Plan is the object *above* the Job, and each step is an
  ordinary Job bound to the Plan's ID.

  **`Stage` is untouched and keeps its reserved meaning** — ordered batches of Tasks within a
  single Operation's fan-out, for the staged rollout in `docs/deferred.md` (canary → gate →
  remainder). The two concepts are orthogonal and compose: a Plan of N steps, each a Job, each Job
  one day possibly multi-stage. A Plan step is not a Stage and the two must never be merged.

- **Relay stores the Plan and the cursor; the driver carries no payload.** The approved Plan and a
  monotonic step cursor live on the Relay. The driver advances it by naming the Plan and the step
  index it believes is next — and **nothing else**. No Operation, no arguments, no Selector. Relay
  looks up that step of the approved route, dispatches what the human approved, and moves the
  cursor.

  This is the load-bearing decision. The alternative — the driver holding the approved step list
  and dispatching each step itself — makes the approval bind nothing, because a hijacked or
  confused agent can reorder, skip, replay or substitute, and each dispatch arrives looking like
  any other. Here there is nothing in the advance call to tamper with, because the call contains
  no description of the work. **The driver decides *whether* and *when* to continue; Relay decides
  *what* runs.**

  The declared step index is an optimistic-concurrency check, not redundancy: a retried advance
  arriving after the cursor has moved is refused rather than re-running a step. That is how
  invariant 4's at-most-once extends from Tasks to steps — **provided the compare-and-advance is
  transactional.** `approval.md` already states the rule this depends on: *"the bound is enforced
  inside the claiming transaction, or it is not a bound."* The cursor must move to an in-flight
  marker **before** the step dispatches, in one transaction with the step's Job creation,
  mirroring the Task-level mark-dispatched-before-dispatch precedent. Without that, two advances
  at the same still-current index both pass the check and both dispatch — and Task dedup does not
  save it, because each advance mints a new Job with new Task IDs, so the daemon sees two
  legitimately distinct Tasks.

- **The AI-agent is the default driver; the advance path is the only execution path.** Driving
  belongs to the agent because the judgement that matters between steps — does the fleet still
  look the way the diagnosis assumed? — is judgement, not a predicate. A Relay-internal driver may
  be added later for unattended routes; it would call the same advance path, and gains no
  privilege by being internal.

- **What runs and who it runs on are both frozen; the binding is by identity, never by count.**
  The Plan hash binds the route — the ordered steps, their Operations, their arguments, their
  normalised Selectors, the failure semantics — **and the resolved Node set the approver was
  shown**. Every advance re-resolves, and **any Node not in the approved set re-parks the Plan
  for re-approval.** There is no tolerance and no ceiling.

  An earlier draft of this decision bound a fan-out *ceiling* instead, on the reasoning that an
  agent-driven route spans real time and a pinned set goes stale — a Node that became affected at
  step 2 would be silently excluded from step 5, which is backwards for remediation. That
  reasoning walks the exclusion direction only. The inclusion direction is an attack: an approver
  sees `{A,B,C}` under a ceiling of 10, and by step 5 the set is `{A,B,C,D}` — or `{D,E,F}`
  entirely — with every step still dispatching under an approval given for different hosts. A
  ceiling binds a number; it binds no identity. And invariant 7 is explicit that a compromised
  Node **can forge its own `node:` labels**, so under a ceiling an attacker owning one Node could
  elect itself into a human-approved route by forging the label the Plan's Selector matches.

  Identity binding degrades that attack from *election into an approved route* to *causing a
  re-park*, which is a denial of convenience and nothing more. It also keeps the property the
  approval domain's plan hash already enforces and documents in its own source comment, so this
  is the existing control extended to routes rather than a new and weaker one.

  **Shrinkage is not drift.** A Node that has left the approved set — offline, or its labels
  changed — is dropped from that step and recorded, never re-parked: a subset of what the human
  approved is within what the human approved. The asymmetry runs in the safe direction, the same
  way a Scope's omitted field does in ADR-0027. Additions re-park; removals proceed and are
  reported.

  Today's single gated dispatch is the one-step case of exactly this rule, so ADR-0027's existing
  behaviour falls out rather than being special-cased.

- **A Plan's approval requirement is derived from its strictest step, never declared.** The Gate
  rules are evaluated against every step **at the approved resolved set**, never at a smaller
  proposal-time count; the strictest requirement any step triggers governs the whole Plan. Naming
  the fan-out matters: a route priced below the fan-out it is permitted to reach would be the
  "what a route costs to approve is never something its requester gets to say" rule failing by
  omission. Identity binding makes this exact rather than approximate — the approved set *is* the
  fan-out, for every step, for the life of the Plan. If no step is gated, the Plan requires no approval and is not a way to manufacture
  one. This mirrors how an Approval grant's cost is derived at its Scope's widest admissible
  dispatch, and for the same reason: what a route costs to approve must never be something its
  requester gets to say.

- **An approved, incomplete Plan is grant-shaped, and inherits the Approval grant's walls.** A
  Plan parked at step 3 of 7 is standing authorization to dispatch steps 4–7 with no further human
  involvement — an Approval grant whose Scope happens to be enumerated instead of described. It
  therefore takes the same discipline, and for the reasons `approval.md` already argues:

  - a **mandatory window**, within ADR-0027's 24-hour ceiling and expected to be far shorter;
  - **revocable**, closing mid-route immediately;
  - **expiry is terminal and never resumable** — an expired Plan stays where it stopped, and the
    remaining steps need a new Plan and a new Approval;
  - **abandonment is an explicit recorded act**, because an abandonment indistinguishable from a
    crashed session is an absence in the audit trail rather than an answer;
  - **the Freeze bites every advance.** An advance is new dispatch, so ADR-0013 applies with no
    new rule: a Freeze engaged at step 3 stops step 4 and leaves step 3's in-flight Tasks running.
    "Already approved" is exactly the intuition that would otherwise smuggle in a Freeze bypass.

- **A Plan composes nothing, and the Node plane does not change.** Invariant 1 forbids anything on
  the wire from composing or escalating a command, and a sequence of commands is superficially
  what a Plan is. It is not: each step is an independent dispatch that the Node's own Policy engine
  evaluates on its own terms, under its own blast cap, exactly as if a human had typed it. **The
  daemon never learns that a Plan exists** — this ADR adds nothing to `/proto`'s node plane, and a
  step arrives as an ordinary Task. A Plan is a control-plane object for sequencing *authorized*
  acts; it is not a program shipped to a Node, and nothing about a Node's threat surface moves.

- **The agent's rationale is asserted; Relay authors the step list.** The diagnosis that produced
  the route is what makes the route reviewable, so a Plan carries it. But it is agent-authored
  prose placed in front of a human about to authorize mutations — a first-class injection surface,
  where a compromised agent's real lever is making six dangerous steps read as routine. So it goes
  in the **asserted** attribution lane with `on_behalf_of`, bounded and stored verbatim, rendered
  as a marked claim and never interleaved with the steps. The step list an approver reads is
  rendered by Relay from the stored Plan, per ADR-0027: the requesting agent can neither truncate
  it nor spin it.

- **Every step is preflighted at proposal, and steps after the first are labelled as-of-proposal.**
  A proposed Plan runs a Policy preflight across all of its steps, which is what lets an approver
  see that the route is actually admissible. Policy itself cannot move underneath a Plan — invariant
  2 means neither Relay nor the Plan can write it — but `state:` labels shift as steps run
  (ADR-0034), so a later step's resolved fan-out and therefore its verdicts are point-in-time
  against the pre-Plan fleet. They are presented as such. A verdict presented as current when it is
  a forecast is the failure mode ADR-0011 exists to prevent, one layer up.

- **Branches are deferred, and the reason is not implementation effort.** A driver that can halt
  between steps, read more, and decline to continue already has most of what a branch offers. What
  a branch adds is a *pre-approved alternative route* — it buys latency, not capability. Without
  it, a deviation costs one approval round-trip, and that is the correct answer: the human approved
  route A, the agent now wants route B, a human should see route B.

  Recorded here so the constraint is not rediscovered if they are ever picked up: a branch
  predicate may read only **Relay-observable outcomes** — Task outcome, exit code, matched count —
  never Node-supplied content, and **a step's arguments may never be derived from a prior step's
  output**. The moment step 4's argv contains a substring of step 3's stdout, a compromised Node is
  writing a command for the Relay to dispatch, and invariant 1 is defeated from a direction it does
  not currently face. A second constraint follows from approval rather than from taint: a human can
  only approve what they can see, so every reachable step must be enumerable at approval time.
  That, and not a simplicity budget, is what bounds branching.

## Considered Options

- **Keep "plan mode" and name the new capability something else** — Procedure, Runbook, Playbook.
  No rename cost on the existing surface. Rejected: `plan_hash` already means the new thing on the
  wire and in storage, so the drift would have to be fought forever rather than once. "Runbook" and
  "Playbook" both collide with existing repo usage and import config-management connotations that
  are out of realm. And the object an AI-agent proposes before acting is a plan in the vocabulary
  of every agent harness that will drive Relay; renaming the smaller, younger concept is the
  cheaper move.

- **Rename today's capability "dry run".** The obvious free word. Rejected as an over-promise: it
  is a Policy question, not a rehearsal — see the preflight decision above. The name stays
  available for a genuine executor-level no-op mode (`systemctl --dry-run`, `apt -s`) if one is
  ever built.

- **The AI-agent holds the approved route and dispatches each step itself.** Simplest possible
  Relay, no stored object, no cursor. Rejected: the approval would bind nothing. This is the option
  the cursor decision exists to refuse.

- **Relay drives the route inline, with no agent in the loop.** Fewer round trips and no
  half-executed Plans held open. Rejected as the v1 default because the between-steps judgement is
  the reason the capability is valuable, and a fixed predicate language is a poor substitute for
  it — but explicitly preserved: an internal driver would use the same advance path.

- **Pin the resolved Node set for every step at approval time.** Maximum fidelity — the human sees
  exactly which Nodes step 5 will touch. Rejected on the staleness argument in the elasticity
  decision above: over an agent-driven route's lifetime it silently excludes Nodes that became
  affected mid-route, which is the wrong failure direction for the incident-response case this
  capability exists to serve.

- **Extend the Approval grant instead of adding a Plan.** A grant already batches approvals and
  already has walls. Rejected: a grant is *described* and a Plan is *enumerated*, and the
  difference is the entire security value. A grant must be bounded by walls precisely because
  nobody can enumerate what it covers; a Plan needs no walls around its content because it has no
  room inside it. They are complements, and the grant remains the right answer for open-ended work.

## Consequences

- **No invariant is amended in substance — but two are amended in wording, and that is not the
  same as nothing to do.** Invariant 1 is addressed above and holds unchanged; invariant 4 is
  extended from Tasks to steps by the cursor rather than relaxed; invariant 5's cap stays
  per-dispatch and is checked at every step; invariant 10 puts the Plan in the capability layer
  with every surface an adapter over it.

  However, **invariant 10 says "plan-by-default" and invariant 12 says "plan mode"**, and both
  spellings now mean the route rather than the preview. Those are terminology amendments to
  `AGENTS.md`, which is a conversation with a human and never a quiet edit — they are named here
  so the work is visible rather than left to rot. Until they land, `docs/security/threat-model.md`
  restates invariant 12 in the *new* wording while the invariant itself carries the old, so
  consumer and source differ verbatim: exactly the drift AGENTS.md warns about, and a reason to
  land the amendment rather than leave it.

- **This amends ADR-0013, which nobody noticed.** ADR-0013 said "**Plans (ADR-0011) still work
  while frozen**" — human-signed-off, and the authority this ADR's own Freeze argument leans on.
  Reassigning the word inverted it into a Freeze exemption for approved routes without anyone
  editing the sentence. Amended in place; `docs/specs/freeze.md` was rewritten in the same change
  to match, which until the amendment landed had the spec contradicting its governing ADR — and
  AGENTS.md's conflict table presumes the *spec* is the defect, so a reader resolving it by the
  rules would have reinstated the exemption. The lesson generalises: **a rename's blast radius
  includes every sentence that merely uses the word, and the ADR tier is where it hurts most.**

- **Amends ADR-0011** — name and framing only; its four decisions are re-affirmed verbatim above.
  Its "terraform plan / Ansible check-mode" sentence is the origin of the collision and is
  withdrawn.

- **Amends ADR-0027** — Plan hash now addresses a *route* rather than a single Operation, and a
  single gated dispatch becomes the one-step case. The shape key follows the same generalisation:
  it addresses *what* a route is for, excluding resolved fan-out, so the anti-fatigue diff answers
  "what did I approve last time that looked like this route?" as a lookup.

- **GLOSSARY.md** takes the largest edit: **Plan** redefined, **Policy preflight** added, **Plan
  hash** and **Shape key** generalised to routes, **Stage** clarified against Plan steps, and the
  **Freeze** entry corrected — a frozen Relay leaves *preflights* available, which is what it
  always meant.

- **Two capability specifications**: `plan.md` for the new capability, and `policy-preflight.md`
  — today's `plan-mode.md`, renamed — describing what exists now. Branching lands in `plan.md`'s
  out-of-scope section as a candidate idea, in the register the Shadow mode entry already uses.

- **The first implementation pins the fan-out ceiling at 1.** `plan.md` specifies a one-Node,
  linear, agent-driven cut: the ceiling mechanism above is built and enforced, set to 1, and a
  Selector matching anything else is refused at proposal with the count. That is not a weaker
  design but the degenerate corner of this one — at a ceiling of 1 the resolved Node set is
  trivially pinnable, so the elasticity rule's hard case does not arise, and widening later raises
  a value rather than re-specifying targeting. The aggregate-consent question in the last
  consequence below must be answered **before** the ceiling rises, not after.

- **Four ADRs and the Console's UI language still carry the old spelling, and are tracked rather
  than swept** — [#574](https://github.com/Felag-Engineering/gleipnir-relay/issues/574) and
  [#575](https://github.com/Felag-Engineering/gleipnir-relay/issues/575) respectively.
  ADR-0009 (`:13`), ADR-0026 (`:63`, `:134`, `:170`) and ADR-0027 (`:234`)
  all say "plan-by-default" or "render the Plan", meaning the preview. None of them inverts the
  way ADR-0013 did — they read as stale rather than dangerous — but the ADR tier carries human
  sign-off by construction, so each is an amendment in front of a person and never a quiet edit.
  Separately, `docs/design/console/` and `docs/design/ui-advisory.md` carry roughly twenty-five
  uses including a literal button label (`"Plan" — not "Run"`). That one is not a sweep at all:
  it is where the two meanings **collide on screen**, since the Console will render preflight
  results *and* approved routes in the same queue, and it is user-facing copy. It wants a product
  decision and its own issue.

- **The code rename is a hard prerequisite, not a follow-up of convenience.** The capability
  layer already defines `Service.Plan` and `PlanResult` for the *old* preview, and the audit kind
  `AuditKindPlan` is spoken for. The first line of code for the route capability cannot be written
  until those are renamed to their Policy-preflight spellings, so the rename PR blocks the whole
  milestone and any issue decomposition must sequence it first.

- **One breaking change on the control-plane surface**: the `plan` option becomes `preflight` on
  `run_operation`, `raw_exec`, `POST /api/v1/operations` and `POST /api/v1/raw-exec`. The
  `plan_hash` field on the approval surface is **unchanged and keeps its meaning**, which is the
  clearest evidence the word was reassigned in the right direction. Roughly 360 of the Go `Plan`
  mentions are `plan_hash`/`PlanHash` and survive untouched.

- **New storage and a new lifecycle.** A Plan is durable. `plan.md` is the spec of record for the
  states and this ADR does not restate them: an ungated Plan is created `approved` with its cursor
  at 0, a gated one starts `pending-approval`, and every terminal state is terminal — none is
  resumable. Retained after it ends; per ADR-0025 the record holds steps, decisions and outcomes,
  **never read output**. The lifecycle is security-relevant rather than bookkeeping, because it is
  what decides whether an advance is permitted at all.

- **A half-executed Plan is a new operational state** that monitoring, the Console and the audit
  trail must all be able to show. A route stopped at step 3 is neither a success nor a failure, and
  reporting it as either would be a lie an operator acts on.

- **One human decision now covers N dispatches.** Invariant 5's cap is per-dispatch and stays so,
  but a route concentrates consent in a way the cap was not sized for. Whether a Plan also needs an
  aggregate ceiling across its steps is left open here and belongs in `plan.md`'s open questions;
  the derived-requirement rule above means a wide route is at least priced at its worst step.

- **The Console renders Plans but does not compose them in v1.** Console execution remains behind
  the `console_execution` flag and is unbuilt (invariant 10's gap row, #438). Proposing a route is
  an agent act; approving one is a human act, and the approval queue is where a Plan meets a person.

## Amendment (2026-09-20): dated, and its consumers recorded

This ADR carried no date; it was accepted on **2026-09-12** (ADR-0013's inline note dates it).
Consumers updated on 2026-09-20: invariants 10 and 12 in `AGENTS.md` now say
*preflight-by-default* and *the Policy preflight*; ADR-0011 carries the rename at its head;
ADR-0026 and ADR-0027 are reworded and record the amendment; ADR-0004, 0009, 0018 and 0019 lose
their incidental "plan mode"; the Console's user-facing word is **Preflight** (#575). Left as
written: the `plan` wire option, until the code follows.
