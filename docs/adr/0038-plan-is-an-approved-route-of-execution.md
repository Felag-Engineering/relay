# Plan is an approved route of execution; Policy preflight is its own capability

**Status:** Accepted; amended by ADR-0044.

"Plan" has meant two things since ADR-0011, whose own opening describes the capability as
"`terraform plan` / Ansible check-mode for the fleet". Those differ. Ansible's check-mode is a
rehearsal; Terraform's plan is a saved artifact you later apply — the noun, not the rehearsal.

ADR-0011 built the rehearsal and took the noun's name. The noun then came back: ADR-0027
defines **Plan hash** as "the content address of a Plan — a hash over the Operation, its
arguments, and the *resolved fan-out*", and binds a human approval to it. A content address
over a preview is meaningless. What the hash addresses is **the act the caller intends to
perform** — the Terraform meaning, arriving through the approval domain where the concept was
genuinely needed.

Meanwhile the capability the product needs has no name. An AI-agent diagnoses an incident with
a series of reads, concludes that six things must happen in order, and needs **one** human
decision over the whole route rather than six. Relay's existing answer is the Approval grant:
a *described* scope with walls — an Operation allow-list, a fan-out ceiling, a window. This ADR
adds the *enumerated* alternative. A grant is a blank cheque with a spending limit; a Plan is
an itemised invoice.

## Decisions

- **A Plan is an approved route of execution.** An ordered sequence of steps, each a fixed
  Operation or Raw Exec with fixed arguments and a fixed Selector, proposed as one object,
  answered by one Approval, and executed and audited as one unit. **v1 is linear** — see the
  branching decision below.

- **Today's plan mode is renamed Policy preflight.** Every decision in ADR-0011 stands and is
  re-affirmed: the daemon's live engine evaluates the hypothetical, the wire carries a distinct
  `PolicyQuery`/`PolicyVerdict` pair rather than a `dry_run` flag, an offline Node yields
  `unknown(offline)` and never a guess, and a preflight reports guardrails instead of failing on
  them. Only the **name** and the check-mode framing were wrong. The tool and API option `plan`
  becomes `preflight`.

  It is deliberately **not** "dry run". A preflight never touches an executor; it asks each
  Node's Policy engine a question. A caller told "the dry run passed" would believe Relay had
  exercised the command, when it only confirmed the doorman would not stop it. GLOSSARY.md
  already refuses that word for this capability.

- **A Plan sits above Jobs: one step is one Job.** A Job is "a single dispatch of an Operation
  or Raw Exec across the Nodes matched by a Selector" — one Operation, by definition. Modelling
  a Plan as one multi-Operation Job would redefine the repo's unit of audit and blast-radius
  control; instead the Plan is the object *above* the Job, and each step is an ordinary Job
  bound to the Plan's ID.

  **`Stage` is untouched and keeps its reserved meaning** — ordered batches of Tasks within a
  single Operation's fan-out, for the staged rollout in `docs/proposals/staged-rollout-and-approval.md` (canary → gate →
  remainder). The two are orthogonal and compose: a Plan of N steps, each a Job, each Job one
  day possibly multi-stage. A Plan step is not a Stage, and the two must never be merged.

- **Relay stores the Plan and the cursor; the driver carries no payload.** The approved Plan and
  a monotonic step cursor live on the Relay. The driver advances it by naming the Plan and the
  step index it believes is next — and **nothing else**: no Operation, no arguments, no
  Selector. Relay looks up that step, dispatches what the human approved, and moves the cursor.

  This is the load-bearing decision. If the driver held the approved step list and dispatched
  each step itself, the approval would bind nothing: a hijacked or confused agent could
  reorder, skip, replay or substitute, and each dispatch would look like any other. Here the
  advance call contains no description of the work, so there is nothing to tamper with. **The
  driver decides *whether* and *when* to continue; Relay decides *what* runs.**

  The declared step index is an optimistic-concurrency check: a retried advance arriving after
  the cursor has moved is refused rather than re-running a step. That is how invariant 4's
  at-most-once extends from Tasks to steps — **provided the compare-and-advance is
  transactional.** `approval.md` states the rule: *"the bound is enforced inside the claiming
  transaction, or it is not a bound."* The cursor must move to an in-flight marker **before**
  the step dispatches, in one transaction with the step's Job creation, mirroring the Task-level
  mark-dispatched-before-dispatch precedent. Otherwise two advances at the same index both pass
  and both dispatch — and Task dedup does not save it, because each advance mints a new Job with
  new Task IDs, so the daemon sees two legitimately distinct Tasks.

- **The AI-agent is the default driver; the advance path is the only execution path.** The
  judgement that matters between steps — does the fleet still look the way the diagnosis
  assumed? — is judgement, not a predicate. A Relay-internal driver may be added later for
  unattended routes; it would call the same advance path and gain no privilege by being
  internal.

- **What runs and who it runs on are both frozen; the binding is by identity, never by count.**
  The Plan hash binds the route — the ordered steps, their Operations, arguments, normalised
  Selectors, the failure semantics — **and the resolved Node set the approver was shown**. Every
  advance re-resolves, and **any Node not in the approved set re-parks the Plan for
  re-approval.** There is no tolerance and no ceiling.

  An earlier draft bound a fan-out *ceiling* instead, reasoning that an agent-driven route spans
  real time and a pinned set goes stale — a Node that became affected at step 2 would be
  silently excluded from step 5, which is backwards for remediation. That reasoning walks only
  the exclusion direction. The inclusion direction is an attack: an approver sees `{A,B,C}`
  under a ceiling of 10, and by step 5 the set is `{A,B,C,D}` — or `{D,E,F}` — with every step
  still dispatching under an approval given for different hosts. A ceiling binds a number, not
  an identity. And invariant 7 says a compromised Node **can forge its own `node:` labels**, so
  under a ceiling an attacker owning one Node could elect itself into a human-approved route by
  forging the label the Plan's Selector matches.

  Identity binding degrades that attack from *election into an approved route* to *causing a
  re-park* — a denial of convenience and nothing more. It also keeps the property the approval
  domain's plan hash already enforces, so this extends the existing control to routes rather
  than adding a weaker one.

  **Shrinkage is not drift.** A Node that has left the approved set — offline, or its labels
  changed — is dropped from that step and recorded, never re-parked: a subset of what the human
  approved is within what they approved. The asymmetry runs in the safe direction, as a Scope's
  omitted field does in ADR-0027. Additions re-park; removals proceed and are reported.

  Today's single gated dispatch is the one-step case of this rule, so ADR-0027's behaviour falls
  out rather than being special-cased.

- **A Plan's approval requirement is derived from its strictest step, never declared.** The
  Gate rules are evaluated against every step **at the approved resolved set**, never at a
  smaller proposal-time count; the strictest requirement any step triggers governs the whole
  Plan. A route priced below the fan-out it may reach would break the rule that what a route
  costs to approve is never something its requester gets to say. Identity binding makes this
  exact: the approved set *is* the fan-out, for every step, for the life of the Plan. If no step
  is gated, the Plan requires no approval and is not a way to manufacture one. This mirrors how
  an Approval grant's cost is derived at its Scope's widest admissible dispatch.

- **An approved, incomplete Plan is grant-shaped, and inherits the Approval grant's walls.** A
  Plan parked at step 3 of 7 is standing authorization to dispatch steps 4–7 with no further
  human involvement — an Approval grant whose Scope is enumerated instead of described. It takes
  the same discipline, for the reasons `approval.md` argues:

  - a **mandatory window**, within ADR-0027's 24-hour ceiling and expected to be far shorter;
    *(Amended 2026-09-24: that ceiling is now 4 hours — ADR-0027 §Amendment (2026-09-24). The
    rule is unchanged; only the number it cites moved.)*
  - **revocable**, closing mid-route immediately;
  - **expiry is terminal and never resumable** — an expired Plan stays where it stopped, and
    the remaining steps need a new Plan and a new Approval;
  - **abandonment is an explicit recorded act**, because an abandonment indistinguishable from a
    crashed session is an absence in the audit trail rather than an answer;
  - **the Freeze bites every advance.** An advance is new dispatch, so ADR-0013 applies with no
    new rule: a Freeze engaged at step 3 stops step 4 and leaves step 3's in-flight Tasks
    running. "Already approved" is exactly the intuition that would smuggle in a Freeze bypass.

- **A Plan composes nothing, and the Node plane does not change.** Invariant 1 forbids anything
  on the wire from composing or escalating a command, and a sequence of commands superficially
  is what a Plan is. It is not: each step is an independent dispatch that the Node's own Policy
  engine evaluates on its own terms, under its own blast cap, exactly as if a human had typed
  it. **The daemon never learns that a Plan exists** — nothing is added to `/proto`'s node
  plane, and a step arrives as an ordinary Task. A Plan sequences *authorized* acts on the
  control plane; it is not a program shipped to a Node, and no Node's threat surface moves.

- **The agent's rationale is asserted; Relay authors the step list.** The diagnosis behind the
  route is what makes it reviewable, so a Plan carries it. But it is agent-authored prose in
  front of a human about to authorize mutations — a first-class injection surface, where a
  compromised agent's real lever is making six dangerous steps read as routine. So it goes in
  the **asserted** attribution lane with `on_behalf_of`, bounded and stored verbatim, rendered
  as a marked claim and never interleaved with the steps. The step list an approver reads is
  rendered by Relay from the stored Plan, per ADR-0027: the requesting agent can neither
  truncate nor spin it.

- **Every step is preflighted at proposal, and steps after the first are labelled
  as-of-proposal.** A proposed Plan runs a Policy preflight across all its steps, so an
  approver can see the route is admissible. Policy cannot move underneath a Plan — invariant 2
  means neither Relay nor the Plan can write it — but `state:` labels shift as steps run
  (ADR-0034), so a later step's resolved fan-out, and so its verdicts, are point-in-time against
  the pre-Plan fleet, and are presented as such. A forecast presented as current is the failure
  ADR-0011 exists to prevent, one layer up.

- **Branches are deferred, and the reason is not implementation effort.** A driver that can
  halt between steps, read more, and decline to continue already has most of what a branch
  offers. A branch adds a *pre-approved alternative route* — it buys latency, not capability.
  Without it, a deviation costs one approval round-trip, which is correct: the human approved
  route A, the agent now wants route B, a human should see route B.

  The constraints, should branches ever be picked up: a branch predicate may read only
  **Relay-observable outcomes** — Task outcome, exit code, matched count — never Node-supplied
  content, and **a step's arguments may never be derived from a prior step's output**. The
  moment step 4's argv contains a substring of step 3's stdout, a compromised Node is writing a
  command for the Relay to dispatch, and invariant 1 is defeated from a direction it does not
  currently face. And a human can only approve what they can see, so every reachable step must
  be enumerable at approval time. That, not a simplicity budget, is what bounds branching.

## Considered Options

- **Keep "plan mode" and name the new capability something else** — Procedure, Runbook,
  Playbook. Rejected: `plan_hash` already means the new thing on the wire and in storage, so the
  drift would be fought forever rather than once. "Runbook" and "Playbook" collide with existing
  repo usage and import out-of-realm config-management connotations. And the object an AI-agent
  proposes before acting is a plan in every agent harness's vocabulary; renaming the smaller,
  younger concept is cheaper.

- **Rename today's capability "dry run".** Rejected as an over-promise: it is a Policy question,
  not a rehearsal. The name stays available for a genuine executor-level no-op mode
  (`systemctl --dry-run`, `apt -s`) if one is ever built.

- **The AI-agent holds the approved route and dispatches each step itself.** Simplest Relay, no
  stored object, no cursor. Rejected: the approval would bind nothing — the option the cursor
  decision exists to refuse.

- **Relay drives the route inline, with no agent in the loop.** Fewer round trips, no
  half-executed Plans held open. Rejected as the v1 default because the between-steps judgement
  is the capability's value, and a fixed predicate language is a poor substitute — but
  preserved: an internal driver would use the same advance path.

- **Pin the resolved Node set for every step at approval time.** Maximum fidelity — the human
  sees exactly which Nodes step 5 will touch. Rejected on the staleness argument in the
  elasticity decision above: over an agent-driven route's lifetime it silently excludes Nodes
  that became affected mid-route, the wrong failure direction for incident response.
  *(Amended 2026-10-21: this bullet is left over from the ceiling draft and contradicts the
  decision above, which **does** bind the resolved Node set. The option actually rejected is
  binding a fan-out ceiling instead of the set: it walks only the exclusion direction, and in
  the inclusion direction a Node forging its `node:` labels elects itself into an approved
  route. See the 2026-10-21 amendment below.)*

- **Extend the Approval grant instead of adding a Plan.** A grant already batches approvals and
  has walls. Rejected: a grant is *described* and a Plan *enumerated*, and that difference is
  the whole security value. A grant needs walls because nobody can enumerate what it covers; a
  Plan has no room inside it. They are complements, and the grant remains the answer for
  open-ended work.

## Consequences

- **No invariant is amended in substance, but two are amended in wording.** Invariant 1 holds
  unchanged; invariant 4 is extended from Tasks to steps by the cursor, not relaxed; invariant
  5's cap stays per-dispatch and is checked at every step; invariant 10 puts the Plan in the
  capability layer with every surface an adapter over it. **Invariant 10 said
  "plan-by-default" and invariant 12 "plan mode"**, and both spellings now mean the route
  rather than the preview — terminology amendments to `AGENTS.md`, made in front of a human
  (recorded in the 2026-09-20 amendment below).

- **This amends ADR-0013, which nobody noticed.** ADR-0013 said "**Plans (ADR-0011) still work
  while frozen**" — human-signed-off, and the authority this ADR's own Freeze argument leans on.
  Reassigning the word inverted it into a Freeze exemption for approved routes without anyone
  editing the sentence. Amended in place; `docs/specs/freeze.md` was rewritten in the same
  change. Until then the spec contradicted its governing ADR, and AGENTS.md's conflict table
  presumes the *spec* is the defect, so a reader following the rules would have reinstated the
  exemption. **A rename's blast radius includes every sentence that merely uses the word, and
  the ADR tier is where it hurts most.**

- **Amends ADR-0011** — name and framing only; its four decisions are re-affirmed above. Its
  "terraform plan / Ansible check-mode" sentence, the origin of the collision, is withdrawn.

- **Amends ADR-0027** — Plan hash now addresses a *route* rather than a single Operation, and a
  single gated dispatch becomes the one-step case. The shape key generalises the same way: it
  addresses *what* a route is for, excluding resolved fan-out, so the anti-fatigue diff answers
  "what did I approve last time that looked like this route?" as a lookup.

- **GLOSSARY.md** takes the largest edit: **Plan** redefined, **Policy preflight** added,
  **Plan hash** and **Shape key** generalised to routes, **Stage** clarified against Plan steps,
  and the **Freeze** entry corrected — a frozen Relay leaves *preflights* available, which is
  what it always meant.

- **Two capability specifications**: `plan.md` for the new capability, and
  `policy-preflight.md` — today's `plan-mode.md`, renamed. Branching lands in `plan.md`'s
  out-of-scope section as a candidate idea, in the register the Shadow mode entry uses.

- **The first implementation pins the fan-out ceiling at 1.** `plan.md` specifies a one-Node,
  linear, agent-driven cut: the ceiling mechanism is built and enforced, set to 1, and a
  Selector matching anything else is refused at proposal with the count. This is the degenerate
  corner of the design, not a weaker one — at a ceiling of 1 the resolved Node set is trivially
  pinnable, so the elasticity rule's hard case does not arise, and widening later raises a value
  rather than re-specifying targeting. The aggregate-consent question below must be answered
  **before** the ceiling rises.
  *(Amended 2026-10-21: read "ceiling" here as the one-Node bound, not a fan-out ceiling the
  binding relies on. At one Node identity binding is node-equality; at N it is set-membership
  over the approved set, where an addition re-parks and a shrinkage proceeds. Widening changes
  how the check is written, never what it guarantees.)*

- **Four ADRs and the Console's UI language carried the old spelling**, tracked rather than
  swept — [#574](https://github.com/Felag-Engineering/relay/issues/574) and
  [#575](https://github.com/Felag-Engineering/relay/issues/575). ADR-0009, ADR-0026 and ADR-0027
  said "plan-by-default" or "render the Plan", meaning the preview; none inverts the way ADR-0013
  did, but the ADR tier carries human sign-off, so each is an amendment in front of a person.
  `docs/design/console/` and `docs/design/ui-advisory.md` carried about twenty-five uses,
  including a literal button label (`"Plan" — not "Run"`). That is where the two meanings
  **collide on screen** — the Console renders preflight results *and* approved routes — so it
  wanted a product decision of its own.
  *(Noted 2026-09-29: the four ADRs' amendments tracked in #574 were completed in #665 on
  2026-09-21, and #574 is closed; see the 2026-09-20 amendment below.)*

- **The code rename is a hard prerequisite.** The capability layer defines `Service.Plan` and
  `PlanResult` for the *old* preview, and the audit kind `AuditKindPlan` is spoken for. No code
  for the route capability can be written until those take their Policy-preflight spellings, so
  the rename PR blocks the milestone and any decomposition must sequence it first.

- **One breaking change on the control-plane surface**: the `plan` option becomes `preflight`
  on `run_operation`, `raw_exec`, `POST /api/v1/operations` and `POST /api/v1/raw-exec`. The
  `plan_hash` field on the approval surface is **unchanged and keeps its meaning** — the
  clearest evidence the word was reassigned in the right direction. About 360 of the Go `Plan`
  mentions are `plan_hash`/`PlanHash` and survive untouched.

- **New storage and a new lifecycle.** A Plan is durable. `plan.md` is the spec of record for
  the states: an ungated Plan is created `approved` with its cursor at 0, a gated one starts
  `pending-approval`, and every terminal state is terminal — none is resumable. Retained after
  it ends; per ADR-0025 the record holds steps, decisions and outcomes, **never read output**.
  The lifecycle is security-relevant, because it decides whether an advance is permitted at all.

- **A half-executed Plan is a new operational state** that monitoring, the Console and the audit
  trail must all show. A route stopped at step 3 is neither success nor failure, and reporting it
  as either would be a lie an operator acts on.

- **One human decision now covers N dispatches.** Invariant 5's cap is per-dispatch and stays
  so, but a route concentrates consent in a way the cap was not sized for. Whether a Plan also
  needs an aggregate ceiling across its steps is open, in `plan.md`'s open questions; the
  derived-requirement rule means a wide route is at least priced at its worst step.

- **The Console renders Plans but does not compose them in v1.** Console execution remains
  behind the `console_execution` flag and is unbuilt (invariant 10's gap row, #438). Proposing a
  route is an agent act; approving one is a human act, and the approval queue is where a Plan
  meets a person.
  *(Amended 2026-10-18 by ADR-0044: the Console has no approval queue. A gated Plan meets a
  person through the requesting client in-band, or on the Control API out-of-band; the Console
  renders a Plan and decides none.)*

## Amendment (2026-09-20): dated, and its consumers recorded

This ADR carried no date; it was accepted on **2026-09-12** (ADR-0013's inline note dates it).
Consumers updated on 2026-09-20: invariants 10 and 12 in `AGENTS.md` now say
*preflight-by-default* and *the Policy preflight*; ADR-0011 carries the rename at its head;
ADR-0026 and ADR-0027 are reworded and record the amendment; ADR-0004, 0009, 0018 and 0019
lose their incidental "plan mode"; the Console's user-facing word is **Preflight** (#575). Left
as written: the `plan` wire option, until the code follows.

## Amendment (2026-10-18): amended by ADR-0044 — no approval queue in the Console

A note on one consequence, not a change to any decision here.
[ADR-0044](0044-the-console-does-not-decide-approvals.md) removes the Console's approval
surface, so *Consequences*' "the approval queue is where a Plan meets a person" no longer names
a Console screen: a gated Plan is approved in-band by the requesting client or out-of-band on
the Control API, and the Console renders it without deciding it. Signposted in place, dated.

## Amendment (2026-10-21): two passages made consistent with identity binding

A correction, not a change to any decision here. *Considered Options* rejected pinning the
resolved Node set "on the staleness argument in the elasticity decision above", and
*Consequences* called the first cut's one-Node bound "the fan-out ceiling". Both are left over
from the earlier ceiling draft that *Decisions* records and rejects: the decision binds the
approved Node set by identity, with no tolerance and no ceiling. Both passages are signposted in
place, dated. `docs/specs/plan.md`'s *Out of scope* entry for multi-Node Plans, which carried
the same wording, is corrected to match.
