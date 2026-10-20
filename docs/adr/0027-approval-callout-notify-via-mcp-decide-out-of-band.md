# Approval callout: notify via MCP, decide out-of-band

**Status:** Accepted; amended by ADR-0010, ADR-0029, ADR-0038, ADR-0040 and ADR-0044.

Some dispatches should not run on an AI-agent's say-so. This ADR decides how a human is
asked, how their answer gets back, and why the answer is trustworthy even when the harness
that requested the action is not.

Grounding: the research note `mcp-approval-primitives.md` (removed from `docs/research/`;
git history keeps it) and `docs/design/approval-and-attribution.md` (the identity and ladder
model). Discharges the research half of epic #210; #208 is the closed-loop shape this serves.

## The problem MCP does not solve for us

MCP has a directly relevant primitive. `elicitation/create` runs **server → client → human
→ client → server** and does not pass through the LLM; its `accept`/`decline`/`cancel` maps
1:1 onto approve/deny/cancel. The Tasks extension lets a long-running call return a handle
the client polls, with an elicitation surfacing *during* the wait — a near-exact fit for a
parked Job.

It is still not a guarantee:

> Elicitation and Tasks travel **over the MCP session, which is the AI's channel and the
> client's responsibility.** MCP's human-in-the-loop story is a *client-side convention*.

A naïve client can feed the approval to its model; a compromised one can auto-answer it. The
known attacks are approval fatigue, description truncation, consent overload, and the
"approval-view fidelity gap", where what the human sees is not what executes. MCP also has
no **audience routing**: elicitation reaches "the current user of the client", never "the
on-call database team". And MCP's roadmap lists human-in-the-loop and approvals as "on the
horizon", not a 2026 priority.

So we cannot build the guarantee *out of* MCP. We can build it *alongside* MCP.

## The core decision

**Notify via MCP, decide out-of-band.**

```
Relay ──authors the request──> delivery (elicitation | task handle | webhook)
                                        │
                                        v
                              human on an authenticated
                              decision channel
                                        │
        Relay <───────decision──────────┘   (never through the MCP session)
```

Two properties follow, and they are the point:

- **The proposing agent is outside the trust path.** The decision lands on an authenticated
  Relay endpoint, on a credential the requesting session does not hold. It works for
  harnesses with no approval features, and for the API-control drive mode, which has no MCP
  session at all.
- **Relay authors the content**: Operation, arguments, resolved fan-out, per-Node plan
  verdicts, blast size, requester. The agent supplies none of the words the human reads,
  which answers the approval-view-fidelity attacks structurally.

## Decisions

1. **A gated Job parks.** The Job enters `pending-approval` — a Job-engine state, not a held
   connection — so the mechanism survives disconnects, restarts, and the 2026-07-28 spec's
   removal of protocol sessions. A Job is already a durable handle; approval reuses it.

   > **Amended, 2026-09-24.** There is no Job to park. The gate sits before the dispatcher,
   > so **parking creates no Job and no Tasks at all** — ADR-0028's amendment of 2026-08-17
   > recorded this, and it is a claim in `docs/specs/approval.md`. What parks is the approval
   > **Request**; a Job is minted only if a decision releases one. The durability argument
   > holds, on the Request instead of the Job.

2. **Three delivery envelopes, and we never hard-depend on any of them.**
   - **Held elicitation** — `elicitation/create` for short waits on elicitation-capable
     harnesses.
   - **MCP task handle + nested elicitation** — the premium path for long waits; the
     approval surfaces under `inputRequests` on `tasks/get`.
   - **Out-of-band webhook / link** — the universal path. Required, always available, and
     the only one that is a *guarantee* rather than a delivery convenience.
     *(Amended 2026-09-24 by ADR-0040: still true of the authenticated decision endpoint's
     **availability**, and no longer a description of where an agent-originated approval is
     expected to arrive — that is the requesting MCP client. As amended 2026-09-25: the
     endpoint still decides any request, including an agent's, and is not relied on. As
     amended 2026-10-18 by ADR-0044: that endpoint is the Control API's, and it is the only
     out-of-band path — the Console decides no approval.)*

   The Tasks extension is still stabilizing (retry and expiry lifecycle gaps), so it is an
   optimization, never a dependency. **A deployment with no elicitation-capable client loses
   convenience, not safety.**

3. **Delivery is not the decision.** Relay decides *whether* approval is required and *what
   the human sees*; the envelope decides only *how they are reached*. Conflating them would
   quietly make the guarantee the client's problem.

4. **Channel strength is per gate rule.**
   - `in-band` — the elicitation answer *is* the decision. Zero friction, and it trusts the
     harness, which holds that session's credential.
   - `out-of-band` — the decision must land on the authenticated decision endpoint, carrying
     a credential the agent session does not hold.

   In-band is *an assumption about the client*; out-of-band is *evidence*. Default the
   self-confirmation rung to in-band and the second-person rung to out-of-band; deployments
   move the dial in root-owned config.
   *(Amended 2026-09-24 by ADR-0040: the first half stands and the second is shelved in the
   shipped posture — no shipped or seeded rule sets a second-person rung, so nothing demands
   `out-of-band`. The mechanism is unchanged and unexercised.)*

5. **The confirmation ladder.** Gate rules select a rung:
   1. **No gate** — below thresholds, runs immediately.
   2. **Self-confirmation** — the requester sees the Relay-authored Plan and confirms.
      **Human requesters only**: an agent cannot confirm itself, so a machine requester's
      minimum gated rung is 3. The Console's step-up apply (ADR-0026) *is* this rung fused
      into the request surface, not a bypass of it.
   3. **Second-person** — audience excludes the requester (`requester_allowed: false`).

   **MCP-originated calls are agent-grade regardless of whose OAuth identity authorizes the
   session.** Session authorization is not per-call human intent: the calls are still
   model-generated, and the session is steerable by prompt injection in content the model
   read (#274, #283). The axis is how strongly the originating surface binds a human's
   intent to the individual action, not whether a human is nominally present.

6. **Gate config is root-owned Relay configuration, and narrows only.** It lives with the
   blast cap, above the AI's reach and outside the Control API (invariant 11). Grammar:

   ```
   match:       risk class · blast size · selector namespace · principal · operation
   requirement: count · audience · requester_allowed · channel · ttl
   ```

   A gate rule can require approval where none was required; it can never grant an approval
   that Policy would refuse. **Approval is not authorization** — an approved Job still
   traverses Selector → Policy → blast cap unchanged. Node Policy remains the floor no human
   can lower over the wire (ADR-0002).

7. **Quorum: store the general shape, expose the narrow config.** The stored schema is
   **requirement vs. a set of decisions** from day one; v1 config exposes only
   `count: 1 | 2`, audience, and `requester_allowed`. N-of-M and richer matching then land
   as a config-language change with **no data migration**, as the Job engine's Stages did.
   Each decision is its own audit record (approver, timestamp, plan-hash, channel), and
   partial state (`1 of 2`) is visible in the queue, so the second approver sees who already
   signed.

8. **Approvals bind to a content-addressed Plan, and drift re-parks.** The approval commits
   to a **plan-hash** over operation, arguments and *resolved fan-out* — never to "the Job"
   in the abstract. If the Plan no longer matches at dispatch time, the Job **re-parks for
   re-approval** rather than running. This closes park-something-innocuous-then-mutate-the-
   world, and is the approval-flow analog of ADR-0011's verdicts-match-execution property.

9. **Everything expires.** Parked Jobs and approval validity both carry a TTL. An approval
   against plan-hash `abc123` is not redeemable indefinitely.

10. **The attribution triple, in two structurally distinct lanes.** Every gated dispatch
    records `requested_by` (**verified**), `on_behalf_of` (**asserted**), and `approved_by`
    (**verified**, with channel and plan-hash). The audit *schema* — not the renderer —
    keeps the lanes apart. A jailbroken agent can assert anything and forge nothing; blurring
    the lanes turns an audit trail into fiction. See GLOSSARY.md, *Attribution*.

11. **The approval request and every decision are first-class audit records**, not log
    lines. "Who asked / for whom / who approved / what happened" must be answerable in one
    query.

12. **Batch and window approvals are first-class, because fatigue is a security property.**
    "The ops team is doing a bunch of work" must not mean forty elicitations. An approval may
    cover a **declared batch** of Jobs or a **scoped window** (`mutate` against
    `service=web`, next 2 hours, requested by `gleipnir-prod` for `ops-team`), with every
    covered Job auditing back to the same approval ID.

    Bounded in scope and time, this is a **time-boxed narrowing grant**, consistent with the
    deferred Grants rule that approvals narrow what is possible and never widen Policy. It is
    in the schema from the start because a mechanism that produces forty prompts produces
    forty rubber stamps, and **a rubber-stamped approval is worse than no approval**: it
    manufactures evidence that a human considered something they did not. The approval
    object also carries a **diff against the last approved similar action** ("same as
    Tuesday, except fan-out grew 3 → 12"), which is where fatigue is actually beaten.

13. **Naming: an MCP task handle is not a Relay Task.** MCP's "task" is a client-polled
    handle for one long-running `tools/call`; a Relay **Task** is one Operation executing on
    one Node. Always write "MCP task handle" in full. GLOSSARY.md carries the
    disambiguation.

### Informational: the Gleipnir-side rule

Gleipnir is a separate repo and this ADR does not bind it, but the contract only closes if
its client honours one rule:

> **Gleipnir's elicitation handler MUST be a deterministic path to the assigned human
> audience — never surfaced to the LLM, never auto-answered.**

That rule is what upgrades MCP HITL from convention to guarantee on the premium path.
Relay's gate config defines *who may approve*; Gleipnir defines *how they are reached*
(#209). Relay never depends on it for correctness — the out-of-band channel stands alone —
but the premium path's security claim is Gleipnir's to keep.

## Alternatives considered

- **In-band elicitation only.** The simplest thing, and the one every MCP example shows.
  Rejected as the *guarantee*: the approval would ride the same session as the request, so a
  compromised or naïve harness could answer for the human undetectably. Kept as a delivery
  envelope, where its weakness is bounded by the rung it may satisfy.

- **Wait for MCP to standardize approvals.** Rejected on evidence: MCP's 2026 priorities are
  Agent Communication, registry, and OAuth/enterprise auth, with human-in-the-loop "on the
  horizon". Designing around a primitive that may not arrive, and would still be client-side
  when it did, is not a plan.

- **Approval as a Policy concept, enforced by the daemon.** Rejected: Policy is deliberately
  local, offline-evaluable, and has no notion of humans, sessions or waiting. Making it block
  on a remote human would put a network dependency inside the one component whose value is
  that it decides alone (ADR-0002). Approval is a Relay-side gate on *dispatch*; Policy
  remains the floor underneath it.

- **Relay pushes directly to Slack/PagerDuty/email.** Rejected for v1: audience routing is
  harness- and org-specific, and a notification-integration surface in a security-critical
  control plane is a large permanent maintenance and credential burden. The webhook plus a
  signed decision link lets someone else own that; #277 is where integrations belong.

- **Per-approval short-lived credentials instead of Console step-up.** Deferred, not
  rejected — the open question for pure-API shops whose approvers are not Console users. v1
  answers with the authenticated decision endpoint and a signed link; a disjoint approver
  credential is left to the [3/6] issue.

## Consequences

- **The Job engine gains a state and the audit schema gains records.** `pending-approval` is
  a real state with a TTL and a re-park transition, not a flag; approval requests and
  decisions are audited objects. Both land in [2/6].

- **The out-of-band endpoint is a new, high-value authenticated surface on the Control API**
  ([3/6]): forging a decision is forging an approval. It is Account-authenticated like every
  other `/api/v1` route, and every decision is bound to a plan-hash, so a replayed decision
  cannot approve a different Plan.

- **Gate config becomes part of the Relay's security floor**, beside the blast cap, as
  root-owned, file-only configuration. A misconfiguration can only make the system ask *less*
  often, never allow more — but asking less often is itself a regression, so the file's
  ownership and review matter.

- **The premium path's guarantee depends on a client we do not ship.** Nobody should mistake
  elicitation delivery for an end-to-end assurance Relay makes on its own. Relay's own
  guarantee is the out-of-band channel.

- **Approval is the third mechanism that must render a preflight** (the Policy preflight,
  the Console composer, the approval object). They share one rendering contract, or they
  drift — and a Plan that renders differently in the approval queue than at execution *is*
  the approval-view fidelity gap, reintroduced by us.
  *(Amended 2026-10-18 by ADR-0044: the Console has no approval queue or approval object. The
  renderings that must agree are the composer's Preflight, the Relay-authored rendering a
  decider is given — in the client's question, or on the Control API — and Job detail.)*

- **Testing the universal path needs no MCP client**: park a Job, POST a decision, watch it
  run. The elicitation envelopes need an elicitation-capable harness — someone else's
  roadmap — which is another reason the webhook is the required path and not the fallback.

## Amendment, 2026-08-14 — what [3/6] settled (#270)

Building the decision endpoint settled four questions this ADR left open. All four are
implemented, and each is a security boundary.

1. **The disjoint-approver credential question is answered with "no new credential."** A
   decision is an ordinary Account-authenticated `/api/v1` call. That already gives the
   property that matters — a credential the requesting session does not hold — and a
   per-approval credential would add a second issuance path to a control plane whose
   identity story is Accounts and their tokens. Revisit if pure-API shops have approvers who
   should hold no Relay Account at all; nothing here forecloses it.

2. **The role floor on a decision is the floor the Action needed to be requested.** Approving
   an Operation needs `operator`, approving a Raw Exec needs `admin` — the same
   `authz.RoleGate` table, not a second one. A lower floor would let an operator release an
   admin's Raw Exec, so ADR-0001's admin-only rule would hold for asking but not granting; a
   *higher* one would hard-code a policy that belongs in a rule's `audience`.

3. **Rung 2's human-only clause is enforced structurally, not by configuration.**
   `requester_allowed` cannot be the mechanism: that knob is the operator's, and a
   misconfigured `true` would hand an AI-agent its own approval. A machine Account is refused
   a decision on its own request under *any* configuration, in the domain type. The
   Account's kind travels on the authenticated Principal, so no surface supplies it, and an
   unknown kind is treated as a machine.

4. **Channel strength is checked, and set by the receiving surface.** A decision must arrive
   over a channel at least as strong as its rule demands. The Control API stamps
   `out-of-band` because of what it *is*; its request body has no channel field. The check
   applies to denials too — a denial is terminal, so a weak-channel deny would let a
   compromised harness end work it could not authorize.

Two smaller consequences. A park renders as **`202 Accepted`** with
`status: pending_approval` on the Control API — not `200` (nothing ran) and not an error
(nothing was denied). And the MCP surface's inability to accept a decision is a **build failure**, not a
convention (`relay/internal/controlplane/mcp/no_decision_test.go`), because "we just won't
call it from here" is the rule whoever later wires an approval tool will forget.

## Amendment, 2026-08-16 — what batch/window grants settled (#378)

Building decision 12's batch and window approvals settled five boundaries it did not state.

1. **A Scope is not a Match, and reusing one for the other inverts the mechanism.** A gate
   rule's `match` and a grant's `scope` look alike. They are duals:

   | | omitted field | fan-out field |
   |---|---|---|
   | `match` | matches anything → gates **more** — the *safe* direction | `min_fan_out` is a **floor** |
   | `scope` | covers anything → pre-approves **more** — the *unsafe* direction | `max_fan_out` is a **ceiling** |

   A `Scope` copied from a `Match` would turn "anything touching 10+ Nodes needs approval"
   into "anything touching 10+ Nodes is pre-approved". So a Scope is a separate type, every
   bound is mandatory, and validation refuses anything unbounded — an empty operation list
   covers **nothing**, never everything.

2. **Requesting a grant is not being granted one, and a grant is not a second approval
   path.** Creating one produces an ordinary approval Request whose subject is a Scope
   instead of a Plan, answered through the same decision endpoint. Quorum, audience,
   requester exclusion, the machine-self-decision rule and channel strength apply to a
   window exactly as to a single dispatch, because it is the same code. A separate path would
   have been a cheaper one, and the cheaper path is the one that gets used. *(Amended
   2026-09-24: exactly-as is now a floor, not an equality — a grant's issuance may never fall
   below second-person and `out-of-band`, whatever the gate derives.)*

3. **What a grant costs to approve is derived, never declared.** The Requirement is computed
   by evaluating the live gate at the Scope's *worst case*: the fan-out ceiling, every
   Operation in the allow-list, Raw Exec if opted in *(amended 2026-09-24: a Scope may no
   longer cover Raw Exec at all, so there is nothing to price)*, and every namespace a
   Selector could use when the Scope does not pin one — merged with the gate's strictest-wins
   rule for overlapping rules. If "mutate on 10+ Nodes needs two people" and a grant could
   release exactly that, the grant needs two people. A request body that named its own
   requirement could name a cheap one. A Scope over work nothing gates is refused: it would
   authorize nothing while sitting in the table with real reach, waiting to be widened by
   someone assuming it was there for a reason.

4. **The bound is enforced inside the claiming transaction, or it is not a bound.** A grant
   is found and consumed by one conditional `UPDATE ... WHERE uses < max_uses AND revoked_at
   IS NULL`. Separate find-and-increment steps would let two concurrent dispatches both see
   the last remaining use — a grant bounded at 20 releasing 21. The same query requires the
   authorizing Request to be `approved`, so a grant's window stays shut until a human opens
   it. Hard maxima (24h, 1000 uses) sit in code as well as in the request, because the
   difference between a batch approval and a standing grant is only ever a number somebody
   typed. *(Amended 2026-09-24: the window maximum is **4 hours**; the use limit is
   unchanged.)*

5. **The approval link is a column, because "what did that window release" is a query under
   time pressure.** Decision 11 requires "who asked / who approved / what happened" in one
   query; prose in `reason` can be read but not queried. Audit records carry `approval_id`
   (the authorizing Request, shared by every dispatch a grant releases — decision 12's "same
   approval ID" made literal) and `grant_id` (set only when a window released the work, so
   an auditor can tell "a human approved *this plan*" from "a human approved a window this
   plan fell inside"). A Grant has no `job_id`: it releases many Jobs, and the join runs from
   the trail.

Two smaller consequences. **Revocation** is a first-class act: a window is a period of
reduced friction, and against a compromised requester somebody must be able to close it
without the fleet-wide Freeze. It carries the role floor of approving the grant, is not
restricted to the original approver (during an incident the person at the keyboard is
whoever is there), and revoking twice is a truthful conflict, not a silent success. And a
grant's authorizing Request is never bound to a Job: `BindJob` models one approval releasing
one Job, so binding each covered Job in turn would leave the Request pointing at whichever
ran last.

**Still deferred from decision 12:** the *diff against the last approved similar action*. It
changes what an approver is shown, not what an approval covers, so it is tracked separately.

## Amendment (2026-09-15): gate rules are store-backed and Console-edited

The gate's decisions are unchanged: what it gates, the rungs, the channel rule, quorum,
audience, the requester exclusion, and the ceiling on any window. What changes is **where the
rules live**.

They were a root-owned JSON file loaded at startup. They are now runtime objects in the
Relay's store, edited by a human `admin` in the **Admin Console only**, with step-up
re-authentication, audited per rule with old and new values, taking effect on the next
dispatch. No MCP tool or Control API route writes them, and none may be added: an AI-agent
must never be able to edit the gate that gates it, and Console-only keeps every writer human,
since a machine Account cannot hold a Console session.

**The webhook stays root-owned**: its URL, secret file and timeout remain security floor.
Repointing the notification path sends every approval request elsewhere and leaves the
humans who should answer seeing nothing — a different class of act from tightening or
loosening a rule.

The reasoning, the tier split and the accepted residual risk — a compromised human Console
session can remove every gate — are in the ADR-0010 amendment of the same date and in
`docs/security/threat-model.md` **R15**. Behaviour is in `docs/specs/relay-configuration.md`;
this ADR remains authoritative for what a rule means.

## Amendment (2026-09-16): the shipped default gate is seeded into the store on first boot

Completes the 2026-09-15 amendment, which did not say how a fresh Relay gets any rules. Owner
decision, 2026-09-16.

- **A Relay whose store holds no gate rules at first start seeds the shipped default** —
  `read` ungated; `mutate` and Raw Exec at in-band confirmation (ADR-0029); second-person and
  out-of-band available to raise any rule to. The seed is one audited act attributed to the
  system, not to an Account.
- **After that the store is the only source.** No file is read, and the startup refusal for
  an unloadable gate file retires with the file. An `admin` who deletes every rule has done so
  in the Console with step-up and audit — the residual accepted as R15 — and the Relay does
  not re-seed on a later start.
- **Declined:** parking every mutation until an admin configures a rule (a fresh Relay could
  do nothing mutating without a Console visit), and a root-owned file that seeds the store
  (two sources for one setting).

Until store-backed rules are built, today's behaviour stands and `docs/specs/approval.md`
must describe it as current: an optional root-owned file, and **no gate at all** when none is
configured.

## Amendment (2026-09-16): grants pin no namespace; overlapping rules keep the audience union, as an accepted risk

Two owner decisions of the same date.

### Grants no longer pin a namespace

Decision 3's "every namespace a Selector could use **when the Scope does not pin one**" loses
its condition: a Scope has no namespace term (`docs/specs/approval.md`; #482). A grant is
always priced over every namespace. A stored grant that carried a pin releases nothing.

### Overlapping rules keep the union of their audiences — accepted, and tracked for improvement

When more than one rule matches a dispatch, or a grant's worst case, the combined Requirement
takes the strictest count, channel, requester exclusion and window, and the **union** of the
audiences; a rule that names no audience makes the result unrestricted. This is unchanged.
The security review of #482's change (#602) found what the union costs:

- With `{relay:… → [alice]}` and `{node:… → [bob]}`, a dispatch matching both may be approved
  by `bob` alone — so adding a `node:` term to a security-lane Selector reaches an approver
  the `relay:` rule did not name.
- A matching rule with no audience makes the combined audience unrestricted, so a broad rule
  silently lifts a narrower rule's restriction on every dispatch they both match.
- Without grant pinning, every grant is priced across all rules, so a grant's audience is
  always the union.

**Decided, 2026-09-16: keep the union for now.** Count, channel, requester exclusion and
window still tighten; only *who* may approve widens. Two better models were deferred, not
rejected: **intersecting** audiences and refusing a dispatch whose intersection is empty
(simple; refuses what disjoint overlapping rules both match), and a **per-rule quorum** in
which every matching rule's audience must be satisfied (most faithful to the rules; the queue
and the Console must track several groups). The choice is future work in
`docs/specs/approval.md`, and the residual is **R18** in `docs/security/threat-model.md`.

**Mitigation until then** is authoring: give a security-lane rule the widest match it needs,
and do not let a broader rule with a different or empty audience overlap it.

## Amendment (2026-09-20): amended by ADR-0038 and ADR-0029

Two amendments other ADRs made to this one, recorded here.

- **ADR-0038** (2026-09-12) reassigned the word **Plan** to an approved route of execution.
  Where this ADR says a Plan hash binds an approval, the hash binds the *rendered preflight*
  of the request being approved, and the "three mechanisms that must render" bullet under
  Consequences says *preflight*. The binding is unchanged.
- **ADR-0029** (2026-08-18) overtook decision 2's "held elicitation" envelope: an in-band
  decision travels through the tool surface (`approve_request`, and MRTR elicitation once
  built), not a held call. Decision 2's text stands as written; this note is its amendment.

## Amendment (2026-09-24): the three approval-grant bounds — 4 hours, never Raw Exec, second-person out-of-band

Owner decisions of **2026-09-14**, taken while working through `docs/specs/approval.md`, and
adopted here as decisions of this ADR: a bound whose only record is a spec's History line is a
bound nobody finds when they next widen the mechanism. Each tightens something the 2026-08-16
amendment settled.

- **An approval grant's window is capped at 4 hours.** This replaces the **24-hour** hard
  maximum in that amendment's decision 4. The use limit is unchanged, and so is the reasoning
  — "the difference between a batch approval and a standing grant is only ever a number
  somebody typed". Four hours keeps a grant inside one person's shift, so the human who
  opened a window is still there when it closes.

- **An approval grant never covers Raw Exec.** This removes "**Raw Exec if opted in**" from
  that amendment's decision 3, which priced a Raw Exec-bearing Scope at the `admin` floor and
  let it through. Pricing is not the control here. A grant hands the AI-agent its *choice* of
  covered work within the Scope (ADR-0029's client-integrity assumption compounds this), and
  Raw Exec's Scope is "an arbitrary command": there is no allow-list to enumerate and so
  nothing for an approver to have seen. Every Raw Exec needs its own decision, alone or inside
  one bulk act *(amended 2026-10-18 by ADR-0044: there is no bulk act — AP-59 is retired — so
  every Raw Exec needs its own decision)*. This is ADR-0001's conspicuous-exception rule
  holding for *granting* as well as asking, like the 2026-08-14 amendment's decision 2.

- **An approval grant is issued only by second-person, out-of-band approval.** This narrows
  that amendment's decision 2 ("apply to a window exactly as to a single dispatch, because it
  is the same code"). Exactly-as is now a floor, not an equality: whatever the live gate
  derives for the Scope, a grant's issuance may not fall below second-person and
  `out-of-band`. Deriving the requirement from the Scope's worst case (decision 3) stays, and
  can only make it *stricter*. The derivation alone is not enough because the gate's shipped
  default is self-confirmation in-band (the 2026-09-16 amendment), so a fresh Relay would issue
  standing authorization on one asserted answer from the requesting session. A grant converts
  a single approval into many dispatches; it is the last place to accept an assertion.

**Not changed:** the Scope's shape, its mandatory bounds, the claiming transaction,
revocation, the audit link, or the derivation rule. **Declined:** raising the *ordinary* gate
default to match — these bounds belong to the standing-authorization mechanism, not the
ladder, and conflating them would make every routine mutation as expensive as issuing a
window.

**Consequence.** Three bounds currently hold at different values or not at all: the cap is 24
hours, a Scope carries a Raw Exec opt-in that is accepted and priced at `admin`, and issuance
is priced by whatever the gate rules say — so a one-approval in-band grant is representable
today. `docs/specs/approval.md` states both sides: the built behaviour as current claims, and
these three as Designed at **v0.6.5**, citing this amendment. Until they land, the residual is
**R25** in `docs/security/threat-model.md`.

**Consumers updated on 2026-09-24:** **ADR-0038**, whose mandatory-window bullet cited the
24-hour ceiling, carries a dated note at that bullet; `docs/security/threat-model.md` is
corrected in the same change; `docs/specs/plan.md` already states the 4-hour figure as intent
(it is `aspirational`, so it adopts this amendment at its migration). `approval.md` carries
AP-56, AP-57 and AP-58.

## Amendment (2026-09-24): one answer path per origin — this ADR is amended by ADR-0040

> **Withdrawn in part, 2026-09-25.** ADR-0040's own amendment of that date withdrew strict
> separation before any of it was built. **This ADR's two paths stay side by side**, and both
> decide any parked request, whichever surface created it. What survives from the section
> below: MCP is the *approved* pathway for agent-originated approval and the Relay surfaces are
> not relied on; decision 2's endpoint is the guarantee of availability and — now — the
> working rescue; and decision 4's second-person-out-of-band default stays unused, because no
> shipped or seeded rule sets a second-person rung. The sequencing paragraph at the end no
> longer applies.

[ADR-0040](0040-the-surface-that-created-a-request-answers-it.md) narrows this ADR's posture
that a decision reaches Relay by two paths existing **side by side because they reach
different people**. Both paths still exist and work; what is removed is the freedom to answer
a request on the path that did not create it. **The surface that created a request is the
surface that answers it** — a request created over MCP is answerable only over MCP, and the
Console and Control API decide only what they themselves originated.

Two consequences, signposted in place above: decision 2's out-of-band envelope remains the
guarantee of the decision **endpoint's availability** and stops describing where an
agent-originated approval arrives; and decision 4's "default the second-person rung to
out-of-band" keeps its mechanism and loses its use, because no shipped or seeded rule sets a
second-person rung.

Nothing else moves. The gate's position, the ladder, the plan-hash binding, drift re-parking,
quorum, expiry, the attribution triple, approval grants and their bounds are unchanged, and an
approval is still never authorization. What ADR-0040 gives up — a Relay-verified approver in
the default path for agent work — it states plainly; the reasoning shelved with it is kept in
`docs/specs/approval-assurance.md`.

**The decision is explicitly interim**, pending the permissions rework, and it must not be
enforced before #646 lands: today a Gleipnir-parked request is answered by a human in the
Console, and closing that before the MRTR round trip exists would leave no answer path at all.

## Amendment (2026-09-28): the answer on a human's own OAuth session, cross-referenced from ADR-0029

A note, not a change to any decision here. Decision 5 — **MCP-originated calls are
agent-grade regardless of whose OAuth identity authorizes the session** — still governs rung
selection for every MCP *request*. The owner decided on 2026-09-28, recorded in ADR-0029's note
of that date, that an in-band MRTR *answer* arriving on an OAuth session of a human Account
counts as that human's own **verified** decision (`docs/specs/approval.md` AP-78 and AP-79,
designed and not built; Claude Code is the one client it applies to today). The request stays
agent-grade; the answer, given in the client's own UI which the model never sees, counts as
the human's. The caveat is accepted: a configured Claude Code hook can answer with no human
present, so the verified approver proves who owns the session, not that a human read the
question — the limit decision 5 names for session authorization, now accepted for one answer
path.

## Amendment (2026-09-29): the answer on a human's OAuth session is built, and keyed on identity

A note, not a change to any decision here; the 2026-09-28 note stands as the record of that
date. The answer path is now **built** (`docs/specs/approval.md` AP-78 and AP-79, PR #765).
By owner decision of 2026-09-29, recorded in ADR-0029's note of that date, it turns on the
signed-in identity rather than the client's declared name: any in-band MRTR answer on an OAuth
session of a human Account is that human's verified decision, whatever the client calls
itself, and a responder assertion on it is ignored. The declared name decides only whether
Relay asks. Decision 5 is untouched: every MCP *request* stays agent-grade. The caveats are
the same — a hook can answer with no human present, and anything holding the human's OAuth
token answers as that human — and OAuth has never run live against a real identity provider
(#351).

## Amendment (2026-10-18): amended by ADR-0044 — the Console does not decide approvals

[ADR-0044](0044-the-console-does-not-decide-approvals.md) removes the Admin Console's approval
surface — the queue, the approval object, the decide action under step-up, and the designed
bulk decisions — and keeps the Control API decision endpoint. Decision 2's out-of-band path,
"required, always available", is therefore the Control API's authenticated decision endpoint
and nothing else; an `out-of-band` rule is satisfied there only. Decision 5's note that the
Console's step-up apply *is* the self-confirmation rung is unchanged — that is execution, not
approval. Signposted in place above, dated. Every other decision here stands.
