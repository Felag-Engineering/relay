# Approval callout: notify via MCP, decide out-of-band

Some dispatches should not run on an AI-agent's say-so. This ADR decides how a human is
asked, how their answer gets back, and — the part that matters — why the answer is
trustworthy even when the harness that requested the action is not.

Grounding: `docs/research/mcp-approval-primitives.md` (what MCP does and does not give us)
and `docs/design/approval-and-attribution.md` (the identity and ladder model). Discharges
the research half of epic #210; #208 is the closed-loop shape this serves.

## The problem MCP does not solve for us

MCP has a directly relevant primitive. `elicitation/create` runs **server → client → human
→ client → server** and explicitly does not pass through the LLM; its
`accept`/`decline`/`cancel` maps 1:1 onto approve/deny/cancel. The Tasks extension lets a
long-running call return a handle the client polls, with an elicitation surfacing *during*
the wait — a near-exact fit for a parked Job.

It is still not a guarantee, for one structural reason:

> Elicitation and Tasks travel **over the MCP session, which is the AI's channel and the
> client's responsibility.** MCP's human-in-the-loop story is a *client-side convention*.

A naïve client can feed the approval to its model; a compromised one can auto-answer it.
The security literature already documents the attacks — approval fatigue, description
truncation, consent overload, and the "approval-view fidelity gap" where what the human
sees is not what executes. MCP also gives no **audience routing**: elicitation reaches
"the current user of the client," never "the on-call database team." And the roadmap will
not rescue this — human-in-the-loop and approvals are explicitly "on the horizon," not a
2026 priority.

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

Two properties fall out, and they are the whole point:

- **The proposing agent is structurally outside the trust path.** The decision lands on an
  authenticated Relay endpoint, riding a credential the requesting session does not hold.
  It works for harnesses with zero approval features, and for the API-control drive mode,
  which has no MCP session at all.
- **Relay authors the content.** Operation, arguments, resolved fan-out, per-Node plan
  verdicts, blast size, requester. The agent supplies none of the words the human reads,
  which is a direct structural answer to the approval-view-fidelity attacks.

## Decisions

1. **A gated Job parks.** The Job enters `pending-approval` — a Job-engine state, not a
   held connection — so the mechanism survives disconnects, restarts, and the 2026-07-28
   spec's removal of protocol sessions. A Job is already a durable handle; approval reuses
   that rather than inventing a second one.

2. **Three delivery envelopes, and we never hard-depend on any of them.**
   - **Held elicitation** — `elicitation/create` for short waits on elicitation-capable
     harnesses.
   - **MCP task handle + nested elicitation** — the premium path for long waits; the
     approval surfaces under `inputRequests` on `tasks/get`.
   - **Out-of-band webhook / link** — the universal path. Required, always available, and
     the only one that is a *guarantee* rather than a delivery convenience.

   The Tasks extension is still stabilizing (retry and expiry lifecycle gaps), so it is an
   optimization we adopt, never a dependency we assume. **A deployment with no
   elicitation-capable client loses convenience, not safety.**

3. **Delivery is not the decision.** Relay decides *whether* approval is required and
   *what the human sees*; the envelope only decides *how they are reached*. Conflating
   them is how the guarantee would quietly become the client's problem.

4. **Channel strength is per gate rule.**
   - `in-band` — the elicitation answer *is* the decision. Zero friction, and it trusts
     the harness, because the requesting harness holds that session's credential.
   - `out-of-band` — the decision must land on the authenticated decision endpoint,
     carrying a credential the agent session does not hold.

   The honest framing: in-band is *an assumption about the client*; out-of-band is
   *evidence*. Default the self-confirmation rung to in-band and the second-person rung to
   out-of-band; deployments move the dial in root-owned config.

5. **The confirmation ladder.** Gate rules select a rung:
   1. **No gate** — below thresholds, runs immediately.
   2. **Self-confirmation** — the requester sees the Relay-authored Plan and confirms.
      **Human requesters only**: an agent cannot confirm itself, so a machine requester's
      minimum gated rung is 3. The Console's step-up apply (ADR-0026) *is* this rung fused
      into the request surface, not a bypass of it.
   3. **Second-person** — audience excludes the requester (`requester_allowed: false`).

   Rung selection turns on a point worth stating outright: **MCP-originated calls are
   agent-grade regardless of whose OAuth identity authorizes the session.** Session
   authorization is not per-call human intent — the calls are still model-generated and
   the session is steerable by prompt injection in content the model read (#274, #283).
   The discriminating axis is how strongly the originating surface binds a human's intent
   to the individual action, not whether a human is nominally present.

6. **Gate config is root-owned Relay configuration, and narrows only.** It lives with the
   blast cap, above the AI's reach and outside the Control API (invariant 11). Grammar:

   ```
   match:       risk class · blast size · selector namespace · principal · operation
   requirement: count · audience · requester_allowed · channel · ttl
   ```

   Narrows-only means a gate rule can require approval where none was required; it can
   never grant an approval that Policy would refuse. **Approval is not authorization** —
   an approved Job still traverses Selector → Policy → blast cap unchanged. Node Policy
   remains the floor no human can lower over the wire (ADR-0002).

7. **Quorum: store the general shape, expose the narrow config.** The stored schema is
   **requirement vs. a set of decisions** from day one; v1 config exposes only
   `count: 1 | 2`, audience, and `requester_allowed`. N-of-M and richer matching then land
   as a config-language change with **no data migration** — the same discipline the Job
   engine's Stages used. Each decision is its own audit record (approver, timestamp,
   plan-hash, channel), and partial state (`1 of 2`) is visible in the queue, with the
   second approver able to see who already signed.

8. **Approvals bind to a content-addressed Plan, and drift re-parks.** The approval
   commits to a **plan-hash** over operation, arguments, and *resolved fan-out* — never to
   "the Job" in the abstract. If the Plan no longer matches at dispatch time, the Job
   **re-parks for re-approval** rather than running. This closes park-something-innocuous
   then-mutate-the-world, and it is the approval-flow analog of ADR-0011's
   verdicts-match-execution property.

9. **Everything expires.** Parked Jobs and approval validity both carry a TTL. An approval
   against plan-hash `abc123` is not redeemable indefinitely.

10. **The attribution triple, in two structurally distinct lanes.** Every gated dispatch
    records `requested_by` (**verified**), `on_behalf_of` (**asserted**), and
    `approved_by` (**verified**, with channel and plan-hash). The audit *schema* — not the
    renderer — keeps the lanes apart. A jailbroken agent can assert anything and forge
    nothing; blurring the lanes is how an audit trail becomes fiction. See CONTEXT.md,
    *Attribution*.

11. **The approval request and every decision are first-class audit records**, not log
    lines. "Who asked / for whom / who approved / what happened" must be answerable in one
    query.

12. **Batch and window approvals are first-class, because fatigue is a security
    property.** "The ops team is doing a bunch of work" must not mean forty elicitations.
    An approval may cover a **declared batch** of Jobs or a **scoped window** (`mutate`
    against `service=web`, next 2 hours, requested by `gleipnir-prod` for `ops-team`),
    with every covered Job auditing back to the same approval ID.

    Bounded in scope and time, this is a **time-boxed narrowing grant** — consistent with
    the deferred Grants rule that approvals narrow what is possible and never widen
    Policy. It is in the schema from the start rather than bolted on later, because a
    mechanism that produces forty prompts produces forty rubber stamps, and **a
    rubber-stamped approval is worse than no approval**: it manufactures evidence that a
    human considered something they did not. The approval object therefore also carries a
    **diff against the last approved similar action** ("same as Tuesday, except fan-out
    grew 3 → 12"), which is where fatigue is actually beaten.

13. **Naming: an MCP task handle is not a Relay Task.** MCP's "task" is a client-polled
    handle for one long-running `tools/call`; a Relay **Task** is one Operation executing
    on one Node. Always write "MCP task handle" in full. CONTEXT.md carries the
    disambiguation in this change.

### Informational: the Gleipnir-side rule

Gleipnir is a separate repo and this ADR does not bind it, but the contract only closes if
its client honours one rule:

> **Gleipnir's elicitation handler MUST be a deterministic path to the assigned human
> audience — never surfaced to the LLM, never auto-answered.**

That client-side rule is what upgrades MCP HITL from convention to guarantee for the
premium path. Relay's gate config defines *who may approve*; Gleipnir defines *how they
are reached* (#209). Relay never depends on it for correctness — the out-of-band channel
stands alone — but the premium path's security claim is Gleipnir's to keep.

## Alternatives considered

- **In-band elicitation only.** The simplest thing that could work, and the one every MCP
  example shows. Rejected as the *guarantee*: the approval would ride the same session as
  the request, so a compromised or naïve harness could answer on the human's behalf and we
  would have no way to tell. Kept as a delivery envelope, where its convenience is real
  and its weakness is bounded by the rung it is allowed to satisfy.

- **Wait for MCP to standardize approvals.** Tempting — a protocol-level primitive would
  be interoperable by construction. Rejected on evidence rather than taste: MCP's 2026
  priorities are Agent Communication, registry, and OAuth/enterprise auth; human-in-the-loop
  and action-approval are explicitly "on the horizon." Designing around a primitive that
  may not arrive, and would still be client-side when it did, is not a plan.

- **Approval as a Policy concept, enforced by the daemon.** Superficially attractive —
  Policy is already the un-evadable floor. Rejected: Policy is deliberately local,
  offline-evaluable, and has no notion of humans, sessions, or waiting. Teaching it to
  block on a remote human would put a network dependency inside the one component whose
  value is that it decides alone (ADR-0002). Approval is a Relay-side gate on *dispatch*;
  Policy remains the floor underneath it.

- **Relay pushes directly to Slack/PagerDuty/email.** Fewer moving parts for the common
  case. Rejected for v1: audience routing is inherently harness- and org-specific, and
  building a notification-integration surface into a security-critical control plane
  trades a large permanent maintenance and credential surface for convenience. The
  webhook plus a signed decision link lets someone else own that, and #277 is where
  integrations belong.

- **Per-approval short-lived credentials instead of Console step-up.** Deferred rather
  than rejected — it is the open question for pure-API shops with approvers who are not
  Console users. v1 answers with the authenticated decision endpoint and a signed link;
  the mechanism for a disjoint approver credential is left to the [3/6] issue.

## Consequences

- **The Job engine gains a state and the audit schema gains records.** `pending-approval`
  is a real state with a TTL and a re-park transition, not a flag; approval requests and
  decisions are audited objects. Both land in [2/6].

- **The out-of-band endpoint is a new authenticated surface on the Control API** ([3/6]),
  and it is high-value: forging a decision is forging an approval. It is Account-authenticated
  like every other `/api/v1` route, and every decision is bound to a plan-hash, so a
  replayed decision cannot approve a different Plan.

- **Gate config becomes part of the Relay's security floor.** It joins the blast cap as
  root-owned, file-only configuration. An operator who misconfigures it can only make the
  system ask *less* often, never allow more — but "asks less often" is itself a security
  regression, so the file's ownership and review matter.

- **The premium path's guarantee depends on a client we do not ship.** Stated plainly here
  so nobody later mistakes elicitation delivery for an end-to-end assurance Relay can make
  on its own. Relay's own guarantee is the out-of-band channel.

- **Approval is now the third mechanism that must render a Plan** (plan mode, the Console
  composer, the approval object). They share one rendering contract, or they will drift —
  and a Plan that renders differently in the approval queue than at execution *is* the
  approval-view fidelity gap, reintroduced by us.

- **Testing the universal path needs no MCP client at all**: park a Job, POST a decision,
  watch it run. The elicitation envelopes need an elicitation-capable harness, which is a
  dependency on someone else's roadmap — another reason the webhook is the required path
  and not the fallback.

## Amendment, 2026-08-14 — what [3/6] settled (#270)

Building the decision endpoint forced four questions this ADR left open or implicit. All
four are implemented; they are recorded here because each is a security boundary someone
will otherwise re-litigate from the code.

1. **The disjoint-approver credential question is answered with "no new credential."**
   The alternatives section left "per-approval short-lived credentials" deferred to this
   issue. v1's answer is that a decision is an ordinary Account-authenticated `/api/v1`
   call. That already satisfies the property that matters — the credential is one the
   requesting session does not hold — and a bespoke per-approval credential would add a
   second issuance path to a control plane whose whole identity story is Accounts and
   their tokens. Revisit if pure-API shops turn out to have approvers who should hold no
   Relay Account at all; nothing here forecloses it.

2. **The role floor on a decision is the floor the Action needed to be requested.**
   Decision 6 says approval narrows only, and this is what that means for the ladder:
   approving an Operation needs `operator`, approving a Raw Exec needs `admin` — the same
   `authz.RoleGate` table, not a second one. A lower floor would have let an operator
   release an admin's Raw Exec, so ADR-0001's admin-only rule would hold for asking and
   not for granting; a *higher* one would have hard-coded a policy that belongs in a
   rule's `audience`.

3. **Rung 2's human-only clause is enforced structurally, not by configuration.** Decision
   5 states it; `requester_allowed` cannot be the mechanism, because that knob is the
   operator's and a misconfigured `true` would hand an AI-agent its own approval. A machine
   Account is therefore refused a decision on its own request under *any* configuration,
   in the domain type. The Account's kind travels on the authenticated Principal, so no
   surface supplies it, and an unknown kind is treated as a machine.

4. **Channel strength is checked, and it is set by the receiving surface.** Decision 4
   defined the two channels but nothing enforced them. A decision must now arrive over a
   channel at least as strong as its rule demands; the Control API stamps `out-of-band`
   because of what it *is*, and its request body has no channel field at all. The check
   applies to denials as well as approvals — a denial is terminal, so a weak-channel deny
   would let a compromised harness end work it could not authorize.

Two smaller consequences worth naming: a park renders as **`202 Accepted`** with
`status: pending_approval` on the Control API — not a `200` (nothing ran) and not an error
(nothing was denied), per this ADR's "accepted, pending approval"; and the MCP surface's
inability to accept a decision is a **build failure**, not a convention
(`mcp/no_decision_test.go`), because "we just won't call it from here" is exactly the kind
of rule that gets forgotten by whoever later wires an approval tool to close a loop.
