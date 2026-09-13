# Approval

**Status:** current as of `2026-09-11`.

## Purpose

Approval is the capability that puts a human decision between a request and its execution, for
the work an operator has decided is too consequential to run on an agent's say-so alone.

It exists because the rest of Relay's guardrails answer *"may this caller do this?"* and none of
them answers *"should this particular thing happen right now?"* A Grant, a Policy rule and a
blast cap are all standing judgements made in advance. Approval is the one control that reaches
a person at the moment of the act.

Its second job is to stay useful under load. A gate that asks too often trains people to
approve without reading, and an approval mechanism nobody reads is worse than none — it
launders an agent's intent through a human who did not exercise judgement. Batch and window
grants, the shape key, and the anti-fatigue diff all exist for that reason.

## Surfaces

| Surface | How it is reached |
|---|---|
| **MCP** | `approve_request` — an ordinary tool call carrying the request ID, the plan hash being answered, the verdict, an asserted approver identity, and an optional reason. Registered only when a decider is configured (ADR-0029). |
| **Control API** | `GET /api/v1/approvals`, `GET /api/v1/approvals/{id}`, `POST /api/v1/approvals/{id}/decision`; grant management under `/api/v1/approval-grants`. |
| **Admin Console** | The approval queue — triage, the request detail, and the anti-fatigue diff against the last approval of the same shape. Deciding from the Console is v0.7.0 (#435) and **not built**. |

Deliberately **not** a surface: MCP elicitation. Delivery envelopes come and go with protocol
revisions; a tool call is the one surface every MCP client has had since 2024-11-05 (ADR-0029).

**This is the one capability where the surfaces genuinely differ**, and the difference is the
point rather than an inconsistency. A decision's *channel* is set by the surface that receives
it, not by the caller — see *Channel strength* below.

## Behaviour

### Where the gate sits

The approval gate runs inside the dispatch pipeline, after Selector resolution, authorization
and the blast-radius cap, and before any Task exists. `execution.md` owns that position and the
reasoning for it; this spec owns everything the gate then does.

Two consequences follow from the position and both are load-bearing. The approver is shown the
**resolved** fan-out, because resolution has already happened — an approval that did not know
how many Nodes it covered would be a fidelity gap by construction. And a park leaves **no Job
and no Pending Tasks** behind, because the dispatcher has not been reached.

### The confirmation ladder

A gate rule selects a rung:

1. **No gate** — below thresholds; runs immediately.
2. **Self-confirmation** — the requester sees the Relay-authored Plan and confirms. **Human
   requesters only.** A machine Account can never satisfy its own gate, so a machine
   requester's minimum gated rung is 3.
3. **Second-person** — the audience excludes the requester.

Rung selection turns on a point the ADR states outright: **MCP-originated calls are agent-grade
regardless of whose OAuth identity authorizes the session.** Session authorization is not
per-call human intent — the calls are still model-generated, and the session is steerable by
prompt injection in content the model read. The discriminating axis is how strongly the
originating surface binds a human's intent to the individual action, not whether a human is
nominally present.

### Channel strength

A decision carries a channel, and **the receiving surface sets it** — never the caller:

- **`in-band`** — the tool-call answer *is* the decision. Zero friction, and it trusts the
  harness, because the requesting harness holds that session's credential.
- **`out-of-band`** — the decision must land on the authenticated decision endpoint, carrying a
  credential the agent session does not hold.

The honest framing, and the reason both exist: **in-band is an assumption about the client;
out-of-band is evidence.** A rule demanding out-of-band is not satisfied by an in-band answer,
and an asserted approver identity does not upgrade one. A stronger channel satisfies a weaker
rule; the reverse is refused. An unstated channel defaults to out-of-band.

### What an approval commits to

An approval binds to a **plan hash** — a content address over the Plan's ordered steps, their
Operations and arguments, and the *resolved fan-out* — never to "the Job" in the abstract. If the
Plan no longer matches at dispatch time, it **re-parks for re-approval** rather than running. That
closes park-something-innocuous-then-mutate-the-world.

A single gated dispatch is the **one-step** case of that, which is how it was first built and
still how it behaves. Since ADR-0038 a Plan may carry several steps, and then the hash covers the
whole route *and* the resolved set — **the binding is by identity, never by count.** Every step
re-resolves, and any Node not in the approved set re-parks; a Node that has *left* the set is
shrinkage rather than drift, dropped from that step and recorded. A ceiling would bind a number
and no identity, which is what a compromised Node forging its own `node:` labels (invariant 7)
would need in order to elect itself into a route approved for other hosts. `plan.md` owns the
route, the cursor and the lifecycle; this spec owns the decision that releases it.

The **shape key** is a different address and must not be confused with it: it addresses *what*
an approval is for, deliberately excluding the resolved fan-out, so that the queue can answer
"what did I approve last time that looked like this?" as a lookup. It powers the anti-fatigue
diff — *"same as Tuesday, except the fan-out grew 1,180 → 2,214"*.

**The shape key is never an authorization or release lookup.** A dispatch proceeds on a matching
plan hash, or on a claimed Grant whose Scope covers it, and on nothing else. A release path that
consulted the shape key would be an approval-gate bypass. An advance of an approved Plan proceeds
on that Plan's hash and its cursor — the same rule, not a third release path. **A Grant does not
cover a route**: a Grant is described and a Plan is enumerated, and letting the first release the
second would amplify a Grant's use limit N-fold while ensuring no human ever saw the route
(`plan.md`).

### Deciding

A decision is refused unless all of these hold: the request is pending and unexpired; the
decider is in the required audience; the decider is not the requester when the rule excludes
them; the decider has not already decided this request; the cited plan hash matches; the channel
is at least as strong as the rule demands; and the decider clears the **role floor** — which is
the floor the *Action* needed in order to be requested, not a separate approval role. An
`operator` cannot release a Raw Exec.

**A machine Account may never decide its own request.** The one relaxation is ADR-0029's: an
in-band answer carrying an asserted approver identity, which records what the client claims
without pretending Relay verified it.

**Deny is terminal and beats approval.** A denied request cannot be revived by a later approval,
and a denial is audited as fully as a release.

### Batch and window grants

A Grant is standing authorization over a bounded **Scope** — an Account, a risk class, an
Operation allow-list, a fan-out ceiling, a time window, and optionally a pinned Selector
namespace. It exists because approval fatigue is a security failure, not a UX complaint.

Four rules govern it, and each closes a way the mechanism could invert:

- **A Scope is not a Match.** A gate rule's `Match` says *when approval is required*; a Grant's
  Scope says *what standing authorization covers*. Reusing one for the other inverts the
  mechanism.
- **Requesting a grant is not being granted one.** The request for a Grant is itself approved
  through this same gate, at a Requirement derived from the Scope's worst case.
- **What a grant costs is derived, never declared.** The Requirement comes from evaluating the
  live gate at the Scope's widest admissible dispatch — never from anything the requester says.
  A multi-step **Plan** is priced the same way and for the same reason: the gate is evaluated
  against every step **at the approved resolved set**, and the strictest requirement any step
  triggers governs the whole route — so one Raw Exec step prices the entire Plan at Raw Exec's
  floor (ADR-0038). Naming the fan-out is part of the rule, not a detail: a route priced at a
  smaller proposal-time count than it is permitted to reach would be this same rule failing by
  omission.
- **The bound is enforced inside the claiming transaction**, or it is not a bound.

A Grant is consulted **only after** the gate has decided approval is required — never as a way
to skip the gate — and it **never bypasses the blast cap**. An exhausted, revoked, or expired
Grant covers nothing and the dispatch parks again. Everything expires: a Grant's window is
capped at 24 hours.

### Attribution

Every gated dispatch records three things in two structurally distinct lanes:

| Field | Lane |
|---|---|
| `requested_by` | **verified** — the Account whose credential made the call |
| `on_behalf_of` | **asserted** — whatever the client said, bounded and stored verbatim |
| `approved_by` | **verified**, with channel and plan hash |

The audit **schema** keeps the lanes apart, not the renderer. A jailbroken agent can assert
anything and forge nothing. An auditor can always separate *"a human authenticated to Relay and
approved this"* from *"a client told us a human approved this"* — and collapsing that
distinction would buy simplicity by making the trail claim more than Relay knows.

## Refusals

A park is **not** a refusal: nothing was denied and nothing ran. It is audited under its own
kind, distinguishing a newly created request from a re-drive bouncing off one already pending,
so the trail's count of asks stays truthful while polling stays visible.

| Refusal | Cause |
|---|---|
| Not pending / not found | The request is terminal, expired, or unknown |
| Requester excluded | The rule demands a second person |
| Not in audience | The decider is outside the audience the rule requires |
| Duplicate decider | This Account has already decided this request |
| Plan changed | The cited plan hash is not the request's |
| Weak channel | The decision's channel is weaker than the rule demands — enforced for denials too |
| Machine self-decision | A machine Account deciding its own request |
| Role floor | The decider is below the floor the Action needed to be requested |
| Grant covers nothing gated | A Scope over work that requires no approval would authorize nothing |
| Grant unbounded | Every Scope bound is required; there are no open-ended windows |
| Approvals unavailable | No gate is configured on this Relay |

## Governing ADRs and invariants

- **ADR-0027** — the callout, the ladder, channel strength, plan-hash binding, expiry, the
  attribution triple, and batch/window grants.
- **ADR-0029** — in-band approval as a tool call rather than elicitation, and the asserted
  approver.
- **Invariant 3** (deny-beats-allow) — a denial is terminal and a stricter rule wins a merge.
- **Invariant 5** — a Grant releases an approval requirement, never the blast cap.
- **Invariant 7** — only `relay:` is a security-lane target, which is what makes a
  namespace-pinned Scope security-relevant.
- **Invariant 10** — the decision path is the capability layer's; a surface records a channel
  and renders a queue, and decides nothing.
- **Invariant 11** — gate configuration is root-owned Relay configuration, unreachable from any
  API, and it **narrows only**.

## Seams and proof

Gate configuration is loaded once at startup from a root-owned file. The approval domain
(`relay/internal/approval`) holds the gate, the grant, the plan hash and the shape key, and its
imports are pinned narrow by test. The capability layer owns parking, deciding and claiming; the
surfaces hold neither.

### What proves each claim

| Behaviour | Proven by | Seam |
|---|---|---|
| A gated dispatch parks and sends nothing | `TestGatedDispatchParksAndSendsNothing` | capability |
| An ungated dispatch is untouched | `TestUngatedDispatchIsUntouched` | capability |
| Reads are not gated by a mutate rule | `TestApprovalCallout_ReadsAreNotGatedByAMutateRule` | e2e |
| Park → decide → run, end to end | `TestApprovalCallout_ParkDecideRun` | e2e |
| An approved Plan dispatches and binds the Job | `TestApprovedPlanDispatchesAndBindsTheJob` | capability |
| A machine cannot satisfy its own gate | `TestApprovalCallout_MachineCannotSatisfyItsOwnGate` | e2e |
| An `operator` cannot release a Raw Exec | `TestApprovalCallout_OperatorCannotReleaseARawExec` | e2e |
| The role floor is the parked Action's floor | `TestDecisionRoleFloorUsesTheParkedActionKind` | capability |
| A refusal by role floor records nothing | `TestDecisionRefusedByRoleFloorRecordsNothing` | capability |
| A decision must cite the request's plan hash | `TestDecisionMustCiteTheRequestsPlanHash` | capability |
| Same shape, different Plan, still parks | `TestSameShapeDifferentPlanStillParks` | capability |
| The shape key is stable across runs | `TestShapeKeyIsStableAcrossRuns` | approval |
| A weak channel is refused — and for denials too | `TestWeakChannelIsRefused`, `TestWeakChannelIsRefusedForDenialsToo` | approval |
| A stronger channel satisfies a weaker rule | `TestStrongChannelSatisfiesAWeakerRule` | approval |
| An unstated channel defaults to out-of-band | `TestUnstatedChannelDefaultsToOutOfBand` | approval |
| An asserted approver does not weaken an out-of-band rule | `TestAssertedApproverDoesNotWeakenAnOutOfBandRule` | approval |
| The audience is enforced | `TestAudienceIsEnforced` | approval |
| Deny is terminal and beats approval | `TestDenyIsTerminalAndBeatsApproval`, `TestDenialIsTerminalAndAudited` | approval |
| An expired request is neither decidable nor satisfiable | `TestExpiredRequestIsNotDecidableOrSatisfiable` | approval |
| Deciding does not itself dispatch | `TestDecideApprovalDoesNotDispatch` | capability |
| The audit entry carries the answer and the channel | `TestDecideApprovalAuditEntryCarriesTheAnswerAndChannel` | capability |
| A Grant is consulted only after the gate | `TestGrantIsConsultedOnlyAfterTheGate` | capability |
| A Grant never bypasses the blast cap | `TestGrantNeverBypassesTheBlastCap` | capability |
| A Grant does not cover outside its Scope | `TestGrantDoesNotCoverOutsideItsScope` | approval |
| Exhausted, revoked and uncovered all park again | `TestExhaustedGrantParksAgain`, `TestRevokedGrantCoversNothing`, `TestUncoveredDispatchStillParks` | approval |
| A grant's cost is derived at the strictest rule | `TestRequestGrantDerivesTheStrictestRequirement` | capability |
| Unbounded Scopes are refused | `TestRequestGrantRefusesUnboundedScopes`, `TestEveryScopeBoundIsRequired` | approval |
| A Scope over ungated work is refused | `TestRequestGrantRefusesWhenNothingIsGated` | capability |
| A requester cannot approve their own window | `TestApprovalGrant_RequesterCannotApproveTheirOwnWindow` | e2e |
| Revoking closes the window immediately | `TestApprovalGrant_RevokeClosesTheWindowImmediately` | e2e |
| Gate config narrows only; an unsatisfiable rule is refused at load | `TestUnsatisfiableRuleIsRejectedAtLoad`, `TestEmptyGateGatesNothing` | approval |
| The approval domain's imports stay narrow | `TestApprovalImportsStayNarrow` | compile-time |

Claims above with **no row**, and so nothing checking them:

- That `RequirementForScope` prices a **namespace-pinned** Scope correctly. It has no unit test
  at all, and #482 is the open defect: a pinned Scope is priced over only the pinned namespace
  while coverage is by containment, so a Grant approved under a weaker rule can release work
  that needed a stronger one.
- That a decision's channel is set by the receiving surface rather than the caller. The channel
  *values* are well covered; which side chooses them is not.

### Performance

| Characteristic | Contract | Measured by |
|---|---|---|
| Grant window | Bounded, 24 hours maximum; every Scope bound required | *(none)* |
| Approval queue | Paged; the anti-fatigue diff is one shape-key lookup, never a scan | *(none)* |
| Parked requests | Expire on a TTL and are swept | *(none)* |

There are no benchmarks in this repository. The shape key exists specifically so the queue's
diff is a lookup rather than a scan, and nothing measures that it stays one.

## Out of scope

- **Where the gate sits in the dispatch pipeline, and what a park leaves behind** —
  `execution.md`.
- **The Plan a decision releases** — `plan.md`: the ordered steps, the cursor, the payload-free
  advance, and the walls on an approved-but-incomplete route. A Plan parks through *this* gate and
  is answered by an ordinary Approval, exactly as a request for an Approval grant is; it is
  deliberately not a second decision surface.
- **Policy** — a Node's own engine decides what may run; approval decides whether a caller may
  ask. They are unrelated mechanisms and neither substitutes for the other.
- **Grants (authorization)** — the Relay-side rule for which Account may request which
  Operations. Unrelated to an **approval grant** despite the name; see `GLOSSARY.md`, and
  `accounts-and-access.md` when it exists.
- **The Freeze** — a global stop, not a per-request judgement (`freeze.md`).
- **Notification delivery** — the Relay notifies, and never depends on delivery for
  correctness. A decision lands on a surface regardless of whether any notice arrived.
- **Querying the approval audit trail after the fact** — `audit-and-read-lane.md`.

## Open questions

- **#482 — a namespace-pinned Grant can release work that needed more approvals.** Open, with
  an implementation plan attached. Its fix changes what a pinned Scope costs and requires an
  ADR-0027 amendment; it also revealed that the issue's own suggested fix would widen coverage,
  because a match-everything Selector reports an empty namespace list and the empty set is a
  subset of anything.
- **Deciding from the Console is unbuilt** (#435). Until it lands, the Console renders the queue
  and the diff, and a decision must be made through MCP or the Control API.
- **Is the in-band relaxation the right shape?** ADR-0029 permits a machine Account to record a
  decision when it carries an asserted approver. That is honest — the assertion is stored as an
  assertion — but it means the weakest rung's audit value rests entirely on client goodwill.
  ADR-0029 accepted this deliberately; it is worth revisiting if in-band ever becomes the
  default for anything above self-confirmation.

## History

- `2026-09-12` — ADR-0038: the plan hash generalised from one Operation to a route, the derived
  requirement extended to a multi-step Plan, and `plan.md` named as the route's owner. No
  behaviour here changed; a single gated dispatch is the one-step case.
- `2026-09-11` — First written, from ADR-0027, ADR-0029 and the approval domain as it stands.
  Written because a dev-loop architect planning #482 reported the governing spec missing.
