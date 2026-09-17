# Approval

**Status:** aspirational — worked through with the owner on `2026-09-14`, awaiting their review
of this draft. Describes intended behaviour, not the code (see the establishing phase in
`README.md`).

## Purpose

Approval is the capability that puts a human decision between a request and its execution, for
the work an operator has decided is too consequential to run on an AI-agent's say-so alone.

It exists because the rest of Relay's guardrails answer *"may this caller do this?"* and none of
them answers *"should this particular thing happen right now?"* A Grant, a Policy rule and a
blast cap are all standing judgements made in advance. Approval is the one control that reaches
a person at the moment of the act.

Its second job is to stay useful under load. A gate that asks too often trains people to
approve without reading, and an approval mechanism nobody reads is worse than none — it
launders an AI-agent's intent through a human who did not exercise judgement. Plans, narrow
approval grants, the shape key and the anti-fatigue diff all exist for that reason.

## Surfaces

| Surface | How it is reached |
|---|---|
| **MCP** | `approve_request` — an ordinary tool call carrying the request ID, the plan hash being answered, the verdict, an asserted approver identity, and an optional reason. This is the in-band path the shipped defaults rely on (ADR-0029). |
| **Control API** | `GET /api/v1/approvals`, `GET /api/v1/approvals/{id}`, `POST /api/v1/approvals/{id}/decision` — the out-of-band decision endpoint; grant management under `/api/v1/approval-grants`. |
| **Admin Console** | The approval queue — triage, the request detail, the anti-fatigue diff against the last approval of the same shape, and deciding from the Console (#435). |

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

### Gate rules, and what ships

Gate rules live in a root-owned file loaded at Relay startup. No API can write them, and they
**narrow only** (invariant 11): a rule can require approval, never waive a guardrail. Operators
loosen or tighten what is gated by editing that file.

**Relay ships a default gate-rule file**, so a fresh install is gated out of the box:

| Request | Shipped requirement |
|---|---|
| `read`, any surface | No gate |
| `mutate`, any surface | In-band confirmation |
| Raw Exec, any surface | In-band confirmation |

Second-person audiences and out-of-band channel requirements remain fully supported; an operator
who wants them configures them in the same file. The shipped file simply does not demand them.

**A gate-rule file that cannot be loaded refuses Relay startup.** The Relay never runs with
nothing gated because a file is missing, unreadable or malformed — a silent ungated start is the
exact failure the shipped default exists to prevent. Startup refusal is `relay-configuration.md`.

### The confirmation ladder

A gate rule selects a rung:

1. **No gate** — below thresholds; runs immediately.
2. **Confirmation** — the request is confirmed by the requester's side. For a human on the Control
   API or Console, that is the requester reviewing the Relay-authored Plan and confirming. For an
   MCP request, it is an **in-band** answer carrying the client's asserted approver, recorded as an
   assertion (ADR-0029).
3. **Second-person** — the audience excludes the requester.

Rung selection turns on a point ADR-0027 states outright: **MCP-originated calls are agent-grade
regardless of whose OAuth identity authorizes the session.** Session authorization is not
per-call human intent — the calls are still model-generated, and the session is steerable by
prompt injection in content the model read.

**How that reads under the shipped defaults, stated plainly.** A machine Account cannot decide its
own request *on its own authority*. The one relaxation is ADR-0029's: an in-band answer carrying an
asserted approver identity is accepted as confirmation, recording what the client claims without
pretending Relay verified it. The shipped defaults make that relaxation the default path for MCP
mutations — so rung 2 for an agent-grade request rests on the client, and an operator who needs
evidence rather than an assertion raises the rule to second-person or out-of-band. See *Accepted
residual risk*.

### Channel strength

A decision carries a channel, and **the receiving surface sets it** — never the caller:

- **`in-band`** — the tool-call answer *is* the decision. Zero friction, and it trusts the
  harness, because the requesting harness holds that session's credential.
- **`out-of-band`** — the decision must land on the authenticated decision endpoint, carrying a
  credential the AI-agent session does not hold.

The honest framing, and the reason both exist: **in-band is an assumption about the client;
out-of-band is evidence.** A rule demanding out-of-band is not satisfied by an in-band answer,
and an asserted approver identity does not upgrade one. A stronger channel satisfies a weaker
rule; the reverse is refused. A rule that states no channel defaults to out-of-band; the shipped
file states in-band explicitly.

### What an approval commits to

An approval binds to a **plan hash** — a content address over the Plan's ordered steps, their
Operations and arguments, and the *resolved fan-out* — never to "the Job" in the abstract. If the
Plan no longer matches at dispatch time, it **re-parks for re-approval** rather than running. That
closes park-something-innocuous-then-mutate-the-world.

A single gated dispatch is the **one-step** case of that. A Plan may carry several steps, and then
the hash covers the whole route *and* the resolved set — **the binding is by identity, never by
count.** Every step re-resolves, and any Node not in the approved set re-parks; a Node that has
*left* the set is shrinkage rather than drift, dropped from that step and recorded. A ceiling would
bind a number and no identity, which is what a compromised Node forging its own `node:` labels
(invariant 7) would need in order to elect itself into a route approved for other hosts.
**A Plan's approval releases its route as context, not its mutations.** Approving a Plan approves
its steps, their order and its Node; `read` steps then advance on that approval alone, but **each
`mutate` step parks at advance for its own approval, bound to the Plan hash and that step**. The
step decision is made against the route the approver already saw, and a stolen proposer credential
can run no mutation a human did not release at that step. `plan.md` owns the route, the cursor and
the lifecycle; this spec owns the decisions that release it.

The **shape key** is a different address and must not be confused with it: it addresses *what*
an approval is for, deliberately excluding the resolved fan-out, so that the queue can answer
"what did I approve last time that looked like this?" as a lookup. It powers the anti-fatigue
diff — *"same as Tuesday, except the fan-out grew 1,180 → 2,214"*.

**The shape key is never an authorization or release lookup.** A dispatch proceeds on a matching
plan hash, or on a claimed approval grant whose Scope covers it, and on nothing else. A release
path that consulted the shape key would be an approval-gate bypass. An advance of an approved Plan
proceeds on that Plan's hash and its cursor — and, for a `mutate` step, on that step's own
approval — the same rule, not a third release path. **An
approval grant does not cover a route**: a grant is described and a Plan is enumerated, and letting
the first release the second would amplify a grant's use limit N-fold while ensuring no human ever
saw the route (`plan.md`).

### Pending requests expire

A parked request expires after an operator-set time — **default 1 hour** — and is swept. An
expired request can be neither decided nor satisfied; the work must be requested again, and the new
request is shown to its approver afresh.

### Deciding

A decision is refused unless all of these hold: the request is pending and unexpired; the
decider is in the required audience; the decider is not the requester when the rule excludes
them; the decider has not already decided this request; the cited plan hash matches; the channel
is at least as strong as the rule demands; and the decider clears the **role floor** — which is
the floor the *Action* needed in order to be requested, not a separate approval role. An
`operator` cannot release a Raw Exec.

**Deny is terminal and beats approval.** A denied request cannot be revived by a later approval,
and a denial is audited as fully as a release.

Deciding does not itself dispatch; a released request proceeds through the dispatch pipeline.

### Plans first; approval grants as the narrow exception

**Plans are the default tool for work that can be enumerated in advance** — the human sees every
step and the exact Nodes, and nothing runs that was not shown (`plan.md`).

An **approval grant** is standing authorization over a bounded **Scope**, for open-ended work that
cannot be enumerated — *"keep restarting whatever falls over on the web tier for the next hour."*
It exists because approval fatigue is a security failure, not a UX complaint: without it, that
work becomes a stream of single approvals that invites rubber-stamping or loosened gate files. It
is deliberately small and conspicuous.

A Scope is: **exactly one Account**, a risk class, an Operation allow-list, a fan-out ceiling, and
a time window. The first-pass limits:

- **Never covers Raw Exec.** Raw Exec is always decided request by request.
- **Window capped at 4 hours.** Everything expires.
- **Issued only by second-person, out-of-band approval** — never self-confirmed and never in-band,
  whatever the shipped defaults allow for ordinary requests.
- **No Selector-namespace pinning.** A Scope does not narrow by label namespace.

Four rules govern it, and each closes a way the mechanism could invert:

- **A Scope is not a Match.** A gate rule's `Match` says *when approval is required*; a grant's
  Scope says *what standing authorization covers*. Reusing one for the other inverts the
  mechanism.
- **Requesting a grant is not being granted one.** The request for a grant is itself approved
  through this same gate, at a requirement derived from the Scope's worst case — and never below
  second-person, out-of-band.
- **What a grant costs is derived, never declared.** The requirement comes from evaluating the
  live gate at the Scope's widest admissible dispatch — never from anything the requester says.
  A multi-step **Plan** is priced the same way and for the same reason: the gate is evaluated
  against every step **at the approved resolved set**, and the strictest requirement any step
  triggers governs the whole route — so one Raw Exec step prices the entire Plan at Raw Exec's
  floor (ADR-0038). Each `mutate` step's own approval at advance is priced by that step.
- **The bound is enforced inside the claiming transaction**, or it is not a bound.

A grant is consulted **only after** the gate has decided approval is required — never as a way
to skip the gate — and it **never bypasses the blast cap**. An exhausted, revoked, or expired
grant covers nothing and the dispatch parks again. A Scope over work that needs no approval is
refused, because it would authorize nothing.

### Notification

When a request parks, Relay notifies (the webhook callout, ADR-0027). Delivery is best-effort and
**correctness never depends on it**: a decision lands on a surface whether or not any notice
arrived.

### Attribution

Every gated dispatch records three things in two structurally distinct lanes:

| Field | Lane |
|---|---|
| `requested_by` | **verified** — the Account whose credential made the call |
| `on_behalf_of` | **asserted** — whatever the client said, bounded and stored verbatim |
| `approved_by` | **verified**, with channel and plan hash — or, for an in-band confirmation, the **asserted** approver, stored as an assertion |

The audit **schema** keeps the lanes apart, not the renderer. A jailbroken AI-agent can assert
anything and forge nothing. An auditor can always separate *"a human authenticated to Relay and
approved this"* from *"a client told us a human approved this"* — and collapsing that
distinction would buy simplicity by making the trail claim more than Relay knows. Under the shipped
defaults, most MCP approvals are the second kind, and the trail says so.

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
| Machine self-decision | A machine Account deciding its own request without the in-band asserted-approver form, or at a rung above confirmation |
| Role floor | The decider is below the floor the Action needed to be requested |
| Grant covers nothing gated | A Scope over work that requires no approval would authorize nothing |
| Grant unbounded | Every Scope bound is required; there are no open-ended windows |
| Grant over Raw Exec | A Scope may never cover Raw Exec |
| Grant window too long | A Scope's window exceeds 4 hours |
| Grant issued on a weak rung | A grant approved other than by second-person, out-of-band |
| Grant pinned to a namespace | Namespace pinning is not part of a Scope |
| Approvals unavailable | No gate file could be loaded — the Relay refuses to start rather than run ungated by accident (`relay-configuration.md`) |

## Governing ADRs and invariants

- **ADR-0027 — needs amending.** The callout, the ladder, channel strength, plan-hash binding,
  expiry, the attribution triple, and approval grants remain its decisions. Amendments: a shipped
  default gate file; grants lose namespace pinning, cap their window at 4 hours, exclude Raw Exec,
  and are issued only second-person out-of-band; pending-request expiry defaults to 1 hour.
- **ADR-0029** — in-band approval as a tool call rather than elicitation, and the asserted
  approver. Now the default path for MCP mutations under the shipped file, which is the case its
  own text flagged as worth revisiting; the owner accepted it knowingly.
- **ADR-0038** — the plan hash covers a route; the derived requirement is priced over every step.
- **Invariant 3** (deny-beats-allow) — a denial is terminal and a stricter rule wins a merge.
- **Invariant 5** — a grant releases an approval requirement, never the blast cap.
- **Invariant 10** — the decision path is the capability layer's; a surface records a channel
  and renders a queue, and decides nothing.
- **Invariant 11** — gate configuration is root-owned Relay configuration, unreachable from any
  API, and it **narrows only**.

## Seams and proof

Gate configuration is loaded once at startup from a root-owned file. The approval domain holds the
gate, the grant, the plan hash and the shape key, and its imports are pinned narrow by test. The
capability layer owns parking, deciding and claiming; the surfaces hold neither.

### What proves each claim

| Behaviour | Proven by | Seam |
|---|---|---|
| A gated dispatch parks and sends nothing | `TestGatedDispatchParksAndSendsNothing` | capability |
| An ungated dispatch is untouched | `TestUngatedDispatchIsUntouched` | capability |
| Reads are not gated by a mutate rule | `TestApprovalCallout_ReadsAreNotGatedByAMutateRule` | e2e |
| Park → decide → run, end to end | `TestApprovalCallout_ParkDecideRun` | e2e |
| An approved Plan dispatches and binds the Job | `TestApprovedPlanDispatchesAndBindsTheJob` | capability |
| A machine cannot satisfy its own gate on its own authority | `TestApprovalCallout_MachineCannotSatisfyItsOwnGate` | e2e |
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
| A grant is consulted only after the gate | `TestGrantIsConsultedOnlyAfterTheGate` | capability |
| A grant never bypasses the blast cap | `TestGrantNeverBypassesTheBlastCap` | capability |
| A grant does not cover outside its Scope | `TestGrantDoesNotCoverOutsideItsScope` | approval |
| Exhausted, revoked and uncovered all park again | `TestExhaustedGrantParksAgain`, `TestRevokedGrantCoversNothing`, `TestUncoveredDispatchStillParks` | approval |
| A grant's cost is derived at the strictest rule | `TestRequestGrantDerivesTheStrictestRequirement` | capability |
| Unbounded Scopes are refused | `TestRequestGrantRefusesUnboundedScopes`, `TestEveryScopeBoundIsRequired` | approval |
| A Scope over ungated work is refused | `TestRequestGrantRefusesWhenNothingIsGated` | capability |
| A requester cannot approve their own window | `TestApprovalGrant_RequesterCannotApproveTheirOwnWindow` | e2e |
| Revoking closes the window immediately | `TestApprovalGrant_RevokeClosesTheWindowImmediately` | e2e |
| Gate config narrows only; an unsatisfiable rule is refused at load | `TestUnsatisfiableRuleIsRejectedAtLoad`, `TestEmptyGateGatesNothing` | approval |
| The approval domain's imports stay narrow | `TestApprovalImportsStayNarrow` | compile-time |

`TestEmptyGateGatesNothing` proves the engine's behaviour for an empty rule set; the shipped default
file that replaces "no file, nothing gated" has no row.

Claims above with **no row**, and so nothing checking them:

- That a fresh install ships and loads the default gate file, and gates `mutate` and Raw Exec at
  in-band confirmation.
- That an in-band asserted approver satisfies a confirmation rung for an MCP request, and nothing
  above it.
- That a pending request expires at the 1-hour default.
- That a grant refuses Raw Exec, a window over 4 hours, issuance on anything but second-person
  out-of-band, and a namespace-pinned Scope. The window cap and pinning are *changes* from today's
  code (24 hours; pinning supported), so existing grant tests do not prove them.
- That a grant's Scope is bound to exactly one Account.
- That a decision's channel is set by the receiving surface rather than the caller. The channel
  *values* are well covered; which side chooses them is not.
- That deciding from the Console records the same decision, channel and attribution as the
  Control API (#435).

### Performance

| Characteristic | Contract | Measured by |
|---|---|---|
| Grant window | Bounded, 4 hours maximum; every Scope bound required | *(none)* |
| Approval queue | Paged; the anti-fatigue diff is one shape-key lookup, never a scan | *(none)* |
| Parked requests | Expire on an operator-set TTL (default 1 hour) and are swept | *(none)* |

There are no benchmarks in this repository. The shape key exists specifically so the queue's
diff is a lookup rather than a scan, and nothing measures that it stays one.

## Out of scope

- **Where the gate sits in the dispatch pipeline, and what a park leaves behind** —
  `execution.md`.
- **The Plan a decision releases** — `plan.md`: the ordered steps, the cursor, the payload-free
  advance, and the walls on an approved-but-incomplete route. A Plan, and each of its `mutate`
  steps, parks through *this* gate and is answered by an ordinary Approval, exactly as a request
  for an approval grant is; it is deliberately not a second decision surface.
- **Policy** — a Node's own engine decides what may run; approval decides whether a caller may
  ask. Policy never says "allow with approval" (`policy.md`).
- **Grants (authorization)** — the Relay-side rule for which Account may request which
  Operations. Unrelated to an **approval grant** despite the name; see `GLOSSARY.md` and
  `accounts-and-access.md`.
- **The Freeze** — a global stop, not a per-request judgement (`freeze.md`).
- **Loading and validating the gate file at startup** — `relay-configuration.md`.
- **Querying the approval audit trail after the fact** — `audit-and-read-lane.md`.

## Accepted residual risk

- **Overlapping rules union their approvers.** When a dispatch or a grant matches several gate
  rules, anyone in any matching rule's audience may approve, and a matching rule with no audience
  makes it anyone at all. A `relay:` rule reserved for one approver can therefore be decided by
  another rule's approver when a Selector also matches that rule. Count, channel, requester exclusion
  and window still take the strictest. Accepted by the owner on `2026-09-16` (ADR-0027 amendment;
  threat model R18) as a stage-appropriate simplification; the improvement is Future work below.

- **Under the shipped defaults, a prompt-injected AI-agent session can approve its own mutation.**
  An in-band confirmation is an assertion by the client, and the session asking is the session
  answering. A fresh install's gate is therefore only as strong as the client. The trail records
  the approver as asserted, never verified, and an operator who needs evidence raises the rule to
  second-person or out-of-band. Stated to the owner and accepted on `2026-09-14`.
- **An approval grant hands the AI-agent choice within its Scope.** Inside a grant, the AI-agent
  picks which covered Operations to run on which Nodes, so a steered session can use a legitimate
  grant for actions nobody intended. Bounded by the Scope, the 4-hour window, the blast cap, Node
  Policy, and the exclusion of Raw Exec.

## Future work

Wanted, deliberately not in the first pass. Named so each is neither re-litigated nor lost;
none is a commitment to an order.

- **Approver audiences that cannot be widened by overlap.** Replace the union of matching rules'
  audiences (Accepted residual risk) with one of two models, decided at pickup: **intersection**,
  refusing a dispatch or grant whose intersection is empty and naming the conflicting rules; or a
  **per-rule quorum**, where every matching rule's audience must be satisfied and one approver in
  several audiences can satisfy them together. Surfaced by #602's security review; ADR-0027
  amendment of `2026-09-16`.
- **Richer multi-person and out-of-band requirements** — rules demanding more than one approver
  (two-person release), and out-of-band requirements that are practical enough to become the
  default for agent-grade mutations.
- **Namespace-pinned approval grants**, if ever re-added — only with pricing that cannot release
  work needing a stronger approval than the grant was issued under (the #482 defect class).

## Open questions

None open. Deciding from the Console (#435) is in scope, not open.

## History

- `2026-09-14` — worked through with the owner. A default gate file ships: `read` ungated,
  `mutate` and Raw Exec at in-band confirmation, second-person and out-of-band kept and
  configurable. Approval grants stay but narrow — one Account, no namespace pinning, never Raw
  Exec, a 4-hour cap, issued only second-person out-of-band — with Plans the default for enumerable
  work. Pending requests expire after 1 hour by default. #482 is resolved in intent by removing
  namespace pinning; the in-band relaxation question is settled by making it the default path, with
  the self-approval risk accepted. Confirmed after drafting: the Relay refuses to start without a
  loadable gate-rule file. Aligned with `plan.md`: each `mutate` step of an approved Plan parks for
  its own approval bound to the Plan hash and step.
- `2026-09-12` — ADR-0038: the plan hash generalised from one Operation to a route, the derived
  requirement extended to a multi-step Plan, and `plan.md` named as the route's owner. No
  behaviour here changed; a single gated dispatch is the one-step case.
- `2026-09-11` — First written, from ADR-0027, ADR-0029 and the approval domain as it stands.
  Written because a dev-loop architect planning #482 reported the governing spec missing.
