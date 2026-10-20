# Approval

**Status:** designed, not built, as of `2026-10-18`.
**Claim prefix:** `AP`

## Purpose

Approval puts a human decision between a request and its execution, for work an operator has
decided is too consequential to run on an AI-agent's say-so alone.

Relay's other guardrails answer *"may this caller do this?"*; none answers *"should this
particular thing happen right now?"* A Grant, a Policy rule and a blast cap are standing
judgements made in advance. Approval is the one control that reaches a person at the moment of
the act.

Its second job is to stay useful under load. A gate that asks too often trains people to
approve without reading, and an approval nobody reads is worse than none: it launders an
AI-agent's intent through a human who did not exercise judgement. Narrow approval grants, the
shape key and the anti-fatigue diff exist for that reason, and so will the Plan (`plan.md`).

## Surfaces

| Surface | How it is reached |
|---|---|
| **MCP** | **`approve_request`** — an ordinary tool call carrying the request ID, the plan hash being answered, the verdict, an asserted approver identity and an optional reason: the in-band decision path, and one every MCP client can make (AP-15, ADR-0029). **MRTR elicitation** — a second envelope over the *same* guarded decision seam (ADR-0029 decisions 5 and 6): the gated `tools/call` answers with an input-required result carrying a Relay-authored approval question, and the client retries the call carrying the answer (AP-60 … AP-71). A park that emitted a question emits no task envelope (AP-71). |
| **Control API** | `GET /api/v1/approvals`, `GET /api/v1/approvals/{id}`, `POST /api/v1/approvals/{id}/decision` — the out-of-band decision endpoint; grant management under `/api/v1/approval-grants`. |
| **Admin Console** | **None** (AP-80, ADR-0044): no approval queue, request screen or decision; the Control API is the one out-of-band path. The Console still shows what an approval left on another record — approver chips on a Job, an `approval` row in Activity. Its execution surface is `execution.md` (ADR-0026). |

Server-initiated elicitation (`elicitation/create` pushed over a stream) is **not** a surface: the
2026-07-28 protocol removed it, and emitting it would cost the MCP surface its stateless property
(ADR-0029). MRTR is the conformant form.

**This is the one capability where the surfaces genuinely differ**, and that is the point: a
decision's *channel* is set by the surface that receives it, not by the caller (*Channel
strength*).

## Behaviour

### Where the gate sits

`execution.md` owns the gate's position in the dispatch pipeline and the reasoning for it; this
spec owns everything the gate then does.

- **AP-1** The gate is consulted inside the dispatch pipeline, after Selector resolution,
  Relay-side authorization and the blast-radius cap, and before any Task exists.
- **AP-2** A park leaves **no Job and no Pending Tasks** behind, because the dispatcher has not
  been reached.
- **AP-3** The approver is shown the **resolved** fan-out — the matched Node count and a capped
  sample of Node IDs — because resolution has already happened; an approval that did not know
  how many Nodes it covered would be a fidelity gap by construction. The sample is what a human
  reads, not what the approval covers: the *full* resolved set is bound by the plan hash (AP-20),
  so nothing outside the set the approver's count described can run on that approval.

### Gate rules, and what ships

- **AP-4** Gate rules are an **optional root-owned file loaded at Relay startup**; when no file
  is configured there is no gate at all.
- **AP-5** No API Token and no MCP tool can write gate rules.
- **AP-6** Gate rules **narrow only**: a rule can require approval, never waive a guardrail.
  Operators loosen or tighten what is gated by editing that file, and a rule no decision could
  ever satisfy is refused when the file loads.
- **AP-7** Packaging ships no gate-rule file and no configured path, so **a fresh install is
  ungated**: nothing requires approval until an operator writes a file and points the Relay at it.

AP-7 is today's truth, not the intent. AP-55 closes it with a default **seeded into the store**,
never shipped as a file: ADR-0027's amendment of `2026-09-16` declined a seeding file as two
sources for one setting. The default it seeds:

| Request | Seeded requirement |
|---|---|
| `read`, any surface | No gate |
| `mutate`, any surface | Self-confirmation, in-band |
| Raw Exec, any surface | Self-confirmation, in-band |

Second-person audiences and out-of-band channels are fully supported for an operator who
configures them; the seed does not demand them. Since ADR-0040, **self-confirmation in-band is
the only rung the shipped posture uses**.

**Why the seed is not a hole in invariant 11.** That invariant has a reach-bounding runtime object
changed only by a human Account with step-up; AP-55's seed is one audited act attributed to the
system. ADR-0027's amendment of `2026-09-16` decided it as the single exception, and it is narrow
three ways: it uses **no credential**, so a stolen one reaches nothing; it fires **only** when the
store holds no rules, and never again, so it cannot overwrite an operator's rules or reopen a gate
an `admin` closed; and it can only **add** gates. Invariant 11 stops a credential *widening*
reach; the seed narrows it from "nothing is gated" (AP-7).

- **AP-8** A gate-rule file that is configured and **cannot be loaded refuses Relay startup**. The
  Relay never runs with nothing gated because a file is unreadable or malformed — a silent ungated
  start is the exact failure AP-55 exists to prevent. Startup refusal is `relay-configuration.md`.

Gate rules are *reach-bounding* under invariant 11, not security floor: ADR-0027 (amended
2026-09-15/16) makes them a store-backed setting edited only by a human `admin` in the Admin
Console with step-up, audited. That is AP-72; when it lands **AP-4, AP-8 and AP-54 retire with the
file**. Until then the same amendment has this spec describe the file behaviour as current.

### The confirmation ladder

The three rungs are ADR-0027 decision 5's, named as `GLOSSARY.md` defines them: **no gate**,
**self-confirmation**, **second-person**. "Confirmation" unqualified names none of them.

**No shipped or seeded rule demands `out-of-band` or sets a second-person rung.** The channel
machinery below (AP-12, AP-13, AP-14 and the weak-channel refusal AP-47) is present, correct and
**unexercised**: an operator who writes a rule reaches all of it; nothing Relay ships does. That
is an interim decision about the shipped configuration (ADR-0040), not about the code; what it
gives up is `approval-assurance.md`.

- **AP-9** A gate rule selects one of three rungs: **no gate** — below thresholds, runs
  immediately; **self-confirmation** — the request is confirmed by the requester's side; and
  **second-person** — the audience excludes the requester. For a human on the Control API or
  Console, self-confirmation is the requester reviewing what Relay rendered and confirming; for an
  MCP request it is an **in-band** answer.
- **AP-10** An MCP in-band answer carries the client's asserted approver identity, and Relay
  records it as an **assertion** (ADR-0029) — never as something it verified. The one exception
  is AP-79: an answer to an elicited approval question arriving on a human Account's OAuth
  session records no asserted identity, even when it carries one, because the verified Account is
  itself the approver. An `approve_request` call is not such an answer: its approver is an
  assertion on every session, a human's OAuth session included.

Rung selection turns on ADR-0027: **MCP-originated calls are agent-grade regardless of whose
OAuth identity authorizes the session.** Session authorization is not per-call human intent; the
calls are model-generated, and the session is steerable by prompt injection. That governs the
*request*. AP-79 settles the *answer* differently: an answer given in the client's own UI, which
the model never sees, on a human Account's OAuth session is that human's verified decision,
whatever the client calls itself (ADR-0027 and ADR-0029 amendments of `2026-09-28` and
`2026-09-29`).

- **AP-11** A machine Account cannot decide its own request *on its own authority*. The one
  relaxation is ADR-0029's: an in-band answer carrying an asserted approver identity is accepted
  as self-confirmation, recording what the client claims without pretending Relay verified it.

Under AP-55's default that relaxation becomes the default path for MCP mutations, so
self-confirmation for an agent-grade request rests on the client. An operator who needs evidence
rather than an assertion raises the rule to second-person or out-of-band (*Accepted residual
risk*).

### Channel strength

A decision carries a channel, and the receiving surface sets it:

- **AP-12** The **receiving surface** sets a decision's channel — never the caller. A request body
  cannot name its own channel.
- **AP-13** A stronger channel satisfies a weaker rule; the reverse is refused. `out-of-band` is
  the stronger: a rule demanding it is not satisfied by an in-band answer, and an asserted approver
  identity does not upgrade one.
- **AP-14** A rule that states no channel defaults to **out-of-band**. This is not in tension with
  ADR-0027 decision 4's "default the self-confirmation rung to in-band": the ADR describes what the
  *shipped rules* set per rung, and AP-14 is what an individual rule's **missing field** resolves
  to — a field nobody filled in resolves strictly, while a rung a rule-author chose resolves to
  what the author wrote.

**In-band is an assumption about the client; out-of-band is evidence.** `in-band` means the
tool-call answer *is* the decision: zero friction, and it trusts the harness that holds the
session's credential. `out-of-band` means the decision lands on the authenticated decision
endpoint, carrying a credential the AI-agent session does not hold.

### Two decision paths

A decision reaches Relay by one of two paths, side by side because they reach different people.

**MCP is the approved pathway** for agent-originated approval (ADR-0040, as amended
`2026-09-25`), and Gleipnir is where the human is expected to answer. The out-of-band path — the
Control API decision endpoint (AP-80) — decides any parked request, whichever surface created it,
and is **not relied on**: it is the rescue, not the route. Nothing Relay ships should direct a
human there for agent-originated work, and nothing refuses one who arrives. **The product's own
text does not say so yet**: the MCP park result's decision path, its schema text and the webhook
payload all name the Relay decision endpoint (*Open questions*).

- **AP-15** **In-band, through the requesting client.** Relay authors the question; the client puts
  it in front of a human and returns the answer over its own session. `approve_request` is that
  call: it carries the request ID, the plan hash being answered, the verdict, an asserted approver
  identity and an optional reason, and it records a Decision.
- **AP-17** Both paths record into the same decision model, and the audit entry carries the answer
  and the channel. What differs is which lane carries the approver: out-of-band the deciding
  Account *is* the approver and is verified, while in-band the verified lane holds the Account that
  relayed the answer and the human is an assertion beside it (AP-39) — except under AP-79,
  where an answer to an elicited question arrives on a human Account's own OAuth session, so the
  relaying Account is the human, is the verified approver, and nothing is asserted beside it.
  `approve_request` never takes that exception (AP-10). Either is a full approval
  path: a rule set to `in-band` is satisfied by either. They are not of equal **strength**: AP-13
  still holds, so a rule set to `out-of-band` is satisfied by the second path only.
- **AP-18** A decision never arrives by any route but these two. **Relay integrates no chat or
  paging system**; its only outbound notice is the best-effort webhook (*Notification*), which
  carries no answer back.

In-band reaches an on-call human wherever they are: Relay is expected to sit behind a firewall
on-call people cannot easily cross, and the client — Gleipnir routing to its on-call audience, or
an operator's own harness — already has. **How the client reaches the human is the client's
concern.** It is expected to keep ADR-0027's rule for Gleipnir's handler — *"a deterministic path
to the assigned human audience — never surfaced to the LLM, never auto-answered"* — which Relay
cannot enforce. Out-of-band is for anyone who can reach Relay directly, and is the only path whose
approver Relay verifies.

- **AP-80** Out-of-band decisions are made on the **Control API decision endpoint only**,
  under a per-person Account. The Admin Console has **no approval surface**: no list of
  pending requests, no approval request screen, no decision on any request — singly or several
  at once — and no step-up taken for one, and its navigation carries no Approvals destination
  and no pending count. It may still render what an approval left on another record — an
  `approval` row in Activity, approver chips on a Job, a Plan's state on its own detail screen
  — with no control that decides. A request's partial quorum (AP-73) is read from the Control
  API's read of that request. Retires AP-16 and AP-19, and narrows AP-73's queue to the
  Control API. (ADR-0044, owner decision 2026-10-18.)

- **AP-60** A gated dispatch that parks under an in-band rule, from a client that can be asked, is
  answered with an approval **question** carrying the Relay-authored summary, the request ID and
  the plan hash — and leaves no Job and no Tasks behind, exactly as a park does today (AP-2).
- **AP-61** A question is emitted only where an answer from that caller could be **accepted**: the
  rule's channel is in-band, the rule does not exclude the requester, and its audience admits the
  calling Account. Otherwise the park renders as today's `pending_approval`.
- **AP-62** A question is emitted only for a park this call **created**; a re-drive that bounces
  off a request already pending re-pages nobody (AP-41).
- **AP-63** An answer carried on the retried call records **the same Decision** as
  `approve_request`, into the same two lanes (AP-39): the in-band channel, the verified Account
  whose credential made the call, the responder identity — where the answer carries one —
  recorded as an assertion, and the same refusals (AP-42 … AP-49). Under AP-79 — an answer on a
  human Account's OAuth session — nothing is written to the asserted lane, whether or not the
  answer carries a responder identity.
- **AP-64** An answer is accepted as a decision only when it carries a **responder assertion**
  whose gate is `permission`, unless it arrives on an **OAuth session** of a **human** Account
  (AP-79), where the verified human is the approver. On such a session a responder assertion may
  be present, but it is not what decides and is not recorded. Any other answer without one is
  machine-originated and is refused exactly as an `approve_request` carrying no approver is
  refused (AP-48). The recognised form today is
  `io.gleipnir/responder` — one form of a general responder assertion, so a standard key later is
  additive.
- **AP-65** The state a client echoes back is **sealed and bound** to the caller, the request, the
  plan and the call; a tampered, cross-request, cross-account, wrong-call or expired one is
  refused.
- **AP-66** An approving retry **re-enters the whole dispatch pipeline** — Freeze, resolution,
  authorization, the cap and the plan-hash match — and a changed Node set re-parks and asks again
  rather than running against a set nobody approved (AP-21).
- **AP-67** A retry whose decision has already released a Job **re-attaches** to that Job and
  mints no second one.
- **AP-68** A denial on the retry is **terminal and audited**, and nothing is dispatched (AP-27).
- **AP-69** An `out-of-band` rule yields **no answerable question**, on any client: the envelope a
  park is rendered in never weakens the channel the rule demands (AP-13).
- **AP-70** A client that cannot be asked sees **no change**: `pending_approval`, `approve_request`
  and the Control API decision endpoint all behave exactly as before, with one exception —
  `approve_request`'s `approver` is bounded by the same rule as an elicited responder (at most 256
  bytes, no control characters), and an approver outside it is refused, never truncated.
- **AP-71** A park that emitted a question emits **no MCP task envelope**. (ADR-0028 §Amendment
  2026-09-24 carves this out of the shim's otherwise unconditional result rewrite.)
- **AP-78** A question is emitted only to a client Relay recognises by the client name it declares
  with the call. `gleipnir` is asked wherever AP-61 allows. `claude-code` is asked only where
  AP-61 allows **and** the call arrives on an **OAuth session** of a **human** Account (AP-79).
  Any other client — including one that advertises elicitation — and a client declaring
  `claude-code` on any other session, an API Token session or a machine Account among them, gets
  today's `pending_approval` and asks nobody. The declared name is self-reported and **decides
  only whether to ask**, never how an answer is accepted or recorded: the answer is bound to the
  caller's own authenticated identity (AP-65) and accepted only under AP-64 or AP-79, which turn
  on the session and the responder assertion, not on the name. Narrows AP-61 (owner decisions
  2026-09-28 and 2026-09-29).
- **AP-79** On a signed-in human session, **the signed-in identity decides, not the client's
  declared name.** Any answer to an approval question arriving on a session whose Principal
  authenticated by **OAuth** and whose Account is **human** is that human's own **verified**
  decision, whatever the client calls itself: recorded in-band, with the deciding Account in the
  verified lane as the approver, no responder assertion required, and nothing written to the
  asserted lane. If the answer also carries a responder assertion (`io.gleipnir/responder`,
  AP-64), the verified human still wins: the assertion is ignored and nothing is written to the
  asserted lane. An `accept` is an approval and a `decline` a denial, and it meets exactly the
  refusals any in-band decision by that Account meets (AP-42 … AP-49) — as the requester too, it
  never satisfies a rule that excludes the requester, and AP-13 keeps it from satisfying an
  `out-of-band` rule. On any other session, an answer is accepted only under AP-64, and a client
  that cannot supply a responder assertion is not asked at all (AP-78). The request stays
  agent-grade (ADR-0027); the answer, given in the client's own UI which the model never sees,
  counts as the human's (owner decisions 2026-09-28 and 2026-09-29).

### What an approval commits to

- **AP-20** An approval binds to a **plan hash** — a content address over the **rendered
  preflight of the request being approved**: its Operation, its arguments and the *resolved
  fan-out* — never to "the Job" in the abstract. (ADR-0027's amendment of `2026-09-20` is what
  gives the word *Plan* in its decision 8 this reading, after ADR-0038 reassigned it.)
- **AP-21** If the Plan no longer matches at dispatch time it **re-parks for re-approval** rather
  than running. That closes park-something-innocuous-then-mutate-the-world.
- **AP-22** The binding is **by identity, never by count**: any Node not in the approved resolved
  set re-parks. A ceiling would bind a number and no identity, which is what a compromised Node
  forging its own `node:` labels (invariant 7) would need in order to elect itself into work
  approved for other hosts.

ADR-0038 generalises that address to a route: a **Plan** whose hash covers ordered steps as well
as the resolved set. A single gated dispatch is the one-step case, and the only one that exists —
a Job carries exactly one Stage and one Action. The rest — each `mutate` step parking at advance,
and a Node that has *left* the set recorded as shrinkage rather than drift — is `plan.md`'s and
unbuilt (*Future work*).

- **AP-23** The **shape key** is a different address from the plan hash: it addresses *what* an
  approval is for, deliberately excluding the resolved fan-out, so that the queue can answer "what
  did I approve last time that looked like this?" as a lookup. It powers the anti-fatigue diff —
  *"same as Tuesday, except the fan-out grew 1,180 → 2,214"* — and it is stable across runs.
- **AP-24** The shape key is **never an authorization or release lookup**. A dispatch proceeds on a
  matching plan hash, or on a claimed approval grant whose Scope covers it, and on nothing else: a
  same-shape, different-plan dispatch still parks. A release path that consulted the shape key
  would be an approval-gate bypass.

### Pending requests expire

- **AP-25** A parked request expires after an operator-set time — **default 4 hours** — and is
  swept. An expired request can be neither decided nor satisfied; the work must be requested again,
  and the new request is shown to its approver afresh.

### Deciding

- **AP-26** A decision is refused unless all of these hold: the request is pending and unexpired;
  the decider is in the required audience; the decider is not the requester when the rule excludes
  them; the decider has not already decided this request; the cited plan hash matches; the channel
  is at least as strong as the rule demands; and the decider clears the **role floor** — which is
  the floor the *Action* needed in order to be requested, not a separate approval role.
- **AP-27** **Deny is terminal and beats approval.** A denied request cannot be revived by a later
  approval, and a denial is audited as fully as a release.
- **AP-73** A Requirement carries a **count** — `1` or `2` in the config a rule may state — and
  a request is released only when that many decisions have arrived from **distinct** Accounts. A
  partial quorum is not an absence: the request stays pending, each decision is its own audit
  record from the first of two, and the queue shows the partial state and who has already signed,
  so the second approver knows what they are joining. An audience entry that is blank cannot pad a
  count.
- **AP-28** Deciding does not itself dispatch; a released request proceeds through the dispatch
  pipeline when it is re-driven.
- **AP-77** **An approval releases one execution.** A released request is bound to exactly one
  Job, and the binding is made once and survives the requesting call ending — a client timeout, a
  dropped connection or a cancelled request cannot leave a dispatched Job unbound. While the
  approval is in force — before its deadline — any later dispatch whose plan hash matches a
  released request, a re-drive on any surface, answered or not, sequential or concurrent,
  re-attaches to that Job and dispatches nothing; of two concurrent dispatches, exactly one runs.
  Re-attaching takes precedence over a covering approval grant, so a re-drive never spends a grant
  use to repeat released work. Once the deadline passes, the same plan parks afresh and needs a new
  approval: an expired approval authorises nothing, including a resurrection of its old Job.
  Re-attaching is not scoped to the requesting Account — the dispatch role floor is checked first,
  and a Job is already readable by any caller who clears it, so nothing is disclosed that was not
  already readable; scoping an unbound release to its requester is tracked for the permissions
  rework (#716). Generalises AP-67 beyond an answered retry (owner decision 2026-09-27).

### Plans first; approval grants as the narrow exception

**Plans are the default tool for work that can be enumerated in advance** — the human sees every
step and the exact Nodes, and nothing runs that was not shown (`plan.md`).

An **approval grant** is standing authorization over a bounded **Scope**, for open-ended work that
cannot be enumerated — *"keep restarting whatever falls over on the web tier for the next hour."*
Approval fatigue is a security failure, not a UX complaint: without a grant, that work becomes a
stream of single approvals that invites rubber-stamping or loosened gate rules. A grant is
deliberately small and conspicuous.

- **AP-29** A Scope is **exactly one Account**, a risk class, an Operation allow-list, a fan-out
  ceiling and an explicit Raw Exec opt-in; the time window lives on the approval grant beside the
  Scope rather than inside it. An approval grant covers nothing outside its Scope.
- **AP-30** Raw Exec **is** coverable by a grant, through the separate opt-in field on the Scope,
  and a Scope that takes it is priced at the `admin` role floor.
- **AP-31** An approval grant's window is bounded by a hard cap of **24 hours**. Everything
  expires.
- **AP-32** A grant's issuance is priced by whatever the live gate rules say (AP-34), and by
  nothing else: there is no floor below which a grant may not be issued, so a one-approval in-band
  grant is representable.
- **AP-33** A Scope has **no Selector-namespace pinning**. A Scope does not narrow by label
  namespace, a request still naming one is refused, and a stored pinned approval grant covers
  nothing.

AP-30 and AP-31 are today's truth, not the intent: ADR-0027's amendment of `2026-09-24` makes
them AP-56 and AP-57, which retire them. **AP-32 has no Designed counterpart.** The third bound —
grant issuance only by second-person, out-of-band approval — was AP-58 until ADR-0040 shelved it
in `approval-assurance.md`; AP-32 is expected to stay true for the interim.

**A Scope is not a Match.** A gate rule's `Match` says *when approval is required*; a grant's
Scope says *what standing authorization covers*. Reusing one for the other inverts the mechanism.
And **requesting a grant is not being granted one**:

- **AP-34** The request for a grant is itself approved through this same gate, at a requirement
  derived from the Scope's worst case, and the requester cannot approve their own window.
- **AP-35** **What a grant costs is derived, never declared.** The requirement comes from
  evaluating the live gate at the Scope's widest admissible dispatch — never from anything the
  requester says — and the strictest requirement it triggers governs. ADR-0038 extends the same
  rule to a multi-step **Plan**, priced over every step at the approved resolved set so that one
  Raw Exec step prices the whole route at Raw Exec's floor; that half is moot today, because a Job
  carries exactly one Stage and one Action and no route object exists.
- **AP-36** **The bound is enforced inside the claiming transaction**, or it is not a bound.
- **AP-37** A grant is consulted **only after** the gate has decided approval is required — never
  as a way to skip the gate — and it **never bypasses the blast cap**. An exhausted, revoked or
  expired grant covers nothing and the dispatch parks again; revoking closes the window
  immediately.

### Notification

- **AP-38** When a request parks, Relay notifies (the webhook callout, ADR-0027). Delivery is
  best-effort and **correctness never depends on it**: a refusing or slow endpoint is survivable
  and never blocks the park, and a decision lands on a surface whether or not any notice arrived.

ADR-0027 decision 2 calls the out-of-band path *"Required, always available, and the only one that
is a guarantee rather than a delivery convenience"*. That is not a delivery guarantee, and AP-38
does not weaken it: what is always available is the **authenticated decision endpoint**. The POST
telling an approver to look is a convenience, the only one Relay makes; a park nobody was notified
of is still pending, still decidable, and still expiring on its own clock.

### Attribution

- **AP-39** Every gated dispatch and every Decision records in two structurally distinct lanes,
  and **the asserted approver never enters the verified one**:

| Lane | What it holds |
|---|---|
| **verified** | The Account the Relay authenticated from the credential presented — the requester on a dispatch, the decider on a Decision, recorded with the decision's channel and the plan hash it answered. It holds the Account whose credential made the call and nothing else, in-band and out-of-band alike. |
| **asserted** | What the caller *claimed*: the `on_behalf_of` identity, bounded and stored verbatim. An in-band approver identity is recorded **here and only here**. |

- **AP-40** The audit **schema** keeps the lanes apart, not the renderer, and a surface that
  renders both renders them as separately labelled trust chips rather than as one approver.

There is no third, blended field. An in-band approval records the machine Account that relayed
the answer as verified, beside an assertion about who authored it. A jailbroken AI-agent can
assert anything and forge nothing, and an auditor can always separate *"a human authenticated to
Relay and approved this"* from *"a client told us a human approved this"*. Once AP-55 seeds its
default, most MCP approvals will be the second kind, and the trail will say so. AP-79 is the one
in-band form of the first kind: the verified lane holds the human on their own OAuth session, and
nothing is asserted, even when the client sent a responder assertion.

## Refusals

- **AP-41** A park is **not** a refusal: nothing was denied and nothing ran. It is audited under
  its own kind, distinguishing a newly created request from a re-drive bouncing off one already
  pending, so the trail's count of asks stays truthful while polling stays visible.

| Claim | Refusal | Cause |
|---|---|---|
| **AP-42** | Not pending / not found | The request is terminal, expired, or unknown |
| **AP-43** | Requester excluded | The rule demands a second person |
| **AP-44** | Not in audience | The decider is outside the audience the rule requires |
| **AP-45** | Duplicate decider | This Account has already decided this request |
| **AP-46** | Plan changed | The cited plan hash is not the request's |
| **AP-47** | Weak channel | The decision's channel is weaker than the rule demands — enforced for denials too |
| **AP-48** | Machine self-decision | A machine Account deciding its own request without the in-band asserted-approver form, or at a rung above self-confirmation |
| **AP-49** | Role floor | The decider is below the floor the Action needed to be requested — an `operator` cannot release a Raw Exec |
| **AP-50** | Approval grant covers nothing gated | A Scope over work that requires no approval would authorize nothing |
| **AP-51** | Approval grant unbounded | Every Scope bound is required; there are no open-ended windows |
| **AP-52** | Approval grant pinned to a namespace | Namespace pinning is not part of a Scope |
| **AP-53** | Approval grant window too long | An approval grant's window exceeds the hard cap (AP-31) |
| **AP-54** | Approvals unavailable | A configured gate file could not be loaded — the Relay refuses to start rather than run ungated by accident (`relay-configuration.md`) |

## Governing ADRs and invariants

- **ADR-0044** — the Console does not decide approvals; the Control API decision endpoint is the
  one out-of-band path, kept as the manual rescue and the only place a rule needing a
  Relay-verified approver can be satisfied, so rescue has no UI. Retires AP-59, AP-16 and AP-19;
  AP-80 states what remains.
- **ADR-0040, as amended `2026-09-25`** — MCP is the approved pathway for agent-originated
  approval, and out-of-band as a rule *requirement* is shelved. **Explicitly interim**, pending
  the permissions rework (#716). Its strict separation by origin was withdrawn unbuilt, and its
  three claims are retired. What the relied-on path gives up — a Relay-verified approver for
  agent-originated work — is in *Accepted residual risk* and threat model R21 and R26; what is
  shelved is `approval-assurance.md`.
- **ADR-0027, as amended 2026-08-14 through 2026-09-24.** The callout, the ladder, channel
  strength, plan-hash binding, expiry, quorum, the attribution triple and approval grants are its
  decisions. Amendments the code does not yet carry are Designed claims here: store-backed gate
  rules (2026-09-15, AP-72), the seeded default (2026-09-16, AP-55), and two of the three grant
  bounds (2026-09-24, AP-56 and AP-57; the third is shelved by ADR-0040). The `2026-09-16`
  amendment has AP-4, AP-8 and AP-54 describe the file as current until AP-72. It sets no figure
  for pending-request expiry; AP-25 states the 4 hours the code applies. Its decision 8's *Plan*
  reads through the `2026-09-20` amendment as the rendered preflight (AP-20), and decision 1's "a
  gated Job parks" through ADR-0028's `2026-08-17` amendment and the `2026-09-24` correction:
  parking creates no Job (AP-2).
- **ADR-0029** — in-band approval as a tool call, the asserted approver, the single guarded
  decision seam (decision 5), and MRTR elicitation as the second envelope over it (decision 6,
  AP-60 … AP-71). Under AP-55 the in-band relaxation becomes the default path for MCP mutations,
  the case ADR-0029 flagged as worth revisiting; the owner accepted it knowingly.
- **ADR-0038** — the plan hash covers a route; the derived requirement is priced over every step.
  Both halves are ahead of the code (AP-22, AP-35), because no route object exists.
- **ADR-0028** — the MCP task handle and the `tasks/update` boundary. AP-60 and AP-71 stand on
  its amendment of `2026-09-24`: the precedence decision replaces the old premise that Relay emits
  no `inputRequests`, and the result rewrite gains the carve-out AP-71 needs.
- **Invariant 3** (deny-beats-allow) — a denial is terminal and a stricter rule wins a merge
  (AP-27).
- **Invariant 4** (at-most-once) — a released decision mints one Job. AP-67 re-attaches a retried
  in-band approval, and AP-77's transactional claim makes that the rule for every re-drive on
  every surface while the approval is in force.
- **Invariant 5** — a grant releases an approval requirement, never the blast cap (AP-37).
- **Invariant 7** — the plan hash binds the resolved set by identity, which is what stops a Node
  forging its own `node:` labels from electing itself into approved work (AP-22).
- **Invariant 10** — the decision path is the capability layer's; a surface records a channel
  and renders what is pending, and decides nothing (AP-12). An adapter may offer less than the
  layer allows: under AP-80 the Console offers no approval at all.
- **Invariant 11** — gate configuration is *reach-bounding*, not security floor: unreachable from
  any API, and it **narrows only** (AP-5, AP-6). Root-owned on the host today (AP-4); a runtime
  object under AP-72. The webhook's URL, secret file and timeout stay security floor either way
  (`relay-configuration.md`).

## Seams and proof

Gate configuration is loaded from an optional root-owned file at startup and re-read on every
`SIGHUP` reload (`relay-configuration.md`); store-backed rules are AP-72. The approval domain
holds the gate, the grant, the plan hash and the shape key, and its imports are pinned narrow by
lint (`.golangci.yml` depguard rule `approval-imports`). The capability layer owns parking,
deciding and claiming; the surfaces hold none of it. `make verify` covers every row below; the
end-to-end rows also need `make test-integration`.

### What proves each claim

| Claim | Proven by | Seam |
|---|---|---|
| AP-1 | `TestGatedDispatchParksAndSendsNothing` | capability |
| AP-2 | `TestGatedDispatchParksAndSendsNothing` | capability |
| AP-4 | `TestEmptyPathMeansNoGates`, `TestUngatedDispatchIsUntouched` | approval, capability |
| AP-6 | `TestUnsatisfiableRuleIsRejectedAtLoad`, `TestEmptyGateGatesNothing` | approval |
| AP-7 | `TestEmptyPathMeansNoGates`, `TestEmptyGateGatesNothing` | approval |
| AP-8 | `TestLoadFailsClosed` | approval |
| AP-9 | `TestApprovalCallout_ReadsAreNotGatedByAMutateRule`, `TestRequesterCannotApproveOwnRequest` | e2e, approval |
| AP-10 | `TestMachineCannotConfirmItself`, `TestElicitedAnswer_ResponderOnAnOAuthHumanSessionIsIgnored`, `TestMCPElicitation_ResponderOnAnOAuthHumanSessionIsIgnored`, `TestE2EOAuth_ApproveRequestOnAHumanSessionStillRecordsAnAssertion` | approval, MCP, e2e |
| AP-11 | `TestApprovalCallout_MachineCannotSatisfyItsOwnGate`, `TestMachineCannotConfirmItself` | e2e, approval |
| AP-12 | `TestDecideApproval_BodyCannotNameAChannel` | API |
| AP-13 | `TestStrongChannelSatisfiesAWeakerRule`, `TestAssertedApproverDoesNotWeakenAnOutOfBandRule` | approval |
| AP-14 | `TestUnstatedChannelDefaultsToOutOfBand` | approval |
| AP-17 | `TestDecideApprovalAuditEntryCarriesTheAnswerAndChannel`, `TestApprovalCallout_ControlAPIDecidesAnMCPParkedRequest`, `TestMCPElicitation_GleipnirOnAnOAuthHumanSessionIsTheHumansVerifiedDecision`, `TestE2EOAuth_ApproveRequestOnAHumanSessionStillRecordsAnAssertion` | capability, MCP, e2e |
| AP-20 | `TestApprovedPlanDispatchesAndBindsTheJob`, `TestDecisionMustCiteTheRequestsPlanHash` | capability |
| AP-21 | `TestRegistryDriftReParksAnApprovedPlan` | capability |
| AP-22 | `TestRegistryDriftReParksAnApprovedPlan` | capability |
| AP-23 | `TestShapeKeyIsStableAcrossRuns` | approval |
| AP-24 | `TestSameShapeDifferentPlanStillParks` | capability |
| AP-25 | `TestExpiredRequestIsNotDecidableOrSatisfiable` | approval |
| AP-26 | `TestApprovalCallout_ParkDecideRun` | e2e |
| AP-27 | `TestDenyIsTerminalAndBeatsApproval`, `TestDenialIsTerminalAndAudited` | approval |
| AP-73 | `TestQuorumNeedsDistinctDeciders`, `TestRecordDecisionPersistsQuorumProgress`, `TestBlankAudienceEntryCannotPadPastQuorumCheck`, `TestApprovalCallout_PartialQuorumIsReadFromTheControlAPI` | approval, capability, e2e |
| AP-28 | `TestDecideApprovalDoesNotDispatch`, `TestApprovalCallout_ParkDecideRun` | capability, e2e |
| AP-77 | `TestBindJob_BindsOnceAndReportsTheBoundJob`, `TestBindJob_ConcurrentClaimsExactlyOneWins`, `TestRun_ReleasedJobStaysBoundWhenTheCallIsCancelledMidDispatch`, `TestJobEngine_ReservedRunSurvivesRequestCancellationAfterCreateJob`, `TestRun_ReDriveOfAReleasedApprovalReAttachesAndDispatchesNothing`, `TestRun_ConcurrentReDrivesDispatchExactlyOneJob`, `TestRun_ReleasedApprovalReAttachesEvenWhenAGrantCoversThePlan`, `TestRun_ReleasedApprovalPastItsDeadlineParksAfresh`, `TestRun_DifferentRequesterReAttachesToTheReleasedJob`, `TestApprovalRelease_ReDriveOnAnySurfaceReAttaches`, `TestApprovalRelease_DifferentAccountReAttachesAndRunsNothing`, `TestRunAuthorizeDeniedShortCircuits` | store, capability, e2e |
| AP-78 | `TestMCPElicitation_UnrecognisedMRTRClientGetsPendingApproval`, `TestMCPElicitation_ClaudeCodeOnAnAPITokenSessionIsNotAsked`, `TestMCPElicitation_ClaudeCodeOnAMachineOAuthSessionIsNotAskedAndNotAccepted`, `TestMCPElicitation_SpoofedClaudeCodeOnANonOAuthSessionEarnsNothing`, `TestElicit_WhoIsAskedByNameAndSession`, `TestElicit_ClaudeCodeOnAnAPITokenSessionIsNotAsked`, `TestElicit_ClaudeCodeRetryOnAnAPITokenSessionIsAnOrdinaryCall`, `TestE2EOAuth_SessionResolvesToTheAccount` | e2e, MCP |
| AP-79 | `TestMCPElicitation_ClaudeCodeOnAnOAuthHumanSessionIsTheHumansVerifiedDecision`, `TestMCPElicitation_GleipnirOnAnOAuthHumanSessionIsTheHumansVerifiedDecision`, `TestMCPElicitation_ClaudeCodeHumanAnswerMeetsTheSameRefusals`, `TestMCPElicitation_ResponderOnAnOAuthHumanSessionIsIgnored`, `TestMCPElicitation_MachineOAuthSessionNeverTakesTheVerifiedPath`, `TestMCPElicitation_HumanAPITokenSessionStillNeedsAResponder`, `TestElicitedAnswer_OAuthHumanSessionAnswerIsTheHumansVerifiedDecision`, `TestElicitedAnswer_OAuthHumanSessionDeclineIsADenial`, `TestElicitedAnswer_ResponderOnAnOAuthHumanSessionIsIgnored`, `TestElicitedAnswer_VerifiedFormIgnoresTheDeclaredName`, `TestElicitedAnswer_OffAnOAuthHumanSessionOnlyTheNamedFormCounts`, `TestElicitedAnswer_VerifiedFormMeetsTheSameRefusals`, `TestOAuthHumanSession_ChecksTheAccountKindNotTheAuthMethod`, `TestDecideApproval_InBandHumanWithNoAssertedApproverIsVerified` | e2e, MCP, capability |
| AP-80 | `TestConsole_HasNoApprovalSurface`, `TestConsole_ADecisionPostOnARealSessionFindsNothing`, `TestApprovalReader_ReadsOneRecordAndCannotListOrDecide`, `TestApprovalCallout_TheConsoleHasNoApprovalSurface`, `TestApprovalCallout_PartialQuorumIsReadFromTheControlAPI` | Console, e2e |
| AP-29 | `TestGrantDoesNotCoverOutsideItsScope`, `TestRawExecIsASeparateOptIn` | approval |
| AP-30 | `TestRawExecIsASeparateOptIn` | approval |
| AP-33 | `TestCreateGrant_RefusesTheRetiredSelectorNamespace` | API |
| AP-34 | `TestApprovalGrant_RequesterCannotApproveTheirOwnWindow` | e2e |
| AP-35 | `TestRequestGrantDerivesTheStrictestRequirement` | capability |
| AP-36 | `TestClaimGrantNeverExceedsItsBoundUnderConcurrency` | store |
| AP-37 | `TestGrantIsConsultedOnlyAfterTheGate`, `TestGrantNeverBypassesTheBlastCap`, `TestExhaustedGrantParksAgain`, `TestRevokedGrantCoversNothing`, `TestUncoveredDispatchStillParks`, `TestApprovalGrant_RevokeClosesTheWindowImmediately` | capability, approval, e2e |
| AP-38 | `TestARefusingEndpointIsSurvivable`, `TestNotifyParkedDoesNotBlock` | approval |
| AP-40 | `TestAttribution_LanesAreStructurallySeparate` | capability |
| AP-41 | `TestRedriveAuditsPendingObservedNotRequested` | capability |
| AP-42 | `TestExpiredRequestIsNotDecidableOrSatisfiable` | approval |
| AP-43 | `TestRequesterCannotApproveOwnRequest`, `TestApprovalGrant_RequesterCannotApproveTheirOwnWindow` | approval, e2e |
| AP-44 | `TestAudienceIsEnforced` | approval |
| AP-45 | `TestQuorumNeedsDistinctDeciders`, `TestRecordDecisionRejectsDuplicateDecider`, `TestDecideApproval_DuplicateDeciderReturnsTheCurrentRequest` | approval, store, capability |
| AP-46 | `TestDecisionMustCiteTheRequestsPlanHash` | capability |
| AP-47 | `TestWeakChannelIsRefused`, `TestWeakChannelIsRefusedForDenialsToo` | approval |
| AP-48 | `TestApprovalCallout_MachineCannotSatisfyItsOwnGate`, `TestMachineCannotConfirmItself` | e2e, approval |
| AP-49 | `TestApprovalCallout_OperatorCannotReleaseARawExec`, `TestDecisionRoleFloorUsesTheParkedActionKind`, `TestDecisionRefusedByRoleFloorRecordsNothing` | e2e, capability |
| AP-50 | `TestRequestGrantRefusesWhenNothingIsGated` | capability |
| AP-51 | `TestRequestGrantRefusesUnboundedScopes`, `TestEveryScopeBoundIsRequired` | capability, approval |
| AP-52 | `TestCreateGrant_RefusesTheRetiredSelectorNamespace` | API |
| AP-53 | `TestGrantWindowCannotExceedTheHardMaximum`, `TestRequestGrantRefusesUnboundedScopes` | approval, capability |
| AP-54 | `TestLoadFailsClosed` | approval |
| AP-60 | `TestCompositionRoot_EnablesElicitation`, `TestMCPElicitation_ApproveRunsTheJobAndReturnsResults`, `TestElicit_AskableParkFromMRTRClientGetsAQuestion` | e2e |
| AP-61 | `TestMCPElicitation_RequesterExcludedAndAudienceRestrictedNeverAsk`, `TestMCPElicitation_OutOfBandRuleNeverAsks` | e2e |
| AP-62 | `TestMCPElicitation_RedriveOfAPendingRequestAsksNobody` | e2e |
| AP-63 | `TestMCPElicitation_DecisionIsInBandVerifiedRequesterAssertedApprover`, `TestMCPElicitation_ApproveRunsTheJobAndReturnsResults`, `TestElicitedAnswer_RecordsTheSameDecisionAsApproveRequest`, `TestAnsweredRetry_DomainRefusalsAreResultsNotErrors`, `TestElicitedAnswer_ClassifiesEveryOutcome`, `TestE2EOAuth_ApproveRequestOnAHumanSessionStillRecordsAnAssertion` | e2e, MCP |
| AP-64 | `TestMCPElicitation_AnswerWithoutAResponderIsAMachineSelfDecision`, `TestElicitedAnswer_WithoutAPermissionResponderIsAMachineSelfDecision`, `TestElicitedAnswer_ResponderOnAnOAuthHumanSessionIsIgnored`, `TestElicitedAnswer_OffAnOAuthHumanSessionOnlyTheNamedFormCounts`, `TestMCPElicitation_HumanAPITokenSessionStillNeedsAResponder` | e2e, MCP |
| AP-65 | `TestMCPElicitation_TamperedStateIsRefused`, `TestMCPElicitation_CrossRequestStateIsRefused`, `TestMCPElicitation_CrossAccountStateIsRefused`, `TestMCPElicitation_WrongCallStateIsRefused`, `TestMCPElicitation_ExpiredStateIsRefused`, `TestBinding_RefusesCrossAccountCrossRequestWrongToolWrongArgs` | e2e, MCP |
| AP-66 | `TestMCPElicitation_FleetChangedRetryReParks`, `TestAnsweredRetry_FleetChangedReParksAndAsksAfresh`, `TestAnsweredRetry_ApproveAtTheHandlerSeamRunsOnceAndCarriesTheDecision`, `TestAnsweredRetry_NextStepFollowsWhatTheDispatchReturned` | e2e, MCP |
| AP-67 | `TestMCPElicitation_DuplicateRetryReAttaches`, `TestAnsweredRetry_BoundJobReAttaches` | e2e |
| AP-68 | `TestMCPElicitation_DeclineIsTerminalAndAudited`, `TestAnsweredRetry_DeclineIsTerminalAndDispatchesNothing` | e2e |
| AP-69 | `TestMCPElicitation_OutOfBandRuleNeverAsks`, `TestElicit_OutOfBandParkNeverAsks` | e2e |
| AP-70 | `TestCompositionRoot_ClientThatCannotBeAskedSeesNoChange`, `TestMCPElicitation_ClientThatCannotBeAskedSeesNoChange`, `TestAnsweredRetry_ClientThatCannotBeAskedIgnoresRetryFields`, `TestApproveRequest_RefusesRatherThanTruncatesAMalformedApprover`, `TestElicitedAnswer_RefusesRatherThanTruncatesAMalformedResponder` | e2e, MCP |
| AP-71 | `TestMCPElicitation_ElicitedParkEmitsNoTaskEnvelope`, `TestElicit_ElicitedParkEmitsNoTaskEnvelope` | e2e, MCP |

Claims with **no row**, and so nothing checking them:

- **AP-3** — the count and the capped sample are built and summarised for the approver, but no
  test asserts what the approver is shown, nor that the sample is a sample rather than the bound.
- **AP-5** — a statement of absence. There is one non-test call site and the gate exposes no
  mutator, but nothing asserts that no API Token or MCP tool can reach it.
- **AP-8** and **AP-54**, composition-root half — `TestLoadFailsClosed` proves the loader fails
  closed on an unreadable or malformed file; **no test drives the resulting startup failure
  through the composition root**, so "the Relay refuses to start" rests on one unexercised
  call site.
- **AP-15** — the tool is registered and its decision path is exercised through the e2e rows, but
  nothing asserts `approve_request`'s own field set (request ID, plan hash, verdict, asserted
  approver, reason).
- **AP-18** — a statement of absence: that no third route delivers a decision.
- **AP-31** — a window past the hard cap is refused (AP-53's row), but no test names the cap's
  value: nothing asserts that it is 24 hours rather than any other duration.
- **AP-32** — that a one-approval in-band grant is representable is the *absence* of a floor.
  Nothing asserts an absence.
- **AP-39** — the two lanes are proven structurally separate (AP-40), but **no end-to-end test
  drives `approve_request` and then checks the two columns**: that the verified lane holds the
  calling Account and never the asserted string, and that the asserted approver reached
  `on_behalf_of` and nowhere else. The claim that matters most here is the one nothing walks.
- **AP-12**, surface half — the Control API is proven not to take a channel from the body; MCP and
  the Console are not asserted the same way.
- **AP-38**, guarantee half — the webhook's best-effort behaviour is proven; that a park
  nobody was notified of is still decidable rests on the decision endpoint's own tests, not
  on one that drops the notice and then decides.

`TestEmptyGateGatesNothing` and `TestEmptyPathMeansNoGates` prove AP-7's ungated fresh install;
AP-55, which replaces it, has nothing to prove yet.

### Performance

| Characteristic | Contract | Measured by |
|---|---|---|
| Approval grant window | Bounded by a hard cap; every Scope bound required (AP-31, AP-51) | *(none)* |
| Approval queue | Paged; the anti-fatigue diff is one shape-key lookup, never a scan | *(none)* |
| Parked requests | Expire on an operator-set TTL (default 4 hours) and are swept | *(none)* |

There are no benchmarks in this repository; nothing measures that the shape-key diff stays a
lookup.

## Designed, not built

| Claim | Statement | Milestone |
|---|---|---|
| AP-55 | A Relay whose store holds no gate rules at first start **seeds the shipped default** — `read` ungated, `mutate` and Raw Exec at self-confirmation in-band, with second-person and out-of-band available to raise any rule to — as one audited act attributed to the system and not to an Account. After that the store is the only source: no file is read, and the Relay does not re-seed on a later start. Retires AP-7; depends on AP-72. (ADR-0027 §Amendment 2026-09-16, which declined a root-owned file seeding the store as two sources for one setting; #590.) | v0.7.0 — Admin Console: Administration & Execution |
| AP-56 | An approval grant never covers Raw Exec: every Raw Exec needs its own decision, and a Scope naming Raw Exec is refused. Retires AP-30. (ADR-0027 §Amendment 2026-09-24.) | v0.6.5 — Install Path: relay init, join string, packages |
| AP-57 | An approval grant's window is capped at 4 hours, and a longer one is refused. Retires AP-31 and narrows AP-53. (ADR-0027 §Amendment 2026-09-24.) | v0.6.5 — Install Path: relay init, join string, packages |
| AP-72 | Gate rules are runtime objects in the Relay's store, edited only by a human `admin` in the Admin Console with step-up re-authentication, audited per rule with old and new values, and taking effect on the next dispatch; no MCP tool and no Control API route writes them, and none may be added. Retires AP-4, AP-8 and AP-54 — the store is the only source, no file is read, and there is nothing left to fail to load. (ADR-0027 §Amendment 2026-09-15; #590, #596.) | v0.7.0 — Admin Console: Administration & Execution |

## Out of scope

- **Where the gate sits in the dispatch pipeline, and what a park leaves behind** —
  `execution.md`.
- **The Plan a decision releases** — `plan.md`: the ordered steps, the cursor, the payload-free
  advance, and the walls on an approved-but-incomplete route. A Plan, and each of its `mutate`
  steps, parks through *this* gate and is answered by an ordinary Approval, as a request for an
  approval grant is; it is not a second decision surface. None of it exists in code.
- **Policy** — a Node's own engine decides what may run; approval decides whether a caller may
  ask. Policy never says "allow with approval" (`policy.md`).
- **Grants (authorization)** — the Relay-side rule for which Account may request which
  Operations. Unrelated to an **approval grant** despite the name; see `GLOSSARY.md` and
  `accounts-and-access.md`.
- **The Freeze** — a global stop, not a per-request judgement (`freeze.md`).
- **Loading and validating the gate file at startup** — `relay-configuration.md`.
- **Querying the approval audit trail after the fact** — `audit-and-read-lane.md`.
- **The assurance properties shelved on `2026-09-24`** — `approval-assurance.md`, a `stub`:
  out-of-band as a rule *requirement*, an approver Relay verifies rather than one a client
  asserts, the grant-issuance floor that AP-58 was, and second-person rules whose second
  person Relay authenticated. None of it is a claim or has a milestone, and none may be cited
  here as a requirement (ADR-0040).

## Accepted residual risk

- **Overlapping rules union their approvers.** When a dispatch or a grant matches several gate
  rules, anyone in any matching rule's audience may approve, and a matching rule with no audience
  makes it anyone at all. A `relay:` rule reserved for one approver can therefore be decided by
  another rule's approver when a Selector also matches that rule. Count, channel, requester
  exclusion and window still take the strictest. Accepted by the owner on `2026-09-16` (ADR-0027
  amendment; threat model R18) as a stage-appropriate simplification; see *Future work*.
- **A fresh install gates nothing at all (AP-7).** Packaging ships no gate rules and configures no
  path, so until an operator writes a file every `mutate` and every Raw Exec runs unapproved:
  not "the gate is only as strong as the client" but "there is no gate". Bounded only by
  Relay-side authorization, the blast cap and Node Policy, none of which is a human. Accepted as a
  stage, not a posture: AP-55 and AP-72 close it, leaving the next risk. Threat model **R23**.
- **Once AP-55 seeds its default, a prompt-injected AI-agent session can approve its own
  mutation.** A self-confirmation answer in-band is an assertion by the client, and the session
  asking is the session answering. A fresh install's gate is therefore only as strong as the
  client. The trail records the approver as asserted, never verified (AP-39), and an operator who
  needs evidence raises the rule to second-person or out-of-band. Stated to the owner and accepted
  on `2026-09-14`. Threat model **R21**.
- **The relied-on path for agent-originated work records an assertion, never a verified
  approver.** An `out-of-band` rule still yields an approver Relay authenticated, but no shipped
  or seeded rule demands a channel and MCP is the approved pathway, so for agent-originated work
  the trail answers *"a client told us a human approved this"*, not *"a human authenticated to
  Relay approved this"*. A verified approver is still **reachable** on the Control API decision
  endpoint (AP-80; the Console decides nothing, ADR-0044), which needs an API Token and the
  request's ID; nothing directs a human there, so it is the rescue rather than a control.
  Accepted by the owner on `2026-09-24` as **interim**, pending the permissions rework, on the
  four grounds ADR-0040 records: the client is where the human already is, on the far side of
  Relay's firewall; Gleipnir checks its approver role server-side and stamps the responder from
  an authenticated session, so *somebody* authenticated the assertion; the alternative in
  practice was an approval nobody answered; and one permission model is a prerequisite for a good
  one. ADR-0044's narrowing to the Control API was accepted on `2026-10-18`. Bounded by
  everything an approval never was: Relay-side authorization, the blast cap, the plan-hash
  binding, drift re-parking, and Node Policy, which no approval can lower. AP-79 makes an answer
  on a human Account's OAuth session a verified approver over MCP (`2026-09-28`, `2026-09-29`),
  but OAuth has never run live against a real identity provider (#351), so that path is
  unexercised in the shipped posture; on every other session this entry stands. Threat model
  **R21** and **R26**; what is shelved is `approval-assurance.md`.
- **An in-band approval is only as honest as the client's path to the human.** Behind a firewall,
  in-band is expected to be the everyday path, so for `in-band` rules the guarantee that a human
  decided rests on the client — Gleipnir's HIL router, or an operator's harness — keeping
  ADR-0027's rule. Relay records such an approver as asserted and cannot detect an auto-answer;
  AP-79's OAuth form, recorded as verified, has the same blind spot (next entry). **The same holds
  for AP-64's responder assertion**, a client's claim that a human and not the model answered:
  Relay checks that it is present and bound (AP-65), not that it is true. An operator who needs
  evidence sets the rule to `out-of-band`. Accepted by the owner on `2026-09-18` (threat model
  R21) and extended to the responder assertion on `2026-09-24`.
- **An answer on a human's OAuth session proves who owns the session, not that a human read the
  question (AP-78, AP-79).** Any answer arriving on a human Account's OAuth session is recorded as
  that human's verified decision, whatever the client calls itself; a Claude Code answer counts
  only there. Verified means Relay authenticated whose session answered, not that the person read
  the question: anything holding that human's OAuth token answers as them, and a configured Claude
  Code **hook** can answer with no human present, indistinguishably. Whether Claude Code speaks
  MRTR at all is a remote feature flag, so it can revert to `pending_approval` with no change
  here. The declared client name decides only whether to ask: the answer is bound to the caller's
  own credential (AP-65), and Claude Code is not asked on an API Token session or a machine
  Account. OAuth has never run live against a real identity provider (#351), so nothing in the
  shipped posture reaches this form yet. Accepted by the owner on `2026-09-28` and generalised to
  every client on such a session on `2026-09-29` (ADR-0027 and ADR-0029 amendments).
- **Gleipnir's form is a vendor key (AP-64).** Its one recognised responder form is
  `io.gleipnir/responder`, a self-report of the same strength as `approve_request`'s `approver`:
  interoperability discipline, not verification. Accepted by the owner on `2026-09-25`; a standard
  responder key would be additive.
- **A released approval's single execution has three narrow residuals (AP-77).** The release is
  a transactional claim made before dispatch with a reserved Job ID, and for that ID the whole
  persist-then-dispatch pipeline runs detached from the request, so no client timeout,
  dropped connection or cancellation strands approved work. **(a)** If the Job row itself fails
  to be created — a genuine store failure — the approval names a Job ID nothing created, and
  re-drives get "job not found" until the deadline, after which the plan parks afresh. **(b)** A
  concurrent loser re-attaching before the winner's Job row commits gets the same "job not found",
  fail-closed; its retry succeeds once the Job exists. **(c)** Release is keyed by plan hash, not
  requester: a different Account's identical re-drive re-attaches and reads the Job, an audited
  read with the same reach as `get_job`; scoping release to the requester is tracked for the
  permissions rework (#716). Accepted by the owner on `2026-09-24`. Threat model **R24**.
- **An approval grant hands the AI-agent choice within its Scope.** Inside a grant, the AI-agent
  picks which covered Operations to run on which Nodes, so a steered session can use a legitimate
  grant for actions nobody intended. Bounded by the Scope, the window, the blast cap and Node
  Policy — and, once AP-56 and AP-57 land, by the exclusion of Raw Exec and the 4-hour cap. Until
  then the bound is a 24-hour window (AP-31) over a Scope that may opt into Raw Exec (AP-30): a
  standing, agent-choosable authorization over an arbitrary command, for a day. Threat model
  **R25**.

## Future work

Named, not decided, and in no order.

- **Multi-step Plan routes, and everything that follows from them** — `plan.md`, which states that
  none of it exists in code. A Plan whose hash covers an ordered route rather than a single
  dispatch; **each `mutate` step parking at advance for its own approval**, bound to the Plan hash
  and that step, so that approving a Plan releases its route as context and not its mutations;
  **shrinkage recorded** — a Node that has *left* the approved set dropped from that step and
  recorded, rather than treated as drift; and **an approval grant never releasing a route**,
  because a grant is described and a Plan is enumerated, and letting the first release the second
  would amplify a grant's use limit N-fold while ensuring no human ever saw the route. No
  milestone, no issues.
- **Approver audiences that cannot be widened by overlap.** Replace the union of matching rules'
  audiences (*Accepted residual risk*) with one of two models, decided at pickup: **intersection**,
  refusing a dispatch or grant whose intersection is empty and naming the conflicting rules; or a
  **per-rule quorum**, where every matching rule's audience must be satisfied and one approver in
  several audiences can satisfy them together (ADR-0027 amendment of `2026-09-16`).
- **Quorum beyond `count: 1 | 2`** — N-of-M, and per-audience rather than per-request counts.
  Two-person release is built (AP-73), and ADR-0027 decision 7 stores the general
  requirement-versus-decisions shape so richer matching is a config-language change with no data
  migration. Also future: out-of-band requirements practical enough to be the default for
  agent-grade mutations.
- **An unnamed confirmation, if ever reintroduced, is its own structural field** (owner,
  `2026-09-28`). An answer accepted without naming an approver is never recorded as an
  asserted-approver string, because `approve_request` lets anyone type any string there and the
  trail could not tell the real form from a forgery; it would be a distinct field in the decision
  and audit record that no typed text can produce. Nothing needs it today (AP-79, AP-64).
- **Retiring `approve_request`.** The owner's intent is that it may be retired once MRTR
  elicitation is usable from the clients Relay is driven by, which first requires those clients to
  negotiate the 2026-07-28 protocol. Not decided here: it needs an ADR-0029 amendment first
  (decisions 1 and 5, and Consequences).
- **Namespace-pinned approval grants**, if ever re-added — only with pricing that cannot release
  work needing a stronger approval than the grant was issued under (the #482 defect class).

## Open questions

- **Does a release dispatch while the requester waits?** An out-of-band decision releases a
  request that runs only when the requester re-drives it (AP-28); AP-66 already makes the re-drive
  automatic for in-band ones. #643 proposes holding the gated call open for a bounded wait and
  dispatching on release, which would change AP-28. What would force it: an owner decision on
  #643.
- **Which envelope a Tasks-capable client gets for a park that cannot be asked.** AP-71 settles
  the case where a question *was* emitted: no task envelope. It says nothing about a park under an
  `out-of-band` rule, or one whose audience excludes the caller, reaching a client that advertised
  the Tasks capability — today that park is rewritten into a task handle, and nothing decides
  whether it should stay that way. `execution.md`, unmigrated, states the rewrite unconditionally.
  What would force it: `execution.md`'s migration, or #644.

- **What the product's own text should say about where to answer.** ADR-0040 as amended makes
  MCP the approved pathway and names "the tool text, the runbook and operator guidance" as where
  that is said. Today three things say the opposite: the MCP park result's decision path, the
  schema text describing it, and the webhook payload, all of which point a human at the Relay
  decision endpoint. Whether each should name the client instead, name both with the client
  first, or be left as the rescue's address is undecided, with no issue. What would force it: the
  demo's approval beat, expected in Gleipnir's UI while the webhook sends the human to the Relay
  decision endpoint.
- **What the shape key is for once the Console has no queue.** AP-23 says the shape key
  powers the anti-fatigue diff (*"same as Tuesday, except the fan-out grew"*), and the only
  surface that renders that diff is the Console's approval object, which AP-80 removes. The key
  stays correct and stays a non-release address (AP-24); what is undecided is whether the diff
  moves to the Relay-authored question a client puts in front of the human, to the Control API's
  read of a request, or nowhere. What forces it: since AP-80, AP-23's second sentence describes a
  rendering no surface makes.

Decided, not open: the Console does not decide (ADR-0044, AP-80), and ADR-0044 rejected removing
the Control API decision endpoint too while threat model R27 is open.

## Retired

- **AP-58** — `2026-09-24` — moved to the `approval-assurance.md` stub when ADR-0040 shelved
  second-person grant issuance.
- **AP-74**, **AP-75**, **AP-76** — `2026-09-25` — retired unbuilt when ADR-0040's strict
  separation by origin was withdrawn (ADR-0040 amendment).
- **AP-59** — `2026-10-18` — retired unbuilt: bulk decisions were a Console act, and ADR-0044
  removes the Console's approval surface. Its accepted residual (threat model R22) and its
  *Bounding bulk approve* future-work entry go with it.
- **AP-16** — `2026-10-18` — retired by AP-80 (ADR-0044). Its Console half — deciding in the
  Console under step-up — was removed; its Control API half, the out-of-band decision endpoint
  under a per-person Account, carries on as AP-80.
- **AP-19** — `2026-10-18` — retired by AP-80 (ADR-0044): the Console's approval UI, its queue,
  request screen and decide action, was removed. Approval records still render on other records
  with no deciding control (AP-80).
