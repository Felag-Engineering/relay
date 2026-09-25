# Approval

**Status:** designed, not built, as of `2026-09-24`.
**Claim prefix:** `AP`

## Purpose

Approval is the capability that puts a human decision between a request and its execution, for
the work an operator has decided is too consequential to run on an AI-agent's say-so alone.

It exists because the rest of Relay's guardrails answer *"may this caller do this?"* and none of
them answers *"should this particular thing happen right now?"* A Grant, a Policy rule and a
blast cap are all standing judgements made in advance. Approval is the one control that reaches
a person at the moment of the act.

Its second job is to stay useful under load. A gate that asks too often trains people to
approve without reading, and an approval mechanism nobody reads is worse than none — it
launders an AI-agent's intent through a human who did not exercise judgement. Narrow approval
grants, the shape key and the anti-fatigue diff all exist for that reason, and the Plan — the
enumerated route a single approval releases — is meant to, once `plan.md` is built.

## Surfaces

| Surface | How it is reached |
|---|---|
| **MCP** | **`approve_request`** — an ordinary tool call carrying the request ID, the plan hash being answered, the verdict, an asserted approver identity, and an optional reason. It is the in-band decision path today, and the one every MCP client has been able to make since 2024-11-05 (AP-15, ADR-0029). **MRTR elicitation** — a second envelope over the *same* single guarded decision seam (ADR-0029 decisions 5 and 6): the gated `tools/call` answers with an input-required result carrying a Relay-authored approval question, and the client retries the call carrying the answer. Designed, not built — AP-60 … AP-71. Which response a gated call receives when a client supports both MRTR and the MCP task handle is settled here by AP-71: a park that emitted a question emits no task envelope. |
| **Control API** | `GET /api/v1/approvals`, `GET /api/v1/approvals/{id}`, `POST /api/v1/approvals/{id}/decision` — the out-of-band decision endpoint; grant management under `/api/v1/approval-grants`. |
| **Admin Console** | The approval queue — triage, the request detail, the anti-fatigue diff against the last approval of the same shape, and deciding from the Console under step-up (#435, #629). Bulk decisions are AP-59, designed and not built. The approval UI is where a human records a Decision and nothing else (AP-19); the Console's execution surface is `execution.md` (ADR-0026). |

Server-initiated elicitation (`elicitation/create` pushed over a stream) is **not** a surface: the
2026-07-28 protocol removed it, and emitting it would cost the MCP surface its stateless property
(ADR-0029). MRTR is the conformant form, and a tool call remains the one surface every MCP client
has had since 2024-11-05, which is why `approve_request` is the in-band path today (ADR-0029).

**This is the one capability where the surfaces genuinely differ**, and the difference is the
point rather than an inconsistency. A decision's *channel* is set by the surface that receives
it, not by the caller — see *Channel strength* below.

## Behaviour

### Where the gate sits

The approval gate runs inside the dispatch pipeline, after Selector resolution, authorization
and the blast-radius cap, and before any Task exists. `execution.md` owns that position and the
reasoning for it; this spec owns everything the gate then does.

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

AP-7 is today's truth and not the intent. AP-55 is the shipped default that closes it, and it is
**seeded into the store**, never shipped as a file: ADR-0027's amendment of `2026-09-16` declined
a root-owned file that seeds the store, because that is two sources for one setting. The default
it seeds:

| Request | Seeded requirement |
|---|---|
| `read`, any surface | No gate |
| `mutate`, any surface | Self-confirmation, in-band |
| Raw Exec, any surface | Self-confirmation, in-band |

Second-person audiences and out-of-band channel requirements are fully supported today; an
operator who wants them configures them. The seeded default simply will not demand them — and
since ADR-0040, **self-confirmation in-band is the only rung the shipped posture uses at all**.
The seed's content is unchanged by that decision; what changed is that it is no longer one
posture among several that ship.

**Why the seed is not a hole in invariant 11.** That invariant says a reach-bounding runtime
object is changed only by a human Account with step-up re-authentication, and AP-55's seed is one
audited act attributed to the system rather than to an Account. It is the single exception, it was
decided in exactly those words by ADR-0027's amendment of `2026-09-16`, and it is narrow in three
ways that the general rule is not: it uses **no credential**, so there is nothing for a stolen one
to reach; it fires **only** when the store holds no rules at all, and never again, so it cannot
overwrite an operator's rules or re-open a gate an `admin` closed; and it can only **add** gates,
which is the direction invariant 11 does not defend — the thing the invariant stops is a
credential *widening* reach, and the seed narrows it from "nothing is gated" (AP-7). Recorded here
so the question is not re-derived from the code later.

- **AP-8** A gate-rule file that is configured and **cannot be loaded refuses Relay startup**. The
  Relay never runs with nothing gated because a file is unreadable or malformed — a silent ungated
  start is the exact failure AP-55 exists to prevent. Startup refusal is `relay-configuration.md`.

Gate rules are a *reach-bounding* setting under invariant 11, not part of the security floor:
ADR-0027 (amended 2026-09-15/16) makes them a store-backed operator setting edited only by a human
`admin` in the Admin Console with step-up re-authentication, audited. That is AP-72 (#590), and
when it lands **AP-4, AP-8 and AP-54 retire with the file**: the store is the only source, no file
is read, and there is nothing left to fail to load. Until then AP-4 and AP-8 are what is built, and
that same ADR-0027 amendment orders this spec to describe the file behaviour as current.

### The confirmation ladder

The three rungs are ADR-0027 decision 5's, named as `GLOSSARY.md` defines them: **no gate**,
**self-confirmation**, **second-person**. "Confirmation" unqualified names none of them.

**No shipped or seeded rule demands `out-of-band`, and none sets a second-person rung.** Since
ADR-0040 the shipped posture uses one rung — self-confirmation, in-band — so the channel
machinery below (AP-12, AP-13, AP-14, and the weak-channel refusal AP-47) is present, correct and
**unexercised**: an operator who writes a rule reaches all of it, and nothing Relay ships does.
That is a decision about the shipped configuration, not about the code, and it is explicitly
interim; what it gives up, and what would bring it back, is `approval-assurance.md`.

- **AP-9** A gate rule selects one of three rungs: **no gate** — below thresholds, runs
  immediately; **self-confirmation** — the request is confirmed by the requester's side; and
  **second-person** — the audience excludes the requester. For a human on the Control API or
  Console, self-confirmation is the requester reviewing what Relay rendered and confirming; for an
  MCP request it is an **in-band** answer.
- **AP-10** An MCP in-band answer carries the client's asserted approver identity, and Relay
  records it as an **assertion** (ADR-0029) — never as something it verified.

Rung selection turns on a point ADR-0027 states outright: **MCP-originated calls are agent-grade
regardless of whose OAuth identity authorizes the session.** Session authorization is not
per-call human intent — the calls are still model-generated, and the session is steerable by
prompt injection in content the model read.

- **AP-11** A machine Account cannot decide its own request *on its own authority*. The one
  relaxation is ADR-0029's: an in-band answer carrying an asserted approver identity is accepted
  as self-confirmation, recording what the client claims without pretending Relay verified it.

Under the default AP-55 seeds, that relaxation becomes the default path for MCP mutations — so
self-confirmation for an agent-grade request rests on the client, and an operator who needs
evidence rather than an assertion raises the rule to second-person or out-of-band. See *Accepted
residual risk*.

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

The honest framing, and the reason both exist: **in-band is an assumption about the client;
out-of-band is evidence.** `in-band` means the tool-call answer *is* the decision — zero friction,
and it trusts the harness, because the requesting harness holds that session's credential.
`out-of-band` means the decision must land on the authenticated decision endpoint, carrying a
credential the AI-agent session does not hold.

### Two decision paths

A decision reaches Relay by one of two paths, and they exist side by side because they reach
different people.

**MCP is the approved pathway** for agent-originated approval (ADR-0040, as amended
`2026-09-25`): the tool text, the runbook and operator guidance name it, and Gleipnir is where the
human is expected to answer. The out-of-band path — the Console and the Control API decision
endpoint — works, decides any parked request whichever surface created it, and is **not relied
on**. It is the rescue, not the route: nothing Relay ships should direct a human there for
agent-originated work, and nothing refuses a human who arrives there anyway. **Today the product
does not yet say so**: the MCP park result's decision path, its schema text and the webhook
payload all still name the Relay decision endpoint. Bringing them in line is open work — see *Open
questions* — and until it lands, the approved pathway is the owner's posture and ADR-0040's, not
yet the product's own text.

- **AP-15** **In-band, through the requesting client.** Relay authors the question; the client puts
  it in front of a human and returns the answer over its own session. `approve_request` is that
  call: it carries the request ID, the plan hash being answered, the verdict, an asserted approver
  identity and an optional reason, and it records a Decision.
- **AP-16** **Out-of-band, on Relay itself.** The Console or the Control API decision endpoint,
  under a per-person Account; a Console decision re-authenticates at the moment of deciding
  (step-up), before the decision is taken.
- **AP-17** Both paths record into the same decision model, and the audit entry carries the answer
  and the channel. What differs is which lane carries the approver: out-of-band the deciding
  Account *is* the approver and is verified, while in-band the verified lane holds the Account that
  relayed the answer and the human is an assertion beside it (AP-39). Either is a full approval
  path: a rule set to `in-band` is satisfied by either. They are not of equal **strength**: AP-13
  still holds, so a rule set to `out-of-band` is satisfied by the second path only.
- **AP-18** A decision never arrives by any route but these two. **Relay integrates no chat or
  paging system**; its only outbound notice is the best-effort webhook (*Notification*), which
  carries no answer back.

In-band is the path that reaches an on-call human wherever they are, because Relay is expected to
sit behind a firewall that on-call people cannot easily cross, while the client — Gleipnir routing
to its on-call audience, or an operator's own harness — already can. **How the client reaches the
human is the client's concern**, and it is expected to keep the rule ADR-0027 states for
Gleipnir's handler: *"a deterministic path to the assigned human audience — never surfaced to the
LLM, never auto-answered."* ADR-0027 does not bind Gleipnir or any other client; Relay cannot
enforce it. Out-of-band is the path for anyone who can reach Relay directly, and the only one
whose approver Relay verifies.

- **AP-19** The Console's approval UI records Decisions and does nothing else, and it decides
  **ordinary parked dispatch requests only, never an approval grant**: a grant-shaped request
  renders its Scope and its released Jobs but no decision control at all, and is answered on the
  Control API. For what it does decide, it shows the pending queue, the request's Relay-authored
  rendering and exact Nodes, and the anti-fatigue diff, and it approves or denies. It never edits
  a request before deciding it — the approver decides exactly what was asked or nothing — and
  nothing is dispatched from it:
  a release proceeds as any other release does (*Deciding*).

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

ADR-0038 generalises that address to a route: a **Plan** whose hash covers several ordered steps
as well as the resolved set. A single gated dispatch is the one-step case, and it is the only case
that exists today — a Job carries exactly one Stage and one Action. The rest of the route
generalisation — each `mutate` step parking at advance for its own approval, and a Node that has
*left* the set being recorded as shrinkage rather than drift — is `plan.md`'s, and none of it
exists in code. See *Future work*.

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

### Plans first; approval grants as the narrow exception

**Plans are the default tool for work that can be enumerated in advance** — the human sees every
step and the exact Nodes, and nothing runs that was not shown (`plan.md`).

An **approval grant** is standing authorization over a bounded **Scope**, for open-ended work that
cannot be enumerated — *"keep restarting whatever falls over on the web tier for the next hour."*
It exists because approval fatigue is a security failure, not a UX complaint: without it, that
work becomes a stream of single approvals that invites rubber-stamping or loosened gate files. It
is deliberately small and conspicuous.

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

AP-30 and AP-31 are today's truth and not the intent: the first pass the owner settled on
`2026-09-14` went unwritten for ten days, became ADR-0027's amendment of `2026-09-24`, and
is AP-56 and AP-57, which retire them. **AP-32 has no Designed counterpart any more.** The
third bound of that pass — a grant issued only by second-person, out-of-band approval — was
AP-58 until ADR-0040 shelved it the same day; it is in `approval-assurance.md` with its
reasoning, and AP-32 stands alone as what is true and expected to stay true for the interim.
The other two bounds did not move with it: neither depends on who may answer or on which
surface.

Four rules govern a grant, and each closes a way the mechanism could invert. The first is a
structural statement rather than a claim about a code path, and it is the one worth keeping in
prose: **a Scope is not a Match.** A gate rule's `Match` says *when approval is required*; a
grant's Scope says *what standing authorization covers*. Reusing one for the other inverts the
mechanism. The other three are claims — and the second of them is that **requesting a grant is
not being granted one**.

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
is a guarantee rather than a delivery convenience"*, which is easy to misread as a delivery
guarantee. It is not, and AP-38 is not a weakening of it. What is always available is the
**authenticated decision endpoint** — an approver who can reach Relay can always decide, with no
envelope in the path. The POST that tells them to go and look is a convenience like any other, and
the only one Relay makes; a park that nobody was notified of is still in the queue, still
decidable, and still expiring on its own clock.

### Attribution

- **AP-39** Every gated dispatch and every Decision records in two structurally distinct lanes,
  and **the asserted approver never enters the verified one**:

| Lane | What it holds |
|---|---|
| **verified** | The Account the Relay authenticated from the credential presented — the requester on a dispatch, the decider on a Decision, recorded with the decision's channel and the plan hash it answered. It holds the Account whose credential made the call and nothing else, in-band and out-of-band alike. |
| **asserted** | What the caller *claimed*: the `on_behalf_of` identity, bounded and stored verbatim. An in-band approver identity is recorded **here and only here**. |

- **AP-40** The audit **schema** keeps the lanes apart, not the renderer, and a surface that
  renders both renders them as separately labelled trust chips rather than as one approver.

There is no third, blended field. An in-band approval does not produce a record naming the
asserted human as the approving Account; it produces a verified record of the machine Account that
relayed the answer, beside an assertion about who authored it. A jailbroken AI-agent can assert
anything and forge nothing. An auditor can always separate *"a human authenticated to Relay and
approved this"* from *"a client told us a human approved this"* — and collapsing that distinction
would buy simplicity by making the trail claim more than Relay knows. Once AP-55 seeds its default,
most MCP approvals will be the second kind, and the trail will say so.

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

- **ADR-0040, as amended `2026-09-25`** — MCP is the approved pathway for agent-originated
  approval, and out-of-band as a rule *requirement* is shelved. **Explicitly interim**,
  pending the permissions rework (#716). Its original strict separation — the surface that
  created a request is the surface that answers it — was **withdrawn before any of it was
  built**, for the availability cost it had not named, and its three claims are retired. The
  Console and the Control API keep deciding any parked request and are not relied on. What the
  relied-on path gives up — a Relay-verified approver for agent-originated work — is stated in
  *Accepted residual risk* and in threat model R21 and R26; what is shelved is
  `approval-assurance.md`.
- **ADR-0027, as amended 2026-08-14 through 2026-09-24.** The callout, the ladder, channel
  strength, plan-hash binding, expiry, quorum, the attribution triple, and approval grants remain
  its decisions. Several of its amendments are recorded intent that the code does not yet carry,
  and each is a Designed claim here rather than a description of today: gate rules as a
  store-backed, Console-edited operator setting (2026-09-15, AP-72), the default seeded into that
  store on first boot (2026-09-16, AP-55), and two of the three grant bounds (2026-09-24, AP-56
  and AP-57 — the third, grant issuance, is shelved by ADR-0040).
  The `2026-09-16` amendment is also what orders this spec to describe the file behaviour as
  current until AP-72 lands, which is why AP-4, AP-8 and AP-54 read as they do. It carries no
  figure for pending-request expiry; the 1-hour default recorded in this spec's `2026-09-14`
  History line was never built, and AP-25 states the 4 hours the code applies. Namespace pinning is
  genuinely gone (AP-33). Its decision 8's word *Plan* is read through the `2026-09-20` amendment
  as the rendered preflight (AP-20), and decision 1's "a gated Job parks" through ADR-0028's
  `2026-08-17` amendment and the correction of `2026-09-24`: parking creates no Job (AP-2).
- **ADR-0029** — in-band approval as a tool call, the asserted approver, the single guarded
  decision seam (decision 5), and MRTR elicitation as the second envelope over the same decision
  path (decision 6, AP-60 … AP-71). Under AP-55 the in-band relaxation becomes the default path
  for MCP mutations, which is the case ADR-0029's own text flagged as worth revisiting; the owner
  accepted it knowingly.
- **ADR-0038** — the plan hash covers a route; the derived requirement is priced over every step.
  Both halves are ahead of the code (AP-22, AP-35), because no route object exists.
- **ADR-0028** — the MCP task handle and the `tasks/update` boundary. Its amendment of
  `2026-09-24` is what AP-60 and AP-71 stand on: the boundary's old premise (Relay emits no
  `inputRequests`) is replaced by the precedence decision, and the unconditional result rewrite
  gains the carve-out AP-71 needs. Without that amendment neither claim could be built.
- **Invariant 3** (deny-beats-allow) — a denial is terminal and a stricter rule wins a merge
  (AP-27).
- **Invariant 4** (at-most-once) — a released decision mints one Job; the re-attach branch of
  AP-67 is the answer for a retried in-band approval, and the concurrent-retry window is an
  accepted residual risk.
- **Invariant 5** — a grant releases an approval requirement, never the blast cap (AP-37).
- **Invariant 7** — the plan hash binds the resolved set by identity, which is what stops a Node
  forging its own `node:` labels from electing itself into approved work (AP-22).
- **Invariant 10** — the decision path is the capability layer's; a surface records a channel
  and renders a queue, and decides nothing (AP-12, AP-19).
- **Invariant 11** — gate configuration is *reach-bounding*, not security floor: unreachable from
  any API, and it **narrows only** (AP-5, AP-6). Root-owned on the host today (AP-4); a runtime
  object a human `admin` edits in the Console with step-up and audit under AP-72. The webhook's
  URL, secret file and timeout stay security floor either way (`relay-configuration.md`).

## Seams and proof

Gate configuration is loaded once at startup from an optional root-owned file (store-backed rules
are designed, not built — #590). The approval domain holds the gate, the grant, the plan hash and
the shape key, and its imports are pinned narrow by test (`TestApprovalImportsStayNarrow`). The
capability layer owns parking, deciding and claiming; the surfaces hold neither. `make verify`
covers every row below; the end-to-end rows additionally need `make test-integration`.

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
| AP-10 | `TestMachineCannotConfirmItself` | approval |
| AP-11 | `TestApprovalCallout_MachineCannotSatisfyItsOwnGate`, `TestMachineCannotConfirmItself` | e2e, approval |
| AP-12 | `TestDecideApproval_BodyCannotNameAChannel` | API |
| AP-13 | `TestStrongChannelSatisfiesAWeakerRule`, `TestAssertedApproverDoesNotWeakenAnOutOfBandRule` | approval |
| AP-14 | `TestUnstatedChannelDefaultsToOutOfBand` | approval |
| AP-16 | `TestDecide_StepUpHappensBeforeTheDecision`, `TestApprovalCallout_ConsoleDecideRun` | Console, e2e |
| AP-17 | `TestDecideApprovalAuditEntryCarriesTheAnswerAndChannel`, `TestApprovalCallout_ConsoleDecideRun` | capability, e2e |
| AP-19 | `TestApprovalCallout_ConsoleDecideRun` | e2e |
| AP-20 | `TestApprovedPlanDispatchesAndBindsTheJob`, `TestDecisionMustCiteTheRequestsPlanHash` | capability |
| AP-21 | `TestRegistryDriftReParksAnApprovedPlan` | capability |
| AP-22 | `TestRegistryDriftReParksAnApprovedPlan` | capability |
| AP-23 | `TestShapeKeyIsStableAcrossRuns` | approval |
| AP-24 | `TestSameShapeDifferentPlanStillParks` | capability |
| AP-25 | `TestExpiredRequestIsNotDecidableOrSatisfiable` | approval |
| AP-26 | `TestApprovalCallout_ParkDecideRun` | e2e |
| AP-27 | `TestDenyIsTerminalAndBeatsApproval`, `TestDenialIsTerminalAndAudited` | approval |
| AP-73 | `TestQuorumNeedsDistinctDeciders`, `TestRecordDecisionPersistsQuorumProgress`, `TestBlankAudienceEntryCannotPadPastQuorumCheck`, `TestDecide_PartialQuorumNamesWhoSigned` | approval, capability, Console |
| AP-28 | `TestDecideApprovalDoesNotDispatch`, `TestApprovalCallout_ParkDecideRun` | capability, e2e |
| AP-29 | `TestGrantDoesNotCoverOutsideItsScope`, `TestRawExecIsASeparateOptIn` | approval |
| AP-30 | `TestRawExecIsASeparateOptIn` | approval |
| AP-33 | `TestCreateGrant_RefusesTheRetiredSelectorNamespace` | API |
| AP-34 | `TestApprovalGrant_RequesterCannotApproveTheirOwnWindow` | e2e |
| AP-35 | `TestRequestGrantDerivesTheStrictestRequirement` | capability |
| AP-37 | `TestGrantIsConsultedOnlyAfterTheGate`, `TestGrantNeverBypassesTheBlastCap`, `TestExhaustedGrantParksAgain`, `TestRevokedGrantCoversNothing`, `TestUncoveredDispatchStillParks`, `TestApprovalGrant_RevokeClosesTheWindowImmediately` | capability, approval, e2e |
| AP-38 | `TestARefusingEndpointIsSurvivable`, `TestNotifyParkedDoesNotBlock` | approval |
| AP-40 | `TestAttribution_LanesAreStructurallySeparate` | capability |
| AP-41 | `TestRedriveAuditsPendingObservedNotRequested` | capability |
| AP-42 | `TestExpiredRequestIsNotDecidableOrSatisfiable` | approval |
| AP-43 | `TestRequesterCannotApproveOwnRequest`, `TestApprovalGrant_RequesterCannotApproveTheirOwnWindow` | approval, e2e |
| AP-44 | `TestAudienceIsEnforced` | approval |
| AP-46 | `TestDecisionMustCiteTheRequestsPlanHash` | capability |
| AP-47 | `TestWeakChannelIsRefused`, `TestWeakChannelIsRefusedForDenialsToo` | approval |
| AP-48 | `TestApprovalCallout_MachineCannotSatisfyItsOwnGate`, `TestMachineCannotConfirmItself` | e2e, approval |
| AP-49 | `TestApprovalCallout_OperatorCannotReleaseARawExec`, `TestDecisionRoleFloorUsesTheParkedActionKind`, `TestDecisionRefusedByRoleFloorRecordsNothing` | e2e, capability |
| AP-50 | `TestRequestGrantRefusesWhenNothingIsGated` | capability |
| AP-51 | `TestRequestGrantRefusesUnboundedScopes`, `TestEveryScopeBoundIsRequired` | capability, approval |
| AP-52 | `TestCreateGrant_RefusesTheRetiredSelectorNamespace` | API |
| AP-54 | `TestLoadFailsClosed` | approval |

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
- **AP-19**, grant half — `TestApprovalCallout_ConsoleDecideRun` proves the decide-and-run path,
  not the carve-out. That a grant-shaped request renders no decision control at all, and is
  answered only on the Control API, is an unchecked box on the Console screen's own specification
  and nothing asserts it here.
- **AP-31**, **AP-53** — the 24-hour cap and its refusal exist in code; no test names the cap.
- **AP-32** — that a one-approval in-band grant is representable is the *absence* of a floor.
  Nothing asserts an absence.
- **AP-36** — the claim is enforced by a conditional update inside one transaction; no test races
  two claims against one grant.
- **AP-39** — the two lanes are proven structurally separate (AP-40), but **no end-to-end test
  drives `approve_request` and then checks the two columns**: that the verified lane holds the
  calling Account and never the asserted string, and that the asserted approver reached
  `on_behalf_of` and nowhere else. The claim that matters most here is the one nothing walks.
- **AP-45** — the duplicate-decider sentinel exists; no test names it.
- **AP-12**, surface half — the Control API is proven not to take a channel from the body; MCP and
  the Console are not asserted the same way.
- **AP-38**, guarantee half — the webhook's best-effort behaviour is proven; that a park
  nobody was notified of is still decidable rests on the decision endpoint's own tests, not
  on one that drops the notice and then decides.

`TestEmptyGateGatesNothing` and `TestEmptyPathMeansNoGates` prove the engine's behaviour for an
empty rule set and an unconfigured path — which is exactly AP-7's ungated fresh install. The
seeded default that replaces it (AP-55) has nothing to prove yet.

### Performance

| Characteristic | Contract | Measured by |
|---|---|---|
| Approval grant window | Bounded by a hard cap; every Scope bound required (AP-31, AP-51) | *(none)* |
| Approval queue | Paged; the anti-fatigue diff is one shape-key lookup, never a scan | *(none)* |
| Parked requests | Expire on an operator-set TTL (default 4 hours) and are swept | *(none)* |

There are no benchmarks in this repository. The shape key exists specifically so the queue's
diff is a lookup rather than a scan, and nothing measures that it stays one.

## Designed, not built

| Claim | Statement | Milestone |
|---|---|---|
| AP-55 | A Relay whose store holds no gate rules at first start **seeds the shipped default** — `read` ungated, `mutate` and Raw Exec at self-confirmation in-band, with second-person and out-of-band available to raise any rule to — as one audited act attributed to the system and not to an Account. After that the store is the only source: no file is read, and the Relay does not re-seed on a later start. Retires AP-7; depends on AP-72. (ADR-0027 §Amendment 2026-09-16, which declined a root-owned file seeding the store as two sources for one setting; #590.) | v0.7.0 — Admin Console: Administration & Execution |
| AP-56 | An approval grant never covers Raw Exec: every Raw Exec needs its own decision, alone or within a bulk act, and a Scope naming Raw Exec is refused. Retires AP-30. (ADR-0027 §Amendment 2026-09-24.) | v0.6.5 — Install Path: relay init, join string, packages |
| AP-57 | An approval grant's window is capped at 4 hours, and a longer one is refused. Retires AP-31 and narrows AP-53. (ADR-0027 §Amendment 2026-09-24.) | v0.6.5 — Install Path: relay init, join string, packages |
| AP-59 | The Console may approve or deny several pending requests in one act, Raw Exec included. A bulk decision is a set of individual Decisions made together, never a new kind and never an approval grant: each request is answered against its own plan hash, checked against every rule in *Deciding*, and audited as its own Decision, and one refused request does not carry the others with it. One step-up re-authentication covers the whole act, entered immediately before it is submitted, and approval grant requests are excluded. | v0.7.0 — Admin Console: Administration & Execution |
| AP-60 | A gated dispatch that parks under an in-band rule, from a client that can be asked, is answered with an approval **question** carrying the Relay-authored summary, the request ID and the plan hash — and leaves no Job and no Tasks behind, exactly as a park does today (AP-2). | v0.7.0 — Admin Console: Administration & Execution |
| AP-61 | A question is emitted only where an answer from that caller could be **accepted**: the rule's channel is in-band, the rule does not exclude the requester, and its audience admits the calling Account. Otherwise the park renders as today's `pending_approval`. | v0.7.0 — Admin Console: Administration & Execution |
| AP-62 | A question is emitted only for a park this call **created**; a re-drive that bounces off a request already pending re-pages nobody (AP-41). | v0.7.0 — Admin Console: Administration & Execution |
| AP-63 | An answer carried on the retried call records **the same Decision** as `approve_request`, into the same two lanes (AP-39): the in-band channel, the verified Account whose credential made the call, the responder identity recorded as an assertion, and the same refusals (AP-42 … AP-49). | v0.7.0 — Admin Console: Administration & Execution |
| AP-64 | An answer is accepted as a decision only when it carries a **responder assertion**; an answer without one is machine-originated and is refused exactly as an `approve_request` carrying no approver is refused (AP-48). | v0.7.0 — Admin Console: Administration & Execution |
| AP-65 | The state a client echoes back is **sealed and bound** to the caller, the request, the plan and the call; a tampered, cross-request, cross-account, wrong-call or expired one is refused. | v0.7.0 — Admin Console: Administration & Execution |
| AP-66 | An approving retry **re-enters the whole dispatch pipeline** — Freeze, resolution, authorization, the cap and the plan-hash match — and a changed Node set re-parks and asks again rather than running against a set nobody approved (AP-21). | v0.7.0 — Admin Console: Administration & Execution |
| AP-67 | A retry whose decision has already released a Job **re-attaches** to that Job and mints no second one. | v0.7.0 — Admin Console: Administration & Execution |
| AP-68 | A denial on the retry is **terminal and audited**, and nothing is dispatched (AP-27). | v0.7.0 — Admin Console: Administration & Execution |
| AP-69 | An `out-of-band` rule yields **no answerable question**, on any client: the envelope a park is rendered in never weakens the channel the rule demands (AP-13). | v0.7.0 — Admin Console: Administration & Execution |
| AP-70 | A client that cannot be asked sees **no change**: `pending_approval`, `approve_request` and the Control API decision endpoint all behave exactly as before. | v0.7.0 — Admin Console: Administration & Execution |
| AP-71 | A park that emitted a question emits **no MCP task envelope**. (ADR-0028 §Amendment 2026-09-24 carves this out of the shim's otherwise unconditional result rewrite.) | v0.7.0 — Admin Console: Administration & Execution |
| AP-72 | Gate rules are runtime objects in the Relay's store, edited only by a human `admin` in the Admin Console with step-up re-authentication, audited per rule with old and new values, and taking effect on the next dispatch; no MCP tool and no Control API route writes them, and none may be added. Retires AP-4, AP-8 and AP-54 — the store is the only source, no file is read, and there is nothing left to fail to load. (ADR-0027 §Amendment 2026-09-15; #590, #596.) | v0.7.0 — Admin Console: Administration & Execution |

## Out of scope

- **Where the gate sits in the dispatch pipeline, and what a park leaves behind** —
  `execution.md`.
- **The Plan a decision releases** — `plan.md`: the ordered steps, the cursor, the payload-free
  advance, and the walls on an approved-but-incomplete route. A Plan, and each of its `mutate`
  steps, parks through *this* gate and is answered by an ordinary Approval, exactly as a request
  for an approval grant is; it is deliberately not a second decision surface. None of it exists in
  code (*Future work*).
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
  person Relay authenticated. Each is kept there with the argument that was made for it, so
  the permissions rework argues with the reasoning rather than with a summary of it. None of
  it is a claim, none of it has a milestone, and none of it may be cited here as a
  requirement (ADR-0040).

## Accepted residual risk

- **Overlapping rules union their approvers.** When a dispatch or a grant matches several gate
  rules, anyone in any matching rule's audience may approve, and a matching rule with no audience
  makes it anyone at all. A `relay:` rule reserved for one approver can therefore be decided by
  another rule's approver when a Selector also matches that rule. Count, channel, requester
  exclusion and window still take the strictest. Accepted by the owner on `2026-09-16` (ADR-0027
  amendment; threat model R18) as a stage-appropriate simplification; the improvement is Future
  work below.
- **A fresh install gates nothing at all (AP-7).** Packaging ships no gate rules and configures no
  path, so until an operator writes a file every `mutate` and every Raw Exec runs unapproved. This
  is strictly larger than the risk below it: not "the gate is only as strong as the client" but
  "there is no gate". Bounded only by Relay-side authorization, the blast cap and Node Policy —
  none of which is a human in the loop. Accepted as a stage, not as a posture: AP-55 and AP-72
  close it, and the seeded default is what the next risk then describes. Threat model **R23**.
- **Once AP-55 seeds its default, a prompt-injected AI-agent session can approve its own
  mutation.** A self-confirmation answer in-band is an assertion by the client, and the session
  asking is the session answering. A fresh install's gate is therefore only as strong as the
  client. The trail records the approver as asserted, never verified (AP-39), and an operator who
  needs evidence raises the rule to second-person or out-of-band. Stated to the owner and accepted
  on `2026-09-14`. Threat model **R21**.
- **The relied-on path for agent-originated work records an assertion, never a verified
  approver.** Before ADR-0040 an operator who wanted evidence raised the rule to `out-of-band`
  and got an approver Relay authenticated. That option is still in the code and is no longer
  in the shipped posture: no shipped or seeded rule demands a channel, and MCP is the approved
  pathway, so the approval Relay is *designed around* for agent-originated work is the
  client's. For that path the audit trail answers *"a client told us a human approved this"*
  and cannot answer *"a human authenticated to Relay approved this"*. A verified approver is
  still **reachable** — the Console and the Control API decide any request, as amended
  `2026-09-25` — but nothing directs a human there, so it is the rescue rather than a control.
  Accepted by the owner on `2026-09-24` as **interim**, pending the permissions rework, on
  four grounds ADR-0040 records: the client is where the human already is, behind a firewall
  Relay sits the far side of; Gleipnir enforces its own approver role check server-side and
  stamps the responder from an authenticated session, so the assertion is backed by an
  authentication *somebody* performed; the alternative in practice was an approval nobody
  answered; and one permission model is a prerequisite for a good one. Bounded by everything
  an approval never was: Relay-side authorization on who may request, the blast cap, the
  plan-hash binding, drift re-parking, and Node Policy, which no approval has ever been able
  to lower. Threat model **R21** and **R26**; what is shelved, and what would bring it back,
  is `approval-assurance.md`.
- **An in-band approval is only as honest as the client's path to the human.** Behind a firewall,
  in-band is expected to be the everyday path, so for `in-band` rules the guarantee that a human
  decided rests on the client — Gleipnir's HIL router, or an operator's harness — keeping
  ADR-0027's rule. Relay records such an approver as asserted and cannot detect an auto-answer.
  **The same acceptance covers AP-64's responder assertion**: a responder assertion on an MRTR
  answer is a claim by the client that a human, and not the model, produced it. Relay checks that
  the assertion is present and bound (AP-65); it cannot check that it is true, and a client that
  auto-answers its own question is indistinguishable from one that asked a person. An operator who
  needs evidence sets the rule to `out-of-band`. Accepted by the owner on `2026-09-18` (threat
  model R21) and extended to the responder assertion on `2026-09-24`.
- **A released approval can dispatch again on any later re-drive (#713).** An approval is not
  used up when it releases a Job: until it expires, any later call matching the approved plan
  passes the gate and mints a second Job, overwriting the audit join. **The ordinary trigger is
  not a race:** an approved Job slower than the client's per-call timeout, after which the model
  re-drives the same call with no request state. AP-67's re-attach covers only a retry carrying
  sealed request state, so it does not close that trigger; two concurrent retries in the gap
  between decision and binding are the narrow case of the same defect. The daemon's Task-ID
  dedup — the actual subject of invariant 4 — is untouched, so no Node executes the same Task
  twice, but the fleet can see one approved plan run twice. Accepted by the owner on
  `2026-09-24`; on `2026-09-25` deferred until after #646, with the likelihood corrected by the
  v0.7.0 design review. Until it is fixed, demo commands should finish well inside the per-call
  timeout. Threat model **R24**.
- **Bulk approve can rubber-stamp (AP-59).** Approving many requests in one act, Raw Exec
  included, is the approval-fatigue pattern this capability's Purpose names, and one step-up
  covers the whole act: a hijacked human Console session plus that Account's password could
  release every pending request it is eligible to decide, Raw Exec included, at once. Bounded by
  each request still binding to its own plan hash and passing every decision check individually,
  by the audience and role floor, by approval grant requests being excluded, and by the audit
  recording each Decision separately. Accepted by the owner on `2026-09-18` (threat model R22),
  with bounding by shape key, excluding Raw Exec, or a step-up per request left as Future work.
- **An approval grant hands the AI-agent choice within its Scope.** Inside a grant, the AI-agent
  picks which covered Operations to run on which Nodes, so a steered session can use a legitimate
  grant for actions nobody intended. Bounded by the Scope, the window, the blast cap and Node
  Policy — and, once AP-56 and AP-57 land, by the exclusion of Raw Exec and the 4-hour cap. Until
  then the bound is a 24-hour window (AP-31) over a Scope that may opt into Raw Exec (AP-30): a
  standing, agent-choosable authorization over an arbitrary command, for a day. Threat model
  **R25**.

## Future work

Wanted, deliberately not in the first pass. Named so each is neither re-litigated nor lost;
none is a commitment to an order.

- **Removing Console approval, so that MCP is the only approval path.** The owner's stated
  intent on `2026-09-25` — *"I eventually want to potentially remove the entire console
  approve thing"* — recorded in ADR-0040's amendment of that date as where the
  approved-pathway posture is heading. **An intent, not a decision**: nothing is removed, and
  no claim below is retired or reworded for it. If taken, it would retire **AP-16**'s Console
  half and **AP-19**, both built, and **AP-59** (bulk decisions), which is Designed at v0.7.0
  and would then never be built or would be retired soon after. The intent names the Console;
  whether the Control API decision endpoint — AP-16's other half — goes with it is not stated
  and would have to be decided. It **waits on #646 being proven in use**, and on the restart
  risk (`approval-assurance.md`; threat model R27) being closed first, because the Console is
  today the only thing that makes a stranded request decidable. Taking it is its own ADR.

- **Multi-step Plan routes, and everything that follows from them** — `plan.md`, which states that
  none of it exists in code. A Plan whose hash covers an ordered route rather than a single
  dispatch; **each `mutate` step parking at advance for its own approval**, bound to the Plan hash
  and that step, so that approving a Plan releases its route as context and not its mutations;
  **shrinkage recorded** — a Node that has *left* the approved set dropped from that step and
  recorded, rather than treated as drift; and **an approval grant never releasing a route**,
  because a grant is described and a Plan is enumerated, and letting the first release the second
  would amplify a grant's use limit N-fold while ensuring no human ever saw the route. All four are
  vacuous today: there is no route object to approve, advance, shrink or release. No milestone, no
  issues.
- **Approver audiences that cannot be widened by overlap.** Replace the union of matching rules'
  audiences (*Accepted residual risk*) with one of two models, decided at pickup: **intersection**,
  refusing a dispatch or grant whose intersection is empty and naming the conflicting rules; or a
  **per-rule quorum**, where every matching rule's audience must be satisfied and one approver in
  several audiences can satisfy them together. Surfaced by #602's security review; ADR-0027
  amendment of `2026-09-16`.
- **Quorum beyond `count: 1 | 2`** — N-of-M, and per-audience rather than per-request counts.
  Two-person release itself is not future work: AP-73 is built, and ADR-0027 decision 7 stored the
  general requirement-versus-decisions shape precisely so richer matching lands as a config-language
  change with no data migration. What is future is the config language, and out-of-band
  requirements practical enough to become the default for agent-grade mutations.
- **Retiring `approve_request`.** The owner's intent is that it may be retired once MRTR
  elicitation is usable from the clients Relay is driven by, which first requires those clients to
  negotiate the 2026-07-28 protocol. Not decided here: it needs an ADR-0029 amendment first
  (decisions 1 and 5, and Consequences).
- **Bounding bulk approve** — by shape key, by excluding Raw Exec, or by a step-up per request —
  if unbounded bulk (AP-59) proves to invite rubber-stamping.
- **Namespace-pinned approval grants**, if ever re-added — only with pricing that cannot release
  work needing a stronger approval than the grant was issued under (the #482 defect class).

## Open questions

- **Does a release dispatch while the requester waits?** An out-of-band decision today releases a
  request that runs only when the requester re-drives it (AP-28). #643 proposes holding the gated
  call open for a bounded wait and dispatching on release, which would change AP-28. Undecided.
  AP-66 makes the re-drive automatic for in-band decisions; this question is about out-of-band
  ones. What would force it: an owner decision on #643, which cannot be built until it is made.
- **Which envelope a Tasks-capable client gets for a park that cannot be asked.** AP-71 settles
  the case where a question *was* emitted: no task envelope. It says nothing about a park under an
  `out-of-band` rule, or one whose audience excludes the caller, reaching a client that advertised
  the Tasks capability — today that park is rewritten into a task handle, and nothing here decides
  whether it should stay that way. `execution.md` states the rewrite unconditionally and is
  unmigrated. What would force it: the ADR-0028 amendment of `2026-09-24` carves out only the
  emitted-question case deliberately, so the remainder is settled when `execution.md` migrates or
  when #644 is picked up.

- **What the product's own text should say about where to answer.** ADR-0040 as amended makes
  MCP the approved pathway and names "the tool text, the runbook and operator guidance" as where
  that is said. Today three things say the opposite: the MCP park result's decision path, the
  schema text describing it, and the webhook payload, all of which point a human at the Relay
  decision endpoint. Whether each should name the client instead, name both with the client
  first, or be left as the rescue's address is not decided, and none of it has an issue. What would
  force it: the demo's approval beat, which is expected to happen in Gleipnir's UI while the
  webhook sends the human to the Console.

Deciding from the Console (#435) is in scope, not open. ADR-0028's stale `tasks/update` premise is
no longer open either: the amendment is drafted in this change.

## History

- `2026-09-25` — **Strict separation withdrawn; AP-74, AP-75 and AP-76 retired unbuilt.**
  Owner decision, one day after ADR-0040, in their words: *"The more we talk about it the more
  I doubt removing the console as approver. We don't want to rely on it though — we should
  have everything run through the MCP as that is the approved pathway. And the console
  approving / API is a complicating factor that shouldn't be used."* Asked to be precise, they
  chose: **the Console and the Control API keep working exactly as today — not enforced, not
  relied on.** The reason is the cost the original decision did not name, **availability**: an
  adversarial review of the v0.7.0 design plan found that under separation every path that
  used to end with "a human answers in the Console" ends with "wait for the TTL" — any rule
  stricter than self-confirmation in-band makes an MCP-originated request undecidable by any
  surface, because the askable predicate correctly declines to ask and the Console was closed;
  the demo gate fixture hits three such rules at once; the park result, its schema text and
  the webhook all point humans at a route that would have refused them; and the Console
  originates nothing until #438. **Nothing was built**, so there is no code to remove. The
  three IDs are retired and never reused; they are not reworded into something else, because
  "MCP is the approved pathway" is a posture — prose and ADR — and not a claim a test can be
  pointed at. **AP-70 stays**, and the contradiction it had with AP-75 — one saying the
  Control API decision endpoint behaves exactly as before for a client that cannot be asked,
  the other refusing that endpoint for the same request — is gone with AP-75. AP-16, AP-17 and
  AP-19 were true throughout and are untouched. One paragraph added where the two decision
  paths are introduced; the ADR-0040 bullet in *Governing ADRs* and the assertion entry in
  *Accepted residual risk* re-premised; every reference to the sequencing constraint removed
  from normative text. Two owner rulings of the same day are **recorded, not solved**, in
  `approval-assurance.md`: restarts strand an in-flight MRTR answer, and whether "answered
  over MCP" means any MCP Account or the exact client that asked. Threat model: R26
  re-premised, R23's narrowing undone, and a row added for the restart risk. ADR-0040 carries
  a dated amendment.

- `2026-09-24` — **Direction change, owner, same day: one answer path per origin, and out-of-band
  as a rule requirement is shelved.** Recorded as **ADR-0040**, explicitly interim pending a
  permissions rework. The owner's decision, in their words: *"For now I want Gleipnir to manage
  all the permissions and the only reason for Console or API to have approval permission is for us
  running a command from those tools."* Asked to be specific they chose **strict separation** over
  a permissive version — a request created over MCP is answerable only over MCP, and the Console
  and Control API decide only what they themselves originated — because a rule saying a request
  *may* be answered anywhere leaves two permission models live over one object and is not
  something a reviewer can check a diff against. New Designed claims **AP-74**, **AP-75** and
  **AP-76** at v0.7.0, each **blocked by #646**: the sequencing is load-bearing, not housekeeping.
  Today a Gleipnir-parked request is answered by a human in the Relay Console; enforce the
  separation before the MRTR round trip exists and the only remaining answer is an
  `approve_request` call Gleipnir does not make, so every gated dispatch would sit until it
  expired — the gate would become a denial of service delivered as a safety improvement.
  **AP-58 is removed from *Designed, not built*** and moves to the new `approval-assurance.md`
  stub with its reasoning; AP-32 now stands alone, and AP-56 and AP-57 do not move, because
  neither depends on who may answer. **AP-69 stays** — while the channel mechanism exists, a rule
  that sets `out-of-band` must not produce a park nobody can answer, which is precisely the
  failure the sequencing constraint warns about. **The built channel claims stay and stay true**
  (AP-12, AP-13, AP-14, AP-47): the code still does all of it, and a spec describes what the
  system does rather than what its shipped configuration exercises. One sentence added where the
  ladder is introduced saying no shipped or seeded rule demands out-of-band, and one on AP-55's
  seed confirming self-confirmation in-band is now the only rung the shipped posture uses. Threat
  model: **R21** re-premised from "most MCP approvals are asserted" to "every approval of
  agent-originated work is", **R23** loses a human deciding in the Console from its compensating
  controls for those requests, and **R26** is added for the separation itself. The demo runbook
  (`docs/operations/demo-fleet.md`) has its approval beat move from the Console to Gleipnir's UI;
  it is named as a consumer and left for whoever next walks it. *Superseded in part the next day
  by the `2026-09-25` entry above: strict separation is withdrawn, AP-74 … AP-76 are retired
  unbuilt, and the sequencing constraint and the R23 narrowing no longer apply. AP-58's move to
  the stub, AP-69, the channel claims and the ladder sentence all stand.*
- `2026-09-24` — **The shipped default is seeded into the store, not shipped as a file.** The
  migration draft made AP-55 a root-owned default gate file; ADR-0027's amendment of `2026-09-16`
  had already decided the opposite and explicitly declined a file that seeds the store, as two
  sources for one setting. AP-55 is rewritten to the seeding mechanism and moves to **v0.7.0**,
  matching #590, which builds it. The store-backed, Console-edited rules that amendment's
  predecessor decided were sitting in prose with no ID; they are now **AP-72**, v0.7.0, #590, and
  they are what retires AP-4, AP-8 and AP-54 — no file is read, so nothing is left to fail to
  load. AP-4 and AP-7 are unchanged: the same amendment orders this spec to describe today's file
  behaviour as current.
- `2026-09-24` — **The three grant bounds get an ADR.** The owner's decisions of `2026-09-14` —
  an approval grant's window capped at 4 hours, never covering Raw Exec, and issued only by
  second-person out-of-band approval — were never written into ADR-0027, so AP-56, AP-57 and AP-58
  were Designed claims resting on a History line. ADR-0027 gains an amendment of this date adopting
  all three and naming what each changes: the 24-hour ceiling in the `2026-08-16` amendment's
  decision 4, the "Raw Exec if opted in" pricing in its decision 3, and its decision 2's
  "exactly as a single dispatch" issuance. The three claims stay at v0.6.5 and now cite it.
- `2026-09-24` — **AP-39 corrected against ADR-0029, which was right.** The draft's attribution
  table carried an `approved_by` field that holds the asserted approver "for an in-band
  confirmation". There is no such field and no such blending: the verified lane always holds the
  Account whose credential made the call, and an asserted approver reaches only `on_behalf_of` and
  its audit column. AP-39 is rewritten as the two lanes with that rule stated outright, AP-40 gains
  the separate-trust-chips rendering, and AP-63 loses the same inherited wording. The proof-gap
  list now records that no end-to-end test drives `approve_request` and then checks the two
  columns — the claim that matters most here is the one nothing walks.
- `2026-09-24` — **Two ADR-0028 problems fixed in one amendment**, drafted in this change so that
  AP-60 and AP-71 have something to stand on: its `tasks/update` boundary rested on the premise
  that Relay emits no `inputRequests`, which AP-60 falsifies, and its result-rewrite rule ("when a
  dispatch parks *and* the client advertised the Tasks capability") had no carve-out for AP-71.
  The replacement premise is the precedence decision itself. ADR-0027 decision 1 also gains a
  one-line correction: it still said a gated Job parks and enters `pending-approval`, which
  ADR-0028's `2026-08-17` amendment had already contradicted (#269) and AP-2 states as a claim.
- `2026-09-24` — **Quorum gains a claim.** `count` is a live Requirement dimension and had no ID
  at all: **AP-73** states what it does today — `1` or `2`, distinct deciders, a partial quorum
  leaving the request pending with each decision its own audit record and the queue naming who
  signed — with proof rows from tests already in the tree. The Future-work item that listed
  two-person release as not in the first pass is narrowed to the config language beyond
  `count: 1 | 2`. Three smaller corrections from the same review: **AP-19** overstated the Console,
  which decides plan requests only and renders no decision control for an approval grant;
  **AP-20** was written in terms of a route object that does not exist and now reads as ADR-0027's
  `2026-09-20` amendment does, binding the rendered preflight; and **AP-53** and the Performance
  table no longer quote AP-57's future 4-hour value. Unqualified "Grant" — an `_Avoid_` term
  naming the authorization rule — is replaced by "approval grant" throughout. GLOSSARY gains
  *Confirmation ladder*, *Responder assertion* and *Sealed request state*, and its *Approval*,
  *Decision* and *MCP task handle* entries are corrected; the threat model's R21 is re-premised on
  AP-7 and AP-55, and R23, R24 and R25 are added.
- `2026-09-24` — **Pending-request expiry settled at 4 hours.** The `2026-09-14` session below
  recorded a 1-hour default; it was never built, and no ADR carries the figure — the ADR-0027
  citation drafted alongside this migration was wrong, and is the reason this line exists rather
  than an Open question. The owner ruled the 1-hour intent superseded: **AP-25** states 4 hours,
  operator-settable per rule, which is what the code does and what its tests pin. No ADR
  amendment is owed and no issue is opened.
- `2026-09-24` — Migrated to the claim format (AP-1 … AP-71; AP-72 and AP-73 were added later
  the same day by the entries above, so the range as merged is AP-1 … AP-73), from the drift
  verdicts of the (45 built, 13 unbuilt, 1 unclear). Owner decisions recorded here: **AP-3** is
  written as what is built — the approver sees the fan-out count and a capped sample of Node
  IDs, and the full resolved set is bound by the plan hash — not as a Designed claim.
  **AP-7** states today's truth, that packaging ships no gate file and a fresh install is
  therefore ungated, and the shipped default becomes **AP-55** ~~at v0.6.5~~ — *superseded the
  same day by the seeding entry above: AP-55 is a store seed, not a shipped file, and it is at
  v0.7.0.* **AP-25** states
  the pending-request expiry default as **4 hours**, operator-settable; this spec previously
  said 1 hour, which was never the code's default and which the owner has since ruled
  superseded (see the line above). The three grant bounds the code does not enforce become
  **AP-56**, **AP-57** and **AP-58** at v0.6.5, each paired with the built claim it retires:
  Raw Exec is coverable today by an explicit opt-in priced at the `admin` floor (**AP-30**),
  the hard window cap is 24 hours (**AP-31**), and issuance is priced by whatever the gate
  rules say, so a one-approval in-band grant is representable (**AP-32**). Bulk decisions
  are unbuilt and become **AP-59** at v0.7.0. Multi-step Plan routes, per-step `mutate`
  approvals, shrinkage recording and "a grant cannot release a route" move to *Future work*
  pointing at `plan.md`, with no milestone — none of it exists in code. **AP-29** is
  corrected to what is built: the window lives on the approval grant rather than inside the
  Scope,
  and the Scope carries a Raw Exec opt-in field. **AP-35**'s multi-step pricing half is
  stated as moot today, because a Job carries exactly one Stage and one Action. The startup
  refusal (**AP-8**, **AP-54**) is built, with the proof-gap list recording that no test
  drives the startup failure through the composition root.
- `2026-09-24` — Twelve Designed claims created for #646, MRTR in-band approval, at v0.7.0:
  **AP-60 … AP-71**, taken in substance from the merged design plan. A park under an in-band rule
  from a client that can be asked is answered with an approval question and still leaves no Job and
  no Tasks; a question is emitted only where an answer could be accepted and only for a park the
  call created; the answer records the same Decision as `approve_request`, only with a responder
  assertion, sealed and bound to the caller, request, plan and call; an approving retry re-enters
  the whole pipeline, re-attaches rather than minting a second Job, and re-parks on a changed Node
  set; a denial is terminal; an out-of-band rule yields no answerable question; a client that
  cannot be asked sees no change; and an elicited park emits no MCP task envelope. Two residual
  risks moved rather than added: the in-band-honesty entry (R21) now also covers the responder
  assertion, and the concurrent-retry race is recorded as a restatement of the pre-existing defect
  #713. ADR-0028's stale premise is raised as an Open question.
- `2026-09-18` — worked through with the owner. Two decision paths recorded: in-band through the
  requesting client (`approve_request`, and MRTR elicitation over the same guarded seam) and
  out-of-band on Relay (Console with step-up, Control API), reachable by different people because
  Relay is expected to sit behind a firewall. Retiring `approve_request` is intent only, pending an
  ADR-0029 amendment. Relay integrates no chat system. The Console's approval UI records Decisions
  only — no editing, no dispatch — and gains unbounded bulk decisions under one step-up, each
  answered and audited individually, excluding approval grant requests. Two residual risks
  accepted: in-band honesty rests on the client (R21), and bulk approve can rubber-stamp (R22).
  Held-call dispatch (#643) left open. MRTR implementation tracked separately.
- `2026-09-17` — a blank (empty or whitespace-only) audience entry is now refused, naming
  the rule and `require.audience`, when gate rules load, when an Approval grant is
  requested, when a dispatch parks, and when an approval Request is stored — nothing trims
  or drops an entry. A stored audience still carrying a blank entry (e.g. `"ana,"`) admits
  no decider, and merging audiences never lets an unrestricted side absorb a malformed one.
  Limit: a row an earlier build wrote from an audience of exactly `[""]` is stored
  identically to an unrestricted audience and still reads back unrestricted; a comma inside
  an entry is a separate, unfixed widening. Spec was still `aspirational`, unmigrated to
  claim IDs; evidence not recorded here (#608).
- `2026-09-16` — namespace pinning removed from approval-grant Scope in code: the Control
  API field and any MCP grant tool are gone, a request still naming it is refused with 400,
  a Grant's requirement is now derived over every namespace, and a stored pinned Grant covers
  nothing. Spec was still `aspirational`, unmigrated to claim IDs; evidence not recorded here
  (#482).
- `2026-09-14` — worked through with the owner. A default gate file ships: `read` ungated,
  `mutate` and Raw Exec at in-band confirmation, second-person and out-of-band kept and
  configurable. Approval grants stay but narrow — one Account, no namespace pinning, never Raw
  Exec, a 4-hour cap, issued only second-person out-of-band — with Plans the default for
  enumerable work. Pending requests expire after 1 hour by default. #482 is resolved in intent by
  removing namespace pinning; the in-band relaxation question is settled by making it the default
  path, with the self-approval risk accepted. Confirmed after drafting: the Relay refuses to start
  without a loadable gate-rule file. Aligned with `plan.md`: each `mutate` step of an approved
  Plan parks for its own approval bound to the Plan hash and step.
- `2026-09-12` — ADR-0038: the plan hash generalised from one Operation to a route, the derived
  requirement extended to a multi-step Plan, and `plan.md` named as the route's owner. No
  behaviour here changed; a single gated dispatch is the one-step case.
- `2026-09-11` — First written, from ADR-0027, ADR-0029 and the approval domain as it stands.
  Written because a dev-loop architect planning #482 reported the governing spec missing.
