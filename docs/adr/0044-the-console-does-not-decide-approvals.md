# The Console does not decide approvals; the Control API is the out-of-band path

**Status:** Accepted (owner decision 2026-10-18). Amends ADR-0040, ADR-0027, ADR-0026, ADR-0029
and ADR-0038. Decisions 2 and 3, where they keep approval grants, quorum and channel strength,
are superseded by ADR-0047.

Approval had three places a decision could be made. **In-band**, through the requesting MCP
client — `approve_request`, or an answer to an MRTR elicitation question — which ADR-0040 made
the approved pathway for agent-originated work. **Out-of-band on the Control API** —
`POST /api/v1/approvals/{id}/decision`, under a per-person Account. And **out-of-band in the
Admin Console** — the Approvals queue, the approval request screen, and an approve/deny action
behind step-up re-authentication, with bulk decisions designed on top (`approval.md` AP-59).

ADR-0040's amendment of `2026-09-25` kept both out-of-band paths working and said neither was
relied on. It also recorded an intent, in the owner's words, *"I eventually want to potentially
remove the entire console approve thing"*, and bounded it: an intent, not a decision; waiting
on MRTR elicitation (#646) being proven in use; and waiting on the restart risk (threat model
R27) being closed first, *"because the Console is the only thing that makes that risk
tolerable"*. Taking it was to be its own ADR. This is that ADR.

The owner's decision, on `2026-10-18`:

> *"In my understanding of the project all approvals are routed via elicitation to the agent so
> we should drop the approvals page and all mechanisms bound to it entirely."*
>
> *"Approvals should be cut out of the UI completely."*

Asked whether the Control API decision endpoint goes with it — the question ADR-0040's
amendment left open — the owner chose to **keep the API endpoint**.

## The decision

1. **The Admin Console has no approval surface.** No Approvals destination in the nav and no
   pending count beside it; no queue; no approval request screen; no approve or deny action,
   and so no step-up taken for one; and no bulk decision. A Console session can neither list
   pending requests nor decide one. The Console still renders what an approval *left behind*
   where that is part of another record — the approver chips on a Job, an `approval` row in
   Activity — because those are the audit trail, not a decision surface.

2. **The Control API is the out-of-band decision path, and the only one.**
   `GET /api/v1/approvals`, `GET /api/v1/approvals/{id}` and
   `POST /api/v1/approvals/{id}/decision` stay exactly as they are, as does approval-grant
   management under `/api/v1/approval-grants`. The endpoint is what remains of ADR-0027 decision
   2's out-of-band guarantee: an approver who can reach Relay can always decide, under an
   Account Relay authenticated, with no client in the path.

3. **Nothing about what an approval is changes.** The gate's position, the ladder, channel
   strength, plan-hash binding, drift re-parking, quorum, expiry, approval grants and the
   two-lane attribution are untouched. The channel mechanism stays: an out-of-band decision is
   one made on the Control API, and a rule demanding `out-of-band` is satisfied there and
   nowhere else.

4. **Where a Console-originated mutate parks, it is decided on the Control API.** When the
   Console's execution composer exists (ADR-0026, #438) and a dispatch from it parks under a
   rule stricter than its own step-up apply, a human answers it on the Control API. The
   self-confirmation rung for a Console requester is still the step-up apply itself (ADR-0027
   decision 5); what has gone is a second human answering the request in the Console.

## Why

Three reasons, in the order the owner weighted them:

1. **Approvals are answered where the human already is.** ADR-0040 settled that the approved
   pathway for agent-originated work is the requesting client — Gleipnir routing to its on-call
   audience, or an operator's own harness — because Relay sits behind a firewall the on-call
   human cannot easily cross and the client already reaches them. MRTR elicitation (#646)
   landed on `2026-09-29`, so that pathway carries a Relay-authored question to the human
   rather than depending on the client to call a tool. A second, browser-shaped answer path
   inside Relay is a place the shipped posture tells people not to go.

2. **The Console was the surface people were told not to rely on.** ADR-0040's amendment kept
   it working as the rescue, not the route. A surface built, maintained, reviewed and
   threat-modelled as a fleet-release lever, while its own governing ADR says nothing should
   direct a human there, costs everything a relied-on surface costs and earns nothing. Removing
   it makes the posture ADR-0040 already states true of the product.

3. **One less surface that can release work.** The Console approval surface carried its own
   security residue: R22 (a hijacked Console session plus a password releasing every pending
   request in one bulk act), a step-up path tuned for approval, an unaudited queue read (#779),
   and a screen whose fidelity to the Relay-authored rendering had to be argued separately from
   every other surface's. Each goes with it.

**Why the Control API stays.** The owner was told three things before choosing, and they are
why only the Console half is taken:

- **The in-band path is a client's word.** An in-band answer records an asserted approver
  except on a human Account's OAuth session (`approval.md` AP-79), and OAuth has never run live
  against a real identity provider (#351). A rule that needs an approver *Relay* verified —
  `out-of-band`, or a second person Relay authenticated — can be satisfied only out-of-band.
  Without the endpoint, every such rule would be undecidable by construction: the availability
  failure ADR-0040's amendment was written to undo.
- **The requesting client can auto-answer.** A client that answers its own question is
  indistinguishable from one that asked a person (threat model R21). The out-of-band path is the
  one place a human can decide with no client in between.
- **A Relay restart strands an in-flight MRTR answer** (threat model R27), and AP-62 means the
  client is never asked again. The out-of-band decision is the only way such a request is
  decided before its TTL. ADR-0040's amendment said the Console made R27 tolerable; it was the
  Console **and** the Control API, and the Control API is the half kept.

## What is retired

In `docs/specs/approval.md`:

- **AP-59** (bulk decisions in the Console) — Designed and unbuilt; retired, its ID never
  reused. Its accepted residual, threat model **R22**, has nothing left to describe.
- **AP-16** (out-of-band: the Console or the Control API, with step-up on a Console decision)
  and **AP-19** (the Console's approval UI) — **built**, so not struck on the day of the
  decision. A Designed claim, **AP-80**, states the target — out-of-band decisions are made on
  the Control API only, and the Console has no approval surface — and retires AP-16 and AP-19
  when the removal lands.
- The Console screen specifications **08 — Approval object** and **14 — Approval queue** are
  retired. They keep their file names so links hold, and say so at their head; once the screens
  are removed from the code they become stubs like 03 and 17.

## Consequences

- **The rescue for a stranded request rests on the Control API alone, which has no UI.** This
  is the cost, stated plainly. A human rescuing a request stranded by a restart (R27), or
  deciding any rule that needs a verified approver (R26), needs an API Token for a human
  Account, a way to make an authenticated HTTP request, and the request's ID — which the webhook
  payload and the MCP park result carry, and which `GET /api/v1/approvals` lists. Before this
  decision the same human could open a browser, see the queue and click. Rescue is therefore
  **harder, slower, and less likely to happen at all** in a deployment whose operators do not
  keep a token to hand. The owner accepted that on `2026-10-18`, knowingly, with this
  paragraph's content in front of them.
- **ADR-0040's two preconditions are answered, not silently dropped.** *#646 proven in use*: it
  is built and tested (`approval.md` AP-60 … AP-71) but has not carried real traffic, and the
  owner chose not to wait. *R27 closed first*: it is not closed; it stays tolerable because the
  rescue it leans on — an out-of-band decision — survives on the Control API. R27's rationale
  rests on the Control API alone, with the condition: **if the Control API decision endpoint is
  ever removed, R27 stops being tolerable and must be closed first.**
- **A hijacked Console session loses a lever.** It can no longer approve anything. R22 is moot,
  and the "Hijacked Console session" adversary's reach in the threat model narrows.
- **The Console's step-up is no longer taken for approval**, only for a mutate apply and the
  privilege-granting Account acts.
- **Nothing in invariant text moves.** Invariant 10 governs the Console's execution, not its
  approvals, and invariant 11's security floor names the approval *notification path*, which is
  unchanged. No invariant is amended.
- **Code follows.** The Console's approval routes, its decide handler, the nav entry and its
  count, and the tests that drive a Console decision are removed under AP-80.
- **Consumers updated on 2026-10-18:** `docs/specs/approval.md` (Surfaces, AP-80, AP-59
  retired, the *Future work* entry recorded as taken); `docs/specs/approval-assurance.md`;
  `docs/specs/plan.md`; `docs/specs/freeze.md`; `docs/security/threat-model.md` (R21, R22, R23,
  R26, R27 and the two adversary sections, and R27 reclassified from anticipatory to shipped,
  since #646 landed on 2026-09-29); `GLOSSARY.md` (**Approval**, **Admin Console**, **Bulk
  decision**); `docs/STATUS.md`; the v0.7.0 design plan; the Console screen specifications (08
  and 14 retired; 00, 04, 05, 11, 19, 99 and the README); and ADR-0040, ADR-0027, ADR-0026,
  ADR-0029 and ADR-0038, each with a dated note.
- **Named as consumers, not edited here:** `docs/operations/demo-fleet.md`, `docs/dev-fleet.md`
  and `docs/operations/relay-install.md` described the Console decision route the binary then
  mounted, and change in the PR that removes the route.

## Amendments to other ADRs

- **ADR-0040.** Its amendment of `2026-09-25` recorded the removal of Console approval as an
  intent. This ADR takes it for the Console half, and decides the question that amendment left
  open: the Control API decision endpoint stays. "The Console and the Control API keep deciding
  any parked request" now reads "the Control API", wherever it appears.
- **ADR-0027.** Decision 2's out-of-band envelope is the Control API decision endpoint, and its
  consequence that a Plan must render identically "in the approval queue" now concerns the
  Control API's rendering of the request, since the Console has no queue.
- **ADR-0026.** Decision 7's second person, where a rule demands one for a Console-originated
  mutate, decides on the Control API.
- **ADR-0029.** Its note of `2026-09-25` names the Console and the Control API as reachable
  out-of-band paths; only the Control API remains.
- **ADR-0038.** "The approval queue is where a Plan meets a person" — for a gated Plan that is
  the requesting client in-band, or the Control API out-of-band; the Console renders a Plan and
  decides none.

ADR-0028 speaks of the pending request staying "visible in the approval queue and audit"; that
reads unchanged as the Control API's pending-request listing, and no note is added there.

## Alternatives considered

**Remove the Control API decision endpoint too, making MCP the only approval path.** The literal
reading of *"all approvals are routed via elicitation"*. Rejected by the owner once its cost was
named: no rule needing a Relay-verified approver could be decided at all, a request stranded by
a restart would wait for its TTL with no rescue, and a client that auto-answers would have no
counterweight anywhere in Relay. Revisited, if ever, only after R27 is closed and a verified
approver exists over MCP in the shipped posture (ADR-0041, Proposed).

**Keep the Console read-only — the queue without the decide action.** A smaller cut that keeps
the rescue *discoverable*: a human could see what is waiting and copy the ID to the API.
Rejected by the owner's instruction that approvals be cut out of the UI completely. It would also
keep the unaudited queue read (#779) and the screen's fidelity obligations for a surface whose
one action had been removed.

**Do nothing until the permissions rework (#716).** ADR-0040 is interim against that rework, and
waiting would let it decide the Console's fate with everything else. Rejected because the
Console path is the one surface the shipped posture already tells people not to use, and every
milestone it survives adds maintenance and review cost — AP-59 was about to be built.
