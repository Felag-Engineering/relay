# The surface that created a request is the surface that answers it

**Status:** Accepted (2026-09-24); amended 2026-09-25 — **strict separation withdrawn before any
of it was built**. **Explicitly interim** — see *What is interim, and what reopens it*.

> **Read the amendment of 2026-09-25 first.** The title and the decision below describe strict
> separation, which the owner withdrew one day later. What stands is narrower: MCP is the
> approved pathway for agent-originated approval, the Console and the Control API keep deciding
> any parked request exactly as today and are not relied on, and out-of-band as a rule
> requirement stays shelved. Every passage the amendment changes is signposted in place.

Approval today has two answer paths reaching two different sets of people, and `approval.md`
says so: in-band through the requesting MCP client, and out-of-band on Relay itself — the
Console or the Control API decision endpoint, under a per-person Account Relay authenticates.
ADR-0027 built the second and called it the guarantee; ADR-0029 later made the first reachable.
Nothing binds a request created on one to being answered on the other, so a dispatch an AI-agent
parked over MCP is, today, routinely answered by a human clicking approve in the Relay Console.

That arrangement has been carrying a question it cannot answer: **whose permission model is
this?** An approver in the Console is an Account with a role, an audience membership and a
step-up window, administered in Relay. An approver in Gleipnir is a person in Gleipnir's own
directory, routed to by Gleipnir's handler, under Gleipnir's roles. Both exist; neither is
authoritative; and the combination has produced a model where the same human is represented
twice, differently, and where adding a permission means deciding — every time, ad hoc — which
of the two systems owns it.

The owner's decision, on `2026-09-24`, is to stop answering that question one case at a time:

> *"For now I want Gleipnir to manage all the permissions and the only reason for Console or API
> to have approval permission is for us running a command from those tools. We need to
> significantly rework and understand how the permissions will work in the future. So let's just
> rely on the MCP client to authenticate and deal with the elicitations."*

This ADR records what that means for Relay, and — because it gives up something real — exactly
what is being given up.

## The decision

**The surface that created a request is the surface that answers it.**

*(Withdrawn by the amendment of 2026-09-25: nothing is refused by origin. The first two bullets below
are replaced by "MCP is the approved pathway; the Console and the Control API keep deciding any
parked request, unchanged, and are not relied on". The third bullet stands.)*

- A request created over **MCP** is answerable only over MCP, by the client that requested it,
  through the in-band decision path (`approve_request` today, MRTR elicitation when #646 lands).
- A request created on the **Admin Console** or the **Control API** is answerable only on that
  surface. Those surfaces keep an approval capability for one reason: a human running a command
  from them needs their own work gated and released, and that release is theirs.
- **Out-of-band as a rule *requirement* is shelved.** No shipped or seeded gate rule demands a
  channel, and nothing in the shipped posture asks for an approver Relay verifies. The mechanism
  stays in the code and stays correct; it is simply unexercised.

*(Reversed by the amendment of 2026-09-25, which adopts in substance the permissive version this
paragraph rejects — with the difference that the Relay surfaces are named as not relied on,
rather than as equal alternatives.)* Strict separation, rather than "MCP requests *may* also be
answered on Relay", is the owner's explicit choice. A permissive version would leave exactly the ambiguity this decision exists to
remove: two permission models, both live, with the cheaper one winning whenever someone is in a
hurry. One path per origin is a rule an agent and a reviewer can both check.

## What is being traded

Stated plainly, because a decision that hides its cost is one somebody re-derives later and is
shocked by:

*(Softened by the amendment of 2026-09-25: the default **relied-on** path for agent work has no
Relay-verified approver, and that is still the posture. But the Console and the Control API still
decide any request, so a verified approver remains reachable — it is simply not the path anyone
is directed to.)*

**After this, no Relay-verified approver exists in the default path for agent-originated work.**
Every approval of an AI-agent's dispatch is an **assertion by the client** — accepted under
ADR-0029's client-integrity assumption, recorded in the asserted lane, never in the verified one
(`approval.md`, *Attribution*). The audit trail answers *"a client told us a human approved
this"* and can no longer, for that class of work, answer *"a human authenticated to Relay and
approved this."*

That is a real reduction in assurance, and it is not argued away here. Three things it is **not**:

- It is not a change to what an approval *is*. The gate still sits before the dispatcher, the
  plan hash still binds the resolved set, drift still re-parks, denial is still terminal, the
  blast cap is still enforced and Node Policy is still the wall underneath everything.
- It is not a widening of what anyone may **request**. Relay-side authorization is untouched.
- It is not silent. `docs/security/threat-model.md` carries it, and `approval.md` states it as
  accepted residual risk rather than as a property.

## Why it is defensible now

Four reasons, in the order they actually weigh:

1. **The client is where the human already is.** ADR-0027 made this argument for the in-band path
   and it has only got stronger: Relay is expected to sit behind a firewall that an on-call human
   cannot easily cross, while the client — Gleipnir routing to its on-call audience, or an
   operator's own harness — already can. The out-of-band path reaches whoever can reach Relay
   directly, which in a real deployment is a smaller and different set of people than the ones who
   should be deciding.

2. **Gleipnir is not a bare MCP client.** It enforces its own approver role check **server-side**
   and stamps the responder from an authenticated session, so the assertion Relay records is
   backed by an authentication Gleipnir performed — it is simply not one *Relay* performed.
   ADR-0027's Gleipnir-side rule ("a deterministic path to the assigned human audience — never
   surfaced to the LLM, never auto-answered") remains informational and unenforceable from here;
   what has changed is that the client honouring it is a first-party system with its own
   server-side check, rather than an arbitrary harness.

3. **The alternative in practice was an approval nobody answered.** A requirement that routes a
   decision to a surface the deciding human does not use does not produce a stronger approval; it
   produces an expired request, and then pressure to loosen the rule that created it. ADR-0027
   named approval fatigue as a security property in its own right. An unanswerable gate is the
   terminal case of that.

4. **One permission model is a prerequisite for a good one.** The rework this ADR is interim
   against cannot be reasoned about while two models are live and neither is authoritative.
   Collapsing to one, temporarily and on the record, is what makes the next decision tractable.

## Sequencing: this MUST NOT be enforced before #646

*(No longer applies — the amendment of 2026-09-25. There is no enforcement to sequence. The section is
kept because the reasoning in it is exactly what exposed the availability cost that led to the
withdrawal: the same argument that forbade enforcing separation before #646 holds after #646 for
every rule stricter than self-confirmation in-band.)*

**This is a constraint on when the claims may be promoted, not a note.**

Today, a Gleipnir-parked request is answered by a human in the Relay Console — the out-of-band
path. Gleipnir does not call `approve_request`. So if strict separation is enforced for
MCP-originated requests **before** the MRTR round trip lands (#646, `approval.md` AP-60 … AP-71,
v0.7.0), the result is not a narrower answer path. It is **no answer path at all**: the Console
is closed to those requests, the tool call is one the client does not make, and every gated
dispatch sits until it expires. The gate would become a denial-of-service on the fleet's own
operators, delivered as a safety improvement.

Therefore:

- The separation claims in `approval.md` are **Designed, not built**, at **v0.7.0**, and each is
  **blocked by #646**.
- The issue that implements them names #646 as a blocker, and no earlier milestone may pull them
  forward.
- Until they land, both paths stay open and `approval.md` describes that as current. A reviewer
  who finds the separation enforced without MRTR present should treat it as a defect, not as
  progress.

## What is interim, and what reopens it

**Interim** is the whole of it — the strict separation *(withdrawn, the amendment of 2026-09-25)*, the
shelving of out-of-band as a requirement, and the single permission model that follows. It is adopted *for now*, at the
owner's word, and it is expected to be revisited.

**What reopens it: the permissions rework.** The owner's stated intent is to "significantly
rework and understand how the permissions will work in the future". When that happens, this ADR
is the first thing it amends, and the material shelved out of `approval.md` is waiting in
`docs/specs/approval-assurance.md` with its reasoning intact, so the next decision argues with
the original argument rather than with a summary of it.

Two smaller triggers, either of which is enough on its own:

- **A deployment where the approver can reach Relay directly** — no firewall between the
  on-call human and the Console. The first reason above evaporates and out-of-band becomes cheap.
- **A customer who needs evidence rather than an assertion** — an audit or compliance posture
  that cannot accept "a client told us". That is a product requirement, not a preference, and
  the mechanism to serve it already exists in the code.

### What is *not* decided here

- **The channel mechanism stays.** `in-band` and `out-of-band` remain first-class in the domain,
  the receiving surface still sets the channel, a stronger channel still satisfies a weaker rule,
  and a weak-channel decision is still refused. Nothing is deleted. What changes is that no
  shipped or seeded rule demands the stronger one — present, correct, and unexercised. Deleting
  it would make the rework a rebuild.
- **Nothing about who may *request*.** Relay-side authorization, roles, Grants and the role floor
  on a decision are all untouched.
- **Nothing about Node Policy.** It is unaffected, locally rooted and remotely immutable as ever
  (invariant 2), and it remains the wall that actually stops a command — the one the demo is
  about. An approval never was authorization and still is not.
- **Nothing about second-person rules as a *mechanism*.** A rule may still exclude the requester;
  what is shelved is the posture that the second person must be someone **Relay** authenticated.

## Amendments to other ADRs

- **Amends ADR-0027.** *(The "one path per origin" half is withdrawn by the amendment of 2026-09-25:
  ADR-0027's two paths stay side by side and both decide any request. The decision-2 and decision-4
  halves below still stand. ADR-0027 carries a dated note.)* Its posture that a decision reaches
  Relay by two paths existing *side by side because they reach different people* is narrowed to
  **one path per origin**. The two paths
  still exist and both still work; what is removed is the freedom to answer a request on the path
  that did not create it. Decision 4's "default the self-confirmation rung to in-band and the
  second-person rung to out-of-band" keeps its first half and loses its second in the shipped
  posture, since no shipped rule sets a second-person rung at all. Decision 2's out-of-band
  channel as "the only one that is a *guarantee*" is unchanged as a statement about the
  **authenticated decision endpoint's availability**, and no longer describes where an
  agent-originated approval is expected to arrive. Signposted in place there, dated.

- **Interaction with ADR-0029, which is not amended.** Every decision in it stands: the tool
  call, the asserted approver, the relaxation of `ErrMachineSelfDecision` for an in-band answer
  carrying an assertion, `ErrWeakChannel` unchanged, and MRTR as the second envelope over the
  same decision path. What changes is the *scope of its consequence*, not its text. ADR-0029
  wrote: *"The guarantee for `in-band` rules is now explicitly a client-integrity assumption"*
  and *"it is why rung 3 exists and why `out-of-band` remains the default for it."* Rung 3 still
  exists and the default still holds where a rule sets one; no shipped rule does, so for
  agent-originated work the client-integrity assumption is no longer one posture among several —
  it is the posture. ADR-0029 carries a dated note to that effect.

## Consequences

- *(The separation claims, the R23 narrowing and the demo-runbook move below are all undone or
  re-premised by the amendment of 2026-09-25; its own Consequences list what each consumer now says.)*
- **`docs/specs/approval.md`** gains the separation as Designed claims at v0.7.0 blocked by #646,
  loses AP-58 (grant issuance second-person out-of-band) to the stub spec, keeps AP-69 (an
  `out-of-band` rule yields no answerable question) as a safety property while the mechanism
  exists, and states where the ladder is introduced that no shipped or seeded rule demands
  out-of-band. The built channel claims are all still true and all stay.
- **`docs/specs/approval-assurance.md`** is created, Status `stub`, holding the shelved material
  — out-of-band as a requirement, a Relay-verified approver, the grant-issuance floor, and
  second-person rules whose second person Relay authenticated — each with what would bring it
  back.
- **`docs/security/threat-model.md`**: R21 grows from "most MCP approvals are asserted" to
  "every approval for agent-originated work is", and R23 can no longer name a human deciding in
  the Console as a compensating control for those requests.
- **`docs/operations/demo-fleet.md`**: the approval beat moves from the Relay Console to
  Gleipnir's own UI, and its *The human approver* section describes a separation that this ADR
  changes the meaning of. **Named as a consumer, not edited here** — the runbook is a procedure
  that has to be walked, and it is updated by whoever next walks it, after #646.
- **`GLOSSARY.md`** is unchanged: no term's meaning moves. *Channel*, *Decision* and *Approval*
  all still mean what they meant; fewer of their values are reachable through a shipped rule.

**Consumers updated on 2026-09-24**, because an amendment is not finished until they are:
ADR-0027 and ADR-0029 carry dated signposts; `approval.md` and the new stub spec carry the
claims and the shelved reasoning; the threat model carries the residual. `docs/operations/
demo-fleet.md` is named above and deliberately left for its next walkthrough.

## Alternatives considered

**Keep both paths open, and merely stop *requiring* out-of-band.** *(Adopted in substance by
the amendment of 2026-09-25, one day later, with one addition this paragraph did not consider: MCP is named
as the approved pathway and the Relay surfaces as not relied on, which answers the reviewability
objection below — the rule a reviewer checks is "the tool text, the runbook and operator guidance
direct the human to the client", not "a request may be answered anywhere".)* The smaller change,
and rejected by the owner in favour of strict separation. It leaves both permission models live and
authoritative over the same object, which is the condition this decision exists to end. It also
fails the reviewability test: "a request may be answered anywhere" is not a rule anyone can
check a diff against, and the ambiguity would be resolved case by case by whoever was in a hurry.

**Make Relay the single permission model instead of Gleipnir.** Coherent, and the opposite bet.
Rejected for now on reach: the approvers are behind the firewall's far side, and building Relay
into the system that reaches them means building notification, routing and on-call
administration that Gleipnir already has — the "Relay integrates no chat or paging system" line
in `approval.md` is a decision, not an omission. Reopened by the permissions rework.

**Delete the channel mechanism.** Rejected. An unexercised mechanism that is correct costs
approximately nothing and is a week of work to rebuild. Since this decision is explicitly
interim, deleting the thing the rework is most likely to want back is the one clearly wrong move.

**Do nothing until the permissions rework.** Rejected because the ambiguity has a cost that is
being paid now: every new permission question is answered ad hoc, and the demo's approval beat
currently depends on a path this direction is abandoning. Deciding the interim posture explicitly
is cheaper than discovering it implement-by-implement.

## Amendment (2026-09-25): strict separation is withdrawn; MCP is the approved pathway, the Relay surfaces are not relied on

Owner decision of **2026-09-25**, one day after this ADR was accepted, and before any of the
separation it decided was built. In the owner's words:

> *"The more we talk about it the more I doubt removing the console as approver. We don't want to
> rely on it though — we should have everything run through the MCP as that is the approved
> pathway. And the console approving / API is a complicating factor that shouldn't be used."*

Asked to be precise, the owner chose: **the Console and the Control API keep working exactly as
today — not enforced, not relied on.**

### What is withdrawn

**Strict separation, entirely.** Nothing is refused by origin. A request created over MCP may still
be decided on the Console or the Control API, exactly as it can today, and a request created on
either may be decided on the other. The origin check this ADR decided — and the three `approval.md`
claims that described it — are retired unbuilt. There was never code to remove.

### What replaces it

**MCP is the approved pathway for agent-originated approval.** The tool text, the demo runbook and
operator guidance name it, and Gleipnir is where the human is expected to answer — through
`approve_request` today and MRTR elicitation once #646 lands. That is a statement about where
Relay *directs* people, not a rule Relay *enforces*: the Console and the Control API keep deciding
any parked request, unchanged, and are **not relied on**. Nothing in the shipped posture, the tool
descriptions or the guidance should point a human at them for agent work; nothing refuses them if
a human gets there anyway.

### Why — the reason, not a concession

**The original decision did not name its cost, and its cost was availability.** An adversarial
review of the v0.7.0 design plan found that under strict separation, every path that used to end
with *"a human answers in the Console"* ends with *"wait for the TTL"*:

- **Any rule stricter than self-confirmation in-band makes an MCP-originated request undecidable
  by any surface.** An `out-of-band` rule, a requester-excluded rule, a named audience that does not
  include the calling Account, `count: 2` — each is correctly *not* offered as an MRTR question
  (the askable predicate exists precisely so a client is never asked something whose answer would
  be refused), and under separation each was also closed to the Console. Nobody could answer.
- **The demo fixture hits three of those at once.** `docker/fixtures/approval-gates.json`'s rules
  are exactly the kind separation would have stranded.
- **Every pointer in the product sends humans to a route that would refuse them.** The
  `DecisionPath` in the MCP park result, its JSON-schema text, and the webhook payload all direct a
  human to the Relay decision endpoint.
- **The Console originates nothing until #438**, so its approval queue would decide nothing at all.
- **Four existing end-to-end tests would break**, not because they were wrong but because they
  prove the Console answering an agent's request — which is the rescue path.
- **AP-70 contradicts AP-75 outright** in `approval.md` as merged: one says a client that cannot be
  asked sees no change and the Control API decision endpoint behaves exactly as before; the other
  refuses that endpoint for the same request.

The sequencing constraint above already said that separation before #646 would leave no answer
path at all. The review showed that separation *after* #646 leaves no answer path for every rule
the MRTR predicate correctly declines to ask about. That is not an edge case; it is every rule an
operator writes to be stricter than the default.

### What still stands

- **Out-of-band as a rule *requirement* stays shelved**, in `docs/specs/approval-assurance.md`. No
  shipped or seeded rule demands `out-of-band`.
- **The client-integrity posture for agent work is still the posture relied on.** The approved
  pathway is the client, so the assertion Relay records — backed by Gleipnir's own server-side
  approver check — is what the shipped posture leans on. *What is being traded* above still
  describes the relied-on path accurately; what is softened is only that a verified approver
  remains *reachable*.
- **Interim, pending the permissions rework** (#716). Unchanged.

### Where the interim posture is heading — an intent, not a decision

The owner, the same day: *"I eventually want to potentially remove the entire console approve
thing."* So the approved-pathway posture is **a step toward MCP being the only approval path**, and
the Console's decide action is a **candidate for removal**. It is recorded here so the direction is
not rediscovered, and bounded so it is not mistaken for a decision:

- **Nothing is removed now.** The Console and the Control API keep deciding exactly as today, and
  no built claim in `approval.md` is retired or reworded for it.
- **It waits on #646 being proven in use.** Removing the rescue before the approved pathway has
  carried real traffic would recreate exactly the availability failure this amendment exists to
  undo — every rule the MRTR predicate correctly declines to ask about, and every restart mid-
  decision, would be undecidable again.
- **Taking it would be its own ADR**, and it inherits a precondition: the restart risk
  (`approval-assurance.md`, threat model R27) must be closed first, because the Console is the only
  thing that makes that risk tolerable.

`approval.md` names the built claims it would retire under *Future work*.
- *What is not decided here* above is unchanged in full.

### What no longer applies

- **The sequencing constraint.** There is no enforcement to sequence.
- **The "Not yet in force" framing** in the threat model, since there is nothing that will come into
  force.
- **The origin-separation claims** — `approval.md` AP-74, AP-75 and AP-76 are retired unbuilt, their
  IDs never reused.

### Two things recorded, not solved

Both are owner rulings of 2026-09-25, and both are held in `docs/specs/approval-assurance.md`
rather than decided here:

- **Restarts are dangerous.** The MRTR seal key is process-lifetime, so a restart while a human is
  deciding strands the answer; with the Console no longer the relied-on path, that is a real
  availability risk rather than a curiosity. Tracked in the stub for a future spec, and as
  threat-model R27. **No fix is designed here.**
- **Surface versus client identity** — whether "answered over MCP" means any MCP Account or only the
  exact client that asked — is a question for a real auth system. **Not decided.**

### Consequences, and consumers updated on 2026-09-25

- **`docs/specs/approval.md`**: AP-74 … AP-76 retired, with one History entry; AP-70 stays, and the
  contradiction is gone with AP-75; one paragraph where the two decision paths are introduced saying
  MCP is the approved pathway and the out-of-band path works and is not relied on; every reference to
  the sequencing constraint removed. AP-16, AP-17 and AP-19 were true throughout and are untouched.
- **`docs/specs/approval-assurance.md`**: two new shelved items — the restart risk and
  surface-versus-client identity — each with its reasoning.
- **`docs/security/threat-model.md`**: R26 re-premised (the Relay surfaces can still produce a
  verified approver; they are just not relied on), its "Not yet in force" dropped; R23's narrowing
  undone; R27 added for the restart risk; R21 and R25 corrected where they cited the withdrawn
  claims or the shelved AP-58.
- **ADR-0027** carries a dated note that its two paths stay side by side. **ADR-0029**'s note is
  corrected: the client-integrity assumption is the *relied-on* posture for agent work, not the only
  one reachable.
- **The v0.7.0 design plan** loses the origin check, the sequencing guard and the origin refusals.
- **`docs/operations/demo-fleet.md`** is still a consumer, differently: the approval beat is
  expected to happen in Gleipnir's UI because that is the approved pathway, and the Console step it
  describes today still works as a rescue. Named, not edited, as before.

## Amendment (2026-09-29): #646 has landed

A note, not a change to any decision here. This ADR says in several places that MRTR elicitation
arrives "when #646 lands"; it has. The in-band decision path over MCP is now both
`approve_request` and MRTR elicitation (`docs/specs/approval.md` AP-60 … AP-71), and the
sequencing constraint's premise — an MCP answer path exists for agent work — is met. Nothing else
changes: strict separation stays withdrawn (§Amendment 2026-09-25), MCP is the approved pathway,
and the Console and the Control API still decide any parked request and are not relied on. Where
the answer arrives on a human Account's OAuth session it is a verified decision (ADR-0029
§Amendment 2026-09-29).
