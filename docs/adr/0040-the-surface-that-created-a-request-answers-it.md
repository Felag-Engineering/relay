# The surface that created a request is the surface that answers it

**Status:** Accepted (2026-09-24). **Explicitly interim** — see *What is interim, and what
reopens it*.

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

- A request created over **MCP** is answerable only over MCP, by the client that requested it,
  through the in-band decision path (`approve_request` today, MRTR elicitation when #646 lands).
- A request created on the **Admin Console** or the **Control API** is answerable only on that
  surface. Those surfaces keep an approval capability for one reason: a human running a command
  from them needs their own work gated and released, and that release is theirs.
- **Out-of-band as a rule *requirement* is shelved.** No shipped or seeded gate rule demands a
  channel, and nothing in the shipped posture asks for an approver Relay verifies. The mechanism
  stays in the code and stays correct; it is simply unexercised.

Strict separation, rather than "MCP requests *may* also be answered on Relay", is the owner's
explicit choice. A permissive version would leave exactly the ambiguity this decision exists to
remove: two permission models, both live, with the cheaper one winning whenever someone is in a
hurry. One path per origin is a rule an agent and a reviewer can both check.

## What is being traded

Stated plainly, because a decision that hides its cost is one somebody re-derives later and is
shocked by:

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

**Interim** is the whole of it — the strict separation, the shelving of out-of-band as a
requirement, and the single permission model that follows. It is adopted *for now*, at the
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

- **Amends ADR-0027.** Its posture that a decision reaches Relay by two paths existing *side by
  side because they reach different people* is narrowed to **one path per origin**. The two paths
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

**Keep both paths open, and merely stop *requiring* out-of-band.** The smaller change, and
rejected by the owner in favour of strict separation. It leaves both permission models live and
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
