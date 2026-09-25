# Approval assurance

**Status:** stub — deliberately not in the first pass. Shelved by ADR-0040 on `2026-09-24`,
pending the permissions rework. Not binding, and carries no claims.

## Why this document exists

This is not a capability Relay has. It is the set of approval properties that were **designed,
argued for, and then deliberately shelved** when the owner decided on `2026-09-24` that Gleipnir
would own the permission model for now and that the surface which created a request would be the
surface that answers it (ADR-0040).

It exists because the alternative was losing the argument. Each property below was reasoned
through with the owner, some of them twice; three of them had reached a Designed claim with a
milestone before the direction changed. Deleting them would leave the next person to pick this up
re-deriving the reasoning from scratch — and, worse, re-deriving it from the *summary* of the
reasoning rather than the reasoning itself, which is how a rejected idea comes back in a weaker
form than the one that was rejected.

So the argument is kept whole here, in the voice it was made in. When the permissions rework
happens, this document is what it argues with.

**A stub carries no claim IDs and no milestones** (`README.md`, *The establishing phase*).
Inventing either for work nobody has scheduled would make this read like a commitment, which is
exactly what it is not. Everything below is prose, and none of it binds the loop.

## What is shelved

### Out-of-band as a rule *requirement*

A gate rule can demand that a decision arrive over the `out-of-band` channel — landing on the
authenticated decision endpoint, carrying a credential the AI-agent's session does not hold —
and be satisfied by nothing weaker. The mechanism is built, correct, and tested both ways
(`approval.md` AP-12, AP-13, AP-14, and the weak-channel refusal). What is shelved is any
**shipped or seeded rule that uses it**.

The argument for it, which has not been refuted and is only outweighed:

> **In-band is an assumption about the client; out-of-band is evidence.**

An in-band answer comes back over the same session that asked, so the guarantee that a human
decided rests entirely on the client keeping a rule Relay cannot check. An out-of-band answer
arrives with a credential the asking session does not have, which is a fact about the world
rather than a claim about a counterparty. That asymmetry is not a matter of degree, and it is
why the two channels were built as an ordered pair rather than as a preference.

The counter-argument that won, for now: Relay is expected to sit behind a firewall the on-call
human cannot easily cross, so a rule demanding out-of-band routes the decision to a surface the
deciding human does not use — and an approval nobody can answer is not a stronger approval, it is
an expired request followed by pressure to loosen the rule (ADR-0040, *Why it is defensible
now*).

### An approver Relay verifies

Distinct from the channel, and the property the channel was a means to. Today, and for the
foreseeable interim, every approval of agent-originated work records the **verified** Account
whose credential made the call — the machine relaying the answer — and the human only as an
**assertion** beside it (`approval.md`, *Attribution*). An auditor can separate the two, which is
the whole point of keeping the lanes structurally apart, but for this class of work the verified
lane will never name the human.

What is shelved is the posture in which it does: a decision whose approver is an Account Relay
itself authenticated, with a role, an audience membership and — on the Console — a step-up
re-authentication taken at the moment of deciding. That is what makes an audit trail able to
answer *"a human authenticated to Relay and approved this"* rather than *"a client told us a
human approved this."*

The reason this is worth keeping distinct from the channel: a future design could plausibly
deliver a verified approver **without** out-of-band — for instance by having the client present
the approver's own Relay credential, or by an identity assertion Relay can check against the
provider it already trusts. Collapsing the two into one shelved idea would hide that option.

### The grant-issuance floor

An **approval grant** converts one human decision into many future dispatches, which makes its
issuance the highest-leverage single approval in the system. The shelved rule: a grant is issued
only by **second-person, out-of-band** approval — never self-confirmed and never in-band,
whatever the gate rules allow for ordinary requests, with a grant approved on a weaker rung
refused.

This was an owner decision of `2026-09-14`, adopted as an ADR-0027 amendment on `2026-09-24`, and
carried as a Designed claim (`approval.md` AP-58, v0.6.5) until ADR-0040 shelved it the same day.
It is **the one shelved item that had already been adopted by an ADR**, which is why it is named
here precisely rather than paraphrased.

The argument, which is about leverage rather than about channels in general: deriving a grant's
requirement from the live gate at the Scope's worst case (`approval.md` AP-35) prices it at what
the gate demands — and the seeded default demands self-confirmation in-band. So on a default
install a single asserted answer from the requesting session can open standing authorization over
a described set of future work. A floor exists precisely because derivation cannot raise a
requirement above what the rules say, and a grant is the last place to accept an assertion.

Worth naming what did **not** move with it. The other two bounds adopted in the same ADR-0027
amendment — a grant never covering Raw Exec, and a 4-hour window cap — are **not** shelved. They
remain Designed at v0.6.5 (`approval.md` AP-56, AP-57), because neither depends on who may answer
or on which surface. Only the issuance rung went.

### Second-person rules whose second person Relay authenticated

A rule may exclude the requester from its own audience, and that mechanism is built and stays
(`approval.md` AP-9, AP-43). What is shelved is the **posture** that the second person must be
someone Relay itself authenticated.

Under the interim direction, a second-person rule on an MCP-originated request is satisfied by a
second human the *client* routed to and asserted — which is a genuine second person, and is not
nothing, but it is a second person in Gleipnir's directory rather than in Relay's. The stronger
version, where the second approver holds a Relay Account and the two-person property is one Relay
can demonstrate from its own records, is what waits here.

The reason this is listed separately from "an approver Relay verifies" rather than folded into
it: two-person release is the property customers ask for by name, and it is the one where the
difference between "we can show you two distinct humans signed" and "a client told us two did" is
most likely to be the thing being bought.

## What would bring each back

No milestone, no issue, and no commitment to an order. Any one of these is enough to reopen the
whole document; the first is the one that is actually expected.

- **The permissions rework.** The owner's stated intent is to "significantly rework and understand
  how the permissions will work in the future" (ADR-0040). Relay and Gleipnir currently represent
  the same human twice, differently, and the interim answer is to let one of them own it. When
  that is worked through properly, this document is an input to it and ADR-0040 is the first thing
  the rework amends.
- **A deployment where the approver can reach Relay directly.** The firewall argument is the load
  bearing one, and it is an argument about *where the Relay sits*, not about approvals. Remove
  the firewall — an operator's own network, a co-located Console, a customer whose on-call people
  already hold Relay Accounts — and out-of-band becomes cheap rather than unreachable, and most of
  the trade ADR-0040 makes stops being worth making.
- **A customer who needs evidence rather than an assertion.** An audit or compliance posture that
  cannot accept "a client told us a human approved this" is a product requirement, not a
  preference. The mechanism to serve it is already in the code and already tested; what is
  missing is a rule that uses it. That makes this the cheapest of the three to act on, and it is
  the reason ADR-0040 declined to delete the channel mechanism.

## Relationship to `approval.md`

`approval.md` is the durable capability specification and describes what Relay does today. This
document describes what it deliberately does not. Nothing here is a claim, nothing here is
Designed, and nothing here may be cited as a requirement.

Two things that did *not* come here, and should not be moved here later without a decision:

- **AP-69** — an `out-of-band` rule yields no answerable question, on any client. It stays in
  `approval.md` as a safety property: while the channel mechanism exists, a rule that sets
  `out-of-band` must not produce a park nobody can answer. It costs nothing and it prevents a
  future rule creating exactly the unanswerable gate ADR-0040's sequencing constraint warns about.
- **The built channel claims** — AP-12, AP-13, AP-14 and the weak-channel refusal. The code still
  does all of it and the claims are still true. A spec describes what the system does, not what
  its shipped configuration exercises.

## History

- `2026-09-24` — Created as a `stub` by ADR-0040, holding what that decision shelved: out-of-band
  as a rule requirement, a Relay-verified approver, the grant-issuance floor that `approval.md`
  AP-58 was, and second-person rules whose second person Relay authenticated. Each kept with its
  original argument rather than a summary, because the reasoning is the part worth preserving.
