# Approval assurance

**Status:** stub — deliberately not in the first pass. Shelved by ADR-0040 on `2026-09-24` and
extended by its amendment of `2026-09-25`, pending the permissions rework (#716). Not binding, and
carries no claims.

## Why this document exists

This is not a capability Relay has. It is the set of approval properties that were **designed,
argued for, and then deliberately shelved** when the owner decided on `2026-09-24` that Gleipnir
would own the permission model for now (ADR-0040). As amended the next day, the posture is:
**MCP is the approved pathway, and the Relay's own surfaces keep deciding any request without
being relied on.** Two more properties, surfaced by that amendment's review, were recorded
rather than solved on `2026-09-25`. Since ADR-0044 (`2026-10-18`) the Console has no approval
surface (`approval.md` AP-80), so the **Control API decision endpoint is the one out-of-band
path**, kept as the rescue.

It exists so the argument is not lost. Each property was reasoned through with the owner, some
twice, and three had reached a Designed claim with a milestone before the direction changed.
Deleting them would leave the next person re-deriving the reasoning from a summary of it, which
is how a rejected idea comes back weaker than the one rejected. When the permissions rework
happens, this document is what it argues with.

**A stub carries no claim IDs and no milestones** (`README.md`, *The establishing phase*):
either would make this read like a commitment. Everything below is prose, and none of it binds
the loop.

## What is shelved

### Out-of-band as a rule *requirement*

A gate rule can demand that a decision arrive over the `out-of-band` channel — landing on the
authenticated decision endpoint, carrying a credential the AI-agent's session does not hold —
and be satisfied by nothing weaker. The mechanism is built, correct, and tested both ways
(`approval.md` AP-12, AP-13, AP-14, and the weak-channel refusal). What is shelved is any
**shipped or seeded rule that uses it**.

The argument for it, which has not been refuted and is only outweighed:

> **In-band is an assumption about the client; out-of-band is evidence.**

An in-band answer comes back over the session that asked, so the guarantee that a human decided
rests on the client keeping a rule Relay cannot check. An out-of-band answer arrives with a
credential the asking session does not have — a fact about the world, not a claim about a
counterparty. That asymmetry is why the two channels were built as an ordered pair rather than
a preference.

The counter-argument that won, for now: Relay is expected to sit behind a firewall the on-call
human cannot easily cross, so a rule demanding out-of-band routes the decision to a surface the
deciding human does not use — and an approval nobody can answer is not a stronger approval, it is
an expired request followed by pressure to loosen the rule (ADR-0040, *Why it is defensible
now*).

### An approver Relay verifies

Distinct from the channel, and the property the channel was a means to. For the foreseeable
interim, every approval of agent-originated work **on the approved pathway** records the
**verified** Account whose credential made the call — the machine relaying the answer — and the
human only as an **assertion** beside it (`approval.md`, *Attribution*). An auditor can separate
the two, but on that path the verified lane never names the human. (A human who decides the
same request on the Control API *is* verified, but nothing directs anyone there.)

What is shelved is the posture in which the verified lane does name the human: a decision whose
approver is an Account Relay itself authenticated, with a role, an audience membership and a
step-up re-authentication taken at the moment of deciding. That lets an audit trail answer *"a
human authenticated to Relay and approved this"* rather than *"a client told us a human approved
this."*

It is kept distinct from the channel because a future design could deliver a verified approver
**without** out-of-band — for instance by having the client present the approver's own Relay
credential, or an identity assertion Relay can check against the provider it already trusts.

### The grant-issuance floor

An **approval grant** converts one human decision into many future dispatches, which makes its
issuance the highest-leverage single approval in the system. The shelved rule: a grant is issued
only by **second-person, out-of-band** approval — never self-confirmed and never in-band,
whatever the gate rules allow for ordinary requests, with a grant approved on a weaker rung
refused.

This was an owner decision of `2026-09-14`, adopted as an ADR-0027 amendment on `2026-09-24`, and
carried as a Designed claim (`approval.md` AP-58, v0.6.5) until ADR-0040 shelved it the same day.
It is **the one shelved item an ADR had already adopted**, so it is stated precisely here.

The argument is about leverage: deriving a grant's requirement from the live gate at the Scope's
worst case (`approval.md` AP-35) prices it at what the gate demands — and the seeded default
demands self-confirmation in-band. So on a default install one asserted answer from the
requesting session can open standing authorization over future work. Derivation cannot raise a
requirement above what the rules say, and a grant is the last place to accept an assertion.

The other two bounds from the same ADR-0027 amendment — a grant never covering Raw Exec, and a
4-hour window cap — are **not** shelved. They remain Designed at v0.6.5 (`approval.md` AP-56,
AP-57), because neither depends on who may answer or on which surface.

### Second-person rules whose second person Relay authenticated

A rule may exclude the requester from its own audience, and that mechanism is built and stays
(`approval.md` AP-9, AP-43). What is shelved is the **posture** that the second person must be
someone Relay itself authenticated.

Under the interim direction, a second-person rule on an MCP-originated request is satisfied by a
second human the *client* routed to and asserted — a genuine second person, but one in
Gleipnir's directory rather than Relay's. What waits here is the stronger version: the second
approver holds a Relay Account, and Relay can demonstrate the two-person property from its own
records.

It is listed apart from "an approver Relay verifies" because two-person release is what
customers ask for by name, and where "we can show you two distinct humans signed" versus "a
client told us two did" is most likely the thing being bought.

### Restarts strand an in-flight approval

*Recorded 2026-09-25 by owner ruling; deliberately not solved.*

The MRTR round trip (`approval.md` AP-60 … AP-71) hands the client a **sealed request state** and
requires it back on the retried call. The sealing key is minted once per process and is never
configuration — right for invariant 11, since there is nothing to reach from an API — so it does
not survive a restart. A restart **while a human is deciding** invalidates the answer: the retry
carries state the new process cannot open, and is refused, fail-closed. The request itself is
still pending and still correct.

**AP-62** turns that refusal into an availability problem: a question is emitted only for a park
the call *created*, and a re-drive that bounces off an already-pending request re-pages nobody.
That stops every poll re-paging a human, but after a restart the client is never asked again.
The request waits, answerable by nobody on the approved pathway, until its TTL expires.

It is tolerable for **one reason only**: the Control API decision endpoint still decides any
request, so a human who notices can rescue it by hand. That rescue is manual, depends on someone
knowing to look, and is the path the shipped posture tells people not to use — so the risk is
real, and accepted rather than closed (threat model **R27**).

Since ADR-0044 (`2026-10-18`) the rescue rests on the Control API alone, which has **no UI**: a
human needs an API Token for a human Account, a way to make an authenticated request, and the
request's ID — from the webhook payload, the MCP park result, or the Control API's list of
pending requests. The owner accepted that on `2026-10-18`. **If the Control API decision
endpoint is ever removed, this risk stops being tolerable and must be closed first** — the
condition ADR-0040's amendment attached to the Console, carried over to what is left.

Two candidate fixes, identified by the review of the v0.7.0 design plan and **not chosen**:

- **Re-ask the requesting client when its state is stale.** Relax AP-62 for the one case where the
  client presents state that fails to open because the key rotated, rather than because it was
  tampered with. Keeps the key process-lifetime; costs a narrow exception to the no-re-page rule
  and a way of telling "stale" from "forged" that does not itself become an oracle.
- **Persist the key in the store.** The state then survives a restart, and a retry landing on
  another replica. Costs a secret at rest in the Relay's store, and the design plan's own rejection
  of a root-owned key file ("adds a security-floor configuration surface for a property the design
  does not need") would have to be revisited under invariant 11.

The owner chose not to solve it in v0.7.0. A future spec picks it up.

### Surface versus client identity

*Recorded 2026-09-25 by owner ruling; unresolved by design.*

When Relay says an answer "arrived over MCP", which identity does that bind — **any MCP Account**,
or **the exact client that asked**? Today the answer is partial and implicit: the sealed request
state binds the *calling Account* (AP-65), and `approve_request` binds nothing beyond an
authenticated session. The owner ruled this a problem for a real authentication system, not for
this spec. The two answers pull in opposite directions:

- **Surface-only** — any authenticated MCP Account may answer. Simple, and it keeps a request
  decidable when the asking client has gone away. But it makes **another MCP Account a
  second-person escape hatch**: a second machine credential, or a second session, can satisfy a
  rule written to exclude the requester, and Relay records a "second person" that is the same
  deployment wearing a different token.
- **Client-bound** — only the client that asked may answer. Closes the escape hatch, and matches
  what the seal already does for MRTR. But it makes **undecidable requests more likely**: a client
  that crashed, timed out or was replaced strands every request it parked, which is the restart
  problem above in a different form.

Unresolved by design. Whatever the permissions rework decides about identity decides this.

## What would bring each back

No milestone, no issue, and no committed order. Any one of these reopens the whole document; the
first is the one expected.

- **The permissions rework.** The owner's stated intent is to "significantly rework and understand
  how the permissions will work in the future" (ADR-0040). Relay and Gleipnir represent the same
  human twice, differently, and the interim answer lets one of them own it. This document is an
  input to that rework, and ADR-0040 is the first thing it amends.
- **A deployment where the approver can reach Relay directly.** The firewall argument is the
  load-bearing one, and it is about *where the Relay sits*, not about approvals. Without the
  firewall — an operator's own network, a co-located Relay, on-call people who already hold Relay
  Accounts — out-of-band becomes cheap, and most of ADR-0040's trade stops being worth making.
- **For the restart risk: a first real outage** — a request stranded by a restart where nobody
  reaches for the Control API. Either candidate fix above is bounded work. Removing the Control
  API decision endpoint would force it outright (ADR-0044).
- **For surface versus client identity: any authentication design at all.** This document should
  not answer it first.
- **A customer who needs evidence rather than an assertion.** An audit or compliance posture that
  cannot accept "a client told us a human approved this" is a product requirement. The mechanism
  is already built and tested; only a rule using it is missing. That makes this the cheapest to
  act on, and is why ADR-0040 declined to delete the channel mechanism.

## Relationship to `approval.md`

`approval.md` describes what Relay does today; this document describes what it deliberately does
not. Nothing here is a claim or Designed, and nothing here may be cited as a requirement.

Two things stay in `approval.md` and should not move here without a decision:

- **AP-69** — an `out-of-band` rule yields no answerable question, on any client. It stays in
  `approval.md` as a safety property: while the channel mechanism exists, a client must never be
  asked a question whose answer the rule would refuse. Such a park renders as `pending_approval`
  and is decided on the Relay surfaces — which is one of the reasons the owner kept them.
- **The built channel claims** — AP-12, AP-13, AP-14 and the weak-channel refusal. They are still
  true: a spec describes what the system does, not what its shipped configuration exercises.
