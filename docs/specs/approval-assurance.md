# Approval assurance

**Status:** stub — deliberately not in the first pass. Shelved by ADR-0040 on `2026-09-24` and
extended by its amendment of `2026-09-25`, pending the permissions rework (#716). Not binding, and
carries no claims.

## Why this document exists

This is not a capability Relay has. It is the set of approval properties that were **designed,
argued for, and then deliberately shelved** when the owner decided on `2026-09-24` that Gleipnir
would own the permission model for now (ADR-0040). That decision first took the form of strict
separation — the surface which created a request answers it — and was amended the next day to
what stands: **MCP is the approved pathway, and the Console and the Control API keep deciding any
request without being relied on.** The shelved properties below survived the amendment unchanged;
two more, which the amendment's review surfaced and the owner chose to record rather than solve,
were added on `2026-09-25`.

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
foreseeable interim, every approval of agent-originated work **on the approved pathway** records
the **verified** Account whose credential made the call — the machine relaying the answer — and
the human only as an **assertion** beside it (`approval.md`, *Attribution*). An auditor can
separate the two, which is the whole point of keeping the lanes structurally apart, but on that
path the verified lane will never name the human. (A human who decides the same request on the
Console *is* verified — the rescue path still works — but nothing directs anyone there, so it is
not the posture this document is about.)

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

### Restarts strand an in-flight approval

*Recorded 2026-09-25 by owner ruling; deliberately not solved.*

The MRTR round trip (#646, `approval.md` AP-60 … AP-71) hands the client a **sealed request
state** and requires it back on the retried call. The key that seals it is minted once per process
and is never configuration — the right choice for invariant 11, because there is nothing to reach
from an API — and so it does not survive a restart. A restart **while a human is deciding**
invalidates the answer: the retry arrives carrying state the new process cannot open, and it is
refused, fail-closed. The request itself is still pending and still correct.

What turns that from a refusal into an availability problem is **AP-62**: a question is emitted
only for a park the call *created*, and a re-drive that bounces off a request already pending
re-pages nobody. That rule exists for a good reason — it is what stops every poll re-paging a
human — but it means that after a restart the client is never asked again. The request waits,
answerable by nobody on the approved pathway, until its TTL expires.

Under strict separation this would have been a hard outage. It is tolerable now for **one reason
only**: the Console and the Control API still decide any request, so a human who notices can
rescue it by hand. That rescue is manual, it depends on someone knowing to look, and it is
precisely the path the shipped posture tells people not to use — so the risk is real, and it is
accepted rather than closed (threat model **R27**).

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
or **the exact client that asked**? Today's code and the MRTR design answer it partly and
implicitly: the sealed request state binds the *calling Account* (AP-65), and `approve_request`
binds nothing at all beyond an authenticated session. Neither is a decision about what the
question *should* be, and the owner ruled that this is a problem for a real authentication system,
not for this spec.

The two answers pull in opposite directions, which is why it is not decided by default:

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
- **For the restart risk specifically: a first real outage.** A request stranded by a restart in
  a deployment with nobody watching the Console is the event that makes this worth solving; either
  candidate fix above is a bounded piece of work once someone needs it.
- **For surface versus client identity: any authentication design at all.** It is not a question
  this document can answer, and it should not be answered here first.
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
  `approval.md` as a safety property: while the channel mechanism exists, a client must never be
  asked a question whose answer the rule would refuse. Such a park renders as `pending_approval`
  and is decided on the Relay surfaces — which is one of the reasons the owner kept them.
- **The built channel claims** — AP-12, AP-13, AP-14 and the weak-channel refusal. The code still
  does all of it and the claims are still true. A spec describes what the system does, not what
  its shipped configuration exercises.

## History

- `2026-09-24` — Created as a `stub` by ADR-0040, holding what that decision shelved: out-of-band
  as a rule requirement, a Relay-verified approver, the grant-issuance floor that `approval.md`
  AP-58 was, and second-person rules whose second person Relay authenticated. Each kept with its
  original argument rather than a summary, because the reasoning is the part worth preserving.
- `2026-09-25` — ADR-0040 amended: strict separation withdrawn, MCP the approved pathway, the
  Console and the Control API kept and not relied on. The four shelved properties are unchanged.
  Two owner rulings recorded here rather than solved: **restarts strand an in-flight approval**
  (with the two candidate fixes named and neither chosen) and **surface versus client identity**
  (unresolved by design). *Why this document exists*, the verified-approver item and the AP-69
  entry are corrected so they no longer describe separation as the posture.
