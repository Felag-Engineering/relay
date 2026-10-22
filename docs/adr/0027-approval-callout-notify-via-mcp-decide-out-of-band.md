# Approval callout: notify via MCP, decide out-of-band

**Status:** Accepted; amended by ADR-0010, ADR-0029, ADR-0038, ADR-0040 and ADR-0044; rewritten
2026-10-22 (ADR-0046).

Behaviour: `docs/specs/approval.md`; shelved properties: `approval-assurance.md`. Decisions keep
their numbers, which code cites; the eleven dated amendments are in git, mapped at the end.

## Decision

Some dispatches must wait for a human. When a gate rule matches, Relay parks the request and
asks a human, in words Relay wrote rather than the AI-agent. The question may travel over the
AI-agent's own MCP session, but the guarantee never depends on that session: an authenticated
decision endpoint on the Control API can always answer, on a credential the requesting session
does not hold. An approval binds to exactly what the human was shown, expires, and never
widens what a Node's Policy allows. Every request and every decision is an audit record that
says who asked, for whom, who approved, and over which channel.

## The decisions

1. **A gated request parks before dispatch.** Parking creates no Job and no Tasks: the
   approval **Request** is the durable object, and a Job is minted only if a decision releases
   one. It survives disconnects and restarts because it is state in the store, not a held call.
2. **Delivery envelopes are conveniences; the Control API endpoint is the guarantee.** A
   question reaches a human in-band over MCP, through the tool surface and MRTR elicitation,
   the protocol's server-asks-the-user round trip (ADR-0029), or as an MCP task handle
   (ADR-0028); or out-of-band through the webhook and the Control API's authenticated decision
   endpoint. Both paths may decide any parked request, whichever surface created it
   (ADR-0040). MCP is the expected path for agent-originated work; the Control API endpoint,
   the only out-of-band path since the Console decides no approval (ADR-0044), is always
   available and is the rescue. A deployment whose client cannot be asked loses convenience,
   not safety. The in-band path holds only if the client routes the question to a human,
   never to its model and never auto-answered; for Gleipnir that is Gleipnir's to keep.
3. **Delivery is not the decision, and Relay writes the content.** Relay decides whether
   approval is required and what the human sees: the Operation, its arguments, the resolved
   fan-out, per-Node preflight verdicts, the blast size and the requester. The AI-agent supplies
   none of the words. The envelope decides only how the human is reached.
4. **Channel strength is per rule, checked, and stamped by the receiving surface.** `in-band`
   trusts the requesting client; `out-of-band` is evidence, a decision on a credential the
   session does not hold. The self-confirmation rung defaults to `in-band`. The Control API
   stamps `out-of-band` because of what it is, and no request body carries a channel. A
   decision, approve or deny, must arrive on a channel at least as strong as its rule demands,
   because a denial is terminal too. Out-of-band as a rule *requirement* is shelved: the
   mechanism stands, and the shipped default does not demand it (ADR-0040).
5. **The confirmation ladder.** Rung 1, no gate. Rung 2, self-confirmation: the requester sees
   the Relay-authored preflight and confirms; **human requesters only**, so a machine
   requester's lowest gated rung is 3. The Console's step-up apply (ADR-0026) is rung 2 fused
   into execution. Rung 3, second-person: the audience excludes the requester. Every request
   made over MCP is agent-grade, whoever's OAuth identity authorizes the session, because the
   calls are model-generated and steerable by injected content. An in-band MRTR *answer* on a
   human Account's OAuth session is that human's verified decision (ADR-0029).
6. **Gate rules narrow only, and approval is not authorization.** A rule may require approval
   where none was required; it never grants what Policy would refuse, and an approved dispatch
   still traverses Selector, Policy and blast cap unchanged. Rules match on risk class, blast
   size, Selector namespace, principal and Operation, and require a count, an audience,
   requester exclusion, a channel and a window.
   - **Where rules live.** Rules are runtime objects in the store, written only by a human
     `admin` in the Console with step-up, audited with old and new values, and in effect from
     the next dispatch. No MCP tool or Control API route writes them, and none may be added:
     an AI-agent must never be able to edit the gate that gates it (invariant 11, ADR-0010).
     The store is the only source; no rule file is read.
   - **The seeded default.** A Relay whose store holds no rules at first start seeds, once, as
     an audited system act: `read` ungated, `mutate` and Raw Exec at in-band self-confirmation,
     with second-person and out-of-band available to raise any rule to. It never re-seeds, even
     after an `admin` deletes every rule (R15).
   - **The webhook's URL, secret and timeout stay security floor**: repointing them hides
     every request from the humans who should answer.
   - **Overlapping rules** take the strictest requirement, but their audiences union and a rule
     naming no audience leaves it unrestricted: accepted as R18 (`docs/security/threat-model.md`).
7. **Quorum: store the general shape.** A requirement is checked against a set of decisions, so
   N-of-M needs no migration; rules expose `count: 1 | 2`, partial state is visible, and each
   decision is its own audit record.
8. **An approval binds to a hash of the rendered preflight, and drift re-parks.** The hash
   covers the Operation, its arguments and the resolved fan-out; a dispatch that no longer
   matches at release parks again. Every rendering of a request, the composer's preflight, the
   rendering a decider is given in the client's question or on the Control API, and Job detail,
   shares one rendering contract, because a request that renders differently where it is
   approved than where it runs reopens the gap between what a human saw and what ran.
9. **Everything expires.** A parked request and an approval's validity both carry a TTL.
10. **The attribution triple, in two structurally separate lanes.** `requested_by` is
    verified, `on_behalf_of` is asserted, `approved_by` is verified with its channel and hash.
    The audit schema keeps the lanes apart, so a jailbroken AI-agent can assert anything and
    forge nothing (`GLOSSARY.md`, *Attribution*).
11. **The request and every decision are first-class audit records**, carrying `approval_id`
    and, where a window released the work, `grant_id`, so who asked, for whom, who approved
    and what happened is one query.
12. **Batch and window approvals, because fatigue is a security property.** A rubber-stamped
    approval is worse than none: it manufactures evidence of consideration. An approval grant
    covers a declared Scope for a bounded time and number of uses, and every Job it releases
    audits back to it.
    - A **Scope is not a Match**: an omitted field in a Match gates more, in a Scope it would
      pre-approve more. Every bound is mandatory, an empty Operation list covers nothing, and a
      Scope over work nothing gates is refused. A Scope has no namespace term, and a stored
      grant that pinned one releases nothing.
    - Requesting a grant is an ordinary approval Request whose subject is a Scope, decided on
      the same path under the same quorum, audience, requester exclusion, machine-self-decision
      rule and channel strength. Its requirement is **derived** from the Scope's worst case
      under the live gate, never declared by the requester. A floor of second-person,
      out-of-band issuance is shelved with decision 4's requirement (`approval-assurance.md`).
    - A grant's window is at most **4 hours**, so it stays inside one shift, and its uses at
      most 1000; both maxima hold in code as well as in the request (AP-57 for the window). A
      grant **never covers Raw Exec** (AP-56): an arbitrary command has no allow-list for an
      approver to have seen.
    - Uses are claimed inside one conditional update that also requires the authorizing Request
      to be approved, so the window stays shut until a human opens it and a bound of 20 never
      releases 21. A grant is never bound to a Job; the join runs from the audit trail.
    - Revocation is a first-class act at the role floor of approving, by anyone at that floor,
      and a second revocation is a conflict.
    - The approver is to be shown a diff against the last approved similar action, which is
      where fatigue is actually beaten; that half is deferred
      (`docs/proposals/approval-diff-against-last-similar.md`).
13. **An MCP task handle is not a Relay Task** (`GLOSSARY.md`).

**For decisions 4 and 5, who may decide.** A decision's role floor is its request's, from the
role table in `accounts-and-access.md`: `operator` for an Operation, `admin` for Raw Exec. A
machine Account never decides its own request, under any configuration; its kind travels on the
authenticated Principal, and an unknown kind is a machine. A park answers `202 Accepted` with
`pending_approval` on the Control API.

## Why

MCP's elicitation maps cleanly onto approve and deny, but it rides the AI-agent's own session:
a naive client can hand the question to its model, a compromised one can answer it, and MCP has
no audience routing or approval standard. So the guarantee is built alongside MCP, on a channel
the requesting session cannot reach, with Relay writing every word the approver reads.

## Alternatives

- **In-band elicitation only.** Rejected as the guarantee; kept as an envelope.
- **Wait for MCP to standardise approvals.** It may not arrive, and would still be client-side.
- **Approval as Policy, on the daemon.** Policy decides alone and offline (ADR-0002).
- **Relay pushes to Slack, PagerDuty or email.** Rejected for now: routing is org-specific and a
  lasting credential burden; the webhook lets someone else own it.
- **A per-approval credential.** Not adopted: an Account-authenticated call already holds what
  the session does not. Revisit if approvers must hold no Relay Account at all.
- **Parking every mutation until an admin writes a rule**, or **a file that seeds the store.**
  Declined: the first leaves a fresh Relay unable to mutate, the second is two sources.
- **Raising the ordinary default to the grant bounds.** Every routine mutation would cost a window.

## Where the amendments went

| Dated amendment | Now in |
|---|---|
| 2026-08-14, the decision endpoint (#270) | decisions 4 and 5 and the paragraph after them |
| 2026-08-16, batch and window grants (#378) | decisions 11 and 12 |
| 2026-09-15 and both of 2026-09-16: store-backed rules, the seeded default, no namespace pin, the audience union | decisions 6 and 12; Alternatives; R15, R18 |
| 2026-09-20, ADR-0038's *Plan* and ADR-0029's envelope | decisions 2 and 8 |
| 2026-09-24, the grant bounds and ADR-0040; 2026-09-25 | decisions 2, 4 and 12; R25 |
| 2026-09-28 and 2026-09-29, the OAuth-session answer | decision 5 |
| 2026-10-18, ADR-0044 | decisions 2 and 8 |
