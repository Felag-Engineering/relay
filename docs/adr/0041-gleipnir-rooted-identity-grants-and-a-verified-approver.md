# Gleipnir-rooted identity, Grants, and a verified approver

**Status:** Proposed — 2026-09-30. Amends ADR-0040 and ADR-0024 once accepted; closes #716 and absorbs the research #578 asked for. A Proposed ADR amends nothing until the owner accepts it.

> **Status: Proposed.** This records the direction the owner settled in conversation on
> 2026-09-29 and 2026-09-30, written up for sign-off. It touches the security surface —
> authentication, approval attribution, and the Account model — and must not be adopted without
> review. Until accepted, ADR-0040's interim posture stands unchanged and nothing below binds.

ADR-0040 made Gleipnir the interim owner of the permission model for agent-originated work and
named the cost plainly: on the relied-on path, no approval of an AI-agent's dispatch names a human
Relay verified. #716 exists because that "interim" had no expiry, and #578 because a machine
Account's role is the only Relay-side limit on what it may ask for. Both wait on one decision:
**whose identity does Relay believe, and how far does a principal's authority reach?**

This ADR answers both at once, because they are the same question asked from opposite ends.

## The decision

Eight parts. Each is a constraint, not a status report; the mechanism that delivers it belongs
in the capability specifications this ADR names under *Consequences*.

1. **Gleipnir is the identity root, and the directory.** For an agent-driven deployment,
   Gleipnir is the authority on which principals exist and which teams they belong to. An
   external OpenID Connect provider may sit behind Gleipnir later and feed it; Relay does not
   change when that happens, because Relay never talks to the IdP for this purpose. ADR-0024's
   direction stands: Relay is a protected resource and never an authorization server. One
   Gleipnir per Relay for now; the trusted-issuer set is a set so a second can be added by
   configuration, not by code.

2. **Humans and agents are principals; a team is a grouping, not a principal.** An AI-agent
   is a principal in its own right, roughly one per Gleipnir policy, and carries the list of
   humans accountable for its actions. That list is attribution and notification, never a cap:
   an agent's authority is what was granted to it, not the intersection of its owners'. A team
   is a set of principals that a Grant or an approval audience may name; authority never attaches
   to the team itself. A team named as an approval audience is satisfied by any **human** member
   — an agent in the team never counts as an approver, which the Account kind already enforces.

3. **An agent authenticates with a short-lived credential Gleipnir mints per run.** Relay
   verifies it against Gleipnir's published signing key and resolves it to an existing machine
   Account for that agent. This retires the single shared `gleipnir` bearer token that every run
   uses today, under which Relay cannot tell one policy from another. The credential's lifetime
   is the run's; a configured agent never needs a human to re-authenticate it (#578's standing
   requirement). The URL of Gleipnir and the key Relay trusts are root-owned configuration —
   invariant 11 — and unreachable from any API.

4. **Relay pulls the directory; Gleipnir never writes into Relay.** Relay fetches a signed
   directory document from Gleipnir on a short interval — principals, kind, accountable humans,
   team membership, keyed by stable identifiers — and derives from it which Accounts exist,
   which are enabled, and who is in which team. A principal that leaves the directory is
   disabled, never deleted. Gleipnir may signal "pull now" after an edit; the signal carries no
   data and Relay believes nothing it did not fetch. Gleipnir holds no Relay credential beyond
   an agent's own; Relay holds a read-only credential to Gleipnir. This is the one relaxation of
   ADR-0024's "no auto-provisioning": Accounts are provisioned from a directory Relay verified,
   never from a bearer claim.

5. **Membership is checked against Relay's copy, not carried in tokens.** A token says who the
   principal is and nothing more. At every authorization and approval decision, Relay consults
   the directory copy it holds. One source of truth; the poll interval is a security parameter,
   and removal from a team takes effect on the next pull.

6. **Every action resolves to Permitted, Permitted with approval, or Forbidden — and Relay is
   authoritative.** Grants are shaped Operation × Selector and are deny-by-default from the day
   they ship: an existing Account's Operation authority is nothing until granted. Account
   administration, Freeze and the other control actions keep their role gates and are not Grant
   objects, so a founding admin can always administer. Gleipnir may narrow inside Relay's answer
   — hide a tool, scope a parameter, add its own approval — and may never widen it or remove an
   approval Relay requires.

7. **A Grant scoped to a Node-writable label is convenience, not a boundary.** A Grant may name
   any label namespace, because routine targeting is by `node:` and `state:` and forbidding that
   would make Grants unusable. But invariant 7 stands: a compromised Node forges its own `node:`
   labels and can influence `state:`, so a Grant that is meant to *contain* a principal must
   scope by `relay:` or `tag:`. The specification records the distinction and the Console shows
   it; nothing enforces it in the first pass, which is the accepted residual risk.

8. **Approvals stay in Gleipnir, and the approver reaches Relay verified.** No human is directed
   to Relay to decide (ADR-0040's firewall argument stands). Instead the call that answers a
   parked request carries the approver's own identity credential beside the agent's session
   credential. Relay verifies it against the trusted issuer, checks the approver's team
   membership against its directory copy, and records the approver in the **verified** lane. The
   asserted lane keeps working for clients that cannot do this; a gate rule may require a
   verified approver, and then an asserted one is refused. This is the property
   `approval-assurance.md` shelved as *An approver Relay verifies*, delivered without
   out-of-band — the option that document was careful to keep open.

## What is being traded

- **Relay trusts Gleipnir for who exists and who is on which team.** A Gleipnir compromise can
  add a principal to the webops team. The owner accepted this for now, with independent
  verification against a third party recorded as the eventual direction rather than the first
  pass. What Relay does *not* trust Gleipnir for is unchanged: Policy, Grants, gate rules and
  blast caps are Relay's, and Gleipnir can only narrow.
- **A shared token is replaced by a key.** Rotating Gleipnir's signing key is now an operator
  act on Relay's root-owned configuration, not a paste into an MCP client.
- **Deny-by-default Grants are a migration.** Every existing machine Account loses Operation
  authority the day Grants ship until someone grants it. The milestone must ship the Console and
  Control API surfaces to write Grants *before* enforcement turns on, or a fleet goes dark.

## Alternatives considered

- **Gleipnir pushes Accounts into Relay over the Control API.** Requires Gleipnir to hold a Relay
  `admin` credential, which turns a Gleipnir compromise into full Relay administration. Rejected
  for pull.
- **Group claims in the token, no directory.** Two sources of truth that can disagree, and no way
  to disable a departed principal before its token expires. Rejected in favour of one pulled copy.
- **An external IdP as the root for both products from day one.** The right end state, and
  ADR-0024 already prepares Relay for it. Rejected as the *first* step because neither product has
  run against a live IdP (#351), and because teams have to exist somewhere before an IdP can feed
  them; Gleipnir is where the agents already are.
- **Building an identity provider into Gleipnir.** The reasons ADR-0024 refused this for Relay
  apply to Gleipnir unchanged: a login and consent surface, resets, MFA, and a hand-rolled issuer
  on a security-critical host. Gleipnir signs agent credentials and a directory; it never becomes a
  human IdP.
- **Team membership caps the agent.** Rejected: an agent is a principal with its own Grants; its
  accountable humans are who answers for it, not what bounds it.

## Consequences

- **ADR-0040** is amended: the relied-on path for agent-originated approval gains a verified
  approver. Its firewall argument stands; its "no Relay-verified approver exists in the default
  path" no longer does. **ADR-0024** is amended by decision 4 only. Both amendments are recorded
  in those files when this ADR is accepted, per the crosslink gate.
- `docs/deferred.md` loses its *IdP-federated teams/audiences* and *multi-principal RBAC and
  Grants* entries; both are now this milestone. The direction "Relay never grows a native org
  chart" is kept and satisfied: the org chart is Gleipnir's, and Relay holds a copy.
- `docs/specs/accounts-and-access.md` migrates to the claim format and gains the directory,
  agent-credential and Grant claims. `docs/specs/approval.md` gains the verified-approver claims;
  `docs/specs/approval-assurance.md` is retired into it. All new claims are *Designed, not built*
  until proven.
- `docs/security/threat-model.md` rows R21, R23 and R26 are rewritten; invariant 7's text is
  unchanged, and the Grant distinction in decision 7 is recorded in the spec, not the invariant.
- **The wire contract between the two products has one home, here.** The directory document,
  its signature, the agent credential's claims, and the approver header are specified under
  `docs/api/`; Gleipnir's developer documentation links to it and does not restate it. Relay is
  the party that verifies and refuses, so Relay owns the contract.
- **Sequencing across the two repositories:** contract first; Relay's verification side next,
  proven against a fake issuer in Relay's own tests; Gleipnir's minting and directory side after;
  the cross-product smoke lane is where the end-to-end proof lands. Every issue names its
  counterpart in the other repository.

## Open questions, for the specification rather than this ADR

- The directory document's freshness bound and what Relay does when a pull fails for longer
  than it: keep serving the last copy, or refuse new dispatches.
- Whether a `tag:` label may be written by Gleipnir through the directory, or stays
  operator-only on the Control API (invariant 7 says the latter today).
- The engine for Grants and gate rules — #285's Cedar proposal, evaluated jointly so Relay does
  not grow two policy languages. Out of this ADR's scope by design.
