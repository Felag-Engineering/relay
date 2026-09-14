# Response lane

**Status:** stub — aspirational, not yet worked through with the owner (`2026-09-13`).

## Purpose

When an operator or an AI-agent comes to distrust a Node, or has to act on a set of Nodes
because of what they *are* rather than what they *say they are*, it needs a lane that a
compromised Node cannot evade and cannot attract itself into. The response lane is that lane:
**quarantine**, **remediation** and **secret or data distribution**, each targeted only through
`relay:` labels, the one namespace no Node can write.

It is the part of Relay that makes "response, not configuration" concrete. Routine fleet work
can trust a Node's own description of itself; response work must not, because the Node being
responded to is the one most likely to be lying.

## Surfaces

Almost nothing reaches this capability today.

- `relay:` labels are **read** everywhere a Label is read, and are **written** only at
  enrollment, stamped from the Enrollment Token's scope (`enrollment.md`).
- The Admin Console fleet view **renders** a Node carrying `relay:quarantine=on` as fenced.
  Nothing can set that label on a live Node yet.
- There is no quarantine, remediation or secret-distribution action on MCP, the Control API or
  the Console. Post-enrollment `relay:` label management is designed (ADR-0020) and unbuilt
  (#430); the Console incident screen is designed and unbuilt (#431).

## Behaviour

_To be established by interrogation._

Candidate claims, from the ADRs and the code — each to be confirmed, changed or dropped:

- A Node is quarantined exactly when it carries `relay:quarantine=on` — key and value; any other
  value, `relay:quarantine=off` included, is not quarantined.
- Setting or removing any `relay:` label on a live Node requires `admin` plus a fresh step-up
  re-authentication, and is audited with actor, Node and reason.
- A `relay:` write accepts explicit Node IDs, or a Selector containing only `relay:` terms.
- A response-lane action constructs its target Selector in the `relay:` namespace by
  construction; it never accepts an arbitrary caller Selector (#243).
- Quarantine is reversible; lifting it carries the same gate as setting it.
- No rung of the incident ladder — quarantine, revoke, Freeze — stops a Task already in flight.
- A compromised Node cannot remove its own quarantine, and cannot place itself into the target
  set of a secret distribution.

## Refusals

_To be established by interrogation._

Candidate claims, from the ADRs and the code — each to be confirmed, changed or dropped:

- A `relay:` write by an `operator`, or by an `admin` without a fresh step-up, is refused.
- A `relay:` write by Selector containing any `node:`, `tag:` or `state:` term is refused, with
  a refusal that names the offending term.
- A response-lane action dispatched against a Selector outside `relay:` is refused at the
  capability layer, not by convention.
- No surface anywhere writes a `node:` or `state:` label.

## Governing ADRs and invariants

- **Invariant 7** (ADR-0006, ADR-0020, ADR-0034) — only `relay:` is a valid security-lane
  target; this capability is the lane that sentence exists to protect.
- **ADR-0006** — sets the two operating rules: remediation and quarantine target `relay:`, and
  anything that distributes secrets or data targets `relay:`.
- **ADR-0017** — accepts `node:` forgeability for launch *on the condition* that this lane stays
  `relay:`-only, and records that the condition is convention, not structure, until #243.
- **ADR-0020** — schedules post-enrollment `relay:` management at `admin` + step-up, and sets the
  incident ladder; ADR-0035 amends the ladder with account suspension (deferred, #443).
- **ADR-0013** — Freeze is the fleet-wide rung; this lane is the per-Node rung below it.
- **Invariant 10** — every action here is one capability-layer method; no surface decides.

## Seams and proof

_Not yet written._

## Out of scope

- The namespaces themselves, who writes each, and Selector grammar — `selectors-and-labels.md`.
- Emergency Freeze — `freeze.md`.
- Node revocation and identity — `enrollment.md`.
- Dispatch, fan-out and the blast-radius cap for whatever a remediation runs — `execution.md`.
- Gating a response action on human approval — `approval.md`; walking a multi-step remedy —
  `plan.md`.
- Converging a Node toward a desired configuration, and distributing configuration content.
  Both are configuration management, which is out of realm (`AGENTS.md`).

## Open questions

1. **What does quarantine actually do to a Node?** Today it is a label and nothing else: no
   dispatch path reads it, so a quarantined Node still receives routine work. Is it a fence
   *out* (refuse all routine dispatch to it), a fence *in* (only response-lane actions reach
   it), a marker for humans and AI-agents to target, or some combination?
2. If quarantine refuses dispatch, **where** is that enforced — Relay-side at Selector
   resolution, or daemon-side? And what may still run on a quarantined Node: read-class
   Operations for forensics, nothing, or only an allow-list?
3. **Is the quarantine vocabulary a single pinned key**, or a small closed set of
   `relay:` response labels (quarantine, emergency cohort, trust tier)? ADR-0006 mentions
   "emergency cohorts"; nothing defines one.
4. **Is secret or data distribution in realm at all?** ADR-0006 names it as a security-lane
   action, but pushing a secret to a Node sits close to configuration management and to
   invariant 11's "secrets as file paths". Is it a response action (rotate a leaked key *now*),
   or should it be dropped from this lane?
5. **Is "remediation" a distinct kind of action**, or just an ordinary Operation or Plan whose
   Selector happens to be `relay:`-only? #243 assumes a typed "security-lane Operation"; the
   simpler answer is that no such type exists and the constraint lives on the target.
6. **Who may quarantine?** The design says `admin` + step-up for both set and lift. Should an
   AI-agent be able to *propose* or *request* a quarantine through approval, and may a machine
   Account ever set one?
7. **Should quarantine be asymmetric like Freeze** — cheap to engage, deliberate to lift? The
   current design gates both identically.
8. Does quarantine **survive a re-enrollment**? A revoked-then-re-enrolled Node gets a fresh
   identity and loses its `relay:` labels.
9. Should a quarantine **expire**, or carry a reason and an owner that must be revisited?
10. What does a quarantined Node's daemon **learn** — is it told, or kept unaware so an
    attacker on it gets no signal?
11. Is quarantine **by Selector** worth having at all, given the Console resolves a filter to
    Node IDs first? Bulk quarantine by `relay:` term is a large lever.
12. How does this lane relate to the **closed remediation loop** (#208) — probe, propose,
    approve, apply — which is currently framed as general-purpose rather than `relay:`-bound?

## History

- `2026-09-13` — stub created to name the capability.
