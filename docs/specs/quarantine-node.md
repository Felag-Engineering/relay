# Quarantine a Node

**Status:** aspirational — worked through with the owner on `2026-09-14`, awaiting their review
of this draft. Describes intended behaviour, not the code (see the establishing phase in
`README.md`).

## Purpose

When an operator or an AI-agent stops trusting a Node — it looks compromised, or behaved in a way
nobody can explain — Relay needs a response between *watching it* and *revoking it*. Quarantine is
that middle rung. No Task of any kind reaches a quarantined Node. It stays enrolled and
connected, so lifting the quarantine restores it at once, without re-enrollment.

**A compromised Node cannot lift its own quarantine**: the quarantine lives in a `relay:` label no
Node can write, and is enforced on the Relay, never by the Node. And **it is reversible**, which
revocation is not: the incident ladder is quarantine, then revoke, then Freeze (`enrollment.md`,
`freeze.md`), each larger and harder to undo than the one before.

Quarantine is deliberately *not* a forensics channel. A distrusted Node could lie in a read, and a
hostile Node's output is a prompt-injection path into the AI-agent reading it. Investigation
happens outside Relay.

## Surfaces

| Surface | How it is reached |
|---|---|
| **MCP** | Engage a quarantine; an AI-agent may do so. Lifting is not offered to machine Accounts. |
| **Control API** | Engage and lift. |
| **Admin Console** | Engage and lift; the fleet view renders a quarantined Node as fenced. Lifting demands step-up. |
| **Selectors** | `relay:quarantine=on` is readable and targetable like any `relay:` label (`selectors-and-labels.md`). |
| **Audit trail** | Every engage and lift, including refused attempts (`audit-and-read-lane.md`). |
| **Node plane** | **Nothing.** No message tells a relay-daemon it is quarantined. |

Each surface adapts one capability-layer action for engaging and one for lifting; no surface
decides who may do either (invariant 10).

## Behaviour

### What a quarantine is

- A Node is quarantined exactly when it carries `relay:quarantine=on`. The label is written only as
  the side effect of engaging a quarantine and cleared only by lifting one
  (`selectors-and-labels.md`).
- A quarantine records **who engaged it, when, and a reason**. A reason is required to engage and
  to lift.
- **A quarantine has no expiry.** It lasts until it is lifted.

### Engaging

- **Who:** an Account of `operator` or above, on any surface, **machine Accounts included**: a
  quarantine only ever reduces what can run.
- **Target:** a Selector containing only `relay:` and `tag:` terms — for example
  `relay:node-id=a1b2` or `tag:incident=4412`.
  - `relay:` is allowed because only the Relay writes it.
  - `tag:` is allowed because no Node can write it.
  - `node:` and `state:` are refused. A Node controls both, so a compromised Node could relabel
    itself out of the Selector at the moment of engagement.
- **The Selector is resolved once, when the quarantine is engaged,** into concrete Nodes. Each
  receives `relay:quarantine=on`, and from then on only that label matters. The caller is shown
  the exact Nodes quarantined.
- **One engage counts against the `mutate` blast cap** (invariant 5), so an AI-agent cannot
  quarantine the fleet in one act — the denial-of-service reasoning that keeps machine Accounts
  from engaging a Freeze. More than the cap takes several deliberate acts, or a Freeze.
- Engaging a quarantine on a Node that is already quarantined leaves it quarantined and records
  the attempt; it does not replace the original reason or engager.

### What a quarantine blocks

- **No Task of any risk class is sent to a quarantined Node**, reads included.
- **A routine dispatch excludes it.** A Selector that matches a quarantined Node — through any
  namespace — dispatches to the rest and reports that Node as `quarantined`, never sent
  (`execution.md`).
- **A dispatch targeting it explicitly is refused the same way.** Naming a quarantined Node through
  `relay:` does not reach past the quarantine; it is excluded and reported `quarantined`, and a
  dispatch whose every matched Node is quarantined sends nothing.
- **A preflight** reports each quarantined Node as `quarantined` and queries nothing on it
  (`policy-preflight.md`).
- **Enforced on the Relay, at Selector resolution.** The relay-daemon is never trusted to enforce
  its own quarantine, and never told about it.
- **Tasks already running when a quarantine lands keep running**, as with a Freeze. Cancelling them
  is a separate act (`execution.md`).

### What a quarantined Node still does

- **It stays connected.** Its heartbeats, `Hello` and reload reports are still received and
  recorded (`node-connection.md`), exactly as untrusted as before.
- **It is not told.** Nothing on the wire signals a quarantine to an attacker on the Node.
- Its certificate renews as usual. Quarantine is not revocation.

### Lifting

- **Who:** an `admin`, **human Account only**, with **step-up** re-authentication and an audited
  reason. A jailbroken AI-agent cannot un-quarantine a Node, and neither can a stolen machine
  credential.
- **Target:** a Selector containing only `relay:` terms — typically `relay:node-id=…`, or
  `relay:quarantine=on` combined with another `relay:` term. `tag:` is not accepted for lifting, so
  an edited tag cannot release Nodes nobody meant to release.
- The Selector is resolved once, when the quarantine is lifted; the caller is shown the Nodes
  released.

### Re-enrollment

- A quarantined Node that enrolls again receives a **new identity and a new registry record**
  (`enrollment.md`). The quarantine stays on the old record and does not follow the new identity.
  Where that matters, revoke the Enrollment Token as well.

### Auditing

- Every engage and lift is audited with the Account, the reason, the Selector as written and the
  Nodes it resolved to.
- A refused engage or lift is audited too, and changes nothing.

### Remediation is not a separate capability

- Repairing a distrusted set of Nodes is ordinary Operations and Plans whose Selector targets
  `relay:` — `selectors-and-labels.md` and `execution.md` govern it. A Node cannot be repaired
  through Relay *while* quarantined; lift the quarantine first, or revoke the Node.

## Refusals

| Refusal | Cause |
|---|---|
| Not authorized to engage | Below `operator` |
| Not authorized to lift | Below `admin`, a machine Account, or no fresh step-up |
| Reason required | An engage or lift with no reason |
| Forbidden target | An engage Selector containing a `node:` or `state:` term, or a lift Selector containing anything but `relay:` terms — the refusal names the offending term |
| Blast cap | An engage resolving to more Nodes than the `mutate` cap |
| `no_nodes_matched` | An engage or lift Selector resolving to no Nodes |
| Frozen | Not a refusal: engaging and lifting a quarantine are not dispatch, and a Freeze does not block them |

Per-Node, not a refusal of the whole act: **`quarantined`** — a Node excluded from a dispatch or a
preflight because it is quarantined, never sent.

## Governing ADRs and invariants

- **Invariant 7 — amended 2026-09-16.** Engaging a quarantine may target `relay:` or `tag:`, which
  no Node can write; lifting stays `relay:`-only, and `node:` and `state:` remain forbidden. The
  accepted residual is R17 in `docs/security/threat-model.md`.
- **ADR-0006 — amended 2026-09-16.** Its operating rule that quarantine targets `relay:` only, and its
  pairing of quarantine with remediation and secret distribution as one lane.
- **ADR-0020 — amended 2026-09-16.** Its design of post-enrollment `relay:` label management at
  `admin` + step-up for both setting and lifting is superseded: a quarantine is engaged by
  `operator`+ and lifted by a human `admin` with step-up, and no Account writes a `relay:` label
  directly.
- **ADR-0017** — accepted `node:` forgeability on the condition that quarantine never trusts
  `node:`. That condition still holds.
- **ADR-0013** — Freeze is the fleet-wide rung above this one; the asymmetry — cheap to engage,
  deliberate to release — is borrowed from it.
- **Invariant 5** — an engage counts against the `mutate` blast cap, enforced on the Relay.
- **Invariant 10** — engaging and lifting are one capability-layer action each; no surface
  decides who may do either.

## Seams and proof

Quarantine is unbuilt; everything here is its testing issue's backlog. The likely seams are the
capability layer (authorization, target validation, the cap) and Selector resolution (exclusion).

### What proves each claim

No claim here is proven yet. Claims with **no row**, and so nothing checking them:

- A quarantined Node receives no Task of any risk class, on any Selector, and is reported
  `quarantined`.
- A preflight reports a quarantined Node as `quarantined` and queries nothing on it.
- Engaging accepts only `relay:` and `tag:` terms; lifting accepts only `relay:` terms.
- An engage counts against the `mutate` blast cap.
- A machine Account can engage and can never lift; lifting demands a human `admin` with step-up.
- A reason is required on both acts.
- Nothing on the Node plane signals a quarantine.
- Engage and lift are audited, including refusals.
- A re-enrolled identity does not inherit a quarantine.

### Performance

| Characteristic | Contract | Measured by |
|---|---|---|
| Exclusion at resolution | Checking the quarantine label adds no per-Node round trip; it is a registry read | *(none)* |

## Out of scope

- The namespaces, who writes each, and the Selector grammar — `selectors-and-labels.md`.
- Revoking a Node's identity — `enrollment.md`.
- The fleet-wide stop — `freeze.md`.
- Dispatch, fan-out, cancellation and the blast-radius cap — `execution.md`.
- Repairing Nodes — ordinary Operations and Plans (`execution.md`, `plan.md`).
- Investigating a quarantined Node — outside Relay by design.
- Converging a Node toward a desired configuration, and distributing configuration content.
  Both are configuration management, which is out of realm (`AGENTS.md`).

## Accepted residual risk

- **A hostile Node's self-reports still flow in.** A quarantined Node stays connected, so its
  reports are recorded. They are no more trusted than before, but could mislead a reader who
  forgets that.
- **A re-enrolled identity escapes the quarantine.** A Node that enrolls again with a still-valid
  Enrollment Token is a new Node and is not quarantined. Revoking the token closes it.
- **`tag:` edits before an engage shape who is caught.** An operator — or an AI-agent — who changes
  tags before a quarantine is engaged by `tag:` decides which Nodes that engage resolves to. The
  caller is shown the resolved Nodes, and every tag write is audited, but nothing prevents it.
- **A quarantine above the `mutate` cap takes several acts.** Deliberate, and slower in a large
  incident; a Freeze is the tool for "everything, now".

## Future work

- **Secret distribution** — delivering a replacement credential to affected Nodes during an
  incident. Starts with research into whether it is in realm at all: it sits close to
  configuration management and to invariant 11's rule on secrets.
- **An Admin Console incident screen** that brings quarantine, revocation and Freeze together
  (#431).

## Open questions

1. **Should an AI-agent's quarantine be subject to approval?** Engaging is permitted to machine
   Accounts and bounded by the `mutate` cap, and the shipped gate rules (`approval.md`) do not name
   it. Forced if AI-agent quarantines prove noisy in practice.
2. **Is a single pinned key enough?** ADR-0006 mentions "emergency cohorts"; nothing defines one.
   Forced if a second response state beyond quarantine is ever proposed.
