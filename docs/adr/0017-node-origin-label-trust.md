# Node-origin (`node:`) label trust is accepted for launch; the security lane stays `relay:`-only

**Status:** Accepted.

A compromised Node can forge its own `node:` labels. This is **accepted for the
`v0.1.0-beta` real-fleet launch.** CM-signed node attributes, which would stop a compromised
daemon forging them, are **not required for launch**; they are a future option if a use-case
needs *trusted* routine targeting. The launch posture rests on one load-bearing rule from
[ADR-0006](0006-node-enrollment-identity-and-label-authority.md): the security-sensitive lane
targets `relay:` labels only, never `node:`.

This ADR discharges the debt ADR-0006 deferred (its "Accepted limitation" paragraph) to the
v0.0.8 pre-launch security pass.

## The question

`node:` labels are node-rooted, Relay-immutable, and authoritative for routine targeting
(env, role, datacenter); the Node defines itself, as with Policy (ADR-0002). A **compromised
Node**, in full control of its relay-daemon, can report any `node:` labels and Facts it likes.
It cannot touch `relay:` labels (Relay-set, Node-immutable).

The question: **given that, is "the security lane targets `relay:` only" a sufficient launch
posture, or must a CM-signed node-attribute mechanism ship first?**

## Attack surface

A forged `node:` label can only do two things: make a Node **match a Selector it should not
match** (attract), or **stop matching a Selector it should match** (evade). Mapped against
the lanes:

| Lane | Forge-to-attract | Forge-to-evade |
|---|---|---|
| **Routine** (`node:`-targeted admin Operations) | **Residual.** The Node pulls a routine Operation toward itself and learns its arguments. Bounded: it already owns the box, cannot attract onto *another* Node, and Policy + risk-class + blast cap still gate what runs. | **Residual.** The Node makes *itself* invisible to a routine Operation. Weaker than what it already has — a compromised Node can simply not apply what it receives — and it can only hide *itself*, never another Node. |
| **Security** (quarantine / remediation) | **Blocked.** Operating rule (1): the remediation/quarantine lane targets `relay:`, which the Node cannot forge. | **Blocked.** Operating rule (1) is precisely why this holds — a compromised Node cannot drop its way out of an action aimed at it. |
| **Secret / data distribution** | **Blocked.** Operating rule (2): any Operation distributing secrets/data targets `relay:` — a Node cannot attract data meant for another trust domain. | n/a |

Every cell that matters for security is **Blocked by the `relay:` namespace**, which is
Node-immutable by construction (ADR-0006, invariant #7). Both **Residual** cells are in the
routine lane and reduce to what the threat model *already accepts* for a compromised Node:

- **Self-representation is untrusted.** Routine `node:` targeting is trusted only as much as
  the Node, by design.
- **A compromised Node controls its own execution.** Evading receipt of a routine Operation
  is strictly weaker than ignoring one it received.

Neither residual crosses to **another** Node, and neither reaches the security lane.

## Decision: accept for launch

We **accept** the forgeability of `node:` labels for `v0.1.0-beta`. The residual risk stays in
the routine lane and does not exceed what the threat model already assumes of a compromised
Node. The security lane is defended structurally by the `relay:` namespace, not by trusting
`node:` values.

**This accept rests on one condition:** ADR-0006's two operating rules must hold in practice.
Everything a compromised Node must not *attract into* or *evade* (quarantine, remediation,
secret/data distribution) targets `relay:` labels, never `node:`.

**Verified for this pass (v0.0.8):** the `relay:` *namespace* is structurally airtight. A
daemon's `Report` carries no relay-space field, and `SetRelayLabels`/`SetRevoked` are the only
write paths, both Relay-side (`relay/internal/registry/registry.go`,
`relay/internal/registry/memory.go`). But that the security lane *targets* `relay:` is
**convention, not structure**: the Selector parser is namespace-aware
(`relay/internal/capability/selector.go`), yet no dispatch path branches on namespace, there is
no typed "security-lane Operation", and nothing rejects a security-sensitive action aimed at a
`node:` label. The security-lane actions are **not built yet**, so this is an **obligation on
those future features**, not a defect in existing code. See [Follow-up](#follow-up).

## Why not CM-signed node attributes now

CM-signed node attributes (config management signs a Node's attributes and the Relay verifies
the signatures) would raise the trust of the routine lane. Declined for launch because:

- **It defends nothing the `relay:` lane does not already defend** for the cases that
  matter. Every security-sensitive decision already routes through `relay:`.
- **It only partially closes even the routine residual.** Signing labels does not force a
  compromised Node to *apply* what it receives, so the forge-to-evade residual survives.
- **It adds attack surface and operational burden:** a signing key in the config-management
  path, a trust root for it, daemon-side verification, and key rotation and revocation, all
  new machinery on the privileged side for a marginal gain.

The more restrictive option on the daemon side is therefore *not* to add the mechanism, and to
keep the trust boundary sharp: `node:` is convenience, `relay:` is authority.

## Follow-up

The accept is only as strong as the `relay:`-only discipline, which is convention, not
structure. When the security-lane actions are built (quarantine/remediation, secret/data
distribution), they must **construct their Selectors in the `relay:` namespace** rather than
accept an arbitrary caller Selector, with a test asserting a security-lane action cannot be
dispatched against a `node:` Selector. That is a smaller, better-targeted control than
CM-signing. Tracked as **#243**, with the residual carried in the register (#225).

CM-signed node attributes remain a future option, revisited only if a concrete use-case needs
*trusted* routine targeting (e.g. compliance-grade inventory that must not rely on Node
self-report). They are **not** a `v0.1.0-beta` launch blocker.

## Consequences

- The launch posture for node-origin label trust is recorded: **accept, with the
  `relay:`-only rule as the load-bearing control.** ADR-0006's "Accepted limitation"
  paragraph points here.
- The threat model's *Compromised Node* adversary cites this decision.
- The residual risk (routine-lane self-representation and routine-Operation argument
  disclosure) is carried into the residual-risk register (issue #225) as **accepted**.
