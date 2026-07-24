# Node-origin (`node:`) label trust is accepted for launch; the security lane stays `relay:`-only

A compromised Node can forge its own `node:` labels. This is **accepted for the
`v0.1.0-beta` real-fleet launch.** CM-signed node attributes — raising the trust of
node-origin labels so a compromised daemon cannot forge them — are **not required for
launch**; they are recorded here as a future option to revisit only if a use-case needs
*trusted* routine targeting. The launch posture rests on one load-bearing rule, already
stated in [ADR-0006](0006-node-enrollment-identity-and-label-authority.md): the
security-sensitive lane targets `relay:` labels only, never `node:`.

This ADR discharges the security debt ADR-0006 explicitly deferred (its
"Accepted limitation" paragraph) to the v0.0.8 pre-launch security pass.

## The question

`node:` labels are node-rooted, Relay-immutable, and authoritative for routine targeting
(env, role, datacenter). The Relay records them but can never modify them, mirroring Policy
(ADR-0002): the Node defines itself. A **compromised Node** — full control of its
relay-daemon process — can therefore report any `node:` label values it likes, and can lie
in the Facts it self-reports. It cannot touch `relay:` labels (Relay-set, Node-immutable).

The question this pass must answer: **given that a compromised Node can forge `node:`
labels, is "the security lane targets `relay:` only" a sufficient launch posture, or must
we ship a CM-signed node-attribute mechanism first?**

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
Node-immutable by construction (ADR-0006, invariant #7). The two **Residual** cells both
live in the routine lane and both reduce to properties the threat model *already accepts*
for a compromised Node:

- **Self-representation is untrusted** — a compromised Node lies about its own `node:`
  labels and Facts. Routine `node:` targeting is trusted only as much as the Node, by design.
- **A compromised Node controls its own execution** — evading receipt of a routine
  Operation is strictly weaker than ignoring one it received.

Neither residual crosses to **another** Node, and neither reaches the security lane.

## Decision: accept for launch

We **accept** the forgeability of `node:` labels for `v0.1.0-beta`. The residual risk is
confined to the routine lane and does not exceed the compromised-Node capabilities the
threat model already assumes. The security-sensitive lane is defended structurally by the
`relay:` namespace, not by trusting `node:` values.

**This accept rests on one condition:** the two operating rules from ADR-0006 must actually
hold in practice — everything a compromised Node must not *attract into* or *evade*
(quarantine, remediation, secret/data distribution) targets `relay:` labels, never `node:`.
That discipline is the load-bearing control here; the label-forgeability itself is
harmless as long as it holds.

**Verified for this pass (v0.0.8):** the `relay:` *namespace* is structurally airtight — a
daemon's `Report` carries no relay-space field, and `SetRelayLabels`/`SetRevoked` are the
only write paths, both Relay-side (`relay/internal/registry/registry.go`,
`relay/internal/registry/memory.go`), so a Node genuinely cannot forge `relay:`. But the
discipline that the security lane *targets* `relay:` is **convention, not structure**: the
Selector parser is namespace-aware (`relay/internal/capability/selector.go`), yet no
dispatch path branches on namespace, there is no typed "security-lane Operation," and
nothing rejects a Selector that points a security-sensitive action at a `node:` label.
The security-lane actions that would need this (a quarantine/remediation Operation,
secret/data distribution) are **not built yet** — so the gap is not a defect in existing
code but an **obligation on those future features**: they must construct `relay:`-namespaced
Selectors by construction rather than accept an arbitrary caller Selector. That obligation
is the real residual to close, and it is a smaller, better-targeted control than signing
labels. See [Follow-up](#follow-up).

## Why not CM-signed node attributes now

CM-signed node attributes (config management signs a Node's attributes; the daemon presents
signatures the Relay verifies, so a compromised daemon cannot forge them) would raise the
trust of the routine lane. We decline it for launch because:

- **It defends nothing the `relay:` lane does not already defend** for the cases that
  matter. Every security-sensitive decision already routes through `relay:`.
- **It only partially closes even the routine residual.** Signing a Node's labels does not
  force it to *apply* what it receives — a compromised Node still controls its own
  execution — so the forge-to-evade residual survives signing.
- **It adds real attack surface and operational burden:** a signing key in the
  config-management path, a trust root for that signer, daemon-side verification, and key
  rotation/revocation — new machinery on the privileged side, for a marginal gain over a
  posture that already isolates every security decision into `relay:`.

The more restrictive option on the privileged (daemon) side is therefore *not* to add the
mechanism, but to keep the trust boundary sharp: `node:` is convenience, `relay:` is
authority.

## Follow-up

The accept is only as strong as the `relay:`-only discipline it rests on, and this pass
verified that discipline is **convention, not structure** (see the Decision above). A scoped
issue tracks closing that gap: when the security-lane actions are built
(quarantine/remediation Operation, secret/data distribution), they must **construct their
Selectors in the `relay:` namespace by construction** rather than accept an arbitrary caller
Selector — with a test asserting a security-lane action cannot be dispatched against a
`node:` Selector. That is a smaller, better-targeted control than CM-signing and directly
protects the condition this decision depends on. Tracked as **#243**, with the residual
carried in the register (#225).

CM-signed node attributes remain a documented future option, to be revisited only if a
concrete use-case needs *trusted* routine targeting (e.g. compliance-grade inventory that
must not rely on Node self-report). It is explicitly **not** a `v0.1.0-beta` launch blocker.

## Consequences

- The launch posture for node-origin label trust is now recorded, not deferred:
  **accept, with the `relay:`-only rule as the load-bearing control.**
- ADR-0006's "Accepted limitation" paragraph is updated to point here; this ADR is the
  resolution of that deferred item.
- The threat model's *Compromised Node* adversary cites this decision as the recorded
  disposition of the `node:`-label-forging risk.
- The residual risk (routine-lane self-representation and routine-Operation argument
  disclosure) is carried into the v0.0.8 residual-risk register (issue #225) as
  **accepted**.
- The `relay:`-only discipline was verified to be convention rather than structure; **#243**
  tracks making it structural when the security-lane actions are built. CM-signed node
  attributes stay shelved as a future option.
