# Node enrollment, identity, and label authority

A Node enrolls using a **reusable, scoped, expiring, revocable enrollment token**. On first
boot the daemon presents the token over server-authenticated TLS and submits a CSR; the
Relay's private CA signs a per-Node client certificate that becomes the Node's identity.
All subsequent connections are plain mTLS. Certificates are short-lived and auto-renewed;
revocation is a Relay-side Node denylist (instant) backed by passive certificate expiry.

## Enrollment at scale

The token is the *enrollment* credential, distinct from the per-Node *identity* certificate.
A single reusable token lets config-management (e.g. Ansible) register hundreds of Nodes in
a loop while each Node still receives its own certificate. Reusable-token risk is bounded by
short TTL, scoping, instant revocation, and the fact that the token can only enroll — never
run Operations.

## Label authority — two non-overlapping namespaces, each immutable from the other side

Labels are the routing input for Operations (remote code execution), so authority over them is
security-critical. The two namespaces have **opposite ownership**, and neither side can touch
the other's:

- **Node-space labels** (`node:…`) are **rooted on the Node** and managed out-of-band by config
  management (e.g. Ansible). The daemon reports them; the **Relay records them but can never
  modify or remove them.** This mirrors Policy (ADR-0002): the Node defines itself, the Relay
  annotates but never overrides. They are **authoritative for routine targeting** (env, role,
  datacenter) and are trusted only as much as the Node.
- **Relay-space labels** (`relay:…`) are **set by the Relay** (stamped at enrollment from the
  token's scope, or by an admin) and **cannot be set, modified, or removed by the Node.** They
  are reserved for the **security-sensitive lane**: quarantine, emergency cohorts, and any
  targeting a compromised Node must not be able to attract-into or evade.

Because the namespaces cannot collide, each side augments labels without overriding the other —
the non-override rule is structural in both directions.

## Consequences

- Making the Node authoritative for its own routine identity prevents careless Relay-side
  overrides (e.g. flipping a `dev` box to `prod`) and routes label changes through the reviewed
  config-management (IaC) path.
- **Two operating rules for the security lane:** (1) remediation/quarantine Selectors target
  `relay:` labels, never `node:` — a compromised Node can't drop its way out of an action aimed
  at it; (2) any Operation that distributes secrets/data targets `relay:` labels — a Node can't
  attract data meant for another trust domain.
- A token scoped to stamp `relay:env=prod` makes bulk-enrolled Nodes provably prod for the
  security lane, without per-Node human label assignment.
- **Accepted limitation:** a compromised Node can forge its own `node:` labels. Routine
  targeting accepts this; the security lane does not. Deeper hardening of node-origin label
  trust (e.g. CM-signed node attributes) and the daemon's privilege model are deferred to a
  pre-launch security pass.

## Amendment — 2026-06-30: label authority reversed

This ADR originally made `relay:` labels the sole authority and treated `node:` labels as
untrusted convenience tags ("security-sensitive Selectors must target `relay:`"). That is
**superseded** by the two-namespace model above: `node:` labels are node-rooted, Relay-immutable,
and authoritative for routine targeting; `relay:` labels are the Relay-set, Node-immutable
security lane. Rationale: Nodes should own their own identity out-of-band like Policy (ADR-0002),
so a careless Relay edit can't mislabel a Node and changes flow through reviewed config
management, while the security-sensitive cases keep an un-evadable `relay:` lane.
