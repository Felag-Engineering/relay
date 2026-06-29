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

## Label authority — two non-overlapping namespaces

- **Node-space labels** (`node:…`) are self-reported by the daemon. They are only as
  trustworthy as the Node and are used for self-description and convenience targeting.
- **Relay-space labels** (`relay:…`) are authoritative, set by the Relay and stamped at
  enrollment from the token's scope. A Node cannot set or forge them.

The namespaces cannot collide, so the Relay augments a Node's labels without ever overriding
its self-reported set — the non-override rule is structural, not a precedence rule.

## Consequences

- **Security-sensitive Selectors must target `relay:` labels.** A compromised Node can lie
  about its `node:` labels (e.g. self-report `node:env=dev` to dodge a patch) but cannot
  forge `relay:env=prod`.
- A token scoped to stamp `relay:env=prod` makes every Node enrolled with it provably prod
  from birth — bulk enrollment without per-Node human label assignment.
