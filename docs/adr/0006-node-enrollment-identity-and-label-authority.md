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

## Amendment 2 — 2026-06-30: certless Enroll path

The `Enrollment.Enroll` unary RPC is served over **server-authenticated TLS without a client
certificate**. This is the only method in the certless allowlist
(`Enrollment_Enroll_FullMethodName`); all other RPCs — including the Tunnel stream — remain
strictly mTLS-required and are unaffected.

The transport layer (`tls.VerifyClientCertIfGiven`) already permits certless connections at the
TLS level; the per-RPC interceptors enforce the default-deny rule and consult the allowlist to
pass Enroll through without a verified client cert. Any presented (but unverified) client cert
is still cryptographically rejected at the TLS layer.

The `node_id` assigned to an enrolling Node and the CN in the issued certificate are both
**Relay-generated at enrollment time**. The CSR subject submitted by the daemon is discarded;
`SignCSR` sets `CN = node_id` authoritatively. A daemon cannot choose or influence its own
identity. This is a hard security invariant (ADR-0006) that must not be relaxed.

## Amendment 3 — 2026-06-30: cert renewal over mTLS

Short-lived identity certificates (~14 days) are renewed before expiry over the Node's
**existing mTLS connection** via a dedicated `Enrollment.Renew` unary RPC — no enrollment
token, same `node_id`, same registry entry and provenance.

### Protocol

`RenewRequest` carries only a PEM CSR. The CSR supplies **only the new public key**; `node_id`
and the certificate CN are derived exclusively from the **verified TLS peer cert CN** (via
`transport.NodeIDFromContext`) and never from the CSR subject. `SignCSR` sets `CN = node_id`
authoritatively as it does for enrollment. The daemon cannot choose or influence its renewed
identity.

`RenewResponse` echoes `node_id`, the new PEM certificate, and the CA bundle. The daemon
asserts `resp.node_id == persisted node_id` and **refuses to persist** if they differ — the
more restrictive option on the privileged side.

### Auth model

`Enrollment.Renew` is **not** in the certless allowlist (`certless` map in `main.go`). The
per-RPC interceptor (`UnaryServerInterceptor`) therefore requires a verified client certificate,
making Renew automatically mTLS-required with no interceptor changes. Enroll (token-authenticated,
certless) and Renew (cert-authenticated over mTLS) are different auth models sharing one service.

### Registry

The registry is **not touched** by Renew: no `Upsert`, no label changes, no new
`EnrollingTokenID`. This structurally preserves provenance and relay-space labels from initial
enrollment. The registry's `CertFingerprint` reflects the renewed cert only after the daemon's
**next Hello `Upsert`** (on reconnect). During the renewal margin (~3.5–7 days before expiry)
the fingerprint is stale relative to the live client cert. **Operators must not treat the
registry fingerprint as a liveness assertion of the current live client cert.**

### Jittered scheduling

The daemon schedules renewal at a random fraction **[50%, 75%]** of the cert lifetime:

- For a 14-day (336 h) cert: renewal fires at [168 h, 252 h] after issuance.
- This leaves [84 h, 168 h] (3.5–7 days) of margin for retries and failure recovery.
- 100 k+ nodes spread their renewals over ~3.5 days rather than hitting the Relay simultaneously.

On RPC failure, the daemon retries with bounded jittered backoff (up to ~1 hour cap). It never
stops retrying while the cert is still valid — the large margin absorbs extended outages.

### Deferred: live-connection reconnect

The renewed cert is adopted on the **next `connect_mtls`** (process restart or reconnect). The
live mTLS session continues with the old cert until then. This is safe: TLS does not re-validate
a cert mid-session, and the renewal fires with days of margin before expiry. Forcing an immediate
reconnect to adopt the new cert on the live connection is **out of scope** for this milestone.
