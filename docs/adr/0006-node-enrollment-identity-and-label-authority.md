# Node enrollment, identity, and label authority

**Status:** Accepted; amended by ADR-0020, ADR-0031 and ADR-0034; amended 2026-10-22 (token scope is the enrollment action's key set; reserved keys refused at mint; the use limit is named at mint).

ADR-0048 supersedes the 2026-10-22 amendment where enrollment's `relay:` key set is the token's
scope alone: the scope is optional, and every enrollment also stamps `relay:node-id`.

A Node enrolls using a **reusable, scoped, expiring, revocable Enrollment Token**. On first
boot the daemon presents the token over server-authenticated TLS (no client certificate yet)
and submits a CSR; the Relay's private CA signs a per-Node client certificate that becomes the
Node's identity. All subsequent connections are mTLS. Certificates are short-lived (~14 days)
and auto-renewed over mTLS before expiry; revocation is a Relay-side Node denylist (instant)
backed by passive certificate expiry.

## Enrollment at scale

The Enrollment Token is the *enrollment* credential, distinct from the per-Node *identity*
certificate. One reusable token lets config management (e.g. Ansible) register hundreds of
Nodes in a loop while each Node still gets its own certificate. The risk is bounded by short
TTL, scoping, instant revocation, and the token's only power being to enroll, never to run
Operations.

## Certless enrollment and Relay-generated identity

The `Enrollment.Enroll` unary RPC is served over **server-authenticated TLS without a client
certificate**. It is the only method in the certless allowlist
(`Enrollment_Enroll_FullMethodName`); every other RPC, the Tunnel stream included, requires mTLS.

The transport layer (`tls.VerifyClientCertIfGiven`) admits certless connections; the per-RPC
interceptors deny by default and consult the allowlist to pass Enroll through. A client cert
that is presented but fails verification is still rejected at the TLS layer.

The `node_id` and the CN in the issued certificate are **Relay-generated at enrollment**. The
daemon's CSR subject is discarded and `SignCSR` sets `CN = node_id`. A daemon cannot choose or
influence its own identity. This is a hard security invariant and must not be relaxed.

## Certificate renewal over mTLS

Identity certificates are renewed before expiry over the Node's **existing mTLS connection**
by a dedicated `Enrollment.Renew` unary RPC: no Enrollment Token, same `node_id`, same registry
entry and provenance.

### Protocol

`RenewRequest` carries only a PEM CSR, which supplies **only the new public key**. `node_id`
and the CN come exclusively from the **verified TLS peer cert CN** (via
`transport.NodeIDFromContext`), never from the CSR subject, and `SignCSR` sets `CN = node_id` as
at enrollment.

`RenewResponse` echoes `node_id`, the new PEM certificate, and the CA bundle. The daemon
asserts `resp.node_id == persisted node_id` and **refuses to persist** if they differ, the
more restrictive option on the privileged side.

### Auth model

`Enrollment.Renew` is **not** in the certless allowlist (`certless` map in `main.go`), so the
per-RPC interceptor (`UnaryServerInterceptor`) requires a verified client certificate for it.
Enroll (token-authenticated, certless) and Renew (cert-authenticated over mTLS) are two auth
models sharing one service.

### Registry

Renew does **not touch** the registry: no `Upsert`, no label changes, no new
`EnrollingTokenID`, so provenance and relay-space labels from enrollment are preserved. The
registry's `CertFingerprint` reflects the renewed cert only after the daemon's **next Hello
`Upsert`** (on reconnect), and until then is stale relative to the live client cert.
**Operators must not treat the registry fingerprint as a liveness assertion of the current live
client cert.**

### Jittered scheduling

The daemon schedules renewal at a random fraction **[50%, 75%]** of the cert lifetime:

- For a 14-day (336 h) cert: renewal fires at [168 h, 252 h] after issuance.
- This leaves [84 h, 168 h] (3.5–7 days) of margin for retries and failure recovery.
- 100k+ Nodes spread their renewals over ~3.5 days rather than hitting the Relay simultaneously.

On RPC failure the daemon retries with bounded jittered backoff (capped at ~1 hour), and never
stops while the cert is still valid; the margin absorbs extended outages.

### Deferred: live-connection reconnect

The renewed cert is adopted on the **next `connect_mtls`** (process restart or reconnect); the
live session keeps the old cert until then. This is safe: TLS does not re-validate a cert
mid-session, and renewal fires days before expiry. Forcing an immediate reconnect to adopt the
new cert was left **out of scope**.

## Label authority — two non-overlapping namespaces, each immutable from the other side

Labels are the routing input for remote code execution, so authority over them is
security-critical. The two namespaces have **opposite ownership**, and neither side can touch
the other's:

- **Node-space labels** (`node:…`) are **rooted on the Node** and managed out-of-band by config
  management (e.g. Ansible). The daemon reports them; the **Relay records them but can never
  modify or remove them.** This mirrors Policy (ADR-0002): the Node defines itself, the Relay
  annotates but never overrides. They are **authoritative for routine targeting** (env, role,
  datacenter) and are trusted only as much as the Node.
- **Relay-space labels** (`relay:…`) are **set by the Relay** (stamped at enrollment from the
  Enrollment Token's scope, or by an admin) and **cannot be set, modified, or removed by the
  Node.** They are reserved for the **security-sensitive lane**: quarantine, emergency cohorts,
  and any targeting a compromised Node must not be able to attract-into or evade.

Because the namespaces cannot collide, the non-override rule is structural in both directions.

**2026-08-07 — third namespace added:** [ADR-0020](0020-tag-labels-operator-grouping-namespace.md)
adds operator-set **`tag:…`** grouping labels (Relay-stored, Node-immutable, never a valid
security-lane target) and post-enrollment `relay:` label management (`admin` + step-up — the
quarantine lever). The authority rules above for `node:`/`relay:` are unchanged.

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
  targeting accepts this; the security lane does not. Node-origin label trust was settled by
  [ADR-0017](0017-node-origin-label-trust.md): accepted for launch, with the `relay:`-only
  security lane as the load-bearing control and CM-signed node attributes shelved.

## History / superseded decisions

The entries below are historical. The body above is authoritative.

- **Before 2026-06-30 — original label authority model:** `relay:` labels were the sole
  authority for security-sensitive Selectors; `node:` labels were treated as untrusted
  convenience tags.
- **2026-06-30 — label authority moved to the two-namespace model** in the body, so a careless
  Relay edit cannot mislabel a Node while the security lane keeps an un-evadable `relay:` lane.
- **2026-06-30 — added the certless Enroll path and certificate renewal over mTLS** (both now
  in the body).
- **2026-08-07 — two namespaces extended to three:** ADR-0020 added the operator-set `tag:`
  grouping namespace and post-enrollment `relay:` label management (see note in the body).

## Amendment (2026-09-16): the security lane targets labels no Node can write; quarantine may engage by `tag:`

Owner decision, 2026-09-16 (#582), ratifying what `docs/specs/selectors-and-labels.md` and
`docs/specs/quarantine-node.md` already asserted. Invariant 7 is rewritten in `AGENTS.md`,
keeping its number.

**What changed.** The two operating rules in *Consequences* are narrowed for one act. Remediation
and any Operation that distributes secrets or data still target `relay:` and only `relay:`, for
the reasons given there. **Engaging a quarantine may target `relay:` or `tag:`.** Lifting one
targets `relay:` only. `node:` and `state:` remain forbidden for every security-lane act.

**Why the rule could be narrowed without losing what it protected.** The rule exists so a
compromised Node cannot attract itself into, or drop itself out of, an action aimed at it. That
is about *who can write the label*, and no Node can write `tag:` any more than `relay:`. The
acts differ in direction: remediation and secret distribution *give* something to the Nodes
they resolve to, so a mis-shaped target is a grant; a quarantine only *reduces* what may run, so
a mis-shaped target over- or under-fences. `tag:` is what an operator reaches for mid-incident
(`tag:incident=4412`); enumerating `relay:node-id` terms instead slows containment.

**Why lifting stays `relay:`-only.** Lifting widens again. An edited tag must never release Nodes
nobody meant to release.

**The pairing of quarantine with remediation and secret distribution as one lane** is loosened
accordingly: quarantine is its own act (`quarantine-node.md`); remediation is ordinary Operations
and Plans on `relay:` targets; secret distribution is Future work there.

**What is given up, and accepted.** Whoever can write tags before an engage decides which Nodes
that engage resolves to — an `operator` or an AI-agent holding an `operator` machine Account. The
engage resolves once, shows the caller the exact Nodes, and every tag write is audited; nothing
prevents it. Recorded as **R17** in `docs/security/threat-model.md`.

## Amendment (2026-09-20): amended by ADR-0031 and ADR-0034

Two amendments other ADRs made to this one, recorded here late.

- **ADR-0031** (2026-08-18): enrollment is bootstrapped by a **join string** (Enrollment Token
  plus CA fingerprint in one pasteable value), and the daemon pins the Relay's CA from it. Token
  scope and identity issuance are unchanged.
- **ADR-0034**: the label namespaces are **four** (`node:`, `relay:`, `tag:`, `state:`), not the
  three the History section stops at. `state:` is Relay-derived from the registry at
  Selector-resolution time, from a closed vocabulary, written by nobody. Invariant 7 as rewritten
  on 2026-09-16 names all four.

## Amendment (2026-10-22): token scope is the enrollment action's key set

Owner decision, 2026-10-22, while migrating `docs/specs/enrollment.md`. ADR-0020's amendment
of 2026-09-16 holds that each `relay:` key is defined with the action that writes it, so that no
Account writes a `relay:` label directly (invariant 7). This ADR predates that rule and lets the
`admin` who mints an Enrollment Token choose the `relay:` scope the enrollment stamps. The
2026-09-14 draft of `enrollment.md` reconciled the two by moving a token's labels to `tag:`;
that draft was retired unbuilt on 2026-10-21, and this amendment records the reconciliation
that stands instead.

**Decided.** Where enrollment writes `relay:` Labels, the key set it writes is the token's
scope, and the minting `admin` defines that set for the enrollment action at mint, under the
same role floor and audit as the mint. The scope is therefore not a generic write to an existing
Node: it is fixed before any Node exists, applies only to Nodes the token enrolls, and is on the
record with the token. **A mint refuses a scope key that any Relay action owns, Enrollment's own
included** — every key in the closed `relay:` set's table in
`docs/specs/selectors-and-labels.md`, and any key the Relay derives — naming the key and its
owning action.
Invariant 7's text is unchanged. `enrollment.md` carries the claims (EN-3 today; the refusal as
EN-35, *Designed, not built*).

**Also recorded.** ADR-0031's amendment of 2026-10-21 narrows this ADR's "reusable" token: a
mint names a positive use limit or asks explicitly for unlimited use, and is refused if it does
neither.
