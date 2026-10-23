# Node connection

**Status:** aspirational — worked through with the owner on `2026-09-14`, awaiting their review
of this draft. Describes intended behaviour, not the code (see the establishing phase in
`README.md`).

## Purpose

An enrolled Node needs one lasting, trusted link to the Relay. The Relay sends Tasks down it; the
relay-daemon sends back results, heartbeats and its view of itself. This
capability is that link: how a relay-daemon dials home, how each side proves who it is, what the
Node says about itself, how the link survives drops and restarts, and how the Relay knows whether
a Node is reachable now.

When this fails silently, a Node looks healthy while unreachable, or unreachable while its daemon
is fine, and the AI-agent and the operator reason about a fleet that does not exist. So
"connected" is defined by evidence the Node is alive, not by a stream that has not yet noticed
it died, and that holds at fleet scale without flooding the network.

## Surfaces

| Surface | How it is reached |
|---|---|
| **Node plane** | One mTLS stream per Node, always opened by the relay-daemon. The daemon sends `Hello`, heartbeats and Task results. The Relay sends Tasks and cancellations. |
| **relay-daemon** | Dials the Relay address persisted at enrollment, checks the Relay against the pinned CA on every connect, holds the stream, and reconnects with bounded, jittered backoff. |
| **Registry reads** | Connected state, last heartbeat, daemon version, `outdated`, clock skew and the other self-reported facts appear through `list_nodes`, `describe_node`, the Control API's Node routes and the Console fleet view. How they read is `query.md`. |
| **Audit trail** | Changes to a Node's security-relevant self-report, and repeated stream replacement, are audit events. Querying them is `audit-and-read-lane.md`. |
| **Relay configuration** | The minimum daemon version and the server certificate, set in the configuration file (`relay-configuration.md`). The heartbeat interval (60 seconds) and the missed-heartbeat allowance (3) are built-in constants. The server certificate and listeners are security floor (invariant 11); the minimum daemon version is a reach-bounding setting. Store-backed settings edited in the Console are not in the MVP (`roadmap: relay/settings-in-the-console`). |
| **MCP / Control API / Console** | No surface opens, closes or reshapes a connection. Revocation disconnects a live Node, but `enrollment.md` owns that. |

## Behaviour

### The link

- **The relay-daemon always starts the connection**, over one long-lived gRPC bidirectional
  stream. A Node never listens on an inbound port.
- **A Node's identity is its client certificate**, never anything the daemon says in a message.
  Every Node-plane call except enrollment requires a verified client certificate.
- **The relay-daemon refuses an untrusted Relay.** On every connect it checks the Relay's
  certificate against the CA pinned at enrollment, and it connects to the Relay address persisted
  at enrollment. First contact — the join string and how that trust is established — is
  `enrollment.md` (ADR-0031).
- **One Relay server certificate** serves the Node plane and the control plane, and is re-issued
  in-process before it expires, so a long-running Relay never presents an expired certificate. Its
  expiry is exposed as a metric (`observability.md`).
- **A renewed Node certificate is used from the next connect.** There is no forced reconnect; the
  registry's certificate fingerprint updates when the Node next connects, and that change is
  audited (below).
- A Node is `state:cert-expiring` once its certificate is inside the last quarter of its lifetime.
  The fraction is built in (`relay-configuration.md`).

### What "connected" means

- **A Node is connected while its heartbeats arrive within the deadline** — not merely while a
  stream has not closed.
- The relay-daemon sends a heartbeat every **60 seconds**, jittered, so a fleet restarted at once
  does not arrive in lockstep. This is built.
- The Relay marks a Node **offline after 3 missed heartbeats** (about 3 minutes) and closes its
  stream. The interval and the allowance are built-in constants, not settings. This is MVP work, not yet
  built.
- **gRPC keepalive runs on both sides**, so a dead link underneath is noticed by the daemon too, and
  it reconnects rather than sitting on a broken stream. This is MVP work, not yet built.
- `last_seen` is a record of the last heartbeat, never a proxy for connected.

### Acknowledging a Task

There is no Task acknowledgement in the MVP. A dispatch to a silently dead Node is caught by the
missed-heartbeat allowance above, not in seconds. An acknowledgement deadline, the
`unacknowledged` outcome it would produce, and marking a Node offline at once on a missed one are
later work (`roadmap: relay/fast-failure-and-fleet-admission`).

### One current stream per Node

- **A Node has exactly one current stream.** Opening a stream for a Node identity closes any
  existing stream for that identity; the newest replaces the old.
- Only the current stream receives Tasks.
- **Closing a replaced stream never marks the Node offline.** Liveness follows the current stream's
  heartbeats.
- A Task already sent on a replaced stream is covered by at-most-once: the relay-daemon dedups by
  Task ID across reconnects and process restarts, and `execution.md` owns those semantics.
- **Repeated replacement for one Node is audited.** Two parties presenting the same certificate
  keep replacing each other; that churn makes a stolen certificate in use visible.

### Reconnecting

- The relay-daemon reconnects with **bounded, jittered exponential backoff**, and resets the
  backoff only after a session that actually opened.
- A fleet reconnecting after a Relay restart is spread only by that jitter. The Relay does not
  pace admission in the MVP; pacing with a retry-after hint is later work
  (`roadmap: relay/fast-failure-and-fleet-admission`).

### What a Node reports about itself

- On connect, `Hello` carries the daemon version, Facts, the declared and built-in `node:` labels
  (`selectors-and-labels.md`), the Policy fingerprint and its validity, and whether Raw Exec is
  enabled (`policy.md`).
- **A Policy or declared-label change takes effect when the relay-daemon restarts**, and the new
  self-report arrives in that connection's `Hello`. A fresh self-report without reconnecting
  comes with live reload (`roadmap: relay/policy-catalog-and-live-reload`).
- **Clock skew** is measured from heartbeats and recorded as a Fact. It never blocks anything.
- **Nothing a Node reports can write `relay:` or `tag:` labels, Policy, or anything on the Relay
  beyond the Node's own self-report.** A self-report is trusted exactly as much as the Node
  (ADR-0017).

### Changes to a self-report

Security-relevant changes are **audit events**, recorded with before and after:

| Change | Why it is audited |
|---|---|
| Policy fingerprint | What the Node permits changed — including Raw Exec becoming enabled, or the Policy becoming `invalid` |
| Daemon version | Called out specially when it is a downgrade |
| Certificate fingerprint | A renewal, or an identity change worth noticing |
| Repeated stream replacement | Possible duplicate use of one certificate |

Facts and `node:` label changes are recorded but not audited, because they churn. **Nothing is
blocked by any of these** — this is visibility, not a gate.

### Daemon versions

- **A daemon too old to speak the protocol is refused at connect** with an error naming the
  version problem.
- **An older but compatible daemon connects** and appears in the registry flagged `outdated`. It is
  refused Tasks by the minimum-version gate, never the connection (ADR-0014), so the registry
  doubles as the upgrade view.
- The connection is never a path for pushing binaries (invariant 14).

### When the Relay is unreachable for a long time

- The relay-daemon retries indefinitely, within its backoff bounds.
- **If its certificate expires before it can renew, the Node goes dark** until an operator
  re-enrolls it. There is no recovery path around enrollment.

### Scale

This spec carries the Node plane's scale contract: **10,000 sessions held today, 100,000 as the
design ceiling**. Full-fleet readmission is not bounded by a Relay-side rate in the MVP.

## Refusals

| Refusal | Cause |
|---|---|
| No or unverified client certificate | Refused before any stream opens |
| Revoked identity | Refused before any stream opens (`enrollment.md` owns revocation) |
| Untrusted Relay | The relay-daemon does not connect and sends no `Hello` |
| Protocol too old | The daemon cannot speak the protocol; refused at connect with a version error |
| `outdated` Node's Task | Resolves `version_refused` and is never sent (`execution.md`) |
| A `relay:` or `tag:` label in a self-report | Never recorded as authoritative |

A replaced stream is not a refusal: it is closed because a newer one exists, and never marks the
Node offline.

## Governing ADRs and invariants

- **Invariant 6** (ADR-0005, ADR-0006) — mTLS everywhere, and the relay-daemon refuses an
  untrusted Relay. Binds on every connect, not only first contact.
- **Invariant 4** (ADR-0004) — at-most-once survives reconnects and stream replacement because the
  daemon dedups by Task ID.
- **Invariant 14** (ADR-0014) — the version gate refuses dispatch, not the connection, and the link
  never carries binaries.
- **Invariant 7** (ADR-0006, ADR-0017) — a self-report can carry `node:` labels and influence
  `state:`, but never write `relay:` or `tag:`.
- **Invariant 11** — the listeners and the server certificate are security floor; the minimum
  daemon version only bounds reach and may become a runtime operator setting.
- **ADR-0005 — needs amending.** It names keepalive tuning at scale as a consequence; this spec
  decides the specifics: the heartbeat deadline, keepalive on both sides, and one current stream
  per Node.
- **ADR-0006** — renewal over the live link, adopted on the next connect; forcing a reconnect stays
  out.
- **ADR-0031** — one server certificate rotated in-process, and the pinned CA the daemon checks.
  First contact is `enrollment.md`.
- **ADR-0017** — a Node's self-report is trusted only as much as the Node.
- **`/proto`** (invariant 8): the MVP needs no addition here. The Task acknowledgement, an
  admission refusal's retry-after hint and a self-report sent on reload would each need one when
  their roadmap work is taken up.

## Seams and proof

_Not yet written._ This spec's claims are the backlog of its testing issue. Connection behaviour
spans both binaries, so most claims need the cross-binary suites or the dev fleet, not `make
verify` alone.

### What proves each claim

No claim here yet cites a test.

Claims with **no row**, and so nothing checking them:

- Connected means a heartbeat within the deadline; offline after 3 missed heartbeats; gRPC
  keepalive on both sides.
- A new stream replaces the old; closing a replaced stream never marks the Node offline; Tasks go
  only to the current stream; repeated replacement is audited.
- A Policy or label change reaches the registry in the `Hello` after a daemon restart.
- The four self-report changes are audited with before and after; Facts and label changes are not.
- A daemon too old for the protocol is refused at connect; a compatible outdated one connects.
- The daemon checks the pinned CA and uses the persisted address on every connect.
- Clock skew is recorded and never blocks.

### Performance

| Characteristic | Contract | Measured by |
|---|---|---|
| Sessions held | 10,000 today; 100,000 design ceiling | *(none)* |
| Full-fleet readmission | Spread by the daemon's jittered backoff; no Relay-side pacing in the MVP | *(none)* |
| Heartbeat load | One heartbeat per Node per interval (60 seconds by default) | *(none)* |
| Dead-Node detection, for dispatch and the fleet view | Within the missed-heartbeat allowance (about 3 minutes by default) | *(none)* |

## Out of scope

- **Issuing, renewing and revoking identity certificates, Enrollment Tokens and the join string**:
  `enrollment.md`.
- **What a Task is, dispatch states, at-most-once semantics, outcomes and cancellation**:
  `execution.md`.
- **The `state:` markers derived from connection facts** (`offline`, `outdated`, `cert-expiring`,
  `policy-invalid`, `raw-exec-enabled`): `selectors-and-labels.md`.
- **What the Policy fingerprint and validity mean**: `policy.md`.
- **How registry state and audit events read on each surface**: `query.md` and
  `audit-and-read-lane.md`.
- **Installing the relay-daemon and its local configuration**: `daemon-installation.md`.
- **Where timing values and the minimum daemon version are set**: `relay-configuration.md`.
- **A Task acknowledgement deadline and admission pacing**: not in the MVP
  (`roadmap: relay/fast-failure-and-fleet-admission`).
- **Metrics for the server certificate and connection health**: `observability.md`.
- **High availability across multiple Relays**: deferred by ADR-0005 to a future ADR.

## Accepted residual risk

- **A Node's self-report is forgeable.** A compromised Node can lie about its version, Facts,
  labels, Policy fingerprint and Raw Exec state. Auditing changes makes a lie visible only when it
  changes; it never makes a report true.
- **A dead Node can show connected for about 3 minutes.** The missed-heartbeat allowance bounds the
  fleet view, and in the MVP it bounds dispatch too: a Task sent to a dead Node in that window gets
  no answer until the Node is marked offline.
- **A fleet reconnecting at once is not paced.** After a Relay restart only the daemons' jittered
  backoff spreads the load.
- **A stolen certificate is detected, not prevented.** Repeated stream replacement surfaces
  duplicate use; stopping it is revocation (`enrollment.md`).

## Open questions

None open; settled with the owner on `2026-09-14`.
