# Node connection

**Status:** designed, not built, as of `2026-11-05`.
**Claim prefix:** `NC`
**Governed by:** ADR-0004, ADR-0005, ADR-0006, ADR-0014, ADR-0017, ADR-0031; invariants 4, 6, 7,
8, 11, 14.

## Purpose

Every managed server (a Node) keeps one lasting, trusted link to the Relay, which it opens
itself: a Node never accepts an incoming connection. Both ends prove who they are on every
connect, so a Node refuses an impostor Relay and the Relay refuses an impostor Node. The Relay
sends work down the link; the Node sends back results, a regular sign of life, and a
description of itself. "Connected" means the Node was heard from recently, not merely that its
connection is still open. What a Node says about itself is trusted only as much as the Node:
it can never grant itself authority, change its Policy, or write the labels the security lane
targets.

## Surfaces

| Surface | How it is reached |
|---|---|
| Node plane | One mutually authenticated TLS stream per Node, the `Tunnel.Open` call, always opened by the relay-daemon. The daemon sends `Hello`, heartbeats, snapshots and Task results; the Relay sends Tasks, cancellations and Policy queries. `Enrollment.Enroll` and `Enrollment.Renew` share the listener and belong to `enrollment.md`. |
| relay-daemon | Dials the Relay, verifies it, holds the stream and reconnects. Which address it dials is `enrollment.md`. |
| Registry reads | Connected state, `last_seen`, `outdated`, and the self-reported fields of the Node's registry record, on `list_nodes`, `describe_node`, the Control API's Node read and the Console fleet view, as `query.md` describes. |
| Audit trail | The connection audit records designed below, read as `audit-and-read-lane.md` describes. |
| Relay configuration | The certificate hostname and the minimum daemon version (`relay-configuration.md`). Every timing here is a built-in constant, not a setting. |
| MCP, Control API, Console | No surface opens, closes or reshapes a connection. Revoking a Node ends its connection, and `enrollment.md` owns that. |

## Behaviour

### The handshake

- **NC-1** The relay-daemon always opens the connection, as one long-lived gRPC bidirectional
  stream, and never listens on an inbound port.
- **NC-2** Every Node-plane call except `Enrollment.Enroll` (`enrollment.md`) is mutual TLS:
  the Relay presents its server certificate and the daemon its client certificate, and each
  verifies the other.
- **NC-3** A Node's identity is the Node ID in its verified client certificate, never a value
  the daemon sends.
- **NC-4** On every connect the daemon verifies the Relay's server certificate against the CA it
  pinned at enrollment, and trusts no system or public roots.
- **NC-5** The daemon reads its identity from its state directory at each connect, so a renewed
  certificate is used from the next connect; nothing forces a reconnect. The registry records
  the certificate fingerprint presented on the Node's latest connect.
- **NC-6** The Relay presents one server certificate on both listeners and re-issues it
  in-process before it expires, so a running Relay never presents an expired one (ADR-0031).
  Only the Node plane asks for a client certificate.

### What connected means

- **NC-7** A Node is connected while its current stream's heartbeats arrive within the deadline,
  not merely while the stream is open. Only a heartbeat resets the deadline.
- **NC-8** The daemon sends a heartbeat every 60 seconds, jittered by up to 20% either way, so a
  fleet restarted at once does not arrive in lockstep.
- **NC-9** The Relay closes a stream that has gone 3 heartbeat intervals (180 seconds) without a
  heartbeat, and marks the Node offline. The interval and the allowance are constants.
- **NC-10** Both sides run HTTP/2 keepalive with constant timings. The Relay pings a connection
  idle for 30 seconds and closes it, marking the Node offline, when the ping goes unanswered for
  20 seconds. The daemon pings every 60 seconds and abandons a connection whose ping goes
  unanswered for 60 seconds.
- **NC-11** `last_seen` records the Node's last contact, a heartbeat or a `Hello`. Connected is
  never derived from it.
- **NC-12** There is no Task acknowledgement: no message acknowledges a Task and no
  `unacknowledged` outcome exists. A Task sent to a silently dead Node waits out NC-9 (R52).

### One current stream

- **NC-13** The Relay holds one current stream per Node for dispatch. A stream opened for a Node
  ID replaces the existing one, and the replaced stream ends with an error naming a newer stream
  as the cause.
- **NC-14** Only the current stream receives Tasks.
- **NC-15** Ending a replaced stream never marks the Node offline.

At-most-once across a replaced or dropped stream is `daemon-installation.md`'s, and a Task's
outcome is `execution.md`'s (invariant 4).

### Reconnecting

- **NC-16** The daemon reconnects with exponential backoff from 1 second to a 30-second cap,
  each wait drawn between half and all of the current step. It returns to the base only after
  a connect whose `Tunnel.Open` call succeeded, never after a failed handshake or `Open`.
- **NC-17** The daemon retries indefinitely. Only a malformed Relay endpoint stops it.
- **NC-18** The Relay applies no admission limit to reconnecting Nodes. After a Relay restart
  only the daemons' jitter spreads the fleet (R53).

### What a Node reports about itself

- **NC-19** The first message on a stream is `Hello`, carrying the daemon version, Facts, the
  declared and built-in `node:` labels, the Policy fingerprint and the template-set fingerprint.
  A `PolicySnapshot` follows, carrying whether Raw Exec is enabled, then a `TemplateSnapshot`.
- **NC-20** The self-report is read once per connection: a Policy or label change on the Node
  reaches the registry in the `Hello` after the daemon restarts, and a later `Hello` on the same
  stream is ignored.
- **NC-21** The Relay records each `Hello` field it keeps only in a bounded shape. The Policy fingerprint
  is 64 lowercase hex characters, and the template-set fingerprint the same or `unloadable`.
  The daemon version is semver of at most 253 bytes. Hostname, OS, kernel and architecture are
  at most 253 bytes of visible ASCII. An IP address is a plain address with no zone, and a list
  of more than 256 is dropped whole. A `node:` label is within the bounds
  `selectors-and-labels.md` sets.
- **NC-22** A field that fails its bound is recorded as not reported, or the entry dropped,
  never truncated or rewritten, and the stream stays up. A stored value that fails its bound is
  declined the same way when read back.
- **NC-23** The fingerprints a `PolicySnapshot` or `TemplateSnapshot` carries are bounded when
  the registry serves them on a Node read: one that fails the `Hello` bound is served empty.
- **NC-24** A self-reported label that is not `node:` is dropped. Nothing a Node reports writes
  `relay:` or `tag:` labels, Policy, or any part of its registry record beyond the self-reported
  fields (invariant 7; R3, R51).
- **NC-25** Each connect replaces the self-reported fields of the Node's registry record. Facts
  and `node:` label changes are recorded and never audited.

### Daemon versions

- **NC-26** A daemon's version never refuses its connection: an older daemon connects and is
  flagged `outdated` in the registry, and the minimum-version gate refuses it at dispatch
  (`execution.md`; invariant 14).
- **NC-27** No Node-plane message installs, upgrades or replaces a binary (invariant 14).

## Refusals

- **NC-28** The Relay refuses a connection whose client certificate does not chain to its CA, or
  names a revoked Node, during the TLS handshake, before any stream opens. It checks revocation
  again before each call runs.
- **NC-29** A Node-plane call other than `Enroll` without a verified client certificate is
  refused as unauthenticated before its handler runs.
- **NC-30** Against a Relay whose certificate does not chain to the pinned CA, the daemon sends
  nothing, `Hello` included, and retries on its backoff.
- **NC-31** An expired client certificate is refused at the handshake like any other unverified
  one. The daemon keeps retrying and cannot succeed; only enrolling again, which issues a new
  Node ID (`enrollment.md`), brings the Node back.
- **NC-32** A stream whose first message is not `Hello` is refused as an invalid argument.

Stream replacement is not a refusal: the older stream ends because a newer one exists (NC-13).

## Designed, not built

| Claim | Statement | Milestone |
|---|---|---|
| NC-33 | Between two connects of the same Node, a change in the reported Policy fingerprint or in whether Raw Exec is enabled writes one audit record with the before and after values. A Node's first connect writes none, and the record blocks nothing. | v0.2.1 |
| NC-34 | Between two connects of the same Node, a change in the reported daemon version writes one audit record with the before and after versions, marked as a downgrade when the new version is lower. The record blocks nothing. | v0.2.1 |
| NC-35 | Between two connects of the same Node, a change in the client certificate fingerprint writes one audit record with the before and after fingerprints. The record blocks nothing. | v0.2.1 |
| NC-36 | The Relay counts stream replacements per Node and writes at most one audit record per Node per 10 minutes, carrying the number of replacements since the previous record, so a single replacement is recorded and a flapping pair writes a bounded number of records (R54). | v0.2.1 |
| NC-37 | The Relay measures each heartbeat's timestamp against its own clock and records the difference on the Node's registry record as its clock skew: a Relay-measured value, kept apart from the self-reported Facts. Clock skew never blocks a connection or a dispatch. | v0.2.1 |
| NC-38 | `Hello` carries no Node ID: its field is deprecated in `/proto`, the daemon never sets it and the Relay never reads it. | v0.2.1 |

## Out of scope

- **Issuing, renewing and revoking certificates, the join string, the first-contact pin and the
  address the daemon dials**: `enrollment.md`.
- **What a Task is, its outcomes, the minimum-version gate's refusal and cancellation**:
  `execution.md`.
- **The `state:` markers derived from connection facts** (`offline`, `outdated`,
  `cert-expiring`, `raw-exec-enabled`): `selectors-and-labels.md`.
- **What the Policy fingerprint means**: `policy.md`.
- **How registry state and audit records read on each surface**: `query.md` and
  `audit-and-read-lane.md`.
- **Installing the relay-daemon and its dedup markers**: `daemon-installation.md`. **Where the
  certificate hostname and minimum daemon version are set**: `relay-configuration.md`.
  **Metrics, including the server certificate's remaining lifetime**: `observability.md`.
- **How control-plane callers authenticate**: `accounts-and-access.md`.
- **Refusing a daemon too old to speak the protocol at connect**: cut. Compatibility across
  daemon versions is the minimum-version gate (ADR-0014) and an additive `/proto`.
- **A Task acknowledgement deadline and admission pacing**:
  `roadmap: relay/fast-failure-and-fleet-admission`.
- **A self-report without reconnecting**: `roadmap: relay/policy-catalog-and-live-reload`.
- **A company-issued certificate**: `roadmap: relay/bring-your-own-pki`.
- **The Node plane's scale contract**, which nothing measures yet:
  `roadmap: relay/research/spec-future-work/node-connection`.
- **Several Relays sharing a fleet**: deferred by ADR-0005 to a future ADR.

## Proof

<!-- proof:begin -->
| Claim | Proven by | Seam |
|---|---|---|

Unproven: NC-1, NC-2, NC-3, NC-4, NC-5, NC-6, NC-7, NC-8, NC-9, NC-10, NC-11, NC-12, NC-13, NC-14, NC-15, NC-16, NC-17, NC-18, NC-19, NC-20, NC-21, NC-22, NC-23, NC-24, NC-25, NC-26, NC-27, NC-28, NC-29, NC-30, NC-31, NC-32.
<!-- proof:end -->

## Retired

None.
