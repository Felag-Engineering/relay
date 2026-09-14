# Node connection

**Status:** stub — aspirational, not yet worked through with the owner (`2026-09-13`).

## Purpose

After a Node has enrolled, it needs one lasting, trusted link to the Relay. The Relay pushes
Tasks down that link, and the relay-daemon sends back results, heartbeats and its view of
itself. This capability is that link: how a relay-daemon dials home, how each side proves to
the other who it is, what the Node says about itself when it arrives, how the link survives
drops and restarts, and how the Relay knows whether a Node is reachable right now.

It is the plumbing that decides whether the fleet is actually there. When it fails silently,
a Node looks healthy while being unreachable, or looks unreachable while its daemon is fine.
Either way the AI-agent and the operator end up reasoning about a fleet that doesn't exist.

## Surfaces

| Surface | Today |
|---|---|
| Node plane | The mTLS-required `Tunnel.Open` bidirectional stream. The daemon sends `Hello`, then `Heartbeat`s and Task results; the Relay sends `Ping`s, Tasks and `TaskCancel`s. |
| relay-daemon | Dials the Relay's address from local config or the persisted identity, holds the stream, and reconnects with jittered backoff. |
| Registry reads | Connected state, `last_seen`, daemon version and `outdated` show up through `list_nodes`, `describe_node`, the Control API Node routes and the Console fleet view. `query.md` owns how they read. |
| Relay config | The minimum daemon version and the server certificate (one certificate, rotated in-process). Operator-set, unreachable from any API. |
| MCP / Control API / Console | No surface opens, closes or reshapes a connection directly. Revocation disconnects a live Node, but `enrollment.md` owns that. *(Uncertain: whether a "disconnect this Node" action is wanted apart from revoke.)* |

## Behaviour

_To be established by interrogation._

Candidate claims, from the ADRs and the code — each to be confirmed, changed or dropped:

- The connection is always started by the daemon, over one long-lived gRPC bidirectional stream. A Node never listens on an inbound port.
- Every Node-plane RPC except `Enroll` needs a verified client certificate, and the Node's identity is the certificate's CN, never anything the daemon claims in a message.
- The daemon refuses a Relay whose certificate chain does not root in the pinned CA.
- One server certificate serves both the Node plane and the control plane. It is re-issued in-process before it expires, so a long-running Relay never presents an expired certificate.
- On `Hello`, the Relay records the daemon version, Facts, `node:` Labels, the Policy fingerprint and the template-set fingerprint. None of these can write `relay:` Labels, Policy or templates.
- A Node is marked connected for exactly as long as its stream is open, and the flag flips the moment the stream closes, however it closed. `last_seen` is never used as a proxy for it.
- A Node below the configured minimum daemon version still connects, heartbeats and appears in the registry flagged `outdated`. It is refused Tasks, not refused the connection.
- The daemon reconnects with bounded, jittered exponential backoff, and resets the backoff only after a session that actually opened.
- The daemon's at-most-once dedup state survives a reconnect and a process restart, so a Task re-sent after a drop never runs twice. `execution.md` owns the semantics.
- A renewed identity certificate is adopted on the next connect, not mid-session.
- Heartbeats are jittered so that a fleet restarted all at once does not reach the Relay in lockstep.

## Refusals

_To be established by interrogation._

Candidate claims, from the ADRs and the code — each to be confirmed, changed or dropped:

- A connection with no client certificate, an unverified one, or a denylisted one is refused before any stream opens.
- A daemon presented with an untrusted Relay certificate does not connect and does not send `Hello`.
- A `relay:` Label in `Hello` is never recorded as authoritative.
- An `outdated` Node's Tasks resolve as refused, with a reason naming the version gate, and are never sent.

## Governing ADRs and invariants

- **ADR-0005** — gRPC bidirectional streaming over mTLS, daemon-initiated, on one long-lived stream. It names keepalive tuning at scale and single-Relay stickiness as consequences.
- **ADR-0006** — the client certificate is the Node's identity. Renewal happens over the live mTLS connection and is adopted on the next connect.
- **ADR-0031** — one server certificate, multiple SANs, in-process rotation, and a join string whose CA fingerprint the daemon pins. It amends how ADR-0005 and ADR-0006 authenticate the Relay on first contact.
- **ADR-0014** — the minimum-version gate refuses dispatch, not connection, and the registry doubles as the upgrade dashboard. `/proto` stays additive within `relay.v1`.
- **ADR-0004** — at-most-once execution depends on the daemon persisting Task IDs it has seen across reconnects. This capability owns only the persistence across the link, not the semantics.
- **ADR-0017** — whatever a Node reports in `Hello` is trusted only as much as the Node.
- **Invariant 6** — mTLS everywhere, and the daemon refuses an untrusted Relay.
- **Invariant 4** — reconnect must never turn at-most-once into at-least-once.
- **Invariant 7** — `Hello` can carry `node:` Labels and can influence `state:`, but can never write `relay:` or `tag:`.
- **Invariant 14** — the connection is never a path for pushing binaries. The version gate is the Relay's only lever.

## Seams and proof

_Not yet written._

## Out of scope

- Issuing, renewing and revoking identity certificates, Enrollment Tokens and the join string → `enrollment.md`.
- What a Task is, dispatch states, at-most-once semantics, cancellation → `execution.md`.
- The `state:` markers derived from connection facts (`offline`, `outdated`, `cert-expiring`) → `selectors-and-labels.md`.
- How registry state reads on each surface → `query.md`.
- Installing the daemon and its local config file → `daemon-installation.md`.
- Where the minimum daemon version and listener addresses are set → `relay-configuration.md`.
- High availability across multiple Relays. ADR-0005 defers it to a future HA ADR.

## Open questions

1. **The join string is decided but not built.** ADR-0031 replaces `RELAY_CA_BUNDLE_PATH` with a fingerprint-pinned join string and says the daemon should persist the Relay address. The daemon and its sample env file still read `RELAY_CA_BUNDLE_PATH`, and `enrollment.md` describes the old path. Is the join string still the intended first-contact shape? If so, does this spec own the pinned-fingerprint check and the address that persists across reconnects, or does `enrollment.md`?
2. **What does "connected" mean when the network half-fails?** The flag is tied to the stream's lifetime, and the Relay itself says no heartbeat timeout is enforced. There is also no gRPC keepalive on the Node plane, though ADR-0005 says one must be tuned. A half-open TCP link could therefore show a Node as connected for a long time. How quickly should a silent Node be declared offline, and by which mechanism: heartbeat deadline, transport keepalive, or both?
3. **Two streams, one Node.** The Relay tracks several concurrent streams per Node, but the connected flag is a single boolean set true on open and false on close. If a daemon reconnects before its old stream is torn down, does the old stream closing mark a live Node offline? Should a second stream replace the first, be refused, or coexist?
4. **Which stream gets a dispatched Task** when two streams are open for one Node?
5. **Relay-side refusal of an outdated Node, beyond dispatch.** ADR-0014 keeps outdated Nodes connected on purpose. Is there a version below which the Relay should refuse the connection outright, for example a daemon too old to speak `relay.v1` at all?
6. **Should the server-certificate rotation window be observable** to an operator, for example the expiry of the certificate currently served? Or is "it rotates" enough?
7. **Reconnect storm at 100k.** Backoff tops out at 30 seconds with equal jitter. After a Relay restart, is it acceptable for 100k daemons to arrive within about 30 seconds? Or should the Relay be able to shed or pace reconnects, and is that behaviour a caller may depend on?
8. **What may a Node claim in `Hello`, and what does the Relay do when that changes mid-life?** A changed Policy fingerprint, template-set fingerprint or daemon version across reconnects is recorded today. Should a change be an audit event, a `state:` marker, or nothing?
9. **Should a renewed certificate take effect immediately?** ADR-0006 deferred forcing a reconnect to pick up a renewed certificate. Does that stay out, given that the registry's certificate fingerprint is stale until the next `Hello`?
10. **Clock trust.** `Heartbeat` and `Ping` carry wall-clock milliseconds. Is Node clock skew something this capability should detect or report, or ignore?
11. **Behaviour while the Relay is unreachable for days.** The daemon retries forever and renewal has 3.5 to 7 days of margin. When that margin runs out, is the intended end state "the Node goes dark until an operator re-enrolls it"?
12. **Is this spec where the Node plane's scale claim lives** (10k now, 100k ceiling)? If so, what is the contract: connections held, time for all Nodes to reconnect, or memory per connection?

## History

- `2026-09-13` — stub created to name the capability.
