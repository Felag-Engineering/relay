# Transport is gRPC bidirectional streaming over mTLS

The relay-daemon connects to the Relay over a single long-lived **gRPC bidirectional
stream** secured with **mutual TLS**, on 443/HTTP-2. The connection is daemon-initiated
(outbound-only, no inbound ports on Nodes). The Relay sends Task messages down the stream;
the daemon sends results, heartbeats, and (future) streaming output chunks up the same
stream.

## Why

- One outbound, bidirectional, persistent connection satisfies the dial-home premise and
  lets the Relay push Tasks without inbound ports on Nodes.
- mTLS provides mutual authentication at the transport layer: the daemon refuses an
  imposter Relay, and the daemon's client certificate *is* its Node identity (see
  enrollment, ADR-0006).
- A typed protobuf contract mirrors the typed Operation vocabulary, so wire schema and
  Operation set cannot silently drift.
- Runs over 443/HTTP-2, traversing most egress firewalls and proxies.

## Considered Options

- **WebSocket + JSON/msgpack** — simpler and proxy-friendly, but hand-rolled framing,
  typing, and streaming, and no compile-time contract.
- **SSH reverse tunnel** — reuses proven crypto but reduces the system to "SSH with extra
  steps," undermining the structured/native Operation model.
- **QUIC/HTTP-3** — better over flaky links; less mature tooling. gRPC can move to HTTP-3
  later.

## Consequences

- At ~10k Nodes a single Relay is comfortable (low single-digit GB RAM, near-zero idle
  CPU); raw connection cost is not the constraint.
- Long-lived HTTP-2 connections are sticky to one Relay instance, so horizontal scaling
  for HA requires a Node→instance routing registry. Deferred to a future HA ADR; v1 runs a
  single Relay.
- gRPC keepalive intervals must be tuned for many idle connections to avoid spurious
  wakeups or GOAWAYs.

## Amendment (2026-09-20): amended by ADR-0031

Recorded late — ADR-0031 (2026-08-18) says it amends this ADR and this file never said so. The
Relay presents **one server certificate** on both listeners, and the daemon pins the Relay by the
**CA fingerprint carried in the join string** rather than by a distributed CA bundle file. The
transport decision here — gRPC bidirectional streaming over mTLS, one long-lived Tunnel per
Node — is unchanged; what changed is how the daemon comes to trust the Relay's certificate.
Designed, not built (#401, #406; milestone v0.6.5).
