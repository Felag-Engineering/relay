# Relay does not carry host telemetry

**Status:** rejected (`2026-10-23`). Origin: owner review of the MVP's observability, asking
whether daemons should push host statistics through the Relay to an aggregator.

## Problem

Customers want metrics, logs and traces from their servers in one pipeline. Every Node already
holds a connection to the Relay, so the Relay could relay host telemetry too, and spare a second
agent and a second network path.

## Proposal

The daemon would collect host metrics (CPU, memory, disk, service health) and push them over its
existing connection; the Relay would forward them to the customer's aggregator, by OpenTelemetry
or Prometheus remote write.

## Changes

`observability.md`; the daemon would gain a collector; the Relay a forwarding pipeline; the
out-of-realm list would lose a line.

## Objections

1. **It mixes telemetry into the command channel.** The connection carries Tasks; sustained
   metric traffic competes with them, so a busy telemetry day slows a Freeze or an incident
   response. — upheld.
2. **It grows the root-privileged daemon.** The daemon is deliberately small; a collector adds
   code, parsing and review surface to the riskiest binary on every Node. — upheld.
3. **It makes the Relay a data pipeline**, with sustained volume, buffering and backpressure,
   which turn scaling and high availability into the main problem for work that is not the
   product. — upheld.
4. **Monitoring agents are a solved, crowded market**, like configuration management. — upheld.
5. **Segmented networks**, where Nodes can reach only the Relay, would save a second path. —
   real, and the customer's network design to solve: run a collector beside the Relay and allow
   that one destination.

## Outcome

Rejected by the owner on 2026-10-23, recorded on AGENTS.md's out-of-realm list. Relay reports
telemetry about itself and the fleet's relationship to it (connected Nodes, daemon versions,
dispatch outcomes, refusals, approvals, certificate expiry), aggregate only, and never forwards
host telemetry. An AI-agent reads host state on demand through read Operations, under Policy and
the audit trail. Relay's own telemetry moving to OpenTelemetry is separate, undecided work in the
private roadmap (`roadmap: relay/opentelemetry`).
