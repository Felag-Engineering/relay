# Asynchronous Job execution model with at-most-once Tasks and a blast-radius cap

**Status:** Accepted.

A `run_operation` or `raw_exec` call creates a **Job** composed of one **Task** per
matched Node. Execution is asynchronous: the call returns a Job ID (optionally blocking
up to a short `wait` budget) and the AI-agent polls for results. Each Task reports an
independent outcome (`success | failure | timeout | denied-by-policy | unreachable`)
with exit code, captured output (size-capped), and duration.

## Decision details

- **At-most-once execution.** Each Task carries a unique ID and the relay-daemon dedupes
  by it across reconnects, so a retry after a dropped connection never double-runs a Task
  with side effects.
- **No automatic rollback.** Arbitrary sysadmin actions cannot be transactionally undone;
  Jobs aggregate per-Node results and the AI-agent decides remediation.
- **Blast-radius cap (hard, for now).** The Relay enforces a maximum number of Nodes per
  Job that the AI-agent cannot exceed. This is a central guardrail Node Policy cannot
  provide, since no single Node can see fleet-wide fan-out. Chosen as a hard cap for v1;
  overridable/staged-rollout and human-in-the-loop approval are planned later.
- **Output is final-only for v1**, but the transport must support streaming so live output
  can be added without re-architecting.
- **Per-Task timeouts**, with Node Policy able to cap the maximum.
- **Per-Node concurrency follows risk class (2026-07-02, ADR-0012).** The daemon runs
  `mutate` Tasks strictly serially and `read` Tasks in parallel under a small fixed
  bound (not configurable in v1). A Task queued behind a running mutate waits with its
  timeout clock already running (started at daemon receipt), so it can time out while
  waiting — the queue is self-limiting and the caller sees an honest `timeout`. This is
  serialization of live, dispatched work by seconds, not store-and-forward. Raw Exec is
  always `mutate`, so arbitrary commands are automatically serialized.
- **Offline Nodes fail fast; there is no store-and-forward queue (2026-07-02).**
  Connectivity is checked against the live connection registry per matched Node at
  dispatch time: not connected → the Task immediately reports `unreachable`, and a Node
  connecting a second later gets nothing. No grace windows — a delayed queue would mean
  Tasks that fire with no intentional actor behind them, breaking the premise every
  guardrail (Plan, caps, Policy, audit attribution) rests on: *someone decided this
  action, now*. Stragglers are the caller's decision to re-target; the Policy preflight's
  `unknown(offline)` verdicts are exactly that retry list.

## Consequences

- The transport must let the relay-daemon persist seen Task IDs across reconnects to honour
  at-most-once.
- Jobs and Tasks are the natural unit of audit.

## Amendment (2026-09-15): where the blast cap is configured

Invariant 5 is unchanged — the cap is enforced on the Relay, before dispatch. The read and
mutate cap **values** moved from startup configuration to store-backed operator settings,
changed by a human `admin` in the Console with step-up and audit. See the ADR-0010 amendment of
the same date, and ADR-0012's, for the reasoning; `docs/specs/relay-configuration.md` for the
behaviour.
