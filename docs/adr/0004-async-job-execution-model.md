# Asynchronous Job execution model with at-most-once Tasks and a blast-radius cap

A `run_operation` or `raw_exec` call creates a **Job** composed of one **Task** per
matched Node. Execution is asynchronous: the call returns a Job ID (optionally blocking
up to a short `wait` budget) and the AI-agent polls for results. Each Task reports an
independent outcome (`success | failure | timeout | denied-by-policy`) with exit code,
captured output (size-capped), and duration.

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

## Consequences

- The transport must let the relay-daemon persist seen Task IDs across reconnects to honour
  at-most-once.
- Jobs and Tasks are the natural unit of audit.
