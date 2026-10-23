# Cancellation and the emergency Freeze

**Status:** Accepted; amended by ADR-0038.

Relay gains two stop controls: **Task/Job cancellation** (stop this action) and a
Relay-wide **Freeze** (stop everything new). Without them nothing could be stopped, an
unacceptable gap in an AI-driven execution plane whose guardrails assume a human can always
regain control.

## Decisions

- **`TaskCancel {task_id}`** (Relay → daemon): the daemon kills the Task's process
  group and reports a new **`OUTCOME_CANCELLED`**. Job-level cancel marks undispatched
  Tasks cancelled and sends `TaskCancel` for in-flight ones.
- **Cancel is best-effort by definition.** A Task may complete inside the race window; the
  result then honestly reports `success`, never a retroactive `cancelled`. A command that
  already ran cannot be un-run (ADR-0004, no rollback), and pretending otherwise would corrupt
  the audit trail. At-most-once dedup is unaffected: a cancelled Task ID stays seen.
- **Freeze halts all new Task dispatch, every risk class.** "I don't trust what's
  driving this" applies to reads (exfiltration) as much as mutations. **Plans
  (ADR-0011) still work while frozen** — observation is wanted during an incident.
  **Amended by [ADR-0038](0038-plan-is-an-approved-route-of-execution.md) (2026-09-12), worded
  by ADR-0049 (2026-10-22): read that clause as "Policy preflights (ADR-0011) still work while frozen."** The
  no-execution preview is now **Policy preflight** (ADR-0049 keeps that rename). Every step of
  a Gleipnir Plan reaches Relay as new dispatch, so it meets this clause's halt, not its
  exemption: the exemption was always about observation. "A human already approved this" is about authorization, and a
  Freeze is not an authorization check.
  In-flight Tasks keep running unless separately cancelled: killing half-finished installs
  creates the second incident.
- **Asymmetric activation — engage cheap, release deliberate.** Engage: any `operator`+
  Account via the Control API, or locally on the Relay host (file/signal), because when the
  distrusted thing may be the API credential itself, root on the box must suffice. Release:
  `admin` via the API, or the local path, with an audited reason. Anyone may pull the fire
  alarm; the chief clears re-entry.
  **Amended by [#397](https://github.com/Felag-Engineering/relay/issues/397)
  (2026-08-24): engaging over the Control API additionally requires a HUMAN Account.** An
  AI-agent's machine Account halting the fleet is not the fire alarm meant here: it is a
  jailbroken driver switching off its overseers, a denial of service the cheapness argument
  does not cover. Automation that needs to stop dispatch uses the host-side lever, where the
  authority is root on the box rather than a stealable credential. Release stays `admin` and
  is deliberately *not* human-only: an incident must have an automated way back.
- Freeze state changes and every engage/release are audited with their Account (or
  `local-host`).

## Considered Options

- **Guaranteed cancellation.** Impossible to honor (the race window is physics) and
  dishonest to promise. Rejected for best-effort with truthful outcomes.
- **Freeze mutations only.** Leaves the exfiltration lane open exactly when trust is
  lowest, for negligible convenience. Rejected.
- **Kill in-flight Tasks on freeze.** Turns one incident into two. Rejected;
  cancellation of in-flight work is a separate, deliberate act.

## Consequences

- Proto gains `TaskCancel` and `OUTCOME_CANCELLED`. Both stop controls ship before the beta:
  a beta on real machines with no stop button is not a beta.
- The daemon supervises Tasks in killable process groups, which timeouts also need.
- Freeze is Relay state, so it is persisted and survives a Relay restart.
