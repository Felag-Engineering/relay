# Cancellation and the emergency Freeze

**Status:** Accepted; amended by ADR-0038.

Relay gains two stop controls: **Task/Job cancellation** (stop this action) and a
Relay-wide **Freeze** (stop everything new). Before this, the system had no way to stop
anything — an unacceptable gap in an AI-driven execution plane where the guardrails
assume a human can always regain control.

## Decisions

- **`TaskCancel {task_id}`** (Relay → daemon): the daemon kills the Task's process
  group and reports a new **`OUTCOME_CANCELLED`**. Job-level cancel marks undispatched
  Tasks cancelled and sends `TaskCancel` for in-flight ones.
- **Cancel is best-effort by definition.** A Task may complete inside the race window;
  the result then honestly reports `success`, never a retroactive `cancelled`. A
  command that already ran cannot be un-run (ADR-0004, no rollback) — pretending
  otherwise would corrupt what the audit trail means. At-most-once dedup is
  unaffected: a cancelled Task ID stays seen.
- **Freeze halts all new Task dispatch, every risk class.** "I don't trust what's
  driving this" applies to reads (exfiltration) as much as mutations. **Plans
  (ADR-0011) still work while frozen** — observation is wanted during an incident.
  **Amended by [ADR-0038](0038-plan-is-an-approved-route-of-execution.md) (2026-09-12):
  read that clause as "Policy preflights (ADR-0011) still work while frozen; every
  advance of a Plan does not."** ADR-0038 reassigned the word *Plan* from the
  no-execution preview — now **Policy preflight** — to an approved route of execution,
  which inverted this sentence without anyone editing it: a Plan is now a thing that
  *dispatches*, and an advance of one is new Task dispatch, so it meets this clause's
  halt rather than its exemption. The exemption was always about observation, and it
  stops where observation stops. "A human already approved this" is a statement about
  authorization, and a Freeze is not an authorization check.
  In-flight Tasks keep running unless separately cancelled: indiscriminately killing
  half-finished installs creates the second incident.
- **Asymmetric activation — engage cheap, release deliberate.** Engage: any
  `operator`+ Account via the Control API, or locally on the Relay host (file/signal)
  — when the distrusted thing may be the API credential itself, root-on-the-box must
  suffice to pull the cord. Release: `admin` via the API, or the local path, with an
  audited reason. Fire-alarm asymmetry: anyone may pull; the chief clears re-entry.
  **Amended by [#397](https://github.com/Felag-Engineering/relay/issues/397)
  (2026-08-24): engaging over the Control API additionally requires a HUMAN Account.**
  A machine Account at `operator` — an AI-agent — halting the fleet is not the fire
  alarm this clause had in mind: it is a jailbroken driver switching off its own
  overseers, which is a denial of service the cheapness argument does not cover.
  "Anyone may pull the handle" was always an argument about people. Automation that
  genuinely needs to stop dispatch uses the host-side lever, where the authority is
  root on the box rather than a stealable credential. Release stays `admin` and is
  deliberately *not* human-only: an incident must have an automated way back.
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

- Proto: `TaskCancel` + `OUTCOME_CANCELLED` land with the executor milestone's work
  (daemon must kill process groups and report honestly); Job cancel and Freeze land
  with the Job-engine milestone. Both ship before the beta — a beta on real machines
  with no stop button is not a beta.
- The daemon must supervise Tasks in killable process groups (also required for
  timeouts) — cancellation shares that machinery.
- Freeze is Relay state, so it must survive a Relay restart (persisted, not
  in-memory).
