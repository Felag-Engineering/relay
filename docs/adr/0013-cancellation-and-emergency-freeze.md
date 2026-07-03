# Cancellation and the emergency Freeze

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
  In-flight Tasks keep running unless separately cancelled: indiscriminately killing
  half-finished installs creates the second incident.
- **Asymmetric activation — engage cheap, release deliberate.** Engage: any
  `operator`+ Account via the Control API, or locally on the Relay host (file/signal)
  — when the distrusted thing may be the API credential itself, root-on-the-box must
  suffice to pull the cord. Release: `admin` via the API, or the local path, with an
  audited reason. Fire-alarm asymmetry: anyone may pull; the chief clears re-entry.
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
