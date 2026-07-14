# Audit output retention: full-output-always

Decision #122, decided in review 2026-07-12 and implemented in #185: the Relay's audit trail
(ADR-0004) retains the **complete** per-Task stdout/stderr, alongside the daemon-side
`truncated` flag, for every dispatched Task — not just its Outcome. This applies to every
`KindDispatch` audit Record that reached execution (or carries a Relay-synthesized refusal
message, e.g. a version-refused Task's `jobs.VersionRefusedMessage`).

## What is retained, and where

- **Task rows** (`internal/store/tasks.go`) have always stored the resolved Task's
  Stdout/Stderr — this is unchanged.
- **Audit rows** (`internal/audit`, `internal/store/audit.go`) now *also* carry the same
  per-Task Stdout/Stderr plus the `truncated` flag, one audit Record per NodeResult
  (ADR-0004's "Tasks are the audit unit"). The 0006 migration
  (`internal/store/migrations/0006_audit_output.sql`) adds these columns additively; rows
  written before this change keep `NULL` output and `truncated = 0`, a truthful default (they
  predate this retention posture and never carried output).

The audit trail is intentionally redundant with the Task store here: the two describe the
same event from two different lifetimes (the Task's own row can be pruned or the Job it
belongs to garbage-collected later; the audit trail is meant to outlive that).

## The only cap: the daemon's output limit

The Relay never truncates output on its own initiative. The **only** cap on stored output is
the daemon-side output limit (the executor's output-size cap, reported back via the wire
`TaskResult.truncated` bool) — the Relay persists exactly what it received, whole, and
persists the daemon's `truncated` flag as-is rather than recomputing or second-guessing it.

**Operators must size audit storage accordingly.** A fleet running commands with large or
unbounded output (log dumps, `find`, verbose builds) will grow its audit database
proportionally. There is no Relay-side output cap, rotation, or expiry today; that is a
future storage-management concern, not part of this decision.

## Secrets in output are retained by design

The Relay stores captured stdout/stderr **raw** — it never scrubs, redacts, or otherwise
inspects output for secret material. If a command emits a secret (an API key printed by a
misconfigured script, for example), that secret is retained in both the Task row and the
audit trail exactly as emitted.

This is deliberate, not an oversight: Policy (ADR-0002) is the place to prevent
secret-emitting commands from running at all — deny-by-default, argument-level granularity,
enforced by the daemon's live engine. The audit trail's job is to be a truthful record of
what actually happened, not to guess at what should be redacted after the fact; a "smart"
redaction pass over captured output would be unreliable (secrets don't announce themselves)
and would undermine the audit trail's evidentiary value for the cases where it isn't tripped.

Consequently: **never log audit output separately.** Nothing in `internal/auditsink` or
`internal/store` writes a Record's Stdout/Stderr to an application log — they flow only into
the audit table. Treat the audit database itself as holding the same sensitivity as command
output can carry, and restrict access accordingly (the same posture as the Task store today).

## Cross-references

- ADR-0004 (async Job execution model) — the audit trail's shape and "Tasks are the audit
  unit" precedent this retention posture extends.
- ADR-0002 (Policy is locally-rooted and remotely-immutable) — where secret-emitting commands
  are prevented, not after the fact in the audit trail.
- Decision #122 — the full-output-always retention posture decided here.
