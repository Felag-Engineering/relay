# Audit output retention: full-output-always for `mutate`, metadata-only for `read`

The Relay's audit trail (ADR-0004) keeps output by risk class (ADR-0025):

- **`mutate`** (and Raw Exec, which is always `mutate`): the audit Record keeps the
  **complete** per-Task stdout/stderr and the daemon-side `truncated` flag, not just the
  Outcome. This covers every `KindDispatch` Record that reached execution or carries a
  Relay-synthesized refusal message (e.g. a version-refused Task's
  `jobs.VersionRefusedMessage`).
- **`read`**: the audit Record keeps **no** stdout/stderr and no `truncated` flag, only the
  access: who, which Operation, which Node, which Selector, the Outcome, and when.
  Non-dispatching read tools (`list_nodes`, `describe_node`, `list_operations`, `get_job`) are
  audited as `KindRead` records, also metadata-only.

Read output is excluded because the shipped read catalog makes it voluminous and sensitive
(`proc.list` returns argv, `log.tail` returns journald content), and at the default read blast
cap of 10,000 Nodes one fan-out would write that content to 10,000 permanent rows. Nothing
consumes audit-stored read output: the caller already had the result, and `get_job` re-reads
it from the Task row.

**Read output therefore survives only as long as its Task row.** After Job/Task garbage
collection the trail can say a read happened, by whom, of what, and when, but not what it
returned. That is deliberate, and the first thing to revisit if a real consumer appears.

## What is retained, and where

- **Task rows** (`internal/store/tasks.go`) store the resolved Task's Stdout/Stderr.
- **Audit rows** (`internal/audit`, `internal/store/audit.go`) carry the same per-Task
  Stdout/Stderr plus the `truncated` flag for `mutate`, one audit Record per NodeResult
  (ADR-0004's "Tasks are the audit unit"). The columns come from migration 0006
  (`internal/store/migrations/0006_audit_output.sql`); rows written before it have `NULL`
  output and `truncated = 0`, because they never carried output.

The redundancy is intentional: the Task row can be pruned or its Job garbage-collected, and the
audit trail is meant to outlive that.

## The only cap: the daemon's output limit

The Relay never truncates output itself. The **only** cap is the daemon's output-size limit,
reported back in the wire `TaskResult.truncated` bool. The Relay persists exactly what it
received, whole, and stores the daemon's `truncated` flag as-is.

**Size audit storage accordingly.** A fleet running commands with large or unbounded output
(log dumps, `find`, verbose builds) grows its audit database proportionally. There is no
Relay-side output cap, rotation, or expiry.

## Secrets in `mutate` output are retained by design

The Relay stores captured stdout/stderr **raw**: it never scrubs, redacts, or inspects output
for secrets. A secret a command emits (an API key printed by a misconfigured script, say) is
retained in both the Task row and the audit trail exactly as emitted.

Policy (ADR-0002) is where secret-emitting commands are prevented from running at all. The
audit trail's job is to be a truthful record; a redaction pass would be unreliable (secrets do
not announce themselves) and would undermine its evidentiary value.

Consequently: **never log audit output separately.** Nothing in `internal/auditsink` or
`internal/store` writes a Record's Stdout/Stderr to an application log; it flows only into the
audit table. Treat the audit database as holding whatever command output can carry, and
restrict access to it as you would to the Task store.

## Cross-references

- ADR-0004 (async Job execution model): the audit trail's shape and "Tasks are the audit
  unit".
- ADR-0025: metadata-only audit for `read`.
- ADR-0002 (Policy is locally-rooted and remotely-immutable): where secret-emitting commands are
  prevented.
