# Read access is audited; read output is not retained

Decision on issue #288, taken 2026-08-12. It resolves two questions the shipped read
catalog (#293) made live, and it **amends decision #122 (full-output-always)** for the
`read` risk class only.

## The problem

Two gaps, opposite in shape.

**Reads that left no trace.** The audit trail was dispatch-only (#102's scope): it recorded
Job/Task actions. Four MCP tools never reach a Node — `list_nodes`, `describe_node`,
`list_operations`, `get_job` — so they produced no record at all beyond a debug log line
that is normally switched off. Those tools disclose the fleet's shape: Node names, all three
Label namespaces, Facts, and a Node's Policy (what is and is not permitted to run there).
`get_job` goes further and returns the captured stdout of a previously-dispatched Task, so a
caller can read back command output someone else produced. After an incident, *"who
enumerated the fleet, and what did they read back"* was unanswerable.

**Reads that left too much.** `read`-class dispatches *are* audited, and by #122 they retain
the complete stdout/stderr, raw, uncapped, unredacted, indefinitely. That posture was set
when the read surface was two native Operations. The shipped catalog added seven more, and
changed both the sensitivity and the volume: `proc.list` returns a process table with argv
(command lines carry credentials), `log.tail` returns journald content (PII, tokens),
`net.listening` the internal service map, `pkg.inventory` a ready-made vulnerability list.
At the default read blast cap of 10,000 Nodes, a single `log.tail` fan-out writes 10,000
audit rows of journald content — permanently, from one tool call an AI-agent can make on a
hunch.

The framing that makes both of these matter is ADR-0021's: **`read` means "cannot change
Node state"; it does not mean "safe to see."** A read result flows to the model provider, so
reading is exfiltration by construction.

## Decisions

1. **Non-dispatching read tools are audited**, as `KindRead` records: who read, which tool,
   what they aimed it at, and when. Both attribution lanes (#300) apply exactly as
   they do to dispatches.

2. **Metadata only, never content — for every read.** A `KindRead` record has no result
   field at all, and a `read`-class **dispatch** record no longer retains stdout/stderr or
   the truncated flag. What was read is recorded; what came back is not.

3. **`mutate`-class output retention is unchanged.** #122 stands there in full. "What did
   this change do" is unanswerable without the output, and the volumes are bounded by the
   much smaller mutate blast cap.

4. **An unauditable read fails.** If the audit write fails, the read tool returns an error
   rather than answering unrecorded — matching the precedent the capability layer already
   sets for Plan.

## Why not retain read output

The honest alternative was to keep #122 uniform and manage the volume elsewhere (caps,
expiry, sampling). It was rejected on three grounds:

- **There is no use case yet.** Nothing in the product reads audit-stored read output. The
  caller already has the result — it was the tool response — and `get_job` re-reads it from
  the Task row, not the audit row. We would be retaining, forever and at the least
  convenient sensitivity, data with no current consumer.
- **The audit trail outlives the Job.** Task rows are prunable and Jobs are
  garbage-collectable; the audit trail is explicitly meant to survive both. So the audit row
  is precisely the *worst* place to hold read content: it is the copy that never expires.
- **Auditing reads without this would make things worse.** Decision 1 adds records for a
  surface that had none. Pairing it with content retention would mean answering "who looked
  at what" by permanently storing more of what they looked at — solving the accountability
  gap by deepening the exposure one.

Retention is easy to add back and impossible to undo: data not written cannot leak. The
reverse is not true.

## Consequences

- **Read output survives only as long as its Task row.** After Job/Task garbage collection,
  the audit trail can say a read happened, by whom, of what, and when — but not what it
  returned. That is the intended trade, and it is the one thing to reconsider first if a
  real need appears.
- **This does not reduce exfiltration to the model provider.** The AI-agent still receives
  the output; it is the tool response. What changes is what the *Relay* keeps. Limiting what
  the model may reach is Policy's job (ADR-0022's deny-list), not the audit trail's.
- **Read volume is now visible in the trail** — one record per read tool call, plus the
  existing per-Node dispatch records. That is a real write-rate increase on a chatty
  surface, traded for the accountability it buys. It is also what makes a SIEM export
  (#277) useful, since read events are what a SOC actually wants.
- **Deliberately not recorded: output size.** Byte counts would preserve a "how much data
  left the fleet" signal at negligible cost, and were left out only because nothing needs
  them yet. Adding them later is a column and a line.
- **Existing rows are untouched.** Read output already written stays written; this is
  forward-only. Purging it is a separate, deliberate operation, not a side effect of a
  deploy.
