# Audit and read lane

**Status:** aspirational — confirmed with the owner on `2026-09-14`; mostly built, with the
alignments and gaps recorded below.

## Purpose

The audit and read lane answers two accountability questions — what happened in the control
plane, and who read fleet or execution information — without making Relay a durable store of
sensitive read results. A `read` risk class means an Operation cannot change Node state, not
that its output is safe to disclose.

The audit trail records the decision and access metadata needed for incident review, never the
content a read-class Operation or non-dispatching read returned. Read output is delivered to the
caller and remains in a Task only until that Task is removed; it is never recoverable from the
audit trail.

## Surfaces

- **Capability layer:** the read lane provides audited registry reads (`list_nodes`,
  `describe_node`), audit-trail queries, Job and Task queries, bounded audit aggregates, and
  event-subscription access recording. It is the current seam for Console fleet, activity,
  Job-detail, read-egress, and event-stream reads.
- **MCP:** `list_nodes`, `describe_node`, `list_operations`, and `get_job` are
  non-dispatching reads. They record a `KindRead` access record before returning content.
  `get_job` can return captured Task output while the Task exists; its access record does not
  contain that output.
- **Control API:** `GET /api/v1/nodes/{node_id}` and `GET /api/v1/jobs/{id}` record the same
  surface-neutral read capability names (`describe_node` and `get_job`) before returning
  content. The Job route can return captured Task output while it exists.
- **Admin Console:** authenticated viewers can reach the fleet, Node-detail, activity,
  Job-detail, read-egress, and event-stream reads. The audited routes use the capability read
  lane; the event stream records one audited subscription with its validated kind set, not one
  record per delivered event. Console screens do not render read-class Task output or a
  read-class denial explanation.

The Control API has no general audit-query endpoint. MCP and the Control API still make
adapter-local read-audit calls for some reads; this draft does not claim every read goes through
the capability read lane.

## Behaviour

### Audit records

- Relay records control-plane decisions and access as append-only audit records. A record
  carries the event kind, time, verified attribution, any asserted attribution, the requested
  target or selector, and the identifiers and decision metadata applicable to that event.
- A non-dispatching read records `KindRead`: who read, which stable capability/tool name they
  used, what they aimed it at, and when. An attempted single-Node or Job read is recorded before
  Relay determines that the requested identifier exists.
- Dispatch audit is Task-grained: a dispatch with Node results writes a record for each Node
  result; one whose dispatcher failed before producing any has one Job-level record; a
  zero-match dispatch is audited as a refusal (`execution.md`). Refusals, Policy preflights,
  approval events, Freeze and cancellation have their own audit kinds and metadata.
- Audit queries return metadata projections, cursor-paginated newest first. An audit row has no
  stdout, stderr, or truncation field. Filters combine by intersection; the lane supports kind,
  verified and asserted attribution, action, Node, Job, approval/grant, outcome, time range,
  and bounded argument filtering.
- Audit-count and audit-reach aggregates require a bounded time window. The requested bucket is
  clamped to the lane's minimum. Paged reads use a default page size and clamp an excessive
  requested limit to the maximum, reporting the effective limit in the page.

### Audited reads

- The capability read lane validates a caller-controlled filter or identifier, records the read,
  and only then reaches its audit, Job/Task, or registry query seam. Its record uses the
  authenticated principal supplied by the calling surface.
- Registry reads disclose the Node registry record, including Labels, Facts, connection and
  certificate provenance, and Policy/template fingerprints. `describe_node` also returns peer
  counts for a non-empty fingerprint; an unknown Node is recorded and then reported as absent.
- Job and Task queries return execution metadata. When the query lane reads Task rows, it strips
  stdout and stderr from every Task whose risk class is not explicitly `mutate`; an unspecified
  class therefore defaults to no output disclosure through this lane.
- A read-class dispatch audit record retains neither stdout nor stderr nor its truncation flag.
  A mutate-class one retains its captured output under the existing retention posture. The
  difference follows the Operation risk class, not the surface that reads the record.
- The two retention decisions key on the risk class from opposite directions, deliberately. The
  audit sink retains unless the class is explicitly `read`; the query lane strips unless it is
  explicitly `mutate`. An unspecified class is therefore retained by the sink and stripped by the
  lane. `risk_class` is non-null and written from the Operation catalog, so an unspecified class
  is not reachable today, but the divergence is load-bearing: a change that made one reachable
  must not turn the query lane's default into a read-output disclosure.
- A live event subscription is recorded after its requested event kinds are validated and
  canonicalised, and before subscribing. The one `KindRead` record describes the kinds and resume
  request, not the events the stream later delivers. The event vocabulary cannot carry
  result-shaped data.

### Fail-closed accountability

- A read that the capability read lane cannot record is refused before its query seam runs, with
  a distinct unauditable-read failure, so an unavailable audit trail never looks like a missing
  Node, Job, or query result.
- The MCP and Control API audited reads likewise record before returning content and fail the
  call if that write fails. Their composition roots supply the auditor in production; a nil
  audit dependency in adapter code is a test accommodation, not a production posture.

### Decided with the owner

Confirmed on `2026-09-14`. Where these contradict an older statement above, these win until the
spec is rewritten:

- **That a read happened is always recorded; what it returned never is.** Every read — a
  read-class Operation or a non-dispatching read — leaves a record of who read, through which
  capability, aimed at what, and when. Its output is delivered to the caller and is never kept in
  the audit trail (ADR-0025). A `mutate`'s captured output is kept with its audit record.
- **New audit events from other capabilities:** changes to a Node's security-relevant self-report
  (`node-connection.md`), and an idempotent repeat that returned an existing Job (`execution.md`).
- **Any `viewer` or above reads all audit metadata** in the first pass.
- **One read lane.** MCP and Control API reads that record their own audit rather than going
  through the capability read lane are a gap to close (invariant 10), as in `query.md`.

## Refusals

- An unauthenticated request cannot use an authenticated control-plane read surface. Console
  routes are mounted with their declared role floor; its read routes are viewer-reachable.
- An invalid filter, malformed cursor, inverted time range, oversized bounded value, task query
  without a Job ID, or unbounded aggregate query is refused before it becomes a query or an
  audit-record payload.
- An unavailable read seam returns a query-unavailable error; an unavailable registry returns a
  registry-unavailable error. Neither condition is treated as an empty result.
- A failed access-record write refuses the read before disclosure. A missing Node or Job is
  reported only after the corresponding access attempt has been recorded.
- The audit lane never supplies read-class output, a read-class denial explanation, output size,
  or a retained stream result set. A caller needing currently available Task output uses the
  applicable Job-read surface, whose access is itself audited.

## Governing ADRs and invariants

- **ADR-0025, Read access is audited; read output is not retained:** requires metadata-only
  `KindRead` records, removes read-class output and truncation from audit retention, leaves the
  mutate-class posture unchanged, and requires an unauditable read to fail. It also establishes
  that task-row lifetime, not the audit trail, bounds any surviving read output.
- **Invariant 10, one capability layer:** Console reads go through the capability read lane, not
  a Console-to-store path. Adapters may narrow the capability but never create a parallel
  decision path.
- **Invariant 13, Operation risk class:** the `read`/`mutate` distinction used by the retention
  rule is the risk class declared by the Operation contract. It is not a confidentiality label
  and does not substitute for Policy. *(Invariant 13 amended 2026-10-02, ADR-0042: a Template
  Operation's class is Node-reported. The dispatch takes the most restrictive class for its cap
  and approval gate, but each Task is recorded under its own Node's class and retention follows
  that per-Task class, so one Node cannot cause another Node's read output to be retained.)*

Changing retention, the material a read surface may disclose, audit attribution, or the
fail-closed rule requires human review against ADR-0025 and the governing security boundaries.

## Seams and proof

The capability service is the primary seam for Console history and registry reads. Its audit and
Job/Task query interfaces keep caller-controlled filters out of store implementations and let
tests prove order and redaction at the highest shared layer. The production audit sink and
SQLite query repository prove persisted record shape and query behaviour; surface tests verify
adapters do not become unrecorded doors. Event-package structural tests are required because an
event type able to name result data would defeat the retention rule by a new transport.

`make verify` is the gate for a change here. A change to read behaviour on a mounted surface
should also run its real surface tests; a wire-contract change starts in `/proto` and needs the
contract gates.

### What proves each claim

| Behaviour | Proven by | Seam |
|---|---|---|
| Every capability audit/Job/Task query records its read before reaching the query seam, and an audit-write failure stops the seam | `TestReadLane_RecordsReadBeforeQuerying` | capability |
| Capability filters reject invalid ranges and a Task query without a Job ID | `TestReadLane_FilterValidation` | capability |
| Aggregate queries reject an unbounded window and clamp their bucket | `TestReadLane_AuditCounts_RejectsUnboundedFilter`, `TestReadLane_AuditReach_RejectsUnboundedFilter`, `TestReadLane_AuditCounts_ClampsBucket` | capability |
| Querying Tasks strips output for read and unspecified risk classes | `TestReadLane_QueryTasksStripsReadClassOutput` | capability |
| Registry and trail halves expose the same unauditable-read sentinel | `TestReadLane_TrailHalfAlsoWrapsErrReadUnaudited` | capability |
| The persisted audit query projection has no output fields | `TestAuditRow_NoOutputFields` | store |
| Audit queries filter, paginate, aggregate, and preserve decision metadata | `TestAuditQuery_FilterComposition`, `TestAuditQuery_Pagination`, `TestAuditQuery_ReachCounts`, `TestAuditQuery_DecisionAnswerRoundTrips` | store |
| MCP records a read target and fails the call if that record cannot be written | `TestAuditRead_RecordsToolAndTarget`, `TestAuditRead_FailsTheCallWhenTheTrailCannotBeWritten` | MCP |
| Every Console route is classified for read auditing and audited routes write through the real lane | `TestConsole_EveryRouteIsClassifiedForReadAuditing`, `TestConsole_AuditedRoutesRecordTheirReadThroughTheRealLane` | Console |
| A Console event subscription records one metadata-only read and refuses an unwritable trail | `TestConsoleEvents_B1_RecordsExactlyOneWatchRead`, `TestConsoleEvents_B5_FailsClosedBeforeSubscribing` | Console |
| The event package cannot import result-bearing internal packages or add result-shaped event fields | `.golangci.yml` depguard rule `events-imports`, `TestToolCallEventFieldsAreExactlyAllowed` | lint, structural |

Claims above with **no row**, and so nothing checking them:

- That every mounted Control API and MCP read adapter is covered by one exhaustive
  read-classification guard comparable to the Console guard.
- That no legacy audit record written before ADR-0025 contains read-class output; the ADR makes
  the retention change forward-only and existing rows deliberately remain untouched.
- That all production composition roots reject a missing read auditor rather than relying on
  adapter nil handling.

### Performance

| Characteristic | Contract | Measured by |
|---|---|---|
| Paged audit, Job, and Task reads | A caller receives at most the effective bounded page limit and a cursor for a later page | *(none)* |
| Audit aggregates | A caller must supply a bounded time window; the lane floors the bucket to its minimum | *(none)* |
| Read audit writes | One access record is written per non-dispatching read or capability query; one event-subscription record covers its whole subscription | *(none)* |
| Large audit-write actions | The token-revocation cascade appends its per-Node audit records all-or-nothing, one transaction per bounded chunk of Nodes rather than one per Node | *(none)* |

## Out of scope

- **What an Operation or Raw Exec may disclose:** daemon Policy and the read catalog govern
  that; this lane records access and controls Relay retention. See `execution.md` and
  `policy-preflight.md`.
- **Dispatch, Task lifecycle, caps, cancellation, and Freeze:** `execution.md` and `freeze.md`.
- **Approval decisions and their visibility policy:** `approval.md`. The audit trail records
  approval-related metadata but does not decide who may approve or view an approval.
- **The Console's screen layout and product workflow:** `docs/design/console/`.
- **SIEM export, a general Control API audit-query endpoint, and changing audit retention.**

## Future work

- **Audit visibility scoped by role or audience**, including the approval-record scoping gap (#469).
- **Retention periods and a durable export** for operational and SIEM use. Retaining read output
  stays out: it would need a new human decision against ADR-0025.
- **A per-Account activity model**, if the Console's agent-activity view (#424) needs more than
  the audit trail. MCP is stateless.
- **Tamper-evident audit** — hash-chained records, so a deleted or altered row is detectable.

## Open questions

None open.
