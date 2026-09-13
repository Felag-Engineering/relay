# Audit and read lane

**Status:** proposed draft, checked against the code as of `2026-09-13`; it requires explicit human approval before it is authoritative.

## Purpose

The audit and read lane answers two related accountability questions without turning Relay
into a durable store of sensitive read results: what happened in the control plane, and who
read fleet or execution information. A `read` risk class means an Operation cannot change
Node state; it does not make the information safe to disclose.

The audit trail records the decision and access metadata needed for incident review. It does
not retain the content returned by a read-class Operation or non-dispatching read. Read output
is delivered to the caller at the time of the read and remains in a Task only until that Task
is removed; it is never recoverable from the audit trail.

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
  Job-detail, read-egress, and event-stream reads that are mounted today. The Console uses the
  capability read lane for the audited routes; the event stream records one audited
  subscription containing its validated kind set, not one record per delivered event. Console
  screens do not render read-class Task output or a read-class denial explanation.

The Control API has no general audit-query endpoint today. MCP and the Control API still have
adapter-local read-audit calls for some existing reads; moving every read through the capability
read lane is not a claim this draft makes.

## Behaviour

### Audit records

- Relay records control-plane decisions and access as append-only audit records. A record
  carries the event kind, time, verified attribution, any asserted attribution, the requested
  target or selector, and the identifiers and decision metadata applicable to that event.
- A non-dispatching read records `KindRead`: who read, which stable capability/tool name they
  used, what they aimed it at, and when. An attempted single-Node or Job read is recorded before
  Relay determines that the requested identifier exists.
- Dispatch audit remains Task-grained: a dispatch with Node results writes a record for each
  Node result; a zero-match dispatch has one Job-level record. Refusals, Policy preflights,
  approval events, Freeze and cancellation have their own audit kinds and metadata as
  applicable.
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
  A mutate-class dispatch audit record retains its captured output under the existing retention
  posture. This difference is based on the Operation risk class, not on the surface that reads
  the record.
- A live event subscription records the subscription after validating and canonicalising the
  requested event kinds and before subscribing. The one `KindRead` record describes the kinds
  and resume request; it does not record events subsequently delivered by the stream. The event
  vocabulary is structurally unable to carry result-shaped data.

### Fail-closed accountability

- A read that the capability read lane cannot record is refused before its query seam runs. The
  caller receives a distinct unauditable-read failure, so an unavailable audit trail is not
  presented as a missing Node, Job, or query result.
- The existing MCP and Control API audited reads likewise record before returning their content
  and fail their call if that audit write fails. Their composition roots supply the auditor in
  production; a nil audit dependency remains a test/construction accommodation in adapter code,
  not an authorised production posture.

## Refusals

- An unauthenticated request cannot use an authenticated control-plane read surface. Console
  routes are also mounted with their declared role floor; its current read routes are viewer
  reachable.
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
- **Invariant 10, one capability layer:** Console read behaviour is exposed through the
  capability read lane rather than a Console-to-store path. Surface adapters may narrow the
  capability but cannot create a parallel decision path.
- **Invariant 13, Operation risk class:** the `read`/`mutate` distinction used by the retention
  rule is the risk class declared by the Operation contract. It is not a confidentiality label
  and does not substitute for Policy.

Changing retention, the material a read surface may disclose, audit attribution, or the
fail-closed rule requires human review against ADR-0025 and the governing security boundaries.

## Seams and proof

The capability service is the primary seam for Console history and registry reads. Its audit and
Job/Task query interfaces keep caller-controlled filters out of store implementations and let
tests prove order and redaction at the highest shared layer. The production audit sink and
SQLite query repository prove persisted record shape and query behaviour; surface tests verify
that adapters do not become unrecorded doors. Event-package structural tests are required
because an event type capable of naming result data would defeat the retention rule by a new
transport.

`make verify` is the appropriate repository gate for a change here. A change to read behaviour
across a mounted surface should also exercise its real surface tests; a change to a wire contract
starts in `/proto` and requires the contract gates.

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
| The event package cannot import result-bearing internal packages or add result-shaped event fields | `TestEventsPackageImportsStdlibOnly`, `TestToolCallEventFieldsAreExactlyAllowed` | structural |

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
| Large audit-write actions | Audit persistence currently appends individual records; token-revocation cascade batching is tracked by #563 | *(none)* |

## Out of scope

- **What an Operation or Raw Exec may disclose:** daemon Policy and the read catalog govern
  that; this lane records access and controls Relay retention. See `execution.md` and
  `policy-preflight.md`.
- **Dispatch, Task lifecycle, caps, cancellation, and Freeze:** `execution.md` and `freeze.md`.
- **Approval decisions and their visibility policy:** `approval.md`. The audit trail records
  approval-related metadata but does not decide who may approve or view an approval.
- **The Console's screen layout and product workflow:** `docs/design/console/` remains the
  surface design. The current Console implementation does not make future screen concepts or
  general audit export behaviour current capability behaviour.
- **SIEM export, a general Control API audit-query endpoint, and changing audit retention:** no
  such capability is made current by this specification.
- **Solving token-cascade audit write latency:** #563 is a store change, not a change to the
  requirement that the per-Node cascade remains auditable.

## Open questions

- Which audit-query and audit-export access should each role and Account be allowed to use? The
  current Console routes are viewer reachable, while approval-record visibility has a known
  principal-scoping gap in #469. A human decision is required before treating audit visibility
  as per-Account or audience-scoped.
- Should MCP and Control API reads be consolidated behind the capability read lane, and what
  compatibility work would that require? Current adapter-local recording is behaviour, not proof
  that the desired one-layer end state is complete.
- What durable audit-query/export interface, retention period, and access controls are required
  for operational or SIEM use? ADR-0025 deliberately leaves read-output retention unchanged;
  any proposal to retain it requires a new human decision rather than an implementation detail.
- What batching shape preserves honest per-Node audit shortfall reporting during Enrollment Token
  revocation without serialising one commit per Node? #563 tracks that performance and failure
  granularity decision.
- Does activity by Account need a separate durable model beyond the current audit trail? #424's
  Console agent-activity design is a surface request and must not be mistaken for a session
  model; MCP is stateless.

## History

- `2026-09-13` — Proposed draft written for human review; it describes current evidence and
  leaves unbuilt or unsettled access, export, and performance behaviour explicit.
