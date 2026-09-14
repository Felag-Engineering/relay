# Query

**Status:** draft for human approval, checked against the code on `2026-09-13`.

## Purpose

Query lets an authenticated Account inspect the fleet information Relay holds without
dispatching an Operation: Nodes in the registry, one Node's recorded identity and state,
the daemon-reported Policy view, and the Operation vocabulary. It answers what Relay knows
and what a Node last reported; it does not make a Policy decision, change a Node, or infer a
desired state.

Read means that the call cannot change Node state, not that its contents are harmless to
disclose. Registry data includes fleet shape, Labels, Facts, identity provenance, and Policy
information, so access is attributable and auditable.

## Surfaces

| Surface | Current query capability |
|---|---|
| **MCP** | `list_nodes` lists registry Nodes, optionally resolved against a Selector. `describe_node` returns one Node's registry data, certificate provenance, cached effective Policy, and reported Template Operation vocabulary. `list_operations` returns the frozen Native Operation vocabulary and, when passed a Node ID, that Node's last reported Template Operations. |
| **Control API** | `GET /api/v1/nodes/{node_id}` returns one Node's registry data and certificate provenance. It does not expose fleet enumeration, effective Policy, or Operation vocabulary. |
| **Console** | Fleet and Node-detail views read registry state. Node detail renders the last daemon-reported effective Policy and reported Template Operation vocabulary; it does not refresh Policy live. The Console's current vocabulary presentation is a product view over the same discovery information. |

No current query surface exposes a general registry search API, a Control API operation-vocabulary route, a Control API effective-Policy route, or a way to query, author, or alter Policy over the wire.

## Behaviour

### Registry reads

- A Node read returns Relay's recorded registry state: Node ID; separate `node:` and
  `relay:` Label maps; self-reported Facts; connection and revocation state; Policy and
  template-set fingerprints; daemon version and `outdated`; and recorded certificate
  provenance when it exists. `state:` Labels are derived at read time and are rendered in
  Selector syntax; they are not stored Labels.
- `list_nodes` accepts an empty Selector or a Selector in the supported `node:`, `relay:`,
  and `state:` namespaces, resolves it against the registry at one evaluation instant, and
  returns matching Nodes in Node-ID order. Its rendered `state:` Labels correspond to that
  same evaluation instant.
- `describe_node` and `GET /api/v1/nodes/{node_id}` identify exactly one Node. A Node that
  is currently disconnected remains readable from its last registry record; `connected` is
  its live Tunnel state and must not be inferred from `last_seen`.
- MCP `describe_node` additionally reports how many registry Nodes share the named Node's
  non-empty Policy fingerprint and template-set fingerprint. These counts are observation
  for rollout and drift visibility; they do not establish Policy equivalence or trust.
- MCP `describe_node` and `list_operations(node_id)` distinguish an absent template-vocabulary
  report from an empty reported vocabulary. A missing report is not evidence that a Node has
  no Template Operations.

### Policy view

- MCP `describe_node` and the Console render a display-only snapshot of effective Policy
  that the relay-daemon previously reported. When no snapshot has been captured, the result
  says it was not reported rather than representing absence as an unrestricted Policy.
- The snapshot is a report, not a live query. Its receipt time is Relay-stamped; an offline
  Node cannot be refreshed through this capability.
- The Relay displays the reported allow and deny rules without evaluating, merging,
  normalizing, or otherwise deriving a Policy verdict. An effective-Policy view neither
  grants permission nor predicts whether a Task will run.

### Operation-vocabulary discovery

- The Native Operation vocabulary is frozen and fleet-wide. MCP `list_operations` reports
  each Native Operation's name, risk class, purpose, argument constraints, and example.
- With no Node ID, `list_operations` reports only Native Operations. With a Node ID, it adds
  the Template Operations last reported by that Node, including their names, risk classes,
  and typed slots. It never returns a template body.
- Vocabulary is per-Node once Template Operations exist. A Template Operation missing from a
  Node's reported vocabulary may produce `unsupported` if dispatched there; it is not a
  Policy denial. Raw Exec is not an Operation and is never listed as one.

### Access and recording

- Every current query surface requires an authenticated Account. The current read floor is
  `viewer`; no separate role gate narrows these reads further.
- Each non-dispatching read is recorded before content is returned. The record identifies the
  authenticated caller and the query's target: an enumeration records its Selector, and a
  single-Node read records the requested Node ID, including an ID that does not exist.
- If the access record cannot be written, the read is refused before it consults the registry
  or returns content. Query-access records contain metadata about the read, never its result.

## Refusals

- An unauthenticated caller receives no query result.
- A malformed Selector, a bare Label key, or a `state:` key outside the closed vocabulary is
  refused rather than treated as an empty match. `tag:` is refused because tag-space has no
  storage or resolution path yet; a successful empty response would falsely assert that no
  Node matched.
- A missing or oversized Node ID is refused before it is recorded. An otherwise valid ID that
  is not in the registry is recorded and then returns a distinguishable no-such-Node result.
- A query that cannot be audited is refused. The caller is not given stale, partial, or
  unaudited registry data as a fallback.
- A missing Policy or Template Operation snapshot is represented as not reported, never as a
  fabricated empty Policy or a claim that the Node supports no templates.
- These reads cannot set Labels, modify Policy, load Templates, refresh a daemon snapshot,
  issue a live Policy verdict, dispatch an Operation, or bypass Selector, authorization,
  blast-cap, and daemon Policy enforcement.

## Governing ADRs and invariants

- **Invariant 2 and ADR-0002** — Policy is locally rooted and remotely immutable. Query may
  show a daemon report, but no surface can write Policy or Template Operations over the wire.
- **Invariant 7, ADR-0006, ADR-0020, and ADR-0034** — Label namespaces remain separate:
  `node:` and `relay:` are returned separately, `state:` is derived, and tag-space is
  honestly refused until it exists. A query has no Label-write authority.
- **Invariant 8 and ADR-0007** — wire-reported data follows the protocol contract; a query
  surface must not invent a second wire vocabulary.
- **Invariant 10 and ADR-0009** — MCP, Control API, and Console are adapters over the
  capability decisions and may narrow exposure only. The current registry-read seam split
  needs human review, recorded below, before this draft can claim that this invariant is met.
- **Invariant 12 and ADR-0011** — only the relay-daemon's live engine evaluates Policy.
  Displaying a snapshot never becomes a Relay-side verdict; a hypothetical belongs to
  policy preflight.
- **ADR-0014** — `outdated` is a registry and dispatch-gate observation. It neither asserts
  Policy drift nor authorizes an upgrade.
- **ADR-0015 and ADR-0021** — Native vocabulary is golden-guarded and frozen; Template
  vocabulary is local, per-Node, report-only, and has no template-body disclosure.
- **ADR-0025** — query access is audited and fails closed when it cannot be recorded. Its
  retention and output rules are specified by `audit-and-read-lane.md`, not here.

## Seams and proof

The capability layer has registry-query methods for list and single-Node reads, including
their access-recording requirement. MCP, the Control API, and the Console currently also
hold narrow read-only adapters for their particular projections. Policy and Template
vocabulary are read from display-only daemon-report caches. These seams cannot dispatch or
mutate their underlying repositories through their declared interfaces.

Changes to query behaviour should be proved at the capability seam and at every affected
surface. `make verify` is sufficient for the current non-wire query paths. A change to a
daemon report or its protocol representation starts in `/proto`, requires regeneration, and
requires the protocol gates in `make verify`.

### What proves each claim

| Behaviour | Proven by | Seam |
|---|---|---|
| Registry enumeration and a single-Node read are recorded before registry access | `TestListNodes_RecordsTheEnumeration`, `TestDescribeNode_RecordsTheNodeItWasAimedAt` | capability |
| A missing Node probe is recorded and remains distinguishable from a read failure | `TestDescribeNode_RecordsAProbeForAMissingNode` | capability |
| Registry reads refuse when no access record can be written | `TestRegistryLane_FailsClosedWhenTheReadCannotBeAudited`, `TestRegistryLane_RefusesWithoutARealAuditSink` | capability |
| A Node ID is bounded before it reaches the access trail | `TestDescribeNode_BoundsTheNodeIdBeforeRecordingIt` | capability |
| MCP lists Nodes through supported Selector namespaces and refuses tag-space | `TestMCP_ListNodes_SelectorFilter`, `TestMCP_ListNodes_TagSelectorIsRefusedNotEmpty` | MCP |
| MCP renders derived state Labels and keeps stored label namespaces separate | `TestMCP_ListNodes_StateLabels`, `TestMCP_ListNodes_All` | MCP |
| MCP describes a Node's reported Policy and represents absent Policy data explicitly | `TestMCP_DescribeNode` | MCP |
| MCP lists frozen Native Operations and a named Node's reported Template Operations | `TestMCP_ListOperations`, `TestMCP_ListOperations_PerNode` | MCP |
| Template bodies do not cross the MCP query response | `TestMCP_DescribeNode` | MCP |
| Control API Node reads render derived state Labels | `TestHandleGetNode_StateLabels` | Control API |
| Console Node detail names Policy receipt time and does not claim an offline Node can refresh it | `TestNode_PolicyPanelCarriesTheReceiptTime`, `TestNode_OfflineNodePolicyCannotBeRefreshed` | Console |

Claims above with no row, and so nothing checking them:

- Every current query surface has the same `viewer` authorization floor. The Control API
  documents and exercises it, but there is no cross-surface authorization-parity test for
  the MCP and Console reads.
- The Control API deliberately omits fleet enumeration, effective Policy, and Operation
  vocabulary. Its route table proves present routes, but no test names these absences as
  this capability's contract.
- The Control API Node read is audited and fails closed when its access record cannot be
  written. The handler implements both, but no dedicated Control API test names this
  behaviour.
- All surfaces are adapters over one registry-read capability decision. The current source
  contains more than one read seam, so this is an unresolved invariant question rather than
  a claim this draft can prove.

### Performance

| Characteristic | Contract | Measured by |
|---|---|---|
| Node enumeration | Returns every Node matching the Selector, sorted by Node ID; it does not silently page or truncate | *(none)* |
| Single-Node detail | Reads one named Node and computes its fingerprint-peer counts without requiring the caller to enumerate the fleet | *(none)* |
| Vocabulary discovery | A fleet-wide request returns Native Operations only; per-Node Template vocabulary requires an exact Node ID | *(none)* |

## Out of scope

- Audit-trail, Job, Task, and read-egress queries, including result retention and output
  disclosure. Those belong to `audit-and-read-lane.md`.
- Live hypothetical Policy evaluation and preflight/apply parity. Those belong to
  `policy-preflight.md`; this capability only displays what a Node already reported.
- Policy authoring, Template loading or distribution, Label writes, Node enrollment and
  revocation, account administration, and dispatch.
- Fleet health monitoring, metrics, desired-state reconciliation, configuration management,
  daemon upgrades, and an unbounded remote shell.

## Open questions

- **Does the current registry-read seam satisfy invariant 10?** The capability layer owns
  audited `ListNodes` and `DescribeNode`, while MCP, the Control API, and Console also hold
  surface-specific narrow registry readers and access-recording paths. A human must decide
  whether the projections are acceptable adapters or whether this is a design gap; that
  decision should precede claiming one capability layer in an approved spec.
- **What query exposure should the Control API eventually have?** It currently offers only
  `GET /api/v1/nodes/{node_id}`. A need for enumeration, effective-Policy display, or
  vocabulary discovery should first establish the authorized audience, disclosure shape,
  audit record, and whether a new surface would merely adapt the existing capability.
- **Should an Account's role constrain high-sensitivity fleet discovery beyond `viewer`?**
  Current code exposes reads to every authenticated Account. A decision is required if a
  tenant, delegated-access, or data-classification requirement makes that floor too broad.
- **What is the durable contract for a Node ID supplied to `list_operations` when the Node is
  absent from the registry?** The current MCP surface uses the ID only to look up the cached
  Template vocabulary and does not establish the Node exists. Decide before another surface
  depends on it as an existence assertion.

## History

- 2026-09-13 — Proposed initial capability specification for explicit human approval; no
  product behaviour changed.
