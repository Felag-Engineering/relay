# Query

**Status:** designed, not built, as of `2026-09-23`.
**Claim prefix:** `QRY`

## Purpose

Query lets an authenticated Account inspect the fleet information Relay holds without
dispatching an Operation: Nodes in the registry, one Node's recorded identity and state, the
daemon-reported Policy view, and the Operation vocabulary. It answers what Relay knows and what
a Node last reported; it does not make a Policy decision, change a Node, or infer a desired
state.

It also holds one write, which only names what it reads: a **Policy alias**, a human-readable
name a human `admin` gives a Policy fingerprint so that people can say which Policy they mean
(*Designed, not built*). An alias changes how a fingerprint is displayed and nothing else.

Read means that the call cannot change Node state, not that its contents are harmless to
disclose. Registry data includes fleet shape, Labels, Facts, identity provenance, and Policy
information, so access is attributable and auditable.

## Surfaces

| Surface | Query capability today |
|---|---|
| **MCP** | `list_nodes` lists registry Nodes, optionally resolved against a Selector. `describe_node` returns one Node's registry data, certificate provenance, the Policy view, and the reported Template Operation vocabulary. `list_operations` returns the frozen Native vocabulary and, given a Node ID, that Node's last-reported Template Operations. |
| **Control API** | `GET /api/v1/nodes/{node_id}` returns one Node's registry data and certificate provenance. No fleet enumeration, Policy-view or vocabulary route (QRY-1). |
| **Admin Console** | The Fleet view and Node detail read the registry through the capability read lane. Node detail renders the Policy view — read from the display-only cache directly — with its receipt time, and the template-set fingerprint; it does not render the Template vocabulary (QRY-14). The Compare screen reads through the lane and is recorded like every other read (QRY-28). |

Policy aliases are *Designed, not built* (QRY-29 … QRY-39): the Console reads and writes them;
the Control API and MCP carry none (QRY-36, *Future work*).

No surface exposes a general registry search, a way to refresh a daemon snapshot, or any way
to query, author or alter Policy over the wire; a live hypothetical is `policy-preflight.md`.

## Behaviour

### Registry reads

- **QRY-1** Of the registry, Policy-view and vocabulary reads, the Control API exposes exactly
  one, the single-Node read; fleet enumeration, the Policy view and vocabulary discovery are MCP
  and Console only.
- **QRY-2** A Node read returns Relay's recorded registry state: Node ID; separate `node:` and
  `relay:` Label maps; self-reported Facts; connection and revocation state; the Policy
  fingerprint and the template-set fingerprint; daemon version and `outdated` (a field on the
  Control API, a `state:` Label on MCP); recorded certificate provenance when it exists; and
  `state:` Labels evaluated at Selector-resolution time, rendered in Selector syntax, never
  stored.
- **QRY-3** `list_nodes` accepts an empty Selector or one in the `node:`, `relay:` and `state:`
  namespaces, resolves it against the registry at one evaluation instant, and returns the
  matches in Node-ID order with `state:` Labels from that same instant.
- **QRY-4** `describe_node` and the Control API Node read identify exactly one Node. A
  disconnected Node stays readable from its last registry record; `connected` is the live
  Tunnel state and is never inferred from `last_seen`.
- **QRY-5** The capability read lane's Node detail, as rendered by the Console, reports how many
  registry Nodes share the Node's non-empty Policy fingerprint and template-set fingerprint.
  These counts are observation for rollout and drift visibility, never evidence of Policy
  equivalence or trust. MCP `describe_node` does not report them today (*Future work*).
- **QRY-6** `describe_node` and `list_operations(node_id)` distinguish an absent
  template-vocabulary report from an empty reported vocabulary: a missing report is not
  evidence that a Node has no Template Operations.

### Policy view

- **QRY-7** MCP `describe_node` and the Console Node detail render the Policy view: a
  display-only copy of the effective Policy the relay-daemon previously reported. When none has
  been captured the result says so, never representing absence as an unrestricted or empty
  Policy.
- **QRY-8** The Policy view is a report, not a live query: its receipt time is Relay-stamped
  (the wire carries no timestamp), and an offline Node cannot be refreshed through this
  capability.
- **QRY-9** The Relay displays the reported rules without evaluating, merging, normalising or
  deriving a verdict; the Compare screen marks differences and never adjudicates them. A Policy
  view neither grants permission nor predicts whether a Task will run.
- **QRY-10** The view shows the whole reported Policy — raw patterns, allowed Operations,
  operation and deny rules, the fingerprint, and (on MCP) whether Raw Exec is enabled — and
  never a Template command body: no RPC carries one as Template metadata (ADR-0021, amended
  2026-10-16; see *Future work*). A `file.read` result may return a Template file where Policy
  allows it (`daemon-installation.md`, R37).

### Operation-vocabulary discovery

- **QRY-11** The Native Operation vocabulary is frozen and fleet-wide; `list_operations` reports
  each Native's name, risk class, purpose, argument constraints and an example.
- **QRY-12** With no Node ID, `list_operations` reports Natives only. With a Node ID it adds the
  Template Operations that Node last reported — names, risk classes and typed slots — and never
  a template body.
- **QRY-13** Raw Exec is not an Operation and is never listed as one.
- **QRY-14** The Console Node detail shows the template-set fingerprint and never the reported
  Template vocabulary (*Future work*).

### Access and recording

- **QRY-15** Every query surface requires an authenticated Account, and the read floor is
  `viewer` on MCP, the Control API and the Console alike; no narrower role gate applies.
- **QRY-16** On the capability read lane, on the MCP tools and on the Control API Node read, a
  read is recorded before content is returned. The record identifies the authenticated caller
  and the target: an enumeration records its Selector, a single-Node read records the requested
  Node ID, including one that does not exist.
- **QRY-17** On the capability read lane and the MCP tools, if the access record cannot be
  written the read is refused before the registry is consulted, on the Control API Node read
  as on the others. A record holds metadata about the read and never its result.
- **QRY-28** Every registry, Policy-view and vocabulary read on MCP, the Control API and the
  Console goes through the capability read lane, is recorded before content is returned, and
  fails closed; the adapters hold no reader of their own, MCP no longer resolves Selectors
  itself, and the Compare screen's exemption is gone (#680).

## Refusals

- **QRY-19** An unauthenticated caller receives no query result on any surface.
- **QRY-20** A malformed Selector, a bare Label key, or a `state:` key outside the closed
  vocabulary is refused rather than treated as an empty match. A `tag:` term is refused with a
  recognisable sentinel, because a successful empty response would falsely assert that no Node
  matched (#430).
- **QRY-21** A well-formed Node ID that is not in the registry is refused as "no such Node" on
  `describe_node`, on `list_operations` and on the Control API, and the refused read is still
  recorded with the ID that was probed.
- **QRY-22** On the capability lane a missing or oversized Node ID is refused before anything is
  recorded, on MCP `describe_node` as on the lane itself; the Control API refuses an empty ID
  before recording.
- **QRY-23** A missing Policy or Template snapshot is represented as not reported on MCP, and a
  missing Policy view as not reported on the Console. The Console's template panel does not
  distinguish "never reported" from "none installed" today.
- **QRY-24** No query surface can set Labels, modify Policy, load Templates, refresh a daemon
  snapshot, issue a Policy verdict or dispatch an Operation: each adapter's structural guard
  forbids the write and dispatch seams, and the read seams expose reads alone.
- **QRY-26** `list_operations` with a well-formed Node ID not in the registry is refused as "no
  such Node", and the refused read is recorded with the probed ID, exactly as `describe_node`
  does (#680).
- **QRY-27** MCP `describe_node` refuses a missing or oversized Node ID before recording
  anything, as the capability read lane does (#680).

## Governing ADRs and invariants

- **Invariant 2 and ADR-0002** — Policy is locally rooted and remotely immutable. Query may show
  a daemon report, but no surface can write Policy or Template Operations over the wire (QRY-24).
  A Policy alias is a name the Relay holds for a fingerprint and never sends to a Node: setting
  one writes no Policy (QRY-31).
- **Invariant 7, ADR-0006, ADR-0020 and ADR-0034** — Label namespaces stay separate: `node:` and
  `relay:` are returned as separate maps, `state:` is derived, `tag:` is refused until it exists
  (QRY-2, QRY-20). A query has no Label-write authority.
- **Invariant 8 and ADR-0007** — wire-reported data follows the protocol contract; a query surface
  never invents a second wire vocabulary. Both *Future work* items change what the daemon
  reports and start in `/proto`.
- **Invariant 10 and ADR-0009** — MCP, the Control API and the Console are adapters over the
  capability layer and may narrow only. Every registry, Policy-view and vocabulary read on all
  three goes through the capability read lane; no adapter holds a reader of its own (QRY-28,
  #680). An alias write is decided in the capability layer, and the Console only exposes it
  (QRY-29, QRY-35).
- **Invariant 9 and ADR-0008** — an alias names a fingerprint and never records which Nodes
  should carry it (QRY-32). That is the line against `policy-catalog.md`'s rule that the Relay
  stores no cohort arrangement: an alias attaches to a fingerprint only, never to a Node, Label,
  Selector or group, so it describes no desired state.
- **Invariant 12 and ADR-0011** — only the relay-daemon's live engine evaluates Policy. Displaying
  a snapshot never becomes a Relay-side verdict (QRY-9); a hypothetical is `policy-preflight.md`.
- **ADR-0014** — `outdated` is a registry observation and a dispatch gate; a query neither
  asserts Policy drift nor authorises an upgrade.
- **ADR-0015 and ADR-0021** — the Native vocabulary is golden-guarded and frozen; Template
  vocabulary is local, per-Node and report-only (QRY-11, QRY-12). ADR-0021 decides that the
  template-set fingerprint travels and the templates do not (QRY-2, QRY-10); both *Future work*
  items below would amend it and land only after that amendment.
- **ADR-0025** — query access is audited and fails closed when it cannot be recorded (QRY-16,
  QRY-17). Both shortfalls against its "what they aimed it at" rule — the Compare screen's
  unrecorded read and `list_operations` recording no Node ID — are closed (QRY-26, QRY-28, #680).
  Retention and output rules are `audit-and-read-lane.md`'s.

## Seams and proof

The capability read lane holds the registry-query methods for enumeration and the single-Node
read, with their access-recording requirement; every surface reads through it and none holds a
reader of its own (QRY-28). The Policy view and the Template vocabulary are
read from caches the Tunnel handler fills; nothing else writes them. `make verify` is sufficient
for every claim here; a change to what the daemon reports starts in `/proto` and needs the
proto gates.

### What proves each claim

| Claim | Proven by | Seam |
|---|---|---|
| QRY-1 | `TestQueryRoutes_TheControlAPIServesNoEnumerationPolicyOrVocabularyRead` (the negative half only, over the Control API's own route table rather than the composed mux, by a route-name heuristic; the positive half rests on QRY-3's, QRY-7's and QRY-11's rows) | API |
| QRY-2 | `TestMCP_ListNodes_All`, `TestMCP_ListNodes_StateLabels`, `TestHandleGetNode_StateLabels` | MCP, API |
| QRY-3 | Ordering half, empty Selector only: `TestListNodes_ReturnsMatchesInNodeIdOrder` (lane) and `TestMCP_ListNodes_ReturnsMatchesInNodeIdOrder` (MCP, seeded out of ID order). Rest of the claim: `TestMCP_ListNodes_SelectorFilter`, `TestMCP_ListNodes_All` | capability, MCP |
| QRY-4 | `Connected_IsNotInferredFromLastSeen` in the shared registry conformance suite, run as `TestRepositoryConformance` (in-memory) and `TestSQLiteRegistryConformance` (SQLite store) | registry, store |
| QRY-5 | `TestDescribeNode_CountsFingerprintPeersAndSkipsEmptyFingerprints` (the lane's arithmetic and empty-fingerprint skip); `TestNode_FingerprintPanelReportsThePeerCounts` (a real lane's counts reach the Node-detail screen); `TestMCP_DescribeNode_ReportsNoFingerprintPeerCounts` (pins today's MCP gap, which is *Future work*, not a prohibition) | capability, Console, MCP |
| QRY-6 | `TestMCP_ListOperations_PerNode`, `TestMCP_DescribeNode` | MCP |
| QRY-7 | `TestMCP_DescribeNode` | MCP |
| QRY-8 | `TestNode_PolicyPanelCarriesTheReceiptTime`, `TestNode_OfflineNodePolicyCannotBeRefreshed` | Console |
| QRY-9 | `TestCompare_MarksDifferencesAndNeverAdjudicatesThem` | Console |
| QRY-10 | `TestMCP_DescribeNode` | MCP |
| QRY-11 | `TestMCP_ListOperations` | MCP |
| QRY-12 | `TestMCP_ListOperations_PerNode`; body half `TestMCP_ListOperations_NeverCarriesATemplateBody` (keys on the field name `body` only; nothing pins the descriptor's field set in `/proto`) | MCP |
| QRY-13 | `TestMCP_ListOperations` | MCP |
| QRY-14 | `TestNode_DetailShowsTheTemplateFingerprintAndNeverTheTemplateVocabulary` (this screen only; pins today's *Future work* gap, not a permanent ban) | Console |
| QRY-15 | `TestMCP_RequiresCredential`; Control API and Console halves `TestQueryReadFloor_IsViewerOnMCPTheControlAPIAndTheConsole` (one `viewer` Account reaches each hand-listed query read on all three adapters; as `viewer` is the lowest role, it cannot tell "no narrower gate" from "no gate") | MCP, e2e |
| QRY-16 | `TestListNodes_RecordsTheEnumeration`, `TestDescribeNode_RecordsTheNodeItWasAimedAt` | capability |
| QRY-17 | `TestRegistryLane_FailsClosedWhenTheReadCannotBeAudited`, `TestRegistryLane_RefusesWithoutARealAuditSink`, `TestHandleGetNode_FailsClosedWhenTheReadCannotBeRecorded` | capability, API |
| QRY-19 | `TestMCP_RequiresCredential`, `TestConsole_UnauthenticatedIsRefused` | MCP, Console |
| QRY-20 | `TestMCP_ListNodes_SelectorFilter`, `TestMCP_ListNodes_TagSelectorIsRefusedNotEmpty` | MCP |
| QRY-21 | `TestDescribeNode_RecordsAProbeForAMissingNode` | capability |
| QRY-22 | `TestDescribeNode_BoundsTheNodeIdBeforeRecordingIt` | capability |
| QRY-23 | `TestMCP_DescribeNode` | MCP |
| QRY-24 | `TestNoDispatchConstruction`, `TestConsole_NoDispatchOutsideCapabilityLayer` | compile-time |
| QRY-26 | `TestListOperations_RefusesAnUnknownNodeAndRecordsTheProbe`, `TestMCP_ListOperations_UnknownNodeIsRefusedNotAnEmptyVocabulary` | capability, MCP |
| QRY-27 | `TestMCP_DescribeNode_BoundsTheNodeIdBeforeRecordingIt` | MCP |
| QRY-28 | `TestDispatchViolations_Fixtures` (MCP, API, Console), `TestNoDispatchConstruction`, `TestConsole_NoDispatchOutsideCapabilityLayer`, `TestSurfaceDeps_NoSurfaceIsHandedTheRegistryOrACache`, `TestMCP_ReadToolsRecordThroughTheRealLane`, `TestHandleGetNode_FailsClosedWhenTheReadCannotBeRecorded`, `TestCompare_RecordsOneReadPerPinnedNode`, `TestMCP_ListNodes_SelectorIsResolvedByTheLane` | compile-time, MCP, API, Console |

Claims with **no row**, and so nothing checking them:

- **QRY-3**, ordering under a *filtered* Selector — Node-ID order is now asserted at the lane and
  at MCP, but for the empty Selector only; nothing checks that a Selector-filtered resolution
  preserves it (#681).

### Performance

| Characteristic | Contract | Measured by |
|---|---|---|
| Node enumeration | Returns every Node matching the Selector, sorted by Node ID; never silently pages or truncates | *(none)* |
| Single-Node detail | Reads one Node and computes its fingerprint-peer counts without the caller enumerating the fleet | *(none)* |
| Vocabulary discovery | A fleet-wide request returns Natives only; per-Node Template vocabulary needs an exact Node ID until QRY-25 | *(none)* |

## Designed, not built

| Claim | Statement | Milestone |
|---|---|---|
| QRY-25 | `list_operations` takes a Selector and reports each Operation reachable across the matched Nodes — description, typed slots and allowed values, risk class, and which Nodes report it; a single Node ID is the one-Node case. Retires the Node-ID-only half of QRY-12 and the vocabulary row in *Performance*. | v0.8.1 — Read and Preflight Wire Contract |
| QRY-29 | A human Account with the `admin` role can set, rename or clear the **Policy alias** of a well-formed Policy fingerprint through the capability layer. | v0.6.0 — Admin Console: Monitoring |
| QRY-30 | Every alias change is recorded on the audit trail with the actor, the fingerprint, and the old and new value, and is not made if the record cannot be written. | v0.6.0 — Admin Console: Monitoring |
| QRY-31 | A Policy alias is a display name the Relay holds for a fingerprint. It is not Policy, is never sent to a Node, and takes no part in Selector resolution, `state:policy-fingerprint=` matching, Policy evaluation, the blast-radius cap, approval or any other decision; a Selector or filter names a Policy only by its fingerprint. | v0.6.0 — Admin Console: Monitoring |
| QRY-32 | An alias attaches to a fingerprint only — never to a Node, Label, Selector or group — and records nothing about which Nodes should carry that fingerprint. | v0.6.0 — Admin Console: Monitoring |
| QRY-33 | Wherever an alias is rendered, the full fingerprint it names is rendered beside it; an alias is never shown in place of the fingerprint. | v0.6.0 — Admin Console: Monitoring |
| QRY-34 | One fingerprint has at most one alias, and one alias names at most one fingerprint. An alias is held in the Relay's store, survives a restart, and stays attached to its fingerprint whether or not any Node currently reports it. | v0.6.0 — Admin Console: Monitoring |
| QRY-35 | The Console's Fleet view, Node detail and Compare screen read aliases through the capability read lane, and the Console offers the write to a human `admin` only, from the Fleet view's fingerprint facet and Node detail's Fingerprints panel. | v0.6.0 — Admin Console: Monitoring |
| QRY-36 | The Control API and MCP carry no alias, on any read, and expose no alias write. | v0.6.0 — Admin Console: Monitoring |
| QRY-37 | Setting, renaming or clearing an alias takes no step-up: an alias gates nothing. | v0.6.0 — Admin Console: Monitoring |
| QRY-38 | An alias write is refused, with a reason naming the rule, to an unauthenticated caller, to a machine Account of any role and to a human Account below `admin`; and for a fingerprint that is not well-formed, an alias that after trimming is empty or longer than 64 characters or contains a control or format character (Unicode categories Cc and Cf, which covers bidirectional overrides), or an alias another fingerprint already carries. Clearing an alias that is not set is not an error. | v0.6.0 — Admin Console: Monitoring |
| QRY-39 | No query surface can set Labels, modify Policy, load Templates, refresh a daemon snapshot, issue a Policy verdict or dispatch an Operation: each adapter's structural guard forbids every write seam but the alias write (QRY-29), and every dispatch seam. Replaces QRY-24 when promoted. | v0.6.0 — Admin Console: Monitoring |

## Out of scope

- Audit-trail, Job, Task and read-egress queries, including result retention and output
  disclosure — `audit-and-read-lane.md`.
- Live hypothetical Policy evaluation and preflight/apply parity — `policy-preflight.md`; this
  capability only displays what a Node already reported.
- Any write but a Policy alias. Policy authoring, Template loading or distribution, Label
  writes, Node enrollment and revocation, Account administration, and dispatch.
- Fleet health monitoring, metrics, desired-state reconciliation, configuration management,
  daemon upgrades, and an unbounded remote shell.

## Future work

The first two items the owner decided in principle on `2026-09-14` and `2026-09-21`, and they
cannot be Designed here: each reverses a decision in ADR-0021 (and ADR-0034), so the amendment
lands first, in the session that migrates `policy.md`, with the threat model and `GLOSSARY.md` as
its consumers. The rest is ordinary Future work.

- **Template command bodies cross the wire.** The relay-daemon reports each Template Operation's
  body with its descriptor, and the Policy view shows it verbatim: a Node tells the Relay what it
  can and cannot do. The bound that must travel with it: the Relay displays a body and never
  substitutes slot values into it or executes a rendered command — substitution happens only on
  the daemon, inside the structure the Template's author fixed (invariant 1, ADR-0021), and no
  verdict is derived from a body (invariant 12). Reverses ADR-0021's "drift visibility without
  the templates traveling"; a `/proto` change; a threat-model row for what a hostile Node's body
  discloses into a `viewer`'s and the AI-agent's context.
- **The template-set fingerprint is retired.** From every Node read and from the `state:`
  vocabulary (`state:template-fingerprint=`, `state:template-unloadable`); a Node read shows the
  Policy fingerprint, whether the Policy is valid, and whether it enables Raw Exec, with "valid"
  defined by `policy.md`. Amends ADR-0021 and ADR-0034.
- **Control API query routes** — fleet enumeration, the Policy view and vocabulary discovery.
  Each would adapt the capability read lane, never add a reader of its own.
- **Peer counts on MCP `describe_node`** — the lane computes them; the tool does not surface them.
- **Template vocabulary on the Console Node detail**, distinguishing "never reported" from "none
  installed".
- **Policy aliases beyond the Console.** The alias on Control API and MCP reads, and a Control API
  write. Both are held back for one reason: either would hand an AI-agent — a machine Account on
  both surfaces (ADR-0010) — an `admin`'s prose name for a Policy, an assertion it could reason
  from in place of the fingerprint it targets by. Exposing one is a decision about that, not an
  adapter's to make alone.
- **Roles tighter than `viewer`** for sensitive fleet data, if a tenant, delegated-access or
  data-classification need appears.

## Accepted residual risk

- **A hijacked human `admin` session can rename aliases to mislead.** Without the Account's
  password, it can name an unhardened fingerprint "web-hardened" and steer the humans who judge a
  rollout by name. Accepted by the owner on `2026-10-18` (Console D22) in taking no step-up for an
  alias; the compensating controls are QRY-33 (the fingerprint is always beside the name) and
  QRY-30 (every change is audited with its old and new value). Threat model **R39**.

## Open questions

None of this capability's own. Neighbours that state one of today's decisions the other way and
adopt this spec at their migration: `operations-and-templates.md` (states Selector-scoped
`list_operations` as current; it is QRY-25), `policy.md` (states template bodies in the Policy view
as current; see *Future work*), `audit-and-read-lane.md` (says MCP `describe_node` returns peer
counts; QRY-5). `audit-and-read-lane.md` lists the audit kinds and does not yet name the
alias-change record (QRY-30); it adopts it at its migration. `selectors-and-labels.md` and
`audit-and-read-lane.md` no longer disagree about Selector resolution or MCP read records: #680 made
both statements true (QRY-28).

## Retired

- **QRY-18** — `2026-09-23` — deleted; QRY-26 … QRY-28 replace it. (#680)
