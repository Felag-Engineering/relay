# Query

**Status:** designed, not built, as of `2026-11-20`.
**Claim prefix:** `QRY`
**Governed by:** ADR-0002, ADR-0006, ADR-0007, ADR-0009, ADR-0011, ADR-0014, ADR-0015, ADR-0020,
ADR-0021, ADR-0025, ADR-0034, ADR-0050, ADR-0051; invariants 2, 7, 8, 9, 10, 12.

## Purpose

Query lets a signed-in Account see what Relay knows about the fleet without running anything:
which Nodes exist, one Node's identity and state, the Policy (the rules a Node runs by) each
Node reported when it last connected, and the Operations a Node offers. It never makes a Policy
decision, changes a Node, or says what a Node ought to be.

Its one write is a **Policy alias**: a readable name a human `admin` gives a Policy fingerprint
(its hash), which changes only how that hash is displayed.

Read means a call cannot change a Node, not that the answer is harmless: fleet shape, Labels,
identity and Policy are sensitive, so every read is attributed and recorded.

## Surfaces

| Surface | Query capability today |
|---|---|
| **MCP** | `list_nodes` lists registry Nodes, optionally resolved against a Selector. `describe_node` returns one Node's registry data, certificate provenance, the Policy view, and the reported Template Operation vocabulary. `list_operations` returns the frozen Native vocabulary and, given a Node ID, the Template Operations that Node reported at the start of its latest stream. |
| **Control API** | `GET /api/v1/nodes/{node_id}` returns one Node's registry data and certificate provenance. No fleet enumeration, Policy-view or vocabulary route (QRY-1). |
| **Admin Console** | The Fleet view and Node detail read the registry through the capability read lane. Node detail renders the Policy view, read through the same lane, with its receipt time, and the template-set fingerprint; it does not render the Template vocabulary (QRY-14). The Compare screen reads through the lane and is recorded like every other read (QRY-28). |

Policy aliases (QRY-29 … QRY-38) are read and written on the Console only; the Control API and
MCP carry none (QRY-36).

No surface exposes a general registry search, a way to refresh a daemon snapshot, or any way
to query, author or alter Policy over the wire; a live hypothetical is `policy-preflight.md`.

## Behaviour

### Registry reads

- **QRY-1** Of the registry, Policy-view and vocabulary reads, the Control API exposes exactly
  one, the single-Node read; fleet enumeration, the Policy view and vocabulary discovery are MCP
  and Console only.
- **QRY-4** `describe_node` and the Control API Node read identify exactly one Node. A
  disconnected Node stays readable from its last registry record; `connected` is the
  connection state as `node-connection.md` defines it, never inferred from `last_seen`.
- **QRY-5** The capability read lane's Node detail, as rendered by the Console, reports how many
  registry Nodes share the Node's non-empty Policy fingerprint and template-set fingerprint.
  These counts are observation for rollout and drift visibility, never evidence of Policy
  equivalence or trust. MCP `describe_node` does not report them.
- **QRY-6** `describe_node` and `list_operations(node_id)` distinguish an absent
  template-vocabulary report from an empty reported vocabulary: a missing report is not
  evidence that a Node has no Template Operations.

- **QRY-40** A Node read returns Relay's recorded registry state: Node ID; separate `node:`,
  `relay:` and `tag:` Label maps, the last holding the Node's Tags; self-reported Facts; connection
  and revocation state; the Policy fingerprint and the template-set fingerprint; daemon version and
  `outdated` (a field on the Control API, a `state:` Label on MCP); recorded certificate provenance
  when it exists; and `state:` Labels evaluated at Selector-resolution time, rendered in Selector
  syntax, never stored.
- **QRY-43** `describe_node`, the Control API Node read and the Console Node detail show the Node's clock skew as `node-connection.md` records it: a signed number of milliseconds with the time it was measured, or "not measured". It is shown apart from the self-reported Facts and never as a warning: no threshold, badge or `state:` term.
- **QRY-44** `describe_node`, the Control API Node read and the Console Node detail show when the Node first connected, beside its certificate provenance (QRY-40), or that it has never connected.
- **QRY-41** `list_nodes` accepts an empty Selector or one in the `node:`, `relay:`, `tag:` and
  `state:` namespaces, resolves it against the registry at one evaluation instant, and returns
  every match, never paged or truncated, in Node-ID order with `state:` Labels from that same
  instant.

### Policy view

- **QRY-7** MCP `describe_node` and the Console Node detail render the Policy view: a
  display-only copy of the effective Policy the relay-daemon reported at the start of its latest
  stream. When none has been captured the result says so, never representing absence as an
  unrestricted or empty Policy.
- **QRY-8** The Policy view is a report, not a live query: its receipt time is Relay-stamped
  (the wire carries no timestamp), and an offline Node cannot be refreshed through this
  capability.
- **QRY-9** The Relay displays the reported rules without evaluating, merging, normalising or
  deriving a verdict; the Compare screen marks differences and never adjudicates them. A Policy
  view neither grants permission nor predicts whether a Task will run.
- **QRY-10** The view shows the whole reported Policy — raw patterns, allowed Operations,
  operation and deny rules, the fingerprint, and (on MCP) whether Raw Exec is enabled — and
  never a Template command body: no RPC carries one as Template metadata (ADR-0021). A
  `file.read` result may return a Template file where Policy allows it (`daemon-installation.md`,
  R37).

### Operation-vocabulary discovery

- **QRY-11** The Native Operation vocabulary is frozen and fleet-wide; `list_operations` reports
  each Native's name, risk class, purpose, argument constraints and an example.
- **QRY-12** With no Node ID, `list_operations` reports Natives only. With a Node ID it adds the
  Template Operations that Node reported at the start of its latest stream — names, risk classes
  and typed slots — and never a template body.
- **QRY-13** Raw Exec is not an Operation and is never listed as one.
- **QRY-14** The Console Node detail shows the template-set fingerprint and never the reported
  Template vocabulary.

### Access and recording

- **QRY-15** Every query surface requires an authenticated Account, and the read floor is
  `viewer` on MCP, the Control API and the Console alike; no narrower role gate applies.
- **QRY-16** On the capability read lane, on the MCP tools and on the Control API Node read, a
  read is recorded before content is returned. The record identifies the Principal
  and the target: an enumeration records its Selector, a single-Node read records the requested
  Node ID, including one that does not exist.
- **QRY-17** On the capability read lane and the MCP tools, if the access record cannot be
  written the read is refused before the registry is consulted, on the Control API Node read
  as on the others. A record holds metadata about the read and never its result.
- **QRY-28** Every registry, Policy-view and vocabulary read on MCP, the Control API and the
  Console goes through the capability read lane, is recorded before content is returned, and
  fails closed; the adapters hold no reader of their own, MCP resolves no Selector itself, and
  the Compare screen has no exemption.

- **QRY-29** A human Account with the `admin` role can set, rename or clear the **Policy alias** of
  a well-formed Policy fingerprint through the capability layer.
- **QRY-30** Every alias change is recorded on the audit trail with the actor, the fingerprint,
  and the old and new value, and is not made if the record cannot be written.
- **QRY-31** A Policy alias is a display name the Relay holds for a fingerprint. It is not Policy,
  is never sent to a Node, and takes no part in Selector resolution, `state:policy-fingerprint=`
  matching, Policy evaluation, the blast-radius cap, approval or any other decision; a Selector or
  filter names a Policy only by its fingerprint.
- **QRY-32** An alias attaches to a fingerprint only — never to a Node, Label, Selector or group —
  and records nothing about which Nodes should carry that fingerprint.
- **QRY-33** Wherever an alias is rendered, the full fingerprint it names is rendered beside it;
  an alias is never shown in place of the fingerprint.
- **QRY-34** One fingerprint has at most one alias, and one alias names at most one fingerprint.
  An alias is held in the Relay's store, survives a restart, and stays attached to its fingerprint
  whether or not any Node currently reports it.
- **QRY-35** The Console's Fleet view, Node detail and Compare screen read aliases through the
  capability read lane, and the Console offers the write to a human `admin` only, from the Fleet
  view's fingerprint facet and Node detail's Fingerprints panel.
- **QRY-36** The Control API and MCP carry no alias, on any read, and expose no alias write.
- **QRY-37** Setting, renaming or clearing an alias takes no step-up: an alias gates nothing (R39).

## Refusals

- **QRY-19** An unauthenticated caller receives no query result on any surface.
- **QRY-42** A malformed Selector, a bare Label key, or a `state:` key outside the closed vocabulary
  is refused rather than treated as an empty match.
- **QRY-21** A well-formed Node ID that is not in the registry is refused as "no such Node" on
  `describe_node`, on `list_operations` and on the Control API, and the refused read is still
  recorded with the ID that was probed.
- **QRY-22** On the capability lane a missing or oversized Node ID is refused before anything is
  recorded, on MCP `describe_node` as on the lane itself; the Control API refuses an empty ID
  before recording.
- **QRY-23** A missing Policy or Template snapshot is represented as not reported on MCP, and a
  missing Policy view as not reported on the Console. The Console's template panel does not
  distinguish "never reported" from "none installed".
- **QRY-24** No query surface can set Labels, modify Policy, load Templates, refresh a daemon
  snapshot, issue a Policy verdict or dispatch an Operation: each adapter's structural guard
  forbids the write and dispatch seams, and the read seams expose reads alone.
- **QRY-26** `list_operations` with a well-formed Node ID not in the registry is refused as "no
  such Node", and the refused read is recorded with the probed ID, exactly as `describe_node`
  does.
- **QRY-27** MCP `describe_node` refuses a missing or oversized Node ID before recording
  anything, as the capability read lane does.
- **QRY-38** An alias write is refused, with a reason naming the rule, to an unauthenticated
  caller, to a machine Account of any role and to a human Account below `admin`; and for a
  fingerprint that is not well-formed, an alias that after trimming is empty or longer than 64
  characters or contains a control or format character (Unicode categories Cc and Cf, which covers
  bidirectional overrides), or an alias another fingerprint already carries. Clearing an alias
  that is not set is not an error.

## Designed, not built

| Claim | Statement | Milestone |
|---|---|---|
| QRY-25 | `list_operations` takes a Selector and reports each Operation reachable across the matched Nodes — description, typed slots and allowed values, risk class, and which Nodes report it; a single Node ID is the one-Node case. Retires the Node-ID-only half of QRY-12. | After MVP |
| QRY-39 | No query surface can set Labels, modify Policy, load Templates, refresh a daemon snapshot, issue a Policy verdict or dispatch an Operation: each adapter's structural guard forbids every write seam but the alias write (QRY-29), and every dispatch seam. Replaces QRY-24 when promoted. | After MVP |

## Out of scope

- Audit-trail, Job, Task and read-egress queries, including result retention and output
  disclosure — `audit-and-read-lane.md`.
- Live hypothetical Policy evaluation and preflight/apply parity — `policy-preflight.md`; this
  capability only displays what a Node already reported.
- Any write but a Policy alias. Policy authoring, Template loading or distribution, Label
  writes (a Tag is written through its own capability action, even where the Console offers it
  beside a query view — `selectors-and-labels.md`, ADR-0050), Node enrollment and revocation
  (`enrollment.md`), Account administration (`accounts-and-access.md`), and dispatch
  (`execution.md`).
- Fleet health monitoring and metrics (`observability.md`); desired-state reconciliation,
  configuration management, daemon upgrades and a remote shell (`AGENTS.md`, out of realm).
- Template bodies on the wire, retiring the template-set fingerprint, Control API query routes,
  peer counts on MCP, the Template vocabulary on the Console, aliases beyond the Console, Raw
  Exec state on the Control API and Console reads, and roles tighter than `viewer`:
  `roadmap: relay/research/spec-future-work/query`.

## Proof

<!-- proof:begin -->
| Claim | Proven by | Seam |
|---|---|---|
| QRY-1 | `TestQueryRoutes_TheControlAPIServesNoEnumerationPolicyOrVocabularyRead` | API |
| QRY-4 | `TestHandleGetNode_ADisconnectedNodeIsReadFromItsLastRecordAndConnectedIsNotLastSeen`, `TestMCP_DescribeNode_ADisconnectedNodeIsReadFromItsLastRecord` | API, MCP |
| QRY-5 | `TestDescribeNode_CountsFingerprintPeersAndSkipsEmptyFingerprints`, `TestMCP_DescribeNode_ReportsNoFingerprintPeerCounts`, `TestNode_FingerprintPanelReportsThePeerCounts` | Console, MCP, capability |
| QRY-6 | `TestMCP_TemplateVocabulary_AnAbsentReportIsNotAnEmptyOne` | MCP |
| QRY-7 | `TestDescribeNode_AnUnwiredCacheReportsNotReportedNotAnEmptyPolicy` | capability |
| QRY-8 | `TestCache_Set_StampsTheRelaysOwnClock`, `TestNode_OfflineNodePolicyCannotBeRefreshed`, `TestNode_PolicyPanelCarriesTheReceiptTime`, `TestWire_PolicySnapshotCarriesNoTimestamp` | Console, policyview |
| QRY-9 | `TestCompare_MarksDifferencesAndNeverAdjudicatesThem`, `TestNode_ReportedPolicyComesFromTheDaemonsOwnEngine` | Console |
| QRY-10 | `TestMCP_DescribeNode_ThePolicyViewIsTheWholeReportAndNoTemplateBody` | MCP |
| QRY-11 | `TestMCP_ListOperations` | MCP |
| QRY-12 | `TestListOperations_WithNoNodeIdRecordsTheToolAndNoTarget`, `TestMCP_ListOperations_NeverCarriesATemplateBody` | MCP, capability |
| QRY-13 | `TestMCP_ListOperations` | MCP |
| QRY-14 | `TestNode_DetailShowsTheTemplateFingerprintAndNeverTheTemplateVocabulary` | Console |
| QRY-15 | `TestQueryReadFloor_IsViewerOnMCPTheControlAPIAndTheConsole` | Relay |
| QRY-16 | `TestListNodes_RecordsTheEnumeration`, `TestListNodes_ResolvesTheSelectorAndRecordsItsCanonicalForm` | capability |
| QRY-17 | `TestHandleGetNode_FailsClosedWhenTheReadCannotBeRecorded` | API |
| QRY-19 | `TestConsole_UnauthenticatedIsRefused`, `TestHandleGetNode_AnUnauthenticatedCallerReceivesNoNode`, `TestMCP_RequiresCredential` | API, Console, MCP |
| QRY-21 | `TestDescribeNode_RecordsAProbeForAMissingNode`, `TestHandleGetNode_AnUnknownNodeIsNoSuchNodeAndTheProbeIsRecorded`, `TestListOperations_RefusesAnUnknownNodeAndRecordsTheProbe`, `TestMCP_DescribeNode_AnUnknownNodeIsRefusedAndTheProbeIsRecorded`, `TestMCP_ListOperations_UnknownNodeIsRefusedNotAnEmptyVocabulary` | API, MCP, capability |
| QRY-22 | `TestDescribeNode_BoundsTheNodeIdBeforeRecordingIt`, `TestMCP_DescribeNode_BoundsTheNodeIdBeforeRecordingIt` | MCP, capability |
| QRY-23 | `TestMCP_TemplateVocabulary_AnAbsentReportIsNotAnEmptyOne`, `TestNode_FactsAppearHereAndPolicySaysWhenItIsUnknown`, `TestNode_FingerprintPanelReportsThePeerCounts`, `TestNode_TemplatePanelDoesNotDistinguishNeverReportedFromNoneInstalled` | Console, MCP |
| QRY-24 | `TestConsole_NoDispatchOutsideCapabilityLayer`, `TestNoDispatchConstruction` | API, Console, MCP |
| QRY-26 | `TestListOperations_RefusesAnUnknownNodeAndRecordsTheProbe`, `TestMCP_ListOperations_UnknownNodeIsRefusedNotAnEmptyVocabulary` | MCP, capability |
| QRY-27 | `TestMCP_DescribeNode_BoundsTheNodeIdBeforeRecordingIt` | MCP |
| QRY-28 | `TestHandleGetNode_FailsClosedWhenTheReadCannotBeRecorded`, `TestMCP_ListNodes_SelectorIsResolvedByTheLane`, `TestMCP_ReadToolsRecordThroughTheRealLane` | API, MCP |
| QRY-29 | `TestConsolePolicyAliases_AHumanAdminSetsRenamesAndClearsThroughTheRealCapabilityLayer`, `TestPolicyAliasAdmin_HumanAdminSetsRenamesAndClears` | Relay, capability |
| QRY-30 | `TestAppendWithPolicyAlias_AnUnwritableRecordLeavesTheAliasUnchanged`, `TestAppendWithPolicyAlias_SetRenameClearWriteOneRecordEach`, `TestConsolePolicyAliases_AHumanAdminSetsRenamesAndClearsThroughTheRealCapabilityLayer`, `TestPolicyAliasAdmin_ChangeIsNotMadeWhenItsRecordCannotBeWritten`, `TestPolicyAliasAdmin_RecordsTheActorFingerprintOldAndNewValue`, `TestRecordPolicyAlias_ReasonCarriesFingerprintOldAndNew` | Relay, auditsink, capability, store |
| QRY-31 | `TestPolicyAlias_IsNeverASelectorTerm`, `TestPolicyAlias_NoWireOrResolutionPackageImportsIt`, `TestPolicyAliases_ReachOnlyTheAliasAdminAndTheReadLane` | capability, policyalias |
| QRY-32 | `TestPolicyAliasShapes_NameNoNodeLabelOrSelector`, `TestPolicyAliases_TableHoldsAFingerprintAndANameOnly` | capability, store |
| QRY-33 | `TestCompare_AFingerprintCarriesOneLetterInEveryColumn`, `TestPolicyAliases_AMachinePrincipalIsDrawnNoAliasName`, `TestPolicyAliases_EveryAliasIsDrawnBesideItsFullFingerprint`, `TestPolicyAliases_FiltersAndLinksCarryTheHashNeverTheAlias`, `TestPolicyAliases_NoLetterOrAliasCarriesColourOrRanking`, `TestPolicyAliases_UnaliasedFingerprintsTakeLettersInOrderOfFirstAppearance` | Console |
| QRY-34 | `TestAppendWithPolicyAlias_OneAliasPerFingerprint`, `TestAppendWithPolicyAlias_OneFingerprintPerAlias`, `TestPolicyAliasAdmin_SetsAnAliasForAFingerprintNoNodeReports`, `TestPolicyAliases_StayAttachedWithNoNodeReportingTheFingerprint`, `TestPolicyAliases_SurviveARestart` | capability, store |
| QRY-35 | `TestFleet_EveryPolicyFingerprintCarriesItsEditorAtScale`, `TestPolicyAliasesOffered_RequiresAWiredWriterAHumanAndTheAdminRoute`, `TestPolicyAliases_AnUnreadableAliasReadIsNamedAsTheAliases`, `TestPolicyAliases_AnUnrecordableAliasReadRefusesThePage`, `TestPolicyAliases_FleetNodeDetailAndCompareReadThroughTheRecordedLane`, `TestPolicyAliases_ReadsOnlyWhenTheyAreDrawn`, `TestPolicyAliases_TheEditControlIsOfferedToAHumanAdminOnly`, `TestPolicyAliases_TheEditorCarriesWhatTheWriteNeeds` | Console |
| QRY-36 | `TestControlAPI_CarriesNoPolicyAlias`, `TestMCP_CarriesNoPolicyAlias` | API, MCP |
| QRY-37 | `TestPolicyAliasAdmin_TakesNoStepUp`, `TestPolicyAliases_AWriteReachesTheCapabilityLayerAndReturnsToWhereItWasMade` | Console, capability |
| QRY-38 | `TestAppendWithPolicyAlias_RefusesAMalformedCall`, `TestAuthorizeControl_PolicyAliasIsAdminAndHumanOnly`, `TestClearPolicyAlias_NotSetIsNotAnError`, `TestNormalizePolicyAlias`, `TestPolicyAliasAdmin_Refusals`, `TestSetPolicyAlias_StoresTheTrimmedValueAndAcceptsTheLengthBoundary`, `TestValidPolicyFingerprint` | authz, capability, store |
| QRY-40 | `TestHandleGetNode_ReturnsTagsAsTheirOwnMap`, `TestMCP_NodeReads_ReturnTagsAsTheirOwnMap` | API, MCP |
| QRY-41 | `TestListNodes_ResolvesATagSelector`, `TestListNodes_ResolvesTheSelectorAndRecordsItsCanonicalForm`, `TestListNodes_ReturnsMatchesInNodeIdOrder`, `TestMCP_ListNodes_ReturnsMatchesInNodeIdOrder`, `TestMCP_ListNodes_TagSelectorResolves`, `TestSelectorMatchesTagReadsOnlyTagLabels` | MCP, capability |
| QRY-42 | `TestMCP_ListNodes_RefusesMalformedBareAndUnknownStateTerms` | MCP |
| QRY-43 | `TestHandleGetNode_ShowsTheMeasuredClockSkewApartFromTheFacts`, `TestMCP_DescribeNode_ShowsTheMeasuredClockSkewApartFromTheFacts`, `TestNode_DetailShowsTheMeasuredClockSkewOutsideTheFactsPanel` | API, Console, MCP |
| QRY-44 | `TestHandleGetNode_ShowsTheFirstConnectOrThatTheNodeNeverConnected`, `TestMCP_DescribeNode_ShowsTheFirstConnectOrThatTheNodeNeverConnected`, `TestNode_DetailShowsTheFirstConnectBesideTheCertificateProvenance` | API, Console, MCP |

Unproven: none.
<!-- proof:end -->

## Retired

- **QRY-2** — `2026-10-26` — a Node read returned `node:` and `relay:` maps only; replaced by QRY-40.
- **QRY-3** — `2026-10-26` — `list_nodes` accepted no `tag:` term; replaced by QRY-41.
- **QRY-20** — `2026-10-26` — a `tag:` term was refused with a sentinel while Tags had no writer;
  replaced by QRY-42.
- **QRY-18** — `2026-09-23` — deleted; QRY-26 … QRY-28 replace it. (#680)
