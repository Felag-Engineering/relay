# Approval

**Status:** current as of `2026-10-30`.
**Claim prefix:** `AP`
**Governed by:** ADR-0047, ADR-0027, ADR-0029, ADR-0049, ADR-0043; invariants 4, 5, 7, 10, 11, 13.

## Purpose

Approval puts a human decision between a request and its execution, for work an operator has
decided is too consequential to run on an AI-agent's say-so alone. Relay's other guardrails
answer "may this caller do this?" in advance; approval asks a person "should this happen now?"
at the moment of the act. Relay writes the question, the requesting client puts it to a person,
and the answer binds to exactly what that person was shown. An approval only adds a check: it
never lowers a Node's own Policy or the fleet's blast-radius cap.

## Surfaces

| Surface | How it is reached |
|---|---|
| **MCP** | **MRTR elicitation.** A gated `tools/call` answers with an input-required result carrying a Relay-written question; the client puts it to a person and retries the call carrying the answer (*Answering*). No MCP tool records a decision (AP-83), and no park is rendered as an MCP task handle (AP-85). |
| **Control API** | `GET /api/v1/approvals`, `GET /api/v1/approvals/{id}`, `POST /api/v1/approvals/{id}/decision`: the rescue, for a client that cannot be asked or a question a restart stranded (AP-80). Specified here, and not featured in getting-started material. |
| **Admin Console** | None (AP-80): no queue, no request screen, no decision. It renders what an approval left on other records. |

Server-initiated elicitation is not a surface: MCP's 2026-07-28 revision removed it, and MRTR is
the conformant form (ADR-0029).

## Behaviour

**Where the gate sits**

- **AP-1** The gate is consulted inside the dispatch pipeline, after Selector resolution,
  Relay-side authorization and the blast-radius cap, and before any Task exists.
- **AP-2** A park leaves no Job and no Pending Tasks behind.
- **AP-3** The approver is shown the resolved fan-out: the matched Node count and a capped
  sample of Node IDs. The full resolved set is bound by the plan hash (AP-20).

**Gate rules**

- **AP-89** Gate rules live where `relay-configuration.md` sets, as a section of the Relay configuration file; a configuration with no gate rules gates nothing.
- **AP-81** A gate rule names what it matches and how long a request it parks lives, and nothing else. A rule naming a count, an audience, a requester exclusion or a channel is refused when the configuration loads, naming the field, and no rule demands a channel.
- **AP-5** No API route and no MCP tool can write gate rules.
- **AP-6** A gate rule only adds a gate; it never waives a guardrail. A rule no decision could
  ever satisfy is refused when the rules load.
- **AP-90** Every configuration Relay ships, the one the package writes and the example a container install starts from, carries rules that gate every `mutate` and every Raw Exec, so a fresh install is gated; `read` is not.
- **AP-8** Gate rules that cannot be loaded refuse Relay startup: the Relay never runs ungated
  because its rules are unreadable or malformed.

**Answering**

- **AP-83** No MCP tool records a decision; `approve_request` does not exist.
- **AP-17** Every decision records into one decision model, and its audit entry carries the
  answer and the channel.
- **AP-60** A gated dispatch from a client that can be asked is answered with a question carrying
  the Relay-written summary, the request ID and the plan hash, and parks.
- **AP-62** A question is emitted only for a park this call created; a re-drive that bounces off
  a request already pending asks nobody.
- **AP-86** Whether Relay asks a client turns on the client advertising elicitation, on any
  session, never on its declared name.
- **AP-65** The state a client echoes back is sealed and bound to the caller, the request, the
  plan hash and the call; a tampered, cross-request, cross-account, wrong-call or expired one is
  refused.
- **AP-63** An answer on the retried call records a Decision: the channel `in-band`, the
  verified Account whose credential made the call, and the responder assertion as asserted,
  except under AP-79.
- **AP-87** An elicited answer on an API Token session is accepted as that session's Account's
  decision without a responder assertion. On a human Account's token the human is the decider,
  recorded as a token-session answer, distinct from an OAuth session's verified decision (AP-79).
  On a machine Account's token the decision is machine self-confirmation, and any responder
  assertion is recorded as asserted. On any other session an answer is accepted only when it
  carries a responder assertion whose gate is `permission`, unless AP-79 applies.
- **AP-79** An elicited answer arriving on an OAuth session of a human Account is that human's verified
  decision, whatever the client calls itself: the human is in the verified lane, and any
  responder assertion is ignored.
- **AP-88** Every elicited decision records how its decider was identified: an OAuth session, an
  API Token session, or a responder assertion, so an auditor can tell them apart (threat model
  R45).
- **AP-10** A responder assertion is at most 256 bytes with no control characters, and one
  outside that bound is refused, never truncated. It is recorded only as asserted, never as
  something Relay verified; under AP-79 it is not recorded.
- **AP-66** An approving retry re-enters the whole dispatch pipeline, Freeze, resolution,
  authorization, the cap and the plan-hash match, and a changed Node set parks again.
- **AP-67** A retry whose decision already released a Job re-attaches to it and mints no second.
- **AP-68** A denial on the retry is terminal and audited, and nothing is dispatched.
- **AP-85** A parked request is never rendered as an MCP task handle: a park that asks nobody
  is answered `pending_approval`.
- **AP-80** The Control API decision endpoint decides any parked request, recording the channel
  `out-of-band`. The Admin Console has no approval surface and renders approval records only
  where another record shows them.
- **AP-12** The receiving surface sets a decision's channel; a request body cannot name one.
- **AP-18** A decision arrives by no route but an in-band answer and the Control API decision
  endpoint. Relay integrates no chat or paging system.

**What a decision does**

- **AP-26** A decision is refused for any cause under *Refusals*, and for no other.
- **AP-82** A request is ended by its first Decision that no refusal stops: an approving Decision releases it, and a denying one ends it.
- **AP-27** A denial is terminal, and audited as fully as a release.
- **AP-11** A machine Account cannot decide its own request on the Control API; only an
  accepted in-band answer counts as its self-confirmation.
- **AP-28** Deciding does not dispatch; a released request proceeds when it is re-driven.
- **AP-77** An approval releases one execution. A released request is bound to exactly one Job,
  the binding survives the requesting call ending, and any later dispatch whose plan hash
  matches re-attaches to that Job until the approval's deadline. After it, a dispatch with that
  plan hash parks afresh.
- **AP-20** An approval binds to a plan hash over the rendered preflight: the Operation, its
  arguments and the resolved fan-out.
- **AP-21** A dispatch whose plan hash does not match the approved one parks again rather than
  running.
- **AP-22** The binding is by identity, never by count: any Node not in the approved set parks.
- **AP-92** No approval request records a shape key; a request is addressed only by its
  ID and its plan hash.
- **AP-25** A parked request expires after an operator-set time, 4 hours by default, and is
  swept; the work must be requested again.

- **AP-84** No surface requests, issues or claims an approval grant.

**Notification and record**

- **AP-38** When a request parks, Relay POSTs a best-effort notice to the configured webhook.
  Correctness never depends on it, and nothing returns on it.
- **AP-39** Every gated dispatch and every Decision records in two separate lanes: verified (the
  Account Relay authenticated) and asserted (what the caller claimed). An asserted approver never
  enters the verified lane.
- **AP-40** The audit schema keeps the lanes apart, and a surface shows them as separately
  labelled trust chips.

## Refusals

- **AP-41** A park is not a refusal: nothing was denied and nothing ran. It is audited under its
  own kind, telling a new request from a re-drive of a pending one.

| Claim | Refusal | Cause |
|---|---|---|
| **AP-42** | Not pending / not found | The request is terminal, expired, or unknown |
| **AP-46** | Plan hash changed | The cited plan hash is not the request's |
| **AP-48** | Machine self-decision | A machine Account deciding its own request other than by an accepted in-band answer |
| **AP-49** | Role floor | The decider is below the floor the Action needed to be requested |
| **AP-54** | Approvals unavailable | The gate rules could not be loaded, so the Relay does not start (AP-8) |
| **AP-93** | Request missing | The decision names no request |
| **AP-94** | Approvals not wired | The Relay was composed without approvals, which no shipped configuration does, so no request exists to decide |
| **AP-95** | Store failed | The Relay's store failed to read or write the request; nothing is decided |

## Out of scope

- **The rest of the dispatch pipeline:** `execution.md`.
- **Loading and checking the configuration:** `relay-configuration.md`.
- **Sequencing several dispatches:** the harness's job (ADR-0049). Each gated step it takes parks
  through this gate on its own.
- **Who is asked:** the requesting client's routing. Gleipnir routes by its own audiences and
  channels.
- **Holding a gated call open until it is released:** #643.
- **What ADR-0047 cuts, and where each waits:** ADR-0047, *What changes* and its amendment.
- **Residual risk:** the threat model's register, R21 (an answer is only as honest as the client), R23 (an upgraded install keeps its own configuration), R24, R26, R27, R43 and R45 (an answer on a token session proves only
  the session).
- **The Freeze:** a global stop, not a per-request judgement (`freeze.md`).

## Proof

Generated by `make spec-proof` from the tests that name the claim they prove.

<!-- proof:begin -->
| Claim | Proven by | Seam |
|---|---|---|
| AP-1 | `TestGatedDispatchParksAndSendsNothing`, `TestRun_GateIsConsultedAfterAuthorizationAndTheCap` | capability |
| AP-2 | `TestElicit_AskableParkFromMRTRClientGetsAQuestion`, `TestGatedDispatchParksAndSendsNothing`, `TestParkIsAskableOnlyWhenThisCallCreatedIt` | Relay, capability |
| AP-3 | `TestHashPlanChangesWithFanOut`, `TestPark_SummaryShowsTheResolvedCountAndACappedSample`, `TestSummaryNeverUnderstatesBlastRadius` | approval, capability |
| AP-5 | `TestNoRouteWritesConfiguration`, `TestNoToolWritesConfiguration` | API, MCP |
| AP-6 | `TestRun_AnApprovalNeverWaivesAGuardrail`, `TestValidate_GateRuleValuesRefusedNamingField` | capability, relayconfig |
| AP-8 | `TestLoadConfig_MalformedGateRuleRefusesStart`, `TestLoad_VariantSpellingOfRulesKeysRefused`, `TestStart_RefusesMalformedGateRule` | Relay, relayconfig |
| AP-10 | `TestElicitedAnswer_RecordsTheSealedRequestAndTheAssertedResponder`, `TestElicitedAnswer_RefusesRatherThanTruncatesAMalformedResponder`, `TestElicitedAnswer_ResponderOnAnOAuthHumanSessionIsIgnored`, `TestMachineRelayKeepsTheAssertedLane` | MCP, approval |
| AP-11 | `TestAnswerElicited_HumanRequesterConfirmsOwnRequest`, `TestApprovalCallout_MachineCannotSatisfyItsOwnGate`, `TestDecideApproval_TokenCarveOutIsInBandOnly`, `TestDecide_HumanRequesterMayConfirmOwnRequest`, `TestMCPElicitation_ClaudeCodeOnAnOAuthHumanSessionIsTheHumansVerifiedDecision` | Relay, approval, capability |
| AP-12 | `TestAnswerElicited_RecordsAnInBandDecision`, `TestDecideApproval_BodyCannotNameAChannel` | API, capability |
| AP-17 | `TestApprovalCallout_ControlAPIDecidesAnMCPParkedRequest`, `TestDecideApprovalAuditEntryCarriesTheAnswerAndChannel` | Relay, capability |
| AP-18 | `TestApprovalDecisions_ArriveByOnlyTheTwoRoutes` | capability |
| AP-20 | `TestDecisionMustCiteTheRequestsPlanHash`, `TestHashPlanChangesWithAction`, `TestHashPlanChangesWithFanOut` | approval |
| AP-21 | `TestAnsweredRetry_FleetChangedReParksAndAsksAfresh`, `TestRegistryDriftReParksAnApprovedPlan`, `TestSameShapeDifferentPlanStillParks` | Relay, capability |
| AP-22 | `TestHashPlanChangesWithFanOut`, `TestRegistryDriftReParksAnApprovedPlan`, `TestRun_ANodeSwappedForAnotherReParks` | approval, capability |
| AP-25 | `TestRun_ReleasedApprovalPastItsDeadlineParksAfresh` | capability |
| AP-27 | `TestDecideApprovalAuditEntryCarriesTheAnswerAndChannel`, `TestDenialIsTerminalAndAudited` | capability |
| AP-28 | `TestApprovedPlanDispatchesAndBindsTheJob`, `TestDecideApprovalDoesNotDispatch` | capability |
| AP-38 | `TestARefusingEndpointIsSurvivable`, `TestDeliversTheRelayAuthoredNotice`, `TestNotifierFiresOncePerPark`, `TestNotifyParkedDoesNotBlock` | approvalnotify, capability |
| AP-39 | `TestApprovalAudit_ParksAndDecisionsKeepTheTwoLanesApart`, `TestElicitedAnswer_RecordsTheSealedRequestAndTheAssertedResponder`, `TestMachineRelayKeepsTheAssertedLane` | MCP, approval, capability |
| AP-40 | `TestAssertedLaneShapesAgree`, `TestAudit_AttributionRoundTrips`, `TestJob_UnattributedApproverRendersInTheAssertedLane`, `TestTrustChip_AssertedAndVerifiedAreNeverInterchangeable` | Console, auditsink, store |
| AP-41 | `TestRecordCarriesTheApprovalLinkOnEveryKind`, `TestRedriveAuditsPendingObservedNotRequested` | auditsink, capability |
| AP-42 | `TestAnswerElicited_TokenSessionMeetsTheSameRefusals`, `TestDecideApproval_ListedCausesRefuseAndOrdinaryDecisionsDoNot` | capability |
| AP-46 | `TestAnswerElicited_TokenSessionMeetsTheSameRefusals`, `TestDecideApproval_ListedCausesRefuseAndOrdinaryDecisionsDoNot` | capability |
| AP-48 | `TestAnswerElicited_TokenSessionMeetsTheSameRefusals`, `TestApprovalCallout_MachineCannotSatisfyItsOwnGate`, `TestDecideApproval_ListedCausesRefuseAndOrdinaryDecisionsDoNot`, `TestDecideApproval_TokenCarveOutIsInBandOnly`, `TestDecide_MachineAPITokenAnswerIsInBandSelfConfirmation`, `TestDecide_MachineSelfDecisionOnlyInBandForms`, `TestElicitedAnswer_OnAnotherSessionAnUnusableAnswerIsAMachineSelfDecision` | MCP, Relay, approval, capability |
| AP-49 | `TestAnswerElicited_TokenSessionMeetsTheSameRefusals`, `TestDecideApproval_ListedCausesRefuseAndOrdinaryDecisionsDoNot` | capability |
| AP-54 | `TestLoadConfig_MalformedGateRuleRefusesStart`, `TestStart_RefusesMalformedGateRule` | Relay |
| AP-60 | `TestElicit_AskableParkFromMRTRClientGetsAQuestion`, `TestElicit_QuestionCarriesNoContent`, `TestMCPElicitation_ApproveRunsTheJobAndReturnsResults` | MCP, Relay |
| AP-62 | `TestElicit_NonAskableParkRendersPendingApproval`, `TestElicit_UnaskableParkNeverAsks_HandlerSeam`, `TestMCPElicitation_RedriveOfAPendingRequestAsksNobody`, `TestParkIsAskableOnlyWhenThisCallCreatedIt`, `TestPlanPreflightNeverEmitsAQuestion`, `TestRedriveOfAPendingRequestIsNotAskable` | MCP, Relay, capability |
| AP-63 | `TestAnswerElicited_RecordsAnInBandDecision`, `TestAnsweredRetry_ApproveRunsTheJobOnce`, `TestMCPElicitation_ApproveRunsTheJobAndReturnsResults`, `TestMCPElicitation_DecisionIsInBandVerifiedRequesterAssertedApprover` | Relay, capability |
| AP-65 | `TestMCPElicitation_CrossAccountStateIsRefused`, `TestMCPElicitation_CrossRequestStateIsRefused`, `TestMCPElicitation_ExpiredStateIsRefused`, `TestMCPElicitation_TamperedStateIsRefused`, `TestMCPElicitation_WrongCallStateIsRefused` | Relay |
| AP-66 | `TestAnsweredRetry_ApproveRunsTheJobOnce`, `TestAnsweredRetry_FleetChangedReParksAndAsksAfresh`, `TestMCPElicitation_FleetChangedRetryReParks` | Relay |
| AP-67 | `TestAnsweredRetry_BoundJobReAttaches`, `TestMCPElicitation_DuplicateRetryReAttaches`, `TestRun_ReAttachThatCannotBeAuditedReturnsNothing` | Relay, capability |
| AP-68 | `TestAnsweredRetry_DeclineIsTerminalAndDispatchesNothing`, `TestMCPElicitation_DeclineIsTerminalAndAudited` | Relay |
| AP-77 | `TestApprovalRelease_DifferentAccountReAttachesAndRunsNothing`, `TestApprovalRelease_ReDriveOnAnySurfaceReAttaches`, `TestBindJob_BindsOnceAndReportsTheBoundJob`, `TestBindJob_ConcurrentClaimsExactlyOneWins`, `TestJobEngine_RunUsesTheReservedJobID`, `TestMCPElicitation_DuplicateRetryReAttaches`, `TestRun_ConcurrentReDrivesDispatchExactlyOneJob`, `TestRun_DifferentRequesterReAttachesToTheReleasedJob`, `TestRun_ReDriveOfAReleasedApprovalReAttachesAndDispatchesNothing`, `TestRun_ReleasedApprovalPastItsDeadlineParksAfresh`, `TestRun_ReleasedJobStaysBoundWhenTheCallIsCancelledMidDispatch` | Relay, capability, store |
| AP-79 | `TestAnswerElicited_OAuthHumanSessionClearsAnyAssertion`, `TestDecideApproval_InBandHumanWithNoAssertedApproverIsVerified`, `TestElicitedAnswer_FailureAfterAVerifiedDecisionMayHaveBeenRecorded`, `TestElicitedAnswer_OAuthHumanSessionAnswerIsTheHumansVerifiedDecision`, `TestElicitedAnswer_OAuthHumanSessionDeclineIsADenial`, `TestElicitedAnswer_ResponderOnAnOAuthHumanSessionIsIgnored`, `TestElicitedAnswer_TheSessionDecidesWhatAResponderIsFor`, `TestElicitedAnswer_VerifiedFormIgnoresTheDeclaredName`, `TestElicitedAnswer_VerifiedFormMeetsTheSameRefusals`, `TestElicitedResponderRule_TurnsOnTheSession`, `TestMCPElicitation_ClaudeCodeOnAMachineOAuthSessionIsAskedButNeedsAResponder`, `TestMCPElicitation_ClaudeCodeOnAnOAuthHumanSessionIsTheHumansVerifiedDecision`, `TestMCPElicitation_GleipnirOnAnOAuthHumanSessionIsTheHumansVerifiedDecision`, `TestMCPElicitation_HumanAPITokenSessionAnswerIsTheHumansTokenSessionDecision`, `TestMCPElicitation_MachineOAuthSessionNeverTakesTheVerifiedPath`, `TestMCPElicitation_ResponderOnAnOAuthHumanSessionIsIgnored` | MCP, Relay, capability |
| AP-80 | `TestApprovalCallout_OneDecisionEndsTheRequest`, `TestApprovalCallout_TheConsoleHasNoApprovalSurface`, `TestApprovalReader_ReadsOneRecordAndCannotListOrDecide`, `TestConsole_ADecisionPostOnARealSessionFindsNothing`, `TestConsole_HasNoApprovalSurface` | Console, Relay |
| AP-81 | `TestAskableOverlappingRulesNameEveryMatch`, `TestGate_OverlappingRulesShortestTTLWins`, `TestLoad_RuleFieldNamingADecisionTermRefusedNamingField`, `TestParkIsAskableOnlyWhenThisCallCreatedIt`, `TestPlanPreflightNeverEmitsAQuestion`, `TestStart_RefusesMalformedGateRule`, `TestValidate_GateRuleValuesRefusedNamingField` | Relay, approval, capability, relayconfig |
| AP-82 | `TestAnsweredRetry_RefusedStateStaysDecidableByTheRescue`, `TestApprovalCallout_OneDecisionEndsTheRequest`, `TestApprovals_HistoricalQuorumAndAudienceRowsReadBack`, `TestDecideApproval_SecondDecisionReturnsTheCurrentRequest`, `TestDecide_FirstDecisionEndsTheRequest`, `TestRecordDecision_SecondDecisionIsNotPending` | Relay, approval, capability, store |
| AP-83 | `TestApproveRequestIsNotRegistered`, `TestCompositionRoot_RegistersNoDecisionTool`, `TestMCPCannotAcceptAnApprovalDecision`, `TestNoDecisionGuardCatchesAnswerElicitedTakenAsAValue`, `TestNoMCPTextPointsAtApproveRequest` | MCP, Relay |
| AP-84 | `TestApprovalGrant_TheComposedRelayServesNoGrantRoute`, `TestApprovals_NoDispatchConsultsAGrant`, `TestControlAPI_ServesNoApprovalGrantRoute`, `TestMCP_NoToolRequestsAnApprovalGrant`, `TestRun_EveryGatedDispatchParksOnItsOwn`, `TestSink_NoRecordCarriesAGrantLink` | API, MCP, Relay, auditsink, capability |
| AP-85 | `TestAnsweredRetry_ClientThatCannotBeAskedIgnoresRetryFields`, `TestCompositionRoot_ClientThatCannotBeAskedSeesNoChange`, `TestElicit_ElicitedParkEmitsNoTaskEnvelope`, `TestElicit_ElicitedParkEmitsNoTaskEnvelope_E2E`, `TestElicit_NonElicitingClientsRetryFieldsAreIgnored`, `TestElicit_OptionOffChangesNothing`, `TestGolden_CreateForANonCapableClient`, `TestMCPElicitation_ClientThatCannotBeAskedSeesNoChange`, `TestMCPElicitation_ElicitedParkEmitsNoTaskEnvelope`, `TestMCP_NoTasksMethodIsServed`, `TestMCP_TasksDeclaringParkThatAsksNobodyIsPendingApproval`, `TestPendingApproval_TasksDeclaringClientGetsPendingApproval`, `TestTasksMethodsAreNotServed` | MCP, Relay |
| AP-86 | `TestElicit_AnyElicitingClientIsAsked`, `TestElicit_AskedOnElicitationNeverOnTheName`, `TestElicit_ClaudeCodeOnAnAPITokenSessionIsAsked`, `TestElicit_RetryDeclaringAnotherNameIsStillAnAnswer`, `TestElicitedAnswer_OAuthHumanSessionAnswerIsTheHumansVerifiedDecision`, `TestElicitedAnswer_ResponderOnAnOAuthHumanSessionIsIgnored`, `TestElicitedAnswer_TheSessionDecidesWhatAResponderIsFor`, `TestElicitedAnswer_VerifiedFormIgnoresTheDeclaredName`, `TestElicitedAnswer_VerifiedFormMeetsTheSameRefusals`, `TestMCPElicitation_AnyElicitingClientIsAskedOnAnySession`, `TestMCPElicitation_ClaudeCodeOnAMachineOAuthSessionIsAskedButNeedsAResponder`, `TestMCPElicitation_ClaudeCodeOnAnAPITokenSessionIsAskedAndItsAnswerCounts`, `TestMCPElicitation_GleipnirOnAnOAuthHumanSessionIsTheHumansVerifiedDecision`, `TestMCPElicitation_MachineOAuthSessionNeverTakesTheVerifiedPath`, `TestMCPElicitation_SpoofedClientNamesEarnNothingBeyondBeingAsked` | MCP, Relay |
| AP-87 | `TestAnswerElicited_HumanTokenSessionIsTheHumansTokenSessionDecision`, `TestAnswerElicited_MachineTokenSessionIsMachineSelfConfirmation`, `TestAnswerElicited_OtherSessionNeedsAResponder`, `TestDecide_MachineAPITokenAnswerIsInBandSelfConfirmation`, `TestElicitedAnswer_AStrayOnBehalfOfHeaderNeverReachesTheAssertedLane`, `TestElicitedAnswer_OnATokenSessionAnUnusableAnswerIsRefusedAccurately`, `TestElicitedAnswer_OnAnotherSessionAnUnusableAnswerIsAMachineSelfDecision`, `TestElicitedAnswer_TheSessionDecidesWhatAResponderIsFor`, `TestElicitedResponderRule_TurnsOnTheSession`, `TestMCPElicitation_AnUnusableAnswerIsRefusedAndRecordsNothing`, `TestMCPElicitation_ClaudeCodeOnAMachineOAuthSessionIsAskedButNeedsAResponder`, `TestMCPElicitation_ClaudeCodeOnAnAPITokenSessionIsAskedAndItsAnswerCounts`, `TestMCPElicitation_HumanAPITokenSessionAnswerIsTheHumansTokenSessionDecision`, `TestMCPElicitation_MachineAPITokenAnswerIsMachineSelfConfirmation`, `TestMCPElicitation_SpoofedClientNamesEarnNothingBeyondBeingAsked` | MCP, Relay, approval, capability |
| AP-88 | `TestActivity_ApprovalDecisionShowsHowTheDeciderWasIdentified`, `TestAnswerElicited_HumanTokenSessionIsTheHumansTokenSessionDecision`, `TestAnswerElicited_MachineTokenSessionIsMachineSelfConfirmation`, `TestAnswerElicited_RecordsHowTheDeciderWasIdentified`, `TestApprovals_DecisionIdentifiedByRoundTrips`, `TestApprovals_DecisionRendersHowTheDeciderWasIdentified`, `TestApprovals_UnknownIdentifiedByIsAnError`, `TestElicitedAnswer_DecisionOutputNamesHowTheDeciderWasIdentified`, `TestJob_DeciderShowsHowItWasIdentified`, `TestMCPElicitation_HumanAPITokenSessionAnswerIsTheHumansTokenSessionDecision`, `TestMCPElicitation_MachineAPITokenAnswerIsMachineSelfConfirmation` | API, Console, MCP, Relay, capability, store |
| AP-89 | `TestApprovalRulesLoadFromTheConfigurationFile`, `TestDiff_GateRulesChangeAppliedByReload`, `TestFleetRelayTOML_GatesFleetWideMutatesAndRawExec`, `TestLoad_GateRulesOnlyAsArrayTables`, `TestLoad_VariantSpellingOfRulesKeysRefused`, `TestLoad_WhitespaceOnlyRuleNameRefusedWithLine`, `TestReloader_GateRulesReloadWithTheFile`, `TestReloader_NonArrayGateRulesRefusedWithoutPanic` | Relay, relayconfig |
| AP-90 | `TestShippedRelayTOML_GatesEveryMutateAndRawExecNeverARead` | relayconfig |
| AP-92 | `TestApprovals_CreateWritesNoShapeKey`, `TestOpen_LeavesStoredShapeKeysAlone`, `TestSameShapeDifferentPlanStillParks` | capability, store |

Unproven: AP-26, AP-93, AP-94, AP-95.
<!-- proof:end -->

## Retired

- **AP-4** — `2026-10-29` — gate rules as an optional root-owned file; replaced by AP-89.
- **AP-7** — `2026-10-29` — packaging ships no gate rules, so a fresh install is ungated; replaced by AP-90.
- **AP-9**, **AP-13**, **AP-14**, **AP-43**, **AP-44**, **AP-47**, **AP-61**, **AP-69** —
  `2026-10-29` — the confirmation ladder, channel strength, requester exclusion, audience and
  the channel a rule demands, and the questions they gated; replaced by AP-81.
- **AP-45** — `2026-10-29` — the duplicate-decider refusal; replaced by AP-82.
- **AP-73** — `2026-10-29` — a rule requiring two decisions from distinct Accounts; replaced
  by AP-81 and AP-82.
- **AP-78** — `2026-10-28` — a question emitted only to a client Relay recognises by its declared
  name; replaced by AP-86.
- **AP-64** — `2026-10-28` — an answer accepted only with a responder assertion; replaced by AP-87.
- **AP-15** — `2026-10-28` — `approve_request`, the in-band decision tool, removed;
  replaced by AP-83 (ADR-0047).
- **AP-70**, **AP-71**, **AP-91** — `2026-10-28` — the MCP task handle,
  removed; replaced by AP-85 (ADR-0047).
- **AP-23**, **AP-24** — `2026-10-28` — the shape key, removed; replaced by AP-92 (ADR-0047).
- **AP-16**, **AP-19** — `2026-10-18` — the Console's approval surface, removed (ADR-0044).
- **AP-29**, **AP-30**, **AP-31**, **AP-32**, **AP-33**, **AP-34**, **AP-35**, **AP-36**,
  **AP-37**, **AP-50**, **AP-51**, **AP-52**, **AP-53** — `2026-10-28` — approval grants
  removed; replaced by AP-84 (ADR-0047).
- **AP-55**, **AP-72** — `2026-10-27` — retired unbuilt: gate rules move into the Relay
  configuration file instead (ADR-0047; AP-89, AP-90) (#1147).
- **AP-56**, **AP-57** — `2026-10-27` — retired unbuilt: approval grants are cut (ADR-0047;
  AP-84) (#1147).
- **AP-58** — `2026-09-24` — second-person grant issuance, shelved by ADR-0040.
- **AP-59** — `2026-10-18` — bulk decisions, removed with the Console's approval surface.
- **AP-74**, **AP-75**, **AP-76** — `2026-09-25` — strict separation by origin, withdrawn unbuilt.
