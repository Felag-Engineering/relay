# Approval

**Status:** designed, not built, as of `2026-10-27`.
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
| **MCP** | **MRTR elicitation.** A gated `tools/call` answers with an input-required result carrying a Relay-written question; the client puts it to a person and retries the call carrying the answer (*Answering*). **`approve_request`**, the tool by which an AI-agent records a decision itself (AP-15), goes with AP-83. A park rendered as an MCP task handle (AP-71, AP-91) goes with AP-85. |
| **Control API** | `GET /api/v1/approvals`, `GET /api/v1/approvals/{id}`, `POST /api/v1/approvals/{id}/decision`: the rescue, for a client that cannot be asked or a question a restart stranded (AP-80). Specified here, and not featured in getting-started material. The approval-grant routes under `/api/v1/approval-grants` (AP-29 … AP-37) go with AP-84. |
| **Admin Console** | None (AP-80): no queue, no request screen, no decision. It renders what an approval left on other records. |

Server-initiated elicitation is not a surface: MCP's 2026-07-28 revision removed it, and MRTR is
the conformant form (ADR-0029).

## Behaviour

Where a row under *Designed, not built* names a claim below, ADR-0047 cuts that claim, and it
retires when the row lands.

**Where the gate sits**

- **AP-1** The gate is consulted inside the dispatch pipeline, after Selector resolution,
  Relay-side authorization and the blast-radius cap, and before any Task exists.
- **AP-2** A park leaves no Job and no Pending Tasks behind.
- **AP-3** The approver is shown the resolved fan-out: the matched Node count and a capped
  sample of Node IDs. The full resolved set is bound by the plan hash (AP-20).

**Gate rules**

- **AP-4** Gate rules are an optional root-owned file, loaded at Relay startup and re-read on
  every successful configuration reload; when no file is configured nothing is gated.
- **AP-5** No API route and no MCP tool can write gate rules.
- **AP-6** A gate rule only adds a gate; it never waives a guardrail. A rule no decision could
  ever satisfy is refused when the rules load.
- **AP-7** Packaging ships no gate-rule file and configures no path, so a fresh install is
  ungated (threat model R23).
- **AP-8** Gate rules that cannot be loaded refuse Relay startup: the Relay never runs ungated
  because its rules are unreadable or malformed.
- **AP-9** A rule selects a rung of the confirmation ladder: no gate, self-confirmation, or
  second-person, where the rule's audience excludes the requester.
- **AP-13** A decision's channel must be at least as strong as the rule demands, and
  `out-of-band` is the stronger: a rule demanding `in-band` is satisfied by either path, one
  demanding `out-of-band` only by the Control API, and an asserted approver does not upgrade an
  in-band answer.
- **AP-14** A rule that states no channel demands `out-of-band`.

**Answering**

- **AP-15** `approve_request` records an in-band decision from its call: the request ID, the
  plan hash answered, the verdict, an asserted approver of at most 256 bytes with no control
  characters, and an optional reason. An approver outside that bound is refused, never truncated.
  Its approver is an assertion on every session, a human's OAuth session included.
- **AP-17** Every decision records into one decision model, and its audit entry carries the
  answer and the channel.
- **AP-60** A gated dispatch from a client that can be asked is answered with a question carrying
  the Relay-written summary, the request ID and the plan hash, and parks.
- **AP-61** A question is emitted only where an answer from that caller could be accepted: the
  rule's channel is in-band, the rule does not exclude the requester, and its audience admits the
  calling Account. Otherwise nobody is asked.
- **AP-62** A question is emitted only for a park this call created; a re-drive that bounces off
  a request already pending asks nobody.
- **AP-78** A question is emitted only to a client Relay recognises by its declared name:
  `gleipnir` on any session, `claude-code` only on an OAuth session of a human Account. Any
  other client is not asked. The name decides only whether Relay asks, never how an answer is
  accepted.
- **AP-65** The state a client echoes back is sealed and bound to the caller, the request, the
  plan hash and the call; a tampered, cross-request, cross-account, wrong-call or expired one is
  refused.
- **AP-63** An answer on the retried call records a Decision: the channel `in-band`, the
  verified Account whose credential made the call, and the responder assertion as asserted,
  except under AP-79.
- **AP-64** An answer is accepted only when it carries a responder assertion whose gate is
  `permission`, such as `io.gleipnir/responder`, unless AP-79 applies.
- **AP-79** An elicited answer arriving on an OAuth session of a human Account is that human's verified
  decision, whatever the client calls itself: the human is in the verified lane, and any
  responder assertion is ignored.
- **AP-10** A responder assertion is at most 256 bytes with no control characters, and one
  outside that bound is refused, never truncated. It is recorded only as asserted, never as
  something Relay verified; under AP-79 it is not recorded.
- **AP-66** An approving retry re-enters the whole dispatch pipeline, Freeze, resolution,
  authorization, the cap and the plan-hash match, and a changed Node set parks again.
- **AP-67** A retry whose decision already released a Job re-attaches to it and mints no second.
- **AP-68** A denial on the retry is terminal and audited, and nothing is dispatched.
- **AP-69** A rule demanding `out-of-band` yields no answerable question, on any client.
- **AP-70** A park that asks nobody is answered `pending_approval`, unless AP-91 applies.
- **AP-71** A park that asked a question is never rendered as an MCP task handle.
- **AP-91** A park that asked nobody, from a client that declares the MCP Tasks extension, is
  returned as an MCP task handle when Relay minted one for it.
- **AP-80** The Control API decision endpoint decides any parked request, recording the channel
  `out-of-band`. The Admin Console has no approval surface and renders approval records only
  where another record shows them.
- **AP-12** The receiving surface sets a decision's channel; a request body cannot name one.
- **AP-18** A decision arrives by no route but an in-band answer and the Control API decision
  endpoint. Relay integrates no chat or paging system.

**What a decision does**

- **AP-26** A decision is refused for any cause under *Refusals*, and for no other.
- **AP-73** A rule may require two decisions from distinct Accounts. Until that many arrive the
  request stays pending, each decision is its own audit record, and the Control API's read of
  the request shows who has decided.
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
- **AP-23** Each request records a shape key: an address over what was asked that leaves out the
  resolved fan-out and is stable across runs.
- **AP-24** The shape key is never an authorization or release lookup; a dispatch of the same
  shape with a different plan hash parks.
- **AP-25** A parked request expires after an operator-set time, 4 hours by default, and is
  swept; the work must be requested again.

**Approval grants**

- **AP-29** An approval grant covers a Scope: exactly one Account, a risk class, an Operation
  allow-list, a fan-out ceiling and an explicit Raw Exec opt-in, for a time window beside it.
  It covers nothing outside its Scope.
- **AP-30** A Scope may opt in to Raw Exec, and one that does is priced at the `admin` role
  floor.
- **AP-31** A grant's window is capped at 24 hours.
- **AP-32** Issuing a grant is priced by the live gate rules and nothing else.
- **AP-33** A Scope has no Selector-namespace pinning; a stored pinned grant covers nothing.
- **AP-34** A grant request is approved through this gate, and its requester cannot approve it.
- **AP-35** A grant's requirement is the strictest the live gate yields at the Scope's widest
  admissible dispatch, never anything the requester declares.
- **AP-36** A grant's bounds are enforced inside the claiming transaction.
- **AP-37** A grant is consulted only after the gate requires approval, never bypasses the blast
  cap, and an exhausted, revoked or expired grant covers nothing.

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
| **AP-43** | Requester excluded | The rule demands a second person |
| **AP-44** | Not in audience | The decider is outside the rule's audience |
| **AP-45** | Duplicate decider | This Account has already decided this request |
| **AP-46** | Plan hash changed | The cited plan hash is not the request's |
| **AP-47** | Weak channel | The decision's channel is weaker than the rule demands, denials included |
| **AP-48** | Machine self-decision | A machine Account deciding its own request other than by an accepted in-band answer |
| **AP-49** | Role floor | The decider is below the floor the Action needed to be requested |
| **AP-50** | Grant covers nothing gated | A Scope over work that needs no approval |
| **AP-51** | Grant unbounded | A Scope missing any of its bounds |
| **AP-52** | Grant pinned to a namespace | A grant request naming a Selector namespace |
| **AP-53** | Grant window too long | A window over the cap (AP-31) |
| **AP-54** | Approvals unavailable | The gate rules could not be loaded, so the Relay does not start (AP-8) |

## Designed, not built

Each row is part of ADR-0047's cut or its 2026-10-23 amendment, and names the claims it replaces,
where it replaces any.

| Claim | Statement | Milestone |
|---|---|---|
| AP-84 | No surface requests, issues or claims an approval grant. Replaces AP-29 to AP-37 and AP-50 to AP-53 when promoted. | MVP |
| AP-85 | A parked request is never rendered as an MCP task handle: a park that asks nobody is answered `pending_approval`. Replaces AP-70, AP-71 and AP-91 when promoted. | MVP |
| AP-92 | No approval request records a shape key; a request is addressed only by its ID and its plan hash. Replaces AP-23 and AP-24 when promoted. | MVP |
| AP-83 | No MCP tool records a decision; `approve_request` does not exist. Replaces AP-15 when promoted. | MVP |
| AP-81 | A gate rule names what it matches and how long a request it parks lives, and nothing else. A rule naming a count, an audience, a requester exclusion or a channel is refused when the configuration loads, naming the field, and no rule demands a channel. Replaces AP-9, AP-13, AP-14, AP-43, AP-44, AP-47, AP-61, AP-69 and AP-73 when promoted. | MVP |
| AP-82 | A request is ended by its first Decision that no refusal stops: an approving Decision releases it, and a denying one ends it. Replaces AP-45 and AP-73 when promoted. | MVP |
| AP-89 | Gate rules live where `relay-configuration.md` sets, as a section of the Relay configuration file; a configuration with no gate rules gates nothing. Replaces AP-4 when promoted. | MVP |
| AP-86 | Whether Relay asks a client turns on the client advertising elicitation, on any session, never on its declared name. Replaces AP-78 when promoted. | MVP |
| AP-87 | An elicited answer on an API Token session is accepted as that session's Account's decision without a responder assertion. On a human Account's token the human is the decider, recorded as a token-session answer, distinct from an OAuth session's verified decision (AP-79). On a machine Account's token the decision is machine self-confirmation, and any responder assertion is recorded as asserted. On any other session an answer is accepted only when it carries a responder assertion whose gate is `permission`, unless AP-79 applies. Replaces AP-64 when promoted. | MVP |
| AP-88 | Every elicited decision records how its decider was identified: an OAuth session, an API Token session, or a responder assertion, so an auditor can tell them apart (threat model R45). | MVP |
| AP-90 | Every configuration Relay ships, the one the package writes and the example a container install starts from, carries rules that gate every `mutate` and every Raw Exec, so a fresh install is gated; `read` is not. Replaces AP-7 when promoted. | MVP |

## Out of scope

- **The rest of the dispatch pipeline:** `execution.md`.
- **Loading and checking the configuration:** `relay-configuration.md`.
- **Sequencing several dispatches:** the harness's job (ADR-0049). Each gated step it takes parks
  through this gate on its own.
- **Who is asked:** the requesting client's routing. Gleipnir routes by its own audiences and
  channels.
- **Holding a gated call open until it is released:** #643.
- **What ADR-0047 cuts, and where each waits:** ADR-0047, *What changes* and its amendment.
- **Residual risk:** the threat model's register, R18 (overlapping rules union their audiences),
  R21 (an answer is only as honest as the client), R23 (a fresh install gates nothing), R24, R25
  (a grant can cover Raw Exec), R26, R27, R43 and R45 (an answer on a token session proves only
  the session).
- **The Freeze:** a global stop, not a per-request judgement (`freeze.md`).

## Proof

Generated by `make spec-proof` from the tests that name the claim they prove.

<!-- proof:begin -->
| Claim | Proven by | Seam |
|---|---|---|
| AP-2 | `TestElicit_AskableParkFromMRTRClientGetsAQuestion`, `TestParkIsAskableOnlyForAnInBandCreatedParkTheCallerCouldAnswer` | Relay, capability |
| AP-17 | `TestApprovalCallout_ControlAPIDecidesAnMCPParkedRequest` | Relay |
| AP-21 | `TestAnsweredRetry_FleetChangedReParksAndAsksAfresh` | Relay |
| AP-25 | `TestRun_ReleasedApprovalPastItsDeadlineParksAfresh` | capability |
| AP-60 | `TestElicit_AskableParkFromMRTRClientGetsAQuestion`, `TestElicit_QuestionCarriesNoContent`, `TestMCPElicitation_ApproveRunsTheJobAndReturnsResults` | MCP, Relay |
| AP-61 | `TestAudienceThatOmitsTheCallerIsNotAskable`, `TestDemoFleetGateFixture_InBandOpenAudienceRequesterAllowed`, `TestElicit_NonAskableParkRendersPendingApproval`, `TestElicitedAnswer_VerifiedFormMeetsTheSameRefusals`, `TestMCPElicitation_ClaudeCodeHumanAnswerMeetsTheSameRefusals`, `TestMCPElicitation_RequesterExcludedAndAudienceRestrictedNeverAsk`, `TestParkIsAskableOnlyForAnInBandCreatedParkTheCallerCouldAnswer`, `TestPlanPreflightNeverEmitsAQuestion`, `TestRelaytest_ElicitationClientSeesTodaysPendingApproval`, `TestRequesterExcludedParkIsNotAskable` | MCP, Relay, approval, capability |
| AP-62 | `TestElicit_NonAskableParkRendersPendingApproval`, `TestMCPElicitation_OutOfBandRuleNeverAsks`, `TestMCPElicitation_RedriveOfAPendingRequestAsksNobody`, `TestPartialQuorumRedriveIsNotAskable`, `TestPlanPreflightNeverEmitsAQuestion`, `TestRedriveOfAPendingRequestIsNotAskable` | MCP, Relay, capability |
| AP-63 | `TestAnsweredRetry_ApproveRunsTheJobOnce`, `TestMCPElicitation_ApproveRunsTheJobAndReturnsResults`, `TestMCPElicitation_DecisionIsInBandVerifiedRequesterAssertedApprover` | Relay |
| AP-64 | `TestElicitedAnswer_OffAnOAuthHumanSessionOnlyTheNamedFormCounts`, `TestMCPElicitation_AnswerWithoutAResponderIsAMachineSelfDecision`, `TestMCPElicitation_HumanAPITokenSessionStillNeedsAResponder` | MCP, Relay |
| AP-65 | `TestMCPElicitation_CrossAccountStateIsRefused`, `TestMCPElicitation_CrossRequestStateIsRefused`, `TestMCPElicitation_ExpiredStateIsRefused`, `TestMCPElicitation_TamperedStateIsRefused`, `TestMCPElicitation_WrongCallStateIsRefused` | Relay |
| AP-66 | `TestAnsweredRetry_ApproveRunsTheJobOnce`, `TestAnsweredRetry_FleetChangedReParksAndAsksAfresh`, `TestMCPElicitation_FleetChangedRetryReParks` | Relay |
| AP-67 | `TestAnsweredRetry_BoundJobReAttaches`, `TestMCPElicitation_DuplicateRetryReAttaches`, `TestRun_ReAttachThatCannotBeAuditedReturnsNothing` | Relay, capability |
| AP-68 | `TestAnsweredRetry_DeclineIsTerminalAndDispatchesNothing`, `TestMCPElicitation_DeclineIsTerminalAndAudited` | Relay |
| AP-69 | `TestElicit_OutOfBandParkNeverAsks`, `TestElicit_OutOfBandParkNeverAsks_HandlerSeam`, `TestMCPElicitation_OutOfBandRuleNeverAsks`, `TestOutOfBandParkIsNeverAskable`, `TestPlanPreflightNeverEmitsAQuestion` | MCP, Relay, capability |
| AP-70 | `TestAnsweredRetry_ClientThatCannotBeAskedIgnoresRetryFields`, `TestCompositionRoot_ClientThatCannotBeAskedSeesNoChange`, `TestElicit_ClaudeCodeRetryOnAnAPITokenSessionIsAnOrdinaryCall`, `TestElicit_OptionOffChangesNothing`, `TestElicit_UnrecognisedClientsRetryFieldsAreIgnored`, `TestMCPElicitation_ClientThatCannotBeAskedSeesNoChange`, `TestPlanPreflightNeverEmitsAQuestion` | MCP, Relay |
| AP-71 | `TestElicit_ElicitedParkEmitsNoTaskEnvelope`, `TestElicit_ElicitedParkEmitsNoTaskEnvelope_E2E`, `TestMCPElicitation_ElicitedParkEmitsNoTaskEnvelope` | MCP, Relay |
| AP-73 | `TestApprovalCallout_PartialQuorumIsReadFromTheControlAPI` | Relay |
| AP-77 | `TestApprovalRelease_DifferentAccountReAttachesAndRunsNothing`, `TestApprovalRelease_ReDriveOnAnySurfaceReAttaches`, `TestBindJob_BindsOnceAndReportsTheBoundJob`, `TestBindJob_ConcurrentClaimsExactlyOneWins`, `TestJobEngine_RunUsesTheReservedJobID`, `TestMCPElicitation_DuplicateRetryReAttaches`, `TestRun_ConcurrentReDrivesDispatchExactlyOneJob`, `TestRun_DifferentRequesterReAttachesToTheReleasedJob`, `TestRun_ReDriveOfAReleasedApprovalReAttachesAndDispatchesNothing`, `TestRun_ReleasedApprovalPastItsDeadlineParksAfresh`, `TestRun_ReleasedApprovalReAttachesEvenWhenAGrantCoversThePlan`, `TestRun_ReleasedJobStaysBoundWhenTheCallIsCancelledMidDispatch` | Relay, capability, store |
| AP-78 | `TestConnectOptions_ClientNameTravelsInClientInfo`, `TestElicit_ClaudeCodeOnAnAPITokenSessionIsNotAsked`, `TestElicit_UnrecognisedMRTRClientGetsPendingApproval`, `TestElicit_WhoIsAskedByNameAndSession`, `TestElicitedAnswer_OAuthHumanSessionAnswerIsTheHumansVerifiedDecision`, `TestElicitedAnswer_ResponderOnAnOAuthHumanSessionIsIgnored`, `TestElicitedAnswer_VerifiedFormIgnoresTheDeclaredName`, `TestElicitedAnswer_VerifiedFormMeetsTheSameRefusals`, `TestMCPElicitation_ClaudeCodeOnAMachineOAuthSessionIsNotAskedAndNotAccepted`, `TestMCPElicitation_ClaudeCodeOnAnAPITokenSessionIsNotAsked`, `TestMCPElicitation_GleipnirOnAnOAuthHumanSessionIsTheHumansVerifiedDecision`, `TestMCPElicitation_SpoofedClaudeCodeOnANonOAuthSessionEarnsNothing`, `TestMCPElicitation_UnrecognisedMRTRClientGetsPendingApproval` | MCP, Relay, e2e |
| AP-79 | `TestDecideApproval_InBandHumanWithNoAssertedApproverIsVerified`, `TestE2EOAuth_ApproveRequestOnAHumanSessionStillRecordsAnAssertion`, `TestElicitedAnswer_FailureAfterAVerifiedDecisionMayHaveBeenRecorded`, `TestElicitedAnswer_OAuthHumanSessionAnswerIsTheHumansVerifiedDecision`, `TestElicitedAnswer_OAuthHumanSessionDeclineIsADenial`, `TestElicitedAnswer_OffAnOAuthHumanSessionOnlyTheNamedFormCounts`, `TestElicitedAnswer_ResponderOnAnOAuthHumanSessionIsIgnored`, `TestElicitedAnswer_VerifiedFormIgnoresTheDeclaredName`, `TestElicitedAnswer_VerifiedFormMeetsTheSameRefusals`, `TestMCPElicitation_ClaudeCodeHumanAnswerMeetsTheSameRefusals`, `TestMCPElicitation_ClaudeCodeOnAMachineOAuthSessionIsNotAskedAndNotAccepted`, `TestMCPElicitation_ClaudeCodeOnAnOAuthHumanSessionIsTheHumansVerifiedDecision`, `TestMCPElicitation_GleipnirOnAnOAuthHumanSessionIsTheHumansVerifiedDecision`, `TestMCPElicitation_HumanAPITokenSessionStillNeedsAResponder`, `TestMCPElicitation_MachineOAuthSessionNeverTakesTheVerifiedPath`, `TestMCPElicitation_ResponderOnAnOAuthHumanSessionIsIgnored`, `TestMCPElicitation_SpoofedClaudeCodeOnANonOAuthSessionEarnsNothing` | MCP, Relay, capability |
| AP-80 | `TestApprovalCallout_PartialQuorumIsReadFromTheControlAPI`, `TestApprovalCallout_TheConsoleHasNoApprovalSurface`, `TestApprovalReader_ReadsOneRecordAndCannotListOrDecide`, `TestConsole_ADecisionPostOnARealSessionFindsNothing`, `TestConsole_HasNoApprovalSurface` | Console, Relay |

Unproven: AP-1, AP-3, AP-4, AP-5, AP-6, AP-7, AP-8, AP-9, AP-10, AP-11, AP-12, AP-13, AP-14, AP-15, AP-18, AP-20, AP-22, AP-23, AP-24, AP-26, AP-27, AP-28, AP-29, AP-30, AP-31, AP-32, AP-33, AP-34, AP-35, AP-36, AP-37, AP-38, AP-39, AP-40, AP-41, AP-42, AP-43, AP-44, AP-45, AP-46, AP-47, AP-48, AP-49, AP-50, AP-51, AP-52, AP-53, AP-54, AP-91.
<!-- proof:end -->

## Retired

- **AP-16**, **AP-19** — `2026-10-18` — the Console's approval surface, removed (ADR-0044).
- **AP-55**, **AP-72** — `2026-10-27` — retired unbuilt: gate rules move into the Relay
  configuration file instead (ADR-0047; AP-89, AP-90) (#1147).
- **AP-56**, **AP-57** — `2026-10-27` — retired unbuilt: approval grants are cut (ADR-0047;
  AP-84) (#1147).
- **AP-58** — `2026-09-24` — second-person grant issuance, shelved by ADR-0040.
- **AP-59** — `2026-10-18` — bulk decisions, removed with the Console's approval surface.
- **AP-74**, **AP-75**, **AP-76** — `2026-09-25` — strict separation by origin, withdrawn unbuilt.
