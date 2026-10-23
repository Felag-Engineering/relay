# Approval

**Status:** designed, not built, as of `2026-10-23`.
**Claim prefix:** `AP`
**Governed by:** ADR-0047, ADR-0027, ADR-0029, ADR-0049, ADR-0043; invariants 5, 10, 11, 13.

## Purpose

Approval puts one human decision between a request and its execution, for work an operator has
decided is too consequential to run on an AI-agent's say-so alone. Relay's other guardrails
answer "may this caller do this?" in advance; approval asks a person "should this happen now?"
at the moment of the act. Relay writes the question, the requesting client puts it to a person,
and the answer binds to exactly what that person was shown. It is deliberately small: one rule
says what waits, one answer releases or denies it, and Relay does not decide who is asked.

## Surfaces

| Surface | How it is reached |
|---|---|
| **MCP** | **MRTR elicitation.** A gated `tools/call` answers with an input-required result carrying a Relay-written question; the client puts it to a person and retries the call carrying the answer (AP-60 … AP-79). No MCP tool records a decision (AP-83), and a park is never an MCP task handle (AP-85). |
| **Control API** | `GET /api/v1/approvals`, `GET /api/v1/approvals/{id}`, `POST /api/v1/approvals/{id}/decision`: the rescue, for a client that cannot be asked or a question a restart stranded (AP-80). Specified here, and not featured in getting-started material. |
| **Admin Console** | None (AP-80): no queue, no request screen, no decision. It renders what an approval left on other records. |

Server-initiated elicitation is not a surface: the 2026-07-28 protocol removed it, and MRTR is
the conformant form (ADR-0029).

## Behaviour

**Where the gate sits**

- **AP-1** The gate is consulted inside the dispatch pipeline, after Selector resolution,
  Relay-side authorization and the blast-radius cap, and before any Task exists.
- **AP-2** A park leaves no Job and no Pending Tasks behind.
- **AP-3** The approver is shown the resolved fan-out: the matched Node count and a capped
  sample of Node IDs. The full resolved set is bound by the plan hash (AP-20).

**Gate rules**

- **AP-4** Gate rules are a section of the Relay configuration file (`relay-configuration.md`),
  read at startup and on every successful reload; a configuration with no rules gates nothing.
- **AP-5** No API route and no MCP tool can write gate rules.
- **AP-6** A gate rule only adds a gate; it never waives a guardrail.
- **AP-7** The package ships a configuration whose rules gate every `mutate` and every Raw Exec,
  so a fresh install is gated; `read` is not.
- **AP-8** A gate rule that cannot be parsed refuses Relay startup, like any configuration error.
- **AP-81** A gate rule names what it matches and how long a request it parks lives, and nothing
  else. A rule naming a count, an audience, a requester exclusion or a channel is refused when
  the configuration loads, naming the field.

**Answering**

- **AP-60** A gated dispatch from a client that can be asked is answered with a question carrying
  the Relay-written summary, the request ID and the plan hash, and parks.
- **AP-62** A question is emitted only for a park this call created; a re-drive that bounces off
  a request already pending asks nobody.
- **AP-78** A question is emitted only to a client Relay recognises by its declared name:
  `gleipnir` on any session, `claude-code` only on an OAuth session of a human Account. Any
  other client gets `pending_approval`. The name decides only whether Relay asks, never how an
  answer is accepted.
- **AP-65** The state a client echoes back is sealed and bound to the caller, the request, the
  plan and the call; a tampered, cross-request, cross-account, wrong-call or expired one is
  refused.
- **AP-63** An answer on the retried call records a Decision: the channel `in-band`, the
  verified Account whose credential made the call, and the responder identity as an assertion.
- **AP-64** An answer is accepted only when it carries a responder assertion whose gate is
  `permission` (today `io.gleipnir/responder`), unless AP-79 applies.
- **AP-79** An answer arriving on an OAuth session of a human Account is that human's verified
  decision, whatever the client calls itself: the human is in the verified lane, and any
  responder assertion is ignored.
- **AP-10** A responder identity is recorded only as an assertion, never as something Relay
  verified, except under AP-79.
- **AP-66** An approving retry re-enters the whole dispatch pipeline, Freeze, resolution,
  authorization, the cap and the plan-hash match, and a changed Node set parks again.
- **AP-67** A retry whose decision already released a Job re-attaches to it and mints no second.
- **AP-68** A denial on the retry is terminal and audited, and nothing is dispatched.
- **AP-70** A client that cannot be asked gets `pending_approval`; the Control API is its path.
- **AP-80** The Control API decision endpoint decides any parked request on a per-person or
  machine Account, recording the channel `out-of-band`. The Admin Console has no approval
  surface and renders approval records only where another record shows them.
- **AP-12** The receiving surface sets a decision's channel; a request body cannot name one.
- **AP-18** A decision arrives by no route but these two. Relay integrates no chat or paging
  system.

**What a decision does**

- **AP-82** A request is ended by its first decision that clears AP-42, AP-46, AP-48 and AP-49:
  an approval releases it, and a denial ends it.
- **AP-27** A denial is terminal, and audited as fully as a release.
- **AP-11** A machine Account cannot decide its own request on its own authority. The one
  exception is an elicited answer accepted under AP-64, which counts as self-confirmation.
- **AP-28** Deciding does not dispatch; a released request proceeds when it is re-driven.
- **AP-77** An approval releases one execution. A released request is bound to exactly one Job,
  the binding survives the requesting call ending, and any later dispatch whose plan hash
  matches re-attaches to that Job until the approval's deadline. After it, the plan parks
  afresh.
- **AP-20** An approval binds to a plan hash over the rendered preflight: the Operation, its
  arguments and the resolved fan-out.
- **AP-21** A dispatch whose plan no longer matches parks again rather than running.
- **AP-22** The binding is by identity, never by count: any Node not in the approved set parks.
- **AP-25** A parked request expires after an operator-set time, 4 hours by default, and is
  swept; the work must be requested again.

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
| **AP-46** | Plan changed | The cited plan hash is not the request's |
| **AP-48** | Machine self-decision | A machine Account deciding its own request other than under AP-64 |
| **AP-49** | Role floor | The decider is below the floor the Action needed to be requested |
| **AP-54** | Approvals unavailable | The configuration's gate rules could not be parsed |
| **AP-83** | No decision tool | No MCP tool records a decision; `approve_request` does not exist |
| **AP-84** | No approval grants | No surface requests, issues or claims an approval grant |
| **AP-85** | No task handle | A parked request is never rendered as an MCP task handle |

## Designed, not built

Owner decision of 2026-10-23 (ADR-0047, amended): ordinary clients answer approvals on an
API-token session, so the MVP needs no identity provider. When AP-86 and AP-87 are promoted,
AP-10 and AP-11 read them alongside AP-79 and AP-64.

| Claim | Statement | Milestone |
|---|---|---|
| AP-86 | A question is emitted to any client that advertises elicitation, on any session. The declared name no longer decides whether Relay asks. Replaces AP-78 when promoted. | MVP |
| AP-87 | An elicited answer on an API-token session is accepted as that session's Account's decision without a responder assertion. On a human Account's token the human is the decider, recorded as a token-session answer, distinct from the verified OAuth lane (AP-79). On a machine Account's token the decision is machine self-confirmation, and any responder assertion is recorded as asserted. Replaces AP-64 when promoted. | MVP |
| AP-88 | Every elicited decision records how its decider was identified: an OAuth session, an API-token session, or a responder assertion, so an auditor can tell them apart (threat model R45). | MVP |

## Out of scope

- **Where the gate sits, and what a park leaves behind:** `execution.md`.
- **Sequencing several dispatches:** the harness's job (ADR-0049). Each gated step it takes parks
  through this gate on its own.
- **Who is asked:** the requesting client's routing. Gleipnir routes by its own audiences and
  channels.
- **Future work** waits in the private roadmap, in its Relay folder: more than one approver,
  a Relay-held audience and approval grants; a channel Relay verifies; editing rules in the
  Console; a diff against the last similar approval, with the shape key; asking more clients and
  always-on agents; MCP Tasks for long-running Jobs; an approval page the person signs in to
  (`roadmap: relay/approval-by-link`); OAuth tested against the common identity providers
  (`roadmap: relay/oauth-against-common-providers`).
- **Residual risk:** the threat model's register, R21 (an answer is only as honest as the
  client), R23, R24, R26, R27, R43 and R45 (an answer on a token session proves only the session).
- **The Freeze:** a global stop, not a per-request judgement (`freeze.md`).

## Proof

Generated by `make spec-proof` from the tests that name the claim they prove.

<!-- proof:begin -->
| Claim | Proven by | Seam |
|---|---|---|
| AP-2 | `TestElicit_AskableParkFromMRTRClientGetsAQuestion`, `TestParkIsAskableOnlyForAnInBandCreatedParkTheCallerCouldAnswer` | Relay, capability |
| AP-21 | `TestAnsweredRetry_FleetChangedReParksAndAsksAfresh` | Relay |
| AP-25 | `TestRun_ReleasedApprovalPastItsDeadlineParksAfresh` | capability |
| AP-60 | `TestElicit_AskableParkFromMRTRClientGetsAQuestion`, `TestElicit_QuestionCarriesNoContent`, `TestMCPElicitation_ApproveRunsTheJobAndReturnsResults` | MCP, Relay |
| AP-62 | `TestElicit_NonAskableParkRendersPendingApproval`, `TestMCPElicitation_OutOfBandRuleNeverAsks`, `TestMCPElicitation_RedriveOfAPendingRequestAsksNobody`, `TestPartialQuorumRedriveIsNotAskable`, `TestPlanPreflightNeverEmitsAQuestion`, `TestRedriveOfAPendingRequestIsNotAskable` | MCP, Relay, capability |
| AP-63 | `TestAnsweredRetry_ApproveRunsTheJobOnce`, `TestMCPElicitation_ApproveRunsTheJobAndReturnsResults`, `TestMCPElicitation_DecisionIsInBandVerifiedRequesterAssertedApprover` | Relay |
| AP-64 | `TestElicitedAnswer_OffAnOAuthHumanSessionOnlyTheNamedFormCounts`, `TestMCPElicitation_AnswerWithoutAResponderIsAMachineSelfDecision`, `TestMCPElicitation_HumanAPITokenSessionStillNeedsAResponder` | MCP, Relay |
| AP-65 | `TestMCPElicitation_CrossAccountStateIsRefused`, `TestMCPElicitation_CrossRequestStateIsRefused`, `TestMCPElicitation_ExpiredStateIsRefused`, `TestMCPElicitation_TamperedStateIsRefused`, `TestMCPElicitation_WrongCallStateIsRefused` | Relay |
| AP-66 | `TestAnsweredRetry_ApproveRunsTheJobOnce`, `TestAnsweredRetry_FleetChangedReParksAndAsksAfresh`, `TestMCPElicitation_FleetChangedRetryReParks` | Relay |
| AP-67 | `TestAnsweredRetry_BoundJobReAttaches`, `TestMCPElicitation_DuplicateRetryReAttaches`, `TestRun_ReAttachThatCannotBeAuditedReturnsNothing` | Relay, capability |
| AP-68 | `TestAnsweredRetry_DeclineIsTerminalAndDispatchesNothing`, `TestMCPElicitation_DeclineIsTerminalAndAudited` | Relay |
| AP-70 | `TestAnsweredRetry_ClientThatCannotBeAskedIgnoresRetryFields`, `TestCompositionRoot_ClientThatCannotBeAskedSeesNoChange`, `TestElicit_ClaudeCodeRetryOnAnAPITokenSessionIsAnOrdinaryCall`, `TestElicit_OptionOffChangesNothing`, `TestElicit_UnrecognisedClientsRetryFieldsAreIgnored`, `TestMCPElicitation_ClientThatCannotBeAskedSeesNoChange`, `TestPlanPreflightNeverEmitsAQuestion` | MCP, Relay |
| AP-77 | `TestApprovalRelease_DifferentAccountReAttachesAndRunsNothing`, `TestApprovalRelease_ReDriveOnAnySurfaceReAttaches`, `TestBindJob_BindsOnceAndReportsTheBoundJob`, `TestBindJob_ConcurrentClaimsExactlyOneWins`, `TestJobEngine_RunUsesTheReservedJobID`, `TestMCPElicitation_DuplicateRetryReAttaches`, `TestRun_ConcurrentReDrivesDispatchExactlyOneJob`, `TestRun_DifferentRequesterReAttachesToTheReleasedJob`, `TestRun_ReDriveOfAReleasedApprovalReAttachesAndDispatchesNothing`, `TestRun_ReleasedApprovalPastItsDeadlineParksAfresh`, `TestRun_ReleasedApprovalReAttachesEvenWhenAGrantCoversThePlan`, `TestRun_ReleasedJobStaysBoundWhenTheCallIsCancelledMidDispatch` | Relay, capability, store |
| AP-78 | `TestConnectOptions_ClientNameTravelsInClientInfo`, `TestElicit_ClaudeCodeOnAnAPITokenSessionIsNotAsked`, `TestElicit_UnrecognisedMRTRClientGetsPendingApproval`, `TestElicit_WhoIsAskedByNameAndSession`, `TestElicitedAnswer_OAuthHumanSessionAnswerIsTheHumansVerifiedDecision`, `TestElicitedAnswer_ResponderOnAnOAuthHumanSessionIsIgnored`, `TestElicitedAnswer_VerifiedFormIgnoresTheDeclaredName`, `TestElicitedAnswer_VerifiedFormMeetsTheSameRefusals`, `TestMCPElicitation_ClaudeCodeOnAMachineOAuthSessionIsNotAskedAndNotAccepted`, `TestMCPElicitation_ClaudeCodeOnAnAPITokenSessionIsNotAsked`, `TestMCPElicitation_GleipnirOnAnOAuthHumanSessionIsTheHumansVerifiedDecision`, `TestMCPElicitation_SpoofedClaudeCodeOnANonOAuthSessionEarnsNothing`, `TestMCPElicitation_UnrecognisedMRTRClientGetsPendingApproval` | MCP, Relay, e2e |
| AP-79 | `TestDecideApproval_InBandHumanWithNoAssertedApproverIsVerified`, `TestE2EOAuth_ApproveRequestOnAHumanSessionStillRecordsAnAssertion`, `TestElicitedAnswer_FailureAfterAVerifiedDecisionMayHaveBeenRecorded`, `TestElicitedAnswer_OAuthHumanSessionAnswerIsTheHumansVerifiedDecision`, `TestElicitedAnswer_OAuthHumanSessionDeclineIsADenial`, `TestElicitedAnswer_OffAnOAuthHumanSessionOnlyTheNamedFormCounts`, `TestElicitedAnswer_ResponderOnAnOAuthHumanSessionIsIgnored`, `TestElicitedAnswer_VerifiedFormIgnoresTheDeclaredName`, `TestElicitedAnswer_VerifiedFormMeetsTheSameRefusals`, `TestMCPElicitation_ClaudeCodeHumanAnswerMeetsTheSameRefusals`, `TestMCPElicitation_ClaudeCodeOnAMachineOAuthSessionIsNotAskedAndNotAccepted`, `TestMCPElicitation_ClaudeCodeOnAnOAuthHumanSessionIsTheHumansVerifiedDecision`, `TestMCPElicitation_GleipnirOnAnOAuthHumanSessionIsTheHumansVerifiedDecision`, `TestMCPElicitation_HumanAPITokenSessionStillNeedsAResponder`, `TestMCPElicitation_MachineOAuthSessionNeverTakesTheVerifiedPath`, `TestMCPElicitation_ResponderOnAnOAuthHumanSessionIsIgnored`, `TestMCPElicitation_SpoofedClaudeCodeOnANonOAuthSessionEarnsNothing` | MCP, Relay, capability |
| AP-80 | `TestApprovalCallout_PartialQuorumIsReadFromTheControlAPI`, `TestApprovalCallout_TheConsoleHasNoApprovalSurface`, `TestApprovalReader_ReadsOneRecordAndCannotListOrDecide`, `TestConsole_ADecisionPostOnARealSessionFindsNothing`, `TestConsole_HasNoApprovalSurface` | Console, Relay |

Unproven: AP-1, AP-3, AP-4, AP-5, AP-6, AP-7, AP-8, AP-10, AP-11, AP-12, AP-18, AP-20, AP-22, AP-27, AP-28, AP-38, AP-39, AP-40, AP-41, AP-42, AP-46, AP-48, AP-49, AP-54, AP-81, AP-82, AP-83, AP-84, AP-85.
<!-- proof:end -->

## Retired

- **AP-9**, **AP-13**, **AP-14**, **AP-17**, **AP-26**, **AP-43**, **AP-44**, **AP-45**,
  **AP-47**, **AP-61**, **AP-69**, **AP-73** — `2026-10-22` — the confirmation ladder's
  second-person rung, channel strength, quorum, audiences and requester exclusion are cut
  (ADR-0047; AP-81, AP-82).
- **AP-15** — `2026-10-22` — `approve_request` is retired (ADR-0047; AP-83).
- **AP-23**, **AP-24** — `2026-10-22` — the shape key is cut (ADR-0047).
- **AP-55**, **AP-72** — `2026-10-22` — retired unbuilt: rules stay in the configuration file, and
  the package ships the default (ADR-0047; AP-4, AP-7).
- **AP-71** — `2026-10-22` — the MCP Tasks shim is removed (ADR-0047; AP-85).
- **AP-29**, **AP-30**, **AP-31**, **AP-32**, **AP-33**, **AP-34**, **AP-35**, **AP-36**,
  **AP-37**, **AP-50**, **AP-51**, **AP-52**, **AP-53**, **AP-56**, **AP-57** — `2026-10-22` —
  approval grants are cut (ADR-0047; AP-84).
- **AP-58** — `2026-09-24` — second-person grant issuance, shelved by ADR-0040.
- **AP-74**, **AP-75**, **AP-76** — `2026-09-25` — strict separation by origin, withdrawn unbuilt.
- **AP-59** — `2026-10-18` — bulk decisions, removed with the Console's approval surface.
- **AP-16**, **AP-19** — `2026-10-18` — the Console's approval surface, removed (ADR-0044).
