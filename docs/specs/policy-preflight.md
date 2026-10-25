# Policy preflight

**Status:** designed, not built, as of `2026-10-19`.
**Claim prefix:** `PF`

> **The capability is Policy preflight; the option is still spelled `plan` on the wire.**
> ADR-0038 renamed the capability, a rename ADR-0049 keeps; **Plan** is Gleipnir's word for a
> series of tool calls. Every decision in ADR-0011 stands. The option rename is **PF-19** under
> *Designed, not built*; until it lands, every surface below takes `plan`, and this spec says so
> wherever it names the option.

## Purpose

Policy preflight answers *"what would happen if I ran this?"* without running it. A caller supplies
the same Operation and the same Selector it would dispatch, and gets back a per-Node verdict —
allow, deny, unsupported, or unknown — with the rule that decided each deny.

It exists so that the preview and the execution cannot disagree. A preflight that guesses is
worse than useless once a caller trusts it, so the verdicts come from **the same engine that
will decide at execution time**, asked the same question, live.

That makes preflight the mechanism behind two product promises: preflight-before-apply as a
guardrail, opt-in on MCP and the Control API, and denials that teach: an AI-agent told which
rule says no does not need to discover Policy by tripping over it.

## Surfaces

| Surface | How the capability is reached |
|---|---|
| **MCP** | `plan: true` on `run_operation` and `raw_exec`. The result carries the per-Node verdicts, the would-be fan-out, and any would-be rejection (frozen, over cap, no Nodes matched) as data. |
| **Control API** | `"plan": true` on `POST /api/v1/operations` and `POST /api/v1/raw-exec`; same body, same result shape. |
| **Admin Console** | Renders existing preflight audit records on the Activity screen. Performs no preflight: the Console does not execute (ADR-0052). The Console's word for it is **Preflight** (#575). |

The preview and the act are the same request with one flag (PF-1), so a caller cannot preflight
one thing and apply another by reaching a different endpoint.

## Behaviour

### One flag on the executing call

- **PF-1** A preflight is the `plan` option on the calls that would otherwise execute —
  `run_operation` and `raw_exec` over MCP, `POST /api/v1/operations` and `POST /api/v1/raw-exec`
  on the Control API — and no surface exposes a separate preflight tool or route.

### It is the dispatch pipeline, minus the dispatch

- **PF-2** A preflight resolves the same Selector and runs the same Relay-side authorization and
  the same blast-cap arithmetic as a real dispatch, then sends each matched, connected daemon a
  read-only `PolicyQuery` instead of a Task. (One divergence is open: an empty Selector is not
  refused on this path today — see *Open questions*.)

Seven differences from execution, each deliberate:

- **PF-3** **Freeze is advisory, never a gate.** A frozen Relay refuses all real dispatch and still
  answers preflights; the response reports that the Relay is frozen, and the verdicts still come
  back. This is the one Freeze exemption.
- **PF-4** **The blast cap is reported, never enforced as an error.** An over-cap preflight returns
  would-be-rejected data — the matched count, the cap, and the risk class — with no error, and
  queries **nothing**: a real dispatch would touch no Node over cap, so neither does the preflight.
- **PF-5** **A Selector matching no Nodes is reported, not refused.** The preflight returns
  would-be-rejected with `no_nodes_matched` and no error, where the same real run is refused.
- **PF-6** **A disconnected Node yields `unknown` (offline) and is never queried.**
- **PF-7** **The Relay never computes a verdict.** Every `allow` and `deny` is the daemon's live
  engine's answer. Every `unsupported` is the daemon's answer, except that for a Template
  Operation a matched Node that does not report the Template is excluded by the Relay and never
  queried, exactly as a real dispatch excludes it (ADR-0042). The Relay consults no Policy view
  to produce any verdict, and consults its cached Template vocabulary only to decide a Template
  Operation's fan-out and risk class — never to produce an `allow` or a `deny` (invariant 12).
  `unknown` and that exclusion are the only Relay-side conclusions: `unknown` says exactly that
  the Relay could not ask — offline, or the query failed — and the exclusion that the Relay will
  not send this Node the Template at all. *(Amended 2026-10-02 for ADR-0042: Template
  exclusion.)*
- **PF-8** **A preflight creates nothing.** No Job, no Task, no dedup entry on the daemon. It is
  audited under its own kind (`plan`), never as a dispatch.
- **PF-23** **The approval gate is never reached.** A preflight of an Action a Gate rule would
  park is answered like any other: it consults no gate rule, parks nothing, and its response does
  not say whether a real run would require approval. The gate is discovered on apply — a
  deliberate choice (owner, `2026-09-20`), so that approval stays entirely out of this capability.

### The query is a different message, not a flag

- **PF-9** On the wire the preflight is a distinct read-only query/verdict pair (`PolicyQuery`,
  `PolicyVerdict`), each its own message; the query carries no Task ID, and the Task message
  carries no preview flag. A flag means one dropped or defaulted bit turns a preview into real
  execution; a separate message type **has no execution code path at all.**

As with the unexported dispatch constructor in `execution.md`, the dangerous thing is
structurally unreachable rather than conditionally skipped.

### The four verdicts, and why they are four

| Verdict | Meaning |
|---|---|
| `allow` | The Node's live Policy engine would permit it |
| `deny` | The Node's Policy decided against it — carries the deciding rule |
| `unsupported` | The Operation is not in that Node's vocabulary, so its Policy was never asked |
| `unknown` | The Relay could not ask — the Node is matched but disconnected, or the query itself failed |

- **PF-10** A preflight yields exactly these four verdicts per Node, and `deny` carries the
  deciding rule. (Quarantine, cut from the MVP, would add a fifth, `quarantined`, never
  queried; these four are what a preflight yields — see *Out of scope*.)
- **PF-22** `unknown` is the zero value of the Relay's verdict — a verdict never obtained reads
  as "not known", never as a fabricated allow — and is never a wire value: the daemon only ever
  answers allow, deny or unsupported.
- **PF-11** `unsupported` is answered by the daemon whose vocabulary lacks the Operation, after
  being queried — or, for a Template Operation, by the Relay without querying, for a matched
  Node that does not report the Template or has reported no vocabulary at all (ADR-0042).
  Either way a real dispatch to that Node reports `unsupported` with the same explanation.
  *(Amended 2026-10-02 for ADR-0042: the Relay-excluded form.)*

The verdicts stay distinct because each calls for a different response: a denial is a Policy
decision to argue with, an unsupported Operation is a vocabulary gap to fill with a Template,
and an unknown is a Node to go look at.

### Preflight/apply parity

- **PF-12** On an unchanged fleet, a preflight's verdicts and a real run's outcomes agree: same
  Selector, same authorization, same cap arithmetic, same engine answering. Divergence is a
  defect, not a caveat, and it is asserted end to end.
- **PF-17** Parity is a point-in-time property. Nothing re-checks that the fleet did not move
  between a preflight and an ungated apply; for gated work the plan hash catches drift
  (`approval.md`). See *Accepted residual risk*.

### Outdated daemons and Raw Exec

- **PF-14** A Node running a daemon below the minimum version still gets a real verdict from a
  preflight, with outdated reported advisorily; the same real dispatch refuses the Task before
  sending it (`execution.md`, `node-connection.md`).
- **PF-15** A Raw Exec preflight carries the argv to the daemon verbatim — no splitting, no
  normalisation on the Relay.
- **PF-16** A Raw Exec preflight is priced at the `mutate` class, so it reports against the mutate
  cap (invariant 13).

## Refusals

A preflight refuses in fewer cases than a dispatch, and the difference is the point.

| Condition | A real dispatch | A preflight |
|---|---|---|
| Frozen | Refused | **Answered** — frozen state reported advisorily (PF-3) |
| Over the blast cap | Refused | **Answered** — would-be-rejected with count, cap and class (PF-4) |
| No Nodes matched | Refused | **Answered** — would-be-rejected with `no_nodes_matched` (PF-5) |
| Requires approval | Parked | **Answered** — the gate is not consulted and not reported (PF-23) |
| Unauthorized | Refused | Refused, audited, no verdicts (PF-18) |
| Unknown argument name | Refused | Refused before any Node is queried (PF-13) |
| Node offline | Per-Node `unreachable` | Per-Node `unknown` (PF-6) |
| Outdated daemon | Task refused before sending | **Answered** — a real verdict, outdated advisory (PF-14) |

- **PF-13** A call naming an argument the Operation does not declare is refused on the Relay
  before any Node is queried. Argument *values* are validated by the daemon's engine, so an
  ill-formed value surfaces as that Node's verdict, not as a Relay refusal.
- **PF-18** A caller not authorized to dispatch is not authorized to preflight: the preflight is
  refused, audited as a refusal, and returns no verdicts — an unauthorized caller learns no
  per-Node deciding rule.

## Governing ADRs and invariants

- **Invariant 12** (ADR-0011) — the load-bearing one. Policy is evaluated **only** by the
  daemon's live engine, including hypotheticals. The Relay never computes a verdict (PF-7), and a
  matched-but-disconnected Node yields `unknown` rather than a guess from cached state (PF-6).
- **ADR-0049** — the name Policy preflight, and the wire option's rename to `preflight` (PF-19),
  because "plan" is Gleipnir's word for a series of tool calls.
- **Invariant 1** — a preflight carries the same typed Operation or verbatim argv as the dispatch
  would (PF-15); the three tiers are unchanged by previewing.
- **Invariant 5** — the cap is computed the same way, then reported instead of enforced (PF-4).
- **Invariant 10** — every adapter reaches this capability through the capability layer. The
  Console does not execute (ADR-0052); where a Console executes, it preflights before every
  apply, and a `mutate` apply is additionally step-up-gated.
- **Invariant 13** — the risk class is declared contract and selects which cap the preflight
  reports against (PF-16). *(Invariant 13 amended 2026-10-02, ADR-0042: a Template Operation's
  class is Node-reported, and a dispatch takes the most restrictive class the Nodes it reaches
  report.)*
- **ADR-0013** — Freeze halts dispatch and deliberately does not halt preflights (PF-3).
- **ADR-0021** — the per-Node vocabulary, which is why `unsupported` is a verdict (PF-11).
- **ADR-0042** — how a Template Operation's fan-out and risk class are decided over the Nodes that
  report it; why a preflight excludes a Node that does not report the Template rather than
  querying it, and reads the cached vocabulary to do so (PF-7, PF-11).

## Seams and proof

The Relay-side half lives in the capability layer beside dispatch and shares its seams; the query
goes out over the same `Conduit` that sends Tasks, through a method that carries no Task ID.
It is tested at the capability seam and again through MCP, because parity is a claim about what
a *caller* sees. The Relay's wire conversion (argv and query fields round-tripping into the
proto message) is tested beside the dispatch router, and the daemon half in its dispatch module.
`make verify` covers every row below.

Test names still say `Plan` (`TestMCP_Plan_PlanVsRealRunParity` and its neighbours); the PR
that lands PF-19 renames them.

### What proves each claim

| Claim | Proven by | Seam |
|---|---|---|
| PF-1 | `TestNoPreflightToolOrMethodIsRegistered`, `TestNoSeparatePreflightRouteIsServed`, `TestRunOperationAndRawExecShareOnePlanFlag`, `TestConsoleServesNoSeparatePreflightRoute` | MCP; Control API (over its route table only, not the composed mux); Console |
| PF-2 | `TestPlanReturnsPerNodeVerdictsNoJobOrTask`, `TestMCP_Plan_PlanVsRealRunParity` | capability, MCP |
| PF-3 | `TestPlanFrozenReportsAdvisoryWhileRunRefuses`, `TestMCP_RunOperation_Plan_FrozenReportsWhileRealRunErrors` | capability, MCP |
| PF-4 | `TestPlanOverCapReportsNotErrors`, `TestMCP_RunOperation_Plan_OverCap_ReportsNotErrors` | capability, MCP |
| PF-5 | `TestPlanZeroMatchReportsNoNodesMatchedWhileRunRefuses`, `TestMCP_Plan_ZeroMatchReportsWhatARealRunRefuses` | capability, MCP |
| PF-6 | `TestPlanOfflineNodeIsUnknownNeverQueried`, `TestMCP_RunOperation_Plan_OfflineIsUnknown` | capability, MCP |
| PF-7 | `TestPreflightNeverConsultsCachedPolicyOrVocabulary` (behavioural, Native Operation: zero cache reads, with an armed control showing the cache spies are wired), `TestPreflightTemplateExclusionNeverDecidesAVerdict` (behavioural, Template Operation: the vocabulary decides only exclusion; every queried Node's verdict is the daemon's even where the cache disagrees; the Policy view is never read), `TestCachedPolicyAndVocabularyReachOnlyTheDisplayReadLane` (structural: the two cached sources reach only the display read lane and, for the vocabulary, `template.go` — not a guard against a future cached source) | capability |
| PF-8 | `TestPlanReturnsPerNodeVerdictsNoJobOrTask`, `TestMCP_RunOperation_Plan_VerdictsNoExecution`, `TestMCP_RunOperation_Plan_AuditedAsPlanNoJobOrTask`, `policy_query_spawns_no_process_and_records_no_dedup` | capability, MCP, daemon |
| PF-9 | `TestPolicyQuery_CarriesNoTaskID`, `TestWireCarriesNoCallerIdentity` (exact field sets of `PolicyQuery`, `Operation` and `RawExec`), `TestTaskRequest_CarriesNoPreviewFlag` (second half: `TaskRequest`'s field set and a nested walk that skips enums) | compile-time |
| PF-10 | `TestPlanReportsUnsupportedDistinctFromDeny`, `TestPlanReturnsPerNodeVerdictsNoJobOrTask` (asserts the deny verdict's `DecidingRule == "deny-rm-rf"`, proving the deciding-rule half), `TestCrossBinary_PreflightDenyCarriesTheRuleReferencePolicyExplainPrints` (real binaries: a deny's deciding rule, pass and rule reference equal what `policy explain` prints for the same question) | capability, cross-binary |
| PF-11 | `plan_and_apply_agree_on_unsupported` (daemon-answered form); `TestPreflightTemplateExclusionNeverDecidesAVerdict`, `TestRun_TemplateExcludesNonReportingNodesAndNeverSendsThem` (Relay-excluded form: the same reason on the verdict and the Task), `TestTemplateDispatchE2E_RunOperationByName` (both halves through MCP against real daemons) | daemon, capability, MCP |
| PF-12 | `TestMCP_Plan_PlanVsRealRunParity` | MCP |
| PF-13 | `TestBuildOperationAction_UnknownArgOnAValidCallIsRejected` (name half); value half, three independent links on different Operations rather than one chain: `TestPreflightCarriesAnIllFormedArgumentValueToTheDaemon` (Relay passes the value through unaltered), `TestBuildOperationAction_IllFormedArgValueIsNotRefused` (MCP), `plan_and_apply_agree_on_a_non_canonical_template_path` (daemon) | MCP, capability, daemon |
| PF-14 | `TestPlanOutdatedNodeGetsRealVerdictAdvisoryOnly`, `TestMCP_RunOperation_Plan_OutdatedAdvisory` | capability, MCP |
| PF-15 | `TestPolicyQuery_RawExecRoundTrip` | Relay wire conversion |
| PF-16 | `TestMCP_RawExec_Plan_ArgvVerbatimMutateClass` | MCP |
| PF-18 | `TestPlanAuthzDeniedRecordsRefusalNoVerdicts` | capability |
| PF-22 | `TestVerdictZeroValueIsUnknownNeverAllow` (zero-value half), `TestPolicyVerdict_CannotExpressUnknown` (wire half: `PolicyVerdict`'s field set and a nested walk that skips enums, plus the exact value names of the two enums `PolicyVerdict` carries, which the walk does not reach) | capability, compile-time |
| PF-23 | `TestPreflightNeverConsultsTheApprovalGate` (behavioural, with an armed control: the same call through a real run parks), `TestPreflightResultCarriesNoApprovalField` (response half, on the result's field sets, which now include the display-only pass and rule-reference fields on `NodeVerdict`; the surfaces rest on invariant 10) | capability |

Claims with **no row**, and so nothing checking them:

- **PF-17** — a property of the design, not a test target.

### Performance

| Characteristic | Contract | Measured by |
|---|---|---|
| Query fan-out | One query per matched, connected Node — sequential, like dispatch | *(none)* |
| Over-cap preflight | Queries **nothing**; reports the count and returns | *(none)* |
| Offline Nodes | Never queried; resolved to `unknown` without a round trip | *(none)* |

There are no benchmarks in this repository. A preflight at the read cap costs the same
sequential round trips as a dispatch — cheap enough that a caller should always preflight.

## Designed, not built

| Claim | Statement | Milestone |
|---|---|---|
| PF-19 | The request option is spelled `preflight` on MCP and the Control API; `plan` is no longer accepted; the audit kind and the test names follow. | After MVP |
| PF-20 | A `deny` verdict carries a reason kind beside the deciding rule: `no_allow` (nothing permitted it) or `denied` (a deny rule vetoed it), with the same two kinds a real dispatch reports (`policy.md`). | After MVP |

## Out of scope

- **Dispatch, the cap's enforcement, and at-most-once** — `execution.md`.
- **Policy itself** — the rules, their syntax, and how the daemon evaluates them. The Relay reads
  Policy and may never write it (invariant 2); what a rule *means* is the daemon's (`policy.md`).
- **Sequencing several dispatches** — the harness's job (ADR-0049). A harness may preflight each
  step it intends before taking any; that is this capability used one dispatch at a time.
- **The plan hash and approval binding** — `approval.md`. An approval commits to a content
  address for one gated dispatch (ADR-0027 decision 8), never over a preview; minting that address
  is not this capability.
- **Console execution** — cut (ADR-0052; roadmap: relay/console-execution-for-skills). The
  Console renders preflight records and performs none.
- **Quarantine** — cut from the MVP (roadmap: relay/quarantine). There is no quarantined Node
  state on the preflight path, so PF-10's four verdicts are the whole set.
- **Shadow mode** — a standing per-Account setting converting every mutate into a preflight is a
  candidate idea, not a commitment, and does not exist.

## Accepted residual risk

- **Preflight/apply parity holds on an unchanged fleet only (PF-17).** For ungated work nothing
  re-checks that the fleet did not move between the preview and the act; a caller could
  reasonably believe otherwise. Accepted by the owner on `2026-09-20`: the compensating control
  for gated work is the plan hash (`approval.md`), and for ungated work the fact that the apply
  itself passes Selector → Policy → blast cap live — a Node that joined since the preview can
  widen the fan-out, but never past the cap and never past its own Policy. The threat model's
  invariant-12 boundary row records the same property ("point-in-time and advisory — never a
  reservation"). Revisit if a surface ever shows verdicts to a human long enough for
  staleness to mislead.

## Future work

Future work is in the private roadmap: roadmap: relay/research/spec-future-work/policy-preflight.

## Open questions

- **An empty Selector matches every Node on both paths and is refused by neither.**
  `execution.md` and `selectors-and-labels.md` say dispatch refuses it; the code refuses it on
  neither path. Settle in those two specs' migrations; this spec then follows whatever dispatch
  does (PF-2).

Who answers `unsupported` for a Node that does not report a Template is settled by ADR-0042
(PF-11).

## Retired

- **PF-21** — `2026-10-23` — retired unbuilt: the Admin Console performing a preflight before
  every apply. The Console does not execute (ADR-0052).
