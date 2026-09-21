# Policy preflight

**Status:** designed, not built, as of `2026-09-20`.
**Claim prefix:** `PF`

> **The capability is Policy preflight; the option is still spelled `plan` on the wire.** ADR-0038
> renamed the capability and reassigned **Plan** to the approved route of execution. Every decision
> in ADR-0011 stands. The option rename is **PF-19** under *Designed, not built*; until it lands,
> every surface below takes `plan`, and this spec says so wherever it names the option.

## Purpose

Policy preflight answers *"what would happen if I ran this?"* without running it. A caller supplies
the same Operation and the same Selector it would dispatch, and gets back a per-Node verdict —
allow, deny, unsupported, or unknown — with the rule that decided each deny.

It exists so that the preview and the execution cannot disagree. Anyone can build a preflight
that guesses; the guess is worthless the moment it diverges, and worse than worthless if a caller
trusts it. So the verdicts here come from **the same engine that will decide at execution time**,
asked the same question, live.

That makes preflight the mechanism behind two things the product promises: preflight-before-apply
as a guardrail — opt-in on MCP and the Control API, mandatory before every apply where a
surface makes it so (the Console, PF-21) — and denials that teach: an AI-agent that can ask
"would this be allowed?" and be told which rule says no does not need to discover Policy by
tripping over it.

## Surfaces

| Surface | How the capability is reached |
|---|---|
| **MCP** | `plan: true` on `run_operation` and `raw_exec`. The result carries the per-Node verdicts, the would-be fan-out, and any would-be rejection (frozen, over cap, no Nodes matched) as data. |
| **Control API** | `"plan": true` on `POST /api/v1/operations` and `POST /api/v1/raw-exec`; same body, same result shape. |
| **Admin Console** | Renders existing preflight audit records on the Agent activity screen. Does **not** perform a preflight today: the composer that preflights before every apply is **PF-21**, behind the `console_execution` flag (ADR-0026, #438). The Console's word for it is **Preflight** (#575). |

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
  back. This is the one Freeze exemption — an approved **Plan** gets no such licence and every
  advance of one is refused while frozen (`plan.md`, ADR-0038).
- **PF-4** **The blast cap is reported, never enforced as an error.** An over-cap preflight returns
  would-be-rejected data — the matched count, the cap, and the risk class — with no error, and
  queries **nothing**: a real dispatch would touch no Node over cap, so neither does the preflight.
- **PF-5** **A Selector matching no Nodes is reported, not refused.** The preflight returns
  would-be-rejected with `no_nodes_matched` and no error, where the same real run is refused.
- **PF-6** **A disconnected Node yields `unknown` (offline) and is never queried.**
- **PF-7** **The Relay never computes a verdict.** Every `allow` and `deny` is the daemon's live
  engine's answer and every `unsupported` is the daemon's answer; the Relay consults no Policy
  view and no cached vocabulary to produce one (invariant 12). `unknown` is the only
  Relay-side conclusion, and it says exactly that the Relay could not ask — offline, or the
  query failed.
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

That is the same reasoning as the unexported dispatch constructor in `execution.md`: make the
dangerous thing structurally unreachable rather than conditionally skipped.

### The four verdicts, and why they are four

| Verdict | Meaning |
|---|---|
| `allow` | The Node's live Policy engine would permit it |
| `deny` | The Node's Policy decided against it — carries the deciding rule |
| `unsupported` | The Operation is not in that Node's vocabulary, so its Policy was never asked |
| `unknown` | The Relay could not ask — the Node is matched but disconnected, or the query itself failed |

- **PF-10** A preflight yields exactly these four verdicts per Node, and `deny` carries the
  deciding rule. (`quarantine-node.md` defines a fifth, `quarantined`, never queried; it lands with
  that capability (#430), and these four are what a preflight yields today — see *Out of scope*.)
- **PF-22** `unknown` is the zero value of the Relay's verdict — a verdict never obtained reads
  as "not known", never as a fabricated allow — and is never a wire value: the daemon only ever
  answers allow, deny or unsupported.
- **PF-11** `unsupported` is answered by the daemon whose vocabulary lacks the Operation, after
  being queried; a real dispatch to that Node reports `unsupported` with the same explanation.

`unsupported` and `unknown` are distinct from `deny` and from each other, and collapsing any pair
would lose information a caller needs. A denial is a Policy decision to argue with; an
unsupported Operation is a vocabulary gap to fill with a Template; an unknown is a Node to go
look at.

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
- **ADR-0038** — the rename, and the reassignment of **Plan** to the approved-route capability.
  Every decision in ADR-0011 is re-affirmed there unchanged; the option rename is PF-19.
- **Invariant 1** — a preflight carries the same typed Operation or verbatim argv as the dispatch
  would (PF-15); the three tiers are unchanged by previewing.
- **Invariant 5** — the cap is computed the same way, then reported instead of enforced (PF-4).
- **Invariant 10** — the Console reaches this capability through the capability layer like every
  adapter; where it executes, it preflights before every apply, and a `mutate` apply is
  additionally step-up-gated (PF-21, ADR-0026 decisions 2 and 3).
- **Invariant 13** — the risk class is declared contract and selects which cap the preflight
  reports against (PF-16).
- **ADR-0013** — Freeze halts dispatch and deliberately does not halt preflights (PF-3).
- **ADR-0021** — the per-Node vocabulary, which is why `unsupported` is a verdict (PF-11).

## Seams and proof

The Relay-side half lives in the capability layer beside dispatch and shares its seams; the query
goes out over the same `Conduit` that sends Tasks, through a method that carries no Task ID.
Tested at the capability seam and again through MCP, because preflight/apply parity is a claim
about what a *caller* sees. The Relay's wire conversion (argv and query fields round-tripping
into the proto message) is tested beside the dispatch router, and the daemon half in its
dispatch module. `make verify` covers every row below.

Test names still say `Plan` — `TestMCP_Plan_PlanVsRealRunParity` and its neighbours — because
they are the names in the tree. They are renamed by the PR that lands PF-19, not by this spec.

### What proves each claim

| Claim | Proven by | Seam |
|---|---|---|
| PF-2 | `TestPlanReturnsPerNodeVerdictsNoJobOrTask`, `TestMCP_Plan_PlanVsRealRunParity` | capability, MCP |
| PF-3 | `TestPlanFrozenReportsAdvisoryWhileRunRefuses`, `TestMCP_RunOperation_Plan_FrozenReportsWhileRealRunErrors` | capability, MCP |
| PF-4 | `TestPlanOverCapReportsNotErrors`, `TestMCP_RunOperation_Plan_OverCap_ReportsNotErrors` | capability, MCP |
| PF-5 | `TestPlanZeroMatchReportsNoNodesMatchedWhileRunRefuses`, `TestMCP_Plan_ZeroMatchReportsWhatARealRunRefuses` | capability, MCP |
| PF-6 | `TestPlanOfflineNodeIsUnknownNeverQueried`, `TestMCP_RunOperation_Plan_OfflineIsUnknown` | capability, MCP |
| PF-8 | `TestPlanReturnsPerNodeVerdictsNoJobOrTask`, `TestMCP_RunOperation_Plan_VerdictsNoExecution`, `TestMCP_RunOperation_Plan_AuditedAsPlanNoJobOrTask`, `policy_query_spawns_no_process_and_records_no_dedup` | capability, MCP, daemon |
| PF-9 | `TestPolicyQuery_CarriesNoTaskID`, `TestWireCarriesNoCallerIdentity` (its exact-field-set assertion on `PolicyQuery`) | compile-time |
| PF-10 | `TestPlanReportsUnsupportedDistinctFromDeny` | capability |
| PF-11 | `plan_and_apply_agree_on_unsupported` | daemon |
| PF-12 | `TestMCP_Plan_PlanVsRealRunParity` | MCP |
| PF-13 | `TestBuildOperationAction_UnknownArgOnAValidCallIsRejected` | MCP |
| PF-14 | `TestPlanOutdatedNodeGetsRealVerdictAdvisoryOnly`, `TestMCP_RunOperation_Plan_OutdatedAdvisory` | capability, MCP |
| PF-15 | `TestPolicyQuery_RawExecRoundTrip` | Relay wire conversion |
| PF-16 | `TestMCP_RawExec_Plan_ArgvVerbatimMutateClass` | MCP |
| PF-18 | `TestPlanAuthzDeniedRecordsRefusalNoVerdicts` | capability |

Claims with **no row**, and so nothing checking them:

- **PF-1** — that no surface exposes a separate preflight tool or route. True by inspection of
  the tool registry and route table; nothing asserts the absence.
- **PF-7** — that the Relay never consults its Policy view or cached vocabulary. The
  observable consequences (PF-6, PF-11) are covered; the *absence* of a consulting path is not.
  The `no_verdicts` guard in *Future work* would close it.
- **PF-13**, value half — that an ill-formed argument value surfaces as the daemon's verdict on a
  preflight rather than a Relay refusal.
- **PF-9**, second half — that the Task message carries no preview flag; both cited tests
  assert on `PolicyQuery` only.
- **PF-10**, deciding-rule half — that a `deny` carries its rule; the row proves only that the
  verdicts are distinct.
- **PF-22** — the zero value and the never-a-wire-value half.
- **PF-23** — nothing asserts that a preflight never touches the approval gate or store; the
  capability tests are built without a gate installed at all.
- **PF-17** — a property of the design, not a test target.

### Performance

| Characteristic | Contract | Measured by |
|---|---|---|
| Query fan-out | One query per matched, connected Node — sequential, like dispatch | *(none)* |
| Over-cap preflight | Queries **nothing**; reports the count and returns | *(none)* |
| Offline Nodes | Never queried; resolved to `unknown` without a round trip | *(none)* |

There are no benchmarks in this repository. A preflight at the read cap is the same sequential
round-trip cost as a dispatch, which matters because preflighting before applying is meant to be
cheap enough that a caller always does it.

## Designed, not built

| Claim | Statement | Milestone |
|---|---|---|
| PF-19 | The request option is spelled `preflight` on MCP and the Control API; `plan` is no longer accepted; the audit kind and the test names follow. | v0.8.1 — Read and Preflight Wire Contract |
| PF-20 | A `deny` verdict carries a reason kind beside the deciding rule: `no_allow` (nothing permitted it) or `denied` (a deny rule vetoed it), with the same two kinds a real dispatch reports (`policy.md`). | v0.8.1 — Read and Preflight Wire Contract |
| PF-21 | The Admin Console performs a preflight before **every** apply and renders its verdicts before an apply is offered; applying is a separate, deliberate act, and a `mutate` apply is additionally step-up-gated (ADR-0026 decisions 2 and 3). | v0.7.0 — Admin Console: Administration & Execution |

## Out of scope

- **Dispatch, the cap's enforcement, and at-most-once** — `execution.md`.
- **Policy itself** — the rules, their syntax, and how the daemon evaluates them. The Relay reads
  Policy and may never write it (invariant 2); what a rule *means* is the daemon's (`policy.md`).
- **The Plan — an approved route of execution** — `plan.md`. A Plan preflights every one of its
  steps at proposal, which is this capability being used by that one; the route, the cursor and
  the approval it parks through are not this capability.
- **The plan hash and approval binding** — `approval.md`. An approval commits to a content
  address over the act the caller intends — a Plan's ordered steps, their Operations and
  arguments, and the resolved fan-out, a single gated dispatch being the one-step case (ADR-0038)
  — never over a preview; minting that address is not this capability.
- **The Console's composer** — the surface's shape is ADR-0026's and the Console's per-screen
  specification's; the verdicts it renders are this capability's (PF-21).
- **Quarantine** — `quarantine-node.md`. It defines the quarantined Node's preflight conclusion
  as `quarantined`, never queried; that lands with the capability (#430). Today there is no such
  Node state on the preflight path, so PF-10's four verdicts are the whole set.
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
  reservation"). Revisit if a Console composer (PF-21) shows verdicts long enough for staleness
  to mislead a human.

## Future work

- **A compile-time guard against a Relay-computed verdict.** Invariant 12 holds today because no
  such code path exists; a `no_verdicts` guard analogous to `no_dispatch` — forbidding the
  capability package from importing the Policy view cache or the vocabulary cache — would make a
  view-consulting shortcut structurally unreachable, and would give PF-7 its proof row.

## Open questions

- **`execution.md` and `operations-and-templates.md` still say the Relay excludes Nodes that do
  not report a Template at Selector resolution and reports `unsupported` itself.** The owner
  decided on `2026-09-20` that the daemon answers `unsupported` after being queried (PF-11,
  ADR-0021); both neighbours are still `aspirational` and must adopt this at their migration.
  Until they do, PF-2's "same Selector resolution" is read with PF-11 winning.
- **An empty Selector matches every Node on both paths and is refused by neither.**
  `execution.md` says dispatch refuses an empty Selector; `selectors-and-labels.md` says it matches
  every Node for reads and is refused for dispatch. The code refuses it on neither path. Settle in
  the `selectors-and-labels.md` and `execution.md` migrations; this spec then follows whatever
  dispatch does (PF-2).

## History

- `2026-09-20` — Migrated to the claim format (PF-1 … PF-23). Owner decisions: a zero-match
  Selector is reported, not refused (PF-5 — the legacy text said refused; the code and its test
  were right); `unsupported` is the daemon's answer, never inferred by the Relay from cached
  vocabulary (PF-11 — the legacy text said the Relay skipped the query); the deny reason kind is
  unbuilt and becomes PF-20 in v0.8.1; the option rename becomes PF-19 in v0.8.1; the Console
  preflight-before-apply becomes PF-21 in v0.7.0; parity-on-unchanged-fleet moves from Open
  questions to Accepted residual risk (PF-17). The *Aligned with the other capabilities* trailer
  is folded into the body (#583). The malformed-call claim is split: argument names are refused
  Relay-side, values are the daemon's (PF-13). Proof rows gained for PF-5, PF-9, PF-11, PF-15
  and the daemon half of PF-8 from tests already in the tree. Empty-Selector handling flagged as
  an Open question for `selectors-and-labels.md`; the Relay-side Template exclusion in
  `execution.md` / `operations-and-templates.md` flagged as an Open question for theirs. After
  `/spec-check`: PF-10 split (PF-22 carries the zero-value claim), the plan-hash sentence in
  *Out of scope* corrected to address the act, not the preview (ADR-0038), quarantine deferred
  to `quarantine-node.md`, and the approval gate named as a difference (PF-23).
- `2026-09-14` — Confirmed with the owner as matching intent; aligned with the Policy denial
  reason kinds, malformed-call refusal, empty and zero-match Selector refusals, and Template
  exclusion. The `no_verdicts` guard moved to Future work.
- `2026-09-12` — Renamed from the plan-mode spec by ADR-0038, which reassigns **Plan** to the
  approved-route capability. Behaviour unchanged; the option on the wire is still `plan` until the
  code follows.
- `2026-09-12` — First written. Closes the dangling reference from `execution.md`'s out-of-scope
  section.
