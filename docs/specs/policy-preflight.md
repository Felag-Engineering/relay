# Policy preflight

**Status:** aspirational — confirmed with the owner on `2026-09-14` as matching intent; built
today, with the alignments below.

> **The capability is Policy preflight; the option is still spelled `plan` on the wire.** ADR-0038
> renames the capability and the option together, but only the first half is a documentation
> change. Every decision in ADR-0011 stands — the name and its "check-mode" framing were the only
> things wrong with it. Until the code change lands, every surface below still takes `plan`, and
> this spec says so wherever it names the option.

## Purpose

Policy preflight answers *"what would happen if I ran this?"* without running it. A caller supplies the
same Operation and the same Selector it would dispatch, and gets back a per-Node verdict — allow,
deny, unsupported, or unknown — with the rule that decided each deny.

It exists so that the preview and the execution cannot disagree. Anyone can build a
preflight that guesses; the guess is worthless the moment it diverges, and worse than
worthless if a caller trusts it. So the verdicts here come from **the same engine that will
decide at execution time**, asked the same question, live.

That makes preflight the mechanism behind two things the product promises: preflight-before-apply
as a guardrail the caller cannot skip, and denials that teach — an AI-agent that can ask "would this
be allowed?" and be told which rule says no does not need to discover Policy by tripping over it.

## Surfaces

A preflight is not a separate call. It is `plan=true` on the calls that would otherwise execute
— the option ADR-0038 renames to `preflight` when the code follows:
`run_operation` and `raw_exec` over MCP, and the Control API's `POST /api/v1/operations` and
`POST /api/v1/raw-exec`. The Console renders a preflight before a mutate apply, which is what
plan-by-default means there.

There is deliberately **no separate preflight route or preflight tool.** The preview and the act
are the same request with one flag, so a caller cannot preflight one thing and apply another by
reaching a different endpoint.

## Behaviour

### It is the dispatch pipeline, minus the dispatch

A preflight resolves the same Selector and runs the same authorization and cap checks as a real
dispatch, then asks each matched, connected daemon a read-only query instead of sending a Task.
Five differences from execution, each deliberate:

**Freeze is advisory, never a gate.** A frozen Relay refuses all real dispatch and still answers
preflights. Observation is exactly what is wanted during an incident, so the query path is exempt
from the Freeze check. The preflight reports that the Relay is frozen — so a caller is told a real
run would be refused — but the verdicts still come back. This is the one Freeze exemption: an
approved **Plan** gets no such licence, and every advance of one is refused while frozen
(`plan.md`, ADR-0038).

**The blast cap is checked but never enforced as an error.** An over-cap preflight returns
would-be-rejected data — the matched count, the cap, and the risk class — with **no error**,
because telling the caller what would happen is the entire point. The query fan-out is then
skipped entirely rather than querying an unbounded fleet: a real dispatch would touch nothing
over-cap, so neither does the preflight.

**Authorization still gates.** A caller not authorized to *ask* does not learn per-Node deciding
rules. A refused preflight is audited as a refusal and returns no verdicts.

**A disconnected Node yields `unknown(offline)`, never a guess.** The Relay holds a Policy
snapshot for display purposes and must not consult it here: the Relay never computes a verdict,
only the daemon's live engine does (invariant 12). "Unknown" is an honest answer and a cached
guess is not.

**A preflight creates nothing.** No Job, no Task, no dedup entry. It is audited under its own
kind, never as a dispatch.

### The query is a different message, not a flag

The wire carries a distinct read-only query/verdict pair rather than a `dry_run` bit on the
execution message. A flag means one dropped or defaulted bit turns a preview into real
execution; a separate message type **has no execution code path at all.** It carries no Task ID,
so it cannot be deduped into a Task or confused with one.

That is the same reasoning as the unexported dispatch constructor in `execution.md`: make the
dangerous thing structurally unreachable rather than conditionally skipped.

### The four verdicts, and why they are four

| Verdict | Meaning |
|---|---|
| `allow` | The Node's live Policy engine would permit it |
| `deny` | The Node's Policy decided against it — carries the deciding rule |
| `unsupported` | The Operation is not in that Node's vocabulary, so its Policy was never asked |
| `unknown` | The Relay could not ask — the Node is matched but disconnected, or the query itself failed |

`unsupported` and `unknown` are distinct from `deny` and from each other, and collapsing any pair
would lose information a caller needs. A denial is a Policy decision to argue with; an
unsupported Operation is a vocabulary gap to fill with a template; an unknown is a Node to go
look at. A real dispatch to an unsupported Node reports the matching outcome, which is the
preflight/apply parity the design requires.

The zero value is `unknown` deliberately — a verdict that was never obtained reads as "not
known", never as a fabricated allow.

### Preflight/apply parity

The property the whole capability rests on: **on an unchanged fleet, a preflight's verdicts and a
real run's outcomes agree.** Same Selector, same authorization, same cap arithmetic, same engine
answering. Divergence is a defect, not a caveat, and it is asserted end to end rather than argued.

### Aligned with the other capabilities

Settled elsewhere on `2026-09-13`/`14`, and applied to a preflight identically:

- A `deny` verdict carries the reason kind from `policy.md`: `no_allow` (nothing permitted it) or
  `denied` (a deny rule vetoed it). A malformed call — unknown argument, ill-formed value — is
  refused before any Node is asked.
- An empty Selector and a Selector matching no Nodes are refused exactly as for dispatch
  (`selectors-and-labels.md`, `execution.md`).
- Targeted Nodes that do not report a Template are reported `unsupported` without being queried
  (`operations-and-templates.md`).
- The request option is `preflight`, renamed from `plan` (ADR-0038).

## Refusals

A preflight refuses in fewer cases than a dispatch, and the difference is the point.

| Condition | A real dispatch | A preflight |
|---|---|---|
| Frozen | Refused | **Answered** — frozen state reported advisorily |
| Over the blast cap | Refused | **Answered** — reports would-be-rejected with the count and cap |
| Unauthorized | Refused | Refused, audited, no verdicts |
| Node offline | Per-Node `unreachable` | Per-Node `unknown(offline)` |
| Outdated daemon | Task refused before sending | **Answered** — a real verdict, with outdated reported advisorily |

## Governing ADRs and invariants

- **Invariant 12** (ADR-0011) — the load-bearing one. Policy is evaluated **only** by the
  daemon's live engine, including hypotheticals. The Relay never computes a verdict, and a
  matched-but-disconnected Node yields `unknown` rather than a guess from cached state.
- **ADR-0038** — the rename, and the reassignment of **Plan** to the approved-route capability.
  Every decision in ADR-0011 is re-affirmed there unchanged.
- **Invariant 1** — a preflight carries the same typed Operation or argv as the dispatch would;
  the three tiers are unchanged by previewing.
- **Invariant 5** — the cap is computed the same way, then reported instead of enforced.
- **Invariant 13** — the risk class is declared contract and selects which cap the preflight reports
  against.
- **ADR-0013** — Freeze halts dispatch and deliberately does not halt preflights.
- **ADR-0021** — the per-Node vocabulary, which is why `unsupported` is a verdict.

## Seams and proof

The Relay-side half lives in the capability layer beside dispatch and shares its seams; the query
goes out over the same `Conduit` that sends Tasks, through a method that carries no Task ID.
Tested at the capability seam and again through MCP, because preflight/apply parity is a claim
about what a *caller* sees.

Test names still say `Plan` — `TestMCP_Plan_PlanVsRealRunParity` and its neighbours — because they
are the names in the tree. They are renamed by the code change that renames the option, not by
this spec.

### What proves each claim

| Behaviour | Proven by | Seam |
|---|---|---|
| **A preflight and a real run agree on an unchanged fleet** | `TestMCP_Plan_PlanVsRealRunParity` | MCP |
| A preflight returns per-Node verdicts and creates no Job or Task | `TestPlanReturnsPerNodeVerdictsNoJobOrTask`, `TestMCP_RunOperation_Plan_VerdictsNoExecution` | capability, MCP |
| A preflight is audited under its own kind, never as a dispatch | `TestMCP_RunOperation_Plan_AuditedAsPlanNoJobOrTask` | MCP |
| A frozen Relay still answers preflights while refusing real runs | `TestPlanFrozenReportsAdvisoryWhileRunRefuses`, `TestMCP_RunOperation_Plan_FrozenReportsWhileRealRunErrors` | capability, MCP |
| An over-cap preflight reports rather than erroring | `TestPlanOverCapReportsNotErrors`, `TestMCP_RunOperation_Plan_OverCap_ReportsNotErrors` | capability, MCP |
| An offline Node is `unknown` and is never queried | `TestPlanOfflineNodeIsUnknownNeverQueried`, `TestMCP_RunOperation_Plan_OfflineIsUnknown` | capability, MCP |
| An outdated Node gets a real verdict, with outdated advisory only | `TestPlanOutdatedNodeGetsRealVerdictAdvisoryOnly`, `TestMCP_RunOperation_Plan_OutdatedAdvisory` | capability, MCP |
| `unsupported` is distinct from `deny` | `TestPlanReportsUnsupportedDistinctFromDeny` | capability |
| An unauthorized preflight is refused, audited, and yields no verdicts | `TestPlanAuthzDeniedRecordsRefusalNoVerdicts` | capability |
| Raw Exec preflights carry argv verbatim at the mutate class | `TestMCP_RawExec_Plan_ArgvVerbatimMutateClass` | MCP |

Claims above with **no row**, and so nothing checking them:

- That the query carries no Task ID and cannot be deduped into execution. It is true by
  construction — the message has no Task ID field — but nothing asserts the absence the way
  `no_dispatch` asserts a missing dispatch path.
- That the Relay never consults its Policy snapshot to answer a verdict. The `unknown(offline)`
  behaviour is covered, which is the observable consequence; the *absence* of a
  snapshot-consulting path is not.

### Performance

| Characteristic | Contract | Measured by |
|---|---|---|
| Query fan-out | One query per matched, connected Node — sequential, like dispatch | *(none)* |
| Over-cap preflight | Queries **nothing**; reports the count and returns | *(none)* |
| Offline Nodes | Never queried; resolved to `unknown` without a round trip | *(none)* |

There are no benchmarks in this repository. A preflight at the read cap is the same sequential
round-trip cost as a dispatch, which matters because preflighting before applying is meant to be
cheap enough that a caller always does it.

## Out of scope

- **Dispatch, the cap's enforcement, and at-most-once** — `execution.md`.
- **Policy itself** — the rules, their syntax, and how the daemon evaluates them. The Relay reads
  Policy and may never write it (invariant 2); what a rule *means* is the daemon's.
- **The Plan — an approved route of execution** — `plan.md`. A Plan preflights every one of its
  steps at proposal, which is this capability being used by that one; the route, the cursor and
  the approval it parks through are not this capability.
- **The plan hash and approval binding** — `approval.md`. An approval commits to a content
  address over a Plan — a route, since ADR-0038 — and minting that address is not this
  capability.
- **The Console's plan-by-default apply flow** — the surface's shape is ADR-0026's; the verdicts
  it renders are this capability's.
- **Shadow mode** — a standing per-Account setting converting every mutate into a preflight is a
  candidate idea, not a commitment, and does not exist.

## Future work

- **A compile-time guard against a Relay-computed verdict.** Invariant 12 holds today because no
  such code path exists; a `no_verdicts` guard analogous to `no_dispatch` would make a
  snapshot-consulting shortcut structurally unreachable.

## Open questions

- **Preflight/apply parity is asserted on an unchanged fleet only.** Drift between preflight and
  apply is what the approval plan hash exists to catch for gated work; for ungated work, nothing re-checks
  that the fleet did not move between the preview and the act, and nothing needs to — but a
  caller could reasonably believe otherwise.

## History

- `2026-09-14` — Confirmed with the owner as matching intent; aligned with the Policy denial
  reason kinds, malformed-call refusal, empty and zero-match Selector refusals, and Template
  exclusion. The `no_verdicts` guard moved to Future work.

- `2026-09-12` — Renamed from `plan-mode.md` by ADR-0038, which reassigns **Plan** to the
  approved-route capability. Behaviour unchanged; the option on the wire is still `plan` until the
  code follows.
- `2026-09-12` — First written. Closes the dangling reference from `execution.md`'s out-of-scope
  section.
