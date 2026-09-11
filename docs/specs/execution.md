# Execution

**Status:** current as of `2026-09-10`.

## Purpose

Execution is the capability that turns *"run this on the fleet"* into Tasks on Nodes and
results back — the pipeline every control-path surface must go through to act on a Node.

An AI-agent that cannot be trusted with a fleet is nonetheless allowed to drive one because
this path bounds it: it resolves who is being targeted, checks whether the caller may ask,
caps how far the blast can reach, and records what happened — before a single Task leaves the
Relay.

Policy is *not* part of this capability. What a Node will actually do is decided on the Node,
by its own engine, after everything here has already passed (invariant 12).

## Surfaces

All three surfaces adapt the same capability-layer entry point. None of them decides anything;
a surface that reaches a Node without going through it is a bug, and a structural one — the
dispatch type and its constructor are unexported, so a parallel path fails to compile.

| Surface | How it is reached |
|---|---|
| **MCP** | The execution meta-tools: `run_operation` (typed Operation), `raw_exec` (arbitrary argv), `get_job`, `cancel_job` |
| **Control API** | `POST /api/v1/operations`, `POST /api/v1/raw-exec`, `GET /api/v1/jobs/{id}`, `POST /api/v1/jobs/{id}/cancel` |
| **Admin Console** | The execution composer — plan-by-default, step-up re-auth on a mutate apply, behind the root-owned `console_execution` flag (ADR-0026). **Designed, not built** (v0.7.0). |

Raw Exec is deliberately *not* a separate path. It is this same pipeline carrying an argv
instead of a typed Operation, always at the mutate risk class. Giving it its own route would be
the parallel control path invariants 1 and 10 exist to forbid. See *The three execution tiers*
below for how it, and the other two, are contained.

## Behaviour

### The pipeline

One call, in this order. Each stage can only refuse; none can widen what a later stage allows.

1. **Freeze gate** (ADR-0013). Outermost — evaluated *before* Selector resolution and before
   authorization. A frozen Relay refuses all new dispatch, every risk class, regardless of who
   asks or how many Nodes would have matched. **A failed read of the freeze state refuses**:
   the guardrail fails closed, at the cost of availability during a store blip.
2. **Selector resolution.** The Selector is resolved against the registry into a concrete set
   of Nodes, across the four Label namespaces (invariant 7). `state:` predicates are evaluated
   here, at resolution time, rather than stored.
3. **Authorization.** The Principal is checked against the requested Action and Selector.
   **Caller-asserted attribution is stripped from the context first** — an authorization
   decision must never be able to read a value the caller supplied about itself.
4. **Blast-radius cap** (invariant 5). Enforced on the Relay, before dispatch, on the count of
   *resolved* Nodes. See below.
5. **Approval gate** (ADR-0027). Sits *after* resolution, authorization and the cap, and
   *before* any Task exists. After, because an approver must be shown the resolved fan-out —
   an approval that did not know how many Nodes it covered would be a fidelity gap by
   construction. Before, because parking must leave **no Job and no Pending Tasks** behind:
   rows a restart reconciler could mistake for interrupted work.
6. **Dispatch.** The authorized, resolved, cap-cleared unit executes. See at-most-once below.
7. **Audit.** Recorded **unconditionally**, including when the dispatcher errored partway: a
   dispatch may execute some Nodes before failing on others, and a partially-executed dispatch
   must never be unaudited. A failed audit write is surfaced alongside the results, never
   swallowed.

A **park is not a refusal.** Nothing was denied and nothing ran, so it is audited under its own
kind — distinguishing a newly created request from a re-drive that bounced off one already
pending, so the trail's count of asks stays truthful while polling stays visible.

### The three execution tiers

Invariant 1's property — nothing on the wire can compose or escalate a command — is held
differently by each tier. ADR-0001 orders them by trust; ADR-0021 froze the first and made the
second the extensibility path.

| Tier | Who fixes the command | How composition is prevented |
|---|---|---|
| **1 — Native** | The daemon's own code | An argv array, never a shell. Arguments are values, so there is nothing to inject into. Frozen at four: `system.facts`, `file.read`, `service.restart`, `pkg.install`. |
| **2 — Template** | A trusted local author, in a root-owned file beside `policy.toml` | The command *structure* comes from that file and the caller cannot alter it; every parameter slot is single-quoted before substitution, so a `;` in a slot is a literal semicolon inside quotes. This is the one deliberate `/bin/sh -c` path in the daemon. |
| **3 — Raw Exec** | The caller | Still an argv array — there is no shell to compose in — so the caller chooses *which binary runs*, not what else runs after it. Regex-gated by Policy on the Node, admin-only on the Relay, and refused by the shipped default Policy. |

**New vocabulary is tier 2, never tier 1.** A fifth Native Operation is a change ADR-0021's
freeze forbids; the extensibility path is a template. Tier 1 kept `system.facts` and `file.read`
as platform intrinsics — facts feeds the registry, and `file.read` needs executor-level
descriptor access for ADR-0018's canonical-path re-check that no template has — while
`service.restart` and `pkg.install` are grandfathered.

**There is no shell-composition path anywhere in the system**, tier 3 included. What tier 3
grants is the choice of binary, behind two independent gates: the admin role on the Relay
(invariant 3's central half) and a Policy regex on the Node, with no allow pattern shipped by
default (ADR-0022).

### Fan-out, ordering and timeouts

**Fan-out is sequential.** One Job produces one Task per matched Node, and the engine
dispatches them one at a time, blocking on each Node's result before moving to the next. No
concurrent dispatcher is wired. A Job's wall-clock is therefore the *sum* of its Tasks, not the
slowest of them.

That is worth stating plainly next to the default read cap of 10,000: a read Job at the cap is
ten thousand sequential round-trips. The cap is generous because reads are cheap per-Node, not
because the fan-out is parallel.

Task order within a Job is the Selector's resolution order and is not a contract; nothing may
depend on one Node running before another.

**Each Task carries its own timeout**, declared by the Operation and sent on the wire. A Task
that exceeds it resolves `timeout` — a real outcome recorded against that Node, not a Relay-side
abandonment. There is no Job-level timeout.

### The blast-radius cap

Two caps, chosen by the Action's declared risk class (invariant 13). The read cap is generous;
the mutate cap is small. **`unspecified` maps to the mutate lane** — the fail-closed default
that guarantees Raw Exec, and any future miswired Action, lands in the strict lane rather than
the generous one. The cap is an inclusive maximum: matched equal to the cap is allowed.

Both are **operator-set at Relay startup and unreachable from any API** (invariant 11); a
non-positive configured value is clamped to the built-in default rather than treated as
unlimited. They cannot change at runtime — only by reconstruction at process start.

### At-most-once execution (invariant 4, ADR-0004)

Task execution is at-most-once and must never become at-least-once. The property is held by
ordering, not by retry logic:

- **IDs are minted before persistence.** A Task ID exists exactly once, from the moment it is
  generated, and is written to the store immediately.
- **Persist-then-dispatch.** Every Task for a Job is created in `Pending` *before* any of them
  is dispatched. A crash in between leaves only Pending rows — never a Task that was sent but
  not recorded.
- **Persist-then-send.** A Task is marked dispatched in the store *before* it goes down the
  Node's tunnel. A crash after that leaves it dispatched with no result, which is exactly the
  in-flight set.
- **On restart**, in-flight Tasks may be re-sent for their result — **safe only because the
  relay-daemon dedups by Task ID.** Never because the Relay trusts its own retry to be novel.
- **Pending survivors are not auto-run.** There is no store-and-forward. Resuming a stalled Job
  is the caller's re-target decision, never an automatic behaviour.
- **Unreachable and version-refused Tasks are already terminal** and never enter reconciliation.

A disconnected Node's Task is **never sent, queued, or retried** — offline fails fast at
dispatch time.

### Job and Task lifecycle

One Job per call. One Task per matched Node. A Task moves through three dispatch states:

```
Pending ──────────▶ Dispatched ──────────▶ Resolved
(persisted,        (sent, awaiting         (outcome recorded;
 not yet sent)      a result)               terminal)
```

Only `Dispatched` with no result is *in flight*, and that set is exactly what a Relay restart
reconciles. Two transitions never reach the wire: a Task refused by the minimum-version gate
(ADR-0014) and a Task cancelled before dispatch both go from `Pending` straight to `Resolved`,
so neither is ever in flight and neither is reconciled.

### Cancellation

`cancel_job` acts on a Job, and what it does depends on where each Task has got to:

- **Pending** — marked cancelled and **never sent**.
- **Dispatched** — asked to cancel over its Tunnel, best-effort.
- **Resolved** — left alone, keeping its truthful outcome.

**Cancel only ever asks.** It never fabricates a `cancelled` outcome for a Task that won the
race and completed; the daemon reports what actually happened through the normal result path.
A Task that transitions `Pending → Dispatched` inside the cancel window runs to completion
uncancelled — a deliberate gap under ADR-0013's contract, not one to close.

The Principal who asked is recorded as its own audit row, on top of the per-Task `cancelled`
outcome, so the trail answers "who asked for the stop" and not only "this stopped". If the
cancel itself fails there is nothing true to record, and no audit row is written.

### What the caller gets back

Per-Node results, each carrying the Node, its outcome, the Job ID, and the captured
stdout/stderr. Output is **size-capped by the daemon before it reaches the wire**, and a
capped result carries a `truncated` flag — the cap is the Node's, so the Relay never sees
what was dropped.

**What is retained differs by risk class, and the difference is deliberate.** A `mutate`
Task's output is kept with its audit record. A `read`'s is not: ADR-0025 records metadata
only — what was read, by whom, when — and never what came back, because *"data not written
cannot leak."* Read output reaches the caller and is not retained afterwards. Anything
implying the audit trail can reproduce a read's content is wrong, and widening it is a
one-way door.

**A Selector matching no Nodes is a success, not a refusal.** It still produces a Job, still
audits, and returns zero results. Callers cannot distinguish "nothing matched" from "matched
and nothing to do" — and, until label management lands, cannot distinguish either from a
`tag:` term that can never match (#560).

Outcomes: `success`, `failure`, `timeout`, `denied_by_policy`, `cancelled`, `unreachable`,
`version_refused`, `unsupported`. The zero value means *not yet resolved* — a Pending or
Dispatched Task has no outcome.

Two of these never involved the Node running anything. `version_refused` is Relay-synthesized
under the ADR-0014 minimum-version gate: the Task was never sent, and its stderr explains that
upgrades flow through the customer's config management because the Relay never pushes binaries.
`unsupported` is daemon-reported: the Operation name is not in that Node's vocabulary, so
nothing executed and Policy was never consulted — neither a failure nor a denial.

## Refusals

A **refusal** stops the whole dispatch: no Job, no Tasks, and an audited reason. Distinct from
a per-Node **outcome**, where a Job did run and individual Nodes failed.

| Refusal | Cause | What the caller learns |
|---|---|---|
| Frozen | An emergency Freeze is engaged (ADR-0013) | The Relay is frozen; cite the ADR and say what to do |
| Unauthorized | The Principal may not request this Action on this Selector | Denied |
| Blast cap | Resolved Node count exceeds the cap for the risk class | The class, the matched count, and the cap |
| Pending approval | The Action requires approval and none covers it | A parked dispatch with its request ID and plan hash |
| Internal | Freeze state unreadable, or the approval check failed | Refused — the guardrail fails closed |

**Known information disclosure, accepted deliberately.** Because the Freeze gate runs before
authorization, a caller not authorized for the Action still learns the Relay is frozen before
being told they are denied. Accepted because every caller reaching this pipeline is already
mTLS-authenticated (ADR-0005/0006) — there is no anonymous caller to leak it to.

Denials are a product surface. A refusal that does not explain itself sends an AI-agent looking
for Raw Exec, which is the opposite of what the design wants.

## Governing ADRs and invariants

- **Invariant 1** (ADR-0001, ADR-0021) — nothing on the wire can compose or escalate a
  command. The three tiers above are how that is held; this spec is where the invariant
  delegates its per-tier mechanism.
- **Invariant 4** (ADR-0004) — at-most-once, held by the ordering above.
- **Invariant 5** (ADR-0004) — the cap is enforced **here, on the Relay, before dispatch**.
  Not on the Node, not by the caller.
- **Invariant 10** (ADR-0009/0010/0026) — every interface is an adapter over this one layer,
  exposing the same controls. The unexported dispatch constructor is the compile-enforced half;
  `no_dispatch` covers the Console.
- **Invariant 12** (ADR-0011) — this pipeline **never evaluates Policy.** Not for real
  dispatch, not for hypotheticals. A matched-but-disconnected Node yields a Relay-side
  `unknown(offline)` conclusion rather than a guess.
- **Invariant 13** (ADR-0012) — the risk class is declared contract in `/proto` and selects
  the cap; Raw Exec always takes the mutate cap.
- **Invariant 7** (ADR-0006/0020/0034) — binds through Selector resolution: the security lane
  targets `relay:` and only `relay:`.
- **ADR-0013** — cancellation's contract: cancel only ever asks, and the Freeze is the
  outermost gate on this path.
- **ADR-0014** — the minimum-version gate refuses a Task to an outdated Node before it is sent.
- **ADR-0025** — read output is not retained. It governs what the audit trail keeps, and
  widening it is a one-way door.
- **ADR-0027** — the approval gate's position in the pipeline.

Referenced above but governing elsewhere: ADR-0005 (transport), ADR-0018 (canonical path
matching, inside `file.read`), ADR-0022 (the shipped default Policy, which is why Raw Exec is
refused out of the box), ADR-0026 (the Console's execution surface).

## Seams and proof

The capability layer is built from injected seams, each with a safe no-op default, and the
package imports only the registry and job domains. Tested at those seams rather than through a
surface:

- `Authorizer`, `CapChecker`, `AuditSink`, `FreezeStore` — the four gates.
- `Conduit` — sends one Task down a connected Node's tunnel and blocks for its result.
- `dispatcher` — unexported interface, unexported parameter type: a foreign package can neither
  implement it nor fabricate a value to pass it.
- `JobEventSink`, `MetricsSink` — observation only.

Load-bearing structural tests: dispatch cannot be constructed outside the layer; no surface
package can dispatch without going through it; the layer imports nothing but registry and jobs;
and the crash test covering at-most-once across a restart.

**A real dispatcher must never ride the no-op defaults.** The allow-all Authorizer, no-op
CapChecker and no-op AuditSink are safe only because the default dispatcher performs no
execution. Any option wiring a real dispatcher must require real implementations of all three.

`make verify` covers this capability. Changes to the composition root or to dispatch wiring
also need `make test-integration`; changes to the daemon-facing contract need the dev fleet.

### What proves each claim

| Behaviour | Proven by | Seam |
|---|---|---|
| The Freeze gate is outermost — a frozen Relay refuses before it would even park | `TestFrozenRelayNeverEvenParks` | capability |
| A Freeze survives a Relay restart | `TestFreezeSurvivesRestart` | capability |
| The cap refuses by risk class, and says the class, count and limit | `TestBlastCapCheck`, `TestCapExceededErrorContent`, `TestCapExceededErrorContentReadCap` | capability |
| A non-positive configured cap clamps to the default rather than meaning unlimited | `TestNewBlastCapClampsNonPositiveToDefaults` | capability |
| An over-cap Selector is refused before anything dispatches | `TestRunBlastCapRejectsOversizedSelector` | capability |
| A zero-match dispatch still writes one job-level audit row | `TestRecordDispatchZeroMatchOneJobLevelRow` | audit sink |
| Every Task is persisted before any is dispatched | `TestEngineOneTaskPerNodePersistedBeforeDispatch` | capability |
| At-most-once holds across a Relay restart, because the daemon dedups | `TestFleetE2E_RelayRestartDaemonReconnects_DedupHolds` | e2e |
| The audit trail survives a restart | `TestFleetE2E_AuditAndRestartSurvival` | e2e |
| A disconnected Node yields `unreachable` and is never sent a Task | `TestEngineOfflineNodeUnreachable` | capability |
| A Conduit error leaves the Task in flight, not resolved | `TestEngineConduitErrorLeavesTaskInFlight` | capability |
| An outdated Node's Task is refused before it is sent | `TestEngineMixedFleetVersionGate` | capability |
| Cancel stops Pending, asks Dispatched, leaves Resolved alone | `TestCancelJobStopsPendingSendsCancelToDispatchedLeavesResolved` | capability |
| A Task that wins the cancel race keeps its true outcome | `TestEngineDispatchOneTreatsConcurrentCancelAsTerminal` | capability |
| No surface can dispatch outside this layer | `TestNoDispatchConstruction`, `TestDispatchSymbolsUnexported` | compile-time |
| The layer imports nothing but registry and jobs | `TestCapabilityImportsOnlyRegistryAndJobs` | compile-time |
| Plan and apply agree on an unchanged fleet | `TestMCP_Plan_PlanVsRealRunParity` | MCP |
| A fan-out returns one result per Node | `TestMCP_RunOperation_PerNodeResults` | MCP |
| A park is a result, not an error | `TestDispatchAndRender_ParkIsAResultNotAnError` | MCP |

Claims above with **no row**, and so nothing checking them:

- Fan-out is sequential.
- A `read`'s output is not retained while a `mutate`'s is.
- Caller-asserted attribution is stripped before the authorization decision. Nothing references
  `withoutAssertions` from a test, and this one guards an authorization input.
- A zero-match Selector returns **success** to the caller. The audit half is proven by the row
  above; that it is not a refusal, and that a Job is created, is not — and see Open questions,
  where the surfaces appear to disagree about it.

This list was wrong in both directions when first written: it claimed zero-match was unproven
when the audit half was covered, and omitted the cap-clamping and over-cap claims, which were.
It is compiled by hand and will be wrong again; `make docs-check` verifies only that a cited
test exists, never that the list is complete.

### Performance

| Characteristic | Contract | Measured by |
|---|---|---|
| Fan-out | Sequential — one Node at a time, blocking; a Job's wall-clock is the sum of its Tasks | *(none)* |
| Read blast cap | 10,000 Nodes by default, operator-set at startup, inclusive maximum | *(none)* |
| Mutate blast cap | 100 Nodes by default; Raw Exec always takes this lane | *(none)* |
| Task timeout | Per-Operation, declared and sent on the wire; no Job-level timeout | *(none)* |
| Task output | Size-capped by the daemon before the wire, `truncated` flagged on the result | *(none)* |

There are **no benchmarks in this repository** — Go or Rust. Every row above is a contract
nothing measures. That is the honest state, and it is most conspicuous for fan-out, where the
sequential contract and the 10,000-Node read cap multiply.

## Out of scope

- **Policy evaluation** — the daemon's live engine, always (invariant 12).
- **Plan mode and hypotheticals** — `plan-mode.md`. Plan carries no Task ID, sends no Task, and
  cannot be deduped into execution.
- **Approval decisions, grants and scope** — `approval.md`. This spec covers only the gate's
  position and the park.
- **Engaging and releasing the Freeze** — `freeze.md`. This spec covers only the Freeze gate as
  a refusal on the dispatch path. Job cancellation is *in* scope here: it acts on a Job this
  capability created, and the engine owns it.
- **Querying Jobs, Tasks and the audit trail after the fact** — `audit-and-read-lane.md`.
- **The Operation vocabulary itself** — `/proto` is the source of truth (invariant 8).
- **Retry, scheduling, store-and-forward** — deliberately absent; re-targeting is the caller's
  decision.

## Open questions

- **Secrets in Operation arguments reach the audit trail verbatim.** Arguments and Raw Exec
  argv are copied as-is into the audit entry, so a secret passed as an argument is recorded.
  Flagged in the code as residual risk from the original audit work. Node-side redaction is a
  candidate idea, not a commitment.
- **A lost response stream can make a blocking mutate dispatch re-executable** (#392). The
  2026-07-28 removal of SSE resumability tells clients to re-issue, which sits uncomfortably
  beside at-most-once. Open defect.
- **The surfaces disagree about a zero-match Job, and one of them is wrong.** This spec says a
  zero-match dispatch still produces a Job, and the engine does create one unconditionally,
  before the matched set is inspected. But the MCP surface's own test comment records that a
  zero-match run "created no Job, so it renders NO job_id key at all" — so a caller gets no
  handle for a Job that was created and audited, and can never retrieve it. Under *When
  documents and the code disagree*, this is a stop-and-escalate rather than something to
  resolve here.
- **Job cancellation is not authorized in this layer.** Engaging a Freeze goes through the
  `ControlAuthorizer`; cancelling a Job does not, and there is no cancel entry in the
  `ControlAction` vocabulary — whether a caller may stop a Job is decided by each surface, if at
  all. That may be deliberate: a stop is a safety action, and making it hard to reach could be
  worse than making it open. But it is an asymmetry with Freeze, and it sits awkwardly beside
  invariant 10's "decided once, inside that layer, never per interface." Needs a call.
- **Is this capability too big?** It may want splitting into dispatch (Selector → authz → cap)
  and Job lifecycle (async, results, reconciliation). Deferred until a second spec needs to
  cite one half without the other.

## History

- `2026-09-10` — Corrects what the audit trail retains: a `read`'s output is **not** retained
  (ADR-0025), where this spec previously said all output was kept whole. Adds fan-out, ordering
  and timeouts; the Job/Task lifecycle; cancellation, moved in from the Freeze spec; zero-match
  behaviour; and the proof and performance tables.
- `2026-09-08` — Gains *The three execution tiers*, which invariant 1 now delegates to for
  per-tier mechanism (ADR-0001 amendment, same date).
- `2026-09-08` — First written, from the capability layer as it stands. Absorbs the milestone
  acceptance criteria that ~15 tests currently cite as "the ROADMAP acceptance line".
