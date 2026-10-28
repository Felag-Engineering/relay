# Execution

**Status:** aspirational — worked through with the owner on `2026-09-14`, awaiting their review
of this draft. Describes intended behaviour, not the code (see the establishing phase in
`README.md`).

## Purpose

Execution turns *"run this on the fleet"* into Tasks on Nodes and results back. It is the
pipeline every control-path surface goes through to act on a Node.

An AI-agent that cannot be trusted with a fleet may still drive one because this path bounds it:
before a single Task leaves the Relay, it resolves who is targeted, checks whether the caller may
ask, caps the blast radius, stops a failing change before it spreads, and records what happened.

Policy is *not* part of this capability. What a Node will do is decided on the Node, by its own
engine, after everything here has passed (invariant 12).

## Surfaces

Both surfaces adapt the same capability-layer entry point and decide nothing. A parallel path
fails to compile: the dispatch type and its constructor are unexported.

| Surface | How it is reached |
|---|---|
| **MCP** | The execution meta-tools: `run_operation` (typed Operation), `raw_exec` (arbitrary argv), `get_job`, `cancel_job`. Every dispatch tool accepts an optional idempotency key argument. |
| **Control API** | `POST /api/v1/operations`, `POST /api/v1/raw-exec`, `GET /api/v1/jobs/{id}`, `POST /api/v1/jobs/{id}/cancel`. Dispatch accepts the `Idempotency-Key` header. |

The Admin Console is not an execution surface: it watches and does not execute (ADR-0052). It
shows Jobs and their results through `query.md` and `audit-and-read-lane.md`. Executing from the
Console is later work (`roadmap: relay/console-execution-for-skills`).

Raw Exec is deliberately *not* a separate path: it is this pipeline carrying an argv instead of
a typed Operation, always at the mutate risk class. Its own route would be the parallel control
path invariants 1 and 10 forbid. *The three execution tiers* below says how each tier is
contained.

## Behaviour

### The pipeline

One call, in this order. Each stage can only refuse; none can widen what a later stage allows.

1. **Idempotency.** If the call carries an idempotency key the same Account used within the
   operator-set window, the existing Job is returned and nothing below runs again. The same key
   with different arguments is refused. See *Handing back the Job* below.
2. **Freeze gate** (ADR-0013). The outermost gate, evaluated *before* Selector resolution and
   authorization. A frozen Relay refuses all new dispatch, every risk class, whoever asks.
   **A failed read of the freeze state refuses**: the guardrail fails closed, at the cost of
   availability during a store blip.
3. **Selector resolution.** The Selector is resolved against the registry into a concrete set
   of Nodes, across the four Label namespaces (invariant 7). `state:` predicates are evaluated
   here, at resolution time, rather than stored. The grammar, the namespaces and who may write
   each are in `selectors-and-labels.md`. This stage also:
   - **refuses an empty Selector** — dispatching to the whole fleet must be written deliberately;
   - **refuses a Selector that matches no Nodes** as `no_nodes_matched`;
   - for a Template Operation, **refuses a name no matched Node reports**, and otherwise
     **excludes matched Nodes that do not report it** before anything below is decided. Excluded
     Nodes appear in the result as `unsupported` and are never dispatched
     (`operations-and-templates.md`);
   - is where quarantine would exclude a Node, whatever namespace matched it. Quarantine is not
     in the MVP (`roadmap: relay/quarantine`).
4. **Authorization.** The Principal is checked against the requested Action and Selector.
   **Caller-asserted attribution is stripped from the context first** — an authorization
   decision must never be able to read a value the caller supplied about itself. Raw Exec
   requires `admin`.
5. **Blast-radius cap** (invariant 5). Enforced on the Relay, before dispatch, on the count of
   resolved Nodes remaining after exclusion. See below.
6. **Approval gate** (ADR-0027). *After* resolution, authorization and the cap, because an
   approver must be shown the resolved fan-out. *Before* any Task exists, because parking must
   leave **no Job and no Pending Tasks** behind: rows a restart reconciler could mistake for
   interrupted work.
7. **Dispatch.** The authorized, resolved, cap-cleared unit executes. See at-most-once below.
8. **Audit.** Recorded **unconditionally**, including when the dispatcher errored partway:
   a partially-executed dispatch must never be unaudited. A failed audit write is surfaced
   alongside the results, never swallowed.

A **park is not a refusal**: nothing was denied and nothing ran, and it is audited under its own
kind (`approval.md` AP-41).

### The three execution tiers

Each tier holds invariant 1 — nothing on the wire can compose or escalate a command — its own
way. ADR-0001 orders them by trust; ADR-0021 froze the first and made the second the
extensibility path.

| Tier | Who fixes the command | How composition is prevented |
|---|---|---|
| **1 — Native** | The daemon's own code | An argv array, never a shell. Arguments are values, so there is nothing to inject into. Frozen at four: `system.facts`, `file.read`, `service.restart`, `pkg.install`. |
| **2 — Template** | A trusted author, in a Template definition inside the Node's root-owned Policy | The command *structure* comes from that definition and the caller cannot alter it. The body runs through a shell, and a slot value is never part of the text the shell parses: each placeholder becomes a quoted positional parameter and the values follow as separate arguments, so a `;` or `$( … )` in a value is only ever data; a slot stands only as a word of a top-level command; one in a code-running position decidable from the body makes the template set `unloadable`, and an undecidable one is a `policy check` warning (ADR-0021, amended 2026-10-14 and 2026-10-15). This is the one deliberate shell path in the daemon (`operations-and-templates.md`). |
| **3 — Raw Exec** | The caller | Still an argv array — there is no shell to compose in — so the caller chooses *which binary runs*, not what else runs after it. `admin`-only on the Relay, and gated on the Node by Policy: allow patterns must match the whole command line, and an argv element containing whitespace is denied (`policy.md`). The shipped default Policy does not enable it. |

**New vocabulary is tier 2, never tier 1**: ADR-0021's freeze forbids a fifth Native. Tier 1
keeps `system.facts` and `file.read` as platform intrinsics — facts feeds the registry, and
`file.read` needs executor-level descriptor access for ADR-0018's canonical-path re-check — and
keeps `service.restart` and `pkg.install` rather than migrating them.

**There is no shell-composition path anywhere in the system**, tier 3 included. Tier 3 grants the
choice of binary, behind two independent gates: the `admin` role on the Relay and a Policy allow
on the Node, none shipped by default (ADR-0022).

### Arguments are never secrets

Operation arguments and Raw Exec argv are **the record of what was done**, audited verbatim. By
contract a caller never passes a secret through one; this spec and `list_operations` say so, and
there is no secret slot type. Getting a secret onto a Node is secret distribution, not yet
designed and not in the MVP, and it must never make a secret an audited argument.

### Fan-out, ordering and timeouts

**Fan-out is concurrent.** One Job produces one Task per resolved Node, and **at most 16 Tasks
of one Job are in flight at once**. The limit is a built-in constant, not a setting. A read Job
at the default cap of 10,000 is about 625 rounds of 16 round-trips. The code already dispatches
concurrently at this bound, read today from the `reach.dispatch_concurrency` setting; the MVP fixes
it as a constant.

A configurable failure tolerance, a configurable in-flight limit and retries are later work
(`roadmap: relay/failure-policy-and-retries`). A retry there would be a new Task with a new ID,
never a re-send of the old one (invariant 4).

Task order within a Job is the Selector's resolution order and is not a contract; nothing may
depend on one Node running before another.

**Each Task carries its own timeout**, declared by the Operation and sent on the wire; a caller
may request a shorter one, never a longer one. A Task that exceeds it resolves `timeout` — a real
outcome recorded against that Node, not a Relay-side abandonment. There is no Job-level timeout.

### Halting a failing mutation

**A `mutate` Job halts on its first failure** (MVP). Once one Task resolves `failure` or `timeout`, no
further Task is sent. Every unsent Task resolves `cancelled` with the halt as its reason, and the
Job's result says it halted, on which Node, and why. Tasks already in flight when the halt happens
finish and report their real outcomes.
A halt is kept across a Relay restart (owner decision, 2026-10-27). At start, before any Node
connects, the Relay sends no Task of a halted Job. A sibling still `Pending`, never sent, resolves
`cancelled` with the halt as its reason. A sibling `Dispatched` may have reached its Node before the
crash, so it resolves `failure` with exit code -1 and stderr saying it may have run, the shape of a
Node-offline result, and an AI-agent never mistakes "maybe ran" for "did not run". The audit records
each outcome as it is stored.

- `denied_by_policy`, `unsupported` and `unreachable` **do not halt** a Job. They describe that
  Node, not the change being made.
- **`read` Jobs never halt.** One Node failing a read says nothing about the others.
- There is no configurable failure threshold in the MVP
  (`roadmap: relay/failure-policy-and-retries`).

### The blast-radius cap

Two caps, chosen by the Action's risk class (invariant 13): a generous read cap and a small
mutate cap. **`unspecified` maps to the mutate lane**, so Raw Exec and any miswired Action fail
closed into the strict lane. For a Template Operation the class is the most restrictive the
reporting Nodes report (`operations-and-templates.md`). The cap is an inclusive maximum.

Both are operator settings in the Relay's configuration file, read at start and re-read on
`SIGHUP` (`relay-configuration.md`); a non-positive value is clamped to the built-in default,
never treated as unlimited. They are *reach-bounding* under invariant 11, never reachable from an
API Token or an MCP tool. Editing them in the Console, by a human `admin` with step-up, audited
(ADR-0004 and ADR-0012 amendments), is not in the MVP (`roadmap: relay/settings-in-the-console`).

### At-most-once execution (invariant 4, ADR-0004)

Task execution is at-most-once and must never become at-least-once. Ordering holds it, not retry
logic:

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
- **Unreachable and version-refused Tasks are already terminal** and never enter
  reconciliation.
- **A re-issued request does not create a second Job.** Task-ID dedup cannot catch a re-sent
  dispatch, which would mint new Tasks; the idempotency key catches it one level up and returns
  the existing Job.

A disconnected Node's Task is **never sent, queued or retried**: it fails fast with
`unreachable`, and a reconnecting Node never runs a Task it missed. A Node that died silently is
noticed by its missed heartbeats, after about 3 minutes, not at send (`node-connection.md`).
Catching it at send, with an acknowledgement deadline and an `unacknowledged` outcome, is not in
the MVP (`roadmap: relay/fast-failure-and-fleet-admission`).

### Handing back the Job

A dispatch returns its Job before the Job finishes, so a broken connection never costs the
caller its handle.

- **MCP and the Control API.** The Job ID is returned in the result after a short bounded wait,
  so a quick read still reads as synchronous, and the caller polls `get_job` (or the Jobs route)
  for the rest. There is no MCP task handle: ADR-0047 removes the Tasks extension shim, and MCP
  Tasks for long-running Jobs is later work (`roadmap: relay/mcp-tasks-for-long-running-jobs`).
- **Idempotency key.** Every dispatch accepts an optional key: a tool argument on MCP, and the
  `Idempotency-Key` header on the Control API. A repeat
  of the same key by the same Account within an operator-set window returns the existing Job; the
  same key with different arguments is refused. A client re-issuing after a broken stream re-sends
  the key with identical arguments, so the repeat is caught for free. The Relay never infers a
  repeat from request content, which would swallow a deliberate second run.

### Job and Task lifecycle

One Job per call. One Task per resolved Node. A Task moves through three dispatch states:

```
Pending ──────────▶ Dispatched ──────────▶ Resolved
(persisted,        (sent, awaiting         (outcome recorded;
 not yet sent)      a result)               terminal)
```

Only `Dispatched` with no result is *in flight*, and that set is what a Relay restart
reconciles, except the Tasks of a halted Job, which are resolved and not re-sent. Three transitions go from `Pending` straight to `Resolved` and are never in flight: a
Task refused by the minimum-version gate (ADR-0014), a Task cancelled before dispatch, and a Task
left unsent when a `mutate` Job halts.

### Cancellation

`cancel_job` (and the Control API's cancel route) acts on a Job, and what it does depends on
where each Task has got to:

- **Pending** — marked cancelled and **never sent**.
- **Dispatched** — asked to cancel over its Tunnel, best-effort.
- **Resolved** — left alone, keeping its truthful outcome.

**Who may cancel is decided in the capability layer** (invariant 10):

- A **human** Account of `operator` or above may cancel **any** Job, not only its own — an on-call
  operator must be able to stop an AI-agent's or another operator's Job mid-incident.
- A **machine** Account of `operator` or above may cancel **only a Job it requested**, so a
  jailbroken AI-agent cannot stop other people's rollouts. That is read from the requester
  recorded on the Job; where none is recorded, the cancel is refused — fail closed.
- A `viewer` may not cancel.

**The rule follows the Account's kind, not how it signed in.** An AI-agent driving a *human*
Account's OAuth session is a human Principal here and may cancel any Job, although ADR-0024 calls
MCP-originated calls agent-grade. Accepted by the owner on `2026-09-17` (threat model R19); see
*Accepted residual risk*.

**Cancel only ever asks.** It never fabricates a `cancelled` outcome for a Task that won the race
and completed; the daemon reports what actually happened. A Task that moves `Pending → Dispatched`
inside the cancel window runs to completion — a deliberate gap under ADR-0013, not one to close.

The Principal who asked is recorded as its own audit row, beside the per-Task `cancelled`
outcomes, so the trail answers "who asked for the stop". If the cancel itself fails, no audit row
is written.

### What the caller gets back

Per-Node results, each carrying the Node, its outcome, the Job ID and the captured
stdout/stderr. Output is **size-capped by the daemon before the wire**, and a capped result
carries a `truncated` flag; the Relay never sees what was dropped. A halted Job names the Node
whose outcome halted it.

**What is retained differs by risk class, deliberately.** A `mutate` Task's output is kept with
its audit record. A `read`'s is not: ADR-0025 records what was read, by whom and when, never what
came back, because *"data not written cannot leak."* Nothing should imply the audit trail can
reproduce a read's content, and widening it is a one-way door.

Outcomes: `success`, `failure`, `timeout`, `denied_by_policy`, `cancelled`, `unreachable`,
`version_refused`, `unsupported`. The zero value means *not yet resolved*: a Pending or
Dispatched Task has no outcome. Two outcomes are not in the MVP: `unacknowledged`
(`roadmap: relay/fast-failure-and-fleet-admission`) and `quarantined`
(`roadmap: relay/quarantine`).

Several never involved the Node running anything:

- `version_refused` is Relay-synthesized under the ADR-0014 minimum-version gate: the Task was
  never sent, and its stderr explains that upgrades flow through the customer's config
  management.
- `unsupported` is daemon-reported when the Operation is not in that Node's vocabulary (nothing
  ran, Policy was not consulted), or Relay-reported for a Node excluded at resolution because it
  does not report the Template. Neither is a failure or a denial.
- `cancelled` on a Task left unsent by a halt carries the halt as its reason.

## Refusals

A **refusal** stops the whole dispatch: no Job, no Tasks, and an audited reason. Distinct from
a per-Node **outcome**, where a Job did run and individual Nodes failed.

| Refusal | Cause | What the caller learns |
|---|---|---|
| Idempotency conflict | The idempotency key was already used by this Account, within the window, with different arguments | The key conflicts; use a new key for a new request |
| Frozen | An emergency Freeze is engaged (ADR-0013) | The Relay is frozen; cite the ADR and say what to do |
| Empty Selector | A dispatch with no Selector | Name the Nodes; the whole fleet must be written deliberately |
| `no_nodes_matched` | The Selector resolved to zero Nodes | The Selector as written, so a typo is visible |
| Template not reported | No matched Node reports this Template | Point at `list_operations` |
| Unauthorized | The Principal may not request this Action on this Selector; Raw Exec without `admin` | Denied |
| Blast cap | Resolved Node count exceeds the cap for the risk class | The class, the matched count, and the cap |
| Pending approval | The Action requires approval and none covers it | A parked dispatch with its request ID and plan hash |
| Unauthorized cancel | A `viewer`, or any Account below `operator`, asks to cancel a Job | Denied; the Job continues |
| Machine cancels another's Job | A machine Account asks to cancel a Job it did not request, or one with no recorded requester | Denied, audited; the Job continues |
| Internal | Freeze state unreadable, or the approval check failed | Refused — the guardrail fails closed |

**Known information disclosure, accepted deliberately.** The Freeze gate runs before
authorization, so a caller not authorized for the Action still learns the Relay is frozen. Every
caller reaching this pipeline is already authenticated, so there is no anonymous
caller to leak it to.

Denials are a product surface: a refusal that does not explain itself sends an AI-agent looking
for Raw Exec.

## Governing ADRs and invariants

- **Invariant 1** (ADR-0001, ADR-0021) — nothing on the wire can compose or escalate a
  command. The invariant delegates its per-tier mechanism to the three tiers above.
- **Invariant 4** (ADR-0004) — at-most-once, held by the ordering above, and against a caller's
  re-issued request by the idempotency key.
- **Invariant 5** (ADR-0004) — the cap is enforced **here, on the Relay, before dispatch**, on
  the Nodes remaining after exclusion. Not on the Node, not by the caller.
- **Invariant 10** (ADR-0009/0010/0026, ADR-0052) — every interface is an adapter over this one
  layer, narrowing only. The unexported dispatch constructor is the compile-enforced half;
  `no_dispatch` covers the Console, which does not execute. Who may cancel a Job is decided here
  too, not per surface.
- **Invariant 12** (ADR-0011) — this pipeline **never evaluates Policy.** Not for real
  dispatch, not for hypotheticals. A matched-but-disconnected Node yields a Relay-side
  `unknown(offline)` conclusion rather than a guess.
- **Invariant 13** (ADR-0012, ADR-0042) — the risk class is security-relevant contract and
  selects the cap; Raw Exec always takes the mutate cap. A Template Operation's class is
  Node-reported, and a dispatch takes the most restrictive class the Nodes it reaches report
  (amended 2026-10-02).
- **Invariant 7** (ADR-0006/0020/0034, ADR-0050) — binds through Selector resolution: the
  security lane targets `relay:` and only `relay:`.
- **ADR-0004 — needs amending.** Concurrent fan-out at a fixed limit, halt-on-first-failure for
  `mutate` Jobs, and client-level idempotency above Task-ID dedup, are not in it.
- **ADR-0013** — cancellation's contract: cancel only ever asks, and the Freeze is the
  outermost gate on this path.
- **ADR-0014** — the minimum-version gate refuses a Task to an outdated Node before it is sent.
- **ADR-0025** — read output is not retained.
- **ADR-0027** — the approval gate's position in the pipeline.
- **ADR-0047** — removed the MCP Tasks extension shim (ADR-0028, superseded), so a Job is handed
  back by ID and polled.
- **ADR-0049** — Relay runs one dispatch at a time and has no Plan of its own.

Referenced above but governing elsewhere: ADR-0005 (transport), ADR-0018 (canonical path
matching, inside `file.read`), ADR-0022 (the shipped default Policy, which is why Raw Exec is
off out of the box), ADR-0052 (the Console watches and does not execute).

## Seams and proof

The capability layer is built from injected seams, each with a safe no-op default, and imports
only the registry and job domains. It is tested at those seams rather than through a surface:

- `Authorizer`, `CapChecker`, `AuditSink`, `FreezeStore` — the four gates.
- `Conduit` — sends one Task down a connected Node's tunnel and blocks for its result.
- `dispatcher` — unexported interface, unexported parameter type: a foreign package can neither
  implement it nor fabricate a value to pass it.
- `JobEventSink`, `MetricsSink` — observation only.

Load-bearing structural tests: dispatch cannot be constructed outside the layer; no surface
package can dispatch without going through it; the layer imports nothing but registry and jobs;
and the crash test covering at-most-once across a restart.

**A real dispatcher must never ride the no-op defaults.** The allow-all Authorizer, no-op
CapChecker and no-op AuditSink are safe only because the default dispatcher executes nothing; any
option wiring a real dispatcher must require real implementations of all three.

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
| Every Task is persisted before any is dispatched | `TestEngineOneTaskPerNodePersistedBeforeDispatch` | capability |
| At-most-once holds across a Relay restart, because the daemon dedups | `TestFleetE2E_RelayRestartDaemonReconnects_DedupHolds` | e2e |
| The audit trail survives a restart | `TestFleetE2E_AuditAndRestartSurvival` | e2e |
| A disconnected Node yields `unreachable` and is never sent a Task | `TestEngineOfflineNodeUnreachable` | capability |
| A Conduit error leaves the Task in flight, not resolved | `TestEngineConduitErrorLeavesTaskInFlight` | capability |
| An outdated Node's Task is refused before it is sent | `TestEngineMixedFleetVersionGate` | capability |
| Cancel stops Pending, asks Dispatched, leaves Resolved alone | `TestCancelJobStopsPendingSendsCancelToDispatchedLeavesResolved` | capability |
| A Task that wins the cancel race keeps its true outcome | `TestEngineDispatchOneTreatsConcurrentCancelAsTerminal` | capability |
| A `mutate` Job halts on its first `failure` or `timeout`; unsent Tasks resolve `cancelled` with the halt as their reason | `TestJobEngine_MutateJobHaltsOnFailureOrTimeout` | capability |
| No further Task is sent once a halting outcome is seen, even before it is persisted | `TestJobEngine_HaltClosesTheGateBeforeTheHaltingOutcomeIsPersisted`, `TestJobEngine_HaltAfterAdmitWithholdsThroughTheGuard`, `TestDispatchWiring_AHaltClosingAfterASiblingPassedAdmitWithholdsItsSend` | capability, composition |
| Tasks in flight when a Job halts finish and report their real outcomes, within the dispatch bound | `TestJobEngine_HaltLetsInFlightTasksFinishWithinTheBound` | capability |
| A Policy denial, `unsupported` and `unreachable` do not halt | `TestJobEngine_NonHaltingOutcomesDoNotHalt` | capability |
| A `read` Job never halts | `TestJobEngine_ReadJobNeverHalts` | capability |
| A Template Job halts on its most restrictive reported class | `TestRun_TemplateJobHaltsOnTheDispatchClass` | capability |
| The halt is recorded on the Job and in the audit trail | `TestExecution_HaltIsRecordedOnTheJobAndAudited` | capability |
| A halted Job's unsent Tasks are never sent after a restart | `TestDispatchWiring_AHaltedJobsUnsentTasksAreNeverSentAfterARestart` | composition |
| After a restart, no Task of a halted Job is sent; a Pending sibling resolves `cancelled` with the halt as its reason and a Dispatched one `failure`, exit -1, saying it may have run, each audited | `TestDispatchWiring_ARestartSendsNoTaskOfAHaltedJobAndCancelsEverySibling`, `TestReconciler_SettleHaltedJobs_SendsNothingAndResolvesEveryUnsentTask`, `TestSink_RecordHaltedSettlementWritesAnOutcomeRowWithNoPrincipal` | composition, capability, audit |
| A halted Job names the halting Node, the same on both surfaces | `TestMCP_HaltedMutateJob_ReportsTheHaltOnRunAndGetJob`, `TestControlAPI_HaltRendersIdenticallyOnBothSurfaces` | MCP, Control API |
| No surface can dispatch outside this layer | `TestNoDispatchConstruction`, `TestDispatchSymbolsUnexported` | compile-time |
| The layer imports nothing but registry and jobs | `.golangci.yml` depguard rule `capability-imports` | lint |
| Policy preflight and apply agree on an unchanged fleet | `TestMCP_Plan_PlanVsRealRunParity` | MCP |
| A fan-out returns one result per Node | `TestMCP_RunOperation_PerNodeResults` | MCP |
| A park is a result, not an error | `TestDispatch_ParkIsAResultNotAnError` | MCP |

Claims above with **no row**, and so nothing checking them:

- At most 16 Tasks of one Job are in flight at once.
- A `read`'s output is not retained while a `mutate`'s is.
- Caller-asserted attribution is stripped before the authorization decision. Nothing references
  `withoutAssertions` from a test, and this one guards an authorization input.
- A zero-match dispatch is refused as `no_nodes_matched` with no Job.
- An empty Selector is refused for dispatch.
- Nodes not reporting a Template are excluded before the cap and reported `unsupported`.
- A dispatch hands back its Job before finishing.
- A repeated idempotency key returns the existing Job; the same key with different arguments is
  refused.
- Only `operator` or above may cancel a Job; a `viewer` is refused. A human at that floor may
  cancel any Job; a machine Account only a Job recorded as requested by it, and a Job with no
  recorded requester is refused to a machine.
- Raw Exec requires `admin` on the Relay.

This list is compiled by hand and will be wrong again; `make docs-check` verifies only that a
cited test exists, never that the list is complete.

### Performance

| Characteristic | Contract | Measured by |
|---|---|---|
| Fan-out | Concurrent, at most 16 Tasks of one Job in flight, a built-in constant | *(none)* |
| Read blast cap | 10,000 Nodes by default, operator-set at startup, inclusive maximum | *(none)* |
| Mutate blast cap | 100 Nodes by default; Raw Exec always takes this lane | *(none)* |
| Task timeout | Per-Operation, declared and sent on the wire; a caller may only shorten it; no Job-level timeout | *(none)* |
| Task output | Size-capped by the daemon before the wire, `truncated` flagged on the result | *(none)* |
| Handing back the Job | The Job ID is returned before the Job finishes, within a short bounded wait | *(none)* |

There are **no benchmarks in this repository**, Go or Rust: nothing measures any row above,
most conspicuously fan-out, where the in-flight limit and the 10,000-Node read cap multiply.

## Out of scope

- **Policy evaluation** — the daemon's live engine, always (invariant 12). What Policy allows,
  including Raw Exec's gate, is `policy.md`.
- **The Operation vocabulary and the Template language** — `operations-and-templates.md`, with
  `/proto` as the source of truth (invariant 8).
- **Policy preflight and hypotheticals** — `policy-preflight.md`. A preflight carries no Task ID,
  sends no Task, and cannot be deduped into execution.
- **Sequencing several dispatches** — the harness's job, not Relay's (ADR-0049). Each step it
  takes is an ordinary Job created by this dispatch path, with its own cap check, at-most-once
  Tasks and audit identity.
- **Approval decisions, grants and scope** — `approval.md`. This spec covers only the gate's
  position and the park.
- **Engaging and releasing the Freeze** — `freeze.md`; this spec covers only the Freeze gate as
  a refusal. Job cancellation *is* in scope: it acts on a Job this capability created.
- **Label namespaces, the Selector grammar and `state:` derivation** —
  `selectors-and-labels.md`. This spec consumes a resolved Node set.
- **Getting a secret onto a Node** — secret distribution, not yet designed.
- **Querying Jobs, Tasks and the audit trail after the fact** — `audit-and-read-lane.md`.
- **Retry, scheduling, store-and-forward** — deliberately absent; re-targeting is the caller's
  decision. Configurable failure tolerance, a configurable in-flight limit and retries are
  `roadmap: relay/failure-policy-and-retries`.
- **Executing from the Admin Console** — the Console watches and does not execute (ADR-0052).

## Accepted residual risk

- **An AI-agent in a human Account's OAuth session cancels as a human.** Machine limits key on the
  Account's kind, so a model driving a human operator's OAuth session may cancel any Job. Accepted
  on `2026-09-17` (R19); revisit with the Accounts work (#578).
- **A careless caller can still put a secret into the audit trail.** The contract that
  arguments are never secrets is only a contract; nothing detects a credential passed as an
  argument or in Raw Exec argv, and it is recorded verbatim.
- **A fleet-wide read is slow at scale.** With 16 Tasks in flight, a 10,000-Node read is about
  625 rounds of round-trips.
- **A halt is not instant.** Up to 15 other Tasks of a halting `mutate` Job may already be in
  flight, and they run to completion.

## Future work

Waits in the private roadmap: failure tolerance, the in-flight limit and retries
(`roadmap: relay/failure-policy-and-retries`); the acknowledgement deadline and `unacknowledged`
(`roadmap: relay/fast-failure-and-fleet-admission`); MCP Tasks for long-running Jobs
(`roadmap: relay/mcp-tasks-for-long-running-jobs`); protecting secrets a caller passes by mistake
(`roadmap: relay/research/spec-future-work/execution`).

## Open questions

None.
