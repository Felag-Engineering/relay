# Execution

**Status:** aspirational — worked through with the owner on `2026-09-14`, awaiting their review
of this draft. Describes intended behaviour, not the code (see the establishing phase in
`README.md`).

## Purpose

Execution is the capability that turns *"run this on the fleet"* into Tasks on Nodes and
results back — the pipeline every control-path surface must go through to act on a Node.

An AI-agent that cannot be trusted with a fleet is nonetheless allowed to drive one because
this path bounds it: it resolves who is being targeted, checks whether the caller may ask,
caps how far the blast can reach, stops a failing change before it spreads, and records what
happened — before a single Task leaves the Relay.

Policy is *not* part of this capability. What a Node will actually do is decided on the Node,
by its own engine, after everything here has already passed (invariant 12).

## Surfaces

All three surfaces adapt the same capability-layer entry point. None of them decides anything;
a surface that reaches a Node without going through it is a bug, and a structural one — the
dispatch type and its constructor are unexported, so a parallel path fails to compile.

| Surface | How it is reached |
|---|---|
| **MCP** | The execution meta-tools: `run_operation` (typed Operation), `raw_exec` (arbitrary argv), `get_job`, `cancel_job`. Where the client declares the Tasks extension (SEP-2663), a dispatch returns a task handle and the Job is also reached through `tasks/get` and `tasks/cancel`. Every dispatch tool accepts an optional idempotency key argument. |
| **Control API** | `POST /api/v1/operations`, `POST /api/v1/raw-exec`, `GET /api/v1/jobs/{id}`, `POST /api/v1/jobs/{id}/cancel`. Dispatch accepts the `Idempotency-Key` header. |
| **Admin Console** | The execution composer — preflight-by-default, step-up re-auth on a mutate apply, behind the root-owned `console_execution` flag (ADR-0026). **Designed, not built** (v0.7.0). |

Raw Exec is deliberately *not* a separate path. It is this same pipeline carrying an argv
instead of a typed Operation, always at the mutate risk class. Giving it its own route would be
the parallel control path invariants 1 and 10 exist to forbid. See *The three execution tiers*
below for how it, and the other two, are contained.

## Behaviour

### The pipeline

One call, in this order. Each stage can only refuse; none can widen what a later stage allows.

1. **Idempotency.** If the call carries an idempotency key the same Account used within the
   operator-set window, the existing Job is returned and nothing below runs again. The same key
   with different arguments is refused. See *Handing back the Job* below.
2. **Freeze gate** (ADR-0013). Outermost of the gates — evaluated *before* Selector resolution
   and before authorization. A frozen Relay refuses all new dispatch, every risk class,
   regardless of who asks or how many Nodes would have matched. **A failed read of the freeze
   state refuses**: the guardrail fails closed, at the cost of availability during a store blip.
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
   - **excludes every quarantined Node**, whatever namespace matched it, `relay:` included.
     Excluded Nodes appear in the result as `quarantined` and are never dispatched; a dispatch
     whose every matched Node is quarantined sends nothing (`quarantine-node.md`).
4. **Authorization.** The Principal is checked against the requested Action and Selector.
   **Caller-asserted attribution is stripped from the context first** — an authorization
   decision must never be able to read a value the caller supplied about itself. Raw Exec
   requires `admin`.
5. **Blast-radius cap** (invariant 5). Enforced on the Relay, before dispatch, on the count of
   resolved Nodes remaining after exclusion. See below.
6. **Approval gate** (ADR-0027). Sits *after* resolution, authorization and the cap, and
   *before* any Task exists. After, because an approver must be shown the resolved fan-out —
   an approval that did not know how many Nodes it covered would be a fidelity gap by
   construction. Before, because parking must leave **no Job and no Pending Tasks** behind:
   rows a restart reconciler could mistake for interrupted work.
7. **Dispatch.** The authorized, resolved, cap-cleared unit executes. See at-most-once below.
8. **Audit.** Recorded **unconditionally**, including when the dispatcher errored partway: a
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
| **2 — Template** | A trusted author, in a Template definition inside the Node's root-owned Policy | The command *structure* comes from that definition and the caller cannot alter it. The body runs through a shell, and every slot is substituted as exactly one single-quoted word standing alone as a token, so a `;` in a slot is a literal semicolon inside quotes. This is the one deliberate shell path in the daemon (`operations-and-templates.md`). |
| **3 — Raw Exec** | The caller | Still an argv array — there is no shell to compose in — so the caller chooses *which binary runs*, not what else runs after it. `admin`-only on the Relay, and gated on the Node by Policy: allow patterns must match the whole command line, and an argv element containing whitespace is denied (`policy.md`). The shipped default Policy does not enable it. |

**New vocabulary is tier 2, never tier 1.** A fifth Native Operation is a change ADR-0021's
freeze forbids; the extensibility path is a Template. Tier 1 kept `system.facts` and `file.read`
as platform intrinsics — facts feeds the registry, and `file.read` needs executor-level
descriptor access for ADR-0018's canonical-path re-check that no Template has — while
`service.restart` and `pkg.install` are kept rather than migrated.

**There is no shell-composition path anywhere in the system**, tier 3 included. What tier 3
grants is the choice of binary, behind two independent gates: the `admin` role on the Relay and
a Policy allow on the Node, with none shipped by default (ADR-0022).

### Arguments are never secrets

Operation arguments and Raw Exec argv are **the record of what was done**, and are audited
verbatim. By contract a caller never passes a secret through one; this spec and
`list_operations` say so to callers, and there is no secret slot type. Getting a secret onto a
Node is secret distribution, which is not yet designed (Future work in `quarantine-node.md`), which is designed so a secret never becomes an
audited argument.

### Fan-out, ordering and timeouts

**Fan-out is sequential.** One Job produces one Task per resolved Node, and the engine
dispatches them one at a time, blocking on each Node's result before moving to the next. A Job's
wall-clock is therefore the *sum* of its Tasks, not the slowest of them.

That is worth stating plainly next to the default read cap of 10,000: a read Job at the cap is
ten thousand sequential round-trips. The cap is generous because reads are cheap per-Node, not
because the fan-out is parallel. Concurrent fan-out is Future work.

Task order within a Job is the Selector's resolution order and is not a contract; nothing may
depend on one Node running before another.

**Each Task carries its own timeout**, declared by the Operation and sent on the wire; a caller
may request a shorter one, never a longer one. A Task that exceeds it resolves `timeout` — a real
outcome recorded against that Node, not a Relay-side abandonment. There is no Job-level timeout.

### Halting a failing mutation

**A `mutate` Job halts on its first failure.** Once one Task resolves `failure`, `timeout` or
`unacknowledged`, no further Task is sent. `unacknowledged` halts because a Node that may or may
not have applied the change is exactly the uncertainty a rollout must stop on. Every Task not yet sent resolves `cancelled`, and the Job's result says it
halted, on which Node, and why.

- `denied_by_policy`, `unsupported` and `unreachable` **do not halt** a Job. They describe that
  Node, not the change being made.
- **`read` Jobs never halt.** One Node failing a read says nothing about the others.
- There is no configurable failure threshold in the first pass.

### The blast-radius cap

Two caps, chosen by the Action's risk class (invariant 13). The read cap is generous; the
mutate cap is small. **`unspecified` maps to the mutate lane** — the fail-closed default that
guarantees Raw Exec, and any future miswired Action, lands in the strict lane rather than the
generous one. For a Template Operation the class is the most restrictive reported by the Nodes
that report it (`operations-and-templates.md`). The cap is an inclusive maximum: matched equal
to the cap is allowed.

Both are today **operator-set at Relay startup** (`relay-configuration.md`); a non-positive
configured value is clamped to the built-in default rather than treated as unlimited, and they
change only by reconstruction at process start. They are *reach-bounding* settings under
invariant 11 as amended 2026-09-15 — never reachable from an API Token or an MCP tool, and
designed to become store-backed operator settings edited only by a human `admin` with step-up
re-authentication, audited (ADR-0004 and ADR-0012 amendments; #596).

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
- **Unreachable, unacknowledged and version-refused Tasks are already terminal** and never enter
  reconciliation.
- **A re-issued request does not create a second Job.** Task-ID dedup cannot catch a caller that
  re-sends a dispatch as a new request, because the re-issue would mint new Tasks. The
  idempotency key closes that gap one level up: the repeat returns the Job that already exists.

A disconnected Node's Task is **never sent, queued, or retried** — offline fails fast at
dispatch time with `unreachable`, and a Node that reconnects never runs a Task it missed.
A Node that died silently is caught at send: a dispatched Task the relay-daemon does not
acknowledge within the acknowledgement deadline resolves **`unacknowledged`** and the Node is
marked offline at once (`node-connection.md`). Unlike `unreachable`, it may or may not have run —
only the acknowledgement is known to be missing — so it is **never re-sent**, and the caller checks
before retrying.

### Handing back the Job

A dispatch returns its Job before the Job finishes, so a broken connection never costs the
caller its handle.

- **MCP, with the Tasks extension.** Where the client declares SEP-2663, a dispatch returns a task
  handle at once. **A Relay Job is the MCP task**: its status and results are read with
  `tasks/get`, it is cancelled with `tasks/cancel`, and it survives the connection that created
  it. The shim that provides this is ADR-0028.
- **MCP without it, and the Control API.** The Job ID is returned in the result after a short
  bounded wait — so a quick read still reads as synchronous — and the caller polls `get_job`
  (or the Jobs route) for the rest.
- **Idempotency key.** Every dispatch accepts an optional key: a tool argument on MCP, since
  SEP-2663 defines no deduplication; the `Idempotency-Key` header on the Control API. A repeat of
  the same key by the same Account within an operator-set window returns the existing Job. The
  same key with different arguments is refused. A client that re-issues a request after a broken
  stream re-sends identical arguments, key included, so the repeat is caught without the caller
  doing anything special. The Relay never infers a repeat from request content — that would
  swallow a deliberate second run.

### Job and Task lifecycle

One Job per call. One Task per resolved Node. A Task moves through three dispatch states:

```
Pending ──────────▶ Dispatched ──────────▶ Resolved
(persisted,        (sent, awaiting         (outcome recorded;
 not yet sent)      a result)               terminal)
```

Only `Dispatched` with no result is *in flight*, and that set is exactly what a Relay restart
reconciles. Three transitions never reach the wire, each going from `Pending` straight to
`Resolved`, so none is ever in flight and none is reconciled: a Task refused by the
minimum-version gate (ADR-0014), a Task cancelled before dispatch, and a Task left unsent when a
`mutate` Job halts.

### Cancellation

`cancel_job` (and MCP `tasks/cancel`) acts on a Job, and what it does depends on where each Task
has got to:

- **Pending** — marked cancelled and **never sent**.
- **Dispatched** — asked to cancel over its Tunnel, best-effort.
- **Resolved** — left alone, keeping its truthful outcome.

**Who may cancel is decided in the capability layer** (invariant 10):

- A **human** Account of `operator` or above may cancel **any** Job, not only its own — an on-call
  operator must be able to stop an AI-agent's or another operator's Job mid-incident.
- A **machine** Account of `operator` or above may cancel **only a Job it requested.** A
  jailbroken AI-agent must not be able to stop other people's rollouts. Whether a machine Account
  requested a Job is read from the requester recorded on the Job when it was created; where no
  requester is recorded, the cancel is refused — fail closed, never assumed.
- A `viewer` may not cancel.

Decided with the owner on `2026-09-17`, narrowing the `2026-09-14` rule for machine Accounts.

**The rule follows the Account's kind, not how it signed in.** An AI-agent driving a *human*
Account's OAuth session is a human Principal here, and may cancel any Job — although ADR-0024 calls
MCP-originated calls agent-grade whatever identity authorizes them. Accepted by the owner on
`2026-09-17` for now, as with the human-only Freeze engage; revisit with the Accounts work (#578).
Threat model R19.

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
what was dropped. A halted Job says so, naming the Node whose outcome halted it.

**What is retained differs by risk class, and the difference is deliberate.** A `mutate`
Task's output is kept with its audit record. A `read`'s is not: ADR-0025 records metadata
only — what was read, by whom, when — and never what came back, because *"data not written
cannot leak."* Read output reaches the caller and is not retained afterwards. Anything
implying the audit trail can reproduce a read's content is wrong, and widening it is a
one-way door.

Outcomes: `success`, `failure`, `timeout`, `denied_by_policy`, `cancelled`, `unreachable`,
`unacknowledged`, `version_refused`, `unsupported`, `quarantined`. The zero value means *not yet resolved* — a Pending or
Dispatched Task has no outcome.

Four of these never involved the Node running anything. `version_refused` is Relay-synthesized
under the ADR-0014 minimum-version gate: the Task was never sent, and its stderr explains that
upgrades flow through the customer's config management because the Relay never pushes binaries.
`unsupported` is either daemon-reported — the Operation name is not in that Node's vocabulary, so
nothing executed and Policy was never consulted — or Relay-reported for a Node excluded at
resolution because it does not report the Template; neither is a failure or a denial.
`cancelled` on a Task left unsent by a halt carries the halt as its reason.
`quarantined` is Relay-reported for a Node excluded at resolution because it carries
`relay:quarantine=on`: the Task was never sent (`quarantine-node.md`).

`unacknowledged` is the one outcome that does not know whether the Node ran anything: the Task was
sent, and the relay-daemon's receipt did not arrive within the deadline (`node-connection.md`).

## Refusals

A **refusal** stops the whole dispatch: no Job, no Tasks, and an audited reason. Distinct from
a per-Node **outcome**, where a Job did run and individual Nodes failed.

| Refusal | Cause | What the caller learns |
|---|---|---|
| Idempotency conflict | The idempotency key was already used by this Account, within the window, with different arguments | The key conflicts; use a new key for a new request |
| Frozen | An emergency Freeze is engaged (ADR-0013) | The Relay is frozen; cite the ADR and say what to do |
| Empty Selector | A dispatch with no Selector | Name the Nodes; the whole fleet must be written deliberately |
| `no_nodes_matched` | The Selector resolved to zero Nodes | The Selector as written, so a typo is visible |
| Unknown Operation | No matched Node reports this Template | Point at `list_operations` |
| All matched Nodes quarantined | Every Node the Selector resolved to is quarantined | Each Node reported `quarantined`; nothing is sent (`quarantine-node.md`) |
| Unauthorized | The Principal may not request this Action on this Selector; Raw Exec without `admin` | Denied |
| Blast cap | Resolved Node count exceeds the cap for the risk class | The class, the matched count, and the cap |
| Pending approval | The Action requires approval and none covers it | A parked dispatch with its request ID and plan hash |
| Unauthorized cancel | A `viewer`, or any Account below `operator`, asks to cancel a Job | Denied; the Job continues |
| Machine cancels another's Job | A machine Account asks to cancel a Job it did not request, or one with no recorded requester | Denied, audited; the Job continues |
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
- **Invariant 4** (ADR-0004) — at-most-once, held by the ordering above, and now also against a
  caller's re-issued request by the idempotency key.
- **Invariant 5** (ADR-0004) — the cap is enforced **here, on the Relay, before dispatch**, on
  the Nodes remaining after exclusion. Not on the Node, not by the caller.
- **Invariant 10** (ADR-0009/0010/0026) — every interface is an adapter over this one layer,
  narrowing only. The unexported dispatch constructor is the compile-enforced half; `no_dispatch`
  covers the Console. Who may cancel a Job is now decided here too, not per surface.
- **Invariant 12** (ADR-0011) — this pipeline **never evaluates Policy.** Not for real
  dispatch, not for hypotheticals. A matched-but-disconnected Node yields a Relay-side
  `unknown(offline)` conclusion rather than a guess.
- **Invariant 13** (ADR-0012) — the risk class is declared contract in `/proto` and selects
  the cap; Raw Exec always takes the mutate cap.
- **Invariant 7** (ADR-0006/0020/0034) — binds through Selector resolution: the security lane
  targets `relay:` and only `relay:`.
- **ADR-0004 — needs amending.** Halt-on-first-failure for `mutate` Jobs, and client-level
  idempotency above Task-ID dedup, are not in it.
- **ADR-0013** — cancellation's contract: cancel only ever asks, and the Freeze is the
  outermost gate on this path.
- **ADR-0014** — the minimum-version gate refuses a Task to an outdated Node before it is sent.
- **ADR-0025** — read output is not retained. It governs what the audit trail keeps, and
  widening it is a one-way door.
- **ADR-0027** — the approval gate's position in the pipeline.
- **ADR-0028** — the MCP Tasks extension shim, through which a Relay Job is an MCP task.

Referenced above but governing elsewhere: ADR-0005 (transport), ADR-0018 (canonical path
matching, inside `file.read`), ADR-0022 (the shipped default Policy, which is why Raw Exec is
off out of the box), ADR-0026 (the Console's execution surface).

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
- A zero-match dispatch is refused as `no_nodes_matched` with no Job.
- An empty Selector is refused for dispatch.
- Nodes not reporting a Template are excluded before the cap and reported `unsupported`.
- A `mutate` Job halts on its first `failure`, `timeout` or `unacknowledged`; unsent Tasks resolve `cancelled`; a
  `read` Job never halts; `denied_by_policy`, `unsupported` and `unreachable` do not halt.
- A dispatched Task not acknowledged within the deadline resolves `unacknowledged`, is never
  re-sent, and marks the Node offline.
- A dispatch hands back its Job before finishing; a Relay Job is an MCP task where the client
  supports SEP-2663.
- A repeated idempotency key returns the existing Job; the same key with different arguments is
  refused.
- Only `operator` or above may cancel a Job; a `viewer` is refused. A human at that floor may cancel any Job; a machine Account only a Job recorded as requested by it, and a Job with no recorded requester is refused to a machine.
- Raw Exec requires `admin` on the Relay.

This list is compiled by hand and will be wrong again; `make docs-check` verifies only that a
cited test exists, never that the list is complete.

### Performance

| Characteristic | Contract | Measured by |
|---|---|---|
| Fan-out | Sequential — one Node at a time, blocking; a Job's wall-clock is the sum of its Tasks | *(none)* |
| Read blast cap | 10,000 Nodes by default, operator-set at startup, inclusive maximum | *(none)* |
| Mutate blast cap | 100 Nodes by default; Raw Exec always takes this lane | *(none)* |
| Task timeout | Per-Operation, declared and sent on the wire; a caller may only shorten it; no Job-level timeout | *(none)* |
| Task output | Size-capped by the daemon before the wire, `truncated` flagged on the result | *(none)* |
| Handing back the Job | The Job ID is returned before the Job finishes, within a short bounded wait | *(none)* |

There are **no benchmarks in this repository** — Go or Rust. Every row above is a contract
nothing measures. That is the honest state, and it is most conspicuous for fan-out, where the
sequential contract and the 10,000-Node read cap multiply.

## Out of scope

- **Policy evaluation** — the daemon's live engine, always (invariant 12). What Policy allows,
  including Raw Exec's gate, is `policy.md`.
- **The Operation vocabulary and the Template language** — `operations-and-templates.md`, with
  `/proto` as the source of truth (invariant 8).
- **Policy preflight and hypotheticals** — `policy-preflight.md`. A preflight carries no Task ID,
  sends no Task, and cannot be deduped into execution. Called *plan mode* until ADR-0038.
- **The Plan — an approved route of execution** — `plan.md`. A Plan is the object *above* a Job:
  each of its steps is an ordinary Job created by this spec's dispatch path, with its own cap
  check, its own at-most-once Tasks and its own audit identity. There is no second dispatch path
  and a Plan step is not a **Stage** (ADR-0038). Staged rollouts belong there, not here.
- **Approval decisions, grants and scope** — `approval.md`. This spec covers only the gate's
  position and the park.
- **Engaging and releasing the Freeze** — `freeze.md`. This spec covers only the Freeze gate as
  a refusal on the dispatch path. Job cancellation is *in* scope here: it acts on a Job this
  capability created, and the engine owns it.
- **Label namespaces, the Selector grammar, and `state:` derivation** —
  `selectors-and-labels.md`. This spec consumes a resolved Node set; it does not define how one
  is addressed.
- **Getting a secret onto a Node** — secret distribution — not yet designed (Future work in `quarantine-node.md`).
- **Querying Jobs, Tasks and the audit trail after the fact** — `audit-and-read-lane.md`.
- **Retry, scheduling, store-and-forward** — deliberately absent; re-targeting is the caller's
  decision.

## Accepted residual risk

- **An AI-agent in a human Account's OAuth session cancels as a human.** Machine limits key on the
  Account's kind, so a model driving a human operator's OAuth session may cancel any Job. Accepted
  on `2026-09-17` (R19); revisit with #578.

- **A careless caller can still put a secret into the audit trail.** The contract that
  arguments are never secrets is only a contract; nothing detects a credential passed as an
  argument or in Raw Exec argv, and it is recorded verbatim.
- **Sequential fan-out is slow at scale.** A fleet-wide read is the sum of its round-trips.

## Future work

Wanted, deliberately not in the first pass. Named so each is neither re-litigated nor lost;
none is a commitment to an order.

- **Concurrent fan-out.** A Job's Tasks dispatched concurrently up to an operator-set limit,
  with a smaller limit for `mutate` than for `read`, so a fleet-wide read is not the sum of
  thousands of round-trips. At-most-once ordering is unchanged by it: every Task is still
  persisted before any is sent.
- **Protecting secrets a caller passes by mistake.** Candidates, none chosen: a `secret` slot
  type audited as a redaction plus a hash (and its process-list exposure on the Node); detection
  that refuses or flags a dispatch whose arguments look like credentials; and how either relates
  to secret distribution, once designed.

## Open questions

None open. The four previously listed — secrets in arguments, #392's re-executable dispatch, the
zero-match Job, and cancellation authorization — were settled with the owner on `2026-09-14`, and
whether to split this spec was answered: it stays one file.

## History

- `2026-09-22` — the Job row now records its requester (Account ID, name, and kind) in the
  same write that creates the Job, before any Task is dispatched; Job queries read the
  requester from the Job row, with the audit-row join kept only for the audit trail. Rows
  written before this change carry no requester and read back as none, never inferred. This is
  the storage the Cancellation section's `2026-09-17` machine-Account rule already described
  (#616). Spec is still `aspirational`; proof not recorded per the legacy-spec rule.
- `2026-09-17` — a zero-match dispatch is now refused as `no_nodes_matched` before any Job
  exists on every dispatch surface and audited as a refusal, while a Policy preflight reports
  it as `would_be_rejected` (#571). Spec is still `aspirational`; proof not recorded per the
  legacy-spec rule.
- `2026-09-17` — a machine Account may cancel only a Job it requested; humans at `operator` or above still cancel any Job. Requires the requester recorded on the Job at creation (#614, and its prerequisite issue).
- `2026-09-17` — Console adapter for `cancel_job` shipped: Job detail and the Agents stream
  gained a Cancel control over the same capability-layer cancel, gated `operator`-or-above
  (#595). Spec is still `aspirational`; proof not recorded per the legacy-spec rule.
- `2026-09-14` — worked through with the owner. Fan-out stays sequential (concurrent is future
  work); a `mutate` Job halts on its first failure; a dispatch hands back its Job before finishing,
  as an MCP task where the client supports it, with an idempotency key so a re-issued request
  returns the same Job (#392); a zero-match or empty-Selector dispatch is refused; Nodes not
  reporting a Template are excluded before the cap; arguments are never secrets by contract;
  cancel is authorized in the capability layer for `operator` and above; Raw Exec stays
  `admin`-only, offline stays fail-fast, no Job-level timeout, read output not retained, Freeze
  before authorization, and the spec stays one file. The three-tier table follows the Policy and
  Template decisions.
- `2026-09-12` — ADR-0038: out-of-scope now names `policy-preflight.md` (renamed from
  `plan-mode.md`) and `plan.md`. A Plan step is an ordinary Job created by this spec's dispatch
  path — there is no second dispatch path.
- `2026-09-10` — Corrects what the audit trail retains: a `read`'s output is **not** retained
  (ADR-0025), where this spec previously said all output was kept whole. Adds fan-out, ordering
  and timeouts; the Job/Task lifecycle; cancellation, moved in from the Freeze spec; zero-match
  behaviour; and the proof and performance tables.
- `2026-09-08` — Gains *The three execution tiers*, which invariant 1 now delegates to for
  per-tier mechanism (ADR-0001 amendment, same date).
- `2026-09-08` — First written, from the capability layer as it stands. Absorbs the milestone
  acceptance criteria that ~15 tests cited as "the ROADMAP acceptance line"; those tests now cite
  this file, and `ROADMAP.md` was retired on 2026-09-12.
