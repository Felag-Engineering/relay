# Execution

**Status:** designed, not built, as of `2026-11-16`.
**Claim prefix:** `EX`
**Governed by:** ADR-0054, ADR-0001, ADR-0011, ADR-0012, ADR-0013, ADR-0014, ADR-0021, ADR-0025,
ADR-0027, ADR-0042, ADR-0047, ADR-0049, ADR-0052; invariants 1, 4, 5, 10, 11, 12, 13, 14.

## Purpose

Execution turns "run this on the fleet" into work on each targeted server and the results back.
It is the one path every caller goes through to act on a server, which is why an AI-agent that
cannot be trusted with a fleet may still drive one. Before anything is sent, Relay works out
exactly which servers are targeted, checks the caller may ask, caps how many servers one
request can reach, and records what happened. A change that starts failing is sent to no
further servers, and nothing runs twice. What each server will actually do is decided on that
server, by rules kept there (its Policy), after everything here has passed.

## Surfaces

| Surface | How it is reached |
|---|---|
| **MCP** | `run_operation` (typed Operation), `raw_exec` (argv), `get_job`, `cancel_job`. |
| **Control API** | `POST /api/v1/operations`, `POST /api/v1/raw-exec`, `GET /api/v1/jobs/{id}`, `POST /api/v1/jobs/{id}/cancel`. |
| **Admin Console** | Starts no dispatch (ADR-0052); it shows Jobs (`audit-and-read-lane.md`) and may cancel one under EX-37. |
| **Node plane** | Each Task travels down its Node's stream (`node-connection.md`). |

## Behaviour

### One pipeline

- **EX-1** MCP and the Control API reach execution through one capability-layer entry point.
  Its dispatch type and constructor are unexported, so a package outside the layer that builds a
  dispatch fails to compile, and a structural guard per adapter forbids naming them.
- **EX-2** The Console names no dispatch entry point; its structural guard forbids every one.
- **EX-3** One call runs its stages in this order: the Freeze gate, the empty-Selector refusal,
  Selector resolution, Template resolution (EX-6, EX-15), authorization, the idempotency lookup,
  the zero-match refusal, the Template refusals (EX-51, EX-61), the blast-radius cap, the
  approval gate, dispatch, audit. A frozen Relay or an unauthorized caller therefore learns
  nothing from a key lookup, a match count or a Template's slots.
- **EX-4** Each stage can only refuse, park or pass the call on; none widens what a later stage
  allows.
- **EX-5** Selector resolution resolves against the registry across the four label namespaces,
  and evaluates `state:` terms at resolution time (`selectors-and-labels.md`).
- **EX-6** For a Template Operation, matched Nodes that do not report the Template are excluded
  before authorization and the cap, appear in the result as `unsupported`, and are never sent a
  Task.
- **EX-7** Caller-asserted attribution is removed from the context before the authorization
  decision, so authorization never reads a value the caller supplied about itself.
- **EX-8** Raw Exec is this pipeline carrying an argv, never a path of its own, and takes the
  mutate risk class whatever the adapter passes.
- **EX-9** On MCP, a dispatch may carry an idempotency key. A repeat of the key by the same
  Account within 24 hours returns the existing Job and dispatches nothing; another Account's use
  of the same key is a separate request, and after 24 hours the key dispatches afresh. The
  window is a constant, and a repeat is audited as a read of the Job.
- **EX-10** The approval gate runs after the cap and before any Task exists; what a park leaves
  and how it is audited are `approval.md`'s.
- **EX-11** Every dispatch, including one whose dispatcher errored partway, has its outcome
  written to the audit trail.
- **EX-68** A dispatch that runs its Job to the end before returning reports a failed outcome
  write to the caller beside the results. One that returns its Job ID once the Tasks are stored,
  whether or not it then waits, only records a failed write in the Relay's error log (R57).
- **EX-12** The execution path never evaluates Policy (invariant 12). What a Node runs is decided
  by its own daemon after every stage here has passed.

### The blast-radius cap

- **EX-13** The Relay enforces the cap before dispatch, on the count of Nodes left after
  Template exclusion (invariant 5).
- **EX-14** There are two caps, chosen by risk class: read, default 10,000 Nodes, and mutate,
  default 100. The cap is an inclusive maximum, and an unspecified class takes the mutate cap.
- **EX-15** A Template dispatch takes the cap of the most restrictive class the reached Nodes
  report (ADR-0042).
- **EX-16** No session can change a cap (`relay-configuration.md`), and a non-positive value at
  the cap check is clamped to the default, never treated as unlimited.

### The three execution tiers

- **EX-17** No Native Operation (`operations-and-templates.md`) runs a shell: any process one
  starts has an argv whose shape the daemon's own code fixes, each argument value its own
  element, and the daemon starts processes only from its executor.
- **EX-18** A Template body runs under `/bin/sh -c`, and every placeholder becomes a quoted
  positional parameter whose value follows as its own argv element, so no slot value is ever
  part of the text the shell parses.
- **EX-19** A placeholder may stand only as a whole word of a top-level command. One in quotes,
  nested, or in a code-running position decidable from the body makes the whole Template set
  unloadable; an undecidable one is a `policy check` warning and an error under `--strict`.
- **EX-20** Raw Exec runs the caller's argv with no shell, so the caller chooses which binary
  runs, not what runs after it. Its gate on the Node is `policy.md`'s.
- **EX-21** Arguments and Raw Exec argv are the record of what was done and are audited
  verbatim; by contract a caller never passes a secret in one, and no slot type holds one (R55).

### Fan-out, timeouts and halts

- **EX-22** A call makes one Job, and the Job one Task per resolved Node. At most 16 Tasks of one
  Job are in flight at once, a built-in constant, in no promised order.
- **EX-23** The daemon runs one `mutate` Task at a time per Node and up to 4 `read` Tasks at once,
  a constant, classing each Task from its own vocabulary and Raw Exec as mutate.
- **EX-24** A Task carries the timeout the caller asked for. The daemon applies 30 seconds when
  none is asked for and caps any longer request at 300 seconds. Its clock starts when the daemon
  receives the Task, so a Task can time out while queued. There is no Job-level timeout.
- **EX-25** A Task that overruns its timeout resolves `timeout`, an outcome recorded against
  that Node.
- **EX-26** A `mutate` Job halts on its first `failure` or `timeout`: no further Task is sent,
  every unsent Task resolves `cancelled` with the halt as its reason, and Tasks already in flight
  finish with their real outcomes (R56), except across a restart (EX-28). The Job's result names
  the halting Node and why.
- **EX-27** `denied_by_policy`, `unsupported`, `unreachable` and `version_refused` do not halt a
  Job, and a `read` Job never halts.
- **EX-28** A halt survives a Relay restart. Before the Relay serves, it sends no Task of a halted
  Job: a sibling still `Pending` resolves `cancelled` with the halt as its reason, and one
  `Dispatched` resolves `failure` with exit code -1 and stderr saying it may have run (R56). Each
  outcome is audited.

### At most once

- **EX-29** Every Task of a Job is written to the store as `Pending`, under its own unique ID,
  in one transaction with an audit record of the dispatch's intent, before any Task is
  dispatched. That record names the caller, the Selector, the Operation with its arguments and
  the number of Nodes; if the transaction fails, nothing is dispatched.
- **EX-30** A Task is marked `Dispatched` in the store before it is sent, so a send error leaves
  it in flight, never resolved.
- **EX-31** On restart the Relay re-sends each Task `Dispatched` without a result, for its
  result, except a halted Job's (EX-28); re-sending is safe because the daemon dedups by Task ID
  (`daemon-installation.md`).
- **EX-32** No `Pending` Task survives a restart into execution, and `unreachable` and
  `version_refused` Tasks are terminal and never reconciled.
- **EX-33** A Task for a disconnected Node is never sent, queued or retried: it resolves
  `unreachable` at once, and a reconnecting Node never runs it.
- **EX-34** A Task moves `Pending` → `Dispatched` → `Resolved`. It resolves straight from
  `Pending`, never in flight, when it is `unreachable`, `version_refused`, excluded under EX-6,
  cancelled before dispatch, or left unsent by a halt.
- **EX-62** A `Dispatched` Task whose Node disconnects while the Relay is serving, before its
  result arrives, resolves `failure`, exit code -1, with stderr saying whether it ran is unknown
  (R56). It is never re-sent, and it halts a `mutate` Job.

### Handing back the Job

- **EX-35** An MCP dispatch returns its Job ID once the Tasks are stored, after an optional wait
  of up to 300 seconds (none by default), and the caller reads the rest with `get_job`.
- **EX-36** A Control API dispatch returns when every Task of the Job is resolved.

### Cancellation

- **EX-37** Cancelling a Job marks each `Pending` Task `cancelled` and never sends it, asks the
  daemon to cancel each `Dispatched` Task, best effort, and leaves each resolved Task alone.
- **EX-38** Cancel only ever asks: a Task that resolved first keeps its real outcome, and one that
  moves from `Pending` to `Dispatched` while the cancel runs is sent and runs to completion.
- **EX-39** Who may cancel is decided in the capability layer. A human Account at `operator` or
  above may cancel any Job; a machine Account at `operator` or above only a Job whose verified
  requester it is. The rule follows the Account's kind, not how it signed in (R19).
- **EX-40** A cancel writes its own audit row naming who asked and the Job, beside the Tasks'
  `cancelled` outcomes. A cancel that errors, for an unknown Job say, writes none; a refused one
  is audited as a refusal (EX-56).

### What the caller gets back

- **EX-41** A result has one row per Node, each with the Node, its outcome, exit code, stdout,
  stderr, truncation and duration, and the Job ID once for the Job.
- **EX-42** The daemon caps stdout and stderr at 1 MiB each before the wire, and a capped result
  carries a `truncated` flag; the Relay never sees what was dropped.
- **EX-43** The outcomes are `success`, `failure`, `timeout`, `denied_by_policy`, `cancelled`,
  `unreachable`, `version_refused` and `unsupported`. A `Pending` or `Dispatched` Task has none.
  A call the daemon refuses as malformed, or for a risk-class mismatch, resolves `failure`, never
  `denied_by_policy`.
- **EX-44** `version_refused` is written by the Relay under the minimum-version gate (ADR-0014),
  for a Task never sent, with stderr saying upgrades flow through the customer's configuration
  management. `unsupported` is reported by the daemon for an Operation not in its vocabulary,
  or by the Relay under EX-6.
- **EX-45** Read output is held only in its Task row, for `get_job`; what the audit record keeps
  of each class is `audit-and-read-lane.md`'s (ADR-0025).

### Seams

- **EX-46** A dispatcher that executes cannot be wired with the allow-all Authorizer, the no-op
  cap checker, the no-op audit sink or the no-op Freeze store: construction refuses each.
- **EX-47** The capability layer imports no wire-protocol or database package; a lint rule
  enforces it.

## Refusals

A refusal in the capability layer stops the whole dispatch: no Job, no Task, and an audited
reason. EX-63 and EX-65 are refused earlier, by the adapter, and leave no audit record. A refusal
differs from an outcome, where a Job ran and a Node failed; a cancel refusal leaves the Job running.

- **EX-48** A frozen Relay refuses every new dispatch of every risk class, citing ADR-0013 and
  saying it lasts until an admin releases the Freeze. Failing closed on an unreadable Freeze
  state, and what the order discloses, are `freeze.md`'s.
- **EX-49** A dispatch with an empty Selector is refused before anything resolves, on every
  surface (`selectors-and-labels.md`).
- **EX-50** A Selector matching no Node is refused as `no_nodes_matched`.
- **EX-51** A Template no matched Node reports is refused, pointing at `list_operations`.
- **EX-61** A Template call whose reporting Nodes disagree on its slots is refused as a vocabulary
  disagreement naming two Nodes that disagree; one whose argument names do not match the slots is
  refused as malformed. Both are audited.
- **EX-63** A Native call with an unknown or missing argument name is refused by the MCP or
  Control API adapter as an invalid request, before the pipeline runs, and is not audited.
- **EX-65** A Raw Exec call with an empty argv is refused by the MCP or Control API adapter as an
  invalid request, before the pipeline runs, and is not audited.
- **EX-52** A Principal whose role does not permit the Action is refused
  (`accounts-and-access.md`); Raw Exec needs `admin`.
- **EX-53** An idempotency key reused by the same Account within its window with different
  arguments is refused, audited: a new request needs a new key.
- **EX-54** A dispatch over the cap for its risk class is refused, naming the class, the matched
  count and the cap.
- **EX-55** An approval check that fails refuses the dispatch: the gate fails closed.
- **EX-56** A cancel below `operator` is refused before any Task is touched. A machine Account's
  cancel of a Job it did not request, or of one with no verified requester, is refused and
  audited, and the Job continues.

## Designed, not built

| Claim | Statement | Milestone |
|---|---|---|
| EX-57 | A Control API dispatch returns its Job ID once the Tasks are stored, after an optional bounded wait, and the caller reads the rest from the Jobs route. Replaces EX-36 when promoted. | v0.2.2 |
| EX-58 | A Control API dispatch accepts an `Idempotency-Key` header under the rule of EX-9 and EX-53. | v0.2.2 |
| EX-59 | A dispatch asking for a Task timeout above 300 seconds is refused in the capability layer, at the stage of EX-61, naming the ceiling. | v0.2.2 |
| EX-60 | The `list_operations` description tells the caller that arguments and Raw Exec argv are audited verbatim and must never carry a secret. | v0.2.2 |
| EX-64 | A Native call with an unknown or missing argument name is refused as malformed in the capability layer, at the stage of EX-61, and the refusal is audited. Replaces EX-63 when promoted. | v0.2.2 |
| EX-66 | A dispatch whose outcome write fails after it has returned its Job ID records the failure on the Job, and `get_job` and the Jobs route show it. Replaces EX-68 when promoted. | v0.2.2 |
| EX-67 | A Raw Exec call with an empty argv is refused as malformed in the capability layer, at the stage of EX-61, and the refusal is audited. Replaces EX-65 when promoted. | v0.2.2 |

## Out of scope

- **Policy, including Raw Exec's gate on the Node**: `policy.md`.
- **The Operation vocabulary, the Template file and its slot types**: `operations-and-templates.md`.
- **Policy preflight, including `unknown(offline)`**: `policy-preflight.md`.
- **Sequencing several dispatches**: the harness's job (ADR-0049).
- **Approval decisions**: `approval.md`; **engaging and releasing the Freeze**: `freeze.md`.
- **Label namespaces and the Selector grammar**: `selectors-and-labels.md`.
- **The daemon's dedup markers**: `daemon-installation.md`.
- **Querying Jobs, Tasks and the audit trail, and what a query strips**: `audit-and-read-lane.md`;
  clearing read output from Task rows after a fixed time, #1345.
- **A per-Operation timeout, a configurable in-flight limit, failure tolerance and retries**:
  `roadmap: relay/failure-policy-and-retries`. A retry would be a new Task with a new ID.
- **An acknowledgement deadline and an `unacknowledged` outcome**:
  `roadmap: relay/fast-failure-and-fleet-admission`.
- **Quarantine and a `quarantined` outcome**: `roadmap: relay/quarantine`.
- **MCP task handles for long-running Jobs**: `roadmap: relay/mcp-tasks-for-long-running-jobs`.
- **Editing the caps in the Console**: `roadmap: relay/settings-in-the-console`.
- **Executing from the Console**: `roadmap: relay/console-execution-for-skills`.
- **Getting a secret onto a Node, protecting one a caller passes by mistake, and a measured
  fan-out rate**: `roadmap: relay/research/spec-future-work/execution`.

## Proof

<!-- proof:begin -->
| Claim | Proven by | Seam |
|---|---|---|

Unproven: EX-1, EX-2, EX-3, EX-4, EX-5, EX-6, EX-7, EX-8, EX-9, EX-10, EX-11, EX-12, EX-13, EX-14, EX-15, EX-16, EX-17, EX-18, EX-19, EX-20, EX-21, EX-22, EX-23, EX-24, EX-25, EX-26, EX-27, EX-28, EX-29, EX-30, EX-31, EX-32, EX-33, EX-34, EX-35, EX-36, EX-37, EX-38, EX-39, EX-40, EX-41, EX-42, EX-43, EX-44, EX-45, EX-46, EX-47, EX-48, EX-49, EX-50, EX-51, EX-52, EX-53, EX-54, EX-55, EX-56, EX-61, EX-62, EX-63, EX-65, EX-68.
<!-- proof:end -->

## Retired

None.
