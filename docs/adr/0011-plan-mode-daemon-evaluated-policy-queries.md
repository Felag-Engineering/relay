# Policy preflight: daemon-evaluated Policy queries, structurally separate from execution

**Status:** Accepted; amended by ADR-0038.

> **Amended by ADR-0038 (2026-09-12; recorded here 2026-09-20).** The mechanism this ADR
> decides is now called the **Policy preflight**; the word **Plan** names an approved route of
> execution. The body below keeps its original wording ("plan", "the Plan") for the preview;
> read it as *preflight*. The `terraform plan` / check-mode framing is withdrawn by ADR-0038 —
> a preflight asks Policy a question and never reaches an executor; it is not a dry run of one.
> The wire option is still spelled `plan` until the code follows.

`run_operation` and `raw_exec` (MCP and Control API) accept a **plan** option: the Relay
resolves the Selector, checks authorization and the blast-radius cap, and asks each
matched daemon whether its Policy *would* allow the action — executing nothing. The
per-Node verdicts (`allow | deny(rule) | unknown(offline)`) plus the would-be fan-out
size are returned as the Plan. This is `terraform plan` / Ansible check-mode for the
fleet, and it gives the AI-agent a safe probe primitive instead of learning Policy
boundaries by triggering real executions.

## Decisions

- **The daemon evaluates the hypothetical.** A new read-only `PolicyQuery` →
  `PolicyVerdict` message pair on the existing stream is answered by the daemon's real
  enforcement engine — the same code that will decide at execution time. The Relay
  never computes verdicts itself.
- **A distinct message type, not a `dry_run` flag on `TaskRequest`.** A flag means one
  dropped or defaulted bit turns a plan into real execution; a separate message type
  has no execution code path at all. `PolicyQuery` carries no Task ID and cannot be
  deduped into or confused with a Task.
- **Offline Nodes yield `unknown(offline)`,** never a guess from cached state.
- **A Plan never hard-fails on guardrails — it reports.** A fan-out exceeding the
  applicable blast cap returns `would-be-rejected: exceeds cap` with the resolved
  count, rather than an error: the entire point is telling the caller what *would*
  happen.

## Considered Options

- **Relay-side evaluation from reported `PolicySnapshot`s.** No wire change and works
  offline, but requires a second Policy evaluator (in Go) that can drift from the Rust
  truth — regex dialect differences, stale snapshots. A plan that says "allow" followed
  by a real "deny" destroys the feature's value: the AI-agent learns to distrust Plans.
  Rejected; ADR-0002/0007's asymmetry stands — Policy is *evaluated* only on the Node,
  merely *displayed* centrally.

## Consequences

- Proto: `PolicyQuery`/`PolicyVerdict` land with the Policy-engine milestone (a second
  entry point into it); the `plan` option on the tool surface lands with the Control
  Surfaces milestone.
- Verdicts are point-in-time advice, not reservations: Policy may change between plan
  and apply. A Plan is advisory, like the System Model (ADR-0008) — it never gates or
  substitutes for enforcement at execution time.
- Denied verdicts include the deciding rule, which is more Policy detail than a failed
  execution reveals; acceptable because `describe_node` already exposes effective
  Policy to authorized callers (ADR-0003).
