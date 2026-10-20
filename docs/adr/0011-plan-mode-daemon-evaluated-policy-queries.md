# Policy preflight: daemon-evaluated Policy queries, structurally separate from execution

**Status:** Accepted; amended by ADR-0038.

> **Amended by ADR-0038 (2026-09-12; recorded here 2026-09-20).** The mechanism this ADR
> decides is now called the **Policy preflight**; **Plan** names an approved route of
> execution. Read the body's "plan" and "the Plan" as *preflight*. ADR-0038 withdraws the
> `terraform plan` / check-mode framing: a preflight asks Policy a question and never reaches
> an executor, so it is not a dry run. The wire option is still spelled `plan`.

`run_operation` and `raw_exec` (MCP and Control API) accept a **plan** option: the Relay
resolves the Selector, checks authorization and the blast-radius cap, and asks each
matched daemon whether its Policy *would* allow the action — executing nothing. The
per-Node verdicts (`allow | deny(rule) | unknown(offline)`) plus the would-be fan-out
size are returned as the Plan. This is `terraform plan` / Ansible check-mode for the
fleet: a safe probe, so the AI-agent need not learn Policy boundaries by triggering real
executions.

## Decisions

- **The daemon evaluates the hypothetical.** A read-only `PolicyQuery` → `PolicyVerdict`
  message pair on the existing stream is answered by the daemon's real enforcement engine,
  the same code that decides at execution time. The Relay never computes verdicts itself.
- **A distinct message type, not a `dry_run` flag on `TaskRequest`.** A flag means one
  dropped or defaulted bit turns a plan into real execution; a separate message type
  has no execution code path at all. `PolicyQuery` carries no Task ID and cannot be
  deduped into or confused with a Task.
- **Offline Nodes yield `unknown(offline)`,** never a guess from cached state.
- **A Plan never hard-fails on guardrails; it reports.** A fan-out exceeding the blast cap
  returns `would-be-rejected: exceeds cap` with the resolved count rather than an error,
  because the point is telling the caller what *would* happen.

## Considered Options

- **Relay-side evaluation from reported `PolicySnapshot`s.** No wire change and works
  offline, but needs a second Policy evaluator (in Go) that can drift from the Rust truth
  (regex dialects, stale snapshots). A plan that says "allow" followed by a real "deny"
  teaches the AI-agent to distrust Plans. Rejected; ADR-0002/0007's asymmetry stands: Policy
  is *evaluated* only on the Node, merely *displayed* centrally.

## Consequences

- Proto gains `PolicyQuery`/`PolicyVerdict`, a second entry point into the Policy engine.
- Verdicts are point-in-time advice, not reservations: Policy may change between plan and
  apply. A Plan is advisory, like the System Model (ADR-0008), and never substitutes for
  enforcement at execution time.
- Denied verdicts include the deciding rule, which is more Policy detail than a failed
  execution reveals; acceptable because `describe_node` already exposes effective
  Policy to authorized callers (ADR-0003).
