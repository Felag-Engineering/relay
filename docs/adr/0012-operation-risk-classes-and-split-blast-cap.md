# Operations declare a risk class (read | mutate); the blast-radius cap splits by class

**Status:** Accepted; amended by ADR-0010 and ADR-0042.

Every Operation in the vocabulary declares a **risk class** in `/proto` alongside its
definition: **`read`** (cannot change Node state) or **`mutate`** (can). The Relay's
blast-radius cap (ADR-0004) becomes two file-configured caps: a generous **read-cap**
and a small **mutate-cap**, each enforced before dispatch by the Job engine. **Raw Exec
is always `mutate`** — arbitrary commands are unclassifiable, so they take the strict
lane by definition.

## Why

The AI-agent's dominant workload is observation, and a single cap sized for the danger of
`service.restart` throttles routine fleet-wide inventory (`system.facts` across 500 Nodes).
Friction on the safe path nudges the AI-agent toward workarounds; the cheap fix is to let the
guardrail know which requests are safe to fan out.

## Decisions

- The class lives in the vocabulary metadata in `/proto` (single source of truth,
  ADR-0007) and is exposed through `list_operations`, so the AI-agent can see which
  tools are freely fan-out-able.
- **Risk class is a blast-radius classification, not a trust classification.** Policy
  is untouched: deny-by-default and argument-level constraints apply identically to both
  classes. `read` Operations keep a cap, not an exemption, because fleet-wide `file.read` is
  a mass-exfiltration primitive; it is just a different number.
- Both caps are Relay-config, file-only — like the single cap they replace, the API
  cannot raise them (ADR-0010).

## Considered Options

- **Single cap (status quo, ADR-0004).** Simpler, but forces one number to serve two
  masters: sized for mutation danger it breaks inventory; sized for inventory it
  guards nothing. Rejected.
- **Exempting reads from any cap.** Ergonomic, but ignores that read fan-out has its
  own abuse class (exfiltration at scale, thundering-herd load). Rejected.
- **Finer class ladders (read/restart/install/destroy…).** More precision, more
  arguing about placement; two classes capture the load-bearing distinction. Revisit
  only with evidence.

## Consequences

- Every Operation carries a class (at the time of this decision, `system.facts` and
  `file.read` were `read` and `service.restart` was `mutate`).
- Misclassifying a new Operation as `read` weakens the mutate guardrail, so vocabulary review
  treats the class as security-relevant (it is `/proto` contract, which always escalates to a
  human).
- Audit and the Console can foreground mutations cheaply, since every Job now carries
  its class.

## Amendment (2026-09-15): the caps are operator settings, not startup configuration

This ADR's decision is unchanged: risk class is `/proto` contract, the cap is chosen by class,
Raw Exec always takes the mutate cap, and the cap is enforced on the Relay before dispatch
(invariant 5).

What changed is **where the two values are set**: no longer startup configuration in a
root-owned file, but operator settings in the Relay's store, changed by a human `admin` in the
Console with step-up re-authentication, audited, and effective on the next dispatch. No MCP
tool or Control API route writes them. The ADR-0010 amendment of the same date gives the
reasoning, the tier split, and the accepted residual risk; `docs/specs/relay-configuration.md`
gives the behaviour.

## Amendment (2026-10-02): amended by ADR-0042 — a Template's class is Node-reported

The class still chooses the cap, Raw Exec is still always `mutate`, and a Native's class is
still `/proto` contract. A Template's class is not: it is declared in each Node's Policy and
reported by that Node, so ADR-0042 resolves it in the capability layer over the reporting
Nodes (`read` only if every one reports `read`, otherwise `mutate`) and records the residual
risk of believing them.

Invariant 13 is amended in place on the same date to match: the class is security-relevant
contract no caller can set or loosen, and where Nodes report it, a dispatch takes the most
restrictive class the Nodes it reaches report.
