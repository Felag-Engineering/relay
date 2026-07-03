# Operations declare a risk class (read | mutate); the blast-radius cap splits by class

Every Operation in the vocabulary declares a **risk class** in `/proto` alongside its
definition: **`read`** (cannot change Node state) or **`mutate`** (can). The Relay's
blast-radius cap (ADR-0004) becomes two file-configured caps: a generous **read-cap**
and a small **mutate-cap**, each enforced before dispatch by the Job engine. **Raw Exec
is always `mutate`** — arbitrary commands are unclassifiable, so they take the strict
lane by definition.

## Why

The AI-agent's dominant workload is observation — facts, status, reading state — and a
single cap sized for the danger of `service.restart` throttles fleet-wide inventory
(`system.facts` across 500 Nodes), which is legitimate and routine. Friction on the
safe path nudges the AI-agent toward workarounds; the cheap fix is to let the guardrail
know which requests are safe to fan out.

## Decisions

- The class lives in the vocabulary metadata in `/proto` (single source of truth,
  ADR-0007) and is exposed through `list_operations`, so the AI-agent can see which
  tools are freely fan-out-able.
- **Risk class is a blast-radius classification, not a trust classification.** Policy
  is untouched: deny-by-default and argument-level constraints apply identically to
  both classes. `read` Operations keep a cap (not an exemption) because fleet-wide
  `file.read` is a mass-exfiltration primitive; it is simply a different number than
  the mutate-cap.
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

- Class declarations land with the Policy & Native Operations milestone (three Operations today —
  `system.facts`/`file.read` are `read`, `service.restart` is `mutate`); the split cap
  lands with the Job-engine milestone.
- Misclassifying a new Operation as `read` weakens the mutate guardrail — vocabulary
  review must treat the class as security-relevant (it is part of the `/proto`
  contract, which always escalates to a human in the dev-loop).
- Audit and the Console can foreground mutations cheaply, since every Job now carries
  its class.
