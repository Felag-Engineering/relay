# Structured Operations as the primary primitive, with a regex-gated Raw Exec escape hatch

The relay-daemon's primary execution primitive is a fixed vocabulary of structured,
typed **Operations** (e.g. restart a service, read a file, install a package) rather
than arbitrary shell command strings. For actions the vocabulary cannot express, a
**Raw Exec** escape hatch allows arbitrary commands, but only when they match a
Node's regex-based **Policy**.

## Considered Options

- **Arbitrary shell strings as the primitive.** Maximally flexible and a natural fit
  for an AI orchestrator, but it makes Policy a string-matching problem. Safely
  matching shell strings is notoriously defeatable (quoting tricks, command
  substitution, symlinks, encode-then-pipe-to-sh), so defense-in-depth built on it
  is weak.
- **Structured Operations only.** Provable control, but cannot express the long tail
  of real administrative work — defeating the point of an open-ended AI-agent.
- **Structured Operations + regex-gated Raw Exec (chosen).** Typed vocabulary gives
  provable control for the common case; the escape hatch preserves open-endedness
  while remaining gated, exceptional, and audited.

## Execution tiers

Execution forms a three-tier model ordered by trust:

1. **Native Operations** (v1, built-in) — implemented in daemon code via an argv array,
   never `/bin/sh`. The argument cannot change the command. Safest.
2. **Template Operations** (planned, not v1) — the extensibility path: shell templates
   authored *locally* by the trusted operator with typed, validated parameters. Safer
   than Raw Exec because a trusted author fixes the command structure; the residual risk
   is parameter injection, mitigated by per-parameter validation and quoting. Will get
   its own ADR when built.
3. **Raw Exec** — the *caller* (AI-agent) supplies the whole command; regex-gated by
   Policy. Most dangerous, exceptional.

## Consequences

- v1 ships a fixed, versioned set of Native Operations; new ones require a daemon
  release. Raw Exec is the interim pressure-valve for anything the vocabulary lacks, and
  recurring Raw Exec patterns are candidates for promotion to Native Operations.
- Policy applies to distinct surfaces (per-Operation rules and per-pattern Raw Exec
  rules); the enforcement model must cover both.
- The Operation vocabulary must be presented to the AI-agent legibly enough that it
  prefers Operations and reaches for Raw Exec only when necessary.
- Raw Exec is the highest-risk path and warrants the strongest auditing.
