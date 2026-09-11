# Internal naming: Relay, not Gleipnir

The product built in this repo is **Relay** — the fleet-administration control plane.
**Gleipnir** is a *different*, first-party project: the AI-agent system that drives Relay
as a consumer (over MCP and the Control API), never a component of it (GLOSSARY.md). The
repo name `gleipnir-relay` is historical, from before that boundary was drawn, and the
name had leaked inward: the proto package (`gleipnir.v1`), the generated Go import path
(`internal/gleipnir/v1`), the daemon crate (`gleipnir-relay-daemon`), the CA subject
CommonNames (`Gleipnir Relay`, `Gleipnir Relay CA`), and scattered doc/comment references.
Internal identifiers naming a different product is a legibility defect on a
security-critical control plane.

## Decisions

- **Internal identifiers, packages, and the wire contract use "Relay".** The proto
  package is renamed `gleipnir.v1` → `relay.v1` (contract-first, ADR-0007), which
  cascades — via regeneration, never hand-editing — to the Go package `relayv1` under
  `relay/internal/relay/v1` and the daemon's generated `relay.v1` prost module. The CA
  subject CommonNames become `Relay` / `Relay CA`, and the daemon crate becomes
  `relay-daemon` (its `[[bin]]` was already `relay-daemon`).
- **"Gleipnir" is retained in exactly two places, both legitimate:** (a) the separate
  first-party AI-agent system that consumes Relay, as framed in GLOSSARY.md/CLAUDE.md/
  README.md; and (b) the historical repo name `gleipnir-relay` and everything that
  derives from it (clone URLs, the Go module path).
- **The `relay.v1` rename is deliberately wire-breaking, and lands now.** The fully
  qualified gRPC method paths change (`/gleipnir.v1.Tunnel/Open` → `/relay.v1.Tunnel/Open`),
  so a stale daemon and a new Relay do not interoperate. This is acceptable because there
  are zero external consumers today, and it **must** precede two future gates: v0.0.7
  enabling buf breaking-change CI (`buf.yaml` `breaking: use: FILE`), and the v1.0.0
  freeze of the `relay.v1` contract. Renaming after either would be prohibitively costly;
  now it is free.
- **The Go module path stays `github.com/Felag-Engineering/gleipnir-relay/relay`.** The
  module path derives from the repository URL; renaming the module without renaming the
  repo breaks `go get`. We rename only the internal package segment
  (`internal/gleipnir/v1` → `internal/relay/v1`), not the `gleipnir-relay` repo segment.
  Renaming the repo itself is a larger, out-of-band decision (remotes, CI, external
  references) and is **deferred pending human sign-off**.

## Considered Options

- **Rename the repo and Go module path too, in this change.** Rejected for now: it
  touches every import prefix and every clone URL / CI reference, and the repo rename is
  an out-of-band org decision, not a code change. Recorded above as deferred, needing
  human sign-off.
- **Leave the proto package as `gleipnir.v1` and rename only surface strings.** Rejected:
  the wire contract is the spine (ADR-0007); leaving a different product's name in the
  package identifier is precisely the legibility defect this ADR closes, and the cost of
  the rename only grows once breaking-change CI and the v1.0.0 freeze land.

## Consequences

- One coordinated, reviewed change carries the wire-breaking rename; it is not a drive-by
  inside a feature PR. Both toolchains regenerate from the moved `/proto` file.
- No message shapes, fields, field numbers, or semantics change — only the package
  identifier and names — so ADR-0001/0002/0004/0012 are untouched. The CA CommonName
  change touches ADR-0005/0006 code but is cosmetic: identity is the certificate and its
  node_id, never the CA subject string, and no code or test asserts the CA CommonName.
- The `gleipnir-relay` repo/module segment remains a standing, intentional exception to
  "no `gleipnir` internally," documented here so future greps do not mistake it for drift.
