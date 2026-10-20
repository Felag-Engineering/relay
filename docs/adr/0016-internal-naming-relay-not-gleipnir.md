# Internal naming: Relay, not Gleipnir

**Status:** Accepted; amended 2026-10-15 (the repo and the Go module path are `relay`, #885).

The product built in this repo is **Relay** — the fleet-administration control plane.
**Gleipnir** is a *different*, first-party project: the AI-agent system that drives Relay
as a consumer (over MCP and the Control API), never a component of it (GLOSSARY.md). The
repo name `gleipnir-relay` predates that boundary, and the name had leaked inward: the proto
package (`gleipnir.v1`), the generated Go import path (`internal/gleipnir/v1`), the daemon
crate (`gleipnir-relay-daemon`), the CA subject CommonNames (`Gleipnir Relay`,
`Gleipnir Relay CA`), and doc and comment references. Internal identifiers naming a different
product are a legibility defect on a security-critical control plane.

## Decisions

- **Internal identifiers, packages, and the wire contract use "Relay".** The proto package
  is renamed `gleipnir.v1` → `relay.v1` (contract-first, ADR-0007), which cascades by
  regeneration to the Go package `relayv1` under `relay/internal/relay/v1` and the daemon's
  `relay.v1` prost module. The CA subject CommonNames become `Relay` / `Relay CA`, and the
  daemon crate becomes `relay-daemon`.
- **"Gleipnir" is retained in exactly two places, both legitimate:** (a) the separate
  first-party AI-agent system that consumes Relay, as framed in GLOSSARY.md/AGENTS.md/
  README.md; and (b) the historical repo name `gleipnir-relay` and everything that
  derives from it (clone URLs, the Go module path).
- **The `relay.v1` rename is deliberately wire-breaking, and lands now.** The gRPC method
  paths change (`/gleipnir.v1.Tunnel/Open` → `/relay.v1.Tunnel/Open`), so a stale daemon and
  a new Relay do not interoperate. Acceptable because there were no external consumers, and
  it **must** precede buf breaking-change CI (`buf.yaml` `breaking: use: FILE`) and the
  v1.0.0 freeze of `relay.v1`, after either of which it would be prohibitively costly.
- **The Go module path stays `github.com/Felag-Engineering/gleipnir-relay/relay`.** It
  derives from the repository URL, and renaming the module without the repo breaks
  `go get`, so only the internal package segment is renamed. Renaming the repo is a larger,
  out-of-band decision (remotes, CI, external references) and is **deferred pending human
  sign-off**.

## Considered Options

- **Rename the repo and Go module path too, in this change.** Rejected for now: it touches
  every import prefix, clone URL and CI reference, and the repo rename is an org decision,
  not a code change. Deferred above.
- **Leave the proto package as `gleipnir.v1` and rename only surface strings.** Rejected:
  the wire contract is the spine (ADR-0007), a different product's name in it is the defect
  this ADR closes, and the cost only grows once breaking-change CI and the v1.0.0 freeze
  land.

## Consequences

- One coordinated, reviewed change carries the wire-breaking rename, not a drive-by inside a
  feature PR. Both toolchains regenerate from the moved `/proto` file.
- No message shapes, fields, field numbers, or semantics change, so ADR-0001/0002/0004/0012
  are untouched. The CA CommonName change touches ADR-0005/0006 code but is cosmetic:
  identity is the certificate and its node_id, never the CA subject string.
- The `gleipnir-relay` repo/module segment is a standing, intentional exception to "no
  `gleipnir` internally", recorded here so greps do not mistake it for drift.

## Amendment (2026-10-15): the repo and the Go module path are `relay`

The repository was renamed `Felag-Engineering/gleipnir-relay` → `Felag-Engineering/relay`, the
human-signed-off decision the fourth decision above deferred. That decision kept the module
path only because it derives from the repository URL, so its reason now points the other way:

- **The Go module path is `github.com/Felag-Engineering/relay/relay`.** Every import, the
  proto `go_package` option (regenerated, never hand-edited, ADR-0007), and the tool modules
  under `tools/` follow it.
- **The `gleipnir-relay` exception in (b) and in Consequences is retired.** "Gleipnir" is
  retained only for the separate AI-agent system that consumes Relay; `gleipnir-relay`
  appears only where the rename is itself the subject: this ADR, GLOSSARY.md, and the
  notes telling an old checkout where to point its remote.
- Nothing on the wire changes: the gRPC method paths are `relay.v1`, set by the proto
  package, not the Go module path.
