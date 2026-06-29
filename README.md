# Gleipnir Relay

A fleet-administration control plane. A lightweight, non-AI daemon (the **relay-daemon**)
runs on every managed Linux server, dials home to a central **Relay**, and holds a
persistent connection open. Through that connection the Relay runs typed administrative
**Operations** on the fleet, and an **AI-agent** drives the whole thing by using the Relay
as a tool — while per-Node **Policy** restricts what may actually run. Defense in depth.

```
┌─────────────┐   MCP    ┌──────────────────┐  gRPC/mTLS   ┌────────────────────┐
│  AI-agent   │ ───────▶ │      Relay       │ ◀─ dial home ─│   relay-daemon ×N  │
│ (MCP client)│  tools   │  (Go server)     │  persistent   │   (Rust, per Node) │
└─────────────┘          └──────────────────┘   bidi stream └────────────────────┘
                                                                  │ enforce local Policy
                                                                  ▼ execute Operation / Raw Exec
```

## Core ideas

- **Typed Operations, not shell strings.** A fixed vocabulary of structured Operations is the
  primary execution primitive; a regex-gated **Raw Exec** escape hatch covers the long tail.
  ([ADR-0001](docs/adr/0001-structured-operations-with-regex-gated-raw-exec.md))
- **The Node distrusts the Relay.** Policy is locally-rooted and remotely-immutable, so a
  compromised Relay or jailbroken AI-agent still cannot exceed a Node's local limits.
  ([ADR-0002](docs/adr/0002-node-side-policy-is-locally-rooted-and-remotely-immutable.md))
- **Selector fan-out.** The AI-agent targets Nodes by label Selector; one call fans out across
  the fleet with a hard blast-radius cap.
  ([ADR-0003](docs/adr/0003-mcp-meta-tool-surface-with-selector-fan-out.md),
  [ADR-0004](docs/adr/0004-async-job-execution-model.md))
- **Outbound-only, mutually authenticated.** Daemons need no inbound ports; identity is an
  mTLS client cert issued at enrollment.
  ([ADR-0005](docs/adr/0005-grpc-bidi-over-mtls-transport.md),
  [ADR-0006](docs/adr/0006-node-enrollment-identity-and-label-authority.md))
- **A System Model the AI maintains.** The Relay holds a git-backed semantic graph that links
  Labels into Services and Dependencies, so the AI-agent understands the fleet as a connected
  system — not isolated Nodes. Advisory only; auditable and human-correctable via git.
  ([ADR-0008](docs/adr/0008-system-model-git-backed-semantic-graph.md))

## Repository layout

```
/proto/        shared protobuf contract — source of truth for the wire + Operation vocabulary
/relay/        the Relay (Go): gRPC server, MCP server, Job engine, CA, registry, store
/daemon/       the relay-daemon (Rust): connection, Policy engine, Operation executors
/docs/adr/     architecture decision records
CONTEXT.md     the domain glossary — read this before touching anything
CLAUDE.md      instructions for AI agents working in this repo
ROADMAP.md     versioned milestones toward v0.1.0-beta
```

## Status

Pre-release. Building toward **`v0.1.0-beta`** (the first deployable vertical slice). See
[ROADMAP.md](ROADMAP.md).

## Documentation

- **[CONTEXT.md](CONTEXT.md)** — the ubiquitous language. Every term here is canonical.
- **[docs/adr/](docs/adr/)** — why the architecture is the way it is.
- **[ROADMAP.md](ROADMAP.md)** — what we're building and in what order.
