# Relay

A fleet-administration control plane. A lightweight, non-AI daemon (the **relay-daemon**)
runs on every managed Linux server, dials home to a central **Relay**, and holds a
persistent connection open. Through that connection the Relay runs typed administrative
**Operations** on the fleet, and an **AI-agent** drives the whole thing by using the Relay
as a tool — while per-Node **Policy** restricts what may actually run. Defense in depth.

**Relay lets you hand your fleet to an AI without handing it trust.** Other tools answer
"what if the operator goes rogue?" with procedure; Relay answers with architecture.

> **Naming:** the product is **Relay**. **Gleipnir** is the first-party AI-agent system
> that will drive Relay — a separate project and a consumer of Relay's MCP/API surfaces,
> with no special privileges. The repo name `gleipnir-relay` is historical.

```
┌─────────────┐   MCP    ┌──────────────────┐  gRPC/mTLS   ┌────────────────────┐
│  AI-agent   │ ───────▶ │      Relay       │ ◀─ dial home ─│   relay-daemon ×N  │
│ (MCP client)│  tools   │  (Go server)     │  persistent   │   (Rust, per Node) │
└─────────────┘          └──────────────────┘   bidi stream └────────────────────┘
                                                                  │ enforce local Policy
                                                                  ▼ execute Operation / Raw Exec
```

## Why Relay

Fleet tools like Ansible, Salt, and Chef were designed around a **trusted human
operator** — the control plane faithfully amplifies whatever the operator says, and
safety is procedure layered on top. Relay's founding assumption is the opposite: the
operator may be wrong, compromised, or not human. Distrust of the operator is the
architecture:

- **Typed, not shell.** The execution primitive is a fixed vocabulary of structured
  Operations whose arguments cannot change what runs; arbitrary commands are a
  conspicuous, regex-gated exception.
- **The Node distrusts the Relay.** Every server enforces its own root-owned Policy
  that nothing on the wire can widen — a fully compromised Relay or jailbroken AI-agent
  still cannot exceed it.
- **Every action is a bounded, attributed, previewable Job.** Blast-radius caps sized
  by risk class, plan-before-apply, and a per-Account audit trail — guardrails the
  caller cannot skip, because they live in the control plane, not in the caller's
  goodwill.

The pitch improves the more you distrust AI — which is precisely the right mood for
giving one your fleet.

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

## Configuration

The Relay's blast-radius caps (above) are startup-only: `-read-blast-cap` /
`RELAY_READ_BLAST_CAP` (default 10000, generous) and `-mutate-blast-cap` /
`RELAY_MUTATE_BLAST_CAP` (default 100, small — Raw Exec always takes this one).
Like the rest of the Relay's config today, they are resolved once from flags/env
at process start; nothing sets or raises them via an API.

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
- **[docs/dev-fleet.md](docs/dev-fleet.md)** — local dev fleet: `docker compose up` for one Relay + N relay-daemons, drivable over MCP (dev-only).
- **[ROADMAP.md](ROADMAP.md)** — what we're building and in what order.
