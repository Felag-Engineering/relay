# CLAUDE.md

Instructions for AI agents working in this repository. Read this fully before making changes.

## What this is

Relay is a **fleet-administration control plane** — a system that runs administrative
commands on a fleet of Linux servers, drivable by an AI orchestrator. It is **security-critical
by nature: it is remote code execution as a service.** Treat every change to the execution,
Policy, transport, or auth paths as security-sensitive. (The product is **Relay**;
**Gleipnir** is the separate first-party AI-agent system that drives it. The repo name is
historical — see CONTEXT.md.)

Start with [README.md](README.md) for the shape, then [CONTEXT.md](CONTEXT.md) for the language,
then the relevant [ADRs](docs/adr/) for the *why*.

## Ubiquitous language — use it exactly

[CONTEXT.md](CONTEXT.md) is the canonical glossary. Use these terms in code, comments, commits,
and docs; do not introduce synonyms.

- **Relay** — the central Go server. Not "hub/master/server".
- **relay-daemon** — the non-AI Rust daemon on each Node. **Never call it "agent".**
- **AI-agent** — the AI orchestrator. The only thing called "agent", and always qualified.
- **Node**, **Operation**, **Raw Exec**, **Policy**, **Job**, **Task**, **Selector**,
  **Label** (`node:` / `relay:`), **Facts**, **Enrollment Token** — see CONTEXT.md.

If you find yourself needing a new domain term, add it to CONTEXT.md in the same change.

## Architecture invariants — do not violate without a new ADR

These are load-bearing decisions. If a task seems to require breaking one, **stop and flag it**;
it needs an ADR, not a quiet workaround.

1. **Operations are typed and native (argv, never `/bin/sh`).** A structured Operation's arguments
   must never be able to change which command runs. Raw Exec is the *only* arbitrary-command path,
   and it is regex-gated by Policy. (ADR-0001)
2. **Policy is locally-rooted and remotely-immutable.** The Relay may *query* a Node's Policy; it
   may **never** modify it over the wire. The daemon enforces; the Relay only reads. (ADR-0002)
3. **Deny-by-default, deny-beats-allow,** with argument-level granularity. (ADR-0002)
4. **At-most-once Task execution.** Tasks carry unique IDs; the daemon dedups across reconnects.
   Never make execution at-least-once. (ADR-0004)
5. **Blast-radius cap is enforced on the Relay before dispatch.** (ADR-0004)
6. **mTLS everywhere; the daemon refuses an untrusted Relay.** Node identity is its client cert.
   (ADR-0005, 0006)
7. **Labels use two namespaces, each immutable from the other side.** `node:` labels are
   node-rooted (set out-of-band via config management), Relay-immutable, and authoritative for
   routine targeting. `relay:` labels are Relay-set, Node-immutable, and reserved for the
   security-sensitive lane (quarantine, remediation, secret-distribution targeting), which must
   target `relay:`. A compromised Node can forge its own `node:` labels but never `relay:`. (ADR-0006)
8. **`/proto` is the single source of truth** for the wire protocol and Operation vocabulary.
   Change the contract there; regenerate both sides. Don't hand-edit generated code. (ADR-0007)
9. **The System Model is advisory; its grounding facts are AI-immutable.** The AI-agent may
   freely create/update/delete Services, Dependencies, and Annotations (with provenance,
   audited via git commits), but may never edit Nodes or `relay:` labels through it, and the
   model never bypasses Selectors → Policy → blast cap. It is never a desired-state spec:
   Relay does not auto-reconcile, ever. (ADR-0008)
10. **One capability layer, three thin surfaces.** MCP, the Control API, and the Admin
    Console all adapt the same control-plane capability layer; never build a parallel
    control path. The Console has **no execution surface** (admin + observability only).
    (ADR-0009, ADR-0010)
11. **The Control API manages runtime objects, never Relay configuration.** Relay config
    (listeners, CA/TLS, auth bootstrap, blast caps) is a root-owned local file; the API
    can never raise its own limits. (ADR-0010)
12. **Policy is evaluated only by the daemon's live engine** — including hypotheticals
    (`PolicyQuery`, plan mode). Never reimplement Policy evaluation on the Relay side.
    (ADR-0011)
13. **Every Operation declares a risk class (`read` | `mutate`)**; blast caps are chosen by
    class, Raw Exec always takes the mutate-cap, and the class is security-relevant contract
    (`/proto`). (ADR-0012)

## Repository layout

```
/proto/        protobuf contract — the spine. Edit here first for any wire/Operation change.
/relay/        Go: gRPC server, MCP server, Job engine, CA, registry, store.   (cd relay)
/daemon/       Rust: connection, Policy engine, Operation executors, exec.      (cd daemon)
/docs/adr/     architecture decision records.
CONTEXT.md     the glossary.   ROADMAP.md   the plan.
```

## Toolchains & commands

Two toolchains. The `Makefile` wraps both — prefer it.

| Task | Command |
|---|---|
| Build everything | `make build` |
| Test everything | `make test` |
| Lint/format everything | `make lint` |
| Regenerate proto code | `make proto` |
| Relay only (Go) | `cd relay && go build ./... && go test ./...` |
| Daemon only (Rust) | `cd daemon && cargo build && cargo test && cargo clippy` |

- **Go (relay):** standard `go` toolchain; `gofmt`/`go vet`/`golangci-lint`.
- **Rust (daemon):** stable toolchain; `cargo fmt`/`cargo clippy -- -D warnings`. Build the
  daemon for musl when producing release artifacts (small static binary for the fleet).

## How to work here

1. **Read before writing.** For any change, read CONTEXT.md and the ADR(s) governing the area you're
   touching (the invariants above name them).
2. **Work the current milestone.** ROADMAP.md defines what's in scope and the acceptance criteria
   that are your definition of done. Don't pull future milestones forward.
3. **Contract-first.** Wire or Operation changes start in `/proto`, then regenerate, then implement
   both sides.
4. **Write an ADR** when you make a decision that is hard to reverse, surprising without context, and
   the result of a real trade-off. Number it sequentially in `docs/adr/`. Keep it short.
5. **Update CONTEXT.md** in the same change whenever the domain language shifts.
6. **Security posture:** never weaken Policy, never add an implicit shell to an Operation, never log
   secrets (tokens, private keys), never make the Relay able to mutate Node Policy. When in doubt on
   the daemon (privileged) side, prefer the more restrictive option and flag it.

## How this repo is developed

This repo is **product-only.** It is built largely by an external, Claude-driven agentic dev-loop
(a user-level `/dev-loop` command, intentionally *not* checked in here) that works one ROADMAP issue
at a time on a branch, runs `make build/test/lint`, has a separate agent review the diff, and opens a
PR for a human to merge. **It never merges autonomously** — a person is always the merge authority.

If you are an agent implementing an issue: **stay in scope**, you have **no merge authority** (open a
PR; a human merges), and **stop and flag** the human rather than guess on a hard call.

**Always escalate to a human — never try to land without review** — anything touching `proto/`,
`docs/adr/`, Policy/exec/transport/mTLS/auth code, `CLAUDE.md`/`CONTEXT.md`, the `Makefile`, or CI;
any failed build; any high-severity review finding. These are the security surface and the
architecture invariants above; they always land in front of a person.

## Current target

Building toward **`v0.1.0-beta`**. Current milestone: see the top unchecked milestone in
[ROADMAP.md](ROADMAP.md).
