# CLAUDE.md

Instructions for AI agents working in this repository. Read this fully before making changes.

## What this is

Gleipnir Relay is a **fleet-administration control plane** — a system that runs administrative
commands on a fleet of Linux servers, drivable by an AI orchestrator. It is **security-critical
by nature: it is remote code execution as a service.** Treat every change to the execution,
Policy, transport, or auth paths as security-sensitive.

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
   model never bypasses Selectors → Policy → blast cap. (ADR-0008)

## Repository layout

```
/proto/        protobuf contract — the spine. Edit here first for any wire/Operation change.
/relay/        Go: gRPC server, MCP server, Job engine, CA, registry, store.   (cd relay)
/daemon/       Rust: connection, Policy engine, Operation executors, exec.      (cd daemon)
/docs/adr/     architecture decision records.
/scripts/dev-loop/  the autonomous development loop (see its README).
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

## The autonomous dev-loop

Much of this repo is built by a self-driving loop in [`scripts/dev-loop/`](scripts/dev-loop/README.md):
it turns the active ROADMAP milestone into GitHub issues, implements them one at a time on a branch,
runs `make build/test/lint`, has a model review the diff, then a **deterministic, non-LLM gate**
decides whether to auto-merge or **escalate to a human**. If you are an agent implementing an issue,
the rules in `scripts/dev-loop/prompts/implement.md` bind you (stay in scope, no merge authority,
flag hard decisions via `DECISION_NEEDED.md`).

What the gate **escalates to a human** (deny-beats-allow): anything touching `proto/`, `docs/adr/`,
Policy/exec/transport/mTLS/auth code, `CLAUDE.md`/`CONTEXT.md`, the `Makefile`, CI, or the loop's own
scripts; any failed build; any high-severity review finding; any oversized diff. So **changes to the
security surface or the architecture invariants above are never merged autonomously** — they always
land in front of a person. Issue order is a dependency chain: the loop works the lowest-numbered open
issue and waits for its escalated PR to merge before starting the next. Operate it with `make loop`;
see the README for the human seams (approve the issue breakdown, review escalations, milestone
acceptance) and the cost/billing model.

## Current target

Building toward **`v0.1.0-beta`**. Current milestone: see the top unchecked milestone in
[ROADMAP.md](ROADMAP.md).
