# CLAUDE.md

Instructions for AI agents working in this repository. Read this fully before making changes.

## What this is

Relay is a **fleet-administration control plane** — a system that runs administrative
commands on a fleet of Linux servers, drivable by an AI orchestrator. It is **security-critical
by nature: it is remote code execution as a service.** Treat every change to the execution,
Policy, transport, or auth paths as security-sensitive.

The product is **Relay**. **Gleipnir** is the separate first-party AI-agent system that drives
it — a consumer of Relay, never a component of it. The repo name is historical (CONTEXT.md,
ADR-0016).

Orient in this order: [README.md](README.md) for the shape, [CONTEXT.md](CONTEXT.md) for the
language, then the [ADRs](docs/adr/) governing the area you're touching — the invariants below
tell you which those are.

## Ubiquitous language — use it exactly

[CONTEXT.md](CONTEXT.md) is the canonical glossary. Use these terms in code, comments, commits,
and docs; do not introduce synonyms. Most entries carry an `_Avoid_` line naming the synonyms
this project has deliberately rejected — those are decisions, not suggestions.

- **Relay** — the central Go server. Not "hub/master/server".
- **relay-daemon** — the non-AI Rust daemon on each Node. **Never call it "agent".**
- **AI-agent** — the AI orchestrator. The only thing called "agent", and always qualified.
- **Node**, **Operation**, **Raw Exec**, **Policy**, **Job**, **Task**, **Selector**,
  **Label** (`node:` / `relay:` / `tag:` / `state:`), **Facts**, **Enrollment Token** —
  see CONTEXT.md.

Internal identifiers say `Relay` / `RELAY_`, never "gleipnir" (ADR-0016).

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
7. **Labels use four namespaces, each immutable from the other sides.** `node:` labels are
   node-rooted (set out-of-band via config management), Relay-immutable, and authoritative for
   routine targeting. `relay:` labels are Relay-set (enrollment-stamped, or `admin` + step-up),
   Node-immutable, and reserved for the security-sensitive lane (quarantine, remediation,
   secret-distribution targeting), which must target `relay:` and only `relay:`. `tag:` labels
   are operator-set through the control plane, Node-immutable, for ad-hoc grouping and routine
   targeting — never a valid security-lane target. `state:` labels are Relay-derived from the
   registry, set by nobody at all, evaluated at Selector-resolution time from a closed vocabulary,
   for routine targeting only and never a valid security-lane target. A compromised Node can forge
   its own `node:` labels, and can influence `state:` by lying in `Hello`, but never `relay:` or
   `tag:`. (ADR-0006, ADR-0020, ADR-0034)
8. **`/proto` is the single source of truth** for the wire protocol and Operation vocabulary.
   Change the contract there; regenerate both sides. Don't hand-edit generated code. (ADR-0007)
9. **The System Model is advisory; its grounding facts are AI-immutable.** The AI-agent may
   freely create/update/delete Services, Dependencies, and Annotations (with provenance,
   audited via git commits), but may never edit Nodes or `relay:` labels through it, and the
   model never bypasses Selectors → Policy → blast cap. It is never a desired-state spec:
   Relay does not auto-reconcile, ever. (ADR-0008)
10. **One capability layer, three thin surfaces.** MCP, the Control API, and the Admin
    Console all adapt the same control-plane capability layer; never build a parallel
    control path. The Console **does** execute (v0.7.0): plan-by-default, step-up re-auth
    on mutate apply, role-gated by the capability layer, behind the root-owned
    `console_execution` flag — but it decides nothing itself, and the `no_dispatch`
    structural guard covers it like every other surface.
    (ADR-0009, ADR-0010, ADR-0026)
11. **The Control API manages runtime objects, never Relay configuration.** Relay config
    (listeners, CA/TLS, auth bootstrap, blast caps) is **operator-set at startup and
    unreachable from any API** — no code path exists from a request to any of those
    values, so the API can never raise its own limits. Secrets are supplied as *file
    paths*, never as values, so nothing sensitive lands in a process listing or a crash
    dump; a file holding one must be root-owned and not world-readable, and the Relay
    refuses to start otherwise. Delivered on a host by a root-owned unit file and
    `EnvironmentFile` (`relay/packaging/`) — the mechanism may change, the property may
    not. (ADR-0010; settled in #362)
12. **Policy is evaluated only by the daemon's live engine** — including hypotheticals
    (`PolicyQuery`, plan mode). Never reimplement Policy evaluation on the Relay side.
    (ADR-0011)
13. **Every Operation declares a risk class (`read` | `mutate`)**; blast caps are chosen by
    class, Raw Exec always takes the mutate-cap, and the class is security-relevant contract
    (`/proto`). (ADR-0012)
14. **The daemon never self-upgrades and the Relay never pushes binaries.** Daemon upgrades
    flow only through the customer's config management; the Relay's lever is the
    dispatch-level minimum-version gate. (ADR-0014)

**The numbering is a public interface.** `docs/security/threat-model.md` maps all fourteen to
the boundaries they defend; ADR-0020, ADR-0026, and ADR-0034 each record amending a specific
numbered invariant; ROADMAP.md, CONTEXT.md, the `docs/testing/validate-*.md` suites, and
several Go source comments cite them by number. Amend an invariant in place and record the
amendment in its ADR. **Never renumber or drop one.**

## Repository layout

```
/proto/          protobuf contract — the spine. Edit here first for any wire/Operation change.
/relay/          Go: gRPC server, MCP server, Job engine, CA, registry, store.   (cd relay)
/daemon/         Rust: connection, Policy engine, Operation executors, exec.      (cd daemon)
/docs/adr/       architecture decision records — the *why*.
/docs/agents/    per-repo configuration agent skills read (tracker, labels, domain rules).
/docs/api/       Control API reference and OpenAPI surface.
/docs/design/    design docs for work not yet an ADR (console, enrollment, open decisions).
/docs/operations/  operator-facing runbooks (version stamping, packaging).
/docs/security/  threat model — maps all fourteen invariants to the boundaries they defend.
/docs/testing/   manual validation scripts, one per milestone (`validate-*.md`).
/docs/reviews/   recorded review passes.
/docs/dev-fleet.md  the local Docker fleet: how to run Relay + real daemons.
CONTEXT.md       the glossary.   ROADMAP.md   the plan.
```

## Toolchains & commands

Two toolchains. The `Makefile` wraps both — prefer it.

| Task | Command |
|---|---|
| Build everything | `make build` |
| Test everything | `make test` |
| Lint/format everything | `make lint` |
| **Full CI-equivalent gate — run before opening a PR** | **`make verify`** |
| Install pinned proto plugins (do this first) | `make proto-tools` |
| Regenerate proto code | `make proto` |
| Local Docker fleet, up / creds / logs / down | `make dev-fleet-up` · `-creds` · `-logs` · `-down` |
| Relay only (Go) | `cd relay && go build ./... && go test ./...` |
| Daemon only (Rust) | `cd daemon && cargo build && cargo test && cargo clippy` |

**`make build test lint` is the fast inner loop. It is not what CI runs, and the gap has
bitten.** CI additionally runs the race detector, the proto-drift and proto-breaking gates,
the operation-schema and OpenAPI drift checks, the devharness absence check, and both
cross-binary suites. Work can pass the inner loop and fail CI on a class of problem the author
never looked at. `make verify` mirrors CI job for job; it is deliberately slow and deliberately
not what you run on every save.

- **Go (relay):** standard `go` toolchain; `gofmt`/`go vet`/`golangci-lint`.
- **Rust (daemon):** stable toolchain; `cargo fmt`/`cargo clippy -- -D warnings`. Build the
  daemon for musl when producing release artifacts (small static binary for the fleet).
- **Proto codegen is version-sensitive.** Run `make proto-tools` before `make proto`: it pins
  protoc-gen-go v1.36.11, protoc-gen-go-grpc v1.5.1, and buf v1.54.0. Unpinned `@latest`
  produces a spurious diff that false-positives the proto-drift gate.
- `make test` is hermetic and will not catch real-binary startup bugs. `make verify` includes
  `make test-integration`; run that target on its own when the diff touches Relay startup, the
  composition root, or config defaults and you are not yet ready for a full verify.
- **Dogfooding:** `make dev-fleet-up` brings up a Relay and real daemons in Docker. See
  `docs/dev-fleet.md`.

## How to work here

**1. Read before writing.** CONTEXT.md, then the ADR(s) governing the area you're touching.
`docs/agents/domain.md` carries the consumer rules; the invariants above are the index into
`docs/adr/`.

**2. Shape before you spec.** Ambiguity is resolved by interrogation, not by guessing.
Stress-test the idea against the codebase and the ADRs *first*; a decision reached in the
conversation is worth more than one discovered mid-implementation.

**3. Shape, spec, tickets, implement.** Work that needs thinking gets a spec at
`docs/specs/<slug>.md` (template and rules in `docs/specs/README.md`): problem and solution
from the user's perspective, the seams it will be tested at, the implementation and testing
decisions, and — explicitly — what is out of scope. The file is canonical; its issue links to
it. Tickets are then tracer-bullet vertical slices, each sized to a single fresh context window
and declaring what blocks it.

Not everything needs a spec. If you can write the acceptance criteria without arguing with
yourself, decompose the milestone straight into issues instead. If you can't, that argument is
the spec. Bugs never get specs — diagnose and fix.

Specs and tickets name modules and contracts, **never file paths or code snippets**: those go
stale within a sprint.

**4. Work the current milestone.** ROADMAP.md is the human-owned planning spine and its
acceptance criteria are your definition of done. **Its Status table is the authority on what is
in flight** — read that, don't infer the target from which heading lacks a checkmark. Milestones
here were deliberately built out of order, and some are gated on things an agent cannot supply
(real hardware, an open licensing decision). Issues decompose a milestone; they never redefine
one. Don't pull future milestones forward, and don't self-assign a gated one.

**5. Contract-first.** Wire or Operation changes start in `/proto`, then regenerate, then
implement both sides. `/proto` is the single source of truth; don't hand-edit generated code.

**6. Verify before you open a PR.** `make verify` is the gate, not `make build test lint` —
see Toolchains above for why the difference has bitten. Two failure modes to report rather
than swallow: a **skipped** gate is not a passed gate, and `verify-proto` skips the proto-drift
and proto-breaking checks with a notice when `buf` is absent. If your diff touches `/proto` and
those gates were skipped, say so in the PR body. CI runs them regardless, and invariant 8 plus
the escalation list below both put `/proto` in front of a person.

**7. Write an ADR** when a decision is hard to reverse, surprising without context, *and* the
result of a real trade-off — all three, not any one. Number it sequentially in `docs/adr/`.
Match the surrounding style: ADRs here are longer than the usual one-paragraph form because
they encode invariants agents are expected to check themselves against.

**Promote decisions out of specs.** A spec is archived when its feature ships; an architectural
decision left inside one becomes invisible, and someone later "fixes" what was deliberate. If a
decision in a spec meets all three tests above, write the ADR in the same change and have the
spec cite the number. This is the most common way a repo loses its own reasoning.

**8. Update CONTEXT.md** in the same change whenever the domain language shifts.

**9. Security posture.** Never weaken Policy, never add an implicit shell to an Operation,
never log secrets (tokens, private keys), never make the Relay able to mutate Node Policy.
When in doubt on the daemon (privileged) side, prefer the more restrictive option and flag it.

## Agent skills

Agent skills read their per-repo configuration from `docs/agents/`. Keep these current: they
are what a fresh session — including an unattended cloud routine — uses instead of asking.

- **Issue tracker** — GitHub Issues on `Felag-Engineering/gleipnir-relay` via the `gh` CLI,
  with ROADMAP.md as the human-owned spine above it. See `docs/agents/issue-tracker.md`.
- **Triage labels** — the five canonical triage roles mapped onto this repo's `loop:*` lanes.
  `decision` and `idea` are human-owned and never loop work. See `docs/agents/triage-labels.md`.
- **Domain docs** — single-context: CONTEXT.md at the root plus `docs/adr/`. Contradicting an
  ADR here is a stop-and-escalate, not a flag-and-proceed. See `docs/agents/domain.md`.
- **Routines** — what a scheduled cloud run executes, the environment it needs, the caps, and
  the `loop:halt` kill switch. See `docs/agents/routines.md`.

## Routines & merge authority

This repo is **product-only.** It is built largely by a Claude-driven agentic loop — working
one ROADMAP issue at a time on a branch, running `make verify`, having a separate
agent review the diff, and opening a PR. It runs both as interactive sessions and as unattended
cloud routines.

**Nothing merges autonomously. A person is always the merge authority.** This is the load-bearing
guardrail on a repo that ships remote code execution; it does not relax because a run is
unattended.

If you are an agent implementing an issue: **stay in scope**, you have **no merge authority**
(open a PR; a human merges), and **stop and flag a human** rather than guess on a hard call.

**Always escalate — never try to land without review** — anything touching `proto/`,
`docs/adr/`, Policy/exec/transport/mTLS/auth code, `CLAUDE.md`/`CONTEXT.md`, the `Makefile`,
or CI; any failed build; any high-severity review finding. These are the security surface and
the architecture invariants above; they always land in front of a person.

**Running unattended changes what you have, not what you may do.** A routine gets a fresh clone
and sees only what is committed here plus whatever skills its environment supplies. If a skill
or command the workflow depends on is missing, say so and stop — do not improvise the pipeline
by hand. An escalation you cannot deliver interactively becomes a PR left unmerged with the
reason stated plainly, never a decision made on the human's behalf.

**Unattended runs use `/dev-loop-queue`,** which takes one `loop:ready` issue per tick and
opens a PR without ever waiting for a merge. The wave-based `/dev-loop-drive` is deliberately
**not** vendored here: it gates each wave on human merges and stalls when nobody is there. Either
way a human merges, and `loop:halt` on any open issue stops every tick before it starts work.

**Schedulers don't source `~/.profile`,** so `cargo`, `go`, and `buf` may be missing from a
routine's `PATH`. The Makefile prepends the usual toolchain directories to compensate, but
`buf` is not part of a normal dev setup and will usually be absent — which silently downgrades
`make verify` by two proto gates. Install it with `make proto-tools`, or report the skip.
Never let a routine's thinner environment quietly become a weaker standard of proof.
