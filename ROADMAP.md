# Roadmap

Pre-1.0 software. Each milestone is a versioned, runnable increment; together they converge on
**`v0.1.0-beta`** — the first complete vertical slice, deployable to a small test fleet. The
strategy is to build *one thin path through every layer* rather than any one layer in full, so
the agentic development loop always has an end-to-end target with a pass/fail signal.

Every milestone lists **acceptance criteria** (the loop's definition of done) and the **ADRs**
it realizes.

---

## `v0.0.1` — Walking Skeleton

Make the two halves exist, build, and talk over the simplest possible channel.

**Deliverables**
- Monorepo scaffold: `/proto`, `/relay` (Go), `/daemon` (Rust) building independently.
- `/proto` codegen wired for both toolchains (buf or protoc → Go + tonic/prost).
- A trivial bidi gRPC stream over **plaintext** (no TLS yet): daemon connects, sends a `Hello`,
  Relay logs it and replies with a `Ping`.
- CI: build + lint + test green for both toolchains.

**Acceptance**
- `make build` produces a `relay` and a `relay-daemon` binary.
- Running the daemon connects to a locally-running Relay and both log the handshake.
- CI is green on a clean checkout.

**ADRs:** 0005 (transport shape), 0007 (polyglot + monorepo).

---

## `v0.0.2` — Secure Channel & Identity

Replace plaintext with real mutual auth and give Nodes identities.

**Deliverables**
- Relay-hosted private **CA**.
- **Enrollment**: reusable, scoped, expiring, revocable token → daemon submits CSR → Relay
  issues a per-Node client cert. Token scope stamps `relay:` labels.
- All daemon↔Relay traffic over **gRPC/mTLS**; daemon refuses an untrusted Relay.
- **Heartbeats** on the stream; Relay maintains a live **Node registry** (identity, facts,
  `node:`/`relay:` labels, last-seen).
- Cert rotation/renewal; Relay-side Node revocation (denylist).

**Acceptance**
- A fresh daemon enrolls with a token, receives a cert, reconnects over mTLS, and appears in the
  registry with correct labels.
- Revoking a Node immediately drops its ability to connect.
- A daemon pointed at a Relay with the wrong CA refuses to proceed.

**ADRs:** 0005 (mTLS), 0006 (enrollment, identity, label authority).

---

## `v0.0.3` — Policy & Execution

Teach the daemon to refuse and to do, safely.

**Deliverables**
- **Policy engine** in the daemon: loaded from a root-owned local file, deny-by-default,
  deny-beats-allow, argument-level constraints, regex gating for Raw Exec. Remotely-immutable.
- **Native Operations** (argv, no shell): `system.facts`, `service.restart`, `file.read`.
- **Raw Exec** path, gated by Policy regex.
- **At-most-once** Task execution: unique Task IDs, daemon-side dedup across reconnects.
- Per-Task timeouts; captured output with size cap; structured per-Task results.

**Acceptance**
- An Operation allowed by Policy runs and returns a correct result; one denied by Policy returns
  `denied-by-policy` without executing.
- `service.restart` constrained to `{nginx}` refuses `sshd`.
- Re-sending a Task with a seen ID does not run it twice.
- The Relay cannot alter a Node's Policy over the wire (verified by attempt).

**ADRs:** 0001 (Operations + Raw Exec), 0002 (Policy), 0004 (at-most-once).

---

## `v0.0.4` — Orchestration & MCP

Make it drivable by an AI-agent across the fleet.

**Deliverables**
- **Job engine**: Selector → fan-out → one Task per matched Node → aggregated per-Node results.
- **Blast-radius hard cap** (Relay config) enforced before dispatch.
- **MCP server** exposing the five meta-tools: `list_nodes`, `describe_node`, `list_operations`,
  `run_operation`, `raw_exec`. `describe_node` returns effective Policy.
- **SQLite** persistence behind a repository interface: Node registry, Jobs, Tasks, audit.
- **Audit**: every Job/Task recorded (principal, selector, op, args, result, timestamps).
- Minimal **Relay-side authz**: single admin principal via a static token on the MCP endpoint.
- Add `pkg.install` Native Operation.

**Acceptance**
- An MCP client calls `run_operation(selector, "system.facts")` and gets per-Node results.
- A Selector matching more Nodes than the blast cap is rejected before any Task runs.
- Every dispatch produces a queryable audit record.
- `describe_node` shows the Node's effective Policy.

**ADRs:** 0003 (MCP surface, Selectors), 0004 (Jobs, blast radius).

---

## `v0.1.0-beta` — Vertical Slice

Harden the end-to-end path into something deployable for real testing.

**Deliverables**
- Full path proven on a real (small) fleet: enroll → connect → dispatch → enforce → execute →
  report, over mTLS, with audit.
- Install/run docs for daemon and Relay; example Policy file; example enrollment workflow
  (incl. bulk enrollment via config management).
- Reconnect resilience, graceful daemon shutdown, basic observability (logs/metrics).
- Hardening pass on the privileged daemon (restricted user, no implicit shell, output limits).

**Acceptance**
- Stand up a Relay, enroll ≥3 Nodes via a reusable token, drive a Selector-targeted Operation
  from an MCP client, and read the audit trail — on real machines.
- Documented, repeatable setup from a clean environment.

**ADRs:** all of 0001–0007.

---

## `v0.2.0` — System Model (post-beta)

Give the AI-agent a persistent understanding of the fleet as a connected system. Kept out of
the beta so the vertical slice stays focused on the execution path.

**Deliverables**
- Git-backed YAML **System Model** store in the Relay: commit-per-change, provenance (author,
  time, reason) on every mutation.
- Semantic layer: **Services** (named Selectors), **Dependencies** (directed edges),
  **Annotations**.
- Grounding from the registry: Nodes and `relay:` labels imported and AI-immutable.
- MCP **Resources** for reading the model; MCP **Tools** for AI writes (`define_service`,
  `set_dependency`, `annotate`, `query_model`).
- Dependency-aware impact reporting alongside the blast-radius cap.

**Acceptance**
- The AI-agent defines a Service from a Selector, adds a Dependency, and a later session reads
  the same model.
- Every AI change is a git commit with author + reason; a human can `git revert` a bad edit.
- `run_operation(service="payments", …)` resolves to the Service's Selector and still obeys
  Policy + blast cap.

**ADRs:** 0008 (System Model); reuses 0003 (Selectors), 0004 (Jobs).

---

## Deferred (post-beta, each its own ADR when picked up)

- **HA / horizontal Relay scaling** — Node→instance routing registry (ADR-0005 caveat).
- **Multi-principal RBAC** — full Relay-side authorization model.
- **Human-in-the-loop approval & richer guardrails** — staged rollout, canaries, overridable
  blast radius (ADR-0004 caveat).
- **Template Operations** — the shell-template extensibility tier (ADR-0001 caveat).
- **Live output streaming** — transport already supports it (ADR-0004 caveat).
- **Postgres store** — swap behind the repository interface when HA lands.
- **Graphic System Model view** — a visual representation layered over the git-backed YAML
  source of truth (ADR-0008 note).
- **System Model entry locking** — pin declared entries so the AI-agent cannot change them
  (ADR-0008 note).
