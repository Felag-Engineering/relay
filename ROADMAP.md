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
- **`relay-daemon policy check <file>`** subcommand: parse + lint a Policy file (invalid
  regex, unknown Operation names, allow rules shadowed by denies) and answer
  hypotheticals (`--would-allow`), so IaC pipelines can validate before deploying.
- **Policy fingerprint**: the daemon reports a hash of its loaded Policy in
  Hello/PolicySnapshot; the registry records it (fleet-wide Policy drift visibility).
- **`PolicyQuery`/`PolicyVerdict`** wire messages (ADR-0011): the daemon answers
  "would Policy allow this?" from its live engine — read-only, no Task ID, no
  execution path. (Powers v0.0.4 plan mode.)

**Acceptance**
- An Operation allowed by Policy runs and returns a correct result; one denied by Policy returns
  `denied-by-policy` without executing.
- `service.restart` constrained to `{nginx}` refuses `sshd`.
- Re-sending a Task with a seen ID does not run it twice.
- The Relay cannot alter a Node's Policy over the wire (verified by attempt).
- `policy check` rejects a malformed file with a useful error and answers
  `--would-allow` consistently with the live engine.

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
- Minimal **Relay-side authz** (ADR-0010, staged): one seeded admin credential —
  hash in the Relay config, plaintext in the operator's vault — is the bearer token
  for both the MCP endpoint and the Control API slice. No Account tables or roles yet;
  the full Account model lands in v0.3.0.
- First **Control API** slice (ADR-0010), REST under `/api/v1`: bearer-token auth,
  mint/revoke Enrollment Tokens, revoke Nodes. The control plane is REST from day
  one; the full surface lands in v0.3.0.
- Structure the control path as a **reusable capability layer** (Selector → Policy →
  blast-cap → audit) with MCP as its first adapter, so the Control API, the Admin
  Console, and a future CLI are thin adapters rather than parallel control paths
  (ADR-0009, ADR-0010).
- **Plan mode** (ADR-0011): `plan=true` on `run_operation`/`raw_exec` returns the
  resolved fan-out and per-Node daemon-evaluated Policy verdicts
  (`allow | deny(rule) | unknown(offline)`) without executing.
- Add `pkg.install` Native Operation.

**Acceptance**
- An MCP client calls `run_operation(selector, "system.facts")` and gets per-Node results.
- A Selector matching more Nodes than the blast cap is rejected before any Task runs.
- `run_operation(…, plan=true)` returns per-Node verdicts and executes nothing; a
  subsequent real run on an unchanged fleet matches the plan's verdicts.
- Every dispatch produces a queryable audit record.
- `describe_node` shows the Node's effective Policy.
- The seeded admin Account mints a scoped Enrollment Token over `/api/v1`; a revoked
  token can no longer enroll.

**ADRs:** 0003 (MCP surface, Selectors), 0004 (Jobs, blast radius).

---

## `v0.1.0-beta` — Vertical Slice

Harden the end-to-end path into something deployable for real testing.

**Deliverables**
- Full path proven on a real (small) fleet: enroll → connect → dispatch → enforce → execute →
  report, over mTLS, with audit.
- Install/run docs for daemon and Relay; example Policy file; example enrollment workflow
  (incl. bulk enrollment via config management).
- **Policy-as-code workflow documented**: Node Policy files live in the customer's IaC
  repo, are validated with `policy check`, and are distributed by config management
  (SSH/Ansible) — never over the wire (ADR-0002); registry fingerprints confirm rollout.
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

## `v0.3.0` — Control API (post-beta)

Complete the REST control-plane surface begun pre-beta (ADR-0010): the programmable
superset — administration *and* execution — for IaC tooling, CLIs, and extensions built
on Gleipnir. Sequenced before the Admin Console: plumbing before porcelain — the Console
renders what this API manages.

**Deliverables**
- Execution endpoints through the shared capability layer: `run_operation`, `raw_exec`
  (requires `admin` role), Job/Task status and result queries.
- Account CRUD and API Token lifecycle (mint, revoke, expiry, last-used).
- MCP endpoint authenticates via Account API Tokens (retiring any interim static token).
- Published, versioned **OpenAPI** spec for `/api/v1`; a documented Ansible example:
  vault-managed bootstrap credential → token mint → fleet enrollment, end to end.
- Audit attribution by Account on every endpoint.

**Acceptance**
- An Ansible playbook stands up the Relay and enrolls Nodes end-to-end with no manual
  steps, using the vault-managed bootstrap Account.
- `run_operation` via `/api/v1` returns per-Node results consistent with MCP's;
  `raw_exec` requires `admin` and is refused for an `operator` Account.
- Every API action appears in the audit trail attributed to its Account (and token).

**ADRs:** 0010 (Control API + Account model); builds on 0003 (capability surface),
0004 (Jobs, blast radius).

---

## `v0.4.0` — Admin Console (post-beta)

A human-facing web **Admin Console** for operators to observe the fleet and administer
the control plane — for the humans who aren't the AI-agent. Built as a **thin adapter**
over the v0.0.4 operator capability layer (ADR-0009). **Admin + observability only: the
Console has no execution surface** — Operations and Raw Exec run only via MCP or the
Control API. Sequenced after the Control API (v0.3.0): the Console renders what the API
manages (Accounts, tokens, audit), and reuses its Account model for login; it draws on
the v0.2.0 System Model for richer monitoring. Built in reviewable phases: monitoring
first, lifecycle control second.

**Deliverables**
- Monitoring: live Node registry (facts, `node:`/`relay:` labels, liveness), Enrollment
  Token inventory, CA/cert lifecycle, Jobs/Tasks, and the audit trail.
- Lifecycle control: mint/revoke Enrollment Tokens, revoke Nodes — through the shared
  capability layer. No `run_operation`, no `raw_exec` (ADR-0009).
- Human auth: username/password login (hashed at rest) with optional OIDC, the shared
  Account roles (ADR-0010), per-human audit attribution.
- Internal-only serving (not internet-facing); server-rendered Go + HTMX (ADR-0009).

**Acceptance**
- An operator logs in, views live fleet state, mints a scoped Enrollment Token,
  revokes a Node, and sees their own actions attributed in the audit trail — with RBAC
  preventing a `viewer` from minting or revoking.
- The Console offers no path to dispatch an Operation or Raw Exec (verified by review,
  not by RBAC).

**ADRs:** 0009 (Admin Console); builds on 0003 (capability surface), 0004 (Jobs, blast
radius), 0006 (identity), 0002 (Policy read-only).

---

## Deferred (post-beta, each its own ADR when picked up)

- **HA / horizontal Relay scaling** — Node→instance routing registry (ADR-0005 caveat).
- **Multi-principal RBAC & Grants** — per-Account authorization rules (Operations ×
  Selectors) managed via the Control API/Console; a Grant only ever narrows what Node
  Policy allows, never widens it (see CONTEXT.md "Grant", ADR-0010).
- **Human-in-the-loop approval & richer guardrails** — staged rollout, canaries, overridable
  blast radius (ADR-0004 caveat).
- **Template Operations** — the shell-template extensibility tier (ADR-0001 caveat).
- **Live output streaming** — transport already supports it (ADR-0004 caveat).
- **Postgres store** — swap behind the repository interface when HA lands.
- **Graphic System Model view** — a visual representation layered over the git-backed YAML
  source of truth (ADR-0008 note).
- **System Model entry locking** — pin declared entries so the AI-agent cannot change them
  (ADR-0008 note).
