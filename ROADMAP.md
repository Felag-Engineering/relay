# Roadmap

Pre-1.0 software. Each milestone is a versioned, runnable increment; together they converge on
**`v0.1.0-beta`** — the first complete vertical slice, deployable to a small test fleet. The
strategy is to build *one thin path through every layer* rather than any one layer in full, so
the agentic development loop always has an end-to-end target with a pass/fail signal.

Every milestone lists **acceptance criteria** (the loop's definition of done) and the **ADRs**
it realizes.

> **Renumbered 2026-07-02** (milestones split for manageability). Mapping from older docs/ADRs:
> old v0.0.3 → v0.0.3 + v0.0.4 · old v0.0.4 → v0.0.5 + v0.0.6 · old v0.3.0 → v0.3.0 + v0.4.0 ·
> old v0.4.0 → v0.5.0 + v0.6.0. New: v0.0.7 (hardening), v0.0.8 (security pass), v1.0.0
> (production release). ADRs cite milestones by name where possible.

> **Re-sequenced 2026-07-08** (vision review; decision issues #135–#140). New pre-1.0
> milestones: **v0.7.0** (read lane, #138) and **v0.8.0** (operator-signed distribution +
> Template Operations, #135/#136 — absorbs old v1.1.0). The official **CLI** joins v0.4.0
> (#137). An **HA/routing design spike** (#139) must complete before the v1.0.0 freeze
> (build stays deferred). Scope rule recorded for all planning: **Relay is response and
> fleet management, never configuration management** — if Ansible could check it in
> check-mode, it is out of realm.

---

## `v0.0.1` — Walking Skeleton ✅

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

## `v0.0.2` — Secure Channel & Identity ✅

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

## `v0.0.3` — Policy Engine & Native Operations

Teach the daemon to refuse and to do, safely. Pure daemon milestone: the enforcement
engine and the execution primitives.

**Deliverables**
- **Policy engine** in the daemon: loaded from a root-owned local file, deny-by-default,
  deny-beats-allow, argument-level constraints, regex gating for Raw Exec. Remotely-immutable.
- **Executor framework**: argv spawn (never `/bin/sh`), Tasks in **killable process groups**,
  per-Task timeouts, size-capped captured output, structured per-Task results.
- **Native Operations**: `system.facts`, `file.read` (`read` class), `service.restart`
  (`mutate` class) — risk classes declared in `/proto` (ADR-0012).
- **Raw Exec** path, gated by Policy regex; always `mutate` class.
- **At-most-once** Task execution: unique Task IDs, daemon-side dedup across reconnects.

**Acceptance**
- An Operation allowed by Policy runs and returns a correct result; one denied by Policy returns
  `denied-by-policy` without executing.
- `service.restart` constrained to `{nginx}` refuses `sshd`.
- Re-sending a Task with a seen ID does not run it twice (including across a reconnect).
- The Relay cannot alter a Node's Policy over the wire (verified by attempt).
- A Task exceeding its timeout is killed (whole process group) and reports `timeout`.

**ADRs:** 0001 (Operations + Raw Exec), 0002 (Policy), 0004 (at-most-once), 0012 (risk
classes in the vocabulary).

---

## `v0.0.4` — Execution Control & Policy Tooling

Give the daemon its control seams (cancel, hypotheticals, scheduling) and operators
their Policy tooling. Still a daemon-centric milestone.

**Deliverables**
- **`TaskCancel` + `OUTCOME_CANCELLED`** (ADR-0013): on cancel the daemon kills the
  Task's process group and reports honestly (a Task that won the race reports
  `success`, never a retroactive `cancelled`).
- **Per-Node concurrency by risk class** (ADR-0004/0012): `mutate` Tasks serial,
  `read` Tasks parallel under a small fixed bound; queued Tasks' timeout clocks run
  while waiting.
- **`PolicyQuery`/`PolicyVerdict`** wire messages (ADR-0011): the daemon answers
  "would Policy allow this?" from its live engine — read-only, no Task ID, no
  execution path. (Powers plan mode in the Control Surfaces milestone.)
- **`relay-daemon policy check <file>`** subcommand: parse + lint a Policy file (invalid
  regex, unknown Operation names, allow rules shadowed by denies) and answer
  hypotheticals (`--would-allow`), so IaC pipelines can validate before deploying.
- **Policy fingerprint**: the daemon reports a hash of its loaded Policy in
  Hello/PolicySnapshot; the registry records it (fleet-wide Policy drift visibility).

**Acceptance**
- Cancelling an in-flight Task kills its process group and reports `cancelled`; a Task
  that completed in the race window reports `success`.
- Two `mutate` Tasks sent together never overlap; `read` Tasks run concurrently.
- `PolicyQuery` verdicts match what real execution then does on an unchanged Policy.
- `policy check` rejects a malformed file with a useful error and answers
  `--would-allow` consistently with the live engine.
- The registry shows a Node's Policy fingerprint after (re)connect.

**ADRs:** 0011 (Policy queries), 0013 (cancellation, daemon half), 0004/0012
(concurrency by class).

---

## `v0.0.5` — Job Engine & Persistence

The Relay learns fleets: fan-out, guardrails, memory, and the stop button. Driven by
tests/harness — the user-facing surfaces arrive next milestone.

**Deliverables**
- **SQLite** persistence behind a repository interface: Node registry, Jobs, Tasks, audit.
- The control path structured as a **reusable capability layer** (Selector → authz →
  blast-cap → dispatch → audit), so MCP, the Control API, the Admin Console, and a
  future CLI are thin adapters — never parallel control paths (ADR-0009, ADR-0010).
  **Enforced mechanically, not by review discipline**: the capability layer is the only
  package that can construct a dispatch (unexported constructor / internal-only type),
  so a surface reaching around it fails to compile rather than failing review. This is
  the load-bearing structural guarantee of the whole multi-surface design.
- **Job engine**: Selector → fan-out → one Task per matched Node → aggregated per-Node
  results. Schema constraint: a Job is modeled as *stages of Task batches* — always
  exactly one stage in v1 — so post-1.0 staged rollout lands without a data migration.
- **Offline Nodes fail fast** (ADR-0004): connectivity checked at dispatch; disconnected
  Nodes report `OUTCOME_UNREACHABLE` — no store-and-forward.
- **Blast-radius hard caps** (Relay config, file-only): a generous read-cap and a small
  mutate-cap, chosen by the Operation's risk class; Raw Exec always takes the
  mutate-cap (ADR-0012).
- **Job cancel + emergency Freeze** (ADR-0013): Job-level cancellation; a Relay-wide
  Freeze halting all new dispatch (Policy queries still work), engaged/released locally
  on the Relay host in this milestone (API paths arrive with the Control Surfaces
  milestone); persisted across Relay restarts.
- **Audit**: every Job/Task recorded (principal, selector, op, args, result, timestamps).
- **At-most-once across a Relay restart** designed explicitly (not just asserted): where
  Task IDs are generated, how in-flight dispatch state is persisted, and what the Relay
  believes about a Task whose result never arrived before a crash. A partition or crash
  mid-Job must never turn into a double-run when the daemon reconnects (ADR-0004).

**Acceptance**
- A Selector matching more Nodes than the applicable cap is rejected before any Task runs.
- A Job spanning an offline Node reports `unreachable` for it and real results for the rest.
- Engaging the Freeze stops a subsequent dispatch before any Task is sent; cancelling
  a Job kills its in-flight Tasks (which report `cancelled`) and stops undispatched ones.
- Every dispatch produces a queryable audit record; Jobs/Tasks survive a Relay restart.
- **Crash-mid-Job test**: kill the Relay after dispatch but before results land; on
  restart+reconnect the Task is not re-run and the Job reconciles to a truthful outcome.
- A route in any surface that attempts to dispatch without going through the capability
  layer does not compile (structural test).

**ADRs:** 0004 (Jobs, blast radius), 0012 (split caps), 0013 (Freeze), 0009/0010
(capability layer).

---

## `v0.0.6` — Control Surfaces: MCP & First API Slice

Make it drivable — by an AI-agent over MCP and by tooling over the first REST slice.

**Deliverables**
- **MCP server** exposing the five meta-tools: `list_nodes`, `describe_node`,
  `list_operations`, `run_operation`, `raw_exec`. `describe_node` returns effective Policy.
- **Vocabulary legibility** (ADR-0001): tool and Operation descriptions, and
  `list_operations` output, written so the AI-agent *prefers* structured Operations and
  reaches for Raw Exec only when the vocabulary genuinely can't express the task. This
  is a security-relevant deliverable, not cosmetics — the safety model assumes the AI
  takes the typed path by default. Each Operation's schema advertises its risk class and
  argument constraints legibly enough to choose without trial-and-error (plan mode is
  the fallback probe, not the primary path).
- **Plan mode** (ADR-0011): `plan=true` on `run_operation`/`raw_exec` returns the
  resolved fan-out and per-Node daemon-evaluated verdicts
  (`allow | deny(rule) | unknown(offline)`) without executing; over-cap Plans report
  `would-be-rejected` rather than erroring.
- Minimal **Relay-side authz** (ADR-0010, staged): one seeded admin credential — hash in
  the Relay config, plaintext in the operator's vault — is the bearer token for both the
  MCP endpoint and the API slice. No Account tables or roles yet (Accounts & Access
  milestone).
- First **Control API** slice (ADR-0010), REST under `/api/v1`: mint/revoke Enrollment
  Tokens, revoke Nodes, engage/release the Freeze. The control plane is REST from day one.
- **Listener separation** (Relay config): the control plane (MCP, `/api/v1`) binds
  separately from the node-plane gRPC listener.
- Add `pkg.install` Native Operation (`mutate`).

**Acceptance**
- An MCP client calls `run_operation(selector, "system.facts")` and gets per-Node results.
- `run_operation(…, plan=true)` returns per-Node verdicts and executes nothing; a
  subsequent real run on an unchanged fleet matches the plan's verdicts.
- `describe_node` shows the Node's effective Policy.
- The seeded admin credential mints a scoped Enrollment Token over `/api/v1`; a revoked
  token can no longer enroll; the Freeze can be engaged and released over the API.
- A request to either surface without the credential is refused.

**ADRs:** 0003 (MCP surface, Selectors), 0010 (staged authz + API slice), 0011 (plan
mode surface).

---

## `v0.0.7` — Hardening & Daemon Lifecycle

Make the path robust enough to put on machines that matter.

**Deliverables**
- Reconnect resilience, graceful daemon shutdown, basic observability (logs/metrics)
  on both sides.
- Hardening pass on the privileged daemon (restricted user, no implicit shell, output
  limits).
- **Daemon lifecycle** (ADR-0014): minimum-daemon-version dispatch gate (`outdated`
  flag in the registry, file-only config); CI enforces additive-only proto changes
  (buf breaking checks).
- Implement the **audit output-retention posture** (decided in review: full output vs
  metadata + truncated output vs configurable) so secrets in captured output have a
  deliberate story before real fleets depend on it.

**Acceptance**
- Killing and restarting the Relay: daemons reconnect, dedup holds, no Task double-runs.
- A below-minimum-version daemon connects and appears `outdated` in the registry, but
  dispatch to it is refused per-Task.
- A proto change that breaks wire compatibility fails CI.

**ADRs:** 0014 (lifecycle); hardening consequences of 0001/0002.

---

## `v0.0.8` — Threat Model & Security Pass

The one milestone driven by *an adversary trying to break this*, not by a feature. For
an RCE-as-a-service product, an adversarial pass before real machines is not optional —
and this is the milestone the autonomous loop must **not** drive alone (human-led, loop
assists). It also discharges the security debt ADR-0006 explicitly deferred "to a
pre-launch security pass" (node-origin label trust, the daemon privilege model).

**Deliverables**
- **Written threat model**: trust boundaries, assumed adversaries (compromised Node,
  stolen API credential, jailbroken AI-agent, malicious Relay, network attacker),
  and the defense each boundary provides. Committed as a doc, kept current. Opens
  with the product bet and its kill criterion (issue #140): Relay exists for
  autonomous AI operation of large fleets under structural distrust.
- **Raw Exec gate red-team**: adversarial attempt to defeat the regex allow/deny gating
  (quoting tricks, argv smuggling, encoding, symlink/path games) — the highest-risk
  path (ADR-0001). Findings become tests.
- **Proto/wire fuzzing**: malformed and hostile messages against both the Relay's gRPC
  handlers and the daemon's, including the certless Enroll path.
- **Privileged-daemon audit**: the daemon's actual capability/syscall surface as run
  (user, filesystem reach, process-spawn boundaries, resource limits); close the gap
  between "documented restricted user" and what the process can actually touch.
- **node-origin label trust** (ADR-0006 deferred item): decide and document how far
  `node:` labels are trusted, and whether CM-signed node attributes are needed before
  launch.
- **Secret-handling audit**: confirm no tokens/keys/password-hashes reach logs, audit
  output, or error messages across every surface.

**Acceptance**
- A threat-model document exists and every architecture invariant maps to a boundary
  in it.
- The Raw Exec red-team produces a regression test suite; no known bypass survives.
- Fuzzers run in CI (bounded) and the known-crash count is zero.
- The daemon runs with a documented, audited, least-privilege profile.

**ADRs:** discharges the ADR-0006 pre-launch-security-pass debt; may spawn new ADRs
from findings.

---

## `v0.1.0-beta` — Vertical Slice

Prove the end-to-end path on real machines, documented well enough for a stranger.

**Deliverables**
- Full path proven on a real (small) fleet: enroll → connect → dispatch → enforce →
  execute → report, over mTLS, with audit.
- Install/run docs for daemon and Relay; example Policy file; example enrollment
  workflow (incl. bulk enrollment via config management); IaC upgrade workflow
  consuming the CD artifacts (ADR-0014).
- **Policy-as-code workflow documented**: Node Policy files live in the customer's IaC
  repo, are validated with `policy check`, and are distributed by config management
  (SSH/Ansible) — never over the wire (ADR-0002); registry fingerprints confirm rollout.
- **CA & disaster posture documented**: CA key backup/permissions, compromise runbook —
  "burn it down" recovery is re-running the enrollment playbook against a fresh CA.
- **LICENSE**: publish as source-available under the **Business Source License (BSL)**
  — parameters (change date, change license, additional-use grant) set before the repo
  gets public attention.

**Acceptance**
- Stand up a Relay, enroll ≥3 Nodes via a reusable token, drive a Selector-targeted
  Operation from an MCP client, and read the audit trail — on real machines.
- Documented, repeatable setup from a clean environment.

**ADRs:** all of 0001–0014; security posture proven in v0.0.8.

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

## `v0.3.0` — Accounts & Access (post-beta)

The unified identity layer (ADR-0010) replaces the single seeded credential: named
Accounts, roles, and revocable API Tokens — the substrate the full Control API and the
Admin Console both render.

**Deliverables**
- **Account model**: Accounts (human and machine) with roles
  (`viewer` / `operator` / `admin`); the config-seeded credential becomes the first
  admin Account.
- **API Token lifecycle**: mint (shown once, hashed at rest, `glp_` prefix), revoke,
  expiry, last-used; tokens bound to Accounts and inheriting their role.
- Account CRUD + token endpoints on `/api/v1`.
- **MCP endpoint authenticates via Account API Tokens** (retiring the interim shared
  credential); the AI-agent becomes a machine Account whose role gates Raw Exec
  centrally.
- **Audit attribution by Account** (and token) on every action, every surface.

**Acceptance**
- An `operator` machine Account's token drives `run_operation` via MCP but is refused
  `raw_exec`; an `admin` token is not.
- Revoking a token immediately cuts its access; the audit trail attributes each action
  to its Account.
- The seeded credential still works and appears in audit as the founding admin Account.

**ADRs:** 0010 (Account model); builds on 0003.

---

## `v0.4.0` — Control API: Execution & OpenAPI (post-beta)

Complete the REST control plane (ADR-0010): the programmable superset — administration
*and* execution — for IaC tooling, CLIs, and extensions built on Relay. Plumbing before
porcelain: the Console renders what this API manages.

**Deliverables**
- Execution endpoints through the shared capability layer: `run_operation`, `raw_exec`
  (requires `admin` role), plan mode, Job/Task status and result queries.
- System Model read/write endpoints (capability parity with the System Model
  milestone's MCP tools, per ADR-0010's parity rule).
- Published, versioned **OpenAPI** spec for `/api/v1`; a documented Ansible example:
  vault-managed bootstrap credential → token mint → fleet enrollment, end to end.
- **Official CLI** (issue #137): a thin adapter over `/api/v1` for the human operator's
  workstation — never a parallel control path. Transport generated from the OpenAPI spec
  (the CLI doubles as the spec's conformance test); UX hand-written. **Plan-by-default
  for `mutate`**: `run` prints the Plan (fan-out, per-Node verdicts, cap check) and stops
  unless `--apply`; `read`-class runs directly. Execution, Job status/cancel, and Freeze
  verbs land here; the Policy/template **signing subcommands** land with v0.8.0.

**Acceptance**
- An Ansible playbook stands up the Relay and enrolls Nodes end-to-end with no manual
  steps, using the vault-managed bootstrap Account.
- `run_operation` via `/api/v1` returns per-Node results consistent with MCP's;
  `raw_exec` requires `admin` and is refused for an `operator` Account.
- A client generated from the OpenAPI spec can drive the fleet.
- The CLI runs a `mutate` Operation only after showing its Plan and receiving `--apply`;
  its actions appear in audit attributed to the operator's Account like any API caller.

**ADRs:** 0010 (Control API); builds on 0003 (capability surface), 0004 (Jobs).

---

## `v0.5.0` — Admin Console: Monitoring (post-beta)

The human web UI, phase one: eyes only. Server-rendered Go + HTMX, internal-only
(ADR-0009), logging in against the v0.3.0 Account model.

**Deliverables**
- Human auth: username/password login (hashed at rest) with optional OIDC; per-human
  audit attribution; `viewer` role enforced.
- Monitoring views: live Node registry (facts, `node:`/`relay:` labels, liveness,
  Policy fingerprints, `outdated` flags), Enrollment Token inventory, CA/cert
  lifecycle, Jobs/Tasks, Freeze state, and the audit trail.
- Internal-only serving; live updates via SSE.

**Acceptance**
- An operator logs in and watches fleet state, Jobs, and audit live — with zero
  mutating routes in the Console (verified by review).
- A `viewer` Account sees everything and can change nothing.

**ADRs:** 0009 (Console, monitoring phase); renders 0010's Account model.

---

## `v0.6.0` — Admin Console: Administration (post-beta)

Phase two: the keys — lifecycle control and access management. Still **no execution
surface** (ADR-0009): Operations and Raw Exec run only via MCP or the Control API.

**Deliverables**
- Lifecycle control: mint/revoke Enrollment Tokens, revoke Nodes, engage/release the
  Freeze — through the shared capability layer.
- **Access management**: view/create/disable Accounts (incl. machine Accounts for
  AI-agents), assign roles, revoke API Tokens — the human seam for governing what may
  drive the fleet over MCP/API.
- **Step-up re-authentication** on privilege-granting actions (create Account, change
  role, mint API Token) per ADR-0009.
- Draws on the System Model for richer monitoring context where available.

**Acceptance**
- An `admin` logs in, mints a scoped Enrollment Token, revokes a Node, creates an
  `operator` machine Account (passing step-up re-auth), and sees every action
  attributed in the audit trail — while a `viewer` is refused all of it.
- The Console offers no path to dispatch an Operation or Raw Exec (verified by review,
  not by RBAC).

**ADRs:** 0009 (Console, admin phase), 0010 (Accounts).

---

## `v0.7.0` — Read Lane: Vocabulary, Streaming & Aggregation (post-beta)

Make observation the adoption wedge (issue #138). The AI earns trust by *looking* before
anyone lets it touch; the split blast cap and read-parallel scheduling already anticipate
this — the vocabulary catches up here. Positioning rule: **interrogation, not
monitoring** — on-demand, Policy-gated questions against live state, never a metrics
pipeline.

**Deliverables**
- **Read-Operation batch, one daemon release** (each Native Op costs a release, so batch):
  process list, service status, disk/mount usage, listening ports, package inventory,
  bounded log tail, file checksum — all `read` class (ADR-0012); the ADR-0014 version
  gate covers lagging daemons.
- **Shipped default Policy**: the `read` class pre-allowed out of the box with a
  confidentiality deny-list (`/etc/shadow`, key material); `mutate` and Raw Exec stay
  opt-in whitelist. Engine semantics unchanged (deny-by-default) — only the shipped file
  changes; needs a short ADR because it looks like it touches invariant #3. A freshly
  enrolled Node is fully interrogable with zero Policy authoring.
- **Live output streaming, read lane first** (promoted from Deferred; ADR-0004 says the
  transport already supports it): bounded `log tail --follow`; the watch step of a canary.
- **Result aggregation primitive**: an AI cannot read 100k per-Node outputs.
  Histogram-by-output with clustered samples ("97,412 identical / 3 divergent — here are
  the 3"), built against the read lane first. Proto/Job-schema impact settled **before**
  the v1.0.0 freeze.
- Audit **output-retention posture** (v0.0.7) re-checked against read-lane volume —
  `read` means "cannot change Node state", not "safe to see".

**Acceptance**
- A Node enrolled with the shipped default Policy answers the full read vocabulary with
  zero local authoring; a deny-listed path (`/etc/shadow`) is refused.
- A fleet-wide `file.checksum` returns an aggregated histogram; a divergent Node is
  identified without reading per-Node output.
- A streamed `log tail --follow` delivers live output over MCP/API and stops on cancel.

**ADRs:** 0012, 0004 (streaming caveat); new short ADR (default Policy posture).

---

## `v0.8.0` — Operator-Signed Distribution & Template Operations (pre-1.0)

The typed path becomes the real path, and central administration stops requiring CM
round-trips — without surrendering the moat (issues #135, #136; absorbs old v1.1.0,
pulled pre-1.0 on 2026-07-08 so the contract freeze reflects it).

**Deliverables**
- **ADR-0002 rewrite** — "locally-rooted" becomes **operator-rooted**: authority is
  separated from transport. Policy and templates are authored centrally, **signed by an
  operator key the Relay never holds**, distributed over the existing mTLS channel, and
  verified by the daemon against a public key **pinned at enrollment** (the Enrollment
  Token carries it) before load. The Relay is a **courier, never an author**: a fully
  compromised Relay can withhold or serve stale bundles, never forge wider Policy.
- **New signing ADR**: bundle format, key custody (workstation/CI — never the Relay
  host), anti-rollback via signed monotonic versions, key rotation & compromise runbook.
  Today's local-file mode is retained as the hardened tier (air-gapped fleets).
- **Template Operations** (realizes ADR-0001 tier 2, extended): a template body may be a
  **full script** — trusted because operator-signed — with named, typed-validated
  parameter slots as the only wire-fillable part; substitution can never alter command
  structure; **mandatory `risk_class`** (ADR-0012); Policy governs templates exactly like
  Native Operations (deny beats allow).
- Daemon-side loading/linting (`policy check` extended to templates); template-set
  fingerprint reported beside the Policy fingerprint; per-Node vocabulary discovery via
  `list_operations`/`describe_node`; distinct `unsupported` per-Node outcome; **template
  packs** convention (shareable per-app packs, installed deliberately).
- **CLI signing workflow** (see v0.4.0): `relay policy lint | sign | push | status`,
  with fingerprint-verified rollout. The AI-agent may *draft* templates; nothing loads
  until a human signs — the AI grows the vocabulary but can never ship it alone.
- Daemon prerequisite: the Operation vocabulary behind a single
  name→(handler, arg-shape, risk-class) lookup (architecture review 2026-07-07,
  candidate 3), so a template tier registers instead of adding dispatch match arms.

**Acceptance**
- An operator authors and signs a template on a workstation and pushes it via the Relay;
  daemons verify and load it; a bundle signed by the wrong key — or an older version
  replayed — is refused.
- A compromised-Relay simulation (forged/wrong-key bundle over the wire) cannot widen any
  Node's Policy or template set.
- The AI-agent drafts a template; it is inert until signed; once signed,
  `run_operation` uses it, a parameter violating its validation is refused daemon-side,
  and a Node without the template reports `unsupported`.

**ADRs:** rewrites 0002; new signing ADR; realizes 0001 tier 2; 0012.

---

## `v1.0.0` — Production Release

The stability promise. Not new surface — the point where everything built so far is
declared production-grade, the wire/API contracts are frozen under a compatibility
promise, and the **BSL change-date clock starts** (ADR: licensing). 1.0 is
*earned by hardening and commitment*, not by adding features.

**Scope (what "1.0" means here)**
- The full stack in production shape: execution path (v0.0.3–v0.0.8), System Model
  (v0.2.0), Accounts & Access (v0.3.0), Control API + OpenAPI + CLI (v0.4.0), the Admin
  Console (v0.5.0–v0.6.0), the read lane (v0.7.0), and operator-signed distribution +
  Template Operations (v0.8.0) — each beyond prototype, with the security pass (v0.0.8)
  re-run against the accumulated surface.
- **HA/routing design spike complete before the freeze** (issue #139): the definitive
  list of additive proto/schema changes horizontal scaling needs — landed additively
  pre-freeze so the first 100k-Node fleet never forces a `relay.v2`. The HA *build*
  stays post-1.0 (see Deferred).
- **Contract stability commitment**: `relay.v1` proto and `/api/v1` OpenAPI are
  frozen — additive-only from here, breaking changes require a new version served in
  parallel (ADR-0010, ADR-0014). This is the promise fleet operators build against.
- **Operational maturity**: documented upgrade path across a 1.x series, backup/restore
  for the Relay store and the System Model git tree, and a supported deployment
  reference (not just "it runs on my machine").
- **Second security pass** over the complete multi-surface system, since v0.0.8 predated
  the Control API, Accounts, and the Console.

**Acceptance**
- A documented, supported production deployment stands up from clean infrastructure and
  survives a full upgrade cycle without data loss.
- Contract-compatibility CI gates are green and the freeze is enforced mechanically.
- The second security pass has no open high-severity findings.
- The `LICENSE` (BSL) is published with finalized parameters and the change-date clock
  is running.

**Decision still open:** whether the System Model (v0.2.0) and the Admin Console
(v0.5.0–v0.6.0) are *required* for 1.0 or may trail into 1.x. Resolve before cutting the
release; the execution path + Control API are non-negotiable for 1.0, the rest is a
scoping call.

---

## `v1.1.0` — (retired)

Template Operations moved **pre-1.0** as part of `v0.8.0` on 2026-07-08 (issues #135,
#136): the typed vocabulary must be rich enough to be the real path *before* the
contract freeze, and its distribution story changed from IaC-only files to
operator-signed bundles (ADR-0002 rewrite). See `v0.8.0` for the current spec.

---

## Deferred (post-beta, each its own ADR when picked up)

- **HA / horizontal Relay scaling** — Node→instance routing registry (ADR-0005 caveat).
  *Build* deferred; the **design spike is required before the v1.0.0 freeze**
  (issue #139, see v1.0.0 acceptance) — the 100k-Node vision makes this a wire-contract
  risk, not a nice-to-have.
- **Multi-principal RBAC & Grants** — per-Account authorization rules (Operations ×
  Selectors) managed via the Control API/Console; a Grant only ever narrows what Node
  Policy allows, never widens it (see CONTEXT.md "Grant", ADR-0010). Design rule when
  built: a Grant used as a *security boundary* must scope by `relay:` labels — a
  `node:`-scoped Grant's reach is partly Node-controlled, since Nodes own their
  `node:` labels (ADR-0006).
- **Staged rollout & approval (post-1.0, shape decided 2026-07-02)** — first-class
  rollout spec on Jobs: canary stage (count/percent) → gate (`all-success` or
  `manual-approval` via Control API/Console) → remainder, executed and audited as one
  Job. Relay config (file-only, like the blast cap) can mandate a canary stage above a
  Node-count threshold — a deterministic guardrail the AI-agent cannot skip. The
  AI-agent's standard arc becomes Plan (ADR-0011) → canary → fleet. Subsumes
  human-in-the-loop approval and overridable blast radius (ADR-0004 caveat).
  *(2026-07-08: write the rollout ADR pre-1.0 — at 100k Nodes the Plan → canary → gate →
  fleet arc is the primary safety mechanism, and the Job schema's Stages already
  anticipate it; execution may still land post-1.0.)*
- **Live output streaming** — transport already supports it (ADR-0004 caveat).
  *(2026-07-08: the read-lane slice is promoted to v0.7.0; mutate-lane streaming stays
  deferred.)*
- **Postgres store** — swap behind the repository interface when HA lands.
- **Graphic System Model view** — a visual representation layered over the git-backed YAML
  source of truth (ADR-0008 note).
- **System Model entry locking** — pin declared entries so the AI-agent cannot change them
  (ADR-0008 note).
- **Per-Account rate limits** — throttle Job creation per Account so a runaway AI-agent
  loop is bounded in time as well as blast radius.
- **Expectations (runtime health only)** — advisory, scheduled *read-class* checks that
  fleet runtime state matches what operators believe (service up, cert expiry, disk
  pressure, quarantine holding) — the Policy-fingerprint pattern generalized. Hard
  boundary (2026-07-08): Expectations assert **runtime state, never configuration
  content** — if Ansible could check it in check-mode, it is out of realm. Findings may
  *propose* a remediation Job; nothing auto-executes (ADR-0008 stands). The scheduler —
  the system's first standing automaton — must be able to construct **read-class
  dispatches only, enforced by type**, or it becomes an unattended executor by the back
  door. Own ADR when picked up; sits naturally after v0.2.0 + v0.7.0.
