# Roadmap

> ## ⚠️ Deprecated — being retired
>
> **Do not add milestones or acceptance criteria to this file.** It is being slimmed to a
> short sequencing note once the content below has moved. Its parts are going to the document
> that is authoritative for each, rather than being copied here:
>
> | What | Moves to |
> |---|---|
> | Milestone acceptance criteria | The relevant capability specification in [`docs/specs/`](docs/specs/). These are durable behavioural statements; ~32 tests already cite them as "the ROADMAP acceptance line" while living in a milestone that closed months ago. |
> | Status — what is in flight | **GitHub milestones**, which are already the authority. The table below is a hand-synced copy and has been observed 65 PRs stale. |
> | Architectural decisions | [`docs/adr/`](docs/adr/) |
> | What must always be true | The architecture invariants in [`CLAUDE.md`](CLAUDE.md) |
> | Domain language | [`GLOSSARY.md`](GLOSSARY.md) |
> | The Deferred list | GitHub issues |
> | Why the order is what it is, and what is gated on a human | **Stays** — this is the short note the file becomes |
>
> **Until that migration lands, this file remains the record of milestone acceptance
> criteria.** A missing capability spec is not permission to ignore an acceptance line here.
> New behaviour gets written into a capability spec instead.

Pre-1.0 software. Each milestone is a versioned, runnable increment; together they converge on
**`v0.1.0-beta`** — the first complete vertical slice, deployable to a small test fleet. The
strategy is to build *one thin path through every layer* rather than any one layer in full, so
the agentic development loop always has an end-to-end target with a pass/fail signal.

Every milestone lists **acceptance criteria** (the loop's definition of done) and the **ADRs**
it realizes. Every milestone also ships a **manual validation script** —
`docs/testing/validate-vX.Y.Z.md` (convention: [docs/testing/README.md](docs/testing/README.md))
— a human-runnable end-to-end walkthrough of its acceptance criteria through the product's real
surfaces; writing/updating it is part of the milestone's definition of done. The baseline
covering everything shipped through v0.0.9 is `docs/testing/validate-v0.0.9-current.md`.

> **Renumbered 2026-07-02** (milestones split for manageability). Mapping from older docs/ADRs:
> old v0.0.3 → v0.0.3 + v0.0.4 · old v0.0.4 → v0.0.5 + v0.0.6 · old v0.3.0 → v0.3.0 + v0.4.0 ·
> old v0.4.0 → v0.5.0 + v0.6.0. New: v0.0.7 (hardening), v0.0.8 (security pass), v1.0.0
> (production release). ADRs cite milestones by name where possible.

> **Re-sequenced 2026-07-08** (vision review; decision issues #135–#140). New pre-1.0
> milestones: **v0.7.0** (read lane, #138) and **v0.8.0** (operator-signed distribution +
> Template Operations, #135/#136 — absorbs old v1.1.0). The official **CLI** joined v0.4.0 (#137) and was
> **cut on 2026-08-13** — see the v0.4.0 entry. An **HA/routing design spike** (#139) must complete before the v1.0.0 freeze
> (build stays deferred). Scope rule recorded for all planning: **Relay is response and
> fleet management, never configuration management** — if Ansible could check it in
> check-mode, it is out of realm.

> **Added 2026-07-24:** **v0.0.9** (release readiness & residual hardening) between the
> security pass and the beta — the v0.0.8 register's residuals plus the artifact/version
> work `v0.1.0-beta` depends on, so the beta stays purely about proving the path on real
> machines. Decision issues #135–#138 closed as discharged into the milestones above
> (v0.8.0, v0.8.0, v0.4.0, v0.7.0 respectively).

> **Re-sequenced 2026-08-07** (records the 2026-08-03 GitHub-milestone changes plus the
> approval/attribution planning session — design notes in `docs/design/`). Mapping from
> the 2026-07-08 sequence: old v0.2.0 (System Model) → **v1.1.0** (post-1.0; resolves the
> v1.0.0 open decision) · **new v0.2.0 — Template Engine & Shipped Catalog** (#266;
> absorbs old v0.7.0's read vocabulary + default Policy; v0.8.0 slims to signing +
> courier) · old v0.3.0/v0.4.0 keep their slots (Accounts gains OAuth resource-server +
> the asserted-attribution lane; API/CLI unchanged) · **new v0.5.0 — Approval Callout**
> (#268–#272) · old v0.5.0/v0.6.0 (Console) → **v0.6.0/v0.7.0**, the latter gaining the
> execution surface per #264's pending ADR · old v0.7.0's remainder (streaming,
> aggregation) → **v0.9.0**. Ordering rationale: Accounts → API → Approvals → Console is
> a strict dependency chain (`docs/design/console-backend-coverage.md`).

## Status, 2026-09-08

**✅ complete · 🚧 in progress · unmarked = not started.**

Post-beta milestones were built ahead of `v0.1.0-beta`, which is deliberate — beta is the
*real-hardware* proof, and there was more value in having something worth proving. What
remains before it is small and named below.

Counts in this table were taken from the GitHub milestones on 2026-09-08. A further ten open
issues carry no milestone — the self-serve enrollment set (#398–#410, feeding `v0.1.0-beta`),
the investor-demo epic (#451–#457), and loose defects the loop is draining.

| Milestone | State | What is actually outstanding |
|---|---|---|
| `v0.0.1`–`v0.0.9` | ✅ | — |
| `v0.1.0-beta` | not started | **Needs real machines** for the runbook. **No `LICENSE` file exists** (BSL parameters are decision #123, still open). Self-serve evaluation was designed out on 2026-08-18/19 into ADR-0030–0033 and #403–#410 (below); #405 is gated on the #397 role-gate fix, and #403 is a live defect that should land ahead of all of it. |
| `v0.2.0` | ✅ | — |
| `v0.3.0` | ✅ code | Decision #279 (per-Account rate limits) still open; `validate-v0.3.0.md` unwritten. |
| `v0.4.0` | ✅ code | [7/7] (#362) merged in #395. [6/7] (#361, the thin Ansible role) **closed as superseded** 2026-08-18 — the enrollment-bundle capability (ADR-0032, #405) renders the same playbook from the capability layer, so it reaches all three surfaces from one implementation. `validate-v0.4.0.md` unwritten. |
| `v0.5.0` | ✅ code | `validate-v0.5.0.md` unwritten. |
| `v0.5.1` | ✅ | Validation run waived, recorded — no MCP client implements Tasks yet. |
| `v0.6.0` | 🚧 | **Current milestone.** 24 of 35 issues closed. Both gating defects (#403 cert rotation, #397 role gate) landed, and #416 (the SSE event seam) merged in #485 — which is what #476 was waiting on to decide the 'live' acceptance. What remains is defects found by driving the UI (#460 CSRF binding, #466 fleet view at scale, #462/#469 approval-record gaps), test debt (#470), the Console-shell ADR (#475), and `validate-v0.6.0.md` (#476). |
| `v0.7.0` | 🚧 | 3 of 17 closed — started ahead of v0.6.0's close, deliberately: #264 settled the execution-surface ADR (ADR-0026, amending invariant 10) and #429/#432 landed Account suspension and agent disconnect. The execution surface itself (#438 composer, #428 step-up, #435 approval decisions) is not built. #482 is an open security defect on approval Grant scope. |

**Where this file sits now.** ROADMAP sequences; it does not describe. What a capability
*does* belongs in its capability specification ([`docs/specs/`](docs/specs/)), what must
always be true belongs in the invariants in [`CLAUDE.md`](CLAUDE.md), and why a shape was
chosen belongs in an
[ADR](docs/adr/). Milestone entries below keep their deliverables and acceptance criteria —
those are the definition of done for a slice of work, not a description of the system.

**The one systematic gap: manual validation scripts.** This file says every milestone ships
one, and `v0.3.0`, `v0.4.0`, and `v0.5.0` have none. Each of those milestones lists it in
its own Acceptance section, so all three are complete in code and incomplete by their own
definition of done. That is worth stating plainly rather than leaving to be discovered:
either the scripts get written, or the runs get waived on the
[README rule 7](docs/testing/README.md) precedent — a dated decision with a stated cost,
which is the opposite of quietly skipping them.

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

## `v0.0.3` — Policy Engine & Native Operations ✅

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

## `v0.0.4` — Execution Control & Policy Tooling ✅

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

## `v0.0.5` — Job Engine & Persistence ✅

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

## `v0.0.6` — Control Surfaces: MCP & First API Slice ✅

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

## `v0.0.7` — Hardening & Daemon Lifecycle ✅

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

## `v0.0.8` — Threat Model & Security Pass ✅

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

## `v0.0.9` — Release Readiness & Residual Hardening ✅

The step between "the security pass is done" and "binaries go on machines that matter."
v0.0.8 ended with a signed-off threat model and a residual-risk register; this milestone
discharges what that register carried, and makes the build **publishable and
identifiable** so `v0.1.0-beta` can be purely about proving the path on real hardware.
Nothing here is new surface — it is the last mile of the existing one.

**Deliverables**
- **Close the last known Raw Exec bypass** (#227 → #248): an anchored per-element deny is
  evadable by merging the denied token into an adjacent argv element, because argv element
  boundaries are attacker-controlled and are not canonicalized before matching. **Canonicalize
  argv before the deny pass** (decided 2026-07-24, following the ADR-0018 precedent for
  `file.read` paths): match deny patterns against the whitespace-split canonical elements as
  well as the raw ones — strictly additive, so the change can only turn Allows into Denies.
  Short ADR (0019), plus a guard on whitespace in `argv[0]` and the neighbouring shapes as
  regression tests. No known bypass may survive into a milestone that ships binaries.
- **Version identity on both binaries** (#249): the daemon has reported a hardcoded `0.0.1`
  since v0.0.1 and the Relay reports nothing at all — which makes the ADR-0014
  minimum-version dispatch gate (correct plumbing, fictional input) untruthful and a tagged
  release unverifiable. Stamped builds, `--version`, fleet-visible version in the registry.
- **CD: publish checksummed release artifacts on tag** (#44 → #250): static musl
  `relay-daemon` + `relay`, `SHA256SUMS`, GitHub pre-release, and a documented
  naming/pinning convention config management can pin against and **verify before install**.
  Container images, SBOM, and cosign signing stay follow-ups (artifact signing revisits
  alongside v0.8.0's key-custody work).
- **Finish the fuzzing deliverable** (#238 → #252): nightly `cargo-fuzz` over the prost
  decode surface — the untrusted-bytes entry point #218's stable-toolchain proptest suite
  could not reach. Nightly-only; per-PR CI stays stable.
- **Close the lint-gate hole** (#239 → #251): `cargo clippy` never compiled `#[cfg(test)]`
  code, so lint findings in the daemon's test modules — where the Policy red-team harness
  lives — were invisible to the merge gate.
- **MCP result-shape legibility** (#207 → #253): `exit_code: -1` as a did-not-run sentinel,
  an empty `job_id` on plan responses, and `allowed_args` mixing `null` with `[]`.
  Legibility is security-relevant (ADR-0001/0003), not cosmetics.

**Acceptance**
- The #227 reproduction is denied, its neighbouring shapes are covered by tests, and the
  register entry is discharged or explicitly narrowed.
- Pushing a `v*` tag publishes verified, checksummed, self-identifying artifacts; a
  digest mismatch fails the documented install path.
- A daemon installed **from a published artifact** enrolls, connects over mTLS, is
  dispatched to, enforces Policy, and is audited — across ≥2 Nodes; its true version drives
  the `outdated` gate correctly (#254, the milestone gate).
- `cargo clippy --all-targets -D warnings` is clean and gated; the nightly Rust fuzz job
  runs bounded with a zero known-crash count.

**ADRs:** new ADR (argv canonicalization for Raw Exec); 0014 (version gate, IaC-distributed
upgrades), 0007 (static musl artifact), 0001/0002 (the gate being hardened), 0003 (MCP
surface legibility). Discharges residuals from the v0.0.8 register.

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
- **Self-serve evaluation** — added 2026-08-19 as five issues, designed out 2026-08-18/19
  into four ADRs and thirteen work items. This milestone already asks for "documented,
  repeatable setup from a clean environment"; this is what makes that true rather than
  aspirational. Full breakdown, dependency order, and per-issue acceptance:
  [`docs/design/self-serve-enrollment.md`](docs/design/self-serve-enrollment.md).

  Standing up a Relay and joining five Nodes is ~51 discrete acts today, across seven
  artifacts that must reach every Node with three different trust properties. The target
  is four commands and two artifacts.

  **Decisions** — [ADR-0030](docs/adr/0030-relay-init-and-the-boundary-of-the-relay-binary.md)
  (what belongs in the `relay` binary; `relay init` as one atomic first-boot transaction) ·
  [ADR-0031](docs/adr/0031-one-server-certificate-and-the-fingerprint-pinned-join-string.md)
  (one server cert for both listeners, multi-SAN, join string replaces
  `RELAY_CA_BUNDLE_PATH`, server-cert rotation) ·
  [ADR-0032](docs/adr/0032-enrollment-bundles-are-minted-and-rendered-in-one-act.md)
  (mint and render are one act) ·
  [ADR-0033](docs/adr/0033-first-party-installation-artifacts.md) (no `curl | sh`;
  installer in the release; daemon OS packages first; Policy as a `noreplace` conffile).

  **Relay (Go)** — #403 server-cert rotation *(live defect; lands first and alone)* ·
  #404 one cert + multi-SAN · #405 enrollment-bundle rendering *(blocked by #397)* ·
  #400 `relay init`.
  **relay-daemon (Rust)** — #406 join string + CA fingerprint pinning, replacing
  `RELAY_CA_BUNDLE_PATH` *(the daemon half of #401)*.
  **Packaging** — #407 `relay-install.sh` in the release · #408 daemon `.deb`/`.rpm` ·
  #399 Relay container image *(evaluation artifact; deliberately no daemon image — #389)*.
  **Migration & docs** — #409 dev fleet + e2e onto `RELAY_JOIN` · #410 operations-docs
  rewrite and the `GLOSSARY.md` **join string** entry · #402 quickstart.

  #398 is satisfied by ADR-0030. One question stays open: whether to build
  `relay-daemon preflight` (design doc, "Open — needs a call").

  > **Why this is here and not in an Ansible milestone.** #361 was going to grow into a
  > first-party Ansible collection; it was triaged down to a thin role and sequenced
  > behind this work. An Ansible collection cannot make evaluation easier, because
  > evaluation is not gated on Ansible — `docker compose up` already works. What is
  > actually missing is a path from the laptop fleet to real machines, and a bootstrap
  > chain that does not read as a one-way door. Notably, the fear driving it was
  > unfounded: everything an operator is asked to copy is re-mintable, and the only
  > unrecoverable artifact — the CA private key — is the one thing never copied by hand.
  >
  > **Closed out 2026-08-18.** That last observation is exactly what ADR-0031 leans on to
  > replace the hand-couriered CA bundle with a fingerprint, and #361 itself is now closed
  > as superseded by #405 — which renders the same playbook from the capability layer, so
  > it lands on the Control API, MCP, and the Console from one implementation.

**Acceptance**
- Stand up a Relay, enroll ≥3 Nodes via a reusable token, drive a Selector-targeted
  Operation from an MCP client, and read the audit trail — on real machines.
- Documented, repeatable setup from a clean environment.
- Manual validation: `docs/testing/validate-v0.1.0-beta.md` (the real-hardware runbook)
  executed and signed off.

**ADRs:** all of 0001–0014; security posture proven in v0.0.8.

---

## `v0.2.0` — Template Engine & Shipped Catalog (post-beta) ✅

The typed path grows without waiting for signing (issue #266; re-sequenced 2026-08-03).
Template **execution** is separable from template **distribution**: a template loaded from
a local, root-owned file beside `policy.toml` shares Policy's trust root (ADR-0002
unchanged), and a catalog shipped inside the daemon package is trusted the way the binary
is. v0.8.0 shrinks to signing + courier distribution of the same objects.

**Deliverables**
- **Template-tier ADR** (#266): operator-authored shell templates with named,
  typed-validated parameter slots; substitution can never alter command structure;
  mandatory `risk_class` (ADR-0012); Policy governs templates exactly like Native
  Operations (deny-beats-allow); the shell boundary treated as hostile — red-team tests
  are an acceptance criterion, not a follow-up. Includes the **data-egress governance**
  section (owner review 2026-08-04): what the shipped catalog makes *reachable*, not just
  an `/etc/shadow` deny-list.
- **Prerequisite refactor**: the Operation vocabulary behind a single
  name→(handler, arg-shape, risk-class) lookup (architecture review 2026-07-07,
  candidate 3), so the template tier registers instead of adding dispatch match arms.
- **Native-vocabulary freeze**: frozen at the current four. `system.facts` + `file.read`
  stay native as platform intrinsics; `service.restart` + `pkg.install` grandfathered.
  New vocabulary = templates.
- **Local template loading**: root-owned template files beside Policy; template-set
  fingerprint reported beside the Policy fingerprint; per-Node vocabulary discovery via
  `list_operations`/`describe_node`; distinct `unsupported` per-Node outcome; **template
  packs** convention.
- **Shipped read catalog**: first-party pack installed with the daemon package — process
  list, service status, disk/mount usage, listening ports, package inventory, bounded log
  tail, file checksum — all `read` class (absorbs the old v0.7.0 native read-Op batch).
- **Shipped default read Policy** (short ADR): `read` pre-allowed out of the box with a
  confidentiality deny-list; `mutate` + Raw Exec stay opt-in whitelist. Engine semantics
  unchanged — only the shipped file. A freshly enrolled Node is fully interrogable with
  zero Policy authoring.
- **`policy check` grows template linting** and the **self-reference lint** (#287): warn
  when an allow rule's reach includes the daemon's own config/binary/unit.
- **Decide #288** (read auditing / output-retention posture) before the catalog makes
  reads ubiquitous.

**Acceptance**
- An operator authors a local template; the daemon loads and fingerprints it;
  `run_operation` uses it; a parameter violating its validation is refused daemon-side; a
  Node without the template reports `unsupported`.
- The template red-team suite (parameter-injection attempts against the shell boundary)
  passes; no known bypass survives.
- A Node enrolled with the shipped default Policy answers the full read catalog with zero
  local authoring; a deny-listed path is refused.
- `policy check` lints templates and flags a self-referential allow rule.
- Manual validation: `docs/testing/validate-v0.2.0.md` written and signed off.

**Closed 2026-08-10.** Every implementation issue merged: #266 (ADR-0021), #289
(vocabulary lookup), #290 (template engine), #291 (local loading, template-set
fingerprint, `unsupported`, per-Node discovery), #292 + #287 (`policy check` template
linting + self-reference lint), #293 (shipped read catalog), #294 (ADR-0022 default read
Policy).

**Manual validation deferred — owner decision, 2026-08-10.** `docs/testing/validate-v0.2.0.md`
is written but has not been executed; the automated suites (`make test`,
`make test-integration`, `make test-crossbinary`, CI) were accepted as sufficient to close
this milestone. This is the convention's first recorded waiver — see
[docs/testing/README.md](docs/testing/README.md) rule 6, amended in the same change to
make a waiver an explicit, recorded act rather than an omission. The script stands ready
for the next fleet run; **what it would have caught that CI cannot is listed in its own
step 9 preamble** — real systemd/journalctl/ss/dpkg behavior behind the shipped catalog,
the loader's refusals against real file ownership, and per-Node vocabulary across two
genuinely different machines.

**Carried forward, still open: #288** (audit reads? / output-retention posture),
human-owned. ADR-0021 asked for it to be settled *before* the catalog made reads
ubiquitous; the catalog is now live with the question open. It is not a code deliverable
of this milestone, so it does not block the close, but it is the one debt this milestone
leaves behind — v0.9.0 re-checks output retention against read-lane volume and is its
natural home if it is not decided sooner.

**ADRs:** ADR-0021 (template tier, amended 2026-08-10 with the self-reference lint and
the rejected daemon-side deny floor), ADR-0022 (default read Policy, amended with the
catalog's allow rules and three further denied paths), 0012; ADR-0002 unchanged.

---

## `v0.3.0` — Accounts & Access (post-beta) ✅

The unified identity layer (ADR-0010) replaces the single seeded credential — and, per the
2026-08-07 attribution design (`docs/design/approval-and-attribution.md`), becomes the
substrate for everything after it: approvals need verifiable approvers, the Console needs
login, audit needs the verified/asserted split.

**Deliverables**
- **Account model**: Accounts (human and machine) with roles
  (`viewer` / `operator` / `admin`); the config-seeded credential becomes the first admin
  Account. Machine Accounts are how orchestrators (Gleipnir) get identities.
- **API Token lifecycle**: mint (shown once, hashed at rest, `glp_` prefix), revoke,
  expiry, last-used; tokens bound to Accounts and inheriting their role.
- Account CRUD + token endpoints on `/api/v1`.
- **MCP endpoint authenticates via Account API Tokens** (retiring the interim shared
  credential); the AI-agent becomes a machine Account whose role gates Raw Exec centrally.
- **OAuth 2.1 resource-server support on the MCP endpoint**: interactive humans connect
  through their harness's standard OAuth flow and get per-human authenticated sessions;
  static machine tokens remain for headless drivers. The standards-based answer to "under
  whose authority is this session operating."
- **Audit: verified/asserted lanes.** Attribution by Account (and token) on every action,
  every surface — plus the **asserted lane** (#276): `on_behalf_of` (user/team as
  free-form string; IdP-group federation is the later direction), session/change refs,
  W3C `traceparent`. Asserted fields structurally distinct from verified fields.
- **Decide #279** (pull per-Account rate limits forward into this milestone or leave
  Deferred).

**Acceptance**
- An `operator` machine Account's token drives `run_operation` via MCP but is refused
  `raw_exec`; an `admin` token is not.
- A human completes an OAuth flow from an off-the-shelf MCP harness; their session's
  dispatches attribute to their Account.
- Revoking a token immediately cuts its access; the audit trail attributes each action to
  its Account and records asserted context in the separate lane.
- The seeded credential still works and appears in audit as the founding admin Account.
- Manual validation: `docs/testing/validate-v0.3.0.md` written and signed off.
  **⚠️ Outstanding — the script does not exist.**

> **Status:** shipped. Two acceptance items remain open: the script above, and decision
> **#279** (whether per-Account rate limits come forward into this milestone or stay
> Deferred), which is listed as a deliverable and is still an open issue.

**ADRs:** 0010 (Account model); builds on 0003. Auth code → human-merge lane, always.

---

## `v0.4.0` — Control API: Execution & OpenAPI (post-beta) 🚧

Complete the REST control plane (ADR-0010): the programmable superset — administration
*and* execution — for IaC tooling, CLIs, and extensions built on Relay. Plumbing before
porcelain: the Console renders what this API manages.

**Deliverables**
- Execution endpoints through the shared capability layer: `run_operation`, `raw_exec`
  (requires `admin` role), plan mode, Job/Task status and result queries.
- Published, versioned **OpenAPI** spec for `/api/v1`; a documented Ansible example:
  vault-managed bootstrap credential → token mint → fleet enrollment, end to end.
- **Generated Go client** for `/api/v1` — the spec's conformance test: a document that is
  valid and route-complete can still be unusable by a real generator, and generating and
  compiling a client on every build is what catches that. The output is deliberately
  **not committed** (nothing imports it); `make apiclient-check` regenerates, compiles,
  and asserts every `operationId` got a client method.
- ~~**Official CLI** (issue #137)~~ — **cut 2026-08-13 (owner decision).** The CLI was
  built (admin verbs, generated transport, config/auth resolution) and then deliberately
  removed. Two reasons: the Admin Console (v0.6.0/v0.7.0) covers the same admin and
  execution surface with better safety ergonomics (step-up re-auth rather than
  `--apply`), and the one workflow that appeared to *require* a CLI — v0.8.0 signing —
  does not. Signing belongs to standard tooling the operator already has key custody for
  (cosign, `ssh-keygen -Y`); `policy check` already ships in `relay-daemon`; push is an
  API call; verification lives in the daemon. **Uploading a signature is not signing**,
  so the Relay never holds the key either way and nothing bespoke is needed. What
  survives is the generated client above. Reopen #137 if operators ask for a terminal
  surface once the Console is real.
- (System Model endpoints move with the System Model itself — see v1.1.0; ADR-0010's
  capability-parity rule applies when it lands.)

**Acceptance**
- An Ansible playbook stands up the Relay and enrolls Nodes end-to-end with no manual
  steps, using the vault-managed bootstrap Account.
- `run_operation` via `/api/v1` returns per-Node results consistent with MCP's;
  `raw_exec` requires `admin` and is refused for an `operator` Account.
- A client generated from the OpenAPI spec can drive the fleet.
- A Go client generated from the spec compiles and covers every operation the spec
  declares (the conformance gate) — the CLI acceptance this replaced was cut with the
  CLI itself; see the deliverables above.
- Manual validation: `docs/testing/validate-v0.4.0.md` written and signed off.

**ADRs:** 0010 (Control API); builds on 0003 (capability surface), 0004 (Jobs).

---

## `v0.5.0` — Approval Callout (post-beta) ✅

Out-of-band human approval for gated dispatches (epics #208/#210; issues #268–#272;
design: `docs/design/approval-and-attribution.md`). Notify via MCP, decide out-of-band:
Relay authors the request content, so the AI/harness can never truncate or spoof what the
approver sees; the guarantee never depends on harness behavior.

**Deliverables**
- **Approval ADR** (#268) — written: [ADR-0027](docs/adr/0027-approval-callout-notify-via-mcp-decide-out-of-band.md).
  The attribution triple (`requested_by` verified /
  `on_behalf_of` asserted / `approved_by` verified); the **confirmation ladder**
  (no-gate → self-confirmation "are you sure" → second-person); MCP-originated calls are
  agent-grade regardless of whose OAuth identity authorizes the session; approval
  ergonomics/fatigue designed in (Plan-shaped approval objects, diffs, batching).
- **Pending-approval Job state + root-owned approval-gate config** (#269): rule grammar
  `match (risk class · blast · selector namespace · principal · operation) → requirement
  (count · audience · requester_allowed · channel · ttl)`. Narrows-only, file-only, above
  the AI's reach.
- **Configurable quorum**: v1 config exposes `count: 1|2`; the stored schema is
  requirement-vs-set-of-decisions from day one (the Job-stages precedent) so N-of-M and
  richer rules (#285 Cedar evaluation covers approval rules + Grants together) land
  without migration. Each decision is its own audit record; partial state visible.
- **Out-of-band decision endpoint** (#270) — the universal path; **MCP Tasks extension**
  for parked Jobs (#271) as the delivery envelope. **channel strength** (in-band answer vs
  authenticated out-of-band decision) is per-rule config.
  > **Corrected 2026-08-17 (ADR-0029).** This bullet and the acceptance criterion below
  > originally named elicitation as "the primary, first-class channel". That was written
  > before #267 made the MCP handler stateless (`JSONResponse: true`), which removed the
  > stream a server-initiated `elicitation/create` needs — and before MCP 2026-07-28
  > removed server-initiated requests outright and forbade `InputRequiredResult` on
  > `tasks/get`, which is what #272 specified. **Both MCP elicitation envelopes named here
  > were non-conformant, and #272 is closed as superseded.** The in-band rung is delivered
  > instead through the tool surface (`approve_request`, ADR-0029), which every MCP client
  > already supports; MRTR (SEP-2322) is a second envelope over the same decision path when
  > clients negotiate 2026-07-28.
- **Plan-hash binding**: approvals bind to the content-addressed Plan (op, args, resolved
  fan-out); material drift at dispatch re-parks for re-approval. **TTL** on parked Jobs.
- **Batch/window approvals**: one approval covering a declared batch or scoped time
  window, every covered Job auditing to the same approval ID — a time-boxed *narrowing*
  grant.

**Acceptance**
- A gated Gleipnir dispatch parks; the approver receives the Relay-authored Plan (via the
  `pending_approval` result, and — since ADR-0029 — answerable in-band through
  `approve_request`); the decision lands on the authenticated endpoint for out-of-band
  rules; the Job runs; audit answers "who asked / for whom / who approved" in one query
  with lanes marked.
- A `count: 2` rule dispatches only after two distinct approvers; `requester_allowed:
  false` refuses the requester's own approval.
- Registry drift between approval and dispatch re-parks the Job; an expired approval
  cannot dispatch.
- A machine Account can never satisfy its own gate on any channel.
- Manual validation: `docs/testing/validate-v0.5.0.md` written and signed off.
  **⚠️ Outstanding — the script does not exist.**

> **Status:** shipped, and it grew two things this entry did not plan for.
>
> **Batch/window approvals** (#378) landed as ADR-0027 decision 12: one human decision
> covering a bounded set of future dispatches, because forty elicitations produce forty
> rubber stamps and a rubber-stamped approval is worse than none.
>
> **The in-band channel became reachable** ([ADR-0029](docs/adr/0029-in-band-approval-through-the-tool-surface.md)).
> ADR-0027 spelled `channel: "in-band"` in the config grammar and then never made any
> surface able to emit such a decision, so the setting was inert and the product shipped a
> two-person-only mechanism. ADR-0029 reconciles that against ADR-0028's guard.

**ADRs:** 0027 (approval callout, #268), 0029 (in-band channel); builds on 0011 (Plans),
0010 (Accounts), 0013 (Job states), 0002 (Policy stays the floor an approval cannot lower).

---

## `v0.5.1` — MCP Tasks Extension (post-beta) ✅

The premium delivery envelope v0.5.0 named but could not build (#372–#377). SEP-2663 is
Final; `modelcontextprotocol/go-sdk` v1.7.0 does not implement it and
[go-sdk#626](https://github.com/modelcontextprotocol/go-sdk/issues/626) is open with no
timeline. **Relay implements the extension itself, as a bounded shim with a written
removal condition — never a fork** ([ADR-0028](docs/adr/0028-mcp-tasks-extension-transport-layer-shim.md)).

This milestone changes **how an agent waits**, and nothing about **who may decide**.

**Deliverables**
- **ADR-0028** (#372) — the shim boundary, the two preconditions it rests on (the SDK
  refuses JSON-RPC batching; the handler runs stateless/JSON, so one message in and one
  object out), and the deletion condition.
- **MCP task handle** (#373) — domain type + durable store. One handle per **parked
  dispatch**, not per Job: parking creates no Job, so the handle carries two nullable
  bindings rather than one overloaded ID. Status is derived from the live approval Request
  on every read, never from a stored column. Owner-only, and a handle that is not yours is
  indistinguishable from one that never existed.
- **`tasks/get` and `tasks/cancel`** (#374) as SDK custom methods — no shim needed for this
  half. `tasks/cancel` ends the *client's* interest: a running Job cancels through the
  ordinary path, and a still-parked request stays pending and decidable.
- **The `CreateTaskResult` shim** (#375), gated on the client advertising
  `io.modelcontextprotocol/tasks`. A no-op object for every request that is not a
  Tasks-capable `tools/call`; when in any doubt, pass through untouched.
- **Structural guards + wire conformance** (#376) — the shim cannot import the MCP SDK at
  all, `tasks/update` is a build failure, both guards have tests that plant a violation and
  assert it is caught, and byte-exact goldens catch SDK-upgrade drift that would otherwise
  degrade the shim into a silent no-op.
- **Docs, validation, removal tracking** (#377).

**Out of scope, as a boundary rather than an omission:** `tasks/update` and any
`inputRequests` elicitation. That is an approval decision arriving over the AI's own MCP
session, and whether an in-band answer can ever count is #272's open rung-2 question.
Implementing it requires amending both ADR-0028 and the structural guard, in front of a
person.

**Acceptance**
- A Tasks-capable client's gated `run_operation` returns a conformant `CreateTaskResult`;
  the returned `taskId` resolves through `tasks/get` and reports results once approved.
- A client that did not advertise the extension gets byte-identical pre-v0.5.1 behaviour.
- Cancelling a parked handle leaves its approval request pending, queued, and decidable.
- Polling another Account's handle is refused, indistinguishably from an unknown one.
- Manual validation: `docs/testing/validate-v0.5.1.md` written — **run waived, 2026-08-17**,
  on the v0.2.0 precedent: no available MCP client implemented Tasks, so the end-to-end
  step had nothing to run it with. The waiver and what it would have covered are recorded
  in the script's header.

**ADRs:** 0028 (Tasks shim, #372); builds on 0027 (approval callout), 0009/0010 (one
capability layer, three thin surfaces).

---

## `v0.6.0` — Admin Console: Monitoring (post-beta) 🚧

The human web UI, phase one: eyes only. Server-rendered Go + HTMX, internal-only
(ADR-0009), logging in against the v0.3.0 Account model.

**Per-screen specifications: [`docs/design/console/`](docs/design/console/)** — a foundations
document, one spec per screen, and an open-decisions register that an implementer must read before
writing code. Backend dependency map: `docs/design/console-backend-coverage.md`.

> **The two defects that gated every Console milestone have landed** (both closed 2026-08).
> #403 (the Relay's server certificate never rotated — both listeners shared it, so the Console's
> own TLS rode on the bug and broke fourteen days after the process started) and #397
> (enrollment-token mint, Node revoke and Freeze engage/release had no role gate). Neither was a
> Console problem; both made Console work unshippable. Both were landed by hand ahead of the loop,
> as `blocking` issues are. #397 also makes Freeze engage human-principal only.

**Deliverables**
- **The Console shell** (`console/11`) — layout, HTMX conventions, session and step-up state,
  CSRF on every mutating route, strict CSP, and the SSE client. ADR-0026 makes CSP and CSRF
  controls on a fleet-RCE path rather than hygiene, so this is built once, first, and carefully.
  The `no_dispatch` structural guard extends to the Console package at creation, not at the
  composer.
- **Login** (`console/12`) — username/password (hashed at rest) with optional OIDC; per-human
  audit attribution; `viewer` role enforced; session/cookie auth.
- **Fleet view** (`console/01`) — live registry, group-by-first with rollup cards, per-Account
  saved views, a view-scoped delta lane, the pixel wall, facets, and an anomaly-first deviation
  table. Renders `state:` labels (**ADR-0034**), which is where fleet-scale targeting comes from.
- **Node detail** (`console/02`) — Facts (this page only), effective Policy from `policyview`,
  template vocabulary, cert and enrollment provenance, recent Tasks, pin-to-compare.
- **Activity** (`console/04`) — the live stream and the audit trail as **one** Job-grained
  surface; live tail on is "now", filtered is history. There is no separate Jobs destination.
- **Job detail** (`console/13`) — grouped outcomes across all eight of the wire vocabulary,
  legible at 3 Nodes and at 10,000, with identical output clustered.
- **Agent activity** (`console/03`, stream only) — every MCP tool call as it happens, per
  Account (MCP is stateless, ADR-0028 — there are no sessions), paired request and result,
  filterable. The trust surface: it shows verified requests, never the model's
  reasoning. Read output is never retained, and the screen says so.
- **Read egress** (`console/17`) — what has been read, by whom, from where, over the existing
  `KindRead` audit records. No new collection. ADR-0021 says reading is exfiltration; this is the
  first surface that admits it.
- **Approval queue and approval object** (`console/14`, `console/08`), **read-only** — pending
  approvals with their Plans and quorum state; deciding arrives in v0.7.0.
- **Day one** (`console/10`) — the Console with zero Nodes, watching live for the first
  enrollment and surfacing rejected attempts with their reason.
- **SSE event seam** (#416) — an in-process pub/sub with **four publishers**: registry
  transitions, Job transitions, MCP tool calls, and enrollment attempts. Monotonic IDs from a
  bounded buffer with `Last-Event-ID` resume and a `gap` event. It carries tool-call *arguments*
  and **never** read results; assert that structurally.
- **Audit and Job query seams** (#441) — kind, principal, time range, Node, Operation, path/arg,
  outcome, cursor pagination, per-principal counts by time bucket — in the **capability layer's
  read lane**, never as Console→store calls. Activity, agent history and read egress read through
  them.
- **Registry carries liveness and certificate validity** (#440) — `cert_not_after`, `enrolled_at`,
  `renewal_count`, `last_renewed_at`, connected/disconnected — what ADR-0034's markers and Node
  detail read; lands before `state:` evaluation (#414).
- **Per-Account Console preference store** (#442) — saved views and the delta-lane watermark; a
  preference, not a runtime object.
- Internal-only serving.

**Acceptance**
- An operator logs in and watches fleet state, Jobs, agent tool calls, pending approvals and audit
  live — with **zero mutating routes** in the Console, where *mutating* means reaching the
  capability layer's write or dispatch path; a session, a saved view or an audit query is not
  that, and Cancel is v0.7.0 (verified by review).
- A `viewer` Account sees everything and can change nothing, and its rendered navigation is
  **structurally smaller** — the routes it may not use are not mounted.
- No Fact appears on a fleet row or in a facet; Facts appear on Node detail and nowhere else.
- A fleet of 10,000 Nodes renders without a list of rows until one is explicitly requested.
- No inline script and no `hx-on:` attribute survives in any rendered page.
- Manual validation: `docs/testing/validate-v0.6.0.md` written and signed off.

**ADRs:** 0009 (Console, monitoring phase); renders 0010's Account model; **0034** (`state:`
labels — required by the fleet view); 0021/0025 (what the read-egress surface may and may not
show).

---

## `v0.7.0` — Admin Console: Administration & Execution (post-beta) 🚧

Phase two: the keys — and, per [ADR-0026](docs/adr/0026-admin-console-execution-surface.md)
(#264; supersedes ADR-0009's no-execution clause, invariant #10 amended in the same
change), the execution surface. Manual experimentation is the trust-building wedge: a skeptical
operator probes the boundary themselves, then hands the keys to the AI. The wall is the same wall.

**Per-screen specifications: [`docs/design/console/`](docs/design/console/).** The composer is
deliberately last, behind the step-up and approval machinery it depends on.

**Deliverables**
- **Step-up re-authentication** on privilege-granting actions and on mutate apply — the strongest
  per-action intent binding in the system. A recent-auth window on the session, its length
  file-only configuration that no Account can extend.
- **Lifecycle and the incident ladder** (`console/16`) — the three rungs on one surface in
  ascending blast radius: quarantine (`relay:`) < revoke a Node < Freeze. (Account suspension,
  ADR-0035, was drafted and deferred — not adopted; #443.) Current state before controls. Cancel is named as the only instrument for
  in-flight Tasks. **Blocked by #397**, which leaves revoke and Freeze ungated.
- **Label management** (ADR-0020) — post-enrollment `relay:` set/remove (`admin` + step-up) and
  operator-set `tag:` grouping, with bulk tag-from-filter as the fleet view's one action.
- **Cancel** from Job detail and the agent stream (`console/13`, `console/03`) — in-flight Tasks
  only, through the capability layer, audited. (Disconnect and Suspend were cut: MCP is stateless
  so there is no connection to drop, and suspension is deferred.)
- **Access management** (`console/15`) — view/create/disable Accounts (incl. machine Accounts for
  AI-agents), assign roles, mint and revoke API Tokens. Every privilege-granting act is step-up
  and audited; an API token's plaintext is shown once.
- **Add Nodes** (`console/09`) — mint an Enrollment Token and render the join artifacts in **one
  act** (ADR-0032), shown once and never reproducible. `admin`-gated, which **requires #397**.
- **Approval-queue decisions** (`console/14`, `console/08`) — approve/deny with step-up, partial
  quorum, batch expansion, and the diff-against-last-approved callout the v0.5.0 shape key exists
  to serve.
- **Policy Author** (`console/06`) — compose a Node Policy from the real Operation vocabulary and
  take the file away, with an Ansible drop-in that validates before it lands. **Generate-and-copy
  only**: the Relay has no code path that writes Policy to a Node (ADR-0002, invariant #2).
- **Policy fix, from a deny** (`console/07`) — the reactive half: one deny in, one minimal rule
  out, plus the rollout ladder that ends at confirming the fingerprint changed.
- **Execution composer** (`console/05`) — `list_operations` schemas, plan-by-default, role-gated
  (`operator`+ run, `admin` raw_exec), **`console_execution = on|off`** root-owned flag (default
  on), and the `no_dispatch` structural guard covering the Console package.

**Acceptance**
- An `admin` logs in, mints a scoped Enrollment Token, revokes a Node, creates an `operator`
  machine Account (passing step-up), approves a parked Job, and runs a `mutate` Operation only
  after its Plan renders and step-up passes — every action attributed in audit; a `viewer` is
  refused all of it.
- With `console_execution = off`, the composer is **absent** and no execution route exists — not
  disabled, not greyed out.
- A Console route that attempts to dispatch outside the capability layer does not compile.
- An `operator` filters the fleet and bulk-applies a `tag:` label without step-up; setting
  `relay:quarantine` demands `admin` + step-up; no surface anywhere writes a `node:` or `state:`
  label.
- Freeze engage is refused to a machine Account of any role; only a human principal may pull the
  cord. Quarantine by Selector refuses any term outside `relay:`.
- The Policy Author emits a file `relay-daemon policy check` accepts, and no route on it writes
  anything anywhere.
- Manual validation: `docs/testing/validate-v0.7.0.md` written and signed off.

**ADRs:** 0026 (Console execution, supersedes 0009's no-execution clause), 0009 (remainder
stands), 0010, 0020 (label management), 0032 (enrollment bundle
rendering), 0002/0022 (why Policy authoring stops at the clipboard). CLAUDE.md invariant #10 was
amended with ADR-0026 and invariant #7 with ADR-0034; the threat model carries the delta as the
"Hijacked Console session" adversary and residual **R11**.

---

## `v0.8.0` — Operator-Signed Distribution (pre-1.0)

Central administration stops requiring CM round-trips — without surrendering the moat
(issues #135/#136). Slimmed by the 2026-08-03 re-sequencing: template *execution*
semantics landed in v0.2.0; this milestone signs and couriers the same objects.

**Deliverables**
- **ADR-0002 rewrite** — "locally-rooted" becomes **operator-rooted**: Policy and
  template bundles authored centrally, **signed by an operator key the Relay never
  holds**, distributed over the existing mTLS channel, verified by the daemon against a
  public key **pinned at enrollment** before load. The Relay is a **courier, never an
  author**. Today's local-file mode is retained as the hardened tier (air-gapped fleets).
- **New signing ADR**: bundle format, key custody (workstation/CI — never the Relay
  host), anti-rollback via signed monotonic versions, key rotation & compromise runbook.
- **Signing workflow on STANDARD TOOLING** (revised 2026-08-13, with the v0.4.0 CLI
  cut): the operator signs a bundle on their workstation with a tool they already have
  key custody for — cosign, `ssh-keygen -Y sign`, or minisign — rather than a bespoke
  Relay signer. Linting already ships as `relay-daemon policy check`; pushing the signed
  bundle is an ordinary `/api/v1` call (curl, config management, or the Console);
  verification lives in the daemon against the enrollment-pinned public key. The Relay
  never holds the signing key, and uploading a *signature* is not signing — so no custom
  keygen, no bespoke key format, and one less crypto surface of our own. The signing ADR
  records the chosen tool and bundle format. The AI-agent may *draft* templates; nothing
  loads until a human signs.
- Artifact signing for release binaries revisits here alongside the key-custody work
  (deferred from #250).

**Acceptance**
- An operator signs a Policy/template bundle on a workstation and pushes it via the
  Relay; daemons verify and load it; a bundle signed by the wrong key — or an older
  version replayed — is refused.
- A compromised-Relay simulation (forged/wrong-key bundle over the wire) cannot widen any
  Node's Policy or template set.
- Manual validation: `docs/testing/validate-v0.8.0.md` written and signed off.

**ADRs:** rewrites 0002; new signing ADR; 0012.

---

## `v0.9.0` — Read Lane: Streaming & Aggregation (pre-1.0)

The remainder of the old read-lane milestone (its vocabulary and default Policy shipped
with v0.2.0's catalog). Positioning rule unchanged: **interrogation, not monitoring** —
on-demand, Policy-gated questions against live state, never a metrics pipeline.

**Deliverables**
- **Live output streaming, read lane first** (ADR-0004 says the transport already
  supports it): bounded `log tail --follow`; the watch step of a canary. Mutate-lane
  streaming stays deferred.
- **Result aggregation primitive**: an AI cannot read 100k per-Node outputs.
  Histogram-by-output with clustered samples ("97,412 identical / 3 divergent — here are
  the 3"), built against the read lane first; the Console's large-fleet views consume the
  same primitive. Proto/Job-schema impact settled **before** the v1.0.0 freeze.
- Audit **output-retention posture** re-checked against read-lane volume, incorporating
  the #288 decision — `read` means "cannot change Node state", not "safe to see".

**Acceptance**
- A fleet-wide `file.checksum` returns an aggregated histogram; a divergent Node is
  identified without reading per-Node output.
- A streamed `log tail --follow` delivers live output over MCP/API and stops on cancel.
- Manual validation: `docs/testing/validate-v0.9.0.md` written and signed off.

**ADRs:** 0012, 0004 (streaming caveat).

---

## `v1.0.0` — Production Release

The stability promise. Not new surface — the point where everything built so far is
declared production-grade, the wire/API contracts are frozen under a compatibility
promise, and the **BSL change-date clock starts** (ADR: licensing). 1.0 is *earned by
hardening and commitment*, not by adding features.

**Scope (what "1.0" means here)**
- The full stack in production shape: execution path (v0.0.3–v0.0.9), templates + shipped
  catalog (v0.2.0), Accounts & identity (v0.3.0), Control API + OpenAPI + CLI (v0.4.0),
  approval callout (v0.5.0), the Admin Console (v0.6.0–v0.7.0), operator-signed
  distribution (v0.8.0), and read-lane streaming + aggregation (v0.9.0) — each beyond
  prototype, with the security pass re-run against the accumulated surface.
- **HA/routing design spike complete before the freeze** (issue #139): the definitive
  list of additive proto/schema changes horizontal scaling needs. The HA *build* stays
  post-1.0 (see Deferred).
- **Contract stability commitment**: `relay.v1` proto and `/api/v1` OpenAPI are frozen —
  additive-only from here, breaking changes require a new version served in parallel
  (ADR-0010, ADR-0014).
- **Operational maturity**: documented upgrade path across a 1.x series, backup/restore
  for the Relay store, and a supported deployment reference.
- **Second security pass** over the complete multi-surface system, since v0.0.8 predated
  Accounts, the Control API, approvals, and the Console — browser attack surface
  (v0.6.0–v0.7.0) and the approval flow explicitly in scope.

**Acceptance**
- A documented, supported production deployment stands up from clean infrastructure and
  survives a full upgrade cycle without data loss.
- Contract-compatibility CI gates are green and the freeze is enforced mechanically.
- The second security pass has no open high-severity findings.
- The `LICENSE` (BSL) is published with finalized parameters and the change-date clock is
  running.

**Resolved 2026-08-07:** the System Model trails 1.0 (see v1.1.0); the Console
(v0.6.0–v0.7.0) is *in* 1.0 scope — #264 makes it part of the trust story, not an
accessory.

---

## `v1.1.0` — System Model (post-1.0)

Give the AI-agent a persistent understanding of the fleet as a connected system
(ADR-0008). Moved post-1.0 on 2026-08-07: the adoption wedge is read + templates +
approvals; the semantic graph is valuable but not on the critical trust path, and
deferring it keeps the 1.0 freeze focused on contracts that already exist.

**Deliverables**
- Git-backed YAML **System Model** store in the Relay: commit-per-change, provenance
  (author, time, reason) on every mutation.
- Semantic layer: **Services** (named Selectors), **Dependencies** (directed edges),
  **Annotations**.
- Grounding from the registry: Nodes and `relay:` labels imported and AI-immutable.
- MCP **Resources** for reading the model; MCP **Tools** for AI writes (`define_service`,
  `set_dependency`, `annotate`, `query_model`); Control API read/write endpoints
  (ADR-0010 parity rule).
- Dependency-aware impact reporting alongside the blast-radius cap.

**Acceptance**
- The AI-agent defines a Service from a Selector, adds a Dependency, and a later session
  reads the same model.
- Every AI change is a git commit with author + reason; a human can `git revert` a bad
  edit.
- `run_operation(service="payments", …)` resolves to the Service's Selector and still
  obeys Policy + blast cap.

**ADRs:** 0008 (System Model); reuses 0003 (Selectors), 0004 (Jobs). Additive-only
against the frozen `relay.v1`/`/api/v1` contracts.

---

## Deferred (each its own ADR when picked up)

- **HA / horizontal Relay scaling** — Node→instance routing registry (ADR-0005 caveat).
  *Build* deferred; the **design spike is required before the v1.0.0 freeze** (issue
  #139).
- **Multi-principal RBAC & Grants** — per-Account authorization rules (Operations ×
  Selectors); a Grant only ever narrows what Node Policy allows, never widens it. Design
  rule when built: a Grant used as a *security boundary* must scope by `relay:` labels
  (ADR-0006). Engine candidate: Cedar (#285) — evaluated jointly with the approval-rule
  grammar (v0.5.0) so Relay never hand-rolls two policy engines.
- **Staged rollout & approval** — first-class rollout spec on Jobs: canary stage → gate
  (`all-success` or `manual-approval` — the v0.5.0 approval mechanism reused as a rollout
  gate) → remainder, executed and audited as one Job. The Job schema's Stages and the
  approval-requirement schema both already anticipate it. Write the rollout ADR pre-1.0;
  execution may land post-1.0.
- **Mutate-lane live streaming** — read-lane streaming lands in v0.9.0; the mutate lane
  stays deferred (ADR-0004 caveat).
- **Postgres store** — swap behind the repository interface when HA lands.
- **Graphic System Model view**; **System Model entry locking** (ADR-0008 notes) — follow
  v1.1.0.
- **Per-Account rate limits** — throttle Job creation per Account so a runaway AI-agent
  loop is bounded in time as well as blast radius. Decide pull-forward into v0.3.0 via
  #279.
- **IdP-federated teams/audiences** — `on_behalf_of` and approval audiences resolved from
  OIDC group claims (direction named in v0.3.0; Relay never grows a native org chart).
- **Expectations (runtime health only)** — advisory, scheduled *read-class* checks;
  findings may *propose* a remediation Job routed through the v0.5.0 approval mechanism;
  nothing auto-executes (ADR-0008 stands). The scheduler must be able to construct
  **read-class dispatches only, enforced by type**. Sits naturally after v0.9.0 +
  v1.1.0.
