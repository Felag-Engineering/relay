# Self-serve enrollment — implementation breakdown

**Status:** live breakdown, maintained. ADR-0030 through ADR-0033 are **merged**, not drafts;
the issues below now live in the GitHub milestone
**v0.6.5 — Install Path: relay init, join string, packages**, which is the authority on what
is in flight (AGENTS.md, "Work the current milestone").

Working document for the `v0.1.0-beta` "Self-serve evaluation" block
([docs/specs/](../specs/) `v0.1.0-beta`). It expands the five issues recorded there
into a dependency-ordered set, after the design conversation of 2026-08-18 settled eleven
decisions across four ADRs.

**Nothing here authorizes work.** Every item below touches at least one of the surfaces
AGENTS.md requires escalating — `proto`-adjacent contract, mTLS/auth/CA code, Policy
distribution, `GLOSSARY.md`, the `Makefile`, or CI. None of it goes through the dev-loop
unreviewed regardless of sequencing.

## The decisions this rests on

| ADR | Settles |
|---|---|
| [0030](../adr/0030-relay-init-and-the-boundary-of-the-relay-binary.md) | What may live in the `relay` binary; `relay init` as one atomic first-boot transaction |
| [0031](../adr/0031-one-server-certificate-and-the-fingerprint-pinned-join-string.md) | One server cert for both listeners; multi-SAN; join string replaces `RELAY_CA_BUNDLE_PATH`; address persistence |
| [0032](../adr/0032-enrollment-bundles-are-minted-and-rendered-in-one-act.md) | Mint and render are one act; no re-render; three formats |
| [0033](../adr/0033-first-party-installation-artifacts.md) | No `curl \| sh`; installer in the release; daemon OS packages first; Policy as a `noreplace` conffile |

## Mapping to the issues already on the ROADMAP

| Existing | Becomes | Note |
|---|---|---|
| #398 — ADR: what belongs in the `relay` binary | **satisfied by ADR-0030** | Close against the ADR |
| #400 — `relay init` | **E4** | Scope unchanged; now depends on E2 + E3 |
| #401 — the join command | **E5 + E6** | Split: daemon-side verification, then steady-state address |
| #399 — container image | **E9** | Unchanged |
| #402 — quickstart | **E12** | Unchanged |
| #361 — thin Ansible role (`v0.4.0` [6/7]) | **closed as superseded** | E3 renders the same playbook from the capability layer (owner decision, 2026-08-18) |
| #397 — enrollment mint has no role gate | **prerequisite of E3** | Rendering on top of an ungated mint would wrap a privilege escalation in a convenience |

---

## Phase 1 — Relay (Go)

### E2a · Server certificate rotation — **live defect, lands first and alone**
**ADR-0031 §5 · escalate: mTLS + CA · no dependencies**

The server certificate is minted once at process start, held static, and carries
`LeafValidity` (336h — the constant documented for *Node identity* certs). Nothing renews
it, so a Relay running longer than fourteen days serves an expired certificate and the
fleet fail-closes off. Unseen only because nothing has run one for two continuous weeks.

- Re-issue through a `GetCertificate` callback when the leaf is within a jittered fraction
  of expiry.
- Give the server leaf its own validity constant; stop borrowing the identity one.

**Acceptance**
- A test advancing past expiry gets a valid certificate without a restart.
- A test asserts the server leaf and Node identity leaf no longer share a constant.

This predates every other decision here and blocks nothing. It should not wait.

### E2 · One server certificate, multi-SAN
**ADR-0031 §1–2 · escalate: mTLS + CA**

- Collapse `main.go:391` and `main.go:575` to one `IssueServerCertificate` call; share the
  `tls.Certificate` between listeners.
- Keep two `tls.Config`s. The Node plane requires a client certificate for every RPC
  except the certless `Enroll`; the control plane requires none.
- SAN set: `-hostname` + detected non-loopback IPs + loopback + a repeatable `-san`.
- Replace the comment at `main.go:572-574`, which currently states the opposite decision.

**Acceptance**
- A structural test asserts the node-plane config requires client certs and the
  control-plane config does not — the failure mode this change makes possible.
- A daemon dialing a detected IP (no DNS) completes enrollment.
- Startup logs the CA fingerprint and the leaf fingerprint, labelled distinctly.

### E3 · Enrollment bundle rendering
**ADR-0032 · escalate: Control API + auth · depends on #397**

- `render: []` on `POST /api/v1/enrollment-tokens`; `renderings` in the response.
- Formats `join`, `ansible`, `shell`. Renderer is a pure function of join string, scope,
  and expiry.
- `admin`-gated — **which requires #397 first.** The gate does not exist today; a `viewer`
  can mint a token that stamps `relay:` labels.
- The `ansible` rendering pins a daemon version + SHA-256 baked into the Relay build
  (ADR-0032 §6), rendered into `get_url` + `checksum` so verify-then-install survives.
- The `ansible` rendering inlines the token (ADR-0030, interim) and carries its expiry in
  a header comment.

**Acceptance**
- A structural test asserts the renderer package has no store dependency.
- OpenAPI spec covers `render`/`renderings`; `make apiclient-check` stays green.
- One audit event per mint, whatever was rendered.

### E4 · `relay init`
**ADR-0030 · escalate: auth + CA · depends on E2, E3**

- One transaction: CA, store, founding admin, first API Token, first Enrollment Token,
  rendered playbook.
- Idempotent — existing CA/store/admin adopted, never recreated or repaired. Re-running
  reports state and emits no new secret without an explicit flag.
- Writes `/etc/relay/relay.env` with `RELAY_CONTROL_ENABLED=true`. The **binary** default
  stays `false`.
- First Enrollment Token defaults to a short TTL (hours), because ADR-0030 inlines it.
- Prints both fingerprints, the Console URL, the admin token, the join string, the
  playbook.

**Acceptance**
- **Falsifier:** `docker/bootstrap.sh` and `docker/mint-credential.sh` are deleted and the
  dev fleet comes up green on `relay init`.
- `init` calls the E3 capability rather than a second implementation.

---

## Phase 2 — relay-daemon (Rust) · parallel with Phase 1

### E5 · Join string and fingerprint verification
**ADR-0031 §3 · escalate: enrollment + mTLS**

- Parse `glp_join_<base64(host:port · ca-fingerprint · enrollment-token)>` from
  `RELAY_JOIN` — one opaque `glp_`-prefixed string, greppable by secret scanners and safe
  unquoted in a shell (ADR-0031 §3).
- Verify the presented chain roots in a certificate whose SHA-256 DER digest matches the
  pin, before anything else happens.
- Remove `RELAY_CA_BUNDLE_PATH` — replaced, not deprecated.

**Acceptance**
- A wrong fingerprint refuses enrollment and exits; it never falls back.
- `RELAY_CA_BUNDLE_PATH` is gone from `config.rs` *and* from
  `daemon/packaging/relay-daemon.env.example` — `daemon/tests/packaging_drift.rs` should
  catch a miss, and that it does is worth asserting.
- The parser gets a fuzz target (`daemon/fuzz/` exists): it is pre-identity attack surface
  reachable by anyone who can hand a Node a config file.

### E6 · Persisted address, `RELAY_ADDR` override
**ADR-0031 §4**

- Persist the Relay address at enrollment alongside identity; use it thereafter.
- `RELAY_ADDR`, when set, wins on every start.

**Acceptance**
- A two-line env file (`RELAY_JOIN`, `RELAY_NODE_LABELS`) enrolls and reconnects.
- Setting `RELAY_ADDR` after enrollment repoints the daemon with no state-directory edit.

---

## Phase 3 — Packaging · depends on E4, E5

### E7 · `relay-install.sh` in the release
**ADR-0033 §1–2 · escalate: CI/release**

Ships beside `SHA256SUMS`. Service account, binary, hardened unit, env file, `relay init`.
Whatever it installs comes under a drift gate of the same kind as
`packaging_drift_test.go` — that drift already happened once and went unnoticed for
several milestones.

### E8 · Daemon `.deb` / `.rpm`
**ADR-0033 §3–4 · escalate: Policy distribution**

`policy.default.toml` → `/etc/relay-daemon/policy.toml` as a conffile /
`%config(noreplace)`.

**Acceptance**
- Fresh install → the Node comes up read-only per ADR-0022, not deny-all.
- **The test that matters:** edit `policy.toml`, upgrade the package, the edit survives.
  An upgrade that restored the shipped default would be a fleet-wide unauthored permission
  change.

### E9 · Relay container image (#399)
**ADR-0033 §5.** Documented as the evaluation artifact, not the production deployment. No
daemon image.

---

## Phase 4 — Documentation

### E10 · Rewrite the operations docs
`relay-install.md`, `relay-daemon-install.md`, `enrollment.md` around the new path.
Includes the DNS guidance (multi-SAN makes DNS optional for the Node plane) and the
fingerprint/trust-store instructions from ADR-0031. Fixes the already-stale claim at
`relay-install.md:112-116` that no packaged Relay unit exists — `relay/packaging/relay.service`
landed in #362.

### E11 · `GLOSSARY.md` — **join string**
**Escalate: AGENTS.md-flagged file.** Must record that it is *not* a synonym for
Enrollment Token; the glossary already lists "join key" as a term to avoid, and the two
entries would otherwise fight.

### E12 · Quickstart (#402)
Ties E4, E5, E7, E8 together. Four commands, two artifacts.

---

## Phase 5 — Migration · depends on E5, E6

### E14 · Dev fleet and e2e suite onto `RELAY_JOIN`
**ADR-0031 · escalate: CI**

Removing `RELAY_CA_BUNDLE_PATH` breaks every existing consumer of the old enrollment
surface, and E4's falsifier only covers `docker/bootstrap.sh`:

- `docker-compose.yml:171-205` — three daemons wired through
  `RELAY_CA_BUNDLE_PATH` + `RELAY_ENROLLMENT_TOKEN`.
- `docker/daemon-entrypoint.sh` — reads the token from a file into the env var.
- `relay/cmd/relay/*_e2e_test.go` and `crossbinary_e2e_test.go` — exercise enrollment
  directly.

**Acceptance**
- `docker compose up` produces an enrolled fleet with no `ca-cert.pem` on any shared
  volume.
- The daemon containers never mount CA material; only the join string reaches them.

---

## Open — needs a call

### E13 · `relay-daemon preflight` *(proposed, unruled)*

**What it is:** a subcommand run *before* `systemctl enable relay-daemon`, answering "will
this Node actually join?" without joining. It resolves the Relay address, completes a TLS
handshake and checks the presented chain against the pinned fingerprint, loads the Policy
file and prints its fingerprint, and confirms the state directory is writable. It
deliberately does **not** validate the Enrollment Token, because doing so would spend a
`max_uses` against a token sized to the batch.

It fits the daemon's existing offline-subcommand pattern (`policy check`,
`dump-operation-schema`) and is outside ADR-0030's boundary question, which governs the
`relay` binary only.

**Why it was raised:** today the whole failure class — SAN mismatch, closed firewall,
group-writable Policy, unreachable address — surfaces as journald lines discovered on N
machines after the fact, which for a 5-Node evaluation means five broken hosts and no
obvious next move.

**Why it might be dropped:** multi-SAN (E2) removes the largest single cause, and `policy
check` already covers the Policy half. The residue is firewall and reachability, which a
`curl` proves nearly as well.

Not carried into any ADR pending a call.
