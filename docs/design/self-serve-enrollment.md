# Self-serve enrollment — implementation breakdown

**Status:** breakdown from the design conversation of 2026-08-18, which settled eleven decisions
across ADR-0030 to ADR-0033 (all accepted). Most items have shipped; each says where it stands.
The GitHub milestone **v0.6.5 — Install Path: relay init, join string, packages** is the
authority on what is in flight (AGENTS.md, "Work the current milestone"), and its
[design plan](plans/v0.6.5-install-path-relay-init-join-string-packages.md) is the step list.

**Nothing here authorizes work.** Every item touches a surface AGENTS.md requires escalating —
`proto`-adjacent contract, mTLS/auth/CA code, Policy distribution, `GLOSSARY.md`, the
`Makefile`, or CI.

## The decisions this rests on

| ADR | Settles |
|---|---|
| [0030](../adr/0030-relay-init-and-the-boundary-of-the-relay-binary.md) | What may live in the `relay` binary; `relay init` |
| [0031](../adr/0031-one-server-certificate-and-the-fingerprint-pinned-join-string.md) | One server cert for both listeners; multi-SAN; the join string; address persistence |
| [0032](../adr/0032-enrollment-bundles-are-minted-and-rendered-in-one-act.md) | Mint and render are one act; no re-render; three formats |
| [0033](../adr/0033-first-party-installation-artifacts.md) | No `curl \| sh`; daemon OS packages first; the Relay as an OS package (amended 2026-10-15) |

## Mapping to the original issues

| Issue | Became | State |
|---|---|---|
| #398 — ADR: what belongs in the `relay` binary | ADR-0030 | closed |
| #400 — `relay init` | **E4** | closed |
| #401 — the join command | **E5 + E6** | closed |
| #399 — container image | **E9** | closed |
| #402 — quickstart | **E12** | open |
| #361 — thin Ansible role | closed as superseded | E3 renders the same playbook from the capability layer (owner decision, 2026-08-18) |
| #397 — enrollment mint has no role gate | prerequisite of E3 | closed by PR #447 |

---

## Phase 1 — Relay (Go)

### E2a · Server certificate rotation — **live defect, lands first and alone**
**ADR-0031 §5 · escalate: mTLS + CA · no dependencies · built (#403)**

The server certificate was minted once at process start with the Node-identity validity
(336h), so a Relay up longer than fourteen days served an expired certificate and the fleet
fail-closed off. The leaf is now re-issued through a `GetCertificate` callback before expiry,
under its own `ServerLeafValidity` constant.

### E2 · One server certificate, multi-SAN
**ADR-0031 §1–2 · escalate: mTLS + CA · open (#404)**

- One `NewServerCertificate` call shared between both listeners, which today each issue
  their own.
- Keep two `tls.Config`s. The Node plane requires a client certificate for every RPC
  except the certless `Enroll`; the control plane requires none.
- SAN set: the hostname + detected non-loopback IPs + loopback + any operator-added names.

**Acceptance**
- A structural test asserts the node-plane config requires client certs and the
  control-plane config does not — the failure mode this change makes possible.
- A daemon dialing a detected IP (no DNS) completes enrollment.
- Startup logs the CA fingerprint and the leaf fingerprint, labelled distinctly.

### E3 · Enrollment bundle rendering
**ADR-0032 · escalate: Control API + auth · unbuilt; deferred in `docs/specs/enrollment.md`,
and DI-35 moved to v0.7.0, where the Console renders bundles**

- `render: []` on `POST /api/v1/enrollment-tokens`; `renderings` in the response.
- Formats `join`, `ansible`, `shell`. The renderer is a pure function of join string, scope
  and expiry.
- `admin`-gated (the mint is role-gated since PR #447).
- The `ansible` rendering pins a daemon version + SHA-256 (ADR-0032 §6), rendered into
  `get_url` + `checksum` so verify-then-install survives.
- The `ansible` rendering inlines the token (ADR-0030, interim) and carries its expiry in
  a header comment.

**Acceptance**
- A structural test asserts the renderer package has no store dependency.
- The OpenAPI spec covers `render`/`renderings`; `make apiclient-check` stays green.
- One audit event per mint, whatever was rendered.

### E4 · `relay init`
**ADR-0030 (amended 2026-10-16) · built (#400)**

Shipped narrower than first planned: `relay init --admin <name>` creates the first admin and
its first API Token, and `--recover <name>` re-mints a token for an enabled human admin. It runs
as the Relay's own account on a store the Relay already created; it creates neither the CA nor
the store, and mints no Enrollment Token. It replaced `relay bootstrap-token` and
`relay console-password`. Behaviour: `docs/specs/relay-configuration.md` RC-28.

---

## Phase 2 — relay-daemon (Rust) · parallel with Phase 1

### E5 · Join string and fingerprint verification
**ADR-0031 §3 · escalate: enrollment + mTLS · built (#401)**

The daemon reads one opaque `glp_join_` string from `RELAY_JOIN` (the Relay's address, its CA
fingerprint and the Enrollment Token), verifies the presented chain against the pin before
sending the token, and refuses a mismatch without fallback. `RELAY_CA_BUNDLE_PATH` and
`RELAY_ENROLLMENT_TOKEN` are gone. Behaviour: `docs/specs/enrollment.md`,
`docs/specs/daemon-installation.md`.

Still owed from the original acceptance: a fuzz target for the parser under `daemon/fuzz/`. It
is pre-identity attack surface reachable by anyone who can hand a Node a config file.

### E6 · Persisted address, `RELAY_ADDRESS` override
**ADR-0031 §4 · built**

The daemon persists the Relay address at enrollment alongside its identity; `RELAY_ADDRESS`, when
set, wins on every start.

---

## Phase 3 — Packaging

### E7 · Relay host install
**ADR-0033 · escalate: CI/release**

`relay-install.sh` was withdrawn before it was built (ADR-0033, amended 2026-10-15): the Relay
host is installed by an OS package that installs, enables where presets allow, and never
starts. Planned as v0.6.5 step S14.

### E8 · Daemon `.deb` / `.rpm`
**ADR-0033 §3–4 · escalate: Policy distribution**

The packages place the live Policy once, if absent, rather than as a conffile (ADR-0033 as
amended; `docs/specs/daemon-installation.md` DI-26).

**Acceptance**
- Fresh install → the Node comes up read-only per ADR-0022, not deny-all.
- **The test that matters:** edit `policy.toml`, upgrade the package, the edit survives.
  An upgrade that restored the shipped default would be a fleet-wide unauthored permission
  change.

### E9 · Relay container image (#399)
**ADR-0033 §5 · built.** The image is a production path (ADR-0033, amended 2026-10-15). No
daemon image.

---

## Phase 4 — Documentation

### E10 · Rewrite the operations docs
`relay-install.md`, `relay-daemon-install.md`, `enrollment.md` around the new path, including
the DNS guidance (multi-SAN makes DNS optional for the Node plane) and the fingerprint and
trust-store instructions from ADR-0031. Planned as v0.6.5 step S17.

### E11 · `GLOSSARY.md` — **join string**
Done: the entry records that a join string is *not* a synonym for Enrollment Token.

### E12 · Quickstart (#402)
Ties E4, E5, E7, E8 together. Four commands, two artifacts. Open.

---

## Phase 5 — Migration

### E14 · Dev fleet and e2e suite onto `RELAY_JOIN`
**ADR-0031 · built.** The dev fleet, the demo compose file and the end-to-end suites enroll
with a join string; no daemon container mounts CA material.

---

## Open — needs a call

### E13 · `relay-daemon preflight` *(proposed, unruled)*

**What it is:** a subcommand run *before* `systemctl enable relay-daemon`, answering "will
this Node actually join?" without joining. It resolves the Relay address, completes a TLS
handshake and checks the presented chain against the pinned fingerprint, loads the Policy
file and prints its fingerprint, and confirms the state directory is writable. It
deliberately does **not** validate the Enrollment Token, because doing so would spend a
`max_uses` against a token sized to the batch.

It fits the daemon's offline-subcommand pattern (`policy check`, `dump-operation-schema`) and
is outside ADR-0030's boundary question, which governs the `relay` binary only.

**Why it was raised:** the whole failure class — SAN mismatch, closed firewall, group-writable
Policy, unreachable address — surfaces as journald lines discovered on N machines after the
fact.

**Why it might be dropped:** multi-SAN (E2) removes the largest single cause, and `policy
check` already covers the Policy half. The residue is firewall and reachability, which a
`curl` proves nearly as well.

Not carried into any ADR pending a call.
