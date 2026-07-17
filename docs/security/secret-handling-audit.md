# Secret-handling audit

## Purpose & scope

This note is a systematic sweep confirming that no secret — Enrollment Token, CA private
key, Node private key, control-plane credential digest, or CSR/certificate material — reaches
a structured log, the audit trail, or an error/RPC message on either side of Relay: the
Relay (Go) or the relay-daemon (Rust). It is a companion to, not a replacement for, the
project's STRIDE threat model, which covers the broader threat surface; this note is narrower
and mechanical — secret inventory crossed with every logging/error-formatting surface,
confirming the guard in place at each intersection. It does not reintroduce or restate the
threat model's contents; see `docs/security/threat-model.md` for the broader STRIDE analysis.

## Secret inventory

1. **Enrollment Token** — the plaintext bootstrap credential presented once by a Node during
   enrollment (`RELAY_ENROLLMENT_TOKEN` on the daemon side; `Token.SecretHash` on the Relay
   side).
2. **CA private key** — the Relay's root signing key, used to issue Node certificates.
3. **Node private key** — the per-Node PKCS#8 key generated at enrollment and held only on
   that Node.
4. **Control-plane credential digest (API Token)** — the bearer credential authenticating
   Control API/Admin Console callers to the Relay.
5. **CSR / certificate material** — the certificate signing request and issued certificate
   exchanged during enrollment and renewal.

## Surface × secret matrix

Rows are secrets; columns are the three surfaces audited: structured logs (`tracing`/`slog`
call sites), the audit trail (`internal/audit`/`internal/store`), and error/RPC messages
(returned `Result`/`status.Error` values). Each cell names the guard.

| Secret | Structured logs | Audit trail | Error / RPC messages |
|---|---|---|---|
| Enrollment Token | Daemon: held only in `EnrollConfig.token` (`enroll.rs:53`); no `Debug`, and no `tracing` call site references it. Relay: only `Token.SecretHash` (a SHA-256 digest) is stored, and `Token.LogValue` (`enroll/token.go:77`) deliberately omits it from any `slog` output. | Never a field on `capability.AuditEntry`; the enroll handler stores only the public token-ID half for provenance (`enroll/handler.go:199-204`), never the secret. | The enroll handler collapses every rejection reason (invalid, expired, revoked, exhausted) into the single constant `PermissionDenied "enrollment token rejected"` (`enroll/handler.go:210-214`) — it never echoes the presented value. |
| CA private key | Never logged anywhere on the Relay. | The CA package never touches the audit path. | `ca.go` wraps stdlib errors with `%w` and only ever surfaces a PEM block type, a file base name, or a key-parse/serial-generation failure reason (`ca.go:245,282,290,295`) — never key bytes. |
| Node private key | Daemon: held only in `Identity.key_pem` (`identity.rs:50`); no `Debug`, and no `tracing` call site references it. | Never leaves the Node; the Relay never receives or stores it. | `IdentityError`/`EnrollError` derive `Debug` (for `{:?}` diagnostics) but no variant embeds `key_pem` — variants carry only scheme strings, node IDs, timestamps, or wrapped library errors. |
| Control-plane credential digest (API Token) | `controlplane/auth.go` compares only SHA-256 digests (`validToken`, `auth.go:82`); `Middleware` never logs or echoes the presented token. | Not a field the middleware ever passes to the audit path. | Every authentication failure — missing header, malformed header, wrong credential — returns the same constant `genericAuthError = "unauthorized"` (`auth.go:20,107`), so no error path can act as an oracle for the credential's value. |
| CSR / certificate material | CSR (public key + signature) and issued cert are not secret; the concern is that nearby CA/enroll errors never embed the *private* key — covered by the CA-key row above. | Not persisted to the audit trail; enrollment provenance stores the node ID, not CSR contents. | The enroll handler explicitly ignores the CSR's stated subject and sets `CN = node_id` authoritatively (`enroll/handler.go:217,223`), so no client-supplied CSR field is echoed back as trust-bearing. |

## Accepted decision: verbatim audit output

Captured `Stdout`/`Stderr` and `OperationArgs`/`RawExecArgv` are stored **verbatim** by
design (ADR-0002, ADR-0004; `auditsink.go` package doc; `docs/operations/audit-output-retention.md`).
If a dispatched command prints or is given a secret, that secret is retained in the audit
trail exactly as emitted or passed. This is intentional: Policy — deny-by-default,
argument-level granularity, enforced by the daemon's live engine — is where secret-emitting
or secret-bearing commands are prevented from running at all; the audit trail's job is to be
a truthful record of what happened, not to guess at redaction after the fact. **This is an
accepted decision, not a bug**, and this audit does not challenge it.

## The `logDecision` seam is narrower than the store

Separately from the verbatim store above, `auditsink.go`'s supplementary decision-log line
(`logDecision`, `auditsink.go:244`) is a distinct, narrower seam: it carries only
routing/attribution metadata — kind, principal, selector, action kind/name, job ID, and
aggregate outcome counts — and by its own package doc's claim never carries an Action's
`OperationArgs` or `RawExecArgv`, any `NodeResult`'s `Stdout`/`Stderr`/`Truncated`, or any
token/key material. That claim was previously unverified by any test — no existing test set
`OperationArgs` — and is now enforced by
`TestRecordDispatchDecisionLineExcludesOperationArgs` in `auditsink_test.go`, which asserts
both halves at once: the decision line omits the secret-bearing arg value and the captured
output, while the store (per the accepted decision above) still retains all three.

## Pinned fragile guarantee: no `Debug` on Rust secret structs

On the Rust side, the "never logged" guarantee for `EnrollConfig` (the Enrollment Token) and
`Identity` (the Node private key) previously rested only on those structs deriving no
`Debug` plus a `/// never logged` doc comment — a convention, not a guarantee enforced by the
compiler. A future `#[derive(Debug)]` on either struct would silently reopen the leak. Both
structs now carry a `#[cfg(test)] mod no_debug_guard` (in `daemon/src/enroll.rs` and
`daemon/src/identity.rs` respectively): a manual `NoDebug` impl that conflicts (`E0119`) with
a blanket impl the moment the struct gains a `Debug` impl, turning that regression into a
build failure under `cargo test` rather than a silent log leak. The guard modules are
`#[cfg(test)]`-only, so nothing changes in the shipped musl binary.

## Findings

None found; no secret reaches any surface. Two previously comment-only guarantees — the
Rust no-`Debug` invariant and the `logDecision` exclusion — are now pinned with tests.
