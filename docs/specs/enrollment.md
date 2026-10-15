# Enrollment

**Status:** aspirational — worked through with the owner on `2026-09-14`, awaiting their review
of this draft. Describes intended behaviour, not the code (see the establishing phase in
`README.md`).

## Purpose

Enrollment gives a new Node a Relay-assigned identity and a bounded credential with which to
obtain it. It lets an operator or config-management system add Nodes without giving the Node a
credential that can administer the fleet. It also provides the containment action for a leaked
Enrollment Token: stop further enrollment and revoke every Node whose recorded provenance names
that token.

Enrollment owns **first contact**: the join string, the first trust decision, and identity
issuance, renewal and revocation. Every later connection of an enrolled Node is
`node-connection.md`.

## Surfaces

| Surface | Behaviour |
|---|---|
| Control API | An `admin` mints a token with `POST /api/v1/enrollment-tokens`, receiving the plaintext token and its **join string** once, and revokes one with `DELETE /api/v1/enrollment-tokens/{id}`. |
| Node plane | The certless `Enrollment.Enroll` RPC accepts a token, CSR, and declared `node:` Labels; `Enrollment.Renew` is mTLS-authenticated. |
| relay-daemon | On first start with no persisted identity, it reads the join string, pins the Relay CA fingerprint it carries, enrolls, then persists its identity and the Relay address. A later start reuses that identity. |
| Console | Shows enrollment attempts and Node enrollment provenance. It does not mint tokens or add Nodes (Future work). |
| MCP | No enrollment-token mint or revoke tool is exposed. |

## Behaviour

### Minting

- The Control API authenticates and authorizes the caller as `admin` before it reads the request
  body. Minting is audited with the actor's attribution and the public token ID.
- A token has a positive TTL of at most one year and an optional positive `max_uses`; a missing or
  non-positive `max_uses` is unlimited.
- A token **may carry `tag:` Labels**, applied to every Node that enrolls with it. Each must be a
  well-formed `tag:` Label within the per-Node tag limits (`selectors-and-labels.md`); a malformed
  one refuses the mint and is never rewritten. A token carries no operator-chosen `relay:` Labels —
  token scope as a list of `relay:` Labels is retired.
- The Relay returns the plaintext `id.secret` credential, and the join string built from it, only
  in the successful mint response. It stores a hash of the secret, never the plaintext; logs and
  lifecycle audit records contain only the public ID and non-secret metadata.
- A valid token is reusable until its expiry, revocation, or use limit. Validation serializes the
  check and use increment, so concurrent enrollment cannot exceed `max_uses`.

### The join string

- One string carries everything first contact needs: the Relay address, the fingerprint of the
  Relay's CA, and the Enrollment Token (ADR-0031). It replaces handing each Node a CA bundle file;
  there is no second bootstrap path.
- On first contact the daemon **pins the CA fingerprint**: it proceeds only if the Relay presents a
  certificate chain rooting in a CA with that fingerprint, and sends nothing — token included —
  otherwise.
- The daemon persists the Relay address and CA with its identity. From then on the join string is
  not needed; every later connect checks the pinned CA and uses the persisted address
  (`node-connection.md`).

### First enrollment and identity

- `Enroll` is the sole certless Node-plane RPC. It uses server-authenticated TLS, while every
  subsequent Node-plane RPC requires the Node's client certificate.
- Before token validation or CSR signing, the Relay applies per-source and global enrollment rate
  limits. Rate limiting precedes token validation so a throttled request cannot reveal whether a
  token is real.
- The Relay rejects an empty token or CSR. It also rejects the entire request if a declared Label is
  not a well-formed `node:` Label, or uses a reserved built-in `node:` key; it never lets a Node
  submit a `relay:` or `tag:` Label in this path.
- After a valid token is accepted, the Relay generates the `node_id`, signs the CSR under that
  identity, and creates the registry record. It then writes the enrollment action's `relay:` Labels —
  **`relay:enrollment-token=<token ID>`** and **`relay:node-id=<node ID>`** — and applies the token's
  `tag:` Labels. The CSR subject does not select the Node identity.
- Certificate signing and registry writes occur only after token validation. A rejected enrollment
  creates neither certificate nor registry entry. A successful response carries the assigned ID,
  certificate, and CA bundle.
- The daemon persists the returned key, certificate, CA bundle, Relay address and identity. Once it
  has a valid persisted identity, it does not enroll again on restart; the join string and its token
  are consequently inert for that Node.
- After recording an enrollment, the Relay rechecks token revocation. If the token was revoked
  during enrollment, it denylists the fresh Node and returns the same token-rejection result used for
  other token failures.

### Re-enrollment

- A Node that enrolls again — for example after its certificate expired while the Relay was
  unreachable (`node-connection.md`) — receives a **new Node ID and a new registry record**. The old
  record stays revoked or offline and is never merged into the new one. Tags applied to the old record
  do not carry over; the new record receives only the enrolling token's tags.

### Renewal, provenance, and revocation

- Renewal requires an mTLS-authenticated Node identity. The Relay derives `node_id` from the verified
  certificate, signs a new CSR under that ID, and returns a new certificate and CA bundle. It never
  uses an Enrollment Token and never changes Labels or initial-enrollment provenance.
- The registry records initial enrollment time and token ID separately from renewal certificate
  provenance. Recording a certificate's provenance is non-fatal after a certificate has been issued; a
  valid issued identity is never withdrawn because bookkeeping failed.
- Revoking a token first prevents further use of it, then cascade-revokes every Node whose
  `relay:enrollment-token` names it. Each matching Node is denylisted, disconnected if live, and
  persistently marked revoked; the scan is repeated to cover a Node recorded while revocation was in
  progress.
- Token revocation is idempotent, including for an unknown token ID. The Control API records the
  token revocation and one attributed Node-revocation record per cascaded Node. If per-Node recording
  fails, revocation still completes and the API reports the audit-record shortfall rather than
  leaving a Node live.

## Refusals

- A non-`admin` Control API caller cannot mint or revoke an Enrollment Token.
- A mint request with a malformed or over-limit `tag:` Label, an invalid TTL, malformed JSON, or
  unknown request fields is refused; nothing is sanitized into another Label.
- An enrollment request with no token or CSR, a malformed or reserved-key `node:` Label, a `relay:` or
  `tag:` Label, an invalid CSR, a full registry, or a rate-limit excess is refused. Rate-limit refusal
  is `ResourceExhausted`; missing inputs and malformed Node data are `InvalidArgument`.
- Invalid, unknown, expired, revoked, exhausted, and legacy scope-carrying tokens all return the same
  `PermissionDenied` token-rejection response. This prevents the certless endpoint from becoming a
  token-state oracle.
- A daemon whose join string names a CA fingerprint the Relay does not present does not enroll and
  sends no token.
- A daemon with neither a persisted identity nor a join string fails closed; it never opens a
  plaintext Node-plane connection. A failed enrollment persists no partial identity.
- A revoked Node cannot reconnect or renew. Re-enrollment creates a new identity, which is why token
  revocation must revoke both the token and its recorded Nodes.

## Governing ADRs and invariants

- **Invariant 6 / ADR-0005** — mTLS for the Node plane. `Enroll` is the narrowly bounded
  first-identity exception; renewal and the Tunnel are not.
- **Invariant 7 / ADR-0006** — the Relay, never a Node, writes `relay:` Labels, and only as the side
  effect of a Relay action; enrollment is such an action, writing `relay:enrollment-token` and
  `relay:node-id`. Enrollment-submitted Labels are `node:` only.
- **ADR-0006 — needs amending.** Token scope as operator-chosen `relay:` Labels stamped at enrollment
  is retired.
- **ADR-0020 — needs amending.** A token may now carry `tag:` Labels applied at join; post-enrollment
  `relay:` management by direct `admin` write is superseded (`selectors-and-labels.md`).
- **ADR-0017** — `node:` Labels support routine targeting only; security-lane targeting uses the
  Relay-written `relay:` Labels.
- **ADR-0031** — the fingerprint-pinned join string. In the first pass.
- **ADR-0032** (rendered bundles) and **ADR-0030** (`relay init`) — approved, deferred to Future work
  here. `relay-configuration.md` schedules `relay init` itself for v0.6.5 (owner decision,
  2026-10-15); its trust-bootstrap contract below remains this spec's to settle.
  ADR-0032's `admin` minting floor stands.

## Seams and proof

The token service, enrollment RPC handler, Control API, and revocation service are the principal
seams. `make verify` is sufficient for changes limited to the Relay side. Changes to the Node-plane
protocol, TLS configuration, the join string, or the relay-daemon enrollment path also require
real-daemon integration coverage.

### What proves each claim

| Behaviour | Proven by | Seam |
|---|---|---|
| Plaintext is returned once and only its hash is stored | `TestCreate_StoresHashedReturnsPlaintextOnce` | capability |
| A token is reusable until bounded by max uses | `TestReusable_ValidatesRepeatedly`, `TestMaxUses_Concurrent` | capability |
| Mint and revoke require `admin` | `TestMintToken_RequiresAdmin`, `TestRevokeToken_RequiresAdmin` | API |
| Mint is audited without recording plaintext | `TestHandleMintToken_Success` | API |
| Relay assigns identity independently of the CSR subject | `TestEnroll_IdentityNotFromCSR` | Node plane |
| Invalid token enrollment has no successful identity outcome | `TestEnroll_InvalidToken` | Node plane |
| Enrollment refuses non-`node:` Labels | `TestEnroll_NonNodeSelfLabel` | Node plane |
| Rate limiting happens without a token oracle | `TestEnroll_RateLimited_NoTokenOracle` | Node plane |
| In-flight enrollment is contained by token revocation | `TestEnroll_PostUpsertRevocationCheck_ClosesRaceWindow` | Node plane |
| Renewal preserves the mTLS-derived identity | `TestRenew_IgnoresCSRSubject`, `TestRenew_MissingNodeID` | Node plane |
| A token cascade records each Node and catches a late record | `TestService_RevokeToken_RecordsEveryCascadedNode`, `TestService_RevokeToken_RecordsNodeFoundOnRescan` | capability |
| Audit failure does not leave cascaded Nodes live | `TestService_RevokeToken_RecordFailureDoesNotStopTheCascade` | capability |
| The Control API records mint and revoke lifecycle events | `TestMintThenRevokeToken_BothProduceAuditRows` | API |

Superseded: `TestCreate_InvalidScope` and `TestCreate_WellFormedScopeAccepted` prove the retired
`relay:` token scope and no longer describe intended behaviour.

Claims above with **no row**, and so nothing checking them:

- Everything about the join string: that it carries address, fingerprint and token; that the daemon
  pins the fingerprint and sends nothing on a mismatch; that the address is persisted.
- That enrollment writes `relay:enrollment-token` and `relay:node-id`, and applies a token's `tag:`
  Labels; that a mint with a malformed or over-limit tag is refused.
- That a reserved built-in `node:` key or a `tag:` Label in an enrollment request is refused.
- That re-enrollment creates a new record and carries no tags.
- That a persisted daemon identity prevents a second enrollment, and that a failed enrollment persists
  no partial identity. Both are daemon-side and would need a Rust seam.
- That a daemon with neither a persisted identity nor a join string fails closed.
- That the one-year TTL ceiling holds. It is a Control API bound, not a token-service one, so a second
  minting path would not inherit it.

### Performance

| Characteristic | Contract | Measured by |
|---|---|---|
| Concurrent enrollment | `max_uses` remains correct under concurrency | *(none)* |
| Token-revocation cascade | Every recorded matching Node is considered, including bounded re-scans for concurrent enrollment | *(none)* |
| Certless enrollment pressure | Per-source and global limits bound admission before token validation | *(none)* |

## Out of scope

- **Every later connection of an enrolled Node** — the pinned-CA check on reconnect, liveness,
  heartbeats: `node-connection.md`.
- **Where the join string or token is stored on a Node**, and how config management delivers it:
  `daemon-installation.md`.
- **Tag management after enrollment**, and the Label namespaces themselves: `selectors-and-labels.md`.
- **The Console's enrollment-attempt view** as durable history: `audit-and-read-lane.md`.
- Relay does not centrally author or distribute a Node's Policy (invariant 2).
- Enrollment does not make a Node an administrator, execute an Operation, bypass a Selector, or alter
  the blast-radius cap.
- Daemon installation, software distribution, and config management. Enrollment consumes a configured
  daemon; it does not push one.
- Reissuing or recovering the CA private key is disaster recovery, not enrollment.

## Accepted residual risk

- **A join string is a bearer credential until used or expired.** Anyone holding it can enroll a Node
  within the token's limits. Containment is token revocation, which also revokes every Node it
  enrolled.
- **Re-enrollment leaves a stale record** beside the new one, and loses the old record's tags; an
  operator reconciles by hand.

## Future work

Wanted, deliberately not in the first pass. None is a commitment to an order.

- **Research: better enrollment at fleet scale.** How enrollment should work across tens of thousands of
  Nodes arriving through config management — token lifetimes and rotation, per-environment tokens,
  unattended bootstrap, and whether the join string remains the right unit.
- **Rendered enrollment bundles** (`join`, `ansible`, `shell`) returned in the same minting act as the
  token (ADR-0032; #404–#410). Blocked on the supported daemon artifact, version and digest source, and
  the migration to OS packages.
- **`relay init`** as an idempotent trust-bootstrap transaction (ADR-0030; #400), including which
  artifacts a rerun may reuse versus mint anew and its secret-output contract.
- **The Console Add Nodes screen** invoking the existing mint capability (#434).
- **Batching revocation audit records** for large cascades without serialising one commit per Node,
  while keeping honest per-Node shortfall reporting (#563).

## Open questions

None open.
