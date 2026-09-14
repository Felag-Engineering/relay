# Enrollment

**Status:** draft for human approval, checked against the code on `2026-09-13`.

## Purpose

Enrollment gives a new Node a Relay-assigned identity and a bounded credential with
which to obtain it.  It lets an operator or config-management system add Nodes
without giving the Node a credential that can administer the fleet.  It also provides
the containment action for a leaked Enrollment Token: stop further enrollment and
revoke every Node whose recorded provenance names that token.

## Surfaces

| Surface | Current behaviour |
|---|---|
| Control API | An `admin` may mint a token with `POST /api/v1/enrollment-tokens` and revoke one with `DELETE /api/v1/enrollment-tokens/{id}`. |
| Node plane | The certless `Enrollment.Enroll` RPC accepts a token, CSR, and node-space Labels; `Enrollment.Renew` is mTLS-authenticated. |
| relay-daemon | On first start with no persisted identity, it reads `RELAY_ENROLLMENT_TOKEN` and the pinned `RELAY_CA_BUNDLE_PATH`, enrolls, then persists its identity. A later start reuses that identity. |
| Console | It shows enrollment attempts and Node enrollment provenance. It does not mint tokens or add Nodes. |
| MCP | No enrollment-token mint or revoke tool is exposed. |

## Behaviour

### Minting

- The Control API authenticates and authorizes the caller as `admin` before it reads
  the request body. Minting is audited with the actor's attribution and the public
  token ID.
- A token has a non-empty scope of well-formed `relay:` Label terms, a positive TTL
  of at most one year, and an optional positive `max_uses`; a missing or non-positive
  `max_uses` is unlimited. The Relay does not rewrite malformed scope terms.
- The Relay returns the plaintext `id.secret` credential only in the successful mint
  response. It stores a hash of the secret, never the plaintext; logs and lifecycle
  audit records contain only the public ID and non-secret metadata.
- A valid token is reusable until its expiry, revocation, or use limit. Validation
  serializes the check and use increment, so concurrent enrollment cannot exceed
  `max_uses`.

### First enrollment and identity

- `Enroll` is the sole certless Node-plane RPC. It uses server-authenticated TLS,
  while every subsequent Node-plane RPC requires the Node's client certificate.
- Before token validation or CSR signing, the Relay applies per-source and global
  enrollment rate limits. Rate limiting precedes token validation so a throttled
  request cannot reveal whether a token is real.
- The Relay rejects an empty token or CSR. It also rejects the entire request if a
  requested node-space Label is not a well-formed `node:` Label; it never lets a Node
  submit a `relay:` Label in this path.
- After a valid token is accepted, the Relay generates the `node_id`, signs the CSR
  under that identity, creates or updates the registry record with the token's public
  ID as enrollment provenance, and stamps the token scope as relay-space Labels. The
  CSR subject does not select the Node identity.
- Certificate signing and registry writes occur only after token validation. A
  rejected enrollment creates neither certificate nor registry entry. A successful
  response carries the assigned ID, certificate, and CA bundle.
- The daemon persists the returned key, certificate, CA bundle, and identity. Once
  it has a valid persisted identity, it does not enroll again on restart; the
  enrollment token is consequently inert for that Node.
- After recording an enrollment, the Relay rechecks token revocation. If the token
  was revoked during enrollment, it denylists the fresh Node and returns the same
  token-rejection result used for other token failures.

### Renewal, provenance, and revocation

- Renewal requires an mTLS-authenticated Node identity. The Relay derives `node_id`
  from the verified certificate, signs a new CSR under that ID, and returns a new
  certificate and CA bundle. It does not use an Enrollment Token or rewrite Labels
  and initial-enrollment provenance.
- The registry records initial enrollment time and token ID separately from renewal
  certificate provenance. Recording a certificate's provenance is non-fatal after a
  certificate has been issued; a valid issued identity is never withdrawn because
  bookkeeping failed.
- Revoking a token first prevents further use of it, then cascade-revokes every Node
  recorded as enrolled by that public token ID. Each matching Node is denylisted,
  disconnected if live, and persistently marked revoked; the scan is repeated to
  cover a Node recorded while revocation was in progress.
- Token revocation is idempotent, including for an unknown token ID. The Control API
  records the token revocation and one attributed Node-revocation record per cascaded
  Node. If per-Node recording fails, revocation still completes and the API reports
  the audit-record shortfall rather than leaving a Node live.

## Refusals

- A non-`admin` Control API caller cannot mint or revoke an Enrollment Token.
- A mint request with an empty or malformed scope, invalid TTL, malformed JSON, or
  unknown request fields is refused; scope is never sanitized into another Label.
- An enrollment request with no token or CSR, malformed node-space Labels, invalid
  CSR, a full registry, or a rate-limit excess is refused. Rate-limit refusal is
  `ResourceExhausted`; missing inputs and malformed Node data are
  `InvalidArgument`.
- Invalid, unknown, expired, revoked, exhausted, and legacy malformed-scope tokens
  all return the same `PermissionDenied` token-rejection response. This prevents the
  certless endpoint from becoming a token-state oracle.
- A daemon with neither a persisted identity nor both enrollment inputs fails closed;
  it never opens a plaintext Node-plane connection. A failed enrollment persists no
  partial identity.
- A revoked Node cannot reconnect or renew. Re-enrollment creates a new random
  identity, which is why token revocation must revoke both the token and its recorded
  Nodes.

## Governing ADRs and invariants

- **ADR-0005 and invariant 6** require mTLS for the Node plane. `Enroll` is the
  narrowly bounded first-identity exception; renewal and the Tunnel are not.
- **ADR-0006 and invariant 7** make the Relay, rather than a Node, the only writer of
  relay-space Labels. Token scope is therefore `relay:` only and is stamped by the
  Relay; enrollment-submitted labels are `node:` only.
- **ADR-0017** limits the trust of node-space Labels. They support routine targeting;
  security-sensitive targeting uses the Relay-stamped scope labels.
- **ADR-0020** preserves the separate operator-owned tag-space. Enrollment neither
  creates nor accepts tag-space Labels.
- **ADR-0031** approves replacing the bootstrap CA-bundle file and token pair with a
  fingerprint-pinned join string. That design is not current behaviour.
- **ADR-0032** approves mint-and-render enrollment bundles and an `admin` minting
  floor. The authorization floor is current; rendering is not.

## Seams and proof

The token service, enrollment RPC handler, Control API, and revocation service are the
principal seams. `make verify` is sufficient for changes limited to this capability's
current implementation. Changes to the Node-plane protocol, TLS configuration, or the
relay-daemon enrollment path also require the relevant real-daemon integration coverage.

### What proves each claim

| Behaviour | Proven by | Seam |
|---|---|---|
| Plaintext is returned once and only its hash is stored | `TestCreate_StoresHashedReturnsPlaintextOnce` | capability |
| A token is reusable until bounded by max uses | `TestReusable_ValidatesRepeatedly`, `TestMaxUses_Concurrent` | capability |
| Scope is relay-space only and well formed | `TestCreate_InvalidScope`, `TestCreate_WellFormedScopeAccepted` | capability |
| Mint and revoke require `admin` | `TestMintToken_RequiresAdmin`, `TestRevokeToken_RequiresAdmin` | API |
| Mint is audited without recording plaintext | `TestHandleMintToken_Success` | API |
| Relay assigns identity independently of the CSR subject | `TestEnroll_IdentityNotFromCSR` | Node plane |
| Invalid token enrollment has no successful identity outcome | `TestEnroll_InvalidToken` | Node plane |
| Enrollment refuses non-node-space Labels | `TestEnroll_NonNodeSelfLabel` | Node plane |
| Rate limiting happens without a token oracle | `TestEnroll_RateLimited_NoTokenOracle` | Node plane |
| In-flight enrollment is contained by token revocation | `TestEnroll_PostUpsertRevocationCheck_ClosesRaceWindow` | Node plane |
| Renewal preserves the mTLS-derived identity | `TestRenew_IgnoresCSRSubject`, `TestRenew_MissingNodeID` | Node plane |
| A token cascade records each Node and catches a late record | `TestService_RevokeToken_RecordsEveryCascadedNode`, `TestService_RevokeToken_RecordsNodeFoundOnRescan` | capability |
| Audit failure does not leave cascaded Nodes live | `TestService_RevokeToken_RecordFailureDoesNotStopTheCascade` | capability |
| The Control API records mint and revoke lifecycle events | `TestMintThenRevokeToken_BothProduceAuditRows` | API |

Claims above with **no row**, and so nothing checking them:

- That a persisted daemon identity prevents a second enrollment, and that a failed
  enrollment persists no partial identity. Both are daemon-side and would need a Rust
  seam; neither is cited here.
- That a daemon with neither a persisted identity nor both enrollment inputs fails closed
  rather than opening a plaintext Node-plane connection.
- That the one-year TTL ceiling holds. It is a Control API bound, not a token-service one:
  `Create` refuses only a non-positive TTL, so a second minting path would not inherit the
  ceiling.

### Performance

| Characteristic | Contract | Measured by |
|---|---|---|
| Concurrent enrollment | `max_uses` remains correct under concurrency | *(none)* |
| Token-revocation cascade | Every recorded matching Node is considered, including bounded re-scans for concurrent enrollment | *(none)* |
| Certless enrollment pressure | Per-source and global limits bound admission before token validation | *(none)* |

## Approved design, not current behaviour

The following work has ADR approval but remains unbuilt and must not be inferred from
the current surfaces above:

- A single fingerprint-pinned **join string** carrying the Relay address, CA
  fingerprint, and Enrollment Token; it replaces `RELAY_CA_BUNDLE_PATH` rather than
  adding another bootstrap path (ADR-0031; #401).
- Rendered `join`, `ansible`, and `shell` enrollment bundles returned as part of the
  same minting act as the plaintext token. A bundle cannot be re-rendered later because
  the secret is not retained (ADR-0032; #404–#410).
- `relay init` as an idempotent trust-bootstrap transaction and the Console Add Nodes
  screen that invokes the existing mint capability with rendering (#400, #434).

## Out of scope

- Relay does not centrally author or distribute a Node's Policy; Policy remains
  locally rooted and remotely immutable.
- Enrollment does not make a Node an administrator, execute an Operation, bypass a
  Selector, or alter the blast-radius cap.
- Enrollment does not manage tag-space or state-space Labels, or let a Node write
  relay-space Labels after enrollment.
- Daemon installation, software distribution, and config management remain outside
  this capability. Enrollment consumes a configured daemon; it does not push one.
- Reissuing or recovering the CA private key is disaster recovery, not enrollment.

## Open questions

- **Blocks the self-serve implementation:** Which bootstrap and enrollment artifacts
  `relay init` may reuse versus mint anew on a rerun, including its exact secret-output
  contract (#400). ADR-0030 constrains the boundary, but the final interface must be
  reviewed with the implementation design.
- **Blocks rendered bundles:** The supported daemon artifact/version and digest source
  for the initial rendered Ansible bundle, and the migration to OS packages
  (ADR-0032). This must be settled in the architect plan before #404–#410 are
  decomposed.
- **Follow-up:** Whether the Console's enrollment-attempt view should become durable
  audit history or remain its current event-stream projection. This belongs with
  `audit-and-read-lane.md`, not a change to token refusal semantics.

## History

- 2026-09-13 — Proposed first durable enrollment specification for human approval.
