# Enrollment

**Status:** designed, not built, as of `2026-10-21`.
**Claim prefix:** `EN`

## Purpose

Enrollment gives a new Node a Relay-assigned identity without handing the Node a credential
that can administer the fleet. An operator or a config-management system adds Nodes; the
Relay's private CA issues each one a client certificate; from then on the Node's identity is
that certificate and nothing else.

Enrollment owns **first contact**: what a Node needs to reach the Relay, the first trust
decision in each direction, identity issuance, renewal and revocation, and the containment of a
leaked enrollment credential. Every later connection of an enrolled Node is `node-connection.md`.

"The daemon" below names the relay-daemon binary in whichever form runs it: the process its
unit starts, or a subcommand such as `relay-daemon join`. Where a claim means the unit start
alone, it says so.

## Surfaces

| Surface | Behaviour |
|---|---|
| Control API | An `admin` mints a token with `POST /api/v1/enrollment-tokens`, receiving the plaintext token and its **join string** once, and revokes one with `DELETE /api/v1/enrollment-tokens/{id}`. |
| Node plane | The certless `Enrollment.Enroll` RPC accepts a token, a CSR and declared `node:` Labels; `Enrollment.Renew` is mTLS-authenticated. |
| relay-daemon | Enrolls by a join string on first start with no persisted identity: it pins the Relay's CA fingerprint, enrolls, persists its identity and the Relay address, and reuses that identity on every later start. Where the join string lives on a Node and how `relay-daemon join` delivers it is `daemon-installation.md`; EN-30 (designed) moves the enrollment into `join`. |
| Console | Shows enrollment attempts and each Node's enrollment provenance. It does not mint tokens today; EN-36 (designed) gives it a mint. |
| MCP | No enrollment tool is exposed: no mint and no revoke. An AI-agent may read a Node's provenance through `query.md` and nothing more. |

## Behaviour

### Minting

- **EN-1** The Control API authorizes the caller as `admin` for a mint before it reads the
  request body. A mint is audited with the actor's attribution and the public token ID.
- **EN-2** A token has a positive TTL of at most one year and an optional positive `max_uses`.
  A missing or non-positive `max_uses` is unlimited.
- **EN-3** A token carries a scope: one or more well-formed `relay:` Labels, each rendering
  as exactly one Selector term. A scope entry that is not such a Label refuses the mint and is
  never rewritten.
- **EN-4** The Relay returns the plaintext `id.secret` credential, and the join string built
  from it, only in the successful mint response. It stores a hash of the secret, never the
  plaintext; logs and lifecycle audit records carry only the public ID and non-secret metadata.
- **EN-5** A valid token is reusable until its expiry, its revocation or its use limit.
  Validation serializes the check and the use increment, so concurrent enrollment cannot
  exceed `max_uses`.

### The join string

- **EN-6** One join string carries everything first contact needs: the Relay address, the
  fingerprint of the Relay's CA and the Enrollment Token (ADR-0031). The daemon takes no CA
  bundle path and no bare token by any other setting; a Relay address set in its environment
  overrides only the address, and the pin still applies to whatever it dials.
- **EN-7** On first contact the daemon pins the CA fingerprint: it proceeds only if the Relay
  presents a certificate chain rooting in a CA with that fingerprint, and sends nothing, token
  included, otherwise.
- **EN-8** The daemon persists the Relay address and the CA bundle with its identity. Every
  later start uses the persisted address, or a Relay address set in its environment, which
  overrides the persisted one on every start (ADR-0031), and checks the pinned CA; the join
  string is not needed again (`node-connection.md`).

### First enrollment and identity

- **EN-9** `Enroll` is the sole certless Node-plane RPC. It uses server-authenticated TLS;
  every other Node-plane RPC requires the Node's client certificate.
- **EN-10** The Relay applies per-source and global enrollment rate limits before token
  validation or CSR signing, so a throttled request cannot reveal whether a token is real.
- **EN-11** The Relay rejects an empty token or an empty CSR. It rejects the whole request if a
  declared Label is not a well-formed `node:` Label; it never accepts a `relay:` or `tag:`
  Label submitted by a Node.
- **EN-12** After a valid token is accepted, the Relay generates the `node_id`, signs the CSR
  under that identity, creates the registry record, stamps the token's scope as the Node's
  `relay:` Labels, and records the token ID and the time as the Node's enrollment provenance.
  The CSR subject never selects the identity.
- **EN-13** Certificate signing and registry writes occur only after token validation. A
  rejected enrollment creates neither a certificate nor a registry record. A successful
  response carries the assigned ID, the certificate and the CA bundle.
- **EN-14** The daemon persists the returned key, certificate, CA bundle, Relay address and
  identity. With a valid persisted identity it does not enroll again on restart, so the join
  string is inert for that Node.
- **EN-15** After recording an enrollment the Relay rechecks the token's revocation. If the
  token was revoked during enrollment it denylists the fresh Node and returns the same
  token-rejection result used for every other token failure.

### A second enrollment

- **EN-16** A Node that enrolls a second time under a token, whether because it was revoked or
  because its certificate expired while the Relay was unreachable (`node-connection.md`),
  receives a new Node ID and a new registry record. The old record stays revoked or offline and
  is never merged into the new one.

### Renewal, provenance and revocation

- **EN-17** Renewal requires an mTLS-authenticated Node identity. The Relay derives `node_id`
  from the verified certificate, signs a new CSR under that ID, and returns a new certificate
  and CA bundle. It never uses an Enrollment Token and never changes Labels or
  initial-enrollment provenance.
- **EN-18** The registry records the initial enrollment time and token ID apart from renewal
  provenance. Recording provenance is non-fatal once a certificate has been issued: a valid
  issued identity is never withdrawn because bookkeeping failed.
- **EN-19** Revoking a token first prevents further use of it, then cascade-revokes every Node
  whose recorded enrollment provenance names it: each is denylisted, disconnected if live and
  persistently marked revoked, and the scan repeats to cover a Node recorded while revocation
  was in progress.
- **EN-20** Token revocation is idempotent, including for an unknown token ID. The Control API
  records the token revocation and one attributed Node-revocation record per cascaded Node. If
  per-Node recording fails, revocation still completes and the Control API reports the
  shortfall rather than leaving a Node live.

### Surfaces today

- **EN-21** The Console shows enrollment attempts, accepted and rejected, and each Node's
  enrollment provenance. It mints nothing and adds no Node. Attempts are an in-memory event
  feed, not durable records.
- **EN-22** MCP registers no enrollment tool: no mint and no revoke.

## Refusals

- **EN-23** A non-`admin` Control API caller cannot mint or revoke an Enrollment Token.
- **EN-24** A mint request with a scope entry that is not a well-formed `relay:` Label, an
  invalid TTL, malformed JSON or an unknown request field is refused; nothing is sanitized into
  another Label.
- **EN-25** An enrollment request with no token or no CSR, a malformed or non-`node:` declared
  Label, an invalid CSR, a full registry, or a rate-limit excess is refused. Rate-limit and
  capacity refusals are `ResourceExhausted`; missing inputs and malformed Node data are
  `InvalidArgument`.
- **EN-26** Invalid, unknown, expired, revoked, exhausted and malformed-scope tokens all
  return the same `PermissionDenied` token-rejection response, so the certless endpoint is
  never a token-state oracle.
- **EN-27** A daemon whose join string names a CA fingerprint the Relay does not present does
  not enroll and sends no token.
- **EN-28** A daemon with neither a persisted identity nor a join string exits cleanly with
  nothing written; it never opens a plaintext Node-plane connection. A failed enrollment
  persists no partial identity.
- **EN-29** A revoked Node cannot reconnect or renew. Re-enrollment creates a new identity,
  which is why revoking a token revokes both the token and the Nodes it enrolled.

## Governing ADRs and invariants

- **Invariant 6 / ADR-0005** — mTLS for the Node plane. `Enroll` is the narrowly bounded
  certless exception; renewal and the Tunnel are not.
- **Invariant 7 / ADR-0006**, amended 2026-10-22 — the Relay, never a Node, writes `relay:`
  Labels, and only as the side effect of a Relay action. Enrollment is that action, and its key
  set is the token's scope, defined by the `admin` at mint; a mint refuses a key that another
  Relay action owns (EN-35). ADR-0048 makes the scope optional and adds `relay:node-id` to the set
  (EN-37, EN-38). Node-submitted Labels are `node:` only. The 2026-09-14 draft
  decision to carry `tag:` Labels on a token in place of a `relay:` scope was retired unbuilt on
  2026-10-21.
- **ADR-0020**, amended 2026-09-16, **/ ADR-0034** — the four Label namespaces, and the rule
  that each `relay:` key belongs to the action that writes it. Enrollment writes `relay:` and
  reads `node:`; it writes no `tag:` and no `state:`.
- **Invariant 10** — the Control API's mint and revoke are role-gated by the capability layer's
  control actions; the Console and MCP offer less, not more.
- **Invariant 11 / ADR-0010** — enrollment rate limits and the registry cap are reach-bounding
  settings; the CA the Relay issues from is the Relay's own key material.
- **ADR-0017** — `node:` Labels support routine targeting only; security-lane targeting uses
  the Relay-written `relay:` Labels.
- **ADR-0031**, amended 2026-10-21 — the fingerprint-pinned join string, and the decision that
  a join string is consumed by the act that enrolls and persisted nowhere on a Node (EN-30,
  EN-31).
- **ADR-0033**, amended 2026-10-21 — `relay-daemon join` enrolls in the process that read the
  join string (`daemon-installation.md`, its `join` claims).
- **ADR-0022** — the shipped default Policy's deny-list names the environment file and the
  daemon's environment oracle; EN-30 is why that deny stops being load-bearing.
- **ADR-0048** — joining is one command: a mint form asks how many Nodes, the command and the join
  string are shown apart, scope is optional and every Node gets `relay:node-id` (EN-31, EN-36 to
  EN-39). It supersedes ADR-0032's Bundles and what ADR-0030's `init` rendered; the `admin`
  minting floor stands.

## Seams and proof

The token service, the enrollment RPC handler, the Control API and the revocation service are
the Relay seams; the daemon's enrollment and pin modules are the Node seams. `make verify`
suffices for Relay-only changes. A change to the Node-plane protocol, the TLS configuration,
the join string or the daemon's enrollment path also needs the cross-binary suite.

### What proves each claim

| Claim | Proven by | Seam |
|---|---|---|
| EN-1 | `TestMintToken_RequiresAdmin`, `TestHandleMintToken_Success` | API |
| EN-2 | `TestHandleMintToken_InvalidScopeOrTTL` | API |
| EN-3 | `TestCreate_InvalidScope`, `TestCreate_WellFormedScopeAccepted` | capability |
| EN-4 | `TestCreate_StoresHashedReturnsPlaintextOnce`, `TestHandleMintToken_Success` | capability · API |
| EN-5 | `TestReusable_ValidatesRepeatedly`, `TestMaxUses_Concurrent` | capability |
| EN-7 | `pin_match_enrolls`, `pin_mismatch_sends_no_token`, `pin_match_with_wrong_server_name_sends_no_token` | daemon |
| EN-8 | `TestCrossBinary_RestartWithoutJoinOrAddrUsesPersistedState`, `persisted_address_written_at_enrollment` | e2e · daemon |
| EN-9 | `TestUnaryInterceptor_CertlessEnroll_PassesWithoutIdentity`, `TestUnaryInterceptor_RenewWithoutPeerCert_Refused` | transport |
| EN-10 | `TestEnroll_RateLimited_NoTokenOracle`, `TestEnroll_RateLimited_PerIP`, `TestEnroll_RateLimited_Global` | Node plane |
| EN-11 | `TestEnroll_EmptyTokenOrCSR`, `TestEnroll_NonNodeSelfLabel` | Node plane |
| EN-12 | `TestEnroll_IdentityNotFromCSR`, `TestEnroll_Success` | Node plane |
| EN-13 | `TestEnroll_InvalidToken`, `TestEnroll_Success` | Node plane |
| EN-14 | `fresh_enroll_persists_identity`, `idempotency_no_op_when_identity_present`, `plan_never_reads_the_join_once_enrolled` | daemon |
| EN-15 | `TestEnroll_PostUpsertRevocationCheck_ClosesRaceWindow` | Node plane |
| EN-17 | `TestRenew_IgnoresCSRSubject`, `TestRenew_MissingNodeID` | Node plane |
| EN-18 | `TestSQLiteRegistry_ProvenanceSurvivesARestart` | store |
| EN-19 | `TestService_RevokeToken_RecordsEveryCascadedNode`, `TestService_RevokeToken_RecordsNodeFoundOnRescan` | capability |
| EN-20 | `TestService_RevokeToken_ToleratesUnknownToken`, `TestService_RevokeToken_RecordFailureDoesNotStopTheCascade`, `TestRevokeTokenCascade_PersistsOneRowPerNode` | capability · API |
| EN-23 | `TestMintToken_RequiresAdmin`, `TestRevokeToken_RequiresAdmin` | API |
| EN-24 | `TestHandleMintToken_MalformedOrUnknownField`, `TestHandleMintToken_InvalidScopeOrTTL` | API |
| EN-25 | `TestEnroll_EmptyTokenOrCSR`, `TestEnroll_NonNodeSelfLabel`, `TestEnroll_BadCSR`, `TestEnroll_RegistryAtCapacity` | Node plane |
| EN-26 | `TestEnroll_LegacyMalformedScopeIsRefusedBeforeAnySideEffect`, `TestEnroll_ExpiredToken`, `TestEnroll_RevokedToken`, `TestEnroll_ExhaustedToken` | Node plane |
| EN-27 | `pin_mismatch_sends_no_token` | daemon |
| EN-28 | `unconfigured_node_exits_zero`, `fresh_enroll_fails_closed_on_key_cert_mismatch` | daemon |
| EN-29 | `TestUnaryInterceptor_RevokedAfterConnect_RenewRefused` | transport |

Claims with **no row**, and so nothing checking them:

- **EN-6** — that the daemon accepts no CA path and no bare token by another setting.
- **EN-16** — nothing enrolls twice and asserts a second record.
- **EN-21**, **EN-22** — the Console's provenance view and MCP's absent tools rest on
  structure, not a test.

Rows worth strengthening, for the testing issue: `TestHandleMintToken_Success` does not assert
the token ID is in the audit record (EN-1); EN-17's tests do not assert Labels and provenance
untouched; EN-18's non-fatal renewal record has no test; EN-28's failed-enrollment tests check
three files, not an empty state directory.

### Performance

| Characteristic | Contract | Measured by |
|---|---|---|
| Concurrent enrollment | `max_uses` remains correct under concurrency | *(none)* |
| Token-revocation cascade | Every recorded matching Node is considered, including bounded re-scans for concurrent enrollment | *(none)* |
| Certless enrollment pressure | Per-source and global limits bound admission before token validation | *(none)* |

## Designed, not built

EN-30 to EN-33 end the join string's life on a Node and bound a token; each replaces the
Behaviour claim it names, and the promoting PR, with the owner retiring the old ID and its
proof rows, lands them together. EN-35 carries ADR-0006's amendment of 2026-10-22;
EN-36 to EN-39 carry ADR-0048.

| Claim | Statement | Milestone |
|---|---|---|
| EN-30 | One join string carries everything first contact needs: the Relay address, the fingerprint of the Relay's CA and the Enrollment Token (ADR-0031). It is read by `relay-daemon join` from a prompt or standard input and consumed by the enrollment `join` performs in that same process (`daemon-installation.md`); it is persisted nowhere on a Node, and the unit start reads no join string. The daemon takes no CA bundle path and no bare token by any other setting; a Relay address set in its environment overrides only the address, and the pin still applies to whatever it dials. Replaces EN-6 when promoted. | v0.6.5 — Install Path: relay init, join string, packages |
| EN-31 | A token has a positive TTL of at most one year. A mint request names a positive `max_uses` or asks explicitly for unlimited use; one that does neither is refused. A surface that offers a mint form asks how many Nodes the token is for, sets the use limit to that number and the TTL to two hours by default, so a used-up or expired token needs no revoke (ADR-0048); the Control API takes explicit values and has no default. Replaces EN-2 when promoted. | v0.6.5 — Install Path: relay init, join string, packages |
| EN-32 | The daemon persists the key, certificate, CA bundle, Relay address and identity that an enrollment returns, and the unit start never enrolls: with a persisted identity it connects, and without one it exits as EN-33 says. Replaces EN-14 when promoted. | v0.6.5 — Install Path: relay init, join string, packages |
| EN-33 | A unit start with no persisted identity exits cleanly with nothing written; the daemon never opens a plaintext Node-plane connection. A failed enrollment in `relay-daemon join` persists no partial identity and exits non-zero. Replaces EN-28 when promoted. | v0.6.5 — Install Path: relay init, join string, packages |
| EN-35 | A mint refuses a scope key that any Relay action owns, Enrollment's own included: every key in the closed `relay:` set's table in `selectors-and-labels.md`, and any key the Relay derives. The refusal names the key and the action that owns it. Extends EN-24 when promoted. | v0.6.5 — Install Path: relay init, join string, packages |
| EN-36 | The Console mints an Enrollment Token through the same capability action and `admin` floor as the Control API, asking how many Nodes it is for (EN-31), and shows the join string once, apart from the command that consumes it (EN-39) (ADR-0048; #434). | v0.7.0 — Admin Console: Administration & Execution |
| EN-37 | A token's scope is zero or more well-formed `relay:` Labels: a mint may name none. Replaces EN-3 when promoted (ADR-0048). | v0.6.5 — Install Path: relay init, join string, packages |
| EN-38 | Every enrollment stamps `relay:node-id` with the Node's Relay-assigned ID on the Node it records. Only the enrollment action writes it, a scope may not name it (EN-35), and the Node cannot change it. Extends EN-12 when promoted (ADR-0048). | v0.6.5 — Install Path: relay init, join string, packages |
| EN-39 | `relay init` shows a freshly minted join string once, apart from the command that consumes it: the command is `sudo relay-daemon join`, and the string is pasted at its prompt, so it is never part of a command line (ADR-0048). | v0.6.5 — Install Path: relay init, join string, packages |

## Out of scope

- **Every later connection of an enrolled Node** — the pinned-CA check on reconnect, liveness,
  heartbeats: `node-connection.md`.
- **Where a join string lives on a Node, and how `relay-daemon join` and config management
  deliver it**: `daemon-installation.md`.
- **Label management after enrollment**, and the Label namespaces themselves:
  `selectors-and-labels.md`.
- **Durable audit records**: `audit-and-read-lane.md`. Enrollment attempts are not durable
  (EN-21).
- **Dispatch approvals, approval gates and grants**: `approval.md`.
- Relay does not centrally author or distribute a Node's Policy (invariant 2).
- Enrollment does not make a Node an administrator, execute an Operation, bypass a Selector or
  alter the blast-radius cap.
- Daemon installation, software distribution and config management. Enrollment consumes a
  configured daemon; it does not push one.
- Reissuing or recovering the CA private key is disaster recovery, not enrollment.

## Accepted residual risk

- **A join string is a bearer credential until used or expired.** Anyone holding it can enroll
  a Node within the token's limits, carrying the token's scope. Accepted by the owner on
  2026-09-14. Containment is token revocation, which also revokes every Node it enrolled; EN-31
  bounds it further. `docs/security/threat-model.md` R41.
- **Where a join string rests on a Node today** (`docs/security/threat-model.md` R16, R36) is
  accepted in `daemon-installation.md` and closes when EN-30 and that spec's `join` claims
  are promoted.
- **`relay-daemon join` enrolls as root outside the hardened unit's sandbox** for the seconds an
  enrollment takes, with the same binary, the same pinned handshake and the same code the
  daemon runs. Accepted by the owner on 2026-10-21 (ADR-0033 amendment); R40.
- **A second enrollment leaves a stale record** beside the new one; an operator reconciles by
  hand. Accepted by the owner on 2026-09-14. `docs/security/threat-model.md` R42.

## Future work

Wanted, deliberately not in a milestone here, and in no committed order.

- **Enrollment as an approval.** A direction the owner wants worked into an ADR: a Node
  arrives pending with only the Relay address and the CA fingerprint, which are not secrets;
  one Relay action, an enrollment approval, assigns the identity and records as provenance the
  proof presented and who approved. A human `admin` approves a Node with no proof, matching a
  code derived from the Node's key that the daemon prints on the Node; a bounded Enrollment
  Token releases in the same request with its scope; a platform attestation is a proof shape
  for later. The ADR has to settle the Console's part against ADR-0044, how the certless
  exception widens under invariant 6, and what an approval may stamp under invariant 7; its
  consumers are `selectors-and-labels.md`, `approval.md`, `audit-and-read-lane.md`,
  `query.md`, `quarantine-node.md`, the glossary and the threat model's enrollment boundary.
- **Attestation verifiers**, one decision each: the AWS instance identity document, GCP and
  Azure signed instance identity, a TPM quote for bare metal. Each argues invariant 11's
  identity-provider clause for itself.
- **A pipeline-driven approval**: config management starts the daemon, reads the code from the
  Node it installed, and approves through the Control API, so no secret ever travels to the
  Node. Whether a machine Account may approve is the approval ADR's question.
- **Replacing a Node in place**: a second enrollment that names the revoked or offline record it
  succeeds, so provenance and history carry over.

## Open questions

- **Whether a token may also carry `tag:` Labels** once `tag:` has storage (#430). The
  2026-09-14 draft carried `tag:` Labels on a token in place of a `relay:` scope; that was
  retired on 2026-10-21 and a token's scope stays `relay:`. Forced by #430.
- **`relay init`'s enrollment acts.** ADR-0030 decides that `relay init` mints a first
  Enrollment Token with a TTL measured in hours, and `relay-configuration.md` assigns the claim
  here. Which artifacts a rerun may reuse versus mint anew is undecided, and the claim waits on it;
  EN-39 decides only how a freshly minted join string is shown. Forced by the first-admin
  flow needing a first token.

## Retired

- **EN-34** — `2026-10-22` — retired unbuilt: Relay renders no Enrollment Bundle; the join
  command is shown instead (EN-39) and the release ships static install files (ADR-0048).
