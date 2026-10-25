# Enrollment

**Status:** designed, not built, as of `2026-10-25`.
**Claim prefix:** `EN`
**Governed by:** ADR-0005, ADR-0006, ADR-0010, ADR-0017, ADR-0020, ADR-0030, ADR-0031,
ADR-0022, ADR-0032, ADR-0033, ADR-0034, ADR-0048, ADR-0050; invariants 6, 7, 10, 11.

## Purpose

Enrollment is how a new server joins the fleet without being handed anything that could
administer it. An administrator mints a short-lived, use-limited Enrollment Token. A person or a
config-management run gives its join string to the new Node once. The Node checks that it is
talking to the real Relay before it sends anything, and the Relay's private certificate
authority issues it a certificate. From then on that certificate is the Node's identity, and
nothing else is. A token can only add Nodes: it never runs a command. Revoking a token revokes
every Node it enrolled. Enrollment owns first contact and the renewal and revocation of a Node's
identity; every later connection belongs to node connection.

## Surfaces

| Surface | Behaviour |
|---|---|
| Control API | An `admin` mints a token with `POST /api/v1/enrollment-tokens`, receiving the plaintext token and its **join string** once, and revokes one with `DELETE /api/v1/enrollment-tokens/{id}`. |
| Node plane | The certless `Enrollment.Enroll` RPC accepts a token, a CSR and declared `node:` Labels; `Enrollment.Renew` is mTLS-authenticated. |
| relay-daemon | Enrolls by a join string on first start with no persisted identity: it pins the Relay's CA fingerprint, enrolls, persists its identity and the Relay address, and reuses that identity on every later start. Where the join string lives on a Node and how `relay-daemon join` delivers it is `daemon-installation.md`; EN-30 (designed) moves the enrollment into `join`. |
| Console | Shows enrollment attempts and each Node's enrollment provenance. It does not mint tokens today; EN-36 (designed) gives it a mint. |
| MCP | No enrollment tool: no mint and no revoke. An AI-agent may read a Node's provenance through `query.md` and nothing more. |

"The daemon" below names the relay-daemon binary in whichever form runs it: the process its
unit starts, or a subcommand such as `relay-daemon join`. Where a claim means the unit start
alone, it says so.

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
- **EN-30** One join string carries everything first contact needs: the Relay address, the
  fingerprint of the Relay's CA and the Enrollment Token (ADR-0031). It is read by `relay-daemon
  join` from a prompt or standard input and consumed by the enrollment `join` performs in that
  same process (`daemon-installation.md`); it is persisted nowhere on a Node, and the unit start
  reads no join string. The daemon takes no CA bundle path and no bare token by any other setting;
  a Relay address set in its environment overrides only the address, and the pin still applies to
  whatever it dials. Replaces EN-6 when promoted.
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
- **EN-32** The daemon persists the key, certificate, CA bundle, Relay address and identity that
  an enrollment returns, and the unit start never enrolls: with a persisted identity it connects,
  and without one it exits as EN-33 says. Replaces EN-14 when promoted.
- **EN-15** After recording an enrollment the Relay rechecks the token's revocation. If the
  token was revoked during enrollment it denylists the fresh Node and returns the same
  token-rejection result used for every other token failure.
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
- **EN-33** A unit start with no persisted identity exits cleanly with nothing written; the daemon
  never opens a plaintext Node-plane connection. A failed enrollment in `relay-daemon join`
  persists no partial identity and exits non-zero. Replaces EN-28 when promoted.
- **EN-29** A revoked Node cannot reconnect or renew. Re-enrollment creates a new identity,
  which is why revoking a token revokes both the token and the Nodes it enrolled.

## Designed, not built

EN-30 to EN-33 end the join string's life on a Node and bound a token; each replaces the
Behaviour claim it names, and the promoting PR lands the replacement, with the owner retiring the
old ID and its proof rows, together. EN-36, EN-38 and EN-39 carry ADR-0048. EN-35 and EN-40 to EN-42 carry
ADR-0050: a token names initial tags, and `relay:` holds only keys a Relay action defines.
EN-43 fixes the rate limits.

| Claim | Statement | Milestone |
|---|---|---|
| EN-31 | A token has a positive TTL of at most one year. A mint request names a positive `max_uses` or asks explicitly for unlimited use; one that does neither is refused. A surface that offers a mint form asks how many Nodes the token is for, sets the use limit to that number and the TTL to two hours by default, so a used-up or expired token needs no revoke (ADR-0048); the Control API takes explicit values and has no default. Replaces EN-2 when promoted. | v0.6.5 — Install Path: relay init, join string, packages |
| EN-35 | A mint that names any `relay:` label is refused, and the refusal names the label. A mint takes only initial tags (EN-40); `relay:node-id` is written by the enrollment itself (EN-38) and never named at mint (ADR-0050). Extends EN-42 when promoted. | MVP |
| EN-36 | The Console mints an Enrollment Token through the same capability action and `admin` floor as the Control API, asking how many Nodes it is for (EN-31), and shows the join string once, apart from the command that consumes it (EN-39) (ADR-0048; #434). | MVP |
| EN-38 | Every enrollment stamps `relay:node-id` with the Node's Relay-assigned ID on the Node it records. Only the enrollment action writes it, no mint may name it (EN-35), and the Node cannot change it. Becomes part of EN-41 when promoted (ADR-0048). | v0.6.5 — Install Path: relay init, join string, packages |
| EN-39 | `relay init` shows a freshly minted join string once, apart from the command that consumes it: the command is `sudo relay-daemon join`, and the string is pasted at its prompt, so it is never part of a command line (ADR-0048). | v0.6.5 — Install Path: relay init, join string, packages |
| EN-40 | A mint names zero or more **initial tags**, each a well-formed `tag:` label rendering as exactly one Selector term; a mint may name none. An entry that is not such a label refuses the mint and is never rewritten (ADR-0050). Replaces EN-3 when promoted. | MVP |
| EN-41 | After a valid token is accepted, the Relay generates the `node_id`, signs the CSR under that identity, creates the registry record, stamps `relay:node-id` (EN-38), writes the token's initial tags on the Node, and records the token ID and the time as the Node's enrollment provenance. It writes no other `relay:` label, and the CSR subject never selects the identity. Once written, an initial tag is an ordinary tag: how it is written, audited and later changed is `selectors-and-labels.md` (ADR-0050). Replaces EN-12 when promoted. | MVP |
| EN-42 | A mint request naming an initial tag that is not a well-formed `tag:` label, an invalid TTL, malformed JSON or an unknown request field is refused; nothing is sanitized into another label (ADR-0050). Replaces EN-24 when promoted. | MVP |
| EN-43 | The per-source and global enrollment rate limits are fixed constants, not settings. The per-source limit admits about 60 enrollments a minute from one address, so some 200 Nodes behind one NAT address join in minutes; the global limit stays the guard against a flood. Both still apply before token validation (EN-10). Extends EN-10 when promoted. | MVP |
| EN-44 | A mint by a machine Account that names any initial tag is refused, and the refusal says only a human Account writes tags (ADR-0050). A machine Account's mint naming no tag is unaffected. | MVP |
| EN-45 | On upgrade, every `relay:` label other than `relay:node-id` that an earlier release wrote from a token's scope is copied to a `tag:` label of the same key and value, and an unused token minted with a scope writes that scope as initial tags. Each copy is attributed to the human Account that minted the token, as EN-41 attributes initial tags; labels from a token a machine Account minted are not copied, and the upgrade lists their Nodes for a person to tag (ADR-0050). | MVP |

## Out of scope

- **Every later connection of an enrolled Node**, the pinned-CA check on reconnect, liveness
  and heartbeats: `node-connection.md`.
- **Where a join string lives on a Node, and how `relay-daemon join` and config management
  deliver it**: `daemon-installation.md`.
- **Labels after enrollment**: writing, auditing and changing tags, initial tags included, and
  the Label namespaces themselves: `selectors-and-labels.md`.
- **Which Relay settings exist**: `relay-configuration.md`. Enrollment's rate limits are not
  among them once EN-43 lands.
- **Durable audit records**: `audit-and-read-lane.md`. Enrollment attempts are not durable
  (EN-21).
- **Dispatch approvals and approval gates**: `approval.md`.
- **Fencing off a token's Nodes without revoking them**: `roadmap: relay/quarantine`.
  Containment today is revoking the token (EN-19); each Node stays addressable by
  `relay:node-id` (EN-38).
- **Enrollment as an approval**, attestation verifiers and a pipeline-driven approval:
  `roadmap: relay/enrollment-is-an-approval`. Replacing a Node in place, so a second enrollment
  inherits the old record (EN-16), waits in the private roadmap too.
- Relay does not centrally author or distribute a Node's Policy (invariant 2).
- Enrollment does not make a Node an administrator, execute an Operation, bypass a Selector or
  alter the blast-radius cap.
- Daemon installation, software distribution and config management. Enrollment consumes a
  configured daemon; it does not push one.
- Reissuing or recovering the CA private key is disaster recovery, not enrollment.
- **Residual risk**: the threat model's register, R16 and R36 (a join string at rest on a
  Node), R40 (`relay-daemon join` outside the unit's sandbox), R41 (a join string is a bearer
  credential), R42 (a second enrollment's stale record) and R44 (a token's Nodes are revoked
  together, not fenced off together).

## Proof

Generated by `make spec-proof` from the tests that name the claim they prove.

<!-- proof:begin -->
| Claim | Proven by | Seam |
|---|---|---|
| EN-1 | `TestHandleMintToken_Success`, `TestMintToken_RequiresAdmin` | API |
| EN-3 | `TestCreate_InvalidScope`, `TestCreate_WellFormedScopeAccepted` | enroll |
| EN-4 | `TestCreate_StoresHashedReturnsPlaintextOnce`, `TestHandleMintToken_Success` | API, enroll |
| EN-5 | `TestMaxUses_Concurrent`, `TestReusable_ValidatesRepeatedly` | enroll |
| EN-7 | `pin_match_enrolls`, `pin_match_with_wrong_server_name_sends_no_token`, `pin_mismatch_sends_no_token` | daemon |
| EN-8 | `TestCrossBinary_RestartWithoutJoinOrAddrUsesPersistedState`, `persisted_address_written_at_enrollment` | Relay, daemon |
| EN-9 | `TestUnaryInterceptor_CertlessEnroll_PassesWithoutIdentity`, `TestUnaryInterceptor_RenewWithoutPeerCert_Refused` | Node plane |
| EN-10 | `TestEnroll_RateLimited_Global`, `TestEnroll_RateLimited_NoTokenOracle`, `TestEnroll_RateLimited_PerIP` | enroll |
| EN-11 | `TestEnroll_EmptyTokenOrCSR`, `TestEnroll_NonNodeSelfLabel` | enroll |
| EN-12 | `TestEnroll_IdentityNotFromCSR`, `TestEnroll_Success` | enroll |
| EN-13 | `TestEnroll_InvalidToken`, `TestEnroll_Success` | enroll |
| EN-15 | `TestEnroll_PostUpsertRevocationCheck_ClosesRaceWindow` | enroll |
| EN-17 | `TestRenew_IgnoresCSRSubject`, `TestRenew_MissingNodeID` | enroll |
| EN-18 | `TestSQLiteRegistry_ProvenanceSurvivesARestart` | store |
| EN-19 | `TestService_RevokeToken_RecordsEveryCascadedNode`, `TestService_RevokeToken_RecordsNodeFoundOnRescan` | revocation |
| EN-20 | `TestRevokeTokenCascade_PersistsOneRowPerNode`, `TestService_RevokeToken_RecordFailureDoesNotStopTheCascade`, `TestService_RevokeToken_ToleratesUnknownToken` | API, revocation |
| EN-23 | `TestMintToken_RequiresAdmin`, `TestRevokeToken_RequiresAdmin` | API |
| EN-24 | `TestHandleMintToken_InvalidScopeOrTTL`, `TestHandleMintToken_MalformedOrUnknownField` | API |
| EN-25 | `TestEnroll_BadCSR`, `TestEnroll_EmptyTokenOrCSR`, `TestEnroll_NonNodeSelfLabel`, `TestEnroll_RegistryAtCapacity` | enroll |
| EN-26 | `TestEnroll_ExhaustedToken`, `TestEnroll_ExpiredToken`, `TestEnroll_LegacyMalformedScopeIsRefusedBeforeAnySideEffect`, `TestEnroll_RevokedToken` | enroll |
| EN-27 | `pin_mismatch_sends_no_token` | daemon |
| EN-29 | `TestUnaryInterceptor_RevokedAfterConnect_RenewRefused` | Node plane |
| EN-30 | `TestCrossBinary_RestartWithoutJoinOrAddrUsesPersistedState`, `join_enroll_config_never_reads_a_ca_path_or_a_bare_token`, `join_enrolls_in_process_and_persists_identity`, `join_pin_applies_to_an_overridden_address`, `join_takes_no_ca_bundle_path_and_no_bare_token` | Relay, daemon |
| EN-32 | `TestCrossBinary_RestartWithoutJoinOrAddrUsesPersistedState`, `fresh_enroll_persists_identity`, `idempotency_no_op_when_identity_present`, `join_enrolls_in_process_and_persists_identity`, `plan_has_two_outcomes`, `unenrolled_start_never_dials` | Relay, daemon |
| EN-33 | `a_failure_after_the_relay_answered_says_a_node_may_be_recorded`, `fresh_enroll_fails_closed_on_key_cert_mismatch`, `join_failed_persist_leaves_no_partial_identity`, `join_interrupted_during_enrollment_persists_nothing`, `join_pin_mismatch_sends_no_token_and_leaves_nothing_on_disk`, `join_token_rejected_leaves_nothing_on_disk`, `join_unreachable_relay_leaves_nothing_on_disk`, `unconfigured_node_exits_zero`, `unenrolled_start_never_dials` | daemon |

Unproven: EN-2, EN-6, EN-14, EN-16, EN-21, EN-22, EN-28.
Designed claims a test already cites: EN-31 (`TestHandleMintToken_InvalidScopeOrTTL`, `TestHandleMintToken_UseLimit`, `TestMinter_Mint_UseLimitMustBeNamed`).
<!-- proof:end -->

## Retired

- **EN-34** — `2026-10-22` — retired unbuilt: Relay renders no Enrollment Bundle; the join
  command is shown instead (EN-39) and the release ships static install files (ADR-0048).
- **EN-37** — `2026-10-23` — retired unbuilt: a token names initial tags, not a scope of
  `relay:` Labels (ADR-0050; EN-40).
