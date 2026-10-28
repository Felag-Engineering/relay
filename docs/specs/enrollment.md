# Enrollment

**Status:** designed, not built, as of `2026-10-28`.
**Claim prefix:** `EN`
**Governed by:** ADR-0005, ADR-0006, ADR-0010, ADR-0017, ADR-0020, ADR-0030, ADR-0031,
ADR-0022, ADR-0032, ADR-0033, ADR-0034, ADR-0048, ADR-0050; invariants 6, 7, 10, 11.

## Purpose

Enrollment is how a new server joins the fleet without being handed anything that could
administer it. An administrator mints an expiring Enrollment Token for a stated number of Nodes,
or explicitly for unlimited use. Its join string is given to the new Node once. The Node checks
that it is talking to the real Relay before it sends anything, and the Relay's private
certificate authority issues it a certificate, which is from then on the Node's only identity. A
token can only add Nodes: it never runs a command. Revoking a token revokes every Node it
enrolled. Enrollment owns first contact and the renewal and revocation of a Node's identity;
every later connection belongs to node connection.

## Surfaces

| Surface | Behaviour |
|---|---|
| Control API | An `admin` mints a token with `POST /api/v1/enrollment-tokens`, receiving the plaintext token and its **join string** once, and revokes one with `DELETE /api/v1/enrollment-tokens/{id}`. |
| Node plane | The certless `Enrollment.Enroll` RPC accepts a token, a CSR and declared `node:` Labels; `Enrollment.Renew` is mTLS-authenticated. |
| relay-daemon | `relay-daemon join` reads a join string, pins the Relay's CA fingerprint, enrolls in that process and persists the identity and the Relay address; the unit start reuses that identity and reads no join string (EN-30, EN-32). Where the join string comes from is `daemon-installation.md`. |
| Console | Shows enrollment attempts and each Node's enrollment provenance. It does not mint tokens today; EN-36 (designed) gives it a mint. |
| `relay init` | Designed: mints the first Enrollment Token on the Relay host through its mint form and shows its join string once (EN-39, EN-46). |
| MCP | No enrollment tool: no mint and no revoke. An AI-agent may read a Node's provenance through `query.md` and nothing more. |

"The daemon" below names the relay-daemon binary in whichever form runs it: the process its
unit starts, or a subcommand such as `relay-daemon join`. Where a claim means the unit start
alone, it says so.

## Behaviour

### Minting

- **EN-1** The Control API authorizes the caller as `admin` for a mint before it reads the
  request body. A mint is audited with the actor's attribution and the public token ID.
- **EN-31** A token has a positive TTL of at most one year. A mint request names a positive
  `max_uses` or sets `unlimited: true`; one that does neither, does both, or names a negative
  `max_uses` is refused with `400`. The Control API has no default for the TTL or the use limit:
  every mint names both.
- **EN-40** A mint names zero or more **initial tags**, each a well-formed `tag:` label rendering
  as exactly one Selector term; a mint may name none. An entry that is not such a label refuses
  the mint and is never rewritten (ADR-0050).
- **EN-4** The Relay returns the plaintext `id.secret` credential, and the join string built
  from it, only in the successful mint response. It stores a hash of the secret, never the
  plaintext; logs and lifecycle audit records carry only the public ID and non-secret metadata.
- **EN-5** A valid token is reusable until its expiry, its revocation or its use limit.
  Validation serializes the check and the use increment, so concurrent enrollment cannot
  exceed `max_uses`.

### The join string

- **EN-30** One join string carries everything first contact needs: the Relay address, the
  fingerprint of the Relay's CA and the Enrollment Token (ADR-0031). It is read by `relay-daemon
  join` from a prompt or standard input and consumed by the enrollment `join` performs in that
  same process (`daemon-installation.md`); it is persisted nowhere on a Node, and the unit start
  reads no join string. The daemon takes no CA bundle path and no bare token by any other setting;
  a Relay address set in its environment overrides only the address, and the pin still applies to
  whatever it dials.
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
  declared Label is not a well-formed `node:` Label, whose key is at most 63 characters and
  whose value at most 255; it never accepts a `relay:` or `tag:` Label submitted by a Node.
- **EN-41** After a valid token is accepted, the Relay generates the `node_id`, signs the CSR
  under that identity, creates the registry record, stamps `relay:node-id` (EN-38), writes the
  token's initial tags on the Node, and records the token ID and the time as the Node's enrollment
  provenance. It writes no other `relay:` label, and the CSR subject never selects the identity.
  Once written, an initial tag is an ordinary tag: how it is written, audited and later changed is
  `selectors-and-labels.md` (ADR-0050).
- **EN-13** Certificate signing and registry writes occur only after token validation. A
  rejected enrollment creates neither a certificate nor a registry record. A successful
  response carries the assigned ID, the certificate and the CA bundle.
- **EN-32** The daemon persists the key, certificate, CA bundle, Relay address and identity that
  an enrollment returns, and the unit start never enrolls: with a persisted identity it connects,
  and without one it exits as EN-33 says.
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

### Upgrade

- **EN-45** On upgrade, every `relay:` label other than `relay:node-id` that an earlier release
  wrote from a token's scope is copied to a `tag:` label of the same key and value, and an unused
  token minted with a scope writes that scope as initial tags. Each copy is attributed to the
  human Account that minted the token, as EN-41 attributes initial tags; labels from a token a
  machine Account minted are not copied, and the upgrade lists their Nodes for a person to tag
  (ADR-0050).

### Surfaces today

- **EN-43** The per-source and global enrollment rate limits are fixed constants, not settings.
  The per-source limit admits about 60 enrollments a minute from one address, so some 200 Nodes
  behind one NAT address join in minutes. The global limit, about 300 a minute with a burst well
  above one address's, stays the guard against a flood, and no single address can exhaust it.
  Both still apply before token validation (EN-10).
- **EN-21** The Console shows enrollment attempts, accepted and rejected, and each Node's
  enrollment provenance. It mints nothing and adds no Node. Attempts are an in-memory event
  feed, not durable records.
- **EN-22** MCP registers no enrollment tool: no mint and no revoke.

## Refusals

- **EN-23** A non-`admin` Control API caller cannot mint or revoke an Enrollment Token.
- **EN-35** A mint that names any `relay:` label is refused, and the refusal names the label. A
  mint takes only initial tags (EN-40); `relay:node-id` is written by the enrollment itself
  (EN-38) and never named at mint (ADR-0050). Extends EN-42 when promoted.
- **EN-42** A mint request naming an initial tag that is not a well-formed `tag:` label, an
  invalid TTL, malformed JSON or an unknown request field is refused; nothing is sanitized into
  another label (ADR-0050).
- **EN-44** A mint by a machine Account that names any initial tag is refused, and the refusal
  says only a human Account writes tags (ADR-0050). A machine Account's mint naming no tag is
  unaffected.
- **EN-25** An enrollment request with no token or no CSR, a malformed or non-`node:` declared
  Label, an invalid CSR, a full registry, or a rate-limit excess is refused. Rate-limit and
  capacity refusals are `ResourceExhausted`; missing inputs and malformed Node data are
  `InvalidArgument`.
- **EN-26** Invalid, unknown, expired, revoked, exhausted and malformed-scope tokens all
  return the same `PermissionDenied` token-rejection response, so the certless endpoint is
  never a token-state oracle.
- **EN-27** A daemon whose join string names a CA fingerprint the Relay does not present does
  not enroll and sends no token.
- **EN-33** A unit start with no persisted identity exits cleanly with nothing written; the daemon
  never opens a plaintext Node-plane connection. A failed enrollment in `relay-daemon join`
  persists no partial identity and exits non-zero.
- **EN-29** A revoked Node cannot reconnect or renew. Re-enrollment creates a new identity,
  which is why revoking a token revokes both the token and the Nodes it enrolled.

## Designed, not built

| Claim | Statement | Milestone |
|---|---|---|
| EN-36 | The Console's mint form (EN-46) mints an Enrollment Token through the same capability action and `admin` floor as the Control API, and shows the join string once, apart from the command that consumes it (EN-39) (ADR-0048; #434). | MVP |
| EN-39 | `relay init` mints through its mint form (EN-46) and shows the freshly minted join string once, apart from the command that consumes it: the command is `sudo relay-daemon join`, and the string is pasted at its prompt, so it is never part of a command line (ADR-0048). | v0.6.5 — Install Path: relay init, join string, packages |
| EN-46 | Wherever a surface offers a mint form (`relay init`, EN-39; the Console, EN-36), it asks how many Nodes the token is for. The use limit is the number given, and the form offers no unlimited option; the TTL defaults to two hours and may be changed. The form mints through the same mint action EN-31 governs, with both values explicit (ADR-0048). | v0.6.5 — Install Path: relay init, join string, packages |

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
  Containment today is revoking the token (EN-19); once EN-38 lands, each Node stays
  addressable by `relay:node-id`.
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
  Node, closed by EN-30 with a residual on Nodes configured before it), R40 (`relay-daemon
  join` outside the unit's sandbox), R41 (a join string is a bearer
  credential), R42 (a second enrollment's stale record) and R44 (a token's Nodes are revoked
  together, not fenced off together).

## Proof

Generated by `make spec-proof` from the tests that name the claim they prove.

<!-- proof:begin -->
| Claim | Proven by | Seam |
|---|---|---|
| EN-1 | `TestHandleMintToken_Success`, `TestMintToken_RequiresAdmin` | API |
| EN-4 | `TestCreate_StoresHashedReturnsPlaintextOnce`, `TestHandleMintToken_Success` | API, enroll |
| EN-5 | `TestMaxUses_Concurrent`, `TestReusable_ValidatesRepeatedly` | enroll |
| EN-7 | `ipv6_literal_relay_whose_certificate_lacks_that_ip_sends_no_token`, `pin_match_enrolls`, `pin_match_with_wrong_server_name_sends_no_token`, `pin_mismatch_sends_no_token` | daemon |
| EN-8 | `TestCrossBinary_RestartWithoutJoinOrAddrUsesPersistedState`, `persisted_address_written_at_enrollment` | Relay, daemon |
| EN-9 | `TestServerCertificate_OneLeafOnBothListenersOnlyTheNodePlaneAsksForAClientCert`, `TestUnaryInterceptor_CertlessEnroll_PassesWithoutIdentity`, `TestUnaryInterceptor_RenewWithoutPeerCert_Refused` | Node plane, Relay |
| EN-10 | `TestEnroll_RateLimited_Global`, `TestEnroll_RateLimited_NoTokenOracle`, `TestEnroll_RateLimited_PerIP` | enroll |
| EN-11 | `TestEnroll_EmptyTokenOrCSR`, `TestEnroll_NonNodeSelfLabel`, `TestEnroll_SelfLabelAtTheLengthBoundsIsAccepted` | enroll |
| EN-13 | `TestEnroll_InitialTagWriteFailureDenylistsTheNode`, `TestEnroll_InvalidToken`, `TestEnroll_Success` | enroll |
| EN-15 | `TestEnroll_PostUpsertRevocationCheck_ClosesRaceWindow` | enroll |
| EN-17 | `TestRenew_IgnoresCSRSubject`, `TestRenew_MissingNodeID` | enroll |
| EN-18 | `TestSQLiteRegistry_ProvenanceSurvivesARestart` | store |
| EN-19 | `TestService_RevokeToken_RecordsEveryCascadedNode`, `TestService_RevokeToken_RecordsNodeFoundOnRescan` | revocation |
| EN-20 | `TestRevokeTokenCascade_PersistsOneRowPerNode`, `TestService_RevokeToken_RecordFailureDoesNotStopTheCascade`, `TestService_RevokeToken_ToleratesUnknownToken` | API, revocation |
| EN-23 | `TestMintToken_RequiresAdmin`, `TestRevokeToken_RequiresAdmin` | API |
| EN-25 | `TestEnroll_BadCSR`, `TestEnroll_EmptyTokenOrCSR`, `TestEnroll_NonNodeSelfLabel`, `TestEnroll_RegistryAtCapacity` | enroll |
| EN-26 | `TestEnroll_ExhaustedToken`, `TestEnroll_ExpiredToken`, `TestEnroll_LegacyMalformedScopeIsRefusedBeforeAnySideEffect`, `TestEnroll_RevokedToken`, `TestEnroll_StoredMalformedInitialTagIsRefusedBeforeAnySideEffect` | enroll |
| EN-27 | `pin_mismatch_sends_no_token` | daemon |
| EN-29 | `TestUnaryInterceptor_RevokedAfterConnect_RenewRefused` | Node plane |
| EN-30 | `TestCrossBinary_RestartWithoutJoinOrAddrUsesPersistedState`, `join_enroll_config_never_reads_a_ca_path_or_a_bare_token`, `join_enrolls_in_process_and_persists_identity`, `join_pin_applies_to_an_overridden_address`, `join_takes_no_ca_bundle_path_and_no_bare_token` | Relay, daemon |
| EN-31 | `TestHandleMintToken_InvalidInitialTagOrTTL`, `TestHandleMintToken_UseLimit`, `TestMinter_Mint_UseLimitMustBeNamed` | API, enroll |
| EN-32 | `TestCrossBinary_RestartWithoutJoinOrAddrUsesPersistedState`, `fresh_enroll_persists_identity`, `idempotency_no_op_when_identity_present`, `join_enrolls_in_process_and_persists_identity`, `plan_has_two_outcomes`, `unenrolled_start_never_dials` | Relay, daemon |
| EN-33 | `a_failure_after_the_relay_answered_says_a_node_may_be_recorded`, `fresh_enroll_fails_closed_on_key_cert_mismatch`, `join_failed_persist_leaves_no_partial_identity`, `join_interrupted_during_enrollment_persists_nothing`, `join_pin_mismatch_sends_no_token_and_leaves_nothing_on_disk`, `join_token_rejected_leaves_nothing_on_disk`, `join_unreachable_relay_leaves_nothing_on_disk`, `unconfigured_node_exits_zero`, `unenrolled_start_never_dials` | daemon |
| EN-35 | `TestCreate_RelayLabelRefusedNamingIt`, `TestHandleMintToken_RelayLabelRefusedNamingIt`, `TestParseInitialTags` | API, enroll, registry |
| EN-40 | `TestCreate_InitialTagMalformedRefused`, `TestCreate_InitialTagsWellFormedAccepted`, `TestEnroll_StoredMalformedInitialTagIsRefusedBeforeAnySideEffect`, `TestHandleMintToken_Success`, `TestParseInitialTags`, `TestParseInitialTags_AgreesWithParseTagLabel`, `TestTagWriter_WriteInitialTags_Refusals`, `TestValidate_StoredMalformedInitialTagRefusedBeforeAUse` | API, capability, enroll, registry |
| EN-41 | `TestControlAPI_InitialTagsAreOrdinaryTags`, `TestEnroll_IdentityNotFromCSR`, `TestEnroll_InitialTagWriteFailureFailsEnrollment`, `TestEnroll_InitialTagsWithoutWriterFailsClosed`, `TestEnroll_NoInitialTagsWritesNone`, `TestEnroll_Success`, `TestTagWriter_WriteInitialTags_OneRecordPerTagAttributedToTheMinter`, `TestValidate_Valid_ReturnsGrant`, `TestWriteInitialTags_RecordsNameTheEnrollmentToken` | Relay, auditsink, capability, enroll |
| EN-42 | `TestHandleMintToken_InvalidInitialTagOrTTL`, `TestHandleMintToken_MalformedOrUnknownField` | API |
| EN-43 | `TestEnrollment_GlobalStillGuardsAFlood`, `TestEnrollment_NATBatchJoinsInMinutes`, `TestEnrollment_OneAddressCannotExhaustTheGlobalLimit`, `TestEnrollment_PerSourceAdmitsSixtyAMinute` | ratelimit |
| EN-44 | `TestCreate_MachineAccountNamingTagsRefused`, `TestEnroll_RefusedMinterLeavesNoNodeAndBurnsNoUse`, `TestHandleMintToken_MachineAccountInitialTags`, `TestTagWriter_CheckInitialTags_DecidesBeforeAnyNodeExists`, `TestTagWriter_WriteInitialTags_RefusesAMachineMinter`, `TestValidate_StoredMachineMintedTagsRefusedBeforeAUse` | API, capability, enroll |
| EN-45 | `TestMigration0033_ScopeLabelsBecomeTagsAndTheAuditChainVerifies`, `TestMigration0033_UnusedHumanTokenEnrollsWithItsScopeAsTags`, `TestMigration0033_UsedHumanTokenIsNotConvertedAndIsListed` | store |

Unproven: EN-16, EN-21, EN-22.
<!-- proof:end -->

## Retired

- **EN-3** — `2026-10-27` — a token carried a scope of `relay:` Labels; replaced by EN-40.
- **EN-12** — `2026-10-27` — enrollment stamped the token's scope as the Node's `relay:` Labels;
  replaced by EN-41.
- **EN-24** — `2026-10-27` — a mint with a malformed `relay:` scope entry was refused; replaced by
  EN-42.
- **EN-38** — `2026-10-27` — the `relay:node-id` stamp as a claim of its own; folded into EN-41,
  which writes it and no other `relay:` label.
- **EN-2** — `2026-10-28` — replaced by EN-31: a mint names its use limit or asks explicitly
  for unlimited use, and a missing `max_uses` is refused rather than unlimited (#1136).
- **EN-6** — `2026-10-25` — the join string's contract named no reader; replaced by EN-30, under
  which `relay-daemon join` consumes it and the unit start reads none.
- **EN-14** — `2026-10-25` — the daemon enrolled at start and the join string was inert after;
  replaced by EN-32.
- **EN-28** — `2026-10-25` — a daemon with neither identity nor join string exited cleanly;
  replaced by EN-33.
- **EN-34** — `2026-10-22` — retired unbuilt: Relay renders no Enrollment Bundle; the join
  command is shown instead (EN-39) and the release ships static install files (ADR-0048).
- **EN-37** — `2026-10-23` — retired unbuilt: a token names initial tags, not a scope of
  `relay:` Labels (ADR-0050; EN-40).
