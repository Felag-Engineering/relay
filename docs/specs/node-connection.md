# Node connection

**Status:** current as of `2026-11-13`.
**Claim prefix:** `NC`
**Governed by:** ADR-0004, ADR-0005, ADR-0006, ADR-0014, ADR-0017, ADR-0031; invariants 4, 6, 7,
8, 11, 14.

## Purpose

Every managed server (a Node) holds one long-lived link to the Relay, and always opens it
itself: a Node never accepts an incoming connection. Both ends prove who they are on every
connect, so neither accepts an impostor. The Relay sends work down the link; the Node returns
results, a regular heartbeat and a description of itself. "Connected" means recently heard from,
not merely still open. A Node's description of itself is trusted only as far as the Node: it can
never grant itself authority, change its Policy, or write the labels that aim remediation and
secret distribution.

## Surfaces

| Surface | How it is reached |
|---|---|
| Node plane | `Tunnel.Open`: one mutual-TLS stream per Node, always opened by the relay-daemon. The daemon sends `Hello`, heartbeats, snapshots and Task results; the Relay sends Tasks, cancellations and Policy queries. `Enrollment.Enroll` and `Enrollment.Renew` share the listener (`enrollment.md`). |
| relay-daemon | Dials, verifies the Relay, holds the stream, reconnects. The address it dials: `enrollment.md`. |
| Registry reads | Connected state, `last_seen`, `outdated` and the self-reported fields (`query.md`). |
| Audit trail | The change and replacement records below (`audit-and-read-lane.md`). |
| Relay configuration | The certificate hostname, the minimum daemon version, and whether the control plane is enabled (NC-13); see `relay-configuration.md`. Every timing is a constant. |
| MCP, Control API, Console | None opens, closes or reshapes a connection; revoking a Node ends its connection (`enrollment.md`). |

## Behaviour

### The handshake

- **NC-1** The relay-daemon always opens the connection as one long-lived gRPC bidirectional stream,
  and listens on no inbound port.
- **NC-2** Every Node-plane call except `Enrollment.Enroll` (`enrollment.md`) is mutual TLS: the
  Relay presents its server certificate, the daemon its client certificate, and each verifies
  the other.
- **NC-3** A Node's identity is the Node ID in its verified client certificate, never a value
  the daemon sends.
- **NC-38** `Hello` carries no Node ID: the field is deprecated in `/proto`, the daemon never
  sets it, and the Relay never reads it.
- **NC-4** On every connect the daemon verifies the Relay's certificate against the CA pinned at
  enrollment, and trusts no other root.
- **NC-5** The daemon reads its identity from its state directory at each connect, so a renewed
  certificate is used from the next one; nothing forces a reconnect. The registry records the
  client-certificate fingerprint issued at enrollment, replaced by the one each connect presents.
- **NC-35** A connect presenting a client-certificate fingerprint other than the one the
  registry holds for the Node writes one audit record with both.
- **NC-6** The Relay presents one server certificate on both listeners and re-issues it in-process
  before expiry, so a running Relay never presents an expired one (ADR-0031). Only the Node plane
  asks for a client certificate.

### What connected means

- **NC-7** A Node is connected while heartbeats on its current stream arrive within the
  deadline, not merely while the stream is open. Only a heartbeat resets the deadline.
- **NC-8** The daemon sends a heartbeat every 60 seconds, jittered by up to 20% either way, so a
  fleet restarted together does not arrive in lockstep.
- **NC-9** The Relay closes a stream that goes 3 heartbeat intervals (180 seconds) without a
  heartbeat and marks the Node offline. The interval and the allowance are constants.
- **NC-10** Both sides run HTTP/2 keepalive with constant timings. The Relay pings a connection
  idle for 30 seconds and, after 20 seconds unanswered, closes it and marks the Node offline.
  The daemon pings every 60 seconds and abandons the connection after 60 seconds unanswered.
- **NC-11** `last_seen` is the time of the Node's last heartbeat or `Hello`. Connected is never
  derived from it.
- **NC-37** The Relay measures each heartbeat's timestamp against its own clock and records the
  difference on the Node's registry record as its clock skew: Relay-measured, kept apart from the
  self-reported Facts, and never a reason to refuse a connection or a dispatch.
- **NC-12** No message acknowledges a Task and no `unacknowledged` outcome exists: a Task sent
  to a silently dead Node waits out NC-9 (R52).

### One current stream

- **NC-13** With the control plane enabled, the Relay holds one current stream per Node for
  dispatch: a new stream for the same Node ID replaces the current one, which ends with an error
  naming a newer stream as the cause.
- **NC-14** Only the current stream receives Tasks.
- **NC-15** Ending a replaced stream never marks the Node offline.
- **NC-36** A stream opened while another stream for the Node is live is a replacement, counted
  with the control plane enabled or not; replacements write an audit record within NC-39's
  limit (R54).

### Reconnecting

- **NC-16** The daemon reconnects with exponential backoff from 1 second to a 30-second cap, each
  wait drawn between half and all of the step. Only a successful `Tunnel.Open` resets the backoff
  to 1 second.
- **NC-17** The daemon retries indefinitely; only a malformed Relay endpoint stops it.
- **NC-18** The Relay applies no admission limit to reconnecting Nodes: after a Relay restart
  only the daemons' jitter spreads the fleet (R53).

### What a Node reports about itself

- **NC-19** A stream opens with `Hello` (daemon version, Facts, declared and built-in `node:`
  labels, Policy fingerprint, template-set fingerprint), then a `PolicySnapshot`, which says
  whether Raw Exec is enabled, then a `TemplateSnapshot`.
- **NC-20** The self-report is read once per stream: a later `Hello`, `PolicySnapshot` or
  `TemplateSnapshot` on it is ignored, so a Policy or label change on the Node arrives with the
  `Hello` after the daemon restarts.
- **NC-21** The Relay keeps a `Hello` field only in its bounded shape. Policy fingerprint: 64
  lowercase hex. Template-set fingerprint: the same, or `unloadable`. Daemon version: semver,
  at most 253 bytes. Hostname, OS, kernel, architecture: at most 253 bytes of visible ASCII. IP
  address: plain, no zone; a list of more than 256 is dropped whole. `node:` label: within
  `selectors-and-labels.md`'s bounds.
- **NC-22** A field that fails its bound is recorded as not reported, or its entry dropped,
  never truncated or rewritten, and the stream stays up. A stored value that fails its bound is
  declined the same way on read.
- **NC-23** On a Node read, a `PolicySnapshot` or `TemplateSnapshot` fingerprint that fails the
  `Hello` bound is served empty.
- **NC-24** A self-reported label outside `node:` is dropped. Nothing a Node reports writes
  `relay:` or `tag:` labels, Policy, or any registry field beyond the self-reported ones
  (invariant 7; R3, R51).
- **NC-25** Each connect replaces the Node's self-reported fields. A Facts or `node:` label
  change is recorded, never audited.
- **NC-33** A reported Policy fingerprint or Raw Exec state that differs from the Node's previous
  connect writes one audit record with both values; a first connect writes none.
- **NC-39** The records of NC-33 to NC-36 are limited per Node and kind to one per 10 minutes,
  each carrying the number of events since the previous record of its kind. An event with no
  record of its kind in the previous 10 minutes is written at once, so a Node that keeps changing
  its report, or two parties on one certificate, write a bounded number. The limit is held in
  memory and starts over when the Relay restarts. No record blocks a connection or a dispatch
  (R51, R54).

### Daemon versions

- **NC-26** A daemon's version never refuses its connection: an older daemon connects, is flagged
  `outdated` in the registry, and is refused at dispatch by the minimum-version gate
  (`execution.md`; invariant 14).
- **NC-27** No Node-plane message installs, upgrades or replaces a binary (invariant 14).
- **NC-34** A reported daemon version that differs from the Node's previous connect writes one
  audit record with both versions, marked a downgrade when lower; a first connect writes none.

## Refusals

- **NC-28** The Relay refuses, in the TLS handshake before any stream opens, a client
  certificate that does not chain to its CA or names a revoked Node, and checks revocation
  again before each call runs.
- **NC-29** A Node-plane call other than `Enroll` without a verified client certificate is
  refused as unauthenticated before its handler runs.
- **NC-30** The daemon sends nothing, `Hello` included, to a Relay whose certificate does not
  chain to the pinned CA, and retries on its backoff.
- **NC-31** An expired client certificate is refused at the handshake like any unverified one. The
  daemon keeps retrying and cannot succeed; only enrolling again, under a new Node ID
  (`enrollment.md`), brings the Node back.
- **NC-32** A stream whose first message is not `Hello` is refused as an invalid argument.

## Out of scope

- **Certificates (issue, renew, revoke), the join string, the first-contact pin, the address
  the daemon dials**: `enrollment.md`.
- **Tasks, their outcomes, cancellation, the minimum-version refusal**: `execution.md`.
- **`state:` markers from connection facts**: `selectors-and-labels.md`.
- **What the Policy fingerprint means**: `policy.md`.
- **Installing the relay-daemon, its dedup markers, and at-most-once across a replaced or dropped
  stream (invariant 4)**: `daemon-installation.md`.
- **Metrics, including the server certificate's remaining lifetime**: `observability.md`.
- **How control-plane callers authenticate**: `accounts-and-access.md`.
- **Refusing at connect a daemon too old to speak the protocol**: not done; compatibility is the
  minimum-version gate (ADR-0014) and an additive `/proto`.
- **A Task acknowledgement deadline, admission pacing**:
  `roadmap: relay/fast-failure-and-fleet-admission`.
- **A self-report without reconnecting**: `roadmap: relay/policy-catalog-and-live-reload`.
- **A company-issued certificate**: `roadmap: relay/bring-your-own-pki`.
- **The Node plane's scale contract**: `roadmap: relay/research/spec-future-work/node-connection`.
- **Several Relays sharing a fleet**: deferred by ADR-0005 to a future ADR.
- **With the control plane disabled: ending a displaced stream, which stream the Node's connected
  state follows; and showing on registry reads a certificate in use by more than one connection**:
  #1330.

## Proof

<!-- proof:begin -->
| Claim | Proven by | Seam |
|---|---|---|
| NC-1 | `TestTunnel_OpenIsTheOneBidirectionalStream`, `the_daemon_never_listens_on_an_inbound_port` | Node plane, daemon |
| NC-2 | `TestCertlessMethods_OnlyEnroll`, `TestServerCertificate_OneLeafOnBothListenersOnlyTheNodePlaneAsksForAClientCert`, `TestTransport_AcceptValidClientCert`, `TestTransport_RejectUntrustedCert`, `wrong_ca_relay_is_refused` | Node plane, Relay, daemon |
| NC-3 | `TestTransport_AcceptValidClientCert`, `TestTunnelOpen_FailClosed`, `TestTunnelOpen_TheNodeIsTheVerifiedCertificateNeverTheHello` | Node plane, Relay |
| NC-4 | `ipv4_literal_relay_is_verified_by_its_ip_san_with_no_server_name`, `the_daemon_trusts_only_the_pinned_ca`, `wrong_ca_relay_is_refused` | daemon |
| NC-5 | `TestLifecycle_SeedEnrollMTLSRenewRevoke`, `TestTunnelOpen_RenewThenReconnectWritesOneCertChangedRecord`, `perform_renewal_happy_path` | Relay, daemon |
| NC-6 | `TestServerCertificate_NeverServesAnExpiredLeaf`, `TestServerCertificate_OneLeafOnBothListenersOnlyTheNodePlaneAsksForAClientCert`, `TestServerCertificate_RotatesAtRenewalThreshold`, `TestTransport_CertificateIsFetchedEveryHandshake` | Node plane, Relay, ca |
| NC-7 | `TestTunnelOpen_HeartbeatsWithinDeadlineKeepNodeConnected`, `TestTunnelOpen_MissedHeartbeatsMarkOfflineAndCloseStream`, `TestTunnelOpen_OnlyHeartbeatsResetTheDeadline` | Relay |
| NC-8 | `heartbeat_delay_bounds_and_midpoint`, `heartbeat_interval_is_sixty_seconds_jittered_twenty_percent` | daemon |
| NC-9 | `TestLivenessConstants_AgreeWithTheDaemon`, `TestTunnelOpen_MissedHeartbeatsMarkOfflineAndCloseStream`, `TestTunnelServer_DefaultDeadlineIsThreeHeartbeatIntervals` | Relay |
| NC-10 | `TestKeepalive_ProductionValuesAreThirtyAndTwentySeconds`, `TestKeepalive_RelayClosesADeadLinkAndMarksTheNodeOffline`, `TestLivenessConstants_AgreeWithTheDaemon`, `keepalive_is_sixty_seconds_each_way` | Node plane, Relay, daemon |
| NC-11 | `TestMarkers_OfflineComesFromConnectedness`, `TestRepositoryConformance`, `TestSQLiteRegistryConformance`, `TestTunnelOpen_HeartbeatUpdatesLastSeen`, `TestTunnelOpen_MissedHeartbeatsMarkOfflineAndCloseStream` | Relay, nodestate, registry, store |
| NC-12 | `TestNodePlane_NoMessageAcknowledgesATask`, `TestTunnelOpen_ATaskToASilentNodeResolvesNodeOfflineAtTheHeartbeatDeadline` | Node plane, Relay |
| NC-13 | `TestRouter_ADisplacedRegistrationIsTold`, `TestRouter_ReplacedRegistrationFailsItsWaitersWithErrStreamReplaced`, `TestTunnelOpen_ANewerRegistrationEndsTheStreamItDisplaced` | Relay, dispatch |
| NC-14 | `TestRouter_OnlyTheCurrentRegistrationReceivesTasks` | dispatch |
| NC-15 | `TestRouter_ReplacedRegistrationEndDoesNotRunOfflineHook`, `TestTunnelOpen_ReplacedStreamEndDoesNotMarkLiveNodeOffline` | Relay, dispatch |
| NC-16 | `backoff_next_delay_advances_and_jitter_bounds`, `backoff_progression_caps`, `backoff_reset_returns_to_base`, `reconnect_backoff_runs_from_one_second_to_a_thirty_second_cap`, `reconnect_loop_backoff_keeps_growing_while_the_relay_refuses_the_open`, `reconnect_loop_backoff_returns_to_base_after_an_open_that_succeeded`, `reconnect_loop_retries_a_relay_outside_the_pinned_ca_and_sends_it_nothing` | daemon |
| NC-17 | `TestFleetE2E_RelayRestartDaemonReconnects_DedupHolds`, `backoff_never_runs_out`, `http_endpoint_is_rejected`, `reconnect_loop_retries_a_relay_outside_the_pinned_ca_and_sends_it_nothing`, `reconnect_loop_returns_an_error_for_a_non_https_endpoint` | Relay, daemon |
| NC-18 | `TestTunnelOpen_AFleetConnectingAtOnceIsAdmittedWhole` | Relay |
| NC-19 | `hello_never_sets_the_node_id`, `policy_snapshot_from_fixture_populates_all_fields`, `run_tunnel_opens_with_hello_then_the_policy_and_template_snapshots` | daemon |
| NC-20 | `TestE2E_PolicyChangeReachesTheRegistryOnlyAfterTheDaemonRestarts`, `TestTunnelOpen_ALaterHelloOrPolicySnapshotOnTheSameStreamChangesNoRegistryField`, `TestTunnelOpen_ALaterPolicyOrTemplateSnapshotOnTheSameStreamChangesNoCache`, `TestTunnelOpen_AReconnectReplacesBothCachesWithItsOwnFirstSnapshots` | Relay |
| NC-21 | `TestHelloReportFromProto`, `TestSelfReportBounds_AreTheSpecValues`, `TestTunnelOpen_HelloAtTheIPAddressCapKeepsEveryAddress`, `TestTunnelOpen_HelloBoundsEverySelfReportedField`, `TestTunnelOpen_HelloOverTheIPAddressCapRecordsNoAddresses`, `TestTunnelOpen_HelloWellFormedPolicyFingerprintIsUnchanged`, `TestWellFormedFingerprint`, `TestWellFormedNodeLabel`, `TestWellFormedSelfReportedText` | Relay, protoconv, registry |
| NC-22 | `TestDeclineMalformedSelfReport`, `TestInMemory_DeclinesOverLongNodeLabelOnRead`, `TestOpen_MalformedNodeLabelDoesNotDropTheStream`, `TestRepositoryConformance`, `TestSQLiteRegistryConformance`, `TestTunnelOpen_HelloMalformedPolicyFingerprintIsStoredAsNotReported`, `TestTunnelOpen_HelloOverTheNodeLabelCapRecordsNoNodeLabels` | Relay, registry, store |
| NC-23 | `TestBoundedSnapshots_ServeAFailingFingerprintAsEmpty`, `TestDescribeNode_SnapshotFingerprintsThatFailTheBoundAreServedEmpty`, `TestListOperations_TemplateSnapshotFingerprintThatFailsTheBoundIsServedEmpty` | capability |
| NC-24 | `TestConnectionObservationWriters_EachHasOnlyItsDefiningCallers`, `TestLabelWriters_EachHasOnlyItsDefiningCallers`, `TestNodeLabelsFromHello`, `TestRepositoryConformance`, `TestSQLiteRegistryConformance`, `TestTunnelOpen_ANodeReportWritesNoRelayOrTagLabel`, `TestTunnelOpen_HelloRegistersNode` | Relay, registry, store |
| NC-25 | `TestRepositoryConformance`, `TestSQLiteRegistryConformance`, `TestTunnelOpen_ChangedFactsAndNodeLabelsAreRecordedAndNeverAudited`, `TestTunnelOpen_HelloOverTheNodeLabelCapReplacesAnEarlierSet` | Relay, registry, store |
| NC-26 | `TestMCP_RunOperation_OutdatedNodeVersionRefused`, `TestTunnelOpen_DaemonVersionBelowTheMinimumStillConnects`, `TestTunnelOpen_DaemonVersionBelowTheMinimumStillConnectsAndIsAudited` | MCP, Relay |
| NC-27 | `TestNodePlane_NoRPCInstallsADaemon` | Node plane |
| NC-28 | `TestServerCredentials_NilObserverStillRefusesARevokedCert`, `TestServerCredentials_RefusesAnUntrustedClientCertAtTheHandshake`, `TestTransport_RejectRevoked_Interceptor`, `TestUnaryInterceptor_RevokedAfterConnect_RenewRefused` | Node plane |
| NC-29 | `TestCertlessMethods_OnlyEnroll`, `TestServerCertificate_OneLeafOnBothListenersOnlyTheNodePlaneAsksForAClientCert`, `TestStreamInterceptor_RefusesACertlessTunnelOpenBeforeItsHandler`, `TestTransport_RejectNoCert`, `TestUnaryInterceptor_RefusesWithoutVerifiedIdentity`, `TestUnaryInterceptor_RenewWithoutPeerCert_Refused` | Node plane, Relay |
| NC-30 | `reconnect_loop_retries_a_relay_outside_the_pinned_ca_and_sends_it_nothing`, `wrong_ca_relay_is_refused` | daemon |
| NC-31 | `TestEnroll_SecondEnrollmentIsANewNode`, `TestServerCredentials_RefusesAnExpiredClientCertAtTheHandshake` | Node plane, Relay |
| NC-32 | `TestTunnelOpen_AFirstMessageThatIsNotHelloIsRefusedAsInvalidArgument` | Relay |
| NC-33 | `TestPolicyChangedReason`, `TestTunnelOpen_ChangedPolicyFingerprintWritesOneRecord`, `TestTunnelOpen_ChangedPolicyWritesOneNodePolicyChangedRow`, `TestTunnelOpen_FailedPolicyRecordKeepsTheStreamUp`, `TestTunnelOpen_FirstConnectWritesNoPolicyRecord`, `TestTunnelOpen_OtherFirstMessageResolvesThePolicyRecordWithoutTheSnapshot`, `TestTunnelOpen_PolicyFingerprintAndRawExecChangeWriteOneRecord`, `TestTunnelOpen_RawExecOnlyChangeWritesOneRecord`, `TestTunnelOpen_StreamEndingBeforeItsPolicySnapshotRecordsRawExecUnknown` | Relay, auditsink |
| NC-34 | `TestDaemonVersionChangedReason`, `TestTunnelOpen_ChangedDaemonVersionWritesOneRecord`, `TestTunnelOpen_DaemonVersionBelowTheMinimumStillConnects`, `TestTunnelOpen_DaemonVersionBelowTheMinimumStillConnectsAndIsAudited`, `TestTunnelOpen_FirstConnectReportingNothingCannotHideTheNextReport`, `TestTunnelOpen_FirstConnectWritesNoVersionRecord`, `TestTunnelOpen_LowerDaemonVersionIsPassedAsADowngrade`, `TestTunnelOpen_OverlappingConnectsOfOneNodeRecordThePersistedOrder`, `TestTunnelOpen_UnreportedDaemonVersionIsRecordedAsUnknownSide` | Relay, auditsink |
| NC-35 | `TestTunnelOpen_RenewThenReconnectWritesOneCertChangedRecord`, `TestTunnelOpen_RenewalBeforeTheFirstConnectIsRecordedOnThatConnect`, `TestTunnelOpen_SameCertificateReconnectWritesNoCertRecord` | Relay |
| NC-36 | `TestConnectionRecorder_ConcurrentFirstEventsRecordOnce`, `TestConnectionRecorder_FailedEntrySurvivesTheSweep`, `TestConnectionRecorder_FirstEventRecordedAtOnce`, `TestConnectionRecorder_KindsAreThrottledIndependently`, `TestConnectionRecorder_ReplacementsInsideTheWindowAreCarriedByTheNextRecord`, `TestConnectionRecorder_SweepDropsIdleEntriesAndKeepsPending`, `TestConnectionRecorder_WriteFailureLosesNoCount`, `TestTunnelOpen_TwoStreamsOnOneCertificateWriteOneReplacedRow`, `TestTunnelOpen_TwoStreamsOnOneCertificateWriteOneReplacedRowWithControlPlane` | Relay, auditsink |
| NC-37 | `TestHeartbeatClockSkew`, `TestRepositoryConformance`, `TestSQLiteRegistryConformance`, `TestTunnelOpen_HeartbeatFiveMinutesOutRecordsAboutThatSkew`, `TestTunnelOpen_NodeYearsOutKeepsItsStreamAndAnswersATask`, `TestTunnelOpen_NonPositiveHeartbeatTimestampRecordsSkewNotMeasured` | Relay, registry, store |
| NC-38 | `TestHello_NodeIDIsDeprecatedInTheContract`, `TestRelay_NoFileSelectsTheHelloNodeID`, `TestTunnelOpen_ForgedHelloNodeIDIsKeyedByTheCertificateAndNeverLogged`, `hello_never_sets_the_node_id` | Node plane, Relay, daemon |
| NC-39 | `TestConnectionRecorder_FirstEventRecordedAtOnce`, `TestConnectionRecorder_KindsAreThrottledIndependently`, `TestConnectionRecorder_NextRecordCarriesTheCountAndItsOwnValues`, `TestConnectionRecorder_NodesAreThrottledIndependently`, `TestConnectionRecorder_SweepDropsIdleEntriesAndKeepsPending`, `TestConnectionRecorder_ThrottledWithinTheWindow`, `TestTunnelOpen_AlternatingDaemonVersionsWriteOneRowPerWindow` | Relay, auditsink |

Unproven: none.
<!-- proof:end -->

## Retired

None.
