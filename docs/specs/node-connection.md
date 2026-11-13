# Node connection

**Status:** current as of `2026-11-12`.
**Claim prefix:** `NC`
**Governed by:** ADR-0004, ADR-0005, ADR-0006, ADR-0014, ADR-0017, ADR-0031; invariants 4, 6, 7,
8, 11, 14.

## Purpose

Every managed server (a Node) keeps one lasting, trusted link to the Relay, which it opens
itself: a Node never accepts an incoming connection. Both ends prove who they are on every
connect, so a Node refuses an impostor Relay and the Relay refuses an impostor Node. The Relay
sends work down the link; the Node sends back results, a regular sign of life, and a
description of itself. "Connected" means the Node was heard from recently, not merely that its
connection is still open. What a Node says about itself is trusted only as much as the Node:
it can never grant itself authority, change its Policy, or write the labels the security lane
targets.

## Surfaces

| Surface | How it is reached |
|---|---|
| Node plane | One mutually authenticated TLS stream per Node, the `Tunnel.Open` call, always opened by the relay-daemon. The daemon sends `Hello`, heartbeats, snapshots and Task results; the Relay sends Tasks, cancellations and Policy queries. `Enrollment.Enroll` and `Enrollment.Renew` share the listener and belong to `enrollment.md`. |
| relay-daemon | Dials the Relay, verifies it, holds the stream and reconnects. Which address it dials is `enrollment.md`. |
| Registry reads | Connected state, `last_seen`, `outdated`, and the self-reported fields of the Node's registry record, on `list_nodes`, `describe_node`, the Control API's Node read and the Console fleet view, as `query.md` describes. |
| Audit trail | The connection audit records designed below, read as `audit-and-read-lane.md` describes. |
| Relay configuration | The certificate hostname and the minimum daemon version (`relay-configuration.md`). Every timing here is a built-in constant, not a setting. |
| MCP, Control API, Console | No surface opens, closes or reshapes a connection. Revoking a Node ends its connection, and `enrollment.md` owns that. |

## Behaviour

### The handshake

- **NC-1** The relay-daemon always opens the connection, as one long-lived gRPC bidirectional
  stream, and never listens on an inbound port.
- **NC-2** Every Node-plane call except `Enrollment.Enroll` (`enrollment.md`) is mutual TLS:
  the Relay presents its server certificate and the daemon its client certificate, and each
  verifies the other.
- **NC-3** A Node's identity is the Node ID in its verified client certificate, never a value
  the daemon sends.
- **NC-38** `Hello` carries no Node ID: its field is deprecated in `/proto`, the daemon never
  sets it and the Relay never reads it.
- **NC-4** On every connect the daemon verifies the Relay's server certificate against the CA it
  pinned at enrollment, and trusts no system or public roots.
- **NC-5** The daemon reads its identity from its state directory at each connect, so a renewed
  certificate is used from the next connect; nothing forces a reconnect. The registry records
  the certificate fingerprint presented on the Node's latest connect.
- **NC-35** Between two connects of the same Node, a change in the client certificate
  fingerprint writes one audit record with the before and after fingerprints. The record
  blocks nothing.
- **NC-6** The Relay presents one server certificate on both listeners and re-issues it
  in-process before it expires, so a running Relay never presents an expired one (ADR-0031).
  Only the Node plane asks for a client certificate.

### What connected means

- **NC-7** A Node is connected while its current stream's heartbeats arrive within the deadline,
  not merely while the stream is open. Only a heartbeat resets the deadline.
- **NC-8** The daemon sends a heartbeat every 60 seconds, jittered by up to 20% either way, so a
  fleet restarted at once does not arrive in lockstep.
- **NC-9** The Relay closes a stream that has gone 3 heartbeat intervals (180 seconds) without a
  heartbeat, and marks the Node offline. The interval and the allowance are constants.
- **NC-10** Both sides run HTTP/2 keepalive with constant timings. The Relay pings a connection
  idle for 30 seconds and closes it, marking the Node offline, when the ping goes unanswered for
  20 seconds. The daemon pings every 60 seconds and abandons a connection whose ping goes
  unanswered for 60 seconds.
- **NC-11** `last_seen` records the Node's last contact, a heartbeat or a `Hello`. Connected is
  never derived from it.
- **NC-37** The Relay measures each heartbeat's timestamp against its own clock and records the
  difference on the Node's registry record as its clock skew: a Relay-measured value, kept apart
  from the self-reported Facts. Clock skew never blocks a connection or a dispatch.
- **NC-12** There is no Task acknowledgement: no message acknowledges a Task and no
  `unacknowledged` outcome exists. A Task sent to a silently dead Node waits out NC-9 (R52).

### One current stream

- **NC-13** The Relay holds one current stream per Node for dispatch. With execution on, a stream
  opened for a Node ID replaces the existing one, and the replaced stream ends with an error
  naming a newer stream as the cause.
- **NC-14** Only the current stream receives Tasks.
- **NC-15** Ending a replaced stream never marks the Node offline.
- **NC-36** The Relay counts stream replacements per Node and, while it runs, writes at most one audit record per Node per 10 minutes, carrying the number of replacements since the previous record, so a single replacement is recorded and a flapping pair writes a bounded number of records (R54).

At-most-once across a replaced or dropped stream is `daemon-installation.md`'s, and a Task's
outcome is `execution.md`'s (invariant 4).

### Reconnecting

- **NC-16** The daemon reconnects with exponential backoff from 1 second to a 30-second cap,
  each wait drawn between half and all of the current step. It returns to the base only after
  a connect whose `Tunnel.Open` call succeeded, never after a failed handshake or `Open`.
- **NC-17** The daemon retries indefinitely. Only a malformed Relay endpoint stops it.
- **NC-18** The Relay applies no admission limit to reconnecting Nodes. After a Relay restart
  only the daemons' jitter spreads the fleet (R53).

### What a Node reports about itself

- **NC-19** The first message on a stream is `Hello`, carrying the daemon version, Facts, the
  declared and built-in `node:` labels, the Policy fingerprint and the template-set fingerprint.
  A `PolicySnapshot` follows, carrying whether Raw Exec is enabled, then a `TemplateSnapshot`.
- **NC-20** The self-report is read once per connection: a Policy or label change on the Node
  reaches the registry in the `Hello` after the daemon restarts, and a later `Hello` on the same
  stream is ignored.
- **NC-21** The Relay records each `Hello` field it keeps only in a bounded shape. The Policy fingerprint
  is 64 lowercase hex characters, and the template-set fingerprint the same or `unloadable`.
  The daemon version is semver of at most 253 bytes. Hostname, OS, kernel and architecture are
  at most 253 bytes of visible ASCII. An IP address is a plain address with no zone, and a list
  of more than 256 is dropped whole. A `node:` label is within the bounds
  `selectors-and-labels.md` sets.
- **NC-22** A field that fails its bound is recorded as not reported, or the entry dropped,
  never truncated or rewritten, and the stream stays up. A stored value that fails its bound is
  declined the same way when read back.
- **NC-23** The fingerprints a `PolicySnapshot` or `TemplateSnapshot` carries are bounded when
  the registry serves them on a Node read: one that fails the `Hello` bound is served empty.
- **NC-24** A self-reported label that is not `node:` is dropped. Nothing a Node reports writes
  `relay:` or `tag:` labels, Policy, or any part of its registry record beyond the self-reported
  fields (invariant 7; R3, R51).
- **NC-25** Each connect replaces the self-reported fields of the Node's registry record. Facts
  and `node:` label changes are recorded and never audited.
- **NC-33** Between two connects of the same Node, a change in the reported Policy fingerprint
  or in whether Raw Exec is enabled writes one audit record with the before and after values. A
  Node's first connect writes none, and the record blocks nothing.
- **NC-39** The change records of NC-33, NC-34 and NC-35 are limited per Node and per kind:
  while the Relay runs, at most one record per 10 minutes, carrying the number of changes since
  the previous record of that kind, so a single change is recorded at once and a Node that keeps
  changing its report, or two parties sharing one certificate, write a bounded number of records
  (R51, R54).

### Daemon versions

- **NC-26** A daemon's version never refuses its connection: an older daemon connects and is
  flagged `outdated` in the registry, and the minimum-version gate refuses it at dispatch
  (`execution.md`; invariant 14).
- **NC-27** No Node-plane message installs, upgrades or replaces a binary (invariant 14).
- **NC-34** Between two connects of the same Node, a change in the reported daemon version
  writes one audit record with the before and after versions, marked as a downgrade when the
  new version is lower. The record blocks nothing.

## Refusals

- **NC-28** The Relay refuses a connection whose client certificate does not chain to its CA, or
  names a revoked Node, during the TLS handshake, before any stream opens. It checks revocation
  again before each call runs.
- **NC-29** A Node-plane call other than `Enroll` without a verified client certificate is
  refused as unauthenticated before its handler runs.
- **NC-30** Against a Relay whose certificate does not chain to the pinned CA, the daemon sends
  nothing, `Hello` included, and retries on its backoff.
- **NC-31** An expired client certificate is refused at the handshake like any other unverified
  one. The daemon keeps retrying and cannot succeed; only enrolling again, which issues a new
  Node ID (`enrollment.md`), brings the Node back.
- **NC-32** A stream whose first message is not `Hello` is refused as an invalid argument.

Stream replacement is not a refusal: with execution on, the older stream ends because a newer
one exists (NC-13).

## Out of scope

- **Issuing, renewing and revoking certificates, the join string, the first-contact pin and the
  address the daemon dials**: `enrollment.md`.
- **What a Task is, its outcomes, the minimum-version gate's refusal and cancellation**:
  `execution.md`.
- **The `state:` markers derived from connection facts** (`offline`, `outdated`,
  `cert-expiring`, `raw-exec-enabled`): `selectors-and-labels.md`.
- **What the Policy fingerprint means**: `policy.md`.
- **How registry state and audit records read on each surface**: `query.md` and
  `audit-and-read-lane.md`.
- **Installing the relay-daemon and its dedup markers**: `daemon-installation.md`. **Where the
  certificate hostname and minimum daemon version are set**: `relay-configuration.md`.
  **Metrics, including the server certificate's remaining lifetime**: `observability.md`.
- **How control-plane callers authenticate**: `accounts-and-access.md`.
- **Refusing a daemon too old to speak the protocol at connect**: cut. Compatibility across
  daemon versions is the minimum-version gate (ADR-0014) and an additive `/proto`.
- **A Task acknowledgement deadline and admission pacing**:
  `roadmap: relay/fast-failure-and-fleet-admission`.
- **A self-report without reconnecting**: `roadmap: relay/policy-catalog-and-live-reload`.
- **A company-issued certificate**: `roadmap: relay/bring-your-own-pki`.
- **The Node plane's scale contract**, which nothing measures yet:
  `roadmap: relay/research/spec-future-work/node-connection`.
- **Several Relays sharing a fleet**: deferred by ADR-0005 to a future ADR.

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
| NC-20 | `TestE2E_PolicyChangeReachesTheRegistryOnlyAfterTheDaemonRestarts`, `TestTunnelOpen_ALaterHelloOrPolicySnapshotOnTheSameStreamChangesNoRegistryField` | Relay |
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
