# Relay configuration

**Status:** designed, not built, as of `2026-10-30`.
**Claim prefix:** `RC`
**Governed by:** ADR-0043, ADR-0010, ADR-0033, ADR-0030, ADR-0047, ADR-0052, ADR-0027, ADR-0024,
ADR-0023, ADR-0014, ADR-0004, ADR-0012, ADR-0009, ADR-0021; invariants 5, 10, 11, 14.

## Purpose

Relay configuration is what a Relay host's administrator fixes about it: where it listens, which
CA it signs with, which identity provider it believes, how far one dispatch may reach, and which
dispatches wait for a human. All of it lives in one configuration file that the Relay reads
itself, and nothing Relay runs or accepts can write that file. Part of it is the security floor,
which decides who may authenticate and how recently they proved it. The rest bounds reach, like
the blast caps. Values nobody needs to tune are built in. A change is an edit to the file, then
a reload or restart. The Relay installs from an OS package or as a container image.

## Surfaces

| Surface | Access to the capability |
|---|---|
| **The host** | Every setting, in one configuration file (RC-12): the security floor and the reach settings alike. A reload re-reads it (RC-21) |
| **Admin Console** | None: no screen reads or changes a setting |
| **Control API** | No configuration write route exists (RC-11) |
| **MCP** | No configuration write tool exists (RC-11) |
| **The `relay` binary's local subcommands** | `relay init` (RC-28): first-boot acts that exist only because no credential can yet exist to perform them over the wire (ADR-0030) |
| **Install** | The OS package, which is the quickstart path (RC-23 to RC-26, RC-45), and the container image with its deployment stack (RC-7, RC-27) |

## Behaviour

- **RC-4** With no optional setting given, the Relay comes up with the gRPC listener only: no
  control plane, no Console, no OAuth and no approval notification.
- **RC-37** Gate rules are a section of the configuration file, checked, read and reloaded with it (RC-15, RC-16, RC-21), so whoever administers the Relay's host sets them and nothing on the wire can (ADR-0047). The separate gate-rules file goes, and with it its own load checks; a configuration naming `approval.gate_rules_path` is refused at start and on reload, naming the key. What the rules ship as is `approval.md`.
- **RC-48** The approval webhook secret file is opened without following a symlink, checked on
  that descriptor and read from it; a directory is refused.
- **RC-6** The shipped systemd unit runs the Relay as an unprivileged Unix account with an empty
  capability set and a read-only filesystem outside its state directory.
- **RC-7** The release publishes a Relay container image to the registry, signed keylessly at its
  digest, running as an unprivileged uid; the deployment stack pins it by digest and runs it with a
  read-only root filesystem, every capability dropped and one durable volume.
- **RC-12** Every setting lives in one TOML configuration file the Relay reads itself:
  `/etc/relay/relay.toml` by default, or the path one command-line flag, `--config`, names. That
  path is the only configuration the Relay accepts from outside the file; the binary otherwise
  accepts `--version`, `--help` and its subcommands (ADR-0043).
- **RC-13** No setting is read from the environment or the command line. A `RELAY_*` variable
  for a setting found in the environment refuses start and names that setting's place in the
  file.
- **RC-14** A secret never passes through the environment or the command line (invariant 11). It
  is read from the configuration file, inline or from a file the configuration names for
  material another tool manages and rotates, as each setting allows.
- **RC-20** A configuration that cannot work is refused at start: the Console enabled without
  the control plane, or OAuth settings without an issuer. One that is coherent but probably a
  mistake, such as a mutate cap above the read cap, starts with a prominent warning.
- **RC-21** `SIGHUP` re-reads the configuration file from the path given at start and applies
  RC-15 before anything else. The reload is all-or-nothing: an invalid value, or a changed
  bind-time setting, refuses the whole reload, logs the setting and that a restart is required,
  and leaves the running configuration untouched. The bind-time settings are the listen
  addresses, the advertised address (RC-36), the CA directory, the store path, the certificate
  hostname and its extra names (RC-47), whether the control plane and Admin Console are enabled, and the OAuth identity
  provider. A failed reload never exits the process. Every reload is audited, attributed to the
  Relay's host rather than to any Account, the way the Freeze signal's host lever is, listing
  what changed.
- **RC-22** The read and mutate blast caps, the minimum daemon version, the Node cap and the log
  level are values in the configuration file, validated like every other value, with built-in
  defaults where absent.
- **RC-38** Enrollment rate limiting is built in, not configured: the per-source and global
  limits, their bursts and the tracked-address ceiling are constants, at the values
  `enrollment.md` sets.
- **RC-39** `state:cert-expiring` uses a built-in fraction: it holds for a Node whose certificate
  has less than a quarter of its lifetime left (`selectors-and-labels.md`).
- **RC-40** The dispatch concurrency is built in at 16. A `mutate` Job is sent 16 Tasks at a time,
  which bounds how much of it is already sent when it stops on a failure (`execution.md`).
- **RC-41** The approval webhook URL and its secret are each read only from a file the
  configuration names; neither may be written inline. The webhook's request timeout is built in.
- **RC-42** The Relay's logs are always JSON. The log level stays a setting (RC-22).
- **RC-43** A Console session's maximum age is built in at 12 hours and the step-up window at 5
  minutes. The Console session's idle timeout stays a setting.
- **RC-27** The Relay container image takes its configuration file, and any secret files it
  names, as a read-only mount: nothing about the floor is in the container's environment, so
  inspecting the container shows a mount path, not settings or secrets. The deployment stack
  runs it unprivileged, with no capabilities, a read-only root filesystem, and the CA and store
  on one durable volume. Its documentation calls it production only once a
  human hardening review of that deployment has closed (ADR-0033).
- **RC-28** `relay init`, run in a terminal on the Relay's host, creates the first admin: on a
  store holding no human Account it creates one human `admin` Account with the name the operator
  gives it, sets that Account's Console password from a prompt with no echo, and mints its first
  API Token once. No Account name is reserved, since nothing about the first admin is fixed. With
  any human Account present, `init` creates nothing and emits no secret, and a re-run reports
  state. An explicit recovery request names an enabled human `admin` and re-mints that Account's
  API Token, audited, refusing a disabled or non-admin Account; this takes over
  `bootstrap-token`'s recovery role in `accounts-and-access.md`. `init` replaces
  `relay bootstrap-token` and `relay console-password` (ADR-0030). Its other first-boot acts in
  ADR-0030, a first Enrollment Token and how it is shown, are `enrollment.md`'s.
- **RC-36** An optional advertised address names the address Nodes are told to dial, which is
  the address a join string carries, when it differs from the gRPC listen address, as behind a
  container port mapping. Unset, the join string carries the certificate hostname and the gRPC
  listen port.
- **RC-46** The one server certificate names `tls.hostname` (an IP SAN when it is an address),
  loopback, up to 64 detected unicast interface addresses (IPv4 first; loopback, link-local,
  multicast and unspecified excluded), the advertised address's host (RC-36), and every entry of
  `[tls] extra_names`. A join string never carries a host the certificate does not name.
- **RC-47** `[tls] extra_names` is a bind-time list of at most 32 DNS names and IP addresses. An
  entry that is malformed or a wildcard refuses start, naming the entry, and a reload that
  changes the list is refused as RC-21 says.

## Refusals

- **RC-9** At start the Relay refuses a webhook secret file, naming why, if a mode bit or
  access-control list lets it or one of its Unix groups write the file, or lets any account read
  it but root, the Relay and the group the Relay runs as. That group holds only the Relay unless
  an operator adds an account to it (ADR-0043).
- **RC-10** OAuth configured with an issuer but without an audience or a public URL refuses
  start.
- **RC-11** No MCP tool and no Control API route writes any configuration, and none may be
  added. There is no endpoint to refuse it.
- **RC-44** A key the configuration file no longer accepts refuses start, and refuses a reload,
  naming the key and never its value. The removed keys are `enrollment.ip_rate_per_minute`,
  `enrollment.ip_burst`, `enrollment.global_rate_per_minute`, `enrollment.global_burst`,
  `enrollment.max_tracked_ips`, `enrollment.cert_expiring_fraction`, `reach.dispatch_concurrency`,
  `approval.webhook_timeout`, `approval.webhook_url`, `approval.webhook_secret`, `log.format`,
  `console.session_max_age` and `console.step_up_window`.
- **RC-53** Gate rules are written only as `[[approval.rules]]` sections; any other spelling of
  `approval.rules`, an inline array, a single table or a variant-case key, is refused at load,
  naming the key.
- **RC-54** A key that differs from a key the Relay accepts only in letter case (`TLS.hostname`
  for `tls.hostname`) is refused at start and on reload, and so is a file that spells one key two
  such ways. The refusal names the key as written and never its value (RC-18). Extends RC-53.

## Designed, not built

| Claim | Statement | Milestone |
|---|---|---|
| RC-15 | At start and on every reload the Relay refuses to run if it could write its configuration file or any file the configuration names, or if any account but it and root could read the configuration file or any file holding a secret. It could write a file when it owns the file on a filesystem mounted writable, when a mode bit or access-control list grants it or one of its groups write, when any directory on the file's resolved path is owned by or writable by it, or when it runs as root or holds any capability (ADR-0043). | MVP |
| RC-16 | Each file the check covers is opened without following a symlink, checked on that descriptor and read from it, so nothing can change between the check and the read; a path that is a symlink is refused. | MVP |
| RC-17 | Everything the Relay generates, its CA private key and its store, lives in its state directory, owned by the Relay's uid. The Relay refuses to start if that directory or the key is readable by any other account. | MVP |
| RC-18 | No secret value, inline or in a file, and no approval webhook URL, appears on any surface, in any log or audit record, or in any refusal message. A parse or validation error names the key and the line, never the value; a reload's audit record names a changed secret setting, never its value. | MVP |
| RC-19 | The CA directory, store path and certificate hostname have no defaults: unset is a refusal naming the setting. Every value is validated at start and at reload, and an invalid one is a refusal naming the setting, never a warning and a fallback to a default. A missing or unreadable configuration file is a refusal. | MVP |
| RC-23 | The release publishes the Relay as `.deb` and `.rpm` packages for each architecture, on the platforms and under the platform list and CI rule `daemon-installation.md` sets for its own packages. The edited configuration an upgrade must preserve is the configuration file. A package wraps the release's guarded binary byte for byte, is reproducible, built twice and compared, is listed in the release `SHA256SUMS`, and carries no signature of its own before v1.0.0. | MVP |
| RC-24 | The Relay package installs the Relay's Unix account, the binary, the hardened unit, the configuration file and the state directory, and prints a configuration guide that carries no secret and names `relay init` (RC-28), also installed as documentation. It enables the Relay on a first install only, only where systemd is running, honouring the distribution's presets, and an upgrade never changes enablement. It never starts the Relay and never runs the first-boot command. The guide says never to capture an image of the host after the Relay has first started, since the CA private key would travel with it. | MVP |
| RC-25 | The Relay package writes the configuration file once, at first install, only if none exists, and never again: the host's fully qualified name as the certificate hostname, the CA directory and store path inside the state directory, the control plane and Admin Console enabled, and the control-plane listener bound to loopback. The file is generated, not package-owned configuration, so no upgrade rewrites it. | MVP |
| RC-26 | Removing the Relay package keeps configuration and state. `apt purge` removes configuration and moves the CA and the store aside together, re-owned by root and readable by nobody else, and prints where; it never deletes them, never splits them, and never deletes the Relay's Unix account. Purge deletes only paths the package itself created. `.rpm` removal never deletes state and prints the paths to delete by hand. | MVP |
| RC-34 | Per-Account Console preferences are stored per Account, not fleet-wide. | After MVP |
| RC-45 | The quickstart installs the Relay from its OS package. The container image with its deployment stack (RC-7, RC-27) stays a supported install, as built. | MVP |

## Out of scope

- **The founding admin Account, Token minting, step-up and OAuth session semantics:**
  `accounts-and-access.md`. This spec owns only where their bounds are set.
- **Enrollment Tokens, join strings and what the rate limits refuse:** `enrollment.md`.
- **What the blast caps, approval gates, stop on failure and Freeze do:** `execution.md`,
  `approval.md`, `freeze.md`.
- **Configuring the relay-daemon on a Node,** which is flags and environment from the
  customer's config management: `daemon-installation.md`.
- **Relay's own health, metrics and logs:** `observability.md`. A separate metrics listener
  waits in roadmap: relay/opentelemetry.
- **Rotating CA or TLS material,** which is an operation rather than a setting.
- **Settings in the Console.** Store-backed operator settings, Console screens that read and
  change them, reading them over MCP and the Control API, and configuration history wait in
  roadmap: relay/settings-in-the-console. Live reload of TLS material waits there too.
- **Residual risk:** the threat model's register, R34 (a purged host keeps its CA private key).
  R35 is closed by RC-27. R15 is closed while reach settings stay in the file, and returns if
  they move into the Console.

## Proof

Generated by `make spec-proof` from the tests that name the claim they prove.

<!-- proof:begin -->
| Claim | Proven by | Seam |
|---|---|---|
| RC-4 | `TestNewServer_MinimalConfigIsGRPCOnly` | Relay |
| RC-6 | `TestRelayUnit_UnprivilegedNoCapsReadOnly` | Relay |
| RC-9 | `TestSecretFilePermissionsAreEnforced` | approvalnotify |
| RC-10 | `TestValidate_OAuthIssuerNeedsAudienceAndPublicURL` | relayconfig |
| RC-11 | `TestDeps_HasNoConfigField`, `TestMuxRegistrationsAreTheKnownSites`, `TestNoRouteWritesConfiguration`, `TestNoToolWritesConfiguration` | API, MCP, Relay |
| RC-12 | `TestMain_ConfigFlagHonoured`, `TestMain_OtherFlagsRefused`, `TestParseArgs` | Relay |
| RC-13 | `TestFreezeReleaseReason_IsTheOnlyEnvironmentRead`, `TestMain_OtherFlagsRefused`, `TestMain_RetiredEnvNameRefusesNamingKey`, `TestRefuseRetiredEnv_NamesKeyNotValue`, `TestRetiredEnvMap_CoversEveryRetiredName` | Relay, relayconfig |
| RC-14 | `TestLoadConfig_FileSecretsResolved`, `TestMain_OtherFlagsRefused`, `TestMain_RetiredEnvNameRefusesNamingKey`, `TestSecret_FileLoad`, `TestStartupLog_CarriesNoWebhookURLOrSecret` | Relay, relayconfig |
| RC-20 | `TestMain_CoherentButSuspectConfigStartsWithWarning`, `TestValidate_ConsoleWithoutControlPlaneRefused`, `TestValidate_MutateCapAboveReadCapWarns`, `TestValidate_OAuthWithoutIssuerRefused` | Relay, relayconfig |
| RC-21 | `TestCapability_ReadsReachSettingsPerRequest`, `TestReload_BindTimeChangeRefusedRestartRequired`, `TestReload_FailedReloadProcessSurvives`, `TestReload_InvalidValueRefusedConfigIntact`, `TestReload_RechecksFileFirst`, `TestReload_ValidChangeAppliedAndAudited` | Relay, capability |
| RC-22 | `TestDefaults_EachReachValueWhenAbsent`, `TestEveryKeyReachesConfig`, `TestFromFile_CarriesEverySetting`, `TestNewLogHandler_JSONAtConfiguredLevel`, `TestValidate_InvalidValueRefusedNamingSetting` | Relay, relayconfig |
| RC-28 | `TestInit_CreatesNamedAdminAndMintsOnce`, `TestInit_NoReservedName`, `TestInit_RecoverReMintsAndAudits`, `TestInit_RecoverRefusesDisabledOrNonAdmin`, `TestInit_RefusesAbsentStore`, `TestInit_RefusesRoot`, `TestInit_RefusesWhenAHumanAccountExists`, `TestInit_RerunEmitsNothing`, `TestInit_TTLAppliesToTheFirstAndTheRecoveredToken`, `TestNewServer_ControlEnabled_SeedsNoAccount`, `TestReadNoEcho_ThePasswordIsNotEchoedAndEchoIsRestored` | Relay |
| RC-36 | `TestMintEnrollmentToken_JoinStringUsesAdvertisedAddress` | Relay |
| RC-37 | `TestLoad_GateRulesOnlyAsArrayTables`, `TestLoad_GateRulesPathRefusedNamingKey`, `TestReloader_GateRulesPathRefusedNamingKey`, `TestStart_RefusesGateRulesPath`, `TestValidate_GateRuleValuesRefusedNamingField` | Relay, relayconfig |
| RC-38 | `TestFromFile_EnrollmentRateLimitsAreBuiltIn` | Relay |
| RC-39 | `TestFromFile_CertExpiringFractionIsAQuarter` | Relay |
| RC-40 | `TestFromFile_DispatchConcurrencyIsSixteen` | Relay |
| RC-41 | `TestFromFile_WebhookTimeoutIsBuiltIn`, `TestValidate_WebhookURLAndSecretOnlyFromFiles` | Relay, relayconfig |
| RC-42 | `TestNewLogHandler_JSONAtConfiguredLevel` | Relay |
| RC-43 | `TestFromFile_ConsoleWindowsAreBuiltIn` | Relay |
| RC-44 | `TestLoad_RemovedKeyRefusedNamingKey`, `TestReloader_RemovedKeyRefusedNamingKey` | Relay, relayconfig |
| RC-46 | `TestServerCertificateNames`, `TestServerCertificate_NamesEveryHostAJoinStringCarries` | Relay |
| RC-47 | `TestDiff_ExtraNamesChangeIsRestartRequired`, `TestReloader_ExtraNamesChangeRefusedRestartRequired`, `TestValidate_ExtraNamesCappedAt32`, `TestValidate_ExtraNamesEachEntryChecked` | Relay, relayconfig |
| RC-48 | `TestGather_DecisionAndReadShareDescriptor`, `TestSecretFilePermissionsAreEnforced`, `TestSecretRule_RefusesADirectory` | approvalnotify, hostfile |
| RC-54 | `TestLoad_CaseVariantKeyRefusedInEverySection`, `TestLoad_KeySpelledTwoWaysRefused`, `TestReloader_CaseVariantKeyRefusedNamingKey`, `TestStart_RefusesCaseVariantKey` | Relay, relayconfig |

Unproven: RC-7, RC-27, RC-53.
Designed claims a test already cites: RC-15 (`TestDecide_Table`, `TestInit_RefusesRoot`, `TestStart_RefusesConfigWritableByRelay`, `TestStart_RefusesSecretReadableByOthers`); RC-16 (`TestStart_RefusesSymlinkedConfig`); RC-17 (`TestCA_RefusesGroupReadableKeyOrDirectory`, `TestStart_RefusesGroupReadableStateOrKey`); RC-18 (`TestNewGate_RefusalNamesNoRuleNameOrValue`, `TestRefusals_CarryNoSecretOrWebhookURL`, `TestReload_AuditNamesSecretKeyNotValue`, `TestValidate_GateRuleValuesRefusedNamingField`); RC-19 (`TestPackagedRelayTOML_WithoutFQDNRefusesNamingTLSHostname`); RC-23 (`release_attaches_every_package_and_its_sbom_under_sha256sums`, `release_packages_are_built_twice_compared_wrap_the_binary_and_carry_no_signature`, `release_publishes_nothing_unless_the_install_matrix_passes_on_its_packages`, `release_signs_and_tests_only_the_sha256sums_the_comparing_job_wrote`); RC-25 (`TestPackagedRelayTOML_FirstInstallSettings`, `TestPackagedRelayTOML_WithoutFQDNRefusesNamingTLSHostname`).
<!-- proof:end -->

## Retired

- **RC-5**, **RC-8**, **RC-35**, **RC-49** — `2026-10-29` — the approval-gate rules file, its
  load checks and its configured path; replaced by RC-37.
- **RC-50** — `2026-10-28` — the `state:cert-expiring` fraction was a configuration value;
  replaced by RC-39.
- **RC-51** — `2026-10-28` — the enrollment rate limits, bursts and tracked-IP ceiling were
  configuration values; replaced by RC-38.
- **RC-52** — `2026-10-28` — the log format was a configuration value; replaced by RC-42.
- **RC-1** — `2026-10-21` — the `bootstrap-token` and `console-password` subcommands are
  replaced by `relay init` (ADR-0030); RC-28 carries the first admin and its recovery.
- **RC-2** — `2026-10-18` — settings from flags and `RELAY_*` variables are replaced by one
  configuration file (ADR-0043); RC-12 and RC-13 carry the rule.
- **RC-3** — `2026-10-18` — the example environment file is replaced by the example
  configuration file, with its own drift test.
- **RC-29**, **RC-31**, **RC-32**, **RC-33** — `2026-10-23` — retired unbuilt: the
  configuration file is the one source of every setting for the MVP. Store-backed operator
  settings, their reads over MCP and the Control API, and the Console's settings screens wait in
  roadmap: relay/settings-in-the-console.
- **RC-30** — `2026-10-23` — retired unbuilt with RC-29; a key the file no longer accepts is
  refused by RC-44.
