# Daemon installation

**Status:** designed, not built, as of `2026-10-26`.
**Claim prefix:** `DI`
**Governed by:** ADR-0014, ADR-0002, ADR-0033, ADR-0021, ADR-0022, ADR-0031, ADR-0036,
ADR-0048, ADR-0053; invariants 2, 4, 14.

## Purpose

A Node joins the fleet only after something installs the relay-daemon on it. At fleet scale that
is the customer's config management, never a person and never the Relay. This capability covers
what config management is handed and what it does with it: the release artifacts and package,
the verified install, the local files the daemon reads, the hardened unit, upgrades, and taking a
Node back out.

The per-Node install is the product's biggest adoption cost and the reason it can be trusted. The
daemon is where deny-by-default Policy lives, where at-most-once is enforced, and where the
Relay's authority stops. So installation is the customer's act, done with tools they already run,
from artifacts they can verify before running them.

## Surfaces

| Surface | What it does |
|---|---|
| **Release artifacts** | The statically linked `relay-daemon` binary for each architecture under the release `SHA256SUMS` (DI-1). Packages are designed (DI-24), and the read Template catalog ships inside the daemon package (DI-29). The Ansible role (DI-45) ships beside them; the customer's config management runs it, and the Relay never does (DI-18). |
| **The customer's config management** | The only installer, configurer and upgrader. |
| **relay-daemon subcommands** | `--version`, `policy check` (`policy.md`), `dump-operation-schema` (`operations-and-templates.md`); `join` is the act that enrolls (DI-42). No other subcommand contacts a Relay. |
| **Relay, MCP, Control API, Console** | Nothing. The Relay never installs, configures or upgrades a daemon, and its only lever over versions is the dispatch-level minimum-version gate. The absence is invariant 14, not a gap (DI-18). |

## Behaviour

### What is released and installed

- **DI-1** The release publishes the relay-daemon as a statically linked binary for `x86_64` and
  `aarch64`, built twice from different paths and refused unless the two builds are
  byte-identical, and listed in the release `SHA256SUMS`, which is signed keylessly.
- **DI-2** No daemon container image is published: a component whose job is to hold the host's
  own authority is not delivered as a container.
- **DI-3** The shipped systemd unit runs the daemon as root, with its capability bounding set
  limited to `CAP_DAC_READ_SEARCH` and the system directories (`/usr`, `/etc`, `/boot`) read-only,
  so even a compromised daemon cannot rewrite its own Policy or Templates, install packages, or
  write outside its state directory.

The unit's syscall filter is still checked by hand on a real systemd host. No package carrying the
unit ships until that check is done.

- **DI-5** Relaxing that sandbox is a drop-in the operator places, documented and never shipped,
  so a Node that may install packages or write elsewhere is one whose operator chose it, visibly,
  in a file on that Node.
- **DI-6** The shipped default Policy permits read Operations behind a confidentiality deny-list,
  every Template of the shipped read catalog included, `log.tail` among them. It allows no
  `mutate` Operation and does not enable Raw Exec (ADR-0022, ADR-0021, ADR-0053).
- **DI-28** Of the daemon's own files, the shipped default Policy denies reading and checksumming
  only those that carry a secret: the Node's identity private key and the environment file, with
  the daemon's environment oracle beside them. It does not deny its Policy, CA bundle, identity
  certificate, binary, unit, override unit, drop-ins or the shipped catalog's Template files: none
  holds a secret, and most are public or already in the Relay's hands. An operator-authored
  Template file is readable under the wildcard and recorded as R37, never a lint finding.
  `relay-daemon policy check --strict` passes on the shipped default with the shipped catalog's
  template root supplied (`--templates`); with no template root supplied, the default's allows for
  the catalog's names are unknown-name findings `--strict` fails, as ADR-0021 decides (ADR-0022).
- **DI-39** The self-reference lint probes reads (`file.read`, `file.checksum` and any supplied
  path-taking Template Operation) only against the daemon's secret-bearing files: the identity
  private key and the environment file. It probes writes (the Raw Exec shapes: edit in place,
  overwrite, copy or move over, delete, redirect, chmod, symlink) against its whole trust root at
  the packaged paths, each by exact path: the Policy file and the Policy directory, the
  environment file, the state directory's identity key and certificate, CA bundle and persisted
  address, the template root, the binary at `/usr/bin/relay-daemon`, the unit at
  `/usr/lib/systemd/system/relay-daemon.service`, the override unit under `/etc/systemd/system/`
  and the `override.conf` drop-in. The probe of the running binary's own path is a write probe
  only. A finding is proof that the Policy lets the wire reach its own gate; reading a file that
  holds no secret is never a finding (ADR-0021).
- **DI-40** The shipped unit runs the binary from `/usr/bin/relay-daemon`, the one binary path a
  packaged and a hand-built install share (ADR-0033, DI-25).
- **DI-7** The shipped example environment file covers every setting the daemon reads.
- **DI-30** A Template in the read catalog the daemon package ships is bound by name to its body
  and risk class: CI refuses a release that changes either for a released name. The body is the
  Template's parsed definition, its command text and its ordered slot declarations as the
  daemon's own parser reads them, and not the text rendered for its shell or the engine that
  renders it. Withdrawing a released name is allowed.
- **DI-32** The release attaches the standalone unit and example environment file under
  `SHA256SUMS`, byte-equal to the copies inside every daemon package, so a hand-built install,
  documented but not supported, verifies its unit like everything else.

### A fresh Node's configuration

- **DI-9** The daemon reads its declared `node:` Labels from `RELAY_NODE_LABELS` in its
  environment file, once at start: a change takes effect when the unit restarts.
- **DI-43** The daemon is configured by a join string given to `relay-daemon join`: Relay address,
  CA fingerprint and Enrollment Token in one value (ADR-0031). `join` pins the Relay's CA from the
  fingerprint and writes the CA bundle into the state directory, so no CA path is configured by
  hand. The unit start reads no join string: `RELAY_JOIN` is not a setting, the shipped example
  environment file carries no join line, and the environment file holds no secret, so DI-28's deny
  of it and DI-39's probe of it stay as defence in depth and no longer guard a secret. A unit
  start with no persisted identity exits cleanly as DI-25 says.
- **DI-44** The daemon persists the Relay address with its identity at enrollment and uses it on
  every later start; a Relay address set in its environment overrides the persisted one. A Node
  holding an identity with neither refuses to start: there is no default address.
- **DI-42** `relay-daemon join` enrolls in the process that read the join string: it reads the
  string from a prompt or standard input, never from its arguments, pins the Relay's CA from the
  fingerprint, enrolls, persists the identity and the Relay address, and then enables and starts
  the unit. It writes the join string nowhere. On a Node that already holds an identity it changes
  nothing and exits zero, so config management may rerun it; a failed enrollment leaves nothing on
  disk and exits non-zero. `enrollment.md` carries the join string's contract.

### File modes

- **DI-11** The daemon requests file modes and never forces them: the operator's umask is a
  ceiling nothing in Node code widens (ADR-0036).

### Upgrades and restarts

Config management swaps the binary and restarts the unit. The daemon never self-upgrades and the
Relay never pushes a binary (invariant 14).

- **DI-14** On a termination signal the daemon stops accepting new Tasks, lets in-flight work
  finish within a configurable shutdown grace, then exits. A Task still running when the grace
  expires is stopped and ends with `OUTCOME_CANCELLED`, with no `TaskCancel` involved, and is
  never retried: its dedup marker was written before it ran.
- **DI-15** Policy and Templates are loaded once at start: a change to either takes effect when
  the unit restarts, and there is no in-place reload.
- **DI-36** Beside the Policy file, `/etc/relay-daemon/policy.toml`, sits the Policy directory,
  `/etc/relay-daemon/policy.d`, which the install creates empty and never writes into again. The
  daemon composes the Policy file and every fragment in it into one Policy with one Policy
  fingerprint, deny beating allow across all of them, and applies a change when the unit restarts.
  A fragment that is a symlink, not a regular file, or group- or world-writable refuses start, and
  one fragment that cannot be read or parsed leaves the whole Policy deny-all.
- **DI-46** The documented way to change a Node's Policy is three steps: write the fragment, run
  `relay-daemon policy check` over the Policy file and the Policy directory together to validate
  the combined Policy offline, then restart the daemon.
- **DI-16** Dedup markers in the state directory carry at-most-once across a reconnect and a
  restart.
- **DI-17** The Relay refuses to dispatch to a Node below the configured minimum daemon version;
  installation itself permits any version, downgrades included.

## Refusals

- **DI-12** A Policy or Template file that is group- or world-writable is refused at load: its
  rules never take effect.
- **DI-13** A umask that leaves the state directory unusable fails the Task before it runs, so no
  Task ever runs unrecorded; dedup markers are written no wider than owner read and write.
- **DI-18** No Relay surface (MCP, the Control API, the Console or the Node transport) installs,
  configures or upgrades a daemon. There is no such path to refuse.
- **DI-19** The daemon refuses to start if its identity or its dedup store cannot be opened.
- **DI-20** An unreadable Policy file, or a missing one with no fragment beside it, leaves the
  daemon running with a deny-all Policy: every Task is denied rather than the daemon refusing to
  start. A missing Policy file beside one or more fragments composes the fragments alone (DI-36).
- **DI-21** A revoked Node that keeps dialling is refused at the transport; the Relay never
  reaches back to stop it.
- **DI-23** A revoked Node's dial attempt is recorded in the audit trail, not only refused: the
  first refused dial is recorded, then at most one record per Node per hour, so a revoked Node
  that keeps dialling cannot flood the trail.

## Designed, not built

| Claim | Statement | Milestone |
|---|---|---|
| DI-24 | The release publishes the daemon as `.deb` and `.rpm` packages for each architecture. A package wraps the release's guarded binary byte for byte (packaging compiles, strips and rewrites nothing), is itself reproducible, built twice and compared, and is listed in the release `SHA256SUMS`. Packages carry no signature of their own before v1.0.0. | v0.6.5 — Install Path: relay init, join string, packages |
| DI-25 | The daemon package installs the binary at `/usr/bin/relay-daemon` and the hardened unit as a system unit, and never starts the daemon. It enables the unit on a first install only, only where systemd is running, honouring the distribution's presets; an upgrade never changes whether it is enabled. An enabled unit on a Node that holds no persisted identity stays inactive at boot without failing or retrying; it starts at the next boot after an identity is present, or when `relay-daemon join` (DI-42) or config management starts it. Nothing watches for an identity to appear. | v0.6.5 — Install Path: relay init, join string, packages |
| DI-26 | The daemon package places the shipped default Policy as the live Policy only on a first install, only if no Policy file exists and no Policy directory existed before the install began; never on an upgrade or a reinstall. On `.rpm` platforms, where a reinstall after removal is indistinguishable from a first install, those absence checks are the whole guard. No install, upgrade or remove rewrites or re-creates the live Policy. | v0.6.5 — Install Path: relay init, join string, packages |
| DI-27 | The daemon package places the environment file on a first install only, if none exists, owned by root and mode `0600`, and never rewrites it. | v0.6.5 — Install Path: relay init, join string, packages |
| DI-29 | The daemon package carries the shipped read Template catalog (`proc.list`, `service.status`, `disk.usage`, `net.listening`, `pkg.inventory`, `log.tail`, `file.checksum`) as package-owned files: replaced on upgrade, removed with the package, and never installed as configuration the package manager would preserve. There is no separate catalog package (ADR-0053, ADR-0021). | v0.6.5 — Install Path: relay init, join string, packages |
| DI-31 | Removing the daemon package removes the binary, the unit and the shipped catalog's Templates, and leaves the Policy, the Policy directory, the environment file and the state directory. `apt purge` removes everything the package created, the Node's identity included; `.rpm` removal never deletes state and prints the paths to delete by hand. Purge deletes only paths the package itself created, never a path read from an operator-edited file. | v0.6.5 — Install Path: relay init, join string, packages |
| DI-33 | A platform is supported only where CI installs the package, upgrades it over the operator's edited configuration and finds the edit intact, and removes it: Ubuntu 24.04 LTS and 26.04 LTS; Debian 13; RHEL-compatible 10, tested on Rocky Linux 10; Amazon Linux 2023. Each is supported on `x86_64` and `aarch64`. A platform whose package manager refuses an unsigned local package by default is not supported. This list also governs the Relay packages (`relay-configuration.md`). | v0.6.5 — Install Path: relay init, join string, packages |
| DI-45 | Each release attaches an Ansible role, listed in `SHA256SUMS` and installed by download, verify, install like every release artifact, that installs that release's daemon package and passes a join string from the operator's vault to `relay-daemon join` on standard input. It writes the string to no file, no command line and no log on the Node, the module arguments Ansible would otherwise log or stage there included, places no Policy fragment, and changes nothing on an enrolled Node (DI-42; ADR-0048). | MVP |
| DI-47 | The release's Ansible role restarts the daemon when a Policy fragment changes: a task that writes a fragment notifies the role's restart handler. The role itself still places no fragment (DI-45). | MVP |

## Out of scope

- **Residual risk:** the threat model's register, R16 and R36 (a join string on disk, closed by
  DI-42 and DI-43, with a residual on Nodes configured before them), R37, R38 and R40.

## Proof

Generated by `make spec-proof` from the tests that name the claim they prove.

<!-- proof:begin -->
| Claim | Proven by | Seam |
|---|---|---|
| DI-7 | `env_example_covers_the_config_surface`, `exemptions_are_real` | daemon |
| DI-9 | `parse_labels_skips_empty_and_garbage` | daemon |
| DI-12 | `group_or_world_writable_file_is_refused`, `loader_accepts_secure_modes`, `loader_rejects_group_or_world_writable`, `secure_modes_are_accepted` | daemon |
| DI-13 | `marker_permissions_are_restrictive`, `umask_tightened_dedup_directory_never_executes_unrecorded` | daemon |
| DI-14 | `drain_grace_expiry_kills_remaining` | daemon |
| DI-16 | `dedup_survives_reconnect_reload` | daemon |
| DI-17 | `TestMCP_RunOperation_OutdatedNodeVersionRefused` | MCP |
| DI-20 | `a_missing_policy_file_beside_fragments_composes_the_fragments_alone`, `a_missing_policy_file_beside_fragments_loads_the_fragments_alone`, `a_missing_policy_file_with_a_refused_fragment_refuses_start`, `a_missing_policy_file_with_no_fragment_is_deny_all`, `an_unreadable_policy_file_beside_fragments_is_deny_all` | daemon |
| DI-21 | `TestRevokedNode_DialAuditedThenThrottled`, `TestRevokedNode_RefusedAfterRestart` | Relay |
| DI-23 | `TestRevokedNode_DialAuditedThenThrottled`, `TestServerCredentials_ReportsRevokedBeforeRefusing` | Node plane, Relay |
| DI-28 | `default_policy_denies_only_secret_bearing_own_files`, `default_policy_passes_strict_with_catalog`, `deny_list_mirrors_adr_0022_exactly` | daemon |
| DI-30 | `catalog_names_match_ledger`, `ledger_check_accepts_a_withdrawn_name_absent_from_the_catalog`, `ledger_check_refuses_a_changed_body`, `ledger_check_refuses_a_changed_risk_class`, `ledger_check_refuses_a_withdrawn_name_back_in_the_catalog` | daemon |
| DI-36 | `a_broken_fragment_is_named_in_the_error`, `a_fragment_change_applies_at_the_next_load`, `a_group_or_world_writable_fragment_refuses_start`, `a_mistyped_table_in_a_fragment_cannot_leave_the_base_allow_active`, `a_non_regular_fragment_refuses_start`, `a_safe_fragment_with_a_non_utf8_name_is_a_deny_all_error`, `a_symlink_or_insecure_fragment_with_a_non_utf8_name_still_refuses_start`, `a_symlinked_fragment_refuses_start`, `a_symlinked_policy_fragment_refuses_start`, `an_absent_or_empty_policy_directory_loads_as_today`, `an_empty_fragment_set_keeps_the_raw_bytes_fingerprint`, `an_unreadable_or_unparsable_fragment_is_a_deny_all_error`, `deny_in_any_file_beats_allow_in_any_other`, `fragments_compose_into_one_policy_with_one_fingerprint`, `install_creates_the_policy_directory_empty_and_never_writes_into_it`, `load_policy_composes_the_policy_directory`, `startup_policy_falls_back_to_deny_all_on_a_broken_fragment`, `startup_policy_is_deny_all_when_a_fragment_has_an_unknown_key`, `startup_policy_refuses_start_on_a_refused_fragment` | daemon |
| DI-39 | `checksum_is_probed_without_templates`, `current_exe_is_a_write_probe_only`, `exe_equal_to_a_packaged_path_is_not_duplicated`, `lint_read_probes_stop_at_secrets`, `lint_write_probes_cover_packaged_trust_root` | daemon |
| DI-40 | `unit_execstart_is_usr_bin` | daemon |
| DI-42 | `TestCrossBinary_JoinStringEnrolls`, `a_join_that_lost_the_race_finds_the_identity_and_changes_nothing`, `a_second_join_is_refused_while_the_first_holds_the_state_dir`, `conclude_never_starts_the_unit_otherwise`, `env_file_and_unit_match_the_packaged_unit`, `join_enrolls_in_process_and_persists_identity`, `join_lets_the_environment_govern_without_an_env_file`, `join_on_an_enrolled_node_changes_nothing_and_exits_zero`, `join_pin_mismatch_sends_no_token_and_leaves_nothing_on_disk`, `join_refuses_a_disagreeing_environment_before_reading`, `join_refuses_argv_join_string`, `join_spawn_argv_is_the_literal_constant`, `join_starts_the_unit_once_and_only_after_the_identity_is_persisted`, `production_and_test_suppressions_are_pinned_apart`, `spawn_family_appears_only_at_the_sanctioned_sites`, `unit_starts_only_for_the_units_state_dir_under_systemd` | Relay, daemon |
| DI-43 | `TestCrossBinary_JoinStringEnrolls`, `TestCrossBinary_RestartWithoutJoinOrAddrUsesPersistedState`, `ca_bundle_mismatch_refused`, `env_example_has_no_join_line`, `join_enrolls_in_process_and_persists_identity`, `join_pin_mismatch_sends_no_token_and_leaves_nothing_on_disk`, `join_refuses_relay_join_before_reading`, `pin_match_enrolls`, `pin_mismatch_sends_no_token`, `relay_join_is_refused_by_name`, `retired_settings_refused_by_name` | Relay, daemon |
| DI-44 | `TestCrossBinary_RestartWithoutJoinOrAddrUsesPersistedState`, `identity_without_address_exits_nonzero`, `persisted_address_written_at_enrollment`, `relay_addr_overrides_persisted_address` | Relay, daemon |
| DI-46 | `check_lints_the_policy_file_and_directory_together`, `check_prints_the_fingerprint_the_daemon_loads`, `check_refuses_a_symlinked_or_non_directory_policy_dir`, `check_refuses_entries_the_daemon_refuses_to_start_on`, `the_runbook_documents_the_three_step_change`, `would_allow_answers_over_the_combined_policy` | daemon |

Unproven: DI-1, DI-2, DI-3, DI-5, DI-6, DI-11, DI-15, DI-18, DI-19, DI-32.
<!-- proof:end -->

## Retired

- **DI-22** — `2026-10-25` — the daemon read a join string at start; replaced by DI-43.
- **DI-37** — `2026-10-25` — `relay-daemon join` wrote the join string where the daemon read it
  and contacted no Relay; replaced by DI-42.
- **DI-38** — `2026-10-25` — the join string was inert once enrolled and could be removed;
  replaced by DI-44, under which no join string reaches the Node's disk.
- **DI-34** — `2026-10-23` — retired unbuilt: the package is the only supported install, and
  no migration off a hand-built Node is documented or supported.
- **DI-35** — `2026-10-22` — retired unbuilt: Relay renders no Enrollment Bundle, so nothing pins
  a version through one (ADR-0048).
- **DI-8** — `2026-10-21` — the daemon enrolls only by join string, pinning the Relay's CA from
  its fingerprint, and reads no CA bundle path (ADR-0031); replaced by DI-22 and DI-38.
- **DI-4** — `2026-10-18` — the unit runs `/usr/bin/relay-daemon`, not `/usr/local/bin`;
  replaced by DI-40.
- **DI-41** — `2026-10-18` — the shipped default denies only the daemon's secret-bearing files
  (ADR-0022); replaced by DI-28.
- **DI-10** — `2026-10-16` — the daemon persists the address it dialled at enrollment, and an
  address in the environment overrides it (ADR-0031); replaced by DI-38.
