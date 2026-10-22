# Daemon installation

**Status:** designed, not built, as of `2026-10-21`.
**Claim prefix:** `DI`

## Purpose

A Node joins the fleet only after something puts the relay-daemon on it, and at fleet scale that
is the customer's config management, never a person. This capability covers what config
management is handed and what it does with it: the release artifacts, the verified install, the
local files the daemon reads, the hardened unit, upgrades, and taking a Node back out.

The per-Node install is the product's biggest adoption cost **and** the reason it can be trusted:
the daemon is where deny-by-default Policy lives, where at-most-once is enforced, and where the
Relay's authority stops. So installation is the customer's act, by tools they already run, from
artifacts they can verify before executing.

## Surfaces

| Surface | What it does |
|---|---|
| **Release artifacts** | The statically linked `relay-daemon` binary for each architecture under the release `SHA256SUMS` (DI-1). Packages are designed (DI-24). The Policy Catalog is published beside them; `policy-catalog.md` owns it |
| **The customer's config management** | The only installer, configurer and upgrader |
| **relay-daemon subcommands** | `--version`, `policy check` (`policy.md`), `dump-operation-schema` (`operations-and-templates.md`); `join` (DI-37) contacts no Relay today; DI-42 makes it the act that enrolls. No other subcommand contacts a Relay |
| **Enrollment bundles** | A rendered artifact for config management, minted with its Enrollment Token (`enrollment.md` owns minting and rendering; DI-35) |
| **Relay, MCP, Control API, Console** | Nothing. The Relay never installs, configures or upgrades a daemon, and its only lever over versions is the dispatch-level minimum-version gate. The absence is the invariant (invariant 14), not a gap (DI-18) |

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
- **DI-5** Relaxing that sandbox is a drop-in the operator places, documented and never shipped,
  so a Node that may install packages or write elsewhere is one whose operator chose it, visibly,
  in a file on that Node.
- **DI-6** The shipped default Policy permits read Operations behind a confidentiality deny-list,
  allows no `mutate` Operation and does not enable Raw Exec (ADR-0022).
- **DI-28** Of the daemon's own files, the shipped default Policy denies reading and
  checksumming only those that carry a secret — the Node's identity private key and the
  environment file, with the daemon's environment oracle beside them. It does not deny its
  Policy, CA bundle, identity certificate, binary, unit, override unit, drop-ins or the shipped
  catalog's Template files: none holds a secret, and most are public or already in the Relay's
  hands. An operator-authored Template file is readable under the wildcard and recorded as R37,
  never a lint finding. `relay-daemon policy check --strict` passes on the shipped default with
  the shipped catalog's template root supplied (`--templates`); with no template root supplied,
  the default's allows for the catalog's names are unknown-name findings `--strict` fails, as
  ADR-0021 decides (ADR-0022, amended 2026-10-16). Retires DI-41.
- **DI-39** The self-reference lint probes reads — `file.read`, `file.checksum` and any supplied
  path-taking Template Operation — only against the daemon's secret-bearing files — the identity
  private key and the environment file — and probes writes — the Raw Exec shapes: edit in place,
  overwrite, copy or move over, delete, redirect, chmod, symlink — against its whole trust root
  at the packaged paths, each by exact path: the Policy file and the Policy directory, the
  environment file, the state directory's identity key and certificate, CA bundle and persisted
  address, the template root, the binary at `/usr/bin/relay-daemon`, the unit at
  `/usr/lib/systemd/system/relay-daemon.service`, the override unit under `/etc/systemd/system/`
  and the `override.conf` drop-in. The probe of the running binary's own path is a write probe
  only. A finding is proof that the Policy lets the wire reach its own gate; reading a file that
  holds no secret is never a finding (ADR-0021, amended 2026-10-16).
- **DI-40** The shipped unit runs the binary from `/usr/bin/relay-daemon`, the one binary path a
  packaged and a hand-built install share (ADR-0033, DI-25). Retires DI-4.
- **DI-7** The shipped example environment file covers every setting the daemon reads.
- **DI-30** A released catalog Template's name is bound to its body and risk class: CI refuses a
  release that changes either for a released name. The body is the Template's parsed
  definition, its command text and its ordered slot declarations as the daemon's own parser
  reads them, and not the text rendered for its shell or the engine that renders it. Withdrawing a
  released name is allowed.
- **DI-32** The release attaches the standalone unit and example environment file under
  `SHA256SUMS`, so a hand-built install — documented, not supported — verifies its unit like
  everything else.

### A fresh Node's configuration

- **DI-9** The daemon reads its declared `node:` Labels from its environment.
- **DI-22** The daemon is configured by a join string — Relay address, CA fingerprint and
  Enrollment Token in one value (ADR-0031). It pins the Relay's CA from the fingerprint and writes
  the CA bundle into its state directory, so no CA path is configured by hand.
- **DI-38** The daemon persists the Relay address with its identity at enrollment and uses it on
  every later start; a Relay address set in its environment overrides the persisted one. With
  neither, the daemon refuses to start: there is no default address. Once enrolled, the join string
  is inert and may be removed (ADR-0031). Retires DI-10.
- **DI-37** `relay-daemon join` configures a fresh Node in one step: it reads a join string from a
  prompt or standard input, never from its arguments, writes it where the daemon reads it, owned by
  root and readable by nobody else, then enables and starts the unit. It refuses on a Node that
  already holds an identity, changing nothing, and contacts no Relay itself: enrollment happens when
  the daemon starts. Config management may run it or write the same file directly.

### File modes

- **DI-11** The daemon requests file modes and never forces them: the operator's umask is a
  ceiling nothing in Node code widens (ADR-0036).

### Upgrades and restarts

Config management swaps the binary and restarts the unit. The daemon never self-upgrades and the
Relay never pushes a binary (invariant 14).

- **DI-14** On a termination signal the daemon stops accepting new Tasks, lets in-flight work
  finish within a configurable shutdown grace, then exits. A Task still running when the grace
  expires is stopped and ends with `OUTCOME_CANCELLED` — no `TaskCancel` is involved — and is
  never retried: its dedup marker was written before it ran.
- **DI-15** Policy and Templates are loaded once at start: a change to either takes effect when
  the unit restarts, and there is no in-place reload.
- **DI-16** Dedup markers in the state directory carry at-most-once across a reconnect and a
  restart.
- **DI-17** The Relay refuses to dispatch to a Node below the configured minimum daemon version;
  installation itself permits any version, downgrades included.

## Refusals

- **DI-12** A Policy or Template file that is group- or world-writable is refused at load: its
  rules never take effect.
- **DI-13** A umask that leaves the state directory unusable fails the Task before it runs, so no
  Task ever runs unrecorded; dedup markers are written no wider than owner read and write.
- **DI-18** No Relay surface — MCP, the Control API, the Console or the Node transport —
  installs, configures or upgrades a daemon. There is no such path to refuse.
- **DI-19** The daemon refuses to start if its identity or its dedup store cannot be opened.
- **DI-20** A missing or unreadable Policy file leaves the daemon running with a deny-all Policy:
  every Task is denied rather than the daemon refusing to start.
- **DI-21** A revoked Node that keeps dialling is refused at the transport; the Relay never
  reaches back to stop it.
- **DI-23** A revoked Node's dial attempt is recorded in the audit trail, not only refused: the
  first refused dial is recorded, then at most one record per Node per hour, so a revoked Node
  that keeps dialling cannot flood the trail.

## Governing ADRs and invariants

- **Invariant 14 / ADR-0014** — installation and upgrade are config management's, never the
  Relay's; the minimum-version gate is the Relay's only lever.
- **Invariant 2 / ADR-0002** — nothing in the install path lets the Relay deliver or change
  Policy. Policy reaches a Node only through the customer's config management.
- **Invariant 4** — the state directory's modes protect at-most-once, and the umask interaction
  fails closed.
- **ADR-0033**, amended 2026-10-21 (`relay-daemon join` enrolls, DI-42) — no `curl | sh`; the
  daemon ships as `.deb` and `.rpm`, not yet `.apk`; the
  default Policy is placed on first install only and never rewritten; no hosted repository and
  no package signing key before v1.0.0; no daemon image; one binary path, `/usr/bin` (DI-40).
  Amended 2026-10-15.
- **ADR-0021** — the shipped read catalog. Amended 2026-10-15: its own optional package,
  package-owned. Amended 2026-10-16: the self-reference lint's read probes stop at secrets and
  its write probes name the packaged trust root (DI-39).
- **ADR-0036** — a declared file mode is a ceiling; Node code never widens what the umask removed.
- **ADR-0032** — the rendered bundle pins a daemon version and digest built into the Relay
  (DI-35).
- **ADR-0031**, amended 2026-10-21 — the join string: address, CA fingerprint and Enrollment
  Token in one value; consumed by `relay-daemon join` and persisted nowhere on a Node (DI-42,
  DI-43).
- **ADR-0022** — the shipped default Policy allows reads with a confidentiality deny-list.
  Amended 2026-10-16: of its own files the default hides only secrets, and `--strict` passes on
  the shipped default (DI-28).
- **ADR-0037** *(Proposed, not accepted)* — an agentless SSH tier. Tracked as a possible future
  path; see *Future work*.

## Seams and proof

Installation has no Relay-side seam, by construction: that absence is the capability's central
property. On the Node, the Policy and Template loaders own mode enforcement, the identity and
dedup stores own the state directory, and the unit owns privilege. Packaging claims are proven by
CI install jobs once they exist; `make verify` alone cannot prove them.

### What proves each claim

| Claim | Proven by | Seam |
|---|---|---|
| DI-7 | `env_example_covers_the_config_surface`, `exemptions_are_real` | packaging |
| DI-9 | `parse_labels_skips_empty_and_garbage` | daemon |
| DI-12 | `loader_rejects_group_or_world_writable`, `loader_accepts_secure_modes`, `group_or_world_writable_file_is_refused`, `secure_modes_are_accepted` | daemon |
| DI-13 | `umask_tightened_dedup_directory_never_executes_unrecorded`, `marker_permissions_are_restrictive` | daemon |
| DI-14 | `drain_grace_expiry_kills_remaining` | daemon |
| DI-16 | `dedup_survives_reconnect_reload` | daemon |
| DI-30 | `catalog_names_match_ledger`, `ledger_check_refuses_a_changed_body`, `ledger_check_refuses_a_changed_risk_class`, `ledger_check_accepts_a_withdrawn_name_absent_from_the_catalog`, `ledger_check_refuses_a_withdrawn_name_back_in_the_catalog`, `scripts/catalog-ledger-test.sh` | daemon, packaging |
| DI-32 | `scripts/package-guard-test.sh`, and the release workflow's guard that `SHA256SUMS` lists the unit and example environment file, byte-equal to the copies inside every daemon package | packaging, release |
| DI-17 | `TestMCP_RunOperation_OutdatedNodeVersionRefused` | MCP |
| DI-21 | `TestRevokedNode_RefusedAfterRestart` | e2e |
| DI-22 | `pin_match_enrolls`, `pin_mismatch_sends_no_token`, `ca_bundle_mismatch_refused`, `TestCrossBinary_JoinStringEnrolls` | daemon, e2e |
| DI-23 | `TestRevokedNode_DialAuditedThenThrottled`, `TestServerCredentials_ReportsRevokedBeforeRefusing` | e2e, transport |
| DI-28 | `default_policy_denies_only_secret_bearing_own_files`, `deny_list_mirrors_adr_0022_exactly`, `default_policy_passes_strict_with_catalog` | daemon |
| DI-37 | `join_refuses_argv_join_string`, `join_refuses_existing_identity_env_file_unchanged`, `join_writes_env_file_root_0600_atomically`, `join_spawn_argv_is_the_literal_constant`, `spawn_family_appears_only_at_the_sanctioned_sites`, `production_and_test_suppressions_are_pinned_apart` | daemon |
| DI-38 | `TestCrossBinary_JoinStringEnrolls`, `TestCrossBinary_RestartWithoutJoinOrAddrUsesPersistedState`, `relay_addr_overrides_persisted_address`, `identity_without_address_exits_nonzero`, `idempotency_no_op_when_identity_present` | e2e, daemon |
| DI-39 | `lint_read_probes_stop_at_secrets`, `checksum_is_probed_without_templates`, `lint_write_probes_cover_packaged_trust_root`, `current_exe_is_a_write_probe_only`, `exe_equal_to_a_packaged_path_is_not_duplicated` | daemon |
| DI-40 | `unit_execstart_is_usr_bin` | packaging |

Claims with **no row**, and so nothing checking them: DI-1 (asserted by the release workflow,
not a test), DI-2, DI-3, DI-5, DI-6, DI-11 (held by the write-ban lint rather than a
claim-named test), DI-15, DI-18 (an absence), DI-19, DI-20. DI-3 also needs a real systemd
host: the unit's syscall filter is still a manual check, and no package carrying the unit ships
until it is done.

### Performance

| Characteristic | Contract | Measured by |
|---|---|---|
| *(none)* | Installation has no scale-dependent contract | *(none)* |

## Designed, not built

| Claim | Statement | Milestone |
|---|---|---|
| DI-24 | The release publishes the daemon as `.deb` and `.rpm` packages for each architecture. A package wraps the release's guarded binary byte for byte — packaging compiles, strips and rewrites nothing — is itself reproducible, built twice and compared, and is listed in the release `SHA256SUMS`. Packages carry no signature of their own before v1.0.0. | v0.6.5 — Install Path: relay init, join string, packages |
| DI-25 | The daemon package installs the binary at `/usr/bin/relay-daemon` and the hardened unit as a system unit, the same binary path a hand-built install uses, and never starts the daemon. It enables the unit on a first install only, only where systemd is running, honouring the distribution's presets; an upgrade never changes whether it is enabled. An enabled unit on a Node that holds no persisted identity stays inactive at boot without failing or retrying; it starts at the next boot after an identity is present, or when `relay-daemon join` (DI-42) or config management starts it. Nothing watches for an identity to appear. | v0.6.5 — Install Path: relay init, join string, packages |
| DI-26 | The daemon package places the shipped default Policy as the live Policy only on a first install, only if no Policy file exists and no Policy directory existed before the install began; never on an upgrade or a reinstall. On `.rpm` platforms, where a reinstall after removal is indistinguishable from a first install, those absence checks are the whole guard. No install, upgrade or remove rewrites or re-creates the live Policy. | v0.6.5 — Install Path: relay init, join string, packages |
| DI-27 | The daemon package places the environment file on a first install only, if none exists, owned by root and mode `0600`, and never rewrites it. | v0.6.5 — Install Path: relay init, join string, packages |
| DI-42 | `relay-daemon join` enrolls in the process that read the join string: it reads the string from a prompt or standard input, never from its arguments, pins the Relay's CA from the fingerprint, enrolls, persists the identity and the Relay address, and then enables and starts the unit. It writes the join string nowhere. On a Node that already holds an identity it changes nothing and exits zero, so config management may rerun it; a failed enrollment leaves nothing on disk and exits non-zero. Replaces DI-37 when promoted; `enrollment.md` carries the join string's contract. | v0.6.5 — Install Path: relay init, join string, packages |
| DI-43 | The daemon is configured by a join string given to `relay-daemon join` — Relay address, CA fingerprint and Enrollment Token in one value (ADR-0031). `join` pins the Relay's CA from the fingerprint and writes the CA bundle into the state directory, so no CA path is configured by hand. The unit start reads no join string: `RELAY_JOIN` is not a setting, the shipped example environment file carries no join line, and the environment file holds no secret, so DI-28's deny of it and DI-39's probe of it stay as defence in depth and no longer guard a secret. A unit start with no persisted identity exits cleanly as DI-25 says. Replaces DI-22 when promoted. | v0.6.5 — Install Path: relay init, join string, packages |
| DI-44 | The daemon persists the Relay address with its identity at enrollment and uses it on every later start; a Relay address set in its environment overrides the persisted one. A Node holding an identity with neither refuses to start: there is no default address. Replaces DI-38 when promoted. | v0.6.5 — Install Path: relay init, join string, packages |
| DI-45 | Each release attaches an Ansible role and a cloud-init config that install the daemon package and pipe a join string the caller supplies into `relay-daemon join`. Neither carries or stores a token, and rerunning either on an enrolled Node changes nothing (DI-42; ADR-0048). | v0.6.5 — Install Path: relay init, join string, packages |
| DI-29 | The shipped read catalog ships as its own optional `.deb` and `.rpm` package, depending on the daemon package. Its files are package-owned: replaced on upgrade, removed with the package, and never installed as configuration the package manager would preserve. | v0.6.5 — Install Path: relay init, join string, packages |
| DI-31 | Removing the daemon package removes the binary, the unit and the catalog package, and leaves the Policy, the Policy directory, the environment file and the state directory. `apt purge` removes everything the package created, the Node's identity included; `.rpm` removal never deletes state and prints the paths to delete by hand. Purge deletes only paths the package itself created, never a path read from an operator-edited file. | v0.6.5 — Install Path: relay init, join string, packages |
| DI-33 | A platform is supported only where CI installs the package, upgrades it over the operator's edited configuration and finds the edit intact, and removes it: Debian 13; Ubuntu 26.04 LTS and 24.04 LTS; RHEL, Rocky Linux and AlmaLinux 10; Fedora's current release; Amazon Linux 2023 — each on `x86_64` and `aarch64`. A platform whose package manager refuses an unsigned local package by default is not supported. This list also governs the Relay packages (`relay-configuration.md`). | v0.6.5 — Install Path: relay init, join string, packages |
| DI-34 | A documented migration moves a hand-built Node onto the package: it removes the old binary and the old unit under `/etc/systemd/system/`, which would otherwise shadow the packaged one, and says to remove by hand the Policy's self-reference denies for the old binary and unit paths, which the shipped default no longer carries (DI-28). | v0.6.5 — Install Path: relay init, join string, packages |
| DI-35 | A rendered enrollment bundle pins a daemon version and digest (ADR-0032); which artifact it pins once packages exist is an open question below. Moved from v0.6.5 on 2026-10-16: nothing renders a bundle until v0.7.0. | v0.7.0 — Admin Console: Administration & Execution |
| DI-36 | Beside the Policy file, `/etc/relay-daemon/policy.toml`, sits the Policy directory, `/etc/relay-daemon/policy.d`, which the install creates empty and never writes into again. The daemon composes the Policy file and every fragment in it into one Policy with one Policy fingerprint, deny beating allow across all of them; a fragment that is a symlink, not a regular file, or group- or world-writable refuses start, and one fragment that cannot be read or parsed leaves the whole Policy deny-all. | v0.7.0 — Admin Console: Administration & Execution |

## Out of scope

- Minting Enrollment Tokens, rendering bundles, identity issuance and revocation —
  `enrollment.md`. DI-21 and DI-23 state only what a revoked Node's daemon meets.
- The connection a running daemon holds — `node-connection.md`, which owns reconnect and the
  minimum-version gate. DI-16, DI-17 and DI-21 restate only what an install, upgrade or removal
  relies on.
- What Policy may say and how it is evaluated — `policy.md`; what a Template may define —
  `operations-and-templates.md`.
- The Relay host's own installation and configuration — `relay-configuration.md`, except the
  shared platform list in DI-33.
- Authoring Policy for a customer. Policy authoring stops at the clipboard (invariant 2); the
  first-party catalog fragments this capability installs are defined in `policy-catalog.md`.
- A hosted package repository, ruled out before v1.0.0 (ADR-0033).
- Init systems other than systemd, Nodes that are not Linux, containers as Nodes, and platforms
  outside DI-33: unaddressed, not promised.

## Accepted residual risk

**The Enrollment Token sits in plaintext on a fresh Node.** It is in a `0600` root-owned
environment file until config management removes it, so root-equivalent access can read it and it
lands in backups and images taken before first start. It is short-lived, scoped and inert once the
Node holds its certificate, but nothing enforces its removal, and a golden image built from an
enrolled Node would carry a live token.

DI-42 and DI-43 remove it: the join string is consumed by `relay-daemon join` in the process
that read it and persisted nowhere (ADR-0031 and ADR-0033, amended 2026-10-21), so this
residual closes when they are promoted. Accepted by the owner on 2026-09-15 as
**R16** in `docs/security/threat-model.md`. The compensating controls are a short token TTL and use
limit, and config management removing the join string after first start. **Revoking the token is
not the cleanup step**: revocation is the containment cascade (`enrollment.md`) and disconnects
every Node the token enrolled; reserve it for a token believed leaked.

**The join string can outlive the daemon.** Removing the daemon package leaves its environment
file, as it leaves the Policy, so a join string config management never cleared survives
decommissioning, and its token stays usable until it expires or is revoked. Accepted by the owner
on 2026-10-15 as **R36**, widening R16. The controls are R16's, plus purging (`.deb`) or deleting
the printed path (`.rpm`) when a Node leaves for good. Closes with DI-42 and DI-43, as R16 does.

**`relay-daemon join` enrolls as root outside the hardened unit's sandbox** for the seconds an
enrollment takes (DI-42): the same binary, the same fingerprint-pinned handshake and the same
enrollment code, without the unit's `ProtectSystem=`, seccomp and capability bounds. Accepted by
the owner on 2026-10-21 (ADR-0033 amendment) as **R40**. Bounded by the pin before any secret is
sent, by `join` taking no argv input and changing nothing on a Node that holds an identity, and
by the window: `join` exits once the identity is persisted and the sandboxed unit takes over.

**An operator-authored Template body is readable under the shipped default.** The default's
`file.read` wildcard reaches the template root, which no exact-path deny can cover, so a read
Task can return an operator's Template file to the AI-agent. No RPC carries a body and drift
visibility stays fingerprint-only (ADR-0021); a body discloses vocabulary, never a secret, and the
wire can never change it. Accepted by the owner on 2026-10-16 as **R37**. The control is
ADR-0022's: replace the wildcard with an explicit allow-list.

**The self-reference lint's write probes name exact paths.** The probes are concrete actions, and
absence of a finding is not proof of unreachability (ADR-0021), so a Raw Exec allow that reaches a
drop-in under any name but `override.conf`, a Policy fragment under any name, a Template file or a
state-directory file under a name the probes do not try, is not flagged (DI-39). The shipped
default enables no Raw Exec, so the exposure exists only where an operator writes a broad allow;
the hardened unit refuses the writes under `/etc` and `/usr` unless an operator drop-in relaxes it
(DI-3, DI-5) but never those in the state directory, which is why the probes name the identity key
and certificate, the CA bundle and the persisted address exactly. Accepted by the owner on
2026-10-16 as **R38**; the control is a Raw Exec deny pattern over those directories beside any
broad allow (ADR-0019).

## Future work

- **Older distribution releases**, one at a time, each with its own CI row.
- **A distinct sandbox-refusal outcome**, so a Task the systemd unit forbids is not reported as a
  failure, which an operator files as a bug and an AI-agent retries. It is a `/proto` outcome,
  decided before it is built.
- **An Alpine package.** It waits on a confinement of the Policy and Templates the daemon applies
  to itself, independent of the init system — Landlock, or a private mount namespace with those
  paths read-only — and on a decision to sign `apk` packages, which `apk` requires by default.
  Two Native Operations would also need an Alpine answer: `service.restart` assumes systemd and
  `pkg.install` knows apt, dnf and yum.
- **A hosted package repository and a package-signing key**, together, not before v1.0.0
  (ADR-0033).
- **OS packages carrying Policy Catalog fragments** (`policy-catalog.md`), alongside the Ansible
  role below. The shipped read catalog's package is not one: it is a template pack, not a
  catalog fragment.
- **A first-party Ansible role** that installs the daemon and places catalog fragments named in a
  group's variables. Until one exists, `policy-catalog.md`'s exported install task stands alone;
  reviving the thin role once closed as superseded is a decision, not a chore.
- **Delivering the join string to `relay-daemon join` from a secret store** or a systemd
  credential, for shops that want no interactive step; DI-42 already keeps it off disk, so this
  is a delivery convenience and not a second place the token rests.
- **In-place Policy and Template reload**, so tightening Policy across a fleet costs no restarts.
  Deliberately not first-pass: it is a second path by which the privileged side's authority
  changes.
- **Agentless SSH (ADR-0037)**, out of this capability. A Node with no daemon has no local Policy
  engine, no argument-level deny-by-default and no at-most-once, so the Relay would be the only
  thing deciding; adopting it needs its own capability spec and ADR.

## Open questions

- **Where do a Node's declared Labels live?** Today the daemon reads them from its environment
  (DI-9); `selectors-and-labels.md` describes a separate root-owned declared-labels file read at
  start and on reload. One home has to be chosen in both specs, with what remove and purge do to
  it.
- **Which artifact does a rendered bundle pin once packages exist?** ADR-0032 pins one daemon
  version and digest and calls the package the end state. With two package formats on two
  architectures, the bundle needs either a digest per platform or a different pin (DI-35).
- **Does a Task stopped at the end of the shutdown grace get a distinct outcome?** Today it is
  reported as cancelled (DI-14). A distinct interrupted outcome is a `/proto` contract, decided
  before it is built.

## Retired

- **DI-8** (retired 2026-10-21) *The daemon enrolls with an Enrollment Token and a CA bundle
  file named by path; the token is used only when no identity is persisted, and is inert on every later
  start.* Untrue once the daemon enrolls only by join string, pinning the Relay's CA from its
  fingerprint, and reads no CA bundle path (ADR-0031). DI-22 carries enrollment, and DI-38 the
  join string's being inert once enrolled.
- **DI-4** (retired 2026-10-18) *The shipped unit runs the binary from
  `/usr/local/bin/relay-daemon`.* Untrue once the shipped unit runs `/usr/bin/relay-daemon`, the
  path the package and a hand-built install share. DI-40 carries the binary path.
- **DI-41** (retired 2026-10-18) *The shipped default Policy's self-reference denies cover the
  daemon's own Policy, environment file, CA bundle and identity, the binary at
  `/usr/local/bin/relay-daemon` and the unit at `/etc/systemd/system/relay-daemon.service`.*
  Untrue once the shipped default denies only the daemon's secret-bearing files (ADR-0022,
  amended 2026-10-16). DI-28 carries the default's self-reference denies.
- **DI-10** (retired 2026-10-16) *The daemon reads the Relay address on every start and its
  persisted identity stores none, so config management stays authoritative for the address after
  enrollment.* Untrue once the daemon persists the address it dialled at enrollment (ADR-0031,
  decision 4). DI-38 carries the address rule: the persisted address is used on every later
  start, and an address set in the environment overrides it, so config management stays
  authoritative for steady state by the override rather than by the absence of a persisted value.
