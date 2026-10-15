# Daemon installation

**Status:** aspirational — worked through with the owner on `2026-09-15`, awaiting their review of
this draft. Describes intended behaviour, not the code (see the establishing phase in
`README.md`). Packaging intent revised with the owner on 2026-10-15 to match ADR-0033's amendment
of that date (milestone v0.6.5).

## Purpose

A Node joins the fleet only after something puts the relay-daemon on it. At fleet scale that
something is the customer's config management, never a person. This capability covers what config
management is handed and what it does with it: the release artifacts, the verified install, the
local files the daemon reads, the hardened init-system unit, upgrades, and taking a Node back
out.

The per-Node install is the product's biggest adoption cost **and** the reason it can be trusted:
the daemon is where deny-by-default Policy lives, where at-most-once is enforced, and where the
Relay's authority stops. So installation is deliberately the customer's act, performed by tools
they already run, from artifacts they can verify before executing.

## Surfaces

| Surface | What it does |
|---|---|
| **Release artifacts** | *(Packages designed for v0.6.5.)* The `relay-daemon` packages (`.deb`, `.rpm`) and the optional shipped read catalog package for each architecture, and the bare binary, unit and example `EnvironmentFile` for a hand-built install — all under the release `SHA256SUMS`. The Policy Catalog is published beside them; `policy-catalog.md` owns it |
| **The customer's config management** | The only installer, configurer and upgrader. Ansible and shell are rendered as bundles; other tools are documented, not rendered |
| **relay-daemon subcommands** | Offline only: `--version`, `policy check`, `dump-operation-schema` |
| **Enrollment bundles** | A rendered artifact carrying the join string, minted with its Enrollment Token (`enrollment.md` owns minting) |
| **Relay, MCP, Control API, Console** | Nothing. The Relay never installs, configures or upgrades a daemon, and its only lever over versions is the dispatch-level minimum-version gate. The absence is the invariant (invariant 14), not a gap |

## Behaviour

### What gets installed

*(Packaging designed for v0.6.5, as is everything below that names a package.)* Config
management installs the **daemon package** for the Node's platform, after verifying it against
the release `SHA256SUMS`. There is no hosted repository before v1.0.0 (ADR-0033), so the package
is a pinned file config management fetches and verifies, not an `apt install`.

The daemon package installs the binary, at the one path packaged and hand-built installs share,
and the hardened systemd unit. It installs the daemon and **does not start it**: config
management starts it once it has written the join string. It also carries the shipped default
Policy — reads allowed with the confidentiality deny-list, mutate and Raw Exec opt-in
(ADR-0022) — as a reference copy it owns.

**The live Policy is placed on first install only, and no package operation ever rewrites it.**
On a first install — never an upgrade or a reinstall — if no Policy file exists and no Policy
directory exists, the package copies the shipped default into place. From then on the Policy
file is the operator's: no install, upgrade or remove rewrites it, whether or not anyone edited
it, and a later upgrade never puts it back once the operator has deleted it. That matters,
because deleting the Policy is a legitimate way to lock a Node down to deny-all, and composing
Policy only from fragments is a legitimate way to run one; neither may be undone by routine
maintenance. A changed default in a later release therefore reaches only Nodes installed after
it. That is deliberate: an upgrade that changed the Policy of any Node would be a permission
change nobody authored on it (ADR-0033 decision 4, as amended 2026-10-15), and the Policy is the
customer's.

The shipped default's self-reference denies (ADR-0022, amended 2026-10-15) name the binary and
unit at the paths the package installs, and the override path where a drop-in for that unit
would live. A Node moved from a hand-built install onto the package keeps its Policy, so its
denies still name the old paths; the documented migration removes the old binary and unit — an
old unit under the override path would otherwise shadow the packaged one — and says to update
those denies by hand.

The `EnvironmentFile` follows the same first-install rule: placed `0600` and root-owned, for the
join string and the Node's declared Labels, and never rewritten by the package.

Shipping the default Policy is what keeps a fresh Node from the worst first impression:
enrolled, healthy, and refusing everything. A missing Policy still means deny-all at runtime —
the safety net stays; installation simply avoids landing on it.

**The shipped read catalog is its own optional package.** It depends on the daemon package, and
a Node offers its Templates only where the operator chose to install it — a Template changes
what may run on a Node, so placing one is never a side effect of installing the daemon. Its
files are **package-owned**: replaced on upgrade and removed with the package, never installed
as configuration the package manager would preserve, and never the operator's to edit, because
the catalog is first-party content trusted the way the binary is (ADR-0021, as amended
2026-10-15). **A released catalog Template's name is bound to its body and risk class**: a change
to either ships under a new name, and CI refuses a release that changes a released one — so a
catalog upgrade never changes what an already-allowed name does. Because the live Policy is
never rewritten, a Template that a later catalog release adds is offered on an existing Node
only once that Node's Policy allows it. An operator who wants a variant defines their own
Template under another name.

A hand-built install from the bare binary is **documented, not supported**: it is the path for a
platform no package covers, and support means a CI row (*Supported platforms*). It uses the same
unit and binary path as the package and places the default Policy under the same first-install
rule, so a hand-built Node and a packaged one behave alike.

**The Policy directory** *(designed for v0.7.0, with `policy-catalog.md`; #648)*. Beside the Policy
file sits a directory of Policy fragments. The install creates it empty and never writes into it
again; config management populates it, typically with catalog fragments. The daemon composes the
Policy file and every fragment into one Policy with one Policy fingerprint, deny beating allow
across all of them. The Policy file keeps the rule above — placed on first install when absent,
the operator's from then on — so an existing Node with no fragments behaves exactly as it does
today.

There is no daemon container image. A component whose job is to hold the host's own authority is
not delivered as a container.

### A fresh Node's configuration

Two lines: the **join string** — Relay address, CA fingerprint and Enrollment Token in one
pasteable value (ADR-0031) — and the Node's `node:` Labels. Today the daemon reads its declared
Labels from the environment file; whether they move to the separate declared-labels file
`selectors-and-labels.md` describes is an open question shared with that spec. The daemon pins
the CA from the fingerprint and writes its bundle into the state directory, so no CA path is
configured by hand.

The Enrollment Token is used only when no identity is persisted and is inert on every later
start. It lives in the `0600` environment file, written by config management into the file the
package placed; config management is expected to remove it after first start, and nothing
enforces that. That is a known posture, not an oversight — see *Accepted residual risk*.

After enrollment, config management stays authoritative for the Relay address.

### Privilege, and what a default Node can do

The shipped unit runs the daemon as root, bounded to `CAP_DAC_READ_SEARCH`, with `/etc`
read-only — so even a compromised daemon cannot rewrite its own Policy or Templates.

**A default Node cannot install packages or mutate the filesystem outside its state directory.**
Where a Node must, the customer places a documented drop-in relaxing the sandbox, and that
decision is visible in a file on that Node. The relaxation is never the default.

That sandbox is why **no Alpine package ships yet**. Alpine runs OpenRC, which cannot express the
unit's read-only filesystem; with nothing else confining the daemon, any Task the Policy allows
that can write would let a malicious Relay rewrite the Policy itself, and invariant 2 would
hold only as far as the operator's Policy authoring. An Alpine package waits on a confinement
the daemon applies to itself, independent of the init system (*Future work*).

A Task refused by the sandbox must say so **as a sandbox refusal**, distinct from a command that
ran and failed. An operator reading "failed" where the truth is "this Node's unit forbids it"
files a bug; an AI-agent reading it retries.

### File modes

The daemon requests modes and never forces them: the operator's umask is a ceiling nothing in
Node code widens (ADR-0036). A Policy or Template file that is group- or world-writable is
refused. A umask that makes the state directory unusable fails loudly — no Task ever runs
unrecorded, because at-most-once depends on that directory.

### Upgrades and restarts

Config management installs the newer package (or swaps the bare binary) and restarts the unit.
The daemon never self-upgrades and the Relay never pushes a binary.

On restart the daemon stops accepting new Tasks, lets in-flight work finish within the shutdown
grace, then exits. Anything still running when the grace expires is killed and reported as an
**interrupted Task** with its own terminal outcome — never retried, because at-most-once is not
negotiable and an interrupted `pkg.install` is exactly the thing that must not run twice. The
outcome has to be legible enough that an AI-agent treats it as terminal.

A Policy or Template change is the same act: push the files — the Policy file, a fragment in
the Policy directory, or a Template — and restart the unit. Dedup markers in
the state directory carry at-most-once across the reconnect.

Downgrades are permitted by installation; the Relay refuses to dispatch to a Node below the
configured minimum version. A rendered bundle pins a version and digest, and a customer pinning
their own version wins — the bundle's pin is a starting default, not a constraint. Which
artifact the bundle pins once packages exist is an open question.

### Decommissioning

Revoke at the Relay **first**, then let config management remove the packages. A removed daemon
holding a live certificate is the worse of the two states. Removing the daemon package removes
the catalog package with it, because the catalog depends on it.

**Remove and purge differ, and the package format decides which exist:**

| Format | Remove | Purge |
|---|---|---|
| `.deb` | Binary, unit and catalog Templates go; Policy, Policy directory and its fragments, environment file and state directory stay | `apt purge` removes all of it, the Node's identity included |
| `.rpm` | As `.deb`. The Policy and environment file were never package-owned, so rpm leaves them exactly as they were | No purge exists. Removal never deletes state; it prints the exact paths to delete by hand |

Purge deletes only paths the package itself created, never a path read from an operator-edited
file. A purged Node has no identity and must enroll again. Left behind by a plain remove, the
Policy is the operator's file, and so is the environment file — with any join string config
management did not clear (R36, widening R16). A revoked Node that keeps dialling is refused at
the transport and visible in the audit trail; the Relay never reaches back to stop it.

### Release integrity

Every release attachment ships under the release `SHA256SUMS`, and no documented install path
executes an artifact before verifying its digest. The release attaches the packages, the bare
binary, and the standalone unit and example `EnvironmentFile` a hand-built install takes, so
that path verifies its unit like everything else. The component that distrusts the operator is
not delivered by `curl | sh` (ADR-0033).

A package wraps the binary the release already built, reproduced and guarded, byte for byte —
packaging compiles nothing, and must not strip or rewrite the binary — and the package is itself
reproducible, built twice and compared. Packages carry no signature of their own before v1.0.0;
`SHA256SUMS` and its keyless signature are the whole integrity story. A platform whose package
manager refuses an unsigned local package by default is not supported until that changes.

### Supported platforms

*(Designed for v0.6.5.)* **Current releases only**, decided 2026-10-15; older releases are
added later, one at a time. Ubuntu 24.04 LTS is the one deliberate exception, kept because it is
still the most widely deployed LTS. A platform is supported only where CI installs the package,
upgrades it over the operator's edited configuration and finds the edit intact, and removes it
(ADR-0033). This list governs the daemon packages and the Relay packages
(`relay-configuration.md`); for the Relay, the edited configuration is its `EnvironmentFile`.

| Family | Releases | Package |
|---|---|---|
| Debian | 13 | `.deb` |
| Ubuntu | 26.04 LTS, 24.04 LTS | `.deb` |
| RHEL, Rocky Linux, AlmaLinux | 10 | `.rpm` |
| Fedora | current release | `.rpm` |
| Amazon Linux | 2023 | `.rpm` |

Every row is `x86_64` and `aarch64`. The binary is static, so a package may install on an
older release; that is not support.

## Refusals

| Refusal | Cause |
|---|---|
| Daemon refuses to start | Its identity or dedup store cannot be opened; a Policy or Template file, or once it exists a fragment in the Policy directory, is group- or world-writable (a fragment also when it is a symlink or not a regular file); the state directory is unusable under the operator's umask |
| Deny-all | No Policy file, or one that cannot be read; once the Policy directory exists, also any fragment in it that cannot be read or parsed — one bad fragment invalidates the whole Policy |
| Sandbox refusal | Under the systemd unit, a Task needing privilege the unit does not grant — reported distinctly from a command that ran and failed |
| Refused at the transport | A revoked Node that keeps dialling |
| Below minimum version | The Relay declines to dispatch; installation itself permits any version |
| No route exists | Any attempt to install, configure or upgrade a daemon from the Relay. There is no such path to refuse |

## Governing ADRs and invariants

- **Invariant 14 / ADR-0014** — installation and upgrade are config management's, never the
  Relay's; the minimum-version gate is the Relay's only lever.
- **Invariant 2 / ADR-0002** — nothing in the install path lets the Relay deliver or change
  Policy. Policy reaches a Node only through the customer's config management.
- **Invariant 4** — the state directory's modes protect at-most-once, and the umask interaction
  fails closed.
- **ADR-0033** — no `curl | sh`; the daemon ships as `.deb` and `.rpm`, not yet `.apk`; the default
  Policy is placed on first install only and never rewritten; no hosted repository and no package signing
  key before v1.0.0; no daemon image. Amended 2026-10-15.
- **ADR-0021** — the shipped read catalog. Amended 2026-10-15: its own optional package,
  package-owned.
- **ADR-0036** — a declared file mode is a ceiling; Node code never widens what the umask removed.
- **ADR-0032** — the rendered bundle pins a daemon version and digest built into the Relay.
- **ADR-0031** — the join string: address, CA fingerprint and Enrollment Token in one value.
- **ADR-0022** — the shipped default Policy allows reads with a confidentiality deny-list.
- **ADR-0037** *(Proposed, not accepted)* — an agentless SSH tier. Tracked as a possible future
  path; see *Future work*.

## Seams and proof

Installation has no Relay-side seam by construction — that absence is the capability's central
property. On the Node, the loaders for Policy and Templates own mode enforcement, the identity
and dedup stores own the state directory, and the unit owns privilege.

### What proves each claim

| Behaviour | Proven by | Seam |
|---|---|---|
| A group- or world-writable Policy file is refused | `loader_rejects_group_or_world_writable`, `loader_accepts_secure_modes` | daemon |
| A group- or world-writable Template file is refused | `group_or_world_writable_file_is_refused`, `secure_modes_are_accepted` | daemon |
| A tightened umask never lets a Task run unrecorded | `umask_tightened_dedup_directory_never_executes_unrecorded` | daemon |
| Dedup markers are written with restrictive permissions | `marker_permissions_are_restrictive` | daemon |
| The shipped example env file covers every setting the daemon reads | `env_example_covers_the_config_surface`, `exemptions_are_real` | packaging |
| A signalled daemon exits cleanly rather than hanging | `sigterm_while_idle_reconnecting_exits_zero_immediately` | daemon e2e |

Claims above with **no row**, and so nothing checking them:

- That the package places the default Policy and environment file on first install only, only
  when absent, never when a Policy directory exists, and that no install, upgrade or remove
  rewrites or re-creates either, on every supported platform. The rule is the
  whole reason a fresh Node is useful, and no install path asserts it.
- That a package contains the guarded release binary byte for byte, and is itself reproducible.
- That remove keeps state and purge (where it exists) removes it, per the table above.
- That the catalog package's files are replaced on upgrade and removed with the daemon package,
  and that no catalog release changes the body or class of a released name.
- That an in-flight Task cut short by a restart is reported as interrupted and never retried.
  Shutdown grace exists; the terminal outcome and its legibility are unbuilt.
- That a sandbox refusal is distinguishable from a command that ran and failed. This is the
  difference between "hardened by default" being a good default and being a support burden.
- That no documented install path executes an unverified artifact. Stated by ADR-0033, asserted
  by nothing.
- That the unit's syscall filter behaves on a real systemd host. Still a manual check, and no
  package carrying the unit ships until it is done.

## Out of scope

- Minting Enrollment Tokens, rendering bundles, identity issuance and revocation —
  `enrollment.md`.
- The connection a running daemon holds, reconnect and the minimum-version gate —
  `node-connection.md`.
- What Policy may say and how it is evaluated — `policy.md`; what a Template may define —
  `operations-and-templates.md`.
- The Relay host's own installation and configuration — `relay-configuration.md`, except the
  shared platform list in *Supported platforms*.
- Authoring Policy for a customer. Policy authoring stops at the clipboard (invariant 2); the
  first-party catalog fragments this capability installs are defined in `policy-catalog.md`.
- A hosted package repository, ruled out before v1.0.0 (ADR-0033).
- Init systems other than systemd, non-Linux hosts, containers-as-hosts, and platforms outside
  *Supported platforms*: unaddressed, not promised.

## Accepted residual risk

**The Enrollment Token sits in plaintext on a fresh Node.** It is in a `0600` root-owned
environment file until config management removes it, so it is readable by root-equivalent access
and lands in backups and host images taken before first start. It is short-lived, scoped, and
inert once the Node holds its certificate — but nothing enforces its removal, and a golden image
built from an enrolled host would carry a live token.

Delivering it through `systemd LoadCredential=` or the customer's secret store removes this, at
the cost of a second supported path; both are named in *Future work*. Accepted by the owner on
2026-09-15 and recorded as **R16** in `docs/security/threat-model.md`. The compensating controls
are a short token TTL and use limit, and config management removing the join string after first
start. **Revoking the token is not the cleanup step**: revocation is the containment cascade
(`enrollment.md`) and disconnects every Node the token enrolled; reserve it for a token believed
leaked (#584).

**The join string can outlive the daemon.** Removing the daemon package leaves its environment
file behind, by the same rule that leaves the Policy, so a join string config management never
cleared survives decommissioning on disk; its token stays usable for other enrollments until it
expires or is revoked. Accepted by the owner on 2026-10-15 and recorded as **R36**, widening R16.
The compensating controls are R16's, plus purging (`.deb`) or deleting the printed path (`.rpm`)
when a Node leaves for good.

## Future work

- **Older distribution releases**, one at a time, each with its own CI row.
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
  group's variables. Until one exists, `policy-catalog.md`'s exported install task stands alone.
  A thin role was closed as superseded once (#361); reviving it is a decision, not a chore.
- **`LoadCredential=` for the Enrollment Token**, closing the residual risk above.
- **In-place Policy and Template reload**, so tightening Policy across a fleet costs no restarts.
  Deliberately not first-pass: it is a second path by which the privileged side's authority
  changes.
- **Agentless SSH (ADR-0037)** — tracked as a possible future path, and out of this capability.
  A Node with no daemon has no local Policy engine, no argument-level deny-by-default and no
  at-most-once, so the Relay would become the only thing deciding. If it is ever adopted it needs
  its own capability spec and its own ADR rather than a row in this one.

## Open questions

- **Where do a Node's declared Labels live?** This spec puts them in the environment file beside
  the join string; `selectors-and-labels.md` puts them in a separate root-owned declared-labels
  file read at start and on reload, and sends getting that file onto a Node here. One home has to
  be chosen in both specs, with what remove and purge do to it.

- **Which artifact does a rendered bundle pin once packages exist?** ADR-0032 pins one daemon
  version and digest and calls the package the end state, at which point the rendered bundle pins
  nothing. With three package formats on two architectures, the bundle needs either a digest per
  platform or a different pin.

- **Does a restart-interrupted Task have a distinct outcome on the wire, or is it an existing
  one?** It is contract (`/proto`) either way, so it is decided before it is built.
