# Daemon installation

**Status:** aspirational — worked through with the owner on `2026-09-15`, awaiting their review of
this draft. Describes intended behaviour, not the code (see the establishing phase in
`README.md`).

## Purpose

A Node joins the fleet only after something puts the relay-daemon on it. At fleet scale that
something is the customer's config management, never a person. This capability covers what config
management is handed and what it does with it: the release artifacts, the verified install, the
local files the daemon reads, the hardened service definition, upgrades, and taking a Node back
out.

The per-Node install is the product's biggest adoption cost **and** the reason it can be trusted:
the daemon is where deny-by-default Policy lives, where at-most-once is enforced, and where the
Relay's authority stops. So installation is deliberately the customer's act, performed by tools
they already run, from artifacts they can verify before executing.

## Surfaces

| Surface | What it does |
|---|---|
| **Release artifacts** | A `relay-daemon` binary under the release `SHA256SUMS`, a hardened systemd unit, and an example `EnvironmentFile` for config management to place. The Policy Catalog is published beside them; `policy-catalog.md` owns it |
| **The customer's config management** | The only installer, configurer and upgrader. Ansible and shell are rendered as bundles; other tools are documented, not rendered |
| **relay-daemon subcommands** | Offline only: `--version`, `policy check`, `dump-operation-schema` |
| **Enrollment bundles** | A rendered artifact carrying the join string, minted with its Enrollment Token (`enrollment.md` owns minting) |
| **Relay, MCP, Control API, Console** | Nothing. The Relay never installs, configures or upgrades a daemon, and its only lever over versions is the dispatch-level minimum-version gate. The absence is the invariant (invariant 14), not a gap |

## Behaviour

### What gets installed

The binary, the unit, an environment file, and — **only when no Policy file exists** — the
shipped default Policy: reads allowed with the confidentiality deny-list, mutate and Raw Exec
opt-in (ADR-0022). A re-run converges the binary and unit and never touches a Policy or Template
the operator has edited.

That "place if absent" rule is what keeps a fresh Node from the worst first impression: enrolled,
healthy, and refusing everything. A missing Policy still means deny-all at runtime — the safety
net stays; installation simply avoids landing on it.

**The Policy directory** *(designed for v0.7.0, with `policy-catalog.md`; #648)*. Beside the Policy
file sits a directory of Policy fragments. The install creates it empty and never writes into it
again; config management populates it, typically with catalog fragments. The daemon composes the
Policy file and every fragment into one Policy with one Policy fingerprint, deny beating allow
across all of them. The Policy file keeps every rule above — place if absent, the operator's from
then on — so an existing Node with no fragments behaves exactly as it does today.

There is no daemon container image. A component whose job is to hold the host's own authority is
not delivered as a container.

### A fresh Node's configuration

Two lines: the **join string** — Relay address, CA fingerprint and Enrollment Token in one
pasteable value (ADR-0031) — and the Node's `node:` Labels. The daemon pins the CA from the
fingerprint and writes its bundle into the state directory, so no CA path is configured by hand.

The Enrollment Token is used only when no identity is persisted and is inert on every later
start. It lives in the `0600` environment file config management already writes; config
management is expected to remove it after first start, and nothing enforces that. That is a
known posture, not an oversight — see *Accepted residual risk*.

After enrollment, config management stays authoritative for the Relay address.

### Privilege, and what a default Node can do

The shipped unit runs the daemon as root, bounded to `CAP_DAC_READ_SEARCH`, with `/etc`
read-only — so even a compromised daemon cannot rewrite its own Policy or Templates.

**A default Node cannot install packages or mutate the filesystem outside its state directory.**
Where a Node must, the customer places a documented drop-in relaxing the sandbox, and that
decision is visible in a file on that Node. The relaxation is never the default.

A Task refused by the sandbox must say so **as a sandbox refusal**, distinct from a command that
ran and failed. An operator reading "failed" where the truth is "this Node's unit forbids it"
files a bug; an AI-agent reading it retries.

### File modes

The daemon requests modes and never forces them: the operator's umask is a ceiling nothing in
Node code widens (ADR-0036). A Policy or Template file that is group- or world-writable is
refused. A umask that makes the state directory unusable fails loudly — no Task ever runs
unrecorded, because at-most-once depends on that directory.

### Upgrades and restarts

Config management swaps the artifact and restarts the unit. The daemon never self-upgrades and
the Relay never pushes a binary.

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
their own version wins — the bundle's pin is a starting default, not a constraint.

### Decommissioning

Revoke at the Relay **first**, then let config management remove the daemon, the unit and the
state directory. A removed daemon holding a live certificate is the worse of the two states.

Policy and Templates are left behind: they are the operator's files. A revoked Node that keeps
dialling is refused at the transport and visible in the audit trail; the Relay never reaches back
to stop it.

### Release integrity

Every installable artifact ships under the release `SHA256SUMS`, and no documented install path
executes an artifact before verifying its digest. The component that distrusts the operator is
not delivered by `curl | sh` (ADR-0033).

## Refusals

| Refusal | Cause |
|---|---|
| Daemon refuses to start | Its identity or dedup store cannot be opened; a Policy or Template file, or once it exists a fragment in the Policy directory, is group- or world-writable (a fragment also when it is a symlink or not a regular file); the state directory is unusable under the operator's umask |
| Deny-all | No Policy file, or one that cannot be read; once the Policy directory exists, also any fragment in it that cannot be read or parsed — one bad fragment invalidates the whole Policy |
| Sandbox refusal | A Task needing privilege the unit does not grant — reported distinctly from a command that ran and failed |
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
- **ADR-0033** — no `curl | sh`; the installer ships inside the release; Policy installs as a
  conffile once packages exist; no hosted repository before v1.0.0; no daemon image.
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

- That the install places the shipped default Policy only when absent, and never overwrites an
  edited one. The rule is the whole reason a fresh Node is useful, and no install path asserts it.
- That an in-flight Task cut short by a restart is reported as interrupted and never retried.
  Shutdown grace exists; the terminal outcome and its legibility are unbuilt.
- That a sandbox refusal is distinguishable from a command that ran and failed. This is the
  difference between "hardened by default" being a good default and being a support burden.
- That no documented install path executes an unverified artifact. Stated by ADR-0033, asserted
  by nothing.
- That the unit's syscall filter behaves on a real systemd host. Still a manual check, and the
  unit ships as the default only once it is done.

## Out of scope

- Minting Enrollment Tokens, rendering bundles, identity issuance and revocation —
  `enrollment.md`.
- The connection a running daemon holds, reconnect and the minimum-version gate —
  `node-connection.md`.
- What Policy may say and how it is evaluated — `policy.md`; what a Template may define —
  `operations-and-templates.md`.
- The Relay host's own installation and configuration — `relay-configuration.md`.
- Authoring Policy for a customer. Policy authoring stops at the clipboard (invariant 2); the
  first-party catalog fragments this capability installs are defined in `policy-catalog.md`.
- A hosted package repository, ruled out before v1.0.0 (ADR-0033).
- Non-systemd init systems, non-Linux hosts and containers-as-hosts: unaddressed, not promised.

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

## Future work

- **OS packages (`.deb`, `.rpm`)**, with the default Policy as a conffile so an upgrade never
  overwrites an edited one (ADR-0033). The packaging decision that makes "place if absent"
  unnecessary.
- **`relay-install.sh`**, shipped inside the release (ADR-0033).
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

- **Which distributions do packages promise?** Unanswerable until packages are scheduled, and the
  answer sets the CI matrix and the signing-key story.
- **Does a restart-interrupted Task have a distinct outcome on the wire, or is it an existing
  one?** It is contract (`/proto`) either way, so it is decided before it is built.
