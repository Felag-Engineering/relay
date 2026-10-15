# First-party installation artifacts

**Status:** Accepted; amended 2026-10-15 (the Relay ships as OS packages; the image is a
production path; Alpine; remove and purge).

"As automated as possible" pulls hard toward `curl -sfL https://get.relay.sh | sh`. It is
what k3s does, what Docker does, what almost everything does, and it is the single
fastest path from a bare host to a running service.

It is also the exact thing this product argues against. Every install document here makes
verify-then-install a principle with the digest check happening *before* the binary is
executed (`release-artifacts.md`, `relay-install.md:18-29`,
`relay-daemon-install.md:24-34`), and the pitch is architectural distrust of the operator.
A pipe-to-shell onboarding contradicts the thesis at the first touchpoint a customer ever
sees, and it does so in the one product category where the contradiction is the story.

## Decision

**1. No `curl | sh`. The installer ships inside the release, beside `SHA256SUMS`.**

The sequence stays download → verify → run. This costs the operator two lines and buys the
property the product is sold on. The installer is an artifact under the same verification
contract as the binaries, not an out-of-band script fetched from a URL that could serve
anything to anyone.

**2. `relay-install.sh` covers the Relay host**: service account, binary, hardened unit
from `relay/packaging/`, `/etc/relay/relay.env`, then `relay init` (ADR-0030). It prints
the CA fingerprint — one number, per ADR-0031 — the Console URL, the admin token, the join
string, and the enrollment playbook.

**3. The daemon gets OS packages before the Relay does.**

This inverts the intuitive order and is the highest-leverage choice here. The Relay is one
host, touched once — a script is sufficient forever. The daemon is every host in the
fleet, and one package collapses four per-Node steps (binary, unit, directories, Policy)
into one artifact on every one of them. If only one OS package is ever built, it is the
daemon's.

Note what this is *not*, until decision 6 changes: with no hosted repository it is
`download → verify → dpkg -i`, not `apt install`. The collapse is four steps into one
**artifact**, not into one **command**. That is a smaller win than the repository version
and still the largest available one, because the artifact is what config management
handles and the extra command is a line in a role either way.

**4. The daemon package installs `policy.default.toml` to `/etc/relay-daemon/policy.toml`
as a conffile** (`dpkg` conffile / rpm `%config(noreplace)`).

This closes the cold-start hole where a Node enrolls, connects, heartbeats, reports
healthy, and denies every Task because no Policy file exists. The Node now comes up
read-only per ADR-0022, which is the intended "eyes before hands" posture instead of an
accident.

The `noreplace` half is not packaging hygiene, it is a security requirement: **an upgrade
that silently restored the shipped default over an operator's edited Policy would be a
security incident**, and it would be one that surfaces as a fleet-wide permission change
nobody authored. It follows that changing the shipped default in a later release never
reaches an existing Node. That is correct — Policy is the customer's (ADR-0002) — and is
recorded here so nobody later "fixes" it.

Nothing about the daemon's own semantics changes: a missing or unreadable Policy is still
deny-all, and a group- or world-writable one is still refused. This decides what the
*package places*, never what the *daemon does*.

**5. The container image is the evaluation artifact, not the recommended production
deployment.** The Relay containerizes cleanly — it is unprivileged by design
(`relay/packaging/README.md:10-25`) — but the CA key and the store want durable volumes
with real permissions, and the hardened unit expresses a posture a compose file does not.
It is the fastest path to a fleet on a laptop and should say so.

There is no daemon image, ever: a containerized daemon has no host to administer.

**6. No hosted package repository before v1.0.0.** Packages are release attachments
verified by digest, exactly like the binaries, and the non-hosted install path is
supported rather than tolerated — it is the only path there is until 1.0, so it gets first-
class documentation and testing.

Running a repository is a standing distribution commitment with its own signing keys,
custody, and availability expectations. It is a 1.0 promise, not a beta convenience, and
committing to it early would mean operating one through every pre-1.0 breaking change.
Operators pin digests in config management either way, so this is consistent with how the
binaries already ship rather than a regression from it.

## Consequences

Four artifacts per release instead of two: `relay`, `relay-daemon`, `relay-install.sh`,
and the daemon packages — all under one `SHA256SUMS`. The release pipeline grows; the
verification contract does not change.

The evaluation path and the production path are now genuinely different artifacts, and
the docs must not blur them. An evaluator running the container and an operator running
the `.deb` under the hardened unit are doing different things on purpose.

`relay-install.sh` becomes a thing that can drift from `relay/packaging/` — the unit file
and the env sample it installs. The existing drift gates
(`relay/cmd/relay/packaging_drift_test.go`, `daemon/tests/packaging_drift.rs`) exist
because exactly that drift already happened once and went unnoticed for several
milestones. Whatever the installer installs belongs under the same kind of gate.

## Amendment (2026-10-15): the Relay ships as OS packages, and the image is a production path

Owner decision, 2026-10-15, taken while scheduling packaging into milestone v0.6.5. Decisions 2
and 5 are replaced below. Decisions 1, 3, 4 and 6 stand unchanged: no `curl | sh`, the daemon's
packages come first, the default Policy is a `noreplace` conffile, and there is no hosted
repository before v1.0.0.

**Decision 2, replaced: the Relay host is installed by an OS package, not a script.**

The argument decision 1 makes against `curl | sh` carries one step further. A script inside the
release is verified, but it is still an imperative program an operator must read before running
it as root, and the operator this product is sold to will not trust one they have not read. A
package is declarative: the package manager the operator already trusts places it, records
every file it owns, and removes it again. `relay-install.sh` is withdrawn before it was built.

Where the Relay package installs, it installs the service account, the binary, the hardened
unit, the `EnvironmentFile`, the state directory, and a root-owned directory for secret files
that the service account may read and nobody else may. It enables and starts the service.

It **never runs the first-boot command** (ADR-0030). Package-manager output is written to logs
the operator does not control and rarely reads, and the first-boot command prints the founding
admin's credentials. The package instead prints a configuration guide that carries no secret:
set the hostname, restart, then run the first-boot command in a terminal. The same guide is
installed as documentation, because a package manager's scroll is not a place anyone reads
twice.

The hostname the Relay starts with is written in the `EnvironmentFile`, never an implicit
default. The package writes the host's fully qualified name there **once, at first install,
and never again**: the file is generated rather than shipped as package-owned configuration, so
an upgrade neither rewrites it nor treats the generated value as an operator edit. The guide
prints the name it chose, because a wrong one fails only from the Node side. Changing it is an
edit on the host and a restart: it is security floor (invariant 11), and no command or surface
is added to set it.

**Decision 5, replaced: the Relay container image is a production deployment path.**

It is the path most operators are expected to take, and the documentation stops calling it the
evaluation artifact. It earns that standing only on the same terms as the hardened unit, and
these are constraints on every documented deployment of it:

- The container runs as an unprivileged user with no capabilities and a read-only root
  filesystem; the CA and the store live on one durable volume, and nothing else is writable.
- The security floor reaches the container only from the host that runs it. Nothing in the
  image carries configuration, and no secret is passed as a value: secret files are mounted
  read-only and meet the same ownership and mode rule as on a packaged host, as the container
  sees them.
- A deployment pins the image by digest.
- The documented deployment gets a human hardening review before it is called production. A
  description of what it mirrors is not a review.

**There is still no daemon image, ever.** A containerised daemon has no host to administer.

**The daemon also ships as an Alpine package.** Decision 3 named `.deb` and `.rpm`; `.apk` joins
them. Each package carries a unit for its host's init system. Where that init
system cannot express a protection the systemd unit gives, the package ships anyway and its
documentation names each protection the Node does not get. The daemon's own guarantees —
deny-by-default Policy, at-most-once, refusing a Policy file others can write — do not depend
on the init system, and that is why a weaker init-system unit is acceptable rather than
disqualifying. Containers as Nodes stay unsupported; the Alpine package is for Alpine hosts.

**A platform is supported only where CI proves it.** Every platform a package claims is one
where CI installs the package, upgrades it over an edited Policy and finds the edit intact, and
removes it. The list of platforms lives in the capability specification, not here, because it
moves with distribution releases.

**Packaging builds nothing.** A package wraps the binaries the release already built, reproduced
and guarded, byte for byte, and is itself reproducible. Every package is listed in the release
`SHA256SUMS` and covered by its signature; that is the whole integrity story. Packages carry no
signature of their own before v1.0.0: a package-signing key is a long-lived secret with custody
and rotation obligations, and it belongs with the hosted repository decision 6 defers.

**One init-system unit per binary.** Packaged and hand-installed deployments run the same unit
from the same binary path, the one distribution packaging policy allows (`/usr/bin`). A second
unit for packages would be a second thing to drift.

**Remove keeps everything the operator cannot recreate; purge removes everything but the
Relay's CA.** Removing a package removes the files it installed and leaves configuration and
state. Purging, where the package format has a purge, removes configuration and state as well.
Where a format has no purge, removal never deletes state, and prints what to delete by hand.

**No package operation destroys the Relay's CA.** Losing it invalidates every Node identity it
ever issued and re-enrolls the fleet, and one mistyped `purge` must not be able to do that.
Purging the Relay moves the CA directory aside, preserved with the same ownership and modes,
and prints where it went; deleting it is a separate, deliberate act by hand. This is the one
exception to "purge removes everything", and it is taken knowingly. A daemon purge has no such
exception: one Node re-enrolling is recoverable.

**The shipped read Template catalog is its own optional package.** A Template changes what may
run on a Node, so placing one is a choice the operator makes, never a side effect of installing
the daemon. The daemon package carries the binary, its init-system unit, the default Policy,
and an `EnvironmentFile` template, all configuration as conffiles.

**The Relay is not packaged for Alpine.** An Alpine host runs the Relay container.

### Consequences of the amendment

The artifact set becomes: both binaries; Relay packages (`.deb`, `.rpm`); daemon packages
(`.deb`, `.rpm`, `.apk`); the read Template catalog package; the Relay image; all under one
`SHA256SUMS`. There is no installer script.

The secret-file rule in invariant 11 — root-owned and not world-readable — is unchanged, and
the packaged layout meets it: secret files root-owned, readable by the service account's group
and no one else. Today the Relay checks a secret file's mode and never its owner, and requires a
mode the packaged layout cannot meet (known-gap row 11 in `AGENTS.md`). Shipping the package
closes that gap rather than inheriting it. The other half of that row — the CA private key,
read back with no check at all — closes with it: the Relay writes the key itself, so it is
owned by the service account rather than root, and the Relay refuses to start if anyone else
can read it.

Consumers to update with this amendment: `docs/specs/daemon-installation.md`,
`docs/specs/relay-configuration.md`, `docs/operations/release-artifacts.md`,
`docs/operations/relay-install.md` (section 7's "evaluation artifact"), and
`docs/design/self-serve-enrollment.md` (E7, E8, E9).
