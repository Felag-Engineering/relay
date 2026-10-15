# First-party installation artifacts

**Status:** Accepted; amended 2026-10-15 (the Relay ships as OS packages; the image is a
production path; place-if-absent Policy; remove and purge; no Alpine package yet).

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

Owner decision, 2026-10-15, taken while scheduling packaging into milestone v0.6.5, and revised
the same day after two adversarial reviews of the first draft. Decisions 2 and 5 are replaced
below, and decision 4 keeps its property under a different mechanism. Decisions 1, 3 and 6
stand unchanged: no `curl | sh`, the daemon's packages come first, and there is no hosted
repository before v1.0.0. This amendment also amends ADR-0010, ADR-0021, ADR-0022 and ADR-0030,
each recorded on its own page, and the wording of invariant 11.

**Decision 2, replaced: the Relay host is installed by an OS package, not a script.**

The argument decision 1 makes against `curl | sh` carries one step further. A script inside the
release is verified, but it is still an imperative program an operator must read before running
it as root, and the operator this product is sold to will not trust one they have not read. A
package is declarative: the package manager the operator already trusts places it, records
every file it owns, and removes it again. `relay-install.sh` is withdrawn before it was built.

Where the Relay package installs, it installs the Relay's Unix account, the binary, the
hardened unit, the `EnvironmentFile`, the state directory, and a secrets directory beneath
`/etc/relay`. Both `/etc/relay` and the secrets directory are root-owned and not writable by the
Relay, because write access to a directory would let it replace the root-owned files inside. **It installs and enables the Relay and never starts it.** Starting at
install would mint the CA private key wherever the package happens to be installed — inside an
image bake, so that every clone shares one CA key, or inside a container build with no running
init. The Relay starts when the operator starts it, after checking its configuration. Enabling
happens on first install only, only where systemd is running, and honours the distribution's
presets where it has them; an upgrade never changes whether the Relay is enabled.

It **never runs the first-boot command** (ADR-0030). Package-manager output is written to logs
the operator does not control and rarely reads, and the first-boot command prints the founding
admin's credentials. The package instead prints a configuration guide that carries no secret:
check `relay.env`, start the Relay, run the first-boot command in a terminal, then widen the
control-plane listener if it is to be reached off the host. The same guide is installed as
documentation, because a package manager's scroll is not a place anyone reads twice. It also
says never to capture an image of a host after the Relay has first started: the CA key would
travel with it.

**The package writes the `EnvironmentFile` once, at first install, and never again.** It is
generated rather than shipped as package-owned configuration, so an upgrade neither rewrites it
nor treats the generated values as an operator's edit. It names the host's fully qualified name
as the certificate hostname — never an implicit default — names the CA directory and store path
inside the state directory, enables the control plane and the Admin Console, and **binds the
control-plane listener to loopback**. Nothing is reachable off the host until the operator
widens that listener, and the guide says to do so only after the first-boot command has run.
Enabling the control plane was assigned to `relay init` (ADR-0030 is amended accordingly). The
guide prints the hostname it chose, because a wrong one fails only from the Node side. Changing
any value is an edit on the host and a restart: it is security floor (invariant 11), and no
command or surface is added to set it.

**Decision 5, replaced: the Relay container image becomes a production deployment path.**

It is the path most operators are expected to take, and the documentation stops calling it the
evaluation artifact. It is documented as a supported deployment path now and called production
once a human hardening review of its documented deployment is done. It holds either standing only on the same terms as the hardened unit, and these are
constraints on every documented deployment of it:

- The container runs as an unprivileged user with no capabilities and a read-only root
  filesystem; the CA and the store live on one durable volume, and nothing else is writable.
- Nothing in the image carries configuration, and no secret is passed as a value: secret files
  are mounted read-only and meet the same rule as on a packaged host, as the container sees
  them.
- A deployment pins the image by digest.

The floor's values are readable to anyone who can inspect the container — values, not secrets,
with one exception the review must close: an approval webhook URL that is itself a capability
URL. That exposure is **R35**. Where the deployment takes its floor from — a compose file, a git
branch a deploy tool follows — is the operator's infrastructure, and its documentation says
plainly that no automated credential, such as a CI system's or an AI-agent's repository token,
should be able to write it.

**There is still no daemon image, ever.** A containerised daemon has no host to administer.

**No Alpine package, for now.** An Alpine Node would run under OpenRC, without the systemd
unit's read-only filesystem; with nothing else confining it, any Task the Policy allows that can
write would let a malicious Relay rewrite the Policy itself, and invariant 2 would hold only as
far as the operator's Policy authoring. `apk` also refuses an unsigned package without
`--allow-untrusted`, which would put "skip verification" into the documented install, and two of
the four Native Operations assume systemd and apt, dnf or yum. An Alpine package waits on two
things: a confinement of the Policy and Templates that the daemon applies itself, independent of
the init system, and a decision on signing `apk` packages.

**A platform is supported only where CI proves it.** Every platform a package claims is one
where CI installs the package, upgrades it over the operator's edited configuration and finds
the edit intact, and removes it. The list of platforms lives in the capability specifications,
not here, because it moves with distribution releases. A hand-built install from the bare
binary on any other platform is documented, not supported.

**Packaging builds nothing.** A package wraps the binaries the release already built, reproduced
and guarded, byte for byte — the packaging step must not strip or rewrite them — and is itself
reproducible, built twice and compared like the binaries. Every package, and the standalone unit
and example `EnvironmentFile` a hand-built install takes, is listed in the release `SHA256SUMS`
and covered by its signature; that is the whole integrity story. Packages carry no signature of
their own before v1.0.0: a package-signing key is a long-lived secret with custody and rotation
obligations, and it belongs with the hosted repository decision 6 defers. A platform whose
package manager refuses unsigned packages by default is not supported until that changes.

**One unit per binary.** Packaged and hand-installed deployments run the same unit from the same
binary path, the one distribution packaging policy allows (`/usr/bin`). A second unit for
packages would be a second thing to drift.

**Decision 4 keeps its property; the conffile mechanism is withdrawn.** Decision 4 chose a
`dpkg` conffile / rpm `%config(noreplace)` so an upgrade never overwrites an edited Policy. A
conffile is replaced on upgrade when the operator has *not* edited it, so a release that changed
the shipped default would change Policy on every untouched Node — a fleet-wide permission change
nobody authored on any of them, which is the incident decision 4 exists to prevent. Instead the
daemon package ships the default Policy as a reference copy it owns, and **places it as the live
Policy on first install only, only when no Policy file exists, and only when no Policy directory
exists.** Never on an upgrade or a reinstall: an operator who deleted the Policy to lock a Node
down to deny-all, or who composes Policy only from fragments, must not find the default back
after the next upgrade. The live Policy is never a package-owned file: no install, upgrade or
remove rewrites it. A changed default in a later release reaches only Nodes installed after it,
and that is correct, because the Policy is the customer's (ADR-0002). The daemon's
`EnvironmentFile` follows the same first-install rule, placed `0600` and root-owned. The daemon
package installs the daemon and does not start it; config management starts it once it has
written the join string.

**The shipped read catalog is its own optional package.** A Template changes what may run on a
Node, so placing the catalog is a choice the operator makes, never a side effect of installing
the daemon. Its files are **package-owned** — replaced on upgrade, removed with the package, never
the operator's to edit, and never installed as configuration the package manager would preserve
— because the catalog is first-party content trusted the way the binary is (ADR-0021, amended
accordingly). Because the shipped default allows the catalog's Templates by name, **a released
catalog Template's name is bound to its behaviour and its risk class**: any change to either
ships under a new name, enforced in CI, so a catalog upgrade can add Templates but never changes
what an already-allowed name does. An operator who wants a variant defines a Template of their
own under another name.

**Remove keeps everything the operator cannot recreate; purge, where it exists, removes the
rest.** Removing a package removes the binary and unit it installed and leaves configuration and
state. `apt purge` removes configuration and state as well. rpm has no purge: removal never
deletes state, and prints what to delete by hand. A daemon left behind by a plain remove leaves
its `EnvironmentFile` behind too, and with it any join string config management did not clear:
**R36** widens R16 to cover it. Purge deletes only paths the package itself created, never a path
read from an operator-edited file.

**Purging the Relay never destroys its CA, and never separates it from its store.** Losing the CA
invalidates every Node identity it ever issued; keeping it without the store is worse, because
the store holds the revocation list, and a CA restored without it would let every revoked Node
back in. So purging the Relay moves the whole state directory — CA and store together — aside,
re-owned by root and readable by nobody else, and prints where it went; deleting it is a
separate, deliberate act by hand. Purge never deletes the Relay's Unix account, so no later
account can inherit its uid. This is the one exception to "purge removes everything", taken
knowingly and recorded as **R34**: a purged host keeps a live CA private key until someone
deletes it. A daemon purge has no such exception: one Node enrolling again is recoverable.

**Invariant 11 is restated around one adversary: a credential, or the Relay itself.** Its old
wording said a secret file must be root-owned, which the Relay could not meet for the key it
generates, and the first draft of this amendment grew to cover every way a floor might be
delivered. It now says only what Relay must guarantee: **neither a credential nor the Relay
itself can change the terms on which credentials are accepted.** The floor is set by whoever
administers the Relay's host, outside Relay, and nothing Relay runs or accepts can write it; the
Relay can read its secrets and cannot rewrite them, except key material it generates itself.

**Relay prevents; it does not police.** Relay's own software must make it impossible for a
credential, or a compromised Relay process, to raise its own power — that is the invariant, and
it is enforced in code. What an operator deliberately does on their own infrastructure — who
they let push to a deploy branch, which tool writes a host's configuration — is outside Relay.
The documentation says what a safe deployment looks like; Relay does not try to detect or
forbid an operator's own choices, and a deliberate circumvention is not an invariant violation.

The mechanics live in the capability specification, not the invariant: an operator-placed secret
is owned by root and readable, not writable, by the Relay's group — never owned by the Relay's
uid, whose owner could make it writable again; a Relay-generated key is owned by the Relay's uid
and readable by nobody else; the floor's configuration is root-owned. The packaged layout meets
this; known-gap row 11 in `AGENTS.md` closes when the Relay enforces it (#864), not when the
package ships (ADR-0010 records the rewording).

### Consequences of the amendment

The artifact set becomes: both binaries; Relay packages (`.deb`, `.rpm`); daemon packages
(`.deb`, `.rpm`); the shipped read catalog package; the standalone units and example
`EnvironmentFile`s; all under one `SHA256SUMS`; and the Relay image, published to the registry,
signed at its digest, and carrying a `relay` binary that `SHA256SUMS` covers. There is no
installer script.

Consumers to update with this amendment, each on its own page: `AGENTS.md` (invariant 11 and
known-gap row 11), `docs/STATUS.md` (its known-deviations mirror), ADR-0010, ADR-0021, ADR-0022,
ADR-0030, `GLOSSARY.md`, `docs/specs/daemon-installation.md`, `docs/specs/relay-configuration.md`,
`docs/specs/policy.md`, `docs/specs/operations-and-templates.md`, `docs/specs/policy-catalog.md`,
`docs/security/threat-model.md` (invariant 11's row, R16, R34–R36),
`docs/operations/release-artifacts.md`, `docs/operations/relay-install.md` (section 7's
"evaluation artifact" and its secret-file modes), `docs/operations/relay-daemon-install.md` (the
binary path, and migrating a hand-built Node onto the package), `docs/operations/template-packs.md`
(the catalog package), `docs/operations/approval-gates.md` (the webhook secret's ownership),
`docs/design/self-serve-enrollment.md` (E7, E8, E9), the deploy/compose stack's comments, and the
Relay's own help and error text that still says "root-owned" (with #864).
