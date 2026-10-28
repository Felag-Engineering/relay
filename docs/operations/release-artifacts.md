# Release artifacts: naming, pinning, and verify-then-install

Pushing a `v*` tag runs `.github/workflows/release.yml`. It builds both binaries for `x86_64`
and `aarch64`, stamped per [version-stamping.md](version-stamping.md), twice and from
different paths (see [Reproducing a release](#reproducing-a-release)); verifies the stamp; and
publishes a signed GitHub Release and a signed Relay image. It also builds the `.deb` and
`.rpm` packages of the relay-daemon and of the Relay for both architectures, and the Ansible
role, and attaches them to the Release once the [install
matrix](#the-install-matrix-gates-the-packages) has passed on exactly those bytes. The daemon
reaches the fleet only through the customer's config management (ADR-0014: the Relay never
pushes binaries), so **the artifact set below is the contract config management pins
against**. Change the convention here and in the workflow together.

## What a release contains

For tag `v<version>` (e.g. `v0.1.0`, `v0.1.0-beta`), the GitHub Release carries:

| File | What it is |
|---|---|
| `relay-daemon-<version>-linux-amd64`, `relay-daemon-<version>-linux-arm64` | The relay-daemon, statically linked (musl, ADR-0007). No libc or distro expectations; drops onto any Linux Node of that architecture. |
| `relay-<version>-linux-amd64`, `relay-<version>-linux-arm64` | The Relay server binary, statically linked (`CGO_ENABLED=0`). It has no libc dependency. |
| `<artifact>.spdx.json` | An SPDX SBOM for each of the four binaries. The Relay's lists the exact Go modules in the binary. The daemon's is derived from `Cargo.lock` — a superset (every target, dev and build dependencies) — because a stripped Rust binary carries no dependency metadata to read. |
| `relay-image-<version>-linux-<arch>.spdx.json` | An SPDX SBOM for each platform of the Relay image. |
| `relay-daemon_<pkgversion>-1_amd64.deb`, `relay-daemon_<pkgversion>-1_arm64.deb`, `relay-daemon-<pkgversion>-1.x86_64.rpm`, `relay-daemon-<pkgversion>-1.aarch64.rpm` | The relay-daemon's packages: the release binary byte for byte, the hardened unit, the shipped Template catalog and the default Policy. `<pkgversion>` is the version with a prerelease's `-` written `~`, so a prerelease sorts below its release, and then with every `~` written `.` in the file name, because GitHub rewrites such characters in an asset's name (`0.2.0-beta` is `0.2.0.beta` in the file name and `0.2.0~beta` inside the package). |
| `relay_<pkgversion>-1_amd64.deb`, `relay_<pkgversion>-1_arm64.deb`, `relay-<pkgversion>-1.x86_64.rpm`, `relay-<pkgversion>-1.aarch64.rpm` | The Relay's packages, named the same way. |
| `<package>.spdx.json` | An SPDX SBOM for each of the eight packages, listing the dependencies of the binary the package wraps: the Relay's from its Go build info, the daemon's from `Cargo.lock`. |
| `relay_daemon-<version>.tar.gz` | The Ansible role that installs the daemon package on a Node (DI-45). Built from the tagged commit (members sorted, owner 0, the commit's time as every mtime) and checked equal to it, it holds `relay_daemon/` and nothing else. |
| `relay-daemon.service`, `relay-daemon.env.example` | The hardened systemd unit and the example environment file a hand-built install takes, byte-equal to the copies inside the daemon packages (DI-32). |
| `relay.service`, `relay.toml.example` | The Relay's hardened systemd unit and its example configuration file, which a hand-built install takes, byte-equal to the copies inside the Relay packages. |
| `SHA256SUMS` | `sha256sum`-format digests of every file above, bare filenames. Packages carry no signature of their own before v1.0.0 (DI-24, ADR-0033): this file's signature and the provenance attestation over its files cover them. |
| `SHA256SUMS.sigstore.json` | A keyless [cosign](https://docs.sigstore.dev/) bundle signing `SHA256SUMS`. |

Plus generated release notes. Also published, not attached to the Release: the Relay image
`ghcr.io/felag-engineering/relay:<version>` (linux/amd64 and linux/arm64), signed with cosign,
and SLSA build-provenance attestations for the binaries and the image, in GitHub's attestation
store (and, for the image, in the registry). `:latest` follows the highest version tag,
prereleases included (`v0.2.0-rc.1` sorts below `v0.2.0`); a tag pushed below the highest, such
as a backport, does not move it.

Tags with a major version of 0 or with any prerelease component (`v0.*`, `v*-beta`,
`v*-rc.1`, …) publish as **GitHub pre-releases**.

## Naming convention (the contract)

```
<binary>-<version>-<platform>
```

- `<binary>` — `relay-daemon` or `relay` (GLOSSARY.md names; never "agent").
- `<version>` — the tag without the leading `v`. The release workflow's
  **stamped-version-equals-tag guard** fails the release unless both binaries' `--version`
  output equals this exactly, so the filename, the git tag, and what the running binary
  reports are one string by construction. This is the value to pin, and the value the Relay's
  `reach.min_daemon_version` gate compares against (ADR-0014).
- `<platform>` — `linux-<arch>`, with the architecture spelled as Debian and OCI spell it:
  `linux-amd64` and `linux-arm64`, for both binaries. The image's SBOMs use the same
  spelling. The `.deb` and `.rpm` packages follow their own distribution's naming instead
  (`relay_<pkgversion>-1_amd64.deb`, `relay-<pkgversion>-1.x86_64.rpm`, where `<pkgversion>` is
  the version with every `~` written `.` in the file name; see the table above). New
  architectures extend the set without changing the scheme.

There are deliberately no unversioned or "latest" **binary** names: the binaries config
management installs, above all the daemon (ADR-0014), must be pinned to an explicit version,
and an upgrade is an explicit pin change, gated Relay-side only by `reach.min_daemon_version`.
The Relay **image** is outside that rule because no documented deployment installs it by name: every one
pins it by digest (ADR-0033, amended 2026-10-15), `deploy/production` included, so a tag only
helps a person find a release. `:latest` exists for that convenience, and no documented
deployment names it. There is no daemon image, ever (ADR-0033, amended 2026-10-15).

## Verify, then install

An unverified binary dropped onto a privileged fleet is the supply-chain failure this product
exists to argue against. The digest check happens **before** the binary is installed or
executed. The IaC role that distributes the daemon should encode exactly this sequence:

```sh
# Pinned by the operator, in config management — not resolved at install time.
VERSION="0.1.0"
ARTIFACT="relay-daemon-${VERSION}-linux-amd64"
BASE="https://github.com/Felag-Engineering/relay/releases/download/v${VERSION}"

# 1. Fetch the binary, the checksum file and its signature into a staging dir (not the
#    install path).
curl -fsSLO "${BASE}/${ARTIFACT}"
curl -fsSLO "${BASE}/SHA256SUMS"
curl -fsSLO "${BASE}/SHA256SUMS.sigstore.json"

# 2. Verify the signature on SHA256SUMS: it was produced by THIS repository's release
#    workflow, at THIS tag. The identity embeds the repository name, so a repository
#    rename changes it.
cosign verify-blob --bundle SHA256SUMS.sigstore.json \
  --certificate-identity "https://github.com/Felag-Engineering/relay/.github/workflows/release.yml@refs/tags/v${VERSION}" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  SHA256SUMS

# 3. Verify the binary against it BEFORE install. --ignore-missing checks only the files present.
sha256sum --check --ignore-missing SHA256SUMS

# 4. Only a verified binary is installed (atomic: install(1) writes then renames).
install -m 0755 "${ARTIFACT}" /usr/bin/relay-daemon

# 5. Confirm the installed binary self-identifies as the pinned version.
/usr/bin/relay-daemon --version   # "relay-daemon 0.1.0 (commit ..., built ...)"
```

The packages and the role are verified the same way, with the same download, `cosign
verify-blob` and `sha256sum --check --ignore-missing` against the signed `SHA256SUMS`, and only
then installed:

```sh
# A prerelease's "~" is "." in the file name; for a release, the two are the same.
PKGVERSION="${VERSION//-/.}"   # a prerelease "-" is "~" in the package, "." in the file name
DEB="relay-daemon_${PKGVERSION}-1_amd64.deb"
curl -fsSLO "${BASE}/${DEB}"
# ... SHA256SUMS and SHA256SUMS.sigstore.json fetched and verified as in steps 1 to 3 ...
sha256sum --check --ignore-missing SHA256SUMS
apt-get install -y "./${DEB}"      # or: dnf install -y ./relay-daemon-${PKGVERSION}-1.x86_64.rpm
```

The Ansible role is the file `relay_daemon-${VERSION}.tar.gz`: verify it as above, extract it
(`tar -xzf`) into a roles path, and point the role's `relay_daemon_package_dir` at the
directory holding the verified package of the same release. The role installs the package it
finds there, so the pairing of role and package is the operator's, here.

The build-provenance attestation can be checked too, and is stronger on one point: it names
the commit the artifact was built from. **Always pin `--signer-workflow` and `--source-ref`**;
without them any workflow in the repository could satisfy the check.

```sh
gh attestation verify "${ARTIFACT}" --repo Felag-Engineering/relay \
  --signer-workflow Felag-Engineering/relay/.github/workflows/release.yml \
  --source-ref "refs/tags/v${VERSION}"
```

The image is verified against its digest, with the same identity. Verifying it needs **cosign
v3 or later**: its signature is a cosign v3 bundle stored as an OCI referrer, and cosign v2
reports "no signatures found" for it.

```sh
cosign verify ghcr.io/felag-engineering/relay@sha256:<digest> \
  --certificate-identity "https://github.com/Felag-Engineering/relay/.github/workflows/release.yml@refs/tags/v${VERSION}" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

Two hardening rules for the IaC role:

- **Pin the digest itself, not just the version.** `SHA256SUMS` is served from the same origin
  as the binary, so fetching both at install time proves download integrity, not provenance.
  Copy the expected `sha256` line into config management when the pin is updated (a human
  step, once per upgrade) and compare against that. The pinned digest is the primary trust
  anchor; the signature adds provenance (built by this repository's release workflow from
  this tag) and does not replace the pin.
- **Failure is fatal.** A digest mismatch must abort the run and page a human, never retry
  with `--insecure`-style fallbacks or install the unverified file.

The same sequence applies to the `relay` binary on the Relay hosts.

Signing is keyless, so there is no long-lived signing key to hold or rotate. The cost: each
signature writes its metadata (organization, repository, workflow path, tag, commit, artifact
digests) to the **public** Rekor transparency log, permanently.

### The install matrix gates the packages

Every release runs the install matrix (`.github/workflows/install-matrix.yml`, DI-33) on
exactly the packages and the role it is about to attach: the platforms DI-33 lists on both
architectures, the install where systemd is not running, the syscall trace of the packaged unit,
and the Ansible role under a hash-locked ansible-core. The matrix takes the packages and the
role from the release's own artifact and checks each against the `SHA256SUMS` that gets signed;
it rebuilds none of them. The digest of that `SHA256SUMS` is handed from the job that wrote it
to the matrix and to `sign-push`, and each compares it against the file it downloaded before
using it, so an artifact replaced between upload and signing is refused. `sign-push`, the first
job that publishes anything (the Rekor entry, the registry), needs the matrix, so a failing row
publishes nothing. For a flaky row, use "Re-run failed jobs" (see
[Release-cutting discipline](#release-cutting-discipline)).

`sign-push` also refuses to run until the owner has recorded, as repository variables, the
decisions the workflow cannot make for itself: `RELEASE_PUBLIC_REKOR_ACCEPTED`,
`RELEASE_ATTESTATIONS_AVAILABLE`, and `RELEASE_UNIT_SYSCALL_FILTER_SIGNED_OFF`, each `true`. The
last records that the owner has checked the packaged unit's syscall filter by hand on a real
systemd host (DI-3), because the release attaches packages carrying that unit.

## Release-cutting discipline

**Set the license Change Date first.** Each release converts to Apache-2.0 on the
`Change Date` in [LICENSE](../../LICENSE), so the tagged commit must carry a date three years
after the day you cut it. The release workflow checks this before building and fails the
release otherwise; on a pull request or a dispatch it only warns. Update `LICENSE` in the same
PR that bumps `daemon/Cargo.toml`.

**Cut a release by pushing a tag, not from the GitHub UI:**

```sh
git fetch origin && git tag v<version> origin/main && git push origin v<version>
```

The workflow creates the GitHub Release itself, with generated notes and the artifacts
attached. A Release created through the UI also creates the tag, which triggers the workflow;
the workflow uploads into that existing Release, but its notes and title are then whatever was
typed by hand.

**Re-run with "Re-run failed jobs", never "Re-run all jobs".** The GitHub Release step is
idempotent (it uploads into whatever Release exists and replaces same-named assets), but the
image is not reproducible, and a published image version never moves: the push job refuses to
repoint an existing `<version>` tag at a different digest. "Re-run failed jobs" reuses the
already-built image archive, so a failed push or publish continues; "Re-run all jobs" rebuilds
the image and is refused once the version has been pushed. If the tag is wrong, cut a new one.

The image is pushed by digest first; it is signed, attested and verified at that digest, and
only then are `:<version>` and `:latest` created, as the last registry writes, so no version
tag ever points at an unsigned image. A failure after the digest push but before the version
tag leaves an untagged digest in the registry; a failure after the tag leaves a version
without a Release until the re-run completes.

**Bump the deployment pin after each release.** `deploy/production/docker-compose.yml` names
one release's image by version and digest and does not follow `:latest`. Once a tag's run has
passed, a human takes the new version's digest (the sign-and-push job's log names it, and
`docker buildx imagetools inspect ghcr.io/felag-engineering/relay:<version>` shows the index
digest), verifies it with cosign v3 or later exactly as in
[Verify, then install](#verify-then-install) against `refs/tags/v<version>`, and changes the
`image:` line to `ghcr.io/felag-engineering/relay:<version>@sha256:<digest>` in a reviewed pull
request. An unattended run never pins a digest it resolved itself: the pin is a trust anchor,
so a person checks it first, the same human step as the IaC role's pinned digest above. The
stack is pinned to whichever release a human last verified, pre-releases included.

The release jobs cannot be run from a tag by hand: `workflow_dispatch` is refused on a tag
ref, because its dry run stamps a `-0.dev` version. Dispatch from a branch to rehearse
everything except publishing.

The workflow enforces what [version-stamping.md](version-stamping.md) documents: tag
`v<version>` must sit on a clean commit whose `daemon/Cargo.toml` says exactly `<version>`. If
`Cargo.toml` was not bumped, was bumped past the tag, or the tag is not visible in the
checkout, the stamp takes the dev path (`X.Y.Z-0.dev+g<sha>`) and the
**stamped-version-equals-tag guard fails the release** instead of publishing a binary that
misreports itself. The build pins `SOURCE_DATE_EPOCH` to the tagged commit's date so a rebuild
of the same tag reproduces the published digest.

Dev builds stamp the target's numeric core as a `-0.dev` prerelease
(`0.1.0-0.dev+g<sha>[.dirty]`). The leading numeric `0` sorts below any alphabetic prerelease
label under the Relay's comparator (`0.1.0-0.dev < 0.1.0-beta`), so a dev build can never
satisfy a `reach.min_daemon_version` gate set to a prerelease or release target. Prerelease
minimums (e.g. `0.1.0-beta`) are safe to set.

## Reproducing a release

Every release is built twice, on separate runners and from different checkout paths, and the
workflow fails unless both builds hash identically before anything is signed or published.
That proves the build is deterministic for that commit, toolchain and runner-image family, and
independent of the checkout path. It does not prove independence from GitHub's infrastructure
or the toolchain downloads, which both builds share, and says nothing about whether the source
is benign. It is the precondition for an independent rebuild, not a substitute for one.

What makes it hold: the Rust toolchain is an exact stable version, named once in
`release.yml` (`RELEASE_RUST_TOOLCHAIN`) and asserted at build time; `go build -trimpath` with
`CGO_ENABLED=0`; `cargo build --locked`; the checkout and `CARGO_HOME` paths remapped out of
the daemon; and `SOURCE_DATE_EPOCH` pinned to the tagged commit. The recipes are the
Makefile's `build-relay` and `build-daemon-release`, the same for development, CI and release.

To rebuild a release yourself, work from a `git clone` checked out at the tag, **not** a
source archive: the version stamp (`scripts/build-version.sh`) reports the release version
only when the tag is visible on a clean `HEAD`. Use the same pinned toolchain and the runner
image family recorded in the workflow, and set `SOURCE_DATE_EPOCH` to the tagged commit's
committer date. The daemon needs `musl-tools`; `make print-release-daemon-bin` prints where it
lands.

The daemon's and the Relay's `.deb` and `.rpm` packages are built in both passes from the
binaries above, by the nfpm pinned under `tools/nfpm` with every manifest's `mtime` taken from
`SOURCE_DATE_EPOCH`. The workflow fails unless the two passes' packages are byte-identical and
each package's `/usr/bin/relay-daemon` or `/usr/bin/relay` is the release binary byte for byte.
Because both passes run the same nfpm, that proves determinism, not integrity. A separate check
reads every package with `dpkg-deb` and `rpm` and compares it with a reviewed baseline in the
repository (`daemon/packaging/expected/` and `relay/packaging/expected/`):

- the package's identity, computed from the release version and architecture rather than read
  from the package: the whole `.deb` control file, and the `.rpm` name, epoch,
  version-release and architecture;
- the payload listing, with modes, owners and rpm file capabilities, and no setuid or setgid
  entry;
- the maintainer scripts and triggers;
- the declared relationships;
- the files carried from the repository: default Policy, LICENSE, posture document, units,
  environment example, example configuration, the Relay's configuration template and guide,
  and catalog.

It does not check timestamps; the binary's bytes are checked separately. A guarded package is
copied into the release set, named by its own distribution's convention, and listed in
`SHA256SUMS` beside the binaries, with an SBOM each; the install matrix then runs on those
bytes (see [The install matrix gates the packages](#the-install-matrix-gates-the-packages)).

The Ansible role tarball compiles nothing and carries repository files only, so it is not built
twice. It is built from the tagged commit (members sorted, owner 0, every mtime the commit's
time), and the workflow fails unless what the tarball extracts to equals
`daemon/packaging/ansible/relay_daemon/` in the checkout.

The **image is not byte-reproducible** (Alpine's package index and file timestamps float).
What is guaranteed is that its `/usr/local/bin/relay` is the released, rebuild-verified
binary: the workflow reads the OCI archive it is about to push and fails unless that file's
digest equals the one in `SHA256SUMS`, and unless the image runs as `10001:10001`. The Alpine
base is pinned by digest (`docker/relay.Dockerfile`). The packages installed on top of it
(`apk add openssl` in the image; `musl-tools` and `skopeo` on the build runners) are not
version-pinned and float with their distribution repositories; the binary check is what holds
regardless.

## Out of scope (deliberate follow-ups, not omissions)

- **A daemon image.** There is none, ever (ADR-0033, amended 2026-10-15); the daemon reaches
  Nodes through config management.
- **Operator-held signing keys.** Release signing is keyless, which sidesteps the deferred
  key-custody decision (the v0.8.0 operator-signing work). Revisit if a key-based scheme is
  wanted instead.
- **A binary-derived daemon SBOM.** The daemon's SBOM is derived from `Cargo.lock`; embedding
  dependency metadata in the binary (`cargo-auditable`) is the follow-up.
