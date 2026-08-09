# Release artifacts: naming, pinning, and verify-then-install

Pushing a `v*` tag runs `.github/workflows/release.yml`, which builds both binaries
stamped per [version-stamping.md](version-stamping.md), verifies the stamp, and publishes
a GitHub Release. The daemon reaches the fleet only through the customer's config
management (ADR-0014: the Relay never pushes binaries), so **the artifact set below is the
contract config management pins against**. Change the convention here and in the workflow
together.

## What a release contains

For tag `v<version>` (e.g. `v0.0.9`, `v0.1.0-beta`), the GitHub Release carries:

| File | What it is |
|---|---|
| `relay-daemon-<version>-x86_64-unknown-linux-musl` | The relay-daemon, statically linked (musl, ADR-0007). No libc or distro expectations; drops onto any x86_64 Linux Node. |
| `relay-<version>-x86_64-unknown-linux-gnu` | The Relay server binary (glibc-linked). |
| `SHA256SUMS` | `sha256sum`-format digests of both binaries, bare filenames. |

plus generated release notes. Tags with a major version of 0 or with any prerelease
component (`v0.*`, `v*-beta`, `v*-rc.1`, …) publish as **GitHub pre-releases**.

## Naming convention (the contract)

```
<binary>-<version>-<target-triple>
```

- `<binary>` — `relay-daemon` or `relay` (CONTEXT.md names; never "agent").
- `<version>` — the tag without the leading `v`. The release workflow's
  **stamped-version-equals-tag guard** fails the release unless both binaries'
  `--version` output equals this exactly, so the filename, the git tag, and what the
  running binary reports are one string by construction. This is the value to pin, and
  the value the Relay's `min-daemon-version` gate compares against (ADR-0014).
- `<target-triple>` — the Rust-style target the binary was built for. Currently
  `x86_64-unknown-linux-musl` (daemon) and `x86_64-unknown-linux-gnu` (relay); new
  architectures extend the set without changing the scheme.

Unversioned or "latest" artifact names are deliberately absent: config management must
pin an explicit version, and an upgrade is an explicit pin change (rolled out by the
customer's config management, gated Relay-side only by `min-daemon-version`).

## Verify, then install

An unverified binary drop onto a privileged fleet is the supply-chain failure mode this
product exists to argue against. The digest check happens **before** the binary is
installed or executed — not after, not "eventually". The IaC role that distributes the
daemon should encode exactly this sequence:

```sh
# Pinned by the operator, in config management — not resolved at install time.
VERSION="0.0.9"
ARTIFACT="relay-daemon-${VERSION}-x86_64-unknown-linux-musl"
BASE="https://github.com/Felag-Engineering/gleipnir-relay/releases/download/v${VERSION}"

# 1. Fetch the binary and the checksum file into a staging dir (not the install path).
curl -fsSLO "${BASE}/${ARTIFACT}"
curl -fsSLO "${BASE}/SHA256SUMS"

# 2. Verify BEFORE install. --ignore-missing checks only the files present.
sha256sum --check --ignore-missing SHA256SUMS

# 3. Only a verified binary is installed (atomic: install(1) writes then renames).
install -m 0755 "${ARTIFACT}" /usr/local/sbin/relay-daemon

# 4. Confirm the installed binary self-identifies as the pinned version.
/usr/local/sbin/relay-daemon --version   # "relay-daemon 0.0.9 (commit ..., built ...)"
```

Two hardening notes for the IaC role:

- **Pin the digest itself, not just the version.** `SHA256SUMS` is served from the same
  origin as the binary, so fetching both at install time only proves download integrity,
  not provenance. Copy the expected `sha256` line into config management when the pin is
  updated (a human step, done once per upgrade) and compare against that. Until artifact
  signing exists (below), the operator's copy of the digest is the trust anchor.
- **Failure is fatal.** A digest mismatch must abort the run and page a human, never
  retry with `--insecure`-style fallbacks or install the unverified file.

The same sequence applies to the `relay` binary on the (far fewer) Relay hosts.

## Release-cutting discipline

The workflow enforces what [version-stamping.md](version-stamping.md) documents: tag
`v<version>` must sit on a clean commit whose `daemon/Cargo.toml` says exactly
`<version>`. If `Cargo.toml` was not bumped, or was bumped past the tag, or the tag is
not visible in the checkout, the stamp takes the dev path (`X.Y.Z-0.dev+g<sha>`, see
below) and the **stamped-version-equals-tag guard fails the release** instead of
publishing a binary that misreports itself. The build also pins `SOURCE_DATE_EPOCH` to
the tagged commit's date so a rebuild of the same tag reproduces the published digest.

Dev builds stamp the target's numeric core as a `-0.dev` prerelease
(`0.1.0-0.dev+g<sha>[.dirty]`). The leading numeric `0` sorts below any alphabetic
prerelease label under the Relay's comparator (`0.1.0-0.dev < 0.1.0-beta`, issue #261),
so a dev build can never satisfy a `min-daemon-version` gate set to a prerelease or
release target — prerelease minimums (e.g. `0.1.0-beta`) are safe to set.

## Out of scope (deliberate follow-ups, not omissions)

- **Container images.** The dev-fleet Dockerfiles are dev-only (and build unstamped, on
  purpose); no image is published.
- **SBOM generation.**
- **cosign/sigstore artifact signing.** Signing is the next tier above checksums —
  digests prove integrity, signatures prove provenance. Revisit alongside the v0.8.0
  operator-signing work: the key-custody question is the same one, and answering it twice
  independently would be worse than answering it once.
