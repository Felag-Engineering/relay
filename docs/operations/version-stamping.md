# Version stamping and the daemon-version gate

Both binaries take their semantic version from one string, `daemon/Cargo.toml`'s `[package]
version`. It names the release the working tree is developing toward, and may itself be a
prerelease (`0.1.0-beta`). `make build` and `make build-daemon-release` derive the build stamp
from it with `scripts/build-version.sh` and stamp it into the `relay` binary (Go
`-ldflags -X`) and the relay-daemon (a `RELAY_BUILD_*` environment triple forwarded by
`daemon/build.rs`).

| Build | Reports |
|---|---|
| `HEAD` is the clean, exact `v<version>` tag | exactly that version, e.g. `0.1.0` or `0.1.0-beta` |
| Any other stamped build (untagged clone, commits after a tag, dirty tree) | the target's **numeric core** (`X.Y.Z`, any prerelease suffix dropped) as a `-0.dev` prerelease with the commit as build metadata, e.g. `0.1.0-0.dev+g0a0f22f03dcf` or `0.1.0-0.dev+g0a0f22f03dcf.dirty` |
| No stamp: a plain `cargo build` | `<numeric core>-0.dev`, e.g. `0.1.0-0.dev` |
| No stamp: `go build` without `-ldflags` | `0.0.0-unknown` |

Both binaries print their stamp with `--version`; the Relay also logs it at startup and exports
it as the `relay_build_info` gauge on `/metrics`.

## Why `-0.dev`

The daemon's version is **fleet-visible and load-bearing**. `relay-daemon` sends it as
`Hello.daemon_version`, the Relay records it in the registry (`list_nodes`, the Console), and it
is the sole input to the `reach.min_daemon_version` dispatch gate (ADR-0014). A Node below the
minimum still connects, heartbeats, and appears in the registry flagged `outdated`, but the Job
engine refuses to send it Tasks.

The Relay compares with `golang.org/x/mod/semver`. `0.dev` is a semver **prerelease** whose
leading identifier is numeric, and semver orders numeric identifiers below alphanumeric ones,
so a dev build sorts strictly below the release it precedes, plain or prerelease:
`0.1.0-0.dev < 0.1.0-beta < 0.1.0`. A Relay requiring `0.1.0` (or `0.1.0-beta`) refuses to
dispatch to a dev build of that line: the fail-closed direction. Any further identifiers (a git
suffix, say) must stay *after* `0.dev`, so the leading numeric identifier keeps deciding.

Two other shapes fail:

- **Appending `-dev` to the full target** inverts the gate for a prerelease target, fail-open:
  `beta-dev` is one identifier lexically greater than `beta`, so `0.1.0-beta-dev > 0.1.0-beta`
  and an unreleased dev daemon would pass a `0.1.0-beta` gate. Dev builds therefore drop the
  target's prerelease suffix rather than append to it.
- **Deriving the version from the last tag** (`git describe`'s `0.1.0-14-gabc1234`) reports a
  build made *after* the 0.1.0 release as a prerelease of 0.1.0, so older than it.

Dirtiness is expressed by the `-0.dev` prerelease, not by the `.dirty` metadata alone, because
semver ignores build metadata: `0.1.0+dirty` compares equal to `0.1.0`.

The ordering is asserted by *executing* the Relay's real comparator:
`relay/internal/registry/daemon_version_contract_test.go`
(`TestNumericDevMarkerSortsBelowEveryShippableBase`) pins `dev(base) < base` for every base
this project intends to ship, the `0.1.0-0.dev < 0.1.0-beta < 0.1.0` chain, and the inversion
above.

## Release discipline

The version in `daemon/Cargo.toml` must equal the tag being cut (tag `v0.1.0` ⇔
`version = "0.1.0"`). Bump it to the next release immediately after a tag is cut, so builds off
`main` report as prereleases of the *next* version rather than the one already shipped.

Both directions fail quietly, so both are guarded. Bumping *early* (tagging `v0.1.0` while
`Cargo.toml` already says `0.1.1`) would publish an artifact reporting `0.1.1-0.dev+g<sha>`
under the `v0.1.0` release. `TestReleaseTagMatchesCargoVersion` fails whenever `HEAD` carries a
`v*` tag that is not `v<Cargo.toml version>`; it skips in a tagless clone, so the release
job's stamped-version-equals-tag guard ([release-artifacts.md](release-artifacts.md)) also
rejects any artifact whose stamp is not the tag, a `-0.dev` one included.

The Relay never upgrades the daemon; upgrades flow only through the customer's config
management (ADR-0014, invariant 14). This version string, and the registry view built from it,
is how an operator sees upgrade progress across the fleet.

## Reproducibility

Two builds of the same commit are byte-identical only if they carry the same stamp, and the
stamp's build date is the *wall-clock* UTC date, so a rebuild on a different day produces a
different hash. Pin `SOURCE_DATE_EPOCH` (honoured by `scripts/build-version.sh`) in any pipeline
that needs rebuild-and-compare verification or artifact signing. Release builds do, and also
pin the Rust toolchain, build with `-trimpath` / `--locked`, and remap the checkout and
`CARGO_HOME` paths out of the daemon; `release.yml` builds every release twice from different
paths and fails unless both are byte-identical
([release-artifacts.md](release-artifacts.md#reproducing-a-release)).
