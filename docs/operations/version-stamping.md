# Version stamping and the daemon-version gate

The semantic version of both binaries is one string, `daemon/Cargo.toml`'s `[package]
version` — it names the release the working tree is developing toward. `make build` and
`make build-daemon-release` derive the build stamp from it with `scripts/build-version.sh`
and stamp it into the `relay` binary (Go `-ldflags -X`) and the relay-daemon (a
`RELAY_BUILD_*` environment triple forwarded by `daemon/build.rs`). A build whose `HEAD`
is the clean, exact `v<version>` tag reports exactly that release version, e.g. `0.0.9`;
every other build — untagged clone, commits after a tag, or a dirty tree — reports it as a
`-dev` prerelease carrying the commit as build metadata, e.g. `0.0.9-dev+g0a0f22f03dcf` or
`0.0.9-dev+g0a0f22f03dcf.dirty`. A build with no stamp at all (a plain `cargo build`, or
`go build` without `-ldflags`) reports `0.0.9-dev` / `0.0.0-unknown` respectively. Both
binaries print their stamp with `--version`; the Relay also logs it at startup and exports
it as the `relay_build_info` gauge on `/metrics`.

The daemon's version is **fleet-visible and load-bearing**. `relay-daemon` sends it as
`Hello.daemon_version`, the Relay records it in the registry (`list_nodes`, the Console),
and it is the sole input to the `min-daemon-version` dispatch gate (ADR-0014): a Node below
the configured minimum still connects, heartbeats, and appears in the registry flagged
`outdated`, but the Job engine refuses to send it Tasks. The Relay compares with
`golang.org/x/mod/semver`, and the `-dev` scheme exists to make that comparison truthful:
`-dev` is a semver **prerelease**, so `0.0.9-dev < 0.0.9` — a dev build of the 0.0.9 line
is not yet 0.0.9, and a Relay requiring `0.0.9` correctly refuses to dispatch to it (the
fail-closed direction). Deriving the version from the *last* tag instead — `git describe`'s
`0.0.9-14-gabc1234` — would invert that: it is a prerelease of `0.0.9`, so a build made
*after* the 0.0.9 release would report as older than it. Dirtiness is likewise expressed by
the `-dev` prerelease and not by the `.dirty` metadata alone, because semver comparison
ignores build metadata entirely — `0.0.9+dirty` compares exactly equal to `0.0.9`.

**Release discipline:** the version in `daemon/Cargo.toml` must equal the tag being cut
(tag `v0.0.9` ⇔ `version = "0.0.9"`), and it should be bumped to the next release
immediately after a tag is cut, so builds off `main` report as prereleases of the *next*
version rather than of the one already shipped. Both directions of that rule are load-bearing
and both fail quietly rather than loudly, so they are guarded: bumping *early* — tagging
`v0.0.9` while `Cargo.toml` already says `0.0.10` — would publish an artifact reporting
`0.0.10-dev+g<sha>`, a prerelease of a version that has not shipped, under the `v0.0.9`
release. `TestReleaseTagMatchesCargoVersion` fails whenever `HEAD` carries a `v*` tag that
is not `v<Cargo.toml version>`; it skips in a tagless clone, so the release job must
additionally reject any artifact whose stamped version contains `-dev`. The daemon is never
upgraded by the Relay — upgrades flow only through the customer's config management
(ADR-0014, invariant #14) — so this version string, and the registry view built from it, is
how an operator sees upgrade progress across the fleet.

**Reproducibility limit:** two builds of the same commit are byte-identical only if they
carry the same stamp, and the stamp's build date is the *wall-clock* UTC date. A rebuild of
the same tag on a different day therefore produces a different binary hash. Pin
`SOURCE_DATE_EPOCH` (honoured by `scripts/build-version.sh`) in any pipeline that needs
rebuild-and-compare verification or artifact signing.

**Version history:** the daemon's reported version jumps from `0.0.1` to the `0.0.9` line
in v0.0.9 — `Cargo.toml` had never been bumped, so every daemon reported `0.0.1` regardless
of what it actually was. The jump is safe for existing deployments: `min-daemon-version`
defaults to empty (gate off, no Node is ever `outdated`), and no deployment could have set
it above `0.0.1` without having frozen dispatch to its entire fleet already.
