//! Build identity for the relay-daemon binary (issue #249, ADR-0014).
//!
//! # Why this module exists
//!
//! `Hello.daemon_version` is not decoration: it is the sole input to the
//! Relay's minimum-daemon-version dispatch gate — the *only* lever the Relay
//! has over daemon upgrades, since the daemon never self-upgrades and the
//! Relay never pushes binaries (ADR-0014, invariant #14). The Relay validates
//! and orders that string with `golang.org/x/mod/semver`
//! (`relay/internal/registry/version.go`), so whatever this module returns
//! must be (a) a valid semver version and (b) ordered the way an operator
//! expects.
//!
//! # The scheme
//!
//! The **semantic** version is `Cargo.toml`'s `version` — the release this
//! working tree is developing toward. Git supplies *identity* (commit,
//! dirtiness), never ordering.
//!
//! | build | reported version |
//! |---|---|
//! | HEAD is the clean, exact `v<Cargo.toml version>` tag | `0.0.9` |
//! | any other stamped build (untagged, post-tag, or dirty tree) | `0.0.9-dev+g<sha>[.dirty]` |
//! | unstamped (`cargo build` with no `RELAY_BUILD_*` env) | `0.0.9-dev` |
//!
//! The `-dev` suffix is a semver **prerelease**, so a dev build sorts strictly
//! *below* the release it precedes (`0.0.9-dev < 0.0.9`). That is the truthful
//! ordering: a build of the 0.0.9 line that is not the 0.0.9 tag is not yet
//! 0.0.9, and a Relay configured with `min-daemon-version = 0.0.9` correctly
//! refuses to dispatch to it (fail-closed direction).
//!
//! Two semver behaviours drove this and rule out the obvious alternative:
//!
//! 1. **A prerelease sorts below its release.** `git describe` after tag
//!    `v0.0.9` yields `0.0.9-14-gabc1234` — a *prerelease of 0.0.9* — so a
//!    build made 14 commits **after** the release would report as *older*
//!    than that release. Deriving from the last tag is therefore backwards;
//!    deriving from the version being developed toward is not.
//! 2. **Build metadata is ignored when comparing.** `0.0.9+dirty` compares
//!    exactly equal to `0.0.9`, so dirtiness must never be expressed as
//!    metadata alone. Here a dirty tree forces the `-dev` prerelease, which
//!    *is* comparable; the `+g<sha>[.dirty]` suffix carries only identity —
//!    fleet-visible in the registry, deliberately invisible to the gate.
//!
//! The stamp is produced by `scripts/build-version.sh` and passed in by the
//! `Makefile`; `build.rs` re-exports it as a tracked `rustc-env` so a changed
//! stamp actually recompiles the crate. Nothing here shells out at runtime.

/// Version reported when the build was not stamped — a plain `cargo build`
/// with no `RELAY_BUILD_VERSION` in the environment. A prerelease of the
/// version in `Cargo.toml`, so an unstamped developer build is honestly
/// ordered below the release it is heading for.
const DEV_VERSION: &str = concat!(env!("CARGO_PKG_VERSION"), "-dev");

/// Placeholder for the git identity fields of an unstamped build.
const UNKNOWN: &str = "unknown";

/// Reads a build-stamp value injected by `build.rs`, treating an empty value
/// as absent so an accidentally-empty env var can never produce an invalid
/// version string on the wire.
macro_rules! stamp {
    ($name:literal, $fallback:expr) => {
        match option_env!($name) {
            Some(v) if !v.is_empty() => v,
            _ => $fallback,
        }
    };
}

/// The daemon's reported version: the string sent as `Hello.daemon_version`
/// and compared by the Relay's ADR-0014 minimum-version gate.
///
/// Always begins with `Cargo.toml`'s version — see the module docs for the
/// full scheme.
pub fn version() -> &'static str {
    stamp!("RELAY_BUILD_VERSION", DEV_VERSION)
}

/// The git commit this binary was built from, or `"unknown"` when unstamped.
/// Identity only — never compared, never sent as `daemon_version`.
pub fn commit() -> &'static str {
    stamp!("RELAY_BUILD_COMMIT", UNKNOWN)
}

/// The UTC date this binary was built (`YYYY-MM-DD`), or `"unknown"` when
/// unstamped.
pub fn build_date() -> &'static str {
    stamp!("RELAY_BUILD_DATE", UNKNOWN)
}

/// The one-line human banner printed by `relay-daemon --version`.
pub fn banner() -> String {
    format!(
        "relay-daemon {} (commit {}, built {})",
        version(),
        commit(),
        build_date()
    )
}

/// `relay-daemon --version` — a fully offline, synchronous subcommand, the
/// same seam as `policy check` and `dump-operation-schema`: no Config, no
/// identity, no network, and no tracing (it runs before the subscriber is
/// installed, so it prints directly to stdout). Returns the process exit code.
pub fn run() -> i32 {
    println!("{}", banner());
    0
}

#[cfg(test)]
mod tests {
    use super::{banner, build_date, commit, run, version, DEV_VERSION};

    #[test]
    fn dev_version_is_a_prerelease_of_the_cargo_version() {
        assert_eq!(DEV_VERSION, format!("{}-dev", env!("CARGO_PKG_VERSION")));
    }

    /// The load-bearing invariant: whatever the build stamps, the reported
    /// version's semantic core is `Cargo.toml`'s version. This holds on both
    /// paths — unstamped (`X-dev`) and stamped (`X` or `X-dev+g<sha>`) — so it
    /// also catches a `Makefile`/`scripts/build-version.sh` stamp that drifted
    /// away from `Cargo.toml`.
    #[test]
    fn reported_version_starts_with_the_cargo_version() {
        let base = env!("CARGO_PKG_VERSION");
        let v = version();
        assert!(
            v == base || v.starts_with(&format!("{base}-")),
            "reported version {v:?} is not the Cargo.toml version {base:?} or a prerelease of it"
        );
    }

    /// Structural semver check on the daemon side. The authoritative check is
    /// the Relay-side `golang.org/x/mod/semver` gate — cross-checked in
    /// `relay/internal/registry/daemon_version_contract_test.go` — but a
    /// malformed stamp should not need a Go test run to surface.
    #[test]
    fn reported_version_is_structurally_semver() {
        // MAJOR.MINOR.PATCH[-prerelease][+build], per semver.org.
        let re = regex::Regex::new(
            r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?$",
        )
        .expect("static regex must compile");
        let v = version();
        assert!(re.is_match(v), "reported version {v:?} is not valid semver");
    }

    #[test]
    fn identity_fields_are_never_empty() {
        assert!(!commit().is_empty());
        assert!(!build_date().is_empty());
    }

    #[test]
    fn banner_carries_version_commit_and_date() {
        let b = banner();
        assert!(b.starts_with("relay-daemon "));
        for part in [version(), commit(), build_date()] {
            assert!(b.contains(part), "banner {b:?} is missing {part:?}");
        }
    }

    #[test]
    fn run_exits_zero() {
        assert_eq!(run(), 0);
    }
}
