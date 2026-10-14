//! Build identity for the relay-daemon binary (ADR-0014).
//!
//! # Why this module exists
//!
//! `Hello.daemon_version` is not decoration: it is the sole input to the
//! Relay's minimum-daemon-version dispatch gate — the *only* lever the Relay
//! has over daemon upgrades, since the daemon never self-upgrades and the
//! Relay never pushes binaries (ADR-0014, invariant 14). The Relay validates
//! and orders that string with `golang.org/x/mod/semver`
//! (`relay/internal/registry/version.go`), so whatever this module returns
//! must be (a) a valid semver version and (b) ordered the way an operator
//! expects.
//!
//! # The scheme
//!
//! The **semantic** version is `Cargo.toml`'s `version` — the release this
//! working tree is developing toward, possibly itself a prerelease
//! (`0.1.0-beta`). Git supplies *identity* (commit, dirtiness), never
//! ordering. Dev builds report the target's **numeric core** (`X.Y.Z`, any
//! prerelease suffix dropped) with the `-0.dev` prerelease marker:
//!
//! | build | reported version |
//! |---|---|
//! | HEAD is the clean, exact `v<Cargo.toml version>` tag | `0.0.9` (or `0.1.0-beta`, exactly the target) |
//! | any other stamped build (untagged, post-tag, or dirty tree) | `0.0.9-0.dev+g<sha>[.dirty]` |
//! | unstamped (`cargo build` with no `RELAY_BUILD_*` env) | `0.0.9-0.dev` |
//!
//! `-0.dev` is a semver **prerelease** whose *first identifier is numeric*,
//! and semver orders every numeric identifier below every alphanumeric one —
//! so a dev build sorts strictly *below* the release it precedes even when
//! that release is itself a prerelease: `0.0.9-0.dev < 0.0.9` and
//! `0.1.0-0.dev < 0.1.0-beta < 0.1.0`. That is the truthful ordering: a build
//! of the 0.0.9 line that is not the 0.0.9 tag is not yet 0.0.9, and a Relay
//! configured with `min-daemon-version = 0.0.9` correctly refuses to dispatch
//! to it (fail-closed direction). Any further identifiers must stay *after*
//! `0.dev` so the leading numeric identifier keeps deciding the order.
//!
//! The original scheme appended `-dev` to the full target and
//! was fail-**open** for prerelease targets: `0.1.0-beta-dev` is a single
//! identifier lexically *greater* than `beta`, so an unreleased dev build
//! reported as newer than `0.1.0-beta` and passed a `min-daemon-version =
//! 0.1.0-beta` gate. The numeric marker replaced it — one
//! rule for plain and prerelease targets alike, verified by executing the
//! Relay's real comparator (`golang.org/x/mod/semver`) in
//! `relay/internal/registry/daemon_version_contract_test.go`.
//!
//! Two further semver behaviours drove this and rule out the obvious
//! alternative:
//!
//! 1. **A prerelease sorts below its release.** `git describe` after tag
//!    `v0.0.9` yields `0.0.9-14-gabc1234` — a *prerelease of 0.0.9* — so a
//!    build made 14 commits **after** the release would report as *older*
//!    than that release. Deriving from the last tag is therefore backwards;
//!    deriving from the version being developed toward is not.
//! 2. **Build metadata is ignored when comparing.** `0.0.9+dirty` compares
//!    exactly equal to `0.0.9`, so dirtiness must never be expressed as
//!    metadata alone. Here a dirty tree forces the `-0.dev` prerelease, which
//!    *is* comparable; the `+g<sha>[.dirty]` suffix carries only identity —
//!    fleet-visible in the registry, deliberately invisible to the gate.
//!
//! The stamp is produced by `scripts/build-version.sh` and passed in by the
//! `Makefile`; `build.rs` re-exports it as a tracked `rustc-env` so a changed
//! stamp actually recompiles the crate. Nothing here shells out at runtime.

/// Version reported when the build was not stamped — a plain `cargo build`
/// with no `RELAY_BUILD_VERSION` in the environment. The `-0.dev` prerelease
/// of the `Cargo.toml` version's numeric core, so an unstamped developer
/// build is honestly ordered below the release it is heading for — including
/// below a prerelease target (`0.1.0-0.dev < 0.1.0-beta`). Built from the
/// MAJOR/MINOR/PATCH env pieces, not `CARGO_PKG_VERSION`, precisely so a
/// prerelease suffix on the target is dropped at compile time.
const DEV_VERSION: &str = concat!(
    env!("CARGO_PKG_VERSION_MAJOR"),
    ".",
    env!("CARGO_PKG_VERSION_MINOR"),
    ".",
    env!("CARGO_PKG_VERSION_PATCH"),
    "-0.dev"
);

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

    /// The numeric core of the Cargo.toml version: `X.Y.Z` with any
    /// prerelease suffix dropped — what dev builds report ahead of `-0.dev`.
    fn cargo_core() -> String {
        format!(
            "{}.{}.{}",
            env!("CARGO_PKG_VERSION_MAJOR"),
            env!("CARGO_PKG_VERSION_MINOR"),
            env!("CARGO_PKG_VERSION_PATCH")
        )
    }

    /// The dev marker must be `<core>-0.dev`: the numeric core (never the
    /// full, possibly-prerelease target) plus the numeric-first `0.dev`
    /// prerelease. Appending to the full target is exactly the #261 defect —
    /// `0.1.0-beta-dev` sorts ABOVE `0.1.0-beta`.
    #[test]
    fn dev_version_is_the_numeric_dev_prerelease_of_the_cargo_core() {
        assert_eq!(DEV_VERSION, format!("{}-0.dev", cargo_core()));
        let prerelease = DEV_VERSION
            .split_once('-')
            .expect("DEV_VERSION carries a prerelease")
            .1;
        assert!(
            prerelease.starts_with("0."),
            "the dev prerelease {prerelease:?} must LEAD with the numeric identifier `0`, \
             or it stops sorting below alphanumeric prerelease targets (issue #261)"
        );
    }

    /// The load-bearing invariant: whatever the build stamps, the reported
    /// version is either exactly `Cargo.toml`'s version (a release build) or
    /// the `-0.dev` prerelease of its numeric core (any dev build, stamped or
    /// not). This also catches a `Makefile`/`scripts/build-version.sh` stamp
    /// that drifted away from `Cargo.toml` — or away from this scheme.
    #[test]
    fn reported_version_is_the_release_or_its_numeric_dev_prerelease() {
        let base = env!("CARGO_PKG_VERSION");
        let dev = format!("{}-0.dev", cargo_core());
        let v = version();
        assert!(
            v == base || v == dev || v.starts_with(&format!("{dev}+")),
            "reported version {v:?} is neither the Cargo.toml version {base:?} \
             nor the {dev:?} dev prerelease of its numeric core"
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
