/// Build-stamp variables re-exported from the ambient environment into the
/// crate's compile-time environment (issue #249).
///
/// The values themselves are derived by `scripts/build-version.sh` and passed
/// in by the `Makefile`; this build script only forwards them. Forwarding is
/// what makes them *tracked*: `cargo:rerun-if-env-changed` re-runs this script
/// when the stamp changes, and the resulting `cargo:rustc-env` change is what
/// actually recompiles the crate so `option_env!` in `src/version.rs` cannot
/// serve a stale stamp. Reading the ambient env from `option_env!` alone would
/// not be tracked by cargo. An unset (or empty) variable is simply not
/// forwarded — `src/version.rs` then falls back to its Cargo.toml-derived
/// `-0.dev` version, so a plain `cargo build` needs no environment at all.
const BUILD_STAMP_VARS: [&str; 3] = [
    "RELAY_BUILD_VERSION",
    "RELAY_BUILD_COMMIT",
    "RELAY_BUILD_DATE",
];

fn main() -> Result<(), Box<dyn std::error::Error>> {
    for var in BUILD_STAMP_VARS {
        println!("cargo:rerun-if-env-changed={var}");
        match std::env::var(var) {
            Ok(value) if !value.is_empty() => println!("cargo:rustc-env={var}={value}"),
            _ => {}
        }
    }

    Ok(())
}
