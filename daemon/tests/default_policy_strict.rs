//! The shipped default Policy passes its own `policy check --strict` with the
//! shipped Template catalog loaded (DI-28; ADR-0022, amended 2026-10-16).
//!
//! It runs on 0644/0755 copies, as `dev_fleet_fixtures.rs` does: `--templates`
//! refuses a group- or world-writable file, and a checkout's modes follow the
//! cloner's umask.

// Integration tests can only drive the bin-only daemon through its compiled binary,
// so spawning it is the point; clippy.toml's spawn ban is for the daemon's own code.
#![allow(clippy::disallowed_methods)]

mod common;

use common::TempDir;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

fn files_under(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(dir)
        .unwrap_or_else(|e| panic!("read {}: {e}", dir.display()))
        .flatten()
    {
        let path = entry.path();
        if path.is_dir() {
            files_under(&path, out);
        } else {
            out.push(path);
        }
    }
}

fn chmod(path: &Path, mode: u32) {
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
        .unwrap_or_else(|e| panic!("chmod {mode:o} {}: {e}", path.display()));
}

// Proves DI-28.
#[test]
fn default_policy_passes_strict_with_catalog() {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let tmp = TempDir::new("default-strict");
    std::fs::create_dir_all(tmp.path()).expect("create scratch dir");

    let shipped_templates = manifest.join("packaging/templates.d");
    let mut shipped = Vec::new();
    files_under(&shipped_templates, &mut shipped);
    assert_eq!(
        shipped,
        [shipped_templates.join("relay-read/catalog.toml")],
        "a new file in packaging/templates.d must be copied here too"
    );

    let policy = tmp.path().join("policy.default.toml");
    let templates = tmp.path().join("templates.d");
    let pack = templates.join("relay-read");
    std::fs::copy(manifest.join("policy.default.toml"), &policy)
        .unwrap_or_else(|e| panic!("copy policy.default.toml: {e}"));
    std::fs::create_dir_all(&pack).expect("create templates.d/relay-read");
    std::fs::copy(&shipped[0], pack.join("catalog.toml"))
        .unwrap_or_else(|e| panic!("copy catalog.toml: {e}"));

    chmod(&policy, 0o644);
    chmod(&pack.join("catalog.toml"), 0o644);
    for dir in [tmp.path(), &templates, &pack] {
        chmod(dir, 0o755);
    }

    let bin = env!("CARGO_BIN_EXE_relay-daemon");
    let output = Command::new(bin)
        .args(["policy", "check"])
        .arg(&policy)
        .arg("--templates")
        .arg(&templates)
        .arg("--strict")
        // The probes then target the packaged paths the default's denies name.
        .env_remove("RELAY_POLICY_PATH")
        .env_remove("RELAY_STATE_DIR")
        .env_remove("RELAY_TEMPLATE_DIR")
        .current_dir(std::env::temp_dir())
        .output()
        .unwrap_or_else(|e| panic!("spawn {bin} policy check: {e}"));

    let mut combined = String::from_utf8_lossy(&output.stdout).into_owned();
    combined.push_str(&String::from_utf8_lossy(&output.stderr));
    let flagged = combined
        .lines()
        .any(|l| l.starts_with("warning:") || l.starts_with("error:"));
    assert!(
        output.status.code() == Some(0) && !flagged,
        "the shipped default must pass `policy check --strict` with the shipped catalog. \
         Fix the default or the lint's targets — do not silence the finding; R37 in \
         docs/security/threat-model.md records the one read the default accepts:\n{combined}"
    );
}
