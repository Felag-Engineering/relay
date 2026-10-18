//! The daemon's exit rule (the daemon half of DI-25). It exits 0 with
//! one log line only when the state directory holds no identity file at all and
//! `RELAY_JOIN` is unset or empty. A malformed `RELAY_JOIN`, a partial identity,
//! or an identity with no Relay address from either source exits non-zero, so a
//! broken Node shows as failed and `Restart=on-failure` never mistakes it for an
//! idle one.
//!
//! Drives the compiled binary, like `shutdown_signal.rs`, with a cleared
//! environment so nothing from the test runner reaches it.

// Spawning the compiled binary is the point; clippy.toml's spawn ban is for the
// daemon's own code.
#![allow(clippy::disallowed_methods)]

mod common;

use common::TempDir;
use std::path::Path;
use std::process::{Command, Output, Stdio};

/// Runs the daemon against `state` with `RUST_LOG=info` plus `extra` env.
fn run(state: &Path, extra: &[(&str, &str)]) -> Output {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_relay-daemon"));
    cmd.env_clear()
        .env("RELAY_STATE_DIR", state)
        .env("RELAY_POLICY_PATH", state.join("no-such-policy.toml"))
        .env("RUST_LOG", "info")
        .stdin(Stdio::null());
    for (k, v) in extra {
        cmd.env(k, v);
    }
    cmd.output().expect("spawn relay-daemon")
}

/// A self-signed identity in the on-disk layout `load_identity` expects; with
/// `only` set, just those of the four files.
fn seed_identity(dir: &Path, only: Option<&[&str]>) {
    std::fs::create_dir_all(dir).expect("create state dir");
    let kp = rcgen::KeyPair::generate().expect("keygen");
    let cert = rcgen::CertificateParams::new(vec!["test-node".to_string()])
        .expect("params")
        .self_signed(&kp)
        .expect("self-signed")
        .pem();
    let files = [
        ("key.pem", kp.serialize_pem()),
        ("cert.pem", cert.clone()),
        ("ca_bundle.pem", cert),
        ("node_id", "test-node-id".to_string()),
    ];
    for (name, body) in files {
        if only.is_none_or(|o| o.contains(&name)) {
            std::fs::write(dir.join(name), body).expect("write identity file");
        }
    }
}

#[test]
fn unconfigured_node_exits_zero() {
    let state = TempDir::new("exit-unconfigured");
    std::fs::create_dir_all(state.path()).expect("create state dir");

    for join in [None, Some("")] {
        let extra: Vec<(&str, &str)> = join.map(|j| ("RELAY_JOIN", j)).into_iter().collect();
        let out = run(state.path(), &extra);
        assert!(
            out.status.success(),
            "an unconfigured Node exits 0 (RELAY_JOIN {join:?}), got {:?}; stderr: {}",
            out.status,
            String::from_utf8_lossy(&out.stderr)
        );
        let stdout = String::from_utf8_lossy(&out.stdout);
        let lines: Vec<&str> = stdout.lines().filter(|l| !l.trim().is_empty()).collect();
        assert_eq!(lines.len(), 1, "exactly one log line, got: {stdout}");
        assert!(lines[0].contains("RELAY_JOIN"), "{}", lines[0]);
    }
    // Nothing was written: no identity, no address, no dedup store.
    let entries: Vec<_> = std::fs::read_dir(state.path()).unwrap().collect();
    assert!(entries.is_empty(), "an unconfigured start writes nothing");
}

#[test]
fn malformed_join_exits_nonzero() {
    let state = TempDir::new("exit-malformed-join");
    std::fs::create_dir_all(state.path()).expect("create state dir");
    let secret = "glp_join_not!valid tok-should-not-print";
    let out = run(state.path(), &[("RELAY_JOIN", secret)]);
    assert!(!out.status.success(), "got {:?}", out.status);
    let all = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        all.contains("RELAY_JOIN"),
        "the refusal names RELAY_JOIN: {all}"
    );
    assert!(
        !all.contains("tok-should-not-print"),
        "the input is never echoed: {all}"
    );
}

#[test]
fn partial_identity_exits_nonzero() {
    let state = TempDir::new("exit-partial-identity");
    seed_identity(state.path(), Some(&["key.pem", "node_id"]));
    let out = run(state.path(), &[("RELAY_ADDR", "https://127.0.0.1:1")]);
    assert!(!out.status.success(), "got {:?}", out.status);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("partial identity"), "stderr: {stderr}");
    assert!(
        stderr.contains("cert.pem") && stderr.contains("ca_bundle.pem"),
        "stderr: {stderr}"
    );
}

#[test]
fn identity_without_address_exits_nonzero() {
    let state = TempDir::new("exit-no-address");
    seed_identity(state.path(), None);
    // Neither RELAY_ADDR nor a persisted address; a join string is inert.
    let out = run(state.path(), &[]);
    assert!(
        !out.status.success(),
        "an identity with no address must exit non-zero, got {:?}",
        out.status
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("RELAY_ADDR"), "stderr: {stderr}");
}
