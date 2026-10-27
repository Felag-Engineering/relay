//! The daemon's exit rule (the daemon half of DI-25). The start has two
//! outcomes: an identity connects, and no identity file at all exits 0 with one
//! log line and dials nothing. A partial identity, an identity with no Relay
//! address from either source, or a set `RELAY_JOIN` (it is not a setting and is
//! refused by name) exits non-zero, so a broken Node shows as failed and
//! `Restart=on-failure` never mistakes it for an idle one. So does a state
//! directory that is group- or world-writable, refused by path before anything
//! in it is read.
//!
//! Drives the compiled binary, like `shutdown_signal.rs`, with a cleared
//! environment so nothing from the test runner reaches it.

// Spawning the compiled binary is the point; clippy.toml's spawn ban is for the
// daemon's own code.
#![allow(clippy::disallowed_methods)]

mod common;

use common::TempDir;
use std::ffi::OsStr;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::process::{Command, Output, Stdio};

/// A well-formed join string, so a test can tell "the join string was ignored"
/// from "it was refused".
fn valid_join() -> String {
    relay_transport::join_string::JoinString::new(
        "relay.example:7654".to_string(),
        [7u8; 32],
        "tok-test".to_string(),
    )
    .encode()
    .expect("encode join string")
}

/// Runs the daemon against `state` with `RUST_LOG=info` plus `extra` env.
fn run<V: AsRef<OsStr>>(state: &Path, extra: &[(&str, V)]) -> Output {
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

// Proves EN-33.
#[test]
fn unconfigured_node_exits_zero() {
    let state = TempDir::new("exit-unconfigured");
    std::fs::create_dir_all(state.path()).expect("create state dir");

    let out = run(state.path(), &[] as &[(&str, &str)]);
    assert!(
        out.status.success(),
        "an unconfigured Node exits 0, got {:?}; stderr: {}",
        out.status,
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    let lines: Vec<&str> = stdout.lines().filter(|l| !l.trim().is_empty()).collect();
    assert_eq!(lines.len(), 1, "exactly one log line, got: {stdout}");
    assert!(lines[0].contains("relay-daemon join"), "{}", lines[0]);
    assert!(!lines[0].contains("RELAY_JOIN"), "{}", lines[0]);
    // Nothing was written: no identity, no address, no dedup store.
    let entries: Vec<_> = std::fs::read_dir(state.path()).unwrap().collect();
    assert!(entries.is_empty(), "an unconfigured start writes nothing");
}

/// The daemon never enrolls: pointed at addresses that are a listening socket,
/// an unenrolled start still exits 0 without a single connection.
// Proves EN-32, EN-33.
#[test]
fn unenrolled_start_never_dials() {
    let state = TempDir::new("exit-never-dials");
    std::fs::create_dir_all(state.path()).expect("create state dir");
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    listener.set_nonblocking(true).expect("nonblocking");
    let addr = format!("https://{}", listener.local_addr().unwrap());

    let out = run(
        state.path(),
        &[
            ("RELAY_ADDRESS", addr.as_str()),
            ("RELAY_ENROLL_ADDRESS", addr.as_str()),
        ],
    );
    assert!(out.status.success(), "got {:?}", out.status);
    assert!(
        matches!(
            listener.accept(),
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock
        ),
        "the daemon connected to the Relay address without an identity"
    );
    assert!(std::fs::read_dir(state.path()).unwrap().next().is_none());
}

/// `RELAY_JOIN` is not a setting: any presence refuses the start by name, on an
/// empty state directory and an enrolled one, and never prints its value.
// Proves DI-43.
#[test]
fn relay_join_is_refused_by_name() {
    let valid = valid_join();
    let values: Vec<(&str, std::ffi::OsString)> = vec![
        ("empty", "".into()),
        ("valid", valid.clone().into()),
        (
            "malformed",
            "glp_join_not!valid tok-should-not-print".into(),
        ),
        (
            "non-utf8",
            OsStr::from_bytes(b"glp_join_\xff\xfe").to_os_string(),
        ),
    ];
    for enrolled in [false, true] {
        for (label, value) in &values {
            let state = TempDir::new("exit-relay-join");
            if enrolled {
                seed_identity(state.path(), None);
            } else {
                std::fs::create_dir_all(state.path()).expect("create state dir");
            }
            let before = names(state.path());
            let out = run(state.path(), &[("RELAY_JOIN", value.as_os_str())]);
            assert!(
                !out.status.success(),
                "{label} (enrolled: {enrolled}) must be refused, got {:?}",
                out.status
            );
            let all = format!(
                "{}{}",
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            );
            assert!(all.contains("RELAY_JOIN"), "{label}: names it: {all}");
            for secret in ["tok-should-not-print", "tok-test", valid.as_str()] {
                assert!(
                    !all.contains(secret),
                    "{label}: the value is printed: {all}"
                );
            }
            assert_eq!(names(state.path()), before, "{label}: state changed");
        }
    }
}

/// The names in `dir`, for "the state directory is unchanged".
fn names(dir: &Path) -> Vec<String> {
    let mut out: Vec<String> = std::fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    out.sort();
    out
}

#[test]
fn partial_identity_exits_nonzero() {
    let state = TempDir::new("exit-partial-identity");
    seed_identity(state.path(), Some(&["key.pem", "node_id"]));
    let out = run(state.path(), &[("RELAY_ADDRESS", "https://127.0.0.1:1")]);
    assert!(!out.status.success(), "got {:?}", out.status);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("partial identity"), "stderr: {stderr}");
    assert!(
        stderr.contains("cert.pem") && stderr.contains("ca_bundle.pem"),
        "stderr: {stderr}"
    );
}

// Proves DI-44.
#[test]
fn identity_without_address_exits_nonzero() {
    let state = TempDir::new("exit-no-address");
    seed_identity(state.path(), None);
    // Neither RELAY_ADDRESS nor a persisted address.
    let out = run(state.path(), &[] as &[(&str, &str)]);
    assert!(
        !out.status.success(),
        "an identity with no address must exit non-zero, got {:?}",
        out.status
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("RELAY_ADDRESS"), "stderr: {stderr}");
}

#[test]
fn an_untrusted_state_dir_exits_nonzero_naming_it() {
    use std::os::unix::fs::PermissionsExt;

    let state = TempDir::new("exit-untrusted-state-dir");
    seed_identity(state.path(), None);
    std::fs::set_permissions(state.path(), std::fs::Permissions::from_mode(0o777))
        .expect("loosen the state dir");
    let out = run(state.path(), &[("RELAY_ADDRESS", "https://127.0.0.1:1")]);
    assert!(!out.status.success(), "got {:?}", out.status);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains(&state.path().display().to_string()),
        "stderr: {stderr}"
    );
    assert!(
        stderr.contains("group- or world-writable"),
        "stderr: {stderr}"
    );
}
