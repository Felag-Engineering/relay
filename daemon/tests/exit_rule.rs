//! The daemon's exit rule (the daemon half of DI-25). The start has two
//! outcomes: an identity connects, and no identity file at all exits 0 with one
//! log line and dials nothing. A partial identity, an identity with no Relay
//! address from either source, or a set `RELAY_JOIN` (it is not a setting and is
//! refused by name) exits non-zero, so a broken Node shows as failed and
//! `Restart=on-failure` never mistakes it for an idle one. So does a state
//! directory that is group- or world-writable, refused by path before anything
//! in it is read. It also covers the refusal to start when the identity or the
//! dedup store cannot be opened (DI-19).
//!
//! Drives the compiled binary, like `shutdown_signal.rs`, with a cleared
//! environment so nothing from the test runner reaches it.

// Spawning the compiled binary is the point; clippy.toml's spawn ban is for the
// daemon's own code.
#![allow(clippy::disallowed_methods)]

mod common;
#[path = "common/spawned_daemon.rs"]
mod spawned_daemon;

use common::TempDir;
use spawned_daemon::{seed_identity, seed_identity_files, wait_bounded};
use std::ffi::OsStr;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

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

// Proves EN-33, DI-25.
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
                seed_identity(state.path());
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

// Proves DI-19.
#[test]
fn partial_identity_exits_nonzero() {
    let state = TempDir::new("exit-partial-identity");
    seed_identity_files(state.path(), &["key.pem", "node_id"]);
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
    seed_identity(state.path());
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
    seed_identity(state.path());
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

/// How long a spawned daemon may take to exit or to dial; a refusal is immediate, so
/// this only bounds a hang if the start were not refused.
const DEADLINE: Duration = Duration::from_secs(15);

/// The daemon against `state`, built as `run` builds it, with the Template root pointed
/// into the state directory as well so nothing the host has installed can reach the
/// result, and stdout and stderr piped.
fn daemon_cmd(state: &Path, extra: &[(&str, String)]) -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_relay-daemon"));
    cmd.env_clear()
        .env("RELAY_STATE_DIR", state)
        .env("RELAY_POLICY_PATH", state.join("no-such-policy.toml"))
        .env("RELAY_TEMPLATE_DIR", state.join("no-such-templates"))
        .env("RUST_LOG", "info")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for (k, v) in extra {
        cmd.env(k, v);
    }
    cmd
}

fn no_connection(listener: &std::net::TcpListener) -> bool {
    matches!(
        listener.accept(),
        Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock
    )
}

fn local_listener() -> (std::net::TcpListener, String) {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    listener.set_nonblocking(true).expect("nonblocking");
    let addr = format!("https://{}", listener.local_addr().unwrap());
    (listener, addr)
}

/// An identity or a dedup store that cannot be opened refuses the start: the daemon
/// exits non-zero, dials nothing, and changes nothing in the state directory. The
/// positive control proves the same setup, unsabotaged, does dial, so each refusal is
/// the sabotage's and not the setup's. No chmod: the cases hold for root.
// Proves DI-19.
#[test]
fn unopenable_identity_or_dedup_store_refuses_start() {
    {
        let state = TempDir::new("exit-di19-control");
        seed_identity(state.path());
        let (listener, addr) = local_listener();
        let mut child = daemon_cmd(state.path(), &[("RELAY_ADDRESS", addr)])
            .spawn()
            .expect("spawn relay-daemon");
        let start = Instant::now();
        let mut connected = false;
        while !connected
            && start.elapsed() < DEADLINE
            && child.try_wait().expect("poll the daemon").is_none()
        {
            connected = listener.accept().is_ok();
            std::thread::sleep(Duration::from_millis(25));
        }
        let _ = child.kill();
        let out = child.wait_with_output().expect("reap the daemon");
        assert!(
            connected,
            "an unsabotaged enrolled start dials the Relay; stderr: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }

    type Sabotage = fn(&Path);
    let cases: [(&str, Sabotage, Option<&str>); 3] = [
        (
            "identity: key.pem is a directory",
            |state| {
                std::fs::remove_file(state.join("key.pem")).expect("remove key.pem");
                std::fs::create_dir(state.join("key.pem")).expect("key.pem as a directory");
            },
            None,
        ),
        (
            "identity: cert.pem is not a certificate",
            |state| std::fs::write(state.join("cert.pem"), "not a pem").expect("overwrite cert"),
            Some("do not hold a usable identity"),
        ),
        (
            "dedup store: seen-tasks is a regular file",
            |state| std::fs::write(state.join("seen-tasks"), "").expect("seen-tasks as a file"),
            None,
        ),
    ];
    for (label, sabotage, stderr_says) in cases {
        let state = TempDir::new("exit-di19-case");
        seed_identity(state.path());
        sabotage(state.path());
        let (listener, addr) = local_listener();
        let before = names(state.path());

        let child = daemon_cmd(state.path(), &[("RELAY_ADDRESS", addr)])
            .spawn()
            .expect("spawn relay-daemon");
        let (status, _stdout, stderr) = wait_bounded(child, DEADLINE);

        let status = status.unwrap_or_else(|| panic!("{label}: the daemon kept running"));
        assert!(
            !status.success(),
            "{label}: must exit non-zero, got {status:?}; stderr: {stderr}"
        );
        assert!(
            no_connection(&listener),
            "{label}: the daemon dialled the Relay"
        );
        assert_eq!(names(state.path()), before, "{label}: state changed");
        if let Some(text) = stderr_says {
            assert!(stderr.contains(text), "{label}: stderr: {stderr}");
        }
    }
}
