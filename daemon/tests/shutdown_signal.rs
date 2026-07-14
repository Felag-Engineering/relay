//! Subprocess integration tests for graceful daemon shutdown (issue #177).
//!
//! These tests signal the CHILD daemon process we spawn below — never the
//! shared `cargo test` binary — so the `unsafe { libc::kill(...) }` calls here
//! are safe: each targets a PID this test process itself created.
//!
//! The daemon is a bin-only crate (no `src/lib.rs`), so integration tests here
//! can only drive it through its compiled binary — `env!("CARGO_BIN_EXE_relay-daemon")`
//! — never by importing its internals directly.

use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// A unique scratch directory that removes itself on drop.
struct TempDir(PathBuf);

impl TempDir {
    fn new(label: &str) -> Self {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "relay-daemon-shutdown-test-{label}-{}-{nanos}",
            std::process::id()
        ));
        TempDir(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn write_file(path: PathBuf, content: &str, mode: u32) {
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(mode)
        .open(&path)
        .unwrap_or_else(|e| panic!("open {path:?}: {e}"));
    f.write_all(content.as_bytes())
        .unwrap_or_else(|e| panic!("write {path:?}: {e}"));
}

/// Writes a self-signed rcgen identity to `dir` in the same on-disk layout
/// `identity::load_identity` expects (`key.pem`, `cert.pem`, `ca_bundle.pem`,
/// `node_id`).
///
/// Replicated here rather than reusing `identity::persist_identity` because
/// that function is `pub(crate)` and this is a separate integration-test
/// crate for a bin-only package with no lib target to share it. With this
/// identity pre-seeded and `RELAY_ENROLLMENT_TOKEN` unset, `acquire_identity`
/// takes the `load_identity` path and never dials an enrollment endpoint.
fn seed_identity(dir: &Path) {
    std::fs::create_dir_all(dir).expect("create state dir");

    let kp = rcgen::KeyPair::generate().expect("keygen");
    let cert = rcgen::CertificateParams::new(vec!["test-node".to_string()])
        .expect("cert params")
        .self_signed(&kp)
        .expect("self-signed cert");

    let key_pem = kp.serialize_pem();
    let cert_pem = cert.pem();

    write_file(dir.join("key.pem"), &key_pem, 0o600);
    write_file(dir.join("cert.pem"), &cert_pem, 0o644);
    // Self-signed: the cert doubles as its own CA bundle. This daemon never
    // reaches a real handshake in this test (connect is refused before TLS),
    // so the bundle's content is not itself exercised — only its presence,
    // which `load_identity` requires.
    write_file(dir.join("ca_bundle.pem"), &cert_pem, 0o644);
    write_file(dir.join("node_id"), "test-node-id", 0o644);
}

/// Spawns the compiled `relay-daemon` binary pointed at an unreachable Relay
/// (`127.0.0.1:1` — nothing listens there, so TCP connect is refused
/// immediately), with a pre-seeded identity so it never attempts enrollment.
///
/// `env_clear()` isolates the child from the test runner's environment (in
/// particular, a stray `RELAY_ENROLLMENT_TOKEN` would divert `acquire_identity`
/// down the enrollment path instead of `load_identity`).
fn spawn_idle_daemon(state_dir: &Path) -> std::process::Child {
    let bin = env!("CARGO_BIN_EXE_relay-daemon");
    Command::new(bin)
        .env_clear()
        .env("PATH", std::env::var("PATH").unwrap_or_default())
        .env("RELAY_STATE_DIR", state_dir)
        .env("RELAY_ADDR", "https://127.0.0.1:1")
        .env("RELAY_POLICY_PATH", state_dir.join("no-such-policy.toml"))
        .env("RUST_LOG", "error")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn relay-daemon")
}

/// Polls `child` until it exits or `bound` elapses; panics on timeout.
fn wait_for_exit(child: &mut std::process::Child, bound: Duration) -> std::process::ExitStatus {
    let start = Instant::now();
    loop {
        if let Some(status) = child.try_wait().expect("try_wait") {
            return status;
        }
        assert!(
            start.elapsed() < bound,
            "daemon did not exit within {bound:?}"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// DoD item 2 / correction #2: SIGTERM while idle and reconnecting to an
/// unreachable Relay must produce an immediate clean exit (code 0) instead of
/// blocking on the unbounded, `connect_timeout`-less `connect()` call or on a
/// reconnect backoff sleep. No Task can be in flight in this state, so this
/// path can never risk at-most-once (ADR-0004).
#[test]
fn sigterm_while_idle_reconnecting_exits_zero_immediately() {
    let state_dir = TempDir::new("idle");
    seed_identity(state_dir.path());

    let mut child = spawn_idle_daemon(state_dir.path());

    // Give the daemon time to load its identity, attempt (and have refused)
    // at least one connect, and settle into the connect/backoff-sleep cycle —
    // i.e. to be demonstrably idle/reconnecting when the signal lands.
    std::thread::sleep(Duration::from_millis(300));

    let pid = child.id() as libc::pid_t;
    // SAFETY: `pid` is this test's own freshly-spawned child (never the
    // shared `cargo test` process), and SIGTERM on a known-owned PID has no
    // memory-safety implications.
    let rc = unsafe { libc::kill(pid, libc::SIGTERM) };
    assert_eq!(rc, 0, "SIGTERM delivery to the child must succeed");

    // Comfortably under the grace period (default 30s): an idle daemon must
    // not wait on the grace timer at all.
    let status = wait_for_exit(&mut child, Duration::from_secs(3));

    assert!(
        status.success(),
        "daemon must exit 0 on SIGTERM while idle/reconnecting, got: {status:?}"
    );
}
