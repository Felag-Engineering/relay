//! Fixtures for the integration tests that spawn the compiled `relay-daemon`: a
//! pre-seeded identity, so a start is `Enrolled` and never dials an enrollment
//! endpoint, and a bounded wait that always reaps the child.
//!
//! The daemon is a bin-only crate with no lib target, so `identity::persist_identity`
//! cannot be reused from here; this is the one test-side copy of its on-disk layout.
//!
//! Mounted with `#[path]`, as `source_walk.rs` is, so Cargo does not build it as a test
//! crate of its own. Each test uses only part of it.
#![allow(dead_code)]

use std::fs::OpenOptions;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::process::{Child, ExitStatus};
use std::time::{Duration, Instant};

/// The four files `load_identity` requires, in the order they are written.
pub const IDENTITY_FILES: [&str; 4] = ["key.pem", "cert.pem", "ca_bundle.pem", "node_id"];

/// How often `wait_bounded` polls the child.
const POLL_INTERVAL: Duration = Duration::from_millis(25);

/// Writes a self-signed identity to `dir` (created if absent) in the layout
/// `load_identity` expects.
pub fn seed_identity(dir: &Path) {
    seed_identity_files(dir, &IDENTITY_FILES);
}

/// As `seed_identity`, but writes only the named files of `IDENTITY_FILES`, for a
/// partial identity.
///
/// The cert doubles as its own CA bundle: a test that reaches a real handshake
/// needs its own CA, and every other test needs only the bundle's presence.
pub fn seed_identity_files(dir: &Path, only: &[&str]) {
    std::fs::create_dir_all(dir).expect("create state dir");
    let kp = rcgen::KeyPair::generate().expect("keygen");
    let cert = rcgen::CertificateParams::new(vec!["test-node".to_string()])
        .expect("cert params")
        .self_signed(&kp)
        .expect("self-signed cert")
        .pem();
    let files = [
        ("key.pem", kp.serialize_pem(), 0o600),
        ("cert.pem", cert.clone(), 0o644),
        ("ca_bundle.pem", cert, 0o644),
        ("node_id", "test-node-id".to_string(), 0o644),
    ];
    for (name, body, mode) in files {
        if only.contains(&name) {
            write_mode(&dir.join(name), &body, mode);
        }
    }
}

fn write_mode(path: &Path, body: &str, mode: u32) {
    let mut f = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(mode)
        .open(path)
        .unwrap_or_else(|e| panic!("open {path:?}: {e}"));
    f.write_all(body.as_bytes())
        .unwrap_or_else(|e| panic!("write {path:?}: {e}"));
}

/// Waits for `child` to exit; past `deadline` it is killed. The status is `None` when
/// it had to be killed. Returns the status, stdout and stderr (empty unless piped),
/// and always reaps, so a failing test never leaves a daemon running.
pub fn wait_bounded(mut child: Child, deadline: Duration) -> (Option<ExitStatus>, String, String) {
    let start = Instant::now();
    let exited = loop {
        if child.try_wait().expect("poll the daemon").is_some() {
            break true;
        }
        if start.elapsed() >= deadline {
            let _ = child.kill();
            break false;
        }
        std::thread::sleep(POLL_INTERVAL);
    };
    let out = child.wait_with_output().expect("reap the daemon");
    (
        exited.then_some(out.status),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

/// Kills `child`, if it is still running, and reaps it.
pub fn stop(mut child: Child) {
    let _ = child.kill();
    let _ = child.wait();
}
