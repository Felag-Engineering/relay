//! The daemon refuses to start with no Relay address: no `RELAY_ADDR`, no
//! `--relay`, and nothing persisted at enrollment (ADR-0031 decision 4). It
//! exits non-zero naming `RELAY_ADDR`, before any identity load or dial.
//!
//! Drives the compiled binary, like `shutdown_signal.rs`.

// Spawning the compiled binary is the point; clippy.toml's spawn ban is for the
// daemon's own code.
#![allow(clippy::disallowed_methods)]

mod common;

use common::TempDir;
use std::process::{Command, Stdio};

#[test]
fn no_address_source_exits_nonzero_naming_relay_addr() {
    let state = TempDir::new("no-relay-addr");
    std::fs::create_dir_all(state.path()).expect("create state dir");
    let out = Command::new(env!("CARGO_BIN_EXE_relay-daemon"))
        .env_clear()
        .env("RELAY_STATE_DIR", state.path())
        .stdin(Stdio::null())
        .output()
        .expect("spawn relay-daemon");

    assert!(
        !out.status.success(),
        "daemon must exit non-zero with no Relay address, got {:?}",
        out.status
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("RELAY_ADDR"), "stderr: {stderr}");
}
