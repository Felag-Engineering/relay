//! Fixtures shared by the daemon's integration tests. A `common/mod.rs`, not
//! a top-level `tests/*.rs`, so Cargo does not build it as a test crate of its
//! own; each integration test that needs it declares `mod common;`.
//!
//! The daemon crate has no `tempfile` dependency, so the scratch directory is
//! hand-rolled.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

/// A unique scratch directory that removes itself on drop. Only named, not
/// created: the caller (or the daemon under test) creates it.
pub struct TempDir(PathBuf);

impl TempDir {
    /// `relay-daemon-test-<label>-<pid>-<nanos>-<seq>` under the system temp
    /// dir; the per-process sequence number keeps same-nanosecond calls
    /// distinct.
    pub fn new(label: &str) -> Self {
        static SEQ: AtomicU64 = AtomicU64::new(0);
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let seq = SEQ.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "relay-daemon-test-{label}-{}-{nanos}-{seq}",
            std::process::id()
        ));
        TempDir(path)
    }

    pub fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
