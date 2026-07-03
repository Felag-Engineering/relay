//! `file.read` Operation — reads a file's bytes directly via `std::fs`.
//!
//! # Why not the executor?
//!
//! The executor (`executor::execute`) is for **running processes** (spawn, timeout,
//! kill-group, output-cap). Reading bytes is not a process: running `cat` through
//! the executor would spawn a process to do what a single `read(2)` syscall already
//! does, with no security benefit and a wider exec surface. `std::fs` is the
//! least-privilege choice and is still fully ADR-0001-compliant: `path` is DATA,
//! never a shell string; `std::fs::File::open` does not expand globs or invoke a
//! shell.
//!
//! # Policy note
//!
//! This Operation does not restrict which paths may be read. Path restriction is
//! the responsibility of Policy arg-constraints (`policy.rs`, ADR-0002): an allow
//! rule for `file.read` with a path argument constraint is what limits access.
//! A missing or unreadable file maps to `OUTCOME_FAILURE` (not
//! `OUTCOME_DENIED_BY_POLICY`), which is a separate Policy-engine concern.

#![allow(dead_code)]

use std::io::Read;

use crate::gen::{Outcome, TaskResult};

/// Reads at most `cap` bytes from `path`.
///
/// Uses the read-one-past-cap trick to detect truncation at the exact boundary:
/// requests `cap + 1` bytes; if the read returned more than `cap`, the content
/// was truncated and the extra byte is discarded.
///
/// Returns `(bytes, truncated)` on success, or an `io::Error` if the file
/// cannot be opened or read.
pub fn read_capped(path: &std::path::Path, cap: usize) -> std::io::Result<(Vec<u8>, bool)> {
    let f = std::fs::File::open(path)?;
    let mut buf = Vec::new();
    // Read one byte past the cap so we can detect whether the file is larger.
    f.take((cap as u64) + 1).read_to_end(&mut buf)?;
    let truncated = buf.len() > cap;
    if truncated {
        buf.truncate(cap);
    }
    Ok((buf, truncated))
}

/// Reads `path` with a byte cap and returns a fully-populated [`TaskResult`].
///
/// On success the file's bytes (up to `cap`) appear in `stdout` with
/// `truncated` set appropriately. On any I/O error the result is
/// `OUTCOME_FAILURE` with the error message in `stderr` — matching
/// executor.rs's spawn-failure mapping.
pub fn file_read(task_id: &str, path: &str, cap: usize) -> TaskResult {
    match read_capped(std::path::Path::new(path), cap) {
        Ok((bytes, truncated)) => TaskResult {
            task_id: task_id.to_string(),
            outcome: Outcome::Success as i32,
            exit_code: 0,
            stdout: bytes,
            stderr: vec![],
            truncated,
            duration_millis: 0,
        },
        Err(e) => TaskResult {
            task_id: task_id.to_string(),
            outcome: Outcome::Failure as i32,
            exit_code: -1,
            stdout: vec![],
            stderr: e.to_string().into_bytes(),
            truncated: false,
            duration_millis: 0,
        },
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // TempFile helper — same pattern as policy.rs's TempFile.
    //
    // PERMISSION-BIT CAVEAT (carried forward from policy.rs):
    //   If a permission-denied test is added later it must use
    //   `std::fs::set_permissions` (not `OpenOptions::mode`) because
    //   `OpenOptions::mode` is masked by the process umask, and must be
    //   skipped when `rustix::process::geteuid().is_root()` because root
    //   bypasses DAC read permissions.
    // -----------------------------------------------------------------------

    struct TempFile(std::path::PathBuf);

    impl TempFile {
        fn new(label: &str, content: &[u8]) -> Self {
            use std::time::{SystemTime, UNIX_EPOCH};
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let path = std::env::temp_dir().join(format!(
                "relay-file-read-test-{}-{}-{}",
                label,
                std::process::id(),
                nanos
            ));
            std::fs::write(&path, content).unwrap();
            TempFile(path)
        }

        fn path(&self) -> &std::path::Path {
            &self.0
        }
    }

    impl Drop for TempFile {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }

    // -----------------------------------------------------------------------
    // read_capped: exact content, no truncation
    // -----------------------------------------------------------------------

    #[test]
    fn read_capped_returns_known_content() {
        let content = b"hello, relay!";
        let tmp = TempFile::new("content", content);
        let (bytes, truncated) = read_capped(tmp.path(), 1024).unwrap();
        assert_eq!(bytes, content);
        assert!(!truncated);
    }

    // -----------------------------------------------------------------------
    // read_capped: file larger than cap → stdout.len() == cap, truncated true
    // -----------------------------------------------------------------------

    #[test]
    fn read_capped_truncates_past_cap() {
        let content = vec![0u8; 200];
        let tmp = TempFile::new("truncate", &content);
        let (bytes, truncated) = read_capped(tmp.path(), 100).unwrap();
        assert_eq!(bytes.len(), 100);
        assert!(truncated);
    }

    // -----------------------------------------------------------------------
    // read_capped: file exactly at cap → len == cap, truncated false
    // -----------------------------------------------------------------------

    #[test]
    fn read_capped_exact_boundary_not_truncated() {
        let content = vec![0u8; 100];
        let tmp = TempFile::new("boundary", &content);
        let (bytes, truncated) = read_capped(tmp.path(), 100).unwrap();
        assert_eq!(bytes.len(), 100);
        assert!(!truncated);
    }

    // -----------------------------------------------------------------------
    // file_read wrapper: missing path → OUTCOME_FAILURE, exit -1, stderr set
    // -----------------------------------------------------------------------

    #[test]
    fn file_read_missing_path_is_failure() {
        let result = file_read("t1", "/nonexistent/relay-test-file-read", 1024);
        assert_eq!(
            result.outcome,
            Outcome::Failure as i32,
            "missing file must yield OUTCOME_FAILURE"
        );
        assert_eq!(result.exit_code, -1);
        assert!(
            !result.stderr.is_empty(),
            "stderr must contain the I/O error message"
        );
        assert!(result.stdout.is_empty());
        assert!(!result.truncated);
    }
}
