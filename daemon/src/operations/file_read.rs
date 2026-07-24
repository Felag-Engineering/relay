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

use std::io::Read;
use std::os::unix::io::AsRawFd;

use crate::gen::{Outcome, TaskResult};

/// Result of the layer-2 resolved-target Policy re-check (ADR-0018): after the
/// executor opens the path and resolves the target it actually got, it asks
/// Policy again about that resolved path.
pub enum PathCheck {
    /// The resolved target is permitted — proceed to read.
    Allowed,
    /// The resolved target is denied; the string is the deny reason.
    Denied(String),
}

/// Reads at most `cap` bytes from an already-open file.
///
/// Uses the read-one-past-cap trick to detect truncation at the exact boundary:
/// requests `cap + 1` bytes; if the read returned more than `cap`, the content
/// was truncated and the extra byte is discarded.
///
/// Returns `(bytes, truncated)` on success, or an `io::Error` if the file
/// cannot be read.
pub fn read_capped_from(f: std::fs::File, cap: usize) -> std::io::Result<(Vec<u8>, bool)> {
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
/// # ADR-0018 layer 2 — resolved-target re-check
///
/// `path` has already cleared Policy's canonical-form precondition (layer 1),
/// but a canonical spelling can still resolve elsewhere via a `/proc` magic
/// link or a symlink. So this opens `path` **once** (the descriptor pins the
/// opened inode), reads the real resolved path back off that descriptor
/// (`/proc/self/fd/<n>`), and calls `recheck` with it. If `recheck` denies the
/// resolved target the file is **not read** — the result is
/// `OUTCOME_DENIED_BY_POLICY`. Reading happens only from the same descriptor
/// that was checked, so there is no check-to-read TOCTOU window. If the
/// resolved path cannot be determined, the read fails closed (denied).
///
/// On success the file's bytes (up to `cap`) appear in `stdout` with
/// `truncated` set appropriately. On any I/O error the result is
/// `OUTCOME_FAILURE` with the error message in `stderr`.
pub fn file_read(
    task_id: &str,
    path: &str,
    cap: usize,
    recheck: impl FnOnce(&str) -> PathCheck,
) -> TaskResult {
    let f = match std::fs::File::open(path) {
        Ok(f) => f,
        Err(e) => return read_failure(task_id, path, &e),
    };

    // Resolve the path the descriptor actually points at, then re-check it.
    let resolved = match std::fs::read_link(format!("/proc/self/fd/{}", f.as_raw_fd())) {
        Ok(p) => p.to_string_lossy().into_owned(),
        // Fail closed: if the resolved target cannot be determined, refuse.
        Err(e) => {
            return denied_by_policy(
                task_id,
                &format!(
                    "cannot resolve opened path {path:?} for policy re-check (ADR-0018): {}",
                    crate::config::clean_io_error(&e)
                ),
            )
        }
    };
    if let PathCheck::Denied(reason) = recheck(&resolved) {
        return denied_by_policy(task_id, &reason);
    }

    match read_capped_from(f, cap) {
        Ok((bytes, truncated)) => TaskResult {
            task_id: task_id.to_string(),
            outcome: Outcome::Success as i32,
            exit_code: 0,
            stdout: bytes,
            stderr: vec![],
            truncated,
            duration_millis: 0,
        },
        Err(e) => read_failure(task_id, path, &e),
    }
}

/// `OUTCOME_DENIED_BY_POLICY` result (mirrors dispatch's `denied_by_policy_result`).
fn denied_by_policy(task_id: &str, reason: &str) -> TaskResult {
    TaskResult {
        task_id: task_id.to_string(),
        outcome: Outcome::DeniedByPolicy as i32,
        exit_code: -1,
        stdout: vec![],
        stderr: reason.as_bytes().to_vec(),
        truncated: false,
        duration_millis: 0,
    }
}

/// `OUTCOME_FAILURE` result for an I/O error, naming the requested `path`.
fn read_failure(task_id: &str, path: &str, e: &std::io::Error) -> TaskResult {
    TaskResult {
        task_id: task_id.to_string(),
        outcome: Outcome::Failure as i32,
        exit_code: -1,
        stdout: vec![],
        stderr: format!("read {}: {}", path, crate::config::clean_io_error(e)).into_bytes(),
        truncated: false,
        duration_millis: 0,
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

    fn open(path: &std::path::Path) -> std::fs::File {
        std::fs::File::open(path).unwrap()
    }

    #[test]
    fn read_capped_returns_known_content() {
        let content = b"hello, relay!";
        let tmp = TempFile::new("content", content);
        let (bytes, truncated) = read_capped_from(open(tmp.path()), 1024).unwrap();
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
        let (bytes, truncated) = read_capped_from(open(tmp.path()), 100).unwrap();
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
        let (bytes, truncated) = read_capped_from(open(tmp.path()), 100).unwrap();
        assert_eq!(bytes.len(), 100);
        assert!(!truncated);
    }

    // -----------------------------------------------------------------------
    // file_read wrapper: missing path → OUTCOME_FAILURE, exit -1, stderr set
    // -----------------------------------------------------------------------

    #[test]
    fn file_read_missing_path_is_failure() {
        let path = "/nonexistent/relay-test-file-read";
        let result = file_read("t1", path, 1024, |_| PathCheck::Allowed);
        assert_eq!(
            result.outcome,
            Outcome::Failure as i32,
            "missing file must yield OUTCOME_FAILURE"
        );
        assert_eq!(result.exit_code, -1);
        let stderr = String::from_utf8_lossy(&result.stderr);
        assert!(
            stderr.contains(path),
            "stderr must name the requested path; got {stderr:?}"
        );
        assert!(
            stderr.contains("No such file or directory"),
            "got {stderr:?}"
        );
        assert!(!stderr.contains("(os error"), "got {stderr:?}");
        assert!(result.stdout.is_empty());
        assert!(!result.truncated);
    }

    // -----------------------------------------------------------------------
    // ADR-0018 layer 2: the executor re-checks the RESOLVED target off the
    // open descriptor. A normal read is allowed; a symlink whose resolved
    // target is denied is refused before any bytes are read.
    // -----------------------------------------------------------------------

    #[test]
    fn resolved_target_recheck_allows_normal_read() {
        let content = b"ok";
        let tmp = TempFile::new("recheck-allow", content);
        let result = file_read("t", tmp.path().to_str().unwrap(), 1024, |_| {
            PathCheck::Allowed
        });
        assert_eq!(
            result.outcome,
            Outcome::Success as i32,
            "stderr={:?}",
            String::from_utf8_lossy(&result.stderr)
        );
        assert_eq!(result.stdout, content);
    }

    #[test]
    fn resolved_target_recheck_denies_symlinked_deny_target() {
        use std::os::unix::fs::symlink;

        // A real target, plus a symlink whose NAME would slip an exact-string
        // deny but whose RESOLVED path is the (denied) target.
        let target = TempFile::new("recheck-target", b"secret");
        let real = std::fs::canonicalize(target.path())
            .unwrap()
            .to_string_lossy()
            .into_owned();
        let link = std::path::PathBuf::from(format!("{}.link", target.path().display()));
        symlink(target.path(), &link).unwrap();

        struct LinkGuard(std::path::PathBuf);
        impl Drop for LinkGuard {
            fn drop(&mut self) {
                let _ = std::fs::remove_file(&self.0);
            }
        }
        let _guard = LinkGuard(link.clone());

        let result = file_read("t", link.to_str().unwrap(), 1024, |resolved| {
            if resolved == real {
                PathCheck::Denied("resolved to a denied target".to_string())
            } else {
                PathCheck::Allowed
            }
        });

        assert_eq!(
            result.outcome,
            Outcome::DeniedByPolicy as i32,
            "a symlink resolving to a denied target must be denied by the re-check; stderr={:?}",
            String::from_utf8_lossy(&result.stderr)
        );
        assert!(
            result.stdout.is_empty(),
            "a denied read must not leak any file content"
        );
    }
}
