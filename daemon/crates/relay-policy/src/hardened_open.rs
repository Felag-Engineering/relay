//! The one hardened, read-only open for the daemon's locally-rooted trust
//! files — the Policy file (`policy::load_policy`, ADR-0002) and each Template
//! Operation file (`templates::read_hardened`, ADR-0021 on ADR-0002).
//!
//! Both loaders used to carry their own copy of this sequence; they now share
//! this one, and each maps a [`HardenedRejection`] to its own error type and
//! keeps its own logging. This module decides nothing beyond the checks below
//! and logs nothing: what a rejection means to its caller is the caller's.
//!
//! **Single-descriptor validate-then-read**: the file is opened exactly once
//! and every check is performed via `fstat` on that *open descriptor*, never
//! on the path. The caller reads the bytes from the returned [`File`] — the
//! same descriptor — so the bytes validated are always the bytes loaded, and
//! there is no metadata/read TOCTOU race. Re-checking the path after open
//! would reopen that race; do not add one.
//!
//! **Read-only**: the open carries `.read(true)` and no write, append, create
//! or truncate flag. `tests/policy_never_opened_for_write.rs` scans this
//! module and pins that it is the only opener in `policy.rs` and
//! `templates.rs` (invariant 2).
//!
//! Fail-closed checks, in this order (the order is part of the contract — a
//! file failing several checks reports the first):
//! 1. The final path component is a symlink: `O_NOFOLLOW` makes `open()` fail
//!    with `ELOOP` → [`HardenedRejection::Symlink`]. This is the only
//!    race-free way to reject a symlink, since `fstat` on the opened fd can
//!    never see one (open already resolved it).
//! 2. The opened file is not a regular file (FIFO, device, socket, directory)
//!    → [`HardenedRejection::NotRegularFile`]. `O_NONBLOCK` guarantees this
//!    check cannot be starved by a FIFO with no writer (a blocking `O_RDONLY`
//!    open of a FIFO waits for a writer); regular-file reads are unaffected.
//! 3. Group- or world-write bits are set (`mode & 0o022 != 0`)
//!    → [`HardenedRejection::InsecurePermissions`], carrying `mode & 0o777`.
//! 4. The owner is neither root (uid 0) nor the daemon's effective uid
//!    → [`HardenedRejection::InsecureOwner`]. The euid branch lets a non-root
//!    deployment or CI runner pass while still refusing files owned by
//!    arbitrary third parties.
//!
//! Any other `open()` error, and an `fstat` error, is
//! [`HardenedRejection::Io`].
//!
//! **Residual (documented, not closed here):** `O_NOFOLLOW` guards only the
//! final path component, so a rename-swap within an attacker-writable parent
//! directory remains possible; mitigated operationally by keeping these files
//! in a root-owned directory (e.g. `/etc/relay-daemon/`).

use std::fs::{self, File, Metadata};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;

/// Why [`open_hardened`] refused a path. Every variant is a refusal; there is
/// no variant that lets a caller proceed.
#[derive(Debug)]
pub enum HardenedRejection {
    /// The final path component is a symlink (`open()` returned `ELOOP`).
    Symlink,
    /// The opened descriptor is not a regular file.
    NotRegularFile,
    /// The file is group- or world-writable; `mode` is `st_mode & 0o777`.
    InsecurePermissions { mode: u32 },
    /// The file is owned by neither root nor the daemon's effective uid.
    InsecureOwner { uid: u32 },
    /// Any other `open()` error, or an `fstat` error on the opened descriptor.
    Io(std::io::Error),
}

/// Open `path` read-only with `O_NOFOLLOW | O_NONBLOCK`, validate the
/// descriptor via `fstat` (see the module docs for the checks and their
/// order), and return the descriptor with the metadata the checks were made
/// against. The caller must read from the returned [`File`], never reopen
/// `path`.
pub fn open_hardened(path: &Path) -> Result<(File, Metadata), HardenedRejection> {
    #[allow(
        clippy::disallowed_methods,
        reason = "the one read-only hardened open; chain pinned by tests/policy_never_opened_for_write.rs"
    )]
    let file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .map_err(|e| match e.raw_os_error() {
            Some(libc::ELOOP) => HardenedRejection::Symlink,
            _ => HardenedRejection::Io(e),
        })?;

    // fstat the open descriptor (NOT the path) for every check below.
    let meta = file.metadata().map_err(HardenedRejection::Io)?;

    if !meta.is_file() {
        return Err(HardenedRejection::NotRegularFile);
    }

    let mode = meta.mode() & 0o777;
    if mode & 0o022 != 0 {
        return Err(HardenedRejection::InsecurePermissions { mode });
    }

    let file_uid = meta.uid();
    if !owner_is_trusted(file_uid, rustix::process::geteuid().as_raw()) {
        return Err(HardenedRejection::InsecureOwner { uid: file_uid });
    }

    Ok((file, meta))
}

/// Whether a trust file owned by `file_uid` may be read by a daemon running as
/// `daemon_euid`: only root or the daemon's own effective uid. A pure function
/// so the decision is unit-tested on any runner — the fixture tests that chown
/// a real file to a third-party uid need root, and CI is not root.
fn owner_is_trusted(file_uid: u32, daemon_euid: u32) -> bool {
    file_uid == 0 || file_uid == daemon_euid
}

#[allow(
    clippy::disallowed_methods,
    reason = "test fixtures; the non-test lib target is linted separately"
)]
#[cfg(test)]
mod tests {
    use super::*;

    /// The owner rule itself, independent of who runs the tests: root and the
    /// daemon's euid are trusted, any other uid is refused — including root
    /// daemons refusing a non-root owner.
    #[test]
    fn owner_rule_trusts_only_root_and_the_daemon() {
        assert!(
            owner_is_trusted(0, 1000),
            "root-owned file, non-root daemon"
        );
        assert!(owner_is_trusted(1000, 1000), "daemon-owned file");
        assert!(owner_is_trusted(0, 0), "root-owned file, root daemon");
        assert!(
            !owner_is_trusted(65534, 1000),
            "third-party owner, non-root daemon"
        );
        assert!(!owner_is_trusted(1000, 0), "non-root owner, root daemon");
        assert!(!owner_is_trusted(1001, 1000), "neighbouring uid");
    }
    use std::io::Read;
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU32, Ordering};

    /// A self-cleaning temp directory (no dev-dep on tempfile; the same
    /// counter-named, pre-cleared shape as templates.rs's).
    struct TempDir(PathBuf);

    impl TempDir {
        fn new(tag: &str) -> TempDir {
            static COUNTER: AtomicU32 = AtomicU32::new(0);
            let n = COUNTER.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "relay-hardened-open-{tag}-{}-{n}",
                std::process::id()
            ));
            let _ = fs::remove_dir_all(&path);
            fs::create_dir_all(&path).expect("create temp dir");
            TempDir(path)
        }

        /// Writes `contents` at `name` with exactly `mode` (chmod, which is
        /// not umask-masked).
        fn file(&self, name: &str, contents: &[u8], mode: u32) -> PathBuf {
            let path = self.0.join(name);
            fs::write(&path, contents).expect("write fixture");
            fs::set_permissions(&path, fs::Permissions::from_mode(mode)).expect("chmod");
            path
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn accepts_secure_file_and_reads_from_the_validated_descriptor() {
        let dir = TempDir::new("ok");
        let path = dir.file("f", b"bytes", 0o644);
        let (mut file, meta) = open_hardened(&path).expect("secure file must open");
        assert!(meta.is_file());
        assert_eq!(meta.mode() & 0o777, 0o644);
        let mut got = String::new();
        file.read_to_string(&mut got).expect("read");
        assert_eq!(got, "bytes");
    }

    #[test]
    fn refuses_symlink() {
        let dir = TempDir::new("symlink");
        let target = dir.file("target", b"x", 0o600);
        assert!(open_hardened(&target).is_ok(), "target alone must open");
        let link = dir.0.join("link");
        std::os::unix::fs::symlink(&target, &link).expect("symlink");
        let got = open_hardened(&link);
        assert!(
            matches!(got, Err(HardenedRejection::Symlink)),
            "got {got:?}"
        );
    }

    #[test]
    fn refuses_fifo_without_blocking() {
        let dir = TempDir::new("fifo");
        let fifo = dir.0.join("fifo");
        let c_path = std::ffi::CString::new(fifo.as_os_str().as_encoded_bytes()).expect("cstring");
        // SAFETY: plain libc call with a valid NUL-terminated path.
        let rc = unsafe { libc::mkfifo(c_path.as_ptr(), 0o600) };
        assert_eq!(rc, 0, "mkfifo failed: {}", std::io::Error::last_os_error());
        let got = open_hardened(&fifo);
        assert!(
            matches!(got, Err(HardenedRejection::NotRegularFile)),
            "got {got:?}"
        );
    }

    #[test]
    fn refuses_directory() {
        let dir = TempDir::new("dir");
        let got = open_hardened(&dir.0);
        assert!(
            matches!(got, Err(HardenedRejection::NotRegularFile)),
            "got {got:?}"
        );
    }

    #[test]
    fn refuses_group_or_world_writable_with_masked_mode() {
        for mode in [0o664_u32, 0o646, 0o666, 0o4666] {
            let dir = TempDir::new("perms");
            let path = dir.file("f", b"x", mode);
            let got = open_hardened(&path);
            assert!(
                matches!(
                    got,
                    Err(HardenedRejection::InsecurePermissions { mode: m }) if m == mode & 0o777
                ),
                "mode {mode:#o}; got {got:?}"
            );
        }
    }

    #[test]
    fn permissions_are_checked_before_owner() {
        // A file failing both the mode and the owner check reports the mode
        // rejection: the order of checks is part of the contract.
        if !rustix::process::geteuid().is_root() {
            eprintln!("skipped: needs root to chown a fixture to a third-party uid");
            return;
        }
        let dir = TempDir::new("order");
        let path = dir.file("f", b"x", 0o666);
        std::os::unix::fs::chown(&path, Some(65534), None).expect("chown");
        let got = open_hardened(&path);
        assert!(
            matches!(got, Err(HardenedRejection::InsecurePermissions { .. })),
            "got {got:?}"
        );
    }

    #[test]
    fn refuses_third_party_owner() {
        // Only root can hand a file to a uid that is neither 0 nor its own
        // euid; on a non-root runner there is no way to build the fixture.
        if !rustix::process::geteuid().is_root() {
            eprintln!("skipped: needs root to chown a fixture to a third-party uid");
            return;
        }
        let dir = TempDir::new("owner");
        let path = dir.file("f", b"x", 0o644);
        std::os::unix::fs::chown(&path, Some(65534), None).expect("chown");
        let got = open_hardened(&path);
        assert!(
            matches!(got, Err(HardenedRejection::InsecureOwner { uid: 65534 })),
            "got {got:?}"
        );
    }

    #[test]
    fn missing_path_is_io() {
        let dir = TempDir::new("missing");
        let got = open_hardened(&dir.0.join("absent"));
        assert!(
            matches!(&got, Err(HardenedRejection::Io(e)) if e.kind() == std::io::ErrorKind::NotFound),
            "got {got:?}"
        );
    }
}
