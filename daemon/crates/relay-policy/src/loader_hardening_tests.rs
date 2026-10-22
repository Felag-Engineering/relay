#![cfg(test)]
//! ---------------------------------------------------------------------------
//! Loader hardening tests (#216) — TOCTOU close, symlink rejection, non-regular
//! rejection. Kept as a separate trailing module so it never touches `mod
//! tests` or `mod raw_exec_redteam` above.
//! ---------------------------------------------------------------------------
use super::*;

// The fixture is the example policy file checked into the repo (mirrors
// `mod tests::FIXTURE`).
const FIXTURE: &str = include_str!("../../../policy.example.toml");

// Unique temp path + forced-mode writer, shared with `mod tests::TempFile`
// (mode set via both OpenOptions::mode and a post-hoc chmod to defeat the
// process umask).
use crate::test_support::{unique_temp_path, write_forced_mode as write_secure_policy};

/// RAII cleanup for a path this module created — covers a regular file,
/// a symlink, or a FIFO, all removable via `remove_file`.
struct Cleanup(std::path::PathBuf);

impl Drop for Cleanup {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

// -------------------------------------------------------------------
// loader_rejects_symlink
// -------------------------------------------------------------------

#[test]
fn loader_rejects_symlink() {
    let target = unique_temp_path("symlink-target");
    write_secure_policy(&target, FIXTURE.as_bytes(), 0o600);
    let _target_cleanup = Cleanup(target.clone());

    // Sanity: the real target loads fine on its own, so the symlink is
    // provably the sole cause of the rejection below.
    assert!(
        load_policy(&target).is_ok(),
        "the symlink target itself must load cleanly"
    );

    let link = unique_temp_path("symlink-link");
    std::os::unix::fs::symlink(&target, &link).unwrap();
    let _link_cleanup = Cleanup(link.clone());

    let result = load_policy(&link);
    assert!(
        matches!(result, Err(PolicyError::SymlinkPath)),
        "a symlinked policy path must be rejected via O_NOFOLLOW; got {result:?}"
    );
}

// -------------------------------------------------------------------
// loader_rejects_fifo — also proves open() does not hang (O_NONBLOCK)
// -------------------------------------------------------------------

#[test]
fn loader_rejects_fifo() {
    let path = unique_temp_path("fifo");
    let path_cstr = std::ffi::CString::new(path.to_str().expect("temp path must be valid UTF-8"))
        .expect("temp path must not contain a NUL byte");

    // SAFETY: `path_cstr` is a valid NUL-terminated C string for the
    // lifetime of this call; mkfifo has no other preconditions.
    let rc = unsafe { libc::mkfifo(path_cstr.as_ptr(), 0o600) };
    assert_eq!(
        rc,
        0,
        "mkfifo must succeed; errno={:?}",
        std::io::Error::last_os_error()
    );
    let _cleanup = Cleanup(path.clone());

    // If load_policy ever regressed to blocking O_RDONLY open, this call
    // would hang forever (no writer ever opens the FIFO) instead of
    // returning promptly with NotRegularFile.
    let result = load_policy(&path);
    assert!(
        matches!(result, Err(PolicyError::NotRegularFile)),
        "a FIFO at the policy path must be rejected as not-a-regular-file; got {result:?}"
    );
}

// -------------------------------------------------------------------
// loader_rejects_third_party_owner — the owner half of the gate: a
// file owned by neither root nor the daemon euid is refused.
// -------------------------------------------------------------------

#[test]
fn loader_rejects_third_party_owner() {
    // Only root can hand a file to a uid that is neither 0 nor its own
    // euid; a non-root runner cannot build this fixture at all.
    if !rustix::process::geteuid().is_root() {
        eprintln!("skipped: needs root to chown a fixture to a third-party uid");
        return;
    }
    let path = unique_temp_path("third-party-owner");
    write_secure_policy(&path, FIXTURE.as_bytes(), 0o644);
    let _cleanup = Cleanup(path.clone());
    assert!(
        load_policy(&path).is_ok(),
        "the root-owned fixture must load, so the owner is the sole cause below"
    );

    std::os::unix::fs::chown(&path, Some(65534), None).expect("chown");
    let result = load_policy(&path);
    assert!(
        matches!(result, Err(PolicyError::InsecureOwner { uid: 65534 })),
        "a policy file owned by a third-party uid must be refused; got {result:?}"
    );
}

// -------------------------------------------------------------------
// loader_reads_validated_descriptor_bytes — descriptor identity: the
// bytes read from the validated fd are exactly the fixture bytes.
// -------------------------------------------------------------------

#[test]
fn loader_reads_validated_descriptor_bytes() {
    let path = unique_temp_path("descriptor-identity");
    write_secure_policy(&path, FIXTURE.as_bytes(), 0o600);
    let _cleanup = Cleanup(path.clone());

    let file_policy = load_policy(&path).expect("secure-mode fixture must load");
    let str_policy = from_toml_str(FIXTURE).expect("fixture must parse");
    assert_eq!(
        file_policy.fingerprint(),
        str_policy.fingerprint(),
        "load_policy must read exactly the validated descriptor's bytes: its \
             fingerprint must match from_toml_str(FIXTURE)'s"
    );
}
