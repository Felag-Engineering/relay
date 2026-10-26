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

/// A Policy directory that was never created: no fragments.
fn no_dir() -> std::path::PathBuf {
    unique_temp_path("no-policy-dir")
}

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
        load_policy(&target, &no_dir()).is_ok(),
        "the symlink target itself must load cleanly"
    );

    let link = unique_temp_path("symlink-link");
    std::os::unix::fs::symlink(&target, &link).unwrap();
    let _link_cleanup = Cleanup(link.clone());

    let result = load_policy(&link, &no_dir());
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
    let result = load_policy(&path, &no_dir());
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
        load_policy(&path, &no_dir()).is_ok(),
        "the root-owned fixture must load, so the owner is the sole cause below"
    );

    std::os::unix::fs::chown(&path, Some(65534), None).expect("chown");
    let result = load_policy(&path, &no_dir());
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

    let file_policy = load_policy(&path, &no_dir()).expect("secure-mode fixture must load");
    let str_policy = from_toml_str(FIXTURE).expect("fixture must parse");
    assert_eq!(
        file_policy.fingerprint(),
        str_policy.fingerprint(),
        "load_policy must read exactly the validated descriptor's bytes: its \
             fingerprint must match from_toml_str(FIXTURE)'s"
    );
}

// -------------------------------------------------------------------
// The Policy directory: fragments composed with the Policy file.
//
// Every directory is forced to 0o755 and every file to 0o644 explicitly:
// directory creation follows the umask, and CI runs strict umasks.
// -------------------------------------------------------------------

use crate::test_support::TempDir;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

const ALLOW_NGINX: &str =
    "[[operation]]\nname = \"service.restart\"\nallowed_args = [[\"nginx\"]]\n";
const ALLOW_SSHD: &str = "[[operation]]\nname = \"service.restart\"\nallowed_args = [[\"sshd\"]]\n";
const DENY_SSHD: &str = "[[deny]]\nname = \"service.restart\"\nargs = [[\"sshd\"]]\n";

/// A Node's config directory: the Policy file (when given) and the path of the
/// Policy directory beside it, which `create_dir` creates.
struct Layout {
    root: TempDir,
}

impl Layout {
    fn new(policy_file: Option<&str>) -> Layout {
        let root = TempDir::created("policy-layout");
        set_mode(root.path(), 0o755);
        if let Some(text) = policy_file {
            write_secure_policy(&root.path().join("policy.toml"), text.as_bytes(), 0o644);
        }
        Layout { root }
    }

    fn file(&self) -> std::path::PathBuf {
        self.root.path().join("policy.toml")
    }

    fn dir(&self) -> std::path::PathBuf {
        self.root.path().join(POLICY_DIR_NAME)
    }

    /// Creates the Policy directory at 0o755.
    fn create_dir(&self) {
        std::fs::create_dir(self.dir()).expect("create the Policy directory");
        set_mode(&self.dir(), 0o755);
    }

    fn fragment(&self, name: &str, text: &str) {
        write_secure_policy(&self.dir().join(name), text.as_bytes(), 0o644);
    }

    fn load(&self) -> Result<Policy, PolicyError> {
        load_policy(&self.file(), &self.dir())
    }
}

fn set_mode(path: &Path, mode: u32) {
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).expect("chmod");
}

fn restart_decision(policy: &Policy, service: &str) -> Decision {
    policy.evaluate("service.restart", &[service.to_string()])
}

// Proves DI-36.
#[test]
fn an_absent_or_empty_policy_directory_loads_as_today() {
    let layout = Layout::new(Some(FIXTURE));
    let expected = {
        let digest = ring::digest::digest(&ring::digest::SHA256, FIXTURE.as_bytes());
        digest
            .as_ref()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    };

    let absent = layout.load().expect("an absent directory is no fragments");
    assert_eq!(absent.fingerprint(), expected);

    layout.create_dir();
    let empty = layout.load().expect("an empty directory is no fragments");
    assert_eq!(
        empty.fingerprint(),
        expected,
        "an empty Policy directory leaves the fingerprint at the Policy file's SHA-256"
    );
}

// Proves DI-36.
#[test]
fn load_policy_composes_the_policy_directory() {
    let layout = Layout::new(Some(ALLOW_NGINX));
    layout.create_dir();
    layout.fragment("10-sshd.toml", ALLOW_SSHD);
    let alone = layout.load().expect("loads");
    assert!(matches!(
        restart_decision(&alone, "sshd"),
        Decision::Allow(_)
    ));
    assert!(matches!(
        restart_decision(&alone, "nginx"),
        Decision::Allow(_)
    ));

    layout.fragment("20-deny.toml", DENY_SSHD);
    let composed = layout.load().expect("loads");
    assert!(
        matches!(restart_decision(&composed, "sshd"), Decision::Deny { .. }),
        "a deny in one fragment beats an allow in another"
    );
    assert!(matches!(
        restart_decision(&composed, "nginx"),
        Decision::Allow(_)
    ));
    assert_ne!(composed.fingerprint(), alone.fingerprint());

    let from_text = compose(
        ALLOW_NGINX,
        &[
            Fragment {
                name: "10-sshd.toml".to_string(),
                text: ALLOW_SSHD.to_string(),
            },
            Fragment {
                name: "20-deny.toml".to_string(),
                text: DENY_SSHD.to_string(),
            },
        ],
    )
    .unwrap();
    assert_eq!(
        composed.fingerprint(),
        from_text.fingerprint(),
        "the loader and the pure compose agree on the fingerprint"
    );
}

// Proves DI-36.
#[test]
fn a_symlinked_fragment_refuses_start() {
    let layout = Layout::new(Some(ALLOW_NGINX));
    layout.create_dir();
    layout.fragment("real.toml", ALLOW_SSHD);
    std::os::unix::fs::symlink(
        layout.dir().join("real.toml"),
        layout.dir().join("link.toml"),
    )
    .unwrap();

    let result = layout.load();
    assert!(
        matches!(&result, Err(PolicyError::FragmentSymlink { name }) if name == "link.toml"),
        "got {result:?}"
    );
    assert!(result.unwrap_err().refuses_start());
}

// Proves DI-36.
#[test]
fn a_symlink_or_insecure_fragment_with_a_non_utf8_name_still_refuses_start() {
    use std::os::unix::ffi::OsStrExt;
    let bad_name = std::ffi::OsStr::from_bytes(b"\xff.toml");

    let layout = Layout::new(Some(ALLOW_NGINX));
    layout.create_dir();
    std::os::unix::fs::symlink(layout.dir().join("elsewhere"), layout.dir().join(bad_name))
        .unwrap();
    let result = layout.load();
    assert!(
        matches!(&result, Err(PolicyError::FragmentSymlink { .. })),
        "got {result:?}"
    );
    assert!(result.unwrap_err().refuses_start());

    let layout = Layout::new(Some(ALLOW_NGINX));
    layout.create_dir();
    write_secure_policy(&layout.dir().join(bad_name), ALLOW_SSHD.as_bytes(), 0o664);
    let result = layout.load();
    assert!(
        matches!(
            &result,
            Err(PolicyError::FragmentInsecurePermissions { .. })
        ),
        "got {result:?}"
    );
    assert!(result.unwrap_err().refuses_start());
}

// Proves DI-36.
#[test]
fn a_safe_fragment_with_a_non_utf8_name_is_a_deny_all_error() {
    use std::os::unix::ffi::OsStrExt;
    let layout = Layout::new(Some(ALLOW_NGINX));
    layout.create_dir();
    write_secure_policy(
        &layout.dir().join(std::ffi::OsStr::from_bytes(b"\xff.toml")),
        ALLOW_SSHD.as_bytes(),
        0o644,
    );
    let result = layout.load();
    assert!(
        matches!(&result, Err(PolicyError::FragmentName { .. })),
        "got {result:?}"
    );
    assert!(!result.unwrap_err().refuses_start());
}

// Proves DI-36.
#[test]
fn a_non_regular_fragment_refuses_start() {
    let layout = Layout::new(Some(ALLOW_NGINX));
    layout.create_dir();
    std::fs::create_dir(layout.dir().join("sub.toml")).unwrap();
    let result = layout.load();
    assert!(
        matches!(&result, Err(PolicyError::FragmentNotRegularFile { name }) if name == "sub.toml"),
        "a subdirectory is not a fragment; got {result:?}"
    );
    assert!(result.unwrap_err().refuses_start());
    std::fs::remove_dir(layout.dir().join("sub.toml")).unwrap();

    // A Unix socket is another entry that is not a regular file; binding one
    // needs no `unsafe`, which the daemon pins (the FIFO case is the Policy
    // file's own test above).
    let socket_path = layout.dir().join("sock.toml");
    let _socket = std::os::unix::net::UnixListener::bind(&socket_path).expect("bind a socket");
    let result = layout.load();
    assert!(
        matches!(&result, Err(PolicyError::FragmentNotRegularFile { name }) if name == "sock.toml"),
        "a socket is refused without being opened; got {result:?}"
    );
    assert!(result.unwrap_err().refuses_start());
}

// Proves DI-36.
#[test]
fn a_group_or_world_writable_fragment_refuses_start() {
    for (mode, bit) in [
        (0o664_u32, "group-writable, other-write clear"),
        (0o646_u32, "world-writable, group-write clear"),
    ] {
        let layout = Layout::new(Some(ALLOW_NGINX));
        layout.create_dir();
        write_secure_policy(
            &layout.dir().join("loose.toml"),
            ALLOW_SSHD.as_bytes(),
            mode,
        );

        let result = layout.load();
        assert!(
            matches!(
                &result,
                Err(PolicyError::FragmentInsecurePermissions { name, mode: reported })
                    if name == "loose.toml" && *reported == mode
            ),
            "mode {mode:#o} ({bit}) must be refused, reporting the mode it was set to; got {result:?}"
        );
        assert!(result.unwrap_err().refuses_start());
    }
}

// Proves DI-36.
#[test]
fn an_unreadable_or_unparsable_fragment_is_a_deny_all_error() {
    for (label, bytes) in [
        ("a parse error", b"this is = = not toml".to_vec()),
        (
            "an invalid regex",
            b"[raw_exec]\nallow = [\"[x\"]\n".to_vec(),
        ),
        ("non-UTF-8 content", vec![0xff, 0xfe, b'\n']),
    ] {
        let layout = Layout::new(Some(ALLOW_NGINX));
        layout.create_dir();
        layout.fragment("good.toml", ALLOW_SSHD);
        write_secure_policy(&layout.dir().join("bad.toml"), &bytes, 0o644);

        let err = layout.load().expect_err(label);
        assert!(!err.refuses_start(), "{label}: got {err:?}");
        assert!(
            err.to_string().contains("\"bad.toml\""),
            "{label}: the error names the fragment: {err}"
        );
    }

    // A refusal wins over a deny-all error, wherever each sits in the directory.
    let layout = Layout::new(Some(ALLOW_NGINX));
    layout.create_dir();
    layout.fragment("a-broken.toml", "= =");
    std::os::unix::fs::symlink("/nonexistent", layout.dir().join("b-link.toml")).unwrap();
    layout.fragment("c-broken.toml", "= =");
    let err = layout.load().unwrap_err();
    assert!(
        matches!(err, PolicyError::FragmentSymlink { .. }),
        "got {err:?}"
    );
}

// Proves DI-36.
#[test]
fn a_mistyped_table_in_a_fragment_cannot_leave_the_base_allow_active() {
    let layout = Layout::new(Some(ALLOW_NGINX));
    layout.create_dir();
    layout.fragment("90-deny.toml", "[[denny]]\nname = \"service.restart\"\n");

    let err = layout
        .load()
        .expect_err("an unknown key makes the fragment unparsable");
    assert!(
        matches!(&err, PolicyError::FragmentInvalid { name, .. } if name == "90-deny.toml"),
        "got {err:?}"
    );
    assert!(
        !err.refuses_start(),
        "an unparsable fragment is deny-all, not a refusal"
    );
    let message = err.to_string();
    assert!(
        message.contains("\"90-deny.toml\"") && message.contains("denny"),
        "the error names the fragment and the key: {message}"
    );
}

#[test]
fn an_unknown_key_in_the_policy_file_is_a_parse_error() {
    for text in [
        "[[denny]]\nname = \"service.restart\"\n",
        "[raw_exec]\nalow = [\"^ls$\"]\n",
        "[[deny]]\nnmae = \"service.restart\"\nname = \"service.restart\"\n",
        "[[operation]]\nname = \"service.restart\"\nallowed_arg = [[\"nginx\"]]\n",
    ] {
        let layout = Layout::new(Some(text));
        let err = layout.load().expect_err(text);
        assert!(matches!(&err, PolicyError::Parse(_)), "{text}: got {err:?}");
        assert!(!err.refuses_start(), "{text}");
    }
}

// Proves DI-36.
#[test]
fn a_fragment_change_applies_at_the_next_load() {
    let layout = Layout::new(Some(ALLOW_NGINX));
    layout.create_dir();
    layout.fragment("f.toml", ALLOW_SSHD);
    let held = layout.load().expect("loads");
    let held_fingerprint = held.fingerprint().to_string();
    assert!(matches!(
        restart_decision(&held, "sshd"),
        Decision::Allow(_)
    ));

    layout.fragment("f.toml", DENY_SSHD);
    assert_eq!(
        held.fingerprint(),
        held_fingerprint,
        "a loaded Policy does not change when a fragment does"
    );
    assert!(matches!(
        restart_decision(&held, "sshd"),
        Decision::Allow(_)
    ));

    let reloaded = layout.load().expect("loads");
    assert_ne!(reloaded.fingerprint(), held_fingerprint);
    assert!(matches!(
        restart_decision(&reloaded, "sshd"),
        Decision::Deny { .. }
    ));
}

#[test]
fn a_third_party_owned_fragment_or_directory_refuses_start() {
    if !rustix::process::geteuid().is_root() {
        eprintln!("skipped: needs root to chown a fixture to a third-party uid");
        return;
    }
    let layout = Layout::new(Some(ALLOW_NGINX));
    layout.create_dir();
    layout.fragment("owned.toml", ALLOW_SSHD);
    layout.load().expect("root-owned fragments load");

    std::os::unix::fs::chown(layout.dir().join("owned.toml"), Some(65534), None).unwrap();
    let result = layout.load();
    assert!(
        matches!(
            &result,
            Err(PolicyError::FragmentInsecureOwner { uid: 65534, .. })
        ),
        "got {result:?}"
    );
    assert!(result.unwrap_err().refuses_start());

    std::os::unix::fs::chown(layout.dir().join("owned.toml"), Some(0), None).unwrap();
    std::os::unix::fs::chown(layout.dir(), Some(65534), None).unwrap();
    let result = layout.load();
    assert!(
        matches!(
            &result,
            Err(PolicyError::PolicyDirectoryInsecureOwner { uid: 65534 })
        ),
        "got {result:?}"
    );
    assert!(result.unwrap_err().refuses_start());
}

#[test]
fn an_insecure_policy_directory_refuses_start() {
    // A symlink where the directory should be.
    let layout = Layout::new(Some(ALLOW_NGINX));
    let real = layout.root.path().join("real-dir");
    std::fs::create_dir(&real).unwrap();
    set_mode(&real, 0o755);
    std::os::unix::fs::symlink(&real, layout.dir()).unwrap();
    let err = layout.load().unwrap_err();
    assert!(
        matches!(err, PolicyError::PolicyDirectorySymlink),
        "got {err:?}"
    );
    assert!(err.refuses_start());

    // A file where the directory should be.
    let layout = Layout::new(Some(ALLOW_NGINX));
    write_secure_policy(&layout.dir(), b"", 0o644);
    let err = layout.load().unwrap_err();
    assert!(
        matches!(err, PolicyError::PolicyDirectoryNotADirectory),
        "got {err:?}"
    );
    assert!(err.refuses_start());

    // Group- or world-writable: whoever can write it can delete a deny fragment.
    for mode in [0o775_u32, 0o757] {
        let layout = Layout::new(Some(ALLOW_NGINX));
        layout.create_dir();
        set_mode(&layout.dir(), mode);
        let err = layout.load().unwrap_err();
        assert!(
            matches!(&err, PolicyError::PolicyDirectoryInsecurePermissions { mode: m } if *m == mode),
            "mode {mode:#o}: got {err:?}"
        );
        assert!(err.refuses_start());
    }
}

#[test]
fn a_missing_policy_file_with_fragments_is_deny_all() {
    let layout = Layout::new(None);
    layout.create_dir();
    layout.fragment("f.toml", ALLOW_SSHD);
    let err = layout.load().unwrap_err();
    assert!(
        !err.refuses_start(),
        "a missing Policy file stays deny-all, fragments or not; got {err:?}"
    );

    // A refusal in the directory still wins over the missing file.
    std::os::unix::fs::symlink("/nonexistent", layout.dir().join("link.toml")).unwrap();
    assert!(layout.load().unwrap_err().refuses_start());
}
