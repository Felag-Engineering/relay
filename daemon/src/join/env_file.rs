//! The one place `relay-daemon join` writes (DI-37): replacing the environment file
//! atomically, and removing temporary files an interrupted run left behind. It is
//! on `policy_never_opened_for_write.rs`'s write-site allowlist and never names the
//! Policy path.

use std::ffi::{OsStr, OsString};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{fchown, OpenOptionsExt};
use std::path::{Path, PathBuf};

/// The mode requested for the environment file. A request, never forced: the umask
/// may tighten it and nothing here widens it back (ADR-0036).
const ENV_FILE_MODE: u32 = 0o600;

/// Why the environment file could not be replaced.
#[derive(Debug, thiserror::Error)]
pub enum WriteError {
    /// Nothing was renamed: the environment file is as it was.
    #[error("cannot write {}: {source}; it is unchanged", path.display())]
    Unchanged { path: PathBuf, source: io::Error },
    /// A leftover temporary file could not be removed; nothing was written.
    #[error(
        "cannot remove the leftover temporary file {} ({reason}); remove it by hand. \
         Nothing was changed",
        path.display()
    )]
    Leftover { path: PathBuf, reason: String },
    /// The rename happened, so the new file is in place, but the directory entry
    /// may not survive a crash.
    #[error(
        "wrote {}, but syncing its directory failed: {source}; the change may not survive \
         a crash",
        path.display()
    )]
    DirSync { path: PathBuf, source: io::Error },
}

/// The directory `path` is in, and the prefix and suffix of the temporary names
/// written beside it.
fn temp_parts(path: &Path) -> io::Result<(&Path, OsString, &'static str)> {
    let dir = match path.parent() {
        Some(d) if !d.as_os_str().is_empty() => d,
        _ => Path::new("."),
    };
    let name = path
        .file_name()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "no file name"))?;
    let mut prefix = OsString::from(".");
    prefix.push(name);
    prefix.push(".join-");
    Ok((dir, prefix, ".tmp"))
}

/// Removes every `.<name>.join-*.tmp` beside `path`. An interrupted run leaves one
/// holding the join string, under a name the shipped Policy's confidentiality
/// deny-list does not cover, so it is never left in place. Only regular files are
/// removed and nothing is followed; anything else under such a name refuses.
pub fn remove_stale_temps(path: &Path) -> Result<(), WriteError> {
    let unchanged = |source| WriteError::Unchanged {
        path: path.to_path_buf(),
        source,
    };
    let (dir, prefix, suffix) = temp_parts(path).map_err(unchanged)?;
    let entries = match fs::read_dir(dir) {
        Ok(e) => e,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(unchanged(e)),
    };
    for entry in entries {
        let entry = entry.map_err(unchanged)?;
        let name = entry.file_name();
        let bytes = name.as_bytes();
        if !(bytes.starts_with(prefix.as_bytes()) && bytes.ends_with(suffix.as_bytes())) {
            continue;
        }
        let stale = dir.join(&name);
        let leftover = |reason: String| WriteError::Leftover {
            path: stale.clone(),
            reason,
        };
        let meta = fs::symlink_metadata(&stale).map_err(|e| leftover(e.to_string()))?;
        if !meta.file_type().is_file() {
            return Err(leftover("not a regular file".to_string()));
        }
        fs::remove_file(&stale).map_err(|e| leftover(e.to_string()))?;
    }
    Ok(())
}

/// Replaces `path` with `content` atomically: a new temporary file in the same
/// directory, mode [`ENV_FILE_MODE`] requested, given to `owner`, written and
/// synced, then renamed over `path`, then the directory synced. Until the rename
/// `path` is untouched, and a temporary file this call created is removed on
/// failure.
pub fn write_atomically(path: &Path, content: &[u8], owner: (u32, u32)) -> Result<(), WriteError> {
    let unchanged = |source| WriteError::Unchanged {
        path: path.to_path_buf(),
        source,
    };
    let (dir, mut tmp_name, suffix) = temp_parts(path).map_err(unchanged)?;
    tmp_name.push(std::process::id().to_string());
    tmp_name.push(suffix);
    let tmp = dir.join(OsStr::new(&tmp_name));

    // create_new is O_CREAT|O_EXCL: it never opens an existing file or follows a
    // symlink planted at the temporary name, and a file it did not create is never
    // removed below.
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(ENV_FILE_MODE)
        .open(&tmp)
        .map_err(unchanged)?;
    let result = (|| {
        fchown(&file, Some(owner.0), Some(owner.1))?;
        file.write_all(content)?;
        file.sync_all()?;
        fs::rename(&tmp, path)
    })();
    drop(file);
    if let Err(e) = result {
        let _ = fs::remove_file(&tmp);
        return Err(unchanged(e));
    }
    File::open(dir)
        .and_then(|d| d.sync_all())
        .map_err(|source| WriteError::DirSync {
            path: path.to_path_buf(),
            source,
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::TempDir;

    fn me() -> (u32, u32) {
        (
            rustix::process::geteuid().as_raw(),
            rustix::process::getegid().as_raw(),
        )
    }

    #[test]
    fn stale_temp_files_are_removed_and_nothing_else() {
        let dir = TempDir::created("join-stale");
        let env = dir.path().join("relay-daemon.env");
        let stale = dir.path().join(".relay-daemon.env.join-4242.tmp");
        fs::write(&stale, b"RELAY_JOIN=glp_join_stale\n").unwrap();
        let other = dir.path().join(".relay-daemon.env.join-4242.keep");
        fs::write(&other, b"x").unwrap();
        let unrelated = dir.path().join("policy.toml");
        fs::write(&unrelated, b"x").unwrap();

        remove_stale_temps(&env).expect("cleanup");
        assert!(
            !stale.exists(),
            "a leftover temporary file holding the token is removed"
        );
        assert!(
            other.exists() && unrelated.exists(),
            "nothing else is touched"
        );

        write_atomically(&env, b"RELAY_JOIN=x\n", me()).expect("write");
        assert_eq!(fs::read(&env).unwrap(), b"RELAY_JOIN=x\n");
    }

    #[test]
    fn a_symlink_under_a_temp_name_refuses_and_is_not_followed() {
        let dir = TempDir::created("join-stale-link");
        let env = dir.path().join("relay-daemon.env");
        let target = dir.path().join("target");
        fs::write(&target, b"keep").unwrap();
        let link = dir.path().join(".relay-daemon.env.join-1.tmp");
        std::os::unix::fs::symlink(&target, &link).unwrap();

        let err = remove_stale_temps(&env).expect_err("must refuse");
        assert!(matches!(err, WriteError::Leftover { .. }), "{err}");
        assert_eq!(fs::read(&target).unwrap(), b"keep");
        assert!(fs::symlink_metadata(&link)
            .unwrap()
            .file_type()
            .is_symlink());
    }
}
