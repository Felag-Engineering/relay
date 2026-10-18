//! `relay-daemon join`: configures a fresh Node in one step (DI-37). It reads a join
//! string from a prompt with echo off, or from standard input, and never from its
//! arguments; validates it offline; writes it as the environment file's `RELAY_JOIN`
//! line, root-owned and readable by nobody else; then enables and starts the unit
//! through `systemctl` (the spawn lives in [`systemctl`]). It refuses on a Node that
//! holds any identity file, changing nothing, and it contacts no Relay: enrollment
//! happens when the daemon starts.
//!
//! The join string is held as the redacting `JoinString` once decoded; no message
//! this module prints carries it or any part of it.

mod systemctl;

use std::ffi::{OsStr, OsString};
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufRead, IsTerminal, Read, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{fchown, OpenOptionsExt};
use std::os::unix::io::{AsRawFd, RawFd};
use std::path::{Path, PathBuf};

use crate::config::{self, ConfigError, IdentityState, MAX_JOIN_STRING_LEN};
use crate::enroll::state_dir_from_env;

/// The environment file the packaged unit reads (`EnvironmentFile=` in
/// `relay-daemon.service`), and so the one `join` writes.
pub const ENV_FILE: &str = "/etc/relay-daemon/relay-daemon.env";

/// The mode requested for the environment file. A request, never forced: the umask
/// may tighten it and nothing here widens it back (ADR-0036).
const ENV_FILE_MODE: u32 = 0o600;

/// The uid and gid the environment file is given.
type Owner = (u32, u32);

const ROOT: Owner = (0, 0);

/// Why `join` refused or failed. No variant holds the join string or input text.
#[derive(Debug, thiserror::Error)]
pub enum JoinError {
    #[error(
        "takes no arguments: the join string is read from a prompt or standard input, never \
         from the command line, where the process list and shell history would keep it"
    )]
    Arguments,
    #[error("must run as root: it writes {ENV_FILE} and starts relay-daemon.service")]
    NotRoot,
    #[error("{} is not a regular file; nothing was changed", path.display())]
    EnvFileNotRegular { path: PathBuf },
    #[error("cannot read {}: {source}", path.display())]
    EnvFileUnreadable { path: PathBuf, source: io::Error },
    #[error(
        "this Node already holds an identity in {}: join configures only a fresh Node; \
         nothing was changed",
        state_dir.display()
    )]
    AlreadyEnrolled { state_dir: PathBuf },
    #[error("{0}")]
    Identity(ConfigError),
    #[error("cannot read the join string: {0}")]
    Read(io::Error),
    #[error("no join string was given; nothing was changed")]
    Empty,
    #[error("refused, nothing was changed: {0}")]
    Invalid(ConfigError),
    #[error("cannot write {}: {source}; it is unchanged", path.display())]
    Write { path: PathBuf, source: io::Error },
    #[error(
        "the join string is written, but running systemctl failed: {0}; start the daemon \
         with `systemctl enable --now relay-daemon.service`"
    )]
    Spawn(io::Error),
    #[error(
        "the join string is written, but `systemctl enable --now relay-daemon.service` \
         exited with {0}"
    )]
    Systemctl(std::process::ExitStatus),
}

impl JoinError {
    /// 2 for a usage error, as the other subcommands use; 1 for everything else.
    fn exit_code(&self) -> i32 {
        match self {
            JoinError::Arguments => 2,
            _ => 1,
        }
    }
}

/// Where `join` reads and writes. Production is [`JoinPaths::production`]; tests
/// point it into a temporary directory.
struct JoinPaths {
    env_file: PathBuf,
    /// The state directory named by the process environment (or the default).
    /// The one the environment file names, if any, is checked as well.
    state_dir: PathBuf,
}

impl JoinPaths {
    fn production() -> Self {
        JoinPaths {
            env_file: PathBuf::from(ENV_FILE),
            state_dir: state_dir_from_env(),
        }
    }
}

/// Runs `relay-daemon join` with the arguments after `join`; returns the exit code.
pub fn run(args: &[String]) -> i32 {
    match run_checked(args) {
        Ok(()) => {
            eprintln!(
                "relay-daemon join: wrote {ENV_FILE}; relay-daemon.service is enabled and \
                 started, and enrolls as it starts (journalctl -u relay-daemon)"
            );
            0
        }
        Err(e) => {
            eprintln!("relay-daemon join: {e}");
            e.exit_code()
        }
    }
}

fn run_checked(args: &[String]) -> Result<(), JoinError> {
    // Checked first, before anything is read: a join string in argv is refused and
    // never echoed back.
    if !args.is_empty() {
        return Err(JoinError::Arguments);
    }
    if !rustix::process::geteuid().is_root() {
        return Err(JoinError::NotRoot);
    }
    configure(&JoinPaths::production(), ROOT, read_join_input)?;
    let status = systemctl::enable_and_start().map_err(JoinError::Spawn)?;
    if !status.success() {
        return Err(JoinError::Systemctl(status));
    }
    Ok(())
}

/// Everything `join` does before starting the unit. The refusals run before the
/// join string is read, so a Node that refuses is never handed the secret, and each
/// leaves the environment file byte-identical.
fn configure(
    paths: &JoinPaths,
    owner: Owner,
    read_input: impl FnOnce() -> Result<String, JoinError>,
) -> Result<(), JoinError> {
    let existing = read_env_file(&paths.env_file)?;

    let mut state_dirs = vec![paths.state_dir.clone()];
    if let Some(named) = existing.as_deref().and_then(env_file_state_dir) {
        if !state_dirs.contains(&named) {
            state_dirs.push(named);
        }
    }
    for state_dir in state_dirs {
        match config::identity_state(&state_dir).map_err(JoinError::Identity)? {
            IdentityState::Absent => {}
            IdentityState::Partial { .. } | IdentityState::Complete => {
                return Err(JoinError::AlreadyEnrolled { state_dir })
            }
        }
    }

    // Surrounding whitespace, the newline included, is never part of a join string.
    let raw = read_input()?;
    let join = config::decode_join(Some(raw.trim().to_string()))
        .map_err(JoinError::Invalid)?
        .ok_or(JoinError::Empty)?;

    let mut line = b"RELAY_JOIN=".to_vec();
    line.extend_from_slice(
        join.encode()
            .map_err(|e| JoinError::Invalid(ConfigError::MalformedJoin(e)))?
            .as_bytes(),
    );
    let content = with_join_line(existing.as_deref(), &line);
    write_atomically(&paths.env_file, &content, owner).map_err(|source| JoinError::Write {
        path: paths.env_file.clone(),
        source,
    })
}

/// The environment file's bytes, or `None` when there is none. A symlink or any
/// other non-regular file is refused: the rename would replace the link, not what
/// it points at.
fn read_env_file(path: &Path) -> Result<Option<Vec<u8>>, JoinError> {
    match fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_file() => {}
        Ok(_) => {
            return Err(JoinError::EnvFileNotRegular {
                path: path.to_path_buf(),
            })
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(source) => {
            return Err(JoinError::EnvFileUnreadable {
                path: path.to_path_buf(),
                source,
            })
        }
    }
    fs::read(path)
        .map(Some)
        .map_err(|source| JoinError::EnvFileUnreadable {
            path: path.to_path_buf(),
            source,
        })
}

/// The value `line` assigns to `key`, if it is an assignment of `key`: optional
/// leading whitespace, the key, optional blanks, `=`.
fn assignment<'a>(line: &'a [u8], key: &[u8]) -> Option<&'a [u8]> {
    let rest = line.trim_ascii_start().strip_prefix(key)?;
    let rest = rest.trim_ascii_start();
    rest.strip_prefix(b"=")
}

/// `RELAY_STATE_DIR` as the environment file sets it (the last assignment wins, as
/// systemd reads it), with one pair of surrounding quotes removed.
fn env_file_state_dir(content: &[u8]) -> Option<PathBuf> {
    let value = content
        .split(|b| *b == b'\n')
        .rev()
        .find_map(|line| assignment(line, b"RELAY_STATE_DIR"))?
        .trim_ascii();
    let value = match value {
        [q @ (b'"' | b'\''), inner @ .., last] if last == q => inner,
        v => v,
    };
    (!value.is_empty()).then(|| PathBuf::from(OsStr::from_bytes(value)))
}

/// `existing` with every `RELAY_JOIN` assignment replaced by `line`, or `line`
/// appended when there is none. Every other byte is kept as it was.
fn with_join_line(existing: Option<&[u8]>, line: &[u8]) -> Vec<u8> {
    let existing = existing.unwrap_or_default();
    let mut out = Vec::with_capacity(existing.len() + line.len() + 1);
    let mut replaced = false;
    for segment in existing.split_inclusive(|b| *b == b'\n') {
        if assignment(segment, b"RELAY_JOIN").is_some() {
            out.extend_from_slice(line);
            out.push(b'\n');
            replaced = true;
        } else {
            out.extend_from_slice(segment);
        }
    }
    if !replaced {
        if !out.is_empty() && !out.ends_with(b"\n") {
            out.push(b'\n');
        }
        out.extend_from_slice(line);
        out.push(b'\n');
    }
    out
}

/// Replaces `path` with `content` atomically: a new temporary file in the same
/// directory, mode [`ENV_FILE_MODE`] requested, given to `owner`, written and
/// synced, then renamed over `path`. On any failure the temporary file is removed
/// and `path` is untouched.
fn write_atomically(path: &Path, content: &[u8], owner: Owner) -> io::Result<()> {
    let dir = match path.parent() {
        Some(d) if !d.as_os_str().is_empty() => d,
        _ => Path::new("."),
    };
    let name = path
        .file_name()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "no file name"))?;
    let mut tmp_name = OsString::from(".");
    tmp_name.push(name);
    tmp_name.push(format!(".join-{}.tmp", std::process::id()));
    let tmp = dir.join(tmp_name);

    // create_new is O_CREAT|O_EXCL: it never opens an existing file or follows a
    // symlink planted at the temporary name, and a file it did not create is never
    // removed below.
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(ENV_FILE_MODE)
        .open(&tmp)?;
    let result = (|| {
        fchown(&file, Some(owner.0), Some(owner.1))?;
        file.write_all(content)?;
        file.sync_all()?;
        fs::rename(&tmp, path)
    })();
    drop(file);
    if let Err(e) = result {
        let _ = fs::remove_file(&tmp);
        return Err(e);
    }
    File::open(dir)?.sync_all()
}

/// Reads one line from standard input: behind a prompt with echo off when it is a
/// terminal, as piped text otherwise. At most a little over the longest join string
/// is read, so an oversized input is refused by the decoder rather than buffered.
fn read_join_input() -> Result<String, JoinError> {
    let stdin = io::stdin();
    let interactive = stdin.is_terminal();
    let mut buf = Vec::new();
    {
        let _echo = if interactive {
            eprint!("Paste the join string (input is hidden): ");
            let _ = io::stderr().flush();
            Some(EchoOff::new(stdin.as_raw_fd()).map_err(JoinError::Read)?)
        } else {
            None
        };
        stdin
            .lock()
            .take(MAX_JOIN_STRING_LEN as u64 + 2)
            .read_until(b'\n', &mut buf)
            .map_err(JoinError::Read)?;
    }
    if interactive {
        eprintln!();
    }
    String::from_utf8(buf).map_err(|_| JoinError::Invalid(ConfigError::JoinNotUnicode))
}

/// Turns terminal echo off for its lifetime and restores the saved settings on drop.
struct EchoOff {
    fd: RawFd,
    saved: libc::termios,
}

impl EchoOff {
    fn new(fd: RawFd) -> io::Result<Self> {
        let saved = tc_get(fd)?;
        let mut quiet = saved;
        quiet.c_lflag &= !libc::ECHO;
        tc_set(fd, &quiet)?;
        Ok(EchoOff { fd, saved })
    }
}

impl Drop for EchoOff {
    fn drop(&mut self) {
        let _ = tc_set(self.fd, &self.saved);
    }
}

fn tc_get(fd: RawFd) -> io::Result<libc::termios> {
    let mut t = std::mem::MaybeUninit::<libc::termios>::uninit();
    // SAFETY: tcgetattr writes a whole termios through a pointer valid for one, and
    // the value is read only when it reports success, so it is initialised then. It
    // reads terminal settings and can neither write a file nor spawn.
    unsafe {
        if libc::tcgetattr(fd, t.as_mut_ptr()) != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(t.assume_init())
    }
}

fn tc_set(fd: RawFd, t: &libc::termios) -> io::Result<()> {
    // SAFETY: `t` is a valid, initialised termios borrowed for the call, which only
    // reads it; tcsetattr changes terminal settings and can neither write a file nor
    // spawn.
    if unsafe { libc::tcsetattr(fd, libc::TCSANOW, t) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::TempDir;
    use relay_transport::join_string::JoinString;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    fn me() -> Owner {
        (
            rustix::process::geteuid().as_raw(),
            rustix::process::getegid().as_raw(),
        )
    }

    fn join_text(addr: &str) -> String {
        JoinString::new(addr.to_string(), [9u8; 32], "tok-join-test".to_string())
            .encode()
            .expect("encode")
    }

    const ENV: &str = "# comment\n#RELAY_JOIN=old-commented\nRELAY_POLICY_PATH=/etc/relay-daemon/policy.toml\nRELAY_JOIN=replace-me\n#RELAY_ADDR=https://x:1\nRELAY_TEMPLATE_DIR=/etc/relay-daemon/templates.d\n";

    struct Fixture {
        _dir: TempDir,
        paths: JoinPaths,
    }

    fn fixture(label: &str, env: Option<&[u8]>) -> Fixture {
        let dir = TempDir::created(label);
        let env_file = dir.path().join("relay-daemon.env");
        if let Some(content) = env {
            fs::write(&env_file, content).expect("write env file");
        }
        let state_dir = dir.path().join("state");
        fs::create_dir(&state_dir).expect("state dir");
        Fixture {
            paths: JoinPaths {
                env_file,
                state_dir,
            },
            _dir: dir,
        }
    }

    fn no_read() -> Result<String, JoinError> {
        panic!("the join string must not be read once join has refused")
    }

    fn leftovers(dir: &Path) -> Vec<String> {
        fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .filter(|n| n.contains(".join-"))
            .collect()
    }

    #[test]
    fn join_refuses_argv_join_string() {
        let secret = join_text("relay.example:7654");
        let err = run_checked(std::slice::from_ref(&secret)).expect_err("argv must be refused");
        assert!(matches!(err, JoinError::Arguments));
        assert_eq!(err.exit_code(), 2);
        assert!(
            !err.to_string().contains(&secret) && !err.to_string().contains("tok-join-test"),
            "the refusal never echoes what was passed"
        );
        assert_eq!(run(&[secret]), 2);
        assert_eq!(run(&["--token".to_string(), "x".to_string()]), 2);
    }

    #[test]
    fn join_refuses_existing_identity_env_file_unchanged() {
        for name in config::IDENTITY_FILES {
            let f = fixture("join-identity", Some(ENV.as_bytes()));
            fs::write(f.paths.state_dir.join(name), b"x").unwrap();
            let before = fs::metadata(&f.paths.env_file).unwrap();
            let err = configure(&f.paths, me(), no_read).expect_err("must refuse");
            assert!(
                matches!(err, JoinError::AlreadyEnrolled { .. }),
                "{name}: got {err}"
            );
            assert_eq!(
                fs::read(&f.paths.env_file).unwrap(),
                ENV.as_bytes(),
                "{name}"
            );
            let after = fs::metadata(&f.paths.env_file).unwrap();
            assert_eq!((before.ino(), before.mtime()), (after.ino(), after.mtime()));
            assert!(leftovers(f.paths.env_file.parent().unwrap()).is_empty());
        }
    }

    #[test]
    fn join_refuses_identity_in_the_state_dir_the_env_file_names() {
        let dir = TempDir::created("join-env-state-dir");
        let named = dir.path().join("named");
        fs::create_dir(&named).unwrap();
        fs::write(named.join("cert.pem"), b"x").unwrap();
        let env = format!("{ENV}RELAY_STATE_DIR=\"{}\"\n", named.display());
        let f = fixture("join-env-state", Some(env.as_bytes()));
        let err = configure(&f.paths, me(), no_read).expect_err("must refuse");
        assert!(matches!(err, JoinError::AlreadyEnrolled { ref state_dir } if *state_dir == named));
        assert_eq!(fs::read(&f.paths.env_file).unwrap(), env.as_bytes());
    }

    #[test]
    fn join_writes_env_file_root_0600_atomically() {
        let f = fixture("join-write", Some(ENV.as_bytes()));
        fs::set_permissions(&f.paths.env_file, fs::Permissions::from_mode(0o644)).unwrap();
        let before = fs::metadata(&f.paths.env_file).unwrap().ino();
        let text = join_text("relay.example:7654");
        let input = text.clone();
        configure(&f.paths, me(), move || Ok(format!("  {input}\r\n"))).expect("join configures");

        let want = ENV.replace("RELAY_JOIN=replace-me", &format!("RELAY_JOIN={text}"));
        assert_eq!(
            String::from_utf8(fs::read(&f.paths.env_file).unwrap()).unwrap(),
            want,
            "only the RELAY_JOIN line changes"
        );
        let meta = fs::metadata(&f.paths.env_file).unwrap();
        assert_ne!(
            meta.ino(),
            before,
            "replaced by rename, never rewritten in place"
        );
        assert_eq!(
            meta.mode() & 0o777 & !0o600,
            0,
            "readable by nobody but its owner"
        );
        assert_eq!((meta.uid(), meta.gid()), me());
        assert_eq!(ROOT, (0, 0), "production gives the file to root");
        assert!(leftovers(f.paths.env_file.parent().unwrap()).is_empty());
    }

    #[test]
    fn join_appends_a_missing_line_and_creates_a_missing_file() {
        let text = join_text("[fd00::1]:7654");
        let f = fixture("join-append", Some(b"RELAY_POLICY_PATH=/p"));
        let input = text.clone();
        configure(&f.paths, me(), move || Ok(input)).expect("append");
        assert_eq!(
            fs::read(&f.paths.env_file).unwrap(),
            format!("RELAY_POLICY_PATH=/p\nRELAY_JOIN={text}\n").as_bytes()
        );

        let f = fixture("join-create", None);
        let input = text.clone();
        configure(&f.paths, me(), move || Ok(input)).expect("create");
        assert_eq!(
            fs::read(&f.paths.env_file).unwrap(),
            format!("RELAY_JOIN={text}\n").as_bytes()
        );
        let meta = fs::metadata(&f.paths.env_file).unwrap();
        assert_eq!(meta.mode() & 0o777 & !0o600, 0);
    }

    #[test]
    fn join_replaces_every_assignment_of_relay_join() {
        let text = join_text("relay:7654");
        let env = b"RELAY_JOIN=a\nX=1\n  RELAY_JOIN = b\nRELAY_JOINed=keep\n";
        let f = fixture("join-every", Some(env));
        let input = text.clone();
        configure(&f.paths, me(), move || Ok(input)).expect("join");
        assert_eq!(
            fs::read(&f.paths.env_file).unwrap(),
            format!("RELAY_JOIN={text}\nX=1\nRELAY_JOIN={text}\nRELAY_JOINed=keep\n").as_bytes()
        );
    }

    #[test]
    fn join_refuses_a_malformed_or_empty_join_string_env_file_unchanged() {
        for (input, empty) in [
            ("glp_join_not!base64", false),
            ("not-a-join-string", false),
            ("", true),
            ("   \n", true),
        ] {
            let f = fixture("join-malformed", Some(ENV.as_bytes()));
            let owned = input.to_string();
            let err = configure(&f.paths, me(), move || Ok(owned)).expect_err("must refuse");
            if empty {
                assert!(matches!(err, JoinError::Empty), "{input:?}: {err}");
            } else {
                assert!(matches!(err, JoinError::Invalid(_)), "{input:?}: {err}");
            }
            assert_eq!(fs::read(&f.paths.env_file).unwrap(), ENV.as_bytes());
            assert!(leftovers(f.paths.env_file.parent().unwrap()).is_empty());
        }
        // A join string whose address could redirect the dial is refused offline too.
        let f = fixture("join-bad-addr", Some(ENV.as_bytes()));
        let bad = join_text("https://relay:7654/x");
        let err = configure(&f.paths, me(), move || Ok(bad)).expect_err("must refuse");
        assert!(matches!(
            err,
            JoinError::Invalid(ConfigError::BadJoinAddress(_))
        ));
        assert!(!err.to_string().contains("tok-join-test"));
        assert_eq!(fs::read(&f.paths.env_file).unwrap(), ENV.as_bytes());
    }

    #[test]
    fn join_refuses_a_symlinked_env_file() {
        let f = fixture("join-symlink", None);
        let target = f.paths.state_dir.parent().unwrap().join("target.env");
        fs::write(&target, ENV).unwrap();
        std::os::unix::fs::symlink(&target, &f.paths.env_file).unwrap();
        let err = configure(&f.paths, me(), no_read).expect_err("must refuse");
        assert!(matches!(err, JoinError::EnvFileNotRegular { .. }));
        assert_eq!(fs::read(&target).unwrap(), ENV.as_bytes());
        assert!(fs::symlink_metadata(&f.paths.env_file)
            .unwrap()
            .file_type()
            .is_symlink());
    }

    #[test]
    fn env_file_state_dir_reads_the_last_assignment() {
        assert_eq!(env_file_state_dir(b"#RELAY_STATE_DIR=/a\n"), None);
        assert_eq!(
            env_file_state_dir(b"RELAY_STATE_DIR=/a\nRELAY_STATE_DIR='/b'\n"),
            Some(PathBuf::from("/b"))
        );
        assert_eq!(env_file_state_dir(b"RELAY_STATE_DIR=\n"), None);
    }

    /// `join` writes the file the packaged unit reads and starts that unit.
    #[test]
    fn env_file_and_unit_match_the_packaged_unit() {
        let unit = fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/packaging/relay-daemon.service"
        ))
        .expect("read the packaged unit");
        assert!(unit.contains(&format!("EnvironmentFile=-{ENV_FILE}\n")));
        assert_eq!(systemctl::SYSTEMCTL_ARGS[2], "relay-daemon.service");
    }
}
