//! `relay-daemon join`: enrolls this Node, in the process that read the join
//! string (DI-42). It reads the join string from a prompt with echo off, or from
//! standard input, never from its arguments; pins the Relay's CA from the string's
//! fingerprint and enrolls through `relay_transport`'s pinned enrollment path
//! (`enroll::ensure_enrolled`); persists the identity and the Relay address; then
//! enables and starts the unit through `systemctl` (the spawn is in
//! [`systemctl`]). The daemon reads no join string, so the string is written
//! nowhere and never sits in an environment: the environment file is read here,
//! never written.
//!
//! Settings. When the environment file exists it governs, as it does for
//! `relay-daemon.service`, and a process-environment value for a setting `join`
//! reads that the file does not assign identically is refused before anything is
//! read. Without an environment file the process environment governs. `join`
//! parses a subset of systemd's `EnvironmentFile=` grammar and refuses what lies
//! outside it: a value it reads that holds a backslash or an unbalanced quote, and
//! any line ending in a backslash. It reads one file; an `Environment=` or extra
//! `EnvironmentFile=` in a drop-in can still give the unit a `RELAY_STATE_DIR` it
//! never sees.
//!
//! Order. Every refusal happens before the join string is read and before any
//! dial, and writes nothing. An existing state directory is checked before anything
//! in it is read: it is refused if it is a symlink, group- or world-writable, or
//! owned by neither root nor the user `join` runs as, and `relay_addr` is opened
//! without following a symlink under the same owner and mode rule. An existing
//! identity is found next, so a rerun by config management exits 0 whatever its
//! shell exports. After the read, `join` takes an exclusive lock on the state
//! directory and looks for an identity again, so a second `join` is refused while
//! the first runs and one that lost the race finds the first's identity. The
//! enrollment then races an interrupt: a failed or interrupted enrollment removes
//! what `join` created and restores what it changed, so the state directory is as
//! it was found, and the message says what, if anything, could not be put back. A SIGKILL cannot be caught; one inside the
//! persist leaves a partial identity, which every rerun refuses with the missing
//! files named.
//!
//! The unit is started only where systemd runs and only for the state directory
//! the unit reads. Signals: SIGINT, SIGTERM and SIGHUP are caught from the end of
//! the read to the end of the run, so a Ctrl-C during `systemctl` reaches
//! `systemctl` (the foreground group) and `join` waits for it to exit.
//!
//! The join string is held as the redacting `JoinString` once decoded, and every
//! buffer this module owns that holds its text is wiped when dropped. Standard
//! input is read unbuffered and the decoder is wiped; the enroller's copy is wiped
//! only if enrollment ends before the request is built. The copies inside prost,
//! tonic, h2 and rustls cannot be wiped. No message this module prints carries the
//! join string or any part of it.

mod systemctl;

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::{OsStr, OsString};
use std::fs;
use std::future::Future;
use std::io::{self, IsTerminal, Write};
use std::os::fd::AsFd;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::process::ExitStatus;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use rustix::io::Errno;
use rustix::termios::{tcgetattr, tcsetattr, LocalModes, OptionalActions, Termios};
use zeroize::Zeroizing;

use crate::config::{
    self, ConfigError, IdentityState, JOIN_SETTINGS, MAX_JOIN_STRING_LEN, RETIRED_SETTINGS,
};
use crate::enroll::{self, EnrollConfig, EnrollError};
use crate::identity::{self, Identity, IdentityError};

/// The environment file the packaged unit reads (`EnvironmentFile=` in
/// `relay-daemon.service`), and so the one `join` takes its settings from.
pub const ENV_FILE: &str = "/etc/relay-daemon/relay-daemon.env";

/// Present, as a directory, exactly when systemd is the running init; the same
/// test the package's own scripts use.
const SYSTEMD_MARKER: &str = "/run/systemd/system";

/// How long the enrollment, pin handshake included, may take.
const JOIN_ENROLL_TIMEOUT: Duration = Duration::from_secs(60);

/// What to do about a token use a cancelled enrollment may have spent.
const MAY_HAVE_RECORDED: &str = "the Relay may have recorded this enrollment; if the rerun \
     reports the token used up, mint another and revoke the stray Node";

/// The text of a join string as read, wiped when dropped.
type Secret = Zeroizing<String>;

/// Why `join` refused or failed. No variant holds the join string or input text.
#[derive(Debug, thiserror::Error)]
pub enum JoinError {
    #[error(
        "takes no arguments: the join string is read from a prompt or standard input, never \
         from the command line, where the process list and shell history would keep it"
    )]
    Arguments,
    #[error("must run as root: it enrolls into {} and starts relay-daemon.service", dir.display())]
    NotRoot { dir: PathBuf },
    #[error("cannot read {}: run it as root (sudo relay-daemon join)", path.display())]
    NeedsRoot { path: PathBuf },
    #[error("{} is not a regular file; nothing was changed", path.display())]
    EnvFileNotRegular { path: PathBuf },
    #[error("cannot read {}: {source}", path.display())]
    EnvFileUnreadable { path: PathBuf, source: io::Error },
    #[error(
        "{} is outside the part of the environment-file syntax join parses ({reason}); \
         nothing was changed: simplify that line",
        path.display()
    )]
    EnvFileUnparsed { path: PathBuf, reason: String },
    #[error(
        "{name} is set in this shell's environment and the environment file {} does not set \
         it to the same value; relay-daemon.service reads only the file, so join refuses \
         rather than enroll somewhere the unit does not look: unset it here or set it in \
         the file",
        path.display()
    )]
    EnvDisagrees { name: &'static str, path: PathBuf },
    #[error("{name} is not valid UTF-8; nothing was changed")]
    SettingNotUnicode { name: &'static str },
    #[error(
        "RELAY_STATE_DIR must be an absolute path: relay-daemon.service runs with / as its \
         working directory; nothing was changed"
    )]
    RelativeStateDir,
    #[error(
        "{name} is set in {place}; it is not a setting (the daemon refuses to start while it \
         is set) and join does not read it: remove it and run relay-daemon join again; \
         nothing was changed"
    )]
    RetiredSetting { name: &'static str, place: String },
    #[error("{0}")]
    Identity(ConfigError),
    #[error("cannot read the join string: {0}")]
    Read(io::Error),
    #[error("no join string was given; nothing was changed")]
    Empty,
    #[error("refused, nothing was changed: {0}")]
    Invalid(ConfigError),
    #[error("{0}; nothing was changed")]
    StateDir(IdentityError),
    #[error("{source}; {}", unchanged(leftovers))]
    Prepare {
        source: IdentityError,
        leftovers: Vec<PathBuf>,
    },
    #[error("refused, nothing was changed: {0}")]
    Config(EnrollError),
    #[error("cannot catch interrupts: {0}; nothing was changed")]
    Signals(io::Error),
    #[error(
        "enrollment failed: {}; {}{}",
        source.to_string().escape_debug(),
        persisted(leftovers),
        recorded_advice(source)
    )]
    Enroll {
        source: EnrollError,
        leftovers: Vec<PathBuf>,
    },
    #[error(
        "the Relay did not answer within {} seconds; {}; {MAY_HAVE_RECORDED}",
        JOIN_ENROLL_TIMEOUT.as_secs(),
        persisted(leftovers)
    )]
    Timeout { leftovers: Vec<PathBuf> },
    #[error("interrupted; {}; {MAY_HAVE_RECORDED}", persisted(leftovers))]
    Interrupted { leftovers: Vec<PathBuf> },
    #[error(
        "enrolled, but running systemctl failed: {0}; the identity is kept: run \
         `systemctl enable --now relay-daemon.service`"
    )]
    Spawn(io::Error),
    #[error(
        "enrolled, but `systemctl enable --now relay-daemon.service` exited with {0}; the \
         identity is kept: run `systemctl enable --now relay-daemon.service`"
    )]
    Systemctl(ExitStatus),
}

/// What a failed enrollment left, worded from what the rollback reports.
fn persisted(leftovers: &[PathBuf]) -> String {
    if leftovers.is_empty() {
        return "nothing was persisted".to_string();
    }
    not_put_back(leftovers)
}

/// The advice to append when the Relay answered before the failure, which a Relay
/// error such as a rejected token never does.
fn recorded_advice(source: &EnrollError) -> String {
    if source.relay_may_have_recorded() {
        format!("; {MAY_HAVE_RECORDED}")
    } else {
        String::new()
    }
}

/// What a failed preparation of the state directory left.
fn unchanged(leftovers: &[PathBuf]) -> String {
    if leftovers.is_empty() {
        return "nothing was changed".to_string();
    }
    not_put_back(leftovers)
}

/// Neutral on purpose: a leftover is either a path join created and could not
/// remove, or an address it could not restore, and the fix differs.
fn not_put_back(leftovers: &[PathBuf]) -> String {
    let paths: Vec<String> = leftovers.iter().map(|p| p.display().to_string()).collect();
    format!(
        "these could not be put back as they were found; check them before join is rerun: {}",
        paths.join(", ")
    )
}

impl JoinError {
    /// 2 for a usage error, as the other subcommands use; 130 for an interrupt, as
    /// a shell reports one; 1 for everything else.
    fn exit_code(&self) -> i32 {
        match self {
            JoinError::Arguments => 2,
            JoinError::Interrupted { .. } => 130,
            _ => 1,
        }
    }
}

/// Where `join` reads. Production is [`JoinPaths::production`]; tests point all
/// three into a temporary directory.
struct JoinPaths {
    env_file: PathBuf,
    /// The state directory the unit reads when the environment file names none,
    /// and one `join` always checks for an identity.
    default_state_dir: PathBuf,
    systemd_marker: PathBuf,
}

impl JoinPaths {
    fn production() -> Self {
        JoinPaths {
            env_file: PathBuf::from(ENV_FILE),
            default_state_dir: PathBuf::from(enroll::DEFAULT_STATE_DIR),
            systemd_marker: PathBuf::from(SYSTEMD_MARKER),
        }
    }
}

/// Whether the unit is started, decided from where `join` enrolled.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum UnitStart {
    /// systemd runs and the identity is in the directory the unit reads.
    Start,
    /// systemd is not running here, so there is no unit to start.
    NoSystemd,
    /// The identity is somewhere the unit does not look, which can happen only
    /// without an environment file.
    NotTheUnitsStateDir,
}

/// The unit starts only when `effective` is the directory it reads (`units_dir`)
/// and systemd is running.
fn unit_start(effective: &Path, units_dir: &Path, systemd_running: bool) -> UnitStart {
    if !systemd_running {
        UnitStart::NoSystemd
    } else if effective != units_dir {
        UnitStart::NotTheUnitsStateDir
    } else {
        UnitStart::Start
    }
}

/// Where a setting is set.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Place {
    Environment,
    File(PathBuf),
}

impl Place {
    fn describe(&self) -> String {
        match self {
            Place::Environment => "this shell's environment".to_string(),
            Place::File(path) => path.display().to_string(),
        }
    }
}

/// What a `join` run concluded, short of an error.
#[derive(Debug)]
enum Joined {
    /// An identity was already there; nothing was read, written or started.
    AlreadyEnrolled {
        state_dir: PathBuf,
        /// A retired setting that is still set, which the unit refuses to start with.
        retired: Option<(&'static str, Place)>,
    },
    Enrolled {
        node_id: String,
        state_dir: PathBuf,
        unit: UnitStart,
    },
}

/// Why an enrollment attempt ended without an identity.
enum Failed {
    Enroll(EnrollError),
    Timeout,
    Interrupted,
}

/// Runs `relay-daemon join` with the arguments after `join`; returns the exit code.
pub async fn run(args: &[String]) -> i32 {
    // Checked first, before anything is read: a join string in argv is refused and
    // never echoed back.
    let result = if args.is_empty() {
        install_crypto_provider();
        configure(
            &JoinPaths::production(),
            &|name| std::env::var_os(name),
            rustix::process::geteuid().is_root(),
            read_join_input,
            production_enroll,
            arm_interrupt,
        )
        .await
    } else {
        Err(JoinError::Arguments)
    };
    let (code, message) = conclude(result, systemctl::enable_and_start);
    eprintln!("relay-daemon join: {message}");
    code
}

/// `main` installs the process default only after it has handed off to `join`.
fn install_crypto_provider() {
    // An error means one is already installed, which is all that is needed.
    let _ = rustls::crypto::ring::default_provider().install_default();
}

/// The closing message and exit code for a run. `start` runs only for a fresh
/// enrollment into the unit's own state directory, after the identity is persisted.
fn conclude(
    result: Result<Joined, JoinError>,
    start: impl FnOnce() -> io::Result<ExitStatus>,
) -> (i32, String) {
    let result = result.and_then(|joined| match joined {
        Joined::Enrolled {
            node_id,
            unit: UnitStart::Start,
            ..
        } => match start() {
            Ok(status) if status.success() => Ok(format!(
                "enrolled as {node_id:?}; relay-daemon.service is enabled and started \
                 (journalctl -u relay-daemon)"
            )),
            Ok(status) => Err(JoinError::Systemctl(status)),
            Err(e) => Err(JoinError::Spawn(e)),
        },
        Joined::Enrolled {
            node_id,
            unit: UnitStart::NoSystemd,
            ..
        } => Ok(format!(
            "enrolled as {node_id:?}; systemd is not running here, so nothing was started: \
             start relay-daemon yourself"
        )),
        Joined::Enrolled {
            node_id,
            state_dir,
            unit: UnitStart::NotTheUnitsStateDir,
        } => Ok(format!(
            "enrolled as {node_id:?} into {}, which is not the state directory \
             relay-daemon.service uses, so the unit was not started",
            state_dir.display()
        )),
        Joined::AlreadyEnrolled { state_dir, retired } => {
            let mut message = format!(
                "this Node already holds an identity in {}; nothing was changed",
                state_dir.display()
            );
            match retired {
                Some((name, Place::File(path))) => message.push_str(&format!(
                    "\nrelay-daemon join: {name} is set in {}; relay-daemon.service refuses \
                     to start until it is removed",
                    path.display()
                )),
                Some((name, Place::Environment)) => message.push_str(&format!(
                    "\nrelay-daemon join: {name} is set in this shell's environment; a daemon \
                     started from it refuses to start until it is unset"
                )),
                None => {}
            }
            Ok(message)
        }
    });
    match result {
        Ok(message) => (0, message),
        Err(e) => (e.exit_code(), e.to_string()),
    }
}

/// The environment file as `join` reads it: only the settings it uses.
struct EnvFile {
    path: PathBuf,
    /// The last non-empty assignment of each of [`JOIN_SETTINGS`].
    values: BTreeMap<&'static str, Vec<u8>>,
    /// Retired settings assigned in the file, even to an empty value.
    retired: Vec<&'static str>,
}

/// Why a line or value is outside the grammar subset `join` parses.
type Unparsed = &'static str;

/// The value `line` assigns to `key`, if it is an assignment of `key`: optional
/// leading whitespace, the key, optional blanks, `=`.
fn assignment<'a>(line: &'a [u8], key: &[u8]) -> Option<&'a [u8]> {
    let rest = line.trim_ascii_start().strip_prefix(key)?;
    let rest = rest.trim_ascii_start();
    rest.strip_prefix(b"=")
}

/// A line ending in a backslash, whether an assignment or a comment: systemd
/// continues it onto the next line, so the next line might be a value instead of
/// an assignment, or ignored instead of read.
fn check_continuations(content: &[u8]) -> Result<(), Unparsed> {
    let continued = content
        .split(|b| *b == b'\n')
        .any(|line| line.trim_ascii_end().ends_with(b"\\"));
    if continued {
        return Err("a line ends in a backslash");
    }
    Ok(())
}

/// `key` as the environment file sets it: the last assignment wins, as systemd
/// reads it, with one pair of surrounding quotes removed. A value holding a
/// backslash, or opening a quote it never closes, is outside the subset.
fn env_file_value<'a>(content: &'a [u8], key: &[u8]) -> Result<Option<&'a [u8]>, Unparsed> {
    let Some(value) = content
        .split(|b| *b == b'\n')
        .rev()
        .find_map(|line| assignment(line, key))
    else {
        return Ok(None);
    };
    let value = value.trim_ascii();
    let value = match value {
        [q @ (b'"' | b'\''), inner @ .., last] if last == q => inner,
        v => v,
    };
    if value.contains(&b'\\') {
        return Err("a value holds a backslash");
    }
    if matches!(value.first(), Some(b'"' | b'\'')) {
        return Err("a value opens a quote it does not close");
    }
    Ok(Some(value))
}

impl EnvFile {
    fn parse(path: &Path, content: &[u8]) -> Result<EnvFile, JoinError> {
        let unparsed = |reason: String| JoinError::EnvFileUnparsed {
            path: path.to_path_buf(),
            reason,
        };
        check_continuations(content).map_err(|r| unparsed(r.to_string()))?;
        let mut values = BTreeMap::new();
        for name in JOIN_SETTINGS {
            match env_file_value(content, name.as_bytes()) {
                Ok(Some(v)) if !v.is_empty() => {
                    values.insert(name, v.to_vec());
                }
                Ok(_) => {}
                Err(reason) => return Err(unparsed(format!("{name}: {reason}"))),
            }
        }
        let retired = RETIRED_SETTINGS
            .iter()
            .map(|(name, _)| *name)
            .filter(|name| {
                content
                    .split(|b| *b == b'\n')
                    .any(|line| assignment(line, name.as_bytes()).is_some())
            })
            .collect();
        Ok(EnvFile {
            path: path.to_path_buf(),
            values,
            retired,
        })
    }

    fn value(&self, name: &str) -> Option<&[u8]> {
        self.values.get(name).map(Vec::as_slice)
    }
}

/// `PermissionDenied` from a caller that is not root: the packaged files are
/// root's, so the cure is `sudo`, not a different path.
fn needs_root(source: &io::Error, is_root: bool) -> bool {
    !is_root && source.kind() == io::ErrorKind::PermissionDenied
}

/// The environment file, parsed, or `None` when there is none. It is followed
/// through a symlink, as systemd follows it, and anything but a regular file
/// (a FIFO would hang the read) is refused.
fn read_env_file(path: &Path, is_root: bool) -> Result<Option<EnvFile>, JoinError> {
    let unreadable = |source: io::Error| {
        if needs_root(&source, is_root) {
            JoinError::NeedsRoot {
                path: path.to_path_buf(),
            }
        } else {
            JoinError::EnvFileUnreadable {
                path: path.to_path_buf(),
                source,
            }
        }
    };
    match fs::metadata(path) {
        Ok(meta) if meta.file_type().is_file() => {}
        Ok(_) => {
            return Err(JoinError::EnvFileNotRegular {
                path: path.to_path_buf(),
            })
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(unreadable(e)),
    }
    // Wiped: a stale line from an earlier configuration may hold a token.
    let content = Zeroizing::new(fs::read(path).map_err(unreadable)?);
    EnvFile::parse(path, &content).map(Some)
}

/// An environment value as text. Empty counts as unset, as it does for the unit;
/// a value that is not UTF-8 is an error rather than unset.
fn text_setting(name: &'static str, raw: Option<&OsStr>) -> Result<Option<String>, JoinError> {
    match raw {
        None => Ok(None),
        Some(v) if v.is_empty() => Ok(None),
        Some(v) => v
            .to_str()
            .map(|s| Some(s.to_string()))
            .ok_or(JoinError::SettingNotUnicode { name }),
    }
}

/// The values of [`JOIN_SETTINGS`] `join` enrolls with.
struct Settings(BTreeMap<&'static str, String>);

/// Takes each setting from the environment file when there is one and from the
/// process environment otherwise. A process-environment value the file does not
/// assign identically is refused: the unit never sees the caller's environment,
/// so enrolling by it would persist what the unit does not read.
fn resolve_settings(
    env: &dyn Fn(&str) -> Option<OsString>,
    file: Option<&EnvFile>,
) -> Result<Settings, JoinError> {
    let mut resolved = BTreeMap::new();
    for name in JOIN_SETTINGS {
        let shell = text_setting(name, env(name).as_deref())?;
        let value = match file {
            None => shell,
            Some(file) => {
                let from_file = text_setting(name, file.value(name).map(OsStr::from_bytes))?;
                if shell.is_some() && shell != from_file {
                    return Err(JoinError::EnvDisagrees {
                        name,
                        path: file.path.clone(),
                    });
                }
                from_file
            }
        };
        if let Some(value) = value {
            resolved.insert(name, value);
        }
    }
    Ok(Settings(resolved))
}

/// A retired setting that is set, in the file or the process environment.
fn retired_setting(
    env: &dyn Fn(&str) -> Option<OsString>,
    file: Option<&EnvFile>,
) -> Option<(&'static str, Place)> {
    for (name, _) in RETIRED_SETTINGS {
        if env(name).is_some() {
            return Some((name, Place::Environment));
        }
        if let Some(file) = file.filter(|f| f.retired.contains(&name)) {
            return Some((name, Place::File(file.path.clone())));
        }
    }
    None
}

/// Looks for an identity where one could be and returns the first that is not
/// absent. A Node holds at most one: the unit's directory, the caller's when no
/// environment file overrides it, and the default, which is always checked.
fn existing_identity(
    candidates: &[PathBuf],
    is_root: bool,
) -> Result<Option<(PathBuf, IdentityState)>, JoinError> {
    for dir in candidates.iter().filter(|d| d.is_absolute()) {
        match config::identity_state(dir) {
            Ok(IdentityState::Absent) => {}
            Ok(state) => return Ok(Some((dir.clone(), state))),
            Err(ConfigError::IdentityUnreadable { state_dir, source })
                if needs_root(&source, is_root) =>
            {
                return Err(JoinError::NeedsRoot { path: state_dir })
            }
            Err(e) => return Err(JoinError::Identity(e)),
        }
    }
    Ok(None)
}

/// The outcome for a Node that holds an identity, or part of one.
fn already_enrolled(
    (state_dir, state): (PathBuf, IdentityState),
    env: &dyn Fn(&str) -> Option<OsString>,
    file: Option<&EnvFile>,
) -> Result<Joined, JoinError> {
    match state {
        IdentityState::Complete => Ok(Joined::AlreadyEnrolled {
            state_dir,
            retired: retired_setting(env, file),
        }),
        IdentityState::Partial { missing } => {
            Err(JoinError::Identity(ConfigError::PartialIdentity {
                state_dir,
                missing,
            }))
        }
        IdentityState::Absent => unreachable!("absent directories are skipped"),
    }
}

/// Everything `join` does before the unit starts. The steps run in this order, and
/// every refusal through the state-directory check happens before the join string
/// is read and before any dial, writing nothing.
async fn configure<R, E, EFut, A, AFut>(
    paths: &JoinPaths,
    env: &dyn Fn(&str) -> Option<OsString>,
    is_root: bool,
    read_input: R,
    enroll: E,
    arm_interrupt: A,
) -> Result<Joined, JoinError>
where
    R: FnOnce() -> Result<Secret, JoinError>,
    E: FnOnce(EnrollConfig) -> EFut,
    EFut: Future<Output = Result<Identity, Failed>>,
    A: FnOnce() -> io::Result<AFut>,
    AFut: Future<Output = ()>,
{
    let file = read_env_file(&paths.env_file, is_root)?;
    let file = file.as_ref();

    let units_dir = file
        .and_then(|f| f.value("RELAY_STATE_DIR"))
        .map(|v| PathBuf::from(OsStr::from_bytes(v)))
        .unwrap_or_else(|| paths.default_state_dir.clone());

    // The caller's own directory counts only without an environment file: with
    // one, the unit never sees the caller's environment.
    let mut candidates = vec![units_dir.clone()];
    if file.is_none() {
        if let Some(dir) = env("RELAY_STATE_DIR").filter(|v| !v.is_empty()) {
            candidates.push(PathBuf::from(dir));
        }
    }
    candidates.push(paths.default_state_dir.clone());
    let mut seen = BTreeSet::new();
    candidates.retain(|dir| seen.insert(dir.clone()));

    if let Some(found) = existing_identity(&candidates, is_root)? {
        return already_enrolled(found, env, file);
    }

    // The unit would refuse to start with this set, so no token is spent first.
    if let Some((name, place)) = retired_setting(env, file) {
        return Err(JoinError::RetiredSetting {
            name,
            place: place.describe(),
        });
    }

    let settings = resolve_settings(env, file)?;
    let effective_dir = settings
        .0
        .get("RELAY_STATE_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| paths.default_state_dir.clone());
    if effective_dir.is_relative() {
        return Err(JoinError::RelativeStateDir);
    }

    let systemd_running = fs::metadata(&paths.systemd_marker).is_ok_and(|m| m.is_dir());
    let unit = unit_start(&effective_dir, &units_dir, systemd_running);
    if unit == UnitStart::Start && !is_root {
        return Err(JoinError::NotRoot { dir: effective_dir });
    }

    identity::check_state_dir_creatable(&effective_dir).map_err(JoinError::StateDir)?;

    // Surrounding whitespace, the newline included, is never part of a join string.
    let raw = read_input()?;
    let join = config::decode_join_str(raw.trim())
        .map_err(JoinError::Invalid)?
        .ok_or(JoinError::Empty)?;
    drop(raw);

    let (cfg, left_out) = config::join_enroll_config(join, effective_dir.clone(), &|name| {
        settings.0.get(name).cloned()
    })
    .map_err(JoinError::Config)?;
    for key in left_out {
        eprintln!(
            "relay-daemon join: the default label node:{key} is not a well-formed node: label and is left out"
        );
    }

    let interrupted = arm_interrupt().map_err(JoinError::Signals)?;
    let prepared = identity::prepare_state_dir(&effective_dir).map_err(|e| JoinError::Prepare {
        source: e.source,
        leftovers: e.leftovers,
    })?;

    // The first look ran before the lock. A `join` that held the lock until now may
    // have enrolled, and this one must not enroll over it or roll it back.
    let rechecked = existing_identity(&candidates, is_root);
    if !matches!(rechecked, Ok(None)) {
        let leftovers = prepared.roll_back();
        if !leftovers.is_empty() {
            return Err(JoinError::Prepare {
                source: IdentityError::StateDir {
                    path: effective_dir,
                    reason: "an identity appeared while join was waiting to enroll".to_string(),
                },
                leftovers,
            });
        }
        return match rechecked? {
            Some(found) => already_enrolled(found, env, file),
            None => unreachable!("only an identity or an error reaches here"),
        };
    }

    // Enrollment first, so one that has finished persisting is never reported as
    // interrupted. A cancel lands only at the enroller's await, which is before
    // anything is persisted.
    let outcome = tokio::select! {
        biased;
        enrolled = enroll(cfg) => enrolled,
        () = interrupted => Err(Failed::Interrupted),
    };
    match outcome {
        Ok(identity) => {
            drop(prepared);
            Ok(Joined::Enrolled {
                node_id: identity.node_id,
                state_dir: effective_dir,
                unit,
            })
        }
        Err(failed) => {
            let leftovers = prepared.roll_back();
            Err(match failed {
                Failed::Enroll(source) => JoinError::Enroll { source, leftovers },
                Failed::Timeout => JoinError::Timeout { leftovers },
                Failed::Interrupted => JoinError::Interrupted { leftovers },
            })
        }
    }
}

/// Enrolls, giving up after [`JOIN_ENROLL_TIMEOUT`]. Persistence is synchronous
/// after the last await, so neither the timeout nor an interrupt can cut a write
/// in half.
async fn production_enroll(cfg: EnrollConfig) -> Result<Identity, Failed> {
    match tokio::time::timeout(JOIN_ENROLL_TIMEOUT, enroll::ensure_enrolled(&cfg)).await {
        Ok(result) => result.map_err(Failed::Enroll),
        Err(_) => Err(Failed::Timeout),
    }
}

/// Registers SIGINT, SIGTERM and SIGHUP, and returns a future that resolves on
/// any of them. Once registered they stay caught for the rest of the process: a
/// Ctrl-C during `systemctl` reaches `systemctl` and `join` waits for it, and a
/// hangup (a dropped SSH session) rolls back instead of leaving the directory.
/// SIGKILL cannot be caught; a kill inside the persist leaves a partial identity,
/// which every rerun refuses as partial with the missing files named.
fn arm_interrupt() -> io::Result<impl Future<Output = ()>> {
    use tokio::signal::unix::{signal, SignalKind};
    let mut interrupt = signal(SignalKind::interrupt())?;
    let mut terminate = signal(SignalKind::terminate())?;
    let mut hangup = signal(SignalKind::hangup())?;
    Ok(async move {
        tokio::select! {
            _ = interrupt.recv() => {}
            _ = terminate.recv() => {}
            _ = hangup.recv() => {}
        }
    })
}

/// Reads one line from `fd` without buffering: at most `limit` bytes, up to and
/// including the first newline, or to end of input. The buffer is allocated at
/// full size so it never reallocates and leaves an unwiped copy behind, and what
/// is read past the newline is discarded in it.
fn read_line_unbuffered(fd: impl AsFd, limit: usize) -> io::Result<Zeroizing<Vec<u8>>> {
    let mut buf = Zeroizing::new(vec![0u8; limit]);
    let mut filled = 0;
    while filled < limit {
        match rustix::io::read(&fd, &mut buf[filled..]) {
            Ok(0) => break,
            Ok(n) => {
                let newline = buf[filled..filled + n].iter().position(|b| *b == b'\n');
                filled += n;
                if let Some(at) = newline {
                    filled -= n - at - 1;
                    break;
                }
            }
            Err(Errno::INTR) => {}
            Err(e) => return Err(e.into()),
        }
    }
    buf.truncate(filled);
    Ok(buf)
}

/// Reads one line from standard input: behind a prompt with echo off when it is a
/// terminal, as piped text otherwise. At most a little over the longest join string
/// is read, so an oversized input is refused by the decoder rather than buffered.
fn read_join_input() -> Result<Secret, JoinError> {
    let stdin = io::stdin();
    let interactive = stdin.is_terminal();
    let limit = MAX_JOIN_STRING_LEN + 2;
    let mut buf = {
        let echo = if interactive {
            eprint!("Paste the join string (input is hidden): ");
            let _ = io::stderr().flush();
            Some(EchoOff::new().map_err(JoinError::Read)?)
        } else {
            None
        };
        let read = read_line_unbuffered(stdin.as_fd(), limit);
        // The prompt ends here, and only one side may end it: if the interrupt
        // handler claimed it first it is restoring echo and exiting 130 having
        // told the operator nothing changed, so this thread must not go on to
        // write anything. Claimed before a read error is returned, too.
        if echo.as_ref().is_some_and(|e| e.on_interrupt.is_some()) && !AT_PROMPT.claim() {
            loop {
                std::thread::park();
            }
        }
        drop(echo);
        read.map_err(JoinError::Read)?
    };
    if interactive {
        eprintln!();
    }
    match String::from_utf8(std::mem::take(&mut *buf)) {
        Ok(text) => Ok(Zeroizing::new(text)),
        Err(e) => {
            drop(Zeroizing::new(e.into_bytes()));
            Err(JoinError::Invalid(ConfigError::JoinNotUnicode))
        }
    }
}

/// Decides which side ends the prompt: the main thread, once the line is read, or
/// the interrupt handler, on a Ctrl-C. Opened once echo is off; each side claims
/// it with one atomic swap, so exactly one wins. The handler restores echo and
/// exits only if it won; the main thread writes nothing unless it won.
struct PromptGate(AtomicBool);

impl PromptGate {
    const fn new() -> Self {
        PromptGate(AtomicBool::new(false))
    }

    fn open(&self) {
        self.0.store(true, Ordering::SeqCst);
    }

    /// True for exactly one caller per `open`.
    fn claim(&self) -> bool {
        self.0.swap(false, Ordering::SeqCst)
    }
}

static AT_PROMPT: PromptGate = PromptGate::new();

/// Turns terminal echo off for its lifetime and restores the saved settings on
/// drop, and on an interrupt: a Ctrl-C while the prompt is up restores echo before
/// the process exits, so the operator's terminal is never left silent.
struct EchoOff {
    saved: Termios,
    on_interrupt: Option<tokio::task::JoinHandle<()>>,
}

impl EchoOff {
    fn new() -> io::Result<Self> {
        let saved = tcgetattr(io::stdin())?;
        // Registered before echo goes off, so no interrupt can land in between.
        let on_interrupt = restore_on_interrupt(saved.clone());
        let mut quiet = saved.clone();
        quiet.local_modes.remove(LocalModes::ECHO);
        if let Err(e) = tcsetattr(io::stdin(), OptionalActions::Now, &quiet) {
            if let Some(task) = on_interrupt {
                task.abort();
            }
            return Err(e.into());
        }
        // Opened only once echo is off, so the handler can never restore echo
        // before this thread turns it off. A Ctrl-C before this point is caught
        // and ignored, with echo still on.
        if on_interrupt.is_some() {
            AT_PROMPT.open();
        }
        Ok(EchoOff {
            saved,
            on_interrupt,
        })
    }
}

impl Drop for EchoOff {
    fn drop(&mut self) {
        let _ = tcsetattr(io::stdin(), OptionalActions::Now, &self.saved);
        if let Some(task) = self.on_interrupt.take() {
            task.abort();
        }
    }
}

/// Listens for SIGINT on the runtime `main` runs in; on one that claims
/// [`AT_PROMPT`], restores `saved` and exits 130 with nothing changed. Any other
/// SIGINT is ignored: once registered, the signal stays caught for the rest of the
/// run, so a Ctrl-C after the prompt is handled by the enrollment's own interrupt
/// (and a child such as `systemctl` still receives it). `None` outside a runtime,
/// which leaves the default action (and `stty echo` as the recovery the install
/// guide documents).
fn restore_on_interrupt(saved: Termios) -> Option<tokio::task::JoinHandle<()>> {
    use tokio::signal::unix::{signal, SignalKind};
    let handle = tokio::runtime::Handle::try_current().ok()?;
    let _entered = handle.enter();
    let mut interrupt = signal(SignalKind::interrupt()).ok()?;
    Some(handle.spawn(async move {
        while interrupt.recv().await.is_some() {
            if AT_PROMPT.claim() {
                let _ = tcsetattr(io::stdin(), OptionalActions::Now, &saved);
                eprintln!();
                eprintln!("relay-daemon join: interrupted; nothing was changed");
                std::process::exit(130);
            }
        }
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::fake_relay::{
        pki, start_fake_relay, start_rejecting_relay, start_silent_listener, Pki, REJECTION_MESSAGE,
    };
    use crate::test_support::TempDir;
    use relay_transport::join_string::JoinString;
    use relay_transport::pin::PinError;
    use std::os::unix::fs::MetadataExt;
    use std::os::unix::net::UnixStream;
    use std::os::unix::process::ExitStatusExt;
    use std::sync::Arc;

    const TOKEN: &str = "tok-join-secret";

    /// A join string naming `addr`, pinning `ca_der`, carrying [`TOKEN`].
    fn join_text(addr: &str, ca_der: &[u8]) -> String {
        let pin: [u8; 32] = ring::digest::digest(&ring::digest::SHA256, ca_der)
            .as_ref()
            .try_into()
            .expect("sha-256 is 32 bytes");
        JoinString::new(addr.to_string(), pin, TOKEN.to_string())
            .encode()
            .expect("encode")
    }

    fn join_for(server: &Pki, port: u16) -> String {
        join_text(&format!("127.0.0.1:{port}"), &server.ca_der)
    }

    fn input(text: impl Into<String>) -> impl FnOnce() -> Result<Secret, JoinError> {
        let text = text.into();
        move || Ok(Zeroizing::new(text))
    }

    fn no_read() -> Result<Secret, JoinError> {
        panic!("the join string must not be read once join has refused")
    }

    async fn no_enroll(_: EnrollConfig) -> Result<Identity, Failed> {
        panic!("no enrollment may start once join has refused")
    }

    fn never_interrupted() -> io::Result<std::future::Pending<()>> {
        Ok(std::future::pending())
    }

    fn interrupted_at_once() -> io::Result<std::future::Ready<()>> {
        Ok(std::future::ready(()))
    }

    fn no_start() -> io::Result<ExitStatus> {
        panic!("the unit must not be started")
    }

    /// An environment answering from a fixed table.
    fn env_of(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<OsString> {
        let table: BTreeMap<String, String> = pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        move |name| table.get(name).map(OsString::from)
    }

    /// A temporary directory holding the environment file, the default state
    /// directory and the systemd marker, all three absent until a test makes them.
    struct Fixture {
        dir: TempDir,
        paths: JoinPaths,
    }

    fn fixture(label: &str) -> Fixture {
        let dir = TempDir::created(label);
        let paths = JoinPaths {
            env_file: dir.path().join("relay-daemon.env"),
            default_state_dir: dir.path().join("state"),
            systemd_marker: dir.path().join("systemd"),
        };
        Fixture { dir, paths }
    }

    impl Fixture {
        fn write_env_file(&self, text: &str) {
            fs::write(&self.paths.env_file, text).expect("write env file");
        }

        fn run_systemd(&self) {
            fs::create_dir(&self.paths.systemd_marker).expect("marker");
        }

        fn state(&self) -> &Path {
            &self.paths.default_state_dir
        }
    }

    /// Every file under `dir` with its bytes, keyed by relative path; a directory
    /// that does not exist is empty.
    fn snapshot(dir: &Path) -> BTreeMap<String, Vec<u8>> {
        fn walk(root: &Path, dir: &Path, out: &mut BTreeMap<String, Vec<u8>>) {
            let Ok(entries) = fs::read_dir(dir) else {
                return;
            };
            for entry in entries.flatten() {
                let path = entry.path();
                let rel = path.strip_prefix(root).unwrap().display().to_string();
                if path.is_dir() {
                    out.insert(format!("{rel}/"), Vec::new());
                    walk(root, &path, out);
                } else {
                    out.insert(rel, fs::read(&path).unwrap());
                }
            }
        }
        let mut out = BTreeMap::new();
        walk(dir, dir, &mut out);
        out
    }

    fn seed_identity(dir: &Path, names: &[&str]) {
        fs::create_dir_all(dir).unwrap();
        for name in names {
            fs::write(dir.join(name), "x").unwrap();
        }
    }

    fn assert_no_secret_on_disk(root: &Path) {
        for (path, bytes) in snapshot(root) {
            let text = String::from_utf8_lossy(&bytes);
            assert!(
                !text.contains(TOKEN) && !text.contains("glp_join_"),
                "{path} holds the join string or its token"
            );
        }
    }

    /// Exactly one side ends the prompt, however the two race.
    #[test]
    fn prompt_gate_lets_exactly_one_side_win() {
        let gate = PromptGate::new();
        assert!(!gate.claim(), "a gate never opened has nothing to claim");
        gate.open();
        assert!(gate.claim());
        assert!(!gate.claim(), "the loser of the swap must not proceed");

        for _ in 0..200 {
            let gate = Arc::new(PromptGate::new());
            gate.open();
            let barrier = Arc::new(std::sync::Barrier::new(2));
            let racers: Vec<_> = (0..2)
                .map(|_| {
                    let (gate, barrier) = (gate.clone(), barrier.clone());
                    std::thread::spawn(move || {
                        barrier.wait();
                        gate.claim()
                    })
                })
                .collect();
            let wins = racers
                .into_iter()
                .map(|t| t.join().unwrap())
                .filter(|w| *w)
                .count();
            assert_eq!(wins, 1);
        }
    }

    // Proves DI-42.
    #[tokio::test]
    async fn join_refuses_argv_join_string() {
        let secret = join_text("relay.example:7654", &[1, 2, 3]);
        let (code, message) = conclude(Err(JoinError::Arguments), no_start);
        assert_eq!(code, 2);
        assert!(
            !message.contains(&secret) && !message.contains(TOKEN),
            "the refusal never echoes what was passed"
        );
        assert_eq!(run(&[secret]).await, 2);
        assert_eq!(run(&["--token".to_string(), "x".to_string()]).await, 2);
    }

    // Proves DI-42, DI-43, EN-30, EN-32.
    #[tokio::test]
    async fn join_enrolls_in_process_and_persists_identity() {
        install_crypto_provider();
        let server = pki("localhost");
        let (port, seen) = start_fake_relay(&server, server.ca_pem.clone()).await;
        let f = fixture("join-enrolls");
        let env_text = format!(
            "RELAY_STATE_DIR={}\nRELAY_NODE_LABELS=role=web\nRELAY_SERVER_NAME=localhost\n",
            f.state().display()
        );
        f.write_env_file(&env_text);
        let before = fs::metadata(&f.paths.env_file).unwrap();

        let joined = configure(
            &f.paths,
            &env_of(&[]),
            false,
            input(join_for(&server, port)),
            production_enroll,
            never_interrupted,
        )
        .await
        .expect("join enrolls");

        let Joined::Enrolled {
            node_id,
            state_dir,
            unit,
        } = joined
        else {
            panic!("want Enrolled, got {joined:?}");
        };
        assert_eq!(node_id, "node-join-test");
        assert_eq!(state_dir, f.state());
        assert_eq!(unit, UnitStart::NoSystemd);
        assert!(identity::load_identity(f.state()).unwrap().is_some());
        assert_eq!(
            identity::load_relay_addr(f.state()).unwrap().as_deref(),
            Some(format!("https://127.0.0.1:{port}").as_str())
        );
        let ca = fs::read_to_string(f.state().join("ca_bundle.pem")).unwrap();
        assert_eq!(ca, server.ca_pem);

        assert_eq!(seen.calls(), 1);
        assert_eq!(*seen.tokens.lock().unwrap(), vec![TOKEN.to_string()]);
        // The declared label first, then the daemon's default labels.
        let sent = seen.self_labels.lock().unwrap().clone();
        assert_eq!(sent[0], ("node:role".to_string(), "web".to_string()));
        assert!(sent.contains(&("node:os".to_string(), std::env::consts::OS.to_string())));
        assert!(sent.contains(&("node:arch".to_string(), std::env::consts::ARCH.to_string())));

        // The environment file is untouched, and nothing on disk holds the string.
        let after = fs::metadata(&f.paths.env_file).unwrap();
        assert_eq!(fs::read_to_string(&f.paths.env_file).unwrap(), env_text);
        assert_eq!((before.ino(), before.mtime()), (after.ino(), after.mtime()));
        assert_no_secret_on_disk(f.dir.path());
    }

    // Proves DI-42.
    #[tokio::test]
    async fn join_starts_the_unit_once_and_only_after_the_identity_is_persisted() {
        install_crypto_provider();
        let server = pki("localhost");
        for (status, want_code) in [(0, 0), (256, 1)] {
            let (port, _seen) = start_fake_relay(&server, server.ca_pem.clone()).await;
            let f = fixture("join-starts");
            f.run_systemd();
            let env = env_of(&[("RELAY_SERVER_NAME", "localhost")]);
            let result = configure(
                &f.paths,
                &env,
                true,
                input(join_for(&server, port)),
                production_enroll,
                never_interrupted,
            )
            .await;
            let state = f.state().to_path_buf();
            let mut calls = 0;
            let (code, message) = conclude(result, || {
                calls += 1;
                assert!(
                    identity::load_identity(&state).unwrap().is_some(),
                    "the unit starts only once the identity is on disk"
                );
                Ok(ExitStatus::from_raw(status))
            });
            assert_eq!(calls, 1, "the unit is started exactly once");
            assert_eq!(code, want_code, "{message}");
            assert!(
                identity::load_identity(f.state()).unwrap().is_some(),
                "the identity is kept either way"
            );
            if want_code == 0 {
                assert!(message.contains("enabled and started"), "{message}");
            } else {
                assert!(message.contains("the identity is kept"), "{message}");
            }
        }

        let joined = Joined::Enrolled {
            node_id: "n".to_string(),
            state_dir: PathBuf::from("/s"),
            unit: UnitStart::Start,
        };
        let (code, message) = conclude(Ok(joined), || Err(io::Error::other("no systemctl")));
        assert_eq!(code, 1, "{message}");
        assert!(message.starts_with("enrolled, but"), "{message}");
    }

    #[test]
    fn a_failed_state_dir_preparation_names_the_path_and_what_it_left() {
        let source = || IdentityError::StateDir {
            path: PathBuf::from("/var/lib/relay-daemon"),
            reason: "Permission denied (os error 13)".to_string(),
        };
        let clean = JoinError::Prepare {
            source: source(),
            leftovers: vec![],
        };
        let message = clean.to_string();
        assert!(message.contains("/var/lib/relay-daemon"), "{message}");
        assert!(message.ends_with("nothing was changed"), "{message}");

        let dirty = JoinError::Prepare {
            source: source(),
            leftovers: vec![PathBuf::from("/var/lib/relay-daemon")],
        };
        let message = dirty.to_string();
        assert!(!message.contains("nothing was changed"), "{message}");
        assert!(message.contains("could not be put back"), "{message}");
    }

    // Proves DI-42.
    #[test]
    fn conclude_never_starts_the_unit_otherwise() {
        let dir = || PathBuf::from("/var/lib/relay-daemon");
        let enrolled = |unit| {
            Ok(Joined::Enrolled {
                node_id: "n".to_string(),
                state_dir: dir(),
                unit,
            })
        };
        let cases: Vec<(Result<Joined, JoinError>, i32)> = vec![
            (
                Ok(Joined::AlreadyEnrolled {
                    state_dir: dir(),
                    retired: None,
                }),
                0,
            ),
            (enrolled(UnitStart::NoSystemd), 0),
            (enrolled(UnitStart::NotTheUnitsStateDir), 0),
            (Err(JoinError::Arguments), 2),
            (Err(JoinError::NotRoot { dir: dir() }), 1),
            (Err(JoinError::NeedsRoot { path: dir() }), 1),
            (Err(JoinError::EnvFileNotRegular { path: dir() }), 1),
            (
                Err(JoinError::EnvFileUnparsed {
                    path: dir(),
                    reason: "r".to_string(),
                }),
                1,
            ),
            (
                Err(JoinError::EnvDisagrees {
                    name: "RELAY_ADDRESS",
                    path: dir(),
                }),
                1,
            ),
            (
                Err(JoinError::SettingNotUnicode {
                    name: "RELAY_ADDRESS",
                }),
                1,
            ),
            (Err(JoinError::RelativeStateDir), 1),
            (
                Err(JoinError::RetiredSetting {
                    name: "RELAY_JOIN",
                    place: "x".to_string(),
                }),
                1,
            ),
            (Err(JoinError::Empty), 1),
            (Err(JoinError::Invalid(ConfigError::JoinNotUnicode)), 1),
            (
                Err(JoinError::Enroll {
                    source: EnrollError::CaBundleMismatch,
                    leftovers: vec![],
                }),
                1,
            ),
            (Err(JoinError::Timeout { leftovers: vec![] }), 1),
            (Err(JoinError::Interrupted { leftovers: vec![] }), 130),
        ];
        for (result, want) in cases {
            let (code, message) = conclude(result, no_start);
            assert_eq!(code, want, "{message}");
        }
    }

    // Proves DI-42.
    #[tokio::test]
    async fn join_on_an_enrolled_node_changes_nothing_and_exits_zero() {
        // Each place an identity can be found, with the settings that point there.
        struct Case {
            label: &'static str,
            env_file: Option<String>,
            shell_state_dir: Option<String>,
            identity_in: &'static str,
        }
        let cases = [
            Case {
                label: "default",
                env_file: None,
                shell_state_dir: None,
                identity_in: "state",
            },
            Case {
                label: "named by the file",
                env_file: Some("RELAY_STATE_DIR={named}\n".to_string()),
                shell_state_dir: None,
                identity_in: "named",
            },
            Case {
                label: "named by the shell, no file",
                env_file: None,
                shell_state_dir: Some("{named}".to_string()),
                identity_in: "named",
            },
            Case {
                label: "default while the file names an empty directory",
                env_file: Some("RELAY_STATE_DIR={empty}\n".to_string()),
                shell_state_dir: None,
                identity_in: "state",
            },
            Case {
                label: "idempotency comes before the agreement check",
                env_file: Some("RELAY_STATE_DIR={named}\n".to_string()),
                shell_state_dir: Some("/somewhere/else".to_string()),
                identity_in: "named",
            },
        ];
        for case in cases {
            let f = fixture("join-enrolled");
            let named = f.dir.path().join("named");
            let empty = f.dir.path().join("empty");
            fs::create_dir(&empty).unwrap();
            let fill = |s: &str| {
                s.replace("{named}", &named.display().to_string())
                    .replace("{empty}", &empty.display().to_string())
            };
            if let Some(text) = &case.env_file {
                f.write_env_file(&fill(text));
            }
            let identity_dir = match case.identity_in {
                "named" => named.clone(),
                _ => f.state().to_path_buf(),
            };
            seed_identity(&identity_dir, &config::IDENTITY_FILES);
            let shell = case.shell_state_dir.as_deref().map(fill);
            let pairs: Vec<(&str, &str)> = shell
                .iter()
                .map(|v| ("RELAY_STATE_DIR", v.as_str()))
                .collect();
            let before = snapshot(f.dir.path());

            let result = configure(
                &f.paths,
                &env_of(&pairs),
                true,
                no_read,
                no_enroll,
                never_interrupted,
            )
            .await;
            let (code, message) = conclude(result, no_start);
            assert_eq!(code, 0, "{}: {message}", case.label);
            assert!(message.contains("nothing was changed"), "{}", case.label);
            assert_eq!(snapshot(f.dir.path()), before, "{}", case.label);
        }
    }

    #[tokio::test]
    async fn join_on_an_enrolled_node_warns_of_a_stale_relay_join() {
        let f = fixture("join-enrolled-stale");
        seed_identity(f.state(), &config::IDENTITY_FILES);
        f.write_env_file("RELAY_JOIN=glp_join_stale-token\n");
        let result = configure(
            &f.paths,
            &env_of(&[]),
            true,
            no_read,
            no_enroll,
            never_interrupted,
        )
        .await;
        let (code, message) = conclude(result, no_start);
        assert_eq!(code, 0, "{message}");
        assert_eq!(message.lines().count(), 2, "{message}");
        assert!(message.lines().nth(1).unwrap().contains("RELAY_JOIN"));
        assert!(message.contains("refuses to start"), "{message}");
        assert!(!message.contains("stale-token"), "{message}");

        // Set in the caller's shell instead, the unit never sees it.
        let result = configure(
            &f.paths,
            &env_of(&[("RELAY_JOIN", "glp_join_other")]),
            true,
            no_read,
            no_enroll,
            never_interrupted,
        )
        .await;
        let (code, message) = conclude(result, no_start);
        assert_eq!(code, 0, "{message}");
        assert!(message.contains("this shell's environment"), "{message}");
        assert!(!message.contains("glp_join_other"), "{message}");
    }

    /// The default state directory is checked even when the environment file names
    /// an empty one, so a rerun on an enrolled Node exits 0 whatever it exports.
    #[tokio::test]
    async fn join_always_checks_the_default_state_dir() {
        let f = fixture("join-default-state");
        let empty = f.dir.path().join("empty");
        fs::create_dir(&empty).unwrap();
        f.write_env_file(&format!("RELAY_STATE_DIR={}\n", empty.display()));
        seed_identity(
            f.state(),
            &["node_id", "key.pem", "cert.pem", "ca_bundle.pem"],
        );
        let result = configure(
            &f.paths,
            &env_of(&[]),
            true,
            no_read,
            no_enroll,
            never_interrupted,
        )
        .await;
        assert!(
            matches!(&result, Ok(Joined::AlreadyEnrolled { state_dir, .. }) if state_dir == f.state()),
            "{result:?}"
        );

        let prod = JoinPaths::production();
        assert_eq!(
            prod.default_state_dir,
            PathBuf::from("/var/lib/relay-daemon")
        );
        assert_eq!(prod.env_file, PathBuf::from(ENV_FILE));
        assert_eq!(prod.systemd_marker, PathBuf::from("/run/systemd/system"));
    }

    #[tokio::test]
    async fn join_refuses_a_partial_identity_changing_nothing() {
        let f = fixture("join-partial");
        seed_identity(f.state(), &["key.pem", "node_id"]);
        f.write_env_file("RELAY_POLICY_PATH=/p\n");
        let before = snapshot(f.dir.path());
        let result = configure(
            &f.paths,
            &env_of(&[]),
            true,
            no_read,
            no_enroll,
            never_interrupted,
        )
        .await;
        let (code, message) = conclude(result, no_start);
        assert_eq!(code, 1, "{message}");
        assert!(message.contains("cert.pem"), "{message}");
        assert_eq!(snapshot(f.dir.path()), before);
    }

    // Proves DI-42, DI-43, EN-33.
    #[tokio::test]
    async fn join_pin_mismatch_sends_no_token_and_leaves_nothing_on_disk() {
        install_crypto_provider();
        let server = pki("localhost");
        let (port, seen) = start_fake_relay(&server, server.ca_pem.clone()).await;
        let f = fixture("join-pin-mismatch");
        // The pin names some other CA.
        let other = pki("localhost");
        let text = join_text(&format!("127.0.0.1:{port}"), &other.ca_der);
        let err = configure(
            &f.paths,
            &env_of(&[("RELAY_SERVER_NAME", "localhost")]),
            false,
            input(text),
            production_enroll,
            never_interrupted,
        )
        .await
        .expect_err("a pin mismatch must refuse");

        assert!(
            matches!(
                &err,
                JoinError::Enroll {
                    source: EnrollError::Pin(PinError::Mismatch),
                    leftovers,
                } if leftovers.is_empty()
            ),
            "{err:?}"
        );
        assert_eq!(
            seen.calls(),
            0,
            "nothing may reach Enroll before the pin matches"
        );
        assert!(!f.state().exists(), "the state directory was never there");
        assert!(!format!("{err} {err:?}").contains(TOKEN));
    }

    // Proves EN-30.
    #[tokio::test]
    async fn join_pin_applies_to_an_overridden_address() {
        install_crypto_provider();
        let a = pki("localhost");
        let b = pki("localhost");
        let (port_a, seen_a) = start_fake_relay(&a, a.ca_pem.clone()).await;
        let (port_b, seen_b) = start_fake_relay(&b, b.ca_pem.clone()).await;
        let b_url = format!("https://127.0.0.1:{port_b}");

        for setting in ["RELAY_ENROLL_ADDRESS", "RELAY_ADDRESS"] {
            for in_file in [false, true] {
                let f = fixture("join-pin-override");
                let mut env_pairs = vec![("RELAY_SERVER_NAME", "localhost")];
                let mut file_text = String::new();
                if in_file {
                    file_text.push_str("RELAY_SERVER_NAME=localhost\n");
                    file_text.push_str(&format!("{setting}={b_url}\n"));
                    f.write_env_file(&file_text);
                    env_pairs.clear();
                } else {
                    env_pairs.push((setting, b_url.as_str()));
                }
                let err = configure(
                    &f.paths,
                    &env_of(&env_pairs),
                    false,
                    input(join_for(&a, port_a)),
                    production_enroll,
                    never_interrupted,
                )
                .await
                .expect_err("the pin names A's CA, not B's");
                assert!(
                    matches!(
                        &err,
                        JoinError::Enroll {
                            source: EnrollError::Pin(PinError::Mismatch),
                            ..
                        }
                    ),
                    "{setting} (file: {in_file}): {err:?}"
                );
                assert!(!f.state().exists());
            }
        }
        assert_eq!(
            seen_a.calls() + seen_b.calls(),
            0,
            "no token reached either"
        );
    }

    // Proves EN-30.
    #[tokio::test]
    async fn join_takes_no_ca_bundle_path_and_no_bare_token() {
        install_crypto_provider();
        let server = pki("localhost");
        let other = pki("localhost");
        let (port, seen) = start_fake_relay(&server, server.ca_pem.clone()).await;
        let f = fixture("join-no-ca-path");
        let other_ca = f.dir.path().join("other-ca.pem");
        fs::write(&other_ca, &other.ca_pem).unwrap();
        let other_ca_path = other_ca.display().to_string();
        // Spelled in two pieces so the packaging drift scan does not mistake the
        // names of settings the daemon does not have for settings it reads.
        let ca_setting = concat!("RELAY_", "CA_BUNDLE_PATH");
        let token_setting = concat!("RELAY_", "ENROLLMENT_TOKEN");
        let env = env_of(&[
            ("RELAY_SERVER_NAME", "localhost"),
            (ca_setting, other_ca_path.as_str()),
            (token_setting, "glp_join_other"),
        ]);
        configure(
            &f.paths,
            &env,
            false,
            input(join_for(&server, port)),
            production_enroll,
            never_interrupted,
        )
        .await
        .expect("the join string alone decides the CA and the token");

        assert_eq!(*seen.tokens.lock().unwrap(), vec![TOKEN.to_string()]);
        let ca = fs::read_to_string(f.state().join("ca_bundle.pem")).unwrap();
        assert_eq!(ca, server.ca_pem);
    }

    // Proves EN-33.
    #[tokio::test]
    async fn join_token_rejected_leaves_nothing_on_disk() {
        install_crypto_provider();
        let server = pki("localhost");
        let (port, seen) = start_rejecting_relay(&server).await;
        let f = fixture("join-rejected");
        let result = configure(
            &f.paths,
            &env_of(&[("RELAY_SERVER_NAME", "localhost")]),
            false,
            input(join_for(&server, port)),
            production_enroll,
            never_interrupted,
        )
        .await;
        assert_eq!(seen.calls(), 1);
        assert!(!f.state().exists());
        let (code, message) = conclude(result, no_start);
        assert_eq!(code, 1, "{message}");
        assert!(message.contains("nothing was persisted"), "{message}");
        assert!(
            REJECTION_MESSAGE.contains('\u{1b}') && !message.contains('\u{1b}'),
            "Relay-supplied text is escaped before it reaches the terminal: {message:?}"
        );
        assert!(!message.contains(TOKEN));
    }

    // Proves EN-33.
    #[tokio::test]
    async fn join_unreachable_relay_leaves_nothing_on_disk() {
        install_crypto_provider();
        let port = {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            listener.local_addr().unwrap().port()
        };
        let server = pki("localhost");
        let f = fixture("join-unreachable");
        let result = configure(
            &f.paths,
            &env_of(&[("RELAY_SERVER_NAME", "localhost")]),
            false,
            input(join_for(&server, port)),
            production_enroll,
            never_interrupted,
        )
        .await;
        assert!(!f.state().exists());
        let (code, message) = conclude(result, no_start);
        assert_eq!(code, 1, "{message}");
        assert!(message.contains("nothing was persisted"), "{message}");
    }

    // Proves EN-33.
    #[tokio::test]
    async fn join_failed_persist_leaves_no_partial_identity() {
        install_crypto_provider();
        let server = pki("localhost");
        let (port, _seen) = start_fake_relay(&server, server.ca_pem.clone()).await;
        let f = fixture("join-failed-persist");
        fs::create_dir_all(f.state()).unwrap();
        // node_id cannot be written: its temporary name is a non-empty directory.
        let blocker = f.state().join("node_id.tmp");
        fs::create_dir(&blocker).unwrap();
        fs::write(blocker.join("inside"), "keep").unwrap();
        fs::write(f.state().join("relay_addr"), "https://old.example:443").unwrap();

        let result = configure(
            &f.paths,
            &env_of(&[("RELAY_SERVER_NAME", "localhost")]),
            false,
            input(join_for(&server, port)),
            production_enroll,
            never_interrupted,
        )
        .await;
        let (code, message) = conclude(result, no_start);
        assert_eq!(code, 1, "{message}");
        assert!(message.contains("nothing was persisted"), "{message}");
        for name in config::IDENTITY_FILES {
            assert!(!f.state().join(name).exists(), "{name} must be rolled back");
        }
        assert_eq!(
            fs::read_to_string(f.state().join("relay_addr")).unwrap(),
            "https://old.example:443"
        );
        assert!(
            blocker.join("inside").exists(),
            "node_id.tmp existed before"
        );
    }

    // Proves EN-33.
    #[test]
    fn a_failure_after_the_relay_answered_says_a_node_may_be_recorded() {
        let after = JoinError::Enroll {
            source: EnrollError::AfterIssue(Box::new(EnrollError::CaBundleMismatch)),
            leftovers: vec![],
        };
        assert!(after.to_string().contains(MAY_HAVE_RECORDED), "{after}");

        let before = JoinError::Enroll {
            source: EnrollError::Pin(PinError::Mismatch),
            leftovers: vec![],
        };
        assert!(
            !before.to_string().contains("may have recorded"),
            "{before}"
        );
    }

    // Proves DI-42.
    #[tokio::test]
    async fn a_second_join_is_refused_while_the_first_holds_the_state_dir() {
        install_crypto_provider();
        let server = pki("localhost");
        let (port, seen) = start_fake_relay(&server, server.ca_pem.clone()).await;
        let text = join_for(&server, port);
        let f = fixture("join-concurrent");
        let env = env_of(&[("RELAY_SERVER_NAME", "localhost")]);
        let paths = &f.paths;
        let state = f.state().to_path_buf();

        let first = configure(
            paths,
            &env,
            false,
            input(text.clone()),
            |cfg| async {
                // The first join is mid-enrollment: it holds the lock on the state
                // directory and has not reached the Relay. A second join arrives now.
                let second = configure(
                    paths,
                    &env,
                    false,
                    input(text.clone()),
                    production_enroll,
                    never_interrupted,
                )
                .await;
                let (code, message) = conclude(second, no_start);
                assert_eq!(code, 1, "{message}");
                assert!(
                    message.contains(&format!(
                        "another relay-daemon join is running against {}",
                        state.display()
                    )),
                    "{message}"
                );
                assert!(
                    !message.contains(TOKEN) && !message.contains("glp_join_"),
                    "{message}"
                );
                assert!(state.is_dir(), "the first join's directory stays");

                production_enroll(cfg).await
            },
            never_interrupted,
        )
        .await
        .expect("the first join enrolls");

        let Joined::Enrolled { node_id, .. } = first else {
            panic!("want Enrolled, got {first:?}");
        };
        assert_eq!(node_id, "node-join-test");
        assert_eq!(seen.calls(), 1, "the refused join never reached the Relay");
        let identity = identity::load_identity(f.state())
            .unwrap()
            .expect("the first join's identity is intact");
        assert_eq!(identity.node_id, "node-join-test");
        assert_eq!(
            identity::load_relay_addr(f.state()).unwrap().as_deref(),
            Some(format!("https://127.0.0.1:{port}").as_str())
        );
        assert_no_secret_on_disk(f.dir.path());
    }

    // Proves DI-42.
    #[tokio::test]
    async fn a_join_that_lost_the_race_finds_the_identity_and_changes_nothing() {
        install_crypto_provider();
        let server = pki("localhost");
        let f = fixture("join-lost-race");

        // The first look finds nothing; by the time this join holds the lock, the
        // join that held it before has persisted an identity.
        let state = f.state().to_path_buf();
        let text = join_for(&server, 1);
        let read_after_the_other_enrolled = move || {
            seed_identity(&state, &config::IDENTITY_FILES);
            Ok(Zeroizing::new(text))
        };
        let result = configure(
            &f.paths,
            &env_of(&[]),
            false,
            read_after_the_other_enrolled,
            no_enroll,
            never_interrupted,
        )
        .await;
        let (code, message) = conclude(result, no_start);
        assert_eq!(code, 0, "{message}");
        assert!(message.contains("already holds an identity"), "{message}");
        for name in config::IDENTITY_FILES {
            assert!(f.state().join(name).exists(), "{name} must not be removed");
        }
    }

    // Proves EN-33.
    #[tokio::test]
    async fn join_interrupted_during_enrollment_persists_nothing() {
        install_crypto_provider();
        let server = pki("localhost");

        // An enrollment that never finishes.
        let f = fixture("join-interrupted");
        let pending = |_: EnrollConfig| std::future::pending::<Result<Identity, Failed>>();
        let result = configure(
            &f.paths,
            &env_of(&[]),
            false,
            input(join_for(&server, 1)),
            pending,
            interrupted_at_once,
        )
        .await;
        let (code, message) = conclude(result, no_start);
        assert_eq!(code, 130, "{message}");
        assert!(message.contains("interrupted"), "{message}");
        assert!(message.contains("nothing was persisted"), "{message}");
        assert!(message.contains("may have recorded"), "{message}");
        assert!(!f.state().exists());

        // A real enrollment that has not answered: a listener that accepts and
        // never speaks, so the pin handshake is pending whenever the interrupt lands.
        let (port, _listener) = start_silent_listener().await;
        let f = fixture("join-interrupted-live");
        let result = configure(
            &f.paths,
            &env_of(&[("RELAY_SERVER_NAME", "localhost")]),
            false,
            input(join_for(&server, port)),
            production_enroll,
            interrupted_at_once,
        )
        .await;
        assert!(
            matches!(&result, Err(JoinError::Interrupted { leftovers }) if leftovers.is_empty()),
            "{result:?}"
        );
        assert!(!f.state().exists());
    }

    // Proves DI-42.
    #[tokio::test]
    async fn join_refuses_a_disagreeing_environment_before_reading() {
        let f = fixture("join-disagree");
        f.write_env_file("RELAY_STATE_DIR=/value-from-file\n");
        let env = env_of(&[("RELAY_STATE_DIR", "/value-from-shell")]);
        let err = configure(&f.paths, &env, true, no_read, no_enroll, never_interrupted)
            .await
            .expect_err("a different directory is refused");
        let text = err.to_string();
        assert!(
            matches!(
                err,
                JoinError::EnvDisagrees {
                    name: "RELAY_STATE_DIR",
                    ..
                }
            ),
            "{text}"
        );
        assert!(text.contains("RELAY_STATE_DIR"), "{text}");
        assert!(
            text.contains(&f.paths.env_file.display().to_string()),
            "{text}"
        );
        assert!(
            !text.contains("value-from-file") && !text.contains("value-from-shell"),
            "values: {text}"
        );

        // A setting the file does not set at all counts as different.
        f.write_env_file("RELAY_POLICY_PATH=/p\n");
        let env = env_of(&[("RELAY_ADDRESS", "https://elsewhere:1")]);
        let err = configure(&f.paths, &env, true, no_read, no_enroll, never_interrupted)
            .await
            .expect_err("an address the file does not set is refused");
        assert!(
            matches!(
                err,
                JoinError::EnvDisagrees {
                    name: "RELAY_ADDRESS",
                    ..
                }
            ),
            "{err:?}"
        );
        assert!(!err.to_string().contains("elsewhere"));

        // The shell's directory holding an identity does not make the Node enrolled
        // when the unit's own directory does not: the caller's environment is not
        // the unit's.
        let elsewhere = f.dir.path().join("elsewhere");
        seed_identity(&elsewhere, &config::IDENTITY_FILES);
        let shell_dir = elsewhere.display().to_string();
        let env = env_of(&[("RELAY_STATE_DIR", shell_dir.as_str())]);
        let result = configure(&f.paths, &env, true, no_read, no_enroll, never_interrupted).await;
        assert!(
            matches!(&result, Err(JoinError::EnvDisagrees { .. })),
            "{result:?}"
        );
        assert!(!f.state().exists());
    }

    // Proves DI-42.
    #[tokio::test]
    async fn join_lets_the_environment_govern_without_an_env_file() {
        install_crypto_provider();
        let server = pki("localhost");
        let (port, _seen) = start_fake_relay(&server, server.ca_pem.clone()).await;
        let f = fixture("join-env-governs");
        f.run_systemd();
        let target = f.dir.path().join("elsewhere");
        let target_text = target.display().to_string();
        let env = env_of(&[
            ("RELAY_STATE_DIR", target_text.as_str()),
            ("RELAY_SERVER_NAME", "localhost"),
        ]);
        let joined = configure(
            &f.paths,
            &env,
            true,
            input(join_for(&server, port)),
            production_enroll,
            never_interrupted,
        )
        .await
        .expect("enrolls");
        assert!(identity::load_identity(&target).unwrap().is_some());
        assert!(!f.state().exists());
        assert!(
            matches!(
                joined,
                Joined::Enrolled {
                    unit: UnitStart::NotTheUnitsStateDir,
                    ..
                }
            ),
            "{joined:?}"
        );
        let (code, message) = conclude(Ok(joined), no_start);
        assert_eq!(code, 0, "{message}");
        assert!(message.contains("was not started"), "{message}");
    }

    #[tokio::test]
    async fn join_refuses_an_env_file_it_cannot_parse() {
        for text in [
            "RELAY_STATE_DIR=/a\\b\n",
            "# note \\\nRELAY_STATE_DIR=/x\n",
            "RELAY_ADDRESS=https://x:1 \\\n  more\n",
            "RELAY_SERVER_NAME=\"unclosed\n",
        ] {
            let f = fixture("join-unparsed");
            f.write_env_file(text);
            let err = configure(
                &f.paths,
                &env_of(&[]),
                true,
                no_read,
                no_enroll,
                never_interrupted,
            )
            .await
            .expect_err("outside the subset");
            assert!(
                matches!(err, JoinError::EnvFileUnparsed { .. }),
                "{text:?}: {err}"
            );
            assert!(!f.state().exists());
        }
    }

    // Proves DI-43.
    #[tokio::test]
    async fn join_refuses_relay_join_before_reading() {
        let f = fixture("join-retired");
        let result = configure(
            &f.paths,
            &env_of(&[("RELAY_JOIN", "glp_join_whatever")]),
            true,
            no_read,
            no_enroll,
            never_interrupted,
        )
        .await;
        let text = result.as_ref().expect_err("refused").to_string();
        assert!(
            matches!(
                &result,
                Err(JoinError::RetiredSetting {
                    name: "RELAY_JOIN",
                    ..
                })
            ),
            "{text}"
        );
        assert!(!text.contains("whatever"), "{text}");
        assert!(!f.state().exists());

        // Assigned in the file, even to nothing.
        f.write_env_file("RELAY_JOIN=\n");
        let result = configure(
            &f.paths,
            &env_of(&[]),
            true,
            no_read,
            no_enroll,
            never_interrupted,
        )
        .await;
        let text = result.as_ref().expect_err("refused").to_string();
        assert!(
            text.contains(&f.paths.env_file.display().to_string()),
            "{text}"
        );
        assert!(!f.state().exists());
    }

    #[tokio::test]
    async fn join_refuses_an_untrusted_state_dir_before_reading() {
        use std::os::unix::fs::{symlink, PermissionsExt};

        // Group- and world-writable.
        let f = fixture("join-writable-state-dir");
        fs::create_dir(f.state()).unwrap();
        fs::set_permissions(f.state(), fs::Permissions::from_mode(0o777)).unwrap();
        // A symlink to a directory that is otherwise fine.
        let g = fixture("join-symlinked-state-dir");
        let real = g.dir.path().join("real");
        fs::create_dir(&real).unwrap();
        fs::set_permissions(&real, fs::Permissions::from_mode(0o700)).unwrap();
        symlink(&real, g.state()).unwrap();

        for fixture in [&f, &g] {
            let before = snapshot(fixture.dir.path());
            let err = configure(
                &fixture.paths,
                &env_of(&[]),
                false,
                no_read,
                no_enroll,
                never_interrupted,
            )
            .await
            .expect_err("an untrusted state directory");
            assert!(
                matches!(
                    &err,
                    JoinError::Identity(ConfigError::UntrustedStateDir { state_dir, .. })
                        if state_dir == fixture.state()
                ),
                "{err:?}"
            );
            assert!(
                err.to_string()
                    .contains(&fixture.state().display().to_string()),
                "{err}"
            );
            assert_eq!(snapshot(fixture.dir.path()), before);
        }
    }

    #[tokio::test]
    async fn join_refuses_an_unusable_state_dir_before_reading() {
        let f = fixture("join-bad-state-dir");
        let file = f.dir.path().join("a-file");
        fs::write(&file, "x").unwrap();
        let under = file.join("state").display().to_string();
        let err = configure(
            &f.paths,
            &env_of(&[("RELAY_STATE_DIR", under.as_str())]),
            false,
            no_read,
            no_enroll,
            never_interrupted,
        )
        .await
        .expect_err("a path under a regular file");
        // Either check refuses it: the identity probe cannot look through a file,
        // and the creatability check names the path.
        assert!(
            matches!(
                err,
                JoinError::StateDir(_)
                    | JoinError::Identity(ConfigError::IdentityUnreadable { .. })
            ),
            "{err:?}"
        );
        assert!(
            err.to_string().contains(&file.display().to_string()),
            "{err}"
        );

        let err = configure(
            &f.paths,
            &env_of(&[("RELAY_STATE_DIR", "relative/state")]),
            false,
            no_read,
            no_enroll,
            never_interrupted,
        )
        .await
        .expect_err("a relative state directory");
        assert!(matches!(err, JoinError::RelativeStateDir), "{err:?}");
        assert!(!Path::new("relative").exists());
    }

    #[tokio::test]
    async fn join_refuses_a_non_regular_env_file() {
        let f = fixture("join-env-dir");
        fs::create_dir(&f.paths.env_file).unwrap();
        let err = configure(
            &f.paths,
            &env_of(&[]),
            true,
            no_read,
            no_enroll,
            never_interrupted,
        )
        .await
        .expect_err("a directory is not an environment file");
        assert!(
            matches!(err, JoinError::EnvFileNotRegular { .. }),
            "{err:?}"
        );
    }

    #[tokio::test]
    async fn join_refuses_a_malformed_or_empty_join_string() {
        for (text, empty) in [
            ("glp_join_not!base64", false),
            ("not-a-join-string", false),
            ("", true),
            ("   \n", true),
        ] {
            let f = fixture("join-malformed");
            let err = configure(
                &f.paths,
                &env_of(&[]),
                false,
                input(text),
                no_enroll,
                never_interrupted,
            )
            .await
            .expect_err("must refuse");
            if empty {
                assert!(matches!(err, JoinError::Empty), "{text:?}: {err}");
            } else {
                assert!(matches!(err, JoinError::Invalid(_)), "{text:?}: {err}");
            }
            assert!(!f.state().exists(), "{text:?}");
        }
        // A join string whose address could redirect the dial is refused too.
        let f = fixture("join-bad-addr");
        let err = configure(
            &f.paths,
            &env_of(&[]),
            false,
            input(join_text("https://relay:7654/x", &[1])),
            no_enroll,
            never_interrupted,
        )
        .await
        .expect_err("must refuse");
        assert!(matches!(
            err,
            JoinError::Invalid(ConfigError::BadJoinAddress(_))
        ));
        assert!(!err.to_string().contains(TOKEN));
        assert!(!f.state().exists());
    }

    // Proves DI-42.
    #[tokio::test]
    async fn unit_starts_only_for_the_units_state_dir_under_systemd() {
        let a = Path::new("/var/lib/relay-daemon");
        let b = Path::new("/elsewhere");
        assert_eq!(unit_start(a, a, true), UnitStart::Start);
        assert_eq!(unit_start(a, a, false), UnitStart::NoSystemd);
        assert_eq!(unit_start(b, a, true), UnitStart::NotTheUnitsStateDir);
        assert_eq!(unit_start(b, a, false), UnitStart::NoSystemd);

        // Starting the unit needs root, and that is known before the read.
        let f = fixture("join-not-root");
        f.run_systemd();
        let err = configure(
            &f.paths,
            &env_of(&[]),
            false,
            no_read,
            no_enroll,
            never_interrupted,
        )
        .await
        .expect_err("a non-root start is refused");
        assert!(matches!(err, JoinError::NotRoot { .. }), "{err:?}");
        assert!(!f.state().exists());
    }

    #[test]
    fn non_root_permission_denied_names_root() {
        let denied = io::Error::from(io::ErrorKind::PermissionDenied);
        assert!(needs_root(&denied, false));
        assert!(!needs_root(&denied, true));
        assert!(!needs_root(
            &io::Error::from(io::ErrorKind::NotFound),
            false
        ));
        let text = JoinError::NeedsRoot {
            path: PathBuf::from(ENV_FILE),
        }
        .to_string();
        assert!(text.contains("sudo relay-daemon join"), "{text}");
    }

    #[test]
    fn read_join_input_handles_eof_without_newline() {
        let read = |bytes: &[u8], limit: usize| {
            let (mut write, read) = UnixStream::pair().unwrap();
            write.write_all(bytes).unwrap();
            drop(write);
            read_line_unbuffered(read, limit).unwrap().to_vec()
        };
        assert_eq!(read(b"glp_join_abc", 64), b"glp_join_abc");
        assert_eq!(read(b"glp_join_abc\n", 64), b"glp_join_abc\n");
        assert_eq!(read(b"first\nsecond\n", 64), b"first\n");
        assert_eq!(read(b"", 64), b"");
        assert_eq!(read(&[b'a'; 100], 10), [b'a'; 10], "at most the limit");
    }

    #[test]
    fn env_file_value_reads_the_last_assignment() {
        let read = |c: &'static [u8]| env_file_value(c, b"RELAY_STATE_DIR");
        assert_eq!(read(b"#RELAY_STATE_DIR=/a\n"), Ok(None));
        assert_eq!(
            read(b"RELAY_STATE_DIR=/a\nRELAY_STATE_DIR='/b'\n"),
            Ok(Some(&b"/b"[..]))
        );
        assert_eq!(read(b"RELAY_STATE_DIR=\n"), Ok(Some(&b""[..])));
        assert_eq!(
            read(b"  RELAY_STATE_DIR = \"/c\"  \n"),
            Ok(Some(&b"/c"[..]))
        );
        assert!(read(b"RELAY_STATE_DIR=/a\\b\n").is_err());
        assert!(read(b"RELAY_STATE_DIR=\"/a\n").is_err());
        assert!(check_continuations(b"A=1\n# note \\\nB=2\n").is_err());
        assert!(check_continuations(b"A=1\n# note\nB=2\n").is_ok());
    }

    /// `join` takes its state directory from the file the packaged unit reads, and
    /// starts that unit.
    // Proves DI-42.
    #[test]
    fn env_file_and_unit_match_the_packaged_unit() {
        let unit = fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/packaging/relay-daemon.service"
        ))
        .expect("read the packaged unit");
        assert!(unit.contains(&format!("EnvironmentFile=-{ENV_FILE}\n")));
        assert!(unit.contains("StateDirectory=relay-daemon\n"));
        assert_eq!(enroll::DEFAULT_STATE_DIR, "/var/lib/relay-daemon");
        assert_eq!(systemctl::SYSTEMCTL_ARGS[2], "relay-daemon.service");
    }
}
