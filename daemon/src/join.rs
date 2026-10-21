//! `relay-daemon join`: configures a fresh Node in one step (DI-37). It reads a join
//! string from a prompt with echo off, or from standard input, and never from its
//! arguments; validates it offline; writes it as the environment file's `RELAY_JOIN`
//! line, root-owned and readable by nobody else (the write is in [`env_file`]); then
//! enables and starts the unit through `systemctl` (the spawn is in [`systemctl`]).
//! It refuses on a Node that holds any identity file, changing nothing, and it
//! contacts no Relay: enrollment happens when the daemon starts.
//!
//! The join string is held as the redacting `JoinString` once decoded, and every
//! buffer this module owns that holds its text is wiped when dropped. Two copies
//! are not: std's buffered stdin reader, and `JoinString`'s own fields, both freed
//! unwiped when the process exits right after. No message this module prints
//! carries the join string or any part of it.

mod env_file;
mod systemctl;

use std::ffi::OsStr;
use std::fs;
use std::io::{self, BufRead, IsTerminal, Read, Write};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};

use rustix::termios::{tcgetattr, tcsetattr, LocalModes, OptionalActions, Termios};
use zeroize::Zeroizing;

use crate::config::{self, ConfigError, IdentityState, MAX_JOIN_STRING_LEN};
use env_file::WriteError;

/// The environment file the packaged unit reads (`EnvironmentFile=` in
/// `relay-daemon.service`), and so the one `join` writes.
pub const ENV_FILE: &str = "/etc/relay-daemon/relay-daemon.env";

/// The unit's state directory (`StateDirectory=relay-daemon`), where the daemon
/// keeps its identity unless the environment file names another.
pub const DEFAULT_STATE_DIR: &str = "/var/lib/relay-daemon";

/// The uid and gid the environment file is given.
type Owner = (u32, u32);

const ROOT: Owner = (0, 0);

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
    #[error("{0}; relay-daemon.service was not started")]
    Write(WriteError),
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
    /// Always checked for an identity. The process environment plays no part: the
    /// daemon reads the unit's environment, not the caller's, so a caller's
    /// `RELAY_STATE_DIR` could only point the check somewhere empty.
    default_state_dir: PathBuf,
}

impl JoinPaths {
    fn production() -> Self {
        JoinPaths {
            env_file: PathBuf::from(ENV_FILE),
            default_state_dir: PathBuf::from(DEFAULT_STATE_DIR),
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
    read_input: impl FnOnce() -> Result<Secret, JoinError>,
) -> Result<(), JoinError> {
    let existing = read_env_file(&paths.env_file)?;
    let existing_bytes = existing.as_ref().map(|v| v.as_slice());

    let mut state_dirs = vec![paths.default_state_dir.clone()];
    if let Some(named) = existing_bytes.and_then(env_file_state_dir) {
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
    let join = config::decode_join_str(raw.trim())
        .map_err(JoinError::Invalid)?
        .ok_or(JoinError::Empty)?;
    drop(raw);

    let encoded = Zeroizing::new(
        join.encode()
            .map_err(|e| JoinError::Invalid(ConfigError::MalformedJoin(e)))?,
    );
    let mut line = Zeroizing::new(b"RELAY_JOIN=".to_vec());
    line.extend_from_slice(encoded.as_bytes());
    let content = Zeroizing::new(with_join_line(existing_bytes, &line));

    env_file::remove_stale_temps(&paths.env_file).map_err(JoinError::Write)?;
    env_file::write_atomically(&paths.env_file, &content, owner).map_err(JoinError::Write)
}

/// The environment file's bytes, or `None` when there is none. A symlink or any
/// other non-regular file is refused: the rename would replace the link, not what
/// it points at.
fn read_env_file(path: &Path) -> Result<Option<Zeroizing<Vec<u8>>>, JoinError> {
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
        .map(|v| Some(Zeroizing::new(v)))
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

/// Reads one line from standard input: behind a prompt with echo off when it is a
/// terminal, as piped text otherwise. At most a little over the longest join string
/// is read, so an oversized input is refused by the decoder rather than buffered.
fn read_join_input() -> Result<Secret, JoinError> {
    let stdin = io::stdin();
    let interactive = stdin.is_terminal();
    // Room for the longest value read, so the buffer never reallocates and leaves
    // an unwiped copy behind.
    let limit = MAX_JOIN_STRING_LEN + 2;
    let mut buf = Zeroizing::new(Vec::with_capacity(limit));
    {
        let echo = if interactive {
            eprint!("Paste the join string (input is hidden): ");
            let _ = io::stderr().flush();
            Some(EchoOff::new().map_err(JoinError::Read)?)
        } else {
            None
        };
        let read = stdin.lock().take(limit as u64).read_until(b'\n', &mut buf);
        // The prompt ends here, and only one side may end it: if the interrupt
        // handler claimed it first it is restoring echo and exiting 130 having
        // told the operator nothing changed, so this thread must not go on to
        // write anything. Claimed before a read error is returned, too.
        if echo.as_ref().is_some_and(|e| e.on_interrupt.is_some()) && !AT_PROMPT.claim() {
            loop {
                std::thread::park();
            }
        }
        read.map_err(JoinError::Read)?;
        drop(echo);
    }
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
/// [`AT_PROMPT`], restores `saved` and exits 130 with nothing written. Any other
/// SIGINT is ignored: once registered, the signal stays caught for the rest of the
/// run, so a Ctrl-C after the prompt does not interrupt `join` (a child such as
/// `systemctl` still receives it). `None` outside a runtime, which leaves the
/// default action (and `stty echo` as the recovery the install guide documents).
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

    fn input(text: impl Into<String>) -> impl FnOnce() -> Result<Secret, JoinError> {
        let text = text.into();
        move || Ok(Zeroizing::new(text))
    }

    const ENV: &str = "# comment\n#RELAY_JOIN=old-commented\nRELAY_POLICY_PATH=/etc/relay-daemon/policy.toml\nRELAY_JOIN=replace-me\n#RELAY_ADDRESS=https://x:1\nRELAY_TEMPLATE_DIR=/etc/relay-daemon/templates.d\n";

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
        let default_state_dir = dir.path().join("state");
        fs::create_dir(&default_state_dir).expect("state dir");
        Fixture {
            paths: JoinPaths {
                env_file,
                default_state_dir,
            },
            _dir: dir,
        }
    }

    fn no_read() -> Result<Secret, JoinError> {
        panic!("the join string must not be read once join has refused")
    }

    fn leftovers(dir: &Path) -> Vec<String> {
        fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .filter(|n| n.contains(".join-"))
            .collect()
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
            let gate = std::sync::Arc::new(PromptGate::new());
            gate.open();
            let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
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
            fs::write(f.paths.default_state_dir.join(name), b"x").unwrap();
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

    /// The default state directory is checked even when the environment file names
    /// an empty one, and the caller's own environment is never consulted, so
    /// `sudo -E RELAY_STATE_DIR=/tmp/empty relay-daemon join` on an enrolled Node
    /// still refuses.
    #[test]
    fn join_always_checks_the_default_state_dir() {
        let dir = TempDir::created("join-default-state");
        let empty = dir.path().join("empty");
        fs::create_dir(&empty).unwrap();
        let env = format!("{ENV}RELAY_STATE_DIR={}\n", empty.display());
        let f = fixture("join-default", Some(env.as_bytes()));
        fs::write(f.paths.default_state_dir.join("node_id"), b"n").unwrap();
        let err = configure(&f.paths, me(), no_read).expect_err("must refuse");
        assert!(
            matches!(err, JoinError::AlreadyEnrolled { ref state_dir } if *state_dir == f.paths.default_state_dir)
        );
        assert_eq!(fs::read(&f.paths.env_file).unwrap(), env.as_bytes());

        let prod = JoinPaths::production();
        assert_eq!(
            prod.default_state_dir,
            PathBuf::from("/var/lib/relay-daemon")
        );
        assert_eq!(prod.env_file, PathBuf::from(ENV_FILE));
    }

    #[test]
    fn join_writes_env_file_root_0600_atomically() {
        let f = fixture("join-write", Some(ENV.as_bytes()));
        fs::set_permissions(&f.paths.env_file, fs::Permissions::from_mode(0o644)).unwrap();
        let before = fs::metadata(&f.paths.env_file).unwrap().ino();
        let text = join_text("relay.example:7654");
        configure(&f.paths, me(), input(format!("  {text}\r\n"))).expect("join configures");

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

    /// A temporary file an interrupted run left behind holds a join string; the
    /// next run removes it before writing.
    #[test]
    fn join_removes_a_stale_temporary_file() {
        let f = fixture("join-stale-run", Some(ENV.as_bytes()));
        let dir = f.paths.env_file.parent().unwrap().to_path_buf();
        fs::write(
            dir.join(".relay-daemon.env.join-99999.tmp"),
            b"RELAY_JOIN=glp_join_old\n",
        )
        .unwrap();
        configure(&f.paths, me(), input(join_text("relay:7654"))).expect("join");
        assert!(leftovers(&dir).is_empty());
    }

    #[test]
    fn join_appends_a_missing_line_and_creates_a_missing_file() {
        let text = join_text("[fd00::1]:7654");
        let f = fixture("join-append", Some(b"RELAY_POLICY_PATH=/p"));
        configure(&f.paths, me(), input(text.clone())).expect("append");
        assert_eq!(
            fs::read(&f.paths.env_file).unwrap(),
            format!("RELAY_POLICY_PATH=/p\nRELAY_JOIN={text}\n").as_bytes()
        );

        let f = fixture("join-create", None);
        configure(&f.paths, me(), input(text.clone())).expect("create");
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
        configure(&f.paths, me(), input(text.clone())).expect("join");
        assert_eq!(
            fs::read(&f.paths.env_file).unwrap(),
            format!("RELAY_JOIN={text}\nX=1\nRELAY_JOIN={text}\nRELAY_JOINed=keep\n").as_bytes()
        );
    }

    #[test]
    fn join_refuses_a_malformed_or_empty_join_string_env_file_unchanged() {
        for (text, empty) in [
            ("glp_join_not!base64", false),
            ("not-a-join-string", false),
            ("", true),
            ("   \n", true),
        ] {
            let f = fixture("join-malformed", Some(ENV.as_bytes()));
            let err = configure(&f.paths, me(), input(text)).expect_err("must refuse");
            if empty {
                assert!(matches!(err, JoinError::Empty), "{text:?}: {err}");
            } else {
                assert!(matches!(err, JoinError::Invalid(_)), "{text:?}: {err}");
            }
            assert_eq!(fs::read(&f.paths.env_file).unwrap(), ENV.as_bytes());
            assert!(leftovers(f.paths.env_file.parent().unwrap()).is_empty());
        }
        // A join string whose address could redirect the dial is refused offline too.
        let f = fixture("join-bad-addr", Some(ENV.as_bytes()));
        let err = configure(&f.paths, me(), input(join_text("https://relay:7654/x")))
            .expect_err("must refuse");
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
        let target = f
            .paths
            .default_state_dir
            .parent()
            .unwrap()
            .join("target.env");
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
        let read = env_file_state_dir;
        assert_eq!(read(b"#RELAY_STATE_DIR=/a\n"), None);
        assert_eq!(
            read(b"RELAY_STATE_DIR=/a\nRELAY_STATE_DIR='/b'\n"),
            Some(PathBuf::from("/b"))
        );
        assert_eq!(read(b"RELAY_STATE_DIR=\n"), None);
    }

    /// `join` writes the file the packaged unit reads, checks the state directory
    /// it uses, and starts that unit.
    #[test]
    fn env_file_and_unit_match_the_packaged_unit() {
        let unit = fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/packaging/relay-daemon.service"
        ))
        .expect("read the packaged unit");
        assert!(unit.contains(&format!("EnvironmentFile=-{ENV_FILE}\n")));
        assert!(unit.contains("StateDirectory=relay-daemon\n"));
        assert_eq!(DEFAULT_STATE_DIR, "/var/lib/relay-daemon");
        assert_eq!(systemctl::SYSTEMCTL_ARGS[2], "relay-daemon.service");
    }
}
