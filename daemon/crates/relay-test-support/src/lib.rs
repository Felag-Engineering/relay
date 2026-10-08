//! Test fixtures shared by the daemon workspace's unit-test modules:
//! self-removing temp directories and files, and the `&[&str]` -> `Vec<String>`
//! argv builder.
//!
//! A dev-only crate (#889): it is only ever a `[dev-dependencies]` entry, which
//! `tests/clippy_write_ban.rs` asserts, so its `OpenOptions::write` calls never
//! reach a production binary. `tests/policy_never_opened_for_write.rs`
//! allowlists this one file as a writer for that reason.
//!
//! The file constructors differ in how they set the mode, and tests depend on
//! the difference: pick by what the test asserts, never by convenience.

use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

/// A fresh path under the system temp dir,
/// `relay-test-<label>-<pid>-<nanos>-<seq>`. Nothing is created there. The
/// per-process sequence number keeps two calls in the same nanosecond
/// (parallel tests, same label) distinct.
pub fn unique_temp_path(label: &str) -> PathBuf {
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let seq = SEQ.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!(
        "relay-test-{label}-{}-{nanos}-{seq}",
        std::process::id()
    ))
}

/// Creates or truncates `path` holding `content` at EXACTLY `mode`.
///
/// `OpenOptions::mode` is masked by the process umask, so on a runner with
/// umask 022 a requested 0o664 lands as 0o644 and a group/world-writable
/// rejection test would spuriously pass the file. chmod is not
/// umask-masked, so the exact mode is forced afterwards.
pub fn write_forced_mode(path: &Path, content: &[u8], mode: u32) {
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(mode)
        .open(path)
        .unwrap();
    f.write_all(content).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
}

/// Builds an argv (or argument list) from string literals.
pub fn args(v: &[&str]) -> Vec<String> {
    v.iter().map(|s| s.to_string()).collect()
}

/// A temp directory that removes itself, recursively, on drop.
pub struct TempDir(PathBuf);

impl TempDir {
    /// Names a fresh directory WITHOUT creating it — for code under test
    /// that creates its own state dir (identity, enrollment, dedup).
    pub fn new(label: &str) -> Self {
        TempDir(unique_temp_path(label))
    }

    /// Names a fresh directory and creates it.
    pub fn created(label: &str) -> Self {
        let path = unique_temp_path(label);
        std::fs::create_dir_all(&path).expect("create temp dir");
        TempDir(path)
    }

    pub fn path(&self) -> &Path {
        &self.0
    }

    pub fn path_str(&self) -> String {
        self.0.to_string_lossy().into_owned()
    }

    /// Writes a file into this directory at a FORCED 0o600, for use as a
    /// Template root. `std::fs::write` is umask-masked, the hardened read
    /// refuses any file with `mode & 0o022 != 0` (`hardened_open`), and
    /// chmod is NOT umask-masked, so the mode is set explicitly.
    pub fn write(&self, name: &str, content: &str) -> PathBuf {
        let path = self.0.join(name);
        std::fs::write(&path, content).expect("write template file");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
            .expect("set template file mode");
        path
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// A temp file that removes itself on drop. One constructor per mode
/// behaviour a test can depend on.
pub struct TempFile(PathBuf);

impl TempFile {
    /// Create-or-truncate at the default 0o666 masked by the umask — for
    /// fixtures whose mode no test looks at.
    pub fn new(label: &str, content: impl AsRef<[u8]>) -> Self {
        let path = unique_temp_path(label);
        std::fs::write(&path, content).expect("create temp file");
        TempFile(path)
    }

    /// `create_new` at a REQUESTED `mode` — a ceiling the umask may
    /// tighten, not a forced one. For fixtures that are inputs to a read
    /// and assert no exact mode: there is no reason to chmod past the
    /// operator's umask, and doing it in a shape copied into production
    /// code is how that pattern spread in the first place (ADR-0036). A
    /// tighter umask simply yields a tighter fixture, which the test
    /// still reads as its own owner.
    pub fn with_requested_mode(label: &str, content: &[u8], mode: u32) -> Self {
        let path = unique_temp_path(label);
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(mode)
            .open(&path)
            .expect("create temp file");
        f.write_all(content).expect("write temp file");
        TempFile(path)
    }

    /// Create-or-truncate at EXACTLY `mode` (see [`write_forced_mode`]) —
    /// for tests whose verdict depends on the mode bits.
    pub fn with_forced_mode(label: &str, content: &[u8], mode: u32) -> Self {
        let path = unique_temp_path(label);
        write_forced_mode(&path, content, mode);
        TempFile(path)
    }

    pub fn path(&self) -> &Path {
        &self.0
    }

    pub fn path_str(&self) -> String {
        self.0.to_string_lossy().into_owned()
    }
}

impl Drop for TempFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

/// Waits (up to 5 s) for a test command to have written a newline-terminated
/// pid to `path`, and returns it. Polls the file — observable state — rather
/// than sleeping a fixed time.
pub async fn read_pid_file(path: &Path) -> i32 {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    loop {
        if let Ok(text) = std::fs::read_to_string(path) {
            if let Some(pid) = text.strip_suffix('\n').and_then(|s| s.parse().ok()) {
                return pid;
            }
        }
        assert!(
            std::time::Instant::now() < deadline,
            "no pid written to {} within 5 s",
            path.display()
        );
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
}

/// Waits (up to `within`) until `pid` no longer exists at all — not even as
/// a zombie — and panics otherwise. `kill(pid, 0)` answers for an
/// unreaped zombie and returns ESRCH only once the process has been reaped,
/// so this proves the process was both killed and collected.
pub async fn wait_until_reaped(pid: i32, within: std::time::Duration) {
    use rustix::io::Errno;
    use rustix::process::{test_kill_process, Pid};
    let probe = Pid::from_raw(pid).expect("a test pid is non-zero");
    let deadline = std::time::Instant::now() + within;
    loop {
        match test_kill_process(probe) {
            Err(Errno::SRCH) => return,
            Err(e) => panic!("pid {pid} must be gone (ESRCH), not another error: {e}"),
            Ok(()) => {}
        }
        assert!(
            std::time::Instant::now() < deadline,
            "pid {pid} still exists after {within:?}"
        );
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
}

/// Captures `tracing` events into memory so a test can assert on what the
/// daemon logs, and on what it must not.
pub mod trace_capture {
    use std::collections::BTreeMap;
    use std::sync::{Arc, Mutex};

    use tracing::field::{Field, Visit};
    use tracing::subscriber::DefaultGuard;
    use tracing_subscriber::layer::Context;
    use tracing_subscriber::prelude::*;
    use tracing_subscriber::Layer;

    #[derive(Debug, Clone)]
    pub struct CapturedEvent {
        pub target: String,
        pub fields: BTreeMap<String, String>,
    }

    impl CapturedEvent {
        pub fn field_names(&self) -> Vec<&str> {
            self.fields.keys().map(String::as_str).collect()
        }
    }

    #[derive(Clone, Default)]
    pub struct Captured(Arc<Mutex<Vec<CapturedEvent>>>);

    impl Captured {
        pub fn events_with_target(&self, target: &str) -> Vec<CapturedEvent> {
            self.0
                .lock()
                .unwrap()
                .iter()
                .filter(|e| e.target == target)
                .cloned()
                .collect()
        }
    }

    struct FieldVisitor<'a>(&'a mut BTreeMap<String, String>);

    impl Visit for FieldVisitor<'_> {
        fn record_str(&mut self, field: &Field, value: &str) {
            self.0.insert(field.name().to_string(), value.to_string());
        }
        fn record_u64(&mut self, field: &Field, value: u64) {
            self.0.insert(field.name().to_string(), value.to_string());
        }
        fn record_i64(&mut self, field: &Field, value: i64) {
            self.0.insert(field.name().to_string(), value.to_string());
        }
        fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
            self.0
                .insert(field.name().to_string(), format!("{value:?}"));
        }
    }

    struct CaptureLayer(Captured);

    impl<S: tracing::Subscriber> Layer<S> for CaptureLayer {
        fn on_event(&self, event: &tracing::Event<'_>, _ctx: Context<'_, S>) {
            let mut fields = BTreeMap::new();
            event.record(&mut FieldVisitor(&mut fields));
            (self.0).0.lock().unwrap().push(CapturedEvent {
                target: event.metadata().target().to_string(),
                fields,
            });
        }
    }

    /// Installs a capturing subscriber for the current thread (the tests
    /// using it are current-thread `#[tokio::test]`s) until the guard drops.
    pub fn capture() -> (Captured, DefaultGuard) {
        ensure_callsites_enabled();
        let captured = Captured::default();
        let guard = tracing::subscriber::set_default(
            tracing_subscriber::registry().with(CaptureLayer(captured.clone())),
        );
        (captured, guard)
    }

    /// Installs, once per process, a global subscriber that enables every
    /// callsite and discards the events. tracing caches each callsite's
    /// interest; a test thread with no subscriber can register a callsite as
    /// "never" while another thread's scoped capture is installed, and that
    /// cached "never" would then drop the event the capture is waiting for.
    /// Once the global subscriber is installed the interest can never be
    /// "never", so each event is decided by the thread's own scoped
    /// subscriber. The first install leaves a window of microseconds, once
    /// per process, in which a callsite registering on another thread can
    /// still cache "never"; repeated full parallel runs have not hit it.
    fn ensure_callsites_enabled() {
        static INSTALLED: std::sync::OnceLock<()> = std::sync::OnceLock::new();
        INSTALLED.get_or_init(|| {
            let _ = tracing::subscriber::set_global_default(tracing_subscriber::registry());
        });
    }

    /// Installs the production formatting layer, filtered at `info`, over a
    /// shared buffer for the current thread until the guard drops.
    pub fn capture_fmt() -> (SharedBuf, DefaultGuard) {
        ensure_callsites_enabled();
        let buf = SharedBuf::default();
        let writer = buf.clone();
        let subscriber = tracing_subscriber::registry()
            .with(tracing_subscriber::EnvFilter::new("info"))
            .with(relay_log::log_fmt_layer(move || writer.clone()));
        (buf, tracing::subscriber::set_default(subscriber))
    }

    /// A shared in-memory writer, for formatting tests.
    #[derive(Clone, Default)]
    pub struct SharedBuf(pub Arc<Mutex<Vec<u8>>>);

    impl std::io::Write for SharedBuf {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
}
