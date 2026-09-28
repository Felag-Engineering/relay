//! Persisted dedup store for at-most-once Task execution (ADR-0004, invariant #4).
//!
//! # Invariant
//!
//! Each Task carries a unique ID. The relay-daemon MUST execute each Task at most once,
//! even across reconnects to the Relay and even across daemon restarts. This module
//! enforces that invariant by persisting a marker to the daemon's state dir BEFORE
//! executing the Task. A retry with the same task_id (after a reconnect or restart)
//! finds the marker and returns a benign already-processed result without re-executing.
//!
//! Dispatch-agnostic: no tunnel/mpsc types here. Wired into the live tunnel loop by #82.
//!
//! # Record-before-execute ordering
//!
//! The ordering is: durably record → execute. This guarantees at-most-once:
//!
//! - **Crash before record persisted**: the id is not seen on restart; the Task runs
//!   on retry (0 → 1 execution). Correct.
//! - **Crash after record, before/during execute**: the id IS seen on restart; the
//!   retry returns a benign result. Net executions ≤ 1 (possibly 0 if the crash
//!   preceded any side effects). This is the deliberate cost — we prefer no-execution
//!   over double-execution (ADR-0004 "never at-least-once").
//! - **Crash after execute**: the id is seen; retry is deduped. 1 execution. Correct.
//!
//! # Persistence format
//!
//! `<state_dir>/seen-tasks/` — directory, mode 0700 **requested**.
//! `<state_dir>/seen-tasks/<hex(task_id.as_bytes())>` — one empty marker file per seen
//! Task, mode 0600 **requested**. Both modes are ceilings the process umask may tighten
//! and this code never forces back (ADR-0036); a umask that tightens the directory out
//! of usability is refused loudly by the fail-closed path below, never worked around.
//! The filename is the lowercase-hex encoding of the task_id's UTF-8
//! bytes: safe [0-9a-f] charset, reversible, no collisions, no hash dependency. A
//! UUID-length task_id (36 bytes) → 72-character filename, well within NAME_MAX (255).
//! The record timestamp is the file mtime; the body is empty.
//!
//! Reload (at `open`) reads the directory, hex-decodes each entry name back to a
//! task_id, and reads the mtime for the timestamp. Non-hex entries are silently skipped
//! (created by other tools or partially-written entries from a future format version).
//!
//! # Retention and eviction
//!
//! Age-based: 24-hour retention window by marker mtime. The reconnect/retry window in
//! practice is seconds to minutes; 24 h is a comfortable margin that prevents spurious
//! eviction of recent entries.
//! Secondary capacity cap: 100,000 entries, oldest-first eviction, to bound memory and
//! disk growth in a long-lived daemon. Eviction runs at `open` and after each `record`.
//!
//! **Age floor on capacity eviction (issue #340):** the capacity pass never evicts a
//! marker younger than a 1-hour floor (`MIN_RETENTION`), even when the store is over the
//! cap. Without it, a flood of >100k fresh Task IDs inside the retry window could evict a
//! still-live marker oldest-first, and the retried Task would then execute twice — an
//! at-most-once violation (ADR-0004). Under such a flood the store grows past the cap
//! rather than drop a live marker; bounding memory yields to the invariant.
//!
//! # Design notes
//!
//! - **id-only markers (no result retention)**: security posture — do not persist
//!   potentially-sensitive captured stdout/stderr at rest. The marker proves "this Task
//!   was dispatched"; it does not reproduce the prior outcome. **Caveat**: a duplicate
//!   always returns a synthesized benign SUCCESS, even when the original run FAILED
//!   (documented trade-off — if idempotent result replay becomes required, a follow-up
//!   ADR adds OUTCOME_ALREADY_PROCESSED to /proto; no proto change here).
//! - **Fail closed on record error**: if the marker cannot be durably written, the Task
//!   is NOT executed. We cannot guarantee dedup on retry without a persisted marker;
//!   prefer no-execution over at-least-once (ADR-0004, most-restrictive-wins).
//! - **Single instance per directory**: two `DedupStore` instances on the same
//!   `seen-tasks/` directory would have independent in-memory maps, breaking the dedup
//!   invariant. The daemon creates exactly one instance at startup and passes it down.
//! - **`run_once` is the sole public dispatch entry**: the record-before-execute ordering
//!   is un-bypassable; a caller cannot execute-before-record.
//! - **Blocking fsync under the Mutex**: `sync_all(file) + fsync(dir)` runs while
//!   holding the lock. This is intentional — it keeps check+record atomic (no two
//!   concurrent `run_once` calls can both see "not seen" for the same task_id) and
//!   mirrors the sync-fs-in-async pattern in identity.rs / renew.rs. The cost is that
//!   a NEW task_id adds blocking I/O latency to the critical section; a duplicate (the
//!   common case on reconnect) is just a HashMap lookup with no I/O.

use std::collections::HashMap;
use std::fs::{self, OpenOptions};
use std::future::Future;
use std::io;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::gen::{Outcome, TaskResult};
use crate::not_executed::not_executed;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const SEEN_SUBDIR: &str = "seen-tasks";

/// Default retention window: Task IDs are remembered for 24 hours after recording.
/// The reconnect/retry window in practice is seconds to minutes; this is a comfortable
/// margin that prevents spurious eviction of entries still within a live retry window.
const RETENTION: Duration = Duration::from_secs(24 * 60 * 60);

/// Capacity-eviction age floor (issue #340): capacity pressure may NEVER evict a
/// marker younger than this, even when the store is over [`MAX_ENTRIES`]. It is the
/// guaranteed-live window — below it, a marker might still be needed to dedup a
/// redelivered Task, and evicting it would let that retry execute twice, violating
/// at-most-once (ADR-0004, invariant #4).
///
/// One hour is a deliberately generous floor: a Task executes for at most `MAX_TIMEOUT`
/// (5 min) and the Relay's reconnect backoff caps at 30 s, so the real redelivery
/// window is minutes; 1 h is ~12× the execution cap. It is also 1/24 of [`RETENTION`],
/// so the capacity cap still has the entire 1 h–24 h band of genuinely-old entries to
/// evict in a long-lived daemon. Must be < the retention window.
const MIN_RETENTION: Duration = Duration::from_secs(60 * 60);

/// Secondary capacity cap: bounds memory and disk growth in a long-lived daemon.
///
/// Best-effort, NOT a hard bound: when honoring it would require evicting a marker
/// younger than [`MIN_RETENTION`], the store instead grows past the cap. Bounding
/// memory yields to at-most-once (ADR-0004 most-restrictive-wins). A sustained flood
/// thus bounds the store at roughly (accept-rate × MIN_RETENTION), not unbounded — the
/// oldest markers cross the floor and become evictable as the flood continues.
const MAX_ENTRIES: usize = 100_000;

/// Directory mode for the seen-tasks directory: owner-only (root-owned daemon state).
const DIR_MODE: u32 = 0o700;

/// File mode for each marker: owner-only read/write.
const FILE_MODE: u32 = 0o600;

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// Persisted dedup store for at-most-once Task execution.
///
/// See the module-level doc for the invariant, persistence format, and design notes.
///
/// **Single-instance constraint**: create exactly one `DedupStore` per `seen-tasks/`
/// directory per process. Two instances on the same directory would have independent
/// in-memory maps; a duplicate task_id could slip through the in-memory check in one
/// instance while the other holds the on-disk record, silently breaking at-most-once.
pub struct DedupStore {
    /// Absolute path to `<state_dir>/seen-tasks/`.
    dir: PathBuf,
    /// In-memory index: task_id → unix milliseconds of the record time (= file mtime).
    inner: Mutex<HashMap<String, i64>>,
    /// Retention window in milliseconds. Defaults to [`RETENTION`]; overridable via
    /// [`DedupStore::open_with`] in tests.
    retention_millis: i64,
    /// Capacity-eviction age floor in milliseconds (issue #340). Defaults to
    /// [`MIN_RETENTION`]; overridable via `open_with` in tests. Capacity eviction never
    /// removes a marker younger than this.
    min_retention_millis: i64,
    /// Capacity cap. Defaults to [`MAX_ENTRIES`]; overridable via `open_with` in tests.
    max_entries: usize,
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

impl DedupStore {
    /// Opens (creating if absent) the seen-tasks store under `state_dir`.
    ///
    /// Loads every persisted marker into the in-memory index (timestamp = file mtime),
    /// then evicts anything past the 24-hour retention window and any excess beyond the
    /// 100,000-entry capacity cap.
    ///
    /// The `seen-tasks/` directory is **requested** at mode 0700 via `DirBuilder::mode()`,
    /// which the process umask may tighten. That is deliberate and load-bearing: a declared
    /// mode is a ceiling — the most this code asks for — and the operator's umask is theirs
    /// to tighten (ADR-0036). Node code never calls `set_permissions` to win that argument
    /// back; what is created and enforced on the Node is enforced on the Node.
    ///
    /// The consequence is accepted, not engineered around. A pathological umask (0o100
    /// strips user-execute from a 0o700 dir) leaves a directory in which no marker file can
    /// be created — and a marker is what makes at-most-once execution durable (ADR-0004,
    /// invariant #4). `run_once` then **fails closed**: every Task is refused with a
    /// durable-record error and nothing executes. That is the correct outcome. Breaking
    /// loudly, attributably, and on the safe side of at-most-once is better than a daemon
    /// that quietly re-widens permissions the operator deliberately removed. See
    /// `umask_tightened_dedup_directory_never_executes_unrecorded` for the demonstration.
    pub fn open(state_dir: &Path) -> io::Result<Self> {
        Self::open_with(
            state_dir,
            RETENTION.as_millis() as i64,
            MIN_RETENTION.as_millis() as i64,
            MAX_ENTRIES,
        )
    }

    /// Runs `exec` for `task_id` at most once, honoring ADR-0004.
    ///
    /// **Ordering (record-before-execute)**: acquires the internal lock; if `task_id`
    /// is already seen, releases the lock immediately and returns a benign
    /// already-processed [`TaskResult`] without calling `exec`. Otherwise, durably
    /// records the id (marker file created 0600, `sync_all` on the file, `fsync` on
    /// the directory to ensure the directory entry survives a crash), inserts it into
    /// the in-memory index, **releases the lock**, then awaits `exec` and returns its
    /// result.
    ///
    /// **Fail closed on record error**: if the marker cannot be written (disk full,
    /// NAME_MAX exceeded, permissions error, etc.), returns a FAILURE [`TaskResult`]
    /// and does NOT call `exec`. Without a durable marker, a subsequent retry after a
    /// crash or reconnect would see the id as "not seen" and re-execute, violating
    /// at-most-once. We prefer no-execution over at-least-once.
    pub async fn run_once<F, Fut>(&self, task_id: &str, exec: F) -> TaskResult
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = TaskResult>,
    {
        // Acquire the lock, check, and record — all in a synchronous block so the
        // MutexGuard is dropped before we ever reach the `.await` on `exec`.
        // clippy::await_holding_lock would flag a guard surviving past `.await`;
        // this block ensures it does not.
        let record_result = {
            let mut guard = self.inner.lock().expect("dedup Mutex not poisoned");
            if guard.contains_key(task_id) {
                // Lock is released as `guard` drops on return.
                return already_processed_result(task_id);
            }
            // Record durably while holding the lock: keeps check+record atomic so no two
            // concurrent run_once calls can both see "not seen" for the same task_id.
            record_marker(
                &mut guard,
                &self.dir,
                task_id,
                self.retention_millis,
                self.min_retention_millis,
                self.max_entries,
            )
            // `guard` drops here — before the `.await` below.
        };

        // Fail closed: if the durable record failed, do not execute. Without a
        // persisted marker, at-most-once cannot be guaranteed on a retry.
        if let Err(e) = record_result {
            return not_executed(
                task_id.to_string(),
                Outcome::Failure,
                format!("dedup: failed to record task id before execute: {e}"),
            );
        }

        // Lock released; exec runs with no lock held.
        exec().await
    }
}

// ---------------------------------------------------------------------------
// Internal implementation
// ---------------------------------------------------------------------------

impl DedupStore {
    /// Internal constructor, parameterized for tests.
    ///
    /// `retention_millis`: how long a seen task_id is retained before age eviction.
    /// `max_entries`: capacity cap, oldest-first eviction when exceeded.
    ///
    /// Not `pub`: the single-instance-per-directory constraint means callers outside
    /// this module should use [`DedupStore::open`] with the production defaults.
    /// Tests access this via `super::` from the descendant `tests` module.
    ///
    /// `min_retention_millis`: capacity-eviction age floor (issue #340); capacity
    /// eviction never removes a marker younger than this.
    fn open_with(
        state_dir: &Path,
        retention_millis: i64,
        min_retention_millis: i64,
        max_entries: usize,
    ) -> io::Result<Self> {
        let dir = state_dir.join(SEEN_SUBDIR);

        // Request the seen-tasks directory (and any missing parents) at mode 0700.
        // DIR_MODE is a ceiling, deliberately left umask-masked (ADR-0036): the operator's
        // umask may tighten it and nothing here may widen it back. No `set_permissions`
        // follow-up — that call is not umask-masked, so it would override the operator on
        // their own host. If a umask tightens this directory into unusability, `run_once`
        // fails closed and refuses every Task (ADR-0004); see [`DedupStore::open`]'s doc.
        fs::DirBuilder::new()
            .recursive(true)
            .mode(DIR_MODE)
            .create(&dir)?;

        // Load persisted markers into the in-memory index.
        let mut map = HashMap::new();
        for entry in fs::read_dir(&dir)? {
            let entry = entry?;
            let name = entry.file_name();
            let name_str = name.to_string_lossy();

            // Only entries whose names are valid lowercase hex are our markers;
            // skip anything else (other tools, partially-written entries, future formats).
            let task_id_bytes = match hex_decode(&name_str) {
                Some(b) => b,
                None => continue,
            };
            let task_id = match String::from_utf8(task_id_bytes) {
                Ok(s) => s,
                Err(_) => continue, // non-UTF-8 ids are not ours; skip
            };

            // Use file mtime as the record timestamp (milliseconds since UNIX_EPOCH).
            let mtime_millis = entry
                .metadata()
                .ok()
                .and_then(|m| m.modified().ok())
                .map(|t| t.duration_since(UNIX_EPOCH).unwrap_or_default().as_millis() as i64)
                .unwrap_or(0);

            map.insert(task_id, mtime_millis);
        }

        let now_millis = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as i64;
        evict_locked(
            &mut map,
            &dir,
            now_millis,
            retention_millis,
            min_retention_millis,
            max_entries,
        );

        Ok(DedupStore {
            dir,
            inner: Mutex::new(map),
            retention_millis,
            min_retention_millis,
            max_entries,
        })
    }
}

/// Synthesizes a benign already-processed [`TaskResult`] for a duplicate task_id.
///
/// Returns OUTCOME_SUCCESS because deduplication is not an execution failure — the
/// Task was previously dispatched and (as far as we know) ran. The proto enum has no
/// ALREADY_PROCESSED or SKIPPED value (no proto change here; a follow-up ADR would add
/// one if idempotent result replay becomes required).
///
/// **Caveat (documented trade-off)**: if the original run FAILED, this result still
/// returns SUCCESS. The id-only persistence design intentionally does not retain the
/// prior outcome (security posture: no sensitive captured output at rest). Surfaced to
/// the human reviewer in the PR description.
fn already_processed_result(task_id: &str) -> TaskResult {
    TaskResult {
        task_id: task_id.to_string(),
        outcome: Outcome::Success as i32,
        exit_code: 0,
        stdout: vec![],
        stderr: b"task already processed; deduplicated (at-most-once, not re-run)".to_vec(),
        truncated: false,
        duration_millis: 0,
    }
}

/// Durably records `task_id` as seen, then runs eviction.
///
/// Creates a marker file at `dir/<hex(task_id)>` (mode 0600), calls `sync_all` on the
/// file to flush the inode (including mtime), then opens the directory and calls
/// `sync_all` to flush the directory entry. This fsync pair ensures the marker survives
/// a power loss or kernel panic between this call and the subsequent exec invocation;
/// at-most-once must hold even across power loss.
///
/// **Blocking I/O under the Mutex**: this function is called while the caller holds the
/// Mutex guard (see `run_once`). The fsync is blocking I/O intentionally: keeping
/// check+record atomic (under the lock) means no two concurrent `run_once` calls can
/// both see "not seen" for the same task_id. The cost — blocking I/O in the critical
/// section — applies only to a NEW task_id; a duplicate (the common case on reconnect)
/// returns after a HashMap lookup with no I/O.
///
/// **NAME_MAX guard**: `hex(task_id.as_bytes())` has length `2 × task_id.len()`. On
/// Linux, NAME_MAX is 255 bytes, so task_ids longer than 127 bytes would produce a
/// filename that exceeds NAME_MAX. Rather than returning a kernel ENAMETOOLONG, this
/// function detects the case early and returns a descriptive [`io::Error`] so the
/// caller can fail closed with a useful diagnostic. UUIDs (36 bytes → 72 hex chars)
/// and typical structured IDs are well within this limit.
fn record_marker(
    map: &mut HashMap<String, i64>,
    dir: &Path,
    task_id: &str,
    retention_millis: i64,
    min_retention_millis: i64,
    max_entries: usize,
) -> io::Result<()> {
    let hex = hex_encode(task_id.as_bytes());

    // NAME_MAX guard: reject over-long ids with a descriptive error before the
    // kernel can return ENAMETOOLONG (which is less diagnosable).
    if hex.len() > 255 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "task_id too long: hex filename ({} bytes) exceeds NAME_MAX (255); \
                 task_id byte length: {}",
                hex.len(),
                task_id.len()
            ),
        ));
    }

    let path = dir.join(&hex);

    // O_CREAT|O_EXCL: fail if the marker already exists.  The in-memory check in
    // run_once guards against this in normal operation, but O_EXCL is a safe net for
    // concurrent calls and logic bugs.
    //
    // FILE_MODE is a ceiling requested through `OpenOptions::mode()`, which the process
    // umask may tighten (ADR-0036). No `set_permissions` follow-up: that call is not
    // umask-masked, and re-adding a bit the operator stripped would override them on
    // their own Node. A marker the umask tightens is still a marker; a directory the
    // umask makes unusable surfaces here as a record error, and `run_once` fails closed.
    let file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(FILE_MODE)
        .open(&path)?;
    // Flush the file's inode (including mtime) to durable storage.
    file.sync_all()?;
    drop(file);
    // Flush the directory entry (filename → inode link) to durable storage.
    // Without this, a crash could leave the inode flushed but the directory entry not
    // yet written, making the marker invisible on the next reload from disk.
    let dir_fd = fs::File::open(dir)?;
    dir_fd.sync_all()?;

    // Record in the in-memory index (timestamp = now).
    let now_millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64;
    map.insert(task_id.to_string(), now_millis);

    // Capacity eviction: keep the store within bounds after every new record.
    evict_locked(
        map,
        dir,
        now_millis,
        retention_millis,
        min_retention_millis,
        max_entries,
    );

    Ok(())
}

/// Evicts expired (age > `retention_millis`) and excess (count > `max_entries`) entries,
/// subject to the capacity-eviction age floor (`min_retention_millis`, issue #340).
///
/// Age eviction runs first (removes all entries older than the retention window).
/// Capacity eviction runs second (removes the oldest remaining entries until within the
/// cap) but **never evicts a marker younger than the age floor** — a still-live marker
/// dropped under capacity pressure would let a redelivered Task execute twice, an
/// at-most-once violation (ADR-0004). When only floor-protected entries remain and the
/// store is still over the cap, it stays over the cap: bounding memory yields to the
/// invariant (most-restrictive-wins). For each evicted entry, the on-disk marker file is
/// removed before the in-memory entry is dropped; removal errors are ignored (the file
/// may already have been cleaned up by a previous pass).
///
/// Called with the Mutex guard held (from `record_marker` and `open_with`).
fn evict_locked(
    map: &mut HashMap<String, i64>,
    dir: &Path,
    now_millis: i64,
    retention_millis: i64,
    min_retention_millis: i64,
    max_entries: usize,
) {
    // Age-based eviction: entries older than the retention window are stale.
    let cutoff = now_millis.saturating_sub(retention_millis);
    let expired: Vec<String> = map
        .iter()
        .filter_map(|(id, &ts)| if ts < cutoff { Some(id.clone()) } else { None })
        .collect();
    for id in expired {
        let _ = fs::remove_file(marker_path(dir, &id));
        map.remove(&id);
    }

    // Capacity-based eviction: oldest-first until within the cap, but only among
    // entries at or beyond the age floor. Entries younger than the floor are
    // guaranteed-live and must not be evicted, even if that leaves the store over the
    // cap (issue #340).
    if map.len() <= max_entries {
        return;
    }
    let floor = now_millis.saturating_sub(min_retention_millis);
    let mut evictable: Vec<(String, i64)> = map
        .iter()
        .filter(|(_, &ts)| ts <= floor) // only markers older than the floor
        .map(|(id, &ts)| (id.clone(), ts))
        .collect();
    evictable.sort_by_key(|(_, ts)| *ts); // ascending = oldest first

    let excess = map.len() - max_entries;
    for (id, _) in evictable.into_iter().take(excess) {
        let _ = fs::remove_file(marker_path(dir, &id));
        map.remove(&id);
    }
}

/// Returns the marker file path for `task_id`.
fn marker_path(dir: &Path, task_id: &str) -> PathBuf {
    dir.join(hex_encode(task_id.as_bytes()))
}

/// Encodes `bytes` as a lowercase hex string.
fn hex_encode(bytes: &[u8]) -> String {
    const CHARS: &[u8] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(CHARS[(b >> 4) as usize] as char);
        out.push(CHARS[(b & 0x0f) as usize] as char);
    }
    out
}

/// Decodes a lowercase-hex string to bytes.
///
/// Returns `None` on any invalid character, including uppercase hex, odd length, or
/// non-hex characters. The strict lowercase-only requirement lets `open_with` use this
/// as a filter to skip any non-marker entry in the seen-tasks directory — our encoder
/// (`hex_encode`) only produces lowercase, so anything else is not our marker.
fn hex_decode(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    s.as_bytes()
        .chunks(2)
        .map(|pair| {
            let hi = hex_nibble(pair[0])?;
            let lo = hex_nibble(pair[1])?;
            Some((hi << 4) | lo)
        })
        .collect()
}

/// Decodes a single lowercase hex character to its nibble value.
///
/// Returns `None` for any character not in `[0-9a-f]`; uppercase is intentionally
/// rejected (see `hex_decode` above).
fn hex_nibble(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gen::{Outcome, TaskResult};
    // Shared ceiling assertion (ADR-0036) — one helper for the whole daemon, so a
    // third mode-assertion shape is never invented.
    use crate::identity::mode_assert;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::time::{SystemTime, UNIX_EPOCH};

    // -----------------------------------------------------------------------
    // Test helpers
    // -----------------------------------------------------------------------

    /// A temp directory that removes itself on drop, for test isolation.
    struct TempDir(PathBuf);
    impl TempDir {
        fn new(label: &str) -> Self {
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let path = std::env::temp_dir().join(format!(
                "relay-test-dedup-{}-{}-{}",
                label,
                std::process::id(),
                nanos
            ));
            TempDir(path)
        }
        fn path(&self) -> &Path {
            &self.0
        }
    }
    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    /// A distinctive exec result (non-empty stdout) so tests can distinguish it from
    /// the benign already-processed result (which has empty stdout).
    fn make_task_result(task_id: &str) -> TaskResult {
        TaskResult {
            task_id: task_id.to_string(),
            outcome: Outcome::Success as i32,
            exit_code: 0,
            stdout: b"exec output".to_vec(),
            stderr: vec![],
            truncated: false,
            duration_millis: 1,
        }
    }

    // -----------------------------------------------------------------------
    // Tests
    // -----------------------------------------------------------------------

    /// A fresh task_id executes exactly once and returns the exec result.
    #[tokio::test]
    async fn fresh_task_executes_once() {
        let state_dir = TempDir::new("fresh-exec");
        let store = DedupStore::open(state_dir.path()).expect("open");

        let counter = Arc::new(AtomicUsize::new(0));
        let c = counter.clone();
        let result = store
            .run_once("t1", move || async move {
                c.fetch_add(1, Ordering::SeqCst);
                make_task_result("t1")
            })
            .await;

        assert_eq!(
            counter.load(Ordering::SeqCst),
            1,
            "exec must run exactly once"
        );
        assert_eq!(result.outcome, Outcome::Success as i32);
        assert_eq!(
            result.stdout, b"exec output",
            "must return exec result, not the benign already-processed result"
        );
    }

    /// Sending the same task_id twice runs exec only on the first call.
    /// [AC: re-sent seen id not executed again]
    #[tokio::test]
    async fn same_id_twice_runs_once() {
        let state_dir = TempDir::new("same-id-twice");
        let store = DedupStore::open(state_dir.path()).expect("open");

        let counter = Arc::new(AtomicUsize::new(0));

        let c = counter.clone();
        store
            .run_once("t1", move || async move {
                c.fetch_add(1, Ordering::SeqCst);
                make_task_result("t1")
            })
            .await;

        let c = counter.clone();
        let result = store
            .run_once("t1", move || async move {
                c.fetch_add(1, Ordering::SeqCst);
                make_task_result("t1")
            })
            .await;

        assert_eq!(
            counter.load(Ordering::SeqCst),
            1,
            "exec must run only once for the same task_id"
        );
        assert!(
            result
                .stderr
                .windows(b"already processed".len())
                .any(|w| w == b"already processed"),
            "second result stderr must contain 'already processed'"
        );
    }

    /// Dedup survives a simulated reconnect: dropping the in-memory store and reloading
    /// from disk must still recognize the previously-seen task_id.
    /// [AC: dedup across reconnect]
    #[tokio::test]
    async fn dedup_survives_reconnect_reload() {
        let state_dir = TempDir::new("reconnect");

        let counter = Arc::new(AtomicUsize::new(0));

        {
            let store = DedupStore::open(state_dir.path()).expect("open first");
            let c = counter.clone();
            store
                .run_once("t1", move || async move {
                    c.fetch_add(1, Ordering::SeqCst);
                    make_task_result("t1")
                })
                .await;
        } // store dropped here: in-memory map gone (simulates reconnect)

        // Re-open from the same dir (loads persisted markers from disk).
        let store = DedupStore::open(state_dir.path()).expect("open second");
        let c = counter.clone();
        let result = store
            .run_once("t1", move || async move {
                c.fetch_add(1, Ordering::SeqCst);
                make_task_result("t1")
            })
            .await;

        assert_eq!(
            counter.load(Ordering::SeqCst),
            1,
            "exec must not run again after reconnect reload"
        );
        assert!(
            result
                .stderr
                .windows(b"already processed".len())
                .any(|w| w == b"already processed"),
            "result after reload must be the benign already-processed result"
        );
    }

    /// Dedup survives a daemon restart: a brand-new DedupStore opened from the same
    /// state dir loads the persisted markers and refuses to re-run the Task.
    /// [AC: dedup across restart via persisted ids]
    #[tokio::test]
    async fn dedup_survives_restart() {
        let state_dir = TempDir::new("restart");

        let counter = Arc::new(AtomicUsize::new(0));

        {
            let store = DedupStore::open(state_dir.path()).expect("open");
            let c = counter.clone();
            store
                .run_once("t1", move || async move {
                    c.fetch_add(1, Ordering::SeqCst);
                    make_task_result("t1")
                })
                .await;
        }

        // Construct a brand-new DedupStore from the same dir (simulates daemon restart).
        let store2 = DedupStore::open(state_dir.path()).expect("open after restart");
        let c = counter.clone();
        let result = store2
            .run_once("t1", move || async move {
                c.fetch_add(1, Ordering::SeqCst);
                make_task_result("t1")
            })
            .await;

        assert_eq!(
            counter.load(Ordering::SeqCst),
            1,
            "exec must not run again after daemon restart"
        );
        assert!(
            result
                .stderr
                .windows(b"already processed".len())
                .any(|w| w == b"already processed"),
            "result after restart must be the benign already-processed result"
        );
    }

    /// Two distinct task_ids each execute exactly once.
    /// [AC: two distinct each execute exactly once]
    #[tokio::test]
    async fn two_distinct_ids_both_run() {
        let state_dir = TempDir::new("two-ids");
        let store = DedupStore::open(state_dir.path()).expect("open");

        let counter = Arc::new(AtomicUsize::new(0));

        let ca = counter.clone();
        let ra = store
            .run_once("a", move || async move {
                ca.fetch_add(1, Ordering::SeqCst);
                make_task_result("a")
            })
            .await;

        let cb = counter.clone();
        let rb = store
            .run_once("b", move || async move {
                cb.fetch_add(1, Ordering::SeqCst);
                make_task_result("b")
            })
            .await;

        assert_eq!(
            counter.load(Ordering::SeqCst),
            2,
            "both distinct task_ids must execute exactly once each"
        );
        assert_eq!(ra.stdout, b"exec output", "'a' must return the exec result");
        assert_eq!(rb.stdout, b"exec output", "'b' must return the exec result");
    }

    /// The synthesized already-processed result has the documented shape.
    ///
    /// Documents the id-only persistence decision: the prior outcome is never retained,
    /// so duplicates always get SUCCESS even if the original run failed.
    #[tokio::test]
    async fn duplicate_returns_benign_result() {
        let state_dir = TempDir::new("benign");
        let store = DedupStore::open(state_dir.path()).expect("open");

        // First call: registers t1.
        store
            .run_once("t1", || async { make_task_result("t1") })
            .await;

        // Second call: must return the synthesized benign result.
        let result = store
            .run_once("t1", || async { make_task_result("t1") })
            .await;

        assert_eq!(
            result.outcome,
            Outcome::Success as i32,
            "benign result must be OUTCOME_SUCCESS (dedup is not a failure)"
        );
        assert_eq!(result.exit_code, 0, "benign result exit_code must be 0");
        assert!(
            result.stdout.is_empty(),
            "benign result stdout must be empty (id-only persistence, no output retained)"
        );
        assert!(
            result
                .stderr
                .windows(b"already processed".len())
                .any(|w| w == b"already processed"),
            "benign result stderr must mention 'already processed'"
        );
        assert!(
            !result.truncated,
            "benign result must not be marked truncated"
        );
        assert_eq!(
            result.duration_millis, 0,
            "benign result duration must be 0 (no exec ran)"
        );
    }

    /// Marker files and the seen-tasks directory carry restrictive Unix permissions.
    ///
    /// The declared modes are **ceilings**, not exact values (ADR-0036): the process
    /// umask may tighten what `DirBuilder::mode()` and `OpenOptions::mode()` produce, and
    /// nothing here may widen them back. So this asserts the two properties that are
    /// actually load-bearing — no bit beyond the declared mode (a regression that widens
    /// the store, such as a re-added `set_permissions` or a looser constant, fails under
    /// every umask), and the group/world bits clear outright — via the shared
    /// `mode_assert::assert_within` helper rather than a third assertion shape.
    ///
    /// The ceilings below are **literals, not `DIR_MODE`/`FILE_MODE`**. Deriving them
    /// from the production constants would make the ceiling rise in lockstep with any
    /// edit to those constants, so the check could never fail on a widened one (#509).
    #[test]
    fn marker_permissions_are_restrictive() {
        let state_dir = TempDir::new("perms");
        let store = DedupStore::open_with(
            state_dir.path(),
            RETENTION.as_millis() as i64,
            MIN_RETENTION.as_millis() as i64,
            MAX_ENTRIES,
        )
        .expect("open_with");

        {
            let mut map = store.inner.lock().unwrap();
            record_marker(
                &mut map,
                &store.dir,
                "perm-test-task",
                RETENTION.as_millis() as i64,
                MIN_RETENTION.as_millis() as i64,
                MAX_ENTRIES,
            )
            .expect("record_marker");
        }

        mode_assert::assert_within(&store.dir, 0o700, 0o077, "seen-tasks dir");

        let marker = marker_path(&store.dir, "perm-test-task");
        mode_assert::assert_within(&marker, 0o600, 0o177, "marker file");
    }

    /// Probes whether this process's privileges bypass Unix permission checks.
    ///
    /// Creates a directory the caller could not write into under ordinary DAC (0600 —
    /// no search bit) and tries to create a file in it. Success means the caller holds
    /// `CAP_DAC_OVERRIDE` (unconfined root, which is what a dev container and some CI
    /// images give you); failure means DAC applies. This probes the *capability*, not
    /// the uid, because the capability is what actually decides the outcome below.
    fn dac_is_bypassed() -> bool {
        let probe = TempDir::new("dac-probe");
        let dir = probe.path().join("no-search");
        // TempDir only names a path; DedupStore::open normally creates it.
        fs::create_dir_all(&dir).expect("probe dir");
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o600)).expect("probe chmod");
        let bypassed = fs::File::create(dir.join("x")).is_ok();
        let _ = fs::set_permissions(&dir, fs::Permissions::from_mode(0o700));
        bypassed
    }

    /// The umask boundary's accepted consequence, demonstrated (ADR-0036, ADR-0004).
    ///
    /// A umask of `0o100` strips user-execute from the `0o700` directory this store
    /// requests, and a directory without user-execute cannot have files created in it.
    /// The store no longer forces the mode back, so that state is now reachable on a
    /// Node — and the claim that it is *safe* has to be demonstrated, not asserted.
    ///
    /// The directory is chmod'd here rather than by setting the umask: `umask(2)` is
    /// process-global, so a test that set it would corrupt every test running beside it
    /// (the strict-umask lane carries an ambient umask instead — see the Makefile). The
    /// resulting on-disk state is identical to what `umask 0100` leaves.
    ///
    /// Both privilege levels are asserted, because both are real and neither is a skip:
    ///
    /// - **DAC applies** (any unprivileged process; a root daemon whenever the umask
    ///   removes a bit its remaining capabilities do not restore — the shipped unit
    ///   bounds the daemon to `CAP_DAC_READ_SEARCH`, so it has no `CAP_DAC_OVERRIDE`):
    ///   the marker cannot be written, `run_once` **fails closed**, and `exec` never
    ///   runs. At-most-once (invariant #4) holds, and the failure is loud and
    ///   attributable to the operator's own setting.
    /// - **DAC is bypassed** (`CAP_DAC_OVERRIDE`): the tightened directory is still
    ///   usable, so the Task runs — exactly once, with its marker durably recorded.
    ///   At-most-once holds here too.
    ///
    /// There is no third outcome, and in particular no outcome where a Task executes
    /// without a marker behind it. That is the whole safety argument for removing the
    /// forced `set_permissions`.
    #[tokio::test]
    async fn umask_tightened_dedup_directory_never_executes_unrecorded() {
        let state_dir = TempDir::new("no-exec-bit");
        let store = DedupStore::open_with(
            state_dir.path(),
            RETENTION.as_millis() as i64,
            MIN_RETENTION.as_millis() as i64,
            MAX_ENTRIES,
        )
        .expect("open_with");

        // Exactly what `umask 0100` would have left: 0700 & !0100 == 0600.
        fs::set_permissions(&store.dir, fs::Permissions::from_mode(0o600))
            .expect("drop the directory's user-execute bit");

        let task_id = "task-under-pathological-umask";
        let ran = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&ran);
        let result = store
            .run_once(task_id, move || async move {
                flag.store(true, Ordering::SeqCst);
                make_task_result(task_id)
            })
            .await;

        // Restore the bit first: every assertion below may panic, and TempDir's
        // recursive remove needs a traversable directory to clean up.
        let _ = fs::set_permissions(&store.dir, fs::Permissions::from_mode(0o700));

        if dac_is_bypassed() {
            assert!(
                ran.load(Ordering::SeqCst),
                "with CAP_DAC_OVERRIDE the tightened directory is still writable, so \
                 the Task must run"
            );
            assert_eq!(
                result.outcome,
                Outcome::Success as i32,
                "a Task that ran must report its own outcome"
            );
            assert!(
                marker_path(&store.dir, task_id).exists(),
                "a Task that ran must have left a durable marker behind it — executing \
                 without one is the at-least-once failure ADR-0004 forbids"
            );
            return;
        }

        assert!(
            !ran.load(Ordering::SeqCst),
            "exec must NOT run when the durable marker cannot be written — executing \
             here would be at-least-once (ADR-0004)"
        );
        assert_eq!(
            result.outcome,
            Outcome::Failure as i32,
            "an unrecordable Task must be refused as FAILURE, not silently succeed"
        );
        let stderr = String::from_utf8_lossy(&result.stderr);
        assert!(
            stderr.contains("failed to record task id before execute"),
            "the refusal must name the durable-record failure so it is attributable to \
             the umask; got {stderr:?}"
        );
        assert!(
            !marker_path(&store.dir, task_id).exists(),
            "no marker may exist for a refused Task"
        );
    }

    /// Capacity eviction removes the oldest marker when the cap is exceeded.
    ///
    /// Uses direct timestamp control (not wall-clock ordering) for determinism on
    /// coarse-resolution CI clocks where consecutive records might share a timestamp.
    #[tokio::test]
    async fn capacity_cap_evicts_oldest() {
        let state_dir = TempDir::new("cap-evict");
        // max_entries=2: adding a third entry must evict the oldest. A zero age
        // floor isolates the capacity mechanics here — the dedicated floor test
        // (`age_floor_protects_a_young_marker_from_capacity_eviction`) covers #340.
        let store = DedupStore::open_with(state_dir.path(), RETENTION.as_millis() as i64, 0, 2)
            .expect("open_with");

        // Reference time: well within the 24h retention window for both a and b.
        let now_ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as i64;
        let ts_a = now_ts - 3_000; // oldest (3 s ago)
        let ts_b = now_ts - 2_000; // middle  (2 s ago)

        // Insert "a" and "b" directly with controlled timestamps so the oldest-first
        // eviction order is deterministic regardless of CI clock resolution.
        {
            let mut map = store.inner.lock().unwrap();

            let path_a = marker_path(&store.dir, "a");
            fs::File::create(&path_a).expect("create marker a");
            fs::set_permissions(&path_a, fs::Permissions::from_mode(FILE_MODE))
                .expect("chmod marker a");
            map.insert("a".to_string(), ts_a);

            let path_b = marker_path(&store.dir, "b");
            fs::File::create(&path_b).expect("create marker b");
            fs::set_permissions(&path_b, fs::Permissions::from_mode(FILE_MODE))
                .expect("chmod marker b");
            map.insert("b".to_string(), ts_b);
        }

        // run_once("c") calls record_marker → evict_locked (map has a,b,c = 3 > cap 2).
        // evict_locked sorts ascending and removes the first (oldest): "a".
        let counter = Arc::new(AtomicUsize::new(0));
        let c = counter.clone();
        store
            .run_once("c", move || async move {
                c.fetch_add(1, Ordering::SeqCst);
                make_task_result("c")
            })
            .await;
        assert_eq!(counter.load(Ordering::SeqCst), 1, "'c' must execute");

        // "a" must be evicted from both the map and disk.
        assert!(
            !store.inner.lock().unwrap().contains_key("a"),
            "'a' must be evicted from the in-memory map"
        );
        assert!(
            !marker_path(&store.dir, "a").exists(),
            "'a' marker file must be deleted from disk"
        );

        // "b" must be retained.
        assert!(
            store.inner.lock().unwrap().contains_key("b"),
            "'b' must remain in the in-memory map"
        );

        // run_once("a") must re-execute because "a" was evicted.
        let counter2 = Arc::new(AtomicUsize::new(0));
        let c2 = counter2.clone();
        let result = store
            .run_once("a", move || async move {
                c2.fetch_add(1, Ordering::SeqCst);
                make_task_result("a")
            })
            .await;
        assert_eq!(
            counter2.load(Ordering::SeqCst),
            1,
            "evicted 'a' must re-execute"
        );
        assert_eq!(
            result.stdout, b"exec output",
            "re-executed 'a' must return the exec result, not the benign already-processed result"
        );
    }

    /// Age floor (issue #340): capacity eviction must NOT drop a marker younger than
    /// the floor, even when the store is over the cap — dropping a still-live marker
    /// would let a redelivered Task execute twice (ADR-0004). Here the cap is 1 and the
    /// floor is 1 h, and every entry is recent, so the over-cap store must keep them all
    /// and a re-send of any id must still be deduplicated.
    ///
    /// Non-vacuous: the pre-#340 code (oldest-first with no floor) would evict "old" to
    /// satisfy cap=1, and the re-send of "old" below would then re-execute — exactly the
    /// at-most-once violation this guards.
    #[tokio::test]
    async fn age_floor_protects_a_young_marker_from_capacity_eviction() {
        let state_dir = TempDir::new("age-floor");
        // cap=1, floor=1h. A flood of fresh ids all sit inside the floor.
        let store = DedupStore::open_with(
            state_dir.path(),
            RETENTION.as_millis() as i64,
            MIN_RETENTION.as_millis() as i64,
            1,
        )
        .expect("open_with");

        let now_ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as i64;

        // Seed "old": recent (5 min ago) but the OLDEST — the entry oldest-first
        // eviction would target first. It is still well within the 1 h floor.
        {
            let mut map = store.inner.lock().unwrap();
            let path = marker_path(&store.dir, "old");
            fs::File::create(&path).expect("create marker old");
            fs::set_permissions(&path, fs::Permissions::from_mode(FILE_MODE)).expect("chmod");
            map.insert("old".to_string(), now_ts - 5 * 60 * 1_000);
        }

        // Record two more fresh ids via the real path. Each record runs capacity
        // eviction with the store at 2 then 3 entries, all over the cap of 1 — but
        // every entry is inside the floor, so NONE may be evicted.
        for id in ["mid", "new"] {
            store.run_once(id, || async { make_task_result("x") }).await;
        }

        // All three markers survive despite being 3× over the cap.
        for id in ["old", "mid", "new"] {
            assert!(
                store.inner.lock().unwrap().contains_key(id),
                "'{id}' is within the age floor and must not be capacity-evicted"
            );
            assert!(
                marker_path(&store.dir, id).exists(),
                "'{id}' marker file must remain on disk"
            );
        }

        // The load-bearing consequence: the oldest marker still dedups a re-send,
        // so a redelivered Task does not execute twice.
        let counter = Arc::new(AtomicUsize::new(0));
        let c = counter.clone();
        let result = store
            .run_once("old", move || async move {
                c.fetch_add(1, Ordering::SeqCst);
                make_task_result("old")
            })
            .await;
        assert_eq!(
            counter.load(Ordering::SeqCst),
            0,
            "the protected 'old' marker must still deduplicate its retry (no re-execution)"
        );
        assert!(
            result
                .stderr
                .windows(b"already processed".len())
                .any(|w| w == b"already processed"),
            "re-sent 'old' must return the benign already-processed result"
        );
    }

    /// Age-based eviction removes expired entries and retains recent ones.
    ///
    /// Uses direct timestamp control for determinism (not relying on actual file mtimes
    /// or wall-clock advancing between inserts).
    #[test]
    fn evict_removes_expired_by_age() {
        let state_dir = TempDir::new("evict-age");
        let store = DedupStore::open_with(
            state_dir.path(),
            RETENTION.as_millis() as i64,
            MIN_RETENTION.as_millis() as i64,
            MAX_ENTRIES,
        )
        .expect("open_with");

        let now_ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as i64;

        // "expired": 1 second past the 24h retention window.
        let expired_ts = now_ts - RETENTION.as_millis() as i64 - 1_000;
        // "recent": 1 second ago — well within the retention window.
        let recent_ts = now_ts - 1_000;

        {
            let mut map = store.inner.lock().unwrap();

            let path_exp = marker_path(&store.dir, "expired-task");
            fs::File::create(&path_exp).expect("create expired marker");
            map.insert("expired-task".to_string(), expired_ts);

            let path_rec = marker_path(&store.dir, "recent-task");
            fs::File::create(&path_rec).expect("create recent marker");
            map.insert("recent-task".to_string(), recent_ts);

            evict_locked(
                &mut map,
                &store.dir,
                now_ts,
                RETENTION.as_millis() as i64,
                MIN_RETENTION.as_millis() as i64,
                MAX_ENTRIES,
            );

            assert!(
                !map.contains_key("expired-task"),
                "'expired-task' must be evicted from the in-memory map"
            );
            assert!(
                !marker_path(&store.dir, "expired-task").exists(),
                "'expired-task' marker must be deleted from disk"
            );

            assert!(
                map.contains_key("recent-task"),
                "'recent-task' must remain in the in-memory map"
            );
            assert!(
                marker_path(&store.dir, "recent-task").exists(),
                "'recent-task' marker must remain on disk"
            );
        }
    }

    /// Two CONCURRENT `run_once` calls for the same task_id, racing on separate OS
    /// threads, must still execute exactly once — the central at-most-once invariant
    /// (ADR-0004 #4). All tests above call `run_once` sequentially, which cannot
    /// exercise the TOCTOU window between the in-memory `contains_key` check and
    /// `record_marker` (dedup.rs:168-184).
    ///
    /// Uses `tokio::spawn` (NOT `tokio::join!` on bare futures) on a multi-thread
    /// runtime with 2 worker threads, so the two `run_once` calls genuinely race on
    /// separate OS threads over the shared `std::sync::Mutex` critical section.
    /// `tokio::join!` on bare async fn calls (with no internal `.await` in the exec
    /// closure) would poll each to completion sequentially within a single task —
    /// structurally incapable of catching the exact TOCTOU this test exists to guard,
    /// a fresh instance of the bug this issue exists to fix.
    ///
    /// Looped: a single race is not guaranteed to hit a reintroduced TOCTOU window on
    /// every run, so iterate to raise detection confidence.
    ///
    /// Non-vacuous: the check+record block runs under one synchronous `Mutex` with no
    /// `.await` inside; a TOCTOU refactor that drops the lock between the check and the
    /// record would let both spawned tasks observe "not seen" and both call `exec`,
    /// making `counter == 2` and failing the assertion below.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn concurrent_same_id_executes_once() {
        for i in 0..20 {
            let state_dir = TempDir::new(&format!("concurrent-{i}"));
            let store = Arc::new(DedupStore::open(state_dir.path()).expect("open"));
            let counter = Arc::new(AtomicUsize::new(0));

            let (s1, c1) = (Arc::clone(&store), Arc::clone(&counter));
            let h1 = tokio::spawn(async move {
                s1.run_once("dup", move || async move {
                    c1.fetch_add(1, Ordering::SeqCst);
                    make_task_result("dup")
                })
                .await
            });

            let (s2, c2) = (Arc::clone(&store), Arc::clone(&counter));
            let h2 = tokio::spawn(async move {
                s2.run_once("dup", move || async move {
                    c2.fetch_add(1, Ordering::SeqCst);
                    make_task_result("dup")
                })
                .await
            });

            let (ra, rb) = tokio::join!(h1, h2); // join! on JoinHandles: awaits both spawned tasks
            let (ra, rb) = (
                ra.expect("task 1 must not panic"),
                rb.expect("task 2 must not panic"),
            );

            assert_eq!(
                counter.load(Ordering::SeqCst),
                1,
                "iteration {i}: exec must run exactly once across two concurrent run_once \
                 calls for the same task_id"
            );

            let is_benign = |r: &TaskResult| {
                r.stdout.is_empty()
                    && r.stderr
                        .windows(b"already processed".len())
                        .any(|w| w == b"already processed")
            };
            let is_exec = |r: &TaskResult| r.stdout == b"exec output";
            let (a_exec, b_exec) = (is_exec(&ra), is_exec(&rb));
            let (a_benign, b_benign) = (is_benign(&ra), is_benign(&rb));

            assert!(
                a_exec != b_exec,
                "iteration {i}: exactly one of the two results must be the exec result; got a_exec={a_exec} b_exec={b_exec}"
            );
            assert!(
                a_benign != b_benign,
                "iteration {i}: exactly one of the two results must be the benign already-processed result; got a_benign={a_benign} b_benign={b_benign}"
            );
        }
    }

    /// Fail-closed on record error: when the marker cannot be durably recorded (here,
    /// the NAME_MAX guard at dedup.rs:330 rejects an over-long task_id), `run_once`
    /// must return FAILURE and NEVER call `exec` (dedup.rs:188-198). At-most-once means
    /// preferring no-execution over at-least-once when we cannot guarantee the marker
    /// will be found on retry.
    ///
    /// Non-vacuous: flipping fail-closed to fail-open (running exec / returning the exec
    /// result on a record error) would make `ran == true` and `outcome == Success`,
    /// failing every assertion below.
    #[tokio::test]
    async fn record_error_fails_closed() {
        let state_dir = TempDir::new("fail-closed");
        let store = DedupStore::open(state_dir.path()).expect("open");

        // 200-char task_id -> hex filename is 400 bytes, exceeding NAME_MAX (255) ->
        // record_marker returns Err before ever reaching exec.
        let task_id = "a".repeat(200);

        let ran = Arc::new(AtomicBool::new(false));
        let ran_c = Arc::clone(&ran);
        let result = store
            .run_once(&task_id, move || async move {
                ran_c.store(true, Ordering::SeqCst);
                make_task_result("x")
            })
            .await;

        assert!(
            !ran.load(Ordering::SeqCst),
            "exec must never run on a record error"
        );
        assert_eq!(result.outcome, Outcome::Failure as i32);
        assert_eq!(result.exit_code, -1);
        assert!(
            result
                .stderr
                .windows(b"failed to record task id before execute".len())
                .any(|w| w == b"failed to record task id before execute"),
            "stderr must contain the fail-closed message; got {:?}",
            String::from_utf8_lossy(&result.stderr)
        );
    }
}
