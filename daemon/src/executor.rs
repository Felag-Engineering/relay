//! Task executor. Runs a command as a direct argv exec (never `/bin/sh`), in its
//! own process group, with a per-Task timeout, optional cancel signal, and
//! size-capped stdout/stderr capture, producing a proto [`TaskResult`].
//! Dispatch-agnostic: no tunnel/mpsc types here.
//!
//! # Architecture references
//! - ADR-0001: argv-only, never `/bin/sh` for structured Operations.
//! - ADR-0004: per-Task timeout, size-capped output, structured results.
//! - ADR-0013: killable process groups for timeouts and cancellation.

use std::process::Stdio;
use std::time::{Duration, Instant};

use tokio::io::AsyncReadExt;
use tokio::process::Command;
use tokio::sync::oneshot;

use crate::config::ResourceLimits;
use crate::gen::{Outcome, TaskResult};

/// Grace period between SIGTERM and SIGKILL when killing a Task's group.
/// Fixed for v1 (privileged side, deterministic); a Policy-configurable value is future work.
const TERM_GRACE: Duration = Duration::from_secs(5);

/// A dispatch-agnostic request to execute one Task.
///
/// Adding `cancel: Option<oneshot::Receiver<()>>` makes this type non-Clone.
/// Confirm no call site constructs ExecRequest via `.clone()` or struct-update
/// (`{ ..base }`); each site must construct fresh. `limits` is `Copy`, which is
/// fine under this rule — it does not enable `.clone()`/struct-update of the
/// whole (still non-Clone) `ExecRequest`.
pub struct ExecRequest {
    /// The Task's unique identifier, echoed into the returned [`TaskResult`].
    pub task_id: String,
    /// `argv[0]` is the program; `argv[1..]` are its arguments. Must be non-empty.
    ///
    /// **Never** pass a shell command string here — this is exec'd directly (ADR-0001).
    pub argv: Vec<String>,
    /// Per-Task wall-clock budget. On expiry the entire process group is killed.
    pub timeout: Duration,
    /// Per-stream byte cap for stdout and stderr independently. Bytes past the cap
    /// are drained (to avoid blocking the child on a full pipe) but discarded;
    /// `truncated` is set in the returned [`TaskResult`].
    pub max_output_bytes: usize,
    /// Optional cancel signal. `Some(rx)` enables cancellation: an explicit
    /// `send(())` on the paired sender kills the process group and sets
    /// `OUTCOME_CANCELLED`. A dropped sender (deregister) resolves to `Err`,
    /// which `recv_cancel` maps to `pending()` — never a spurious cancel.
    /// `None` makes the Task uncancellable (used in tests and data-only handlers).
    pub cancel: Option<oneshot::Receiver<()>>,
    /// Resource limits (`setrlimit`) applied to the spawned child in `pre_exec`
    /// (post-fork, pre-exec). Copy; does not affect the non-Clone status.
    /// Deny-closed: a setrlimit failure aborts the spawn -> `OUTCOME_FAILURE`.
    pub limits: ResourceLimits,
}

/// Executes `req` and returns a fully-populated [`TaskResult`].
///
/// Never returns an error: spawn failures and empty-argv guards are mapped to
/// `OUTCOME_FAILURE` with the OS error in `stderr`. No `OUTCOME_ERROR` exists in
/// proto; FAILURE + exit_code -1 is the honest available mapping.
pub async fn execute(req: ExecRequest) -> TaskResult {
    let started = Instant::now();

    // Guard: empty argv must never reach Command::new. Return immediately without
    // touching a shell (ADR-0001 invariant #1).
    if req.argv.is_empty() {
        return failure_result(&req.task_id, b"empty argv", started);
    }

    // Build the command — argv ONLY, never /bin/sh (ADR-0001).
    let mut cmd = Command::new(&req.argv[0]);
    cmd.args(&req.argv[1..]);
    cmd.stdin(Stdio::null());
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());
    // process_group(0): child becomes its own process-group leader (pgid == child pid).
    // This lets us kill the whole process tree with kill(-pgid, SIG) — required for
    // timeouts and cancellation (ADR-0013).
    cmd.process_group(0);
    // kill_on_drop is a panic-time safety net for the direct child only.
    // The authoritative no-orphan path is the explicit kill(-pgid) in kill_group_graceful.
    cmd.kill_on_drop(true);

    // Copy into the closure (async-signal-safe capture).
    let limits = req.limits;
    // SAFETY: runs in the forked child before exec; performs only async-signal-safe
    // work (stack-only libc::setrlimit syscalls, Copy capture, no heap/locks). A
    // setrlimit failure returns Err, failing the spawn closed (never an unbounded child).
    unsafe {
        cmd.pre_exec(move || apply_rlimits(&limits));
    }

    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => {
            let msg = format!(
                "spawn {}: {}",
                req.argv[0],
                crate::config::clean_io_error(&e)
            );
            return failure_result(&req.task_id, msg.as_bytes(), started);
        }
    };

    // pgid == child pid because we used process_group(0).
    let pgid = child.id().expect("spawned child has a pid") as i32;

    // Spawn two concurrent drain tasks to read stdout/stderr to EOF. Running them
    // concurrently with child.wait() prevents the classic two-pipe deadlock where a
    // full pipe blocks the child forever while we wait on it (ADR-0004).
    let out_pipe = child.stdout.take().expect("stdout piped");
    let err_pipe = child.stderr.take().expect("stderr piped");
    let cap = req.max_output_bytes;
    let out_task = tokio::spawn(drain_capped(out_pipe, cap));
    let err_task = tokio::spawn(drain_capped(err_pipe, cap));

    let cancel = req.cancel;
    let mut timed_out = false;
    let mut cancelled = false;
    let mut exit_code: i32 = -1;
    // kill_needed: set inside the select! to avoid holding &mut child borrow
    // across select arms; kill_group_graceful is called once AFTER the select.
    let mut kill_needed = false;

    // biased; makes the wait arm win over the cancel arm when both are ready
    // simultaneously — an already-exited child reports its real outcome, never a
    // retroactive OUTCOME_CANCELLED (ADR-0013 honest-race semantics).
    tokio::select! {
        biased;
        res = tokio::time::timeout(req.timeout, child.wait()) => {
            match res {
                Ok(Ok(status)) => {
                    exit_code = status.code().unwrap_or(-1);
                }
                Ok(Err(_io_err)) => {
                    // wait() failed: leave exit_code = -1, treat as failure below.
                }
                Err(_elapsed) => {
                    timed_out = true;
                    kill_needed = true;
                }
            }
        }
        _ = recv_cancel(cancel) => {
            // KNOWN LIMITATION: a daemonized grandchild inheriting pipe fds could
            // block the drain tasks below (executor.rs ~L116-119 applies here too);
            // this is not solved by the cancel path.
            cancelled = true;
            kill_needed = true;
        }
    }

    if kill_needed {
        // Kill the whole process group: SIGTERM first, then SIGKILL after the
        // grace period. Both the direct child and all grandchildren receive the
        // signal because pgid == child pid and kill(-pgid) targets the group.
        kill_group_graceful(pgid, &mut child).await;
    }

    // KNOWN LIMITATION: if the child backgrounded a process that inherited the pipe
    // fds (e.g. daemonized without closing fd 1/2), these awaits can block until that
    // process exits. v1 structured Operations do not daemonize; the tunnel-loop wiring
    // issue should add a timeout/select around this point.
    let (stdout, out_trunc) = out_task.await.unwrap_or_default();
    let (stderr, err_trunc) = err_task.await.unwrap_or_default();

    // Intentionally discard the process's signal exit code when cancelled; use -1.
    // The process was externally killed (not a normal exit), so its signal-derived
    // exit code is meaningless — -1 is the honest "externally killed" mapping.
    let outcome = if cancelled {
        Outcome::Cancelled
    } else if timed_out {
        Outcome::Timeout
    } else if exit_code == 0 {
        Outcome::Success
    } else {
        Outcome::Failure
    };

    TaskResult {
        task_id: req.task_id,
        outcome: outcome as i32,
        exit_code: if timed_out || cancelled {
            -1
        } else {
            exit_code
        },
        stdout,
        stderr,
        truncated: out_trunc || err_trunc,
        duration_millis: started.elapsed().as_millis() as i64,
    }
}

/// Sends SIGTERM to the process group, waits for the grace period, then sends SIGKILL.
///
/// Reaps the direct child so no zombie remains. All grandchildren in the group
/// also receive the signal because pgid == child pid and `kill(-pgid, SIG)` targets
/// the whole group (ADR-0013, ADR-0001).
async fn kill_group_graceful(pgid: i32, child: &mut tokio::process::Child) {
    signal_group(pgid, libc::SIGTERM);
    match tokio::time::timeout(TERM_GRACE, child.wait()).await {
        Ok(_) => {} // exited within the grace period
        Err(_) => {
            signal_group(pgid, libc::SIGKILL);
            // Reap the direct child so we don't leave a zombie. The group
            // SIGKILL also takes all grandchildren.
            let _ = child.wait().await;
        }
    }
}

/// Resolves only on an explicit `send(())` from the paired sender.
///
/// - `Some(rx)` + `Ok(())` → resolves (cancel arm fires).
/// - `Some(rx)` + `Err(_)` → the sender was dropped (deregister); maps to
///   `std::future::pending()` so the select never fires the cancel arm.
/// - `None` → no cancel handle; maps to `std::future::pending()`.
///
/// This design guarantees that dropping a sender (e.g. calling `deregister`)
/// cannot accidentally cancel a Task — only an explicit `send(())` can.
async fn recv_cancel(rx: Option<oneshot::Receiver<()>>) {
    match rx {
        Some(rx) => match rx.await {
            Ok(()) => {}                                  // explicit cancel signal — resolve
            Err(_) => std::future::pending::<()>().await, // sender dropped — never resolve
        },
        None => std::future::pending::<()>().await, // no cancel handle — uncancellable
    }
}

/// Drains `reader` to EOF, keeping at most `cap` bytes.
///
/// Bytes past the cap are read (to avoid blocking the child on a full pipe)
/// but discarded. Returns `(bytes, truncated)`.
async fn drain_capped<R>(mut reader: R, cap: usize) -> (Vec<u8>, bool)
where
    R: tokio::io::AsyncRead + Unpin,
{
    let mut buf = Vec::new();
    let mut truncated = false;
    let mut chunk = [0u8; 8192];
    loop {
        match reader.read(&mut chunk).await {
            Ok(0) => break, // EOF
            Ok(n) => {
                if buf.len() < cap {
                    let take = n.min(cap - buf.len());
                    buf.extend_from_slice(&chunk[..take]);
                    if take < n {
                        truncated = true;
                    }
                } else {
                    truncated = true; // still draining, just discarding
                }
            }
            Err(_) => break, // pipe error: return what we have
        }
    }
    (buf, truncated)
}

/// Sends `signal` to the entire process group led by `pgid`.
///
/// The child was launched with `process_group(0)`, so `pgid == child pid` and
/// `kill(-pgid, sig)` reaches the whole process tree (ADR-0013). ESRCH (group
/// already exited) is a valid non-error return — the child may have raced to exit
/// between the timeout firing and this call.
fn signal_group(pgid: i32, signal: libc::c_int) {
    // Safety: libc::kill is a raw POSIX syscall that takes two integers; no memory
    // is accessed. ESRCH (group already exited) is a valid non-UB return value;
    // we intentionally ignore the return value.
    unsafe { libc::kill(-pgid, signal) };
}

/// Applies `limits` to the calling process via `setrlimit`. Async-signal-safe: only
/// stack `libc::rlimit` values and `setrlimit` syscalls; no heap, no locks. Returns
/// `Err` on the first failure so the caller (the `pre_exec` closure in [`execute`])
/// fails the spawn closed. `rlim_t` is `u64` on Linux (glibc and musl), so limit
/// values need no cast; each `libc::RLIMIT_*` constant is passed directly to
/// `setrlimit` so no target-specific resource-type cast is needed (portable across
/// the glibc dev/CI build and the musl release build).
fn apply_rlimits(limits: &ResourceLimits) -> std::io::Result<()> {
    if let Some(v) = limits.nproc {
        let rl = libc::rlimit {
            rlim_cur: v,
            rlim_max: v,
        };
        // SAFETY: setrlimit reads one stack rlimit; async-signal-safe syscall.
        if unsafe { libc::setrlimit(libc::RLIMIT_NPROC, &rl) } != 0 {
            return Err(std::io::Error::last_os_error());
        }
    }
    if let Some(v) = limits.data_bytes {
        let rl = libc::rlimit {
            rlim_cur: v,
            rlim_max: v,
        };
        // SAFETY: setrlimit reads one stack rlimit; async-signal-safe syscall.
        if unsafe { libc::setrlimit(libc::RLIMIT_DATA, &rl) } != 0 {
            return Err(std::io::Error::last_os_error());
        }
    }
    if let Some(v) = limits.nofile {
        let rl = libc::rlimit {
            rlim_cur: v,
            rlim_max: v,
        };
        // SAFETY: setrlimit reads one stack rlimit; async-signal-safe syscall.
        if unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &rl) } != 0 {
            return Err(std::io::Error::last_os_error());
        }
    }
    if let Some(v) = limits.cpu_seconds {
        let rl = libc::rlimit {
            rlim_cur: v,
            rlim_max: v,
        };
        // SAFETY: setrlimit reads one stack rlimit; async-signal-safe syscall.
        if unsafe { libc::setrlimit(libc::RLIMIT_CPU, &rl) } != 0 {
            return Err(std::io::Error::last_os_error());
        }
    }
    if let Some(v) = limits.fsize_bytes {
        let rl = libc::rlimit {
            rlim_cur: v,
            rlim_max: v,
        };
        // SAFETY: setrlimit reads one stack rlimit; async-signal-safe syscall.
        if unsafe { libc::setrlimit(libc::RLIMIT_FSIZE, &rl) } != 0 {
            return Err(std::io::Error::last_os_error());
        }
    }
    Ok(())
}

/// Synthesizes a failure [`TaskResult`] for spawn errors and empty-argv guards.
///
/// `OUTCOME_ERROR` does not exist in proto; `OUTCOME_FAILURE` + `exit_code -1` +
/// the OS error in `stderr` is the honest available mapping (documented in the plan).
fn failure_result(task_id: &str, stderr: &[u8], started: Instant) -> TaskResult {
    TaskResult {
        task_id: task_id.to_string(),
        outcome: Outcome::Failure as i32,
        exit_code: -1,
        stdout: vec![],
        stderr: stderr.to_vec(),
        truncated: false,
        duration_millis: started.elapsed().as_millis() as i64,
    }
}

#[cfg(test)]
mod tests {
    use super::{execute, ExecRequest};
    use crate::config::ResourceLimits;
    use crate::gen::Outcome;
    use std::time::{Duration, Instant};

    fn big_cap() -> usize {
        64 * 1024 * 1024 // 64 MiB — effectively unlimited for most tests
    }

    /// No resource bounds applied — existing tests stay behaviorally identical
    /// to pre-#220 behavior (no limits) regardless of the CI host's own limits.
    fn no_limits() -> ResourceLimits {
        ResourceLimits {
            nproc: None,
            data_bytes: None,
            nofile: None,
            cpu_seconds: None,
            fsize_bytes: None,
        }
    }

    // 1. /bin/true → OUTCOME_SUCCESS, exit 0
    #[tokio::test]
    async fn true_yields_success() {
        let result = execute(ExecRequest {
            task_id: "t1".to_string(),
            argv: vec!["/bin/true".to_string()],
            timeout: Duration::from_secs(5),
            max_output_bytes: big_cap(),
            cancel: None,
            limits: no_limits(),
        })
        .await;
        assert_eq!(result.outcome, Outcome::Success as i32);
        assert_eq!(result.exit_code, 0);
        assert!(!result.truncated);
    }

    // 2. /bin/false → OUTCOME_FAILURE, exit non-zero (1)
    #[tokio::test]
    async fn false_yields_failure() {
        let result = execute(ExecRequest {
            task_id: "t2".to_string(),
            argv: vec!["/bin/false".to_string()],
            timeout: Duration::from_secs(5),
            max_output_bytes: big_cap(),
            cancel: None,
            limits: no_limits(),
        })
        .await;
        assert_eq!(result.outcome, Outcome::Failure as i32);
        assert_ne!(result.exit_code, 0);
    }

    // 3. stdout is captured correctly
    #[tokio::test]
    async fn captures_stdout() {
        let result = execute(ExecRequest {
            task_id: "t3".to_string(),
            argv: vec!["/bin/echo".to_string(), "hello".to_string()],
            timeout: Duration::from_secs(5),
            max_output_bytes: big_cap(),
            cancel: None,
            limits: no_limits(),
        })
        .await;
        assert_eq!(result.stdout, b"hello\n");
        assert_eq!(result.outcome, Outcome::Success as i32);
    }

    // 4. stderr is captured and non-zero exit is reported correctly.
    // Note: this test passes /bin/sh as the caller-supplied argv — the executor
    // still exec's argv[0] directly; it does NOT construct the shell invocation.
    #[tokio::test]
    async fn captures_stderr_and_exit_code() {
        let result = execute(ExecRequest {
            task_id: "t4".to_string(),
            argv: vec![
                "/bin/sh".to_string(),
                "-c".to_string(),
                "echo boom 1>&2; exit 2".to_string(),
            ],
            timeout: Duration::from_secs(5),
            max_output_bytes: big_cap(),
            cancel: None,
            limits: no_limits(),
        })
        .await;
        assert_eq!(result.stderr, b"boom\n");
        assert_eq!(result.exit_code, 2);
        assert_eq!(result.outcome, Outcome::Failure as i32);
    }

    // 5. ACCEPTANCE-CRITICAL: timeout kills the entire process group (no orphans).
    #[tokio::test]
    async fn timeout_kills_group_no_orphans() {
        let result = execute(ExecRequest {
            task_id: "t5".to_string(),
            // The shell backgrounds a sleep 30 (grandchild) and prints its PID to
            // stdout, then sleeps 30 itself. Both are in the same process group
            // (pgid == shell pid). The executor kills the whole group on timeout,
            // taking both the shell and the background sleep.
            argv: vec![
                "/bin/sh".to_string(),
                "-c".to_string(),
                "sleep 30 & echo $!; sleep 30".to_string(),
            ],
            timeout: Duration::from_secs(1),
            max_output_bytes: 4096,
            cancel: None,
            limits: no_limits(),
        })
        .await;
        assert_eq!(result.outcome, Outcome::Timeout as i32);
        assert_eq!(result.exit_code, -1);

        // Parse the PID of the backgrounded grandchild from stdout.
        let stdout_str = String::from_utf8_lossy(&result.stdout);
        let grandchild_pid: libc::pid_t = stdout_str
            .trim()
            .parse()
            .expect("stdout must contain the background sleep PID");

        // Poll kill(pid, 0) until ESRCH: waits for PID 1 to reap the reparented
        // zombie. When the grandchild is killed by the group SIGKILL it becomes a
        // zombie (reparented to init/PID 1); kill(pid, 0) returns 0 for a
        // not-yet-reaped zombie, and ESRCH once init has collected it. A future
        // reader should not remove this loop thinking it defensive noise — without
        // it we would only prove the grandchild received a signal, not that the
        // kernel has fully released it as an orphan.
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            let ret = unsafe { libc::kill(grandchild_pid, 0) };
            if ret == -1 {
                let err = std::io::Error::last_os_error();
                assert_eq!(
                    err.raw_os_error(),
                    Some(libc::ESRCH),
                    "grandchild (pid={grandchild_pid}) must be gone (ESRCH), not another error"
                );
                break; // grandchild fully reaped — no orphan
            }
            assert!(
                Instant::now() < deadline,
                "grandchild (pid={grandchild_pid}) still alive after 2 s — orphan not reaped"
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }

    // 6. ACCEPTANCE-CRITICAL: output past the cap is truncated and drained (no deadlock).
    #[tokio::test]
    async fn large_output_is_truncated() {
        let result = execute(ExecRequest {
            task_id: "t6".to_string(),
            // 1 MB of null bytes from /dev/zero. The write far exceeds the ~64 KB
            // kernel pipe buffer, so a stop-reading implementation would deadlock
            // here — this test also proves keep-draining-past-cap works.
            argv: vec![
                "/bin/sh".to_string(),
                "-c".to_string(),
                "head -c 1000000 /dev/zero".to_string(),
            ],
            timeout: Duration::from_secs(5),
            max_output_bytes: 1024,
            cancel: None,
            limits: no_limits(),
        })
        .await;
        assert_eq!(result.stdout.len(), 1024);
        assert!(result.truncated);
        assert_eq!(result.outcome, Outcome::Success as i32);
    }

    // 6b. Cap boundary, exact cap: output of exactly `cap` bytes is NOT truncated.
    #[tokio::test]
    async fn output_exactly_at_cap_is_not_truncated() {
        let result = execute(ExecRequest {
            task_id: "t6b".to_string(),
            argv: vec![
                "/bin/sh".to_string(),
                "-c".to_string(),
                "head -c 1024 /dev/zero".to_string(),
            ],
            timeout: Duration::from_secs(5),
            max_output_bytes: 1024,
            cancel: None,
            limits: no_limits(),
        })
        .await;
        assert_eq!(result.stdout.len(), 1024);
        assert!(!result.truncated);
        assert_eq!(result.outcome, Outcome::Success as i32);
    }

    // 6c. Cap boundary, cap+1: output one byte past the cap IS truncated and
    // captured length stays exactly the cap (no off-by-one, memory stays bounded).
    #[tokio::test]
    async fn output_one_byte_past_cap_is_truncated() {
        let result = execute(ExecRequest {
            task_id: "t6c".to_string(),
            argv: vec![
                "/bin/sh".to_string(),
                "-c".to_string(),
                "head -c 1025 /dev/zero".to_string(),
            ],
            timeout: Duration::from_secs(5),
            max_output_bytes: 1024,
            cancel: None,
            limits: no_limits(),
        })
        .await;
        assert_eq!(result.stdout.len(), 1024);
        assert!(result.truncated);
        assert_eq!(result.outcome, Outcome::Success as i32);
    }

    // 7. Spawn failure maps to OUTCOME_FAILURE with OS error in stderr (no shell fallback).
    #[tokio::test]
    async fn spawn_failure_yields_failure() {
        let result = execute(ExecRequest {
            task_id: "t7".to_string(),
            argv: vec!["/nonexistent/definitely-not-a-binary".to_string()],
            timeout: Duration::from_secs(5),
            max_output_bytes: big_cap(),
            cancel: None,
            limits: no_limits(),
        })
        .await;
        assert_eq!(result.outcome, Outcome::Failure as i32);
        assert_eq!(result.exit_code, -1);
        assert!(!result.stderr.is_empty(), "OS error must appear in stderr");
    }

    // 7b. Spawn failure names argv[0] and strips the noisy "(os error N)" suffix.
    #[tokio::test]
    async fn spawn_failure_names_argv0() {
        let result = execute(ExecRequest {
            task_id: "t7b".to_string(),
            argv: vec!["/nonexistent/relay-missing-xyz".to_string()],
            timeout: Duration::from_secs(5),
            max_output_bytes: big_cap(),
            cancel: None,
            limits: no_limits(),
        })
        .await;
        assert_eq!(result.outcome, Outcome::Failure as i32);
        assert_eq!(result.exit_code, -1);
        let stderr = String::from_utf8_lossy(&result.stderr);
        assert!(
            stderr.starts_with("spawn /nonexistent/relay-missing-xyz:"),
            "got {stderr:?}"
        );
        assert!(
            stderr.contains("No such file or directory"),
            "got {stderr:?}"
        );
        assert!(!stderr.contains("(os error"), "got {stderr:?}");
    }

    // 8. Empty argv is guarded without panic.
    #[tokio::test]
    async fn empty_argv_yields_failure() {
        let result = execute(ExecRequest {
            task_id: "t8".to_string(),
            argv: vec![],
            timeout: Duration::from_secs(5),
            max_output_bytes: big_cap(),
            cancel: None,
            limits: no_limits(),
        })
        .await;
        assert_eq!(result.outcome, Outcome::Failure as i32);
        assert_eq!(result.exit_code, -1);
    }

    // 9. ACCEPTANCE-CRITICAL [AC1]: cancel kills the entire process group (no orphans).
    //    Mirrors timeout_kills_group_no_orphans with the cancel signal.
    #[tokio::test]
    async fn cancel_kills_group_no_orphans() {
        let (cancel_tx, cancel_rx) = tokio::sync::oneshot::channel::<()>();

        // Fire the cancel signal after 300 ms — well after the grandchild PID is
        // printed to stdout but well before the 30 s timeout.
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(300)).await;
            let _ = cancel_tx.send(());
        });

        let result = execute(ExecRequest {
            task_id: "t-cancel-group".to_string(),
            argv: vec![
                "/bin/sh".to_string(),
                "-c".to_string(),
                // Background a grandchild and print its PID, then sleep 30.
                // The cancel must kill both the shell and the grandchild.
                "sleep 30 & echo $!; sleep 30".to_string(),
            ],
            timeout: Duration::from_secs(30), // long — cancel fires before timeout
            max_output_bytes: 4096,
            cancel: Some(cancel_rx),
            limits: no_limits(),
        })
        .await;

        assert_eq!(result.outcome, Outcome::Cancelled as i32);
        assert_eq!(result.exit_code, -1);

        // Parse the grandchild PID from stdout and verify it's reaped (ESRCH),
        // proving the whole group (not just the direct child) was killed.
        let stdout_str = String::from_utf8_lossy(&result.stdout);
        let grandchild_pid: libc::pid_t = stdout_str
            .trim()
            .parse()
            .expect("stdout must contain the background sleep PID");

        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            let ret = unsafe { libc::kill(grandchild_pid, 0) };
            if ret == -1 {
                let err = std::io::Error::last_os_error();
                assert_eq!(
                    err.raw_os_error(),
                    Some(libc::ESRCH),
                    "grandchild (pid={grandchild_pid}) must be gone (ESRCH), not another error"
                );
                break; // grandchild fully reaped — no orphan
            }
            assert!(
                Instant::now() < deadline,
                "grandchild (pid={grandchild_pid}) still alive after 2 s — orphan not reaped"
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }

    // 10. ACCEPTANCE-CRITICAL [AC2]: a Task that finishes before cancel lands reports its
    //     real outcome. cancel fires at 2 s; `exit 7` completes in < 10 ms (20× margin).
    //     biased; guarantees the already-exited child wins over a simultaneously-ready
    //     cancel signal.
    #[tokio::test]
    async fn finished_before_cancel_reports_real_outcome() {
        let (cancel_tx, cancel_rx) = tokio::sync::oneshot::channel::<()>();

        // Fire cancel at 2 s — far after the child exits.
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(2)).await;
            let _ = cancel_tx.send(());
        });

        let result = execute(ExecRequest {
            task_id: "t-cancel-real".to_string(),
            argv: vec![
                "/bin/sh".to_string(),
                "-c".to_string(),
                "exit 7".to_string(),
            ],
            timeout: Duration::from_secs(30),
            max_output_bytes: 1024,
            cancel: Some(cancel_rx),
            limits: no_limits(),
        })
        .await;

        assert_eq!(
            result.outcome,
            Outcome::Failure as i32,
            "real outcome (exit 7 = Failure) must be reported, not Cancelled"
        );
        assert_eq!(result.exit_code, 7, "real exit code must be preserved");
    }

    // 11. ACCEPTANCE-CRITICAL: pins `biased;` at executor.rs:110 with BOTH select arms
    //     genuinely ready heading into the resolving poll — no process-timing race.
    //
    //     Test 10 above (`finished_before_cancel_reports_real_outcome`) fires cancel at
    //     2 s while the child exits in <10 ms, so the wait arm is Ready long before the
    //     cancel arm and `biased;` is never exercised as a tiebreak — it would still pass
    //     with `biased;` deleted.
    //
    //     A naive "pre-buffer the cancel + timeout: Duration::ZERO" construction (the
    //     issue's literal design, and an earlier draft of this test) is structurally
    //     incapable of proving anything: `tokio::time::timeout(dur, fut)` always computes
    //     its deadline as `Instant::now() + dur` at the moment `execute()`'s `select!`
    //     constructs it, so a freshly-registered timer entry can NEVER be already-elapsed
    //     on its own first poll (confirmed against tokio 1.52's timer wheel — a new entry
    //     is only fast-pathed as `Elapsed` when its deadline is *strictly before* the
    //     driver's already-processed tick, which a same-instant `Duration::ZERO` deadline
    //     never is). With the cancel pre-buffered (trivially Ready from the very first
    //     poll), `select!` always resolves at that very first poll — where the wait arm is
    //     unconditionally Pending — so that construction yields `Cancelled` deterministically
    //     REGARDLESS of `biased;` (verified empirically: it fails 100% of the time with
    //     `biased;` intact, i.e. it doesn't merely flake, it can never pass).
    //
    //     This test instead uses tokio's paused/virtual clock (`start_paused = true`,
    //     dev-only `test-util` feature) to force a genuine tie deterministically:
    //     1. Spawn `execute()` (timeout: 5 ms) as its own task and `yield_now` once so it
    //        runs up to the `select!`'s first poll, registering (but not yet satisfying)
    //        both the wait-arm timer and the cancel-arm receiver — both Pending.
    //     2. `tokio::time::advance(10 ms)` — processes the virtual clock forward past the
    //        wait arm's deadline, marking its timer entry Elapsed in the driver's shared
    //        state. This does NOT re-poll the suspended task; it only marks it ready.
    //     3. `tx.send(())` — buffers the cancel signal. The cancel arm is now also Ready.
    //     4. `.await` the `JoinHandle`, which is what actually re-polls the suspended
    //        `select!`. At THAT poll, both arms are genuinely, simultaneously Ready — the
    //        exact condition needed to exercise `biased;` as a tiebreak, with zero
    //        process-timing race. With `biased;`, the wait arm (listed first) wins ->
    //        `Outcome::Timeout`. Delete `biased;` and tokio's non-biased select picks a
    //        pseudo-random starting arm, so the winner flips between Timeout and Cancelled
    //        across iterations.
    //
    //     Looped 32x with a fresh channel per iteration; each iteration is fast because
    //     the `sleep 30` child is SIGTERM'd by `kill_group_graceful` well under TERM_GRACE
    //     (real OS signal delivery — unaffected by the paused *time* driver).
    #[tokio::test(start_paused = true)]
    async fn timeout_beats_buffered_cancel_biased() {
        for _ in 0..32 {
            let (tx, rx) = tokio::sync::oneshot::channel::<()>();

            let handle = tokio::spawn(execute(ExecRequest {
                task_id: "t-timeout-vs-cancel".to_string(),
                argv: vec![
                    "/bin/sh".to_string(),
                    "-c".to_string(),
                    "sleep 30".to_string(),
                ],
                timeout: Duration::from_millis(5),
                max_output_bytes: 4096,
                cancel: Some(rx),
                limits: no_limits(),
            }));

            // Let the spawned task run up to (and register) its select!'s first poll.
            tokio::task::yield_now().await;

            // Advance the paused clock past the 5 ms deadline: marks the wait arm's
            // timer Elapsed in shared driver state without re-polling the task.
            tokio::time::advance(Duration::from_millis(10)).await;

            // Buffer the cancel. Both arms are now simultaneously Ready heading into
            // the task's next (resolving) poll.
            tx.send(()).expect("buffered send to an open receiver");

            let result = handle.await.expect("execute task must not panic");

            assert_eq!(
                result.outcome,
                Outcome::Timeout as i32,
                "with biased;, an already-elapsed timeout must beat a simultaneously-\
                 buffered cancel deterministically; got outcome {}",
                result.outcome
            );
            assert_eq!(result.exit_code, -1);
        }
    }

    // -------------------------------------------------------------------------
    // Resource limits (issue #220)
    // -------------------------------------------------------------------------

    /// Finds the `/proc/self/limits` line whose label matches `label` exactly
    /// (labels start at column 0, so no ambiguity with e.g. "Max cpu time" vs
    /// "Max cpu time" prefixed variants) and returns its Soft Limit column.
    fn soft_limit_value(limits_text: &str, label: &str) -> String {
        let line = limits_text
            .lines()
            .find(|l| l.starts_with(label))
            .unwrap_or_else(|| panic!("no line starting with {label:?} in:\n{limits_text}"));
        line[label.len()..]
            .split_whitespace()
            .next()
            .unwrap_or_else(|| panic!("no soft-limit column in line: {line:?}"))
            .to_string()
    }

    // 12. Applied-limits / fork- & alloc-bomb containment, by configuration
    //     inspection. /bin/cat /proc/self/limits reports the exec'd child's own
    //     enforced rlimits; the kernel cannot let the child exceed "Max
    //     processes"/"Max data size" (etc), so a fork or allocation bomb is
    //     provably bounded — without ever triggering a real fork storm or a
    //     real memory-alloc detonation in CI.
    #[tokio::test]
    async fn child_runs_under_configured_rlimits() {
        let limits = ResourceLimits {
            nproc: Some(111),
            data_bytes: Some(200_000_000),
            nofile: Some(222),
            cpu_seconds: Some(333),
            fsize_bytes: Some(44_000_000),
        };

        let result = execute(ExecRequest {
            task_id: "t-rlimits".to_string(),
            argv: vec!["/bin/cat".to_string(), "/proc/self/limits".to_string()],
            timeout: Duration::from_secs(5),
            max_output_bytes: big_cap(),
            cancel: None,
            limits,
        })
        .await;

        assert_eq!(result.outcome, Outcome::Success as i32);
        let stdout = String::from_utf8_lossy(&result.stdout);

        assert_eq!(soft_limit_value(&stdout, "Max processes"), "111");
        assert_eq!(soft_limit_value(&stdout, "Max data size"), "200000000");
        assert_eq!(soft_limit_value(&stdout, "Max open files"), "222");
        assert_eq!(soft_limit_value(&stdout, "Max cpu time"), "333");
        assert_eq!(soft_limit_value(&stdout, "Max file size"), "44000000");
    }

    // 13. LIVE runaway-write containment: RLIMIT_FSIZE actually trips SIGXFSZ
    //     on a write that would exceed the configured cap. This is the one
    //     LIVE-detonation test in this suite (coreutils only; unique temp
    //     path; cleaned up after).
    #[tokio::test]
    async fn fsize_limit_caps_runaway_write() {
        use std::time::{SystemTime, UNIX_EPOCH};

        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "relay-executor-fsize-test-{}-{}",
            std::process::id(),
            nanos
        ));
        let path_str = path.to_string_lossy().into_owned();

        let fsize_cap: u64 = 1024 * 1024; // 1 MiB
        let limits = ResourceLimits {
            nproc: None,
            data_bytes: None,
            nofile: None,
            cpu_seconds: None,
            fsize_bytes: Some(fsize_cap),
        };

        // Attempt a 100 MiB write — far past the 1 MiB cap.
        let cmd = format!("head -c 104857600 /dev/zero > {path_str}");
        let result = execute(ExecRequest {
            task_id: "t-fsize".to_string(),
            argv: vec!["/bin/sh".to_string(), "-c".to_string(), cmd],
            timeout: Duration::from_secs(5),
            max_output_bytes: big_cap(),
            cancel: None,
            limits,
        })
        .await;

        assert_eq!(
            result.outcome,
            Outcome::Failure as i32,
            "a write past RLIMIT_FSIZE raises SIGXFSZ, yielding a non-success exit"
        );

        let written_len = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
        assert!(
            written_len > 0,
            "some bytes must have been written before the cap tripped"
        );
        assert!(
            written_len <= fsize_cap,
            "written file ({written_len} bytes) must not exceed the configured \
             FSIZE cap ({fsize_cap} bytes)"
        );

        let _ = std::fs::remove_file(&path);
    }

    // 14. Deny-closed: a setrlimit failure in pre_exec must fail the spawn
    //     closed — the child is refused, never spawned unbounded. `nofile:
    //     Some(1 << 40)` exceeds `fs.nr_open` (sysctl, default ~1048576 ==
    //     1<<20), the unconditional ceiling `do_prlimit` enforces for
    //     RLIMIT_NOFILE — NOT INT_MAX, and NOT CAP_SYS_RESOURCE-gated — so
    //     setrlimit fails EPERM for root and non-root alike.
    #[tokio::test]
    async fn misconfigured_limit_fails_closed() {
        let limits = ResourceLimits {
            nproc: None,
            data_bytes: None,
            nofile: Some(1 << 40),
            cpu_seconds: None,
            fsize_bytes: None,
        };

        let result = execute(ExecRequest {
            task_id: "t-deny-closed".to_string(),
            argv: vec!["/bin/echo".to_string(), "hi".to_string()],
            timeout: Duration::from_secs(5),
            max_output_bytes: big_cap(),
            cancel: None,
            limits,
        })
        .await;

        assert_eq!(
            result.outcome,
            Outcome::Failure as i32,
            "a setrlimit failure in pre_exec must fail the spawn closed"
        );
        assert_eq!(result.exit_code, -1);
        assert!(
            !result.stderr.is_empty(),
            "the spawn error must be surfaced in stderr"
        );
    }

    // 15. Regression guard: the shipped defaults don't break a legitimate
    //     command (and, transitively, that raw_exec/service_restart/pkg_install
    //     under ResourceLimits::DEFAULT are safe).
    #[tokio::test]
    async fn default_limits_allow_normal_command() {
        let result = execute(ExecRequest {
            task_id: "t-default-limits".to_string(),
            argv: vec!["/bin/echo".to_string(), "hi".to_string()],
            timeout: Duration::from_secs(5),
            max_output_bytes: big_cap(),
            cancel: None,
            limits: ResourceLimits::DEFAULT,
        })
        .await;

        assert_eq!(result.outcome, Outcome::Success as i32);
        assert_eq!(result.stdout, b"hi\n");
    }
}
