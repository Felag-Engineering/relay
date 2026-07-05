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

use crate::gen::{Outcome, TaskResult};

/// Grace period between SIGTERM and SIGKILL when killing a Task's group.
/// Fixed for v1 (privileged side, deterministic); a Policy-configurable value is future work.
const TERM_GRACE: Duration = Duration::from_secs(5);

/// A dispatch-agnostic request to execute one Task.
///
/// Adding `cancel: Option<oneshot::Receiver<()>>` makes this type non-Clone.
/// Confirm no call site constructs ExecRequest via `.clone()` or struct-update
/// (`{ ..base }`); each site must construct fresh.
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

    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => {
            let msg = e.to_string();
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
    use crate::gen::Outcome;
    use std::time::{Duration, Instant};

    fn big_cap() -> usize {
        64 * 1024 * 1024 // 64 MiB — effectively unlimited for most tests
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
        })
        .await;
        assert_eq!(result.outcome, Outcome::Failure as i32);
        assert_eq!(result.exit_code, -1);
        assert!(!result.stderr.is_empty(), "OS error must appear in stderr");
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
        })
        .await;

        assert_eq!(
            result.outcome,
            Outcome::Failure as i32,
            "real outcome (exit 7 = Failure) must be reported, not Cancelled"
        );
        assert_eq!(result.exit_code, 7, "real exit code must be preserved");
    }
}
