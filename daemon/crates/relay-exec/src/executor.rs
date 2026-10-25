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

use rustix::process::{
    kill_process_group, setrlimit, test_kill_process_group, Pid, Resource, Rlimit, Signal,
};
use tokio::io::AsyncReadExt;
use tokio::process::Command;
use tokio::sync::oneshot;

use crate::gen::{Outcome, TaskResult};
use crate::limits::ResourceLimits;
use crate::not_executed::not_executed_after;

/// Grace period between SIGTERM and SIGKILL when killing a Task's group.
/// Fixed for v1 (privileged side, deterministic); a Policy-configurable value is future work.
const TERM_GRACE: Duration = Duration::from_secs(5);

/// How long the output drain may still run after a timeout or cancel has killed
/// the process group, to collect what the group wrote before it died. A killed
/// group's pipes normally reach EOF at once; this only bounds the case where a
/// process outside the group (one that left it with `setsid(2)`) still holds
/// them. Fixed, like [`TERM_GRACE`], so the Task's overrun past its timeout is
/// bounded by constants (ADR-0004).
const POST_KILL_DRAIN_GRACE: Duration = Duration::from_secs(1);

/// Poll interval while waiting for a process group whose leader has already
/// been reaped to empty after SIGTERM (see [`sweep_reaped_group`]).
const GROUP_EMPTY_POLL: Duration = Duration::from_millis(25);

/// Fixed `PATH` handed to every spawned child. The daemon's own `PATH` is
/// deliberately *not* inherited (see `env_clear()` in [`execute`]): a bare-name
/// `argv[0]` must resolve against this trusted, standard search path — never one
/// an attacker could influence through the daemon's start-up environment. The
/// standard superuser + user bin directories cover the fleet's admin tooling
/// (`apt-get`, `systemctl`, `dnf`, …).
const SAFE_CHILD_PATH: &str = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";

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
    /// Per-Task wall-clock budget, covering both the run and the drain of the
    /// command's output (see [`execute`]). On expiry the entire process group is
    /// killed and the Task reports `OUTCOME_TIMEOUT`.
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
///
/// # One wall-clock bound for the whole Task (ADR-0004)
///
/// `req.timeout` bounds the whole Task, from a single deadline taken on entry:
/// the wait for the child **and** the drain of its output.
///
/// 1. **Run.** Wait for the direct child, racing the deadline and the cancel
///    signal. If either wins while the child is still running, the process
///    group is killed (`kill_group_graceful`) and the drain gets a short, fixed
///    [`POST_KILL_DRAIN_GRACE`] to collect what the group wrote before it died.
/// 2. **Drain.** A child that exited normally can still leave its pipes open: a
///    backgrounded process inherits stdout/stderr and holds them past the
///    child's exit. So the drain races the *same* deadline and the *same* cancel
///    signal.
///
/// **A timeout or cancel is honoured only while something of the Task is still
/// running** (ADR-0013: a Task that completed inside the race window reports
/// its real outcome, never a retroactive one). Concretely:
///
/// - If a member of the Task's process group is alive when the deadline or
///   cancel wins, what is left of the group is swept ([`sweep_reaped_group`]),
///   the drain is stopped with the output collected so far, `truncated` is set,
///   and the Task reports `OUTCOME_TIMEOUT` or `OUTCOME_CANCELLED` with exit
///   code `-1`.
/// - If the child has exited and its process group is empty, the command has
///   completed: it reports its real outcome and exit code, after the drain
///   collects what it wrote (within [`POST_KILL_DRAIN_GRACE`]; `truncated` is
///   set if a process outside the group still holds the pipes then).
///
/// The overrun past `req.timeout` is therefore bounded by fixed constants —
/// [`TERM_GRACE`] for the kill plus [`POST_KILL_DRAIN_GRACE`] for the drain —
/// unless the kernel holds the child in uninterruptible sleep, where even
/// SIGKILL waits for the kernel and so does reaping it. Nothing else the
/// command does can extend it. A process that left the group with `setsid(2)`
/// is outside the group's reach: it is not killed, and only loses the pipes.
pub async fn execute(req: ExecRequest) -> TaskResult {
    let started = Instant::now();
    // The one deadline both phases race. A `tokio::time::Instant`, so the paused
    // test clock drives it.
    let deadline = tokio::time::Instant::now() + req.timeout;

    // Guard: empty argv must never reach Command::new. Return immediately without
    // touching a shell (ADR-0001 invariant 1).
    if req.argv.is_empty() {
        return failure_result(&req.task_id, b"empty argv", started);
    }

    // Build the command — argv ONLY, never /bin/sh (ADR-0001).
    // The daemon's one sanctioned spawn site: clippy.toml disallows Command::new
    // everywhere else, so a second process-spawning path cannot appear unreviewed.
    #[allow(clippy::disallowed_methods)]
    let mut cmd = Command::new(&req.argv[0]);
    cmd.args(&req.argv[1..]);
    cmd.stdin(Stdio::null());
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());
    // Isolate the child's environment. The daemon holds no join string in its
    // environment, but an operator can still put a secret there. Without this,
    // every executed Operation and Raw Exec inherits that environment and could
    // read it straight out of `/proc/self/environ` (e.g. a Policy-allowed
    // `env`/`printenv`). `env_clear()` also pins `PATH`
    // so a bare-name `argv[0]` (e.g. `apt-get`, service_restart's `systemctl`)
    // resolves against a fixed, trusted search path rather than one the daemon
    // happened to be started with. Deny-closed by construction: the child sees
    // only the variables set explicitly below.
    cmd.env_clear();
    cmd.env("PATH", SAFE_CHILD_PATH);
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
    // work (stack-only prlimit64 syscalls issued by rustix::process::setrlimit, Copy
    // capture, no heap/locks). A setrlimit failure returns Err, failing the spawn
    // closed (never an unbounded child).
    unsafe {
        cmd.pre_exec(move || apply_rlimits(&limits));
    }

    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => {
            let msg = format!(
                "spawn {}: {}",
                req.argv[0],
                crate::limits::clean_io_error(&e)
            );
            return failure_result(&req.task_id, msg.as_bytes(), started);
        }
    };

    // pgid == child pid because we used process_group(0).
    let pgid = Pid::from_raw(child.id().expect("spawned child has a pid") as i32)
        .expect("a spawned child's pid is never zero");

    // Drain stdout/stderr to EOF in one spawned task, concurrently with
    // child.wait(): that prevents the classic two-pipe deadlock where a full pipe
    // blocks the child forever while we wait on it (ADR-0004). `stop_drain` ends
    // the drain early, keeping what it has collected (see `drain_output`).
    let out_pipe = child.stdout.take().expect("stdout piped");
    let err_pipe = child.stderr.take().expect("stderr piped");
    let (stop_drain, stop_rx) = oneshot::channel::<()>();
    let mut drain = tokio::spawn(drain_output(
        out_pipe,
        err_pipe,
        req.max_output_bytes,
        stop_rx,
    ));

    // Pinned once and shared by both phases, so a cancel is honoured whichever
    // phase it lands in. It is never polled again once it has resolved: every
    // poll below is guarded by `requested.is_none()`, and it sets `requested`.
    let mut cancel = std::pin::pin!(recv_cancel(req.cancel));
    let mut exit_code: i32 = -1;
    let mut leader_exited = false;
    // A timeout or cancel that has arrived. Whether it is *honoured* — the
    // Task reported stopped — depends on whether anything of it is still running.
    let mut requested: Option<Outcome> = None;

    // Phase 1 — run. biased; makes the wait arm win over the cancel arm when both
    // are ready simultaneously — an already-exited child reports its real
    // outcome, never a retroactive OUTCOME_CANCELLED (ADR-0013 honest-race
    // semantics).
    tokio::select! {
        biased;
        res = tokio::time::timeout_at(deadline, child.wait()) => {
            match res {
                Ok(Ok(status)) => {
                    leader_exited = true;
                    exit_code = status.code().unwrap_or(-1);
                }
                Ok(Err(_io_err)) => {
                    // wait() failed: leave exit_code = -1, treat as failure below.
                    leader_exited = true;
                }
                Err(_elapsed) => requested = Some(Outcome::Timeout),
            }
        }
        () = &mut cancel => requested = Some(Outcome::Cancelled),
    }

    // `wait()` sees an exit only once the runtime's reaper has been woken, which
    // can lag the exit itself — so a deadline or cancel can win the race above
    // against a leader that has in fact already exited. Ask the kernel directly
    // before treating the leader as running: an exited leader reports its real
    // outcome (ADR-0013).
    if !leader_exited {
        if let Ok(Some(status)) = child.try_wait() {
            leader_exited = true;
            exit_code = status.code().unwrap_or(-1);
        }
    }

    // Whether anything of the process group outlived the leader, sampled as soon
    // as the leader is known to have exited. A group that is empty then stays
    // empty — setpgid(2) only joins an existing group — so it is never the
    // Task's again and is never signalled later, when its pgid may have been
    // recycled.
    let group_outlived_leader = leader_exited && group_is_nonempty(pgid);

    // Set when the Task is reported stopped short of completing.
    let mut stopped: Option<Outcome> = None;
    let output = if !leader_exited {
        // The leader was still running when the deadline or cancel arrived. Kill
        // the whole process group: SIGTERM first, then SIGKILL after the grace
        // period. Both the direct child and all grandchildren receive the signal
        // because pgid == child pid and kill(-pgid) targets the group. Then give
        // the drain a short grace to collect what the group wrote.
        stopped = requested;
        kill_group_graceful(pgid, &mut child).await;
        collect_output(drain, stop_drain, POST_KILL_DRAIN_GRACE).await
    } else {
        // Phase 2 — drain, racing the same deadline and cancel. biased; a drain
        // that has reached EOF wins: complete output is the Task's real result.
        // Then the deadline beats a simultaneous cancel, as in phase 1. A
        // timeout or cancel that already arrived in phase 1 is still pending.
        let mut drained = None;
        tokio::select! {
            biased;
            res = &mut drain => drained = Some(res.unwrap_or_default()),
            () = tokio::time::sleep_until(deadline), if requested.is_none() => {
                requested = Some(Outcome::Timeout);
            }
            () = &mut cancel, if requested.is_none() => requested = Some(Outcome::Cancelled),
            () = std::future::ready(()), if requested.is_some() => {}
        }
        match drained {
            Some(output) => output,
            // Something of the Task's process group is still running and holding
            // its pipes: the Task has not completed, so the timeout or cancel is
            // honoured. Sweep the group, then stop the drain.
            None if group_outlived_leader && group_is_nonempty(pgid) => {
                stopped = requested;
                sweep_reaped_group(pgid).await;
                // The stop cut the command's output short, even if killing the
                // group let the pipes reach EOF during the sweep.
                let mut output = collect_output(drain, stop_drain, Duration::ZERO).await;
                output.stdout.truncated = true;
                output.stderr.truncated = true;
                output
            }
            // Nothing of the Task's process group is running: the command has
            // completed, and reports its real outcome and exit code — never a
            // retroactive timeout or cancel (ADR-0013). Collect what it wrote,
            // still bounded: a process that left the group with setsid(2) can
            // hold the pipes open indefinitely.
            None => collect_output(drain, stop_drain, POST_KILL_DRAIN_GRACE).await,
        }
    };

    // Intentionally discard the process's exit code when stopped; use -1.
    // The Task was externally stopped (not a normal completion), so its exit code
    // is meaningless — -1 is the honest "externally killed" mapping.
    let outcome = match stopped {
        Some(outcome) => outcome,
        None if exit_code == 0 => Outcome::Success,
        None => Outcome::Failure,
    };

    TaskResult {
        task_id: req.task_id,
        outcome: outcome as i32,
        exit_code: if stopped.is_some() { -1 } else { exit_code },
        stdout: output.stdout.bytes,
        stderr: output.stderr.bytes,
        truncated: output.stdout.truncated || output.stderr.truncated,
        duration_millis: started.elapsed().as_millis() as i64,
    }
}

/// Waits up to `grace` for the drain to reach EOF on both streams and returns
/// its output. If it has not by then, the drain is stopped, what it collected
/// is returned, and both streams are marked `truncated`. `Duration::ZERO`
/// stops it at once unless it has already finished.
async fn collect_output(
    mut drain: tokio::task::JoinHandle<Output>,
    stop_drain: oneshot::Sender<()>,
    grace: Duration,
) -> Output {
    if let Ok(res) = tokio::time::timeout(grace, &mut drain).await {
        return res.unwrap_or_default();
    }
    let _ = stop_drain.send(());
    let mut output = drain.await.unwrap_or_default();
    output.stdout.truncated = true;
    output.stderr.truncated = true;
    output
}

/// Kills what is left of a Task's process group once its leader has already
/// been reaped — the background process holding the Task's pipes past the
/// leader's exit (see [`execute`], phase 2).
///
/// SIGTERM, then SIGKILL to any member still present after [`TERM_GRACE`],
/// mirroring [`kill_group_graceful`]. The leader is gone, so there is no child to
/// wait on: the group's emptiness is polled instead.
///
/// pgid-reuse safety follows [`kill_group_graceful`]'s rule for a reaped leader:
/// signal only while the group is non-empty, because a surviving member holds
/// `pgid` and keeps the kernel from recycling it, and an empty group is the one
/// case where `pgid` may already name an unrelated process. The same residual
/// microsecond race between the check and the signal applies.
async fn sweep_reaped_group(pgid: Pid) {
    if !group_is_nonempty(pgid) {
        // Empty — e.g. the pipe holder left the group with setsid(2). Nothing of
        // the Task's group remains to signal, and pgid may have been recycled.
        return;
    }
    signal_group(pgid, Signal::TERM);
    let grace_end = tokio::time::Instant::now() + TERM_GRACE;
    while group_is_nonempty(pgid) {
        if tokio::time::Instant::now() >= grace_end {
            signal_group(pgid, Signal::KILL);
            return;
        }
        tokio::time::sleep(GROUP_EMPTY_POLL).await;
    }
}

/// Sends SIGTERM to the process group, waits for the grace period, then sends SIGKILL
/// to any survivors.
///
/// Reaps the direct child so no zombie remains. All grandchildren in the group also
/// receive the signal because pgid == child pid and `kill(-pgid, SIG)` targets the
/// whole group (ADR-0013, ADR-0001).
///
/// # No-orphan guarantee across leader exit
///
/// The SIGKILL sweep must run even when the group **leader** exits during the grace
/// window, because a SIGTERM-ignoring **grandchild** can outlive it. The earlier
/// version gated SIGKILL on `child.wait()` NOT returning in time, so a leader that
/// exited within grace skipped the sweep and left such a grandchild running — the
/// orphan this fixes.
///
/// # pgid-reuse safety
///
/// `kill(-pgid, …)` is only unambiguous while the kernel cannot recycle `pgid` as an
/// unrelated process. That pid is held (not recyclable) exactly while process group
/// `pgid` is non-empty. Two safe cases, and the one we must avoid:
///
/// - **Leader not reaped** (it ignored SIGTERM and outran the grace window): the leader
///   itself still holds `pgid`. SIGKILL the group, then reap the leader.
/// - **Leader reaped, group still non-empty**: a surviving member (the grandchild) holds
///   `pgid`, so the kernel has not recycled it — the group is still ours. SIGKILL it.
/// - **Leader reaped, group empty**: nothing to kill — and this is the *only* case where
///   `pgid` may already have been recycled, so we must NOT signal it. We skip.
///
/// The residual race (a surviving member exits, is reaped by init, and its pid is
/// recycled into a new group `pgid` in the microseconds between the emptiness check and
/// the SIGKILL) is not closed here; it is astronomically unlikely on the privileged
/// daemon's low process-spawn rate, and the prior code offered no protection at all.
async fn kill_group_graceful(pgid: Pid, child: &mut tokio::process::Child) {
    signal_group(pgid, Signal::TERM);
    let leader_reaped = tokio::time::timeout(TERM_GRACE, child.wait()).await.is_ok();

    if !leader_reaped {
        // Leader still holds pgid — unambiguous. SIGKILL the group, then reap.
        signal_group(pgid, Signal::KILL);
        let _ = child.wait().await;
    } else if group_is_nonempty(pgid) {
        // Leader gone but a survivor keeps the group (and thus pgid) alive: it is
        // still ours, and it needs killing. An empty group is skipped —
        // nothing to kill, and the one case where pgid could have been recycled.
        signal_group(pgid, Signal::KILL);
    }
}

/// Returns whether process group `pgid` still has any member (including a zombie).
///
/// `kill(-pgid, 0)` sends no signal but performs the same target lookup and permission
/// check as a real signal: `Ok` means the group exists and has at least one
/// member; `ESRCH` means it is empty/gone. The daemon runs privileged, so `EPERM` is not
/// a concern here; any Err is treated as "not clearly non-empty" and the caller
/// conservatively skips the SIGKILL.
fn group_is_nonempty(pgid: Pid) -> bool {
    test_kill_process_group(pgid).is_ok()
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

/// One stream's captured output: at most the cap's worth of bytes, and whether
/// anything was cut.
#[derive(Default)]
struct Captured {
    bytes: Vec<u8>,
    truncated: bool,
}

/// Both streams' captured output.
#[derive(Default)]
struct Output {
    stdout: Captured,
    stderr: Captured,
}

/// Drains stdout and stderr concurrently to EOF, each capped at `cap` bytes,
/// until both reach EOF or `stop` resolves.
///
/// The bytes live here, outside the per-stream drain futures, so stopping keeps
/// everything collected so far: on `stop` the reads are dropped (closing the
/// pipes' read ends) and the partial output is returned. A dropped sender counts
/// as `stop` too — if [`execute`] itself is dropped, the drain does not outlive
/// it. `stop` is polled first, so a stream that is always readable cannot starve
/// it.
async fn drain_output<O, E>(out: O, err: E, cap: usize, stop: oneshot::Receiver<()>) -> Output
where
    O: tokio::io::AsyncRead + Unpin,
    E: tokio::io::AsyncRead + Unpin,
{
    let mut output = Output::default();
    let both = async {
        tokio::join!(
            drain_capped(out, cap, &mut output.stdout),
            drain_capped(err, cap, &mut output.stderr),
        )
    };
    tokio::select! {
        biased;
        _ = stop => {}
        _ = both => {}
    }
    output
}

/// Drains `reader` to EOF into `into`, keeping at most `cap` bytes.
///
/// Bytes past the cap are read (to avoid blocking the child on a full pipe)
/// but discarded, and `into.truncated` is set.
async fn drain_capped<R>(mut reader: R, cap: usize, into: &mut Captured)
where
    R: tokio::io::AsyncRead + Unpin,
{
    let mut chunk = [0u8; 8192];
    loop {
        match reader.read(&mut chunk).await {
            Ok(0) => break, // EOF
            Ok(n) => {
                let buf = &mut into.bytes;
                if buf.len() < cap {
                    let take = n.min(cap - buf.len());
                    buf.extend_from_slice(&chunk[..take]);
                    if take < n {
                        into.truncated = true;
                    }
                } else {
                    into.truncated = true; // still draining, just discarding
                }
            }
            Err(_) => break, // pipe error: keep what we have
        }
    }
}

/// Sends `signal` to the entire process group led by `pgid`.
///
/// The child was launched with `process_group(0)`, so `pgid == child pid` and
/// `kill_process_group(pgid, sig)` reaches the whole process tree (ADR-0013). ESRCH
/// (group already exited) is a valid non-error return — the child may have raced to
/// exit between the timeout firing and this call.
fn signal_group(pgid: Pid, signal: Signal) {
    let _ = kill_process_group(pgid, signal);
}

/// Builds the soft==hard `Rlimit` this daemon always applies: both the current
/// (soft) and maximum (hard) limit set to `v`. `None` in either field would mean
/// RLIM_INFINITY, which is never what we want here — constructing it in one place
/// makes a soft/hard mix-up unrepresentable at the five call sites.
#[inline]
fn fixed_rlimit(v: u64) -> Rlimit {
    Rlimit {
        current: Some(v),
        maximum: Some(v),
    }
}

/// Applies `limits` to the calling process via `setrlimit`. Async-signal-safe: rustix
/// issues `prlimit64` directly (linux_raw backend, no libc wrapper) over one stack
/// `Rlimit` — no heap, no locks. Returns `Err` on the first failure so the caller (the
/// `pre_exec` closure in [`execute`]) fails the spawn closed. `Resource` is a typed
/// enum, so no target-specific resource cast is needed; `Rlimit` is `u64`-valued on
/// every target, so the `ResourceLimits` values need no cast.
fn apply_rlimits(limits: &ResourceLimits) -> std::io::Result<()> {
    if let Some(v) = limits.nproc {
        setrlimit(Resource::Nproc, fixed_rlimit(v))?;
    }
    if let Some(v) = limits.data_bytes {
        setrlimit(Resource::Data, fixed_rlimit(v))?;
    }
    if let Some(v) = limits.nofile {
        setrlimit(Resource::Nofile, fixed_rlimit(v))?;
    }
    if let Some(v) = limits.cpu_seconds {
        setrlimit(Resource::Cpu, fixed_rlimit(v))?;
    }
    if let Some(v) = limits.fsize_bytes {
        setrlimit(Resource::Fsize, fixed_rlimit(v))?;
    }
    Ok(())
}

/// Synthesizes a failure [`TaskResult`] for spawn errors and empty-argv guards.
///
/// `OUTCOME_ERROR` does not exist in proto; `OUTCOME_FAILURE` + `exit_code -1` +
/// the OS error in `stderr` is the honest available mapping (documented in the plan).
fn failure_result(task_id: &str, stderr: &[u8], started: Instant) -> TaskResult {
    not_executed_after(
        task_id.to_string(),
        Outcome::Failure,
        stderr,
        started.elapsed(),
    )
}

#[cfg(test)]
mod tests {
    use super::{execute, ExecRequest, SAFE_CHILD_PATH};
    use crate::gen::Outcome;
    use crate::limits::ResourceLimits;
    use rustix::io::Errno;
    use rustix::process::{test_kill_process, Pid};
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
        let grandchild_pid: i32 = stdout_str
            .trim()
            .parse()
            .expect("stdout must contain the background sleep PID");
        let probe = Pid::from_raw(grandchild_pid).expect("a shell-reported pid is non-zero");

        // Poll kill(pid, 0) until ESRCH: waits for PID 1 to reap the reparented
        // zombie. When the grandchild is killed by the group SIGKILL it becomes a
        // zombie (reparented to init/PID 1); kill(pid, 0) returns 0 for a
        // not-yet-reaped zombie, and ESRCH once init has collected it. A future
        // reader should not remove this loop thinking it defensive noise — without
        // it we would only prove the grandchild received a signal, not that the
        // kernel has fully released it as an orphan.
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            match test_kill_process(probe) {
                Err(Errno::SRCH) => break, // fully reaped — no orphan
                Err(e) => panic!(
                    "grandchild (pid={grandchild_pid}) must be gone (ESRCH), not another error: {e}"
                ),
                Ok(()) => {} // still alive — fall through to the deadline check
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
        let grandchild_pid: i32 = stdout_str
            .trim()
            .parse()
            .expect("stdout must contain the background sleep PID");
        let probe = Pid::from_raw(grandchild_pid).expect("a shell-reported pid is non-zero");

        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            match test_kill_process(probe) {
                Err(Errno::SRCH) => break, // fully reaped — no orphan
                Err(e) => panic!(
                    "grandchild (pid={grandchild_pid}) must be gone (ESRCH), not another error: {e}"
                ),
                Ok(()) => {} // still alive — fall through to the deadline check
            }
            assert!(
                Instant::now() < deadline,
                "grandchild (pid={grandchild_pid}) still alive after 2 s — orphan not reaped"
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }

    // 9b. ACCEPTANCE-CRITICAL (issue #342): the SIGKILL sweep must fire even when the
    //     group LEADER exits during the SIGTERM grace window, as long as a
    //     SIGTERM-ignoring grandchild survives — otherwise that grandchild is orphaned.
    //
    //     The leader `sleep 30` dies on SIGTERM (default disposition) within the grace
    //     window, so `child.wait()` returns and the leader is reaped — the exact
    //     condition the pre-#342 code treated as "done, no SIGKILL". The backgrounded
    //     subshell installs `trap "" TERM` and loops, so it IGNORES SIGTERM and outlives
    //     the leader; only the group SIGKILL can reap it. Its pid is tracked via `echo $!`.
    //
    //     Non-vacuous: with the old `Ok(_) => {}` arm (no sweep on leader exit), the
    //     subshell loops forever and the ESRCH poll below times out and fails.
    #[tokio::test]
    async fn sigkill_sweep_kills_a_grandchild_that_outlives_the_leader() {
        let result = execute(ExecRequest {
            task_id: "t-sweep-survivor".to_string(),
            argv: vec![
                "/bin/sh".to_string(),
                "-c".to_string(),
                // Background a subshell that IGNORES SIGTERM and loops (survives the
                // grace window); print its pid; then the leader sleeps and is itself
                // SIGTERM'd to death within grace.
                "( trap '' TERM; while true; do sleep 1; done ) & echo $!; sleep 30".to_string(),
            ],
            timeout: Duration::from_secs(1), // times out → kill_group_graceful runs
            max_output_bytes: 4096,
            cancel: None,
            limits: no_limits(),
        })
        .await;
        assert_eq!(result.outcome, Outcome::Timeout as i32);

        let stdout_str = String::from_utf8_lossy(&result.stdout);
        let survivor_pid: i32 = stdout_str
            .trim()
            .parse()
            .expect("stdout must contain the SIGTERM-ignoring subshell PID");
        let probe = Pid::from_raw(survivor_pid).expect("a shell-reported pid is non-zero");

        // The survivor must be gone (ESRCH) — SIGKILL swept the group even though the
        // leader had already exited. Deadline exceeds TERM_GRACE (5 s) so a correct
        // sweep, which happens right after the leader is reaped, has ample margin.
        let deadline = Instant::now() + Duration::from_secs(8);
        loop {
            match test_kill_process(probe) {
                Err(Errno::SRCH) => break, // survivor reaped — no orphan left behind
                Err(e) => panic!(
                    "survivor (pid={survivor_pid}) must be gone (ESRCH), not another error: {e}"
                ),
                Ok(()) => {} // still alive — fall through to the deadline check
            }
            assert!(
                Instant::now() < deadline,
                "SIGTERM-ignoring survivor (pid={survivor_pid}) still alive — the SIGKILL \
                 sweep was skipped when the leader exited first (issue #342)"
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

    // 11. ACCEPTANCE-CRITICAL: pins phase 1's `biased;` (in `execute`) with BOTH select arms
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

    /// Value-column indices in a /proc/self/limits line: Soft Limit, Hard Limit, Units.
    const SOFT_LIMIT: usize = 0;
    const HARD_LIMIT: usize = 1;

    /// Finds the `/proc/self/limits` line whose label matches `label` exactly
    /// (labels start at column 0, so no ambiguity with e.g. "Max cpu time" vs
    /// "Max cpu time" prefixed variants) and returns its requested value column
    /// (see `SOFT_LIMIT`/`HARD_LIMIT`).
    fn limit_column(limits_text: &str, label: &str, column: usize) -> String {
        let line = limits_text
            .lines()
            .find(|l| l.starts_with(label))
            .unwrap_or_else(|| panic!("no line starting with {label:?} in:\n{limits_text}"));
        line[label.len()..]
            .split_whitespace()
            .nth(column)
            .unwrap_or_else(|| panic!("no column {column} in line: {line:?}"))
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

        assert_eq!(limit_column(&stdout, "Max processes", SOFT_LIMIT), "111");
        assert_eq!(
            limit_column(&stdout, "Max data size", SOFT_LIMIT),
            "200000000"
        );
        assert_eq!(limit_column(&stdout, "Max open files", SOFT_LIMIT), "222");
        assert_eq!(limit_column(&stdout, "Max cpu time", SOFT_LIMIT), "333");
        assert_eq!(
            limit_column(&stdout, "Max file size", SOFT_LIMIT),
            "44000000"
        );

        // Guard against a soft/hard mix-up in the rustix `Rlimit` mapping (#670).
        // In an unprivileged run, a `maximum: None` regression already trips earlier,
        // at the `Outcome::Success` assertion above: raising a hard limit to
        // RLIM_INFINITY is EPERM for a non-root process, so the spawn fails closed
        // before execution ever reaches `/proc/self/limits`. Run as root, that EPERM
        // path does not fire, so these five assertions are what catch it instead:
        // `fixed_rlimit` sets `maximum: Some(v)` for every limit, so the Hard Limit
        // column must equal the Soft Limit column here too.
        assert_eq!(limit_column(&stdout, "Max processes", HARD_LIMIT), "111");
        assert_eq!(
            limit_column(&stdout, "Max data size", HARD_LIMIT),
            "200000000"
        );
        assert_eq!(limit_column(&stdout, "Max open files", HARD_LIMIT), "222");
        assert_eq!(limit_column(&stdout, "Max cpu time", HARD_LIMIT), "333");
        assert_eq!(
            limit_column(&stdout, "Max file size", HARD_LIMIT),
            "44000000"
        );
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

        #[allow(
            clippy::disallowed_methods,
            reason = "test fixture cleanup; the exec ban stays live in this module"
        )]
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

    // The child must NOT inherit the daemon's environment. A secret set in the
    // daemon's own process (here standing in for an operator's secret) must be
    // absent from the child's environment, and PATH must be the fixed safe path
    // — proving `env_clear()` closed the `/proc/self/environ` leak while still
    // letting a bare-name argv[0] resolve.
    #[tokio::test]
    async fn child_does_not_inherit_daemon_environment() {
        // Distinctive name so no other (concurrent) test reads or asserts on it.
        const SECRET_KEY: &str = "RELAY_TEST_INHERIT_SECRET_9f3a";
        std::env::set_var(SECRET_KEY, "super-secret-enrollment-token");

        // `env` is a bare name: it can only run if PATH was injected.
        let result = execute(ExecRequest {
            task_id: "t-env-isolation".to_string(),
            argv: vec!["env".to_string()],
            timeout: Duration::from_secs(5),
            max_output_bytes: big_cap(),
            cancel: None,
            limits: no_limits(),
        })
        .await;

        std::env::remove_var(SECRET_KEY);

        assert_eq!(
            result.outcome,
            Outcome::Success as i32,
            "bare-name `env` must resolve against the injected PATH"
        );
        let env_dump = String::from_utf8_lossy(&result.stdout);
        assert!(
            !env_dump.contains(SECRET_KEY),
            "child inherited a daemon secret from the environment:\n{env_dump}"
        );
        assert!(
            env_dump
                .lines()
                .any(|l| l == format!("PATH={SAFE_CHILD_PATH}")),
            "child PATH must be exactly the fixed safe path; got:\n{env_dump}"
        );
    }

    // -------------------------------------------------------------------------
    // The drain of a finished child's output is bounded (ADR-0004)
    // -------------------------------------------------------------------------

    /// A command whose leader exits at once but leaves a backgrounded `sleep`
    /// holding its stdout/stderr — so the output never reaches EOF on its own.
    /// It writes the leader's own pid to `leader_pid_file` first, and prints the
    /// background holder's pid to stdout.
    fn leader_exits_holder_keeps_pipe(leader_pid_file: &std::path::Path) -> Vec<String> {
        vec![
            "/bin/sh".to_string(),
            "-c".to_string(),
            format!(
                "echo $$ > {}; sleep 30 & echo $!",
                leader_pid_file.display()
            ),
        ]
    }

    // 16. The Task's timeout bounds the drain, not just the wait. The leader exits
    //     straight away, so the whole budget is spent in the drain. Before the fix
    //     the drain awaited EOF with no bound and `execute` hung for the holder's
    //     full 30 s; the outer 10 s guard turns that hang into a failure.
    #[tokio::test]
    async fn drain_is_bounded_by_the_task_timeout() {
        let pid_file = crate::test_support::unique_temp_path("drain-timeout-leader");
        // Long enough that even a loaded runner sees the leader exit well before
        // the deadline, so the budget is spent in the drain, not the run phase.
        let timeout = Duration::from_secs(2);
        let started = Instant::now();
        let result = tokio::time::timeout(
            Duration::from_secs(10),
            execute(ExecRequest {
                task_id: "t-drain-timeout".to_string(),
                argv: leader_exits_holder_keeps_pipe(&pid_file),
                timeout,
                max_output_bytes: 4096,
                cancel: None,
                limits: no_limits(),
            }),
        )
        .await
        .expect("execute must return at its timeout, not wait for the pipe holder to exit");
        let elapsed = started.elapsed();
        #[allow(
            clippy::disallowed_methods,
            reason = "test fixture cleanup; the exec ban stays live in this module"
        )]
        let _ = std::fs::remove_file(&pid_file);

        assert_eq!(result.outcome, Outcome::Timeout as i32);
        assert_eq!(result.exit_code, -1);
        assert!(
            result.truncated,
            "a drain stopped short of EOF must be marked truncated"
        );
        assert!(
            elapsed >= timeout,
            "returned after {elapsed:?}, before its {timeout:?} timeout"
        );
        assert!(
            elapsed < timeout + super::TERM_GRACE,
            "overran its timeout by more than the kill grace: {elapsed:?}"
        );

        // Output collected before the deadline is kept, and the holder — still in
        // the Task's process group — was swept, not left running.
        let holder: i32 = String::from_utf8_lossy(&result.stdout)
            .trim()
            .parse()
            .expect("stdout keeps the output written before the deadline");
        crate::test_support::wait_until_reaped(holder, Duration::from_secs(2)).await;
    }

    // 17. A cancel that lands while the drain is still waiting on a pipe holder
    //     (the leader already exited and was reaped) stops the Task. Before the fix
    //     the cancel arm had already been dropped with the run-phase select!, so
    //     the cancel was ignored and `execute` hung for the holder's full 30 s.
    #[tokio::test]
    async fn cancel_during_the_drain_stops_the_task() {
        let pid_file = crate::test_support::unique_temp_path("drain-cancel-leader");
        let (cancel_tx, cancel_rx) = tokio::sync::oneshot::channel::<()>();
        let task = tokio::spawn(execute(ExecRequest {
            task_id: "t-drain-cancel".to_string(),
            argv: leader_exits_holder_keeps_pipe(&pid_file),
            timeout: Duration::from_secs(30), // long: only the cancel can end it
            max_output_bytes: 4096,
            cancel: Some(cancel_rx),
            limits: no_limits(),
        }));

        // The leader being *reaped* (ESRCH, not merely exited) means `execute`'s
        // own `child.wait()` collected it, so the run phase is over and `execute`
        // is in the drain: the cancel below lands there, deterministically.
        let leader = crate::test_support::read_pid_file(&pid_file).await;
        #[allow(
            clippy::disallowed_methods,
            reason = "test fixture cleanup; the exec ban stays live in this module"
        )]
        let _ = std::fs::remove_file(&pid_file);
        crate::test_support::wait_until_reaped(leader, Duration::from_secs(5)).await;
        cancel_tx
            .send(())
            .expect("execute still holds the cancel receiver");

        let result = tokio::time::timeout(Duration::from_secs(10), task)
            .await
            .expect("a cancel during the drain must end the Task promptly")
            .expect("execute must not panic");

        assert_eq!(result.outcome, Outcome::Cancelled as i32);
        assert_eq!(result.exit_code, -1);
        assert!(result.truncated);
        let holder: i32 = String::from_utf8_lossy(&result.stdout)
            .trim()
            .parse()
            .expect("stdout keeps the output written before the cancel");
        crate::test_support::wait_until_reaped(holder, Duration::from_secs(2)).await;
    }

    // 18. Regression guard for the common case: a child whose pipes close when it
    //     exits still reports its real outcome, exit code and complete output —
    //     the drain bound changes nothing unless something holds the pipes.
    #[tokio::test]
    async fn drain_reaching_eof_reports_the_real_outcome() {
        let result = execute(ExecRequest {
            task_id: "t-drain-eof".to_string(),
            argv: vec![
                "/bin/sh".to_string(),
                "-c".to_string(),
                "echo out; echo err 1>&2; exit 3".to_string(),
            ],
            timeout: Duration::from_secs(5),
            max_output_bytes: 4096,
            cancel: None,
            limits: no_limits(),
        })
        .await;
        assert_eq!(result.outcome, Outcome::Failure as i32);
        assert_eq!(result.exit_code, 3);
        assert_eq!(result.stdout, b"out\n");
        assert_eq!(result.stderr, b"err\n");
        assert!(!result.truncated);
    }

    /// Blocking: spins (up to 5 s) until the leader whose pid the command writes
    /// to `pid_file` has exited — a zombie, or already reaped and gone from
    /// `/proc` — then sends `cancel` at once. Spinning on observable state,
    /// rather than sleeping, sends the cancel as close to the exit as possible:
    /// inside the window where the runtime has not yet reaped the leader.
    fn cancel_once_exited(pid_file: std::path::PathBuf, cancel: tokio::sync::oneshot::Sender<()>) {
        let deadline = Instant::now() + Duration::from_secs(5);
        let pid: i32 = loop {
            let text = std::fs::read_to_string(&pid_file).unwrap_or_default();
            if let Some(pid) = text.strip_suffix('\n').and_then(|s| s.parse().ok()) {
                break pid;
            }
            assert!(Instant::now() < deadline, "no pid written within 5 s");
            std::thread::yield_now();
        };
        #[allow(
            clippy::disallowed_methods,
            reason = "test fixture cleanup; the exec ban stays live in this module"
        )]
        let _ = std::fs::remove_file(&pid_file);
        // Gone from /proc means reaped already.
        while let Ok(stat) = std::fs::read_to_string(format!("/proc/{pid}/stat")) {
            // The state is the first field after the parenthesised command.
            let state = stat
                .rsplit_once(')')
                .and_then(|(_, rest)| rest.split_whitespace().next());
            if state == Some("Z") {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "pid {pid} did not exit within 5 s"
            );
            std::thread::yield_now();
        }
        // Execute may already have finished and dropped the receiver.
        let _ = cancel.send(());
    }

    // 19. ADR-0013: a cancel that arrives only after the command has exited — its
    //     leader already a zombie, its output fully written — must report the
    //     real outcome and exit code, never a retroactive OUTCOME_CANCELLED. The
    //     runtime's reaper can lag the exit, so the cancel often wins the run
    //     phase's race against `wait()`; and the drain may not have seen EOF
    //     yet, so it can win the drain phase's race too. Looped on a
    //     multi-threaded runtime because the race is timing-dependent: before
    //     the fix a large share of iterations reported CANCELLED.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn cancel_after_the_command_exited_reports_its_real_outcome() {
        for i in 0..20 {
            let pid_file = crate::test_support::unique_temp_path("cancel-after-exit");
            let (cancel_tx, cancel_rx) = tokio::sync::oneshot::channel::<()>();
            let task = tokio::spawn(execute(ExecRequest {
                task_id: format!("t-cancel-after-exit-{i}"),
                argv: vec![
                    "/bin/sh".to_string(),
                    "-c".to_string(),
                    format!("echo $$ > {}; printf done; exit 7", pid_file.display()),
                ],
                timeout: Duration::from_secs(30),
                max_output_bytes: 4096,
                cancel: Some(cancel_rx),
                limits: no_limits(),
            }));

            tokio::task::spawn_blocking(move || cancel_once_exited(pid_file, cancel_tx))
                .await
                .expect("the cancel sender must not panic");

            let result = tokio::time::timeout(Duration::from_secs(10), task)
                .await
                .expect("execute must return")
                .expect("execute must not panic");
            assert_eq!(
                (result.outcome, result.exit_code),
                (Outcome::Failure as i32, 7),
                "iteration {i}: an exited command must report its real outcome, not CANCELLED"
            );
            assert_eq!(result.stdout, b"done", "iteration {i}");
            assert!(!result.truncated, "iteration {i}");
        }
    }

    // 20. The same rule at the deadline. The command exits at once, but a process
    //     that left its process group with setsid(2) keeps the stdout pipe open.
    //     Nothing of the Task's group is running at the deadline, so the command
    //     has completed: it reports its real outcome and exit code — with the
    //     output marked truncated, since the drain was stopped short of EOF —
    //     not OUTCOME_TIMEOUT.
    #[tokio::test]
    async fn deadline_with_only_an_escaped_pipe_holder_reports_the_real_outcome() {
        let timeout = Duration::from_secs(2);
        let started = Instant::now();
        let result = tokio::time::timeout(
            Duration::from_secs(15),
            execute(ExecRequest {
                task_id: "t-escaped-holder".to_string(),
                argv: vec![
                    "/bin/sh".to_string(),
                    "-c".to_string(),
                    "setsid sleep 30 & echo $!; exit 4".to_string(),
                ],
                timeout,
                max_output_bytes: 4096,
                cancel: None,
                limits: no_limits(),
            }),
        )
        .await
        .expect("execute must return despite the escaped pipe holder");
        let elapsed = started.elapsed();

        // The holder left the Task's group, so nothing in execute kills it: this
        // test cleans up the one process it created, by its own pid.
        let holder: i32 = String::from_utf8_lossy(&result.stdout)
            .trim()
            .parse()
            .expect("stdout keeps the holder's pid");
        let _ = rustix::process::kill_process(
            Pid::from_raw(holder).expect("a shell-reported pid is non-zero"),
            rustix::process::Signal::KILL,
        );

        assert_eq!(result.outcome, Outcome::Failure as i32);
        assert_eq!(result.exit_code, 4);
        assert!(result.truncated);
        assert!(
            elapsed < timeout + super::POST_KILL_DRAIN_GRACE + Duration::from_secs(2),
            "the drain must still be bounded: {elapsed:?}"
        );
        crate::test_support::wait_until_reaped(holder, Duration::from_secs(2)).await;
    }
}
