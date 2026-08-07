//! Task dispatch pipeline — dedup → Policy → execute (ADR-0002, ADR-0004).
//!
//! Wires the already-merged primitives (Policy engine, executor, Native
//! Operations, Raw Exec, DedupStore) into a single entry point that an inbound
//! `TaskRequest` flows through.
//!
//! Ordering (matches the issue requirement):
//! 1. `dedup.run_once` — check and record the task_id marker BEFORE running
//!    the pipeline. A denied Task also consumes a dedup marker, so a retry
//!    with the same task_id always returns the benign already-processed result
//!    even if the first run was denied by Policy.
//! 2. Policy gate — deny-before-execute (ADR-0002 invariant #3, deny-by-default).
//! 3. Execute — only if Policy allows.

use std::future::Future;
use std::time::Duration;

use tokio::sync::oneshot;
use tokio::time::Instant;

use crate::config::MAX_OUTPUT_BYTES;
use crate::dedup::DedupStore;
use crate::executor::{execute, ExecRequest};
use crate::gen::{
    policy_query, task_request, Operation, Outcome, PolicyQuery, PolicyVerdict, TaskRequest,
    TaskResult,
};
use crate::operations;
use crate::operations::file_read::{file_read, PathCheck};
use crate::operations::pkg_install::pkg_install;
use crate::operations::schema::{OP_ARG_NAME, OP_ARG_PATH, OP_ARG_UNIT, OP_ARG_VERSION};
use crate::operations::service_restart::service_restart;
use crate::operations::system_facts::gather_facts;
use crate::policy::{Decision, Policy};
use crate::raw_exec::run_raw_exec;
use crate::scheduler::{QueuedOutcome, Scheduler};

// ---------------------------------------------------------------------------
// Daemon-level v0.0.3 constants
// ---------------------------------------------------------------------------

/// Default per-Task timeout applied when `TaskRequest.timeout_seconds` is ≤ 0.
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);

/// Hard upper bound on per-Task wall-clock time (ADR-0004).
///
/// Policy-configurable per-Task timeout caps are a v0.0.4 item; until then,
/// this constant is the sole enforced upper bound. Any request for more is
/// silently clamped to this value.
const MAX_TIMEOUT: Duration = Duration::from_secs(300);

// MAX_OUTPUT_BYTES (per-Task output byte cap for stdout/stderr independently,
// ADR-0004) is defined in `config.rs` — the daemon's single home for
// compile-time hard limits — and imported above.

// v1 arg-key contract (`OP_ARG_PATH`/`OP_ARG_UNIT`/`OP_ARG_NAME`/`OP_ARG_VERSION`):
// relocated to `operations::schema` (ADR-0015) — the single definition site
// for every side of the arg-key contract (this dispatch pipeline reads them
// out of `Operation.args`; the schema module also advertises them in the
// golden Operation schema). Re-exported here via the `use` above.

// ---------------------------------------------------------------------------
// Public dispatch entry
// ---------------------------------------------------------------------------

/// Ordered dispatch pipeline: dedup → schedule → Policy → execute.
///
/// Wraps [`dispatch_scheduled_with_runner`] with the real [`execute`] runner.
/// The scheduler acquires a concurrency slot keyed off the Task's ADR-0012 risk
/// class before Policy is evaluated. If the Task's deadline expires while queued
/// or an explicit cancel signal arrives, the Task reports `OUTCOME_TIMEOUT` or
/// `OUTCOME_CANCELLED` without ever executing.
///
/// `received_at` is the `tokio::time::Instant` captured at true receipt in the
/// tunnel loop — it is the single clock origin for both the queue-wait budget and
/// the in-executor remaining budget (ADR-0004).
///
/// `cancel` is forwarded through scheduling into the executor so the in-flight
/// cancel path (ADR-0013 honest-race) is intact for Tasks that make it past the
/// queue.
pub async fn dispatch(
    task: &TaskRequest,
    policy: &Policy,
    dedup: &DedupStore,
    scheduler: &Scheduler,
    received_at: Instant,
    cancel: Option<oneshot::Receiver<()>>,
) -> TaskResult {
    dispatch_scheduled_with_runner(task, policy, dedup, scheduler, received_at, execute, cancel)
        .await
}

// ---------------------------------------------------------------------------
// Testable core (runner-injected, test-only)
// ---------------------------------------------------------------------------

/// Dedup → Policy → execute with an injected runner for hermeticity.
///
/// The `run` closure is the sole process-spawning seam: [`execute`] in
/// production; a fake that records argv in tests. Only `service.restart` and
/// `pkg.install` invoke the runner; `system.facts` and `file.read` are data-only.
///
/// **Dedup ordering** (ADR-0004, invariant #4): `dedup.run_once` records the
/// task_id marker BEFORE invoking the pipeline (deny-or-execute). A denied
/// Task also consumes a marker: a retry with the same task_id returns the
/// benign already-processed result, even if the first run was denied by Policy.
/// A cancelled Task's id is equally recorded before execution; a re-send is
/// deduplicated (at-most-once holds across cancel, ADR-0004).
///
/// `cancel` is moved into the `run_once` closure (FnOnce); a dedup hit drops
/// it without sending — no accidental cancel effect.
///
/// Production Tasks flow through [`dispatch_scheduled_with_runner`] instead;
/// this function is kept for the existing test suite that exercises the
/// dedup → Policy → execute pipeline directly without a scheduler.
#[cfg(test)]
async fn dispatch_with_runner<R, Fut>(
    task: &TaskRequest,
    policy: &Policy,
    dedup: &DedupStore,
    run: R,
    cancel: Option<oneshot::Receiver<()>>,
) -> TaskResult
where
    R: Fn(ExecRequest) -> Fut + Clone,
    Fut: Future<Output = TaskResult>,
{
    dedup
        .run_once(&task.task_id, move || async move {
            let timeout = effective_timeout(task.timeout_seconds);
            evaluate_and_execute(task, timeout, policy, run, cancel).await
        })
        .await
}

// ---------------------------------------------------------------------------
// Scheduler-aware testable core (runner-injected)
// ---------------------------------------------------------------------------

/// Dedup → schedule → Policy → execute with an injected runner and scheduler.
///
/// This is the production-path core. All invariants hold in a single nested
/// structure:
///
/// - `dedup.run_once` is the **outermost** wrapper (ADR-0004 dedup-before-enqueue):
///   the `task_id` marker is recorded before the closure enters the queue. A
///   Task whose deadline expires or is cancelled while queued still has its id
///   recorded — a re-send is deduplicated (at-most-once holds for queued exits).
/// - `scheduler.acquire` blocks inside the closure until a slot is available,
///   the deadline fires, or cancel fires. The permit is held across execution
///   (mutate serial invariant).
/// - A single timeout clock runs from `received_at`: `deadline = received_at +
///   effective_timeout`. The executor receives only the REMAINING budget so the
///   clock never restarts at dispatch time.
/// - The still-owned `cancel` receiver is forwarded to the executor so the
///   in-flight cancel path and honest-race (ADR-0013) remain intact.
async fn dispatch_scheduled_with_runner<R, Fut>(
    task: &TaskRequest,
    policy: &Policy,
    dedup: &DedupStore,
    scheduler: &Scheduler,
    received_at: Instant,
    run: R,
    cancel: Option<oneshot::Receiver<()>>,
) -> TaskResult
where
    R: Fn(ExecRequest) -> Fut + Clone,
    Fut: Future<Output = TaskResult>,
{
    dedup
        .run_once(&task.task_id, move || async move {
            let effective = effective_timeout(task.timeout_seconds);
            let deadline = received_at + effective;
            let class = Scheduler::classify(task);
            let mut cancel = cancel;
            match scheduler.acquire(class, deadline, &mut cancel).await {
                Err(QueuedOutcome::Timeout) => timeout_result(task.task_id.clone(), received_at),
                Err(QueuedOutcome::Cancelled) => {
                    cancelled_result(task.task_id.clone(), received_at)
                }
                Ok(_permit) => {
                    // Single clock from receipt: give the executor only the
                    // REMAINING wall-clock budget, not a fresh effective_timeout.
                    let remaining = deadline.saturating_duration_since(Instant::now());
                    if remaining.is_zero() {
                        // Deadline elapsed between acquire returning and now:
                        // report timeout without executing (no race with the
                        // executor — permit is held, so no other mutate Task ran).
                        timeout_result(task.task_id.clone(), received_at)
                    } else {
                        // _permit held across evaluate_and_execute: keeps the gate
                        // occupied for the duration of execution (mutate serial).
                        evaluate_and_execute(task, remaining, policy, run, cancel).await
                    }
                    // _permit drops here, releasing the gate for the next Task.
                }
            }
        })
        .await
}

// ---------------------------------------------------------------------------
// Read-only PolicyQuery evaluator (ADR-0011)
// ---------------------------------------------------------------------------

/// Evaluate a hypothetical `Operation` or `RawExec` against the loaded Policy.
///
/// This function takes **no** `DedupStore` and never reaches the executor — it
/// is structurally incapable of recording a marker or spawning a process
/// (ADR-0011). It calls the exact same `policy.evaluate` /
/// `policy.evaluate_raw_exec` entry points that the execution path uses (via
/// `operation_positional_args`), so the verdict can never diverge from what a
/// real Task dispatch would decide (ADR-0011 invariant 12).
pub fn evaluate_policy_query(query: &PolicyQuery, policy: &Policy) -> PolicyVerdict {
    let query_id = query.query_id.clone();
    match &query.action {
        Some(policy_query::Action::Operation(op)) => {
            let positional = operation_positional_args(op);
            let decision = policy.evaluate(&op.name, &positional);
            decision_to_verdict(query_id, decision)
        }
        Some(policy_query::Action::RawExec(raw)) => {
            let decision = policy.evaluate_raw_exec(&raw.argv);
            decision_to_verdict(query_id, decision)
        }
        // Malformed query with no action: deny with a non-empty deciding_rule so
        // the caller can distinguish a protocol error from a Policy deny.
        None => PolicyVerdict {
            query_id,
            allowed: false,
            deciding_rule: "empty policy query action".to_string(),
        },
    }
}

/// Convert an engine `Decision` into a `PolicyVerdict`.
///
/// `deciding_rule` is the engine's own `reason` string verbatim, for every
/// deny sub-case (explicit operation deny, explicit raw_exec deny, or
/// deny-by-default with or without an args-mismatch). This is the same
/// `reason` `denied_by_policy_result` writes to stderr on the execution
/// path, so the plan-verdict text and the apply-path stderr text are
/// identical for the same input — one shared source, no re-decision, no
/// parallel evaluator (ADR-0011).
fn decision_to_verdict(query_id: String, decision: Decision) -> PolicyVerdict {
    match decision {
        Decision::Allow(_) => PolicyVerdict {
            query_id,
            allowed: true,
            deciding_rule: String::new(),
        },
        Decision::Deny { reason, .. } => PolicyVerdict {
            query_id,
            allowed: false,
            deciding_rule: reason,
        },
    }
}

/// Map an `Operation`'s named args to the positional arg vector the Policy engine expects.
///
/// This is the **single definition** of the arg-map → positional mapping used by
/// both the execution path (`handle_operation`) and the query path
/// (`evaluate_policy_query`). Both paths MUST call this function; duplicating
/// the match would risk silent drift between "would allow" and "actually allows"
/// (ADR-0011).
///
/// Unknown operation names receive an empty positional list, which causes
/// deny-by-default to fire in the Policy engine — identical to what execution
/// would report.
fn operation_positional_args(op: &Operation) -> Vec<String> {
    match op.name.as_str() {
        operations::SYSTEM_FACTS => vec![],
        operations::FILE_READ => {
            let path = op.args.get(OP_ARG_PATH).cloned().unwrap_or_default();
            vec![path]
        }
        operations::SERVICE_RESTART => {
            let unit = op.args.get(OP_ARG_UNIT).cloned().unwrap_or_default();
            vec![unit]
        }
        operations::PKG_INSTALL => {
            // Stable 2-position schema: [name, version]. version defaults to ""
            // when absent — matched by a Policy "*" wildcard rule (ADR-0011: the
            // same mapping feeds both the query and execution paths, so a
            // PolicyQuery verdict can never diverge from what dispatch decides).
            let name = op.args.get(OP_ARG_NAME).cloned().unwrap_or_default();
            let version = op.args.get(OP_ARG_VERSION).cloned().unwrap_or_default();
            vec![name, version]
        }
        _ => vec![], // deny-by-default will catch this
    }
}

// ---------------------------------------------------------------------------
// Policy gate and handler dispatch
// ---------------------------------------------------------------------------

async fn evaluate_and_execute<R, Fut>(
    task: &TaskRequest,
    timeout: Duration,
    policy: &Policy,
    run: R,
    cancel: Option<oneshot::Receiver<()>>,
) -> TaskResult
where
    R: Fn(ExecRequest) -> Fut + Clone,
    Fut: Future<Output = TaskResult>,
{
    let task_id = task.task_id.clone();

    match &task.action {
        Some(task_request::Action::RawExec(raw)) => {
            // Raw Exec: fully gated by Policy regex before any spawn (ADR-0001, ADR-0002).
            run_raw_exec(task_id, raw, timeout, MAX_OUTPUT_BYTES, policy, cancel).await
        }
        Some(task_request::Action::Operation(op)) => {
            handle_operation(task_id, op, timeout, policy, run, cancel).await
        }
        None => {
            // Missing action: protocol error → FAILURE (not DENIED_BY_POLICY).
            // cancel drops naturally here (no process spawned).
            failure_result(task_id, b"missing task action")
        }
    }
}

async fn handle_operation<R, Fut>(
    task_id: String,
    op: &Operation,
    timeout: Duration,
    policy: &Policy,
    run: R,
    cancel: Option<oneshot::Receiver<()>>,
) -> TaskResult
where
    R: Fn(ExecRequest) -> Fut + Clone,
    Fut: Future<Output = TaskResult>,
{
    // Build the positional arg vector from the named args map (v1 arg-key contract).
    // Unknown operations receive an empty positional list and are denied by
    // Policy's deny-by-default (no allow rule can exist for an unknown name).
    // Shared with evaluate_policy_query via operation_positional_args so query
    // and execution derive args through the same function (ADR-0011: no drift).
    let positional = operation_positional_args(op);

    // Policy gate: deny-before-execute, deny-by-default (ADR-0002, invariant #3).
    match policy.evaluate(&op.name, &positional) {
        Decision::Deny { reason, rule } => {
            // cancel drops naturally here — denied before any process spawned.
            tracing::warn!(
                task_id = %task_id,
                operation = %op.name,
                args = ?positional,
                rule = ?rule,
                reason = %reason,
                "operation denied by policy"
            );
            denied_by_policy_result(task_id, &reason)
        }
        Decision::Allow(_rule) => {
            match op.name.as_str() {
                operations::SYSTEM_FACTS => {
                    // Data-only: no process spawned; cancel is irrelevant.
                    let _ = cancel;
                    // KNOWN LIMITATION: gather_facts calls fs::read_to_string
                    // (blocking) and libc::getifaddrs (blocking syscall) inside
                    // this async context. Safe for v0.0.3 single-flight; move to
                    // spawn_blocking in v0.0.4 (mirrors executor.rs:117-120).
                    let facts = gather_facts();
                    TaskResult {
                        task_id,
                        outcome: Outcome::Success as i32,
                        exit_code: 0,
                        stdout: format_facts_as_kv(&facts),
                        stderr: vec![],
                        truncated: false,
                        duration_millis: 0,
                    }
                }
                operations::FILE_READ => {
                    // Data-only: no process spawned; cancel is irrelevant.
                    let _ = cancel;
                    // KNOWN LIMITATION: file_read calls std::fs::File::open
                    // (blocking) inside this async context. Safe for v0.0.3
                    // single-flight; move to spawn_blocking in v0.0.4
                    // (mirrors executor.rs:117-120).
                    let path = positional.first().map(String::as_str).unwrap_or("");
                    // ADR-0018 layer 2: file_read resolves the target it opens
                    // and calls back here to re-evaluate Policy on the RESOLVED
                    // path, closing `/proc`-magic and symlink evasions that are
                    // canonical in form and so pass layer 1.
                    file_read(&task_id, path, MAX_OUTPUT_BYTES, |resolved| {
                        match policy.evaluate(operations::FILE_READ, &[resolved.to_string()]) {
                            Decision::Deny { reason, .. } => PathCheck::Denied(reason),
                            Decision::Allow(_) => PathCheck::Allowed,
                        }
                    })
                }
                operations::SERVICE_RESTART => {
                    let unit = positional.into_iter().next().unwrap_or_default();
                    service_restart(
                        task_id,
                        &unit,
                        timeout,
                        MAX_OUTPUT_BYTES,
                        cancel,
                        run.clone(),
                    )
                    .await
                }
                operations::PKG_INSTALL => {
                    let mut it = positional.into_iter();
                    let name = it.next().unwrap_or_default();
                    let version = it.next().filter(|v| !v.is_empty());
                    pkg_install(
                        task_id,
                        &name,
                        version.as_deref(),
                        timeout,
                        MAX_OUTPUT_BYTES,
                        cancel,
                        run.clone(),
                    )
                    .await
                }
                _ => {
                    // Policy allowed a name this daemon does not implement.
                    // FAILURE (not DENIED_BY_POLICY): the Policy engine is not at fault.
                    // cancel drops naturally here — no process spawned.
                    let _ = cancel;
                    failure_result(task_id, b"unknown operation")
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Clamps `timeout_seconds` to `[DEFAULT_TIMEOUT, MAX_TIMEOUT]`.
///
/// `≤0` → `DEFAULT_TIMEOUT` (absent or unset by the AI-agent).
/// `>0` → `min(requested, MAX_TIMEOUT)` — the daemon hard cap (ADR-0004).
/// Policy-configurable per-Task timeout caps are a v0.0.4 item; until then
/// this function is the sole timeout enforcer.
fn effective_timeout(timeout_seconds: i32) -> Duration {
    if timeout_seconds <= 0 {
        DEFAULT_TIMEOUT
    } else {
        Duration::from_secs(timeout_seconds as u64).min(MAX_TIMEOUT)
    }
}

/// Synthesizes an `OUTCOME_TIMEOUT` [`TaskResult`] for a Task that expired in the queue.
///
/// `duration_millis` is measured from `received_at` (true receipt), covering
/// both queue-wait time and the zero execution time.
fn timeout_result(task_id: String, received_at: Instant) -> TaskResult {
    TaskResult {
        task_id,
        outcome: Outcome::Timeout as i32,
        exit_code: -1,
        stdout: Vec::new(),
        stderr: Vec::new(),
        truncated: false,
        duration_millis: received_at.elapsed().as_millis() as i64,
    }
}

/// Synthesizes an `OUTCOME_CANCELLED` [`TaskResult`] for a Task cancelled while queued.
///
/// `duration_millis` is measured from `received_at`, covering queue-wait time.
/// The Task never executed — no process was spawned.
fn cancelled_result(task_id: String, received_at: Instant) -> TaskResult {
    TaskResult {
        task_id,
        outcome: Outcome::Cancelled as i32,
        exit_code: -1,
        stdout: Vec::new(),
        stderr: Vec::new(),
        truncated: false,
        duration_millis: received_at.elapsed().as_millis() as i64,
    }
}

/// Synthesizes a `OUTCOME_DENIED_BY_POLICY` [`TaskResult`] — no process spawned.
fn denied_by_policy_result(task_id: String, reason: &str) -> TaskResult {
    TaskResult {
        task_id,
        outcome: Outcome::DeniedByPolicy as i32,
        exit_code: -1,
        stdout: Vec::new(),
        stderr: reason.as_bytes().to_vec(),
        truncated: false,
        duration_millis: 0,
    }
}

/// Synthesizes an `OUTCOME_FAILURE` result for protocol errors and unknown operations.
fn failure_result(task_id: String, stderr: &[u8]) -> TaskResult {
    TaskResult {
        task_id,
        outcome: Outcome::Failure as i32,
        exit_code: -1,
        stdout: Vec::new(),
        stderr: stderr.to_vec(),
        truncated: false,
        duration_millis: 0,
    }
}

/// Formats a [`Facts`] struct as newline-terminated `key=value` lines.
///
/// `ip_addresses` is comma-joined on a single line. This is the daemon-local
/// encoding for the `system.facts` Operation's stdout: it is NOT a proto-level
/// encoding and may change in future milestones without a wire-protocol change.
fn format_facts_as_kv(facts: &crate::gen::Facts) -> Vec<u8> {
    format!(
        "hostname={}\nos={}\narch={}\nkernel={}\nip_addresses={}\n",
        facts.hostname,
        facts.os,
        facts.arch,
        facts.kernel,
        facts.ip_addresses.join(","),
    )
    .into_bytes()
}

// ---------------------------------------------------------------------------
// Tests — pipeline acceptance criteria (a)–(e) Rust-half
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::fs;
    use std::io::Write;
    use std::os::unix::fs::PermissionsExt;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::SystemTime;
    use std::time::UNIX_EPOCH;

    use super::*;
    use crate::executor::execute;
    use crate::gen::{Outcome, TaskResult};
    use crate::operations;
    use crate::policy::from_toml_str;

    // -----------------------------------------------------------------------
    // Shared helpers
    // -----------------------------------------------------------------------

    const FIXTURE: &str = include_str!("../policy.example.toml");

    fn fixture_policy() -> Policy {
        from_toml_str(FIXTURE).expect("policy.example.toml must parse cleanly")
    }

    /// Temp directory that removes itself on drop (test isolation).
    struct TempDir(PathBuf);

    impl TempDir {
        fn new(label: &str) -> Self {
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let path = std::env::temp_dir().join(format!(
                "relay-dispatch-test-{}-{}-{}",
                label,
                std::process::id(),
                nanos
            ));
            fs::create_dir_all(&path).expect("create temp dir");
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

    /// Temp file with explicit mode (set_permissions, not umask-masked OpenOptions::mode).
    struct TempFile(PathBuf);

    impl TempFile {
        fn new(label: &str, content: &[u8]) -> Self {
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let path = std::env::temp_dir().join(format!(
                "relay-dispatch-tf-{}-{}-{}",
                label,
                std::process::id(),
                nanos
            ));
            let mut f = fs::File::create(&path).expect("create temp file");
            f.write_all(content).expect("write temp file");
            // Explicit set_permissions: OpenOptions::mode is umask-masked;
            // this call is umask-proof (matches policy.rs pattern).
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
                .expect("set temp file permissions");
            TempFile(path)
        }
        fn path_str(&self) -> String {
            self.0.to_string_lossy().into_owned()
        }
    }

    impl Drop for TempFile {
        fn drop(&mut self) {
            let _ = fs::remove_file(&self.0);
        }
    }

    fn make_task_file_read(task_id: &str, path: &str) -> TaskRequest {
        let mut args = std::collections::HashMap::new();
        args.insert(OP_ARG_PATH.to_string(), path.to_string());
        TaskRequest {
            task_id: task_id.to_string(),
            timeout_seconds: 5,
            action: Some(task_request::Action::Operation(crate::gen::Operation {
                name: operations::FILE_READ.to_string(),
                args,
            })),
        }
    }

    fn make_task_service_restart(task_id: &str, unit: &str) -> TaskRequest {
        let mut args = std::collections::HashMap::new();
        args.insert(OP_ARG_UNIT.to_string(), unit.to_string());
        TaskRequest {
            task_id: task_id.to_string(),
            timeout_seconds: 5,
            action: Some(task_request::Action::Operation(crate::gen::Operation {
                name: operations::SERVICE_RESTART.to_string(),
                args,
            })),
        }
    }

    fn make_task_pkg_install(task_id: &str, name: &str, version: &str) -> TaskRequest {
        let mut args = std::collections::HashMap::new();
        args.insert(OP_ARG_NAME.to_string(), name.to_string());
        if !version.is_empty() {
            args.insert(OP_ARG_VERSION.to_string(), version.to_string());
        }
        TaskRequest {
            task_id: task_id.to_string(),
            timeout_seconds: 5,
            action: Some(task_request::Action::Operation(crate::gen::Operation {
                name: operations::PKG_INSTALL.to_string(),
                args,
            })),
        }
    }

    fn make_task_system_facts(task_id: &str) -> TaskRequest {
        TaskRequest {
            task_id: task_id.to_string(),
            timeout_seconds: 5,
            action: Some(task_request::Action::Operation(crate::gen::Operation {
                name: operations::SYSTEM_FACTS.to_string(),
                args: Default::default(),
            })),
        }
    }

    fn make_task_raw_exec(task_id: &str, argv: Vec<String>) -> TaskRequest {
        TaskRequest {
            task_id: task_id.to_string(),
            timeout_seconds: 5,
            action: Some(task_request::Action::RawExec(crate::gen::RawExec { argv })),
        }
    }

    // -----------------------------------------------------------------------
    // (a) file.read of a temp file → SUCCESS + stdout == contents
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn file_read_returns_contents() {
        let state_dir = TempDir::new("file-read");
        let dedup = crate::dedup::DedupStore::open(state_dir.path()).expect("open dedup");
        let policy = from_toml_str(
            r#"
[[operation]]
name = "file.read"
allowed_args = [["*"]]
"#,
        )
        .expect("parse policy");

        let content = b"hello from dispatch test\n";
        let tmp = TempFile::new("content", content);
        let task = make_task_file_read("t-file-read", &tmp.path_str());

        let result = dispatch_with_runner(&task, &policy, &dedup, execute, None).await;

        assert_eq!(result.task_id, "t-file-read");
        assert_eq!(
            result.outcome,
            Outcome::Success as i32,
            "file.read must succeed; stderr={:?}",
            String::from_utf8_lossy(&result.stderr)
        );
        assert_eq!(result.stdout, content, "stdout must equal file contents");
        assert!(!result.truncated);
    }

    // -----------------------------------------------------------------------
    // (a) raw_exec allowed by policy → SUCCESS (full pipeline)
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn raw_exec_allowed_returns_success() {
        let state_dir = TempDir::new("raw-exec-allow");
        let dedup = crate::dedup::DedupStore::open(state_dir.path()).expect("open dedup");
        let policy = from_toml_str(
            r#"
[raw_exec]
allow = ["^/bin/echo hello$"]
"#,
        )
        .expect("parse policy");

        let task = make_task_raw_exec(
            "t-raw-allow",
            vec!["/bin/echo".to_string(), "hello".to_string()],
        );

        let result = dispatch_with_runner(&task, &policy, &dedup, execute, None).await;

        assert_eq!(result.outcome, Outcome::Success as i32);
        assert_eq!(result.stdout, b"hello\n");
    }

    // -----------------------------------------------------------------------
    // (b) denied raw_exec → DENIED_BY_POLICY, side-effect file absent
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn raw_exec_denied_does_not_spawn() {
        let state_dir = TempDir::new("raw-exec-deny");
        let dedup = crate::dedup::DedupStore::open(state_dir.path()).expect("open dedup");

        // Policy that does NOT allow /bin/sh (deny-by-default).
        let policy = from_toml_str(
            r#"
[raw_exec]
allow = ["^/bin/echo hello$"]
"#,
        )
        .expect("parse policy");

        // Side-effect marker: would be created by /bin/sh if the command ran.
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let marker = std::env::temp_dir().join(format!(
            "relay-dispatch-deny-marker-{}-{}",
            std::process::id(),
            nanos
        ));
        let marker_str = marker.to_string_lossy().into_owned();

        let cmd = format!("echo x > {marker_str}");
        let task = make_task_raw_exec(
            "t-raw-deny",
            vec!["/bin/sh".to_string(), "-c".to_string(), cmd],
        );

        let result = dispatch_with_runner(&task, &policy, &dedup, execute, None).await;

        assert_eq!(
            result.outcome,
            Outcome::DeniedByPolicy as i32,
            "denied raw_exec must yield DENIED_BY_POLICY"
        );
        assert_eq!(result.exit_code, -1);
        assert!(
            !marker.exists(),
            "side-effect marker must not exist — no process must have been spawned"
        );

        let _ = fs::remove_file(&marker);
    }

    // -----------------------------------------------------------------------
    // (c) service.restart with fake runner:
    //     nginx → runner called with [systemctl, restart, nginx] → SUCCESS
    //     sshd  → DENIED_BY_POLICY, runner never called
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn service_restart_nginx_calls_runner() {
        let state_dir = TempDir::new("svc-nginx");
        let dedup = crate::dedup::DedupStore::open(state_dir.path()).expect("open dedup");
        let policy = fixture_policy(); // nginx allowed, sshd denied

        let recorded = Arc::new(Mutex::new(None::<Vec<String>>));
        let rec = recorded.clone();
        let fake_run = move |req: ExecRequest| {
            *rec.lock().unwrap() = Some(req.argv.clone());
            let task_id = req.task_id.clone();
            async move {
                TaskResult {
                    task_id,
                    outcome: Outcome::Success as i32,
                    exit_code: 0,
                    stdout: vec![],
                    stderr: vec![],
                    truncated: false,
                    duration_millis: 0,
                }
            }
        };

        let task = make_task_service_restart("t-nginx", "nginx");
        let result = dispatch_with_runner(&task, &policy, &dedup, fake_run, None).await;

        assert_eq!(
            result.outcome,
            Outcome::Success as i32,
            "nginx restart must succeed"
        );
        let argv = recorded
            .lock()
            .unwrap()
            .clone()
            .expect("runner must be called");
        assert_eq!(
            argv,
            ["systemctl", "restart", "nginx"],
            "runner must receive [systemctl, restart, nginx]"
        );
    }

    #[tokio::test]
    async fn service_restart_sshd_denied_runner_not_called() {
        let state_dir = TempDir::new("svc-sshd");
        let dedup = crate::dedup::DedupStore::open(state_dir.path()).expect("open dedup");
        let policy = fixture_policy(); // sshd not in allowed list → deny-by-default

        let runner_called = Arc::new(AtomicUsize::new(0));
        let calls = runner_called.clone();
        let fake_run = move |req: ExecRequest| {
            calls.fetch_add(1, Ordering::SeqCst);
            let task_id = req.task_id.clone();
            async move {
                TaskResult {
                    task_id,
                    outcome: Outcome::Success as i32,
                    exit_code: 0,
                    stdout: vec![],
                    stderr: vec![],
                    truncated: false,
                    duration_millis: 0,
                }
            }
        };

        let task = make_task_service_restart("t-sshd", "sshd");
        let result = dispatch_with_runner(&task, &policy, &dedup, fake_run, None).await;

        assert_eq!(
            result.outcome,
            Outcome::DeniedByPolicy as i32,
            "sshd restart must be denied"
        );
        assert_eq!(
            runner_called.load(Ordering::SeqCst),
            0,
            "runner must never be called for a denied operation"
        );
    }

    // -----------------------------------------------------------------------
    // pkg.install netcat (not in the fixture's {nginx, curl} allow list) →
    // DENIED_BY_POLICY, runner never called. Host-independent: Policy denies
    // before dispatch ever reaches pkg_install's detect_package_manager, so
    // this test is hermetic regardless of what package manager (if any) is
    // installed on the machine running the test suite. The allow+argv path
    // is covered at the unit level in operations/pkg_install.rs (an injected
    // PackageManager and fake runner — no real package manager needed).
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn pkg_install_netcat_denied_runner_not_called() {
        let state_dir = TempDir::new("pkg-netcat");
        let dedup = crate::dedup::DedupStore::open(state_dir.path()).expect("open dedup");
        let policy = fixture_policy(); // netcat not in allowed list → deny-by-default

        let runner_called = Arc::new(AtomicUsize::new(0));
        let calls = runner_called.clone();
        let fake_run = move |req: ExecRequest| {
            calls.fetch_add(1, Ordering::SeqCst);
            let task_id = req.task_id.clone();
            async move {
                TaskResult {
                    task_id,
                    outcome: Outcome::Success as i32,
                    exit_code: 0,
                    stdout: vec![],
                    stderr: vec![],
                    truncated: false,
                    duration_millis: 0,
                }
            }
        };

        let task = make_task_pkg_install("t-pkg-netcat", "netcat", "");
        let result = dispatch_with_runner(&task, &policy, &dedup, fake_run, None).await;

        assert_eq!(
            result.outcome,
            Outcome::DeniedByPolicy as i32,
            "netcat install must be denied"
        );
        assert_eq!(
            runner_called.load(Ordering::SeqCst),
            0,
            "runner must never be called for a denied operation"
        );
    }

    // -----------------------------------------------------------------------
    // (d) dedup: same task_id twice → runner ran once, 2nd result is benign
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn dedup_same_task_id_runs_once() {
        let state_dir = TempDir::new("dedup-once");
        let dedup = crate::dedup::DedupStore::open(state_dir.path()).expect("open dedup");
        let policy = fixture_policy();

        let runner_calls = Arc::new(AtomicUsize::new(0));
        let calls = runner_calls.clone();
        let fake_run = move |req: ExecRequest| {
            calls.fetch_add(1, Ordering::SeqCst);
            let task_id = req.task_id.clone();
            async move {
                TaskResult {
                    task_id,
                    outcome: Outcome::Success as i32,
                    exit_code: 0,
                    stdout: b"exec output".to_vec(),
                    stderr: vec![],
                    truncated: false,
                    duration_millis: 1,
                }
            }
        };

        let task = make_task_service_restart("dedup-id-1", "nginx");

        let r1 = dispatch_with_runner(&task, &policy, &dedup, fake_run.clone(), None).await;
        let r2 = dispatch_with_runner(&task, &policy, &dedup, fake_run, None).await;

        assert_eq!(
            runner_calls.load(Ordering::SeqCst),
            1,
            "runner must run exactly once for the same task_id"
        );
        assert_eq!(
            r1.stdout, b"exec output",
            "first result must be the exec result"
        );
        // Second result: benign already-processed (dedup.run_once synthesizes this).
        assert!(
            r2.stderr
                .windows(b"already processed".len())
                .any(|w| w == b"already processed"),
            "second result stderr must contain 'already processed'"
        );
    }

    // -----------------------------------------------------------------------
    // (e) policy immutability (Rust-half):
    //     &Policy is a shared borrow — no setter; dispatch only reads it.
    //     raw_exec that would edit the policy file is denied by policy.
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn raw_exec_editing_policy_file_is_denied() {
        // A policy with no raw_exec allow rules → deny-by-default for all raw exec.
        let policy = from_toml_str("").expect("empty policy must parse");
        let state_dir = TempDir::new("policy-immut");
        let dedup = crate::dedup::DedupStore::open(state_dir.path()).expect("open dedup");

        // Construct a raw_exec that would overwrite the policy file if executed.
        // The actual policy path doesn't matter for this test: deny-by-default
        // fires before any process is spawned, regardless of the target file.
        let task = make_task_raw_exec(
            "t-immut-raw",
            vec![
                "/bin/sh".to_string(),
                "-c".to_string(),
                "echo 'allow all' > /etc/relay-daemon/policy.toml".to_string(),
            ],
        );

        let result = dispatch_with_runner(&task, &policy, &dedup, execute, None).await;

        assert_eq!(
            result.outcome,
            Outcome::DeniedByPolicy as i32,
            "raw_exec targeting the policy file must be denied (deny-by-default, no raw_exec allow rule)"
        );
        // No process was spawned → no side effect.
        assert_eq!(result.exit_code, -1);

        // Compile-time proof: Policy has no setter. The following would not compile:
        //   policy.set_operations(vec![]);     // no such method
        //   policy.operations = vec![];        // field is private
        // Verified by the fact that this file compiles with &Policy (shared borrow only).
    }

    // -----------------------------------------------------------------------
    // system.facts (pipeline smoke): allowed → non-empty stdout with key=value
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn system_facts_returns_kv_stdout() {
        let state_dir = TempDir::new("sys-facts");
        let dedup = crate::dedup::DedupStore::open(state_dir.path()).expect("open dedup");
        let policy = from_toml_str(
            r#"
[[operation]]
name = "system.facts"
allowed_args = []
"#,
        )
        .expect("parse policy");

        let task = make_task_system_facts("t-facts");
        let result = dispatch_with_runner(&task, &policy, &dedup, execute, None).await;

        assert_eq!(
            result.outcome,
            Outcome::Success as i32,
            "system.facts must succeed"
        );
        let stdout = String::from_utf8(result.stdout).expect("stdout must be utf-8");
        assert!(
            stdout.contains("hostname="),
            "stdout must contain 'hostname='"
        );
        assert!(stdout.contains("os="), "stdout must contain 'os='");
        assert!(stdout.contains("arch="), "stdout must contain 'arch='");
    }

    // -----------------------------------------------------------------------
    // effective_timeout unit tests
    // -----------------------------------------------------------------------

    #[test]
    fn effective_timeout_zero_gives_default() {
        assert_eq!(effective_timeout(0), DEFAULT_TIMEOUT);
    }

    #[test]
    fn effective_timeout_negative_gives_default() {
        assert_eq!(effective_timeout(-1), DEFAULT_TIMEOUT);
    }

    #[test]
    fn effective_timeout_positive_within_max() {
        assert_eq!(effective_timeout(10), Duration::from_secs(10));
    }

    #[test]
    fn effective_timeout_exceeds_max_is_clamped() {
        // 1000 s > MAX_TIMEOUT (300 s) → clamped to MAX_TIMEOUT.
        assert_eq!(effective_timeout(1000), MAX_TIMEOUT);
    }

    #[test]
    fn effective_timeout_exact_max() {
        assert_eq!(effective_timeout(300), MAX_TIMEOUT);
    }

    // -----------------------------------------------------------------------
    // PolicyQuery tests (acceptance criteria for issue #92)
    // -----------------------------------------------------------------------

    /// Policy used by query tests: explicit allow/deny rules covering all five
    /// matrix cases without reaching the filesystem or spawning real services.
    fn make_query_test_policy() -> crate::policy::Policy {
        from_toml_str(
            r#"
[[operation]]
name = "service.restart"
allowed_args = [["nginx"]]

[[operation]]
name = "file.read"
allowed_args = [["*"]]

[[operation]]
name = "pkg.install"
allowed_args = [["nginx", "curl"], ["*"]]

[[deny]]
name = "file.read"
args = [["/etc/shadow"]]

[raw_exec]
allow = ["^/bin/echo .+$"]
deny = ["secret"]
"#,
        )
        .expect("query test policy must parse")
    }

    fn make_policy_query_operation(
        query_id: &str,
        name: &str,
        key: &str,
        val: &str,
    ) -> crate::gen::PolicyQuery {
        let mut args = std::collections::HashMap::new();
        if !key.is_empty() {
            args.insert(key.to_string(), val.to_string());
        }
        crate::gen::PolicyQuery {
            query_id: query_id.to_string(),
            action: Some(policy_query::Action::Operation(crate::gen::Operation {
                name: name.to_string(),
                args,
            })),
        }
    }

    fn make_policy_query_raw_exec(query_id: &str, argv: Vec<String>) -> crate::gen::PolicyQuery {
        crate::gen::PolicyQuery {
            query_id: query_id.to_string(),
            action: Some(policy_query::Action::RawExec(crate::gen::RawExec { argv })),
        }
    }

    /// Policy query verdict must match the outcome of actually dispatching the same
    /// action (ADR-0011: the same engine methods are called; no divergence possible).
    ///
    /// The matrix covers seven distinct cases: allowed operation, denied operation
    /// (deny-by-default), denied operation (deny-beats-allow), allowed raw exec,
    /// denied raw exec (deny-beats-allow), and an allowed/denied `pkg.install` pair
    /// (deny-by-default, argument-level — ADR-0002). Each case is checked against
    /// BOTH the query verdict and the dispatch result so a single test enforces
    /// consistency.
    #[tokio::test]
    async fn policy_query_verdict_matches_execution() {
        let policy = make_query_test_policy();
        let state_dir = TempDir::new("pq-matrix");
        let dedup = crate::dedup::DedupStore::open(state_dir.path()).expect("open dedup");

        // Fake runner: always returns Success — hermetic for service.restart.
        // Raw exec goes through run_raw_exec → execute() internally, not this closure.
        let fake_run = move |req: ExecRequest| {
            let task_id = req.task_id.clone();
            async move {
                TaskResult {
                    task_id,
                    outcome: Outcome::Success as i32,
                    exit_code: 0,
                    stdout: vec![],
                    stderr: vec![],
                    truncated: false,
                    duration_millis: 0,
                }
            }
        };

        struct Case {
            label: &'static str,
            query: crate::gen::PolicyQuery,
            task: TaskRequest,
            expected_allowed: bool,
        }

        let cases = vec![
            // (1) service.restart nginx -> allowed
            Case {
                label: "service.restart nginx",
                query: make_policy_query_operation(
                    "q1",
                    operations::SERVICE_RESTART,
                    OP_ARG_UNIT,
                    "nginx",
                ),
                task: make_task_service_restart("pq-t1", "nginx"),
                expected_allowed: true,
            },
            // (2) service.restart sshd -> deny-by-default
            Case {
                label: "service.restart sshd",
                query: make_policy_query_operation(
                    "q2",
                    operations::SERVICE_RESTART,
                    OP_ARG_UNIT,
                    "sshd",
                ),
                task: make_task_service_restart("pq-t2", "sshd"),
                expected_allowed: false,
            },
            // (3) file.read /etc/shadow -> deny-beats-allow
            Case {
                label: "file.read /etc/shadow",
                query: make_policy_query_operation(
                    "q3",
                    operations::FILE_READ,
                    OP_ARG_PATH,
                    "/etc/shadow",
                ),
                task: make_task_file_read("pq-t3", "/etc/shadow"),
                expected_allowed: false,
            },
            // (4) /bin/echo hi -> allowed raw exec
            Case {
                label: "/bin/echo hi (allowed)",
                query: make_policy_query_raw_exec("q4", vec!["/bin/echo".into(), "hi".into()]),
                task: make_task_raw_exec("pq-t4", vec!["/bin/echo".into(), "hi".into()]),
                expected_allowed: true,
            },
            // (5) /bin/echo secret -> deny-beats-allow (deny pattern "secret")
            Case {
                label: "/bin/echo secret (denied)",
                query: make_policy_query_raw_exec("q5", vec!["/bin/echo".into(), "secret".into()]),
                task: make_task_raw_exec("pq-t5", vec!["/bin/echo".into(), "secret".into()]),
                expected_allowed: false,
            },
            // (6) pkg.install nginx -> allowed. NOTE: the dispatch side calls the
            // production pkg_install entry, which runs detect_package_manager()
            // against the real host — outside this test's control. The core
            // assertion below only checks "not DENIED_BY_POLICY" (exec_allowed),
            // never Outcome::Success, so this case is host-independent: whether
            // the host has apt/dnf/yum installed, a Policy-allowed install is
            // never DENIED_BY_POLICY.
            Case {
                label: "pkg.install nginx",
                query: make_policy_query_operation(
                    "q6",
                    operations::PKG_INSTALL,
                    OP_ARG_NAME,
                    "nginx",
                ),
                task: make_task_pkg_install("pq-t6", "nginx", ""),
                expected_allowed: true,
            },
            // (7) pkg.install netcat -> deny-by-default (not in {nginx, curl})
            Case {
                label: "pkg.install netcat",
                query: make_policy_query_operation(
                    "q7",
                    operations::PKG_INSTALL,
                    OP_ARG_NAME,
                    "netcat",
                ),
                task: make_task_pkg_install("pq-t7", "netcat", ""),
                expected_allowed: false,
            },
        ];

        for case in &cases {
            let verdict = evaluate_policy_query(&case.query, &policy);
            let result = dispatch_with_runner(&case.task, &policy, &dedup, fake_run, None).await;

            // Core assertion: verdict matches execution outcome.
            let exec_allowed = result.outcome != Outcome::DeniedByPolicy as i32;
            assert_eq!(
                verdict.allowed,
                exec_allowed,
                "[{label}] verdict.allowed ({}) != exec_allowed ({})",
                verdict.allowed,
                exec_allowed,
                label = case.label,
            );
            assert_eq!(
                verdict.allowed,
                case.expected_allowed,
                "[{label}] verdict.allowed ({}) != expected ({})",
                verdict.allowed,
                case.expected_allowed,
                label = case.label,
            );

            // Deny verdicts must carry a non-empty deciding_rule.
            if !verdict.allowed {
                assert!(
                    !verdict.deciding_rule.is_empty(),
                    "[{}] deny verdict must have a non-empty deciding_rule",
                    case.label,
                );
            }
        }

        // Case (3): file.read /etc/shadow — deny-beats-allow; deciding_rule must name the rule.
        {
            let verdict = evaluate_policy_query(&cases[2].query, &policy);
            assert!(
                verdict.deciding_rule.contains("file.read"),
                "case (3) deciding_rule must name the file.read deny rule; got {:?}",
                verdict.deciding_rule,
            );
        }

        // Case (5): /bin/echo secret — deny-beats-allow; deciding_rule must name the deny pattern.
        {
            let verdict = evaluate_policy_query(&cases[4].query, &policy);
            assert!(
                verdict.deciding_rule.contains("secret"),
                "case (5) deciding_rule must name the deny pattern; got {:?}",
                verdict.deciding_rule,
            );
        }
    }

    /// Identity test (issue #186): for each Policy-deny form on the Operation
    /// path (no-rule, args-mismatch, explicit-deny), the plan-verdict
    /// `deciding_rule` from `evaluate_policy_query` must be byte-for-byte
    /// identical to the apply-path stderr from a real `dispatch`, for the
    /// same input. This is the DoD's "identical for the same input" check,
    /// exercised through both real code paths — not just the shared `reason`
    /// source in isolation — mirroring the harness in
    /// `policy_query_verdict_matches_execution` above.
    #[tokio::test]
    async fn deny_reason_identical_between_verdict_and_stderr() {
        let policy = make_query_test_policy();
        let state_dir = TempDir::new("deny-reason-identity");
        let dedup = crate::dedup::DedupStore::open(state_dir.path()).expect("open dedup");
        let scheduler = Scheduler::new();

        struct Case {
            label: &'static str,
            query: crate::gen::PolicyQuery,
            task: TaskRequest,
        }

        let cases = vec![
            // (a) no-rule: an operation name absent from the Policy entirely.
            Case {
                label: "no-rule (unknown operation)",
                query: make_policy_query_operation("q-no-rule", "totally.unknown", "", ""),
                task: TaskRequest {
                    task_id: "identity-no-rule".to_string(),
                    timeout_seconds: 5,
                    action: Some(task_request::Action::Operation(crate::gen::Operation {
                        name: "totally.unknown".to_string(),
                        args: Default::default(),
                    })),
                },
            },
            // (b) args-mismatch: service.restart is an allowed operation, but
            // "sshd" is not an allowed arg.
            Case {
                label: "args-mismatch (service.restart sshd)",
                query: make_policy_query_operation(
                    "q-args-mismatch",
                    operations::SERVICE_RESTART,
                    OP_ARG_UNIT,
                    "sshd",
                ),
                task: make_task_service_restart("identity-args-mismatch", "sshd"),
            },
            // (c) explicit-deny: file.read /etc/shadow (deny-beats-allow).
            Case {
                label: "explicit-deny (file.read /etc/shadow)",
                query: make_policy_query_operation(
                    "q-explicit-deny",
                    operations::FILE_READ,
                    OP_ARG_PATH,
                    "/etc/shadow",
                ),
                task: make_task_file_read("identity-explicit-deny", "/etc/shadow"),
            },
        ];

        for case in &cases {
            let verdict = evaluate_policy_query(&case.query, &policy);
            let result = dispatch(
                &case.task,
                &policy,
                &dedup,
                &scheduler,
                tokio::time::Instant::now(),
                None,
            )
            .await;

            assert_eq!(
                result.outcome,
                Outcome::DeniedByPolicy as i32,
                "[{}] must be denied by policy",
                case.label,
            );
            assert_eq!(
                verdict.deciding_rule,
                String::from_utf8_lossy(&result.stderr),
                "[{}] plan-verdict deciding_rule must be identical to the apply-path stderr",
                case.label,
            );
        }
    }

    /// A PolicyQuery allowed by Policy must not spawn any process and must not
    /// record a dedup marker — the query path is structurally incapable of both
    /// (it takes no DedupStore and never reaches the executor).
    ///
    /// The absence of a `DedupStore` parameter on `evaluate_policy_query` is the
    /// compile-time proof that it cannot record a dedup marker.
    #[test]
    fn policy_query_spawns_no_process_and_records_no_dedup() {
        // Policy that allows /bin/sh so the verdict is "allowed" — proving the
        // test exercises the allow path, not the deny path.
        let policy = from_toml_str(
            r#"
[raw_exec]
allow = ["^/bin/sh"]
"#,
        )
        .expect("policy must parse");

        // Marker file: would be created by the shell if anything were spawned.
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let marker = std::env::temp_dir().join(format!(
            "relay-pq-spawn-marker-{}-{}",
            std::process::id(),
            nanos
        ));
        let marker_str = marker.to_string_lossy().into_owned();

        let cmd = format!("echo x > {marker_str}");
        let query =
            make_policy_query_raw_exec("pq-no-spawn", vec!["/bin/sh".into(), "-c".into(), cmd]);

        let verdict = evaluate_policy_query(&query, &policy);

        // Verdict must be "allowed" so we know the policy gate passed.
        assert!(
            verdict.allowed,
            "verdict must be allowed; policy allows /bin/sh"
        );
        // Nothing was spawned — the marker must not exist.
        assert!(
            !marker.exists(),
            "marker must not exist — evaluate_policy_query must never spawn a process"
        );
        let _ = fs::remove_file(&marker);

        // No-dedup: build a fresh DedupStore and verify the seen-tasks dir has
        // zero entries after calling evaluate_policy_query (which takes no store).
        let state_dir = TempDir::new("pq-no-dedup");
        // evaluate_policy_query is a sync fn; call it — compile-time proof that
        // it does not accept a DedupStore parameter.
        let _verdict2 = evaluate_policy_query(&query, &policy);

        // The seen-tasks dir may not even exist (DedupStore was never opened).
        // Treat "absent or empty" as pass.
        let seen_dir = state_dir.path().join("seen-tasks");
        if seen_dir.exists() {
            let entries: Vec<_> = fs::read_dir(&seen_dir).expect("read seen-tasks").collect();
            assert!(
                entries.is_empty(),
                "seen-tasks dir must be empty; evaluate_policy_query must not record any dedup markers"
            );
        }
    }

    /// Malformed PolicyQuery actions must always produce a deny verdict with a
    /// non-empty deciding_rule — never a panic, never a dropped message.
    #[test]
    fn policy_query_malformed_action_denies() {
        let policy = from_toml_str("").expect("empty policy must parse");

        // (a) action: None — protocol error; must deny with deciding_rule set.
        let query_none = crate::gen::PolicyQuery {
            query_id: "pq-malformed-none".to_string(),
            action: None,
        };
        let verdict = evaluate_policy_query(&query_none, &policy);
        assert!(!verdict.allowed, "None action must be denied");
        assert!(
            !verdict.deciding_rule.is_empty(),
            "None action deny must carry a non-empty deciding_rule; got {:?}",
            verdict.deciding_rule,
        );

        // (b) Unknown operation name — deny-by-default, no panic.
        let query_unknown =
            make_policy_query_operation("pq-malformed-op", "completely.unknown.operation", "", "");
        let verdict_unknown = evaluate_policy_query(&query_unknown, &policy);
        assert!(
            !verdict_unknown.allowed,
            "unknown operation must be denied by default"
        );
        assert!(
            !verdict_unknown.deciding_rule.is_empty(),
            "unknown operation deny must carry a non-empty deciding_rule; got {:?}",
            verdict_unknown.deciding_rule,
        );
    }

    // -----------------------------------------------------------------------
    // ACCEPTANCE-CRITICAL [AC3] (issue #90): a cancelled task_id stays in the
    // dedup store. A re-sent TaskRequest with the same id is deduped, not re-run.
    // -----------------------------------------------------------------------
    #[tokio::test]
    async fn cancelled_task_id_is_deduped_on_resend() {
        let state_dir = TempDir::new("dedup-cancel");
        let dedup = crate::dedup::DedupStore::open(state_dir.path()).expect("open dedup");

        // Policy allows the sleep command via raw exec.
        let policy = from_toml_str(
            r#"
[raw_exec]
allow = ["^/bin/sh "]
"#,
        )
        .expect("parse policy");

        let task = make_task_raw_exec(
            "cancel-dedup-id-1",
            vec![
                "/bin/sh".to_string(),
                "-c".to_string(),
                "sleep 30".to_string(),
            ],
        );

        // Send cancel before the dispatch future is awaited. The signal is buffered
        // in the oneshot channel. When execute's select! runs, the child (sleep 30)
        // hasn't exited, so the cancel arm fires immediately → Cancelled.
        let (cancel_tx, cancel_rx) = tokio::sync::oneshot::channel::<()>();
        cancel_tx
            .send(())
            .expect("cancel send must succeed (buffered)");

        // First dispatch: real execute runner; cancel fires immediately.
        let r1 = dispatch_with_runner(&task, &policy, &dedup, execute, Some(cancel_rx)).await;

        assert_eq!(
            r1.outcome,
            Outcome::Cancelled as i32,
            "first dispatch must yield Cancelled"
        );

        // Second dispatch: same task_id, no cancel — must be deduped (runner not called).
        let runner_calls = Arc::new(AtomicUsize::new(0));
        let calls = runner_calls.clone();
        let fake_run = move |req: ExecRequest| {
            calls.fetch_add(1, Ordering::SeqCst);
            let task_id = req.task_id.clone();
            async move {
                TaskResult {
                    task_id,
                    outcome: Outcome::Success as i32,
                    exit_code: 0,
                    stdout: vec![],
                    stderr: vec![],
                    truncated: false,
                    duration_millis: 0,
                }
            }
        };

        let r2 = dispatch_with_runner(&task, &policy, &dedup, fake_run, None).await;

        assert_eq!(
            runner_calls.load(Ordering::SeqCst),
            0,
            "runner must NOT be called on re-send of a cancelled task_id (deduped)"
        );
        assert!(
            r2.stderr
                .windows(b"already processed".len())
                .any(|w| w == b"already processed"),
            "second result must be benign already-processed"
        );
    }

    // -----------------------------------------------------------------------
    // ACCEPTANCE-CRITICAL [AC1] (issue #91): two mutate Tasks dispatched
    // concurrently via the scheduler must never execute simultaneously.
    // An injected slow runner asserts the concurrency gauge never exceeds 1.
    // -----------------------------------------------------------------------
    #[tokio::test]
    async fn ac1_two_mutate_tasks_never_overlap() {
        let state_dir = TempDir::new("sched-m-overlap");
        let dedup = crate::dedup::DedupStore::open(state_dir.path()).expect("open dedup");
        let policy = fixture_policy(); // nginx allowed (service.restart = MUTATE)
        let scheduler = crate::scheduler::Scheduler::new();
        let received_at = tokio::time::Instant::now();

        let current = Arc::new(AtomicUsize::new(0));
        let peak = Arc::new(AtomicUsize::new(0));

        let cur1 = Arc::clone(&current);
        let pk1 = Arc::clone(&peak);
        let slow_run = move |req: ExecRequest| {
            let cur = Arc::clone(&cur1);
            let pk = Arc::clone(&pk1);
            let task_id = req.task_id.clone();
            async move {
                let n = cur.fetch_add(1, Ordering::SeqCst) + 1;
                pk.fetch_max(n, Ordering::SeqCst);
                tokio::time::sleep(std::time::Duration::from_millis(40)).await;
                cur.fetch_sub(1, Ordering::SeqCst);
                TaskResult {
                    task_id,
                    outcome: Outcome::Success as i32,
                    exit_code: 0,
                    stdout: vec![],
                    stderr: vec![],
                    truncated: false,
                    duration_millis: 40,
                }
            }
        };

        // Two distinct task IDs for nginx — both are MUTATE (service.restart).
        let task1 = make_task_service_restart("sched-m1", "nginx");
        let task2 = make_task_service_restart("sched-m2", "nginx");

        let (r1, r2) = tokio::join!(
            dispatch_scheduled_with_runner(
                &task1,
                &policy,
                &dedup,
                &scheduler,
                received_at,
                slow_run.clone(),
                None
            ),
            dispatch_scheduled_with_runner(
                &task2,
                &policy,
                &dedup,
                &scheduler,
                received_at,
                slow_run,
                None
            ),
        );

        assert_eq!(r1.outcome, Outcome::Success as i32, "task1 must succeed");
        assert_eq!(r2.outcome, Outcome::Success as i32, "task2 must succeed");
        assert_eq!(
            peak.load(Ordering::SeqCst),
            1,
            "mutate Tasks must NEVER overlap: peak concurrent runners must be 1"
        );
    }

    // -----------------------------------------------------------------------
    // Queued-timeout: a Task whose deadline expires while waiting in the queue
    // reports OUTCOME_TIMEOUT, the runner is never called, and the task_id is
    // deduped on re-send (ADR-0004 at-most-once for queued exits).
    // -----------------------------------------------------------------------
    #[tokio::test]
    async fn queued_timeout_outcome_no_runner_then_deduped() {
        let state_dir = TempDir::new("sched-qt");
        let dedup = crate::dedup::DedupStore::open(state_dir.path()).expect("open dedup");
        // Policy allows the operation (Policy gate must not fire before scheduler).
        let policy = fixture_policy();
        let scheduler = crate::scheduler::Scheduler::new();

        let runner_calls = Arc::new(AtomicUsize::new(0));
        let calls = Arc::clone(&runner_calls);
        let fake_run = move |req: ExecRequest| {
            calls.fetch_add(1, Ordering::SeqCst);
            let task_id = req.task_id.clone();
            async move {
                TaskResult {
                    task_id,
                    outcome: Outcome::Success as i32,
                    exit_code: 0,
                    stdout: vec![],
                    stderr: vec![],
                    truncated: false,
                    duration_millis: 0,
                }
            }
        };

        // Use a received_at far in the past so the deadline is already expired.
        // effective_timeout(5) = 5s; deadline = (now - 100s) + 5s = now - 95s (past).
        let received_at = tokio::time::Instant::now() - std::time::Duration::from_secs(100);

        let task = make_task_service_restart("sched-qt-1", "nginx");
        let result = dispatch_scheduled_with_runner(
            &task,
            &policy,
            &dedup,
            &scheduler,
            received_at,
            fake_run.clone(),
            None,
        )
        .await;

        assert_eq!(
            result.outcome,
            Outcome::Timeout as i32,
            "expired deadline must yield OUTCOME_TIMEOUT"
        );
        assert_eq!(result.exit_code, -1, "queued-timeout exit_code must be -1");
        assert_eq!(
            runner_calls.load(Ordering::SeqCst),
            0,
            "runner must never be called when Task expires in the queue"
        );

        // Re-dispatch same task_id → deduped benign (at-most-once: id recorded before queue).
        let result2 = dispatch_scheduled_with_runner(
            &task,
            &policy,
            &dedup,
            &scheduler,
            tokio::time::Instant::now(),
            fake_run,
            None,
        )
        .await;
        assert!(
            result2
                .stderr
                .windows(b"already processed".len())
                .any(|w| w == b"already processed"),
            "re-dispatched queued-timeout task_id must be deduped (already processed)"
        );
        assert_eq!(
            runner_calls.load(Ordering::SeqCst),
            0,
            "runner must not be called on the deduped re-send"
        );
    }

    // -----------------------------------------------------------------------
    // Queued-cancel: a Task cancelled while waiting in the queue reports
    // OUTCOME_CANCELLED, the runner is never called, and the task_id is deduped
    // on re-send (ADR-0004, ADR-0013: queued-cancel never spawns; id stays recorded).
    // -----------------------------------------------------------------------
    #[tokio::test]
    async fn queued_cancel_outcome_no_runner_then_deduped() {
        let state_dir = TempDir::new("sched-qc");
        let dedup = crate::dedup::DedupStore::open(state_dir.path()).expect("open dedup");
        let policy = fixture_policy();
        let scheduler = crate::scheduler::Scheduler::new();

        // Occupy the mutate gate so the Task queues (doesn't acquire immediately).
        let mut blocker_cancel = None;
        let _blocker_permit = scheduler
            .acquire(
                crate::scheduler::Class::Mutate,
                tokio::time::Instant::now() + std::time::Duration::from_secs(60),
                &mut blocker_cancel,
            )
            .await
            .expect("blocker must acquire mutate gate");

        let runner_calls = Arc::new(AtomicUsize::new(0));
        let calls = Arc::clone(&runner_calls);
        let fake_run = move |req: ExecRequest| {
            calls.fetch_add(1, Ordering::SeqCst);
            let task_id = req.task_id.clone();
            async move {
                TaskResult {
                    task_id,
                    outcome: Outcome::Success as i32,
                    exit_code: 0,
                    stdout: vec![],
                    stderr: vec![],
                    truncated: false,
                    duration_millis: 0,
                }
            }
        };

        // Set up cancel: fire after a short delay (after the dispatch is queued).
        let (cancel_tx, cancel_rx) = tokio::sync::oneshot::channel::<()>();
        tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            let _ = cancel_tx.send(());
        });

        let task = make_task_service_restart("sched-qc-1", "nginx");
        let received_at = tokio::time::Instant::now();
        let result = dispatch_scheduled_with_runner(
            &task,
            &policy,
            &dedup,
            &scheduler,
            received_at,
            fake_run.clone(),
            Some(cancel_rx),
        )
        .await;

        assert_eq!(
            result.outcome,
            Outcome::Cancelled as i32,
            "queued cancel must yield OUTCOME_CANCELLED"
        );
        assert_eq!(result.exit_code, -1, "queued-cancel exit_code must be -1");
        assert_eq!(
            runner_calls.load(Ordering::SeqCst),
            0,
            "runner must never be called when Task is cancelled in the queue"
        );

        // Re-dispatch same task_id → deduped benign (id stays recorded per ADR-0004).
        drop(_blocker_permit); // release the gate so the re-send can proceed
        let result2 = dispatch_scheduled_with_runner(
            &task,
            &policy,
            &dedup,
            &scheduler,
            tokio::time::Instant::now(),
            fake_run,
            None,
        )
        .await;
        assert!(
            result2
                .stderr
                .windows(b"already processed".len())
                .any(|w| w == b"already processed"),
            "re-dispatched queued-cancel task_id must be deduped (already processed)"
        );
        assert_eq!(
            runner_calls.load(Ordering::SeqCst),
            0,
            "runner must not be called on the deduped re-send"
        );
    }

    // -----------------------------------------------------------------------
    // M4: queued timeout-clock carryover (issue #127).
    //
    // queued_timeout_outcome_no_runner_then_deduped above only proves the
    // deadline is rooted at received_at using an ALREADY-EXPIRED deadline,
    // which fires on the very first select! poll — a good but limited proxy.
    // The two tests below use tokio's paused/virtual clock (already enabled
    // by the dev-only `test-util` feature and used in executor.rs:597) to
    // prove the stronger, previously-untested properties: (a) a deadline that
    // is genuinely in the FUTURE at dispatch still fires while the Task
    // remains queued behind a live blocker, and (b) time spent queued is
    // deducted from the executor's budget from a SINGLE clock (not reset to
    // a fresh effective_timeout once the gate frees up).
    //
    // NOT tested here: the `remaining.is_zero()` post-acquire branch at
    // dispatch.rs:193 (a deadline that elapses in the narrow window between
    // `scheduler.acquire` returning `Ok` and the subsequent `Instant::now()`
    // read). This is intentionally not covered — see the comment above
    // `queued_task_deadline_fires_while_genuinely_queued` below for why it is
    // not deterministically reachable at this seam without a product-side
    // clock injection point (out of scope for a test-only change).
    // -----------------------------------------------------------------------

    // M4(a): a Task whose deadline is genuinely in the future at dispatch
    // still times out while queued behind a live (never-released) blocker —
    // as opposed to the already-past-deadline case covered by
    // queued_timeout_outcome_no_runner_then_deduped above.
    #[tokio::test(start_paused = true)]
    async fn queued_task_deadline_fires_while_genuinely_queued() {
        let state_dir = TempDir::new("sched-qt-live");
        let dedup = crate::dedup::DedupStore::open(state_dir.path()).expect("open dedup");
        let policy = fixture_policy();
        let scheduler = crate::scheduler::Scheduler::new();

        // Occupy the mutate gate with a permit that is never released within
        // this test, so the Task under test genuinely queues rather than
        // acquiring immediately.
        let mut blocker_cancel = None;
        let _blocker_permit = scheduler
            .acquire(
                crate::scheduler::Class::Mutate,
                tokio::time::Instant::now() + std::time::Duration::from_secs(3600),
                &mut blocker_cancel,
            )
            .await
            .expect("blocker must acquire mutate gate");

        let runner_calls = Arc::new(AtomicUsize::new(0));
        let calls = Arc::clone(&runner_calls);
        let fake_run = move |req: ExecRequest| {
            calls.fetch_add(1, Ordering::SeqCst);
            let task_id = req.task_id.clone();
            async move {
                TaskResult {
                    task_id,
                    outcome: Outcome::Success as i32,
                    exit_code: 0,
                    stdout: vec![],
                    stderr: vec![],
                    truncated: false,
                    duration_millis: 0,
                }
            }
        };

        // received_at = t0 (paused clock). make_task_service_restart sets
        // timeout_seconds = 5, so effective_timeout(5) = 5s -> deadline =
        // t0 + 5s, IN THE FUTURE at dispatch (the distinguishing property vs.
        // queued_timeout_outcome_no_runner_then_deduped's 100s-past
        // received_at, which fires on the very first poll). The blocker
        // never releases the gate, so the only pending timer for the whole
        // test is acquire's `sleep_until(deadline)`; with nothing else
        // runnable, the paused runtime auto-advances virtual time to it.
        let received_at = tokio::time::Instant::now();
        let task = make_task_service_restart("sched-qt-live-1", "nginx");
        let result = dispatch_scheduled_with_runner(
            &task,
            &policy,
            &dedup,
            &scheduler,
            received_at,
            fake_run,
            None,
        )
        .await;

        assert_eq!(
            result.outcome,
            Outcome::Timeout as i32,
            "deadline firing while genuinely queued must yield OUTCOME_TIMEOUT"
        );
        assert_eq!(result.exit_code, -1, "queued-timeout exit_code must be -1");
        assert_eq!(
            runner_calls.load(Ordering::SeqCst),
            0,
            "runner must never be called when the Task times out while queued"
        );
        // Paused-clock elapsed time is exactly 5000ms (not merely "close to"
        // or "at least"): received_at.elapsed() in virtual time proves the
        // clock genuinely ran across ~5s of queue-wait, not a first-poll
        // expiry. A clock rooted at dispatch-time (not received_at) would
        // never reach the deadline while queued and this would never fire.
        assert_eq!(
            result.duration_millis, 5000,
            "queued-timeout duration_millis must be exactly the 5s effective \
             timeout measured from received_at"
        );
    }

    // M4(b): the single received_at clock deducts real queue-wait time from
    // the executor's budget — a Task that waits ~3s behind a live blocker
    // must receive ~2s remaining, not a fresh 5s effective_timeout.
    #[tokio::test(start_paused = true)]
    async fn queued_wait_deducts_from_exec_budget_single_clock() {
        let state_dir = TempDir::new("sched-carryover");
        let dedup = crate::dedup::DedupStore::open(state_dir.path()).expect("open dedup");
        let policy = fixture_policy();
        let scheduler = crate::scheduler::Scheduler::new();
        let received_at = tokio::time::Instant::now();

        // task1 (blocker): acquires the single mutate permit immediately and
        // holds it for 3 virtual seconds before completing.
        let blocker_run = |req: ExecRequest| {
            let task_id = req.task_id.clone();
            async move {
                tokio::time::sleep(std::time::Duration::from_secs(3)).await;
                TaskResult {
                    task_id,
                    outcome: Outcome::Success as i32,
                    exit_code: 0,
                    stdout: vec![],
                    stderr: vec![],
                    truncated: false,
                    duration_millis: 3000,
                }
            }
        };

        // task2 (under test): records the REMAINING budget the executor
        // actually receives and returns immediately.
        let recorded_timeout: Arc<Mutex<Option<Duration>>> = Arc::new(Mutex::new(None));
        let rec = Arc::clone(&recorded_timeout);
        let probe_run = move |req: ExecRequest| {
            *rec.lock().unwrap() = Some(req.timeout);
            let task_id = req.task_id.clone();
            async move {
                TaskResult {
                    task_id,
                    outcome: Outcome::Success as i32,
                    exit_code: 0,
                    stdout: vec![],
                    stderr: vec![],
                    truncated: false,
                    duration_millis: 0,
                }
            }
        };

        let task1 = make_task_service_restart("sched-co-blocker", "nginx");
        let task2 = make_task_service_restart("sched-co-probe", "nginx");

        // join! polls task1 first: it takes the (single) mutate permit and
        // suspends on its 3s sleep, still holding the permit. task2 then
        // queues on the semaphore. The only pending timers are task1's 3s
        // sleep and task2's 5s deadline; the paused clock auto-advances to
        // the earlier one (3s), releasing the permit to task2, which then
        // computes remaining = deadline(t0+5s) - now(t0+3s) = exactly 2s.
        let (r1, r2) = tokio::join!(
            dispatch_scheduled_with_runner(
                &task1,
                &policy,
                &dedup,
                &scheduler,
                received_at,
                blocker_run,
                None,
            ),
            dispatch_scheduled_with_runner(
                &task2,
                &policy,
                &dedup,
                &scheduler,
                received_at,
                probe_run,
                None,
            ),
        );

        assert_eq!(
            r1.outcome,
            Outcome::Success as i32,
            "blocker task must succeed"
        );
        assert_eq!(
            r2.outcome,
            Outcome::Success as i32,
            "probe task must succeed"
        );

        let got = recorded_timeout
            .lock()
            .unwrap()
            .expect("probe runner must have been called");
        assert_eq!(
            got,
            Duration::from_secs(2),
            "the executor must receive the REMAINING budget (5s effective - \
             3s queue-wait = 2s), not a fresh 5s effective_timeout; a \
             regression handing the executor a fresh budget would record 5s \
             here instead"
        );
    }
}

// ---------------------------------------------------------------------------
// Property tests (issue #218) — bounded proptest fuzzing of the dispatch
// pipeline, the risk-class/timeout helpers, and the Operation validators.
// ---------------------------------------------------------------------------
//
// Red-team posture: this suite ATTACKS the dedup -> schedule -> Policy ->
// execute pipeline for panics and invariant violations. It asserts only
// invariants the pipeline already implements — a Deny never reaches the
// runner, the gate-allowed argv is byte-identical to the runner-received
// argv (ADR-0001), at-most-once dedup (ADR-0004), the strict risk-class lane
// (ADR-0012), and the bounded timeout — and never changes dispatch, the
// scheduler, or the validators. A drift between an assertion and the real
// behavior is a TEST bug — fix the test, never the production code.
//
// This module is a sibling of `mod tests` above; it never edits it and
// builds its own fixtures and its own self-cleaning temp-dir helper rather
// than reaching into that private sibling module's `TempDir`.
#[cfg(test)]
mod proptests {
    use std::fs;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use proptest::prelude::*;

    use super::*;
    use crate::gen::RawExec;
    use crate::policy::from_toml_str;
    use crate::scheduler::Class;

    // -------------------------------------------------------------------
    // Self-cleaning temp dir for a fresh `DedupStore` per proptest case.
    // Deliberately NOT the private `TempDir` in `mod tests` (disjointness:
    // this module must not touch that sibling test module).
    // -------------------------------------------------------------------

    static PT_SEQ: AtomicU64 = AtomicU64::new(0);

    struct PtTempDir(PathBuf);

    impl PtTempDir {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "relay-pt-{}-{}",
                std::process::id(),
                PT_SEQ.fetch_add(1, Ordering::SeqCst)
            ));
            fs::create_dir_all(&path).expect("create PtTempDir");
            PtTempDir(path)
        }

        fn path(&self) -> &std::path::Path {
            &self.0
        }
    }

    impl Drop for PtTempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    /// A canned `OUTCOME_SUCCESS` result — existing tests inline this; a
    /// helper keeps the fake runners in this module terse.
    fn ok_result(task_id: String) -> TaskResult {
        TaskResult {
            task_id,
            outcome: Outcome::Success as i32,
            exit_code: 0,
            stdout: vec![],
            stderr: vec![],
            truncated: false,
            duration_millis: 0,
        }
    }

    /// The ONLY policy used by the pipeline properties (P1, P3): allows
    /// `service.restart` with any single unit, everything else is
    /// deny-by-default. This is the single design choice that keeps the
    /// pipeline properties fully hermetic and host-independent — every
    /// fuzzed action other than an allowed `service.restart` is denied
    /// before any spawn / file-read / `detect_package_manager` call, and the
    /// one path that does reach the injected recording runner produces the
    /// deterministic argv `[systemctl, restart, <unit>]`.
    fn pipeline_policy() -> Policy {
        from_toml_str("[[operation]]\nname = \"service.restart\"\nallowed_args = [[\"*\"]]\n")
            .expect("pipeline_policy TOML must parse")
    }

    // -------------------------------------------------------------------
    // Bounded strategies
    // -------------------------------------------------------------------

    /// A non-empty, short task id — `record_marker` (dedup.rs) never fails
    /// on a filename this small.
    fn arb_task_id() -> impl Strategy<Value = String> {
        prop::string::string_regex("[A-Za-z0-9._-]{1,24}").unwrap()
    }

    /// One argv/arg element: full-Unicode (including control chars), 0-8
    /// chars — bounded but wide enough to probe the panic surface.
    fn arb_argv_elem() -> impl Strategy<Value = String> {
        prop::collection::vec(any::<char>(), 0..8).prop_map(|cs| cs.into_iter().collect())
    }

    /// A bounded argv vector, 0-6 elements.
    fn arb_argv() -> impl Strategy<Value = Vec<String>> {
        prop::collection::vec(arb_argv_elem(), 0..6)
    }

    /// A `service.restart` unit: usually a plausible name, occasionally an
    /// arbitrary (possibly charset-invalid) element.
    fn arb_unit() -> impl Strategy<Value = String> {
        prop_oneof![
            Just("nginx".to_string()),
            Just("curl".to_string()),
            arb_argv_elem(),
        ]
    }

    /// One `TaskRequest::action` variant: RawExec, one of the four known
    /// Operations, or an unknown Operation name.
    fn arb_action() -> impl Strategy<Value = task_request::Action> {
        prop_oneof![
            arb_argv().prop_map(|argv| task_request::Action::RawExec(RawExec { argv })),
            arb_unit().prop_map(|unit| {
                let mut args = std::collections::HashMap::new();
                args.insert(OP_ARG_UNIT.to_string(), unit);
                task_request::Action::Operation(Operation {
                    name: operations::SERVICE_RESTART.to_string(),
                    args,
                })
            }),
            arb_argv_elem().prop_map(|path| {
                let mut args = std::collections::HashMap::new();
                args.insert(OP_ARG_PATH.to_string(), path);
                task_request::Action::Operation(Operation {
                    name: operations::FILE_READ.to_string(),
                    args,
                })
            }),
            (arb_argv_elem(), arb_argv_elem()).prop_map(|(name, version)| {
                let mut args = std::collections::HashMap::new();
                args.insert(OP_ARG_NAME.to_string(), name);
                args.insert(OP_ARG_VERSION.to_string(), version);
                task_request::Action::Operation(Operation {
                    name: operations::PKG_INSTALL.to_string(),
                    args,
                })
            }),
            arb_argv_elem().prop_map(|name| {
                task_request::Action::Operation(Operation {
                    name,
                    args: std::collections::HashMap::new(),
                })
            }),
        ]
    }

    /// A full `TaskRequest`: bounded task id, an arbitrary (possibly
    /// out-of-range) timeout, and an optional action — `Just(None)` covers
    /// the missing-action protocol-error case.
    fn arb_task() -> impl Strategy<Value = TaskRequest> {
        (
            arb_task_id(),
            any::<i32>(),
            prop_oneof![arb_action().prop_map(Some), Just(None)],
        )
            .prop_map(|(task_id, timeout_seconds, action)| TaskRequest {
                task_id,
                timeout_seconds,
                action,
            })
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(64))]

        // ---------------------------------------------------------------
        // P1 `pipeline_never_panics_deny_never_reaches_runner_argv_identity`
        // ---------------------------------------------------------------
        #[test]
        fn pipeline_never_panics_deny_never_reaches_runner_argv_identity(task in arb_task()) {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            let pt_dir = PtTempDir::new();
            let dedup = DedupStore::open(pt_dir.path()).expect("open dedup");
            let policy = pipeline_policy();
            let scheduler = Scheduler::new();

            let recorded: Arc<Mutex<Option<Vec<String>>>> = Arc::new(Mutex::new(None));
            let rec = Arc::clone(&recorded);
            let run = move |req: ExecRequest| {
                *rec.lock().unwrap() = Some(req.argv.clone());
                let task_id = req.task_id.clone();
                async move { ok_result(task_id) }
            };

            let result = rt.block_on(dispatch_scheduled_with_runner(
                &task,
                &policy,
                &dedup,
                &scheduler,
                tokio::time::Instant::now(),
                run,
                None,
            ));

            // Never panics is implicit — the case completes. task_id is echoed
            // on every outcome.
            prop_assert_eq!(&result.task_id, &task.task_id, "task_id must be echoed");

            let recorded_snapshot = recorded.lock().unwrap().clone();

            if result.outcome == Outcome::DeniedByPolicy as i32 {
                prop_assert!(
                    recorded_snapshot.is_none(),
                    "a Deny must never reach the runner"
                );
            }

            // IMPLEMENTATION NOTE: an ALLOWED service.restart whose unit passes
            // Policy but FAILS validate_unit_name's charset check (e.g. a
            // leading '-' or a non-ASCII unit — reachable because arb_unit()
            // includes arb_argv_elem()) returns Outcome::Failure with
            // recorded == None. So recorded_snapshot.is_none() can ALSO occur
            // for an allowed service.restart, not only for a Deny. Therefore
            // assert argv-identity ONLY on the recorded == Some(argv) branch
            // below, and do NOT assert the converse ("allowed => runner
            // always called") — an allowed-but-invalid-unit case legitimately
            // leaves the runner uncalled.
            if let Some(argv) = recorded_snapshot {
                match &task.action {
                    Some(task_request::Action::Operation(op))
                        if op.name == operations::SERVICE_RESTART =>
                    {
                        let unit = op.args.get(OP_ARG_UNIT).cloned().unwrap_or_default();
                        prop_assert_eq!(
                            argv,
                            vec!["systemctl".to_string(), "restart".to_string(), unit],
                            "the gate-allowed argv must be byte-identical to the \
                             runner-received argv (no mutation between decision \
                             and exec, ADR-0001)"
                        );
                    }
                    _ => prop_assert!(
                        false,
                        "under pipeline_policy() the runner is reachable only \
                         via an allowed service.restart"
                    ),
                }
            }
        }

        // ---------------------------------------------------------------
        // P3 `dedup_holds_across_duplicate_task_ids`
        // ---------------------------------------------------------------
        #[test]
        fn dedup_holds_across_duplicate_task_ids(task in arb_task()) {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            let pt_dir = PtTempDir::new();
            let dedup = DedupStore::open(pt_dir.path()).expect("open dedup");
            let policy = pipeline_policy();
            let scheduler = Scheduler::new();

            let calls = Arc::new(AtomicUsize::new(0));
            let c = Arc::clone(&calls);
            let run = move |req: ExecRequest| {
                c.fetch_add(1, Ordering::SeqCst);
                let task_id = req.task_id.clone();
                async move { ok_result(task_id) }
            };

            let r2 = rt.block_on(async {
                let _r1 = dispatch_scheduled_with_runner(
                    &task,
                    &policy,
                    &dedup,
                    &scheduler,
                    tokio::time::Instant::now(),
                    run.clone(),
                    None,
                )
                .await;
                dispatch_scheduled_with_runner(
                    &task,
                    &policy,
                    &dedup,
                    &scheduler,
                    tokio::time::Instant::now(),
                    run,
                    None,
                )
                .await
            });

            prop_assert!(
                calls.load(Ordering::SeqCst) <= 1,
                "at-most-once: runner called {} times for the same task_id",
                calls.load(Ordering::SeqCst)
            );
            prop_assert!(
                r2.stderr
                    .windows(b"already processed".len())
                    .any(|w| w == b"already processed"),
                "the second dispatch of a duplicate task_id must be the benign \
                 already-processed result"
            );
            prop_assert_eq!(&r2.task_id, &task.task_id);
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(256))]

        // ---------------------------------------------------------------
        // P4 `classify_strict_lane` — proves RawExec/unknown-op/missing-action
        // -> Mutate (ADR-0012 risk lane).
        // ---------------------------------------------------------------
        #[test]
        fn classify_strict_lane(task in arb_task()) {
            let class = Scheduler::classify(&task);
            match &task.action {
                None => prop_assert_eq!(class, Class::Mutate, "missing action must classify Mutate"),
                Some(task_request::Action::RawExec(_)) => {
                    prop_assert_eq!(class, Class::Mutate, "RawExec must always classify Mutate")
                }
                Some(task_request::Action::Operation(op)) => match op.name.as_str() {
                    operations::SYSTEM_FACTS | operations::FILE_READ => {
                        prop_assert_eq!(class, Class::Read, "{} must classify Read", op.name)
                    }
                    _ => prop_assert_eq!(
                        class,
                        Class::Mutate,
                        "{} (mutate or unknown) must classify Mutate",
                        op.name
                    ),
                },
            }
        }

        // ---------------------------------------------------------------
        // P5 `effective_timeout_always_bounded`
        // ---------------------------------------------------------------
        #[test]
        fn effective_timeout_always_bounded(secs in any::<i32>()) {
            let d = effective_timeout(secs);

            prop_assert!(d <= MAX_TIMEOUT, "effective_timeout must never exceed MAX_TIMEOUT");
            prop_assert!(d >= Duration::from_secs(1), "effective_timeout must never be below 1s");

            if secs <= 0 {
                prop_assert_eq!(d, DEFAULT_TIMEOUT);
            } else if secs >= 300 {
                prop_assert_eq!(d, MAX_TIMEOUT);
            } else {
                prop_assert_eq!(d, Duration::from_secs(secs as u64));
            }
        }

        // ---------------------------------------------------------------
        // P6 `validators_never_panic_ok_implies_charset` — mirrors the
        // exhaustive proof style in operations/schema.rs:390.
        // ---------------------------------------------------------------
        #[test]
        fn validators_never_panic_ok_implies_charset(
            s in prop_oneof![
                arb_argv_elem(),
                // Second arm biases toward Ok-hits so the Ok branch is
                // actually exercised, not just the reject branch.
                prop::string::string_regex("[A-Za-z0-9@._:+~-]{0,12}").unwrap(),
            ],
        ) {
            if crate::operations::service_restart::validate_unit_name(&s).is_ok() {
                prop_assert!(!s.is_empty());
                prop_assert!(!s.starts_with('-'));
                prop_assert!(s.chars().all(|c| matches!(
                    c,
                    'A'..='Z' | 'a'..='z' | '0'..='9' | '@' | '.' | '_' | '-'
                )));
            }

            if crate::operations::pkg_install::validate_pkg_name(&s).is_ok() {
                prop_assert!(s.chars().all(|c| matches!(
                    c,
                    'A'..='Z' | 'a'..='z' | '0'..='9' | '+' | '.' | '_' | '-'
                )));
                prop_assert!(s.chars().next().unwrap().is_ascii_alphanumeric());
                prop_assert!(s.chars().next_back().unwrap().is_ascii_alphanumeric());
            }

            if crate::operations::pkg_install::validate_pkg_version(&s).is_ok() {
                prop_assert!(s.chars().all(|c| matches!(
                    c,
                    'A'..='Z' | 'a'..='z' | '0'..='9' | '+' | '.' | ':' | '~' | '_' | '-'
                )));
                prop_assert!(s.chars().next().unwrap().is_ascii_alphanumeric());
                prop_assert!(s.chars().next_back().unwrap().is_ascii_alphanumeric());
            }
        }
    }
}
