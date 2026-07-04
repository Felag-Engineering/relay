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

use crate::dedup::DedupStore;
use crate::executor::{execute, ExecRequest};
use crate::gen::{
    policy_query, task_request, Operation, Outcome, PolicyQuery, PolicyVerdict, TaskRequest,
    TaskResult,
};
use crate::operations;
use crate::operations::file_read::file_read;
use crate::operations::service_restart::service_restart;
use crate::operations::system_facts::gather_facts;
use crate::policy::{Decision, Policy, Rule};
use crate::raw_exec::run_raw_exec;

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

/// Per-Task output byte cap for stdout and stderr independently (ADR-0004).
///
/// Bytes past the cap are drained (to avoid blocking the child on a full pipe)
/// but discarded; `truncated` is set in the [`TaskResult`]. Policy-configurable
/// output caps are a v0.0.4 item.
const MAX_OUTPUT_BYTES: usize = 1024 * 1024; // 1 MiB

/// v1 arg-key contract: `file.read` callers must supply the path under this key.
///
/// Any `TaskRequest.Operation.args` map sent by the Relay must use `"path"`
/// to address the file. Any other key is treated as absent (empty-string fallback).
/// This constant is the single definition site for all sides of the contract.
const OP_ARG_PATH: &str = "path";

/// v1 arg-key contract: `service.restart` callers must supply the unit name under this key.
///
/// The Relay must send the systemd unit name as `args["unit"]`. Any other key
/// is treated as absent (empty-string fallback, which will fail unit-name validation).
/// This constant is the single definition site for all sides of the contract.
const OP_ARG_UNIT: &str = "unit";

// ---------------------------------------------------------------------------
// Public dispatch entry
// ---------------------------------------------------------------------------

/// Ordered dispatch pipeline: dedup → Policy → execute.
///
/// Delegates to [`dispatch_with_runner`] with the real [`execute`] as the
/// process-spawning runner. `service.restart` is the only Operation that
/// spawns; all other handlers are data-only and never call the runner.
pub async fn dispatch(task: &TaskRequest, policy: &Policy, dedup: &DedupStore) -> TaskResult {
    dispatch_with_runner(task, policy, dedup, execute).await
}

// ---------------------------------------------------------------------------
// Testable core (runner-injected)
// ---------------------------------------------------------------------------

/// Dedup → Policy → execute with an injected runner for hermeticity.
///
/// The `run` closure is the sole process-spawning seam: [`execute`] in
/// production; a fake that records argv in tests. Only `service.restart`
/// invokes the runner; `system.facts` and `file.read` are data-only.
///
/// **Dedup ordering** (ADR-0004, invariant #4): `dedup.run_once` records the
/// task_id marker BEFORE invoking the pipeline (deny-or-execute). A denied
/// Task also consumes a marker: a retry with the same task_id returns the
/// benign already-processed result, even if the first run was denied by Policy.
async fn dispatch_with_runner<R, Fut>(
    task: &TaskRequest,
    policy: &Policy,
    dedup: &DedupStore,
    run: R,
) -> TaskResult
where
    R: Fn(ExecRequest) -> Fut + Clone,
    Fut: Future<Output = TaskResult>,
{
    dedup
        .run_once(&task.task_id, || async {
            evaluate_and_execute(task, policy, run).await
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
/// Derives the `deciding_rule` string from the engine's own `Rule` / `reason`,
/// so a deny verdict names the same rule a real denial would attribute — no
/// re-decision, no parallel evaluator.
fn decision_to_verdict(query_id: String, decision: Decision) -> PolicyVerdict {
    match decision {
        Decision::Allow(_) => PolicyVerdict {
            query_id,
            allowed: true,
            deciding_rule: String::new(),
        },
        Decision::Deny { reason, rule } => {
            let deciding_rule = match rule {
                Some(Rule::OperationDeny { operation }) => {
                    format!("operation deny: {operation}")
                }
                Some(Rule::RawExecDeny { pattern }) => format!("raw_exec deny: {pattern}"),
                // These two variants are unreachable on a Deny decision but are
                // required for exhaustive matching — the compiler cannot prove
                // Allow-only variants never appear inside Deny.
                Some(Rule::OperationAllow { operation }) => {
                    format!("operation allow: {operation}")
                }
                Some(Rule::RawExecAllow { pattern }) => format!("raw_exec allow: {pattern}"),
                // Deny-by-default: no specific rule fired; use the engine's
                // reason string, which is always non-empty.
                None => reason,
            };
            PolicyVerdict {
                query_id,
                allowed: false,
                deciding_rule,
            }
        }
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
        _ => vec![], // deny-by-default will catch this
    }
}

// ---------------------------------------------------------------------------
// Policy gate and handler dispatch
// ---------------------------------------------------------------------------

async fn evaluate_and_execute<R, Fut>(task: &TaskRequest, policy: &Policy, run: R) -> TaskResult
where
    R: Fn(ExecRequest) -> Fut + Clone,
    Fut: Future<Output = TaskResult>,
{
    let timeout = effective_timeout(task.timeout_seconds);
    let task_id = task.task_id.clone();

    match &task.action {
        Some(task_request::Action::RawExec(raw)) => {
            // Raw Exec: fully gated by Policy regex before any spawn (ADR-0001, ADR-0002).
            run_raw_exec(task_id, raw, timeout, MAX_OUTPUT_BYTES, policy).await
        }
        Some(task_request::Action::Operation(op)) => {
            handle_operation(task_id, op, timeout, policy, run).await
        }
        None => {
            // Missing action: protocol error → FAILURE (not DENIED_BY_POLICY).
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
                    // KNOWN LIMITATION: file_read calls std::fs::File::open
                    // (blocking) inside this async context. Safe for v0.0.3
                    // single-flight; move to spawn_blocking in v0.0.4
                    // (mirrors executor.rs:117-120).
                    let path = positional.first().map(String::as_str).unwrap_or("");
                    file_read(&task_id, path, MAX_OUTPUT_BYTES)
                }
                operations::SERVICE_RESTART => {
                    let unit = positional.into_iter().next().unwrap_or_default();
                    service_restart(task_id, &unit, timeout, MAX_OUTPUT_BYTES, run.clone()).await
                }
                _ => {
                    // Policy allowed a name this daemon does not implement.
                    // FAILURE (not DENIED_BY_POLICY): the Policy engine is not at fault.
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

        let result = dispatch_with_runner(&task, &policy, &dedup, |req| execute(req)).await;

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

        let result = dispatch_with_runner(&task, &policy, &dedup, |req| execute(req)).await;

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

        let result = dispatch_with_runner(&task, &policy, &dedup, |req| execute(req)).await;

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
        let result = dispatch_with_runner(&task, &policy, &dedup, fake_run).await;

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
        let result = dispatch_with_runner(&task, &policy, &dedup, fake_run).await;

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

        let r1 = dispatch_with_runner(&task, &policy, &dedup, fake_run.clone()).await;
        let r2 = dispatch_with_runner(&task, &policy, &dedup, fake_run).await;

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

        let result = dispatch_with_runner(&task, &policy, &dedup, |req| execute(req)).await;

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
        let result = dispatch_with_runner(&task, &policy, &dedup, |req| execute(req)).await;

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
    /// The matrix covers five distinct cases: allowed operation, denied operation
    /// (deny-by-default), denied operation (deny-beats-allow), allowed raw exec,
    /// denied raw exec (deny-beats-allow). Each case is checked against BOTH the
    /// query verdict and the dispatch result so a single test enforces consistency.
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
        ];

        for case in &cases {
            let verdict = evaluate_policy_query(&case.query, &policy);
            let result = dispatch_with_runner(&case.task, &policy, &dedup, fake_run.clone()).await;

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
}
