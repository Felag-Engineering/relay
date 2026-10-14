//! The one shape of a [`TaskResult`] for a Task that never executed.
//!
//! Every path that answers a Task without spawning a process — a Policy
//! denial, an out-of-vocabulary Operation, an argument that failed
//! validation, a queue timeout or cancel, a dedup record failure, a spawn
//! error — reports it the same way: the never-executed exit code `-1`, no
//! stdout, nothing truncated, and the reason in stderr. Callers keep their own
//! named wrappers (`denied_by_policy_result`, `timeout_result`, ...) so call
//! sites stay readable; this is only the literal they share.

use std::time::Duration;

use crate::gen::{Outcome, TaskResult};

/// A never-executed [`TaskResult`]: `exit_code` `-1`, empty stdout,
/// `truncated` false, `duration_millis` `0`.
pub fn not_executed(task_id: String, outcome: Outcome, stderr: impl Into<Vec<u8>>) -> TaskResult {
    TaskResult {
        task_id,
        outcome: outcome as i32,
        exit_code: -1,
        stdout: Vec::new(),
        stderr: stderr.into(),
        truncated: false,
        duration_millis: 0,
    }
}

/// An `OUTCOME_DENIED_BY_POLICY` result — no process was spawned. Shared by
/// the Operation dispatch path and Raw Exec.
pub fn denied_by_policy_result(task_id: String, reason: &str) -> TaskResult {
    not_executed(task_id, Outcome::DeniedByPolicy, reason)
}

/// [`not_executed`], with `duration_millis` set to `elapsed` — for the paths
/// that report the time a Task spent (queued, or before a spawn failed)
/// before it was answered.
pub fn not_executed_after(
    task_id: String,
    outcome: Outcome,
    stderr: impl Into<Vec<u8>>,
    elapsed: Duration,
) -> TaskResult {
    TaskResult {
        duration_millis: elapsed.as_millis() as i64,
        ..not_executed(task_id, outcome, stderr)
    }
}
