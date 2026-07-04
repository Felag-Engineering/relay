//! `service.restart` Operation — restarts a named systemd unit via
//! `["systemctl", "restart", <unit>]`.
//!
//! The unit name is a **single validated argv element**, never interpolated into a
//! shell string (ADR-0001). The fixed command is `systemctl restart`; the argument
//! can never change which command runs.
//!
//! `restart_argv` is the pure primary test seam: tests call it directly to assert
//! the exact argv without spawning systemctl. The async `service_restart` function
//! accepts an injectable `run` closure so the end-to-end async path is also testable
//! without touching real services.

use std::time::Duration;

use crate::executor::ExecRequest;
use crate::gen::{Outcome, TaskResult};

/// Validates that `unit` is a safe systemd unit name.
///
/// Three layers of protection (belt-and-suspenders; argv already prevents shell
/// injection, but these close remaining argv-level injection vectors):
///
/// 1. Rejects empty strings — systemctl would treat `""` as a malformed unit.
/// 2. Rejects a leading `-` — names like `--version`/`-h` are options to
///    systemctl itself; argv does not prevent option injection.
/// 3. Rejects any character outside `[A-Za-z0-9@._-]` — this allowlist
///    excludes whitespace, `/`, NUL/control chars, and every shell
///    metacharacter. It also matches the Policy fixture charset so any name
///    that validates here is one Policy can also express.
fn validate_unit_name(unit: &str) -> Result<(), super::OperationError> {
    if unit.is_empty() {
        return Err(super::OperationError::InvalidUnitName(unit.to_string()));
    }
    if unit.starts_with('-') {
        return Err(super::OperationError::InvalidUnitName(unit.to_string()));
    }
    if !unit
        .chars()
        .all(|c| matches!(c, 'A'..='Z' | 'a'..='z' | '0'..='9' | '@' | '.' | '_' | '-'))
    {
        return Err(super::OperationError::InvalidUnitName(unit.to_string()));
    }
    Ok(())
}

/// Validates `unit` and returns the exact argv for `systemctl restart <unit>`.
///
/// This is the **primary test seam** — tested directly and never executes.
/// Returns `Err(InvalidUnitName)` if the name fails validation.
pub fn restart_argv(unit: &str) -> Result<Vec<String>, super::OperationError> {
    validate_unit_name(unit)?;
    Ok(vec!["systemctl".into(), "restart".into(), unit.into()])
}

/// Validates `unit`, builds the argv, and delegates execution to `run`.
///
/// `run` is an injected closure so the async path is testable without touching
/// real services: tests pass a fake closure that records the argv and returns a
/// canned [`TaskResult`]; production callers (#82) pass `executor::execute`.
///
/// Short-circuits to `OUTCOME_FAILURE` (exit_code -1, error in stderr) if the
/// unit name is invalid — `run` is **never called** in that case.
pub async fn service_restart<F, Fut>(
    task_id: String,
    unit: &str,
    timeout: Duration,
    max_output_bytes: usize,
    run: F,
) -> TaskResult
where
    F: FnOnce(ExecRequest) -> Fut,
    Fut: std::future::Future<Output = TaskResult>,
{
    let argv = match restart_argv(unit) {
        Ok(v) => v,
        Err(e) => {
            return TaskResult {
                task_id,
                outcome: Outcome::Failure as i32,
                exit_code: -1,
                stdout: vec![],
                stderr: e.to_string().into_bytes(),
                truncated: false,
                duration_millis: 0,
            };
        }
    };
    let req = ExecRequest {
        task_id,
        argv,
        timeout,
        max_output_bytes,
    };
    run(req).await
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    };

    // -----------------------------------------------------------------------
    // restart_argv: exact argv (ACCEPTANCE-CRITICAL)
    // -----------------------------------------------------------------------

    #[test]
    fn restart_argv_nginx_exact() {
        let argv = restart_argv("nginx").unwrap();
        assert_eq!(
            argv,
            ["systemctl", "restart", "nginx"],
            "restart_argv must produce exactly [systemctl, restart, nginx]"
        );
    }

    // -----------------------------------------------------------------------
    // restart_argv: valid systemd name set
    // -----------------------------------------------------------------------

    #[test]
    fn restart_argv_accepts_valid_names() {
        for name in &["php-fpm", "user@1000.service", "foo.socket", "my_app"] {
            assert!(
                restart_argv(name).is_ok(),
                "expected Ok for valid unit name {:?}",
                name
            );
        }
    }

    // -----------------------------------------------------------------------
    // restart_argv: invalid name rejection set (→ Err(InvalidUnitName))
    // -----------------------------------------------------------------------

    #[test]
    fn restart_argv_rejects_invalid_names() {
        let bad = [
            "",                // empty
            "--version",       // leading dash / option injection
            "-h",              // leading dash / option injection
            "nginx; rm -rf /", // semicolon + shell metacharacters
            "$(reboot)",       // command substitution
            "`id`",            // backtick substitution
            "a b",             // whitespace
            "nginx|cat",       // pipe
            "../etc",          // path separator
            "a/b",             // path separator
            "a\nb",            // newline
        ];
        for name in &bad {
            assert!(
                restart_argv(name).is_err(),
                "expected Err(InvalidUnitName) for {:?}",
                name
            );
        }
    }

    // -----------------------------------------------------------------------
    // fake-runner: records argv, returns canned Success, never spawns systemctl
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn fake_runner_records_argv_and_never_spawns() {
        let recorded = Arc::new(Mutex::new(Vec::<String>::new()));
        let rec = recorded.clone();

        let result = service_restart(
            "t1".to_string(),
            "nginx",
            Duration::from_secs(5),
            1024,
            move |req| {
                *rec.lock().unwrap() = req.argv.clone();
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
            },
        )
        .await;

        assert_eq!(
            *recorded.lock().unwrap(),
            ["systemctl", "restart", "nginx"],
            "fake runner must receive exactly [systemctl, restart, nginx]"
        );
        assert_eq!(
            result.outcome,
            Outcome::Success as i32,
            "canned Success must be returned"
        );
    }

    // -----------------------------------------------------------------------
    // short-circuit: invalid name → Failure, runner never called
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn short_circuit_on_invalid_unit_name() {
        let runner_called = Arc::new(AtomicBool::new(false));
        let called = runner_called.clone();

        let result = service_restart(
            "t2".to_string(),
            "bad;name",
            Duration::from_secs(5),
            1024,
            move |req| {
                called.store(true, Ordering::SeqCst);
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
            },
        )
        .await;

        assert!(
            !runner_called.load(Ordering::SeqCst),
            "runner must not be called when unit name is invalid"
        );
        assert_eq!(
            result.outcome,
            Outcome::Failure as i32,
            "invalid unit name must yield OUTCOME_FAILURE"
        );
        assert_eq!(result.exit_code, -1);
        assert!(
            !result.stderr.is_empty(),
            "stderr must contain the validation error"
        );
    }
}
