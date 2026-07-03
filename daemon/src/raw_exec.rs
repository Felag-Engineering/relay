//! Raw Exec handler — the escape hatch for arbitrary commands (ADR-0001).
//!
//! Every invocation is regex-gated by the Node's Policy before anything is
//! spawned (ADR-0002, fail-closed). Raw Exec is always classified as `mutate`
//! (ADR-0012): arbitrary commands are unclassifiable, so they take the strict
//! mutate lane by definition.
//!
//! This module is a pure handler. Task-dispatch / tunnel wiring is deferred to
//! issue #82.

// Not-yet-wired public API; Task-dispatch wiring lands in issue #82.
// Suppresses dead_code for the whole module at the source so that
// `cargo clippy -- -D warnings` stays green without requiring a blanket #[allow]
// on the `mod raw_exec` declaration in main.rs.
#![allow(dead_code)]

use std::time::Duration;

use crate::executor::{execute, ExecRequest};
use crate::gen::{Outcome, RawExec, RiskClass, TaskResult};
use crate::policy::{Decision, Policy};

/// Raw Exec is always classified as `mutate` (ADR-0012).
///
/// Arbitrary commands are unclassifiable, so Raw Exec always takes the strict
/// mutate lane by definition — never conditional on the command content.
pub const RAW_EXEC_RISK_CLASS: RiskClass = RiskClass::Mutate;

/// Evaluate and execute a Raw Exec task.
///
/// The Policy gate is evaluated **first**, before constructing any `ExecRequest`
/// or spawning any process (fail-closed, ADR-0002 invariant #3). If the Policy
/// denies, returns `OUTCOME_DENIED_BY_POLICY` without touching the executor.
pub async fn run_raw_exec(
    task_id: String,
    raw: &RawExec,
    timeout: Duration,
    max_output_bytes: usize,
    policy: &Policy,
) -> TaskResult {
    let decision = policy.evaluate_raw_exec(&raw.argv);

    match decision {
        Decision::Deny { reason, rule } => {
            tracing::warn!(
                task_id = %task_id,
                command = %raw.argv.join(" "),
                rule = ?rule,
                reason = %reason,
                "raw exec denied by policy"
            );
            denied_by_policy_result(task_id, &reason)
        }
        Decision::Allow(rule) => {
            tracing::info!(
                task_id = %task_id,
                command = %raw.argv.join(" "),
                rule = ?rule,
                "raw exec allowed by policy"
            );
            execute(ExecRequest {
                task_id,
                argv: raw.argv.clone(),
                timeout,
                max_output_bytes,
            })
            .await
        }
    }
}

/// Synthesizes a `TaskResult` for a Policy denial — no process was spawned.
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

#[cfg(test)]
mod tests {
    use super::{run_raw_exec, RAW_EXEC_RISK_CLASS};
    use crate::gen::{Outcome, RawExec, RiskClass};
    use crate::policy::from_toml_str;
    use std::time::Duration;

    fn big_cap() -> usize {
        64 * 1024 * 1024
    }

    fn argv(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    fn make_raw_exec(argv: Vec<String>) -> RawExec {
        RawExec { argv }
    }

    // -----------------------------------------------------------------------
    // 1. Allowed command runs and returns a real result
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn allowed_raw_exec_runs_and_returns_real_result() {
        let policy = from_toml_str(
            r#"
[raw_exec]
allow = ["^/bin/echo hello$"]
"#,
        )
        .expect("policy must parse");

        let raw = make_raw_exec(argv(&["/bin/echo", "hello"]));
        let result = run_raw_exec(
            "t-allow".to_string(),
            &raw,
            Duration::from_secs(5),
            big_cap(),
            &policy,
        )
        .await;

        assert_eq!(result.outcome, Outcome::Success as i32, "must succeed");
        assert_eq!(result.exit_code, 0);
        assert_eq!(result.stdout, b"hello\n");
    }

    // -----------------------------------------------------------------------
    // 2. Denied command spawns nothing (deny-by-default; no marker file created)
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn denied_raw_exec_spawns_nothing() {
        use std::time::{SystemTime, UNIX_EPOCH};

        // Unique marker path so parallel test runs don't collide.
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let marker = std::env::temp_dir().join(format!(
            "relay-raw-exec-test-{}-{}",
            std::process::id(),
            nanos
        ));
        let marker_str = marker.to_string_lossy().into_owned();

        // allow = ["^/bin/echo"] — the joined argv "/bin/sh -c ..." does NOT
        // match, so deny-by-default fires before any process is spawned.
        let policy = from_toml_str(
            r#"
[raw_exec]
allow = ["^/bin/echo"]
"#,
        )
        .expect("policy must parse");

        let cmd = format!("echo x > {marker_str}");
        let raw = make_raw_exec(argv(&["/bin/sh", "-c", &cmd]));
        let result = run_raw_exec(
            "t-deny".to_string(),
            &raw,
            Duration::from_secs(5),
            big_cap(),
            &policy,
        )
        .await;

        assert_eq!(
            result.outcome,
            Outcome::DeniedByPolicy as i32,
            "must be denied by policy"
        );
        assert_eq!(result.exit_code, -1);

        // No process was spawned, so the marker must not exist.
        assert!(
            !marker.exists(),
            "marker file must not exist — no process must have been spawned"
        );

        // Cleanup in case the assertion above fires and the file somehow exists.
        let _ = std::fs::remove_file(&marker);
    }

    // -----------------------------------------------------------------------
    // 3. Deny beats an overlapping allow (deny-beats-allow)
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn deny_beats_overlapping_allow() {
        let policy = from_toml_str(
            r#"
[raw_exec]
allow = ["^/bin/echo .+$"]
deny = ["secret"]
"#,
        )
        .expect("policy must parse");

        // Joined argv "/bin/echo secret" matches the allow regex, but the
        // deny pattern "secret" matches the element "secret" — deny wins.
        let raw = make_raw_exec(argv(&["/bin/echo", "secret"]));
        let result = run_raw_exec(
            "t-deny-beats-allow".to_string(),
            &raw,
            Duration::from_secs(5),
            big_cap(),
            &policy,
        )
        .await;

        assert_eq!(
            result.outcome,
            Outcome::DeniedByPolicy as i32,
            "deny must beat an overlapping allow"
        );
    }

    // -----------------------------------------------------------------------
    // 4. No implicit shell — shell metacharacters are passed as literals
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn no_implicit_shell_injected() {
        let policy = from_toml_str(
            r#"
[raw_exec]
allow = ["^/bin/echo"]
"#,
        )
        .expect("policy must parse");

        // "$HOME;ls" must arrive at /bin/echo as a literal argument, not be
        // expanded or split by a shell (ADR-0001: argv-only, never /bin/sh).
        let raw = make_raw_exec(argv(&["/bin/echo", "$HOME;ls"]));
        let result = run_raw_exec(
            "t-no-shell".to_string(),
            &raw,
            Duration::from_secs(5),
            big_cap(),
            &policy,
        )
        .await;

        assert_eq!(result.outcome, Outcome::Success as i32, "must succeed");
        assert_eq!(
            result.stdout, b"$HOME;ls\n",
            "shell metacharacters must be treated as literals"
        );
    }

    // -----------------------------------------------------------------------
    // 5. RAW_EXEC_RISK_CLASS is always Mutate (ADR-0012)
    // -----------------------------------------------------------------------

    #[test]
    fn raw_exec_is_mutate() {
        assert_eq!(RAW_EXEC_RISK_CLASS, RiskClass::Mutate);
    }
}
