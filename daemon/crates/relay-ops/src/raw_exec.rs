//! Raw Exec runner — the escape hatch for arbitrary commands (ADR-0001).
//!
//! This module does not decide whether a command may run: dispatch's Policy
//! gate does (ADR-0002, fail-closed), and [`run_raw_exec`] is reachable only
//! with the [`RawExecPermit`] that `Policy::decide` mints on Allow, carrying
//! the exact argv it allowed. Raw Exec is always classified as `mutate`
//! (ADR-0012): arbitrary commands are unclassifiable, so they take the strict
//! mutate lane by definition.

use std::future::Future;
use std::time::Duration;

use tokio::sync::oneshot;

use crate::executor::ExecRequest;
use crate::gen::TaskResult;
use crate::limits::ResourceLimits;
use crate::policy::RawExecPermit;

/// Raw Exec is always classified as `mutate` (ADR-0012).
///
/// Arbitrary commands are unclassifiable, so Raw Exec always takes the strict
/// mutate lane by definition — never conditional on the command content.
///
/// The Policy decision log (`policy::decision_log`) reports it on every Raw
/// Exec decision event; dispatch routes via Policy, not this constant.
pub const RAW_EXEC_RISK_CLASS: crate::gen::RiskClass = crate::gen::RiskClass::Mutate;

/// Run a Raw Exec command that Policy has already allowed.
///
/// `permit` is the proof: it is minted only by `Policy::decide`, only on
/// Allow, and the argv executed is the argv inside it — never a second copy
/// that could differ from what Policy evaluated. `cancel` is threaded into the
/// [`ExecRequest`] so the executor can kill the process group on an in-flight
/// cancel signal (ADR-0013). `run` is the executor seam (`execute` in
/// production), as for `service.restart`.
pub async fn run_raw_exec<F, Fut>(
    task_id: String,
    permit: RawExecPermit,
    timeout: Duration,
    max_output_bytes: usize,
    cancel: Option<oneshot::Receiver<()>>,
    run: F,
) -> TaskResult
where
    F: FnOnce(ExecRequest) -> Fut,
    Fut: Future<Output = TaskResult>,
{
    run(ExecRequest {
        task_id,
        argv: permit.into_argv(),
        timeout,
        max_output_bytes,
        cancel,
        limits: ResourceLimits::DEFAULT,
    })
    .await
}

#[cfg(test)]
mod tests {
    use super::{run_raw_exec, RAW_EXEC_RISK_CLASS};
    use crate::executor::execute;
    use crate::gen::{Outcome, RiskClass};
    use crate::policy::{from_toml_str, Policy, RawExecPermit, Request};
    use std::time::Duration;

    fn big_cap() -> usize {
        64 * 1024 * 1024
    }

    use crate::test_support::args as argv;

    /// The permit `Policy::decide` mints for an argv it allows.
    fn permit(policy: &Policy, argv: &[String]) -> RawExecPermit {
        policy
            .decide(&Request::RawExec { argv })
            .raw_exec_permit
            .expect("allowed")
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

        let raw = argv(&["/bin/echo", "hello"]);
        let result = run_raw_exec(
            "t-allow".to_string(),
            permit(&policy, &raw),
            Duration::from_secs(5),
            big_cap(),
            None, // cancel: uncancellable in tests
            execute,
        )
        .await;

        assert_eq!(result.outcome, Outcome::Success as i32, "must succeed");
        assert_eq!(result.exit_code, 0);
        assert_eq!(result.stdout, b"hello\n");
    }

    // -----------------------------------------------------------------------
    // 4. No implicit shell — shell metacharacters are passed as literals
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn no_implicit_shell_injected() {
        let policy = from_toml_str(
            r#"
[raw_exec]
allow = ["^/bin/echo .+$"]
"#,
        )
        .expect("policy must parse");

        // "$HOME;ls" must arrive at /bin/echo as a literal argument, not be
        // expanded or split by a shell (ADR-0001: argv-only, never /bin/sh).
        let raw = argv(&["/bin/echo", "$HOME;ls"]);
        let result = run_raw_exec(
            "t-no-shell".to_string(),
            permit(&policy, &raw),
            Duration::from_secs(5),
            big_cap(),
            None, // cancel: uncancellable in tests
            execute,
        )
        .await;

        assert_eq!(result.outcome, Outcome::Success as i32, "must succeed");
        assert_eq!(
            result.stdout, b"$HOME;ls\n",
            "shell metacharacters must be treated as literals"
        );
    }

    // -----------------------------------------------------------------------
    // 4a. argv is data, never shell-expanded — re-pins the DoD property for
    // #223 across a richer encoding/shell-metacharacter token vector than
    // no_implicit_shell_injected above ($IFS, backticks, $(...), &&, |,
    // percent-encoding, backslash-escapes).
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn argv_is_data_not_shell_expanded() {
        let policy = from_toml_str(
            r#"
[raw_exec]
allow = ["^/bin/echo .+$"]
"#,
        )
        .expect("policy must parse");

        // Every token below is shell-meaningful in some interpreter but must
        // arrive at /bin/echo as a literal argument (ADR-0001: argv-only,
        // never /bin/sh — no expansion, no word-splitting, no C-unescape).
        let raw = argv(&[
            "/bin/echo",
            "$HOME;ls",
            "$IFS",
            "`id`",
            "$(id)",
            "&&",
            "|",
            "%2f",
            "\\x2f",
        ]);
        let result = run_raw_exec(
            "t-argv-is-data".to_string(),
            permit(&policy, &raw),
            Duration::from_secs(5),
            big_cap(),
            None, // cancel: uncancellable in tests
            execute,
        )
        .await;

        assert_eq!(result.outcome, Outcome::Success as i32, "must succeed");
        assert_eq!(
            result.stdout, b"$HOME;ls $IFS `id` $(id) && | %2f \\x2f\n",
            "every token must arrive literally — no shell expansion, word-splitting, or \
             C-unescape of any element"
        );
    }

    // -----------------------------------------------------------------------
    // 4b. A NUL anywhere in argv fails closed at the executor (execv), not
    // just at the Policy gate — the "real argv that reaches Command::new"
    // pin for control bytes referenced by policy.rs red-team rows
    // ctl_nul_in_arg_breaks_anchored_class_allow / ctl_slash_s_does_not_match_nul.
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn nul_in_argv_fails_closed_at_executor() {
        let policy = from_toml_str(
            r#"
[raw_exec]
allow = ["^/bin/echo .+$"]
"#,
        )
        .expect("policy must parse");

        // Policy allows this argv (joined form starts with "/bin/echo"), but
        // an interior NUL in an argument makes Command::spawn fail with
        // InvalidInput — the process never runs, regardless of what the
        // Policy gate decided.
        let raw = argv(&["/bin/echo", "a\0b"]);
        let result = run_raw_exec(
            "t-nul-argv".to_string(),
            permit(&policy, &raw),
            Duration::from_secs(5),
            big_cap(),
            None, // cancel: uncancellable in tests
            execute,
        )
        .await;

        assert_eq!(
            result.outcome,
            Outcome::Failure as i32,
            "a NUL in argv must fail closed at spawn, not run"
        );
        assert_eq!(result.exit_code, -1);
        assert!(result.stdout.is_empty(), "nothing must have been spawned");
    }

    // -----------------------------------------------------------------------
    // 5. RAW_EXEC_RISK_CLASS is always Mutate (ADR-0012)
    // -----------------------------------------------------------------------

    #[test]
    fn raw_exec_is_mutate() {
        assert_eq!(RAW_EXEC_RISK_CLASS, RiskClass::Mutate);
    }
}
