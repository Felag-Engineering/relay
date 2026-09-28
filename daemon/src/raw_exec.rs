//! Raw Exec handler — the escape hatch for arbitrary commands (ADR-0001).
//!
//! Every invocation is regex-gated by the Node's Policy before anything is
//! spawned (ADR-0002, fail-closed). Raw Exec is always classified as `mutate`
//! (ADR-0012): arbitrary commands are unclassifiable, so they take the strict
//! mutate lane by definition.
//!
//! This module is a pure handler. Task-dispatch / tunnel wiring is deferred to
//! issue #82.

use std::time::Duration;

use tokio::sync::oneshot;

use crate::config::ResourceLimits;
use crate::executor::{execute, ExecRequest};
use crate::gen::{RawExec, TaskResult};
use crate::not_executed::denied_by_policy_result;
use crate::policy::{Decision, Policy};

/// Raw Exec is always classified as `mutate` (ADR-0012).
///
/// Arbitrary commands are unclassifiable, so Raw Exec always takes the strict
/// mutate lane by definition — never conditional on the command content.
///
/// Only referenced in tests (blast-radius classification); dispatch routes via
/// Policy, not this constant. Compiled only under test; a future production
/// use lifts the `cfg`.
#[cfg(test)]
pub const RAW_EXEC_RISK_CLASS: crate::gen::RiskClass = crate::gen::RiskClass::Mutate;

/// Evaluate and execute a Raw Exec task.
///
/// The Policy gate is evaluated **first**, before constructing any `ExecRequest`
/// or spawning any process (fail-closed, ADR-0002 invariant #3). If the Policy
/// denies, `cancel` is dropped (no process spawned) and `OUTCOME_DENIED_BY_POLICY`
/// is returned. On allow, `cancel` is threaded into the [`ExecRequest`] so the
/// executor can kill the process group on an in-flight cancel signal (ADR-0013).
pub async fn run_raw_exec(
    task_id: String,
    raw: &RawExec,
    timeout: Duration,
    max_output_bytes: usize,
    policy: &Policy,
    cancel: Option<oneshot::Receiver<()>>,
) -> TaskResult {
    let decision = policy.evaluate_raw_exec(&raw.argv);

    // Never log the full argv: Raw Exec arguments are caller-supplied and may
    // embed credentials (e.g. `curl -H "Authorization: ..."`, a `--password`
    // flag). Log only the program name (`argv[0]`) and the argument count. The
    // Policy `reason` is already bounded to a short, char-boundary-safe fragment
    // (policy.rs `reason_fragment`), so attribution survives without dumping the
    // whole command line into the log.
    let program = raw.argv.first().map_or("", String::as_str);
    let argc = raw.argv.len();

    match decision {
        Decision::Deny { reason, rule } => {
            // cancel drops naturally here — denied before any process spawned.
            tracing::warn!(
                task_id = %task_id,
                program = %program,
                argc,
                rule = ?rule,
                reason = %reason,
                "raw exec denied by policy"
            );
            denied_by_policy_result(task_id, &reason)
        }
        Decision::Allow(rule) => {
            tracing::info!(
                task_id = %task_id,
                program = %program,
                argc,
                rule = ?rule,
                "raw exec allowed by policy"
            );
            execute(ExecRequest {
                task_id,
                argv: raw.argv.clone(),
                timeout,
                max_output_bytes,
                cancel,
                limits: ResourceLimits::DEFAULT,
            })
            .await
        }
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
            None, // cancel: uncancellable in tests
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

        // argv[2] (the shell script) contains whitespace, so the ADR-0019
        // whitespace guard refuses this before any allow pattern runs, and
        // deny-by-default is moot here — no process is spawned either way.
        let policy = from_toml_str(
            r#"
[raw_exec]
allow = ["^/bin/echo .+$"]
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
            None, // cancel: uncancellable in tests
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
    // 2a. A secret-bearing whitespace argument never appears in the Deny
    // reason. `denied_by_policy_result` puts the reason verbatim into
    // `TaskResult.stderr`, and `run_raw_exec` logs the same `reason` string
    // above (`tracing::warn!`) -- this module's own doc comment on
    // `run_raw_exec` says the full argv is never logged for exactly this
    // reason (a Raw Exec argument may embed a credential, e.g. a `curl -H
    // "Authorization: ..."` header). The ADR-0019 whitespace-guard reason
    // must uphold that: it names the offending index, never the argument's
    // value.
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn secret_bearing_whitespace_argument_never_appears_in_deny_reason() {
        let policy = from_toml_str(
            r#"
[raw_exec]
allow = ["^/bin/curl .+$"]
"#,
        )
        .expect("policy must parse");

        // argv[2] carries whitespace, so the ADR-0019 guard denies this
        // before any allow pattern is consulted -- no allow pattern needs to
        // "leak" the secret; the guard's own Deny reason must not either.
        let secret = "Authorization: Bearer topsecrettoken";
        let raw = make_raw_exec(argv(&["/bin/curl", "-H", secret]));
        let result = run_raw_exec(
            "t-secret".to_string(),
            &raw,
            Duration::from_secs(5),
            big_cap(),
            &policy,
            None, // cancel: uncancellable in tests
        )
        .await;

        assert_eq!(
            result.outcome,
            Outcome::DeniedByPolicy as i32,
            "must be denied by the whitespace guard"
        );

        // The Task result's stderr IS the Deny reason (denied_by_policy_result).
        let reason = String::from_utf8_lossy(&result.stderr);
        assert!(
            reason.contains("argv[2]"),
            "the reason must name the offending index; got {reason:?}"
        );
        assert!(
            !reason.contains("topsecrettoken") && !reason.contains(secret),
            "the Deny reason must never quote a caller-controlled argument, which may hold a \
             secret (ADR-0019; AGENTS.md security posture: never log secrets); got {reason:?}"
        );
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
            None, // cancel: uncancellable in tests
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
allow = ["^/bin/echo .+$"]
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
            None, // cancel: uncancellable in tests
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
        let raw = make_raw_exec(argv(&[
            "/bin/echo",
            "$HOME;ls",
            "$IFS",
            "`id`",
            "$(id)",
            "&&",
            "|",
            "%2f",
            "\\x2f",
        ]));
        let result = run_raw_exec(
            "t-argv-is-data".to_string(),
            &raw,
            Duration::from_secs(5),
            big_cap(),
            &policy,
            None, // cancel: uncancellable in tests
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
        let raw = make_raw_exec(argv(&["/bin/echo", "a\0b"]));
        let result = run_raw_exec(
            "t-nul-argv".to_string(),
            &raw,
            Duration::from_secs(5),
            big_cap(),
            &policy,
            None, // cancel: uncancellable in tests
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
