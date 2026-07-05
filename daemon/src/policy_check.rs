//! Offline `relay-daemon policy check <file>` subcommand (#93).
//!
//! Lints a Policy file **before** it is deployed by config management
//! (ADR-0002: Policy is locally-rooted and remotely-immutable — this is the
//! IaC-pipeline-facing linter for the same file format, not a wire path) and
//! answers `--would-allow` hypotheticals through the exact same engine
//! methods the live daemon uses (`Policy::evaluate` / `evaluate_raw_exec`,
//! ADR-0011).
//!
//! Fully synchronous: no tokio, no rustls, no network. [`try_run`] is called
//! from the very top of `main()`, before any daemon startup, so this
//! subcommand never touches a socket or a certificate.
//!
//! **Deliberately bypasses `policy::load_policy`.** The daemon's secure load
//! path requires the file be root-owned and not group/world-writable — a
//! requirement that makes sense for the file the daemon actually enforces,
//! but not for an arbitrary checkout in an IaC pipeline's working directory.
//! This linter reads the file with `std::fs::read_to_string` and parses it
//! with `policy::from_toml_str` directly. It executes nothing, so the
//! permission gate does not apply; it must never be reused on an execution
//! path.
//!
//! Never prints the Policy body (ADR-0002) — only the fingerprint (safe to
//! log; see `Policy::fingerprint`), lint findings, and the `--would-allow`
//! verdict, which echoes only the caller's own input.
//!
//! ## Argument grammar
//!
//! ```text
//! relay-daemon policy check <file> [--strict] [--would-allow operation <name> [arg...]]
//! relay-daemon policy check <file> [--strict] [--would-allow raw-exec <argv...>]
//! relay-daemon policy check --help
//! ```
//!
//! `policy check` must be the **leading** form of the invocation — it cannot
//! be combined with a preceding daemon flag (e.g. `--relay`); [`try_run`]
//! only recognizes `argv[1] == "policy"` and `argv[2] == "check"`.
//!
//! `--would-allow` consumes the **rest** of the command line as its payload
//! (a hypothetical Operation name + args, or a Raw Exec argv, may itself
//! contain arbitrary tokens that look like flags). Consequently `--strict`
//! must come **before** `--would-allow`; any flag written after
//! `--would-allow` — including `--strict` — becomes part of its payload
//! rather than a separate flag.
//!
//! ## Exit codes
//!
//! | Code | Meaning |
//! |------|---------|
//! | 0    | Valid policy (warnings are allowed unless `--strict`) |
//! | 1    | Invalid policy file, unknown Operation name, or `--strict` with warnings |
//! | 2    | `--would-allow` verdict is DENY |
//! | 3    | Usage error (missing `<file>`, unknown flag, malformed `--would-allow`) |
//!
//! Precedence when multiple conditions apply: usage error (3) is checked
//! before the file is even read; otherwise invalid-file / unknown-operation /
//! strict-shadow (1) beats a would-allow DENY (2), which beats a clean pass (0).

use crate::operations;
use crate::policy::{self, Decision, Rule};

const USAGE: &str = "\
Usage: relay-daemon policy check <file> [--strict] [--would-allow operation <name> [arg...]]
       relay-daemon policy check <file> [--strict] [--would-allow raw-exec <argv...>]
       relay-daemon policy check --help

'policy check' must be the leading form of the invocation; it cannot be
combined with a preceding daemon flag such as --relay.

Reads <file> directly with the linter's own loader (NOT the daemon's
root-owned secure-load path) and reports:
  - TOML parse errors and invalid [raw_exec] regex patterns (fatal).
  - Operation names in [[operation]] or [[deny]] outside the v1 vocabulary (fatal).
  - [[operation]] allow rules fully shadowed by a [[deny]] rule (warning;
    fatal with --strict).

--would-allow answers a hypothetical through the same Policy engine methods
the daemon uses at runtime (ADR-0011). It consumes the REST of the command
line, so --strict must come BEFORE --would-allow: any flag written after
--would-allow (including --strict) is part of its payload, not a separate flag.

Exit codes:
  0  valid policy (warnings allowed unless --strict)
  1  invalid policy file, unknown operation name, or --strict with warnings
  2  --would-allow verdict is DENY
  3  usage error (missing <file>, unknown flag, malformed --would-allow)
";

// ---------------------------------------------------------------------------
// CLI entry point (I/O shell)
// ---------------------------------------------------------------------------

/// Entry point called from the top of `main()`.
///
/// Returns `None` when `args` is not a `policy check` invocation — the caller
/// falls through to the normal daemon startup path. Returns `Some(exit_code)`
/// when handled; the caller must `std::process::exit(exit_code)` immediately
/// (this function never spawns the daemon runtime, connects to the Relay, or
/// installs the rustls crypto provider).
pub fn try_run(args: &[String]) -> Option<i32> {
    if args.get(1).map(String::as_str) != Some("policy")
        || args.get(2).map(String::as_str) != Some("check")
    {
        return None;
    }
    let rest = &args[3..];

    // --help must be checked before any filesystem access, so `policy check
    // --help` does not try to open a file named "--help".
    if matches!(
        rest.first().map(String::as_str),
        Some("--help") | Some("-h")
    ) {
        print!("{USAGE}");
        return Some(0);
    }

    let (file, opts) = match parse_args(rest) {
        Ok(parsed) => parsed,
        Err(message) => {
            eprintln!("error: {message}");
            eprint!("{USAGE}");
            return Some(3);
        }
    };

    let contents = match std::fs::read_to_string(&file) {
        Ok(contents) => contents,
        Err(err) => {
            eprintln!("error: failed to read '{file}': {err}");
            return Some(1);
        }
    };

    let report = check_contents(&contents, &opts);

    for error in &report.errors {
        eprintln!("error: {error}");
    }
    for warning in &report.warnings {
        eprintln!("warning: {warning}");
    }
    if let Some(fingerprint) = &report.fingerprint {
        println!("policy fingerprint: {fingerprint}");
    }
    match &report.would_allow {
        Some(result) if result.allowed => println!("would-allow: ALLOW"),
        Some(result) => println!("would-allow: DENY ({})", result.deciding_rule),
        None if report.exit_code == 0 => println!("OK"),
        None => {}
    }

    Some(report.exit_code)
}

// ---------------------------------------------------------------------------
// Argument parsing (manual, no clap)
// ---------------------------------------------------------------------------

/// A `--would-allow` hypothetical: either a named Operation with positional
/// args, or a Raw Exec argv.
#[derive(Debug, Clone, PartialEq, Eq)]
enum WouldAllow {
    Operation { name: String, args: Vec<String> },
    RawExec { argv: Vec<String> },
}

/// Parsed, non-fatal lint options (everything after `<file>`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct CheckOpts {
    strict: bool,
    would_allow: Option<WouldAllow>,
}

/// Parse `argv[3..]` (i.e. everything after `policy check`) into the target
/// file path and lint options. Returns `Err(message)` for any usage error.
fn parse_args(rest: &[String]) -> Result<(String, CheckOpts), String> {
    let mut iter = rest.iter();

    let file = iter
        .next()
        .ok_or_else(|| "missing <file>".to_string())?
        .clone();

    let mut opts = CheckOpts::default();

    while let Some(token) = iter.next() {
        match token.as_str() {
            "--strict" => opts.strict = true,
            "--would-allow" => {
                let kind = iter.next().ok_or_else(|| {
                    "--would-allow requires a kind (operation|raw-exec)".to_string()
                })?;
                // --would-allow consumes the rest of argv as its payload —
                // anything after it (including a stray --strict) is data,
                // not a flag. This is why --strict must precede --would-allow.
                let payload: Vec<String> = iter.by_ref().cloned().collect();
                opts.would_allow = Some(parse_would_allow(kind, payload)?);
                break;
            }
            other => return Err(format!("unknown flag '{other}'")),
        }
    }

    Ok((file, opts))
}

fn parse_would_allow(kind: &str, payload: Vec<String>) -> Result<WouldAllow, String> {
    match kind {
        "operation" => {
            let mut payload = payload.into_iter();
            let name = payload
                .next()
                .ok_or_else(|| "--would-allow operation requires <name>".to_string())?;
            Ok(WouldAllow::Operation {
                name,
                args: payload.collect(),
            })
        }
        "raw-exec" => {
            if payload.is_empty() {
                return Err("--would-allow raw-exec requires at least one argv element".to_string());
            }
            Ok(WouldAllow::RawExec { argv: payload })
        }
        other => Err(format!(
            "unknown --would-allow kind '{other}' (expected operation|raw-exec)"
        )),
    }
}

// ---------------------------------------------------------------------------
// Pure core (unit-testable, no filesystem, no process::exit)
// ---------------------------------------------------------------------------

/// The verdict for a `--would-allow` hypothetical.
#[derive(Debug, Clone, PartialEq, Eq)]
struct WouldAllowResult {
    allowed: bool,
    deciding_rule: String,
}

/// The result of linting a Policy file's contents.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct Report {
    exit_code: i32,
    /// Fatal findings: TOML/regex parse errors, unknown Operation names.
    errors: Vec<String>,
    /// Non-fatal findings: shadowed allow rules.
    warnings: Vec<String>,
    /// `None` only when the file failed to parse.
    fingerprint: Option<String>,
    /// `None` unless `--would-allow` was requested.
    would_allow: Option<WouldAllowResult>,
}

/// Lint `contents` (the raw bytes of a Policy file) against `opts`. Pure —
/// no filesystem access, no process exit; every finding is accumulated
/// rather than short-circuited, so a single run reports every unknown
/// Operation name and every shadowed-allow warning (better IaC UX than
/// stopping at the first failure).
fn check_contents(contents: &str, opts: &CheckOpts) -> Report {
    let policy = match policy::from_toml_str(contents) {
        Ok(policy) => policy,
        Err(err) => {
            // InsecurePermissions/InsecureOwner cannot occur here —
            // from_toml_str never touches the filesystem, so those loader-only
            // variants are unreachable from this call site. Every remaining
            // variant (Parse, InvalidRegex, Io) is reported the same way: it
            // names the concrete problem via its Display impl (InvalidRegex
            // names the offending pattern; Parse names the TOML error).
            return Report {
                exit_code: 1,
                errors: vec![format!("invalid policy file: {err}")],
                ..Default::default()
            };
        }
    };

    let mut errors = Vec::new();
    let mut warnings = Vec::new();

    // Unknown-Operation lint: accumulate every offender in both [[operation]]
    // and [[deny]] rather than stopping at the first — a typo'd deny name is
    // a latent security hole, a typo'd allow name is a dead rule, and an IaC
    // pipeline wants to see all of them in one run.
    for name in policy.allow_rule_names() {
        if operations::risk_class(name).is_none() {
            errors.push(format!(
                "unknown operation '{name}' in [[operation]] allow rule"
            ));
        }
    }
    for name in policy.deny_rule_names() {
        if operations::risk_class(name).is_none() {
            errors.push(format!("unknown operation '{name}' in [[deny]] rule"));
        }
    }

    for shadowed in policy.shadowed_allow_rules() {
        warnings.push(format!(
            "allow rule for operation '{}' is fully shadowed by a deny rule and can never fire",
            shadowed.operation
        ));
    }

    let fingerprint = Some(policy.fingerprint().to_string());

    // --would-allow: call the engine directly with the same methods
    // evaluate_policy_query uses (ADR-0011) — no second evaluator.
    let would_allow = opts.would_allow.as_ref().map(|would_allow| {
        let decision = match would_allow {
            WouldAllow::Operation { name, args } => policy.evaluate(name, args),
            WouldAllow::RawExec { argv } => policy.evaluate_raw_exec(argv),
        };
        let (allowed, deciding_rule) = decision_verdict(decision);
        WouldAllowResult {
            allowed,
            deciding_rule,
        }
    });

    // Exit-code precedence: invalid/unknown-op/strict-shadow (1) beats a
    // would-allow DENY (2), which beats a clean pass (0). Usage errors (3)
    // are handled entirely in try_run, before this function is ever called.
    let exit_code = if !errors.is_empty() || (opts.strict && !warnings.is_empty()) {
        1
    } else if would_allow.as_ref().is_some_and(|r| !r.allowed) {
        2
    } else {
        0
    };

    Report {
        exit_code,
        errors,
        warnings,
        fingerprint,
        would_allow,
    }
}

/// Convert a `Decision` into `(allowed, deciding_rule)` using the identical
/// mapping `dispatch::decision_to_verdict` uses to build a wire
/// `PolicyVerdict`. Both this function and `decision_to_verdict` merely
/// format a `Decision` that already came out of `Policy::evaluate` /
/// `evaluate_raw_exec` — the shared engine call ADR-0011 requires — so this
/// is a presentation duplicate, not a second evaluator. The consistency test
/// below asserts the two stay byte-identical.
fn decision_verdict(decision: Decision) -> (bool, String) {
    match decision {
        Decision::Allow(_) => (true, String::new()),
        Decision::Deny { reason, rule } => {
            let deciding_rule = match rule {
                Some(Rule::OperationDeny { operation }) => format!("operation deny: {operation}"),
                Some(Rule::RawExecDeny { pattern }) => format!("raw_exec deny: {pattern}"),
                // Unreachable on a real Deny decision, but required for
                // exhaustive matching (mirrors dispatch::decision_to_verdict).
                Some(Rule::OperationAllow { operation }) => format!("operation allow: {operation}"),
                Some(Rule::RawExecAllow { pattern }) => format!("raw_exec allow: {pattern}"),
                None => reason,
            };
            (false, deciding_rule)
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dispatch::evaluate_policy_query;
    use crate::gen::{policy_query, Operation, PolicyQuery, RawExec};

    // -----------------------------------------------------------------------
    // Invalid file
    // -----------------------------------------------------------------------

    #[test]
    fn bad_regex_names_the_pattern_and_exits_1() {
        let contents = r#"
[raw_exec]
allow = ["[invalid regex"]
"#;
        let report = check_contents(contents, &CheckOpts::default());
        assert_eq!(report.exit_code, 1);
        assert!(
            report.errors.iter().any(|e| e.contains("[invalid regex")),
            "error must name the offending pattern; got {:?}",
            report.errors
        );
        assert!(report.fingerprint.is_none());
    }

    #[test]
    fn unknown_operation_in_allow_and_deny_exits_1() {
        let contents = r#"
[[operation]]
name = "totally.unknown"
allowed_args = [["*"]]

[[deny]]
name = "also.unknown"
args = []
"#;
        let report = check_contents(contents, &CheckOpts::default());
        assert_eq!(report.exit_code, 1);
        assert!(report
            .errors
            .iter()
            .any(|e| e.contains("totally.unknown") && e.contains("[[operation]]")));
        assert!(report
            .errors
            .iter()
            .any(|e| e.contains("also.unknown") && e.contains("[[deny]]")));
    }

    // -----------------------------------------------------------------------
    // Shadowed allow
    // -----------------------------------------------------------------------

    #[test]
    fn empty_args_deny_shadow_is_warning_unless_strict() {
        let contents = r#"
[[operation]]
name = "service.restart"
allowed_args = [["nginx"]]

[[deny]]
name = "service.restart"
args = []
"#;
        let lenient = check_contents(contents, &CheckOpts::default());
        assert_eq!(lenient.exit_code, 0, "shadow alone must not fail the check");
        assert!(lenient
            .warnings
            .iter()
            .any(|w| w.contains("service.restart")));

        let strict_opts = CheckOpts {
            strict: true,
            would_allow: None,
        };
        let strict = check_contents(contents, &strict_opts);
        assert_eq!(strict.exit_code, 1, "--strict must turn the warning fatal");
    }

    #[test]
    fn finite_enumeration_shadow_is_flagged() {
        // Deny-rule positions do not support the "*" wildcard, so both
        // allowed values must be listed explicitly to shadow every case.
        let contents = r#"
[[operation]]
name = "service.restart"
allowed_args = [["nginx", "php-fpm"]]

[[deny]]
name = "service.restart"
args = [["nginx", "php-fpm"]]
"#;
        let report = check_contents(contents, &CheckOpts::default());
        assert_eq!(report.exit_code, 0);
        assert!(report
            .warnings
            .iter()
            .any(|w| w.contains("service.restart")));
    }

    #[test]
    fn wildcard_allow_with_specific_deny_not_flagged() {
        let contents = r#"
[[operation]]
name = "file.read"
allowed_args = [["*"]]

[[deny]]
name = "file.read"
args = [["/etc/shadow"]]
"#;
        let report = check_contents(contents, &CheckOpts::default());
        assert_eq!(report.exit_code, 0);
        assert!(
            report.warnings.is_empty(),
            "wildcard allow with a narrower deny must not be flagged; got {:?}",
            report.warnings
        );
    }

    // -----------------------------------------------------------------------
    // --would-allow
    // -----------------------------------------------------------------------

    fn would_allow_operation(name: &str, args: &[&str]) -> CheckOpts {
        CheckOpts {
            strict: false,
            would_allow: Some(WouldAllow::Operation {
                name: name.to_string(),
                args: args.iter().map(|s| s.to_string()).collect(),
            }),
        }
    }

    fn would_allow_raw_exec(argv: &[&str]) -> CheckOpts {
        CheckOpts {
            strict: false,
            would_allow: Some(WouldAllow::RawExec {
                argv: argv.iter().map(|s| s.to_string()).collect(),
            }),
        }
    }

    const QUERY_POLICY: &str = r#"
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
"#;

    #[test]
    fn would_allow_allowed_operation_exits_0() {
        let opts = would_allow_operation("service.restart", &["nginx"]);
        let report = check_contents(QUERY_POLICY, &opts);
        assert_eq!(report.exit_code, 0);
        assert!(report.would_allow.as_ref().unwrap().allowed);
    }

    #[test]
    fn would_allow_deny_by_default_exits_2() {
        let opts = would_allow_operation("service.restart", &["sshd"]);
        let report = check_contents(QUERY_POLICY, &opts);
        assert_eq!(report.exit_code, 2);
        assert!(!report.would_allow.as_ref().unwrap().allowed);
    }

    #[test]
    fn would_allow_deny_beats_allow_exits_2_and_names_rule() {
        let opts = would_allow_operation("file.read", &["/etc/shadow"]);
        let report = check_contents(QUERY_POLICY, &opts);
        assert_eq!(report.exit_code, 2);
        let result = report.would_allow.as_ref().unwrap();
        assert!(!result.allowed);
        assert!(result.deciding_rule.contains("file.read"));
    }

    #[test]
    fn would_allow_raw_exec_allowed_exits_0() {
        let opts = would_allow_raw_exec(&["/bin/echo", "hi"]);
        let report = check_contents(QUERY_POLICY, &opts);
        assert_eq!(report.exit_code, 0);
        assert!(report.would_allow.as_ref().unwrap().allowed);
    }

    #[test]
    fn would_allow_raw_exec_denied_exits_2_and_names_pattern() {
        let opts = would_allow_raw_exec(&["/bin/echo", "secret"]);
        let report = check_contents(QUERY_POLICY, &opts);
        assert_eq!(report.exit_code, 2);
        let result = report.would_allow.as_ref().unwrap();
        assert!(!result.allowed);
        assert!(result.deciding_rule.contains("secret"));
    }

    // -----------------------------------------------------------------------
    // Fingerprint
    // -----------------------------------------------------------------------

    #[test]
    fn fingerprint_matches_from_toml_str() {
        let report = check_contents(QUERY_POLICY, &CheckOpts::default());
        let policy = policy::from_toml_str(QUERY_POLICY).expect("must parse");
        assert_eq!(
            report.fingerprint.as_deref(),
            Some(policy.fingerprint()),
            "printed fingerprint must equal from_toml_str(contents).fingerprint()"
        );
    }

    #[test]
    fn empty_file_fingerprint_is_known_sha256() {
        let report = check_contents("", &CheckOpts::default());
        assert_eq!(
            report.fingerprint.as_deref(),
            Some("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
        );
        assert_eq!(
            report.exit_code, 0,
            "empty file is a valid (deny-all) policy"
        );
    }

    // -----------------------------------------------------------------------
    // Usage errors (argument parsing)
    // -----------------------------------------------------------------------

    fn args(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn missing_file_is_usage_error() {
        assert_eq!(parse_args(&args(&[])), Err("missing <file>".to_string()));
    }

    #[test]
    fn unknown_flag_is_usage_error() {
        let result = parse_args(&args(&["policy.toml", "--bogus"]));
        assert_eq!(result, Err("unknown flag '--bogus'".to_string()));
    }

    #[test]
    fn would_allow_missing_kind_is_usage_error() {
        let result = parse_args(&args(&["policy.toml", "--would-allow"]));
        assert!(result.is_err());
    }

    #[test]
    fn would_allow_unknown_kind_is_usage_error() {
        let result = parse_args(&args(&["policy.toml", "--would-allow", "bogus", "x"]));
        assert!(result.is_err());
    }

    #[test]
    fn would_allow_operation_empty_payload_is_usage_error() {
        let result = parse_args(&args(&["policy.toml", "--would-allow", "operation"]));
        assert!(result.is_err());
    }

    #[test]
    fn would_allow_raw_exec_empty_payload_is_usage_error() {
        let result = parse_args(&args(&["policy.toml", "--would-allow", "raw-exec"]));
        assert!(result.is_err());
    }

    #[test]
    fn strict_after_would_allow_becomes_payload_not_a_flag() {
        // --strict written AFTER --would-allow is swallowed into the raw-exec
        // argv, not applied as the strict flag — --would-allow consumes the
        // rest of argv, so ordering matters (documented in USAGE).
        let (file, opts) = parse_args(&args(&[
            "policy.toml",
            "--would-allow",
            "raw-exec",
            "/bin/echo",
            "--strict",
        ]))
        .expect("must parse");
        assert_eq!(file, "policy.toml");
        assert!(
            !opts.strict,
            "--strict after --would-allow must NOT set the strict flag"
        );
        assert_eq!(
            opts.would_allow,
            Some(WouldAllow::RawExec {
                argv: vec!["/bin/echo".to_string(), "--strict".to_string()]
            }),
            "--strict after --would-allow must be part of the raw-exec payload"
        );
    }

    #[test]
    fn strict_before_would_allow_is_recognized() {
        let (file, opts) = parse_args(&args(&[
            "policy.toml",
            "--strict",
            "--would-allow",
            "operation",
            "service.restart",
            "nginx",
        ]))
        .expect("must parse");
        assert_eq!(file, "policy.toml");
        assert!(opts.strict);
        assert_eq!(
            opts.would_allow,
            Some(WouldAllow::Operation {
                name: "service.restart".to_string(),
                args: vec!["nginx".to_string()]
            })
        );
    }

    // -----------------------------------------------------------------------
    // try_run dispatch (None vs Some)
    // -----------------------------------------------------------------------

    #[test]
    fn try_run_falls_through_for_non_policy_check_invocations() {
        assert_eq!(try_run(&args(&["relay-daemon"])), None);
        assert_eq!(try_run(&args(&["relay-daemon", "policy"])), None);
        assert_eq!(try_run(&args(&["relay-daemon", "policy", "list"])), None);
        assert_eq!(
            try_run(&args(&[
                "relay-daemon",
                "--relay",
                "host",
                "policy",
                "check"
            ])),
            None,
            "policy check must be the leading form; a preceding daemon flag must not be recognized"
        );
    }

    #[test]
    fn try_run_help_exits_0_without_touching_filesystem() {
        // "--help" in the <file> position must be handled before any fs
        // access — a file literally named --help does not need to exist.
        assert_eq!(
            try_run(&args(&["relay-daemon", "policy", "check", "--help"])),
            Some(0)
        );
        assert_eq!(
            try_run(&args(&["relay-daemon", "policy", "check", "-h"])),
            Some(0)
        );
    }

    #[test]
    fn try_run_missing_file_exits_3() {
        assert_eq!(
            try_run(&args(&["relay-daemon", "policy", "check"])),
            Some(3)
        );
    }

    #[test]
    fn try_run_nonexistent_file_exits_1() {
        assert_eq!(
            try_run(&args(&[
                "relay-daemon",
                "policy",
                "check",
                "/nonexistent/does-not-exist.toml"
            ])),
            Some(1)
        );
    }

    // -----------------------------------------------------------------------
    // CONSISTENCY TEST (ADR-0011, acceptance-critical)
    // -----------------------------------------------------------------------

    /// `--would-allow`'s verdict must equal `evaluate_policy_query`'s verdict
    /// for the equivalent `PolicyQuery` over the same Policy — both bottom out
    /// in `Policy::evaluate` / `evaluate_raw_exec`, so they can never diverge.
    #[test]
    fn would_allow_verdict_matches_evaluate_policy_query() {
        let policy = policy::from_toml_str(QUERY_POLICY).expect("policy must parse");

        struct Case {
            label: &'static str,
            opts: CheckOpts,
            query: PolicyQuery,
        }

        let cases = vec![
            Case {
                label: "allowed operation",
                opts: would_allow_operation("service.restart", &["nginx"]),
                query: operation_query("q1", "service.restart", "unit", "nginx"),
            },
            Case {
                label: "deny-by-default operation",
                opts: would_allow_operation("service.restart", &["sshd"]),
                query: operation_query("q2", "service.restart", "unit", "sshd"),
            },
            Case {
                label: "deny-beats-allow operation",
                opts: would_allow_operation("file.read", &["/etc/shadow"]),
                query: operation_query("q3", "file.read", "path", "/etc/shadow"),
            },
            Case {
                label: "allowed raw-exec",
                opts: would_allow_raw_exec(&["/bin/echo", "hi"]),
                query: raw_exec_query("q4", vec!["/bin/echo", "hi"]),
            },
            Case {
                label: "denied raw-exec",
                opts: would_allow_raw_exec(&["/bin/echo", "secret"]),
                query: raw_exec_query("q5", vec!["/bin/echo", "secret"]),
            },
        ];

        for case in cases {
            let report = check_contents(QUERY_POLICY, &case.opts);
            let cli_result = report
                .would_allow
                .expect("--would-allow must produce a result");

            let verdict = evaluate_policy_query(&case.query, &policy);

            assert_eq!(
                cli_result.allowed, verdict.allowed,
                "[{}] policy_check allowed ({}) != evaluate_policy_query allowed ({})",
                case.label, cli_result.allowed, verdict.allowed
            );
            assert_eq!(
                cli_result.deciding_rule, verdict.deciding_rule,
                "[{}] policy_check deciding_rule ({:?}) != evaluate_policy_query deciding_rule ({:?})",
                case.label, cli_result.deciding_rule, verdict.deciding_rule
            );
        }
    }

    fn operation_query(query_id: &str, name: &str, key: &str, val: &str) -> PolicyQuery {
        let mut args = std::collections::HashMap::new();
        args.insert(key.to_string(), val.to_string());
        PolicyQuery {
            query_id: query_id.to_string(),
            action: Some(policy_query::Action::Operation(Operation {
                name: name.to_string(),
                args,
            })),
        }
    }

    fn raw_exec_query(query_id: &str, argv: Vec<&str>) -> PolicyQuery {
        PolicyQuery {
            query_id: query_id.to_string(),
            action: Some(policy_query::Action::RawExec(RawExec {
                argv: argv.into_iter().map(String::from).collect(),
            })),
        }
    }
}
