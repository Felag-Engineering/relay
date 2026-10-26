#![cfg(test)]
//! ---------------------------------------------------------------------------
//! Tests
//! ---------------------------------------------------------------------------
use super::*;
use crate::test_support::{args, unique_temp_path, TempFile};

// The fixture is the example policy file checked into the repo. Tests
// use it directly so the documented examples stay honest.
const FIXTURE: &str = include_str!("../../../policy.example.toml");

fn fixture_policy() -> Policy {
    from_toml_str(FIXTURE).expect("policy.example.toml must parse cleanly")
}

// -----------------------------------------------------------------------
// 1a. allow_service_restart_nginx
// -----------------------------------------------------------------------

#[test]
fn allow_service_restart_nginx() {
    let policy = fixture_policy();
    let decision = policy.evaluate("service.restart", &args(&["nginx"]));
    assert!(
        matches!(
            &decision,
            Decision::Allow(Rule::OperationAllow { operation })
            if operation == "service.restart"
        ),
        "service.restart nginx must be allowed; got {decision:?}"
    );
}

// -----------------------------------------------------------------------
// 1b. deny_service_restart_sshd — sshd is not in the allowed list
//     (deny-by-default, no explicit deny rule needed)
// -----------------------------------------------------------------------

#[test]
fn deny_service_restart_sshd() {
    let policy = fixture_policy();
    let decision = policy.evaluate("service.restart", &args(&["sshd"]));
    assert!(
        matches!(&decision, Decision::Deny { rule: None, .. }),
        "service.restart sshd must be denied by default; got {decision:?}"
    );
}

// -----------------------------------------------------------------------
// 2. deny_by_default_unlisted_operation
// -----------------------------------------------------------------------

#[test]
fn deny_by_default_unlisted_operation() {
    let policy = fixture_policy();
    let decision = policy.evaluate("package.install", &args(&["curl"]));
    assert!(
        matches!(&decision, Decision::Deny { rule: None, .. }),
        "unlisted operation must be denied by default; got {decision:?}"
    );
}

// -----------------------------------------------------------------------
// 3. deny_beats_allow — file.read /etc/shadow is denied despite the
//    wildcard allow rule for file.read
// -----------------------------------------------------------------------

#[test]
fn deny_beats_allow() {
    let policy = fixture_policy();
    let decision = policy.evaluate("file.read", &args(&["/etc/shadow"]));
    assert!(
        matches!(
            &decision,
            Decision::Deny {
                rule: Some(Rule::OperationDeny { operation }),
                ..
            }
            if operation == "file.read"
        ),
        "file.read /etc/shadow must be denied by the explicit deny rule; got {decision:?}"
    );
}

// -----------------------------------------------------------------------
// vacuous_deny_fires_on_shorter_invocation — pins the `i >= args.len()`
// more-restrictive rule at the vacuous-satisfaction branch above: a deny
// written for N argument positions also fires on an invocation with
// fewer args (the unlisted trailing positions are vacuously satisfied,
// not vacuously un-satisfied). No fixture deny has >=2 positions, so this
// uses an inline deny-only TOML fixture.
//
// Non-vacuous: the assertion requires `rule: Some(OperationDeny)`, not
// merely "is denied". Flipping `true -> false` at the vacuous-satisfaction
// branch would make position 1 (absent here) evaluate false, so the
// deny's `all()` is false and the explicit deny does not fire; the
// decision would fall through to deny-by-default (`Deny { rule: None }`),
// which fails the `Some(...)` match below.
// -----------------------------------------------------------------------

#[test]
fn vacuous_deny_fires_on_shorter_invocation() {
    let policy = from_toml_str(
        r#"
            [[deny]]
            name = "service.restart"
            args = [["nginx"], ["extra"]]
            "#,
    )
    .expect("inline deny-only TOML must parse cleanly");

    // Invocation has only 1 arg; the deny lists 2 positions. Position 1
    // ("extra") is absent — it must be treated as vacuously satisfied.
    let decision = policy.evaluate("service.restart", &args(&["nginx"]));
    assert!(
        matches!(
            &decision,
            Decision::Deny {
                rule: Some(Rule::OperationDeny { operation }),
                ..
            }
            if operation == "service.restart"
        ),
        "a deny written for 2 arg positions must also fire on a shorter \
             (1-arg) invocation, with the explicit rule attributed; got {decision:?}"
    );
}

// -----------------------------------------------------------------------
// arg_constraint_wildcard_and_count
//   - file.read /etc/hostname → Allow (wildcard matches)
//   - service.restart with 0 args → Deny (count mismatch)
//   - service.restart with 2 args → Deny (count mismatch)
// -----------------------------------------------------------------------

#[test]
fn arg_constraint_wildcard_allows_any_path() {
    let policy = fixture_policy();
    let decision = policy.evaluate("file.read", &args(&["/etc/hostname"]));
    assert!(
        matches!(&decision, Decision::Allow(Rule::OperationAllow { operation }) if operation == "file.read"),
        "file.read /etc/hostname must be allowed (wildcard); got {decision:?}"
    );
}

#[test]
fn arg_count_mismatch_zero_args_denied() {
    let policy = fixture_policy();
    // service.restart requires exactly one arg; zero args must be denied.
    let decision = policy.evaluate("service.restart", &args(&[]));
    assert!(
        matches!(&decision, Decision::Deny { rule: None, .. }),
        "service.restart with 0 args must be denied (count mismatch); got {decision:?}"
    );
}

#[test]
fn arg_count_mismatch_two_args_denied() {
    let policy = fixture_policy();
    // service.restart allows exactly one arg; two args must be denied.
    let decision = policy.evaluate("service.restart", &args(&["nginx", "php-fpm"]));
    assert!(
        matches!(&decision, Decision::Deny { rule: None, .. }),
        "service.restart with 2 args must be denied (count mismatch); got {decision:?}"
    );
}

// -----------------------------------------------------------------------
// Golden deny-reason tests (issue #186) — pin the EXACT `reason` string
// for all three deny forms. These are the security-legibility contract:
// an AI-agent reading the reason must be able to tell "narrow the args"
// (args-mismatch) apart from "this operation is not allowed at all"
// (no-rule) apart from "an explicit deny fired" (explicit-deny).
//
// All three still assert `rule: None` for the first two (no rule fired,
// per ADR-0002 deny-by-default) — only the `reason` text differs.
// Flipping the args-mismatch branch back to always emit the no-rule
// text, or to `rule: Some(...)`, is exactly what these tests guard
// against.
// -----------------------------------------------------------------------

#[test]
fn golden_reason_no_rule_for_unlisted_operation() {
    let policy = fixture_policy();
    let decision = policy.evaluate("package.install", &args(&["curl"]));
    assert!(
        matches!(
            &decision,
            Decision::Deny { rule: None, reason }
            if reason == "deny-by-default: no allow rule for operation 'package.install'"
        ),
        "unlisted operation must report the no-rule reason verbatim; got {decision:?}"
    );
}

#[test]
fn golden_reason_args_mismatch_for_service_restart_sshd() {
    let policy = fixture_policy();
    let decision = policy.evaluate("service.restart", &args(&["sshd"]));
    assert!(
        matches!(
            &decision,
            Decision::Deny { rule: None, reason }
            if reason == "no allow rule matched args [\"sshd\"] for operation \
                'service.restart' (allow rules exist for other arguments)"
        ),
        "service.restart sshd must report the args-mismatch reason (an allow rule \
             exists for service.restart, just not for \"sshd\"), not the no-rule text, \
             and `rule` must stay None; got {decision:?}"
    );
}

#[test]
fn golden_reason_explicit_deny_for_file_read_shadow() {
    let policy = fixture_policy();
    let decision = policy.evaluate("file.read", &args(&["/etc/shadow"]));
    assert!(
        matches!(
            &decision,
            Decision::Deny {
                rule: Some(Rule::OperationDeny { operation }),
                reason,
            }
            if operation == "file.read"
                && reason == "denied by explicit rule for operation 'file.read'"
        ),
        "file.read /etc/shadow must report the explicit-deny reason with the rule \
             attributed; got {decision:?}"
    );
}

// -----------------------------------------------------------------------
// 4a. raw_exec_allow — systemctl restart nginx passes
// -----------------------------------------------------------------------

#[test]
fn raw_exec_allow() {
    let policy = fixture_policy();
    let decision = policy.evaluate_raw_exec(&args(&["/usr/bin/systemctl", "restart", "nginx"]));
    assert!(
        matches!(
            &decision,
            Decision::Allow(Rule::RawExecAllow { pattern })
            if pattern.contains("systemctl")
        ),
        "systemctl restart nginx must be allowed; got {decision:?}"
    );
}

// -----------------------------------------------------------------------
// 4b. raw_exec_deny_precedence — deny fires because --force is a deny-
//     pattern element match; the allow regex does NOT match this argv
// -----------------------------------------------------------------------

#[test]
fn raw_exec_deny_precedence() {
    let policy = fixture_policy();
    // The joined string "/usr/bin/systemctl restart nginx --force" does NOT
    // match the allow regex: "--force" appended after "nginx" breaks the
    // anchored `$`. The deny fires because "--force" matches the deny
    // pattern as an individual argv element.
    let decision = policy.evaluate_raw_exec(&args(&[
        "/usr/bin/systemctl",
        "restart",
        "nginx",
        "--force",
    ]));
    assert!(
        matches!(
            &decision,
            Decision::Deny {
                rule: Some(Rule::RawExecDeny { pattern }),
                ..
            }
            if pattern == "--force"
        ),
        "raw exec with --force must be denied; got {decision:?}"
    );
}

// -----------------------------------------------------------------------
// raw_exec_deny_matches_joined_string_only — deny pattern matches only the
// space-joined argv, never a single element
// -----------------------------------------------------------------------

#[test]
fn raw_exec_deny_matches_joined_string_only() {
    // "restart nginx" is a substring of the joined command
    // "systemctl restart nginx" but never appears in any single argv
    // element ("systemctl", "restart", "nginx"). Only the
    // `is_match(&joined)` disjunct at evaluate_raw_exec can catch it.
    let policy = from_toml_str(
        r#"
[raw_exec]
allow = ["^systemctl .+$"]
deny = ["restart nginx"]
"#,
    )
    .expect("policy must parse");
    let decision = policy.evaluate_raw_exec(&args(&["systemctl", "restart", "nginx"]));
    assert!(
        matches!(
            &decision,
            Decision::Deny {
                rule: Some(Rule::RawExecDeny { pattern }),
                ..
            }
            if pattern == "restart nginx"
        ),
        "deny pattern matching only the joined command must fire; got {decision:?}"
    );
}

// -----------------------------------------------------------------------
// raw_exec_empty_argv_denied — empty argv is always denied, never
// silently joined into an empty string that falls through to allow
// -----------------------------------------------------------------------

#[test]
fn raw_exec_empty_argv_denied() {
    let policy = fixture_policy();
    let decision = policy.evaluate_raw_exec(&[]);
    assert!(
        matches!(
            &decision,
            Decision::Deny { rule: None, reason }
            if reason == "empty argv"
        ),
        "empty argv must be denied with reason 'empty argv'; got {decision:?}"
    );
}

// -----------------------------------------------------------------------
// 4c. raw_exec_deny_beats_matching_allow — deny wins when BOTH an allow
//     regex AND a deny regex match the same argv
// -----------------------------------------------------------------------

#[test]
fn raw_exec_deny_beats_matching_allow() {
    let policy = fixture_policy();
    // argv: ["/usr/bin/systemctl", "status", "rm.service"]
    //
    // Allow side: the joined string "/usr/bin/systemctl status rm.service"
    // matches the allow regex ^/usr/bin/systemctl (status|restart) [A-Za-z0-9@._-]+$
    // because "rm.service" satisfies [A-Za-z0-9@._-]+.
    //
    // Deny side: \brm\b matches the word "rm" in "rm.service" — the period
    // is a non-word character, so \b fires between 'm' and '.'.
    //
    // Deny-beats-allow: the result must be Deny with RawExecDeny.
    let decision = policy.evaluate_raw_exec(&args(&["/usr/bin/systemctl", "status", "rm.service"]));
    assert!(
        matches!(
            &decision,
            Decision::Deny {
                rule: Some(Rule::RawExecDeny { pattern }),
                ..
            }
            if pattern.contains("rm")
        ),
        "deny must beat a simultaneously-matching allow; got {decision:?}"
    );
}

// -----------------------------------------------------------------------
// raw_exec_deny_by_default — unmatched command is denied
// -----------------------------------------------------------------------

#[test]
fn raw_exec_deny_by_default() {
    let policy = fixture_policy();
    let decision = policy.evaluate_raw_exec(&args(&["/bin/echo", "hi"]));
    assert!(
        matches!(&decision, Decision::Deny { rule: None, .. }),
        "/bin/echo hi must be denied by default; got {decision:?}"
    );
}

// -----------------------------------------------------------------------
// Raw Exec allow: whole-command match (ADR-0019, amended 2026-09-16)
// -----------------------------------------------------------------------

#[test]
fn raw_exec_allow_pattern_must_match_whole_command() {
    // A substring no longer admits: the joined command must match the
    // allow pattern IN FULL.
    let policy = from_toml_str("[raw_exec]\nallow = [\"/bin/echo\"]\n").expect("policy must parse");
    let decision = policy.evaluate_raw_exec(&args(&["/bin/echo", "hi"]));
    assert!(
        matches!(&decision, Decision::Deny { rule: None, .. }),
        "a pattern matching only a prefix of the joined command must no \
             longer admit it; got {decision:?}"
    );

    // Unanchored but exact: the whole joined command IS "/bin/echo hi".
    let policy =
        from_toml_str("[raw_exec]\nallow = [\"/bin/echo hi\"]\n").expect("policy must parse");
    let decision = policy.evaluate_raw_exec(&args(&["/bin/echo", "hi"]));
    assert!(
        matches!(
            &decision,
            Decision::Allow(Rule::RawExecAllow { pattern })
            if pattern == "/bin/echo hi"
        ),
        "an unanchored pattern that exactly equals the whole joined command must allow, \
             and RawExecAllow.pattern must be the author's original string, not the wrapped \
             one; got {decision:?}"
    );

    // An already-anchored pattern behaves identically.
    let policy =
        from_toml_str("[raw_exec]\nallow = [\"^/bin/echo hi$\"]\n").expect("policy must parse");
    let decision = policy.evaluate_raw_exec(&args(&["/bin/echo", "hi"]));
    assert!(
        matches!(decision, Decision::Allow(_)),
        "an already-anchored pattern must behave identically; got {decision:?}"
    );

    // The non-capturing group pins the top-level alternation whole: an
    // unwrapped `\A/bin/true` (without the group) would wrongly admit
    // "/bin/true x" via a leftmost \A match with no \z on that branch.
    let policy = from_toml_str("[raw_exec]\nallow = [\"/bin/true|/bin/false\"]\n")
        .expect("policy must parse");
    let decision = policy.evaluate_raw_exec(&args(&["/bin/true", "x"]));
    assert!(
        matches!(&decision, Decision::Deny { rule: None, .. }),
        "the alternation must be wrapped so the WHOLE command must match one branch \
             end-to-end, not just a leftmost prefix; got {decision:?}"
    );
    let decision = policy.evaluate_raw_exec(&args(&["/bin/false"]));
    assert!(
        matches!(decision, Decision::Allow(_)),
        "the other alternative, matching the whole command, must still allow; got {decision:?}"
    );
}

#[test]
fn raw_exec_allow_wrapping_cannot_validate_an_invalid_pattern() {
    // "a)|(?:b" is invalid alone (a stray closing paren) but would become
    // valid if merely wrapped in a bare (?:...) group without validating
    // the pattern alone first — compile_allow_regex must reject it.
    let result = from_toml_str("[raw_exec]\nallow = ['a)|(?:b']\n");
    match &result {
        Err(PolicyError::InvalidRegex { pattern, .. }) => {
            assert_eq!(pattern, "a)|(?:b");
        }
        other => panic!("expected InvalidRegex; got {other:?}"),
    }

    let report = lint("[raw_exec]\nallow = ['a)|(?:b']\n");
    assert!(report.parse_error.is_none());
    let errors: Vec<_> = report
        .findings
        .iter()
        .filter(|f| f.severity == LintSeverity::Error)
        .collect();
    assert_eq!(
        errors.len(),
        1,
        "lint must report exactly one Error; got {:?}",
        report.findings
    );
    assert!(errors[0].location.contains("[raw_exec].allow[0]"));
}

#[test]
fn raw_exec_allow_verbose_trailing_comment_load_and_lint_agree() {
    // A verbose-mode pattern whose last line is an unterminated `#`
    // comment: compile_allow_regex's wrapping step appends `)\z` AFTER
    // this text, and the open-ended comment always swallows it — the
    // wrapped compile fails ("unclosed group") even though the pattern
    // compiles fine unwrapped. Both entry points must refuse the file
    // (fail-closed): a load failure here drops the daemon's live Policy
    // to deny-all (main.rs's fail-closed startup path), never to a
    // partially-loaded Policy.
    let toml = "[raw_exec]\nallow = ['(?x)^/bin/true$ # comment']\n";

    match from_toml_str(toml) {
        Err(PolicyError::InvalidRegex { pattern, hint, .. }) => {
            assert_eq!(pattern, "(?x)^/bin/true$ # comment");
            assert!(
                hint.contains("verbose-mode"),
                "the InvalidRegex hint must name the verbose-mode trailing-comment fix; \
                     got {hint:?}"
            );
        }
        other => panic!("expected InvalidRegex (fail-closed); got {other:?}"),
    }

    let report = lint(toml);
    assert!(report.parse_error.is_none());
    let errors: Vec<_> = report
        .findings
        .iter()
        .filter(|f| f.severity == LintSeverity::Error)
        .collect();
    assert_eq!(
        errors.len(),
        1,
        "the lint must agree with the loader and refuse the same pattern; got {:?}",
        report.findings
    );
    assert!(errors[0].location.contains("[raw_exec].allow[0]"));
    assert!(
        errors[0].message.contains("verbose-mode"),
        "the lint message must carry the same hint as the loader; got {:?}",
        errors[0].message
    );
}

#[test]
fn lint_deny_invalid_regex_gets_no_verbose_wrapping_hint() {
    // `compile_deny_regex` never wraps a pattern (deny semantics are
    // unchanged by the ADR-0019 amendment), so a deny pattern that fails
    // to compile is invalid ON ITS OWN — an unclosed group here, not the
    // wrap-swallows-the-comment edge case `compile_allow_regex` has. The
    // pattern still "looks verbose" (`(?x)`) and its last line still ends
    // in a `#` comment, so a hint scoped only by that heuristic would
    // misattribute the failure to wrapping. Loader and lint must agree
    // that no such hint is attached on the deny side.
    let toml = "[raw_exec]\ndeny = ['(?x)a(b # comment']\n";

    match from_toml_str(toml) {
        Err(PolicyError::InvalidRegex { pattern, hint, .. }) => {
            assert_eq!(pattern, "(?x)a(b # comment");
            assert!(
                hint.is_empty(),
                "a deny pattern's InvalidRegex must carry no wrapping hint \
                     (deny is never wrapped); got {hint:?}"
            );
        }
        other => panic!("expected InvalidRegex; got {other:?}"),
    }

    let report = lint(toml);
    let errors: Vec<_> = report
        .findings
        .iter()
        .filter(|f| f.severity == LintSeverity::Error)
        .collect();
    assert_eq!(errors.len(), 1, "got {:?}", report.findings);
    assert!(errors[0].location.contains("[raw_exec].deny[0]"));
    assert!(
        !errors[0].message.contains("verbose-mode"),
        "the lint message for a deny pattern must not carry the allow-only wrapping \
             hint; got {:?}",
        errors[0].message
    );
}

// -----------------------------------------------------------------------
// Raw Exec allow anchoring lint (ADR-0019, amended 2026-09-16)
// -----------------------------------------------------------------------

#[test]
fn lint_warns_on_unanchored_raw_exec_allow() {
    let patterns = ["/bin/echo", "^/bin/echo", "/bin/echo$", r"^/bin/echo \$"];
    for pattern in patterns {
        let toml = format!("[raw_exec]\nallow = ['{pattern}']\n");
        let report = lint(&toml);
        assert!(
            report.parse_error.is_none(),
            "pattern {pattern:?}: got {:?}",
            report.parse_error
        );
        let warnings: Vec<_> = report
            .findings
            .iter()
            .filter(|f| f.severity == LintSeverity::Warning)
            .collect();
        assert_eq!(
            warnings.len(),
            1,
            "pattern {pattern:?}: got {:?}",
            report.findings
        );
        assert!(warnings[0].location.contains("[raw_exec].allow[0]"));
        assert!(
            warnings[0].message.contains("WHOLE command"),
            "pattern {pattern:?}: got {:?}",
            warnings[0].message
        );
    }
}

#[test]
fn lint_does_not_warn_on_anchored_raw_exec_allow() {
    // `(?i)^/bin/echo$` pins that a leading inline flag group is skipped
    // before the start-anchor check (review of #589's plan).
    let patterns = [
        "^/bin/echo$",
        r"\A/bin/echo\z",
        r"^/bin/echo \\$",
        "(?i)^/bin/echo$",
    ];
    for pattern in patterns {
        let toml = format!("[raw_exec]\nallow = ['{pattern}']\n");
        let report = lint(&toml);
        assert!(
            report.parse_error.is_none(),
            "pattern {pattern:?}: got {:?}",
            report.parse_error
        );
        assert!(
            report.findings.is_empty(),
            "pattern {pattern:?} must not warn; got {:?}",
            report.findings
        );
    }
}

#[test]
fn lint_does_not_warn_anchoring_on_deny_patterns() {
    let report = lint("[raw_exec]\ndeny = [\"--force\"]\n");
    assert!(report.parse_error.is_none());
    assert!(
        report.findings.is_empty(),
        "a deny-only Policy must not trigger the allow-anchoring lint; got {:?}",
        report.findings
    );
}

#[test]
fn lint_invalid_allow_gets_error_not_anchoring_warning() {
    let report = lint("[raw_exec]\nallow = [\"[invalid\"]\n");
    assert!(report.parse_error.is_none());
    assert_eq!(
        report.findings.len(),
        1,
        "an invalid pattern must get exactly one finding (Error), not also \
             an anchoring Warning; got {:?}",
        report.findings
    );
    assert_eq!(report.findings[0].severity, LintSeverity::Error);
}

// -----------------------------------------------------------------------
// 5. Loader permission checks
// -----------------------------------------------------------------------

/// The gate is `mode & 0o022`: two independent bits, group-write (`0o020`)
/// and other-write (`0o002`). Either one alone re-admits a Policy file that
/// an unprivileged local user can rewrite, and a rewritable Policy file is
/// a Policy bypass — the locally-rooted, remotely-immutable trust root and
/// deny-by-default both rest on this file (ADR-0002). So each case here
/// trips **one** named bit; a mode that trips both at once (`0o666` on its
/// own, as the world-writable case once was) proves nothing about either,
/// and a mask narrowed to `0o002` or `0o020` would still pass it. Asserting
/// the *reported* mode is what pins the fixture: `TempFile::new` chmods
/// after open because `OpenOptions::mode` is umask-masked, and this
/// assertion fails loudly if the file ever lands short of the bits asked
/// for. Mirrors `templates::tests::group_or_world_writable_file_is_refused`
/// — the two loaders share a trust root and must not drift apart again.
// Proves DI-12.
#[test]
fn loader_rejects_group_or_world_writable() {
    for (mode, bit) in [
        (0o664_u32, "group-writable, other-write clear"),
        (0o646_u32, "world-writable, group-write clear"),
        (0o666_u32, "both write bits"),
    ] {
        let tmp = TempFile::with_forced_mode("writable", FIXTURE.as_bytes(), mode);
        let result = load_policy(tmp.path(), &unique_temp_path("no-policy-dir"));
        assert!(
                matches!(
                    result,
                    Err(PolicyError::InsecurePermissions { mode: reported })
                        if reported == mode
                ),
                "mode {mode:#o} ({bit}) must be refused, reporting the mode it was set to; got {result:?}"
            );
    }
}

// Proves DI-12.
#[test]
fn loader_accepts_secure_modes() {
    // Secure modes: no group- or world-write bit; owned by the test
    // runner's euid (exercises the uid == geteuid() branch in the loader).
    for mode in [0o600_u32, 0o644] {
        let tmp = TempFile::with_forced_mode("secure", FIXTURE.as_bytes(), mode);
        let result = load_policy(tmp.path(), &unique_temp_path("no-policy-dir"));
        assert!(
                result.is_ok(),
                "policy file with mode {mode:#o} owned by test-runner euid must be accepted; got {result:?}"
            );
    }
}

// -----------------------------------------------------------------------
// invalid_regex_is_rejected — fail-closed on a bad policy
// -----------------------------------------------------------------------

#[test]
fn invalid_regex_is_rejected() {
    let bad_policy = r#"
[raw_exec]
allow = ["[invalid regex"]
deny = []
"#;
    let result = from_toml_str(bad_policy);
    assert!(
        matches!(result, Err(PolicyError::InvalidRegex { .. })),
        "malformed regex pattern must cause InvalidRegex error; got {result:?}"
    );
}

// -----------------------------------------------------------------------
// Policy fingerprint tests
// -----------------------------------------------------------------------

#[test]
fn fingerprint_is_deterministic() {
    let p1 = from_toml_str(FIXTURE).expect("fixture must parse");
    let p2 = from_toml_str(FIXTURE).expect("fixture must parse");
    assert_eq!(
        p1.fingerprint(),
        p2.fingerprint(),
        "same input bytes must always produce the same fingerprint"
    );
}

#[test]
fn fingerprint_changes_on_edit() {
    let p1 = from_toml_str(FIXTURE).expect("fixture must parse");
    // Append a comment — changes the bytes, must change the fingerprint.
    let modified = format!("{FIXTURE}\n# cosmetic edit");
    let p2 = from_toml_str(&modified).expect("modified fixture must parse");
    assert_ne!(
        p1.fingerprint(),
        p2.fingerprint(),
        "different bytes must produce a different fingerprint"
    );
}

#[test]
fn fingerprint_is_64_hex_lowercase() {
    let p = from_toml_str(FIXTURE).expect("fixture must parse");
    let fp = p.fingerprint();
    assert_eq!(
        fp.len(),
        64,
        "SHA-256 hex must be 64 characters; got {fp:?}"
    );
    assert!(
        fp.chars()
            .all(|c| c.is_ascii_digit() || matches!(c, 'a'..='f')),
        "fingerprint must be lowercase hex [0-9a-f]; got {fp:?}"
    );
}

#[test]
fn fingerprint_empty_policy_is_known_sha256() {
    // SHA-256 of the empty string is the well-known constant.
    let p = from_toml_str("").expect("empty TOML must parse as deny-all");
    assert_eq!(
        p.fingerprint(),
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "empty policy fingerprint must equal SHA-256 of the empty string"
    );
}

#[test]
fn load_policy_fingerprint_matches_from_toml_str() {
    // Prove byte-identity: loading from a file produces the same fingerprint
    // as parsing the string directly. This is the seam the `policy check`
    // subcommand (#93) will rely on.
    let tmp = TempFile::with_forced_mode("fingerprint-eq", FIXTURE.as_bytes(), 0o600);
    let file_policy = load_policy(tmp.path(), &unique_temp_path("no-policy-dir"))
        .expect("secure-mode fixture must load");
    let str_policy = from_toml_str(FIXTURE).expect("fixture must parse");
    assert_eq!(
        file_policy.fingerprint(),
        str_policy.fingerprint(),
        "load_policy and from_toml_str must produce the same fingerprint for the same bytes"
    );
}

// -----------------------------------------------------------------------
// PolicySnapshot accessors (#151)
// -----------------------------------------------------------------------

#[test]
fn snapshot_accessors_from_fixture() {
    let policy = fixture_policy();
    assert!(
        policy.raw_exec_enabled(),
        "fixture has a raw_exec allow pattern"
    );
    assert_eq!(
        policy.raw_allow_patterns(),
        vec!["^/usr/bin/systemctl (status|restart) [A-Za-z0-9@._-]+$".to_string()]
    );
    assert_eq!(
        policy.raw_deny_patterns(),
        vec!["--force".to_string(), "\\brm\\b".to_string()]
    );
    assert_eq!(
        policy.allowed_operations(),
        vec![
            "service.restart".to_string(),
            "system.facts".to_string(),
            "file.read".to_string(),
            "pkg.install".to_string(),
        ]
    );
}

#[test]
fn snapshot_accessors_empty_policy() {
    let policy = from_toml_str("").expect("empty TOML must parse as deny-all");
    assert!(!policy.raw_exec_enabled());
    assert!(policy.raw_allow_patterns().is_empty());
    assert!(policy.raw_deny_patterns().is_empty());
    assert!(policy.allowed_operations().is_empty());
}

#[test]
fn allowed_operations_dedups() {
    let toml = r#"
[[operation]]
name = "service.restart"
allowed_args = [["nginx"]]

[[operation]]
name = "service.restart"
allowed_args = [["php-fpm"]]
"#;
    let policy = from_toml_str(toml).expect("inline policy must parse");
    assert_eq!(
        policy.allowed_operations(),
        vec!["service.restart".to_string()],
        "duplicate operation names must appear once, first-appearance order"
    );
}

#[test]
fn snapshot_operation_rules_from_fixture() {
    let policy = fixture_policy();
    assert_eq!(
        policy.operation_allow_rules(),
        vec![
            OperationAllowRule {
                name: "service.restart".to_string(),
                allowed_args: vec![vec!["nginx".to_string(), "php-fpm".to_string()]],
            },
            OperationAllowRule {
                name: "system.facts".to_string(),
                allowed_args: vec![],
            },
            OperationAllowRule {
                name: "file.read".to_string(),
                allowed_args: vec![vec!["*".to_string()]],
            },
            OperationAllowRule {
                name: "pkg.install".to_string(),
                allowed_args: vec![
                    vec!["nginx".to_string(), "curl".to_string()],
                    vec!["*".to_string()],
                ],
            },
        ],
        "operation_allow_rules must preserve every [[operation]] block, in file order"
    );
}

#[test]
fn snapshot_deny_rules_from_fixture() {
    let policy = fixture_policy();
    assert_eq!(
        policy.deny_rules(),
        vec![OperationDenyRule {
            name: "file.read".to_string(),
            args: vec![vec!["/etc/shadow".to_string()]],
        }]
    );
}

#[test]
fn snapshot_operation_and_deny_rules_empty_policy() {
    let policy = from_toml_str("").expect("empty TOML must parse as deny-all");
    assert!(policy.operation_allow_rules().is_empty());
    assert!(policy.deny_rules().is_empty());
}

#[test]
fn operation_allow_rules_keeps_duplicates_no_dedup() {
    let toml = r#"
[[operation]]
name = "service.restart"
allowed_args = [["nginx"]]

[[operation]]
name = "service.restart"
allowed_args = [["php-fpm"]]
"#;
    let policy = from_toml_str(toml).expect("inline policy must parse");
    assert_eq!(
        policy.operation_allow_rules(),
        vec![
            OperationAllowRule {
                name: "service.restart".to_string(),
                allowed_args: vec![vec!["nginx".to_string()]],
            },
            OperationAllowRule {
                name: "service.restart".to_string(),
                allowed_args: vec![vec!["php-fpm".to_string()]],
            },
        ],
        "unlike allowed_operations, operation_allow_rules must keep every block \
             (no dedup by name) since arg rules are per-block"
    );
}

// -----------------------------------------------------------------------
// Lint tests (#93)
// -----------------------------------------------------------------------

#[test]
fn lint_fixture_is_clean() {
    // Guards against false positives: the fixture's `file.read "*"` +
    // deny `/etc/shadow` is a partial shadow (the allow still fires for
    // every other path) and must NOT be flagged.
    let report = lint(FIXTURE);
    assert!(
        report.parse_error.is_none(),
        "fixture must parse cleanly; got {:?}",
        report.parse_error
    );
    assert!(
        report.findings.is_empty(),
        "fixture must lint with zero findings; got {:?}",
        report.findings
    );
}

#[test]
fn lint_reports_all_invalid_regexes() {
    let bad_policy = r#"
[raw_exec]
allow = ["[invalid1", "[invalid2"]
"#;
    let report = lint(bad_policy);
    assert!(report.parse_error.is_none());
    let errors: Vec<_> = report
        .findings
        .iter()
        .filter(|f| f.severity == LintSeverity::Error)
        .collect();
    assert_eq!(
            errors.len(),
            2,
            "both invalid regexes must be reported (collect-all, unlike from_toml_str's fail-on-first); got {:?}",
            report.findings
        );
    assert!(errors[0].location.contains("allow[0]"));
    assert!(errors[1].location.contains("allow[1]"));
}

#[test]
fn lint_reports_unknown_operation() {
    let policy = r#"
[[operation]]
name = "pkg.remove"
allowed_args = []
"#;
    let report = lint(policy);
    assert!(report.parse_error.is_none());
    assert_eq!(
        report.findings.len(),
        1,
        "unknown operation name must produce exactly one finding; got {:?}",
        report.findings
    );
    let finding = &report.findings[0];
    // Warning, not Error, when the caller supplied no template set: since
    // ADR-0021 an unrecognized name may be a Template Operation on the
    // target Node, and this linter cannot tell that from a typo. It names
    // the fix, and --strict still fails the pipeline on it.
    assert_eq!(finding.severity, LintSeverity::Warning);
    assert!(finding.location.contains("[[operation]] #0"));
    assert!(finding.message.contains("pkg.remove"));
    assert!(
        finding.message.contains("--templates"),
        "the warning must name the fix; got {:?}",
        finding.message
    );
}

/// With a template set supplied, the vocabulary IS knowable — so a name in
/// neither half is provably unrunnable there and returns to an Error.
#[test]
fn lint_with_vocabulary_errors_on_a_name_in_neither_half() {
    let policy = r#"
[[operation]]
name = "pkg.remove"
allowed_args = []
"#;
    let names = vec!["disk.usage".to_string()];
    let report = lint_with_vocabulary(policy, &names, true);
    assert_eq!(report.findings.len(), 1);
    assert_eq!(report.findings[0].severity, LintSeverity::Error);
    assert!(report.has_errors());

    // ...and a rule naming a supplied template is clean.
    let ok = r#"
[[operation]]
name = "disk.usage"
allowed_args = []
"#;
    let report = lint_with_vocabulary(ok, &names, true);
    assert!(
        report.findings.is_empty(),
        "a rule naming a loaded template must lint clean; got {:?}",
        report.findings
    );
}

#[test]
fn lint_reports_unknown_operation_in_deny() {
    let policy = r#"
[[deny]]
name = "pkg.remove"
args = []
"#;
    let report = lint(policy);
    assert_eq!(report.findings.len(), 1);
    let finding = &report.findings[0];
    // Warning without a template set, for the same reason as the allow-side
    // check above; still flagged, because a no-op deny an operator believes
    // is protecting them is the dangerous reading.
    assert_eq!(finding.severity, LintSeverity::Warning);
    assert!(finding.location.contains("[[deny]] #0"));
    assert!(finding.message.contains("pkg.remove"));
}

#[test]
fn lint_flags_fully_shadowed_allow() {
    // Non-empty deny.args that exactly covers the allow's single position.
    let policy = r#"
[[operation]]
name = "service.restart"
allowed_args = [["nginx"]]

[[deny]]
name = "service.restart"
args = [["nginx"]]
"#;
    let report = lint(policy);
    assert!(report.parse_error.is_none());
    assert_eq!(
        report.findings.len(),
        1,
        "fully shadowed allow must produce exactly one finding; got {:?}",
        report.findings
    );
    let finding = &report.findings[0];
    assert_eq!(finding.severity, LintSeverity::Warning);
    assert!(finding.location.contains("[[operation]] #0"));
    assert!(finding.message.contains("[[deny]] #0"));
}

#[test]
fn lint_flags_shadowed_allow_by_empty_args_deny() {
    // An empty deny.args blocks the operation entirely regardless of arguments.
    let policy = r#"
[[operation]]
name = "service.restart"
allowed_args = [["nginx"]]

[[deny]]
name = "service.restart"
args = []
"#;
    let report = lint(policy);
    assert_eq!(
        report.findings.len(),
        1,
        "empty-args deny must shadow the allow unconditionally; got {:?}",
        report.findings
    );
    assert_eq!(report.findings[0].severity, LintSeverity::Warning);
}

#[test]
fn lint_does_not_flag_partial_shadow() {
    // allow file.read "*" + deny file.read "/etc/shadow" — the allow
    // still fires for every other path, so it must NOT be flagged.
    let policy = r#"
[[operation]]
name = "file.read"
allowed_args = [["*"]]

[[deny]]
name = "file.read"
args = [["/etc/shadow"]]
"#;
    let report = lint(policy);
    assert!(
        report.findings.is_empty(),
        "partial shadow (wildcard allow position) must not be flagged; got {:?}",
        report.findings
    );
}

// -----------------------------------------------------------------------
// No-op deny args lint (issue #343). A native `name` and no `[[operation]]`
// rule keeps the unknown-name and shadowed-allow lints silent, so any
// finding is unambiguously from `lint_deny_arg_noops`.
// -----------------------------------------------------------------------

#[test]
fn lint_flags_wildcard_in_deny_args() {
    // `args = [["*"]]` reads like "deny any value" but deny args are
    // exact-match: it denies only the literal "*", so the rule is dead.
    let policy = r#"
[[deny]]
name = "file.read"
args = [["*"]]
"#;
    let report = lint(policy);
    assert_eq!(
        report.findings.len(),
        1,
        "a '*' in deny args must be flagged; got {:?}",
        report.findings
    );
    let f = &report.findings[0];
    assert_eq!(f.severity, LintSeverity::Warning);
    assert!(f.location.contains("[[deny]] #0"));
    assert!(f.location.contains("args[0]"));
    assert!(
        f.message.contains("literally") && f.message.contains("wildcard"),
        "message must explain '*' is literal, not a wildcard; got {:?}",
        f.message
    );
}

#[test]
fn lint_flags_wildcard_even_alongside_real_values() {
    // The '*' is dead weight even when the position also lists real values:
    // the operator likely believes the position is a catch-all deny.
    let policy = r#"
[[deny]]
name = "file.read"
args = [["/etc/shadow", "*"]]
"#;
    let report = lint(policy);
    assert_eq!(report.findings.len(), 1, "got {:?}", report.findings);
    assert_eq!(report.findings[0].severity, LintSeverity::Warning);
    assert!(report.findings[0].message.contains("wildcard"));
}

#[test]
fn lint_flags_empty_inner_args_list_in_deny() {
    // `args = [[]]` — one position with no values — can be satisfied by no
    // argument, so the whole deny never fires. Distinct from `args = []`.
    let policy = r#"
[[deny]]
name = "file.read"
args = [[]]
"#;
    let report = lint(policy);
    assert_eq!(
        report.findings.len(),
        1,
        "an empty inner args position must be flagged; got {:?}",
        report.findings
    );
    let f = &report.findings[0];
    assert_eq!(f.severity, LintSeverity::Warning);
    assert!(f.location.contains("args[0]"));
    assert!(
        f.message.contains("never fire"),
        "message must say the rule can never fire; got {:?}",
        f.message
    );
}

#[test]
fn lint_does_not_flag_outer_empty_deny_all() {
    // `args = []` is the legitimate unconditional deny-all — NOT a no-op.
    let policy = r#"
[[deny]]
name = "file.read"
args = []
"#;
    let report = lint(policy);
    assert!(
        report.findings.is_empty(),
        "the deny-all rule (empty outer args) must not be flagged; got {:?}",
        report.findings
    );
}

#[test]
fn lint_does_not_flag_exact_value_deny() {
    // A real exact-match deny has neither a '*' nor an empty position.
    let policy = r#"
[[deny]]
name = "file.read"
args = [["/etc/shadow"]]
"#;
    let report = lint(policy);
    assert!(
        report.findings.is_empty(),
        "an exact-value deny must lint clean; got {:?}",
        report.findings
    );
}

#[test]
fn lint_does_not_flag_finite_partial_shadow() {
    // allow service.restart [nginx, php-fpm] + deny service.restart
    // [nginx] — neither allowed value is "*", so this reaches the `.all()`
    // finite-subset predicate at allow_is_shadowed_by_deny (unlike
    // lint_does_not_flag_partial_shadow above, which is rejected one
    // clause earlier by the wildcard guard). php-fpm is not covered by
    // the deny, so the allow can still fire and must NOT be flagged.
    let policy = r#"
[[operation]]
name = "service.restart"
allowed_args = [["nginx", "php-fpm"]]

[[deny]]
name = "service.restart"
args = [["nginx"]]
"#;
    let report = lint(policy);
    assert!(report.parse_error.is_none());
    assert!(
        report.findings.is_empty(),
        "finite partial shadow (php-fpm still uncovered) must not be flagged; got {:?}",
        report.findings
    );
}

#[test]
fn lint_reports_invalid_regex_in_deny_section() {
    // Mirrors lint_reports_all_invalid_regexes but feeds the deny section,
    // exercising the otherwise-unexercised
    // lint_raw_exec_regexes(&file.raw_exec.deny, ...) call.
    let bad_policy = r#"
[raw_exec]
deny = ["[invalid"]
"#;
    let report = lint(bad_policy);
    assert!(report.parse_error.is_none());
    let errors: Vec<_> = report
        .findings
        .iter()
        .filter(|f| f.severity == LintSeverity::Error)
        .collect();
    assert_eq!(
        errors.len(),
        1,
        "invalid deny-section regex must be reported; got {:?}",
        report.findings
    );
    assert!(errors[0].location.contains("[raw_exec].deny[0]"));
}

#[test]
fn lint_reports_toml_parse_error() {
    let malformed = "this is not [ valid toml =";
    let report = lint(malformed);
    assert!(
        report.parse_error.is_some(),
        "malformed TOML must set parse_error"
    );
    assert!(
        report.findings.is_empty(),
        "no findings should be collected when the file fails to parse"
    );
}

#[test]
fn lint_report_has_errors_and_has_warnings() {
    let error_only = LintReport {
        parse_error: None,
        parse_errors: vec![],
        findings: vec![LintFinding {
            severity: LintSeverity::Error,
            location: "x".to_string(),
            message: "y".to_string(),
        }],
    };
    assert!(error_only.has_errors());
    assert!(!error_only.has_warnings());

    let warning_only = LintReport {
        parse_error: None,
        parse_errors: vec![],
        findings: vec![LintFinding {
            severity: LintSeverity::Warning,
            location: "x".to_string(),
            message: "y".to_string(),
        }],
    };
    assert!(!warning_only.has_errors());
    assert!(warning_only.has_warnings());

    let parse_err = LintReport {
        parse_error: Some("bad".to_string()),
        parse_errors: vec!["bad".to_string()],
        findings: vec![],
    };
    assert!(parse_err.has_errors());
    assert!(!parse_err.has_warnings());
}

// -----------------------------------------------------------------------
// Policy fragments: one Policy, one fingerprint, deny beating allow across
// every file.
// -----------------------------------------------------------------------

const EMPTY_SHA256: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

const ALLOW_RESTART_NGINX: &str =
    "[[operation]]\nname = \"service.restart\"\nallowed_args = [[\"nginx\"]]\n";
const DENY_RESTART_NGINX: &str = "[[deny]]\nname = \"service.restart\"\nargs = [[\"nginx\"]]\n";
const ALLOW_FILE_READ: &str = "[[operation]]\nname = \"file.read\"\nallowed_args = [[\"*\"]]\n";
const ALLOW_RAW_TRUE: &str = "[raw_exec]\nallow = [\"^/bin/true$\"]\n";
const DENY_RAW_TRUE: &str = "[raw_exec]\ndeny = [\"^/bin/true$\"]\n";

fn fragment(name: &str, text: &str) -> Fragment {
    Fragment {
        name: name.to_string(),
        text: text.to_string(),
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    ring::digest::digest(&ring::digest::SHA256, bytes)
        .as_ref()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// The documented set-fingerprint stream, built independently of the loader.
fn set_stream(records: &[(&str, &str)]) -> Vec<u8> {
    let mut stream = b"relay-policy-set-v1\n".to_vec();
    for (label, text) in records {
        stream.extend_from_slice(label.as_bytes());
        stream.push(0);
        stream.extend_from_slice(text.len().to_string().as_bytes());
        stream.push(b'\n');
        stream.extend_from_slice(text.as_bytes());
    }
    stream
}

fn restart(policy: &Policy, service: &str) -> Explained {
    policy.decide(&Request::Operation {
        name: "service.restart",
        positional: &args(&[service]),
        path_positions: &[],
    })
}

// Proves DI-36.
#[test]
fn an_empty_fragment_set_keeps_the_raw_bytes_fingerprint() {
    let composed = compose(FIXTURE, &[]).expect("fixture composes");
    let direct = from_toml_str(FIXTURE).expect("fixture parses");
    assert_eq!(composed.fingerprint(), direct.fingerprint());
    assert_eq!(
        composed.fingerprint(),
        sha256_hex(FIXTURE.as_bytes()),
        "with no fragment the fingerprint is the SHA-256 of the Policy file's raw bytes"
    );
    assert_eq!(
        compose("", &[]).expect("empty composes").fingerprint(),
        EMPTY_SHA256
    );
}

/// With no Policy file the fragments compose by the same rules, and the set
/// fingerprint omits the Policy file's record rather than recording it empty.
#[test]
fn fragments_compose_alone_with_no_policy_file() {
    let fragments = [
        fragment("b", ALLOW_RAW_TRUE),
        fragment("a", ALLOW_RESTART_NGINX),
    ];
    let policy = compose_fragments(&fragments).expect("composes");
    assert!(matches!(
        restart(&policy, "nginx").decision,
        Decision::Allow(_)
    ));
    assert!(matches!(
        policy.evaluate_raw_exec(&args(&["/bin/true"])),
        Decision::Allow(_)
    ));
    assert!(matches!(
        restart(&policy, "sshd").decision,
        Decision::Deny { .. }
    ));
    assert_eq!(
        policy.fingerprint(),
        sha256_hex(&set_stream(&[
            ("policy.d/a", ALLOW_RESTART_NGINX),
            ("policy.d/b", ALLOW_RAW_TRUE),
        ]))
    );
    assert_ne!(
        policy.fingerprint(),
        compose("", &fragments).expect("composes").fingerprint(),
        "a missing Policy file is not fingerprinted as an empty one"
    );

    // A fragment rule has no line, the first fragment's included.
    let first = restart(&policy, "nginx");
    assert_eq!(first.rule.expect("an allow rule decided").line, None);

    // Deny-by-default: an empty composition denies everything.
    let empty = compose_fragments(&[]).expect("composes");
    assert!(matches!(
        restart(&empty, "nginx").decision,
        Decision::Deny { .. }
    ));
    assert!(matches!(
        empty.evaluate_raw_exec(&args(&["/bin/true"])),
        Decision::Deny { .. }
    ));
}

// Proves DI-36.
#[test]
fn fragments_compose_into_one_policy_with_one_fingerprint() {
    let fragments = [
        fragment("a", ALLOW_FILE_READ),
        fragment("b", ALLOW_RAW_TRUE),
    ];
    let policy = compose(ALLOW_RESTART_NGINX, &fragments).expect("composes");

    assert!(matches!(
        restart(&policy, "nginx").decision,
        Decision::Allow(_)
    ));
    assert!(matches!(
        policy.evaluate("file.read", &args(&["/etc/hostname"])),
        Decision::Allow(_)
    ));
    assert!(matches!(
        policy.evaluate_raw_exec(&args(&["/bin/true"])),
        Decision::Allow(_)
    ));

    let expected = sha256_hex(&set_stream(&[
        ("policy.toml", ALLOW_RESTART_NGINX),
        ("policy.d/a", ALLOW_FILE_READ),
        ("policy.d/b", ALLOW_RAW_TRUE),
    ]));
    assert_eq!(policy.fingerprint(), expected);
    assert_ne!(
        policy.fingerprint(),
        sha256_hex(ALLOW_RESTART_NGINX.as_bytes()),
        "a Policy with fragments is not fingerprinted as its Policy file alone"
    );

    let reversed = [fragments[1].clone(), fragments[0].clone()];
    let same = compose(ALLOW_RESTART_NGINX, &reversed).expect("composes");
    assert_eq!(
        same.fingerprint(),
        expected,
        "the order of the slice must not matter: composition sorts by name"
    );

    let renamed = [fragment("c", ALLOW_FILE_READ), fragments[1].clone()];
    assert_ne!(
        compose(ALLOW_RESTART_NGINX, &renamed)
            .unwrap()
            .fingerprint(),
        expected,
        "a fragment's file name is part of the fingerprint"
    );
    let edited = [
        fragment("a", &format!("{ALLOW_FILE_READ}\n")),
        fragments[1].clone(),
    ];
    assert_ne!(
        compose(ALLOW_RESTART_NGINX, &edited).unwrap().fingerprint(),
        expected,
        "a fragment's bytes are part of the fingerprint"
    );
}

// Proves DI-36.
#[test]
fn deny_in_any_file_beats_allow_in_any_other() {
    let denied_operation = |policy_file: &str, fragments: &[Fragment]| {
        let policy = compose(policy_file, fragments).expect("composes");
        let explained = restart(&policy, "nginx");
        assert!(
            matches!(explained.decision, Decision::Deny { .. }),
            "got {:?}",
            explained.decision
        );
        assert_eq!(explained.pass, Pass::Deny);
    };
    // A Policy-file allow, a fragment deny.
    denied_operation(
        ALLOW_RESTART_NGINX,
        &[fragment("deny.toml", DENY_RESTART_NGINX)],
    );
    // A fragment allow, a Policy-file deny.
    denied_operation(
        DENY_RESTART_NGINX,
        &[fragment("allow.toml", ALLOW_RESTART_NGINX)],
    );
    // An allow in one fragment, a deny in another, in either name order.
    denied_operation(
        "",
        &[
            fragment("1-allow.toml", ALLOW_RESTART_NGINX),
            fragment("2-deny.toml", DENY_RESTART_NGINX),
        ],
    );
    denied_operation(
        "",
        &[
            fragment("1-deny.toml", DENY_RESTART_NGINX),
            fragment("2-allow.toml", ALLOW_RESTART_NGINX),
        ],
    );

    // Raw Exec: an allow in the Policy file, a deny in a fragment.
    let policy = compose(ALLOW_RAW_TRUE, &[fragment("deny.toml", DENY_RAW_TRUE)]).unwrap();
    let argv = args(&["/bin/true"]);
    let explained = policy.decide(&Request::RawExec { argv: &argv });
    assert!(matches!(explained.decision, Decision::Deny { .. }));
    assert_eq!(explained.pass, Pass::Deny);
    assert!(explained.raw_exec_permit.is_none());
}

// Proves DI-36.
#[test]
fn a_broken_fragment_is_named_in_the_error() {
    let broken_toml = compose("", &[fragment("x.toml", "this is = = not toml")]);
    let Err(PolicyError::FragmentInvalid { name, source }) = broken_toml else {
        panic!("a fragment parse error must be FragmentInvalid");
    };
    assert_eq!(name, "x.toml");
    assert!(matches!(*source, PolicyError::Parse(_)));

    let broken_regex = compose(
        "",
        &[fragment("x.toml", "[raw_exec]\nallow = [\"[unclosed\"]\n")],
    )
    .unwrap_err();
    assert!(
        matches!(&broken_regex, PolicyError::FragmentInvalid { source, .. }
            if matches!(**source, PolicyError::InvalidRegex { .. })),
        "got {broken_regex:?}"
    );
    assert!(
        broken_regex.to_string().contains("\"x.toml\""),
        "the message must quote the fragment's name: {broken_regex}"
    );

    // A newline in a file name is escaped, so it cannot split a journal line.
    let hostile = compose(
        "",
        &[fragment("a\nb.toml", "[raw_exec]\nallow = [\"[\"]\n")],
    )
    .unwrap_err()
    .to_string();
    assert!(
        hostile.starts_with("Policy fragment \"a\\nb.toml\" is invalid: "),
        "got {hostile:?}"
    );
    let refusal = PolicyError::FragmentSymlink {
        name: "a\nb.toml".to_string(),
    }
    .to_string();
    assert!(!refusal.contains('\n'), "got {refusal:?}");

    // A failure in the Policy file keeps its own variant, with no fragment named.
    let file_error = compose("not toml = =", &[fragment("ok.toml", "")]).unwrap_err();
    assert!(
        matches!(file_error, PolicyError::Parse(_)),
        "got {file_error:?}"
    );
}

#[test]
fn fragment_rules_carry_composed_index_and_no_line() {
    let policy = compose(
        ALLOW_RESTART_NGINX,
        &[
            fragment("a", ALLOW_FILE_READ),
            fragment("b", DENY_RESTART_NGINX),
        ],
    )
    .unwrap();

    let at = restart(&policy, "nginx")
        .rule
        .expect("the deny from fragment b decided");
    assert_eq!(
        (at.section, at.index, at.line),
        (RuleSection::Deny, 0, None),
        "a fragment rule has the composed index and no line"
    );

    let only_file = compose(ALLOW_RESTART_NGINX, &[fragment("a", ALLOW_FILE_READ)]).unwrap();
    let at = restart(&only_file, "nginx").rule.expect("file allow");
    assert_eq!(
        (at.section, at.index, at.line),
        (RuleSection::Operation, 0, Some(1)),
        "a Policy-file rule keeps its own index and line"
    );
    let read = only_file.decide(&Request::Operation {
        name: "file.read",
        positional: &args(&["/etc/hostname"]),
        path_positions: &[0],
    });
    let at = read.rule.expect("fragment allow");
    assert_eq!(
        (at.section, at.index, at.line),
        (RuleSection::Operation, 1, None),
        "the fragment's allow follows the Policy file's in the composed section"
    );
}

#[test]
fn snapshot_lists_follow_composition_order() {
    let policy = compose(
        ALLOW_RESTART_NGINX,
        &[
            fragment("b", ALLOW_RAW_TRUE),
            fragment("a", ALLOW_FILE_READ),
        ],
    )
    .unwrap();
    let names: Vec<String> = policy
        .operation_allow_rules()
        .into_iter()
        .map(|r| r.name)
        .collect();
    assert_eq!(names, ["service.restart", "file.read"]);
    assert_eq!(policy.raw_allow_patterns(), ["^/bin/true$"]);
}

#[test]
fn refuses_start_classifies_every_variant() {
    let io = || std::io::Error::other("x");
    let toml_error = toml::from_str::<PolicyFile>("= =").unwrap_err();
    let regex_error = compile_deny_regex("[").unwrap_err();
    let name = || "f.toml".to_string();

    let refusals = [
        PolicyError::FragmentSymlink { name: name() },
        PolicyError::FragmentNotRegularFile { name: name() },
        PolicyError::FragmentInsecurePermissions {
            name: name(),
            mode: 0o666,
        },
        PolicyError::FragmentInsecureOwner {
            name: name(),
            uid: 1,
        },
        PolicyError::PolicyDirectorySymlink,
        PolicyError::PolicyDirectoryNotADirectory,
        PolicyError::PolicyDirectoryInsecurePermissions { mode: 0o777 },
        PolicyError::PolicyDirectoryInsecureOwner { uid: 1 },
    ];
    for e in &refusals {
        assert!(e.refuses_start(), "{e:?} must refuse start");
    }

    let deny_all = [
        PolicyError::InsecurePermissions { mode: 0o666 },
        PolicyError::InsecureOwner { uid: 1 },
        PolicyError::SymlinkPath,
        PolicyError::NotRegularFile,
        PolicyError::Io(io()),
        PolicyError::Parse(toml_error),
        PolicyError::InvalidRegex {
            pattern: "[".to_string(),
            source: regex_error,
            hint: String::new(),
        },
        PolicyError::FragmentUnreadable {
            name: name(),
            source: io(),
        },
        PolicyError::FragmentInvalid {
            name: name(),
            source: Box::new(PolicyError::SymlinkPath),
        },
        PolicyError::FragmentName {
            name: std::ffi::OsString::from("f"),
        },
        PolicyError::PolicyDirectoryIo(io()),
    ];
    for e in &deny_all {
        assert!(!e.refuses_start(), "{e:?} must leave the daemon deny-all");
    }
}

// -----------------------------------------------------------------------
// Lint over a Policy file and its fragments
// -----------------------------------------------------------------------

#[test]
fn lint_composed_with_no_fragment_equals_the_single_source_lint() {
    for text in [
        FIXTURE,
        "[[operation]]\nname = \"nope\"\n",
        "[[operation]]\nname = \"service.restart\"\nallowed_args = [[\"nginx\"]]\n[[deny]]\nname = \"service.restart\"\n",
        "this is = = not toml",
    ] {
        assert_eq!(
            lint_composed(text, &[], &[], false),
            lint_with_vocabulary(text, &[], false)
        );
    }
}

#[test]
fn lint_composed_shadows_an_allow_across_files() {
    let report = lint_composed(
        ALLOW_RESTART_NGINX,
        &[fragment("deny.toml", DENY_RESTART_NGINX)],
        &[],
        false,
    );
    assert!(report.parse_error.is_none());
    assert_eq!(report.findings.len(), 1, "{:?}", report.findings);
    let finding = &report.findings[0];
    assert_eq!(finding.severity, LintSeverity::Warning);
    assert_eq!(
        finding.location, "[[operation]] #0 (name=\"service.restart\")",
        "a Policy-file allow keeps its plain location"
    );
    assert!(
        finding
            .message
            .contains("[[deny]] #0 (name=\"service.restart\") in \"deny.toml\""),
        "the message names the deny's fragment: {}",
        finding.message
    );

    let report = lint_composed(
        DENY_RESTART_NGINX,
        &[fragment("allow.toml", ALLOW_RESTART_NGINX)],
        &[],
        false,
    );
    assert_eq!(
        report.findings[0].location,
        "\"allow.toml\": [[operation]] #0 (name=\"service.restart\")"
    );
    assert!(!report.findings[0].message.contains(" in "));
}

#[test]
fn lint_composed_prefixes_a_fragment_finding_with_its_name() {
    let report = lint_composed(
        "",
        &[fragment("bad.toml", "[raw_exec]\nallow = [\"[x\"]\n")],
        &[],
        true,
    );
    assert!(report.has_errors());
    assert!(report
        .findings
        .iter()
        .all(|f| f.location.starts_with("\"bad.toml\": [raw_exec].allow[0]")));

    let unknown = lint_composed(
        "",
        &[fragment(
            "ops.toml",
            "[[operation]]\nname = \"nope.nope\"\n",
        )],
        &[],
        true,
    );
    assert_eq!(unknown.findings.len(), 1);
    assert_eq!(unknown.findings[0].severity, LintSeverity::Error);
    assert!(unknown.findings[0].location.starts_with("\"ops.toml\": "));
}

#[test]
fn lint_composed_reports_every_failing_source() {
    let report = lint_composed(
        "= =",
        &[
            fragment("b.toml", "also = ="),
            fragment("a.toml", "[raw_exec]\n"),
            fragment("c.toml", "x = ="),
        ],
        &[],
        false,
    );
    assert!(report.findings.is_empty());
    assert_eq!(report.parse_errors.len(), 3);
    assert!(!report.parse_errors[0].starts_with("\"b.toml\": "));
    assert!(report.parse_errors[1].starts_with("\"b.toml\": "));
    assert!(report.parse_errors[2].starts_with("\"c.toml\": "));
    assert_eq!(
        report.parse_error.as_deref(),
        Some(report.parse_errors.join("\n").as_str())
    );
}

// -----------------------------------------------------------------------
// Unknown keys are a parse error, so lint and the loader agree
// -----------------------------------------------------------------------

#[test]
fn an_unknown_key_at_every_level_is_a_parse_error_naming_the_key() {
    for (text, key) in [
        ("[[denny]]\nname = \"service.restart\"\n", "denny"),
        ("[raw_exec]\nalow = [\"^ls$\"]\n", "alow"),
        (
            "[[deny]]\nnmae = \"service.restart\"\nname = \"service.restart\"\n",
            "nmae",
        ),
        (
            "[[operation]]\nname = \"service.restart\"\nallowed_arg = [[\"nginx\"]]\n",
            "allowed_arg",
        ),
    ] {
        let err = from_toml_str(text).expect_err(text);
        assert!(matches!(err, PolicyError::Parse(_)), "{text}: {err:?}");
        assert!(err.to_string().contains(key), "{text}: {err}");

        let report = lint(text);
        let parse_error = report.parse_error.as_deref().expect(text);
        assert!(parse_error.contains(key), "{text}: {parse_error}");
        assert!(report.has_errors(), "{text}");
    }
}

#[test]
fn every_key_the_loader_reads_is_accepted() {
    let text = "[[operation]]\nname = \"service.restart\"\nallowed_args = [[\"nginx\"]]\n\
         [[deny]]\nname = \"file.read\"\nargs = [[\"/etc/shadow\"]]\n\
         [raw_exec]\nallow = [\"^ls$\"]\ndeny = [\"rm\"]\n";
    assert!(from_toml_str(text).is_ok());
    assert!(lint(text).findings.is_empty());
}

#[test]
fn lint_composed_reports_an_unknown_key_in_a_fragment_under_its_name() {
    let report = lint_composed(
        ALLOW_RESTART_NGINX,
        &[fragment(
            "90-deny.toml",
            "[[denny]]\nname = \"service.restart\"\nargs = []\n",
        )],
        &[],
        false,
    );
    assert_eq!(report.parse_errors.len(), 1, "{:?}", report.parse_errors);
    assert!(
        report.parse_errors[0].starts_with("\"90-deny.toml\": "),
        "{}",
        report.parse_errors[0]
    );
    assert!(
        report.parse_errors[0].contains("denny"),
        "{}",
        report.parse_errors[0]
    );
    assert!(report.has_errors());
}

#[test]
fn lint_escapes_a_fragment_name_with_control_characters() {
    let report = lint_composed("", &[fragment("a\nb.toml", "[[denny]]\n")], &[], false);
    assert!(
        report.parse_errors[0].starts_with("\"a\\nb.toml\": "),
        "{}",
        report.parse_errors[0]
    );
}
