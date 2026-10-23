#![cfg(test)]
//! ---------------------------------------------------------------------------
//! `Policy::decide` — the pass, the rule and the evidence behind each verdict.
//! A sibling module: it never edits the suites above, which reach the engine
//! through the `evaluate*` test shims and so prove `decide`'s verdicts are
//! unchanged.
//! ---------------------------------------------------------------------------
use super::*;
use proptest::prelude::*;

fn s(items: &[&str]) -> Vec<String> {
    items.iter().map(|x| (*x).to_string()).collect()
}

/// A Policy whose rules sit on known lines (the first line is line 1).
fn lined_policy() -> Policy {
    let text = [
        "# a leading comment",                    // 1
        "[[operation]]",                          // 2
        "name = \"service.restart\"",             // 3
        "allowed_args = [[\"nginx\", \"sshd\"]]", // 4
        "",                                       // 5
        "[[deny]]  # trailing comment",           // 6
        "name = \"service.restart\"",             // 7
        "args = [[\"sshd\"]]",                    // 8
        "",                                       // 9
        "[[deny]]",                               // 10
        "name = \"pkg.remove\"",                  // 11
        "args = []",                              // 12
        "",                                       // 13
        "[raw_exec]",                             // 14
        "allow = [",                              // 15
        "  \"^/bin/echo [a-z]*$\",",              // 16
        "  \"^/bin/true$\",",                     // 17
        "]",                                      // 18
        "deny = [",                               // 19
        "  \"^--force$\",",                       // 20
        "]",                                      // 21
    ]
    .join("\n");
    from_toml_str(&text).expect("fixture parses")
}

fn op<'a>(name: &'a str, positional: &'a [String], paths: &'a [usize]) -> Request<'a> {
    Request::Operation {
        name,
        positional,
        path_positions: paths,
    }
}

fn reason(e: &Explained) -> &str {
    match &e.decision {
        Decision::Deny { reason, .. } => reason,
        Decision::Allow(_) => "",
    }
}

fn at(section: RuleSection, index: usize, line: Option<usize>) -> Option<RuleRef> {
    Some(RuleRef {
        section,
        index,
        line,
    })
}

#[test]
fn decide_reports_pass_rule_and_matched_on() {
    let p = lined_policy();
    let nginx = s(&["nginx"]);
    let sshd = s(&["sshd"]);
    let other = s(&["cron"]);
    let bad_path = s(&["/etc/../shadow"]);
    let none: Vec<String> = Vec::new();

    // Operation requests: (request, pass, rule, matched_on, reason).
    let e = p.decide(&op("service.restart", &nginx, &[]));
    assert!(matches!(e.decision, Decision::Allow(_)));
    assert_eq!(e.pass, Pass::Allow);
    assert_eq!(e.rule, at(RuleSection::Operation, 0, Some(2)));
    assert_eq!(e.matched_on, MatchedOn::Arguments);
    assert!(e.raw_exec_permit.is_none());

    let e = p.decide(&op("service.restart", &sshd, &[]));
    assert_eq!(e.pass, Pass::Deny);
    assert_eq!(e.rule, at(RuleSection::Deny, 0, Some(6)));
    assert_eq!(e.matched_on, MatchedOn::Arguments);
    assert_eq!(
        reason(&e),
        "denied by explicit rule for operation 'service.restart'"
    );

    let e = p.decide(&op("pkg.remove", &nginx, &[]));
    assert_eq!(e.pass, Pass::Deny);
    assert_eq!(e.rule, at(RuleSection::Deny, 1, Some(10)));
    assert_eq!(e.matched_on, MatchedOn::WholeOperation);

    let e = p.decide(&op("service.restart", &other, &[]));
    assert_eq!(e.pass, Pass::Default);
    assert_eq!(e.rule, None);
    assert_eq!(e.matched_on, MatchedOn::NoMatchingArguments);
    assert_eq!(
        reason(&e),
        "no allow rule matched args [\"cron\"] for operation 'service.restart' \
             (allow rules exist for other arguments)"
    );

    let e = p.decide(&op("pkg.install", &nginx, &[]));
    assert_eq!(e.pass, Pass::Default);
    assert_eq!(e.matched_on, MatchedOn::NoAllowRule);
    assert_eq!(
        reason(&e),
        "deny-by-default: no allow rule for operation 'pkg.install'"
    );

    let e = p.decide(&op("file.read", &bad_path, &[0]));
    assert_eq!(e.pass, Pass::Precondition);
    assert_eq!(e.rule, None);
    assert_eq!(e.matched_on, MatchedOn::NonCanonicalPath { position: 0 });
    assert!(reason(&e).contains("not in canonical form (ADR-0018)"));

    // Raw Exec requests.
    let e = p.decide(&Request::RawExec { argv: &none });
    assert_eq!(e.pass, Pass::Precondition);
    assert_eq!(e.matched_on, MatchedOn::EmptyArgv);
    assert_eq!(reason(&e), "empty argv");
    assert!(e.raw_exec_permit.is_none());

    let argv = s(&["/bin/echo", "hi"]);
    let e = p.decide(&Request::RawExec { argv: &argv });
    assert!(matches!(e.decision, Decision::Allow(_)));
    assert_eq!(e.pass, Pass::Allow);
    assert_eq!(e.rule, at(RuleSection::RawExecAllow, 0, Some(16)));
    assert_eq!(e.matched_on, MatchedOn::WholeCommand);
    assert_eq!(e.raw_exec_permit.expect("permit").into_argv(), argv);

    let argv = s(&["/bin/echo", "--force"]);
    let e = p.decide(&Request::RawExec { argv: &argv });
    assert_eq!(e.pass, Pass::Deny);
    assert_eq!(e.rule, at(RuleSection::RawExecDeny, 0, Some(20)));
    assert_eq!(e.matched_on, MatchedOn::ArgvElement { index: 1 });
    assert_eq!(
        reason(&e),
        "raw exec denied by pattern \"^--force$\" (matched argv element \"--force\")"
    );
    assert!(e.raw_exec_permit.is_none());

    let argv = s(&["/bin/echo", "x --force"]);
    let e = p.decide(&Request::RawExec { argv: &argv });
    assert_eq!(e.pass, Pass::Deny);
    // The joined command re-split on whitespace: ["/bin/echo", "x", "--force"].
    assert_eq!(e.matched_on, MatchedOn::CanonicalElement { index: 2 });

    let argv = s(&["/bin/echo", "a b"]);
    let e = p.decide(&Request::RawExec { argv: &argv });
    assert_eq!(e.pass, Pass::Guard);
    assert_eq!(e.rule, None);
    assert_eq!(e.matched_on, MatchedOn::WhitespaceElement { index: 1 });
    assert_eq!(
        reason(&e),
        "raw exec argv[1] contains whitespace: no Raw Exec argument may carry \
             whitespace, so the command Policy matched is exactly the argv that \
             runs; pass such an argument through a Template Operation (ADR-0019)"
    );

    let argv = s(&["/bin/ls"]);
    let e = p.decide(&Request::RawExec { argv: &argv });
    assert_eq!(e.pass, Pass::Default);
    assert_eq!(e.matched_on, MatchedOn::NoRawExecAllow);
    assert_eq!(
        reason(&e),
        "deny-by-default: no raw_exec allow pattern matched"
    );
    assert!(e.raw_exec_permit.is_none());

    // A deny that matches the joined command only.
    let p2 = from_toml_str("[raw_exec]\ndeny = [\"echo hi\"]\n").unwrap();
    let argv = s(&["/bin/echo", "hi"]);
    let e = p2.decide(&Request::RawExec { argv: &argv });
    assert_eq!(e.matched_on, MatchedOn::JoinedCommand);
}

#[test]
fn rule_ref_display_uses_the_lint_location_grammar() {
    let r = |section, index, line| RuleRef {
        section,
        index,
        line,
    };
    assert_eq!(
        r(RuleSection::Operation, 1, None).to_string(),
        "[[operation]] #1"
    );
    assert_eq!(
        r(RuleSection::Deny, 0, Some(6)).to_string(),
        "[[deny]] #0, line 6"
    );
    assert_eq!(
        r(RuleSection::RawExecAllow, 2, Some(3)).to_string(),
        "[raw_exec].allow[2], line 3"
    );
    assert_eq!(
        r(RuleSection::RawExecDeny, 0, None).to_string(),
        "[raw_exec].deny[0]"
    );
}

fn line_of_rule(text: &str, section: RuleSection, index: usize) -> Option<usize> {
    let p = from_toml_str(text).expect("parses");
    let name = |sec: RuleSection| match sec {
        RuleSection::Operation => p.operations[index].at,
        RuleSection::Deny => p.denies[index].at,
        RuleSection::RawExecAllow => p.raw_allow[index].at,
        RuleSection::RawExecDeny => p.raw_deny[index].at,
    };
    name(section).line
}

#[test]
fn rule_lines_point_at_the_header_or_pattern() {
    // A plain header.
    let t = "[[operation]]\nname = \"x\"\n\n[[operation]]\nname = \"y\"\n";
    assert_eq!(line_of_rule(t, RuleSection::Operation, 0), Some(1));
    assert_eq!(line_of_rule(t, RuleSection::Operation, 1), Some(4));

    // A header with a trailing comment.
    let t = "# c\n[[operation]]  # note\nname = \"x\"\n";
    assert_eq!(line_of_rule(t, RuleSection::Operation, 0), Some(2));

    // An [[operation]] placed after [raw_exec].
    let t = "[raw_exec]\nallow = []\n\n[[operation]]\nname = \"x\"\n";
    assert_eq!(line_of_rule(t, RuleSection::Operation, 0), Some(4));

    // The inline form: the line of the `{`.
    let t = "\noperation = [{ name = \"x\", allowed_args = [] }]\n";
    assert_eq!(line_of_rule(t, RuleSection::Operation, 0), Some(2));

    // A multi-line allowed_args array stays on the header's line.
    let t = "[[operation]]\nname = \"x\"\nallowed_args = [\n  [\"a\"],\n  [\"b\"],\n]\n\n[[operation]]\nname = \"y\"\n";
    assert_eq!(line_of_rule(t, RuleSection::Operation, 0), Some(1));
    assert_eq!(line_of_rule(t, RuleSection::Operation, 1), Some(8));

    // [[deny]].
    let t = "[[operation]]\nname = \"x\"\n\n[[deny]]\nname = \"x\"\nargs = []\n";
    assert_eq!(line_of_rule(t, RuleSection::Deny, 0), Some(4));

    // Each raw_exec pattern on its own line inside a multi-line array.
    let t = "[raw_exec]\nallow = [\n  \"^a$\",\n  \"^b$\",\n]\ndeny = [\n  \"c\",\n  \"d\",\n]\n";
    assert_eq!(line_of_rule(t, RuleSection::RawExecAllow, 0), Some(3));
    assert_eq!(line_of_rule(t, RuleSection::RawExecAllow, 1), Some(4));
    assert_eq!(line_of_rule(t, RuleSection::RawExecDeny, 0), Some(7));
    assert_eq!(line_of_rule(t, RuleSection::RawExecDeny, 1), Some(8));
}

#[test]
fn line_of_is_none_without_a_usable_span() {
    assert_eq!(line_of("a\nb\n", 0..0), None);
    assert_eq!(line_of("a\nb\n", 2..2), None);
    assert_eq!(line_of("a\nb\n", 0..99), None);
    assert_eq!(line_of("a\nb\n", 2..3), Some(2));
}

#[test]
fn deny_star_is_literal_allow_star_is_any() {
    let p = from_toml_str(
        "[[operation]]\nname = \"a\"\nallowed_args = [[\"*\"]]\n\
             [[operation]]\nname = \"d\"\nallowed_args = [[\"x\", \"*\"]]\n\
             [[deny]]\nname = \"d\"\nargs = [[\"*\"]]\n",
    )
    .unwrap();
    // Allow `*` accepts any value.
    assert_eq!(p.decide(&op("a", &s(&["whatever"]), &[])).pass, Pass::Allow);
    // Deny `*` matches only the literal "*"; every other value falls
    // through to the allow pass.
    assert_eq!(p.decide(&op("d", &s(&["*"]), &[])).pass, Pass::Deny);
    assert_eq!(p.decide(&op("d", &s(&["x"]), &[])).pass, Pass::Allow);
}

#[test]
fn precondition_runs_before_deny_for_template_path_positions() {
    let p = from_toml_str("[[deny]]\nname = \"disk.usage\"\nargs = []\n").unwrap();
    let args = s(&["/var/../etc"]);
    let e = p.decide(&op("disk.usage", &args, &[0]));
    assert_eq!(e.pass, Pass::Precondition);
    assert_eq!(e.matched_on, MatchedOn::NonCanonicalPath { position: 0 });
    // Without a declared path position the deny rule decides, as before.
    let e = p.decide(&op("disk.usage", &args, &[]));
    assert_eq!(e.pass, Pass::Deny);
    // The first non-canonical position wins.
    let two = s(&["/ok", "/a//b", "/c/."]);
    let e = p.decide(&op("disk.usage", &two, &[0, 1, 2]));
    assert_eq!(e.matched_on, MatchedOn::NonCanonicalPath { position: 1 });
    // A position past the arguments is ignored.
    let e = p.decide(&op("disk.usage", &two, &[9]));
    assert_eq!(e.pass, Pass::Deny);
}

#[test]
fn guard_runs_after_deny_and_before_allow() {
    let p = from_toml_str("[raw_exec]\nallow = [\".*\"]\ndeny = [\"^--force$\"]\n").unwrap();
    // Whitespace argv that a deny claims: the deny keeps the attribution.
    let denied = s(&["/bin/x", "--force y"]);
    assert_eq!(
        p.decide(&Request::RawExec { argv: &denied }).pass,
        Pass::Deny
    );
    // Whitespace argv no deny claims: the guard refuses it, though an
    // allow-everything pattern would otherwise approve it.
    let guarded = s(&["/bin/x", "a b"]);
    let e = p.decide(&Request::RawExec { argv: &guarded });
    assert_eq!(e.pass, Pass::Guard);
    assert!(e.raw_exec_permit.is_none());
    // An empty argv[0] is the guard's too.
    let empty0 = s(&["", "x"]);
    assert_eq!(
        p.decide(&Request::RawExec { argv: &empty0 }).matched_on,
        MatchedOn::WhitespaceElement { index: 0 }
    );
}

#[test]
fn permit_debug_never_prints_the_argv() {
    let p = from_toml_str("[raw_exec]\nallow = [\".*\"]\n").unwrap();
    let argv = s(&["/bin/x", "SECRET-TOKEN"]);
    let permit = p
        .decide(&Request::RawExec { argv: &argv })
        .raw_exec_permit
        .expect("allowed");
    let shown = format!("{permit:?}");
    assert_eq!(shown, "RawExecPermit { argc: 2 }");
    assert!(!shown.contains("SECRET"));
}

/// The deleted `allow_is_shadowed_by_deny`, verbatim, as the oracle the
/// matcher-subsumption check must agree with.
fn reference_shadow(allow: &[Vec<String>], deny: &[Vec<String>]) -> bool {
    if deny.is_empty() {
        return true;
    }
    allow
        .iter()
        .enumerate()
        .all(|(i, allowed_vals)| match deny.get(i) {
            Some(denied_vals) => {
                !allowed_vals.iter().any(|v| v == "*")
                    && allowed_vals.iter().all(|v| denied_vals.contains(v))
            }
            None => true,
        })
}

fn arg_lists() -> impl Strategy<Value = Vec<Vec<String>>> {
    let val = prop::sample::select(vec!["a", "b", "c", "*", ""]).prop_map(str::to_string);
    prop::collection::vec(prop::collection::vec(val, 0..4), 0..4)
}

fn request_strategy() -> impl Strategy<Value = (bool, String, Vec<String>)> {
    let names = prop::sample::select(vec!["service.restart", "pkg.remove", "file.read", "other"])
        .prop_map(str::to_string);
    let arg = prop_oneof![
        prop::sample::select(vec![
            "nginx", "sshd", "/ok", "/a/../b", "--force", "a b", ""
        ])
        .prop_map(str::to_string),
        "\\PC{0,8}",
    ];
    (any::<bool>(), names, prop::collection::vec(arg, 0..4))
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    #[test]
    fn subsumption_agrees_with_reference_shadow_predicate(
        allow in arg_lists(),
        deny in arg_lists(),
    ) {
        let got = compile_deny_args(&deny).covers(&compile_allow_args(&allow));
        prop_assert_eq!(got, reference_shadow(&allow, &deny));
    }

    #[test]
    fn explained_is_consistent_with_decision((raw, name, args) in request_strategy()) {
        let p = lined_policy();
        let paths: &[usize] = if name == "file.read" { &[0] } else { &[] };
        let request = if raw {
            Request::RawExec { argv: &args }
        } else {
            Request::Operation { name: &name, positional: &args, path_positions: paths }
        };
        let e = p.decide(&request);
        let allowed = matches!(e.decision, Decision::Allow(_));
        prop_assert_eq!(e.pass == Pass::Allow, allowed);
        prop_assert_eq!(
            e.rule.is_some(),
            matches!(e.pass, Pass::Deny | Pass::Allow)
        );
        let deny_with_rule = matches!(e.decision, Decision::Deny { rule: Some(_), .. });
        prop_assert_eq!(deny_with_rule, e.pass == Pass::Deny);
        prop_assert_eq!(e.raw_exec_permit.is_some(), raw && e.pass == Pass::Allow);
        if let Some(permit) = e.raw_exec_permit {
            prop_assert_eq!(permit.into_argv(), args);
        }
    }
}
