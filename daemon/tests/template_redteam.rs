//! Red-team suite for the Template tier's value boundary (ADR-0021 amendment of
//! 2026-10-14, invariant 1).
//!
//! Every row is a reproduction from the #974 and #975 reviews that the
//! positional-parameter rendering must keep inert. A row compiles its body,
//! invokes it through the production `ResolvedOp::invoke`, and runs the rendered
//! argv through the production executor under dash, bash and `bash --posix`. A
//! body the lexer refuses is asserted to be refused at compile time. A missing
//! shell fails the test (`shell_runner`).
//!
//! The canary values spell the token the injected command prints as `PW""NED`,
//! so `PWNED` appears in an output only if a command actually ran.

#[path = "common/shell_runner.rs"]
mod shell_runner;

use relay_ops::operations::template::{compile, TemplateError};
use shell_runner::{
    invoke, path_template, retired_splice, run_sh_argv, shells, stderr, stdout, ShellRunner,
};

/// Values a `Path` slot accepts and that a shell would act on if it ever saw
/// them as text.
const CANARIES: [&str; 5] = [
    "/tmp/$(echo PW\"\"NED >&2)",
    "/tmp/`echo PW\"\"NED`",
    "/tmp/x;echo PW\"\"NED",
    "/tmp/a b",
    "/tmp/*",
];

fn refusal(body: &str) -> TemplateError {
    match compile(&path_template(body)) {
        Ok(_) => panic!("{body:?} must be refused at compile time"),
        Err(e) => e,
    }
}

fn assert_clean(label: &str, value: &str, r: &relay_proto::TaskResult) {
    let (out, err) = (stdout(r), stderr(r));
    assert!(
        !out.contains("PWNED") && !err.contains("PWNED"),
        "[{label}] {value:?} ran as a command: stdout={out:?} stderr={err:?}"
    );
}

/// Run `body` with every canary under every shell. With `expect`, also assert
/// the exact stdout (for values the context prints verbatim).
async fn every_canary_is_inert(body: &str, expect: Option<fn(&str) -> String>) {
    for shell in shells() {
        let runner = ShellRunner::new(&shell);
        for value in CANARIES {
            let r = invoke(&path_template(body), &[("p", value)], &runner).await;
            assert_clean(shell.label, value, &r);
            if let Some(expected) = expect {
                // An unquoted outer substitution globs `/tmp/*`; skip the
                // exact comparison for it only.
                if value == "/tmp/*" && body.contains('`') {
                    continue;
                }
                assert_eq!(stdout(&r), expected(value), "[{}] {value:?}", shell.label);
            }
        }
    }
}

#[tokio::test]
async fn here_document() {
    // An unquoted here-document expands `$(…)`; the value must arrive as data,
    // printed between the literal double quotes of the parameter reference.
    every_canary_is_inert("cat <<EOF\n{{p}}\nEOF", Some(|v| format!("\"{v}\"\n"))).await;
}

#[tokio::test]
async fn backquote() {
    every_canary_is_inert("echo `echo {{p}}`", Some(|v| format!("{v}\n"))).await;
}

#[tokio::test]
async fn command_substitution_with_a_quoted_close_paren() {
    // The `)` inside the inner double quotes does not end the `$(`: the
    // placeholder after it is still inside the substitution, and the lexer
    // agrees with the shell about where it ends.
    every_canary_is_inert(
        "echo \"$(echo \")\" {{p}} \")\")\"",
        Some(|v| format!(") {v} )\n")),
    )
    .await;
}

#[tokio::test]
async fn dollar_paren() {
    every_canary_is_inert("echo $(echo {{p}})", None).await;
}

#[tokio::test]
async fn escaped_space_is_not_a_boundary() {
    assert!(matches!(
        refusal("printf '[%s]\\n' a\\ {{p}}"),
        TemplateError::PlaceholderNotStandalone { .. }
    ));
    assert!(matches!(
        refusal("printf '[%s]\\n' {{p}}\\ a"),
        TemplateError::PlaceholderNotStandalone { .. }
    ));
}

#[tokio::test]
async fn form_feed_and_carriage_return_are_not_boundaries() {
    for body in [
        "printf '[%s]\\n' a\u{c}{{p}}",
        "printf '[%s]\\n' {{p}}\u{c}a",
        "printf '[%s]\\n' b\r{{p}}",
        "printf '[%s]\\n' {{p}}\rb",
    ] {
        assert!(
            matches!(
                refusal(body),
                TemplateError::PlaceholderNotStandalone { .. }
            ),
            "{body:?}"
        );
    }
}

#[tokio::test]
async fn line_continuation_joins_lines_without_a_boundary() {
    // After a blank, the continuation leaves the placeholder an argument.
    for shell in shells() {
        let runner = ShellRunner::new(&shell);
        for value in CANARIES {
            let r = invoke(&path_template("echo a \\\n{{p}}"), &[("p", value)], &runner).await;
            assert_clean(shell.label, value, &r);
            assert_eq!(stdout(&r), format!("a {value}\n"), "[{}]", shell.label);
        }
    }
    // Glued to a word, the continuation removes the line break and the blank.
    assert!(matches!(
        refusal("echo a\\\n{{p}}"),
        TemplateError::PlaceholderNotStandalone { .. }
    ));
}

#[tokio::test]
async fn crlf_line_ending_data_row() {
    // `a\<CR>` is an escaped carriage return; the next line is a new command.
    for shell in shells() {
        let runner = ShellRunner::new(&shell);
        for value in CANARIES {
            let r = invoke(
                &path_template("echo a\\\r\necho {{p}}"),
                &[("p", value)],
                &runner,
            )
            .await;
            assert_clean(shell.label, value, &r);
            assert_eq!(stdout(&r), format!("a\r\n{value}\n"), "[{}]", shell.label);
        }
    }
}

#[tokio::test]
async fn crlf_command_name_row_is_inert_for_non_executables() {
    // The slot lands in command-name position, which ADR-0021 decision 2
    // refuses; positional rendering alone must already keep a non-executable
    // value from becoming shell text.
    for shell in shells() {
        let runner = ShellRunner::new(&shell);
        for value in CANARIES {
            let r = invoke(
                &path_template("echo a\\\r\n{{p}} RAN"),
                &[("p", value)],
                &runner,
            )
            .await;
            assert_clean(shell.label, value, &r);
        }
    }
}

#[tokio::test]
async fn ansi_c_quoting_hides_the_placeholder_from_the_shell() {
    assert!(matches!(
        refusal("echo $'\\' {{p}} \\''"),
        TemplateError::PlaceholderNotExpanded { .. }
    ));
    // A closed ANSI-C string before the placeholder leaves it an argument.
    every_canary_is_inert("echo $'a' {{p}}", None).await;
}

#[tokio::test]
async fn comment_text_is_not_a_quote() {
    every_canary_is_inert("true #'\necho {{p}} \\'", Some(|v| format!("{v} '\n"))).await;
    assert!(matches!(
        refusal("true # {{p}}"),
        TemplateError::PlaceholderNotExpanded { .. }
    ));
}

#[tokio::test]
async fn arithmetic_is_refused_at_load() {
    // Bash re-evaluates an expanded value inside arithmetic as an expression.
    for body in [
        "(( {{p}} ))",
        "echo $(( {{p}} + 1 ))",
        "echo \"$(( {{p}} ))\"",
    ] {
        assert!(
            matches!(refusal(body), TemplateError::PlaceholderInArithmetic { .. }),
            "{body:?}"
        );
    }
}

#[tokio::test]
async fn bodies_the_lexer_cannot_read_are_refused_at_load() {
    // A `case` pattern's `)` ends the `$(` early, so the value would be split.
    // A `$((` that is not arithmetic is a command substitution to bash.
    for body in [
        "echo \"$(case x in x) printf '<%s>' \" {{p}} \" ;; esac)\"",
        "echo \"$((echo a) ; printf '<%s>' \" {{p}} \")\"",
        "echo $(echo {{p}}",
    ] {
        assert!(
            matches!(refusal(body), TemplateError::BodyNotAnalysable { .. }),
            "{body:?}"
        );
    }
}

#[tokio::test]
async fn array_subscript_is_inert() {
    every_canary_is_inert("a[ {{p}} ]=1", None).await;
}

/// The retired rendering — single-quote the value and splice it into the shell
/// text — is reproduced here on the rows that were real, so the suite is shown
/// not to be vacuous. It models the retired mechanism.
#[tokio::test]
async fn retired_splicing_reproduces_each_row_that_was_real() {
    /// Run the retired rendering of `body` with `value` under every shell and
    /// report whether `defect` holds under at least one.
    async fn reproduces(
        body: &str,
        value: &str,
        defect: impl Fn(&relay_proto::TaskResult) -> bool,
    ) -> bool {
        for shell in shells() {
            let runner = ShellRunner::new(&shell);
            let cmd = retired_splice(body, &[("p", value)]);
            let argv = vec!["/bin/sh".to_string(), "-c".to_string(), cmd];
            if defect(&run_sh_argv(&runner, argv).await) {
                return true;
            }
        }
        false
    }

    // Here-document: the substitution in the value ran.
    let body = "cat <<EOF\n{{p}}\nEOF";
    let value = CANARIES[0];
    assert!(reproduces(body, value, |r| stderr(r).contains("PWNED")).await);
    for shell in shells() {
        let r = invoke(
            &path_template(body),
            &[("p", value)],
            &ShellRunner::new(&shell),
        )
        .await;
        assert_clean(shell.label, value, &r);
    }

    // Backquote: the value's backquote ended the outer substitution, so the
    // output is not the value (a syntax error under dash).
    let body = "echo `echo {{p}}`";
    let value = CANARIES[1];
    let expected = format!("{value}\n");
    assert!(reproduces(body, value, |r| stdout(r) != expected || r.exit_code != 0).await);
    for shell in shells() {
        let r = invoke(
            &path_template(body),
            &[("p", value)],
            &ShellRunner::new(&shell),
        )
        .await;
        assert_eq!(
            (stdout(&r), r.exit_code),
            (expected.clone(), 0),
            "{}",
            shell.label
        );
    }

    // Escaped space and form feed: the author's word and the value fused into
    // one argument. The new compile refuses both bodies.
    for (body, fused) in [
        ("printf '[%s]\\n' a\\ {{p}}", "[a /tmp/a b]\n"),
        ("printf '[%s]\\n' a\u{c}{{p}}", "[a\u{c}/tmp/a b]\n"),
    ] {
        assert!(
            reproduces(body, "/tmp/a b", |r| stdout(r) == fused).await,
            "{body:?}"
        );
        assert!(matches!(
            refusal(body),
            TemplateError::PlaceholderNotStandalone { .. }
        ));
    }
}
