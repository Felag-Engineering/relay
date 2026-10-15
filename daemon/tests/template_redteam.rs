//! Red-team suite for the Template tier's value boundary (ADR-0021 amendment of
//! 2026-10-14, invariant 1).
//!
//! Two independent layers, each tested apart from the other:
//!
//! - **Placement.** A slot is accepted only as a plain word of the top-level
//!   command list. Every reproduction that put a slot anywhere else is asserted
//!   to be refused at load.
//! - **Value.** A `Path` slot refuses whitespace and shell-significant
//!   characters. The shell-level rows use an `Enum` slot (which admits whatever
//!   its author lists) so a hostile value reaches the shell and the render
//!   boundary is shown inert on its own.
//!
//! Rows that load run through the production `ResolvedOp::invoke` and executor
//! under dash, bash and `bash --posix`; a missing shell fails the test
//! (`shell_runner`). The canary values spell the token the injected command
//! prints as `PW""NED`, so `PWNED` appears in an output only if a command ran.

#[path = "common/shell_runner.rs"]
mod shell_runner;

use relay_ops::operations::template::{compile, TemplateError};
use shell_runner::{
    enum_template, invoke, path_template, retired_splice, run_sh_argv, shells, stderr, stdout,
    ShellRunner,
};

/// Values a shell would act on if it ever saw them as text.
const CANARIES: [&str; 5] = [
    "/tmp/$(echo PW\"\"NED >&2)",
    "/tmp/`echo PW\"\"NED`",
    "/tmp/x;echo PW\"\"NED",
    "/tmp/a b",
    "/tmp/*",
];

fn hostile(body: &str) -> relay_ops::operations::template::TemplateDef {
    enum_template(body, &CANARIES)
}

fn refusal(body: &str) -> TemplateError {
    match compile(&path_template(body)) {
        Ok(_) => panic!("{body:?} must be refused at compile time"),
        Err(e) => e,
    }
}

fn assert_not_analysable(body: &str) {
    assert!(
        matches!(refusal(body), TemplateError::BodyNotAnalysable { .. }),
        "{body:?}"
    );
}

fn assert_not_top_level(body: &str) {
    assert!(
        matches!(refusal(body), TemplateError::PlaceholderNotTopLevel { .. }),
        "{body:?}"
    );
}

fn assert_clean(label: &str, value: &str, r: &relay_proto::TaskResult) {
    let (out, err) = (stdout(r), stderr(r));
    assert!(
        !out.contains("PWNED") && !err.contains("PWNED"),
        "[{label}] {value:?} ran as a command: stdout={out:?} stderr={err:?}"
    );
}

/// Run `body` with every canary under every shell. With `expect`, also assert
/// the exact stdout.
async fn every_canary_is_inert(body: &str, expect: Option<fn(&str) -> String>) {
    for shell in shells() {
        let runner = ShellRunner::new(&shell);
        for value in CANARIES {
            let r = invoke(&hostile(body), &[("p", value)], &runner).await;
            assert_clean(shell.label, value, &r);
            if let Some(expected) = expect {
                assert_eq!(stdout(&r), expected(value), "[{}] {value:?}", shell.label);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Placement: refused at load
// ---------------------------------------------------------------------------

#[tokio::test]
async fn nested_placements_are_refused_at_load() {
    for body in [
        // here-documents and here-strings
        "cat <<EOF\n{{p}}\nEOF",
        "sh <<EOF\necho {{p}}\nEOF",
        "cat <<EOF\n$(( 1 $(echo {{p}}) ))\nEOF",
        "cat <<< {{p}}",
        // substitutions
        "echo $(echo {{p}})",
        "echo \"$(echo {{p}})\"",
        "echo $({{p}} x)",
        "(echo {{p}})",
        "echo \"$(echo \")\" {{p}} \")\")\"",
        "find $(dirname {{p}}) -maxdepth 0 -print",
        "ls -ld $(dirname {{p}})",
        // arithmetic, in every spelling
        "(( {{p}} ))",
        "echo $(( {{p}} + 1 ))",
        "echo $(( 1 $(echo {{p}}) ))",
        "echo $[ 1 {{p}} ]",
        "echo $[ 1 $(echo {{p}}) ]",
        "(( 1 $(echo {{p}}) ))",
        "for (( i=1$(echo {{p}}); i<0; )); do :; done",
        "echo $(( $(echo 1 {{p}}) ))",
        // parameter expansion
        "x=abc; echo ${x:1$(echo {{p}})}",
        "x=(a b); echo ${x[1$(echo {{p}})]}",
        // tests and arrays
        "[[ 1 -eq {{p}} ]]",
        "x=( {{p}} )",
    ] {
        assert!(refusal(body) != TemplateError::EmptyBody, "{body:?}");
    }
    for body in [
        "cat <<EOF\n{{p}}\nEOF",
        "sh <<EOF\necho {{p}}\nEOF",
        "cat <<< {{p}}",
        "echo $(echo {{p}})",
        "(echo {{p}})",
        "find $(dirname {{p}}) -maxdepth 0 -print",
        "ls -ld $(dirname {{p}})",
        "[[ 1 -eq {{p}} ]]",
    ] {
        assert_not_top_level(body);
    }
}

#[tokio::test]
async fn backquotes_are_refused_at_load() {
    // Backquote substitutions strip backslashes before the text is re-read, so
    // the lexer cannot tell where a placeholder ends up. Authors use `$( )`.
    for body in [
        "echo `echo {{p}}`",
        "printf '<%s>' \"`printf '[%s]' \\\" {{p}} \\\"`\"",
        "printf '<%s>' `printf '[%s]' \\\\\\\" {{p}} \\\\\\\"`",
        "cat <<EOF\n`printf '[%s]' \\\" {{p}} \\\"`\nEOF",
        "printf '<%s>' \"${x:-`printf '[%s]' \\\" {{p}} \\\"`}\"",
    ] {
        assert_not_analysable(body);
    }
}

#[tokio::test]
async fn arithmetic_brackets_and_case_are_refused_at_load() {
    for body in ["(( {{p}} ))", "echo $[ 1 {{p}} ]", "echo \"$(( {{p}} ))\""] {
        assert!(
            matches!(refusal(body), TemplateError::PlaceholderInArithmetic { .. }),
            "{body:?}"
        );
    }
    assert_not_analysable("echo {{p}} $[ 1 + 2");
    // A `case` pattern's `)` ends the `$(` early, so the value would be split.
    assert_not_analysable("echo \"$(case x in x) printf '<%s>' \" {{p}} \" ;; esac)\"");
    // A `$((` that is not arithmetic is a command substitution to bash.
    assert_not_analysable("echo \"$((echo a) ; printf '<%s>' \" {{p}} \")\"");
    assert_not_analysable("echo {{p}} $(echo");
}

#[tokio::test]
async fn continuations_that_split_keywords_are_refused_at_load() {
    // The shell joins `\`+newline before it reads `case`, so the lexer would
    // miss the keyword and the pattern `)` that ends the `$(` early.
    for body in [
        "printf '<%s>' \"$(ca\\\nse x in x) printf '[%s]' \" {{p}} \" ;; esac)\"",
        "printf '<%s>' \"$(case\\\n x in x) printf '[%s]' \" {{p}} \" ;; esac)\"",
        "echo $\\\n(echo) {{p}}",
    ] {
        assert_not_analysable(body);
    }
}

#[tokio::test]
async fn escaped_space_is_not_a_boundary() {
    for body in ["printf '[%s]\\n' a\\ {{p}}", "printf '[%s]\\n' {{p}}\\ a"] {
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
async fn ansi_c_quoting_hides_the_placeholder_from_the_shell() {
    assert!(matches!(
        refusal("echo $'\\' {{p}} \\''"),
        TemplateError::PlaceholderNotExpanded { .. }
    ));
}

// ---------------------------------------------------------------------------
// Placement: top-level rows that load stay inert for every value
// ---------------------------------------------------------------------------

#[tokio::test]
async fn plain_word_at_the_top_level() {
    every_canary_is_inert("echo {{p}}", Some(|v| format!("{v}\n"))).await;
    every_canary_is_inert("echo x | cat -n {{p}} | wc -c", None).await;
    every_canary_is_inert("{ echo {{p}} ; }", Some(|v| format!("{v}\n"))).await;
}

#[tokio::test]
async fn line_continuation_after_a_blank_keeps_the_slot_an_argument() {
    for shell in shells() {
        let runner = ShellRunner::new(&shell);
        for value in CANARIES {
            let r = invoke(&hostile("echo a \\\n{{p}}"), &[("p", value)], &runner).await;
            assert_clean(shell.label, value, &r);
            assert_eq!(stdout(&r), format!("a {value}\n"), "[{}]", shell.label);
        }
    }
    // Glued to a word, a join in the middle of a word is refused.
    assert_not_analysable("echo a\\\n{{p}}");
}

#[tokio::test]
async fn crlf_line_ending_data_row() {
    // `a\<CR>` is an escaped carriage return; the next line is a new command.
    for shell in shells() {
        let runner = ShellRunner::new(&shell);
        for value in CANARIES {
            let r = invoke(&hostile("echo a\\\r\necho {{p}}"), &[("p", value)], &runner).await;
            assert_clean(shell.label, value, &r);
            assert_eq!(stdout(&r), format!("a\r\n{value}\n"), "[{}]", shell.label);
        }
    }
}

/// A slot where its value would be executed is refused at load (ADR-0021
/// amendment of 2026-10-15, decision 3), not left to positional rendering.
#[test]
fn code_positions_are_refused_at_load() {
    for body in [
        // command-name position, including a position reached by an escaped CR
        "echo a\\\r\n{{p}} RAN",
        "{{p}} RAN",
        "echo a ; {{p}} RAN",
        "A=1 {{p}}",
        "exec {{p}}",
        "command {{p}}",
        "eval {{p}}",
        ". {{p}}",
        "source {{p}}",
        "let {{p}}",
        "sh -c {{p}}",
        "bash -lc {{p}}",
        "python3 -c {{p}}",
        "perl -e {{p}}",
    ] {
        assert!(
            matches!(
                refusal(body),
                TemplateError::PlaceholderInCodePosition { .. }
            ),
            "{body:?}"
        );
    }
}

/// Where a slot's value is data, an ordinary command keeps running it inert.
#[tokio::test]
async fn lookups_and_redirections_are_not_code_positions() {
    every_canary_is_inert("command -v {{p}} || true", None).await;
    every_canary_is_inert("exec 3< /dev/null; echo {{p}}", None).await;
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
async fn ansi_c_string_before_the_slot_is_inert() {
    every_canary_is_inert("echo $'a' {{p}}", None).await;
}

#[tokio::test]
async fn array_subscript_assignment_is_inert() {
    every_canary_is_inert("a[ {{p}} ]=1", None).await;
}

// ---------------------------------------------------------------------------
// Value: the Path gate, tested through an accepted top-level body
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_path_slot_refuses_hostile_values_before_any_spawn() {
    for value in [
        "/x[$(echo PW\"\"NED>&2)]",
        "/tmp -maxdepth 0 -exec echo PWNED-find ; -quit/x",
        "/tmp/$(echo PW\"\"NED >&2)",
        "/tmp/`echo PW\"\"NED`",
        "/tmp/a b",
        "/tmp/a\u{a0}b",
        "/tmp/a\\b",
    ] {
        for shell in shells() {
            let runner = ShellRunner::new(&shell);
            let r = invoke(
                &path_template("find {{p}} -maxdepth 0 -print"),
                &[("p", value)],
                &runner,
            )
            .await;
            assert_ne!(r.exit_code, 0, "[{}] {value:?}", shell.label);
            assert!(stdout(&r).is_empty(), "[{}] {value:?}", shell.label);
            assert!(
                stderr(&r).contains("failed path validation"),
                "[{}] {value:?}: {}",
                shell.label,
                stderr(&r)
            );
        }
    }
}

#[tokio::test]
async fn a_path_slot_passes_an_ordinary_path_verbatim() {
    for shell in shells() {
        let runner = ShellRunner::new(&shell);
        for value in ["/var/log/syslog", "/home/josé/notes"] {
            let r = invoke(&path_template("echo {{p}}"), &[("p", value)], &runner).await;
            assert_eq!(stdout(&r), format!("{value}\n"), "[{}]", shell.label);
        }
    }
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

    // Here-document: the substitution in the value ran. The body is refused now.
    let body = "cat <<EOF\n{{p}}\nEOF";
    assert!(reproduces(body, CANARIES[0], |r| stderr(r).contains("PWNED")).await);
    assert_not_top_level(body);

    // Backquote: the value's backquote ended the outer substitution, so the
    // output is not the value (a syntax error under dash). Refused at load.
    let body = "echo `echo {{p}}`";
    let expected = format!("{}\n", CANARIES[1]);
    assert!(
        reproduces(body, CANARIES[1], |r| stdout(r) != expected
            || r.exit_code != 0)
        .await
    );
    assert_not_analysable(body);

    // Escaped space and form feed: the author's word and the value fused into
    // one argument. The compile refuses both bodies.
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
