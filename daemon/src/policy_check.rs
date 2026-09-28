//! `relay-daemon policy check <file>` — offline Policy lint + `--would-allow`
//! for IaC pipelines (issue #93).
//!
//! Reads the Policy file directly with `std::fs::read_to_string` — **not**
//! `policy::load_policy` — because this subcommand runs pre-deployment on a
//! non-root IaC checkout, where `load_policy`'s owner/group-write fail-closed
//! gate (a runtime-load concern, ADR-0002) would spuriously reject an
//! otherwise-valid file. This does not weaken runtime Policy: the daemon
//! still applies the full permission gate when it loads the Policy on the
//! Node.
//!
//! `--would-allow` is answered by building a [`crate::gen::PolicyQuery`] and
//! calling the exact same [`crate::dispatch::evaluate_policy_query`] entry
//! point the live wire path uses — ADR-0011: no second evaluator. Reusing
//! that function (rather than calling `Policy::evaluate`/`evaluate_raw_exec`
//! directly) also reuses its `operation_positional_args` arg-key mapping and
//! `deciding_rule` formatting, so a `--would-allow` verdict can never diverge
//! from what a real Task dispatch would decide.
//!
//! This module runs **before** `tracing_subscriber::fmt().init()` in `main`
//! (it is fully offline and needs no network/identity setup) — it must print
//! directly to stdout/stderr and must **never** call `tracing::*`; those
//! calls are silently dropped before the subscriber is installed.

use std::collections::HashMap;

use crate::config;
use crate::dispatch::evaluate_policy_query;
use crate::gen::{policy_query, Operation, PolicyQuery, RawExec};
use crate::policy;
use crate::selfref;
use crate::templates;

// ---------------------------------------------------------------------------
// Exit codes (stable, documented for IaC pipeline gating)
// ---------------------------------------------------------------------------

/// Valid: no fatal findings; if `--would-allow` was given, its verdict was
/// ALLOW; under `--strict`, no warnings either.
const EXIT_VALID: i32 = 0;

/// Invalid: parse error, invalid regex, unknown Operation name, file I/O
/// error, or (`--strict` only) any lint warning present.
const EXIT_INVALID: i32 = 1;

/// Would-deny: the file is valid, but the `--would-allow` verdict is DENY.
///
/// Precedence: `EXIT_INVALID` (1) > `EXIT_WOULD_DENY` (2) > `EXIT_VALID` (0) —
/// pipelines must distinguish "the Policy file is broken" from "the file is
/// fine but this action isn't permitted."
const EXIT_WOULD_DENY: i32 = 2;

const HELP: &str = "\
Usage: relay-daemon policy check <file> [--strict] [--templates <dir>]
                                  [--would-allow <spec>]

Parses and lints a Policy file: invalid regex, unknown Operation names, allow
rules that are fully shadowed by a deny rule and can therefore never fire,
deny rules with a \"*\" or empty argument clause that (deny args being
exact-match) can never fire either, and a Raw Exec allow pattern not anchored
^...$ (its meaning changed: allow patterns now match the whole command).
Always runs the self-reference lint (#287): a warning when the Policy's
own reach includes this daemon's config, templates, state dir, binary, or
unit — decided by probing the real Policy engine, not a second matcher.

With --templates, also lints the Template Operation files under <dir>
(ADR-0021) and resolves Operation names against natives + those templates.
Without it, a name that is not native is only a WARNING: vocabulary is
per-Node, so the linter cannot tell a Template Operation from a typo.

Optionally answers a --would-allow hypothetical through the exact same
evaluation code the live wire path uses (ADR-0011) — no second evaluator.

Options:
  --strict               Treat lint warnings (a shadowed allow rule, a deny
                         rule that can never fire, an unresolvable Operation
                         name, an unanchored Raw Exec allow pattern, a
                         self-reference finding) as failures.
  --templates <dir>      Lint the template root at <dir> alongside the Policy
                         and resolve Operation names against it.
  --would-allow <spec>   Ask whether the given action would be allowed.
                         <spec> is one of:
                           operation <name> [key=value ...]
                           raw-exec -- <argv...>
  -h, --help             Print this message.

Exit codes:
  0   valid       no fatal findings (and, under --strict, no warnings);
                  if --would-allow was given, its verdict was ALLOW.
  1   invalid     parse error, invalid regex, a bad template file, an
                  Operation name in neither half of a supplied vocabulary,
                  file I/O error, or (under --strict) any lint warning.
  2   would-deny  the file is valid but the --would-allow verdict is DENY
                  or UNSUPPORTED (the Operation is not in the vocabulary).

Precedence: 1 (invalid) > 2 (would-deny) > 0 (valid).
";

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

/// Runs `policy check` and returns the process exit code.
///
/// `argv` is the full `std::env::args()` vector (`argv[0]` the program name,
/// `argv[1]`/`argv[2]` the already-matched `"policy"`/`"check"` literals);
/// subcommand arguments start at `argv[3]`.
pub fn run(argv: &[String]) -> i32 {
    let args = &argv[3.min(argv.len())..];

    if args.iter().any(|a| a == "-h" || a == "--help") {
        print!("{HELP}");
        return EXIT_VALID;
    }

    let parsed = match parse_args(args) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("error: {e}");
            return EXIT_INVALID;
        }
    };

    let contents = match std::fs::read_to_string(&parsed.file) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("error: failed to read {:?}: {e}", parsed.file);
            return EXIT_INVALID;
        }
    };

    // Template linting (issue #292): only when the caller named a template
    // root. Its findings are printed with the Policy's and share the same
    // exit-code contract; its accepted names complete the vocabulary the
    // unknown-name check resolves against (ADR-0021: vocabulary is per-Node,
    // so without a root the linter genuinely cannot tell a Template Operation
    // from a typo).
    let template_report = parsed
        .templates
        .as_ref()
        .map(|dir| templates::lint_dir(std::path::Path::new(dir)));
    let template_names: Vec<String> = template_report
        .as_ref()
        .map(|r| r.names.clone())
        .unwrap_or_default();

    let report =
        policy::lint_with_vocabulary(&contents, &template_names, template_report.is_some());
    print_report(&report);
    if let Some(tr) = &template_report {
        print_findings(&tr.findings);
    }

    // Self-reference lint (#287): does this Policy's reach include the
    // daemon's own trust root? Answered by probing the LIVE engine, never by a
    // second matcher (ADR-0011) — so it can only run once the file compiles.
    let compiled = if report.parse_error.is_none() {
        policy::from_toml_str(&contents).ok()
    } else {
        None
    };
    let self_reference = compiled
        .as_ref()
        .map(|p| {
            let path_ops = template_report
                .as_ref()
                .map(|r| r.path_slot_names.clone())
                .unwrap_or_default();
            selfref::lint(p, &path_ops)
        })
        .unwrap_or_default();
    print_findings(&self_reference);

    let template_errors = template_report.as_ref().is_some_and(|r| {
        r.findings
            .iter()
            .any(|f| f.severity == policy::LintSeverity::Error)
    });
    if report.has_errors() || template_errors {
        return EXIT_INVALID;
    }
    let template_warnings = template_report.as_ref().is_some_and(|r| {
        r.findings
            .iter()
            .any(|f| f.severity == policy::LintSeverity::Warning)
    });
    if parsed.strict && (report.has_warnings() || template_warnings || !self_reference.is_empty()) {
        eprintln!("error: lint warnings present and --strict was given");
        return EXIT_INVALID;
    }

    if let Some(would_allow) = &parsed.would_allow {
        // The file is regex/parse-valid at this point (checked above), so
        // from_toml_str cannot fail on anything lint didn't already catch.
        let compiled =
            compiled.expect("policy::lint reported no errors; from_toml_str must succeed");
        let query = build_query(would_allow);
        // Resolve names against the same per-Node vocabulary the live engine
        // uses (ADR-0011): Native Operations plus the Template Operations of
        // the root the caller named — or, absent `--templates`, whatever is
        // installed on THIS machine. Loaded silently (this subcommand runs
        // before tracing is initialized and its output is a machine-readable
        // contract) and fail-closed, so a broken or absent root simply yields
        // no template vocabulary and a template name then answers
        // `unsupported`, exactly as a dispatch here would.
        let template_dir = parsed
            .templates
            .clone()
            .map(std::path::PathBuf::from)
            .unwrap_or_else(config::template_dir_from_env);
        let templates = templates::TemplateSet::load(&template_dir)
            .unwrap_or_else(|_| templates::TemplateSet::unloadable());
        let verdict = evaluate_policy_query(&query, &compiled, &templates);
        if verdict.allowed {
            println!("would-allow: ALLOW");
        } else if verdict.unsupported {
            println!("would-allow: UNSUPPORTED ({})", verdict.deciding_rule);
            return EXIT_WOULD_DENY;
        } else {
            println!(
                "would-allow: DENY (deciding rule: {})",
                verdict.deciding_rule
            );
            return EXIT_WOULD_DENY;
        }
    }

    EXIT_VALID
}

/// Prints all lint findings to stderr, `error:`/`warning:` prefixed.
fn print_report(report: &policy::LintReport) {
    if let Some(err) = &report.parse_error {
        eprintln!("error: {err}");
        return;
    }
    print_findings(&report.findings);
}

/// Prints a bare finding list (template lint, self-reference lint) in the same
/// `error:`/`warning: <location> — <message>` format as the Policy report, so
/// a pipeline parses one stderr grammar regardless of which lint produced the
/// line.
fn print_findings(findings: &[policy::LintFinding]) {
    for finding in findings {
        let prefix = match finding.severity {
            policy::LintSeverity::Error => "error",
            policy::LintSeverity::Warning => "warning",
        };
        eprintln!("{prefix}: {} — {}", finding.location, finding.message);
    }
}

// ---------------------------------------------------------------------------
// Argument parsing (manual — no clap, ADR-0007 musl-size posture)
// ---------------------------------------------------------------------------

struct ParsedArgs {
    file: String,
    strict: bool,
    /// `--templates <dir>`: the template root to lint alongside the Policy and
    /// to resolve Operation names against (issue #292).
    templates: Option<String>,
    would_allow: Option<WouldAllow>,
}

enum WouldAllow {
    Operation {
        name: String,
        args: HashMap<String, String>,
    },
    RawExec {
        argv: Vec<String>,
    },
}

fn parse_args(args: &[String]) -> Result<ParsedArgs, String> {
    let mut iter = args.iter().peekable();

    let file = iter
        .next()
        .ok_or_else(|| "missing <file> argument".to_string())?
        .clone();

    let mut strict = false;
    let mut templates = None;
    let mut would_allow = None;

    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--strict" => strict = true,
            "--templates" => {
                templates = Some(
                    iter.next()
                        .ok_or_else(|| "--templates requires a directory".to_string())?
                        .clone(),
                );
            }
            "--would-allow" => {
                let kind = iter.next().ok_or_else(|| {
                    "--would-allow requires a spec: 'operation' or 'raw-exec'".to_string()
                })?;
                match kind.as_str() {
                    "operation" => {
                        let name = iter
                            .next()
                            .ok_or_else(|| "--would-allow operation requires <name>".to_string())?
                            .clone();
                        let mut op_args = HashMap::new();
                        while let Some(next) = iter.peek() {
                            if next.starts_with("--") {
                                break;
                            }
                            let kv = iter.next().expect("peek confirmed Some");
                            let (k, v) = kv
                                .split_once('=')
                                .ok_or_else(|| format!("invalid key=value pair: {kv:?}"))?;
                            op_args.insert(k.to_string(), v.to_string());
                        }
                        would_allow = Some(WouldAllow::Operation {
                            name,
                            args: op_args,
                        });
                    }
                    "raw-exec" => {
                        let sep = iter.next();
                        if sep.map(String::as_str) != Some("--") {
                            return Err(
                                "--would-allow raw-exec requires '--' before the argv".to_string()
                            );
                        }
                        let argv: Vec<String> = iter.by_ref().cloned().collect();
                        if argv.is_empty() {
                            return Err(
                                "--would-allow raw-exec requires a non-empty argv after '--'"
                                    .to_string(),
                            );
                        }
                        would_allow = Some(WouldAllow::RawExec { argv });
                    }
                    other => {
                        return Err(format!(
                        "unknown --would-allow spec {other:?}; expected 'operation' or 'raw-exec'"
                    ))
                    }
                }
            }
            other => return Err(format!("unrecognized argument {other:?}")),
        }
    }

    Ok(ParsedArgs {
        file,
        strict,
        templates,
        would_allow,
    })
}

/// Builds the `PolicyQuery` for a parsed `--would-allow` spec.
///
/// The `key=value` pairs of an `operation` spec populate `Operation.args`
/// directly, so the shared `operation_positional_args` mapping in
/// `dispatch.rs` consumes them unchanged — no duplication of the arg-key
/// contract. `query_id` is a fixed dummy value; it does not affect the verdict.
fn build_query(would_allow: &WouldAllow) -> PolicyQuery {
    let action = match would_allow {
        WouldAllow::Operation { name, args } => policy_query::Action::Operation(Operation {
            name: name.clone(),
            args: args.clone(),
        }),
        WouldAllow::RawExec { argv } => {
            policy_query::Action::RawExec(RawExec { argv: argv.clone() })
        }
    };
    PolicyQuery {
        query_id: "policy-check".to_string(),
        action: Some(action),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::templates::TemplateSet;
    use std::io::Write;
    use std::os::unix::fs::PermissionsExt;
    use std::path::{Path, PathBuf};
    use std::time::{SystemTime, UNIX_EPOCH};

    /// Temp file that removes itself on drop (test isolation). No explicit
    /// mode is set — `policy_check::run` never calls `load_policy`, so the
    /// owner/group-write permission gate is irrelevant here.
    struct TempFile(PathBuf);

    impl TempFile {
        fn new(label: &str, content: &str) -> Self {
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let path = std::env::temp_dir().join(format!(
                "relay-policy-check-test-{}-{}-{}",
                label,
                std::process::id(),
                nanos
            ));
            let mut f = std::fs::File::create(&path).expect("create temp file");
            f.write_all(content.as_bytes()).expect("write temp file");
            TempFile(path)
        }

        fn path_str(&self) -> String {
            self.0.to_string_lossy().into_owned()
        }
    }

    impl Drop for TempFile {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }

    fn argv(file: &str, rest: &[&str]) -> Vec<String> {
        let mut v = vec![
            "relay-daemon".to_string(),
            "policy".to_string(),
            "check".to_string(),
            file.to_string(),
        ];
        v.extend(rest.iter().map(|s| s.to_string()));
        v
    }

    /// Builds a `TaskRequest::Action::Operation` from a name and key=value arg
    /// pairs — mirrors the `--would-allow operation <name> key=value ...` CLI
    /// spec so a case can dispatch the exact equivalent real TaskRequest.
    fn task_action_operation(
        name: &str,
        args: &[(&'static str, &'static str)],
    ) -> crate::gen::task_request::Action {
        crate::gen::task_request::Action::Operation(Operation {
            name: name.to_string(),
            args: args
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
        })
    }

    // -----------------------------------------------------------------------
    // Exit-code table
    // -----------------------------------------------------------------------

    #[test]
    fn exit_code_valid_policy_is_zero() {
        let tmp = TempFile::new(
            "valid",
            r#"
[[operation]]
name = "service.restart"
allowed_args = [["nginx"]]
"#,
        );
        let code = run(&argv(&tmp.path_str(), &[]));
        assert_eq!(code, EXIT_VALID);
    }

    #[test]
    fn exit_code_invalid_regex_is_one() {
        let tmp = TempFile::new(
            "bad-regex",
            r#"
[raw_exec]
allow = ["[invalid regex"]
"#,
        );
        let code = run(&argv(&tmp.path_str(), &[]));
        assert_eq!(code, EXIT_INVALID);
    }

    #[test]
    fn exit_code_unknown_operation_is_one() {
        let tmp = TempFile::new(
            "unknown-op",
            r#"
[[operation]]
name = "pkg.remove"
allowed_args = []
"#,
        );
        // Without --templates the name is only a WARNING (it could be a
        // Template Operation on the target Node, ADR-0021), so the plain run
        // is valid and --strict is what fails the pipeline.
        assert_eq!(run(&argv(&tmp.path_str(), &[])), EXIT_VALID);
        assert_eq!(run(&argv(&tmp.path_str(), &["--strict"])), EXIT_INVALID);

        // With a template root supplied, the vocabulary is knowable and a name
        // in neither half is an error again — the pre-template behavior, now
        // earned rather than assumed.
        let empty_root = TempDir::new("unknown-op-templates");
        let code = run(&argv(
            &tmp.path_str(),
            &["--templates", &empty_root.path_str()],
        ));
        assert_eq!(code, EXIT_INVALID);
    }

    // -----------------------------------------------------------------------
    // Template linting via --templates (issue #292)
    // -----------------------------------------------------------------------

    const GOOD_TEMPLATE: &str = r#"
[[template]]
name = "disk.usage"
risk_class = "read"
body = "df -PT"
"#;

    /// A malformed template file fails the check with a useful, located error —
    /// the IaC pipeline's lint-before-deploy gate now covers templates.
    #[test]
    fn templates_a_malformed_file_is_invalid() {
        let policy = TempFile::new("tmpl-bad-policy", "");
        let root = TempDir::new("tmpl-bad");
        // A placeholder glued to adjacent text can change command structure, so
        // the engine refuses to compile it (ADR-0021).
        root.write(
            "bad.toml",
            r#"
[[template]]
name = "bad.tmpl"
risk_class = "read"
body = "tail --file={{path}}"

[[template.slots]]
name = "path"
type = "path"
"#,
        );
        let code = run(&argv(
            &policy.path_str(),
            &["--templates", &root.path_str()],
        ));
        assert_eq!(
            code, EXIT_INVALID,
            "a malformed template must fail the check"
        );
    }

    /// A template missing its mandatory risk class (ADR-0012) fails too.
    #[test]
    fn templates_missing_risk_class_is_invalid() {
        let policy = TempFile::new("tmpl-norisk-policy", "");
        let root = TempDir::new("tmpl-norisk");
        root.write(
            "x.toml",
            r#"
[[template]]
name = "no.class"
body = "df -PT"
"#,
        );
        assert_eq!(
            run(&argv(
                &policy.path_str(),
                &["--templates", &root.path_str()]
            )),
            EXIT_INVALID
        );
    }

    /// A template shadowing a Native Operation is refused by the linter for the
    /// same reason the loader refuses it: natives are frozen and resolve first.
    #[test]
    fn templates_shadowing_a_native_is_invalid() {
        let policy = TempFile::new("tmpl-shadow-policy", "");
        let root = TempDir::new("tmpl-shadow");
        root.write(
            "x.toml",
            r#"
[[template]]
name = "file.read"
risk_class = "read"
body = "cat /etc/hostname"
"#,
        );
        assert_eq!(
            run(&argv(
                &policy.path_str(),
                &["--templates", &root.path_str()]
            )),
            EXIT_INVALID
        );
    }

    /// A good pack plus a Policy that allows it lints clean, and --would-allow
    /// over the template answers from the live engine (ADR-0011) rather than
    /// reporting `unsupported` as it would with no template root.
    #[test]
    fn templates_would_allow_resolves_a_template_name() {
        let policy = TempFile::new(
            "tmpl-good-policy",
            r#"
[[operation]]
name = "disk.usage"
allowed_args = []
"#,
        );
        let root = TempDir::new("tmpl-good");
        root.write("pack.toml", GOOD_TEMPLATE);

        let code = run(&argv(
            &policy.path_str(),
            &[
                "--templates",
                &root.path_str(),
                "--strict",
                "--would-allow",
                "operation",
                "disk.usage",
            ],
        ));
        assert_eq!(
            code, EXIT_VALID,
            "a template allowed by Policy must answer ALLOW under --strict"
        );

        // The same Policy without the template root: the name cannot be
        // resolved, so the verdict is UNSUPPORTED, not a fabricated ALLOW.
        let code = run(&argv(
            &policy.path_str(),
            &["--would-allow", "operation", "disk.usage"],
        ));
        assert_eq!(code, EXIT_WOULD_DENY);
    }

    /// `TempDir::write` must force a mode `TemplateSet::load`'s hardened read
    /// will accept, regardless of the ambient process umask. Asserting on a
    /// freshly-created file is a vacuous guard: the umask itself clears the
    /// group/world-write bits under 022, 027 and 077, so the assertion would
    /// already be satisfied with no forcing at all and only goes red in the
    /// same narrow 002/000 window that made the original bug invisible
    /// everywhere but one machine. Instead, pre-seed the target path
    /// group/world-writable via an explicit `set_permissions` call (not a
    /// creation mode, which the umask masks) before writing through it.
    /// `std::fs::write` truncates an existing file in place and never
    /// reapplies a creation mode, so the write itself leaves the pre-seeded
    /// bits untouched; only the helper's forced chmod can clear them. That
    /// makes the observation deterministic under every umask.
    #[test]
    fn template_helper_writes_a_mode_the_loader_accepts() {
        let root = TempDir::new("tmpl-mode-pin");
        let target = root.path().join("pin.toml");

        // Pre-seed the exact path group- and world-writable, forced by chmod so
        // the ambient umask cannot pre-clear the bits we are about to check for.
        std::fs::write(&target, "").expect("pre-seed template file");
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o666))
            .expect("pre-seed template file mode");

        // std::fs::write truncates in place, so the helper's forced chmod is the
        // ONLY thing that can clear those bits.
        let written = root.write("pin.toml", GOOD_TEMPLATE);
        assert_eq!(written, target, "helper must write the path we pre-seeded");

        let mode = std::fs::metadata(&target)
            .expect("stat template file")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(
            mode & 0o022,
            0,
            "TempDir::write must clear group/world-write: templates::read_hardened \
             refuses any template file with mode & 0o022 != 0, so a helper that leaves \
             the mode to the ambient umask makes every template test umask-dependent \
             (got {mode:o})"
        );
    }

    // -----------------------------------------------------------------------
    // Self-reference lint (#287)
    // -----------------------------------------------------------------------

    /// The #287 acceptance line: a Policy allowing Raw Exec over the daemon's
    /// own config dir triggers the lint, and --strict fails the pipeline.
    #[test]
    fn self_reference_over_the_config_dir_fails_under_strict() {
        let policy = TempFile::new(
            "selfref-policy",
            r#"
[raw_exec]
allow = ["^/usr/bin/sed .*$"]
"#,
        );
        // Warning only: the file is valid, so a plain run still passes...
        assert_eq!(run(&argv(&policy.path_str(), &[])), EXIT_VALID);
        // ...and --strict is the pipeline gate.
        assert_eq!(run(&argv(&policy.path_str(), &["--strict"])), EXIT_INVALID);
    }

    /// A narrow Policy is not flagged — the lint must not cry wolf on the
    /// shape operators are told to write.
    #[test]
    fn self_reference_does_not_flag_a_narrow_policy() {
        let policy = TempFile::new(
            "selfref-narrow",
            r#"
[[operation]]
name = "service.restart"
allowed_args = [["nginx"]]

[raw_exec]
allow = ["^/usr/bin/systemctl (status|restart) [A-Za-z0-9@._-]+$"]
"#,
        );
        assert_eq!(run(&argv(&policy.path_str(), &["--strict"])), EXIT_VALID);
    }

    #[test]
    fn exit_code_strict_promotes_shadow_warning_to_failure() {
        let policy = r#"
[[operation]]
name = "service.restart"
allowed_args = [["nginx"]]

[[deny]]
name = "service.restart"
args = [["nginx"]]
"#;
        let tmp = TempFile::new("shadowed", policy);

        // Without --strict: shadowed-allow is only a warning → valid.
        let code_lenient = run(&argv(&tmp.path_str(), &[]));
        assert_eq!(code_lenient, EXIT_VALID);

        // With --strict: the same warning fails the pipeline.
        let code_strict = run(&argv(&tmp.path_str(), &["--strict"]));
        assert_eq!(code_strict, EXIT_INVALID);
    }

    #[test]
    fn exit_code_strict_promotes_deny_noop_warning_to_failure() {
        // A `[[deny]]` with a "*" position reads like a catch-all deny but,
        // deny args being exact-match, can never fire (issue #343). The lint
        // warns; --strict turns that warning into a pipeline failure so an
        // operator cannot ship a Policy whose deny silently protects nothing.
        let policy = r#"
[[operation]]
name = "file.read"
allowed_args = [["*"]]

[[deny]]
name = "file.read"
args = [["*"]]
"#;
        let tmp = TempFile::new("deny-noop", policy);

        // Without --strict the file is valid (the no-op deny is only a warning).
        assert_eq!(run(&argv(&tmp.path_str(), &[])), EXIT_VALID);
        // With --strict the warning fails the pipeline.
        assert_eq!(run(&argv(&tmp.path_str(), &["--strict"])), EXIT_INVALID);
    }

    /// A Raw Exec allow pattern not written `^...$` warns (its meaning
    /// changed with the ADR-0019 amendment: allow patterns now match the
    /// whole command) — a warning, not an Error, so the file is still valid;
    /// `--strict` is what fails the pipeline on it.
    #[test]
    fn unanchored_raw_exec_allow_warns_and_fails_under_strict() {
        let tmp = TempFile::new(
            "unanchored-raw-exec-allow",
            r#"
[raw_exec]
allow = ["/bin/echo hi"]
"#,
        );

        assert_eq!(run(&argv(&tmp.path_str(), &[])), EXIT_VALID);
        assert_eq!(run(&argv(&tmp.path_str(), &["--strict"])), EXIT_INVALID);
    }

    #[test]
    fn exit_code_would_allow_allow_is_zero() {
        let tmp = TempFile::new(
            "would-allow-ok",
            r#"
[[operation]]
name = "service.restart"
allowed_args = [["nginx"]]
"#,
        );
        let code = run(&argv(
            &tmp.path_str(),
            &[
                "--would-allow",
                "operation",
                "service.restart",
                "unit=nginx",
            ],
        ));
        assert_eq!(code, EXIT_VALID);
    }

    #[test]
    fn exit_code_would_allow_deny_is_two() {
        let tmp = TempFile::new(
            "would-allow-deny",
            r#"
[[operation]]
name = "service.restart"
allowed_args = [["nginx"]]
"#,
        );
        let code = run(&argv(
            &tmp.path_str(),
            &["--would-allow", "operation", "service.restart", "unit=sshd"],
        ));
        assert_eq!(code, EXIT_WOULD_DENY);
    }

    #[test]
    fn exit_code_would_allow_raw_exec() {
        let tmp = TempFile::new(
            "would-allow-raw-exec",
            r#"
[raw_exec]
allow = ["^/bin/echo .+$"]
deny = ["secret"]
"#,
        );

        let allowed = run(&argv(
            &tmp.path_str(),
            &["--would-allow", "raw-exec", "--", "/bin/echo", "hi"],
        ));
        assert_eq!(allowed, EXIT_VALID);

        let denied = run(&argv(
            &tmp.path_str(),
            &["--would-allow", "raw-exec", "--", "/bin/echo", "secret"],
        ));
        assert_eq!(denied, EXIT_WOULD_DENY);
    }

    /// A Raw Exec argv element carrying whitespace is refused by the
    /// ADR-0019 guard before the (now full-match) allow pattern ever runs —
    /// `--would-allow` must answer the same as a real dispatch would (ADR-0011).
    #[test]
    fn would_allow_raw_exec_whitespace_element_is_would_deny() {
        let tmp = TempFile::new(
            "would-allow-raw-exec-whitespace",
            r#"
[raw_exec]
allow = ["^/bin/echo .+$"]
"#,
        );

        let denied = run(&argv(
            &tmp.path_str(),
            &[
                "--would-allow",
                "raw-exec",
                "--",
                "/bin/echo",
                "hello world",
            ],
        ));
        assert_eq!(denied, EXIT_WOULD_DENY);

        let allowed = run(&argv(
            &tmp.path_str(),
            &["--would-allow", "raw-exec", "--", "/bin/echo", "hello"],
        ));
        assert_eq!(allowed, EXIT_VALID);
    }

    #[test]
    fn exit_code_invalid_beats_would_deny() {
        // The file has both a lint ERROR (invalid regex) and a raw_exec deny
        // that the --would-allow spec would trip. has_errors() at run():114
        // must short-circuit before the would-allow evaluation ever runs, so
        // the exit code must be EXIT_INVALID (1), not EXIT_WOULD_DENY (2).
        let tmp = TempFile::new(
            "invalid-beats-would-deny",
            r#"
[raw_exec]
allow = ["[invalid"]
deny = ["secret"]
"#,
        );
        let code = run(&argv(
            &tmp.path_str(),
            &["--would-allow", "raw-exec", "--", "/bin/echo", "secret"],
        ));
        assert_eq!(
            code, EXIT_INVALID,
            "an invalid Policy file must report EXIT_INVALID (1) even when \
             the would-allow spec would also have been a would-deny (2); a \
             reordering of the checks would return 2 here instead"
        );
    }

    #[test]
    fn exit_code_missing_file_is_one() {
        let code = run(&argv("/nonexistent/path/does-not-exist.toml", &[]));
        assert_eq!(code, EXIT_INVALID);
    }

    #[test]
    fn help_flag_prints_exit_codes_and_returns_zero() {
        // Assert on the actual documented exit-code table strings, not just
        // that HELP contains the characters '0'/'1'/'2' (near-vacuous — any
        // digit anywhere in the text, e.g. a version number, would satisfy
        // that). A HELP edit that drops the exit-code table now fails.
        let code = run(&argv("ignored.toml", &["-h"]));
        assert_eq!(code, EXIT_VALID);
        assert!(
            HELP.contains("0   valid"),
            "help text must document exit code 0 (valid)"
        );
        assert!(
            HELP.contains("1   invalid"),
            "help text must document exit code 1 (invalid)"
        );
        assert!(
            HELP.contains("2   would-deny"),
            "help text must document exit code 2 (would-deny)"
        );
        assert!(
            HELP.contains("Precedence: 1 (invalid) > 2 (would-deny) > 0 (valid)."),
            "help text must document the exit-code precedence"
        );
    }

    // -----------------------------------------------------------------------
    // Argument-parsing edge cases
    // -----------------------------------------------------------------------

    #[test]
    fn parse_args_rejects_unrecognized_flag() {
        let result = parse_args(&["file.toml".to_string(), "--bogus".to_string()]);
        assert!(result.is_err());
    }

    #[test]
    fn parse_args_operation_args_stop_before_next_flag() {
        let args: Vec<String> = [
            "file.toml",
            "--would-allow",
            "operation",
            "x.y",
            "k=v",
            "--strict",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        let parsed = parse_args(&args).expect("must parse");
        assert!(
            parsed.strict,
            "--strict after the key=value pairs must still be recognized"
        );
        match parsed.would_allow {
            Some(WouldAllow::Operation { name, args }) => {
                assert_eq!(name, "x.y");
                assert_eq!(args.get("k"), Some(&"v".to_string()));
            }
            _ => panic!("expected an Operation would_allow"),
        }
    }

    #[test]
    fn parse_args_raw_exec_requires_separator() {
        let args: Vec<String> = ["file.toml", "--would-allow", "raw-exec", "/bin/echo"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        assert!(parse_args(&args).is_err());
    }

    // -----------------------------------------------------------------------
    // Shared-code consistency test (ADR-0011): a query built via the CLI-
    // parsing path (parse_args -> build_query) must produce the identical
    // verdict as an equivalent, independently-constructed PolicyQuery, for a
    // matrix of operation-allow / operation-deny-by-default /
    // operation-deny-beats-allow / raw-exec-allow / raw-exec-deny cases.
    // Structurally tautological (both paths call evaluate_policy_query) —
    // that is the point: it fails the moment anyone reimplements evaluation
    // in this subcommand.
    // -----------------------------------------------------------------------

    fn matrix_policy() -> policy::Policy {
        policy::from_toml_str(
            r#"
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
"#,
        )
        .expect("matrix policy must parse")
    }

    #[test]
    fn would_allow_query_matches_manually_built_equivalent() {
        let policy = matrix_policy();

        struct Case {
            label: &'static str,
            cli_args: Vec<&'static str>,
            manual_query: PolicyQuery,
        }

        let cases = vec![
            Case {
                label: "operation allow",
                cli_args: vec!["operation", "service.restart", "unit=nginx"],
                manual_query: PolicyQuery {
                    query_id: "manual".to_string(),
                    action: Some(policy_query::Action::Operation(Operation {
                        name: "service.restart".to_string(),
                        args: HashMap::from([("unit".to_string(), "nginx".to_string())]),
                    })),
                },
            },
            Case {
                label: "operation deny-by-default",
                cli_args: vec!["operation", "service.restart", "unit=sshd"],
                manual_query: PolicyQuery {
                    query_id: "manual".to_string(),
                    action: Some(policy_query::Action::Operation(Operation {
                        name: "service.restart".to_string(),
                        args: HashMap::from([("unit".to_string(), "sshd".to_string())]),
                    })),
                },
            },
            Case {
                label: "operation deny-beats-allow",
                cli_args: vec!["operation", "file.read", "path=/etc/shadow"],
                manual_query: PolicyQuery {
                    query_id: "manual".to_string(),
                    action: Some(policy_query::Action::Operation(Operation {
                        name: "file.read".to_string(),
                        args: HashMap::from([("path".to_string(), "/etc/shadow".to_string())]),
                    })),
                },
            },
            Case {
                label: "raw-exec allow",
                cli_args: vec!["raw-exec", "--", "/bin/echo", "hi"],
                manual_query: PolicyQuery {
                    query_id: "manual".to_string(),
                    action: Some(policy_query::Action::RawExec(RawExec {
                        argv: vec!["/bin/echo".to_string(), "hi".to_string()],
                    })),
                },
            },
            Case {
                label: "raw-exec deny",
                cli_args: vec!["raw-exec", "--", "/bin/echo", "secret"],
                manual_query: PolicyQuery {
                    query_id: "manual".to_string(),
                    action: Some(policy_query::Action::RawExec(RawExec {
                        argv: vec!["/bin/echo".to_string(), "secret".to_string()],
                    })),
                },
            },
        ];

        for case in cases {
            let mut full_args = vec!["file.toml".to_string(), "--would-allow".to_string()];
            full_args.extend(case.cli_args.iter().map(|s| s.to_string()));
            let parsed = parse_args(&full_args).expect("must parse");
            let would_allow = parsed.would_allow.expect("must have a would_allow spec");
            let cli_query = build_query(&would_allow);

            let verdict_cli =
                evaluate_policy_query(&cli_query, &policy, TemplateSet::empty_static());
            let verdict_manual =
                evaluate_policy_query(&case.manual_query, &policy, TemplateSet::empty_static());

            assert_eq!(
                verdict_cli.allowed, verdict_manual.allowed,
                "[{}] verdict.allowed must match",
                case.label
            );
            assert_eq!(
                verdict_cli.deciding_rule, verdict_manual.deciding_rule,
                "[{}] deciding_rule must match",
                case.label
            );
        }
    }

    // -----------------------------------------------------------------------
    // Non-tautological parity test (REQUIRED — satisfies the acceptance
    // criterion literally): the --would-allow verdict, built via the CLI
    // parsing path, must match the outcome of an ACTUAL dispatch of the
    // equivalent TaskRequest through crate::dispatch::dispatch (real
    // DedupStore + Scheduler + executor) — mirroring
    // dispatch.rs::policy_query_verdict_matches_execution. This proves
    // --would-allow agrees with what execution then does, not just that the
    // CLI re-calls the same function.
    // -----------------------------------------------------------------------

    struct TempDir(PathBuf);

    impl TempDir {
        fn new(label: &str) -> Self {
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let path = std::env::temp_dir().join(format!(
                "relay-policy-check-dir-{}-{}-{}",
                label,
                std::process::id(),
                nanos
            ));
            std::fs::create_dir_all(&path).expect("create temp dir");
            TempDir(path)
        }
        fn path(&self) -> &Path {
            &self.0
        }
        fn path_str(&self) -> String {
            self.0.to_string_lossy().into_owned()
        }
        /// Writes a template file into this directory (used as a template root).
        /// `std::fs::write` is umask-masked, `TemplateSet::load`'s hardened read
        /// refuses any template file with `mode & 0o022 != 0` (templates.rs:682-688),
        /// and chmod is NOT umask-masked, so the mode is forced explicitly here.
        fn write(&self, name: &str, content: &str) -> PathBuf {
            let path = self.0.join(name);
            std::fs::write(&path, content).expect("write template file");
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
                .expect("set template file mode");
            path
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[tokio::test]
    async fn would_allow_parity_with_actual_dispatch() {
        use crate::dedup::DedupStore;
        use crate::gen::{task_request, Outcome, RawExec as GenRawExec, TaskRequest};
        use crate::scheduler::Scheduler;
        use crate::services::Services;
        use crate::templates::TemplateSet;

        let policy = matrix_policy();
        let state_dir = TempDir::new("parity");
        let dedup = DedupStore::open(state_dir.path()).expect("open dedup");
        let services = Services {
            policy,
            templates: TemplateSet::empty(),
            dedup,
            scheduler: Scheduler::new(),
        };

        // L1 (issue #127): a per-case action so an OPERATION case (arg-key
        // path: `unit=sshd` -> operation_positional_args -> evaluate) can be
        // parity-tested at the CLI layer alongside the raw-exec cases, not
        // just the tautological would_allow_query_matches_manually_built_
        // equivalent above.
        enum CaseAction {
            RawExec(Vec<String>),
            Operation {
                name: &'static str,
                args: &'static [(&'static str, &'static str)],
            },
        }

        struct Case {
            label: &'static str,
            action: CaseAction,
            expect_allow: bool,
        }

        let cases = [
            Case {
                label: "raw-exec allow",
                action: CaseAction::RawExec(vec!["/bin/echo".to_string(), "hi".to_string()]),
                expect_allow: true,
            },
            Case {
                label: "raw-exec deny",
                action: CaseAction::RawExec(vec!["/bin/echo".to_string(), "secret".to_string()]),
                expect_allow: false,
            },
            Case {
                label: "raw-exec whitespace element denied",
                action: CaseAction::RawExec(vec![
                    "/bin/echo".to_string(),
                    "hello world".to_string(),
                ]),
                expect_allow: false,
            },
            Case {
                label: "operation deny (service.restart sshd)",
                action: CaseAction::Operation {
                    name: "service.restart",
                    args: &[("unit", "sshd")],
                },
                expect_allow: false,
            },
        ];

        for (i, case) in cases.iter().enumerate() {
            // --would-allow verdict via the CLI-parsing path.
            let mut full_args = vec!["file.toml".to_string(), "--would-allow".to_string()];
            let task_action = match &case.action {
                CaseAction::RawExec(argv) => {
                    full_args.push("raw-exec".to_string());
                    full_args.push("--".to_string());
                    full_args.extend(argv.iter().cloned());
                    task_request::Action::RawExec(GenRawExec { argv: argv.clone() })
                }
                CaseAction::Operation { name, args } => {
                    full_args.push("operation".to_string());
                    full_args.push(name.to_string());
                    for (k, v) in *args {
                        full_args.push(format!("{k}={v}"));
                    }
                    task_action_operation(name, args)
                }
            };
            let parsed = parse_args(&full_args).expect("must parse");
            let would_allow = parsed.would_allow.expect("must have a would_allow spec");
            let query = build_query(&would_allow);
            let verdict =
                evaluate_policy_query(&query, &services.policy, TemplateSet::empty_static());

            // Actual dispatch of the equivalent TaskRequest.
            let task = TaskRequest {
                task_id: format!("policy-check-parity-{i}"),
                timeout_seconds: 5,
                action: Some(task_action),
            };
            let result =
                crate::dispatch::dispatch(&task, &services, tokio::time::Instant::now(), None)
                    .await;
            let exec_allowed = result.outcome != Outcome::DeniedByPolicy as i32;

            assert_eq!(
                verdict.allowed, case.expect_allow,
                "[{}] verdict.allowed must match expectation",
                case.label
            );
            assert_eq!(
                exec_allowed, case.expect_allow,
                "[{}] actual dispatch outcome must match expectation",
                case.label
            );
            assert_eq!(
                verdict.allowed, exec_allowed,
                "[{}] --would-allow verdict must match the actual dispatch outcome",
                case.label
            );
        }
    }
}
