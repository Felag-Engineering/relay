//! `relay-daemon policy check <file>` — offline Policy lint + `--would-allow`
//! for IaC pipelines.
//!
//! Reads the Policy file directly with `std::fs::read_to_string` — **not**
//! `policy::load_policy` — because this subcommand runs pre-deployment on a
//! non-root IaC checkout, where `load_policy`'s owner/group-write fail-closed
//! gate (a runtime-load concern, ADR-0002) would spuriously reject an
//! otherwise-valid file. This does not weaken runtime Policy: the daemon
//! still applies the full permission gate when it loads the Policy on the
//! Node.
//!
//! With `--policy-dir <dir>` it reads every file in `<dir>` as a Policy
//! fragment, the same way, and lints and compiles them with `<file>` through
//! `policy::lint_composed` and `policy::compose` — the functions the daemon's
//! own composition uses (DI-36, DI-46) — so the verdict and the printed
//! fingerprint are the ones the Node will have. A symlinked directory, and a
//! symlink or a non-regular entry, are errors here because the daemon refuses
//! to start on one; the directory's and a fragment's mode and owner are not
//! checked, for the reason the Policy file's are not. A missing `<file>`
//! beside a fragment composes the fragments alone, through
//! `policy::lint_fragments` and `policy::compose_fragments`, as the daemon
//! does (DI-20).
//!
//! `--would-allow` is answered by building a [`crate::gen::PolicyQuery`] and
//! calling the exact same [`crate::dispatch::evaluate_policy_query`] entry
//! point the live wire path uses — ADR-0011: no second evaluator. Reusing
//! that function (rather than calling `Policy::decide` directly) also reuses
//! its `operation_inputs` arg-key mapping and `deciding_rule` formatting, so a
//! `--would-allow` verdict can never diverge from what a real Task dispatch
//! would decide. `policy explain` makes the same `decide_query` call and prints
//! the pass and rule behind the verdict.
//!
//! This module runs **before** `tracing_subscriber::fmt().init()` in `main`
//! (it is fully offline and needs no network/identity setup) — it must print
//! directly to stdout/stderr and must **never** call `tracing::*`; those
//! calls are silently dropped before the subscriber is installed.

use std::collections::HashMap;

use crate::config;
use crate::dispatch::{decide_query, evaluate_policy_query, QueryDecision, UNSUPPORTED_REASON};
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
Usage: relay-daemon policy check <file> [--policy-dir <dir>] [--strict]
                                  [--templates <dir>] [--would-allow <spec>]

Parses and lints a Policy file: invalid regex, unknown Operation names, allow
rules that are fully shadowed by a deny rule and can therefore never fire,
deny rules with a \"*\" or empty argument clause that (deny args being
exact-match) can never fire either, and a Raw Exec allow pattern not anchored
^...$ (its meaning changed: allow patterns now match the whole command).
Always runs the self-reference lint (ADR-0021): a warning when the Policy
allows reading this daemon's identity private key or environment file, or
writing its trust root (Policy, environment file, state dir files, template
root, binary, unit) — decided by probing the real Policy engine, not a
second matcher.

With --templates, also lints the Template Operation files under <dir>
(ADR-0021) and resolves Operation names against natives + those templates.
Without it, a name that is not native is only a WARNING: vocabulary is
per-Node, so the linter cannot tell a Template Operation from a typo.

Optionally answers a --would-allow hypothetical through the exact same
evaluation code the live wire path uses (ADR-0011) — no second evaluator.

On success it prints \"fingerprint: <hex>\" to stdout: the Policy fingerprint a
Node holding exactly these files reports. Without --policy-dir the fingerprint
covers <file> alone, and does not match a Node whose Policy directory holds
fragments.

Options:
  --policy-dir <dir>     Compose every file in <dir> with <file>, as the daemon
                         composes its Policy directory with its Policy file:
                         one Policy, deny beating allow across all of them. File
                         names are part of the fingerprint. Mode and owner are
                         not checked here; a symlinked <dir>, or a symlink or a
                         non-regular entry in it, is an error, because the
                         daemon refuses to start on one. <file> may be absent
                         when <dir> holds a fragment: the daemon then composes
                         the fragments alone, and this prints a warning, which
                         --strict makes a failure, so a mistyped <file> cannot
                         pass a strict gate. With neither, the daemon runs
                         deny-all, and that is an error here.
                         A <dir> that does not exist is an error here, although
                         the daemon treats a missing Policy directory as having
                         no fragments: a mistyped path should not pass a gate.
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
  1   invalid     parse error, invalid regex, a bad template file or Policy
                  fragment, an Operation name in neither half of a supplied
                  vocabulary, file I/O error, or (under --strict) any lint
                  warning.
  2   would-deny  the file is valid but the --would-allow verdict is DENY
                  or UNSUPPORTED (the Operation is not in the vocabulary).

Precedence: 1 (invalid) > 2 (would-deny) > 0 (valid).

See also: relay-daemon policy explain --help (which pass and rule decided).
";

const EXPLAIN_HELP: &str = "\
Usage: relay-daemon policy explain <file> [--templates <dir>] <spec>

Asks the same hypothetical as `policy check --would-allow`, through the same
Policy code the live wire path uses (ADR-0011), and prints which pass and
rule decided it.

It reads only <file> and does not compose a Policy directory. The combined
verdict comes from `policy check <file> --policy-dir <dir> --would-allow <spec>`.

<spec> is one of:
  operation <name> [key=value ...]
  raw-exec -- <argv...>

Output (stdout):
  explain: ALLOW | DENY | UNSUPPORTED
  pass: <precondition|deny|guard|allow|default>
  rule: <the deciding rule and, where known, its line> | none
  matched on: <what the pass matched, by position -- never an argument value>
  reason: <the Deny reason>                         (deny only)

Passes:
  precondition  decided before any rule ran: a non-canonical path argument
                (ADR-0018), or an empty Raw Exec argv.
  deny          a deny rule matched; deny beats allow.
  guard         the Raw Exec whitespace guard refused (ADR-0019). It runs after
                the deny pass and before the allow pass, so a deny pattern that
                matches keeps the attribution.
  allow         an allow rule matched.
  default       nothing matched: deny-by-default (rule: none).

Exit codes:
  0   ALLOW
  1   invalid     bad arguments, an unreadable file, or an invalid Policy.
  2   DENY or UNSUPPORTED (the Operation is not in the vocabulary).
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

    if wants_help(args) {
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

    if let Some(refusal) = refused_policy_file(&parsed.file) {
        eprintln!(
            "error: {:?}: {refusal}; the daemon runs deny-all on it",
            parsed.file
        );
        return EXIT_INVALID;
    }

    // With --policy-dir a missing Policy file is not yet an error: the daemon
    // composes the fragments alone (DI-20). Whether the check then fails
    // depends on what the directory read below finds, as it does for the daemon.
    let contents = match std::fs::read_to_string(&parsed.file) {
        Ok(c) => Some(c),
        Err(_) if parsed.fragment_dir.is_some() && policy_file_is_missing(&parsed.file) => None,
        Err(e) => {
            eprintln!("error: failed to read {:?}: {e}", parsed.file);
            return EXIT_INVALID;
        }
    };

    let fragments = match &parsed.fragment_dir {
        Some(dir) => match read_fragment_dir(dir) {
            Ok(fragments) => fragments,
            Err(errors) => {
                for error in errors {
                    eprintln!("error: {error}");
                }
                return EXIT_INVALID;
            }
        },
        None => Vec::new(),
    };
    if let (None, Some(dir)) = (&contents, &parsed.fragment_dir) {
        if fragments.is_empty() {
            eprintln!(
                "error: {:?} does not exist and {dir:?} holds no Policy fragment: the daemon \
                 runs deny-all with neither",
                parsed.file
            );
            return EXIT_INVALID;
        }
        // A mistyped <file> must not pass silently as a fragments-only Policy:
        // a warning, which --strict makes a failure.
        eprintln!(
            "warning: {:?} does not exist; checking the fragments in {dir:?} alone, as the \
             daemon composes them, without any deny that file would hold",
            parsed.file
        );
    }
    let uncovered_policy_dir = match parsed.fragment_dir {
        Some(_) => None,
        None => populated_sibling_policy_dir(&parsed.file),
    };
    if let Some(dir) = &uncovered_policy_dir {
        eprintln!(
            "warning: {dir:?} is populated, but --policy-dir was not given: this result \
             covers the Policy file alone, not the Policy the daemon will compose; pass \
             --policy-dir {dir:?}"
        );
    }

    // Template linting: only when the caller named a template
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

    let report = match &contents {
        Some(contents) => policy::lint_composed(
            contents,
            &fragments,
            &template_names,
            template_report.is_some(),
        ),
        None => policy::lint_fragments(&fragments, &template_names, template_report.is_some()),
    };
    print_report(&report);
    if let Some(tr) = &template_report {
        print_findings(&tr.findings);
    }

    // Self-reference lint: does this Policy's reach include the
    // daemon's own trust root? Answered by probing the LIVE engine, never by a
    // second matcher (ADR-0011) — so it can only run once the file compiles.
    let compiled = match (&report.parse_error, &contents) {
        (Some(_), _) => None,
        (None, Some(contents)) => policy::compose(contents, &fragments).ok(),
        (None, None) => policy::compose_fragments(&fragments).ok(),
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
    if parsed.strict
        && (report.has_warnings()
            || template_warnings
            || !self_reference.is_empty()
            || uncovered_policy_dir.is_some()
            || contents.is_none())
    {
        eprintln!("error: lint warnings present and --strict was given");
        return EXIT_INVALID;
    }

    // The files are regex/parse-valid at this point (checked above), so compose
    // cannot fail on anything lint didn't already catch.
    let compiled = compiled.expect("policy::lint reported no errors; policy::compose must succeed");
    println!("fingerprint: {}", compiled.fingerprint());

    if let Some(would_allow) = &parsed.would_allow {
        let query = build_query(would_allow);
        let templates = load_vocabulary_templates(parsed.templates.as_deref());
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

/// Runs `policy explain` and returns the process exit code.
///
/// `argv` is what follows `policy explain` on the command line:
/// `<file> [--templates <dir>] <spec>`. Prints which pass and rule decided the
/// hypothetical — the same `decide` call `--would-allow` makes
/// ([`decide_query`]), so the two can never disagree. Prints plain text to
/// stdout (never `tracing`, which is not yet initialised here); a rule's line
/// is where the loader knew it, and no argument value is ever printed except in
/// the Deny reason, which Policy already bounds.
///
/// Exit codes: 0 allow, 2 deny or unsupported, 1 invalid.
pub fn run_explain(argv: &[String]) -> i32 {
    let out = explain(argv);
    print!("{}", out.stdout);
    eprint!("{}", out.stderr);
    out.code
}

/// Whether `-h`/`--help` appears before the first `--`. What follows `--` is a
/// Raw Exec argv, so a `--help` there is the command's own argument, not ours.
fn wants_help(args: &[String]) -> bool {
    args.iter()
        .take_while(|a| a.as_str() != "--")
        .any(|a| a == "-h" || a == "--help")
}

/// What `policy explain` would print, and its exit code — separate from
/// [`run_explain`] so the output can be asserted on.
struct Explanation {
    code: i32,
    stdout: String,
    stderr: String,
}

fn explain(argv: &[String]) -> Explanation {
    let invalid = |message: String| Explanation {
        code: EXIT_INVALID,
        stdout: String::new(),
        stderr: format!("error: {message}\n"),
    };

    if wants_help(argv) {
        return Explanation {
            code: EXIT_VALID,
            stdout: EXPLAIN_HELP.to_string(),
            stderr: String::new(),
        };
    }

    let (file, templates_dir, spec) = match parse_explain_args(argv) {
        Ok(p) => p,
        Err(e) => return invalid(e),
    };
    if let Some(refusal) = refused_policy_file(&file) {
        return invalid(format!(
            "{file:?}: {refusal}; the daemon runs deny-all on it"
        ));
    }
    let contents = match std::fs::read_to_string(&file) {
        Ok(c) => c,
        Err(e) => return invalid(format!("failed to read {file:?}: {e}")),
    };
    let compiled = match policy::from_toml_str(&contents) {
        Ok(p) => p,
        Err(e) => return invalid(e.to_string()),
    };
    let policy_dir_warning = populated_sibling_policy_dir(&file)
        .map(|dir| {
            format!(
                "warning: {dir:?} is populated, but explain reads only the Policy file: this \
                 verdict does not cover the fragments the daemon will compose\n"
            )
        })
        .unwrap_or_default();

    let templates = load_vocabulary_templates(templates_dir.as_deref());
    let query = build_query(&spec);
    match decide_query(query.action.as_ref(), &compiled, &templates) {
        QueryDecision::Unsupported => Explanation {
            code: EXIT_WOULD_DENY,
            stdout: format!("explain: UNSUPPORTED\nreason: {UNSUPPORTED_REASON}\n"),
            stderr: policy_dir_warning,
        },
        QueryDecision::NoAction => invalid("empty policy query action".to_string()),
        QueryDecision::Decided(e) => {
            let allowed = matches!(e.decision, policy::Decision::Allow(_));
            let rule = match (e.rule, e.pass) {
                (Some(rule), _) => rule.to_string(),
                (None, policy::Pass::Default) => "none (deny-by-default)".to_string(),
                (None, _) => "none".to_string(),
            };
            let mut stdout = format!(
                "explain: {}\npass: {}\nrule: {rule}\nmatched on: {}\n",
                if allowed { "ALLOW" } else { "DENY" },
                e.pass,
                e.matched_on
            );
            if let policy::Decision::Deny { reason, .. } = &e.decision {
                stdout.push_str(&format!("reason: {reason}\n"));
            }
            Explanation {
                code: if allowed { EXIT_VALID } else { EXIT_WOULD_DENY },
                stdout,
                stderr: policy_dir_warning,
            }
        }
    }
}

/// The `policy.d` directory beside the Policy file `file`, when it exists and
/// holds at least one entry, for the commands that were not told to read it.
/// `policy check` and `policy explain` then say their result covers the Policy
/// file alone; the daemon composes every entry.
fn populated_sibling_policy_dir(file: &str) -> Option<String> {
    let beside = match std::path::Path::new(file).parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent,
        _ => std::path::Path::new("."),
    };
    let dir = beside.join(policy::POLICY_DIR_NAME);
    let mut entries = std::fs::read_dir(&dir).ok()?;
    let _first_entry = entries.next()?;
    Some(dir.display().to_string())
}

/// Parses `<file> [--templates <dir>] <spec>`.
fn parse_explain_args(args: &[String]) -> Result<(String, Option<String>, WouldAllow), String> {
    let mut iter = args.iter().peekable();
    let file = iter
        .next()
        .ok_or_else(|| "missing <file> argument".to_string())?
        .clone();

    let mut templates = None;
    while iter.peek().map(|a| a.as_str()) == Some("--templates") {
        iter.next();
        templates = Some(
            iter.next()
                .ok_or_else(|| "--templates requires a directory".to_string())?
                .clone(),
        );
    }

    let spec = parse_spec(&mut iter, "explain")?;
    if let Some(extra) = iter.next() {
        return Err(format!("unrecognized argument {extra:?}"));
    }
    Ok((file, templates, spec))
}

/// Loads the Template Operations a hypothetical resolves names against.
///
/// The same per-Node vocabulary the live engine uses (ADR-0011): Native
/// Operations plus the Template Operations of the root the caller named — or,
/// absent `--templates`, whatever is installed on THIS machine. Loaded silently
/// (this subcommand runs before tracing is initialized and its output is a
/// machine-readable contract) and fail-closed, so a broken or absent root simply
/// yields no template vocabulary and a template name then answers
/// `unsupported`, exactly as a dispatch here would.
fn load_vocabulary_templates(dir: Option<&str>) -> templates::TemplateSet {
    let template_dir = dir
        .map(std::path::PathBuf::from)
        .unwrap_or_else(config::template_dir_from_env);
    templates::TemplateSet::load(&template_dir)
        .unwrap_or_else(|_| templates::TemplateSet::unloadable())
}

/// The loader's refusal of the Policy file at `file`, if it refuses one: the
/// daemon opens it without following a final symlink and loads only a regular
/// file, running deny-all otherwise, so a check that read through either would
/// pass a Policy the Node never runs. A regular or missing file is `None`; the
/// read reports everything else.
fn refused_policy_file(file: &str) -> Option<policy::PolicyError> {
    let meta = std::fs::symlink_metadata(file).ok()?;
    if meta.file_type().is_symlink() {
        Some(policy::PolicyError::SymlinkPath)
    } else if !meta.is_file() {
        Some(policy::PolicyError::NotRegularFile)
    } else {
        None
    }
}

/// Whether nothing at all is at `file`, which is what the loader means by a
/// missing Policy file: a dangling symlink is there, and the loader refuses it.
fn policy_file_is_missing(file: &str) -> bool {
    matches!(
        std::fs::symlink_metadata(file),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound
    )
}

/// Reads every entry of the Policy directory at `dir` as a Policy fragment.
///
/// The offline counterpart of the daemon's loader: the directory itself must
/// be a real directory, checked without following a symlink, and every entry
/// is a fragment (no suffix filter); an entry the daemon refuses to start on,
/// a symlink or a non-regular file, is an error. Mode and owner are not checked,
/// of the directory or of a fragment (the module doc says why). Every problem
/// with an entry is collected, so a pipeline sees them all at once. The order
/// of the result is unspecified: composition sorts.
fn read_fragment_dir(dir: &str) -> Result<Vec<policy::Fragment>, Vec<String>> {
    // `read_dir` follows a symlink, and the daemon refuses to start on a
    // symlinked Policy directory: check the directory's own type first, with
    // the loader's own error.
    let meta = std::fs::symlink_metadata(dir).map_err(|e| vec![format!("{dir}: {e}")])?;
    if meta.file_type().is_symlink() {
        return Err(vec![format!(
            "{dir}: {}",
            policy::PolicyError::PolicyDirectorySymlink
        )]);
    }
    if !meta.is_dir() {
        return Err(vec![format!(
            "{dir}: {}",
            policy::PolicyError::PolicyDirectoryNotADirectory
        )]);
    }
    let entries = std::fs::read_dir(dir).map_err(|e| vec![format!("{dir}: {e}")])?;

    let mut fragments = Vec::new();
    let mut errors = Vec::new();
    for entry in entries {
        let entry = match entry {
            Ok(entry) => entry,
            Err(e) => {
                errors.push(format!("{dir}: {e}"));
                continue;
            }
        };
        let file_name = entry.file_name();
        let Some(name) = file_name.to_str() else {
            errors.push(format!(
                "a Policy fragment's file name is not UTF-8: {file_name:?}"
            ));
            continue;
        };
        let file_type = match entry.file_type() {
            Ok(file_type) => file_type,
            Err(e) => {
                errors.push(format!("{name:?}: {e}"));
                continue;
            }
        };
        if file_type.is_symlink() {
            errors.push(format!(
                "{name:?}: is a symlink; the daemon refuses to start on a symlinked Policy fragment"
            ));
        } else if !file_type.is_file() {
            errors.push(format!(
                "{name:?}: is not a regular file; the daemon refuses to start on one"
            ));
        } else {
            match std::fs::read_to_string(entry.path()) {
                Ok(text) => fragments.push(policy::Fragment {
                    name: name.to_string(),
                    text,
                }),
                Err(e) => errors.push(format!("{name:?}: {e}")),
            }
        }
    }
    if errors.is_empty() {
        Ok(fragments)
    } else {
        Err(errors)
    }
}

/// Prints all lint findings to stderr, `error:`/`warning:` prefixed.
///
/// Each source that failed to parse is its own `error:` block: the Policy
/// file's error is printed bare, as for a lone file, and a fragment's error
/// opens with its name.
fn print_report(report: &policy::LintReport) {
    if report.parse_error.is_some() {
        for err in &report.parse_errors {
            eprintln!("error: {err}");
        }
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
    /// `--policy-dir <dir>`: a directory of Policy fragments to compose with
    /// `file`.
    fragment_dir: Option<String>,
    strict: bool,
    /// `--templates <dir>`: the template root to lint alongside the Policy and
    /// to resolve Operation names against.
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

    let mut fragment_dir = None;
    let mut strict = false;
    let mut templates = None;
    let mut would_allow = None;

    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--policy-dir" => {
                fragment_dir = Some(
                    iter.next()
                        .ok_or_else(|| "--policy-dir requires a directory".to_string())?
                        .clone(),
                );
            }
            "--strict" => strict = true,
            "--templates" => {
                templates = Some(
                    iter.next()
                        .ok_or_else(|| "--templates requires a directory".to_string())?
                        .clone(),
                );
            }
            "--would-allow" => would_allow = Some(parse_spec(&mut iter, "--would-allow")?),
            other => return Err(format!("unrecognized argument {other:?}")),
        }
    }

    Ok(ParsedArgs {
        file,
        fragment_dir,
        strict,
        templates,
        would_allow,
    })
}

/// Parses an action spec — `operation <name> [key=value ...]` or
/// `raw-exec -- <argv...>` — shared by `--would-allow` and `policy explain`.
/// `flag` names the option in the error messages.
fn parse_spec(
    iter: &mut std::iter::Peekable<std::slice::Iter<'_, String>>,
    flag: &str,
) -> Result<WouldAllow, String> {
    let kind = iter
        .next()
        .ok_or_else(|| format!("{flag} requires a spec: 'operation' or 'raw-exec'"))?;
    match kind.as_str() {
        "operation" => {
            let name = iter
                .next()
                .ok_or_else(|| format!("{flag} operation requires <name>"))?
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
            Ok(WouldAllow::Operation {
                name,
                args: op_args,
            })
        }
        "raw-exec" => {
            let sep = iter.next();
            if sep.map(String::as_str) != Some("--") {
                return Err(format!("{flag} raw-exec requires '--' before the argv"));
            }
            let argv: Vec<String> = iter.by_ref().cloned().collect();
            if argv.is_empty() {
                return Err(format!(
                    "{flag} raw-exec requires a non-empty argv after '--'"
                ));
            }
            Ok(WouldAllow::RawExec { argv })
        }
        other => Err(format!(
            "unknown {flag} spec {other:?}; expected 'operation' or 'raw-exec'"
        )),
    }
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
    use crate::test_support::{TempDir, TempFile};
    use std::os::unix::fs::PermissionsExt;

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
        let empty_root = TempDir::created("unknown-op-templates");
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
        let root = TempDir::created("tmpl-bad");
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
        let root = TempDir::created("tmpl-norisk");
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
        let root = TempDir::created("tmpl-shadow");
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

    fn path_template(body: &str) -> String {
        format!(
            "[[template]]\nname = \"code.position\"\nrisk_class = \"read\"\nbody = '{body}'\n\n\
             [[template.slots]]\nname = \"path\"\ntype = \"path\"\n"
        )
    }

    fn check_template_body(tag: &str, body: &str, extra: &[&str]) -> i32 {
        let policy = TempFile::new(&format!("{tag}-policy"), "");
        let root = TempDir::created(tag);
        root.write("x.toml", &path_template(body));
        let dir = root.path_str();
        let mut args = vec!["--templates", dir.as_str()];
        args.extend_from_slice(extra);
        run(&argv(&policy.path_str(), &args))
    }

    /// A slot where its value would run as code makes the template set
    /// unloadable, so the check exits 1 with or without `--strict`
    /// (ADR-0021, 2026-10-15 decision 3).
    #[test]
    fn templates_a_slot_in_a_code_position_is_invalid() {
        for body in ["{{path}} --version", "eval {{path}}", "sh -c {{path}}"] {
            assert_eq!(
                check_template_body("tmpl-code-err", body, &[]),
                EXIT_INVALID
            );
        }
    }

    /// An undecidable code position loads and passes a plain check; `--strict`
    /// fails it.
    #[test]
    fn templates_an_undecidable_code_position_fails_only_under_strict() {
        let body = "find / -maxdepth 1 -exec {{path}} \\;";
        assert_eq!(check_template_body("tmpl-code-warn", body, &[]), EXIT_VALID);
        assert_eq!(
            check_template_body("tmpl-code-warn", body, &["--strict"]),
            EXIT_INVALID
        );
    }

    /// A slot that is only an argument of an ordinary command is clean under
    /// `--strict`.
    #[test]
    fn templates_a_slot_as_an_argument_is_clean_under_strict() {
        assert_eq!(
            check_template_body("tmpl-code-ok", "sha256sum -- {{path}}", &["--strict"]),
            EXIT_VALID
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
        let root = TempDir::created("tmpl-good");
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
        let root = TempDir::created("tmpl-mode-pin");
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

    #[tokio::test]
    async fn would_allow_parity_with_actual_dispatch() {
        use crate::dedup::DedupStore;
        use crate::gen::{
            task_request, Outcome, PolicyRuleSection, RawExec as GenRawExec, TaskRequest,
        };
        use crate::scheduler::Scheduler;
        use crate::services::Services;
        use crate::templates::TemplateSet;

        let policy = matrix_policy();
        let state_dir = TempDir::created("parity");
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
            // The rule the verdict names: (section, index); Unspecified when
            // no rule decided.
            expect_rule: (crate::gen::PolicyRuleSection, u32),
        }

        let cases = [
            Case {
                label: "raw-exec allow",
                action: CaseAction::RawExec(vec!["/bin/echo".to_string(), "hi".to_string()]),
                expect_allow: true,
                expect_rule: (PolicyRuleSection::RawExecAllow, 0),
            },
            Case {
                label: "raw-exec deny",
                action: CaseAction::RawExec(vec!["/bin/echo".to_string(), "secret".to_string()]),
                expect_allow: false,
                expect_rule: (PolicyRuleSection::RawExecDeny, 0),
            },
            Case {
                label: "raw-exec whitespace element denied",
                action: CaseAction::RawExec(vec![
                    "/bin/echo".to_string(),
                    "hello world".to_string(),
                ]),
                expect_allow: false,
                expect_rule: (PolicyRuleSection::Unspecified, 0),
            },
            Case {
                label: "operation deny (service.restart sshd)",
                action: CaseAction::Operation {
                    name: "service.restart",
                    args: &[("unit", "sshd")],
                },
                expect_allow: false,
                expect_rule: (PolicyRuleSection::Unspecified, 0),
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
                risk_class: 0,
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
                (verdict.rule_section, verdict.rule_index),
                (case.expect_rule.0 as i32, case.expect_rule.1),
                "[{}] verdict must name the deciding rule",
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

    // -----------------------------------------------------------------------
    // --policy-dir: the Policy file and its fragments, checked together
    // -----------------------------------------------------------------------

    const ALLOW_NGINX: &str = "\
[[operation]]
name = \"service.restart\"
allowed_args = [[\"nginx\"]]
";
    const DENY_NGINX: &str = "\
[[deny]]
name = \"service.restart\"
args = [[\"nginx\"]]
";

    /// A fragment directory holding `fragments`, removed on drop.
    fn fragment_dir(fragments: &[(&str, &str)]) -> TempDir {
        let dir = TempDir::created("policy-check-fragments");
        for (name, text) in fragments {
            dir.write(name, text);
        }
        dir
    }

    fn check_with_dir(file: &TempFile, dir: &TempDir, rest: &[&str]) -> i32 {
        let mut full = argv(&file.path_str(), &["--policy-dir", &dir.path_str()]);
        full.extend(rest.iter().map(|s| s.to_string()));
        run(&full)
    }

    // Proves DI-46.
    #[test]
    fn check_lints_the_policy_file_and_directory_together() {
        let file = TempFile::new("pc-together", ALLOW_NGINX);

        // A valid pair.
        let ok = fragment_dir(&[(
            "10-sshd.toml",
            "[[operation]]\nname = \"service.restart\"\nallowed_args = [[\"sshd\"]]\n",
        )]);
        assert_eq!(check_with_dir(&file, &ok, &["--strict"]), EXIT_VALID);

        // A parse error in a fragment is invalid.
        let broken = fragment_dir(&[("bad.toml", "this is = = not toml")]);
        assert_eq!(check_with_dir(&file, &broken, &[]), EXIT_INVALID);

        // An unknown Operation in a fragment is an error once the vocabulary is
        // complete (an empty --templates root supplies none).
        let unknown =
            fragment_dir(&[("ops.toml", "[[operation]]\nname = \"no.such.operation\"\n")]);
        let empty_root = TempDir::created("pc-together-templates");
        let templates = empty_root.path_str();
        assert_eq!(
            check_with_dir(&file, &unknown, &["--templates", &templates]),
            EXIT_INVALID
        );

        // A Policy-file allow shadowed by a fragment deny is a warning:
        // valid plain, invalid under --strict.
        let shadow = fragment_dir(&[("deny.toml", DENY_NGINX)]);
        assert_eq!(check_with_dir(&file, &shadow, &[]), EXIT_VALID);
        assert_eq!(check_with_dir(&file, &shadow, &["--strict"]), EXIT_INVALID);
    }

    // Proves DI-46.
    #[test]
    fn would_allow_answers_over_the_combined_policy() {
        let allow_spec = [
            "--would-allow",
            "operation",
            "service.restart",
            "unit=nginx",
        ];

        // The only allow is in a fragment.
        let empty_file = TempFile::new("pc-wa-empty", "");
        let allowing = fragment_dir(&[("allow.toml", ALLOW_NGINX)]);
        assert_eq!(
            check_with_dir(&empty_file, &allowing, &allow_spec),
            EXIT_VALID
        );

        // A fragment deny over a Policy-file allow.
        let file = TempFile::new("pc-wa-file", ALLOW_NGINX);
        let denying = fragment_dir(&[("deny.toml", DENY_NGINX)]);
        assert_eq!(
            check_with_dir(&file, &denying, &allow_spec),
            EXIT_WOULD_DENY
        );
    }

    // Proves DI-46.
    #[test]
    fn check_refuses_entries_the_daemon_refuses_to_start_on() {
        let file = TempFile::new("pc-refuse", ALLOW_NGINX);

        let symlinked = fragment_dir(&[("real.toml", ALLOW_NGINX)]);
        std::os::unix::fs::symlink(
            symlinked.path().join("real.toml"),
            symlinked.path().join("link.toml"),
        )
        .unwrap();
        assert_eq!(check_with_dir(&file, &symlinked, &[]), EXIT_INVALID);

        let nested = fragment_dir(&[]);
        std::fs::create_dir(nested.path().join("sub.toml")).unwrap();
        assert_eq!(check_with_dir(&file, &nested, &[]), EXIT_INVALID);

        let absent = TempDir::new("pc-refuse-absent");
        assert_eq!(check_with_dir(&file, &absent, &[]), EXIT_INVALID);
    }

    // Proves DI-46.
    #[test]
    fn the_runbook_documents_the_three_step_change() {
        let doc = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../docs/operations/policy-as-code.md"
        ))
        .expect("read the Policy-as-code runbook");

        let heading = "### Change a Node's Policy";
        let start = doc
            .find(heading)
            .expect("the runbook must have a \"Change a Node's Policy\" subsection");
        let section = doc[start + heading.len()..]
            .split("\n#")
            .next()
            .expect("split yields at least one piece");

        let lines: Vec<&str> = section.lines().map(str::trim).collect();
        let numbered: Vec<&str> = lines
            .iter()
            .copied()
            .filter(|l| {
                l.split_once(". ")
                    .is_some_and(|(n, _)| !n.is_empty() && n.chars().all(|c| c.is_ascii_digit()))
            })
            .collect();
        assert_eq!(
            numbered.len(),
            3,
            "exactly three numbered steps: {numbered:?}"
        );
        assert!(numbered[0].starts_with("1. ") && numbered[0].contains("fragment"));
        assert!(numbered[1].starts_with("2. "));
        assert!(
            numbered[2].starts_with("3. ")
                && numbered[2].contains("systemctl restart relay-daemon")
        );

        const COMMAND: &str = "$ relay-daemon policy check ";
        let command_at = lines
            .iter()
            .position(|l| l.starts_with(COMMAND))
            .expect("step 2 must show the policy check command line");
        let step_at = |n: &str| lines.iter().position(|l| *l == n).unwrap();
        assert!(
            step_at(numbered[0]) < step_at(numbered[1])
                && step_at(numbered[1]) < command_at
                && command_at < step_at(numbered[2]),
            "the steps must come in order: write, check, restart"
        );

        let args: Vec<String> = lines[command_at][COMMAND.len()..]
            .split_whitespace()
            .map(String::from)
            .collect();
        let parsed = parse_args(&args).expect("the documented command line must parse");
        assert_eq!(parsed.file, "policies/web-prod.toml");
        assert_eq!(parsed.fragment_dir.as_deref(), Some("policies/web-prod.d"));
        assert!(parsed.strict);
    }

    #[test]
    fn parse_args_accepts_policy_dir() {
        let parsed = parse_args(&[
            "p.toml".to_string(),
            "--policy-dir".to_string(),
            "p.d".to_string(),
            "--strict".to_string(),
        ])
        .unwrap();
        assert_eq!(parsed.fragment_dir.as_deref(), Some("p.d"));
        assert!(parsed.strict);
        assert!(parse_args(&["p.toml".to_string()])
            .unwrap()
            .fragment_dir
            .is_none());
    }

    #[test]
    fn parse_args_policy_dir_requires_a_value() {
        let err = parse_args(&["p.toml".to_string(), "--policy-dir".to_string()])
            .err()
            .expect("a flag with no value is refused");
        assert_eq!(err, "--policy-dir requires a directory");
    }

    #[test]
    fn help_mentions_the_fingerprint_needs_policy_dir() {
        assert!(HELP.contains("--policy-dir <dir>"));
        let flat = HELP.split_whitespace().collect::<Vec<_>>().join(" ");
        assert!(
            flat.contains("Without --policy-dir the fingerprint covers <file> alone"),
            "HELP must say a fingerprint printed without --policy-dir covers the file alone"
        );
        assert!(EXPLAIN_HELP.contains("does not compose a Policy directory"));
    }
}

// ---------------------------------------------------------------------------
// `policy explain` (#898): which pass and rule decided, through the same
// `decide_query` call `--would-allow` makes.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod explain_tests {
    use super::*;
    use crate::test_support::{TempDir, TempFile};

    const POLICY: &str = "\
[[operation]]
name = \"service.restart\"
allowed_args = [[\"nginx\"]]

[[deny]]
name = \"service.restart\"
args = [[\"sshd\"]]

[raw_exec]
allow = [\".*\"]
";

    fn s(parts: &[&str]) -> Vec<String> {
        parts.iter().map(|p| p.to_string()).collect()
    }

    fn explain_with(policy: &TempFile, rest: &[&str]) -> Explanation {
        let mut a = vec![policy.path_str()];
        a.extend(rest.iter().map(|p| p.to_string()));
        explain(&a)
    }

    #[test]
    fn explain_prints_allow_pass_and_rule_line() {
        let f = TempFile::new("explain-allow", POLICY);
        let out = explain_with(&f, &["operation", "service.restart", "unit=nginx"]);
        assert_eq!(out.code, EXIT_VALID);
        assert_eq!(
            out.stdout,
            "explain: ALLOW\npass: allow\nrule: [[operation]] #0, line 1\n\
             matched on: the invocation's arguments\n"
        );
        assert!(out.stderr.is_empty());
    }

    #[test]
    fn explain_deny_by_rule_exit_two() {
        let f = TempFile::new("explain-deny", POLICY);
        let out = explain_with(&f, &["operation", "service.restart", "unit=sshd"]);
        assert_eq!(out.code, EXIT_WOULD_DENY);
        assert_eq!(
            out.stdout,
            "explain: DENY\npass: deny\nrule: [[deny]] #0, line 5\n\
             matched on: the invocation's arguments\n\
             reason: denied by explicit rule for operation 'service.restart'\n"
        );
    }

    #[test]
    fn explain_default_prints_no_rule() {
        let f = TempFile::new("explain-default", POLICY);
        let out = explain_with(&f, &["operation", "service.restart", "unit=cron"]);
        assert_eq!(out.code, EXIT_WOULD_DENY);
        assert!(out.stdout.contains("pass: default\n"), "{}", out.stdout);
        assert!(
            out.stdout.contains("rule: none (deny-by-default)\n"),
            "{}",
            out.stdout
        );
    }

    #[test]
    fn explain_precondition_non_canonical() {
        let f = TempFile::new("explain-precondition", POLICY);
        let out = explain_with(&f, &["operation", "file.read", "path=/etc/../shadow"]);
        assert_eq!(out.code, EXIT_WOULD_DENY);
        assert!(
            out.stdout.contains("pass: precondition\n"),
            "{}",
            out.stdout
        );
        assert!(out.stdout.contains("rule: none\n"), "{}", out.stdout);
        assert!(
            out.stdout
                .contains("matched on: argument 0 is not a canonical path\n"),
            "{}",
            out.stdout
        );
    }

    #[test]
    fn explain_raw_exec_guard_names_index_not_value() {
        let f = TempFile::new("explain-guard", POLICY);
        let out = explain_with(&f, &["raw-exec", "--", "/bin/echo", "TOPSECRET value"]);
        assert_eq!(out.code, EXIT_WOULD_DENY);
        assert!(out.stdout.contains("pass: guard\n"), "{}", out.stdout);
        assert!(out.stdout.contains("argv[1]"), "{}", out.stdout);
        assert!(!out.stdout.contains("TOPSECRET"), "{}", out.stdout);
    }

    #[test]
    fn explain_unsupported_exit_two() {
        let f = TempFile::new("explain-unsupported", POLICY);
        let root = TempDir::created("explain-unsupported-root");
        let out = explain_with(
            &f,
            &["--templates", &root.path_str(), "operation", "no.such.op"],
        );
        assert_eq!(out.code, EXIT_WOULD_DENY);
        assert!(
            out.stdout.starts_with("explain: UNSUPPORTED\n"),
            "{}",
            out.stdout
        );
        assert!(!out.stdout.contains("pass:"), "{}", out.stdout);
    }

    #[test]
    fn explain_invalid_file_exit_one() {
        let bad = TempFile::new("explain-bad", "[[operation\n");
        let out = explain_with(&bad, &["operation", "service.restart"]);
        assert_eq!(out.code, EXIT_INVALID);
        assert!(out.stdout.is_empty());
        assert!(out.stderr.starts_with("error: "), "{}", out.stderr);

        let missing = explain(&s(&["/nonexistent/relay-explain.toml", "operation", "x"]));
        assert_eq!(missing.code, EXIT_INVALID);

        let no_spec = explain_with(&bad, &[]);
        assert_eq!(no_spec.code, EXIT_INVALID);
    }

    #[test]
    fn help_flag_after_the_raw_exec_separator_is_the_commands_own() {
        assert!(wants_help(&s(&["f.toml", "--help"])));
        assert!(wants_help(&s(&["-h"])));
        assert!(!wants_help(&s(&[
            "f.toml", "raw-exec", "--", "/bin/foo", "--help"
        ])));
        assert!(!wants_help(&s(&["f.toml", "raw-exec", "--", "-h"])));
    }

    #[test]
    fn explain_help_returns_zero() {
        let out = explain(&s(&["--help"]));
        assert_eq!(out.code, EXIT_VALID);
        for pass in ["precondition", "deny", "guard", "allow", "default"] {
            assert!(out.stdout.contains(pass), "help must document {pass}");
        }
        assert_eq!(run_explain(&s(&["-h"])), EXIT_VALID);
    }

    #[test]
    fn explain_and_would_allow_agree() {
        let f = TempFile::new("explain-agree", POLICY);
        let root = TempDir::created("explain-agree-root");
        let specs: [&[&str]; 6] = [
            &["operation", "service.restart", "unit=nginx"],
            &["operation", "service.restart", "unit=sshd"],
            &["operation", "service.restart", "unit=cron"],
            &["operation", "file.read", "path=/a/../b"],
            &["raw-exec", "--", "/bin/echo", "hi"],
            &["raw-exec", "--", "/bin/echo", "a b"],
        ];
        for spec in specs {
            let mut would = vec![
                "relay-daemon".to_string(),
                "policy".to_string(),
                "check".to_string(),
                f.path_str(),
                "--templates".to_string(),
                root.path_str(),
                "--would-allow".to_string(),
            ];
            would.extend(spec.iter().map(|p| p.to_string()));
            let would_code = run(&would);

            let root_path = root.path_str();
            let mut explain_args = vec!["--templates", root_path.as_str()];
            explain_args.extend_from_slice(spec);
            let out = explain_with(&f, &explain_args);

            assert_eq!(out.code, would_code, "{spec:?}");
            assert_eq!(
                out.code == EXIT_VALID,
                out.stdout.starts_with("explain: ALLOW")
            );
        }
    }

    /// The in-process twin of the cross-binary preflight test: the wire verdict
    /// and `explain` read the same `Explained`.
    #[test]
    fn explain_and_policy_verdict_name_the_same_rule() {
        let compiled = policy::from_toml_str(POLICY).expect("policy must parse");
        let specs: [Vec<String>; 4] = [
            s(&["operation", "service.restart", "unit=nginx"]),
            s(&["operation", "service.restart", "unit=sshd"]),
            s(&["operation", "service.restart", "unit=cron"]),
            s(&["raw-exec", "--", "/bin/echo", "hi"]),
        ];
        for spec in specs {
            let mut iter = spec.iter().peekable();
            let parsed = parse_spec(&mut iter, "--would-allow").expect("spec must parse");
            let query = build_query(&parsed);
            let QueryDecision::Decided(e) = decide_query(
                query.action.as_ref(),
                &compiled,
                crate::templates::TemplateSet::empty_static(),
            ) else {
                panic!("{spec:?} must be decided");
            };
            let v = crate::dispatch::evaluate_policy_query(
                &query,
                &compiled,
                crate::templates::TemplateSet::empty_static(),
            );
            let want_pass = format!("POLICY_PASS_{}", e.pass.to_string().to_uppercase());
            assert_eq!(
                crate::gen::PolicyPass::try_from(v.pass).map(|p| p.as_str_name()),
                Ok(want_pass.as_str()),
                "{spec:?}"
            );
            assert_eq!(
                v.rule_index,
                e.rule.map_or(0, |r| r.index as u32),
                "{spec:?}"
            );
            assert_eq!(
                v.rule_line,
                e.rule.and_then(|r| r.line).map_or(0, |l| l as u32),
                "{spec:?}"
            );
            assert_eq!(v.rule_section != 0, e.rule.is_some(), "{spec:?}");
            assert_eq!(v.matched_on, e.matched_on.to_string(), "{spec:?}");
        }
    }

    /// A config directory holding `policy.toml` and, when `fragments` is
    /// `Some`, a `policy.d` with those file names in it.
    fn config_dir(label: &str, fragments: Option<&[&str]>) -> TempDir {
        let root = TempDir::created(label);
        std::fs::write(root.path().join("policy.toml"), POLICY).unwrap();
        if let Some(names) = fragments {
            let dir = root.path().join("policy.d");
            std::fs::create_dir(&dir).unwrap();
            for name in names {
                std::fs::write(dir.join(name), "").unwrap();
            }
        }
        root
    }

    #[test]
    fn a_populated_policy_directory_beside_the_file_is_found() {
        let root = config_dir("sibling-populated", Some(&["10-a.toml"]));
        let file = root.path().join("policy.toml");
        let found = populated_sibling_policy_dir(&file.to_string_lossy());
        assert_eq!(
            found.as_deref(),
            Some(root.path().join("policy.d").to_str().unwrap())
        );
    }

    #[test]
    fn an_empty_or_absent_policy_directory_beside_the_file_is_not_reported() {
        for fragments in [None, Some(&[][..])] {
            let root = config_dir("sibling-quiet", fragments);
            let file = root.path().join("policy.toml");
            assert_eq!(populated_sibling_policy_dir(&file.to_string_lossy()), None);
        }
    }

    #[test]
    fn explain_warns_that_it_reads_only_the_file_when_policy_d_is_populated() {
        let root = config_dir("explain-sibling", Some(&["10-a.toml"]));
        let file = root
            .path()
            .join("policy.toml")
            .to_string_lossy()
            .into_owned();
        let out = explain(&s(&[&file, "operation", "service.restart", "unit=nginx"]));
        assert_eq!(out.code, EXIT_VALID);
        assert!(out.stderr.starts_with("warning: "), "{}", out.stderr);
        assert!(
            out.stderr.contains("explain reads only the Policy file"),
            "{}",
            out.stderr
        );

        let root = config_dir("explain-sibling-empty", Some(&[]));
        let file = root
            .path()
            .join("policy.toml")
            .to_string_lossy()
            .into_owned();
        let out = explain(&s(&[&file, "operation", "service.restart", "unit=nginx"]));
        assert!(out.stderr.is_empty(), "{}", out.stderr);
    }
}
