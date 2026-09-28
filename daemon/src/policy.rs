//! Daemon Policy engine — last line of defense (ADR-0002).
//!
//! Implements the **per-Node Policy** that decides what may run on this Node:
//!
//! - **Locally-rooted**: loaded from a root-owned local file; no network path.
//! - **Remotely-immutable**: the Relay may query the Policy (v0.0.4) but may
//!   **never** modify it over the wire. Only humans / config management may edit
//!   the Policy file on the Node.
//! - **Deny-by-default**: any Operation or Raw Exec not covered by an allow rule
//!   is denied without requiring an explicit deny entry.
//! - **Deny-beats-allow**: a matching deny rule always overrides an allow rule.
//! - **Argument-level granularity**: allow and deny rules constrain individual
//!   argument positions, not just the operation name.
//! - **Raw Exec regex-gated** (ADR-0001): Raw Exec commands are only permitted
//!   when an allow regex matches the joined `argv.join(" ")` **in full** — the
//!   daemon enforces the whole-command match itself (ADR-0019, amended
//!   2026-09-16) — and no deny regex matches the joined command, any raw argv
//!   element, or any canonical element (the joined command re-split on
//!   whitespace — ADR-0019); the Deny reason names which form matched. Every
//!   argv element must be free of whitespace, and `argv[0]` must be
//!   non-empty: any offending element is refused before the allow pass runs
//!   (ADR-0019, amended 2026-09-16).
//!
//! **Not yet wired**: this module provides a pure evaluation API. Task-dispatch
//! wiring lands in a later v0.0.3 issue.

use std::fmt::Write as _;
use std::io::Read;
use std::path::Path;

use regex::Regex;
use serde::Deserialize;

use crate::hardened_open::{open_hardened, HardenedRejection};
use crate::operations;

// ---------------------------------------------------------------------------
// On-disk serde model
// ---------------------------------------------------------------------------

/// Top-level Policy file as deserialized from TOML.
///
/// All fields default to empty so a minimal file (e.g. just `[raw_exec]`) is
/// valid. The `Default` derive is required because the containing struct uses
/// `#[serde(default)]` on nested-struct fields.
#[derive(Debug, Deserialize, Default)]
struct PolicyFile {
    #[serde(default)]
    operation: Vec<OperationRuleRaw>,
    #[serde(default)]
    deny: Vec<DenyRuleRaw>,
    #[serde(default)]
    raw_exec: RawExecRaw,
}

/// One `[[operation]]` allow block from the Policy file.
///
/// `allowed_args[i]` is the set of permitted values at argument position `i`.
/// `"*"` at any inner position matches any value (wildcard). An empty outer
/// list means the operation is allowed with zero arguments.
#[derive(Debug, Deserialize, Default)]
struct OperationRuleRaw {
    name: String,
    #[serde(default)]
    allowed_args: Vec<Vec<String>>,
}

/// One `[[deny]]` block from the Policy file.
///
/// `args[i]` is the set of values denied at argument position `i`. An empty
/// outer list blocks the entire operation regardless of arguments. Trailing
/// positions beyond what is listed are vacuously satisfied (more-restrictive
/// deny-beats-allow reading; see module doc).
#[derive(Debug, Deserialize, Default)]
struct DenyRuleRaw {
    name: String,
    #[serde(default)]
    args: Vec<Vec<String>>,
}

/// The `[raw_exec]` section from the Policy file.
///
/// `allow` patterns are tested against the WHOLE joined `argv.join(" ")` —
/// the daemon compiles each pattern to a full match (ADR-0019, amended
/// 2026-09-16), so anchoring is enforced, not merely recommended.
/// `deny` patterns are tested against `argv.join(" ")`, each raw argv element,
/// and each canonical element (the joined command re-split on whitespace —
/// ADR-0019).
#[derive(Debug, Deserialize, Default)]
struct RawExecRaw {
    #[serde(default)]
    allow: Vec<String>,
    #[serde(default)]
    deny: Vec<String>,
}

// ---------------------------------------------------------------------------
// Compiled in-memory model
// ---------------------------------------------------------------------------

/// A compiled regex paired with the original pattern string.
///
/// The pattern is kept so the deciding-rule report can surface it in
/// `Decision` without re-extracting it from the `Regex`.
#[derive(Debug, Clone)]
struct CompiledRe {
    pattern: String,
    re: Regex,
}

/// The compiled, in-memory Policy derived from a `PolicyFile`.
///
/// All regex patterns are compiled once at load time; evaluation is pure.
#[derive(Debug)]
pub struct Policy {
    operations: Vec<OperationRuleRaw>,
    denies: Vec<DenyRuleRaw>,
    raw_allow: Vec<CompiledRe>,
    raw_deny: Vec<CompiledRe>,
    fingerprint: String,
}

// ---------------------------------------------------------------------------
// Decision types
// ---------------------------------------------------------------------------

/// The deciding rule surfaced alongside a `Decision`.
///
/// Captured on both `Allow` and `Deny` variants so the caller (and later
/// `PolicyQuery`) can attribute the decision to the exact rule that fired.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Rule {
    /// An `[[operation]]` allow block matched.
    OperationAllow { operation: String },
    /// A `[[deny]]` block matched and overrode an allow.
    OperationDeny { operation: String },
    /// A `[raw_exec]` allow pattern matched.
    RawExecAllow { pattern: String },
    /// A `[raw_exec]` deny pattern matched (deny wins).
    RawExecDeny { pattern: String },
}

/// One `[[operation]]` allow rule, as a display-only mirror of the Policy file
/// for the `PolicySnapshot` (ADR-0002) — not an evaluated form. `allowed_args[i]`
/// is the permitted-value set at argv position `i`; `"*"` marks a wildcard
/// position; an empty outer list means the operation is allowed with zero
/// arguments.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OperationAllowRule {
    pub name: String,
    pub allowed_args: Vec<Vec<String>>,
}

/// One `[[deny]]` rule, as a display-only mirror of the Policy file for the
/// `PolicySnapshot` (ADR-0002) — not an evaluated form. `args[i]` is the
/// denied-value set at argv position `i`; an empty outer list denies the
/// whole operation regardless of arguments. Deny rules never carry a `"*"`
/// wildcard (they list explicit values).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OperationDenyRule {
    pub name: String,
    pub args: Vec<Vec<String>>,
}

/// The outcome of a Policy evaluation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    /// The operation or command is permitted. The deciding rule is included for
    /// audit and `PolicyQuery` use.
    Allow(Rule),
    /// The operation or command is denied.
    ///
    /// `reason` is a human-readable explanation. `rule` is `Some` when a
    /// specific deny rule fired; `None` when deny-by-default applies.
    Deny { reason: String, rule: Option<Rule> },
}

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Errors from the Policy loader.
///
/// All variants are fail-closed — the caller must not proceed with execution
/// if any of these is returned.
#[derive(Debug, thiserror::Error)]
pub enum PolicyError {
    /// The Policy file has group- or world-write permission bits set.
    ///
    /// Anyone who can write the file can escalate privileges, so the daemon
    /// refuses to load it.
    #[error("policy file has insecure permissions (mode {mode:#o}); group/world-writable — refusing to load (fail closed)")]
    InsecurePermissions { mode: u32 },

    /// The Policy file is not owned by root (uid 0) or the daemon's euid.
    #[error("policy file has insecure owner (uid {uid}); must be owned by root or the daemon euid — refusing to load (fail closed)")]
    InsecureOwner { uid: u32 },

    /// The Policy file path is (or ends in) a symlink; refused via O_NOFOLLOW.
    #[error("policy file path is a symlink; refusing to follow (fail closed)")]
    SymlinkPath,

    /// The Policy file is not a regular file (FIFO, device, socket, directory).
    #[error("policy file is not a regular file; refusing to load (fail closed)")]
    NotRegularFile,

    /// Filesystem I/O error reading the Policy file.
    #[error(transparent)]
    Io(#[from] std::io::Error),

    /// TOML parse error.
    #[error(transparent)]
    Parse(#[from] toml::de::Error),

    /// A `[raw_exec]` regex pattern failed to compile.
    ///
    /// An invalid regex in the Policy file is treated as a load failure
    /// (fail-closed): a partial policy that skips a bad pattern would silently
    /// widen the allow surface.
    ///
    /// `hint` is empty except for the one known allow-side edge case (a
    /// verbose-mode pattern ending in an unterminated `#` comment — see
    /// [`compile_allow_regex`]), where it names the fix so the error is
    /// actionable rather than a bare "unclosed group" from the wrapped text.
    #[error("invalid regex pattern {pattern:?}: {source}{hint}")]
    InvalidRegex {
        pattern: String,
        #[source]
        source: regex::Error,
        hint: String,
    },
}

// ---------------------------------------------------------------------------
// Parse API (pure, no filesystem access)
// ---------------------------------------------------------------------------

/// Compute the SHA-256 fingerprint of raw Policy file bytes.
///
/// Returns a 64-character lowercase-hex string with no prefix — the same
/// format used for cert fingerprints in `transport.go`.
///
/// **Canonical form:** the fingerprint is over the **raw file bytes**, not a
/// canonicalized or compiled form. Consequences:
/// - Identical bytes → identical fingerprint (strict byte-identity).
/// - Cosmetic edits (whitespace, comments, key reorder) **change** the
///   fingerprint — intended; policy-as-code pushes the same file everywhere,
///   so byte-identity is exactly the drift signal an operator needs.
/// - An empty / deny-all Policy produces the SHA-256 of the empty string:
///   `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`.
///
/// The TOML serializer is excluded from the daemon binary for musl size
/// (ADR-0007); re-adding it plus a stable field-ordering round-trip for
/// canonicalization adds weight on a security-adjacent path for no gain.
fn policy_fingerprint(bytes: &[u8]) -> String {
    let digest = ring::digest::digest(&ring::digest::SHA256, bytes);
    let mut s = String::with_capacity(64);
    for b in digest.as_ref() {
        write!(&mut s, "{b:02x}").expect("write to String is infallible");
    }
    s
}

/// Parse and compile a Policy from a TOML string.
///
/// Pure function — no filesystem access. Used by `load_policy` and directly
/// by tests (which supply the fixture via `include_str!`).
///
/// Fails closed: a malformed regex in `[raw_exec]` returns `Err(InvalidRegex)`
/// rather than silently skipping the pattern.
pub fn from_toml_str(s: &str) -> Result<Policy, PolicyError> {
    let file: PolicyFile = toml::from_str(s)?;

    let raw_allow =
        compile_regexes(file.raw_exec.allow, compile_allow_regex).map_err(with_allow_regex_hint)?;
    let raw_deny = compile_regexes(file.raw_exec.deny, compile_deny_regex)?;

    Ok(Policy {
        operations: file.operation,
        denies: file.deny,
        raw_allow,
        raw_deny,
        fingerprint: policy_fingerprint(s.as_bytes()),
    })
}

/// Compiles a `[raw_exec] deny` pattern verbatim — deny semantics are
/// unchanged by the ADR-0019 amendment (2026-09-16): a deny still matches
/// wherever its pattern matches (joined command, raw element, or canonical
/// element), never a full match.
fn compile_deny_regex(pattern: &str) -> Result<Regex, regex::Error> {
    Regex::new(pattern)
}

/// Compiles a `[raw_exec] allow` pattern so it matches only the WHOLE joined
/// command (ADR-0019, amended 2026-09-16): allow patterns no longer match as
/// a substring anywhere in `argv.join(" ")`.
///
/// Two steps, in order:
/// 1. Validate `pattern` alone with `Regex::new`. This must run FIRST:
///    wrapping a pattern that is invalid on its own must never turn it into a
///    valid one. `a)|(?:b` is invalid alone but would become valid once
///    wrapped in a bare `(?:...)` group — validating first closes that.
/// 2. Compile `\A(?:pattern)\z`. `\A`/`\z` are used instead of `^`/`$` so the
///    anchors hold no matter what inline flags the author sets (an `(?m)`
///    inside the group cannot make `^`/`$` match a line boundary and thereby
///    reach past the wrapper); the non-capturing group keeps a top-level
///    alternation whole, so `a|b` wraps to `\A(?:a|b)\z`, matching the whole
///    command against "a" OR "b", not `\Aa` OR `b\z`.
///
/// **Known edge case (fail-closed, not a bug):** a verbose-mode (`(?x)`)
/// pattern that ends in a `#` end-of-line comment with no trailing newline
/// swallows the appended `)\z` into that comment, so the wrapped compile
/// fails and the whole Policy is refused as `InvalidRegex`. There is no
/// silent-success case here: the wrapped regex either compiles to the
/// intended full match or fails to compile at all, so this only ever costs
/// availability (a load failure), never a security property — but see the
/// module's test for what a load failure does to the Node's Policy (deny-all,
/// ADR-0002's fail-closed loader).
fn compile_allow_regex(pattern: &str) -> Result<Regex, regex::Error> {
    Regex::new(pattern)?;
    Regex::new(&format!(r"\A(?:{pattern})\z"))
}

fn compile_regexes(
    patterns: Vec<String>,
    compile: fn(&str) -> Result<Regex, regex::Error>,
) -> Result<Vec<CompiledRe>, PolicyError> {
    patterns
        .into_iter()
        .map(|pattern| {
            compile(&pattern)
                .map(|re| CompiledRe {
                    pattern: pattern.clone(),
                    re,
                })
                .map_err(|source| PolicyError::InvalidRegex {
                    pattern,
                    source,
                    hint: String::new(),
                })
        })
        .collect()
}

/// Textual hint for the one known [`compile_allow_regex`] edge case: a
/// verbose-mode (`(?x)`) pattern whose last line is an unterminated `#`
/// comment. Wrapping appends `)\z` *after* the author's pattern text, and a
/// verbose-mode end-of-line comment with no trailing newline swallows
/// whatever follows it on that line — turning a pattern that compiles alone
/// into one that does not once wrapped. Purely textual (never re-runs the
/// compiler), so it may miss unusual spellings of the flag; it exists to make
/// a confusing "unclosed group" error actionable, not to classify every
/// `InvalidRegex`.
fn verbose_trailing_comment_hint(pattern: &str) -> String {
    let looks_verbose = [
        "(?x)", "(?x:", "(?xi)", "(?ix)", "(?xs)", "(?sx)", "(?xm)", "(?mx)",
    ]
    .iter()
    .any(|flag| pattern.contains(flag));
    if !looks_verbose {
        return String::new();
    }
    let last_line = pattern.rsplit('\n').next().unwrap_or(pattern);
    if last_line.contains('#') {
        " (a verbose-mode ((?x)) pattern must not end in a `#` comment with no trailing \
          newline; add a trailing newline after the comment)"
            .to_string()
    } else {
        String::new()
    }
}

/// Attaches [`verbose_trailing_comment_hint`] to an `InvalidRegex` error from
/// the ALLOW list. Only the allow side's wrapping ([`compile_allow_regex`])
/// can turn this pattern shape from compiling into non-compiling, so the hint
/// is computed here rather than generically in [`compile_regexes`].
fn with_allow_regex_hint(err: PolicyError) -> PolicyError {
    match err {
        PolicyError::InvalidRegex {
            pattern, source, ..
        } => {
            let hint = verbose_trailing_comment_hint(&pattern);
            PolicyError::InvalidRegex {
                pattern,
                source,
                hint,
            }
        }
        other => other,
    }
}

// ---------------------------------------------------------------------------
// Loader (filesystem + fail-closed permission gate)
// ---------------------------------------------------------------------------

/// Load and compile a Policy from the file at `path`.
///
/// **Local only** — takes a `&Path`; there is no network branch.
///
/// **Single-descriptor validate-then-read**: the file is opened exactly once;
/// every check below (symlink, regular-file, mode, owner) is performed via
/// `fstat` on that *open descriptor*, and the bytes are read from the same
/// descriptor. This closes the metadata/read TOCTOU race that a path-based
/// check-then-read has — the bytes validated are always the bytes loaded.
///
/// Fail-closed checks (ADR-0002), in order, performed by the shared
/// [`open_hardened`] (the same open Template Operation files use); each
/// refusal is logged here and mapped to this loader's own [`PolicyError`]:
/// 1. Refuses to load if the final path component is a symlink. Enforced via
///    `O_NOFOLLOW` at `open()` (an `ELOOP` open error, not an `lstat`
///    afterward — re-checking the path after open would reopen the race).
/// 2. Refuses to load if the opened file is not a regular file (FIFO, device,
///    socket, directory), via the `fstat`'d file type. `O_NONBLOCK` at
///    `open()` guarantees this check can't be starved by a FIFO with no
///    writer (regular-file reads are unaffected by `O_NONBLOCK`).
/// 3. Refuses to load if the file has group- or world-write bits set (`mode &
///    0o022 != 0`). Logged via `tracing::error!` with path and mode; file
///    contents are never logged.
/// 4. Refuses to load if the file owner is neither root (uid 0) nor the
///    daemon's effective uid (`rustix::process::geteuid()`). The euid branch
///    allows the check to pass on a non-root CI runner while remaining
///    more-restrictive than the floor requirement (group/world-write only).
///
/// **Residual (documented, not closed here):** parent-directory writability.
/// `O_NOFOLLOW` only guards the final path component — a rename-swap of the
/// Policy file within an attacker-writable *parent* directory remains
/// possible even though the file itself is root-owned and mode-correct.
/// This is mitigated operationally by requiring the Policy file to live in a
/// root-owned directory (e.g. `/etc/relay-daemon/`); fully closing it would
/// require validating the parent directory itself (e.g. `openat` from a
/// validated directory descriptor), which is out of scope here.
pub fn load_policy(path: &Path) -> Result<Policy, PolicyError> {
    // Open once and validate the descriptor — checks 1-4 above, in that order —
    // in the shared hardened open (`hardened_open`, the same one templates
    // use): O_NOFOLLOW | O_NONBLOCK, no write flag, and every check an fstat
    // on the opened fd, never on the path. Each refusal is mapped back to this
    // loader's own error and logged here.
    let (mut file, _meta) = open_hardened(path).map_err(|rejection| match rejection {
        HardenedRejection::Symlink => {
            tracing::error!(
                path = %path.display(),
                "policy file path is a symlink; refusing to follow (fail closed)"
            );
            PolicyError::SymlinkPath
        }
        HardenedRejection::NotRegularFile => {
            tracing::error!(
                path = %path.display(),
                "policy file is not a regular file; refusing to load (fail closed)"
            );
            PolicyError::NotRegularFile
        }
        // Permission floor: group- or world-write means the file can be
        // modified by an attacker with group membership, which would let them
        // escalate privileges through the Policy. Fail closed.
        HardenedRejection::InsecurePermissions { mode } => {
            tracing::error!(
                path = %path.display(),
                mode = format!("{mode:#o}"),
                "policy file is group/world-writable; refusing to load (fail closed)"
            );
            PolicyError::InsecurePermissions { mode }
        }
        HardenedRejection::InsecureOwner { uid } => {
            tracing::error!(
                path = %path.display(),
                uid = uid,
                "policy file is not owned by root or the daemon euid; refusing to load (fail closed)"
            );
            PolicyError::InsecureOwner { uid }
        }
        HardenedRejection::Io(e) => PolicyError::Io(e),
    })?;

    // Read from the SAME descriptor that was validated above — this is the
    // line that closes the metadata/read TOCTOU race.
    let mut contents = String::new();
    file.read_to_string(&mut contents)?;
    from_toml_str(&contents)
}

// ---------------------------------------------------------------------------
// Lint API (collect-all diagnostics for `relay-daemon policy check`, #93)
// ---------------------------------------------------------------------------

/// Severity of a single lint finding.
///
/// `Error` findings mean the Policy file cannot be trusted (parse error,
/// invalid regex, unknown Operation name) and must fail a pipeline. `Warning`
/// findings are Policy smells that do not invalidate the file (a fully
/// shadowed allow rule) — non-fatal unless `--strict` is given.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LintSeverity {
    Error,
    Warning,
}

/// One lint finding, naming the offending rule by section + index + name.
///
/// Serde-parsed structs carry no source line numbers, so the rule is
/// identified positionally, e.g. `[[operation]] #1 (name="pkg.remove")`,
/// `[raw_exec].allow[0]`, `[[deny]] #0 (name="file.read")`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LintFinding {
    pub severity: LintSeverity,
    pub location: String,
    pub message: String,
}

/// The result of linting a Policy file.
///
/// A TOML parse error means nothing else is checkable, so `parse_error` is
/// mutually exclusive with `findings` being non-empty: when `parse_error` is
/// `Some`, `findings` is always empty.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LintReport {
    pub parse_error: Option<String>,
    pub findings: Vec<LintFinding>,
}

impl LintReport {
    /// `true` if the file cannot be trusted: a parse error or any
    /// `Error`-severity finding.
    pub fn has_errors(&self) -> bool {
        self.parse_error.is_some()
            || self
                .findings
                .iter()
                .any(|f| f.severity == LintSeverity::Error)
    }

    /// `true` if any `Warning`-severity finding is present.
    pub fn has_warnings(&self) -> bool {
        self.findings
            .iter()
            .any(|f| f.severity == LintSeverity::Warning)
    }
}

/// Lints a Policy file, collecting **all** findings rather than failing
/// closed on the first bad rule.
///
/// Contrast [`from_toml_str`], which is fail-closed for runtime loading (stops
/// at the first bad regex): a pipeline linter needs to report every problem
/// in one pass, not one problem per invocation.
///
/// Checks, in order:
/// 1. TOML parse — on failure, `parse_error` is set and nothing else is
///    checked (an unparsable file has no rules to lint).
/// 2. Invalid `[raw_exec]` regex patterns (`Error`) — compiled with the same
///    `regex::Regex` engine `from_toml_str` uses, so the lint verdict matches
///    load-time behavior.
/// 3. Unknown Operation names in `[[operation]]` and `[[deny]]`, checked
///    against the vocabulary — see [`lint_with_vocabulary`] for the
///    Error-vs-Warning rule, which depends on whether the caller supplied the
///    Node's Template Operation names.
/// 4. Allow rules fully shadowed by a `[[deny]]` rule of the same name
///    (`Warning`) — see [`allow_is_shadowed_by_deny`].
/// 5. `[[deny]]` rules whose `args` contain a `"*"` or an empty inner list and
///    can therefore never fire (`Warning`) — see [`lint_deny_arg_noops`].
/// 6. A `[raw_exec]` allow pattern not anchored `^...$` (`Warning`) — its
///    meaning changed with the ADR-0019 amendment (2026-09-16): allow patterns
///    now match the WHOLE command, so an unanchored pattern no longer matches
///    as a substring anywhere in it — see [`lint_raw_exec_allow_anchoring`].
///
/// **Known limitations** (documented, not attempted):
/// - Shadowing by the *union* of multiple deny rules (set-cover) is not
///   detected; only single-deny-rule shadowing is. This is conservative — it
///   may miss a shadowed allow, but never flags one that isn't actually dead.
/// - `[raw_exec]` allow-vs-deny regex shadowing is not attempted: regex
///   language subset containment is undecidable in general.
///
/// Production callers go through [`lint_with_vocabulary`] (the CLI always knows
/// whether a template root was supplied); this no-vocabulary shorthand is kept
/// for the lint suite, which exercises the Policy-only checks directly.
#[cfg(test)]
pub fn lint(toml: &str) -> LintReport {
    lint_with_vocabulary(toml, &[], false)
}

/// [`lint`], plus the Template Operation names that complete this Node's
/// vocabulary (ADR-0021, issue #292).
///
/// `template_names` are the names a template set supplies; `vocabulary_complete`
/// says whether the caller actually knows the whole vocabulary (i.e. a template
/// root was supplied — even an empty one), which decides how an unrecognized
/// name is reported:
///
/// - **`vocabulary_complete == true`** — the caller enumerated the Node's
///   natives *and* templates, so a name in neither is provably unrunnable
///   there: `Error`, exactly as before templates existed.
/// - **`vocabulary_complete == false`** — the linter was given only a Policy
///   file. Since ADR-0021 the vocabulary is **per-Node**, so an unrecognized
///   name may be a perfectly good Template Operation on the target Node, or a
///   typo, and this linter cannot tell them apart. Reporting it as an `Error`
///   would fail pipelines for correct Policy; reporting nothing would lose the
///   typo check. It is therefore a `Warning` that names the fix (`--templates`),
///   and `--strict` still fails the pipeline on it.
///
/// The rule for `[[deny]]` names is the same. A deny for a name this vocabulary
/// lacks is still flagged rather than silently accepted: a no-op deny rule an
/// operator believes is protecting them is the dangerous reading.
pub fn lint_with_vocabulary(
    toml: &str,
    template_names: &[String],
    vocabulary_complete: bool,
) -> LintReport {
    let file: PolicyFile = match toml::from_str(toml) {
        Ok(f) => f,
        Err(e) => {
            return LintReport {
                parse_error: Some(e.to_string()),
                findings: Vec::new(),
            }
        }
    };

    let mut findings = Vec::new();

    lint_raw_exec_regexes(
        &file.raw_exec.allow,
        "allow",
        compile_allow_regex,
        true,
        &mut findings,
    );
    lint_raw_exec_regexes(
        &file.raw_exec.deny,
        "deny",
        compile_deny_regex,
        false,
        &mut findings,
    );
    lint_raw_exec_allow_anchoring(&file.raw_exec.allow, &mut findings);

    let known = |name: &str| {
        operations::risk_class(name).is_some() || template_names.iter().any(|t| t == name)
    };
    let (severity, hint) = if vocabulary_complete {
        (
            LintSeverity::Error,
            "not a Native Operation and not in the supplied template set",
        )
    } else {
        (
            LintSeverity::Warning,
            "not a Native Operation; if this names a Template Operation, pass \
             --templates <dir> so the linter can confirm it exists on the target Node \
             (vocabulary is per-Node, ADR-0021)",
        )
    };

    for (i, op) in file.operation.iter().enumerate() {
        if !known(&op.name) {
            findings.push(LintFinding {
                severity,
                location: format!("[[operation]] #{i} (name={:?})", op.name),
                message: format!("unknown Operation name {:?}: {hint}", op.name),
            });
        }
    }

    for (i, deny) in file.deny.iter().enumerate() {
        if !known(&deny.name) {
            findings.push(LintFinding {
                severity,
                location: format!("[[deny]] #{i} (name={:?})", deny.name),
                message: format!("unknown Operation name {:?}: {hint}", deny.name),
            });
        }
    }

    lint_shadowed_allows(&file.operation, &file.deny, &mut findings);
    lint_deny_arg_noops(&file.deny, &mut findings);

    LintReport {
        parse_error: None,
        findings,
    }
}

/// The ADR-0018 lexical canonical-form test for a path argument: absolute, and
/// with no empty, `.`, `..`, or trailing-slash segment.
///
/// Pure and I/O-free — it does NOT fold case or Unicode (ADR-0018 records that
/// as a narrow residual), and it is deliberately the SINGLE definition used
/// both by [`Policy::evaluate`]'s `file.read` precondition and by the dispatch
/// gate that applies the same precondition to a Template Operation's
/// `path`-typed slots (issue #293). One predicate, two call sites — never two
/// notions of "canonical".
pub fn path_is_canonical(path: &str) -> bool {
    path == "/"
        || (path.starts_with('/')
            && !path.ends_with('/')
            && !path
                .split('/')
                .skip(1)
                .any(|seg| seg.is_empty() || seg == "." || seg == ".."))
}

/// The `Decision` a non-canonical path argument produces, with the reason text
/// shared by every caller of [`path_is_canonical`] so the plan verdict, the
/// apply-path stderr, and the audit record all read identically.
pub fn non_canonical_path_denial(path: &str) -> Decision {
    Decision::Deny {
        reason: format!(
            "path argument {path:?} is not in canonical form (ADR-0018): must be absolute \
             with no '.', '..', '//', or trailing-slash segment"
        ),
        rule: None,
    }
}

/// Checks every pattern in a `[raw_exec]` allow/deny list for regex validity.
///
/// Compiled with the same function `from_toml_str` uses for that section
/// (`compile_allow_regex` for "allow", `compile_deny_regex` for "deny"), so
/// the lint verdict can never diverge from load-time behavior. Only the
/// ALLOW section's wrapping (`compile_allow_regex`) can turn a
/// verbose-mode/trailing-`#`-comment pattern from compiling into
/// non-compiling — `compile_deny_regex` never wraps, so a deny pattern that
/// fails to compile is invalid on its own, and the wrapping hint would
/// misattribute the cause. `is_allow` gates the hint accordingly, matching
/// `with_allow_regex_hint`'s loader-side scoping.
fn lint_raw_exec_regexes(
    patterns: &[String],
    section: &str,
    compile: fn(&str) -> Result<Regex, regex::Error>,
    is_allow: bool,
    findings: &mut Vec<LintFinding>,
) {
    for (i, pattern) in patterns.iter().enumerate() {
        if let Err(e) = compile(pattern) {
            let hint = if is_allow {
                verbose_trailing_comment_hint(pattern)
            } else {
                String::new()
            };
            findings.push(LintFinding {
                severity: LintSeverity::Error,
                location: format!("[raw_exec].{section}[{i}]"),
                message: format!("invalid regex {pattern:?}: {e}{hint}"),
            });
        }
    }
}

/// Flags a `[raw_exec]` allow pattern that COMPILES (an invalid pattern is
/// already an `Error` from [`lint_raw_exec_regexes`]) but is not anchored at
/// both ends — its meaning changed with the ADR-0019 amendment (2026-09-16):
/// allow patterns now match the WHOLE joined command (the daemon wraps every
/// pattern as `\A(?:pattern)\z`), so an unanchored pattern no longer matches
/// as a substring anywhere in the command. `Warning`, not `Error`: the file is
/// still valid and evaluates exactly as written, just possibly not as the
/// author intended before this release; `--strict` makes it a pipeline gate.
///
/// A leading inline flag group (`(?i)^...$`) is skipped before the start-anchor
/// check, so a flag-prefixed anchored pattern does not false-alarm under
/// `--strict` (see [`strip_leading_flag_group`]).
///
/// **Known limit (documented, conservative):** a textually anchored top-level
/// alternation (`^a|b$`) does not warn even though only the `b` branch is
/// actually anchored at the start (the pattern parses as `(^a)|(b$)`) — its
/// meaning still narrowed by the ADR-0019 amendment, same as an unanchored
/// pattern, but this textual check cannot see inside the alternation.
fn lint_raw_exec_allow_anchoring(patterns: &[String], findings: &mut Vec<LintFinding>) {
    for (i, pattern) in patterns.iter().enumerate() {
        if compile_allow_regex(pattern).is_err() {
            // Already an Error from lint_raw_exec_regexes; don't pile on.
            continue;
        }
        if !allow_pattern_is_anchored(pattern) {
            findings.push(LintFinding {
                severity: LintSeverity::Warning,
                location: format!("[raw_exec].allow[{i}]"),
                message: format!(
                    "allow pattern {pattern:?} is not anchored ^...$: its meaning changed in \
                     this release -- allow patterns now match the WHOLE command (ADR-0019, \
                     amended 2026-09-16), so it no longer matches as a substring anywhere in \
                     the command; write it as ^...$ so it says what it matches"
                ),
            });
        }
    }
}

/// `true` if `pattern` is textually anchored at both the start (`^` or
/// `\A`) and the end (`$` or `\z`, the latter's own leading backslash not
/// itself escaped).
///
/// `\A`/`\z` count as anchors deliberately: they mean the same thing an
/// unwrapped `^`/`$` did before this release, and warning on them would be a
/// false alarm under `--strict` for an author who already wrote the
/// full-match form. See [`lint_raw_exec_allow_anchoring`]'s doc comment for
/// this test's documented limits.
fn allow_pattern_is_anchored(pattern: &str) -> bool {
    let body = strip_leading_flag_group(pattern);
    let starts_anchored = body.starts_with('^') || body.starts_with(r"\A");

    let ends_anchored = if let Some(rest) = pattern.strip_suffix('$') {
        // An escaped `\$` must not count: count the run of trailing
        // backslashes immediately before the `$` — an EVEN count means the
        // `$` itself is unescaped (each pair is a literal backslash).
        rest.chars().rev().take_while(|&c| c == '\\').count() % 2 == 0
    } else if let Some(rest) = pattern.strip_suffix(r"\z") {
        // Same test for the backslash that introduces `\z` itself: an ODD
        // number of further backslashes before it would escape it away.
        rest.chars().rev().take_while(|&c| c == '\\').count() % 2 == 0
    } else {
        false
    };

    starts_anchored && ends_anchored
}

/// Strips a single leading inline flag group (`(?i)`, `(?im)`, `(?-s)`, ...)
/// from `pattern`, if present, so [`allow_pattern_is_anchored`] checks for `^`
/// / `\A` after it rather than treating a flag-prefixed anchor as unanchored
/// (an author writing `(?i)^/bin/echo$` means the same full-match intent as
/// `^/bin/echo$`).
///
/// Deliberately narrow: only a group whose contents are drawn from the
/// regex crate's flag letters (`imsxU`) and `-` (separating positive from
/// negative flags) counts. A scoped flag group (`(?i:...)`), a non-capturing
/// group (`(?:...)`), a named group, or a lookaround is left untouched and
/// falls through to the ordinary anchor check on the pattern as written.
fn strip_leading_flag_group(pattern: &str) -> &str {
    let Some(rest) = pattern.strip_prefix("(?") else {
        return pattern;
    };
    let Some(close) = rest.find(')') else {
        return pattern;
    };
    let flags = &rest[..close];
    let is_bare_flag_group = !flags.is_empty() && flags.chars().all(|c| "imsxU-".contains(c));
    if is_bare_flag_group {
        &rest[close + 1..]
    } else {
        pattern
    }
}

/// Flags `[[deny]]` rules that can never fire — a silent no-op the operator
/// likely believes is protecting them (issue #343). On the last line of
/// defense (Policy, ADR-0002), a deny that looks active but matches nothing is
/// a false sense of security, and catching exactly that is the lint's job.
///
/// `Policy::evaluate`'s deny pass matches each argument position by EXACT VALUE
/// (`denied_vals.contains(arg)`); unlike the allow pass, it gives deny args no
/// wildcard semantics. So two constructs are dead:
///
/// - **`"*"` in a position** matches only the literal argument string `"*"`,
///   never "any value" as it would in an allow rule. An operator who writes
///   `args = [["*"]]` to mean "deny every value here" gets a rule that denies
///   almost nothing.
/// - **an empty inner list `[]`** at a position is satisfiable by no value at
///   all, so the whole `all-positions-match` test can never succeed and the
///   deny never fires.
///
/// Both are `Warning`s (promoted to failure by `--strict`), matching the
/// shadowed-allow lint. The legitimate unconditional deny — an empty OUTER
/// args list (`args = []`, "block every invocation", handled at
/// `evaluate`'s deny pass) — is explicitly NOT flagged; only a non-empty rule
/// with a dead inner position is. Real exact-match denies
/// (`args = [["nginx"]]`) contain neither construct and are never flagged.
fn lint_deny_arg_noops(denies: &[DenyRuleRaw], findings: &mut Vec<LintFinding>) {
    for (di, deny) in denies.iter().enumerate() {
        // `args = []` is the legitimate unconditional deny-all, not a no-op.
        if deny.args.is_empty() {
            continue;
        }
        for (pos, vals) in deny.args.iter().enumerate() {
            if vals.is_empty() {
                findings.push(LintFinding {
                    severity: LintSeverity::Warning,
                    location: format!("[[deny]] #{di} (name={:?}) args[{pos}]", deny.name),
                    message: format!(
                        "empty value list at argument position {pos}: no value can satisfy it, so \
                         this deny rule can never fire (a silent no-op). To block every invocation \
                         of the operation, use an empty top-level args list (args = []) instead."
                    ),
                });
            } else if vals.iter().any(|v| v == "*") {
                findings.push(LintFinding {
                    severity: LintSeverity::Warning,
                    location: format!("[[deny]] #{di} (name={:?}) args[{pos}]", deny.name),
                    message: format!(
                        "\"*\" at argument position {pos} is matched literally in a deny rule, NOT \
                         as a wildcard (deny args are exact-match): it does not broaden this \
                         position to every value. To deny regardless of this argument, omit the \
                         position; to block the whole operation, use an empty args list (args = [])."
                    ),
                });
            }
        }
    }
}

/// Flags every `[[operation]]` allow rule that is fully shadowed by some
/// `[[deny]]` rule of the same name (see [`allow_is_shadowed_by_deny`]).
fn lint_shadowed_allows(
    allows: &[OperationRuleRaw],
    denies: &[DenyRuleRaw],
    findings: &mut Vec<LintFinding>,
) {
    for (ai, allow) in allows.iter().enumerate() {
        for (di, deny) in denies.iter().enumerate() {
            if deny.name != allow.name {
                continue;
            }
            if allow_is_shadowed_by_deny(allow, deny) {
                findings.push(LintFinding {
                    severity: LintSeverity::Warning,
                    location: format!("[[operation]] #{ai} (name={:?})", allow.name),
                    message: format!(
                        "allow rule is fully shadowed by [[deny]] #{di} (name={:?}); it can never fire",
                        deny.name
                    ),
                });
            }
        }
    }
}

/// `true` if `deny` (same operation name as `allow`, checked by the caller)
/// covers every invocation `allow` would otherwise permit — i.e. the allow
/// rule can never fire.
///
/// Mirrors [`Policy::evaluate`]'s own deny/allow semantics exactly, so a
/// flagged allow provably can never fire:
/// - An empty `deny.args` blocks the whole operation unconditionally
///   (`Policy::evaluate`'s empty-`args` deny branch) → always shadowed.
/// - Otherwise, `deny` covers `allow` iff for **every** position `i` in
///   `0..allow.allowed_args.len()`:
///   - if `i < deny.args.len()`: `allow.allowed_args[i]` contains no `"*"`
///     wildcard **and** every value in it is present in `deny.args[i]`
///     (finite subset — a deny has no wildcard, so a `"*"` allow position is
///     never coverable);
///   - if `i >= deny.args.len()`: covered (the deny's vacuous-satisfaction
///     rule fires for absent trailing positions, matching `Policy::evaluate`,
///     and `allow`'s fixed arg count means the invocation has exactly
///     `allow.allowed_args.len()` args).
///
/// Positions beyond `allow.allowed_args.len()` (when `deny` is longer than
/// `allow`) are not examined: they index beyond the invocation's args and are
/// vacuously satisfied on the deny side, so they never block coverage.
fn allow_is_shadowed_by_deny(allow: &OperationRuleRaw, deny: &DenyRuleRaw) -> bool {
    if deny.args.is_empty() {
        return true;
    }

    allow
        .allowed_args
        .iter()
        .enumerate()
        .all(|(i, allowed_vals)| match deny.args.get(i) {
            Some(denied_vals) => {
                !allowed_vals.iter().any(|v| v == "*")
                    && allowed_vals.iter().all(|v| denied_vals.contains(v))
            }
            None => true,
        })
}

// ---------------------------------------------------------------------------
// Raw Exec deny-match reporting helpers
// ---------------------------------------------------------------------------

/// The first form of a Raw Exec command that a `[raw_exec]` deny pattern
/// matches, as `(form label, matched text)`; `None` if the pattern matches no
/// form.
///
/// The three forms are tried in the same order the deny pass has always
/// evaluated them — joined command, raw argv element, canonical element — so
/// this decides nothing new; it only records *which* disjunct fired, for the
/// Deny reason. Reporting it matters because a canonical element (ADR-0019)
/// need not appear anywhere in argv: attributing a deny to `^--force$` on the
/// argv `["prog", "--force x"]` without saying "canonical element" leaves an
/// operator unable to reconcile the verdict with what they sent.
fn first_raw_deny_match<'a>(
    re: &Regex,
    joined: &'a str,
    argv: &'a [String],
    canonical: &[&'a str],
) -> Option<(&'static str, &'a str)> {
    if re.is_match(joined) {
        return Some(("joined command", joined));
    }
    if let Some(arg) = argv.iter().find(|arg| re.is_match(arg)) {
        return Some(("argv element", arg.as_str()));
    }
    if let Some(elem) = canonical.iter().find(|elem| re.is_match(elem)) {
        return Some(("canonical element", elem));
    }
    None
}

/// Character budget for matched text quoted into a Deny reason.
const REASON_FRAGMENT_BUDGET: usize = 120;

/// Bound a caller-controlled fragment before it is quoted into a Deny reason.
///
/// Used for every caller-controlled string this module quotes: the text a deny
/// pattern matched, and `argv[0]` in the ADR-0019 guard reason. The reason
/// travels as `PolicyVerdict.deciding_rule` and into the audit trail, while the
/// fragment can be arbitrarily long (a `.*` deny against a megabyte of argv
/// matches the whole joined command; the guard reason needs no pattern at all,
/// so an empty Policy still emits it). Truncation keeps the explanation useful
/// without letting a caller choose the size of an audit record.
///
/// Cuts on a **character** boundary via `char_indices` and marks the cut — a
/// byte-index slice (`&text[..BUDGET]`) would panic on multi-byte input, which
/// here is attacker-controlled argv.
fn reason_fragment(text: &str) -> String {
    match text.char_indices().nth(REASON_FRAGMENT_BUDGET) {
        Some((cut, _)) => format!("{}…", &text[..cut]),
        None => text.to_string(),
    }
}

// ---------------------------------------------------------------------------
// Evaluation engine (pure methods on Policy)
// ---------------------------------------------------------------------------

impl Policy {
    /// The SHA-256 fingerprint of the raw Policy file bytes, as a 64-character
    /// lowercase-hex string. Safe to log; the Policy body is not (ADR-0002).
    pub fn fingerprint(&self) -> &str {
        &self.fingerprint
    }

    /// Whether Raw Exec is enabled at all on this Node: `true` iff the
    /// `[raw_exec]` block has at least one allow pattern.
    ///
    /// Report-only / display-only (ADR-0002): this reads the live engine's own
    /// loaded state for the `PolicySnapshot` the Relay displays; it never
    /// evaluates or grants anything itself. An empty (or absent) `allow` list
    /// means Raw Exec is denied-by-default, matching `evaluate_raw_exec`.
    pub fn raw_exec_enabled(&self) -> bool {
        !self.raw_allow.is_empty()
    }

    /// The `[raw_exec] allow` regex patterns, in file order.
    ///
    /// Report-only / display-only (ADR-0002) — for the `PolicySnapshot` the
    /// Relay displays; not used for evaluation (the compiled `Regex` on
    /// `CompiledRe` is what `evaluate_raw_exec` uses).
    pub fn raw_allow_patterns(&self) -> Vec<String> {
        self.raw_allow.iter().map(|c| c.pattern.clone()).collect()
    }

    /// The `[raw_exec] deny` regex patterns, in file order.
    ///
    /// Report-only / display-only (ADR-0002) — see [`Policy::raw_allow_patterns`].
    pub fn raw_deny_patterns(&self) -> Vec<String> {
        self.raw_deny.iter().map(|c| c.pattern.clone()).collect()
    }

    /// The distinct `[[operation]]` allow-rule names, in first-appearance file
    /// order.
    ///
    /// Report-only / display-only (ADR-0002): a raw report of allow-rule
    /// names for the `PolicySnapshot` the Relay displays. `[[deny]]` rule
    /// names are NOT included — this is not a re-evaluation of what is
    /// actually permitted (that would reimplement `Policy::evaluate`,
    /// forbidden by ADR-0011); it mirrors the proto field's own contract.
    pub fn allowed_operations(&self) -> Vec<String> {
        let mut names = Vec::new();
        for op in &self.operations {
            if !names.contains(&op.name) {
                names.push(op.name.clone());
            }
        }
        names
    }

    /// Every `[[operation]]` allow block, in file order.
    ///
    /// Report-only / display-only (ADR-0002): a raw mirror of the Policy file
    /// for the `PolicySnapshot` the Relay displays. Unlike
    /// [`Policy::allowed_operations`], this does NOT dedup by name — a name
    /// may appear in multiple blocks with different `allowed_args`, and every
    /// block is preserved. This is not a re-evaluation of what is actually
    /// permitted (that would reimplement `Policy::evaluate`, forbidden by
    /// ADR-0011); it is a verbatim copy of the loaded rules.
    pub fn operation_allow_rules(&self) -> Vec<OperationAllowRule> {
        self.operations
            .iter()
            .map(|op| OperationAllowRule {
                name: op.name.clone(),
                allowed_args: op.allowed_args.clone(),
            })
            .collect()
    }

    /// Every `[[deny]]` block, in file order.
    ///
    /// Report-only / display-only (ADR-0002): a raw mirror of the Policy
    /// file's deny rules for the `PolicySnapshot` the Relay displays. It
    /// never folds allow and deny together into an effective verdict — that
    /// would reimplement `Policy::evaluate`, forbidden by ADR-0011.
    pub fn deny_rules(&self) -> Vec<OperationDenyRule> {
        self.denies
            .iter()
            .map(|d| OperationDenyRule {
                name: d.name.clone(),
                args: d.args.clone(),
            })
            .collect()
    }

    /// Evaluate whether `operation_name` may run with the given `args`.
    ///
    /// Semantics (ADR-0002):
    /// 1. **Deny pass first** — any matching `[[deny]]` rule wins immediately.
    ///    Vacuous-deny: if an invocation has fewer args than a deny rule lists,
    ///    the unlisted trailing positions are vacuously satisfied (the deny
    ///    still fires). This is the more-restrictive interpretation.
    /// 2. **Allow pass** — a matching `[[operation]]` rule with exact arg count
    ///    and all positions satisfied (or `"*"` wildcard) → `Allow`.
    /// 3. **Deny-by-default** — no rule matched → `Deny{rule: None}`.
    pub fn evaluate(&self, operation_name: &str, args: &[String]) -> Decision {
        // --- 0. Path-argument canonical-form precondition (ADR-0018) --------
        // `file.read`'s `path` is the only path-typed argument today. A path
        // argument must be in strict canonical form, else Deny (fail closed):
        // this makes an exact-string path deny (e.g. `/etc/shadow`) hold
        // against lexical evasions like `/etc/../etc/shadow` or `//etc/shadow`.
        // Pure lexical test, no I/O — does NOT fold case/Unicode (ADR-0018
        // records that as a narrow residual). The executor additionally
        // re-checks the *resolved* target for `/proc`-magic and symlink
        // evasions that are canonical in form (ADR-0018 layer 2).
        if operation_name == operations::FILE_READ {
            if let Some(path) = args.first() {
                if !path_is_canonical(path) {
                    return non_canonical_path_denial(path);
                }
            }
        }

        // --- 1. Deny pass (deny-beats-allow, evaluated first) ---------------
        for deny_rule in &self.denies {
            if deny_rule.name != operation_name {
                continue;
            }

            // An empty `args` list blocks any invocation of the operation.
            if deny_rule.args.is_empty() {
                return Decision::Deny {
                    reason: format!("denied by explicit rule for operation '{operation_name}'"),
                    rule: Some(Rule::OperationDeny {
                        operation: operation_name.to_string(),
                    }),
                };
            }

            // Check each listed position. Positions beyond args.len() are
            // vacuously satisfied (absent arg → deny still fires). This is the
            // more-restrictive deny-beats-allow reading: a deny written for N
            // args also blocks shorter invocations.
            let matches = deny_rule.args.iter().enumerate().all(|(i, denied_vals)| {
                if i >= args.len() {
                    // Vacuously satisfied: argument absent, deny still fires.
                    return true;
                }
                denied_vals.contains(&args[i])
            });

            if matches {
                return Decision::Deny {
                    reason: format!("denied by explicit rule for operation '{operation_name}'"),
                    rule: Some(Rule::OperationDeny {
                        operation: operation_name.to_string(),
                    }),
                };
            }
        }

        // --- 2. Allow pass --------------------------------------------------
        for op_rule in &self.operations {
            if op_rule.name != operation_name {
                continue;
            }

            // Argument count must match exactly.
            if args.len() != op_rule.allowed_args.len() {
                continue;
            }

            // Every position must be in the allowed set or be a wildcard.
            let allowed = op_rule
                .allowed_args
                .iter()
                .enumerate()
                .all(|(i, allowed_vals)| {
                    allowed_vals.iter().any(|s| s == "*") || allowed_vals.contains(&args[i])
                });

            if allowed {
                return Decision::Allow(Rule::OperationAllow {
                    operation: operation_name.to_string(),
                });
            }
        }

        // --- 3. Deny-by-default ---------------------------------------------
        // Neither the deny pass nor the allow pass matched: this is still a
        // plain deny-by-default (`rule: None` in both branches below). The
        // reason text only distinguishes *why* no allow rule matched, for
        // legibility: an allow rule may exist for this operation but not for
        // these particular args (wrong arg count, or an arg value outside
        // the allowed set), versus no allow rule existing for the operation
        // at all. This must never enumerate the allowed values (the
        // PolicySnapshot owns discovery) and must never change the outcome
        // — only the string differs.
        let reason = if self.operations.iter().any(|op| op.name == operation_name) {
            format!(
                "no allow rule matched args {args:?} for operation '{operation_name}' \
                 (allow rules exist for other arguments)"
            )
        } else {
            format!("deny-by-default: no allow rule for operation '{operation_name}'")
        };
        Decision::Deny { reason, rule: None }
    }

    /// Evaluate whether the Raw Exec command `argv` may run.
    ///
    /// Semantics (ADR-0001, ADR-0002, ADR-0019, amended 2026-09-16):
    /// - No shell is invoked; `argv` is the exact argument vector the executor
    ///   will pass to `execv`. The join here is only for regex matching.
    /// - Allow patterns are tested against `argv.join(" ")`, and must match it
    ///   **in FULL** — the daemon enforces this itself (`compile_allow_regex`
    ///   compiles every allow pattern to `\A(?:pattern)\z`), so an author's
    ///   unanchored pattern behaves exactly as an anchored one. This removed
    ///   the substring-match footgun `mod raw_exec_redteam` used to document
    ///   as intended.
    /// - Every argv element must be free of whitespace (`char::is_whitespace`,
    ///   the definition `split_whitespace` below already uses), and `argv[0]`
    ///   must additionally be non-empty. An offending element is Deny **before
    ///   the allow pass runs**, with a reason naming its index — see the
    ///   "whitespace guard" below. Once the guard passes, `argv.join(" ")` is
    ///   injective: with no element containing whitespace, the single space
    ///   the join inserts between elements can never be confused with a
    ///   space *inside* an element, so no two distinct argvs join to the same
    ///   string (an empty non-`argv[0]` element is allowed and simply
    ///   contributes an empty span between its neighbouring separators).
    /// - Deny patterns are tested against three forms; **any** match denies:
    ///   1. the joined command;
    ///   2. each raw `argv[i]` — catches deny patterns that are substrings of
    ///      elements (e.g. `--force`) regardless of position, and is the only
    ///      form that can match a deny written against a *merged* element
    ///      (`^--force x$`);
    ///   3. each **canonical element** — `argv.join(" ")` re-split on
    ///      whitespace (ADR-0019). This closes finding #227: an element-anchored
    ///      deny (`^--force$`) was evaded by merging the denied token into a
    ///      neighbouring element (`"--force x"`), which changes no raw element
    ///      the deny matches and leaves the joined string untouched, so the
    ///      allow still fired.
    ///
    ///   The union is **monotonic in the deny direction**: adding a disjunct to
    ///   a deny pass can only turn Allows into Denies, never the reverse — no
    ///   Policy that denies something today stops denying it. The Deny reason
    ///   names **which** form matched and the text it matched, so an operator
    ///   can reconcile the verdict against the argv they sent (a canonical
    ///   element need not appear in argv at all).
    /// - Order: **deny pass, then the whitespace guard, then the allow pass**.
    ///   The guard runs **after** the deny pass on purpose: a command a deny
    ///   pattern would have attributed keeps that attribution
    ///   (`rule: Some(RawExecDeny)`), and the guard only catches what no deny
    ///   pattern claimed. Both orders Deny, so this is an audit-legibility
    ///   choice, not a semantic one. The guard runs before the allow pass so
    ///   no allow pattern — however written — can approve a command whose
    ///   element boundaries are ambiguous (invariant #1: an argument must
    ///   never change *which* command runs).
    /// - Deny-by-default: no allow match → deny with `rule: None`.
    pub fn evaluate_raw_exec(&self, argv: &[String]) -> Decision {
        // Empty argv is always denied (nothing to run).
        if argv.is_empty() {
            return Decision::Deny {
                reason: "empty argv".to_string(),
                rule: None,
            };
        }

        let joined = argv.join(" ");

        // Canonical elements: the joined command re-split on whitespace. This
        // collapses attacker-chosen element boundaries (merged, padded, empty,
        // or tab/newline/CR-separated) onto one normal form, so an
        // element-anchored deny sees the tokens an operator wrote it against
        // (ADR-0019). Computed once; the deny lists are short.
        let canonical: Vec<&str> = joined.split_whitespace().collect();

        // --- Deny pass (deny-beats-allow, evaluated first) ------------------
        // Test deny patterns against the joined command, each raw element, AND
        // each canonical element. All three are kept: dropping the raw-element
        // pass would lose the only form that matches a deny written against a
        // merged element (`^--force x$`).
        for compiled in &self.raw_deny {
            if let Some((form, matched)) =
                first_raw_deny_match(&compiled.re, &joined, argv, &canonical)
            {
                return Decision::Deny {
                    reason: format!(
                        "raw exec denied by pattern {:?} (matched {form} {:?})",
                        compiled.pattern,
                        reason_fragment(matched)
                    ),
                    rule: Some(Rule::RawExecDeny {
                        pattern: compiled.pattern.clone(),
                    }),
                };
            }
        }

        // --- Whitespace guard (ADR-0019, amended 2026-09-16) -----------------
        // Fail closed: `argv[0]` must be exactly one non-empty program token,
        // and every OTHER element must carry no whitespace at all — an allow
        // pattern now matches the whole joined command, so an element boundary
        // the gate cannot see would let an argument reshape what the pattern
        // is really matching against. Whitespace is the Unicode definition,
        // matching `split_whitespace` above so the guard and the canonical
        // split agree on what a separator is. Runs after the deny pass so an
        // attributable deny keeps its attribution, and before the allow pass
        // so no allow pattern can approve an argv whose element boundaries are
        // ambiguous. Returns the FIRST offending element, by index.
        //
        // `argv[0]` is quoted into its reason (pre-existing, out of scope for
        // this issue) and so is bounded by `reason_fragment` like every other
        // caller-controlled fragment on this path — it is the CHEAPEST reason
        // to provoke, needing no allow and no deny pattern, so even an empty
        // Policy emits it. A later element's reason names only its index and
        // never its value: a Raw Exec argument can carry a secret (e.g. an
        // `Authorization: Bearer <token>` header value), and this reason lands
        // in `deciding_rule`, the Task result and the daemon log, none of
        // which may hold one (ADR-0019; AGENTS.md security posture — never
        // log secrets).
        for (i, elem) in argv.iter().enumerate() {
            if i == 0 {
                if elem.is_empty() || elem.chars().any(char::is_whitespace) {
                    return Decision::Deny {
                        reason: format!(
                            "raw exec argv[0] {:?} is not a single program token (empty or \
                             containing whitespace): the program to execute must be exactly one \
                             argv element (ADR-0019)",
                            reason_fragment(elem)
                        ),
                        rule: None,
                    };
                }
            } else if elem.chars().any(char::is_whitespace) {
                return Decision::Deny {
                    reason: format!(
                        "raw exec argv[{i}] contains whitespace: no Raw Exec argument may carry \
                         whitespace, so the command Policy matched is exactly the argv that \
                         runs; pass such an argument through a Template Operation (ADR-0019)"
                    ),
                    rule: None,
                };
            }
        }

        // --- Allow pass -------------------------------------------------
        // `re` is the full-match regex `compile_allow_regex` compiled
        // (`\A(?:pattern)\z`): matching the joined command against it is
        // already a whole-command test, so the call below needs no change
        // from a substring `is_match` — only what `re` means changed.
        for compiled in &self.raw_allow {
            if compiled.re.is_match(&joined) {
                return Decision::Allow(Rule::RawExecAllow {
                    pattern: compiled.pattern.clone(),
                });
            }
        }

        // --- Deny-by-default ------------------------------------------------
        Decision::Deny {
            reason: "deny-by-default: no raw_exec allow pattern matched".to_string(),
            rule: None,
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    use std::os::unix::fs::PermissionsExt;

    // The fixture is the example policy file checked into the repo. Tests
    // use it directly so the documented examples stay honest.
    const FIXTURE: &str = include_str!("../policy.example.toml");

    fn fixture_policy() -> Policy {
        from_toml_str(FIXTURE).expect("policy.example.toml must parse cleanly")
    }

    fn args(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    // -----------------------------------------------------------------------
    // Temp file helper (mirrors identity.rs pattern)
    // -----------------------------------------------------------------------

    struct TempFile(std::path::PathBuf);

    impl TempFile {
        fn new(label: &str, content: &[u8], mode: u32) -> Self {
            use std::time::{SystemTime, UNIX_EPOCH};
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let path = std::env::temp_dir().join(format!(
                "relay-policy-test-{}-{}-{}",
                label,
                std::process::id(),
                nanos
            ));
            let mut f = std::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(mode)
                .open(&path)
                .unwrap();
            f.write_all(content).unwrap();
            // OpenOptions::mode() is masked by the process umask, so on a
            // runner with umask 022 a requested 0o664 lands as 0o644 and the
            // group/world-writable rejection tests would spuriously pass the
            // file. chmod is not umask-masked, so force the exact mode here.
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
            TempFile(path)
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TempFile {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
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
        let decision =
            policy.evaluate_raw_exec(&args(&["/usr/bin/systemctl", "status", "rm.service"]));
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
        let policy =
            from_toml_str("[raw_exec]\nallow = [\"/bin/echo\"]\n").expect("policy must parse");
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
    #[test]
    fn loader_rejects_group_or_world_writable() {
        for (mode, bit) in [
            (0o664_u32, "group-writable, other-write clear"),
            (0o646_u32, "world-writable, group-write clear"),
            (0o666_u32, "both write bits"),
        ] {
            let tmp = TempFile::new("writable", FIXTURE.as_bytes(), mode);
            let result = load_policy(tmp.path());
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

    #[test]
    fn loader_accepts_secure_modes() {
        // Secure modes: no group- or world-write bit; owned by the test
        // runner's euid (exercises the uid == geteuid() branch in the loader).
        for mode in [0o600_u32, 0o644] {
            let tmp = TempFile::new("secure", FIXTURE.as_bytes(), mode);
            let result = load_policy(tmp.path());
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
        let tmp = TempFile::new("fingerprint-eq", FIXTURE.as_bytes(), 0o600);
        let file_policy = load_policy(tmp.path()).expect("secure-mode fixture must load");
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
            findings: vec![],
        };
        assert!(parse_err.has_errors());
        assert!(!parse_err.has_warnings());
    }
}

// ---------------------------------------------------------------------------
// Raw Exec red-team harness (issue #214)
// ---------------------------------------------------------------------------

/// Adversarial, table-driven red-team suite against `evaluate_raw_exec`'s
/// matching model: regex anchoring, argv-join ambiguity, and the deny/allow
/// asymmetry (deny is tested against the joined command, any raw element, OR
/// any canonical element; allow is now tested against the WHOLE joined
/// command — ADR-0019, amended 2026-09-16 — and every argv element is guarded
/// against whitespace before the allow pass runs at all).
///
/// Test-only: this module never touches `evaluate_raw_exec`, `from_toml_str`,
/// `compile_regexes`, the loader, or the lint code above. It asserts current
/// behavior (green rows, some of which document accepted footguns rather than
/// bugs). The one genuine deny-evasion bypass it found (#227) was committed as
/// a standalone `#[ignore]`d test while the fix was an open ADR-gated decision;
/// that decision is ADR-0019 (canonical-element deny matching + the argv[0]
/// whitespace guard), so the test is now enabled and pins the fix, with the
/// neighbouring shapes added as Axis 7 rows. The #214 "documented-intended"
/// unanchored-allow footgun this module used to pin as accepted was removed
/// outright by the 2026-09-16 amendment: an unanchored allow pattern now
/// matches the whole command, so it can no longer admit a hostile argv merely
/// because the pattern text appears somewhere inside the joined string.
///
/// `redteam_cases()` is the single extension point later red-team issues
/// (e.g. argv-smuggling/encoding) append rows to.
///
/// Issue #223 appended three further axes on top of #214's anchoring/join
/// baseline above: interpreter smuggling (argv[0] / permitted wrapper),
/// whitespace/control bytes against the space-join, and encoding/inert-data
/// (regex-as-if-shell footguns). That red-team pass found NO new genuine
/// bypass — every appended row is a green regression, either fail-closed
/// (safe) or a documented operator footgun where the engine matches exactly
/// what the pattern literally says. The one tracked bypass against
/// `evaluate_raw_exec` was #227 (element-merge deny evasion), fixed under
/// ADR-0019 and pinned by the Axis 7 rows and
/// `deny_element_merge_closed_by_canonical_elements` below; #236 is a
/// file.read (structured-Operation, `evaluate()`) finding covered by the
/// second table further below in this module — it is unrelated to the Raw
/// Exec argv gate this section's `redteam_cases()` covers. No `#[ignore]`d
/// bypass remains in either table.
#[cfg(test)]
mod raw_exec_redteam {
    use super::*;

    /// Build an argv `Vec<String>` from string-literal elements. Mirrors the
    /// `args` helper in `mod tests`, renamed to Raw Exec vocabulary.
    fn argv(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    /// Coarse red-team classification of a Raw Exec `Decision`: does the
    /// command run, is it denied by a specific rule, refused by the ADR-0019
    /// `argv[0]` guard, or denied by default. Deliberately coarser than
    /// `Decision` itself — the exact `reason` string is owned by the
    /// golden-reason tests in `mod tests`, and on this path by
    /// `argv0_refused_unless_single_program_token` and
    /// `deny_reason_names_the_matched_form_and_text` below, not by this
    /// harness.
    #[derive(Debug, Clone, Copy)]
    enum Expect {
        /// `Decision::Allow(_)`.
        Allow,
        /// `Decision::Deny` with a specific `Rule::RawExecDeny` attributed.
        DenyByPattern,
        /// `Decision::Deny` with `rule: None` from the ADR-0019 whitespace
        /// guard: `argv[0]` empty or containing whitespace, or ANY other
        /// element containing whitespace (amended 2026-09-16). Structurally
        /// identical to `DenyByDefault` in `Decision`, so the table
        /// distinguishes the two by the reason starting with `"raw exec
        /// argv["`.
        DenyByGuard,
        /// `Decision::Deny` with `rule: None` because no allow pattern
        /// matched — and specifically *not* the whitespace guard.
        DenyByDefault,
    }

    /// One red-team case: a self-contained Policy fixture, an argv, and the
    /// expected coarse decision. `redteam_cases()` is the extension point for
    /// follow-up red-team issues to append rows to.
    struct Case {
        name: &'static str,
        policy_toml: &'static str,
        argv: &'static [&'static str],
        expect: Expect,
        note: &'static str,
    }

    fn redteam_cases() -> Vec<Case> {
        vec![
            // --- Axis 1: regex anchoring / unanchored substring -------------
            Case {
                name: "anchored_allow_rejects_suffix_injection",
                policy_toml: "[raw_exec]\nallow = [\"^/usr/bin/systemctl (status|restart) [A-Za-z0-9@._-]+$\"]\n",
                argv: &["/usr/bin/systemctl", "restart", "nginx", ";", "touch", "/tmp/pwn"],
                expect: Expect::DenyByDefault,
                note: "trailing tokens appended after the injected command break the anchored $, so the anchored allow correctly refuses the suffix-injection attempt",
            },
            Case {
                name: "anchored_allow_rejects_prefix_injection",
                policy_toml: "[raw_exec]\nallow = [\"^/usr/bin/systemctl (status|restart) [A-Za-z0-9@._-]+$\"]\n",
                argv: &["/bin/sh", "-c", "/usr/bin/systemctl restart nginx"],
                expect: Expect::DenyByGuard,
                note: "argv[2] \"/usr/bin/systemctl restart nginx\" carries whitespace, so the ADR-0019 whitespace guard now refuses this before any allow pattern runs; the anchored-^ coverage this row used to pin moved to anchored_allow_blocks_same_foreign_argv0 below, whose argv has no whitespace and so reaches the (now full-match) allow pass",
            },
            Case {
                name: "unanchored_allow_full_match_denies_foreign_argv0",
                policy_toml: "[raw_exec]\nallow = [\"/usr/bin/systemctl (status|restart) nginx\"]\n",
                argv: &["/bin/rm", "-rf", "/var/log", "&&", "/usr/bin/systemctl", "restart", "nginx"],
                expect: Expect::DenyByDefault,
                note: "the #214 unanchored-substring footgun this row used to document as intended is gone: an allow pattern now matches the WHOLE joined command (ADR-0019, amended 2026-09-16), so a pattern that merely APPEARS as a substring of the joined command no longer admits the hostile argv whose real argv[0] is /bin/rm",
            },
            Case {
                name: "anchored_allow_blocks_same_foreign_argv0",
                policy_toml: "[raw_exec]\nallow = [\"^/usr/bin/systemctl (status|restart) [A-Za-z0-9@._-]+$\"]\n",
                argv: &["/bin/rm", "-rf", "/var/log", "&&", "/usr/bin/systemctl", "restart", "nginx"],
                expect: Expect::DenyByDefault,
                note: "paired contrast with unanchored_allow_full_match_denies_foreign_argv0: the identical hostile argv is refused whether the allow pattern is anchored or not, since full-match is now enforced either way",
            },
            // --- Axis 2: argv-join ambiguity ---------------------------------
            Case {
                name: "join_collapse_two_args_same_decision_two_elements",
                policy_toml: "[raw_exec]\nallow = [\"^/usr/bin/systemctl (status|restart) [A-Za-z0-9@._-]+$\"]\n",
                argv: &["/usr/bin/systemctl", "restart", "nginx"],
                expect: Expect::Allow,
                note: "the intended three-element shape; paired with join_collapse_two_args_same_decision_merged_element, which used to get the identical decision from the same joined string but is now refused by the ADR-0019 whitespace guard before the two argvs can be confused (R10 closed)",
            },
            Case {
                name: "join_collapse_two_args_same_decision_merged_element",
                policy_toml: "[raw_exec]\nallow = [\"^/usr/bin/systemctl (status|restart) [A-Za-z0-9@._-]+$\"]\n",
                argv: &["/usr/bin/systemctl", "restart nginx"],
                expect: Expect::DenyByGuard,
                note: "argv[1] \"restart nginx\" carries whitespace, so the ADR-0019 whitespace guard (amended 2026-09-16) refuses this before the allow pass ever runs — no two distinct argvs can share a joined form anymore (R10 closed)",
            },
            Case {
                name: "join_single_element_whole_command",
                policy_toml: "[raw_exec]\nallow = [\"^/usr/bin/systemctl (status|restart) [A-Za-z0-9@._-]+$\"]\n",
                argv: &["/usr/bin/systemctl restart nginx"],
                expect: Expect::DenyByGuard,
                note: "was the sharpest 'what the gate cannot see' row under #214 (a single argv element containing the whole command joins to the same string and was ALLOWED, though execv's real target is a literal filename containing spaces); the ADR-0019 argv[0]-whitespace guard now refuses it before any pattern is consulted — argv[0] is the program, and the joined form must not be able to disguise which program that is (invariant #1). Deny carries rule: None (a fail-closed precondition, not a matched deny pattern)",
            },
            // --- Axis 3: deny/allow asymmetry --------------------------------
            Case {
                name: "deny_matches_joined_only",
                policy_toml: "[raw_exec]\nallow = [\"^systemctl .+$\"]\ndeny = [\"restart nginx\"]\n",
                argv: &["systemctl", "restart", "nginx"],
                expect: Expect::DenyByPattern,
                note: "duplicates the existing raw_exec_deny_matches_joined_string_only test in mod tests (policy.rs:1121-1143); kept here only to seed the self-contained extensible table with the joined disjunct of the deny pass",
            },
            Case {
                name: "deny_matches_per_element_only_beats_allow",
                policy_toml: "[raw_exec]\nallow = [\"^systemctl restart nginx --force$\"]\ndeny = [\"^--force$\"]\n",
                argv: &["systemctl", "restart", "nginx", "--force"],
                expect: Expect::DenyByPattern,
                note: "the allow pattern is anchored to match this exact joined command, so the allow pass alone would let it through, but the deny pass runs first (deny-beats-allow) and the anchored deny ^--force$ fires on the --force argv element even though it does not match the joined string; exercises the per-element disjunct of the deny pass",
            },
            Case {
                name: "allow_joined_only_is_fail_closed",
                policy_toml: "[raw_exec]\nallow = [\"^nginx$\"]\n",
                argv: &["systemctl", "restart", "nginx"],
                expect: Expect::DenyByDefault,
                note: "key red-team result: the deny/allow asymmetry cannot widen allow — an allow pattern that matches only an individual argv element ('nginx') never fires because the allow pass tests the joined string only (policy.rs:765-771); the gate stays fail-closed",
            },
            // --- Axis 4: interpreter smuggling (argv[0] / permitted wrapper) ---
            Case {
                name: "interp_anchored_allow_rejects_shell_wrapper_argv0",
                policy_toml: "[raw_exec]\nallow = [\"^/usr/bin/ansible-playbook /etc/ansible/site.yml$\"]\n",
                argv: &["/bin/sh", "-c", "/usr/bin/ansible-playbook /etc/ansible/site.yml"],
                expect: Expect::DenyByGuard,
                note: "interpreter-flavored sibling of anchored_allow_rejects_prefix_injection: argv[2] carries whitespace, so the ADR-0019 whitespace guard refuses this before the allow pass ever runs",
            },
            Case {
                name: "interp_unanchored_allow_full_match_denies_shell_argv0",
                policy_toml: "[raw_exec]\nallow = [\"/usr/bin/ansible-playbook\"]\n",
                argv: &["/bin/sh", "-c", "/usr/bin/ansible-playbook"],
                expect: Expect::DenyByDefault,
                note: "no argv element carries whitespace, so this row isolates full-match rather than the guard: the allow pattern must now match the WHOLE joined command (ADR-0019, amended 2026-09-16), and \"/usr/bin/ansible-playbook\" alone does not equal \"/bin/sh -c /usr/bin/ansible-playbook\" — the #214 substring-admits-a-shell-argv0 footgun this row used to pin as intended is gone",
            },
            Case {
                name: "interp_shell_c_script_with_spaces_refused_by_guard",
                policy_toml: "[raw_exec]\nallow = [\"/usr/bin/ansible-playbook\"]\n",
                argv: &["/bin/sh", "-c", "/usr/bin/ansible-playbook --check"],
                expect: Expect::DenyByGuard,
                note: "the pre-amendment argv for interp_unanchored_allow_full_match_denies_shell_argv0: argv[2] \"/usr/bin/ansible-playbook --check\" carries whitespace, so the ADR-0019 guard refuses it before the (now full-match) allow pass would even get to say no",
            },
            Case {
                name: "interp_env_wrapper_full_anchor_allows_intended",
                policy_toml: "[raw_exec]\nallow = [\"^/usr/bin/env python3 /opt/deploy/run.py$\"]\n",
                argv: &["/usr/bin/env", "python3", "/opt/deploy/run.py"],
                expect: Expect::Allow,
                note: "documented-intended baseline: the intended env-wrapped invocation, fully anchored end-to-end, is allowed; pairs with interp_env_wrapper_argv0_anchor_admits_arbitrary_interpreter to show that anchoring the WHOLE command (not just argv[0]) is what makes this safe",
            },
            Case {
                name: "interp_env_wrapper_argv0_anchor_admits_arbitrary_interpreter",
                policy_toml: "[raw_exec]\nallow = [\"^/usr/bin/env .*$\"]\n",
                argv: &["/usr/bin/env", "bash", "-c", "id"],
                expect: Expect::Allow,
                note: "KEY interpreter-smuggling result, materially higher severity than the others, and it SURVIVES full-match: even a pattern anchored end-to-end (^...$) is INSUFFICIENT when argv[0] is an exec-wrapper (/usr/bin/env) and the author writes a trailing .*, because env re-dispatches to argv[1] and thus reaches bash — a plausible, seemingly-careful anchored allow still yields arbitrary command execution; not a code bug (the engine matched the pattern exactly; the regex engine has no model of which binaries re-dispatch, and denylisting them would be an ADR-gated binary-semantics change), so no finding is filed, but operator guidance is: anchor the WHOLE command for wrapper interpreters (env, xargs, nice, timeout, sudo, nohup, setsid, ...), never just argv[0]+space, and never a trailing .*",
            },
            Case {
                name: "interp_env_wrapper_prefix_only_allow_now_denied",
                policy_toml: "[raw_exec]\nallow = [\"^/usr/bin/env \"]\n",
                argv: &["/usr/bin/env", "bash", "-c", "id"],
                expect: Expect::DenyByDefault,
                note: "the OLD R4 pattern (anchored at argv[0]+space only, no trailing .* and no closing $): under full-match this no longer admits anything, since \"^/usr/bin/env \" cannot match the whole command \"/usr/bin/env bash -c id\" end-to-end. Contrast interp_env_wrapper_argv0_anchor_admits_arbitrary_interpreter, whose trailing .* is what keeps the re-dispatch footgun alive under full-match",
            },
            // --- Axis 5: whitespace / control bytes vs the space-join (policy.rs:813) ---
            Case {
                name: "ctl_tab_in_arg_breaks_anchored_class_allow",
                policy_toml: "[raw_exec]\nallow = [\"^/usr/bin/systemctl (status|restart) [A-Za-z0-9@._-]+$\"]\n",
                argv: &["/usr/bin/systemctl", "restart", "nginx\tevil"],
                expect: Expect::DenyByGuard,
                note: "argv[2] \"nginx<TAB>evil\" carries whitespace, so the ADR-0019 whitespace guard refuses this before any allow pattern runs; the original allow-side pin (the character class rejects the tab) is now moot, since the guard fires first",
            },
            Case {
                name: "ctl_cr_in_arg_breaks_anchored_class_allow",
                policy_toml: "[raw_exec]\nallow = [\"^/usr/bin/systemctl (status|restart) [A-Za-z0-9@._-]+$\"]\n",
                argv: &["/usr/bin/systemctl", "restart", "nginx\revil"],
                expect: Expect::DenyByGuard,
                note: "same mechanism as ctl_tab_in_arg_breaks_anchored_class_allow with an embedded carriage return instead of a tab: the ADR-0019 whitespace guard now refuses this before any allow pattern runs, so the original allow-side pin is moot",
            },
            Case {
                name: "ctl_nul_in_arg_breaks_anchored_class_allow",
                policy_toml: "[raw_exec]\nallow = [\"^/usr/bin/systemctl (status|restart) [A-Za-z0-9@._-]+$\"]\n",
                argv: &["/usr/bin/systemctl", "restart", "nginx\0"],
                expect: Expect::DenyByDefault,
                note: "NUL is not Unicode whitespace, so the ADR-0019 guard does not fire; an embedded NUL still cannot satisfy [class]$ at the gate, so this fails closed too — independently, any NUL anywhere in argv also fails closed at execv, pinned end-to-end by raw_exec.rs::nul_in_argv_fails_closed_at_executor",
            },
            Case {
                name: "ctl_newline_in_arg_dot_does_not_cross",
                policy_toml: "[raw_exec]\nallow = [\"^/usr/bin/systemctl restart .+$\"]\n",
                argv: &["/usr/bin/systemctl", "restart", "nginx\n; rm -rf /"],
                expect: Expect::DenyByGuard,
                note: "argv[2] carries an embedded newline, so the ADR-0019 whitespace guard refuses this before any allow pattern runs; the original allow-side pin (RE2-style `.` not crossing a newline) is now moot, since the guard fires first",
            },
            Case {
                name: "ctl_trailing_newline_defeats_dollar_anchor",
                policy_toml: "[raw_exec]\nallow = [\"^/usr/bin/systemctl restart nginx$\"]\n",
                argv: &["/usr/bin/systemctl", "restart", "nginx\n"],
                expect: Expect::DenyByGuard,
                note: "argv[2] \"nginx\\n\" carries a trailing newline, so the ADR-0019 whitespace guard refuses this before any allow pattern runs; the original allow-side pin (the non-multiline $ semantics) is now moot, since the guard fires first",
            },
            Case {
                name: "ctl_slash_s_matches_unicode_nbsp",
                policy_toml: "[raw_exec]\nallow = ['(?s).*']\ndeny = ['y\\sz']\n",
                argv: &["x", "y\u{00A0}z"],
                expect: Expect::DenyByPattern,
                note: "semantics pin, moved to the DENY side: an NBSP-bearing element can no longer reach the allow pass at all (the ADR-0019 guard would refuse it first), so the \\s-matches-U+00A0-NBSP pin now lives on a deny, which the deny pass evaluates before the guard ever runs. Unicode-mode \\s (the regex crate default) matches NBSP in addition to tab/CR/LF; operator relevance: a \\s-based deny DOES catch NBSP used as a separator",
            },
            Case {
                name: "ctl_slash_s_does_not_match_nul",
                policy_toml: "[raw_exec]\nallow = ['^x y\\sz$']\n",
                argv: &["x", "y\0z"],
                expect: Expect::DenyByDefault,
                note: "semantics pin, paired with ctl_slash_s_matches_unicode_nbsp (a different fixture now — that row moved its \\s pin to a deny since an NBSP-bearing element can no longer reach the allow pass): \\s does NOT match NUL, so an operator writing \\s to catch 'any separator' catches NBSP/tab/CR/LF but not NUL; NUL is likewise not Unicode whitespace, so it neither trips the ADR-0019 guard nor splits a canonical element. Independently inert either way, since a NUL-bearing argv fails closed at execv regardless (executor test). NOT a new finding",
            },
            Case {
                name: "ctl_join_emits_ascii_space_matched_by_slash_s",
                policy_toml: "[raw_exec]\nallow = ['^/bin/rm -rf /$']\ndeny = ['rm\\s+-rf']\n",
                argv: &["/bin/rm", "-rf", "/"],
                expect: Expect::DenyByPattern,
                note: "positive pin: the space-join always emits ASCII 0x20 between elements (attacker-uncontrolled at the token boundary), which \\s+ matches, so a cross-token \\s-based deny fires on this canonical argv (deny-beats-allow); NUL-in-argv is independently inert regardless of any deny/allow outcome — any NUL anywhere in argv fails closed at execv, pinned by raw_exec.rs::nul_in_argv_fails_closed_at_executor, so it never reaches execution",
            },
            Case {
                name: "ctl_homoglyph_fails_anchored_ascii_allow_closed",
                policy_toml: "[raw_exec]\nallow = [\"^/usr/bin/systemctl restart nginx$\"]\n",
                argv: &["/usr/bin/systemctl", "restart", "ng\u{0456}nx"],
                expect: Expect::DenyByDefault,
                note: "a homoglyph in \"ng\u{0456}nx\" (Cyrillic U+0456, not Latin 'i') cannot satisfy an ASCII-literal allow — different bytes, no match, fail-closed — and cannot reach the real nginx unit either, since it is a different byte sequence; homoglyphs are inert to the argv gate, they never widen an allow",
            },
            // --- Axis 6: encoding / inert data + regex-as-if-shell footguns ---
            Case {
                name: "enc_dollar_paren_deny_matches_literal_inert",
                policy_toml: "[raw_exec]\nallow = ['^/bin/echo .+$']\ndeny = ['\\$\\(']\n",
                argv: &["/bin/echo", "$(id)"],
                expect: Expect::DenyByPattern,
                note: "regex-as-if-shell footgun: an operator writes deny = \\$\\( believing it 'blocks command substitution'; under argv exec there is NO shell (ADR-0001), so \"$(id)\" is inert literal data to /bin/echo — there was never a substitution to block. The deny DOES fire, on the literal characters, giving false confidence AND a false positive (it would also block a legitimate command that merely prints \"$(\"). Fold into #225. NOT a code bug",
            },
            Case {
                name: "enc_ampersand_deny_matches_literal_inert",
                policy_toml: "[raw_exec]\nallow = [\"^/bin/echo .+$\"]\ndeny = [\"&&\"]\n",
                argv: &["/bin/echo", "&&", "id"],
                expect: Expect::DenyByPattern,
                note: "regex-as-if-shell footgun, same class as enc_dollar_paren_deny_matches_literal_inert: deny = && ('block chaining') fires on the literal \"&&\" element, but /bin/echo receives \"&&\" and \"id\" as two literal, inert arguments — no shell chaining occurs. False-confidence footgun for &&/|/; deny patterns. Fold into #225. NOT a code bug",
            },
            Case {
                name: "enc_percent_encoding_is_literal_data",
                policy_toml: "[raw_exec]\nallow = [\"^/bin/echo .+$\"]\n",
                argv: &["/bin/echo", "%2fetc%2fshadow"],
                expect: Expect::Allow,
                note: "argv-is-data pin: percent-encoding is never decoded by the argv gate or the executor; \"%2fetc%2fshadow\" is literal bytes, not \"/etc/shadow\". Percent-encoding buys an attacker nothing at the argv gate — there is no decoding layer. A deny listing \"/etc/shadow\" would not match this either; expected, they are different strings, and Raw Exec does no decoding (any decoding is the target program's business, out of scope)",
            },
            Case {
                name: "enc_backslash_escapes_are_literal_data",
                policy_toml: "[raw_exec]\nallow = [\"^/bin/echo .+$\"]\n",
                argv: &["/bin/echo", "\\x2f\\t"],
                expect: Expect::Allow,
                note: "argv-is-data pin: backslash escape sequences are NOT C-unescaped anywhere on this path; argv carries the literal backslash bytes (\\x2f\\t is the 6 literal characters backslash-x-2-f-backslash-t, not a slash and a tab). `.+` matches them (no newline present), so the anchored allow admits it — pins that backslash-encoding is inert data",
            },
            Case {
                name: "enc_ifs_token_is_literal_not_expanded",
                policy_toml: "[raw_exec]\nallow = [\"^/bin/echo .+$\"]\n",
                argv: &["/bin/echo", "$IFS"],
                expect: Expect::Allow,
                note: "argv-is-data pin: $IFS (like $HOME, backticks) is a literal argv token to the gate; there is no shell, so no variable expansion or word-splitting ever happens (ADR-0001). The gate sees the literal string \"$IFS\"; the executor passes it literally too, re-pinned end-to-end by raw_exec.rs::argv_is_data_not_shell_expanded",
            },
            // --- Axis 7: argv canonicalization before the deny pass (#227 / ADR-0019) ---
            //
            // Every row below uses the #227 fixture: an anchored allow written
            // for the merged joined command plus the most precise deny an
            // operator can write for the flag (`^--force$`). Before ADR-0019
            // each merge/padding shape ALLOWED; the canonical-element disjunct
            // (joined re-split on whitespace) denies them all.
            Case {
                name: "canon_element_merge_denied",
                policy_toml: "[raw_exec]\nallow = [\"^systemctl restart nginx --force x$\"]\ndeny = [\"^--force$\"]\n",
                argv: &["systemctl", "restart", "nginx", "--force x"],
                expect: Expect::DenyByPattern,
                note: "the #227 reproduction, table form: merging the denied token into the next element leaves the joined string (and so the allow) intact and defeats the raw-element deny, but the canonical elements are [systemctl, restart, nginx, --force, x] and ^--force$ fires on --force (ADR-0019)",
            },
            Case {
                name: "canon_unmerged_form_still_denied",
                policy_toml: "[raw_exec]\nallow = [\"^systemctl restart nginx --force x$\"]\ndeny = [\"^--force$\"]\n",
                argv: &["systemctl", "restart", "nginx", "--force", "x"],
                expect: Expect::DenyByPattern,
                note: "control for canon_element_merge_denied: the honest, unmerged argv was denied before ADR-0019 (raw-element pass) and still is — monotonic in the deny direction, nothing that denied stops denying",
            },
            Case {
                name: "canon_merged_form_deny_still_fires_via_raw_element",
                policy_toml: "[raw_exec]\nallow = [\"^systemctl restart nginx --force x$\"]\ndeny = [\"^--force x$\"]\n",
                argv: &["systemctl", "restart", "nginx", "--force x"],
                expect: Expect::DenyByPattern,
                note: "proves the RAW-element pass is still live and was not replaced by the canonical one: a deny anchored to the merged element (^--force x$) matches neither the joined command (anchors) nor any canonical element ([--force], [x]) — only the raw element \"--force x\". Dropping the raw pass would silently lose this deny path",
            },
            Case {
                name: "canon_merged_form_deny_does_not_cover_unmerged_argv",
                policy_toml: "[raw_exec]\nallow = [\"^systemctl restart nginx --force x$\"]\ndeny = [\"^--force x$\"]\n",
                argv: &["systemctl", "restart", "nginx", "--force", "x"],
                expect: Expect::Allow,
                note: "honest limit, paired with canon_merged_form_deny_still_fires_via_raw_element: a deny anchored to a merged element is NARROW — it does not cover the unmerged argv, whose elements are \"--force\" and \"x\". Not a regression and not a bypass of anything ADR-0019 claims: the correct deny for this operator is ^--force$, which after ADR-0019 covers both shapes",
            },
            Case {
                name: "canon_leading_trailing_whitespace_merge_denied",
                policy_toml: "[raw_exec]\nallow = [\"^systemctl restart nginx .*$\"]\ndeny = [\"^--force$\"]\n",
                argv: &["systemctl", "restart", "nginx", "  --force  "],
                expect: Expect::DenyByPattern,
                note: "padding the denied token with leading/trailing whitespace inside one element does not survive canonicalization — split_whitespace discards leading and trailing runs, so the canonical element is exactly \"--force\" and the anchored deny fires",
            },
            Case {
                name: "canon_repeated_whitespace_merge_denied",
                policy_toml: "[raw_exec]\nallow = [\"^systemctl restart nginx .*$\"]\ndeny = [\"^--force$\"]\n",
                argv: &["systemctl", "restart", "nginx", "--force     x"],
                expect: Expect::DenyByPattern,
                note: "a repeated-whitespace run between the merged tokens collapses under split_whitespace (runs are one separator, no empty canonical elements), so the deny still sees a bare \"--force\"",
            },
            Case {
                name: "canon_tab_separator_merge_denied",
                policy_toml: "[raw_exec]\nallow = [\"^systemctl restart nginx .*$\"]\ndeny = [\"^--force$\"]\n",
                argv: &["systemctl", "restart", "nginx", "--force\tx"],
                expect: Expect::DenyByPattern,
                note: "TAB is Unicode whitespace, so it is a canonical-element separator even though the space-join never emits one: the merged element splits into [--force, x] and the anchored deny fires. Contrast ctl_tab_in_arg_breaks_anchored_class_allow, where a tab defeats an anchored ALLOW — canonicalization is deny-side only",
            },
            Case {
                name: "canon_newline_separator_merge_denied",
                policy_toml: "[raw_exec]\nallow = [\"^systemctl restart nginx (.|\\n)*$\"]\ndeny = [\"^--force$\"]\n",
                argv: &["systemctl", "restart", "nginx", "--force\nx"],
                expect: Expect::DenyByPattern,
                note: "LF likewise splits the merged element. The allow here spells (.|\\n)* because RE2-style `.` does not cross a newline (ctl_newline_in_arg_dot_does_not_cross) — the point of the row is that the deny fires even where an allow WOULD have matched, so the allow must genuinely match",
            },
            Case {
                name: "canon_cr_separator_merge_denied",
                policy_toml: "[raw_exec]\nallow = [\"^systemctl restart nginx .*$\"]\ndeny = [\"^--force$\"]\n",
                argv: &["systemctl", "restart", "nginx", "--force\rx"],
                expect: Expect::DenyByPattern,
                note: "CR splits the merged element too (Unicode whitespace), so a CR-separated merge is denied like the space- and tab-separated forms",
            },
            Case {
                name: "canon_nbsp_separator_merge_denied",
                policy_toml: "[raw_exec]\nallow = [\"^systemctl restart nginx .*$\"]\ndeny = [\"^--force$\"]\n",
                argv: &["systemctl", "restart", "nginx", "--force\u{00A0}x"],
                expect: Expect::DenyByPattern,
                note: "U+00A0 NBSP is Unicode whitespace, so split_whitespace treats it as a separator and the merge is denied; consistent with ctl_slash_s_matches_unicode_nbsp (the same Unicode notion of whitespace the regex crate's \\s uses) and with the ADR-0019 argv[0] guard, which is written against the same predicate",
            },
            Case {
                name: "canon_empty_elements_do_not_perturb_split",
                policy_toml: "[raw_exec]\nallow = [\"^systemctl .*$\"]\ndeny = [\"^--force$\"]\n",
                argv: &["systemctl", "", "restart", "nginx", "", "--force x"],
                expect: Expect::DenyByPattern,
                note: "empty argv elements inject extra spaces into the join (\"systemctl  restart nginx  --force x\") but produce NO empty canonical elements (split_whitespace skips runs), so a merged token surrounded by empty elements is still canonicalized to a bare \"--force\" and denied",
            },
            Case {
                name: "canon_three_token_merge_denied",
                policy_toml: "[raw_exec]\nallow = [\"^systemctl restart nginx --force x$\"]\ndeny = [\"^--force$\"]\n",
                argv: &["systemctl", "restart nginx --force x"],
                expect: Expect::DenyByPattern,
                note: "the whole tail collapsed into ONE element (four tokens merged): the joined string is unchanged so the anchored allow still matches, but canonicalization recovers every token and the anchored deny fires. argv[0] is clean here, so this is the canonical pass doing the work, not the ADR-0019 argv[0] guard",
            },
            Case {
                name: "guard_argv0_whitespace_refused_though_joined_form_allows",
                policy_toml: "[raw_exec]\nallow = [\"^systemctl restart nginx$\"]\n",
                argv: &["systemctl restart", "nginx"],
                expect: Expect::DenyByGuard,
                note: "ADR-0019 companion guard: the joined form \"systemctl restart nginx\" matches the anchored allow, but argv[0] is the literal two-word string \"systemctl restart\" — NOT the program the operator authorized (execv would look for a file of that name, which is ENOENT unless someone planted one). Refused with rule: None and a reason naming argv[0]. Pairs with guard_argv0_clean_same_joined_form_allowed",
            },
            Case {
                name: "guard_argv0_clean_same_joined_form_allowed",
                policy_toml: "[raw_exec]\nallow = [\"^systemctl restart nginx$\"]\n",
                argv: &["systemctl", "restart", "nginx"],
                expect: Expect::Allow,
                note: "control for guard_argv0_whitespace_refused_though_joined_form_allows: the identical joined string with a single-token argv[0] is still allowed — the guard rejects only the ambiguity about WHICH program runs, it does not narrow legitimate Raw Exec whose argv[0] is a single token",
            },
            Case {
                name: "guard_empty_argv0_refused",
                policy_toml: "[raw_exec]\nallow = [\"^ nginx$\"]\n",
                argv: &["", "nginx"],
                expect: Expect::DenyByGuard,
                note: "an EMPTY argv[0] is not a program either: the join emits a leading space so a (peculiar) allow can match, but execv would get \"\" and fail with ENOENT. Refusing it at the gate removes a 'Policy said yes' audit record for a command that can never run — same guard, same monotonic direction",
            },
            // --- ADR-0019 (amended 2026-09-16): the guard now covers EVERY
            // element, not just argv[0]. `allow = ['(?s).*']` and no deny, so
            // only the guard itself can produce a Deny on these rows.
            Case {
                name: "guard_tab_in_later_element_refused",
                policy_toml: "[raw_exec]\nallow = ['(?s).*']\n",
                argv: &["systemctl", "restart", "nginx\tx"],
                expect: Expect::DenyByGuard,
                note: "a tab in a NON-argv[0] element is refused by the amended guard before the (fully permissive) allow pattern is ever consulted",
            },
            Case {
                name: "guard_nbsp_in_later_element_refused",
                policy_toml: "[raw_exec]\nallow = ['(?s).*']\n",
                argv: &["systemctl", "restart", "nginx\u{00A0}x"],
                expect: Expect::DenyByGuard,
                note: "U+00A0 NBSP is Unicode whitespace, so a NON-argv[0] element carrying it is refused by the amended guard, same as a tab or newline",
            },
            Case {
                name: "guard_newline_in_later_element_refused",
                policy_toml: "[raw_exec]\nallow = ['(?s).*']\n",
                argv: &["systemctl", "restart", "nginx\nx"],
                expect: Expect::DenyByGuard,
                note: "a newline in a NON-argv[0] element is refused by the amended guard, even though the permissive `(?s).*` allow would otherwise match it (dot-matches-newline) — the guard runs before the allow pass",
            },
            Case {
                name: "guard_empty_later_element_allowed",
                policy_toml: "[raw_exec]\nallow = ['(?s).*']\n",
                argv: &["systemctl", "", "restart"],
                expect: Expect::Allow,
                note: "an empty element past argv[0] is NOT refused (only emptiness AT argv[0] is): the guard only checks non-argv[0] elements for whitespace, and an empty string contains none",
            },
            Case {
                name: "guard_runs_after_deny_pass_so_attribution_is_kept",
                policy_toml: "[raw_exec]\nallow = [\".*\"]\ndeny = [\"^--force$\"]\n",
                argv: &["prog x", "--force"],
                expect: Expect::DenyByPattern,
                note: "ordering pin: argv[0] here trips the guard AND a deny pattern matches. The deny pass runs first, so the Deny is attributed to ^--force$ (rule: Some) rather than collapsing to the guard's rule: None — same outcome either way, but the operator keeps the more specific explanation. Reordering the guard ahead of the deny pass flips this row to DenyByGuard",
            },
        ]
    }

    #[test]
    fn raw_exec_redteam_table() {
        for case in redteam_cases() {
            let policy = from_toml_str(case.policy_toml)
                .unwrap_or_else(|e| panic!("case {}: policy TOML failed to parse: {e}", case.name));
            let decision = policy.evaluate_raw_exec(&argv(case.argv));
            // `DenyByGuard` and `DenyByDefault` are both `Deny { rule: None }`;
            // the ADR-0019 whitespace guard is the one whose reason starts
            // with "raw exec argv[", and each expectation asserts the
            // *absence* of the other.
            let matched = match (case.expect, &decision) {
                (Expect::Allow, Decision::Allow(_)) => true,
                (
                    Expect::DenyByPattern,
                    Decision::Deny {
                        rule: Some(Rule::RawExecDeny { .. }),
                        ..
                    },
                ) => true,
                (Expect::DenyByGuard, Decision::Deny { rule: None, reason }) => {
                    reason.starts_with("raw exec argv[")
                }
                (Expect::DenyByDefault, Decision::Deny { rule: None, reason }) => {
                    !reason.starts_with("raw exec argv[")
                }
                _ => false,
            };
            assert!(
                matched,
                "case {}: {}: expected {:?}, got {decision:?}",
                case.name, case.note, case.expect
            );
        }
    }

    // -------------------------------------------------------------------
    // Cross-axis (Axis 2 x Axis 3) — finding #227, RESOLVED by ADR-0019
    // -------------------------------------------------------------------
    //
    // A deny rule could be evaded by merging the denied token into an
    // adjacent argv element: an anchored per-element deny (`^--force$`)
    // only ever saw the exact element `--force`, so appending anything to
    // that element ("--force x") slipped past both the joined-string
    // disjunct and the per-element disjunct of the deny pass, while an
    // anchored allow pattern written for the merged form still matched the
    // joined command. That defeated a deny rule outright — more severe than
    // the unanchored-allow footgun above, which only ever over-widens an
    // allow — and, unlike that footgun, it was not fixable by operator
    // anchoring discipline: the operator wrote the most precise rule
    // available and still lost.
    //
    // RESOLVED by ADR-0019: the deny pass now also runs over the CANONICAL
    // elements (`argv.join(" ").split_whitespace()`), in addition to the
    // joined string and the raw elements. This test was `#[ignore]`d while
    // the finding was open; it now pins the fix. The neighbouring shapes
    // (padding, tab/LF/CR/NBSP separators, empty elements, three-token
    // merge, and the raw-element pass still firing on a merged-form deny)
    // are the Axis 7 rows in `redteam_cases()` above.
    #[test]
    fn deny_element_merge_closed_by_canonical_elements() {
        let policy = from_toml_str(
            "[raw_exec]\nallow = [\"^systemctl restart nginx --force x$\"]\ndeny = [\"^--force$\"]\n",
        )
        .expect("policy must parse");

        // The exact #227 reproduction: merged form must now be denied, and
        // denied *by the deny pattern* (not by deny-by-default) — the allow
        // still matches the joined string, so only the deny pass can stop it.
        let decision =
            policy.evaluate_raw_exec(&argv(&["systemctl", "restart", "nginx", "--force x"]));
        assert!(
            matches!(
                &decision,
                Decision::Deny {
                    rule: Some(Rule::RawExecDeny { pattern }),
                    ..
                } if pattern == "^--force$"
            ),
            "anchored per-element deny ^--force$ must not be evadable by merging the denied \
             token into an adjacent argv element (#227 / ADR-0019); got {decision:?}"
        );

        // The unmerged form stays denied — the change is monotonic in the
        // deny direction, it never turns a Deny into an Allow.
        let unmerged =
            policy.evaluate_raw_exec(&argv(&["systemctl", "restart", "nginx", "--force", "x"]));
        assert!(
            matches!(unmerged, Decision::Deny { .. }),
            "the unmerged argv must remain denied; got {unmerged:?}"
        );
    }

    // -------------------------------------------------------------------
    // ADR-0019 companion guard — argv[0] must be one non-empty program token
    // -------------------------------------------------------------------
    //
    // The joined form is a lossy projection of argv: `["systemctl restart",
    // "nginx"]` joins identically to the legitimate three-element form, so an
    // allow pattern can approve a joined string whose argv[0] is not the
    // program that will actually execute. Invariant #1 is that an argument
    // must never change *which* command runs; for Raw Exec that is argv[0].
    // The guard is fail-closed, so the Deny carries `rule: None` and a reason
    // naming argv[0]; it runs AFTER the deny pass (so an attributable deny
    // keeps its attribution) and BEFORE the allow pass. Since the 2026-09-16
    // amendment the same guard also covers every OTHER argv element (a
    // non-empty element carrying whitespace is refused too) — this test keeps
    // its original argv[0]-only scope; the every-element case is
    // `whitespace_in_any_argv_element_refused_naming_its_index` below.
    #[test]
    fn argv0_refused_unless_single_program_token() {
        // A permissive allow and no deny, so nothing but the guard can produce
        // the Deny.
        let policy = from_toml_str("[raw_exec]\nallow = [\".*\"]\n").expect("policy must parse");

        // Every Unicode-whitespace shape, in every position within argv[0],
        // plus the empty argv[0].
        for bad in [
            "",                                 // empty: not a program at all
            "systemctl restart",                // interior ASCII space (the #227-adjacent shape)
            "systemctl\trestart",               // interior tab
            "systemctl\nrestart",               // interior newline
            "systemctl\rrestart",               // interior carriage return
            "systemctl\u{00A0}restart",         // interior NBSP (Unicode whitespace)
            " systemctl",                       // leading space
            "systemctl ",                       // trailing space
            "/usr/bin/systemctl restart nginx", // the whole command as one element
        ] {
            let decision = policy.evaluate_raw_exec(&argv(&[bad, "nginx"]));
            assert!(
                matches!(
                    &decision,
                    Decision::Deny { rule: None, reason }
                    if reason.contains("argv[0]")
                ),
                "argv[0] {bad:?} is not a single non-empty program token and must be refused \
                 with an argv[0] reason (ADR-0019); got {decision:?}"
            );
        }

        // Control: the same permissive allow admits a clean argv[0], so the
        // guard is what rejects the cases above — and NUL, which is not
        // Unicode whitespace, is not caught by this guard (it fails closed
        // later, at execv — raw_exec.rs::nul_in_argv_fails_closed_at_executor).
        for good in ["systemctl", "systemctl\0x"] {
            let decision = policy.evaluate_raw_exec(&argv(&[good, "nginx"]));
            assert!(
                matches!(decision, Decision::Allow(_)),
                "argv[0] {good:?} is a single non-empty token with no whitespace and must not \
                 be caught by the ADR-0019 guard; got {decision:?}"
            );
        }

        // Ordering: the guard runs after the deny pass, so a command that a
        // deny pattern claims keeps the pattern attribution instead of
        // collapsing to the guard's rule: None.
        let with_deny = from_toml_str("[raw_exec]\nallow = [\".*\"]\ndeny = [\"^--force$\"]\n")
            .expect("policy must parse");
        let decision = with_deny.evaluate_raw_exec(&argv(&["prog x", "--force"]));
        assert!(
            matches!(
                &decision,
                Decision::Deny {
                    rule: Some(Rule::RawExecDeny { pattern }),
                    ..
                } if pattern == "^--force$"
            ),
            "an argv that trips BOTH the deny pass and the argv[0] guard must be attributed to \
             the deny pattern (deny pass runs first); got {decision:?}"
        );
    }

    // -------------------------------------------------------------------
    // Whitespace guard — ADR-0019, amended 2026-09-16: EVERY argv element,
    // not just argv[0]
    // -------------------------------------------------------------------
    //
    // Once an allow pattern must match the WHOLE joined command, an argument
    // that carries whitespace can shift what the pattern is really matching
    // against without the gate seeing an element boundary move. This test
    // pins the every-element half of the guard; `argv0_refused_unless_
    // single_program_token` above keeps pinning the argv[0]-only half.
    #[test]
    fn whitespace_in_any_argv_element_refused_naming_its_index() {
        let policy = from_toml_str("[raw_exec]\nallow = ['(?s).*']\n").expect("policy must parse");

        // Every Unicode-whitespace shape, plus leading/trailing ASCII space,
        // in a NON-argv[0] element (argv[2]) — must be refused, naming the
        // index and pointing to a Template Operation as the remedy.
        for bad in [
            "a b",
            "a\tb",
            "a\nb",
            "a\rb",
            "a\u{00A0}b",
            "a\u{2028}b",
            " a",
            "a ",
        ] {
            let decision = policy.evaluate_raw_exec(&argv(&["prog", "ok", bad]));
            assert!(
                matches!(
                    &decision,
                    Decision::Deny { rule: None, reason }
                    if reason.contains("argv[2]") && reason.contains("Template")
                ),
                "argv[2] {bad:?} carries whitespace and must be refused, naming the index and \
                 a Template Operation as the remedy; got {decision:?}"
            );
        }

        // The FIRST offending element is named, not a later one.
        let decision = policy.evaluate_raw_exec(&argv(&["prog", "a b", "c d"]));
        match &decision {
            Decision::Deny { rule: None, reason } => {
                assert!(
                    reason.contains("argv[1]"),
                    "the first offending element (argv[1]) must be named; got {reason:?}"
                );
                assert!(
                    !reason.contains("argv[2]"),
                    "only the FIRST offending element may be named, not a later one too; \
                     got {reason:?}"
                );
            }
            other => panic!("expected a Deny; got {other:?}"),
        }

        // An empty element past argv[0] is allowed — only argv[0]'s emptiness
        // is refused.
        let decision = policy.evaluate_raw_exec(&argv(&["prog", "", "x"]));
        assert!(
            matches!(decision, Decision::Allow(_)),
            "an empty NON-argv[0] element must not be refused; got {decision:?}"
        );

        // NUL is not Unicode whitespace, so it does not trip this guard
        // either (it fails closed later, at execv).
        let decision = policy.evaluate_raw_exec(&argv(&["prog", "a\0b"]));
        assert!(
            matches!(decision, Decision::Allow(_)),
            "a NUL-bearing element must not be refused by the whitespace guard; got {decision:?}"
        );

        // Ordering: the deny pass still runs first and keeps its attribution
        // even when the guard would also fire on the same argv.
        let with_deny = from_toml_str("[raw_exec]\nallow = ['(?s).*']\ndeny = ['^--force$']\n")
            .expect("policy must parse");
        let decision = with_deny.evaluate_raw_exec(&argv(&["prog", "--force x"]));
        assert!(
            matches!(
                &decision,
                Decision::Deny {
                    rule: Some(Rule::RawExecDeny { pattern }),
                    ..
                } if pattern == "^--force$"
            ),
            "an argv that trips BOTH the deny pass and the whitespace guard must be attributed \
             to the deny pattern (deny pass runs first); got {decision:?}"
        );
    }

    // -------------------------------------------------------------------
    // Deny reasons name which form matched, and the text it matched
    // -------------------------------------------------------------------
    //
    // The reason is `PolicyVerdict.deciding_rule` verbatim (dispatch.rs
    // `decision_to_verdict`), so it is the wire-visible explanation in
    // PolicyQuery, plan mode and `policy check`. A canonical element need not
    // appear anywhere in argv, so a bare "denied by pattern X" is not
    // reconcilable against the argv the caller sent.
    #[test]
    fn deny_reason_names_the_matched_form_and_text() {
        let policy = from_toml_str(
            "[raw_exec]\nallow = [\".*\"]\ndeny = [\"restart nginx\", \"^--force x$\", \"^--force$\"]\n",
        )
        .expect("policy must parse");

        // (argv, expected fragment of the reason)
        let cases: &[(&[&str], &str)] = &[
            (
                &["systemctl", "restart", "nginx"],
                "raw exec denied by pattern \"restart nginx\" \
                 (matched joined command \"systemctl restart nginx\")",
            ),
            (
                &["systemctl", "--force x"],
                "raw exec denied by pattern \"^--force x$\" (matched argv element \"--force x\")",
            ),
            (
                &["systemctl", "--force y"],
                "raw exec denied by pattern \"^--force$\" (matched canonical element \"--force\")",
            ),
        ];

        for (command, expected) in cases {
            let decision = policy.evaluate_raw_exec(&argv(command));
            match &decision {
                Decision::Deny { reason, .. } => assert_eq!(
                    reason, expected,
                    "the deny reason for {command:?} must name the matched form and text"
                ),
                other => panic!("{command:?} must be denied; got {other:?}"),
            }
        }

        // Form precedence is contract, not incidental: a pattern that matches
        // more than one form must report the FIRST form in the documented
        // order (joined command, then raw argv element, then canonical
        // element), since that is the most concrete thing the caller sent.
        // Without these two rows, swapping arms in `first_raw_deny_match`
        // leaves the whole suite green while silently changing both the label
        // and the quoted text an operator sees.
        let precedence: &[(&str, &[&str], &str)] = &[
            (
                // Matches the joined command AND the raw element "prog".
                "prog",
                &["prog", "x"],
                "raw exec denied by pattern \"prog\" (matched joined command \"prog x\")",
            ),
            (
                // Anchored at ^, so it cannot match the joined command
                // ("prog …"), but matches the raw element "--force x" AND the
                // canonical element "--force".
                "^--force",
                &["prog", "--force x"],
                "raw exec denied by pattern \"^--force\" (matched argv element \"--force x\")",
            ),
        ];
        for (pattern, command, expected) in precedence {
            let policy = from_toml_str(&format!("[raw_exec]\ndeny = [{pattern:?}]\n"))
                .expect("policy must parse");
            match &policy.evaluate_raw_exec(&argv(command)) {
                Decision::Deny { reason, .. } => assert_eq!(
                    reason, expected,
                    "a pattern matching several forms must report the first form in the \
                     documented order (joined, raw element, canonical element)"
                ),
                other => panic!("{command:?} must be denied; got {other:?}"),
            }
        }

        // Caller-controlled text is bounded on the two reasons that quote
        // it: a `.*`-style deny against a long joined command, and the
        // ADR-0019 argv[0] guard — which is the cheaper one to provoke,
        // since it needs no allow and no deny pattern (an empty Policy still
        // emits it). The later-element guard reason (added by the
        // 2026-09-16 amendment) does NOT quote the caller's text at all — a
        // Raw Exec argument can carry a secret (e.g. an `Authorization:
        // Bearer <token>` header value), and this reason lands verbatim in
        // `deciding_rule`, the Task result and the daemon log — so it is
        // checked separately below, against a short secret rather than these
        // `long_texts` fixtures (see that check for why).
        //
        // The fixtures are deliberately NOT uniform-width: with an ASCII byte
        // ahead of 4-byte codepoints, byte index REASON_FRAGMENT_BUDGET falls
        // INSIDE a character, so a future `&text[..BUDGET]` "simplification"
        // panics here (on attacker-controlled argv) instead of passing.
        let mixed_width = format!("x{}", "🔥".repeat(1024));
        let combining = format!("x{}", "e\u{0301}".repeat(1024));
        let long_texts = [
            ("ascii", "x".repeat(4096)),
            ("mixed-width 4-byte codepoints", mixed_width),
            ("combining marks", combining),
        ];

        let wide = from_toml_str("[raw_exec]\ndeny = [\"^x\"]\n").expect("policy must parse");
        let empty_policy = from_toml_str("").expect("an empty policy must parse");

        // The property that matters is INDEPENDENCE from caller size, not a
        // magic number: the same input four times longer must produce the
        // byte-identical reason. An absolute cap is asserted too, generous
        // enough for `{:?}` escaping — a combining mark quotes as `\u{301}`,
        // so an escaped character can be ~10 times its own width. That
        // expansion is bounded by the fragment budget; the caller's length is
        // not a factor either way.
        const REASON_CHAR_CAP: usize = 1_500;

        let reason_of = |decision: Decision, which: &str, label: &str| -> String {
            match decision {
                Decision::Deny { reason, .. } => reason,
                other => panic!("{which} ({label}): must be denied; got {other:?}"),
            }
        };

        for (label, text) in &long_texts {
            let longer = text.repeat(4);
            for (which, short, long) in [
                // 1. deny-matched text (needs a deny pattern).
                (
                    "deny reason",
                    reason_of(wide.evaluate_raw_exec(&argv(&[text])), "deny reason", label),
                    reason_of(
                        wide.evaluate_raw_exec(&argv(&[&longer])),
                        "deny reason",
                        label,
                    ),
                ),
                // 2. the argv[0] guard reason: the same text with a space
                //    appended so the guard fires, against a Policy with NO
                //    patterns at all — the cheapest reason to provoke.
                (
                    "guard reason",
                    reason_of(
                        empty_policy.evaluate_raw_exec(&argv(&[&format!("{text} ")])),
                        "guard reason",
                        label,
                    ),
                    reason_of(
                        empty_policy.evaluate_raw_exec(&argv(&[&format!("{longer} ")])),
                        "guard reason",
                        label,
                    ),
                ),
            ] {
                assert!(
                    short.contains('…'),
                    "{which} ({label}): an over-long fragment must be truncated and marked; \
                     got {short:?}"
                );
                assert_eq!(
                    short, long,
                    "{which} ({label}): a 4x longer argv must produce the identical reason — \
                     the caller must not be able to size an audit record"
                );
                assert!(
                    short.chars().count() < REASON_CHAR_CAP,
                    "{which} ({label}): the reason must stay small; got {} chars ({} bytes)",
                    short.chars().count(),
                    short.len()
                );
            }
        }

        // The later-element guard reason must name the offending index and
        // must NEVER quote the caller's argument text, since a Raw Exec
        // argument can carry a secret (e.g. an `Authorization: Bearer
        // <token>` header value). This is deliberately a SHORT secret, not
        // one of the `long_texts` fixtures above: those all exceed the
        // `REASON_FRAGMENT_BUDGET` (120-character) fragment budget, so the
        // pre-fix code — which quoted up to that budget and truncated the
        // rest — would ALSO fail to find the whole fixture in its
        // (truncated) reason, making `!reason.contains(candidate)` pass
        // against the old, buggy behaviour and prove nothing. A secret well
        // under that budget is quoted in full by the pre-fix code, so
        // finding it absent here is what actually distinguishes "never
        // quoted" from "a truncated quote that happens not to contain the
        // whole fixture". See
        // `raw_exec::secret_bearing_whitespace_argument_never_appears_in_deny_reason`
        // for the end-to-end property, through `run_raw_exec`'s Task result
        // rather than `evaluate_raw_exec` alone.
        let secret = "Authorization: Bearer s3cr3t-value";
        let secret_argv = argv(&["prog", "-H", secret]);
        let reason = reason_of(
            empty_policy.evaluate_raw_exec(&secret_argv),
            "later-element guard reason",
            "short secret",
        );
        assert!(
            reason.contains("argv[2]"),
            "later-element guard reason: must name the offending index; got {reason:?}"
        );
        assert!(
            !reason.contains(secret),
            "later-element guard reason: must never quote the caller's argument text, which \
             may hold a secret; got {reason:?}"
        );
    }

    // ---------------------------------------------------------------------------
    // Structured-Operation path-argument red-team (issue #215)
    // ---------------------------------------------------------------------------
    //
    // This second table drives `Policy::evaluate` (the structured-Operation
    // path, policy.rs:705) via `evaluate("file.read", ...)`, NOT
    // `evaluate_raw_exec` above. `file.read` takes a filesystem-path
    // argument and is the representative case for path-taking Operations.
    // It asserts the documented-intended behaviors GREEN (exact-string deny
    // fires on the exact literal, wildcard allow admits an ordinary path,
    // arg-count mismatch is deny-by-default) and captures the confirmed
    // exact-string-deny path bypass as a separate `#[ignore]`d test below,
    // rather than fixing it here — see the comment above that test.

    /// Shared fixture: mirrors the shipped example policy's `file.read`
    /// rules (policy.example.toml:56-85) — a `["*"]` wildcard allow paired
    /// with an exact-string `[[deny]]` for `/etc/shadow` — inlined so this
    /// table stays self-contained, like the Raw Exec fixtures above.
    const FILE_READ_SHADOW_POLICY: &str =
        "[[operation]]\nname = \"file.read\"\nallowed_args = [[\"*\"]]\n\n\
         [[deny]]\nname = \"file.read\"\nargs = [[\"/etc/shadow\"]]\n";

    /// Coarse red-team classification of a structured-Operation `Decision`,
    /// mirroring `Expect` above but over `Policy::evaluate`'s
    /// `Rule::Operation*` variants. Kept separate from `Expect` because the
    /// two entry points return different `Rule` variants (RawExec* vs
    /// Operation*), so a shared enum would be wrong.
    #[derive(Debug, Clone, Copy)]
    enum PathExpect {
        /// `Decision::Allow(Rule::OperationAllow { .. })`.
        Allow,
        /// `Decision::Deny` with a specific `Rule::OperationDeny` attributed.
        DenyByRule,
        /// `Decision::Deny` with `rule: None` (no allow rule matched).
        DenyByDefault,
    }

    /// One structured-op path-argument red-team case: a self-contained
    /// Policy fixture, an Operation name + argv, and the expected coarse
    /// decision. `op` is always "file.read" today but carried per-row for
    /// legibility and to let later red-team issues extend this table to
    /// other path-taking Operations. Reuses the module's `argv` helper for
    /// `args`, so no new helper is needed.
    struct PathCase {
        name: &'static str,
        policy_toml: &'static str,
        op: &'static str,
        args: &'static [&'static str],
        expect: PathExpect,
        note: &'static str,
    }

    /// The GREEN extension point: documented-intended structured-op
    /// behaviors against `FILE_READ_SHADOW_POLICY`.
    ///
    /// Deliberately does NOT include a zero-arg row: under this fixture the
    /// `/etc/shadow` deny fires *vacuously* on a shorter invocation
    /// (policy.rs:726-732, see vacuous_deny_fires_on_shorter_invocation), so
    /// a zero-arg `file.read` call is `DenyByRule`, not `DenyByDefault` — a
    /// zero-arg row expecting `DenyByDefault` would be wrong here.
    fn file_read_path_cases() -> Vec<PathCase> {
        vec![
            PathCase {
                name: "exact_string_deny_fires_on_exact_path",
                policy_toml: FILE_READ_SHADOW_POLICY,
                op: "file.read",
                args: &["/etc/shadow"],
                expect: PathExpect::DenyByRule,
                note: "documented-intended: the [[deny]] protects the EXACT literal /etc/shadow; deny-beats-allow fires (policy.rs:731)",
            },
            PathCase {
                name: "wildcard_allow_admits_ordinary_path",
                policy_toml: FILE_READ_SHADOW_POLICY,
                op: "file.read",
                args: &["/etc/hostname"],
                expect: PathExpect::Allow,
                note: "documented-intended: the [\"*\"] wildcard admits any path the exact deny does not list (mirrors arg_constraint_wildcard_allows_any_path, policy.rs:1034)",
            },
            PathCase {
                name: "wrong_arg_count_two_args_deny_by_default",
                policy_toml: FILE_READ_SHADOW_POLICY,
                op: "file.read",
                args: &["/etc/hostname", "extra"],
                expect: PathExpect::DenyByDefault,
                note: "documented-intended: two args vs the one-arg allow shape → count mismatch → deny-by-default (policy.rs:751)",
            },
        ]
    }

    #[test]
    fn file_read_path_redteam_table() {
        for case in file_read_path_cases() {
            let policy = from_toml_str(case.policy_toml)
                .unwrap_or_else(|e| panic!("case {}: policy TOML failed to parse: {e}", case.name));
            let decision = policy.evaluate(case.op, &argv(case.args));
            let matched = matches!(
                (case.expect, &decision),
                (
                    PathExpect::Allow,
                    Decision::Allow(Rule::OperationAllow { .. })
                ) | (
                    PathExpect::DenyByRule,
                    Decision::Deny {
                        rule: Some(Rule::OperationDeny { .. }),
                        ..
                    },
                ) | (PathExpect::DenyByDefault, Decision::Deny { rule: None, .. })
            );
            assert!(
                matched,
                "case {}: {}: expected {:?}, got {decision:?}",
                case.name, case.note, case.expect
            );
        }
    }

    // -------------------------------------------------------------------
    // Finding #236 — exact-string [[deny]] for file.read /etc/shadow evaded
    // by any non-canonical path spelling — RESOLVED by ADR-0018.
    // -------------------------------------------------------------------
    //
    // Root cause: `Policy::evaluate`'s deny pass compares each argument by
    // exact byte equality (`denied_vals.contains(&args[i])`, policy.rs:731)
    // with NO path canonicalization anywhere in daemon/src (grep-confirmed:
    // zero `canonicalize`/`read_link` hits). The `file.read` executor
    // delegates path restriction to Policy entirely and then `File::open`s
    // the literal string (operations/file_read.rs:15-17, 34/52), so the
    // kernel resolves `..`/`//`/`.`/`/proc/self/root` only *after* the deny
    // has already been evaded. So every alternate spelling of /etc/shadow
    // slips the exact-string deny and is admitted by the `["*"]` allow.
    //
    // RESOLVED by ADR-0018: `Policy::evaluate` now fail-closes on a
    // non-canonical `file.read` path (layer 1) and the executor re-checks the
    // resolved target off the open descriptor (layer 2). This test was
    // `#[ignore]`d while the finding was open; it now pins the layer-1 fix.
    //
    // Symlink / bind-mount / Unicode-normalization siblings: at the Policy
    // string layer a symlink or bind-mount alias is simply a DIFFERENT
    // literal the deny does not list — the SAME root cause — but only fully
    // demonstrable through the executor against a real filesystem (out of
    // scope here, confined to policy.rs). They are documented here and in
    // finding #236, not asserted as string-layer rows. `/etc/Shadow`
    // (case/Unicode) is canonical *form* and fs-fold-dependent: its
    // desired=Deny only holds on a case-folding/normalizing mount, and
    // canonical-form matching (like canonicalize) folds `..`/`.`/`//`/symlinks
    // but never case or Unicode. ADR-0018 records it as a narrow residual, so
    // it is not asserted here.
    #[test]
    fn noncanonical_path_denied_by_canonical_form_precondition() {
        // Only the LEXICAL respellings — the ones the canonical-form
        // precondition (ADR-0018 layer 1) closes at the Policy layer.
        // `/proc/self/root/...`, `/proc/<pid>/root/...`, and symlinks are
        // canonical *form* and are closed by the executor re-checking the
        // resolved target (ADR-0018 layer 2 — see operations/file_read.rs
        // `resolved_target_recheck_*` tests). `/etc/Shadow` (case/Unicode) is
        // canonical form and fs-fold-dependent; ADR-0018 records it as a
        // narrow residual, so it is not asserted here.
        const LEXICAL_EVASIONS: &[(&str, &str)] = &[
            ("/etc/../etc/shadow", "parent-dir traversal"),
            ("//etc/shadow", "doubled leading slash"),
            ("/etc//shadow", "doubled interior slash"),
            ("/etc/./shadow", "dot segment"),
            ("/etc/shadow/", "trailing slash"),
        ];

        let policy = from_toml_str(FILE_READ_SHADOW_POLICY).expect("policy must parse");
        for (path, why) in LEXICAL_EVASIONS {
            let decision = policy.evaluate("file.read", &argv(&[path]));
            assert!(
                matches!(decision, Decision::Deny { .. }),
                "non-canonical path must be denied by the canonical-form precondition \
                 ({why}: {path:?}, finding #236 / ADR-0018); got {decision:?}"
            );
        }

        // The canonical spelling stays denied — by its [[deny]] rule, proving
        // the precondition does not shadow the real deny.
        assert!(
            matches!(
                policy.evaluate("file.read", &argv(&["/etc/shadow"])),
                Decision::Deny { .. }
            ),
            "canonical /etc/shadow must remain denied by its [[deny]] rule"
        );
    }
}

// ---------------------------------------------------------------------------
// Loader hardening tests (#216) — TOCTOU close, symlink rejection, non-regular
// rejection. Kept as a separate trailing module so it never touches `mod
// tests` or `mod raw_exec_redteam` above.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod loader_hardening_tests {
    use super::*;
    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt as _;
    use std::os::unix::fs::PermissionsExt as _;

    // The fixture is the example policy file checked into the repo (mirrors
    // `mod tests::FIXTURE`).
    const FIXTURE: &str = include_str!("../policy.example.toml");

    // -------------------------------------------------------------------
    // Unique temp path + secure-mode writer, mirroring `mod tests::TempFile`
    // (unique path via SystemTime nanos + pid; mode set via both
    // OpenOptions::mode and a post-hoc chmod to defeat the process umask).
    // -------------------------------------------------------------------

    fn unique_temp_path(label: &str) -> std::path::PathBuf {
        use std::time::{SystemTime, UNIX_EPOCH};
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!(
            "relay-policy-loader-test-{}-{}-{}",
            label,
            std::process::id(),
            nanos
        ))
    }

    fn write_secure_policy(path: &Path, content: &[u8], mode: u32) {
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(mode)
            .open(path)
            .unwrap();
        f.write_all(content).unwrap();
        // chmod is not umask-masked, unlike OpenOptions::mode(); force the
        // exact mode so a runner umask can't spuriously affect these tests.
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
    }

    /// RAII cleanup for a path this module created — covers a regular file,
    /// a symlink, or a FIFO, all removable via `remove_file`.
    struct Cleanup(std::path::PathBuf);

    impl Drop for Cleanup {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }

    // -------------------------------------------------------------------
    // loader_rejects_symlink
    // -------------------------------------------------------------------

    #[test]
    fn loader_rejects_symlink() {
        let target = unique_temp_path("symlink-target");
        write_secure_policy(&target, FIXTURE.as_bytes(), 0o600);
        let _target_cleanup = Cleanup(target.clone());

        // Sanity: the real target loads fine on its own, so the symlink is
        // provably the sole cause of the rejection below.
        assert!(
            load_policy(&target).is_ok(),
            "the symlink target itself must load cleanly"
        );

        let link = unique_temp_path("symlink-link");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        let _link_cleanup = Cleanup(link.clone());

        let result = load_policy(&link);
        assert!(
            matches!(result, Err(PolicyError::SymlinkPath)),
            "a symlinked policy path must be rejected via O_NOFOLLOW; got {result:?}"
        );
    }

    // -------------------------------------------------------------------
    // loader_rejects_fifo — also proves open() does not hang (O_NONBLOCK)
    // -------------------------------------------------------------------

    #[test]
    fn loader_rejects_fifo() {
        let path = unique_temp_path("fifo");
        let path_cstr =
            std::ffi::CString::new(path.to_str().expect("temp path must be valid UTF-8"))
                .expect("temp path must not contain a NUL byte");

        // SAFETY: `path_cstr` is a valid NUL-terminated C string for the
        // lifetime of this call; mkfifo has no other preconditions.
        let rc = unsafe { libc::mkfifo(path_cstr.as_ptr(), 0o600) };
        assert_eq!(
            rc,
            0,
            "mkfifo must succeed; errno={:?}",
            std::io::Error::last_os_error()
        );
        let _cleanup = Cleanup(path.clone());

        // If load_policy ever regressed to blocking O_RDONLY open, this call
        // would hang forever (no writer ever opens the FIFO) instead of
        // returning promptly with NotRegularFile.
        let result = load_policy(&path);
        assert!(
            matches!(result, Err(PolicyError::NotRegularFile)),
            "a FIFO at the policy path must be rejected as not-a-regular-file; got {result:?}"
        );
    }

    // -------------------------------------------------------------------
    // loader_rejects_third_party_owner — the owner half of the gate: a
    // file owned by neither root nor the daemon euid is refused.
    // -------------------------------------------------------------------

    #[test]
    fn loader_rejects_third_party_owner() {
        // Only root can hand a file to a uid that is neither 0 nor its own
        // euid; a non-root runner cannot build this fixture at all.
        if !rustix::process::geteuid().is_root() {
            eprintln!("skipped: needs root to chown a fixture to a third-party uid");
            return;
        }
        let path = unique_temp_path("third-party-owner");
        write_secure_policy(&path, FIXTURE.as_bytes(), 0o644);
        let _cleanup = Cleanup(path.clone());
        assert!(
            load_policy(&path).is_ok(),
            "the root-owned fixture must load, so the owner is the sole cause below"
        );

        std::os::unix::fs::chown(&path, Some(65534), None).expect("chown");
        let result = load_policy(&path);
        assert!(
            matches!(result, Err(PolicyError::InsecureOwner { uid: 65534 })),
            "a policy file owned by a third-party uid must be refused; got {result:?}"
        );
    }

    // -------------------------------------------------------------------
    // loader_reads_validated_descriptor_bytes — descriptor identity: the
    // bytes read from the validated fd are exactly the fixture bytes.
    // -------------------------------------------------------------------

    #[test]
    fn loader_reads_validated_descriptor_bytes() {
        let path = unique_temp_path("descriptor-identity");
        write_secure_policy(&path, FIXTURE.as_bytes(), 0o600);
        let _cleanup = Cleanup(path.clone());

        let file_policy = load_policy(&path).expect("secure-mode fixture must load");
        let str_policy = from_toml_str(FIXTURE).expect("fixture must parse");
        assert_eq!(
            file_policy.fingerprint(),
            str_policy.fingerprint(),
            "load_policy must read exactly the validated descriptor's bytes: its \
             fingerprint must match from_toml_str(FIXTURE)'s"
        );
    }
}

// ---------------------------------------------------------------------------
// Property tests (issue #218) — bounded proptest fuzzing of the Policy engine
// ---------------------------------------------------------------------------
//
// Red-team posture: this suite ATTACKS `evaluate`/`evaluate_raw_exec` for
// panics and invariant violations. It asserts only invariants the engine
// already implements — deny-by-default (PB1) and deny-beats-allow (PB2, PB3)
// — and never reimplements Policy evaluation (ADR-0011): every oracle below
// calls the real engine and compares against a literal-string mirror of its
// documented semantics (`Policy::evaluate` / `Policy::evaluate_raw_exec`).
// A drift between an oracle and the engine is a TEST bug — fix the test,
// never the engine (see the module CONSTRAINTS note).
//
// This module is a sibling of `mod tests`, `mod raw_exec_redteam`, and
// `mod loader_hardening_tests` above; it never edits them and builds its own
// fixtures from literal TOML rather than reaching into a private sibling
// module's helpers.
#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::prelude::*;

    // -------------------------------------------------------------------
    // Bounded strategies
    // -------------------------------------------------------------------

    /// One argv/arg element: full-Unicode (including control chars), 0-8
    /// chars — bounded but wide enough to probe the panic surface.
    fn arb_argv_elem() -> impl Strategy<Value = String> {
        prop::collection::vec(any::<char>(), 0..8).prop_map(|cs| cs.into_iter().collect())
    }

    /// A bounded argv/args vector, 0-6 elements.
    fn arb_argv() -> impl Strategy<Value = Vec<String>> {
        prop::collection::vec(arb_argv_elem(), 0..6)
    }

    /// An operation name: usually one of the four known names, occasionally
    /// an arbitrary string (unknown-operation coverage).
    fn arb_op_name() -> impl Strategy<Value = String> {
        prop_oneof![
            Just(operations::SYSTEM_FACTS.to_string()),
            Just(operations::FILE_READ.to_string()),
            Just(operations::SERVICE_RESTART.to_string()),
            Just(operations::PKG_INSTALL.to_string()),
            arb_argv_elem(),
        ]
    }

    /// A TOML- and regex-literal-safe token: no escaping needed when spliced
    /// into a generated Policy TOML string or a regex pattern.
    fn arb_safe_token() -> impl Strategy<Value = String> {
        prop::string::string_regex("[A-Za-z0-9._@-]{1,8}").unwrap()
    }

    // -------------------------------------------------------------------
    // PB1 — evaluate / evaluate_raw_exec never panic; an empty Policy denies
    // everything by default (ADR-0002 invariant #3).
    // -------------------------------------------------------------------

    /// A hand-written, richer fixed Policy for PB1's panic-surface coverage
    /// only — similar in shape to `policy.example.toml`. Deliberately NOT
    /// `super::tests::make_query_test_policy()`: that helper is private to a
    /// sibling test module and unreachable from here; this is a
    /// self-contained literal built fresh in this module.
    const RICHER_POLICY_TOML: &str = r#"
[[operation]]
name = "service.restart"
allowed_args = [["nginx", "php-fpm"]]

[[operation]]
name = "pkg.install"
allowed_args = [["nginx", "curl"], ["*"]]

[[operation]]
name = "system.facts"
allowed_args = []

[[deny]]
name = "file.read"
args = [["/etc/shadow"]]

[raw_exec]
allow = ["^/usr/bin/systemctl (status|restart) [A-Za-z0-9@._-]+$"]
deny = ["--force", "\\brm\\b"]
"#;

    fn richer_policy() -> Policy {
        from_toml_str(RICHER_POLICY_TOML).expect("hand-written richer policy must parse")
    }

    // -------------------------------------------------------------------
    // PB3 fixture — Raw Exec deny-beats-allow (`evaluate_raw_exec`).
    // -------------------------------------------------------------------

    fn raw_exec_pb3_policy() -> Policy {
        from_toml_str("[raw_exec]\nallow = [\".*\"]\ndeny = [\"secret\"]\n")
            .expect("PB3 fixed raw_exec policy must parse")
    }

    // -------------------------------------------------------------------
    // PB4 fixture — the whitespace guard in isolation, no deny at all.
    // -------------------------------------------------------------------

    fn raw_exec_pb4_policy() -> Policy {
        // DOTALL (`(?s)`), unlike PB3's plain `.*`, so this policy's allow
        // pass would admit ANY argv (newlines included) if it ever ran —
        // isolating the guard as the only thing that can produce a Deny.
        from_toml_str("[raw_exec]\nallow = ['(?s).*']\n")
            .expect("PB4 fixed raw_exec policy must parse")
    }

    /// `denied` paired with an `arg` that is drawn from `denied` itself about
    /// half the time (via `prop::sample::select`) and from the same
    /// `arb_safe_token()` domain otherwise. Independent sampling of `arg` and
    /// `denied` makes a `denied.contains(&arg)` hit astronomically unlikely
    /// (~0.12% observed) because the token space is large, so the deny
    /// branch of `op_deny_beats_allow` almost never fired; biasing `arg`
    /// toward an actual element of `denied` makes both oracle branches fire
    /// at a normal rate without changing the oracle itself.
    fn denied_and_arg() -> impl Strategy<Value = (Vec<String>, String)> {
        prop::collection::vec(arb_safe_token(), 1..4).prop_flat_map(|denied| {
            let arg = prop_oneof![prop::sample::select(denied.clone()), arb_safe_token()];
            (Just(denied), arg)
        })
    }

    /// `arb_argv()`, but with the literal deny token ("secret" or a
    /// substring match "run-secret-now") injected as an occasional element,
    /// so `raw_exec_deny_beats_allow`'s deny (`hits`) branch fires reliably
    /// instead of relying on wide-Unicode `arb_argv_elem()` to ever emit the
    /// literal ASCII word "secret" (observed: 0 times in 12,800 cases).
    fn arb_argv_with_secret() -> impl Strategy<Value = Vec<String>> {
        prop::collection::vec(
            prop_oneof![
                arb_argv_elem(),
                Just("secret".to_string()),
                Just("run-secret-now".to_string()),
            ],
            0..6,
        )
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(256))]

        // ---------------------------------------------------------------
        // PB1 `evaluate_never_panics_and_deny_by_default`
        // ---------------------------------------------------------------
        #[test]
        fn evaluate_never_panics_and_deny_by_default(
            name in arb_op_name(),
            args in arb_argv(),
            argv in arb_argv(),
        ) {
            let empty = from_toml_str("").expect("empty policy string must parse (deny-all)");

            prop_assert!(
                matches!(empty.evaluate(&name, &args), Decision::Deny { .. }),
                "an empty Policy must deny-by-default for every operation/args pair"
            );
            prop_assert!(
                matches!(empty.evaluate_raw_exec(&argv), Decision::Deny { .. }),
                "an empty Policy must deny-by-default for every Raw Exec argv"
            );

            // Panic-surface only against a richer fixed Policy — no oracle here,
            // the point is only that neither call panics on arbitrary Unicode
            // input; PB2/PB3 below own the narrower deny-beats-allow oracles.
            let richer = richer_policy();
            let _ = richer.evaluate(&name, &args);
            let _ = richer.evaluate_raw_exec(&argv);
        }

        // ---------------------------------------------------------------
        // PB2 `op_deny_beats_allow` — mirrors policy.rs:705-790 exactly.
        // ---------------------------------------------------------------
        #[test]
        fn op_deny_beats_allow((denied, arg) in denied_and_arg()) {
            let denied_toml = denied
                .iter()
                .map(|d| format!("{d:?}"))
                .collect::<Vec<_>>()
                .join(", ");
            let toml = format!(
                "[[operation]]\nname = \"op\"\nallowed_args = [[\"*\"]]\n\n\
                 [[deny]]\nname = \"op\"\nargs = [[{denied_toml}]]\n"
            );
            let policy = from_toml_str(&toml)
                .unwrap_or_else(|e| panic!("generated TOML {toml:?} failed to parse: {e}"));

            let decision = policy.evaluate("op", std::slice::from_ref(&arg));

            if denied.contains(&arg) {
                prop_assert!(
                    matches!(decision, Decision::Deny { .. }),
                    "denied arg {arg:?} in {denied:?} must be denied despite the wildcard allow"
                );
            } else {
                prop_assert!(
                    matches!(decision, Decision::Allow(_)),
                    "arg {arg:?} not in denied set {denied:?} must be allowed by the wildcard"
                );
            }
        }

        // ---------------------------------------------------------------
        // PB3 `raw_exec_deny_beats_allow` — mirrors `evaluate_raw_exec`
        // exactly, including the ADR-0019 whitespace guard (amended
        // 2026-09-16 to cover every element, not just argv[0]).
        // ---------------------------------------------------------------
        #[test]
        fn raw_exec_deny_beats_allow(argv in arb_argv_with_secret()) {
            let policy = raw_exec_pb3_policy();
            let decision = policy.evaluate_raw_exec(&argv);

            if argv.is_empty() {
                // Empty argv rule: always denied, before any allow/deny
                // pattern is even consulted.
                let is_deny = matches!(decision, Decision::Deny { .. });
                prop_assert!(is_deny, "empty argv must always be denied");
            } else {
                // Mirrors the engine's order exactly: deny pass, then the
                // whitespace guard, then the allow pass.
                //
                // "secret" is a literal regex, so is_match <=> contains; deny
                // is tested against the joined string, any raw element, OR any
                // canonical element (ADR-0019 — for a substring pattern this
                // third disjunct is implied by the joined one, since every
                // canonical element is a substring of the joined string; it is
                // spelled out so the oracle mirrors the engine's three
                // disjuncts rather than a simplification of them).
                let joined = argv.join(" ");
                let hits = joined.contains("secret")
                    || argv.iter().any(|a| a.contains("secret"))
                    || joined.split_whitespace().any(|c| c.contains("secret"));
                // The guard: argv[0] must be non-empty, and EVERY element
                // (including argv[0]) must carry no `char::is_whitespace`
                // char. `arb_argv_elem()` is full-Unicode and 0-8 chars, so it
                // generates both empty and whitespace-bearing elements
                // regularly, in every position.
                let guarded = argv[0].is_empty()
                    || argv.iter().any(|a| a.chars().any(char::is_whitespace));
                if hits {
                    // Deny-beats-allow AND deny-beats-guard: a deny pattern
                    // keeps its attribution even when the guard would also fire.
                    let attributed = matches!(
                        decision,
                        Decision::Deny { rule: Some(Rule::RawExecDeny { .. }), .. }
                    );
                    prop_assert!(
                        attributed,
                        "argv containing 'secret' must be denied by the deny pattern, with the \
                         pattern attributed, despite the .* allow (and despite the whitespace \
                         guard)"
                    );
                } else if guarded {
                    let is_guard_deny = matches!(
                        &decision,
                        Decision::Deny { rule: None, reason } if reason.starts_with("raw exec argv[")
                    );
                    prop_assert!(
                        is_guard_deny,
                        "an empty argv[0], or any element carrying whitespace, with no deny hit \
                         must be refused by the ADR-0019 guard"
                    );
                } else {
                    // No element carries whitespace, so the joined string has
                    // no newline (the join separator is an ASCII space, not a
                    // newline) and `.*` (no DOTALL) matches all of it.
                    let is_allow = matches!(decision, Decision::Allow(_));
                    prop_assert!(is_allow, "argv not containing 'secret' must be allowed by .*");
                }
            }
        }

        // ---------------------------------------------------------------
        // PB4 `raw_exec_whitespace_element_never_allowed` — the whitespace
        // guard in isolation: no deny pattern exists at all, and the allow
        // pattern is permissive enough (DOTALL) to admit anything the guard
        // does not refuse first.
        // ---------------------------------------------------------------
        #[test]
        fn raw_exec_whitespace_element_never_allowed(argv in arb_argv()) {
            let policy = raw_exec_pb4_policy();
            let decision = policy.evaluate_raw_exec(&argv);

            if !argv.is_empty() {
                let guarded = argv[0].is_empty()
                    || argv.iter().any(|a| a.chars().any(char::is_whitespace));
                if guarded {
                    let is_guard_deny = matches!(
                        &decision,
                        Decision::Deny { rule: None, reason } if reason.starts_with("raw exec argv[")
                    );
                    prop_assert!(
                        is_guard_deny,
                        "an empty argv[0], or any element carrying whitespace, must be refused \
                         by the whitespace guard; got {decision:?}"
                    );
                } else {
                    prop_assert!(
                        matches!(decision, Decision::Allow(_)),
                        "with no deny pattern and a DOTALL allow, a whitespace-clean, \
                         non-empty-argv[0] argv must be allowed; got {decision:?}"
                    );
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Shipped default Policy tests (ADR-0022)
//
// The shipped default file (`daemon/policy.default.toml`) is validated here
// against the REAL engine — the same `from_toml_str` the fail-closed loader
// uses and the same `lint` that backs `relay-daemon policy check` — so the
// posture ADR-0022 records (read pre-allowed, confidentiality deny-list
// authoritative, mutate + Raw Exec opt-in) is CI-enforced, not aspirational.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod default_policy_tests {
    use super::*;

    /// The shipped default Policy file, included verbatim so the checked-in
    /// artifact is exactly what these tests validate.
    const DEFAULT: &str = include_str!("../policy.default.toml");

    /// The full confidentiality deny-list ADR-0022 records, in canonical form
    /// (ADR-0018). `deny_list_mirrors_adr_0022_exactly` asserts the file
    /// carries exactly this set, so file, ADR, and tests cannot drift apart
    /// silently.
    const DENY_LISTED_PATHS: &[&str] = &[
        // Local credential databases.
        "/etc/shadow",
        "/etc/shadow-",
        "/etc/gshadow",
        "/etc/gshadow-",
        // Host key material.
        "/etc/ssh/ssh_host_rsa_key",
        "/etc/ssh/ssh_host_ecdsa_key",
        "/etc/ssh/ssh_host_ed25519_key",
        "/etc/ssh/ssh_host_dsa_key",
        "/etc/krb5.keytab",
        // Root's default SSH private keys.
        "/root/.ssh/id_rsa",
        "/root/.ssh/id_ecdsa",
        "/root/.ssh/id_ed25519",
        "/root/.ssh/id_dsa",
        // The daemon's own config and credentials (#287 posture). The last
        // three were added with the shipped read catalog (#293), surfaced by
        // pointing `policy check`'s own self-reference lint at this file.
        "/etc/relay-daemon/policy.toml",
        "/etc/relay-daemon/relay-daemon.env",
        "/etc/relay-daemon/ca-bundle.pem",
        "/var/lib/relay-daemon/key.pem",
        "/var/lib/relay-daemon/cert.pem",
        "/usr/local/bin/relay-daemon",
        "/etc/systemd/system/relay-daemon.service",
        // Kernel/process memory and environment oracles.
        "/proc/kcore",
        "/dev/mem",
        "/dev/kmem",
        "/proc/self/mem",
        "/proc/self/environ",
    ];

    fn default_policy() -> Policy {
        from_toml_str(DEFAULT).expect("policy.default.toml must parse with the fail-closed loader")
    }

    fn args(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn default_file_parses_with_real_loader() {
        default_policy();
    }

    #[test]
    fn default_file_lints_clean() {
        // Same check `relay-daemon policy check --templates <shipped pack>`
        // performs: no parse error, no findings (the wildcard-allow + partial
        // deny-list is a PARTIAL shadow and must not be flagged).
        //
        // The template names are supplied because the shipped file now names
        // the shipped read catalog's Operations (issue #293): they are real
        // vocabulary on a Node with the pack installed, which is exactly the
        // Node this file is shipped to. Linting it WITHOUT them is checked
        // below — it must warn, never error, since the linter cannot see the
        // target Node's template root (ADR-0021).
        let names: Vec<String> = SHIPPED_TEMPLATE_NAMES
            .iter()
            .map(|s| s.to_string())
            .collect();
        let report = lint_with_vocabulary(DEFAULT, &names, true);
        assert!(
            report.parse_error.is_none(),
            "default file must parse cleanly; got {:?}",
            report.parse_error
        );
        assert!(
            report.findings.is_empty(),
            "default file must lint with zero findings; got {:?}",
            report.findings
        );
    }

    /// Linting the shipped file with no template root supplied: the catalog
    /// names cannot be confirmed, so they warn (naming the fix) and never
    /// error — a pipeline that lints the shipped default without pointing at
    /// the pack must not fail (ADR-0021's per-Node vocabulary, issue #292).
    #[test]
    fn default_file_without_a_template_root_warns_but_does_not_error() {
        let report = lint(DEFAULT);
        assert!(!report.has_errors(), "got {:?}", report.findings);
        assert!(
            report.has_warnings(),
            "the catalog names must at least be surfaced; got {:?}",
            report.findings
        );
        for f in &report.findings {
            assert!(
                f.message.contains("--templates"),
                "every such warning must name the fix; got {:?}",
                f.message
            );
        }
    }

    /// The catalog names the shipped default Policy allows, as a list this test
    /// module owns; `catalog.rs` binds the same names to the packaged pack, so
    /// the two files cannot drift apart silently.
    const SHIPPED_TEMPLATE_NAMES: [&str; 7] = [
        "proc.list",
        "disk.usage",
        "net.listening",
        "pkg.inventory",
        "service.status",
        "log.tail",
        "file.checksum",
    ];

    // -- Read class pre-allowed (ADR-0022) ---------------------------------

    #[test]
    fn system_facts_is_allowed_with_zero_authoring() {
        let policy = default_policy();
        assert_eq!(
            policy.evaluate(operations::SYSTEM_FACTS, &[]),
            Decision::Allow(Rule::OperationAllow {
                operation: operations::SYSTEM_FACTS.to_string()
            }),
            "a freshly enrolled Node must answer system.facts out of the box"
        );
    }

    #[test]
    fn file_read_of_innocuous_paths_is_allowed() {
        let policy = default_policy();
        for path in ["/etc/hostname", "/etc/os-release", "/var/log/syslog"] {
            assert_eq!(
                policy.evaluate(operations::FILE_READ, &args(&[path])),
                Decision::Allow(Rule::OperationAllow {
                    operation: operations::FILE_READ.to_string()
                }),
                "file.read {path} must be allowed by the shipped default"
            );
        }
    }

    // -- Confidentiality deny-list (deny-beats-allow) ----------------------

    #[test]
    fn every_deny_listed_path_is_denied_with_attribution() {
        let policy = default_policy();
        for path in DENY_LISTED_PATHS {
            let decision = policy.evaluate(operations::FILE_READ, &args(&[path]));
            assert_eq!(
                decision,
                Decision::Deny {
                    reason: format!(
                        "denied by explicit rule for operation '{}'",
                        operations::FILE_READ
                    ),
                    rule: Some(Rule::OperationDeny {
                        operation: operations::FILE_READ.to_string()
                    }),
                },
                "file.read {path} must be denied by an ATTRIBUTED deny rule \
                 (deny-beats-allow over the wildcard read allow)"
            );
        }
    }

    #[test]
    fn deny_list_mirrors_adr_0022_exactly() {
        // Set equality both ways: a path added to the file without the
        // ADR/test being updated fails here, and so does a path silently
        // dropped from the file.
        let policy = default_policy();
        let in_file: std::collections::BTreeSet<String> = policy
            .deny_rules()
            .iter()
            .filter(|r| r.name == operations::FILE_READ)
            .flat_map(|r| r.args.iter().flatten().cloned())
            .collect();
        let expected: std::collections::BTreeSet<String> =
            DENY_LISTED_PATHS.iter().map(|s| s.to_string()).collect();
        assert_eq!(
            in_file, expected,
            "policy.default.toml's file.read deny values must exactly mirror \
             the ADR-0022 deny-list pinned in this test (as amended by #293)"
        );
    }

    #[test]
    fn lexical_evasions_of_deny_listed_paths_are_denied() {
        // Non-canonical spellings never reach string matching: ADR-0018's
        // canonical-form precondition denies them outright.
        let policy = default_policy();
        for path in [
            "/etc/../etc/shadow",
            "//etc/shadow",
            "/etc/shadow/",
            "/etc/./shadow",
            "/var/lib/relay-daemon//key.pem",
        ] {
            assert!(
                matches!(
                    policy.evaluate(operations::FILE_READ, &args(&[path])),
                    Decision::Deny { .. }
                ),
                "non-canonical spelling {path} must be denied (ADR-0018)"
            );
        }
    }

    // -- Mutate class + Raw Exec stay opt-in -------------------------------

    #[test]
    fn mutate_operations_are_denied_by_default() {
        let policy = default_policy();
        for (name, invocation_args) in [
            (operations::SERVICE_RESTART, vec!["nginx"]),
            (operations::PKG_INSTALL, vec!["nginx", ""]),
        ] {
            let decision = policy.evaluate(name, &args(&invocation_args));
            assert!(
                matches!(decision, Decision::Deny { rule: None, .. }),
                "{name} must be deny-by-default (no shipped mutate allow); got {decision:?}"
            );
        }
    }

    #[test]
    fn raw_exec_is_denied_by_default() {
        let policy = default_policy();
        assert!(
            !policy.raw_exec_enabled(),
            "the shipped default must carry no [raw_exec] allow patterns"
        );
        let decision = policy.evaluate_raw_exec(&args(&["/usr/bin/uptime"]));
        assert!(
            matches!(decision, Decision::Deny { rule: None, .. }),
            "Raw Exec must be deny-by-default under the shipped default; got {decision:?}"
        );
    }
}
