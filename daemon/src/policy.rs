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
//!   when the full `argv.join(" ")` matches an allow regex and no deny regex
//!   matches any element or the joined command.
//!
//! **Not yet wired**: this module provides a pure evaluation API. Task-dispatch
//! wiring lands in a later v0.0.3 issue.

use std::fmt::Write as _;
use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::Path;

use regex::Regex;
use serde::Deserialize;

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
/// `allow` patterns are tested against `argv.join(" ")`.
/// `deny` patterns are tested against `argv.join(" ")` and each element.
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
    #[error("invalid regex pattern {pattern:?}: {source}")]
    InvalidRegex {
        pattern: String,
        #[source]
        source: regex::Error,
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

    let raw_allow = compile_regexes(file.raw_exec.allow)?;
    let raw_deny = compile_regexes(file.raw_exec.deny)?;

    Ok(Policy {
        operations: file.operation,
        denies: file.deny,
        raw_allow,
        raw_deny,
        fingerprint: policy_fingerprint(s.as_bytes()),
    })
}

fn compile_regexes(patterns: Vec<String>) -> Result<Vec<CompiledRe>, PolicyError> {
    patterns
        .into_iter()
        .map(|pattern| {
            Regex::new(&pattern)
                .map(|re| CompiledRe {
                    pattern: pattern.clone(),
                    re,
                })
                .map_err(|source| PolicyError::InvalidRegex { pattern, source })
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Loader (filesystem + fail-closed permission gate)
// ---------------------------------------------------------------------------

/// Load and compile a Policy from the file at `path`.
///
/// **Local only** — takes a `&Path`; there is no network branch.
///
/// Fail-closed on permission checks (ADR-0002):
/// 1. Refuses to load if the file has group- or world-write bits set (`mode &
///    0o022 != 0`). Logged via `tracing::error!` with path and mode; file
///    contents are never logged.
/// 2. Refuses to load if the file owner is neither root (uid 0) nor the
///    daemon's effective uid (`rustix::process::geteuid()`). The euid branch
///    allows the check to pass on a non-root CI runner while remaining
///    more-restrictive than the floor requirement (group/world-write only).
///
/// TOCTOU note: the metadata check and `read_to_string` are not atomic. Full
/// hardening (open-then-fstat, directory-writability, symlink/FIFO checks) is
/// deferred as future work.
pub fn load_policy(path: &Path) -> Result<Policy, PolicyError> {
    let meta = fs::metadata(path)?;
    let mode = meta.mode() & 0o777;

    // Permission floor: group- or world-write means the file can be modified
    // by an attacker with group membership, which would let them escalate
    // privileges through the Policy. Fail closed.
    if mode & 0o022 != 0 {
        tracing::error!(
            path = %path.display(),
            mode = format!("{mode:#o}"),
            "policy file is group/world-writable; refusing to load (fail closed)"
        );
        return Err(PolicyError::InsecurePermissions { mode });
    }

    // Owner check: accept uid==0 (root) or uid==geteuid() (daemon's own euid).
    // Allowing the daemon's euid lets non-root deployments and CI runners pass
    // the check while still refusing files owned by arbitrary third parties.
    let file_uid = meta.uid();
    let daemon_euid = rustix::process::geteuid().as_raw();
    if file_uid != 0 && file_uid != daemon_euid {
        tracing::error!(
            path = %path.display(),
            uid = file_uid,
            "policy file is not owned by root or the daemon euid; refusing to load (fail closed)"
        );
        return Err(PolicyError::InsecureOwner { uid: file_uid });
    }

    let contents = fs::read_to_string(path)?;
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
/// 3. Unknown Operation names in `[[operation]]` and `[[deny]]` (`Error`),
///    checked against the proto Operation vocabulary
///    (`crate::operations::risk_class`). An unknown name in `[[deny]]` is
///    flagged as an `Error` (not a `Warning`) for typo-safety: a defensive
///    deny for an operation this daemon doesn't implement is indistinguishable
///    from a typo, and the more-restrictive choice is to fail the pipeline
///    visibly rather than silently accept a no-op deny rule.
/// 4. Allow rules fully shadowed by a `[[deny]]` rule of the same name
///    (`Warning`) — see [`allow_is_shadowed_by_deny`].
///
/// **Known limitations** (documented, not attempted):
/// - Shadowing by the *union* of multiple deny rules (set-cover) is not
///   detected; only single-deny-rule shadowing is. This is conservative — it
///   may miss a shadowed allow, but never flags one that isn't actually dead.
/// - `[raw_exec]` allow-vs-deny regex shadowing is not attempted: regex
///   language subset containment is undecidable in general.
pub fn lint(toml: &str) -> LintReport {
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

    lint_raw_exec_regexes(&file.raw_exec.allow, "allow", &mut findings);
    lint_raw_exec_regexes(&file.raw_exec.deny, "deny", &mut findings);

    for (i, op) in file.operation.iter().enumerate() {
        if operations::risk_class(&op.name).is_none() {
            findings.push(LintFinding {
                severity: LintSeverity::Error,
                location: format!("[[operation]] #{i} (name={:?})", op.name),
                message: format!("unknown Operation name {:?}", op.name),
            });
        }
    }

    for (i, deny) in file.deny.iter().enumerate() {
        if operations::risk_class(&deny.name).is_none() {
            findings.push(LintFinding {
                severity: LintSeverity::Error,
                location: format!("[[deny]] #{i} (name={:?})", deny.name),
                message: format!("unknown Operation name {:?}", deny.name),
            });
        }
    }

    lint_shadowed_allows(&file.operation, &file.deny, &mut findings);

    LintReport {
        parse_error: None,
        findings,
    }
}

/// Checks every pattern in a `[raw_exec]` allow/deny list for regex validity.
fn lint_raw_exec_regexes(patterns: &[String], section: &str, findings: &mut Vec<LintFinding>) {
    for (i, pattern) in patterns.iter().enumerate() {
        if let Err(e) = Regex::new(pattern) {
            findings.push(LintFinding {
                severity: LintSeverity::Error,
                location: format!("[raw_exec].{section}[{i}]"),
                message: format!("invalid regex {pattern:?}: {e}"),
            });
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
    /// Semantics (ADR-0001, ADR-0002):
    /// - No shell is invoked; `argv` is the exact argument vector the executor
    ///   will pass to `execv`. The join here is only for regex matching.
    /// - Allow patterns are tested against `argv.join(" ")` (the canonical
    ///   joined form).
    /// - Deny patterns are tested against `argv.join(" ")` AND each individual
    ///   `argv[i]`. This catches deny patterns that are substrings of elements
    ///   (e.g. `--force`) regardless of their position.
    /// - Deny pass is evaluated first (deny-beats-allow).
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

        // --- Deny pass (deny-beats-allow, evaluated first) ------------------
        // Test deny patterns against the joined command AND each element.
        for compiled in &self.raw_deny {
            if compiled.re.is_match(&joined) || argv.iter().any(|arg| compiled.re.is_match(arg)) {
                return Decision::Deny {
                    reason: format!("raw exec denied by pattern {:?}", compiled.pattern),
                    rule: Some(Rule::RawExecDeny {
                        pattern: compiled.pattern.clone(),
                    }),
                };
            }
        }

        // --- Allow pass -----------------------------------------------------
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
    // 5. Loader permission checks
    // -----------------------------------------------------------------------

    #[test]
    fn loader_rejects_group_writable() {
        let tmp = TempFile::new("group-writable", FIXTURE.as_bytes(), 0o664);
        let result = load_policy(tmp.path());
        assert!(
            matches!(result, Err(PolicyError::InsecurePermissions { .. })),
            "group-writable policy file must be rejected; got {result:?}"
        );
    }

    #[test]
    fn loader_rejects_world_writable() {
        let tmp = TempFile::new("world-writable", FIXTURE.as_bytes(), 0o666);
        let result = load_policy(tmp.path());
        assert!(
            matches!(result, Err(PolicyError::InsecurePermissions { .. })),
            "world-writable policy file must be rejected; got {result:?}"
        );
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
        assert_eq!(finding.severity, LintSeverity::Error);
        assert!(finding.location.contains("[[operation]] #0"));
        assert!(finding.message.contains("pkg.remove"));
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
        assert_eq!(finding.severity, LintSeverity::Error);
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
/// asymmetry (deny is tested against the joined command OR any element;
/// allow is tested against the joined command only — policy.rs:749-771).
///
/// Test-only: this module never touches `evaluate_raw_exec`, `from_toml_str`,
/// `compile_regexes`, the loader, or the lint code above. It asserts current
/// behavior (green rows, some of which document accepted footguns rather than
/// bugs) plus one genuine deny-evasion bypass, committed as a standalone
/// `#[ignore]`d test tagged with the filed finding (#227) rather than fixed
/// here — closing it would be a Policy-evaluation semantics change requiring
/// an ADR (ADR-0001, ADR-0002).
///
/// `redteam_cases()` is the single extension point later red-team issues
/// (e.g. argv-smuggling/encoding) append rows to.
#[cfg(test)]
mod raw_exec_redteam {
    use super::*;

    /// Build an argv `Vec<String>` from string-literal elements. Mirrors the
    /// `args` helper in `mod tests`, renamed to Raw Exec vocabulary.
    fn argv(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    /// Coarse red-team classification of a Raw Exec `Decision`: does the
    /// command run, is it denied by a specific rule, or denied by default.
    /// Deliberately coarser than `Decision` itself — the exact `reason`
    /// string is owned by the golden-reason tests in `mod tests`, not this
    /// harness.
    #[derive(Debug, Clone, Copy)]
    enum Expect {
        /// `Decision::Allow(_)`.
        Allow,
        /// `Decision::Deny` with a specific `Rule::RawExecDeny` attributed.
        DenyByPattern,
        /// `Decision::Deny` with `rule: None` (no allow pattern matched).
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
                expect: Expect::DenyByDefault,
                note: "argv[0] is the literal /bin/sh (no shell is invoked — ADR-0001), so the joined form starts with /bin/sh and the anchored ^ fails",
            },
            Case {
                name: "unanchored_allow_admits_foreign_argv0",
                policy_toml: "[raw_exec]\nallow = [\"/usr/bin/systemctl (status|restart) nginx\"]\n",
                argv: &["/bin/rm", "-rf", "/var/log", "&&", "/usr/bin/systemctl", "restart", "nginx"],
                expect: Expect::Allow,
                note: "documented-intended (#214): an operator's unanchored 'obvious' pattern is only ever a substring match anywhere in the joined command, so it admits a hostile argv whose real argv[0] is /bin/rm; RE2-style substring semantics are by design (module doc), and the mitigation is operator anchoring (policy.example.toml:94), never an engine change",
            },
            Case {
                name: "anchored_allow_blocks_same_foreign_argv0",
                policy_toml: "[raw_exec]\nallow = [\"^/usr/bin/systemctl (status|restart) [A-Za-z0-9@._-]+$\"]\n",
                argv: &["/bin/rm", "-rf", "/var/log", "&&", "/usr/bin/systemctl", "restart", "nginx"],
                expect: Expect::DenyByDefault,
                note: "paired contrast with unanchored_allow_admits_foreign_argv0: the identical hostile argv is refused once the allow pattern is anchored, proving anchoring is the mitigation",
            },
            // --- Axis 2: argv-join ambiguity ---------------------------------
            Case {
                name: "join_collapse_two_args_same_decision_two_elements",
                policy_toml: "[raw_exec]\nallow = [\"^/usr/bin/systemctl (status|restart) [A-Za-z0-9@._-]+$\"]\n",
                argv: &["/usr/bin/systemctl", "restart", "nginx"],
                expect: Expect::Allow,
                note: "documented-intended (#214): three-element argv, the intended shape; paired with join_collapse_two_args_same_decision_merged_element to show the joined gate cannot distinguish this from a different real argv",
            },
            Case {
                name: "join_collapse_two_args_same_decision_merged_element",
                policy_toml: "[raw_exec]\nallow = [\"^/usr/bin/systemctl (status|restart) [A-Za-z0-9@._-]+$\"]\n",
                argv: &["/usr/bin/systemctl", "restart nginx"],
                expect: Expect::Allow,
                note: "documented-intended (#214): the second element carries the space that used to separate two argv elements; argv.join(\" \") (policy.rs:749) is blind to the element boundary, so this two-element argv gets the identical decision as join_collapse_two_args_same_decision_two_elements though the real argv differs",
            },
            Case {
                name: "join_single_element_whole_command",
                policy_toml: "[raw_exec]\nallow = [\"^/usr/bin/systemctl (status|restart) [A-Za-z0-9@._-]+$\"]\n",
                argv: &["/usr/bin/systemctl restart nginx"],
                expect: Expect::Allow,
                note: "documented-intended (#214): sharpest 'what the gate cannot see' — a single argv element containing the whole command joins to the same string and is allowed, though execv's real target would be a literal filename containing spaces (ENOENT); no shell re-parses argv (ADR-0001), so the non-injective join is a legibility limit, not an exploitable escalation under argv exec",
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
        ]
    }

    #[test]
    fn raw_exec_redteam_table() {
        for case in redteam_cases() {
            let policy = from_toml_str(case.policy_toml)
                .unwrap_or_else(|e| panic!("case {}: policy TOML failed to parse: {e}", case.name));
            let decision = policy.evaluate_raw_exec(&argv(case.argv));
            let matched = matches!(
                (case.expect, &decision),
                (Expect::Allow, Decision::Allow(_))
                    | (
                        Expect::DenyByPattern,
                        Decision::Deny {
                            rule: Some(Rule::RawExecDeny { .. }),
                            ..
                        },
                    )
                    | (Expect::DenyByDefault, Decision::Deny { rule: None, .. })
            );
            assert!(
                matched,
                "case {}: {}: expected {:?}, got {decision:?}",
                case.name, case.note, case.expect
            );
        }
    }

    // -------------------------------------------------------------------
    // Cross-axis (Axis 2 x Axis 3) — genuine bypass, filed as finding #227
    // -------------------------------------------------------------------
    //
    // A deny rule can be evaded by merging the denied token into an
    // adjacent argv element: an anchored per-element deny (`^--force$`)
    // only ever sees the exact element `--force`, so appending anything to
    // that element ("--force x") slips past both the joined-string disjunct
    // and the per-element disjunct of the deny pass, while an anchored
    // allow pattern written for the merged form still matches the joined
    // command. This defeats a deny rule outright — more severe than the
    // unanchored-allow footgun above, which only ever over-widens an allow.
    // Committed here as a known, tracked bypass rather than silently fixed:
    // closing it needs a Policy-evaluation semantics change (e.g.
    // argv-structure-aware or normalized per-element deny matching), which
    // is an ADR-gated decision (ADR-0001, ADR-0002), not a test-only change.
    #[test]
    #[ignore = "finding #227: anchored per-element deny (^--force$) evaded by merging the denied token into an adjacent argv element; desired=Deny, current=Allow; fixing needs a Policy-semantics change gated on an ADR (ADR-0001/0002) — do NOT change evaluate_raw_exec here"]
    fn deny_anchored_per_element_evaded_by_element_merge() {
        let policy = from_toml_str(
            "[raw_exec]\nallow = [\"^systemctl restart nginx --force x$\"]\ndeny = [\"^--force$\"]\n",
        )
        .expect("policy must parse");
        let decision =
            policy.evaluate_raw_exec(&argv(&["systemctl", "restart", "nginx", "--force x"]));
        assert!(
            matches!(decision, Decision::Deny { .. }),
            "anchored per-element deny ^--force$ must not be evadable by merging the denied \
             token into an adjacent argv element (#227); got {decision:?}"
        );
    }
}
