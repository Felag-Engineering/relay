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
// Evaluation engine (pure methods on Policy)
// ---------------------------------------------------------------------------

impl Policy {
    /// The SHA-256 fingerprint of the raw Policy file bytes, as a 64-character
    /// lowercase-hex string. Safe to log; the Policy body is not (ADR-0002).
    pub fn fingerprint(&self) -> &str {
        &self.fingerprint
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
        Decision::Deny {
            reason: format!("deny-by-default: no allow rule for operation '{operation_name}'"),
            rule: None,
        }
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
}
