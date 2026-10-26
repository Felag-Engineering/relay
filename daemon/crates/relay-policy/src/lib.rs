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
//! Every verdict comes from one function, [`Policy::decide`], over a typed
//! [`Request`]; it returns an [`Explained`] naming the pass and rule that
//! decided. Raw Exec runs only with the [`RawExecPermit`] that `decide` mints
//! on Allow.

#![cfg_attr(not(test), forbid(unsafe_code))]

use std::fmt;
use std::fmt::Write as _;
use std::fs;
use std::io::Read;
use std::ops::Range;
use std::os::unix::fs::MetadataExt as _;
use std::path::Path;

use regex::Regex;
use serde::Deserialize;

use crate::hardened_open::{open_hardened, HardenedRejection};
use crate::model::{compile_allow_args, compile_deny_args, CompiledAllow, CompiledDeny, DenyScope};
use crate::natives as operations;

// Crate-private aliases so the `crate::x::...` paths in the moved files resolve
// unchanged.
use crate as policy;
pub(crate) use relay_log as log_field;
pub(crate) use relay_proto as gen;
#[cfg(test)]
pub(crate) use relay_test_support as test_support;

pub mod decision_log;
pub mod hardened_open;
mod model;
pub mod natives;

pub use model::{Explained, MatchedOn, Pass, Request, RuleRef, RuleSection};

#[cfg(feature = "ban-probe")]
#[allow(dead_code)]
#[path = "../ban_probe.rs"]
mod ban_probe;

// ---------------------------------------------------------------------------
// On-disk serde model
// ---------------------------------------------------------------------------

/// Top-level Policy file as deserialized from TOML.
///
/// Every on-disk struct rejects an unknown key, so a mistyped table such as
/// `[[denny]]` is a parse error and the whole Policy is deny-all, never an
/// empty rule that leaves an allow standing.
///
/// All fields default to empty so a minimal file (e.g. just `[raw_exec]`) is
/// valid. The `Default` derive is required because the containing struct uses
/// `#[serde(default)]` on nested-struct fields.
#[derive(Debug, Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct PolicyFile {
    #[serde(default)]
    operation: Vec<toml::Spanned<OperationRuleRaw>>,
    #[serde(default)]
    deny: Vec<toml::Spanned<DenyRuleRaw>>,
    #[serde(default)]
    raw_exec: RawExecRaw,
}

/// One `[[operation]]` allow block from the Policy file.
///
/// `allowed_args[i]` is the set of permitted values at argument position `i`.
/// `"*"` at any inner position matches any value (wildcard). An empty outer
/// list means the operation is allowed with zero arguments.
#[derive(Debug, Deserialize, Default)]
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
struct RawExecRaw {
    #[serde(default)]
    allow: Vec<toml::Spanned<String>>,
    #[serde(default)]
    deny: Vec<toml::Spanned<String>>,
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
    at: RuleRef,
}

/// The compiled, in-memory Policy derived from a `PolicyFile`.
///
/// All regex patterns are compiled once at load time; evaluation is pure.
#[derive(Debug)]
pub struct Policy {
    operations: Vec<CompiledAllow>,
    denies: Vec<CompiledDeny>,
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

/// Proof that [`Policy::decide`] allowed one exact Raw Exec argv.
///
/// Running Raw Exec requires one, and only `decide` mints one — on Allow, for
/// the argv it evaluated — so the argv that runs is by construction the argv
/// Policy allowed, and a call that skipped the gate does not compile. It has no
/// constructor, no `Clone`, no `Default` and no deserializer. `Debug` prints
/// the argument count only: an argv may hold a secret.
///
/// The positive control and both negative cases name the type by the same path,
/// so a typo in it fails the first and cannot make the others pass:
///
/// ```
/// let policy = relay_policy::from_toml_str("[raw_exec]\nallow = [\"^/bin/true$\"]\n").unwrap();
/// let argv = vec!["/bin/true".to_string()];
/// let permit: relay_policy::RawExecPermit = policy
///     .decide(&relay_policy::Request::RawExec { argv: &argv })
///     .raw_exec_permit
///     .expect("allowed");
/// assert_eq!(permit.into_argv(), argv);
/// ```
///
/// ```compile_fail
/// let _ = relay_policy::RawExecPermit { argv: vec![String::new()] };
/// ```
///
/// ```compile_fail
/// let _ = <relay_policy::RawExecPermit as Default>::default();
/// ```
#[must_use]
pub struct RawExecPermit {
    argv: Vec<String>,
}

impl RawExecPermit {
    /// The argv Policy allowed, to execute.
    pub fn into_argv(self) -> Vec<String> {
        self.argv
    }
}

impl fmt::Debug for RawExecPermit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "RawExecPermit {{ argc: {} }}", self.argv.len())
    }
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

    /// A Policy fragment is a symlink; the daemon refuses to start.
    #[error("Policy fragment {name:?} is a symlink; refusing to start (fail closed)")]
    FragmentSymlink { name: String },

    /// A Policy fragment is not a regular file; the daemon refuses to start.
    #[error("Policy fragment {name:?} is not a regular file; refusing to start (fail closed)")]
    FragmentNotRegularFile { name: String },

    /// A Policy fragment is group- or world-writable; the daemon refuses to
    /// start.
    #[error("Policy fragment {name:?} is group/world-writable (mode {mode:#o}); refusing to start (fail closed)")]
    FragmentInsecurePermissions { name: String, mode: u32 },

    /// A Policy fragment is owned by neither root nor the daemon's euid; the
    /// daemon refuses to start.
    #[error("Policy fragment {name:?} is owned by uid {uid}, not root or the daemon euid; refusing to start (fail closed)")]
    FragmentInsecureOwner { name: String, uid: u32 },

    /// A Policy fragment could not be opened or read (non-UTF-8 content
    /// included). The whole Policy is deny-all.
    #[error("Policy fragment {name:?} could not be read: {source}")]
    FragmentUnreadable {
        name: String,
        #[source]
        source: std::io::Error,
    },

    /// A Policy fragment failed to parse or compile. The whole Policy is
    /// deny-all.
    #[error("Policy fragment {name:?} is invalid: {source}")]
    FragmentInvalid {
        name: String,
        #[source]
        source: Box<PolicyError>,
    },

    /// A Policy fragment's file name is not UTF-8. The whole Policy is
    /// deny-all.
    #[error("a Policy fragment's file name is not UTF-8: {name:?}")]
    FragmentName { name: std::ffi::OsString },

    /// The Policy directory is a symlink; the daemon refuses to start.
    #[error("the Policy directory is a symlink; refusing to start (fail closed)")]
    PolicyDirectorySymlink,

    /// The Policy directory is not a directory; the daemon refuses to start.
    #[error("the Policy directory is not a directory; refusing to start (fail closed)")]
    PolicyDirectoryNotADirectory,

    /// The Policy directory is group- or world-writable; the daemon refuses to
    /// start. Whoever can write it can remove a root-owned deny fragment.
    #[error("the Policy directory is group/world-writable (mode {mode:#o}); refusing to start (fail closed)")]
    PolicyDirectoryInsecurePermissions { mode: u32 },

    /// The Policy directory is owned by neither root nor the daemon's euid; the
    /// daemon refuses to start.
    #[error("the Policy directory is owned by uid {uid}, not root or the daemon euid; refusing to start (fail closed)")]
    PolicyDirectoryInsecureOwner { uid: u32 },

    /// The Policy directory could not be listed. The whole Policy is deny-all.
    #[error("the Policy directory could not be read: {0}")]
    PolicyDirectoryIo(#[source] std::io::Error),
}

impl PolicyError {
    /// Whether the daemon must refuse to start on this error rather than run
    /// deny-all: a fragment that is a symlink, not a regular file or insecure,
    /// and an insecure Policy directory. Every Policy-file error, and a
    /// fragment or directory that merely cannot be read or parsed, leaves the
    /// daemon running deny-all (fail closed). The match has no wildcard arm, so
    /// a new variant has to be classified here.
    pub fn refuses_start(&self) -> bool {
        match self {
            PolicyError::FragmentSymlink { .. }
            | PolicyError::FragmentNotRegularFile { .. }
            | PolicyError::FragmentInsecurePermissions { .. }
            | PolicyError::FragmentInsecureOwner { .. }
            | PolicyError::PolicyDirectorySymlink
            | PolicyError::PolicyDirectoryNotADirectory
            | PolicyError::PolicyDirectoryInsecurePermissions { .. }
            | PolicyError::PolicyDirectoryInsecureOwner { .. } => true,
            PolicyError::InsecurePermissions { .. }
            | PolicyError::InsecureOwner { .. }
            | PolicyError::SymlinkPath
            | PolicyError::NotRegularFile
            | PolicyError::Io(_)
            | PolicyError::Parse(_)
            | PolicyError::InvalidRegex { .. }
            | PolicyError::FragmentUnreadable { .. }
            | PolicyError::FragmentInvalid { .. }
            | PolicyError::FragmentName { .. }
            | PolicyError::PolicyDirectoryIo(_) => false,
        }
    }
}

// ---------------------------------------------------------------------------
// Parse API (pure, no filesystem access)
// ---------------------------------------------------------------------------

/// The Policy file's label in the set fingerprint, whatever its configured name.
const POLICY_FILE_LABEL: &str = "policy.toml";

/// Domain tag opening the set fingerprint's stream, so it cannot collide with
/// the SHA-256 of a lone Policy file.
const FINGERPRINT_DOMAIN: &[u8] = b"relay-policy-set-v1\n";

/// One Policy fragment: its file name in the Policy directory and its text.
#[derive(Debug, Clone)]
pub struct Fragment {
    pub name: String,
    pub text: String,
}

/// Compute the Policy fingerprint of a Policy file and its fragments.
///
/// Returns a 64-character lowercase-hex string with no prefix — the same
/// format used for cert fingerprints in `transport.go`. `fragments` must
/// already be in composition order (file name, byte order).
///
/// **Canonical form:** the fingerprint is over the **raw bytes**, not a
/// canonicalized or compiled form. Consequences:
/// - Identical bytes → identical fingerprint (strict byte-identity).
/// - Cosmetic edits (whitespace, comments, key reorder) **change** the
///   fingerprint — intended; policy-as-code pushes the same files everywhere,
///   so byte-identity is exactly the drift signal an operator needs.
/// - An empty / deny-all Policy produces the SHA-256 of the empty string:
///   `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`.
///
/// **No fragment** (the Policy directory is absent or empty): the SHA-256 of
/// the Policy file's raw bytes alone, so a Node without fragments reports what
/// `sha256sum` of its Policy file prints.
///
/// **One or more fragments:** the SHA-256 of a stream that opens with
/// [`FINGERPRINT_DOMAIN`] and then holds one record per source, the Policy file
/// first, then each fragment in order:
/// `<label> NUL <byte length in decimal ASCII> LF <raw bytes>`. The label is
/// `policy.toml` for the Policy file and `policy.d/<file name>` for a
/// fragment. Records are length-prefixed and a file name cannot hold NUL, so
/// the encoding is injective; it cannot collide with the no-fragment form
/// because a parsed Policy is valid TOML, which cannot hold NUL, and the stream
/// always does. Fragment file names are part of the fingerprint, so a stray or
/// renamed file shows as drift; the Policy file's name and the directory paths
/// are not.
///
/// The TOML serializer is excluded from the daemon binary for musl size
/// (ADR-0007); re-adding it plus a stable field-ordering round-trip for
/// canonicalization adds weight on a security-adjacent path for no gain.
fn policy_fingerprint(policy_file: &str, fragments: &[&Fragment]) -> String {
    let digest = if fragments.is_empty() {
        ring::digest::digest(&ring::digest::SHA256, policy_file.as_bytes())
    } else {
        let mut ctx = ring::digest::Context::new(&ring::digest::SHA256);
        ctx.update(FINGERPRINT_DOMAIN);
        let mut record = |label: &str, bytes: &[u8]| {
            ctx.update(label.as_bytes());
            ctx.update(b"\0");
            ctx.update(bytes.len().to_string().as_bytes());
            ctx.update(b"\n");
            ctx.update(bytes);
        };
        record(POLICY_FILE_LABEL, policy_file.as_bytes());
        for fragment in fragments {
            record(
                &format!("{POLICY_DIR_NAME}/{}", fragment.name),
                fragment.text.as_bytes(),
            );
        }
        ctx.finish()
    };
    let mut s = String::with_capacity(64);
    for b in digest.as_ref() {
        write!(&mut s, "{b:02x}").expect("write to String is infallible");
    }
    s
}

/// Parse and compile a Policy from a TOML string.
///
/// Pure function — no filesystem access. Used directly by tests (which supply
/// the fixture via `include_str!`). It is [`compose`] with no fragments.
///
/// Fails closed: a malformed regex in `[raw_exec]` returns `Err(InvalidRegex)`
/// rather than silently skipping the pattern.
pub fn from_toml_str(s: &str) -> Result<Policy, PolicyError> {
    compose(s, &[])
}

/// Parse and compile one Policy file and its fragments into ONE [`Policy`]
/// with one fingerprint.
///
/// Pure function — no filesystem access. The rules of each of the four lists
/// (`[[operation]]`, `[[deny]]`, `[raw_exec].allow`, `[raw_exec].deny`) are
/// concatenated in composition order: the Policy file, then the fragments by
/// file name. Deny-beats-allow across files needs no logic of its own:
/// [`Policy::decide`] runs its deny pass over the whole composed deny list
/// before any allow (invariant 3). `fragments` are sorted here, so no caller
/// can get the order wrong and the daemon and `policy check` agree.
///
/// A fragment error is [`PolicyError::FragmentInvalid`] and names the
/// fragment; an error in the Policy file keeps its own variants.
pub fn compose(policy_file: &str, fragments: &[Fragment]) -> Result<Policy, PolicyError> {
    let ordered = in_composition_order(fragments);

    let mut parts = vec![compile_source(toml::from_str(policy_file)?, policy_file)?];
    for fragment in &ordered {
        let invalid = |source: PolicyError| PolicyError::FragmentInvalid {
            name: fragment.name.clone(),
            source: Box::new(source),
        };
        let parsed: PolicyFile = toml::from_str(&fragment.text).map_err(|e| invalid(e.into()))?;
        parts.push(compile_source(parsed, &fragment.text).map_err(invalid)?);
    }
    Ok(assemble(parts, policy_fingerprint(policy_file, &ordered)))
}

/// References to `fragments` in composition order: file name, byte order.
fn in_composition_order(fragments: &[Fragment]) -> Vec<&Fragment> {
    let mut ordered: Vec<&Fragment> = fragments.iter().collect();
    ordered.sort_by(|a, b| a.name.cmp(&b.name));
    ordered
}

/// The 1-based source line a TOML span starts on, or `None` when the parser
/// gave no usable span. Counts bytes, so it never slices a `str`.
fn line_of(src: &str, span: Range<usize>) -> Option<usize> {
    if span.start >= span.end || span.end > src.len() {
        return None;
    }
    let newlines = src.as_bytes()[..span.start]
        .iter()
        .filter(|&&b| b == b'\n')
        .count();
    Some(newlines + 1)
}

/// The compiled rules of one source (the Policy file or one fragment).
struct Parts {
    operations: Vec<CompiledAllow>,
    denies: Vec<CompiledDeny>,
    raw_allow: Vec<CompiledRe>,
    raw_deny: Vec<CompiledRe>,
}

/// Compiles the parsed file into rules, recording where each sits in `source`
/// (the text `file` was parsed from). Indices are within `source`;
/// [`assemble`] renumbers them.
fn compile_source(file: PolicyFile, source: &str) -> Result<Parts, PolicyError> {
    let raw_allow = compile_regexes(
        file.raw_exec.allow,
        RuleSection::RawExecAllow,
        source,
        compile_allow_regex,
    )
    .map_err(with_allow_regex_hint)?;
    let raw_deny = compile_regexes(
        file.raw_exec.deny,
        RuleSection::RawExecDeny,
        source,
        compile_deny_regex,
    )?;

    let operations = file
        .operation
        .into_iter()
        .enumerate()
        .map(|(index, spanned)| {
            let at = RuleRef {
                section: RuleSection::Operation,
                index,
                line: line_of(source, spanned.span()),
            };
            let rule = spanned.into_inner();
            CompiledAllow {
                name: rule.name,
                matchers: compile_allow_args(&rule.allowed_args),
                source_args: rule.allowed_args,
                at,
            }
        })
        .collect();
    let denies = file
        .deny
        .into_iter()
        .enumerate()
        .map(|(index, spanned)| {
            let at = RuleRef {
                section: RuleSection::Deny,
                index,
                line: line_of(source, spanned.span()),
            };
            let rule = spanned.into_inner();
            CompiledDeny {
                name: rule.name,
                scope: compile_deny_args(&rule.args),
                source_args: rule.args,
                at,
            }
        })
        .collect();

    Ok(Parts {
        operations,
        denies,
        raw_allow,
        raw_deny,
    })
}

/// Concatenates `parts` (the Policy file's first) into one [`Policy`].
///
/// Each rule's [`RuleRef::index`] becomes its position in the composed section,
/// which is what the `PolicySnapshot` lists use; a rule from any part but the
/// first (a fragment) loses its line, because a line number without a file
/// name would mislead.
fn assemble(parts: Vec<Parts>, fingerprint: String) -> Policy {
    let mut policy = Policy {
        operations: Vec::new(),
        denies: Vec::new(),
        raw_allow: Vec::new(),
        raw_deny: Vec::new(),
        fingerprint,
    };
    for (source, part) in parts.into_iter().enumerate() {
        let from_fragment = source > 0;
        let place = |at: &mut RuleRef, index: usize| {
            at.index = index;
            if from_fragment {
                at.line = None;
            }
        };
        for mut rule in part.operations {
            place(&mut rule.at, policy.operations.len());
            policy.operations.push(rule);
        }
        for mut rule in part.denies {
            place(&mut rule.at, policy.denies.len());
            policy.denies.push(rule);
        }
        for mut rule in part.raw_allow {
            place(&mut rule.at, policy.raw_allow.len());
            policy.raw_allow.push(rule);
        }
        for mut rule in part.raw_deny {
            place(&mut rule.at, policy.raw_deny.len());
            policy.raw_deny.push(rule);
        }
    }
    policy
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
    patterns: Vec<toml::Spanned<String>>,
    section: RuleSection,
    source: &str,
    compile: fn(&str) -> Result<Regex, regex::Error>,
) -> Result<Vec<CompiledRe>, PolicyError> {
    patterns
        .into_iter()
        .enumerate()
        .map(|(index, spanned)| {
            let at = RuleRef {
                section,
                index,
                line: line_of(source, spanned.span()),
            };
            let pattern = spanned.into_inner();
            compile(&pattern)
                .map(|re| CompiledRe {
                    pattern: pattern.clone(),
                    re,
                    at,
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

/// The Policy directory's name beside the Policy file: the daemon reads
/// fragments from `<parent of the Policy file>/policy.d`.
pub const POLICY_DIR_NAME: &str = "policy.d";

/// Load and compile a Policy from the file at `path` and the fragments in the
/// directory `dir`, composed into one [`Policy`] by [`compose`].
///
/// **Local only** — takes two `&Path`s; there is no network branch. The Policy
/// is read once, here; nothing re-reads it, so a change to the file or to a
/// fragment is applied by restarting the daemon.
///
/// **The Policy file** is opened exactly once and validated by `fstat` on that
/// *open descriptor*, and the bytes are read from the same descriptor. This
/// closes the metadata/read TOCTOU race that a path-based check-then-read has —
/// the bytes validated are always the bytes loaded. Fail-closed checks
/// (ADR-0002), in order, performed by the shared [`open_hardened`] (the same
/// open Template Operation files use):
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
/// **The Policy directory** `dir` holds the fragments; every entry in it is a
/// fragment (no suffix filter, no recursion), so nothing in it is silently
/// ignored. An absent directory means no fragments. Each fragment is opened
/// through the same [`open_hardened`], so the same four checks apply to it.
/// The directory itself is checked by path: it must be a real directory (not a
/// symlink), not group- or world-writable and owned by root or the daemon's
/// euid, because whoever can write it can delete a root-owned deny fragment.
///
/// **Two kinds of failure.** A fragment that is a symlink, not a regular file,
/// group- or world-writable or owned by a third party, and an insecure
/// directory, return an error whose [`PolicyError::refuses_start`] is `true`:
/// the daemon exits non-zero. A fragment that cannot be read or parsed, a
/// directory that cannot be listed, and every Policy-file failure, return an
/// error for which it is `false`: the caller runs deny-all. A refusal anywhere
/// wins over any deny-all error — the whole directory is scanned first — so a
/// loud failure is never masked by a quiet one. There is no partial load and no
/// last-known-good.
///
/// **Residual (documented, not closed here):** parent-directory writability.
/// `O_NOFOLLOW` only guards the final path component — a rename-swap of the
/// Policy file within an attacker-writable *parent* directory remains
/// possible even though the file itself is root-owned and mode-correct. The
/// directory checks are by path, so the same rename-swap class applies to
/// `dir`. This is mitigated operationally by requiring both to live in a
/// root-owned directory (e.g. `/etc/relay-daemon/`); fully closing it would
/// require an `openat`-style walk from a validated directory descriptor, which
/// is out of scope here.
pub fn load_policy(path: &Path, dir: &Path) -> Result<Policy, PolicyError> {
    let (fragments, directory_error) = match read_policy_directory(dir) {
        Ok(fragments) => (fragments, None),
        Err(e) if e.refuses_start() => return Err(e),
        Err(e) => (Vec::new(), Some(e)),
    };
    let text = read_policy_file(path)?;
    if let Some(e) = directory_error {
        return Err(e);
    }
    compose(&text, &fragments)
}

/// Opens, validates and reads the Policy file at `path`.
fn read_policy_file(path: &Path) -> Result<String, PolicyError> {
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
    Ok(contents)
}

/// Opens, validates and reads the Policy fragment at `path`, named `name` in
/// errors. The refusals are fragment-worded [`PolicyError`]s for which
/// [`PolicyError::refuses_start`] holds; the caller logs them once.
fn read_fragment(path: &Path, name: &str) -> Result<String, PolicyError> {
    let unreadable = |source: std::io::Error| PolicyError::FragmentUnreadable {
        name: name.to_string(),
        source,
    };
    let (mut file, _meta) = open_hardened(path).map_err(|rejection| match rejection {
        HardenedRejection::Symlink => PolicyError::FragmentSymlink {
            name: name.to_string(),
        },
        HardenedRejection::NotRegularFile => PolicyError::FragmentNotRegularFile {
            name: name.to_string(),
        },
        HardenedRejection::InsecurePermissions { mode } => {
            PolicyError::FragmentInsecurePermissions {
                name: name.to_string(),
                mode,
            }
        }
        HardenedRejection::InsecureOwner { uid } => PolicyError::FragmentInsecureOwner {
            name: name.to_string(),
            uid,
        },
        HardenedRejection::Io(e) => unreadable(e),
    })?;

    // Read from the SAME descriptor that was validated above.
    let mut contents = String::new();
    file.read_to_string(&mut contents).map_err(unreadable)?;
    Ok(contents)
}

/// Reads every fragment in the Policy directory `dir`, sorted by file name
/// ([`compose`] sorts again, so no caller depends on this order). An absent
/// directory has none.
///
/// The directory is checked by path with `symlink_metadata` (which does not
/// follow a symlink), then listed. A refusal ([`PolicyError::refuses_start`])
/// is returned at once; any other error is remembered and the scan continues,
/// so a refusal later in the directory still wins over it.
fn read_policy_directory(dir: &Path) -> Result<Vec<Fragment>, PolicyError> {
    let meta = match fs::symlink_metadata(dir) {
        Ok(meta) => meta,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(PolicyError::PolicyDirectoryIo(e)),
    };
    if meta.file_type().is_symlink() {
        return Err(PolicyError::PolicyDirectorySymlink);
    }
    if !meta.is_dir() {
        return Err(PolicyError::PolicyDirectoryNotADirectory);
    }
    let mode = meta.mode() & 0o777;
    if mode & 0o022 != 0 {
        return Err(PolicyError::PolicyDirectoryInsecurePermissions { mode });
    }
    let uid = meta.uid();
    if !hardened_open::owner_is_trusted(uid, rustix::process::geteuid().as_raw()) {
        return Err(PolicyError::PolicyDirectoryInsecureOwner { uid });
    }

    let mut deny_all: Option<PolicyError> = None;
    let mut entries = Vec::new();
    for entry in fs::read_dir(dir).map_err(PolicyError::PolicyDirectoryIo)? {
        match entry {
            Ok(entry) => entries.push(entry),
            Err(e) => {
                deny_all.get_or_insert(PolicyError::PolicyDirectoryIo(e));
            }
        }
    }
    entries.sort_by_key(|entry| entry.file_name());

    let mut fragments = Vec::new();
    for entry in entries {
        // The lossy rendering names the entry in refusals; a name that is not
        // UTF-8 is classified only after every refusal check has passed.
        let file_name = entry.file_name();
        let name = file_name.to_string_lossy().into_owned();
        let file_type = match entry.file_type() {
            Ok(file_type) => file_type,
            Err(source) => {
                deny_all.get_or_insert(PolicyError::FragmentUnreadable { name, source });
                continue;
            }
        };
        if file_type.is_symlink() {
            return Err(PolicyError::FragmentSymlink { name });
        }
        if !file_type.is_file() {
            return Err(PolicyError::FragmentNotRegularFile { name });
        }
        match read_fragment(&entry.path(), &name) {
            Ok(text) => match file_name.into_string() {
                Ok(name) => fragments.push(Fragment { name, text }),
                Err(name) => {
                    deny_all.get_or_insert(PolicyError::FragmentName { name });
                }
            },
            Err(e) if e.refuses_start() => return Err(e),
            Err(e) => {
                deny_all.get_or_insert(e);
            }
        }
    }
    match deny_all {
        Some(e) => Err(e),
        None => Ok(fragments),
    }
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

/// The result of linting a Policy file, or a Policy file and its fragments.
///
/// A TOML parse error means nothing else is checkable, so `parse_error` is
/// mutually exclusive with `findings` being non-empty: when `parse_error` is
/// `Some`, `findings` is always empty.
///
/// `parse_errors` holds one entry per source that failed to parse, the Policy
/// file first and then the fragments by name; a fragment's entry opens with
/// `<name>: `, the name Debug-escaped as the daemon logs it. `parse_error` is
/// the same entries joined with a newline, and is `Some` exactly when
/// `parse_errors` is not empty.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LintReport {
    pub parse_error: Option<String>,
    pub parse_errors: Vec<String>,
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
///    (`Warning`) — see `lint_shadowed_allows`.
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
    lint_composed(toml, &[], template_names, vocabulary_complete)
}

/// One parsed source of a composed lint: the Policy file (`fragment` is
/// `None`) or one Policy fragment.
struct LintSource<'a> {
    fragment: Option<&'a str>,
    file: PolicyFile,
}

impl LintSource<'_> {
    /// Prefix for a finding's location: a fragment's findings name the
    /// fragment, the Policy file's are unchanged.
    fn locate(&self, location: String) -> String {
        match self.fragment {
            Some(name) => format!("{name:?}: {location}"),
            None => location,
        }
    }

    /// The clause that names this source where a message points at one of its
    /// rules; empty for the Policy file.
    fn in_clause(&self) -> String {
        match self.fragment {
            Some(name) => format!(" in {name:?}"),
            None => String::new(),
        }
    }
}

/// [`lint_with_vocabulary`] over a Policy file and its fragments, linted as
/// the daemon would load them: one pass reports every problem in every source.
///
/// - A source that fails to parse is reported in `parse_error` and nothing else
///   is checked, as for a lone Policy file; every failing source is listed.
/// - The per-rule checks (regexes, anchoring, unknown names, deny no-ops) run
///   over each source, and a finding in a fragment has its location prefixed
///   with `<fragment name>: ` (Debug-escaped). Locations count rules per file,
///   which is what an operator editing the file needs; the composed Policy
///   numbers them across files.
/// - The shadowed-allow check runs across sources: an allow in any source is
///   shadowed by a deny in any source, because the daemon composes them into
///   one deny list.
///
/// Fragments are linted in name order. With no fragment the report is exactly
/// [`lint_with_vocabulary`]'s.
pub fn lint_composed(
    policy_file: &str,
    fragments: &[Fragment],
    template_names: &[String],
    vocabulary_complete: bool,
) -> LintReport {
    let mut sources = Vec::new();
    let mut parse_errors = Vec::new();
    match toml::from_str::<PolicyFile>(policy_file) {
        Ok(file) => sources.push(LintSource {
            fragment: None,
            file,
        }),
        Err(e) => parse_errors.push(e.to_string()),
    }
    for fragment in in_composition_order(fragments) {
        match toml::from_str::<PolicyFile>(&fragment.text) {
            Ok(file) => sources.push(LintSource {
                fragment: Some(&fragment.name),
                file,
            }),
            Err(e) => parse_errors.push(format!("{:?}: {e}", fragment.name)),
        }
    }
    if !parse_errors.is_empty() {
        return LintReport {
            parse_error: Some(parse_errors.join("\n")),
            parse_errors,
            findings: Vec::new(),
        };
    }

    let known =
        |name: &str| operations::is_native(name) || template_names.iter().any(|t| t == name);
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

    let mut findings = Vec::new();

    for source in &sources {
        let file = &source.file;
        let mut local = Vec::new();

        lint_raw_exec_regexes(
            &file.raw_exec.allow,
            "allow",
            compile_allow_regex,
            true,
            &mut local,
        );
        lint_raw_exec_regexes(
            &file.raw_exec.deny,
            "deny",
            compile_deny_regex,
            false,
            &mut local,
        );
        lint_raw_exec_allow_anchoring(&file.raw_exec.allow, &mut local);

        for (i, op) in file.operation.iter().map(|s| s.get_ref()).enumerate() {
            if !known(&op.name) {
                local.push(LintFinding {
                    severity,
                    location: format!("[[operation]] #{i} (name={:?})", op.name),
                    message: format!("unknown Operation name {:?}: {hint}", op.name),
                });
            }
        }

        for (i, deny) in file.deny.iter().map(|s| s.get_ref()).enumerate() {
            if !known(&deny.name) {
                local.push(LintFinding {
                    severity,
                    location: format!("[[deny]] #{i} (name={:?})", deny.name),
                    message: format!("unknown Operation name {:?}: {hint}", deny.name),
                });
            }
        }

        for mut finding in local {
            finding.location = source.locate(finding.location);
            findings.push(finding);
        }
    }

    lint_shadowed_allows(&sources, &mut findings);

    for source in &sources {
        let mut local = Vec::new();
        lint_deny_arg_noops(&source.file.deny, &mut local);
        for mut finding in local {
            finding.location = source.locate(finding.location);
            findings.push(finding);
        }
    }

    LintReport {
        parse_error: None,
        parse_errors: Vec::new(),
        findings,
    }
}

/// The ADR-0018 lexical canonical-form test for a path argument: absolute, and
/// with no empty, `.`, `..`, or trailing-slash segment.
///
/// Pure and I/O-free — it does NOT fold case or Unicode (ADR-0018 records that
/// as a narrow residual), and it is deliberately the SINGLE definition used
/// by [`Policy::decide`]'s path precondition, which every dispatch path
/// (Native and Template `path`-typed slots, issue #293) reaches through
/// `decide`. Outside `decide` only the catalog tests call it — never a second
/// notion of "canonical".
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
/// apply-path stderr, and the audit record all read identically. The quoted
/// path is caller-controlled and not yet validated here, so it is bounded by
/// [`reason_fragment`].
pub fn non_canonical_path_denial(path: &str) -> Decision {
    Decision::Deny {
        reason: format!(
            "path argument {:?} is not in canonical form (ADR-0018): must be absolute \
             with no '.', '..', '//', or trailing-slash segment",
            reason_fragment(path)
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
    patterns: &[toml::Spanned<String>],
    section: &str,
    compile: fn(&str) -> Result<Regex, regex::Error>,
    is_allow: bool,
    findings: &mut Vec<LintFinding>,
) {
    for (i, pattern) in patterns.iter().map(|s| s.get_ref()).enumerate() {
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
fn lint_raw_exec_allow_anchoring(
    patterns: &[toml::Spanned<String>],
    findings: &mut Vec<LintFinding>,
) {
    for (i, pattern) in patterns.iter().map(|s| s.get_ref()).enumerate() {
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
/// `Policy::decide`'s deny pass matches each argument position by EXACT VALUE
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
/// `decide`'s deny pass) — is explicitly NOT flagged; only a non-empty rule
/// with a dead inner position is. Real exact-match denies
/// (`args = [["nginx"]]`) contain neither construct and are never flagged.
fn lint_deny_arg_noops(denies: &[toml::Spanned<DenyRuleRaw>], findings: &mut Vec<LintFinding>) {
    for (di, deny) in denies.iter().map(|s| s.get_ref()).enumerate() {
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
/// `[[deny]]` rule of the same name (see `DenyScope::covers`), in the same
/// source or in any other: the daemon composes all of them into one deny list.
///
/// A deny covers an allow iff the allow can never fire: an empty `args` blocks
/// the whole operation; otherwise for every position the allow lists, the deny
/// either lists no such position (vacuous) or its value set subsumes the
/// allow's. A `"*"` allow position is never subsumed, because a deny has no
/// wildcard. The finding sits at the allow; its message names the deny by its
/// per-file index, and its fragment when it is in one.
fn lint_shadowed_allows(sources: &[LintSource<'_>], findings: &mut Vec<LintFinding>) {
    for source in sources {
        for (ai, allow) in source
            .file
            .operation
            .iter()
            .map(|s| s.get_ref())
            .enumerate()
        {
            let allow_matchers = compile_allow_args(&allow.allowed_args);
            for other in sources {
                for (di, deny) in other.file.deny.iter().map(|s| s.get_ref()).enumerate() {
                    if deny.name != allow.name {
                        continue;
                    }
                    if compile_deny_args(&deny.args).covers(&allow_matchers) {
                        findings.push(LintFinding {
                            severity: LintSeverity::Warning,
                            location: source
                                .locate(format!("[[operation]] #{ai} (name={:?})", allow.name)),
                            message: format!(
                                "allow rule is fully shadowed by [[deny]] #{di} (name={:?}){}; \
                                 it can never fire",
                                deny.name,
                                other.in_clause()
                            ),
                        });
                    }
                }
            }
        }
    }
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
) -> Option<(&'static str, &'a str, MatchedOn)> {
    if re.is_match(joined) {
        return Some(("joined command", joined, MatchedOn::JoinedCommand));
    }
    if let Some((index, arg)) = argv.iter().enumerate().find(|(_, arg)| re.is_match(arg)) {
        return Some((
            "argv element",
            arg.as_str(),
            MatchedOn::ArgvElement { index },
        ));
    }
    if let Some((index, elem)) = canonical
        .iter()
        .enumerate()
        .find(|(_, elem)| re.is_match(elem))
    {
        return Some((
            "canonical element",
            elem,
            MatchedOn::CanonicalElement { index },
        ));
    }
    None
}

/// Character budget for matched text quoted into a Deny reason.
const REASON_FRAGMENT_BUDGET: usize = 120;

/// Bound a caller-controlled fragment before it is quoted into a Deny reason.
///
/// Used for every caller-controlled string this module quotes: the text a deny
/// pattern matched, `argv[0]` in the ADR-0019 guard reason, the structured-
/// Operation args rendering in the deny-by-default reason, and the path in
/// `non_canonical_path_denial`. The reason
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
    /// The Policy fingerprint, as a 64-character lowercase-hex string: the
    /// SHA-256 of the raw Policy file bytes when there is no fragment, else
    /// over the Policy file and its fragments (see `policy_fingerprint`). Safe
    /// to log; the Policy body is not (ADR-0002).
    pub fn fingerprint(&self) -> &str {
        &self.fingerprint
    }

    /// Whether Raw Exec is enabled at all on this Node: `true` iff the
    /// `[raw_exec]` block has at least one allow pattern.
    ///
    /// Report-only / display-only (ADR-0002): this reads the live engine's own
    /// loaded state for the `PolicySnapshot` the Relay displays; it never
    /// evaluates or grants anything itself. An empty (or absent) `allow` list
    /// means Raw Exec is denied-by-default, matching `decide`'s Raw Exec chain.
    pub fn raw_exec_enabled(&self) -> bool {
        !self.raw_allow.is_empty()
    }

    /// The `[raw_exec] allow` regex patterns, in composition order: the Policy
    /// file, then fragments by name.
    ///
    /// Report-only / display-only (ADR-0002) — for the `PolicySnapshot` the
    /// Relay displays; not used for evaluation (the compiled `Regex` on
    /// `CompiledRe` is what `decide` uses).
    pub fn raw_allow_patterns(&self) -> Vec<String> {
        self.raw_allow.iter().map(|c| c.pattern.clone()).collect()
    }

    /// The `[raw_exec] deny` regex patterns, in composition order.
    ///
    /// Report-only / display-only (ADR-0002) — see [`Policy::raw_allow_patterns`].
    pub fn raw_deny_patterns(&self) -> Vec<String> {
        self.raw_deny.iter().map(|c| c.pattern.clone()).collect()
    }

    /// The distinct `[[operation]]` allow-rule names, in first-appearance
    /// composition order.
    ///
    /// Report-only / display-only (ADR-0002): a raw report of allow-rule
    /// names for the `PolicySnapshot` the Relay displays. `[[deny]]` rule
    /// names are NOT included — this is not a re-evaluation of what is
    /// actually permitted (that would reimplement `Policy::decide`,
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

    /// Every `[[operation]]` allow block, in composition order.
    ///
    /// Report-only / display-only (ADR-0002): a raw mirror of the Policy
    /// for the `PolicySnapshot` the Relay displays. Unlike
    /// [`Policy::allowed_operations`], this does NOT dedup by name — a name
    /// may appear in multiple blocks with different `allowed_args`, and every
    /// block is preserved. This is not a re-evaluation of what is actually
    /// permitted (that would reimplement `Policy::decide`, forbidden by
    /// ADR-0011); it is a verbatim copy of the loaded rules.
    pub fn operation_allow_rules(&self) -> Vec<OperationAllowRule> {
        self.operations
            .iter()
            .map(|op| OperationAllowRule {
                name: op.name.clone(),
                allowed_args: op.source_args.clone(),
            })
            .collect()
    }

    /// Every `[[deny]]` block, in composition order.
    ///
    /// Report-only / display-only (ADR-0002): a raw mirror of the Policy's
    /// deny rules for the `PolicySnapshot` the Relay displays. It
    /// never folds allow and deny together into an effective verdict — that
    /// would reimplement `Policy::decide`, forbidden by ADR-0011.
    pub fn deny_rules(&self) -> Vec<OperationDenyRule> {
        self.denies
            .iter()
            .map(|d| OperationDenyRule {
                name: d.name.clone(),
                args: d.source_args.clone(),
            })
            .collect()
    }

    /// The one Policy decision: may this [`Request`] run?
    ///
    /// Every entry path — Task apply, `PolicyQuery`, `policy check
    /// --would-allow`, `file.read`'s layer-2 recheck, the self-reference lint —
    /// makes exactly one call here, so there is a single place where Policy is
    /// evaluated (invariant 12).
    ///
    /// An Operation request runs: canonical-path precondition (ADR-0018), deny
    /// pass, allow pass, deny-by-default. A Raw Exec request runs: empty-argv
    /// precondition, deny pass, whitespace guard, allow pass, deny-by-default
    /// (ADR-0019). Deny always runs before the guard and the guard before
    /// allow; a deny written for N arguments also blocks a shorter invocation.
    ///
    /// The returned [`Explained`] carries the verdict, the pass and rule that
    /// produced it and, for an allowed Raw Exec only, the [`RawExecPermit`].
    pub fn decide(&self, request: &Request<'_>) -> Explained {
        match request {
            Request::Operation {
                name,
                positional,
                path_positions,
            } => {
                if let Some(e) = self.evaluate_path_precondition(positional, path_positions) {
                    return e;
                }
                if let Some(e) = self.evaluate_operation_deny(name, positional) {
                    return e;
                }
                if let Some(e) = self.evaluate_operation_allow(name, positional) {
                    return e;
                }
                self.evaluate_operation_default(name, positional)
            }
            Request::RawExec { argv } => {
                let mut explained = 'chain: {
                    // Empty argv is always denied (nothing to run).
                    if argv.is_empty() {
                        break 'chain Explained {
                            decision: Decision::Deny {
                                reason: "empty argv".to_string(),
                                rule: None,
                            },
                            pass: Pass::Precondition,
                            rule: None,
                            matched_on: MatchedOn::EmptyArgv,
                            raw_exec_permit: None,
                        };
                    }

                    let joined = argv.join(" ");

                    // Canonical elements: the joined command re-split on
                    // whitespace. This collapses attacker-chosen element
                    // boundaries (merged, padded, empty, or tab/newline/CR-
                    // separated) onto one normal form, so an element-anchored
                    // deny sees the tokens an operator wrote it against
                    // (ADR-0019). Computed once; the deny lists are short.
                    let canonical: Vec<&str> = joined.split_whitespace().collect();

                    if let Some(e) = self.evaluate_raw_exec_deny(&joined, argv, &canonical) {
                        break 'chain e;
                    }
                    if let Some(e) = self.evaluate_raw_exec_guard(argv) {
                        break 'chain e;
                    }
                    if let Some(e) = self.evaluate_raw_exec_allow(&joined) {
                        break 'chain e;
                    }
                    self.evaluate_raw_exec_default()
                };
                if matches!(explained.decision, Decision::Allow(_)) {
                    explained.raw_exec_permit = Some(RawExecPermit {
                        argv: argv.to_vec(),
                    });
                }
                explained
            }
        }
    }

    /// Path-argument canonical-form precondition (ADR-0018).
    ///
    /// A path argument must be in strict canonical form, else Deny (fail
    /// closed): this makes an exact-string path deny (e.g. `/etc/shadow`) hold
    /// against lexical evasions like `/etc/../etc/shadow` or `//etc/shadow`.
    /// Pure lexical test, no I/O — does NOT fold case/Unicode (ADR-0018 records
    /// that as a narrow residual). The first non-canonical position wins. The
    /// executor additionally re-checks the *resolved* target for `/proc`-magic
    /// and symlink evasions that are canonical in form (ADR-0018 layer 2).
    fn evaluate_path_precondition(
        &self,
        positional: &[String],
        path_positions: &[usize],
    ) -> Option<Explained> {
        for &position in path_positions {
            let Some(path) = positional.get(position) else {
                continue;
            };
            if !path_is_canonical(path) {
                return Some(Explained {
                    decision: non_canonical_path_denial(path),
                    pass: Pass::Precondition,
                    rule: None,
                    matched_on: MatchedOn::NonCanonicalPath { position },
                    raw_exec_permit: None,
                });
            }
        }
        None
    }

    /// Operation deny pass (deny-beats-allow, evaluated first).
    fn evaluate_operation_deny(&self, operation_name: &str, args: &[String]) -> Option<Explained> {
        for deny_rule in &self.denies {
            if deny_rule.name != operation_name {
                continue;
            }

            // An empty `args` list blocks any invocation of the operation;
            // otherwise each listed position must match, and positions beyond
            // args.len() are vacuously satisfied (a deny written for N args
            // also blocks shorter invocations).
            if deny_rule.scope.matches(args) {
                let matched_on = match deny_rule.scope {
                    DenyScope::Every => MatchedOn::WholeOperation,
                    DenyScope::Positions(_) => MatchedOn::Arguments,
                };
                return Some(Explained {
                    decision: Decision::Deny {
                        reason: format!("denied by explicit rule for operation '{operation_name}'"),
                        rule: Some(Rule::OperationDeny {
                            operation: operation_name.to_string(),
                        }),
                    },
                    pass: Pass::Deny,
                    rule: Some(deny_rule.at),
                    matched_on,
                    raw_exec_permit: None,
                });
            }
        }
        None
    }

    /// Operation allow pass: exact argument count, every position matched.
    fn evaluate_operation_allow(&self, operation_name: &str, args: &[String]) -> Option<Explained> {
        for op_rule in &self.operations {
            if op_rule.name != operation_name {
                continue;
            }

            // Argument count must match exactly.
            if args.len() != op_rule.matchers.len() {
                continue;
            }

            // Every position must be in the allowed set or be a wildcard.
            let allowed = op_rule
                .matchers
                .iter()
                .zip(args)
                .all(|(matcher, arg)| matcher.matches(arg));

            if allowed {
                return Some(Explained {
                    decision: Decision::Allow(Rule::OperationAllow {
                        operation: operation_name.to_string(),
                    }),
                    pass: Pass::Allow,
                    rule: Some(op_rule.at),
                    matched_on: MatchedOn::Arguments,
                    raw_exec_permit: None,
                });
            }
        }
        None
    }

    fn evaluate_operation_default(&self, operation_name: &str, args: &[String]) -> Explained {
        // --- Deny-by-default ------------------------------------------------
        // Neither the deny pass nor the allow pass matched: this is still a
        // plain deny-by-default (`rule: None` in both branches below). The
        // reason text only distinguishes *why* no allow rule matched, for
        // legibility: an allow rule may exist for this operation but not for
        // these particular args (wrong arg count, or an arg value outside
        // the allowed set), versus no allow rule existing for the operation
        // at all. This must never enumerate the allowed values (the
        // PolicySnapshot owns discovery) and must never change the outcome
        // — only the string differs.
        //
        // The args are caller-controlled and not yet validated here (Template
        // slot validators run after the Policy gate), so the rendering is
        // bounded by `reason_fragment`. The whole Debug rendering is
        // truncated, deliberately, rather than each element: that gives one
        // total budget whatever the arity, whereas per-element bounding would
        // grow with the Operation's slot count. The cost is that the cut may
        // land mid-escape or drop the closing `"]`; the `…` marks it, and
        // nothing parses this text (ADR-0019).
        let (reason, matched_on) = if self.operations.iter().any(|op| op.name == operation_name) {
            (
                format!(
                    "no allow rule matched args {} for operation '{operation_name}' \
                     (allow rules exist for other arguments)",
                    reason_fragment(&format!("{args:?}"))
                ),
                MatchedOn::NoMatchingArguments,
            )
        } else {
            (
                format!("deny-by-default: no allow rule for operation '{operation_name}'"),
                MatchedOn::NoAllowRule,
            )
        };
        Explained {
            decision: Decision::Deny { reason, rule: None },
            pass: Pass::Default,
            rule: None,
            matched_on,
            raw_exec_permit: None,
        }
    }

    /// The Raw Exec deny pass. Semantics of the whole Raw Exec chain, as
    /// `decide` runs it (ADR-0001, ADR-0002, ADR-0019, amended 2026-09-16):
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
    ///   element boundaries are ambiguous (invariant 1: an argument must
    ///   never change *which* command runs).
    /// - Deny-by-default: no allow match → deny with `rule: None`.
    fn evaluate_raw_exec_deny(
        &self,
        joined: &str,
        argv: &[String],
        canonical: &[&str],
    ) -> Option<Explained> {
        // --- Deny pass (deny-beats-allow, evaluated first) ------------------
        // Test deny patterns against the joined command, each raw element, AND
        // each canonical element. All three are kept: dropping the raw-element
        // pass would lose the only form that matches a deny written against a
        // merged element (`^--force x$`).
        for compiled in &self.raw_deny {
            if let Some((form, matched, matched_on)) =
                first_raw_deny_match(&compiled.re, joined, argv, canonical)
            {
                return Some(Explained {
                    decision: Decision::Deny {
                        reason: format!(
                            "raw exec denied by pattern {:?} (matched {form} {:?})",
                            compiled.pattern,
                            reason_fragment(matched)
                        ),
                        rule: Some(Rule::RawExecDeny {
                            pattern: compiled.pattern.clone(),
                        }),
                    },
                    pass: Pass::Deny,
                    rule: Some(compiled.at),
                    matched_on,
                    raw_exec_permit: None,
                });
            }
        }
        None
    }

    fn evaluate_raw_exec_guard(&self, argv: &[String]) -> Option<Explained> {
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
                    return Some(guard_denial(
                        format!(
                            "raw exec argv[0] {:?} is not a single program token (empty or \
                             containing whitespace): the program to execute must be exactly one \
                             argv element (ADR-0019)",
                            reason_fragment(elem)
                        ),
                        i,
                    ));
                }
            } else if elem.chars().any(char::is_whitespace) {
                return Some(guard_denial(
                    format!(
                        "raw exec argv[{i}] contains whitespace: no Raw Exec argument may carry \
                         whitespace, so the command Policy matched is exactly the argv that \
                         runs; pass such an argument through a Template Operation (ADR-0019)"
                    ),
                    i,
                ));
            }
        }
        None
    }

    fn evaluate_raw_exec_allow(&self, joined: &str) -> Option<Explained> {
        // --- Allow pass -------------------------------------------------
        // `re` is the full-match regex `compile_allow_regex` compiled
        // (`\A(?:pattern)\z`): matching the joined command against it is
        // already a whole-command test, so the call below needs no change
        // from a substring `is_match` — only what `re` means changed.
        for compiled in &self.raw_allow {
            if compiled.re.is_match(joined) {
                return Some(Explained {
                    decision: Decision::Allow(Rule::RawExecAllow {
                        pattern: compiled.pattern.clone(),
                    }),
                    pass: Pass::Allow,
                    rule: Some(compiled.at),
                    matched_on: MatchedOn::WholeCommand,
                    raw_exec_permit: None,
                });
            }
        }
        None
    }

    fn evaluate_raw_exec_default(&self) -> Explained {
        // --- Deny-by-default ------------------------------------------------
        Explained {
            decision: Decision::Deny {
                reason: "deny-by-default: no raw_exec allow pattern matched".to_string(),
                rule: None,
            },
            pass: Pass::Default,
            rule: None,
            matched_on: MatchedOn::NoRawExecAllow,
            raw_exec_permit: None,
        }
    }
}

/// The Raw Exec whitespace guard's refusal for `argv[index]`.
fn guard_denial(reason: String, index: usize) -> Explained {
    Explained {
        decision: Decision::Deny { reason, rule: None },
        pass: Pass::Guard,
        rule: None,
        matched_on: MatchedOn::WhitespaceElement { index },
        raw_exec_permit: None,
    }
}

// Test shims: they keep the pre-`decide` call shape for the suites that predate
// it, and are compiled only for tests and the bin's `test-util` dev-dependency.
// Production must call `decide`; `tests/policy_decide_single_gate.rs` enforces it.
#[cfg(any(test, feature = "test-util"))]
impl Policy {
    /// Test shim; production must call `decide`. Treats `file.read`'s first
    /// argument as the path position, as the engine did before `Request`
    /// carried positions.
    pub fn evaluate(&self, name: &str, args: &[String]) -> Decision {
        let path_positions: &[usize] = if name == operations::FILE_READ {
            &[0]
        } else {
            &[]
        };
        self.decide(&Request::Operation {
            name,
            positional: args,
            path_positions,
        })
        .decision
    }

    /// Test shim; production must call `decide`. Drops the permit.
    pub fn evaluate_raw_exec(&self, argv: &[String]) -> Decision {
        self.decide(&Request::RawExec { argv }).decision
    }
}

// ---------------------------------------------------------------------------
// Tests: each suite is its own test-only file beside this one.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod decide_tests;
#[cfg(test)]
mod default_policy_tests;
#[allow(
    clippy::disallowed_methods,
    reason = "test fixtures; the non-test lib target is linted separately"
)]
#[cfg(test)]
mod loader_hardening_tests;
#[cfg(test)]
mod proptests;
#[cfg(test)]
mod raw_exec_redteam;
#[cfg(test)]
mod tests;
