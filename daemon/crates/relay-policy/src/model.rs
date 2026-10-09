//! The compiled matcher model and the typed request / explained-decision
//! vocabulary of [`crate::Policy::decide`].
//!
//! `"*"` is a magic string only in the Policy *file*: [`compile_allow_args`]
//! turns it into [`ArgMatcher::Any`] once, at load time, so evaluation and the
//! lint's shadowing check both reason over matchers and never re-read the
//! sentinel. A deny position never compiles to `Any` — `"*"` there stays a
//! literal value, exactly as it always has.

use std::fmt;

/// What one argument position of a rule accepts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ArgMatcher {
    /// Any value (an allow position that listed `"*"`).
    Any,
    /// Exactly one of these values. An empty list matches nothing.
    OneOf(Vec<String>),
}

impl ArgMatcher {
    pub(crate) fn matches(&self, value: &str) -> bool {
        match self {
            ArgMatcher::Any => true,
            ArgMatcher::OneOf(values) => values.iter().any(|v| v == value),
        }
    }

    /// `true` if every value `other` accepts is also accepted by `self`.
    pub(crate) fn subsumes(&self, other: &ArgMatcher) -> bool {
        match (self, other) {
            (ArgMatcher::Any, _) => true,
            (ArgMatcher::OneOf(_), ArgMatcher::Any) => false,
            (ArgMatcher::OneOf(denied), ArgMatcher::OneOf(allowed)) => {
                allowed.iter().all(|v| denied.contains(v))
            }
        }
    }
}

/// Compiles an `[[operation]]` rule's `allowed_args`: a position listing `"*"`
/// anywhere accepts any value; otherwise it accepts exactly its listed values.
pub(crate) fn compile_allow_args(allowed_args: &[Vec<String>]) -> Vec<ArgMatcher> {
    allowed_args
        .iter()
        .map(|vals| {
            if vals.iter().any(|v| v == "*") {
                ArgMatcher::Any
            } else {
                ArgMatcher::OneOf(vals.clone())
            }
        })
        .collect()
}

/// Which invocations a `[[deny]]` rule covers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum DenyScope {
    /// The rule listed no arguments: every invocation of the operation.
    Every,
    /// The rule listed per-position values. Positions beyond the invocation's
    /// arguments are vacuously satisfied (the more-restrictive reading).
    Positions(Vec<ArgMatcher>),
}

/// Compiles a `[[deny]]` rule's `args`. `"*"` stays a literal value here.
pub(crate) fn compile_deny_args(args: &[Vec<String>]) -> DenyScope {
    if args.is_empty() {
        return DenyScope::Every;
    }
    DenyScope::Positions(
        args.iter()
            .map(|vals| ArgMatcher::OneOf(vals.clone()))
            .collect(),
    )
}

impl DenyScope {
    pub(crate) fn matches(&self, args: &[String]) -> bool {
        match self {
            DenyScope::Every => true,
            DenyScope::Positions(positions) => positions
                .iter()
                .enumerate()
                .all(|(i, matcher)| i >= args.len() || matcher.matches(&args[i])),
        }
    }

    /// `true` if this deny covers every invocation the allow rule `allow`
    /// would permit, so that allow can never fire. Only positions the allow
    /// rule has are examined; a deny position the allow lacks is beyond the
    /// invocation, hence vacuous.
    pub(crate) fn covers(&self, allow: &[ArgMatcher]) -> bool {
        match self {
            DenyScope::Every => true,
            DenyScope::Positions(positions) => allow
                .iter()
                .enumerate()
                .all(|(i, a)| positions.get(i).is_none_or(|d| d.subsumes(a))),
        }
    }
}

/// An `[[operation]]` allow rule, compiled.
#[derive(Debug)]
pub(crate) struct CompiledAllow {
    pub(crate) name: String,
    pub(crate) matchers: Vec<ArgMatcher>,
    /// The file's own `allowed_args`, verbatim, for the display-only
    /// `PolicySnapshot` accessors.
    pub(crate) source_args: Vec<Vec<String>>,
    pub(crate) at: RuleRef,
}

/// A `[[deny]]` rule, compiled.
#[derive(Debug)]
pub(crate) struct CompiledDeny {
    pub(crate) name: String,
    pub(crate) scope: DenyScope,
    /// The file's own `args`, verbatim, for the display-only `PolicySnapshot`
    /// accessors.
    pub(crate) source_args: Vec<Vec<String>>,
    pub(crate) at: RuleRef,
}

/// Which section of the Policy file a rule lives in.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RuleSection {
    /// An `[[operation]]` allow block.
    Operation,
    /// A `[[deny]]` block.
    Deny,
    /// A `[raw_exec]` `allow` pattern.
    RawExecAllow,
    /// A `[raw_exec]` `deny` pattern.
    RawExecDeny,
}

/// Where a rule sits in the Policy file: its section, its index within that
/// section, and its 1-based source line where the loader knows it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RuleRef {
    pub section: RuleSection,
    pub index: usize,
    pub line: Option<usize>,
}

impl fmt::Display for RuleRef {
    /// The lint's location grammar, plus `, line N` when the line is known.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let i = self.index;
        match self.section {
            RuleSection::Operation => write!(f, "[[operation]] #{i}")?,
            RuleSection::Deny => write!(f, "[[deny]] #{i}")?,
            RuleSection::RawExecAllow => write!(f, "[raw_exec].allow[{i}]")?,
            RuleSection::RawExecDeny => write!(f, "[raw_exec].deny[{i}]")?,
        }
        if let Some(line) = self.line {
            write!(f, ", line {line}")?;
        }
        Ok(())
    }
}

/// Which stage of [`crate::Policy::decide`] produced the verdict.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Pass {
    /// Decided before any rule ran: a non-canonical path argument, or an empty
    /// Raw Exec argv.
    Precondition,
    /// A deny rule matched.
    Deny,
    /// The Raw Exec whitespace guard refused. It runs after the deny pass and
    /// before the allow pass.
    Guard,
    /// An allow rule matched.
    Allow,
    /// Nothing matched: deny-by-default.
    Default,
}

impl fmt::Display for Pass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Pass::Precondition => "precondition",
            Pass::Deny => "deny",
            Pass::Guard => "guard",
            Pass::Allow => "allow",
            Pass::Default => "default",
        })
    }
}

/// What the deciding pass matched on. Positions and indices only — never an
/// argument value, which may be a secret.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MatchedOn {
    NonCanonicalPath { position: usize },
    EmptyArgv,
    WhitespaceElement { index: usize },
    WholeOperation,
    Arguments,
    JoinedCommand,
    ArgvElement { index: usize },
    CanonicalElement { index: usize },
    WholeCommand,
    NoAllowRule,
    NoMatchingArguments,
    NoRawExecAllow,
}

impl fmt::Display for MatchedOn {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MatchedOn::NonCanonicalPath { position } => {
                write!(f, "argument {position} is not a canonical path")
            }
            MatchedOn::EmptyArgv => f.write_str("empty argv"),
            MatchedOn::WhitespaceElement { index } => write!(
                f,
                "argv[{index}] is empty or contains whitespace (not a single token)"
            ),
            MatchedOn::WholeOperation => {
                f.write_str("the whole operation (the rule lists no arguments)")
            }
            MatchedOn::Arguments => f.write_str("the invocation's arguments"),
            MatchedOn::JoinedCommand => f.write_str("the joined command"),
            MatchedOn::ArgvElement { index } => write!(f, "argv[{index}]"),
            MatchedOn::CanonicalElement { index } => write!(f, "canonical element {index}"),
            MatchedOn::WholeCommand => f.write_str("the whole joined command"),
            MatchedOn::NoAllowRule => f.write_str("no allow rule for this operation"),
            MatchedOn::NoMatchingArguments => {
                f.write_str("no allow rule for these arguments (rules exist for others)")
            }
            MatchedOn::NoRawExecAllow => f.write_str("no raw_exec allow pattern"),
        }
    }
}

/// The one question [`crate::Policy::decide`] answers.
#[derive(Clone, Copy, Debug)]
pub enum Request<'a> {
    /// May this Operation run with these positional arguments?
    /// `path_positions` are the indices into `positional` that carry a path,
    /// which must be in canonical form (ADR-0018) before any rule is read.
    Operation {
        name: &'a str,
        positional: &'a [String],
        path_positions: &'a [usize],
    },
    /// May this Raw Exec argv run?
    RawExec { argv: &'a [String] },
}

/// A verdict plus the pass and rule that produced it.
///
/// Not `Clone` or `PartialEq`: the permit is neither.
#[derive(Debug)]
pub struct Explained {
    pub decision: crate::Decision,
    pub pass: Pass,
    /// The rule that decided. `Some` exactly when the pass is `Deny` or `Allow`.
    pub rule: Option<RuleRef>,
    pub matched_on: MatchedOn,
    /// Present exactly on an allowed Raw Exec request.
    pub raw_exec_permit: Option<crate::RawExecPermit>,
}
