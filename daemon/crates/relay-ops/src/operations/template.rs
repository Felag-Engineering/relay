//! Template Operation engine — the tier-2 execution path (ADR-0001 tier 2,
//! realized by ADR-0021).
//!
//! A **Template Operation** is an operator-authored shell template with named,
//! typed-validated **parameter slots**. The trusted author fixes the command
//! structure; the caller supplies only parameter *values*. ADR-0021's central
//! guarantee is that **substitution can never alter command structure**: a slot
//! value can never add words, operators, redirections, or expansions — it fills
//! exactly the lexical position the author wrote and nothing more.
//!
//! # Why this is a shell path (and not argv-only)
//!
//! ADR-0021 explicitly rejected an argv-only template tier: the vocabulary gap
//! templates exist to close *is* shell composition (pipes, filters,
//! redirection), and an argv-only template is just a Native Operation authored
//! in TOML. The chosen posture is **hostile-shell**: the shell boundary is
//! treated as adversarial, and the mitigation for the tier's residual risk
//! (parameter injection, per ADR-0001) is **per-parameter typed validation +
//! quoting**, gated by a **red-team suite** (an acceptance criterion of the
//! milestone, not a follow-up).
//!
//! This is the ONE place in the daemon that constructs a `/bin/sh -c` command
//! from a template. Invariant #1 ("argv, never `/bin/sh`") governs *Native
//! Operations* (tier 1); the template tier is tier 2, whose whole reason to
//! exist is shell composition. The command *structure* is author-fixed (from a
//! root-owned local file, ADR-0002 trust root — file loading is #291); only the
//! quoted slot values vary.
//!
//! # Two-layer defense (belt-and-suspenders, mirroring `service_restart.rs`)
//!
//! 1. **Typed validation** ([`SlotType::validate`]): each value is checked
//!    against its slot's declared type. `Identifier`, `Integer`, and `Enum`
//!    reject every shell metacharacter, whitespace (ASCII and non-ASCII such as
//!    NBSP), and control character outright. `Path` is the deliberately-permissive
//!    type (real filenames contain `$`, `;`, spaces, quotes) and leans on layer 2.
//! 2. **POSIX single-quoting** ([`shell_single_quote`]): every value —
//!    regardless of type — is wrapped so the shell sees it as exactly one word
//!    with no metacharacter interpretation. Even a value a validator lets
//!    through can never break out of its quoted token.
//!
//! # Command-structure integrity is proven at *compile* time
//!
//! [`compile`] parses the template body once, tracking shell quote state, and
//! refuses any template where a placeholder is not a **standalone,
//! space-, tab- or newline-delimited token in an unquoted context**. That single
//! rule makes the runtime guarantee trivial: a standalone token replaced by one
//! quoted word stays one word, so no value can change the token count or the
//! operators around it. (The more-restrictive reading of ADR-0021's "fills
//! exactly one lexical position" — see the PR body for the judgment calls.)
//!
//! The rule is only as good as the tracker's agreement with the shell (#974).
//! "Standalone" means bounded by the start or end of the body or by a shell
//! separator (space, tab or newline), never form feed or carriage return, which
//! the shell treats as word characters; a placeholder may not follow
//! backslash-escaped whitespace. The tracker follows only `'`, `"`, `\` and
//! separators, so a body with a placeholder may not also contain a construct
//! whose lexing it cannot follow: a here-document or here-string, a backquote,
//! `$(` (including `$((` and `$[`), `${`, `$'`, an unquoted `#`, a backslash
//! before a line end, a `((` arithmetic command, a `name[` array subscript or
//! `=(` compound assignment, or the word `alias`. See [`ShellConstruct`].
//!
//! That list is the set of constructs found to desynchronise the tracker from
//! dash and from bash-as-`/bin/sh` (#974). Refusal is by denylist, so a
//! construct not listed is not guaranteed safe. Residual, not refused:
//! eval-class commands and dynamically built command names.
//!
//! # Policy parity
//!
//! A compiled [`TemplateOp`] implements [`super::registry::ResolvedOp`], the
//! same `name → (handler, arg-shape, risk class)` contract Native Operations
//! resolve through (issue #310). Its [`ResolvedOp::positional_args`] uses the
//! identical named-args → positional mapping, so `policy.evaluate(name,
//! positional)` governs a template **byte-for-byte** like a Native Operation:
//! deny-by-default, deny-beats-allow, argument-level constraints. The Policy
//! engine is name-agnostic; the template's name simply enters the same
//! vocabulary. There is no second evaluator (ADR-0011).
//!
//! # Scope
//!
//! This module is the engine (issue #290): definitions, compilation, typed
//! validation, quoting, and rendering. Loading those definitions from
//! root-owned local files, the template-set fingerprint, the `unsupported`
//! per-Node outcome, and live discovery are [`crate::templates`] (issue #291);
//! the shipped read catalog is #293.

use std::collections::HashSet;

use serde::{Deserialize, Serialize};

use crate::executor::ExecRequest;
use crate::gen::{Operation, Outcome, RiskClass};
use crate::limits::ResourceLimits;
use crate::not_executed::not_executed;

use super::registry::{OpCtx, OpFuture, ResolvedOp};

// ---------------------------------------------------------------------------
// Bounds — every caller-controlled dimension is capped (oversized inputs are a
// red-team axis; fail closed before doing work).
// ---------------------------------------------------------------------------

/// Largest template body accepted by [`compile`]. Author-fixed, but bounded so
/// a malformed pack can't produce a pathological parse.
const MAX_BODY_BYTES: usize = 64 * 1024;

/// Largest number of slots a single template may declare.
const MAX_SLOTS: usize = 64;

/// Largest accepted value for an `Identifier` slot.
const MAX_IDENTIFIER_BYTES: usize = 256;

/// Largest accepted value for a `Path` slot (PATH_MAX-class bound).
const MAX_PATH_BYTES: usize = 4096;

/// Largest accepted value for an `Integer` slot (fits i64/u64 decimal digits).
const MAX_INTEGER_DIGITS: usize = 19;

// ---------------------------------------------------------------------------
// Serde-ready definition model (#291 deserializes into these; no loader here)
// ---------------------------------------------------------------------------

/// A template's risk class as authored. **Mandatory** (ADR-0012): there is no
/// `unspecified` variant, so a definition without a valid `risk_class` fails to
/// deserialize / fails to build — "a template without one fails to load".
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskClassDef {
    Read,
    Mutate,
}

impl From<RiskClassDef> for RiskClass {
    fn from(r: RiskClassDef) -> Self {
        match r {
            RiskClassDef::Read => RiskClass::Read,
            RiskClassDef::Mutate => RiskClass::Mutate,
        }
    }
}

/// The declared type of a parameter slot — the typed-validation contract.
///
/// `Identifier`, `Integer`, and `Enum` are *closed* accept-sets that exclude
/// every shell metacharacter by construction. `Path` is the deliberately
/// permissive type (canonical absolute paths, but real filenames legitimately
/// contain shell metacharacters) and relies on the quoting layer; it is the
/// primary red-team target.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case", tag = "type", content = "values")]
pub enum SlotType {
    /// `^[A-Za-z0-9][A-Za-z0-9_.@+-]*$`, ≤256 bytes. First char alphanumeric,
    /// so a leading `-` (option injection) is impossible. Excludes whitespace,
    /// quotes, and every shell metacharacter. Good for unit/package/interface
    /// names.
    Identifier,
    /// `^[0-9]+$`, ≤19 digits. Unsigned only — no sign, so a `-N`/`--`-prefix
    /// option injection is impossible (the more-restrictive choice; a signed
    /// type can be added later if a template needs one).
    Integer,
    /// An absolute, canonical path (ADR-0018 lexical rule: starts `/`, no `.`,
    /// `..`, empty, or trailing-slash segment), ≤4096 bytes, no ASCII control
    /// characters. Other bytes — spaces, `$`, `;`, quotes, non-ASCII — are
    /// permitted and neutralized by quoting.
    Path,
    /// The value must be exactly one of a fixed author-supplied allow-list. The
    /// safest slot type: the value space is finite and author-controlled.
    Enum(Vec<String>),
}

/// One parameter slot as authored: a name and its type.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct SlotDef {
    pub name: String,
    #[serde(flatten)]
    pub ty: SlotType,
}

/// A Template Operation definition, as authored (and, in #291, deserialized
/// from a root-owned local file).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct TemplateDef {
    /// The Operation name this template registers under (enters the Policy
    /// vocabulary exactly like a Native Operation name).
    pub name: String,
    /// Mandatory risk class (ADR-0012).
    pub risk_class: RiskClassDef,
    /// The shell template body: author-fixed structure with `{{slot}}`
    /// placeholders standing as whole, space-, tab- or newline-delimited tokens.
    pub body: String,
    /// The declared parameter slots. Every slot must be referenced by the body
    /// exactly as `{{name}}`, and every `{{name}}` in the body must resolve to
    /// a declared slot.
    #[serde(default)]
    pub slots: Vec<SlotDef>,
}

// ---------------------------------------------------------------------------
// Errors — structured, and deliberately never echo the raw caller value.
// ---------------------------------------------------------------------------

/// A shell construct the loader's quote tracker (which follows only `'`, `"`,
/// `\` and separators) cannot follow. [`compile`] refuses a body that has a
/// placeholder and also contains one (#974).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShellConstruct {
    /// `<<`, `<<-` or `<<<`.
    HereDocument,
    /// A backquote command substitution.
    Backquote,
    /// `$(`, `$((` or `$[`.
    CommandSubstitution,
    /// `${`.
    ParameterExpansion,
    /// `$'`.
    AnsiCQuote,
    /// An unquoted `#`.
    Comment,
    /// A backslash before a line end (newline or carriage return).
    LineContinuation,
    /// The word `alias`, in any ASCII case.
    Alias,
    /// A `((` arithmetic command, including `for ((`.
    ArithmeticCommand,
    /// A bash array subscript or compound array assignment (`name[` or `=(`).
    ArraySubscript,
}

impl ShellConstruct {
    /// A fixed, value-free description for error messages.
    pub fn reason(self) -> &'static str {
        match self {
            ShellConstruct::HereDocument => "a here-document or here-string operator (<<, <<-, <<<): single quotes are literal in an unquoted here-document body, so a slot value there is expanded",
            ShellConstruct::Backquote => "a backquote command substitution: a backquote in a slot value would end it early",
            ShellConstruct::CommandSubstitution => "a $( command substitution, or a $(( or $[ arithmetic expansion: the shell re-lexes quoting inside it, which the loader cannot follow",
            ShellConstruct::ParameterExpansion => "a ${ parameter expansion: quoting inside it is shell-specific, which the loader cannot follow",
            ShellConstruct::AnsiCQuote => "a $' quote: under bash it ends at a different quote than the loader tracks",
            ShellConstruct::Comment => "an unquoted '#': the shell discards the rest of the line, quotes included, which desynchronises the loader's quote tracking",
            ShellConstruct::LineContinuation => "a backslash before a line end (newline or carriage return): the shell re-joins or splits the text on either side differently from the loader",
            ShellConstruct::Alias => "the word 'alias' (matched case-insensitively, ignoring quote and backslash characters; this includes bash's BASH_ALIASES): alias expansion re-lexes later text with quote state the loader cannot follow",
            ShellConstruct::ArithmeticCommand => "a (( arithmetic command (including for (( ): bash expands its contents as if double-quoted, so single quotes in a slot value are literal and a $( in it runs",
            ShellConstruct::ArraySubscript => "a bash array subscript or compound array assignment (name[ or =( ): bash joins it into one word and expands the subscript as if double-quoted, so a $( in a slot value runs",
        }
    }
}

impl std::fmt::Display for ShellConstruct {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.reason())
    }
}

/// Errors from compiling or rendering a Template Operation.
///
/// **No variant embeds the raw slot value.** The reason travels into the audit
/// trail and to the AI-agent; a red-team value can be huge or hostile, so
/// failures are attributed by slot name and failure *class* plus the value's
/// byte length — never its contents.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum TemplateError {
    #[error(
        "template name {name:?} is invalid: must match ^[a-z][a-z0-9_.]*$ and not be 'raw_exec'"
    )]
    InvalidName { name: String },

    #[error("template body is empty")]
    EmptyBody,

    #[error("template body exceeds {max} bytes ({len})")]
    BodyTooLong { len: usize, max: usize },

    #[error("template declares {count} slots; the maximum is {max}")]
    TooManySlots { count: usize, max: usize },

    #[error("slot name {name:?} is invalid: must match ^[a-z][a-z0-9_]*$")]
    InvalidSlotName { name: String },

    #[error("slot {name:?} is declared more than once")]
    DuplicateSlot { name: String },

    #[error("enum slot {name:?} must list at least one non-empty value")]
    EmptyEnum { name: String },

    #[error("placeholder {{{{{name}}}}} references a slot that is not declared")]
    UnknownSlot { name: String },

    #[error("slot {name:?} is declared but never referenced by the body")]
    UnusedSlot { name: String },

    #[error(
        "a placeholder near byte {at} is not a standalone whitespace-delimited token \
         (a slot must fill exactly one lexical position, bounded by a space, tab or \
         newline or by the start or end of the body; it may not be glued to adjacent \
         text or quotes, and a carriage return or form feed is not a boundary — save \
         template files with LF line endings)"
    )]
    PlaceholderNotStandalone { at: usize },

    #[error("a placeholder appears inside a quoted region near byte {at}; slots must sit in an unquoted context")]
    PlaceholderInQuotedContext { at: usize },

    #[error("a placeholder near byte {at} follows backslash-escaped whitespace; the shell joins it to the preceding word, so it is not a standalone token")]
    PlaceholderAfterEscapedWhitespace { at: usize },

    #[error("template body has a placeholder and, near byte {at}, {construct}; a slot value could change the command's structure there, so the template is refused")]
    UntrackableConstructWithPlaceholder {
        at: usize,
        construct: ShellConstruct,
    },

    #[error("a placeholder near byte {at} is malformed: {detail}")]
    MalformedPlaceholder { at: usize, detail: &'static str },

    #[error(
        "template body has unbalanced quoting (an unterminated ' or \" or a trailing backslash)"
    )]
    UnbalancedQuotes,

    #[error(
        "parameter for slot {slot:?} (length {value_len}) failed {slot_type} validation: {reason}"
    )]
    ParameterValidation {
        slot: String,
        slot_type: &'static str,
        value_len: usize,
        reason: &'static str,
    },

    /// Defensive: the positional vector handed to [`TemplateOp::render`] did not
    /// match the slot count. Cannot happen when the vector comes from this
    /// template's own [`ResolvedOp::positional_args`]; guarded anyway.
    #[error("internal arity mismatch: {got} values for {want} slots")]
    ArityMismatch { got: usize, want: usize },
}

// ---------------------------------------------------------------------------
// Compiled model
// ---------------------------------------------------------------------------

/// A compiled parameter slot (name + type, validated at compile time).
#[derive(Debug, Clone, PartialEq, Eq)]
struct Slot {
    name: String,
    ty: SlotType,
}

/// One piece of a parsed template body: author-fixed literal text, or a slot to
/// substitute (by index into [`TemplateOp::slots`]).
#[derive(Debug, Clone, PartialEq, Eq)]
enum Segment {
    Literal(String),
    Slot(usize),
}

/// A compiled Template Operation: name, risk class, ordered slots, and the body
/// parsed into literal/slot segments. Immutable after [`compile`]; rendering is
/// pure.
#[derive(Debug, Clone)]
pub struct TemplateOp {
    name: String,
    risk: RiskClass,
    slots: Vec<Slot>,
    segments: Vec<Segment>,
}

impl TemplateOp {
    /// The positions of `path`-typed slots, in positional (Policy) order.
    ///
    /// Consumed by the dispatch gate (issue #293) to apply ADR-0018's
    /// canonical-form precondition to a template's path arguments BEFORE Policy
    /// evaluates them — so an exact-path `[[deny]]` on a template cannot be
    /// evaded by a non-canonical spelling like `/etc/../etc/shadow`, exactly as
    /// it cannot be for `file.read`.
    pub fn path_slot_positions(&self) -> Vec<usize> {
        self.slots
            .iter()
            .enumerate()
            .filter(|(_, s)| matches!(s.ty, SlotType::Path))
            .map(|(i, _)| i)
            .collect()
    }

    /// The declared parameter slots as `(name, type)`, in declaration order —
    /// which is also the positional order Policy evaluates args in. The
    /// discovery surface (#291) renders these into `TemplateDescriptor.slots`
    /// so `list_operations`/`describe_node` can show a Node's live vocabulary
    /// with its argument constraints.
    pub fn slot_specs(&self) -> Vec<(&str, &SlotType)> {
        self.slots
            .iter()
            .map(|s| (s.name.as_str(), &s.ty))
            .collect()
    }

    /// Map a caller `Operation`'s named args to the positional vector the Policy
    /// engine evaluates, in slot-declaration order — the identical contract as
    /// [`super::registry::OpRegistration::positional_args`]. A missing key maps
    /// to `""` (matched only by a Policy `"*"` wildcard). This is the SAME
    /// vector [`render`] validates, so what Policy evaluated is exactly what is
    /// substituted — no gap between the decision and the executed command.
    ///
    /// [`render`]: TemplateOp::render
    fn positional_args(&self, op: &Operation) -> Vec<String> {
        self.slots
            .iter()
            .map(|s| op.args.get(&s.name).cloned().unwrap_or_default())
            .collect()
    }

    /// Validate and substitute, producing the argv to execute.
    ///
    /// `positional[i]` is the raw value for `slots[i]` — the very vector Policy
    /// evaluated (see [`positional_args`]). Each value is validated against its
    /// slot type (fail closed on the first violation — no spawn) and then POSIX
    /// single-quoted before substitution. The result is
    /// `["/bin/sh", "-c", <rendered>]`: a shell command whose structure is
    /// author-fixed and whose only variable parts are single-quoted words.
    ///
    /// [`positional_args`]: TemplateOp::positional_args
    fn render(&self, positional: &[String]) -> Result<Vec<String>, TemplateError> {
        if positional.len() != self.slots.len() {
            return Err(TemplateError::ArityMismatch {
                got: positional.len(),
                want: self.slots.len(),
            });
        }

        let mut quoted: Vec<String> = Vec::with_capacity(self.slots.len());
        for (slot, value) in self.slots.iter().zip(positional) {
            slot.ty
                .validate(value)
                .map_err(|reason| TemplateError::ParameterValidation {
                    slot: slot.name.clone(),
                    slot_type: slot.ty.type_name(),
                    value_len: value.len(),
                    reason,
                })?;
            quoted.push(shell_single_quote(value));
        }

        let mut cmd = String::new();
        for seg in &self.segments {
            match seg {
                Segment::Literal(s) => cmd.push_str(s),
                Segment::Slot(idx) => cmd.push_str(&quoted[*idx]),
            }
        }

        Ok(vec!["/bin/sh".to_string(), "-c".to_string(), cmd])
    }
}

// ---------------------------------------------------------------------------
// Registry integration — a compiled template resolves through the SAME
// name → (handler, arg-shape, risk class) contract as a Native Operation
// (issue #310), so Policy governs it identically and dispatch needs no
// per-name arm (the structural test in dispatch.rs proves zero dispatch edits).
// ---------------------------------------------------------------------------

impl ResolvedOp for TemplateOp {
    fn name(&self) -> &str {
        &self.name
    }

    fn risk(&self) -> RiskClass {
        self.risk
    }

    fn tier(&self) -> crate::policy::decision_log::Tier {
        crate::policy::decision_log::Tier::Template
    }

    fn positional_args(&self, op: &Operation) -> Vec<String> {
        TemplateOp::positional_args(self, op)
    }

    fn path_arg_positions(&self) -> Vec<usize> {
        TemplateOp::path_slot_positions(self)
    }

    fn invoke<'a>(&'a self, ctx: OpCtx<'a>) -> OpFuture<'a> {
        Box::pin(async move {
            let OpCtx {
                task_id,
                positional,
                timeout,
                max_output_bytes,
                cancel,
                runner,
                policy: _,
            } = ctx;

            // Validate + substitute the exact vector Policy evaluated. A
            // validation failure fails closed — OUTCOME_FAILURE, never a spawn,
            // never DENIED_BY_POLICY (Policy already allowed; this is the
            // template's own stricter typed gate, like an invalid unit name in
            // service.restart).
            match self.render(&positional) {
                Ok(argv) => {
                    runner
                        .run(ExecRequest {
                            task_id,
                            argv,
                            timeout,
                            max_output_bytes,
                            cancel,
                            limits: ResourceLimits::DEFAULT,
                        })
                        .await
                }
                Err(e) => {
                    // `cancel` is moved into ExecRequest only on the Ok arm; on
                    // this no-spawn path it is simply dropped here — never a
                    // spurious cancel.
                    not_executed(task_id, Outcome::Failure, e.to_string())
                }
            }
        })
    }
}

// ---------------------------------------------------------------------------
// Compilation — parse + validate the body ONCE (structure integrity proven here)
// ---------------------------------------------------------------------------

/// Compile a [`TemplateDef`] into a runnable [`TemplateOp`], or fail closed.
///
/// Every check that could let substitution alter command structure is enforced
/// here, at load time, so rendering is a pure validate-and-quote pass:
/// - the name and every slot name are well-formed and unique;
/// - the body is non-empty and bounded;
/// - the body's quoting is balanced;
/// - every `{{slot}}` is a **standalone, space-, tab- or newline-delimited
///   token in an unquoted context** and resolves to a declared slot;
/// - no placeholder follows backslash-escaped whitespace;
/// - a body with a placeholder contains no [`ShellConstruct`] the quote tracker
///   cannot follow;
/// - every declared slot is referenced.
pub fn compile(def: &TemplateDef) -> Result<TemplateOp, TemplateError> {
    // --- name ---
    if !is_valid_template_name(&def.name) {
        return Err(TemplateError::InvalidName {
            name: def.name.clone(),
        });
    }

    // --- body bounds ---
    if def.body.is_empty() {
        return Err(TemplateError::EmptyBody);
    }
    if def.body.len() > MAX_BODY_BYTES {
        return Err(TemplateError::BodyTooLong {
            len: def.body.len(),
            max: MAX_BODY_BYTES,
        });
    }

    // --- slots: bounds, names, uniqueness, enum contents ---
    if def.slots.len() > MAX_SLOTS {
        return Err(TemplateError::TooManySlots {
            count: def.slots.len(),
            max: MAX_SLOTS,
        });
    }
    let mut seen: HashSet<&str> = HashSet::new();
    let mut slots: Vec<Slot> = Vec::with_capacity(def.slots.len());
    for sd in &def.slots {
        if !is_valid_slot_name(&sd.name) {
            return Err(TemplateError::InvalidSlotName {
                name: sd.name.clone(),
            });
        }
        if !seen.insert(sd.name.as_str()) {
            return Err(TemplateError::DuplicateSlot {
                name: sd.name.clone(),
            });
        }
        if let SlotType::Enum(values) = &sd.ty {
            if values.is_empty() || values.iter().any(|v| v.is_empty()) {
                return Err(TemplateError::EmptyEnum {
                    name: sd.name.clone(),
                });
            }
        }
        slots.push(Slot {
            name: sd.name.clone(),
            ty: sd.ty.clone(),
        });
    }

    // --- parse the body into segments, resolving placeholders to slot indices ---
    let (segments, referenced) = parse_body(&def.body, &slots)?;

    // --- every declared slot must actually be used ---
    for (idx, slot) in slots.iter().enumerate() {
        if !referenced.contains(&idx) {
            return Err(TemplateError::UnusedSlot {
                name: slot.name.clone(),
            });
        }
    }

    Ok(TemplateOp {
        name: def.name.clone(),
        risk: def.risk_class.into(),
        slots,
        segments,
    })
}

/// The characters dash and bash actually end a word on (outside
/// metacharacters, which the loader never accepts as a boundary anyway): space
/// and tab are blanks, newline ends the command.
///
/// `char::is_ascii_whitespace` also accepts form feed and carriage return. The
/// shell treats both as ordinary word characters, so a value next to one joins
/// the neighbouring word (#974).
fn is_shell_separator(c: char) -> bool {
    matches!(c, ' ' | '\t' | '\n')
}

/// A backquote or `$`-expansion starting at `chars[i]`, if any. `$'` is only an
/// ANSI-C quote outside double quotes.
fn expansion_at(chars: &[char], i: usize, in_double: bool) -> Option<ShellConstruct> {
    match chars[i] {
        '`' => Some(ShellConstruct::Backquote),
        '$' => match chars.get(i + 1) {
            Some('(') | Some('[') => Some(ShellConstruct::CommandSubstitution),
            Some('{') => Some(ShellConstruct::ParameterExpansion),
            Some('\'') if !in_double => Some(ShellConstruct::AnsiCQuote),
            _ => None,
        },
        _ => None,
    }
}

/// The original char index of the first `alias` (ASCII case-insensitive) left
/// once every `'`, `"` and `\` is removed from `chars`.
///
/// - It runs over the whole body, single-quoted text included, because
///   `'alias'` as a command name still runs the builtin.
/// - Case-insensitivity catches bash's `BASH_ALIASES[q]=...`, which defines an
///   alias without the lower-case word `alias` and still works under
///   `bash --posix`.
/// - It catches `alias`, `"alias"`, `a'l'ias`, `al\ias`, `unalias` and
///   `command alias`, and over-matches words like `aliases` (deliberate,
///   fail-closed).
/// - The offset is the exact index of the matched `a`, but the match may span
///   removed quote characters.
/// - `al\<newline>ias` is not matched here; it is already refused as a line
///   continuation.
///
/// The match is literal text only: it cannot see a command name or an
/// assignment target built by expansion (`$a`, `al$x'ias'`).
fn alias_at(chars: &[char]) -> Option<usize> {
    let kept: Vec<(usize, char)> = chars
        .iter()
        .copied()
        .enumerate()
        .filter(|(_, c)| !matches!(c, '\'' | '"' | '\\'))
        .collect();
    kept.windows(5)
        .find(|w| {
            w.iter()
                .map(|&(_, c)| c.to_ascii_lowercase())
                .eq("alias".chars())
        })
        .map(|w| w[0].0)
}

/// Record `construct` at `char_index` unless an earlier hazard is already held.
fn note(
    hazard: &mut Option<(usize, ShellConstruct)>,
    char_index: usize,
    construct: ShellConstruct,
) {
    if hazard.is_none() {
        *hazard = Some((char_index, construct));
    }
}

/// Parse `body` into literal/slot segments, tracking shell quote state.
///
/// Returns the segments plus the set of referenced slot indices. Enforces the
/// standalone-token, unquoted-context rule that makes structure integrity
/// trivial at render time.
fn parse_body(body: &str, slots: &[Slot]) -> Result<(Vec<Segment>, HashSet<usize>), TemplateError> {
    let chars: Vec<char> = body.chars().collect();
    // Byte offsets per char index, for legible error positions.
    let byte_at = |ci: usize| -> usize { body.chars().take(ci).map(|c| c.len_utf8()).sum() };

    let n = chars.len();
    let mut segments: Vec<Segment> = Vec::new();
    let mut referenced: HashSet<usize> = HashSet::new();
    let mut lit = String::new();

    let mut i = 0usize;
    let mut in_single = false;
    let mut in_double = false;
    let mut escaped = false;
    let mut escaped_char_at: Option<usize> = None;
    // The earliest construct the quote tracker cannot follow; only refused if
    // the body turns out to have a placeholder.
    let mut hazard: Option<(usize, ShellConstruct)> = None;

    while i < n {
        let c = chars[i];

        // A backslash-escaped char is always literal (unquoted or double-quoted
        // context; single quotes have no escape).
        if escaped {
            // `escaped` is only set by a backslash at i - 1. Backslash-CR is
            // noted too: in a CRLF body the shell escapes the CR and the LF ends
            // the command, so the next line starts a new one.
            if c == '\n' || c == '\r' {
                note(&mut hazard, i - 1, ShellConstruct::LineContinuation);
            }
            escaped_char_at = Some(i);
            lit.push(c);
            escaped = false;
            i += 1;
            continue;
        }

        if in_single {
            // Inside single quotes NOTHING is special except the closing '.
            // A `{{` here is literal shell text, but we still refuse it: an
            // author who writes `{{x}}` inside quotes almost certainly expects
            // substitution, and silently treating it as literal would be a trap.
            if c == '{' && i + 1 < n && chars[i + 1] == '{' {
                return Err(TemplateError::PlaceholderInQuotedContext { at: byte_at(i) });
            }
            lit.push(c);
            if c == '\'' {
                in_single = false;
            }
            i += 1;
            continue;
        }

        if in_double {
            if c == '{' && i + 1 < n && chars[i + 1] == '{' {
                return Err(TemplateError::PlaceholderInQuotedContext { at: byte_at(i) });
            }
            if let Some(k) = expansion_at(&chars, i, true) {
                note(&mut hazard, i, k);
            }
            if c == '\\' {
                lit.push(c);
                escaped = true;
                i += 1;
                continue;
            }
            lit.push(c);
            if c == '"' {
                in_double = false;
            }
            i += 1;
            continue;
        }

        // --- unquoted context ---
        if c == '{' && i + 1 < n && chars[i + 1] == '{' {
            // Left boundary: start-of-body or a shell separator (space, tab,
            // newline) only.
            if !(i == 0 || is_shell_separator(chars[i - 1])) {
                return Err(TemplateError::PlaceholderNotStandalone { at: byte_at(i) });
            }
            // An escaped separator is a word character to the shell, so the
            // value would join the preceding word (#974).
            if i > 0 && escaped_char_at == Some(i - 1) {
                return Err(TemplateError::PlaceholderAfterEscapedWhitespace { at: byte_at(i) });
            }
            // Find the closing `}}`.
            let mut j = i + 2;
            let mut close: Option<usize> = None;
            while j + 1 < n {
                if chars[j] == '}' && chars[j + 1] == '}' {
                    close = Some(j);
                    break;
                }
                // A nested `{{` inside a placeholder is malformed.
                if chars[j] == '{' && chars[j + 1] == '{' {
                    return Err(TemplateError::MalformedPlaceholder {
                        at: byte_at(i),
                        detail: "nested '{{' before a closing '}}'",
                    });
                }
                j += 1;
            }
            let Some(j) = close else {
                return Err(TemplateError::MalformedPlaceholder {
                    at: byte_at(i),
                    detail: "unterminated placeholder (no closing '}}')",
                });
            };

            // Right boundary: end-of-body or a shell separator (space, tab,
            // newline) only.
            if !(j + 2 >= n || is_shell_separator(chars[j + 2])) {
                return Err(TemplateError::PlaceholderNotStandalone { at: byte_at(i) });
            }

            let inner: String = chars[i + 2..j].iter().collect();
            let name = inner.trim();
            if !is_valid_slot_name(name) {
                return Err(TemplateError::MalformedPlaceholder {
                    at: byte_at(i),
                    detail: "placeholder name must match ^[a-z][a-z0-9_]*$",
                });
            }
            let Some(idx) = slots.iter().position(|s| s.name == name) else {
                return Err(TemplateError::UnknownSlot {
                    name: name.to_string(),
                });
            };

            if !lit.is_empty() {
                segments.push(Segment::Literal(std::mem::take(&mut lit)));
            }
            segments.push(Segment::Slot(idx));
            referenced.insert(idx);
            i = j + 2;
            continue;
        }

        if let Some(k) = expansion_at(&chars, i, false) {
            note(&mut hazard, i, k);
        }
        if c == '<' && chars.get(i + 1) == Some(&'<') {
            note(&mut hazard, i, ShellConstruct::HereDocument);
        }
        if c == '(' && chars.get(i + 1) == Some(&'(') {
            note(&mut hazard, i, ShellConstruct::ArithmeticCommand);
        }
        let after_name_char =
            i > 0 && (chars[i - 1].is_ascii_alphanumeric() || chars[i - 1] == '_');
        if (c == '[' && after_name_char) || (c == '=' && chars.get(i + 1) == Some(&'(')) {
            note(&mut hazard, i, ShellConstruct::ArraySubscript);
        }
        if c == '#' {
            note(&mut hazard, i, ShellConstruct::Comment);
        }

        // Track quote/escape transitions; keep the char as literal structure.
        match c {
            '\'' => in_single = true,
            '"' => in_double = true,
            '\\' => escaped = true,
            _ => {}
        }
        lit.push(c);
        i += 1;
    }

    if in_single || in_double || escaped {
        return Err(TemplateError::UnbalancedQuotes);
    }
    if !referenced.is_empty() {
        if let Some(ai) = alias_at(&chars) {
            if hazard.is_none_or(|(ci, _)| ai < ci) {
                hazard = Some((ai, ShellConstruct::Alias));
            }
        }
        if let Some((ci, construct)) = hazard {
            return Err(TemplateError::UntrackableConstructWithPlaceholder {
                at: byte_at(ci),
                construct,
            });
        }
    }
    if !lit.is_empty() {
        segments.push(Segment::Literal(lit));
    }

    Ok((segments, referenced))
}

// ---------------------------------------------------------------------------
// Slot-type validation — the typed gate (layer 1 of the two-layer defense)
// ---------------------------------------------------------------------------

impl SlotType {
    /// A stable label for error messages / audit (never the value), and the
    /// wire `TemplateSlot.type` string a surface renders for discovery (#291).
    pub fn type_name(&self) -> &'static str {
        match self {
            SlotType::Identifier => "identifier",
            SlotType::Integer => "integer",
            SlotType::Path => "path",
            SlotType::Enum(_) => "enum",
        }
    }

    /// The author-supplied allow-list for an `Enum` slot; empty for every other
    /// type. Part of the discovery surface (#291): an `enum` slot's finite
    /// value set is exactly what a caller needs to build valid args without
    /// trial-and-error (ADR-0001 legibility).
    pub fn enum_values(&self) -> &[String] {
        match self {
            SlotType::Enum(values) => values,
            _ => &[],
        }
    }

    /// Validate `value` against this slot's type, returning a static reason on
    /// rejection. Fail closed: an empty value is always rejected (all slots are
    /// required in this engine — optional slots are deferred; see the PR body).
    fn validate(&self, value: &str) -> Result<(), &'static str> {
        match self {
            SlotType::Identifier => {
                if value.is_empty() {
                    return Err("must not be empty");
                }
                if value.len() > MAX_IDENTIFIER_BYTES {
                    return Err("exceeds the maximum length");
                }
                let mut cs = value.chars();
                let first = cs.next().expect("non-empty checked above");
                if !first.is_ascii_alphanumeric() {
                    return Err("must start with an ASCII alphanumeric (no leading '-')");
                }
                if !value
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '@' | '+' | '-'))
                {
                    return Err("contains a character outside [A-Za-z0-9_.@+-]");
                }
                Ok(())
            }
            SlotType::Integer => {
                if value.is_empty() {
                    return Err("must not be empty");
                }
                if value.len() > MAX_INTEGER_DIGITS {
                    return Err("has too many digits");
                }
                if !value.bytes().all(|b| b.is_ascii_digit()) {
                    return Err("must be ASCII digits [0-9] only (no sign, no whitespace)");
                }
                Ok(())
            }
            SlotType::Path => {
                if value.is_empty() {
                    return Err("must not be empty");
                }
                if value.len() > MAX_PATH_BYTES {
                    return Err("exceeds the maximum length");
                }
                // Reject ASCII control chars (NUL, newline, tab, CR, …) and DEL.
                // These are the bytes that could split or terminate a command
                // even the shell-lexer way; quoting is not a licence to pass a
                // newline through.
                if value.chars().any(|c| (c as u32) < 0x20 || c == '\u{7f}') {
                    return Err("contains an ASCII control character");
                }
                // ADR-0018 lexical canonical-absolute form.
                let canonical = value == "/"
                    || (value.starts_with('/')
                        && !value.ends_with('/')
                        && !value
                            .split('/')
                            .skip(1)
                            .any(|seg| seg.is_empty() || seg == "." || seg == ".."));
                if !canonical {
                    return Err(
                        "must be an absolute canonical path: no '.', '..', '//', or trailing '/' (ADR-0018)",
                    );
                }
                Ok(())
            }
            SlotType::Enum(values) => {
                if values.iter().any(|v| v == value) {
                    Ok(())
                } else {
                    Err("is not one of the allowed enum values")
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Shell quoting — layer 2: make ANY string exactly one shell word.
// ---------------------------------------------------------------------------

/// POSIX single-quote a string so the shell reads it as exactly one word with
/// no metacharacter interpretation, no expansion, and no word-splitting.
///
/// Wrap in `'…'`; the only character that cannot appear literally inside single
/// quotes is `'` itself, encoded as `'\''` (close-quote, escaped literal quote,
/// reopen-quote). This is the canonical, injection-proof shell quoting and is
/// the second, type-independent layer of the defense — even a `Path` value
/// containing `$(reboot)` or `'; rm -rf /` becomes one inert word.
pub(crate) fn shell_single_quote(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 2);
    out.push('\'');
    for c in value.chars() {
        if c == '\'' {
            out.push_str("'\\''");
        } else {
            out.push(c);
        }
    }
    out.push('\'');
    out
}

// ---------------------------------------------------------------------------
// Name predicates
// ---------------------------------------------------------------------------

/// `^[a-z][a-z0-9_.]*$` and not `raw_exec` (reserved; ADR-0001 / issue #310).
fn is_valid_template_name(name: &str) -> bool {
    if name == "raw_exec" {
        return false;
    }
    let mut cs = name.chars();
    match cs.next() {
        Some(c) if c.is_ascii_lowercase() => {}
        _ => return false,
    }
    name.chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '_' | '.'))
}

/// `^[a-z][a-z0-9_]*$`.
fn is_valid_slot_name(name: &str) -> bool {
    let mut cs = name.chars();
    match cs.next() {
        Some(c) if c.is_ascii_lowercase() => {}
        _ => return false,
    }
    name.chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// A minimal POSIX-ish word splitter used ONLY by tests to assert that
/// substitution never changes the token structure of a command. Honors
/// single/double quotes and unquoted backslash escapes; performs no expansion
/// (matching what a real shell tokenizes before expansion). Module-scoped so
/// both the unit tests and the property tests share one implementation.
#[cfg(test)]
fn shell_words(s: &str) -> Vec<String> {
    let mut words = Vec::new();
    let mut cur = String::new();
    let mut has = false;
    let mut in_single = false;
    let mut in_double = false;
    let mut escaped = false;
    for c in s.chars() {
        if escaped {
            cur.push(c);
            escaped = false;
            continue;
        }
        if in_single {
            if c == '\'' {
                in_single = false;
            } else {
                cur.push(c);
            }
            continue;
        }
        if in_double {
            if c == '\\' {
                escaped = true;
            } else if c == '"' {
                in_double = false;
            } else {
                cur.push(c);
            }
            continue;
        }
        match c {
            '\'' => {
                in_single = true;
                has = true;
            }
            '"' => {
                in_double = true;
                has = true;
            }
            '\\' => {
                escaped = true;
                has = true;
            }
            c if c.is_ascii_whitespace() => {
                if has {
                    words.push(std::mem::take(&mut cur));
                    has = false;
                }
            }
            _ => {
                cur.push(c);
                has = true;
            }
        }
    }
    if has {
        words.push(cur);
    }
    words
}

#[cfg(test)]
mod tests {
    use super::*;

    // -- construction helpers -------------------------------------------------

    fn def(name: &str, body: &str, slots: Vec<SlotDef>) -> TemplateDef {
        TemplateDef {
            name: name.to_string(),
            risk_class: RiskClassDef::Read,
            body: body.to_string(),
            slots,
        }
    }

    fn slot(name: &str, ty: SlotType) -> SlotDef {
        SlotDef {
            name: name.to_string(),
            ty,
        }
    }

    fn op(args: &[(&str, &str)]) -> Operation {
        Operation {
            name: "t".to_string(),
            args: args
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
        }
    }

    /// Render helper: compile, map named args → positional (the Policy vector),
    /// then render. Returns the rendered `/bin/sh -c` command string on success.
    fn render_cmd(t: &TemplateOp, args: &[(&str, &str)]) -> Result<String, TemplateError> {
        let positional = t.positional_args(&op(args));
        let argv = t.render(&positional)?;
        assert_eq!(argv[0], "/bin/sh");
        assert_eq!(argv[1], "-c");
        Ok(argv[2].clone())
    }

    // -----------------------------------------------------------------------
    // shell_single_quote
    // -----------------------------------------------------------------------

    #[test]
    fn single_quote_wraps_plain() {
        assert_eq!(shell_single_quote("nginx"), "'nginx'");
    }

    #[test]
    fn single_quote_encodes_embedded_quote() {
        assert_eq!(shell_single_quote("a'b"), "'a'\\''b'");
        // The encoded form tokenizes back to the exact original as ONE word.
        assert_eq!(shell_words(&shell_single_quote("a'b")), ["a'b"]);
    }

    #[test]
    fn single_quote_neutralizes_metacharacters() {
        for hostile in [
            "; reboot",
            "$(reboot)",
            "`id`",
            "a|b",
            "x && y",
            "> /etc/passwd",
            "$HOME",
            "*",
            "a b c",
            "'; rm -rf / #",
        ] {
            let q = shell_single_quote(hostile);
            let words = shell_words(&q);
            assert_eq!(
                words,
                [hostile.to_string()],
                "single-quoted {hostile:?} must be exactly one inert word"
            );
        }
    }

    // -----------------------------------------------------------------------
    // Slot-type validation (typed gate)
    // -----------------------------------------------------------------------

    #[test]
    fn identifier_accepts_valid_names() {
        for good in ["nginx", "php-fpm", "user@1000.service", "a1", "x_y", "a+b"] {
            assert!(SlotType::Identifier.validate(good).is_ok(), "{good:?}");
        }
    }

    #[test]
    fn identifier_rejects_injection_and_edges() {
        for bad in [
            "",           // empty
            "-h",         // leading dash / option injection
            "--force",    // leading dash
            "a b",        // space
            "a\tb",       // tab
            "a\u{00a0}b", // NBSP (non-ASCII whitespace, ADR-0019 lesson)
            "a;b",        // metachar
            "a|b",        // metachar
            "a$b",        // expansion char
            "a`b",        // backtick
            "a'b",        // single quote
            "a\"b",       // double quote
            "a\nb",       // newline
            "a/b",        // path separator
            "a\u{202e}b", // RTL override
        ] {
            assert!(
                SlotType::Identifier.validate(bad).is_err(),
                "identifier must reject {bad:?}"
            );
        }
    }

    #[test]
    fn identifier_rejects_oversized() {
        let big = "a".repeat(MAX_IDENTIFIER_BYTES + 1);
        assert!(SlotType::Identifier.validate(&big).is_err());
    }

    #[test]
    fn integer_accepts_and_rejects() {
        for good in ["0", "42", "1000000"] {
            assert!(SlotType::Integer.validate(good).is_ok(), "{good:?}");
        }
        for bad in ["", "-5", "+5", "1.0", "0x10", "1 2", "12a", " 3", "3 "] {
            assert!(SlotType::Integer.validate(bad).is_err(), "{bad:?}");
        }
        assert!(SlotType::Integer
            .validate(&"9".repeat(MAX_INTEGER_DIGITS + 1))
            .is_err());
    }

    #[test]
    fn path_accepts_canonical_absolute() {
        for good in ["/", "/etc/hostname", "/var/log/syslog", "/a/b/c.txt"] {
            assert!(SlotType::Path.validate(good).is_ok(), "{good:?}");
        }
    }

    #[test]
    fn path_rejects_noncanonical_and_control() {
        for bad in [
            "",               // empty
            "etc/passwd",     // relative
            "/etc/../shadow", // ..
            "/etc/./x",       // .
            "//etc/x",        // empty seg
            "/etc/x/",        // trailing slash
            "/etc/\n/x",      // newline (control)
            "/etc/\0/x",      // NUL
            "/etc/\tx",       // tab
        ] {
            assert!(
                SlotType::Path.validate(bad).is_err(),
                "path must reject {bad:?}"
            );
        }
    }

    #[test]
    fn path_permits_metachars_relying_on_quoting() {
        // Deliberately-permissive: real filenames contain these; the quoting
        // layer (not the type) neutralizes them. Proven inert below in
        // render_quotes_hostile_path_value.
        for tricky in ["/tmp/$(reboot)", "/tmp/a;b", "/tmp/a b", "/tmp/a'b"] {
            assert!(SlotType::Path.validate(tricky).is_ok(), "{tricky:?}");
        }
    }

    #[test]
    fn enum_is_exact_allowlist() {
        let e = SlotType::Enum(vec!["active".into(), "enabled".into()]);
        assert!(e.validate("active").is_ok());
        assert!(e.validate("enabled").is_ok());
        for bad in ["", "ACTIVE", "active ", "active;x", "other"] {
            assert!(e.validate(bad).is_err(), "{bad:?}");
        }
    }

    // -----------------------------------------------------------------------
    // compile() — structure-integrity gate
    // -----------------------------------------------------------------------

    #[test]
    fn compile_accepts_a_well_formed_template() {
        let t = compile(&def(
            "svc.status",
            "systemctl status {{unit}}",
            vec![slot("unit", SlotType::Identifier)],
        ))
        .expect("must compile");
        assert_eq!(t.name(), "svc.status");
        assert_eq!(t.risk(), RiskClass::Read);
    }

    #[test]
    fn compile_rejects_missing_and_unused_and_unknown_slots() {
        // placeholder references an undeclared slot
        assert_eq!(
            compile(&def("t.a", "echo {{x}}", vec![])).unwrap_err(),
            TemplateError::UnknownSlot { name: "x".into() }
        );
        // declared slot never referenced
        assert_eq!(
            compile(&def(
                "t.b",
                "echo hello",
                vec![slot("x", SlotType::Identifier)]
            ))
            .unwrap_err(),
            TemplateError::UnusedSlot { name: "x".into() }
        );
    }

    #[test]
    fn compile_rejects_placeholder_glued_to_text() {
        // Not a standalone token (glued on the left).
        assert!(matches!(
            compile(&def(
                "t.c",
                "echo x{{unit}}",
                vec![slot("unit", SlotType::Identifier)]
            ))
            .unwrap_err(),
            TemplateError::PlaceholderNotStandalone { .. }
        ));
        // Glued on the right (e.g. --flag={{n}} is refused — the more
        // restrictive reading; documented in the PR).
        assert!(matches!(
            compile(&def(
                "t.d",
                "tail -n {{n}}x",
                vec![slot("n", SlotType::Integer)]
            ))
            .unwrap_err(),
            TemplateError::PlaceholderNotStandalone { .. }
        ));
    }

    #[test]
    fn compile_rejects_placeholder_inside_quotes() {
        for body in ["echo \"{{x}}\"", "echo '{{x}}'", "echo \"a {{x}} b\""] {
            let e = compile(&def("t.q", body, vec![slot("x", SlotType::Identifier)])).unwrap_err();
            assert!(
                matches!(
                    e,
                    TemplateError::PlaceholderInQuotedContext { .. }
                        | TemplateError::PlaceholderNotStandalone { .. }
                ),
                "quoted placeholder must be refused, got {e:?}"
            );
        }
    }

    #[test]
    fn compile_rejects_unbalanced_quotes_and_bad_placeholders() {
        assert_eq!(
            compile(&def("t.u", "echo 'unterminated", vec![])).unwrap_err(),
            TemplateError::UnbalancedQuotes
        );
        assert!(matches!(
            compile(&def(
                "t.v",
                "echo {{unit",
                vec![slot("unit", SlotType::Identifier)]
            ))
            .unwrap_err(),
            TemplateError::MalformedPlaceholder { .. }
        ));
    }

    #[test]
    fn compile_rejects_bad_names_dupes_and_empty_enum() {
        assert!(matches!(
            compile(&def("Bad Name", "echo hi", vec![])).unwrap_err(),
            TemplateError::InvalidName { .. }
        ));
        assert!(matches!(
            compile(&def("raw_exec", "echo hi", vec![])).unwrap_err(),
            TemplateError::InvalidName { .. }
        ));
        assert!(matches!(
            compile(&def(
                "t.dup",
                "echo {{x}}",
                vec![
                    slot("x", SlotType::Identifier),
                    slot("x", SlotType::Identifier)
                ]
            ))
            .unwrap_err(),
            TemplateError::DuplicateSlot { .. }
        ));
        assert!(matches!(
            compile(&def(
                "t.e",
                "echo {{x}}",
                vec![slot("x", SlotType::Enum(vec![]))]
            ))
            .unwrap_err(),
            TemplateError::EmptyEnum { .. }
        ));
    }

    #[test]
    fn compile_rejects_empty_body() {
        assert_eq!(
            compile(&def("t.empty", "", vec![])).unwrap_err(),
            TemplateError::EmptyBody
        );
    }

    // -----------------------------------------------------------------------
    // compile() — shell contexts the quote tracker cannot follow (#974)
    // -----------------------------------------------------------------------

    fn untrackable(at: usize, construct: ShellConstruct) -> TemplateError {
        TemplateError::UntrackableConstructWithPlaceholder { at, construct }
    }

    fn compile_p(body: &str) -> Result<TemplateOp, TemplateError> {
        compile(&def("t.x", body, vec![slot("p", SlotType::Path)]))
    }

    fn compile_n(body: &str) -> Result<TemplateOp, TemplateError> {
        compile(&def("t.x", body, vec![slot("n", SlotType::Integer)]))
    }

    /// An escaped space/tab/newline is a word character, so the value joins the
    /// preceding word: `printf '[%s]\n' a\ '/tmp/x'` prints `[a /tmp/x]` (one
    /// word); `a\<LF>'/tmp/x'` prints `[a/tmp/x]`; `a\<TAB>'/tmp/x'` keeps the
    /// tab. `'/tmp/x'\ b` (row a4) was already refused: `\` is not a separator.
    #[test]
    fn compile_rejects_placeholder_after_escaped_whitespace() {
        for body in ["echo a\\ {{p}}", "echo a\\\t{{p}}", "echo a\\\n{{p}}"] {
            assert_eq!(
                compile_p(body).unwrap_err(),
                TemplateError::PlaceholderAfterEscapedWhitespace { at: 8 },
                "{body:?}"
            );
        }
        assert_eq!(
            compile_p("echo {{p}}\\ b").unwrap_err(),
            TemplateError::PlaceholderNotStandalone { at: 5 }
        );
        // An escaped backslash followed by a real space is a real separator.
        let t = compile_p("echo a\\\\ {{p}}").unwrap();
        assert_eq!(
            render_cmd(&t, &[("p", "/tmp/x")]).unwrap(),
            "echo a\\\\ '/tmp/x'"
        );
    }

    /// Single quotes are literal in an unquoted here-document body, so the
    /// shell expands `$(…)` in the value: `cat <<EOF⏎'/tmp/$(echo INJECTED)'⏎EOF`
    /// prints `'/tmp/INJECTED'` (same for `<<-`). A quoted `<<` is literal
    /// (`echo "a<<b" '/tmp/x' '<<'`), so it stays allowed.
    #[test]
    fn compile_rejects_heredoc_operator_in_a_body_with_a_placeholder() {
        for body in [
            "cat <<EOF\n{{p}}\nEOF",
            "cat <<-EOF\n\t{{p}}\n\tEOF",
            "cat <<< {{p}}",
        ] {
            assert_eq!(
                compile_p(body).unwrap_err(),
                untrackable(4, ShellConstruct::HereDocument),
                "{body:?}"
            );
        }
        for (body, rendered) in [
            ("echo \"a<<b\" {{p}}", "echo \"a<<b\" '/tmp/x'"),
            ("echo '<<' {{p}}", "echo '<<' '/tmp/x'"),
        ] {
            let t = compile_p(body).unwrap();
            assert_eq!(render_cmd(&t, &[("p", "/tmp/x")]).unwrap(), rendered);
        }
    }

    /// ``echo `echo '/tmp/x`'`` is a dash syntax error: the value's quote is
    /// re-lexed inside the backquotes.
    #[test]
    fn compile_rejects_backquote_in_a_body_with_a_placeholder() {
        assert_eq!(
            compile_p("echo ` echo {{p}} `").unwrap_err(),
            untrackable(5, ShellConstruct::Backquote)
        );
        assert_eq!(
            compile_p("echo \"`date`\" {{p}}").unwrap_err(),
            untrackable(6, ShellConstruct::Backquote)
        );
    }

    /// The desync row compiled before the fix and dash ran the value: the
    /// tracker reads the `'` inside `"…"` as literal while the shell re-lexes it
    /// inside `$(`, so `echo "$(echo ')" '/tmp/x;echo PWNED' "')"` runs
    /// `echo PWNED`. `$[ … ]` is a live re-lexing arithmetic expansion under
    /// `bash --posix` (`echo $[ 1 + 1 ]` prints `2`).
    #[test]
    fn compile_rejects_command_substitution_in_a_body_with_a_placeholder() {
        for body in [
            "echo $( echo {{n}} )",
            "echo $(( {{n}} + 1 ))",
            "echo $[ {{n}} ]",
        ] {
            assert_eq!(
                compile_n(body).unwrap_err(),
                untrackable(5, ShellConstruct::CommandSubstitution),
                "{body:?}"
            );
        }
        assert_eq!(
            compile_p("echo \"$(echo ')\" {{p}} \"')\"").unwrap_err(),
            untrackable(6, ShellConstruct::CommandSubstitution)
        );
    }

    /// Quoting inside `${…}` is partly unspecified by POSIX and dash and bash
    /// diverge (`echo ${u:- '/tmp/}x'}` prints `/tmp/}x`).
    #[test]
    fn compile_rejects_parameter_expansion_in_a_body_with_a_placeholder() {
        assert_eq!(
            compile_p("echo ${u:- {{p}} }").unwrap_err(),
            untrackable(5, ShellConstruct::ParameterExpansion)
        );
        assert_eq!(
            compile_p("echo \"${HOME}\" {{p}}").unwrap_err(),
            untrackable(6, ShellConstruct::ParameterExpansion)
        );
    }

    /// `echo $'\' '/tmp/x;echo PWNED_ANSI' \'`: dash is inert, but under
    /// `bash --posix` (`/bin/sh` on RHEL) `$'\'` ends at a different quote than
    /// the loader tracks and the value ran as a command (PWNED_ANSI).
    #[test]
    fn compile_rejects_ansi_c_quote_in_a_body_with_a_placeholder() {
        assert_eq!(
            compile_p("echo $'\\' {{p}} \\'").unwrap_err(),
            untrackable(5, ShellConstruct::AnsiCQuote)
        );
    }

    /// A comment hides a `'` from the shell that the tracker still counts:
    /// `true #'⏎echo ' '/tmp/x;echo PWNED_COMMENT' \'` ran the value.
    #[test]
    fn compile_rejects_comment_in_a_body_with_a_placeholder() {
        assert_eq!(
            compile_p("true #'\necho ' {{p}} \\'").unwrap_err(),
            untrackable(5, ShellConstruct::Comment)
        );
        assert_eq!(
            compile_p("echo hi # note {{p}}").unwrap_err(),
            untrackable(8, ShellConstruct::Comment)
        );
    }

    /// A line continuation builds a `<<` (`cat <\⏎<EOF…`) or a `$(`
    /// (`echo $\⏎(…)`) out of characters the tracker saw separately. In a CRLF
    /// body `\`+CR+LF escapes the CR and the LF ends the command, so the next
    /// line runs as its own command with the quoted word in command position:
    /// `echo a\<CR><LF>'/bin/echo' RAN` prints `a<CR>` then `RAN`.
    #[test]
    fn compile_rejects_line_continuation_in_a_body_with_a_placeholder() {
        assert_eq!(
            compile_p("cat <\\\n<EOF\n{{p}}\nEOF").unwrap_err(),
            untrackable(5, ShellConstruct::LineContinuation)
        );
        assert_eq!(
            compile_p("echo $\\\n( echo {{p}} )").unwrap_err(),
            untrackable(6, ShellConstruct::LineContinuation)
        );
        assert_eq!(
            compile_p("echo a\\\r\n{{p}}").unwrap_err(),
            untrackable(6, ShellConstruct::LineContinuation)
        );
    }

    /// A placeholder-free body has no slot to subvert: every construct above
    /// still compiles and renders byte-for-byte.
    #[test]
    fn constructs_without_a_placeholder_still_compile_and_render_unchanged() {
        for body in [
            "cat <<EOF\nhi\nEOF",
            "echo `date`",
            "echo $(date) $((1+1)) $[1+1] ${HOME}",
            "echo hi # c",
            "echo a\\\nb",
            "echo a\\\r\nb",
            "echo $'x'",
            "alias ll='ls -l'",
            "(( 1 ))",
            "a[1]=2; b=(x y)",
            "if command -v dpkg-query > /dev/null 2>&1; then dpkg-query -W -f '${Package}\\t${Version}\\n'; elif command -v rpm > /dev/null 2>&1; then rpm -qa --qf '%{NAME}\\t%{VERSION}-%{RELEASE}\\n'; else echo 'no supported package manager (dpkg/rpm)' 1>&2; exit 1; fi",
        ] {
            let t = compile(&def("t.x", body, vec![])).unwrap_or_else(|e| panic!("{body:?}: {e}"));
            assert_eq!(render_cmd(&t, &[]).unwrap(), body);
        }
    }

    /// dash and `bash --posix` end a word only on space and tab: `printf
    /// '[%s]\n' a<FF>'/tmp/x' b<CR>'/tmp/y'` prints `[a<FF>/tmp/x]` and
    /// `[b<CR>/tmp/y]` (one word each); `'/tmp/z'<FF>c` and `'/tmp/w'<CR><LF>`
    /// join the same way (the CR of a CRLF line ending joins the value).
    #[test]
    fn compile_rejects_placeholder_bounded_by_non_shell_whitespace() {
        for body in ["echo a\x0c{{p}}", "echo a\r{{p}}"] {
            assert_eq!(
                compile_p(body).unwrap_err(),
                TemplateError::PlaceholderNotStandalone { at: 7 },
                "{body:?}"
            );
        }
        for body in [
            "echo {{p}}\x0cb",
            "echo {{p}}\rb",
            "echo {{p}}\r\necho done",
        ] {
            assert_eq!(
                compile_p(body).unwrap_err(),
                TemplateError::PlaceholderNotStandalone { at: 5 },
                "{body:?}"
            );
        }
        compile_p("echo a\t{{p}}\nx").unwrap();
        compile_p("echo a {{p}} b").unwrap();
    }

    /// bash expands the contents of a `((` arithmetic command as if
    /// double-quoted, so single quotes in a slot value are literal and a `$(`
    /// in it runs: `bash --posix -c "(( '/x\$(echo PWNED_DPAREN >&2)' ))"`
    /// printed PWNED_DPAREN, and the `for ((` form printed PWNED_FOR. dash is
    /// inert (it reads `((` as nested subshells); `let`, `declare -i` and
    /// `[[ … -eq … ]]` were probed and are inert. `$((` is noted at the `$`
    /// first, so it stays a `CommandSubstitution`.
    #[test]
    fn compile_rejects_arithmetic_command_in_a_body_with_a_placeholder() {
        for (body, at) in [
            ("(( {{p}} ))", 0),
            ("for (( i= {{p}} ; 0; )); do :; done", 4),
        ] {
            assert_eq!(
                compile_p(body).unwrap_err(),
                untrackable(at, ShellConstruct::ArithmeticCommand),
                "{body:?}"
            );
        }
    }

    /// bash joins `name[ … ]` into one word and expands the subscript as if
    /// double-quoted, so a single-quoted slot value there is literal and a `$(`
    /// in it runs. Under `bash --posix -c`, `a[ '/x$(echo PWNED_SUB >&2)' ]=1`
    /// printed PWNED_SUB, the `]+=1` form printed PWNED_PLUSEQ, and
    /// `a=( [ '/x$(echo PWNED_COMPOUND >&2)' ]=1 )` printed PWNED_COMPOUND.
    /// `[ -f … ]` and `[[ -e … ]]` are inert, as is dash. The offset is the `[`
    /// (or, for a compound assignment, the `=`).
    #[test]
    fn compile_rejects_array_subscript_in_a_body_with_a_placeholder() {
        for (body, at) in [
            ("a[ {{p}} ]=1", 1),
            ("a=( [ {{p}} ]=1 )", 1),
            ("echo x; a[ {{p}} ]+=1", 9),
        ] {
            assert_eq!(
                compile_p(body).unwrap_err(),
                untrackable(at, ShellConstruct::ArraySubscript),
                "{body:?}"
            );
        }
        for body in ["[ -f {{p}} ]", "[[ -e {{p}} ]]", "test -f {{p}}"] {
            let t = compile_p(body).unwrap_or_else(|e| panic!("{body:?}: {e}"));
            assert_eq!(
                render_cmd(&t, &[("p", "/x")]).unwrap(),
                body.replace("{{p}}", "'/x'"),
                "{body:?}"
            );
        }
    }

    /// Alias expansion carries an open `'` into text the loader already lexed:
    /// `alias q="echo '"⏎q '/tmp/x;echo PWNED_ALIAS' \'` prints ` /tmp/x` then
    /// `PWNED_ALIAS \` in dash and `bash --posix` (plain `bash -c` does not
    /// expand aliases). This body compiled before the fix. The quoted spellings
    /// (`a'l'ias`, `al\ias`, `"alias"`, `command alias`) reach the builtin after
    /// quote removal and were reproduced the same way. The offset is the matched
    /// `a`; the match ignores `'`, `"`, `\` and ASCII case.
    #[test]
    fn compile_rejects_alias_word_in_a_body_with_a_placeholder() {
        for (body, at) in [
            ("alias q=\"echo '\"\nq {{p}} \\'", 0),
            ("a'l'ias q=\"echo '\"\nq {{p}} \\'", 0),
            ("true; al\\ias q=\"echo '\"\nq {{p}} \\'", 6),
            ("command \"alias\" q=x\necho {{p}}", 9),
            // Over-match, deliberately fail-closed.
            ("cat /etc/aliases {{p}}", 9),
            // The earliest hazard wins, whichever kind.
            ("alias x=y; echo $(x) {{p}}", 0),
        ] {
            assert_eq!(
                compile_p(body).unwrap_err(),
                untrackable(at, ShellConstruct::Alias),
                "{body:?}"
            );
        }
    }

    /// bash defines an alias without the lower-case word `alias`:
    /// `bash --posix -c` with `BASH_ALIASES[q]="echo '"⏎q '/tmp/x;echo PWNED_BA' \'`
    /// printed ` /tmp/x` then `PWNED_BA \` (dash has no BASH_ALIASES). The
    /// offset is the `A` after `BASH_`.
    #[test]
    fn compile_rejects_bash_aliases_assignment_with_a_placeholder() {
        assert_eq!(
            compile_p("BASH_ALIASES[q]=\"echo '\"\nq {{p}} \\'").unwrap_err(),
            untrackable(5, ShellConstruct::Alias)
        );
    }

    // -----------------------------------------------------------------------
    // render() — substitution correctness
    // -----------------------------------------------------------------------

    #[test]
    fn render_substitutes_quoted_value_at_the_slot_position() {
        let t = compile(&def(
            "svc.status",
            "systemctl status {{unit}}",
            vec![slot("unit", SlotType::Identifier)],
        ))
        .unwrap();
        let cmd = render_cmd(&t, &[("unit", "nginx")]).unwrap();
        assert_eq!(cmd, "systemctl status 'nginx'");
        assert_eq!(shell_words(&cmd), ["systemctl", "status", "nginx"]);
    }

    #[test]
    fn render_multiple_slots_and_shell_composition() {
        // A genuine shell template (pipe + redirection are author-fixed).
        let t = compile(&def(
            "log.tail",
            "tail -n {{lines}} {{path}} | grep -c error",
            vec![
                slot("lines", SlotType::Integer),
                slot("path", SlotType::Path),
            ],
        ))
        .unwrap();
        let cmd = render_cmd(&t, &[("lines", "100"), ("path", "/var/log/syslog")]).unwrap();
        assert_eq!(cmd, "tail -n '100' '/var/log/syslog' | grep -c error");
        assert_eq!(
            shell_words(&cmd),
            [
                "tail",
                "-n",
                "100",
                "/var/log/syslog",
                "|",
                "grep",
                "-c",
                "error"
            ]
        );
    }

    #[test]
    fn render_quotes_hostile_path_value() {
        // Path permits metacharacters; quoting must keep the whole value ONE
        // inert word — no command substitution, no argument splitting.
        let t = compile(&def(
            "file.cksum",
            "sha256sum {{path}}",
            vec![slot("path", SlotType::Path)],
        ))
        .unwrap();
        let cmd = render_cmd(&t, &[("path", "/tmp/$(reboot)")]).unwrap();
        assert_eq!(cmd, "sha256sum '/tmp/$(reboot)'");
        assert_eq!(shell_words(&cmd), ["sha256sum", "/tmp/$(reboot)"]);
    }

    #[test]
    fn render_rejects_invalid_parameter_before_producing_argv() {
        let t = compile(&def(
            "svc.status",
            "systemctl status {{unit}}",
            vec![slot("unit", SlotType::Identifier)],
        ))
        .unwrap();
        let err = render_cmd(&t, &[("unit", "nginx; reboot")]).unwrap_err();
        assert!(matches!(err, TemplateError::ParameterValidation { .. }));
        // The error must not echo the raw value.
        assert!(!err.to_string().contains("reboot"));
    }

    #[test]
    fn render_missing_required_value_is_rejected() {
        let t = compile(&def(
            "svc.status",
            "systemctl status {{unit}}",
            vec![slot("unit", SlotType::Identifier)],
        ))
        .unwrap();
        // No "unit" arg → positional maps to "" → empty → validation failure.
        let err = render_cmd(&t, &[]).unwrap_err();
        assert!(matches!(err, TemplateError::ParameterValidation { .. }));
    }

    // -----------------------------------------------------------------------
    // positional_args — Policy parity contract
    // -----------------------------------------------------------------------

    #[test]
    fn positional_args_maps_in_slot_order() {
        let t = compile(&def(
            "log.tail",
            "tail -n {{lines}} {{path}}",
            vec![
                slot("lines", SlotType::Integer),
                slot("path", SlotType::Path),
            ],
        ))
        .unwrap();
        // Order follows slot declaration, not the args map insertion order.
        assert_eq!(
            t.positional_args(&op(&[("path", "/x"), ("lines", "5")])),
            ["5", "/x"]
        );
        // Missing keys map to "" (Policy wildcard territory) — same as native.
        assert_eq!(t.positional_args(&op(&[])), ["", ""]);
    }

    // -----------------------------------------------------------------------
    // serde-readiness (#291 will deserialize; NO loader committed here)
    // -----------------------------------------------------------------------

    #[test]
    fn template_def_deserializes_from_toml() {
        let toml_src = r#"
name = "log.tail"
risk_class = "read"
body = "tail -n {{lines}} {{path}}"

[[slots]]
name = "lines"
type = "integer"

[[slots]]
name = "path"
type = "path"
"#;
        let def: TemplateDef = toml::from_str(toml_src).expect("must deserialize");
        assert_eq!(def.name, "log.tail");
        assert_eq!(def.risk_class, RiskClassDef::Read);
        let t = compile(&def).expect("must compile");
        let cmd = render_cmd(&t, &[("lines", "20"), ("path", "/var/log/x")]).unwrap();
        assert_eq!(cmd, "tail -n '20' '/var/log/x'");
    }

    /// toml_parser 1.1.3 (spec 1.1.0) keeps the CR of a CRLF line ending in a
    /// multi-line string: `decode_ml_basic_string` pushes the raw `"\r\n"`
    /// slice and only a leading newline is stripped. So a CRLF-saved body whose
    /// slot ends a line reaches `compile` with the CR and is refused, while one
    /// whose slots do not end a line renders exactly as before.
    #[test]
    fn crlf_multiline_toml_body_keeps_the_cr_and_is_checked() {
        let head = "name = \"t.crlf\"\r\nrisk_class = \"read\"\r\n";
        let tail = "[[slots]]\r\nname = \"p\"\r\ntype = \"path\"\r\n";

        let src = format!("{head}body = \"\"\"\r\ncat {{{{p}}}}\r\necho done\"\"\"\r\n{tail}");
        let d: TemplateDef = toml::from_str(&src).expect("must deserialize");
        assert_eq!(d.body, "cat {{p}}\r\necho done");
        assert_eq!(
            compile(&d).unwrap_err(),
            TemplateError::PlaceholderNotStandalone { at: 4 }
        );

        let src =
            format!("{head}body = \"\"\"\r\ncat {{{{p}}}} /dev/null\r\necho done\"\"\"\r\n{tail}");
        let d: TemplateDef = toml::from_str(&src).expect("must deserialize");
        assert_eq!(d.body, "cat {{p}} /dev/null\r\necho done");
        let t = compile(&d).unwrap();
        assert_eq!(
            render_cmd(&t, &[("p", "/tmp/x")]).unwrap(),
            "cat '/tmp/x' /dev/null\r\necho done"
        );

        // A literal ''' string: in """ TOML itself consumes a line-ending
        // backslash.
        let src = format!("{head}body = '''\r\necho a\\\r\n{{{{p}}}}'''\r\n{tail}");
        let d: TemplateDef = toml::from_str(&src).expect("must deserialize");
        assert_eq!(d.body, "echo a\\\r\n{{p}}");
        assert_eq!(
            compile(&d).unwrap_err(),
            untrackable(6, ShellConstruct::LineContinuation)
        );
    }

    #[test]
    fn template_def_missing_risk_class_fails_to_deserialize() {
        // ADR-0021 / ADR-0012: a template without a risk class fails to load.
        let toml_src = r#"
name = "svc.status"
body = "systemctl status {{unit}}"

[[slots]]
name = "unit"
type = "identifier"
"#;
        assert!(toml::from_str::<TemplateDef>(toml_src).is_err());
    }

    #[test]
    fn enum_slot_deserializes_with_values() {
        let toml_src = r#"
name = "svc.show"
risk_class = "read"
body = "systemctl show --property {{prop}} nginx"

[[slots]]
name = "prop"
type = "enum"
values = ["ActiveState", "LoadState"]
"#;
        let def: TemplateDef = toml::from_str(toml_src).expect("must deserialize");
        let t = compile(&def).expect("must compile");
        assert_eq!(
            render_cmd(&t, &[("prop", "ActiveState")]).unwrap(),
            "systemctl show --property 'ActiveState' nginx"
        );
        assert!(render_cmd(&t, &[("prop", "Evil; reboot")]).is_err());
    }

    // =======================================================================
    // RED-TEAM SUITE (ADR-0021 acceptance criterion, not a follow-up).
    //
    // Adversarial parameter-injection attempts against the substitution
    // boundary, one row per attack class. For EVERY row the invariant is the
    // same and is asserted mechanically:
    //
    //   the rendered command tokenizes to the SAME word sequence as the
    //   template with the slot replaced by a benign sentinel, with the
    //   slot's word carrying the attacker's value verbatim as ONE inert word
    //   — OR the value is refused (structured error) and NOTHING renders.
    //
    // No row may add a word, an operator, a redirection, or an expansion.
    // =======================================================================

    struct RedTeam {
        name: &'static str,
        slot_type: SlotType,
        value: &'static str,
        // true  = the typed gate must REFUSE the value (fail closed);
        // false = the value is accepted but quoting keeps it one inert word.
        must_refuse: bool,
        note: &'static str,
    }

    fn redteam_rows() -> Vec<RedTeam> {
        vec![
            // --- quoting escapes ------------------------------------------
            RedTeam {
                name: "single_quote_breakout",
                slot_type: SlotType::Path,
                value: "/tmp/'; reboot; '",
                must_refuse: false,
                note: "the classic ' breakout is defused by '\\'' encoding; stays one word",
            },
            RedTeam {
                name: "double_quote_in_identifier",
                slot_type: SlotType::Identifier,
                value: "a\"b",
                must_refuse: true,
                note: "identifier charset excludes the double quote outright",
            },
            // --- whitespace / NBSP (ADR-0019 lessons) ---------------------
            RedTeam {
                name: "space_splitting_identifier",
                slot_type: SlotType::Identifier,
                value: "nginx other",
                must_refuse: true,
                note: "a space would split into a second argv word; identifier rejects it",
            },
            RedTeam {
                name: "nbsp_identifier",
                slot_type: SlotType::Identifier,
                value: "ngi\u{00a0}nx",
                must_refuse: true,
                note: "NBSP is non-ASCII whitespace; identifier rejects non-charset bytes",
            },
            RedTeam {
                name: "newline_in_path",
                slot_type: SlotType::Path,
                value: "/tmp/a\nreboot",
                must_refuse: true,
                note: "a newline is a command separator even inside quotes-as-lexed; path rejects control chars",
            },
            RedTeam {
                name: "space_in_path_quoted",
                slot_type: SlotType::Path,
                value: "/tmp/a b",
                must_refuse: false,
                note: "a real path with a space: accepted, quoting keeps it one word",
            },
            // --- metacharacters -------------------------------------------
            RedTeam {
                name: "semicolon_chain",
                slot_type: SlotType::Path,
                value: "/tmp/x;reboot",
                must_refuse: false,
                note: "'; is inert inside single quotes",
            },
            RedTeam {
                name: "command_substitution_dollar",
                slot_type: SlotType::Path,
                value: "/tmp/$(reboot)",
                must_refuse: false,
                note: "$() substitution is inert inside single quotes",
            },
            RedTeam {
                name: "command_substitution_backtick",
                slot_type: SlotType::Path,
                value: "/tmp/`reboot`",
                must_refuse: false,
                note: "backtick substitution is inert inside single quotes",
            },
            RedTeam {
                name: "pipe_and_redirect",
                slot_type: SlotType::Path,
                value: "/tmp/x|tee>/etc/passwd",
                must_refuse: false,
                note: "pipe/redirect metacharacters are inert inside single quotes",
            },
            RedTeam {
                name: "glob_and_brace",
                slot_type: SlotType::Path,
                value: "/tmp/*",
                must_refuse: false,
                note: "no glob expansion inside single quotes",
            },
            RedTeam {
                name: "var_expansion",
                slot_type: SlotType::Path,
                value: "/tmp/$HOME",
                must_refuse: false,
                note: "no parameter expansion inside single quotes",
            },
            // --- argument splitting / -- prefix injection -----------------
            RedTeam {
                name: "dash_dash_identifier",
                slot_type: SlotType::Identifier,
                value: "--force",
                must_refuse: true,
                note: "leading '-' option injection; identifier requires a leading alnum",
            },
            RedTeam {
                name: "dash_dash_path",
                slot_type: SlotType::Path,
                value: "--output=/etc/x",
                must_refuse: true,
                note: "path requires a leading '/', so a --option can never be a path value",
            },
            RedTeam {
                name: "negative_integer_option",
                slot_type: SlotType::Integer,
                value: "-1",
                must_refuse: true,
                note: "integer is unsigned; a leading '-' (option injection) is impossible",
            },
            // --- empty / oversized ----------------------------------------
            RedTeam {
                name: "empty_identifier",
                slot_type: SlotType::Identifier,
                value: "",
                must_refuse: true,
                note: "empty values are refused (all slots required)",
            },
            RedTeam {
                name: "empty_path",
                slot_type: SlotType::Path,
                value: "",
                must_refuse: true,
                note: "empty values are refused",
            },
            // --- NUL / control --------------------------------------------
            RedTeam {
                name: "nul_in_path",
                slot_type: SlotType::Path,
                value: "/tmp/a\u{0}b",
                must_refuse: true,
                note: "NUL is a control char; path rejects it",
            },
            // --- unicode direction override -------------------------------
            RedTeam {
                name: "rtl_override_identifier",
                slot_type: SlotType::Identifier,
                value: "a\u{202e}b",
                must_refuse: true,
                note: "RTL override is outside the identifier charset",
            },
            RedTeam {
                name: "rtl_override_path_quoted",
                slot_type: SlotType::Path,
                value: "/tmp/a\u{202e}b",
                must_refuse: false,
                note: "path permits non-ASCII display trickery but quoting keeps it one word (a display concern, not an injection)",
            },
        ]
    }

    #[test]
    fn redteam_no_case_alters_command_structure() {
        // Fixed one-slot template; the sentinel word marks where the slot sits.
        const SENTINEL: &str = "SENTINEL_WORD";
        for row in redteam_rows() {
            let t = compile(&def(
                "rt.probe",
                "run --flag before {{p}} after",
                vec![slot("p", row.slot_type.clone())],
            ))
            .expect("probe template compiles");

            let positional = vec![row.value.to_string()];
            let rendered = t.render(&positional);

            if row.must_refuse {
                let err = match rendered {
                    Ok(_) => panic!("[{}] must be refused (fail closed): {}", row.name, row.note),
                    Err(e) => e,
                };
                assert!(
                    matches!(err, TemplateError::ParameterValidation { .. }),
                    "[{}] refusal must be a structured ParameterValidation error, got {err:?}",
                    row.name
                );
                continue;
            }

            // Accepted: prove the structure is identical to the sentinel form.
            let argv = match rendered {
                Ok(a) => a,
                Err(e) => panic!("[{}] expected to render: {e:?}", row.name),
            };
            assert_eq!(
                argv.len(),
                3,
                "[{}] argv must be [/bin/sh, -c, cmd]",
                row.name
            );
            assert_eq!(argv[0], "/bin/sh");
            assert_eq!(argv[1], "-c");
            let cmd = &argv[2];

            let words = shell_words(cmd);
            let expected: Vec<String> = shell_words("run --flag before SENTINEL_WORD after")
                .into_iter()
                .map(|w| {
                    if w == SENTINEL {
                        row.value.to_string()
                    } else {
                        w
                    }
                })
                .collect();
            assert_eq!(
                words, expected,
                "[{}] tokenized structure changed — {}",
                row.name, row.note
            );
            // And the slot's word is the value verbatim, exactly once.
            assert_eq!(
                words
                    .iter()
                    .filter(|w| *w == &row.value.to_string())
                    .count(),
                1,
                "[{}] the value must appear as exactly one word",
                row.name
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Property tests — structural-invariance under arbitrary inputs (issue #218
// posture: attack the substitution boundary for structure drift and panics).
// ---------------------------------------------------------------------------
//
// Regression seeds are tracked, not ignored (#259): commit
// `daemon/proptest-regressions/` files with the fix; the full rule is in
// `policy.rs`'s `mod proptests` header.

#[cfg(test)]
mod proptests {
    use super::{compile, shell_words, RiskClassDef, SlotDef, SlotType, TemplateDef, TemplateOp};
    use proptest::prelude::*;

    fn one_slot_template(ty: SlotType) -> TemplateOp {
        compile(&TemplateDef {
            name: "pt.probe".to_string(),
            risk_class: RiskClassDef::Read,
            body: "cmd a {{p}} b".to_string(),
            slots: vec![SlotDef {
                name: "p".to_string(),
                ty,
            }],
        })
        .expect("probe template compiles")
    }

    proptest! {
        // Whatever arbitrary string arrives, render either fails closed OR
        // produces a command whose token structure equals the sentinel form
        // with the slot word carrying the value verbatim. Never a panic,
        // never an extra word/operator.
        #[test]
        fn arbitrary_value_never_alters_structure(value in ".{0,64}") {
            let t = one_slot_template(SlotType::Path);
            match t.render(std::slice::from_ref(&value)) {
                Err(_) => { /* fail closed — acceptable */ }
                Ok(argv) => {
                    prop_assert_eq!(argv.len(), 3);
                    prop_assert_eq!(&argv[0], "/bin/sh");
                    prop_assert_eq!(&argv[1], "-c");
                    let words = shell_words(&argv[2]);
                    // Expected structure: ["cmd", "a", <value>, "b"].
                    prop_assert_eq!(words.len(), 4);
                    prop_assert_eq!(&words[0], "cmd");
                    prop_assert_eq!(&words[1], "a");
                    prop_assert_eq!(&words[2], &value);
                    prop_assert_eq!(&words[3], "b");
                }
            }
        }

        // Any value the Identifier gate ACCEPTS is a single shell word equal to
        // itself and contains no shell metacharacter.
        #[test]
        fn accepted_identifier_is_one_clean_word(value in "[A-Za-z0-9][A-Za-z0-9_.@+-]{0,31}") {
            let t = one_slot_template(SlotType::Identifier);
            let argv = t.render(std::slice::from_ref(&value)).expect("valid identifier renders");
            let words = shell_words(&argv[2]);
            prop_assert_eq!(words, vec!["cmd".to_string(), "a".to_string(), value, "b".to_string()]);
        }

        // Any accepted Path value — including hostile metacharacters — remains
        // exactly one word after tokenization.
        #[test]
        fn accepted_path_is_one_word(seg in "[^/\u{0}-\u{1f}\u{7f}]{1,24}") {
            let value = format!("/tmp/{seg}");
            let t = one_slot_template(SlotType::Path);
            // Some segments (containing '.'/'..' whole segments) are refused;
            // only assert structure when accepted.
            if let Ok(argv) = t.render(std::slice::from_ref(&value)) {
                let words = shell_words(&argv[2]);
                prop_assert_eq!(words.len(), 4);
                prop_assert_eq!(&words[2], &value);
            }
        }

        // Integer gate: accepts iff all-ASCII-digits within the digit bound.
        #[test]
        fn integer_gate_matches_spec(value in ".{0,24}") {
            let t = one_slot_template(SlotType::Integer);
            let accepted = t.render(std::slice::from_ref(&value)).is_ok();
            let expected = !value.is_empty()
                && value.len() <= 19
                && value.bytes().all(|b| b.is_ascii_digit());
            prop_assert_eq!(accepted, expected);
        }
    }
}
