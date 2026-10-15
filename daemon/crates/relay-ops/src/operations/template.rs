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
//! passing the values as data**, gated by a **red-team suite** (an acceptance
//! criterion of the milestone, not a follow-up).
//!
//! This is the ONE place in the daemon that constructs a `/bin/sh -c` command
//! from a template. Invariant 1 ("argv, never `/bin/sh`") governs *Native
//! Operations* (tier 1); the template tier is tier 2, whose whole reason to
//! exist is shell composition. The command *structure* is author-fixed (from a
//! root-owned local file, ADR-0002 trust root — loaded by [`crate::templates`]);
//! only the positional parameter values vary.
//!
//! # Two layers of defense
//!
//! 1. **Typed validation** ([`SlotType::validate`]): each value is checked
//!    against its slot's declared type. `Identifier`, `Integer`, and `Enum`
//!    reject every shell metacharacter, whitespace (ASCII and non-ASCII such as
//!    NBSP), and control character outright. `Path` admits plain filenames only:
//!    no whitespace and none of ``$ ` \ " ' ; | & < > ( ) { } [ ] * ? ! # ~ =``.
//! 2. **Positional parameters** (ADR-0021, amended 2026-10-14; invariant 1): no
//!    value is ever part of the text the shell parses. Each placeholder compiles
//!    to a quoted reference (`"$1"`, `"$2"`, …) and the values travel as the
//!    arguments of the fixed script: `["/bin/sh", "-c", <script>,
//!    "relay-template", v1, …, vN]`. The script is the same for every call.
//!
//! # Command-structure integrity is proven at *compile* time
//!
//! [`compile`] lexes the template body once (`template_body`) and
//! refuses any template where a placeholder is not a **standalone word in an
//! unquoted, expanding context**. A standalone word replaced by one quoted
//! parameter reference stays one word, so no value can change the token count
//! or the operators around it.
//!
//! # Policy parity
//!
//! A compiled [`TemplateOp`] implements [`super::registry::ResolvedOp`], the
//! same `name → (handler, arg-shape, risk class)` contract Native Operations
//! resolve through. Its [`ResolvedOp::positional_args`] uses the
//! identical named-args → positional mapping, so `policy.evaluate(name,
//! positional)` governs a template **byte-for-byte** like a Native Operation:
//! deny-by-default, deny-beats-allow, argument-level constraints. The Policy
//! engine is name-agnostic; the template's name simply enters the same
//! vocabulary. There is no second evaluator (ADR-0011).
//!
//! # Scope
//!
//! This module is the engine: definitions, compilation, typed
//! validation, and rendering. Loading those definitions from
//! root-owned local files, the template-set fingerprint, the `unsupported`
//! per-Node outcome, and live discovery are [`crate::templates`].

use std::collections::HashSet;

use serde::{Deserialize, Serialize};

use crate::executor::ExecRequest;
use crate::gen::{Operation, Outcome, RiskClass};
use crate::limits::ResourceLimits;
use crate::not_executed::not_executed;

use super::registry::{OpCtx, OpFuture, ResolvedOp};
use super::template_body::{self, BodyAnalysis};
pub use super::template_code::{BodyWarning, CodePosition, WarningKind};

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

/// Characters a `Path` slot refuses (besides whitespace and control characters).
const PATH_REFUSED_CHARS: &str = "$`\\\"';|&<>(){}[]*?!#~=";

/// Largest accepted value for an `Integer` slot (fits i64/u64 decimal digits).
const MAX_INTEGER_DIGITS: usize = 19;

// ---------------------------------------------------------------------------
// Serde-ready definition model ([`crate::templates`] deserializes into these;
// no loader here)
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
/// every shell metacharacter by construction. `Path` is the widest type
/// (canonical absolute paths of plain filenames: letters of any script, digits
/// and a few punctuation marks, no whitespace and no shell-significant
/// character); it is the primary red-team target. Values are passed as
/// positional parameters whatever the type.
///
/// No daemon-owned type admits a value that begins with `-` (ADR-0021 decision
/// 3), so a slot value can never be read as an option. A new variant must keep
/// that property or say why not.
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
    /// characters, no Unicode whitespace, and none of ``$ ` \\ " ' ; | & < > ( ) { }
    /// [ ] * ? ! # ~ =``. Letters of any script, digits and `- _ . , + @ % : ^`
    /// are permitted. This is narrower than Native `file.read`'s path check.
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

/// A Template Operation definition, as authored (and deserialized from a
/// root-owned local file by [`crate::templates`]).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct TemplateDef {
    /// The Operation name this template registers under (enters the Policy
    /// vocabulary exactly like a Native Operation name).
    pub name: String,
    /// Mandatory risk class (ADR-0012).
    pub risk_class: RiskClassDef,
    /// The shell template body: author-fixed structure with `{{slot}}`
    /// placeholders standing as whole, whitespace-delimited words. Each is
    /// passed to the shell as a positional parameter.
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
        "a placeholder near byte {at} is not a standalone whitespace-delimited word \
         (a slot must fill exactly one lexical position; it may not be glued to \
         adjacent text, quotes or an operator, or follow an escaped space)"
    )]
    PlaceholderNotStandalone { at: usize },

    #[error("a placeholder appears inside a quoted region near byte {at}; slots must sit in an unquoted context")]
    PlaceholderInQuotedContext { at: usize },

    #[error("a placeholder near byte {at} sits in {context}, where the shell never expands it")]
    PlaceholderNotExpanded { at: usize, context: &'static str },

    #[error("a placeholder near byte {at} sits in {context}; a slot may only stand as a plain word of the top-level command list")]
    PlaceholderNotTopLevel { at: usize, context: &'static str },

    #[error("a placeholder near byte {at} stands in {kind}")]
    PlaceholderInCodePosition { at: usize, kind: CodePosition },

    #[error("a placeholder near byte {at} sits inside arithmetic, where the shell evaluates expanded values as expressions")]
    PlaceholderInArithmetic { at: usize },

    #[error(
        "template body near byte {at} cannot be analysed ({reason}), and it holds a placeholder"
    )]
    BodyNotAnalysable { at: usize, reason: &'static str },

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
pub(super) struct Slot {
    pub(super) name: String,
    pub(super) ty: SlotType,
}

/// `$0` of every Template script: a fixed, recognisable name in shell error
/// messages, never a value.
const TEMPLATE_ARGV0: &str = "relay-template";

/// The quoted positional-parameter reference for the slot at declaration index
/// `index`: slot `i` is `"$<i+1>"`, or `"${<i+1>}"` from the tenth on, because
/// `$10` would read as `${1}0`.
pub(super) fn positional_ref(index: usize) -> String {
    let n = index + 1;
    if n <= 9 {
        format!("\"${n}\"")
    } else {
        format!("\"${{{n}}}\"")
    }
}

/// A compiled Template Operation: name, risk class, ordered slots, and the
/// script `/bin/sh -c` runs. Immutable after [`compile`]; rendering is pure.
#[derive(Debug, Clone)]
pub struct TemplateOp {
    name: String,
    risk: RiskClass,
    slots: Vec<Slot>,
    script: String,
    warnings: Vec<BodyWarning>,
}

impl TemplateOp {
    /// What `policy check` reports about the body: it loads, and `--strict`
    /// fails it.
    pub fn warnings(&self) -> &[BodyWarning] {
        &self.warnings
    }

    /// The script `/bin/sh -c` runs: the body with each placeholder replaced by
    /// its quoted positional parameter. Built once at compile time, so it is the
    /// same text for every call whatever the values are.
    pub fn script(&self) -> &str {
        &self.script
    }

    /// The positions of `path`-typed slots, in positional (Policy) order.
    ///
    /// Consumed by the dispatch gate to apply ADR-0018's
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
    /// discovery surface renders these into `TemplateDescriptor.slots`
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
    /// vector [`render`] validates and passes to the shell, so what Policy
    /// evaluated is exactly what the command receives.
    ///
    /// [`render`]: TemplateOp::render
    fn positional_args(&self, op: &Operation) -> Vec<String> {
        self.slots
            .iter()
            .map(|s| op.args.get(&s.name).cloned().unwrap_or_default())
            .collect()
    }

    /// Validate the values and produce the argv to execute.
    ///
    /// `positional[i]` is the raw value for `slots[i]` — the very vector Policy
    /// evaluated (see [`positional_args`]). Each value is validated against its
    /// slot type (fail closed on the first violation — no spawn) and then
    /// passed untouched as a positional parameter. The result is
    /// `["/bin/sh", "-c", <script>, "relay-template", v1, …, vN]`: the script is
    /// fixed at compile time and `v1…vN` are byte-identical to `positional`.
    ///
    /// [`positional_args`]: TemplateOp::positional_args
    fn render(&self, positional: &[String]) -> Result<Vec<String>, TemplateError> {
        if positional.len() != self.slots.len() {
            return Err(TemplateError::ArityMismatch {
                got: positional.len(),
                want: self.slots.len(),
            });
        }

        for (slot, value) in self.slots.iter().zip(positional) {
            slot.ty
                .validate(value)
                .map_err(|reason| TemplateError::ParameterValidation {
                    slot: slot.name.clone(),
                    slot_type: slot.ty.type_name(),
                    value_len: value.len(),
                    reason,
                })?;
        }

        let mut argv = Vec::with_capacity(4 + positional.len());
        argv.push("/bin/sh".to_string());
        argv.push("-c".to_string());
        argv.push(self.script.clone());
        argv.push(TEMPLATE_ARGV0.to_string());
        argv.extend(positional.iter().cloned());
        Ok(argv)
    }
}

// ---------------------------------------------------------------------------
// Registry integration — a compiled template resolves through the SAME
// name → (handler, arg-shape, risk class) contract as a Native Operation,
// so Policy governs it identically and dispatch needs no
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

            // Validate the exact vector Policy evaluated and pass it on. A
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
/// Every check that could let a value alter command structure is enforced
/// here, at load time, so rendering is a pure validate-and-pass step:
/// - the name and every slot name are well-formed and unique;
/// - the body is non-empty and bounded;
/// - the body's quoting is balanced;
/// - every `{{slot}}` is a **standalone, whitespace-delimited word in an
///   unquoted context** and resolves to a declared slot;
/// - no placeholder stands where its value would be executed (`template_code`);
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

    // --- lex the body, replacing placeholders with positional parameters ---
    let BodyAnalysis {
        script,
        referenced,
        warnings,
    } = template_body::analyse(&def.body, &slots)?;

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
        script,
        warnings,
    })
}

// ---------------------------------------------------------------------------
// Slot-type validation — the typed gate (layer 1 of the two layers of defense)
// ---------------------------------------------------------------------------

impl SlotType {
    /// A stable label for error messages / audit (never the value), and the
    /// wire `TemplateSlot.type` string a surface renders for discovery.
    pub fn type_name(&self) -> &'static str {
        match self {
            SlotType::Identifier => "identifier",
            SlotType::Integer => "integer",
            SlotType::Path => "path",
            SlotType::Enum(_) => "enum",
        }
    }

    /// The author-supplied allow-list for an `Enum` slot; empty for every other
    /// type. Part of the discovery surface: an `enum` slot's finite
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
                // Reject ASCII control chars (NUL, newline, tab, CR, …) and DEL:
                // a Path value is a filename, never a place for a newline.
                if value.chars().any(|c| (c as u32) < 0x20 || c == '\u{7f}') {
                    return Err("contains an ASCII control character");
                }
                // A Template path is a plain filename: no Unicode whitespace and
                // no character a shell, a glob or an argument parser gives
                // meaning to, so a path stays inert wherever a command reads it.
                if value
                    .chars()
                    .any(|c| c.is_whitespace() || PATH_REFUSED_CHARS.contains(c))
                {
                    return Err("contains whitespace or a shell-significant character");
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
// Name predicates
// ---------------------------------------------------------------------------

/// `^[a-z][a-z0-9_.]*$` and not `raw_exec` (reserved; ADR-0001).
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
pub(super) fn is_valid_slot_name(name: &str) -> bool {
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

    /// Render helper: map named args → positional (the Policy vector), then
    /// render. Returns the full argv on success.
    fn render_argv(t: &TemplateOp, args: &[(&str, &str)]) -> Result<Vec<String>, TemplateError> {
        let positional = t.positional_args(&op(args));
        let argv = t.render(&positional)?;
        assert_eq!(argv[0], "/bin/sh");
        assert_eq!(argv[1], "-c");
        assert_eq!(argv[3], TEMPLATE_ARGV0);
        assert_eq!(argv[4..], positional[..], "values are passed untouched");
        Ok(argv)
    }

    /// Render helper: the `/bin/sh -c` script of a successful render.
    fn render_cmd(t: &TemplateOp, args: &[(&str, &str)]) -> Result<String, TemplateError> {
        render_argv(t, args).map(|argv| argv[2].clone())
    }

    // -----------------------------------------------------------------------
    // positional_ref
    // -----------------------------------------------------------------------

    #[test]
    fn positional_ref_braces_from_the_tenth_slot() {
        assert_eq!(positional_ref(0), "\"$1\"");
        assert_eq!(positional_ref(8), "\"$9\"");
        // `$10` would read as `${1}0`.
        assert_eq!(positional_ref(9), "\"${10}\"");
        assert_eq!(positional_ref(63), "\"${64}\"");
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
    fn path_refuses_whitespace_and_shell_significant_characters() {
        for c in "$`\\\"';|&<>(){}[]*?!#~=".chars() {
            let value = format!("/tmp/a{c}b");
            assert!(
                SlotType::Path.validate(&value).is_err(),
                "path must refuse {c:?}"
            );
        }
        for ws in [' ', '\u{a0}', '\u{2003}', '\u{3000}', '\u{85}', '\u{2028}'] {
            let value = format!("/tmp/a{ws}b");
            assert!(SlotType::Path.validate(&value).is_err(), "{ws:?}");
        }
        for value in [
            "/x[$(echo PWNED>&2)]",
            "/tmp -maxdepth 0 -exec echo PWNED-find ; -quit/x",
            "/tmp/$(reboot)",
            "/tmp/`reboot`",
        ] {
            assert!(SlotType::Path.validate(value).is_err(), "{value:?}");
        }
    }

    #[test]
    fn path_accepts_ordinary_filenames() {
        for good in [
            "/var/log/syslog",
            "/etc/nginx/sites-enabled/default.conf",
            "/srv/app-1.2_x/data@2026,v2+final.txt",
            "/home/josé/notes",
            "/home/用户/文档.txt",
            "/var/lib/a%b/c:d^e",
        ] {
            assert!(SlotType::Path.validate(good).is_ok(), "{good:?}");
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
    // render() — substitution correctness
    // -----------------------------------------------------------------------

    #[test]
    fn render_passes_the_value_as_a_positional_parameter() {
        let t = compile(&def(
            "svc.status",
            "systemctl status {{unit}}",
            vec![slot("unit", SlotType::Identifier)],
        ))
        .unwrap();
        let argv = render_argv(&t, &[("unit", "nginx")]).unwrap();
        assert_eq!(
            argv,
            [
                "/bin/sh",
                "-c",
                "systemctl status \"$1\"",
                "relay-template",
                "nginx"
            ]
        );
        assert_eq!(t.script(), "systemctl status \"$1\"");
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
        let argv = render_argv(&t, &[("lines", "100"), ("path", "/var/log/syslog")]).unwrap();
        assert_eq!(argv[2], "tail -n \"$1\" \"$2\" | grep -c error");
        assert_eq!(argv[4..], ["100", "/var/log/syslog"]);
    }

    #[test]
    fn render_passes_hostile_value_as_data() {
        // An Enum value is whatever its author listed; the value never enters
        // the script, so it cannot be substituted, split or expanded.
        let t = compile(&def(
            "file.cksum",
            "sha256sum {{path}}",
            vec![slot("path", SlotType::Enum(vec!["/tmp/$(reboot)".into()]))],
        ))
        .unwrap();
        let argv = render_argv(&t, &[("path", "/tmp/$(reboot)")]).unwrap();
        assert_eq!(argv[2], "sha256sum \"$1\"");
        assert_eq!(argv[4], "/tmp/$(reboot)");
        assert!(!argv[2].contains("reboot"));
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
        assert_eq!(cmd, "tail -n \"$1\" \"$2\"");
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
            "systemctl show --property \"$1\" nginx"
        );
        assert!(render_cmd(&t, &[("prop", "Evil; reboot")]).is_err());
    }

    // =======================================================================
    // RED-TEAM SUITE (ADR-0021 acceptance criterion, not a follow-up).
    //
    // Adversarial parameter-injection attempts against the typed gate and the
    // render boundary, one row per attack class. For EVERY row the invariant is
    // the same and is asserted mechanically:
    //
    //   the argv is the fixed script plus the attacker's value verbatim as a
    //   positional parameter — OR the value is refused (structured error) and
    //   NOTHING renders.
    //
    // The same rows run through a real shell in `tests/template_redteam.rs`.
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
                slot_type: SlotType::Enum(vec!["/tmp/'; reboot; '".into()]),
                value: "/tmp/'; reboot; '",
                must_refuse: false,
                note: "the classic ' breakout is inert: the value is data, never shell text",
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
                note: "a newline is a command separator in shell text; path rejects control chars",
            },
            RedTeam {
                name: "space_in_path_quoted",
                slot_type: SlotType::Enum(vec!["/tmp/a b".into()]),
                value: "/tmp/a b",
                must_refuse: false,
                note: "a real path with a space: accepted, passed as one argument",
            },
            // --- metacharacters -------------------------------------------
            RedTeam {
                name: "semicolon_chain",
                slot_type: SlotType::Enum(vec!["/tmp/x;reboot".into()]),
                value: "/tmp/x;reboot",
                must_refuse: false,
                note: "`;` is inert: the value is never parsed as shell",
            },
            RedTeam {
                name: "command_substitution_dollar",
                slot_type: SlotType::Enum(vec!["/tmp/$(reboot)".into()]),
                value: "/tmp/$(reboot)",
                must_refuse: false,
                note: "$() substitution is inert: the value is never parsed as shell",
            },
            RedTeam {
                name: "command_substitution_backtick",
                slot_type: SlotType::Enum(vec!["/tmp/`reboot`".into()]),
                value: "/tmp/`reboot`",
                must_refuse: false,
                note: "backtick substitution is inert: the value is never parsed as shell",
            },
            RedTeam {
                name: "pipe_and_redirect",
                slot_type: SlotType::Enum(vec!["/tmp/x|tee>/etc/passwd".into()]),
                value: "/tmp/x|tee>/etc/passwd",
                must_refuse: false,
                note: "pipe/redirect metacharacters are inert: the value is never parsed as shell",
            },
            RedTeam {
                name: "glob_and_brace",
                slot_type: SlotType::Enum(vec!["/tmp/*".into()]),
                value: "/tmp/*",
                must_refuse: false,
                note: "no glob expansion: the parameter reference is double-quoted",
            },
            RedTeam {
                name: "var_expansion",
                slot_type: SlotType::Enum(vec!["/tmp/$HOME".into()]),
                value: "/tmp/$HOME",
                must_refuse: false,
                note: "no second-level expansion: the value is never re-parsed",
            },
            RedTeam {
                name: "path_refuses_command_substitution",
                slot_type: SlotType::Path,
                value: "/tmp/$(reboot)",
                must_refuse: true,
                note: "a Path slot refuses shell-significant characters outright",
            },
            RedTeam {
                name: "path_refuses_embedded_option_text",
                slot_type: SlotType::Path,
                value: "/tmp -maxdepth 0 -exec echo PWNED ; -quit/x",
                must_refuse: true,
                note: "a Path slot refuses whitespace and ';'",
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
                slot_type: SlotType::Enum(vec!["/tmp/a\u{202e}b".into()]),
                value: "/tmp/a\u{202e}b",
                must_refuse: false,
                note: "path permits non-ASCII display trickery; it is passed as one argument (a display concern, not an injection)",
            },
        ]
    }

    #[test]
    fn redteam_no_case_alters_command_structure() {
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

            let argv = match rendered {
                Ok(a) => a,
                Err(e) => panic!("[{}] expected to render: {e:?}", row.name),
            };
            assert_eq!(
                argv,
                [
                    "/bin/sh",
                    "-c",
                    "run --flag before \"$1\" after",
                    "relay-template",
                    row.value
                ],
                "[{}] {}",
                row.name,
                row.note
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Property tests — structural-invariance under arbitrary inputs: attack the
// render boundary for structure drift and panics.
// ---------------------------------------------------------------------------
//
// Regression seeds are tracked, not ignored: commit
// `daemon/proptest-regressions/` files with the fix; the full rule is in
// `policy.rs`'s `mod proptests` header.

#[cfg(test)]
mod proptests {
    use super::{compile, RiskClassDef, SlotDef, SlotType, TemplateDef, TemplateOp};
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

    /// A fixture for the invariance property: a body, its slot names in
    /// declaration order, and the script it must compile to, written out by
    /// hand so the expectation does not come from the code under test.
    struct Fixture {
        body: String,
        slots: Vec<String>,
        golden: String,
    }

    fn fixtures() -> Vec<Fixture> {
        let names = |ns: &[&str]| ns.iter().map(|n| n.to_string()).collect::<Vec<_>>();
        // Twelve slots referenced in reverse order: positional index follows
        // declaration order, not order of appearance, and `${10}` is braced.
        let many: Vec<String> = (1..=12).map(|i| format!("a{i}")).collect();
        let many_body = (1..=12)
            .rev()
            .map(|i| format!("{{{{a{i}}}}}"))
            .collect::<Vec<_>>()
            .join(" ");
        let many_golden = (1..=12)
            .rev()
            .map(|i| {
                if i <= 9 {
                    format!("\"${i}\"")
                } else {
                    format!("\"${{{i}}}\"")
                }
            })
            .collect::<Vec<_>>()
            .join(" ");
        vec![
            Fixture {
                body: "cmd a {{p}} b".into(),
                slots: names(&["p"]),
                golden: "cmd a \"$1\" b".into(),
            },
            Fixture {
                body: "tail -n {{b}} {{a}} | grep -c x".into(),
                slots: names(&["a", "b"]),
                golden: "tail -n \"$2\" \"$1\" | grep -c x".into(),
            },
            Fixture {
                body: "cat {{a}} {{b}} {{a}}".into(),
                slots: names(&["a", "b"]),
                golden: "cat \"$1\" \"$2\" \"$1\"".into(),
            },
            Fixture {
                body: "echo {{p}} | cat -n {{p}}".into(),
                slots: names(&["p"]),
                golden: "echo \"$1\" | cat -n \"$1\"".into(),
            },
            Fixture {
                body: "{ echo {{p}} ; }".into(),
                slots: names(&["p"]),
                golden: "{ echo \"$1\" ; }".into(),
            },
            Fixture {
                body: format!("f {many_body}"),
                slots: many,
                golden: format!("f {many_golden}"),
            },
        ]
    }

    fn compile_fixture(f: &Fixture) -> TemplateOp {
        compile(&TemplateDef {
            name: "pt.fixture".to_string(),
            risk_class: RiskClassDef::Read,
            body: f.body.clone(),
            slots: f
                .slots
                .iter()
                .map(|n| SlotDef {
                    name: n.clone(),
                    ty: SlotType::Path,
                })
                .collect(),
        })
        .expect("fixture compiles")
    }

    /// A valid `Path` value: one segment of shell-hostile characters, with a
    /// per-value sentinel that must never appear outside `argv[4..]`.
    fn path_value() -> impl Strategy<Value = String> {
        ("[a-f0-9]{8}", "[a-zA-Z0-9_.,+@%:^-]{0,16}")
            .prop_map(|(sentinel, tail)| format!("/SENT{sentinel}{tail}"))
    }

    proptest! {
        // The parsed text never depends on the values. Four independent checks,
        // none of which reads `TemplateOp::script()` as its own oracle: the
        // script is a golden literal, no sentinel byte of any value reaches
        // argv[0..4], argv[2] is the same for two different value vectors, and
        // argv[4..] is the positional vector verbatim.
        #[test]
        fn parsed_text_is_invariant_across_values(
            seeds in proptest::collection::vec((path_value(), path_value()), 12),
        ) {
            for f in fixtures() {
                let t = compile_fixture(&f);
                let n = f.slots.len();
                let first: Vec<String> = seeds.iter().take(n).map(|(a, _)| a.clone()).collect();
                let second: Vec<String> = seeds.iter().take(n).map(|(_, b)| b.clone()).collect();

                let a = t.render(&first).expect("valid values render");
                let b = t.render(&second).expect("valid values render");

                prop_assert_eq!(&a[2], &f.golden);
                prop_assert_eq!(&a[2], &b[2]);
                prop_assert_eq!(&a[..2], ["/bin/sh", "-c"]);
                prop_assert_eq!(&a[3], "relay-template");
                for v in first.iter().chain(&second) {
                    let sentinel = &v[1..13];
                    for fixed in a[..4].iter().chain(&b[..4]) {
                        prop_assert!(!fixed.contains(sentinel));
                    }
                }
                prop_assert_eq!(&a[4..], &first[..]);
                prop_assert_eq!(&b[4..], &second[..]);
            }
        }

        // Whatever arbitrary string arrives, render either fails closed OR
        // produces the fixed argv with the value verbatim. Never a panic.
        #[test]
        fn arbitrary_value_never_alters_structure(value in ".{0,64}") {
            let t = one_slot_template(SlotType::Path);
            if let Ok(argv) = t.render(std::slice::from_ref(&value)) {
                prop_assert_eq!(
                    argv,
                    vec![
                        "/bin/sh".to_string(),
                        "-c".to_string(),
                        "cmd a \"$1\" b".to_string(),
                        "relay-template".to_string(),
                        value,
                    ]
                );
            }
        }

        // Any value the Identifier gate ACCEPTS is passed verbatim.
        #[test]
        fn accepted_identifier_is_passed_verbatim(value in "[A-Za-z0-9][A-Za-z0-9_.@+-]{0,31}") {
            let t = one_slot_template(SlotType::Identifier);
            let argv = t.render(std::slice::from_ref(&value)).expect("valid identifier renders");
            prop_assert_eq!(&argv[4..], std::slice::from_ref(&value));
        }

        // Any accepted Path value — including hostile metacharacters — is
        // passed verbatim as exactly one argument.
        #[test]
        fn accepted_path_is_passed_verbatim(seg in "[^/\u{0}-\u{1f}\u{7f}]{1,24}") {
            let value = format!("/tmp/{seg}");
            let t = one_slot_template(SlotType::Path);
            // Some segments (containing '.'/'..' whole segments) are refused;
            // only assert when accepted.
            if let Ok(argv) = t.render(std::slice::from_ref(&value)) {
                prop_assert_eq!(argv.len(), 5);
                prop_assert_eq!(&argv[4], &value);
            }
        }

        // Independent oracle for the Path allow-set: whatever is accepted is an
        // absolute path with no whitespace and no shell-significant character.
        #[test]
        fn accepted_path_is_plain(value in ".{0,40}") {
            if SlotType::Path.validate(&value).is_ok() {
                prop_assert!(value.starts_with('/'));
                prop_assert!(!value.chars().any(|c| c.is_whitespace() || c.is_control()));
                let refused = "$`\\\"';|&<>(){}[]*?!#~=";
                prop_assert!(!value.chars().any(|c| refused.contains(c)));
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

        // ADR-0021 decision 3: no daemon-owned slot type admits a value that
        // begins with '-', so a slot value is never read as an option.
        #[test]
        fn no_daemon_owned_slot_type_admits_a_leading_dash(
            anything in ".{0,32}",
            dashed in "-.{0,31}",
        ) {
            for ty in [SlotType::Identifier, SlotType::Integer, SlotType::Path] {
                prop_assert!(ty.validate(&dashed).is_err(), "{} admitted a leading dash", ty.type_name());
                if ty.validate(&anything).is_ok() {
                    prop_assert!(!anything.starts_with('-'));
                }
            }
        }
    }

    /// Every slot type must be decided here. The exhaustive `match` has no
    /// wildcard, so a new variant does not compile until its leading-dash
    /// behaviour is stated.
    #[test]
    fn leading_dash_property_is_decided_per_type() {
        let candidates = [
            SlotType::Identifier,
            SlotType::Integer,
            SlotType::Path,
            SlotType::Enum(vec!["-x".into()]),
        ];
        for ty in candidates {
            match &ty {
                // Daemon-owned types: the type itself refuses a leading dash.
                SlotType::Identifier | SlotType::Integer | SlotType::Path => {
                    for v in ["-", "--", "-x", "-1", "--output=/etc/x", "-/etc/x"] {
                        assert!(ty.validate(v).is_err(), "{} admitted {v:?}", ty.type_name());
                    }
                }
                // Author-owned: the value space is the author's list, and
                // nothing else is admitted.
                SlotType::Enum(values) => {
                    assert!(ty.validate(&values[0]).is_ok());
                    assert!(ty.validate("--other").is_err());
                }
            }
        }
    }
}
