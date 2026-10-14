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
//! from a template. Invariant 1 ("argv, never `/bin/sh`") governs *Native
//! Operations* (tier 1); the template tier is tier 2, whose whole reason to
//! exist is shell composition. The command *structure* is author-fixed (from a
//! root-owned local file, ADR-0002 trust root — loaded by [`crate::templates`]);
//! only the quoted slot values vary.
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
//! whitespace-delimited token in an unquoted context**. That single rule makes
//! the runtime guarantee trivial: a standalone token replaced by one quoted
//! word stays one word, so no value can change the token count or the operators
//! around it. (The more-restrictive reading of ADR-0021's "fills exactly one
//! lexical position" — see the PR body for the judgment calls.)
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
//! validation, quoting, and rendering. Loading those definitions from
//! root-owned local files, the template-set fingerprint, the `unsupported`
//! per-Node outcome, and live discovery are [`crate::templates`].

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
    /// placeholders standing as whole, whitespace-delimited tokens.
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
        "a placeholder near byte {at} is not a standalone whitespace-delimited token \
         (a slot must fill exactly one lexical position; it may not be glued to \
         adjacent text or quotes)"
    )]
    PlaceholderNotStandalone { at: usize },

    #[error("a placeholder appears inside a quoted region near byte {at}; slots must sit in an unquoted context")]
    PlaceholderInQuotedContext { at: usize },

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
/// - every `{{slot}}` is a **standalone, whitespace-delimited token in an
///   unquoted context** and resolves to a declared slot;
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

    while i < n {
        let c = chars[i];

        // A backslash-escaped char is always literal (unquoted or double-quoted
        // context; single quotes have no escape).
        if escaped {
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
            // Left boundary: start-of-body or ASCII whitespace only.
            if !(i == 0 || chars[i - 1].is_ascii_whitespace()) {
                return Err(TemplateError::PlaceholderNotStandalone { at: byte_at(i) });
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

            // Right boundary: end-of-body or ASCII whitespace only.
            if !(j + 2 >= n || chars[j + 2].is_ascii_whitespace()) {
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
