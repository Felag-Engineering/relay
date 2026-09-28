//! Canonical, machine-readable Operation schema — the golden-artifact
//! contract guard (ADR-0015).
//!
//! The Relay's `opvocab` package advertises per-argument constraint prose to
//! the AI-agent (charset, "no leading '-'", "start and end alphanumeric").
//! That prose MUST exactly match what the daemon's own `validate_*`
//! functions actually enforce — a mismatch here is a *safety* defect: it
//! misleads the AI-agent about what argument is safe. This module is the
//! daemon-side half of three independent trip-wires that make such a lie
//! unable to survive:
//!
//!   (a) [`charset_matches_real_validator_byte_space`] (binds `predicate` to
//!       the real `validate_*` function) plus
//!       [`display_matches_declared_predicate_byte_space`] (binds the
//!       serialized `display` string to that same `predicate`) — together,
//!       this file's exhaustive proof tests bind every [`ArgSpec`]'s
//!       ADVERTISED charset to the real validator, byte by byte, not just
//!       its test-only `predicate` twin.
//!   (b) `opschema-drift` CI step — regenerates `operations.schema.json` via
//!       the `dump-operation-schema` subcommand and fails on any diff.
//!   (c) `relay/internal/opvocab/opvocab_test.go` — a hermetic Go test that
//!       cross-checks `opvocab.Operations()` against the committed golden.
//!
//! **Deliberate trade-off:** the [`ArgSpec`] charset predicates below are a
//! SECOND, independent expression of each validator's accept-set — not the
//! validator itself, and not a shared const the validator consumes. Rewiring
//! the validators to consume this table would touch the ADR-0001
//! argv-injection gate; the proof test proves the two expressions equal
//! instead, leaving the security-critical validation code untouched.
//!
//! `file.read`'s `path` argument is unconstrained DATA (`charset: None`) —
//! see `file_read.rs`'s module doc: path restriction is a Policy
//! arg-constraint concern, not an Operation-level charset.

use super::{pkg_install, service_restart, OperationError};

// ---------------------------------------------------------------------------
// OP_ARG_* key constants — relocated here from dispatch.rs (the single
// definition site for every side of the arg-key contract: dispatch.rs reads
// them out of `Operation.args`, this schema advertises them, and
// `relay/internal/opvocab` documents them against the golden).
// ---------------------------------------------------------------------------

/// v1 arg-key contract: `file.read` callers must supply the path under this key.
pub const OP_ARG_PATH: &str = "path";

/// v1 arg-key contract: `service.restart` callers must supply the unit name under this key.
pub const OP_ARG_UNIT: &str = "unit";

/// v1 arg-key contract: `pkg.install` callers must supply the package name under this key.
pub const OP_ARG_NAME: &str = "name";

/// v1 arg-key contract: `pkg.install` callers may supply an optional package version
/// under this key.
pub const OP_ARG_VERSION: &str = "version";

// ---------------------------------------------------------------------------
// Schema types
// ---------------------------------------------------------------------------

/// Whether an argument is required or may be omitted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArgKind {
    Required,
    Optional,
}

impl ArgKind {
    fn as_str(self) -> &'static str {
        match self {
            ArgKind::Required => "required",
            ArgKind::Optional => "optional",
        }
    }
}

/// An argument's accept-set: a human-readable display class (emitted into the
/// JSON schema and cross-checked against `opvocab`'s prose) plus an
/// independently-written predicate (used only by the proof test below — never
/// serialized).
#[derive(Clone, Copy)]
pub struct CharsetSpec {
    /// Display form, e.g. `"[A-Za-z0-9@._-]"` — matches the prose convention
    /// already used in the validator doc comments and in `opvocab.go`.
    pub display: &'static str,
    // Only read by `contains()`, which is only exercised by the proof test
    // (`#[cfg(test)]`). A struct field cannot be `#[cfg(test)]` without
    // changing every constructor, so it carries `#[allow(dead_code)]` instead.
    #[allow(dead_code)]
    predicate: fn(char) -> bool,
}

impl CharsetSpec {
    /// Returns whether `c` is inside this charset, per the schema's OWN
    /// (independently-declared) predicate — not the real validator. The
    /// proof test is what proves this agrees with the validator.
    #[allow(dead_code)]
    pub fn contains(&self, c: char) -> bool {
        (self.predicate)(c)
    }
}

/// The signature every `validate_*` function shares (proof-test binding only).
type ValidateFn = fn(&str) -> Result<(), OperationError>;

/// One documented argument of an [`OpSchema`].
pub struct ArgSpec {
    pub key: &'static str,
    /// `None` = unconstrained data (e.g. `file.read`'s `path`): the Operation
    /// itself imposes no charset; Policy arg-constraints are the gate.
    pub charset: Option<CharsetSpec>,
    /// The real validator requires the first AND last character to be
    /// alphanumeric (independent of the interior `charset`).
    pub first_last_alnum: bool,
    /// The real validator rejects a leading `-` specifically (option
    /// injection), with no matching end-anchor restriction.
    pub no_leading_dash: bool,
    pub kind: ArgKind,
    /// The real validator this spec is proven equal to (proof test only;
    /// never part of the emitted JSON). `None` for unconstrained args.
    #[allow(dead_code)]
    validate: Option<ValidateFn>,
}

impl ArgSpec {
    /// An unconstrained-data argument (`charset: None`, no validator; Policy
    /// arg-constraints are the gate) — the ONLY `ArgSpec` form constructible
    /// outside this module (the `validate` field is private). Deliberately
    /// restrictive: a charset-validated argument can only be declared here in
    /// `schema.rs`, next to the ADR-0015 proof tests that bind its charset to
    /// its real validator.
    pub(crate) const fn data_only(key: &'static str, kind: ArgKind) -> Self {
        ArgSpec {
            key,
            charset: None,
            first_last_alnum: false,
            no_leading_dash: false,
            kind,
            validate: None,
        }
    }
}

/// One Operation's full schema: name, risk class, and its documented args.
pub struct OpSchema {
    pub name: &'static str,
    pub risk: crate::gen::RiskClass,
    pub args: &'static [ArgSpec],
}

// ---------------------------------------------------------------------------
// Charset predicates — independently written, NOT calls into the validators
// (see module doc: this duplication is deliberate; the proof test reconciles
// it).
// ---------------------------------------------------------------------------

fn unit_charset_matches(c: char) -> bool {
    matches!(c, 'A'..='Z' | 'a'..='z' | '0'..='9' | '@' | '.' | '_' | '-')
}

fn pkg_name_charset_matches(c: char) -> bool {
    matches!(c, 'A'..='Z' | 'a'..='z' | '0'..='9' | '+' | '.' | '_' | '-')
}

fn pkg_version_charset_matches(c: char) -> bool {
    matches!(c, 'A'..='Z' | 'a'..='z' | '0'..='9' | '+' | '.' | ':' | '~' | '_' | '-')
}

const UNIT_CHARSET: CharsetSpec = CharsetSpec {
    display: "[A-Za-z0-9@._-]",
    predicate: unit_charset_matches,
};

const PKG_NAME_CHARSET: CharsetSpec = CharsetSpec {
    display: "[A-Za-z0-9+._-]",
    predicate: pkg_name_charset_matches,
};

const PKG_VERSION_CHARSET: CharsetSpec = CharsetSpec {
    display: "[A-Za-z0-9+.:~_-]",
    predicate: pkg_version_charset_matches,
};

// ---------------------------------------------------------------------------
// The arg-shape tables — the single definition of each Operation's declared
// args, referenced by the vocabulary registry ([`super::registry::REGISTRY`],
// issue #289), which feeds dispatch's arg mapping, this golden schema, and
// `opvocab`'s prose alike.
// ---------------------------------------------------------------------------

/// `system.facts` takes no arguments.
pub(crate) static SYSTEM_FACTS_ARGS: [ArgSpec; 0] = [];

/// `file.read`'s `path` is first-class "unconstrained data" (`charset: None`):
/// Operation-level charset does not apply; Policy arg-constraints are the gate
/// for which paths are readable.
pub(crate) static FILE_READ_ARGS: [ArgSpec; 1] =
    [ArgSpec::data_only(OP_ARG_PATH, ArgKind::Required)];

/// `service.restart`'s single validated `unit` argument.
pub(crate) static SERVICE_RESTART_ARGS: [ArgSpec; 1] = [ArgSpec {
    key: OP_ARG_UNIT,
    charset: Some(UNIT_CHARSET),
    first_last_alnum: false,
    no_leading_dash: true,
    kind: ArgKind::Required,
    validate: Some(service_restart::validate_unit_name),
}];

/// `pkg.install`'s stable 2-position arg-shape: `[name, version]`.
pub(crate) static PKG_INSTALL_ARGS: [ArgSpec; 2] = [
    ArgSpec {
        key: OP_ARG_NAME,
        charset: Some(PKG_NAME_CHARSET),
        first_last_alnum: true,
        no_leading_dash: false,
        kind: ArgKind::Required,
        validate: Some(pkg_install::validate_pkg_name),
    },
    ArgSpec {
        key: OP_ARG_VERSION,
        charset: Some(PKG_VERSION_CHARSET),
        first_last_alnum: true,
        no_leading_dash: false,
        kind: ArgKind::Optional,
        validate: Some(pkg_install::validate_pkg_version),
    },
];

// ---------------------------------------------------------------------------
// The schema view
// ---------------------------------------------------------------------------

/// Returns the canonical v1 Operation schema, derived from the vocabulary
/// registry ([`super::registry::REGISTRY`]) in its canonical order — the same
/// single source of truth that feeds dispatch, arg validation, and risk
/// classification (issue #289), so this golden schema can never drift from
/// what the daemon actually executes.
pub fn schemas() -> Vec<OpSchema> {
    super::registry::REGISTRY
        .iter()
        .map(|e| OpSchema {
            name: e.name,
            risk: e.risk,
            args: e.args,
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Canonical JSON emitter (hand-rolled: no serde_json dependency — matches
// this crate's existing "no clap" small-musl-binary posture, policy_check.rs)
// ---------------------------------------------------------------------------

fn risk_str(risk: crate::gen::RiskClass) -> &'static str {
    match risk {
        crate::gen::RiskClass::Unspecified => "unspecified",
        crate::gen::RiskClass::Read => "read",
        crate::gen::RiskClass::Mutate => "mutate",
    }
}

/// Escapes a string for embedding in a JSON string literal. The schema's own
/// strings are all trusted constants (no attacker-controlled input reaches
/// this emitter), so this only needs to handle `"` and `\` correctly, not a
/// full JSON-escaping suite.
fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            _ => out.push(c),
        }
    }
    out
}

/// Renders `schemas()` as canonical, deterministically-ordered, pretty
/// JSON (2-space indent) — the same string on every run given the same
/// table, so `git diff --exit-code` (the `opschema-drift` CI step) is a
/// faithful drift check.
pub fn to_canonical_json() -> String {
    let mut out = String::new();
    out.push_str("{\n  \"operations\": [\n");
    let ops = schemas();
    for (i, op) in ops.iter().enumerate() {
        out.push_str("    {\n");
        out.push_str(&format!("      \"name\": \"{}\",\n", json_escape(op.name)));
        out.push_str(&format!("      \"risk\": \"{}\",\n", risk_str(op.risk)));
        if op.args.is_empty() {
            out.push_str("      \"args\": []\n");
        } else {
            out.push_str("      \"args\": [\n");
            for (j, arg) in op.args.iter().enumerate() {
                out.push_str("        {\n");
                out.push_str(&format!(
                    "          \"key\": \"{}\",\n",
                    json_escape(arg.key)
                ));
                match &arg.charset {
                    Some(cs) => out.push_str(&format!(
                        "          \"charset\": \"{}\",\n",
                        json_escape(cs.display)
                    )),
                    None => out.push_str("          \"charset\": null,\n"),
                }
                out.push_str(&format!(
                    "          \"first_last_alnum\": {},\n",
                    arg.first_last_alnum
                ));
                out.push_str(&format!(
                    "          \"no_leading_dash\": {},\n",
                    arg.no_leading_dash
                ));
                out.push_str(&format!("          \"kind\": \"{}\"\n", arg.kind.as_str()));
                out.push_str(if j + 1 == op.args.len() {
                    "        }\n"
                } else {
                    "        },\n"
                });
            }
            out.push_str("      ]\n");
        }
        out.push_str(if i + 1 == ops.len() {
            "    }\n"
        } else {
            "    },\n"
        });
    }
    out.push_str("  ]\n}\n");
    out
}

// ---------------------------------------------------------------------------
// `dump-operation-schema` subcommand entry point
// ---------------------------------------------------------------------------

/// Exit code for `dump-operation-schema` — it never fails once invoked
/// (the schema table is a compile-time constant), so there is exactly one
/// stable code.
pub const EXIT_OK: i32 = 0;

/// Runs `relay-daemon dump-operation-schema`: prints the canonical JSON
/// schema to stdout and returns the process exit code.
///
/// Fully offline and synchronous (no Config/network/identity/tracing setup),
/// intercepted in `main` before `tracing_subscriber::fmt().init()` — same
/// seam as `policy check` (`policy_check::run`). It must print directly to
/// stdout, never `tracing::*` (dropped silently before the subscriber is
/// installed).
pub fn run() -> i32 {
    print!("{}", to_canonical_json());
    EXIT_OK
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn schemas_cover_the_full_v1_vocabulary_in_order() {
        let ops = schemas();
        assert_eq!(ops.len(), 4);
        assert_eq!(ops[0].name, super::super::SYSTEM_FACTS);
        assert_eq!(ops[1].name, super::super::FILE_READ);
        assert_eq!(ops[2].name, super::super::SERVICE_RESTART);
        assert_eq!(ops[3].name, super::super::PKG_INSTALL);
    }

    #[test]
    fn file_read_path_is_unconstrained_data() {
        let ops = schemas();
        let op = ops
            .iter()
            .find(|o| o.name == super::super::FILE_READ)
            .unwrap();
        assert_eq!(op.args.len(), 1);
        assert_eq!(op.args[0].key, OP_ARG_PATH);
        assert!(
            op.args[0].charset.is_none(),
            "file.read's path must be unconstrained (charset: None) — path restriction is a \
             Policy arg-constraint concern, not an Operation-level charset"
        );
        assert!(op.args[0].validate.is_none());
    }

    // -----------------------------------------------------------------------
    // THE LOAD-BEARING PROOF TEST (ADR-0015 trip-wire (a)): binds every
    // ArgSpec's independently-declared charset to the real validate_* function,
    // byte by byte over the full printable-ASCII range, plus a handful of
    // multibyte samples. A drift between the schema's charset and what the
    // validator actually enforces fails HERE, at compile-test time — not as a
    // silently-wrong argument-constraint description shown to the AI-agent.
    // -----------------------------------------------------------------------

    #[test]
    fn charset_matches_real_validator_byte_space() {
        for op in schemas() {
            for arg in op.args {
                let (Some(charset), Some(validate)) = (arg.charset, arg.validate) else {
                    // Unconstrained args (file.read's path) have nothing to prove.
                    assert!(
                        arg.charset.is_none() && arg.validate.is_none(),
                        "{}.{}: charset and validate must both be None or both be Some",
                        op.name,
                        arg.key
                    );
                    continue;
                };

                for byte in 0x00u8..=0x7F {
                    let c = byte as char;
                    // Pad with a fixed, always-valid 'a' on both sides so this
                    // probes ONLY the interior-charset acceptance of `c`,
                    // independent of first/last-anchor rules (checked below).
                    let probe = format!("a{c}a");
                    let accepted = validate(&probe).is_ok();
                    let declared = charset.contains(c);
                    assert_eq!(
                        accepted, declared,
                        "{}.{}: byte {:#04x} ({:?}): validator accepted={accepted}, \
                         schema charset.contains={declared} — schema/validator charset drift",
                        op.name, arg.key, byte, c
                    );
                }

                // Multibyte samples: both sides must reject non-ASCII input,
                // proving the byte-space loop's 0x00..=0x7F coverage isn't
                // hiding a Unicode-range disagreement.
                for c in ['é', '中', '🚀'] {
                    let probe = format!("a{c}a");
                    let accepted = validate(&probe).is_ok();
                    let declared = charset.contains(c);
                    assert_eq!(
                        accepted, declared,
                        "{}.{}: multibyte char {:?}: validator accepted={accepted}, \
                         schema charset.contains={declared} — schema/validator charset drift",
                        op.name, arg.key, c
                    );
                }
            }
        }
    }

    #[test]
    fn anchor_flags_match_real_validator_first_last_char_behavior() {
        for op in schemas() {
            for arg in op.args {
                let Some(validate) = arg.validate else {
                    continue;
                };

                if arg.no_leading_dash {
                    assert!(
                        validate("-a").is_err(),
                        "{}.{}: no_leading_dash=true but the validator accepted a leading '-'",
                        op.name,
                        arg.key
                    );
                    assert!(
                        validate("a-").is_ok(),
                        "{}.{}: no_leading_dash is a LEADING-only rule (no end anchor) but the \
                         validator rejected a trailing '-'",
                        op.name,
                        arg.key
                    );
                }

                if arg.first_last_alnum {
                    assert!(
                        validate("-ab").is_err(),
                        "{}.{}: first_last_alnum=true but the validator accepted a non-alnum \
                         leading character",
                        op.name,
                        arg.key
                    );
                    assert!(
                        validate("ab-").is_err(),
                        "{}.{}: first_last_alnum=true but the validator accepted a non-alnum \
                         trailing character",
                        op.name,
                        arg.key
                    );
                    assert!(
                        validate("ab").is_ok(),
                        "{}.{}: first_last_alnum=true but the validator rejected an all-alnum \
                         string",
                        op.name,
                        arg.key
                    );
                }
            }
        }
    }

    // -----------------------------------------------------------------------
    // THE display <-> predicate BINDING (closes the gap the byte-space proof
    // test above leaves open): `charset_matches_real_validator_byte_space`
    // binds `CharsetSpec::contains` (the `predicate` fn) to the real
    // validator, but `predicate` is `#[cfg(test)]`-only plumbing — it is
    // NEVER serialized. The field that IS serialized into the golden and
    // advertised to the AI-agent via `opvocab` is `display`, and nothing
    // above proves `display` agrees with `predicate`. A wrong `display`
    // (e.g. a narrowed "[A-Za-z0-9]" left next to a correct `predicate`)
    // would sail through every other test in this file untouched. This test
    // parses each `display` bracket-charset string byte by byte and asserts
    // it describes exactly the same accept-set as `predicate` — transitively
    // binding `display` to the real validator via the test above.
    // -----------------------------------------------------------------------

    #[test]
    fn display_matches_declared_predicate_byte_space() {
        for op in schemas() {
            for arg in op.args {
                match arg.charset {
                    Some(charset) => {
                        for byte in 0x00u8..=0x7F {
                            let c = byte as char;
                            let via_predicate = charset.contains(c);
                            let via_display = display_charset_contains(charset.display, c);
                            assert_eq!(
                                via_display, via_predicate,
                                "{}.{}: display {:?} claims byte {:#04x} ({:?}) \
                                 membership={via_display}, but predicate says \
                                 {via_predicate} — display/predicate drift (the string \
                                 actually advertised to the AI-agent would be a lie)",
                                op.name, arg.key, charset.display, byte, c
                            );
                        }

                        // Multibyte samples: `display`'s bracket notation is
                        // ASCII-only by convention, so it must never claim to
                        // accept a non-ASCII char, matching the predicate's
                        // (and the real validator's) Unicode rejection proven
                        // above.
                        for c in ['é', '中', '🚀'] {
                            assert!(
                                !display_charset_contains(charset.display, c),
                                "{}.{}: display {:?} must not claim to accept multibyte \
                                 char {:?}",
                                op.name,
                                arg.key,
                                charset.display,
                                c
                            );
                        }
                    }
                    None => {
                        // `charset: None` (e.g. file.read's path) IS the
                        // display value here: it serializes to `"charset":
                        // null` (asserted below in
                        // to_canonical_json_contains_every_operation_and_arg_key),
                        // which unambiguously reads as "no charset
                        // restriction" — there is no bracket string that
                        // could drift from `predicate`.
                        assert!(
                            arg.validate.is_none(),
                            "{}.{}: charset=None must mean unconstrained (validate must \
                             also be None)",
                            op.name,
                            arg.key
                        );
                    }
                }
            }
        }
    }

    /// Parses a `display` charset string of the bracket-notation form
    /// `"[A-Za-z0-9@._-]"` — the ONLY convention this module uses (see
    /// `UNIT_CHARSET`/`PKG_NAME_CHARSET`/`PKG_VERSION_CHARSET`) — and returns
    /// whether `target` is inside the set it describes. A `-` immediately
    /// before the closing `]` (with nothing after it to complete a range) is
    /// a literal hyphen, not a dangling range, matching every `display`
    /// string in this file.
    ///
    /// Exists ONLY for [`display_matches_declared_predicate_byte_space`]:
    /// this is what actually reads the string serialized into the golden and
    /// advertised to the AI-agent, instead of trusting that whoever edits
    /// `display` also correctly edits `predicate`.
    fn display_charset_contains(display: &str, target: char) -> bool {
        let inner = display.strip_prefix('[').and_then(|s| s.strip_suffix(']'));
        let Some(inner) = inner else {
            panic!("display charset {display:?} must be bracket notation \"[...]\"");
        };
        let chars: Vec<char> = inner.chars().collect();
        let mut i = 0;
        while i < chars.len() {
            // A range is `X-Y` where a THIRD character follows the `-`
            // (otherwise the `-` is a trailing literal, e.g. the final `-`
            // in "[A-Za-z0-9@._-]").
            if i + 2 < chars.len() && chars[i + 1] == '-' {
                let (start, end) = (chars[i], chars[i + 2]);
                if target >= start && target <= end {
                    return true;
                }
                i += 3;
            } else {
                if chars[i] == target {
                    return true;
                }
                i += 1;
            }
        }
        false
    }

    // -----------------------------------------------------------------------
    // JSON emitter: stable shape, deterministic
    // -----------------------------------------------------------------------

    #[test]
    fn to_canonical_json_is_deterministic() {
        assert_eq!(to_canonical_json(), to_canonical_json());
    }

    #[test]
    fn to_canonical_json_contains_every_operation_and_arg_key() {
        let json = to_canonical_json();
        for name in [
            super::super::SYSTEM_FACTS,
            super::super::FILE_READ,
            super::super::SERVICE_RESTART,
            super::super::PKG_INSTALL,
        ] {
            assert!(
                json.contains(&format!("\"name\": \"{name}\"")),
                "missing {name} in JSON"
            );
        }
        for key in [OP_ARG_PATH, OP_ARG_UNIT, OP_ARG_NAME, OP_ARG_VERSION] {
            assert!(
                json.contains(&format!("\"key\": \"{key}\"")),
                "missing arg key {key} in JSON"
            );
        }
        assert!(
            json.contains("\"charset\": null"),
            "file.read's path must emit charset: null"
        );
    }

    #[test]
    fn run_prints_ok_exit_code() {
        // run() prints to stdout as a side effect; just pin the stable exit code.
        assert_eq!(EXIT_OK, 0);
    }
}
