//! Models for `fuzz_template_render` and `gen_corpus`. Each is written from the
//! documented contract (the `TemplateDef` and `SlotType` docs, ADR-0021 decision
//! 9, ADR-0018), never by calling relay-ops, so a drift in the code shows up as a
//! crash.
//!
//! Outside the test module nothing here calls the relay-ops lexer, a slot
//! validator, `render` or `positional_ref`: the only relay-ops items named are
//! the public definition types, and the only Policy call is loading a fixed
//! harness Policy (`allow_any`).

use relay_ops::operations::template::{SlotDef, SlotType, TemplateDef};
use relay_policy::{from_toml_str, Policy};

use crate::policy_oracle::lexical_normalise;
use crate::template_oracle::body_def;

/// Path admits bidi and invisible characters, which are inert to the shell.
/// Display surfaces escape them (ADR-0021 decision 9).
pub const PATH_ADMITS_BIDI: bool = true;

/// The Unicode bidirectional formatting controls, each written out.
pub const BIDI_CONTROLS: &[char] = &[
    '\u{061c}', '\u{200e}', '\u{200f}', '\u{202a}', '\u{202b}', '\u{202c}', '\u{202d}', '\u{202e}',
    '\u{2066}', '\u{2067}', '\u{2068}', '\u{2069}',
];

/// Ten Identifier slots, `w0` to `w9`. Appended after `body_slots`, they push
/// declaration indices to 9 and beyond, where the braced references start.
pub fn wide_slots() -> Vec<SlotDef> {
    (0..10)
        .map(|k| SlotDef {
            name: format!("w{k}"),
            ty: SlotType::Identifier,
        })
        .collect()
}

/// `body_def(sel, body)`, with `wide_slots()` appended when `sel & 0x20` is set.
/// Bits 0 to 3 and bit 4 keep their `body_def` meaning. Bit 7 is file mode (the
/// target handles it). Bit 6 is unused.
pub fn render_def(sel: u8, body: &str) -> TemplateDef {
    let mut def = body_def(sel, body);
    if sel & 0x20 != 0 {
        def.slots.extend(wide_slots());
    }
    def
}

/// The quoted positional-parameter reference for the slot at declaration
/// `index`: `"$N"` for N = index + 1 up to 9, and `"${N}"` from the tenth, where
/// `$10` would read as `${1}0`.
pub fn positional_ref_model(index: usize) -> String {
    let n = index + 1;
    if n <= 9 {
        format!("\"${n}\"")
    } else {
        format!("\"${{{n}}}\"")
    }
}

/// The script a body compiles to, by a plain left-to-right scan: each `{{name}}`
/// (whitespace inside the braces trimmed) becomes the quoted positional
/// reference of the declared slot of that name, and every other character is
/// copied verbatim. There is no backslash, quote or here-document rule: a body
/// holds `{{` only as a placeholder (EX-19), so a body that compiles has no
/// other reading.
///
/// An `Err`, or a mismatch, on a body `compile` accepted is a finding.
pub fn expected_script(body: &str, slots: &[SlotDef]) -> Result<String, &'static str> {
    let mut out = String::with_capacity(body.len());
    let mut rest = body;
    while let Some(open) = rest.find("{{") {
        out.push_str(&rest[..open]);
        let after = &rest[open + 2..];
        let Some(close) = after.find("}}") else {
            return Err("unterminated");
        };
        let name = after[..close].trim();
        let Some(index) = slots.iter().position(|s| s.name == name) else {
            return Err("undeclared");
        };
        out.push_str(&positional_ref_model(index));
        rest = &after[close + 2..];
    }
    out.push_str(rest);
    Ok(out)
}

/// The slot validators' contract restated: whether `v` is a value `ty` accepts.
pub fn value_ok(ty: &SlotType, v: &str) -> bool {
    match ty {
        SlotType::Identifier => {
            (1..=256).contains(&v.len())
                && v.starts_with(|c: char| c.is_ascii_alphanumeric())
                && v.chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '@' | '+' | '-'))
        }
        SlotType::Integer => (1..=19).contains(&v.len()) && v.bytes().all(|b| b.is_ascii_digit()),
        SlotType::Path => path_ok(v),
        SlotType::Enum(values) => values.iter().any(|m| m == v),
    }
}

/// The 22 characters ADR-0021 decision 9 refuses in a Path value.
const PATH_REFUSED: &str = "$`\\\"';|&<>(){}[]*?!#~=";

fn path_ok(v: &str) -> bool {
    if !(1..=4096).contains(&v.len()) {
        return false;
    }
    let refused = v.chars().any(|c| {
        matches!(c, '\u{0}'..='\u{1f}' | '\u{7f}' | '\u{80}'..='\u{9f}')
            || matches!(
                c,
                '\u{9}'..='\u{d}'
                    | ' '
                    | '\u{85}'
                    | '\u{a0}'
                    | '\u{1680}'
                    | '\u{2000}'..='\u{200a}'
                    | '\u{2028}'
                    | '\u{2029}'
                    | '\u{202f}'
                    | '\u{205f}'
                    | '\u{3000}'
            )
            || PATH_REFUSED.contains(c)
            || (!PATH_ADMITS_BIDI && BIDI_CONTROLS.contains(&c))
    });
    !refused && v.starts_with('/') && lexical_normalise(v) == v
}

/// The label the refusal message gives a slot type.
pub fn type_name_model(ty: &SlotType) -> &'static str {
    match ty {
        SlotType::Identifier => "identifier",
        SlotType::Integer => "integer",
        SlotType::Path => "path",
        SlotType::Enum(_) => "enum",
    }
}

/// The static reasons a refusal of a `ty` value can give.
///
/// Drift crashes the target, which flags it. It never makes a refusal pass.
pub fn refusal_reasons(ty: &SlotType) -> &'static [&'static str] {
    match ty {
        SlotType::Identifier => &[
            "must not be empty",
            "exceeds the maximum length",
            "must start with an ASCII alphanumeric (no leading '-')",
            "contains a character outside [A-Za-z0-9_.@+-]",
        ],
        SlotType::Integer => &[
            "must not be empty",
            "has too many digits",
            "must be ASCII digits [0-9] only (no sign, no whitespace)",
        ],
        SlotType::Path => &[
            "must not be empty",
            "exceeds the maximum length",
            "contains a control character",
            "contains whitespace or a shell-significant character",
            "must be an absolute canonical path: no '.', '..', '//', or trailing '/' (ADR-0018)",
        ],
        SlotType::Enum(_) => &["is not one of the allowed enum values"],
    }
}

/// Whether `stderr` is exactly a refusal of a `value_len`-byte value for slot
/// `slot`: the fixed words, the slot name, the length and one static reason.
///
/// This is the "never echoes the value" oracle. Every byte of an accepted
/// message is text that is not the value, so it needs no `contains(value)` check,
/// which gives false positives on short values such as "1" or "path".
pub fn refusal_message_ok(stderr: &[u8], slot: &str, ty: &SlotType, value_len: usize) -> bool {
    let head = format!(
        "parameter for slot {slot:?} (length {value_len}) failed {} validation: ",
        type_name_model(ty)
    );
    refusal_reasons(ty)
        .iter()
        .any(|reason| stderr == format!("{head}{reason}").as_bytes())
}

/// Two valid value sets that differ at every non-Path slot. Path slots get `exe`
/// in both.
pub fn canonical_values(slots: &[SlotDef], exe: &str) -> [Vec<String>; 2] {
    let pick = |last: bool| -> Vec<String> {
        slots
            .iter()
            .map(|s| match &s.ty {
                SlotType::Identifier => if last { "Z9.x@y+z-1" } else { "a" }.to_string(),
                SlotType::Integer => if last { "1234567890123456789" } else { "0" }.to_string(),
                SlotType::Path => exe.to_string(),
                SlotType::Enum(values) => {
                    let m = if last { values.last() } else { values.first() };
                    m.expect("compile refuses an empty enum").clone()
                }
            })
            .collect()
    };
    [pick(false), pick(true)]
}

/// A Policy that allows `name` with any value at each of `arity` positions. It is
/// what a Template's layer-2 path re-check consults inside `invoke`, through the
/// real `Policy::decide` (invariant 12); the harness never evaluates it itself.
///
/// `compile` holds `name` to `^[a-z][a-z0-9_.]*$`, so interpolating it is safe.
pub fn allow_any(name: &str, arity: usize) -> Policy {
    let args = vec!["[\"*\"]"; arity].join(", ");
    from_toml_str(&format!(
        "[[operation]]\nname = \"{name}\"\nallowed_args = [{args}]\n"
    ))
    .unwrap_or_else(|e| panic!("harness policy for {name:?} with {arity} positions: {e}"))
}

/// A TOML basic string: backslash and double quote escaped, and every char below
/// U+0020 and U+007F written as `\uXXXX`.
pub fn toml_basic_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\u{0}'..='\u{1f}' | '\u{7f}' => out.push_str(&format!("\\u{:04X}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// A one-template file in the loader's format: every string goes through
/// [`toml_basic_string`].
pub fn template_toml(name: &str, body: &str, slots: &[SlotDef]) -> String {
    let mut out = format!(
        "[[template]]\nname = {}\nrisk_class = \"read\"\nbody = {}\n",
        toml_basic_string(name),
        toml_basic_string(body)
    );
    for s in slots {
        out.push_str(&format!(
            "\n[[template.slots]]\nname = {}\ntype = \"{}\"\n",
            toml_basic_string(&s.name),
            type_name_model(&s.ty)
        ));
        if let SlotType::Enum(values) = &s.ty {
            let items: Vec<String> = values.iter().map(|v| toml_basic_string(v)).collect();
            out.push_str(&format!("values = [{}]\n", items.join(", ")));
        }
    }
    out
}

/// Render-target body seeds as `(sel, body, refused)`. `refused` marks the bodies
/// `compile` refuses on purpose, so the refusals stay exercised (see `compile_refuses_the_refused_context_seeds`).
pub const RENDER_BODY_SEEDS: &[(u8, &str, bool)] = &[
    // The table of standalone placeholders, which compile.
    (0x01, "echo {{p}}", false),
    (0x01, "echo x {{p}}", false),
    (0x01, "echo {{ p }}", false),
    (0x01, "echo\t{{p}}\ttail", false),
    (0x01, "a\necho {{p}}\nb", false),
    (0x01, "echo a \\\n{{p}}", false),
    (0x01, "echo {{p}} | cat -n {{p}}", false),
    (0x01, "true && echo {{p}} || echo {{p}} ; echo", false),
    (0x01, "{ echo {{p}} ; }", false),
    (0x01, "f() { echo {{p}} ; }", false),
    (0x01, "echo $(echo x) {{p}} \"$(echo y)\"", false),
    // Placeholder in a context the shell would glue to or expand: refused.
    (0x01, "echo a\\ {{p}}", true),
    (0x01, "cat <<EOF\n{{p}}\nEOF\n", true),
    (0x01, "echo `{{p}}`", true),
    (0x01, "echo $( {{p}} )", true),
    // A `{{` left in the script after substitution: refused.
    (0x01, "echo \\{{p}} {{p}}", true),
    (0x01, "echo \"\\{{p}}\" {{p}}", true),
    (0x01, "echo $'\\{{p}}' {{p}}", true),
    (0x01, "echo ${x:-\\{{p}}} {{p}}", true),
    (0x01, "cat <<E\nx\\{{p}}\nE\necho {{p}}", true),
    // A here-document beside a placeholder: refused (EX-19).
    (0x01, "cat <<E\nx\nE\necho {{p}}", true),
    // Fourteen slots, so the last five are referenced as `${10}` to `${14}`.
    (
        0x2f,
        "cmd {{p}} {{n}} {{i}} {{e}} {{w0}} {{w1}} {{w2}} {{w3}} {{w4}} {{w5}} {{w6}} {{w7}} {{w8}} {{w9}}",
        false,
    ),
];

/// The six fixtures of relay-ops' `fixtures()` invariance property, as `(body,
/// Path slot names in declaration order, golden script)`.
pub const PROPTEST_FIXTURES: &[(&str, &[&str], &str)] = &[
    ("cmd a {{p}} b", &["p"], "cmd a \"$1\" b"),
    (
        "tail -n {{b}} {{a}} | grep -c x",
        &["a", "b"],
        "tail -n \"$2\" \"$1\" | grep -c x",
    ),
    (
        "cat {{a}} {{b}} {{a}}",
        &["a", "b"],
        "cat \"$1\" \"$2\" \"$1\"",
    ),
    (
        "echo {{p}} | cat -n {{p}}",
        &["p"],
        "echo \"$1\" | cat -n \"$1\"",
    ),
    ("{ echo {{p}} ; }", &["p"], "{ echo \"$1\" ; }"),
    (
        "f {{a12}} {{a11}} {{a10}} {{a9}} {{a8}} {{a7}} {{a6}} {{a5}} {{a4}} {{a3}} {{a2}} {{a1}}",
        &[
            "a1", "a2", "a3", "a4", "a5", "a6", "a7", "a8", "a9", "a10", "a11", "a12",
        ],
        "f \"${12}\" \"${11}\" \"${10}\" \"$9\" \"$8\" \"$7\" \"$6\" \"$5\" \"$4\" \"$3\" \"$2\" \"$1\"",
    ),
];

/// The rows of relay-ops' private red-team table, as `(slot type, value, must the
/// typed gate refuse it)`.
pub fn redteam_seeds() -> Vec<(SlotType, &'static str, bool)> {
    let one = |v: &str| SlotType::Enum(vec![v.to_string()]);
    vec![
        (one("/tmp/'; reboot; '"), "/tmp/'; reboot; '", false),
        (SlotType::Identifier, "a\"b", true),
        (SlotType::Identifier, "nginx other", true),
        (SlotType::Identifier, "ngi\u{a0}nx", true),
        (SlotType::Path, "/tmp/a\nreboot", true),
        (one("/tmp/a b"), "/tmp/a b", false),
        (one("/tmp/x;reboot"), "/tmp/x;reboot", false),
        (one("/tmp/$(reboot)"), "/tmp/$(reboot)", false),
        (one("/tmp/`reboot`"), "/tmp/`reboot`", false),
        (
            one("/tmp/x|tee>/etc/passwd"),
            "/tmp/x|tee>/etc/passwd",
            false,
        ),
        (one("/tmp/*"), "/tmp/*", false),
        (one("/tmp/$HOME"), "/tmp/$HOME", false),
        (SlotType::Path, "/tmp/$(reboot)", true),
        (
            SlotType::Path,
            "/tmp -maxdepth 0 -exec echo PWNED ; -quit/x",
            true,
        ),
        (SlotType::Identifier, "--force", true),
        (SlotType::Path, "--output=/etc/x", true),
        (SlotType::Integer, "-1", true),
        (SlotType::Identifier, "", true),
        (SlotType::Path, "", true),
        (SlotType::Path, "/tmp/a\u{0}b", true),
        (SlotType::Identifier, "a\u{202e}b", true),
        (one("/tmp/a\u{202e}b"), "/tmp/a\u{202e}b", false),
    ]
}

/// Validator seeds for the `(d)` oracle, as `(sel, values in slot order)`. Slot
/// `n` is Identifier (sel 0x02), `i` Integer (0x04), `p` Path (0x01). The Path
/// values with U+202E and U+200B are ones the validator accepts (ADR-0021
/// decision 9).
pub const VALIDATOR_SEEDS: &[(u8, &[&str])] = &[
    (0x02, &["ab\u{202e}"]),
    (0x02, &["a\u{202e}b"]),
    (0x02, &["a\u{2066}b"]),
    (0x02, &["a\u{200b}b"]),
    (0x02, &["a\u{85}b"]),
    (0x02, &["a\u{9b}b"]),
    (0x02, &["a\u{0}b"]),
    (0x04, &["-1"]),
    (0x04, &["+1"]),
    (0x04, &["\u{ff11}"]),
    (0x04, &["1\u{202e}2"]),
    (0x04, &["12345678901234567890"]),
    (0x01, &["/a/../b"]),
    (0x01, &["//x"]),
    (0x01, &["/tmp/"]),
    (0x01, &["tmp/x"]),
    (0x01, &["/tmp/a b"]),
    (0x01, &["/tmp/a\u{85}b"]),
    (0x01, &["/tmp/a\u{9b}b"]),
    (0x01, &["/tmp/a\u{0}b"]),
    (0x01, &["/tmp/a\u{202e}b"]),
    (0x01, &["/tmp/a\u{200b}b"]),
    (0x01, &["/tmp/a\u{2028}b"]),
    (0x01, &["/tmp/a\u{a0}b"]),
];

#[cfg(test)]
mod tests {
    use super::*;
    use crate::template_oracle::TemplateFileMirror;
    use relay_ops::operations::template::compile;

    fn slot(name: &str, ty: SlotType) -> SlotDef {
        SlotDef {
            name: name.to_string(),
            ty,
        }
    }

    fn path_slots(names: &[&str]) -> Vec<SlotDef> {
        names.iter().map(|n| slot(n, SlotType::Path)).collect()
    }

    #[test]
    fn positional_ref_model_braces_from_the_tenth() {
        assert_eq!(positional_ref_model(0), "\"$1\"");
        assert_eq!(positional_ref_model(8), "\"$9\"");
        assert_eq!(positional_ref_model(9), "\"${10}\"");
    }

    #[test]
    fn expected_script_matches_the_standalone_table() {
        let slots = path_slots(&["p"]);
        for (body, want) in [
            ("echo {{p}}", "echo \"$1\""),
            ("echo x {{p}}", "echo x \"$1\""),
            ("echo {{ p }}", "echo \"$1\""),
            ("echo\t{{p}}\ttail", "echo\t\"$1\"\ttail"),
            ("a\necho {{p}}\nb", "a\necho \"$1\"\nb"),
            ("echo a \\\n{{p}}", "echo a \\\n\"$1\""),
            ("echo {{p}} | cat -n {{p}}", "echo \"$1\" | cat -n \"$1\""),
            (
                "true && echo {{p}} || echo {{p}} ; echo",
                "true && echo \"$1\" || echo \"$1\" ; echo",
            ),
            ("{ echo {{p}} ; }", "{ echo \"$1\" ; }"),
            ("f() { echo {{p}} ; }", "f() { echo \"$1\" ; }"),
            (
                "echo $(echo x) {{p}} \"$(echo y)\"",
                "echo $(echo x) \"$1\" \"$(echo y)\"",
            ),
        ] {
            assert_eq!(
                expected_script(body, &slots).as_deref(),
                Ok(want),
                "{body:?}"
            );
        }
        assert_eq!(expected_script("echo {{q}}", &slots), Err("undeclared"));
        assert_eq!(expected_script("echo {{p", &slots), Err("unterminated"));
    }

    #[test]
    fn expected_script_matches_the_proptest_goldens() {
        for (body, names, golden) in PROPTEST_FIXTURES {
            let slots = path_slots(names);
            assert_eq!(expected_script(body, &slots).as_deref(), Ok(*golden));
            let def = TemplateDef {
                slots,
                ..body_def(0x00, body)
            };
            assert_eq!(compile(&def).expect("fixture compiles").script(), *golden);
        }
    }

    #[test]
    fn expected_script_matches_compile_on_the_shipped_catalogs() {
        for text in [
            include_str!("../../packaging/templates.d/relay-read/catalog.toml"),
            include_str!("../../templates.example.toml"),
        ] {
            let file: TemplateFileMirror = toml::from_str(text).expect("shipped file parses");
            for def in &file.template {
                let op = compile(def).unwrap_or_else(|e| panic!("{}: {e}", def.name));
                assert_eq!(
                    expected_script(&def.body, &def.slots).as_deref(),
                    Ok(op.script()),
                    "{}",
                    def.name
                );
            }
        }
    }

    #[test]
    fn compile_refuses_the_refused_context_seeds() {
        for (sel, body, refused) in RENDER_BODY_SEEDS {
            assert_eq!(
                compile(&render_def(*sel, body)).is_err(),
                *refused,
                "{body:?}"
            );
        }
    }

    #[test]
    fn value_model_agrees_with_every_redteam_row() {
        for (ty, value, must_refuse) in redteam_seeds() {
            assert_eq!(must_refuse, !value_ok(&ty, value), "{ty:?} {value:?}");
        }
    }

    #[test]
    fn identifier_and_integer_refuse_every_bidi_control() {
        for &c in BIDI_CONTROLS {
            assert!(!value_ok(&SlotType::Identifier, &format!("a{c}b")), "{c:?}");
            assert!(!value_ok(&SlotType::Integer, &format!("1{c}2")), "{c:?}");
        }
    }

    #[test]
    fn path_model_follows_adr_0021_decision_9() {
        assert!(value_ok(&SlotType::Path, "/tmp/a\u{202e}b"));
        assert!(value_ok(&SlotType::Path, "/tmp/a\u{200b}b"));
        for c in [
            '\u{0}', '\u{1f}', '\u{7f}', '\u{80}', '\u{85}', '\u{9b}', '\u{9f}', ' ', '\t',
            '\u{a0}', '\u{1680}', '\u{2000}', '\u{2028}', '\u{3000}', '$', '=',
        ] {
            assert!(!value_ok(&SlotType::Path, &format!("/tmp/a{c}b")), "{c:?}");
        }
    }

    #[test]
    fn refusal_message_ok_rejects_an_echo() {
        let ty = SlotType::Path;
        let exact = b"parameter for slot \"p\" (length 3) failed path validation: contains a control character";
        assert!(refusal_message_ok(exact, "p", &ty, 3));
        assert!(!refusal_message_ok(exact, "p", &ty, 4));
        assert!(!refusal_message_ok(exact, "q", &ty, 3));
        let echo = b"parameter for slot \"p\" (length 3) failed path validation: /a\n";
        assert!(!refusal_message_ok(echo, "p", &ty, 3));
        let echo = b"parameter for slot \"p\" (length 3) failed path validation: contains a control character: /a\n";
        assert!(!refusal_message_ok(echo, "p", &ty, 3));
    }

    #[test]
    fn toml_basic_string_round_trips() {
        let s = "a\\b\"c\u{0}d\u{1f}e\u{7f}f\ng\u{85}h";
        let parsed: toml::Table =
            toml::from_str(&format!("x = {}", toml_basic_string(s))).expect("parses");
        assert_eq!(parsed["x"].as_str(), Some(s));
    }

    #[test]
    fn template_toml_parses_the_way_the_loader_does() {
        let slots = vec![
            slot("p", SlotType::Path),
            slot("e", SlotType::Enum(vec!["a\"b".into(), "c\nd".into()])),
            slot("n", SlotType::Identifier),
        ];
        let text = template_toml("fuzz.fixture", "x {{p}} {{e}} {{n}}", &slots);
        let file: TemplateFileMirror = toml::from_str(&text).expect("parses");
        assert_eq!(file.template.len(), 1);
        assert_eq!(file.template[0].slots, slots);
        assert_eq!(file.template[0].body, "x {{p}} {{e}} {{n}}");
    }

    #[test]
    fn allow_any_loads_for_every_arity_and_a_native_name() {
        for name in ["fuzz.probe", "file.read", "service.restart", "a"] {
            for arity in [0, 1, 2, 64] {
                allow_any(name, arity);
            }
        }
    }

    #[test]
    fn canonical_values_are_valid_and_differ() {
        let slots = render_def(0x2f, "x").slots;
        let [a, b] = canonical_values(&slots, "/exe");
        for set in [&a, &b] {
            for (s, v) in slots.iter().zip(set) {
                assert!(value_ok(&s.ty, v), "{} {v:?}", s.name);
            }
        }
        assert_ne!(a, b);
    }
}
