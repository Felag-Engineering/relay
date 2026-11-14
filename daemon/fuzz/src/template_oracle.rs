//! Pure helpers for `fuzz_template_compile` and `gen_corpus`. Nothing here
//! renders, invokes or opens a file: the only relay-ops code reached is serde on
//! the definition types and `compile`.

use relay_ops::operations::template::{RiskClassDef, SlotDef, SlotType, TemplateDef};
use serde::Deserialize;

/// Mirror of relay-ops `templates.rs`'s private `TemplateFile`, the struct the
/// loader parses a template file into; keep it in step with that one.
///
/// Any divergence makes this target parse a different set of files than the
/// loader does, so it fuzzes less, never something else: every assertion is on
/// the real `compile`, so drift cannot produce a false finding. The unit tests
/// below pin the mirror to the loader's behaviour.
///
/// This is not the load gate: the loader's Native-shadow and duplicate-name
/// refusals, its UTF-8 check and its hardened open are not reached here.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TemplateFileMirror {
    #[serde(default)]
    pub template: Vec<TemplateDef>,
}

/// The Template name of every body-mode definition.
pub const BODY_TEMPLATE_NAME: &str = "fuzz.body";

/// The slots of a body-mode definition: bit `k` (0..3) of `sel` includes slot
/// `k` of the fixed table `p` (Path), `n` (Identifier), `i` (Integer) and `e`
/// (Enum of "start", "stop"), in that order.
pub fn body_slots(sel: u8) -> Vec<SlotDef> {
    let table = [
        ("p", SlotType::Path),
        ("n", SlotType::Identifier),
        ("i", SlotType::Integer),
        (
            "e",
            SlotType::Enum(vec!["start".to_string(), "stop".to_string()]),
        ),
    ];
    table
        .into_iter()
        .enumerate()
        .filter(|(k, _)| sel & (1 << k) != 0)
        .map(|(_, (name, ty))| SlotDef {
            name: name.to_string(),
            ty,
        })
        .collect()
}

/// The definition body mode compiles: `body` under the slots `sel` selects, with
/// risk class Mutate when `sel & 0x10` is set and Read otherwise.
pub fn body_def(sel: u8, body: &str) -> TemplateDef {
    TemplateDef {
        name: BODY_TEMPLATE_NAME.to_string(),
        risk_class: if sel & 0x10 != 0 {
            RiskClassDef::Mutate
        } else {
            RiskClassDef::Read
        },
        body: body.to_string(),
        slots: body_slots(sel),
    }
}

/// Body-mode seeds as `(sel, body)`, shared by `gen_corpus` and the unit test
/// that runs each through the oracle.
pub const BODY_SEEDS: &[(u8, &str)] = &[
    (0x00, "df -P -T"),
    (0x01, "cat {{p}}"),
    (0x03, "journalctl -u {{n}} --file {{p}}"),
    (0x0f, "cmd {{p}} {{n}} {{i}} {{e}}"),
    (0x10, "uptime"),
    (0x01, "a{{p}}"),
    (0x01, "echo \"{{p}}\""),
    (0x01, "{{p}}"),
    (0x01, "sh -c {{p}}"),
    (0x04, "echo $(( {{i}} + 1 ))"),
    (0x01, "cat <<EOF\n{{p}}\nEOF\n"),
    (0x01, "echo 'abc {{p}}"),
    (0x01, "cat {{ p }}"),
    (0x01, "cat {{\tp}}"),
    (0x03, "cat {{ n }} {{p}}"),
    (0x01, "cat {{q}}"),
    (0x03, "cat {{p}}"),
    (0x01, "f() { cat {{p}}; }"),
    (0x01, "find / -name x -exec cat {{p}} \\;"),
];

/// File-mode seed texts (hand-written; the shipped files are added by
/// `gen_corpus`).
pub const FILE_SEEDS: &[&str] = &[
    // The typo the loader's deny_unknown_fields exists to catch.
    "[[templates]]\nname = \"x.y\"\nrisk_class = \"read\"\nbody = \"uptime\"\n",
    // A missing risk_class.
    "[[template]]\nname = \"x.y\"\nbody = \"uptime\"\n",
    // risk_class has no `unspecified` variant.
    "[[template]]\nname = \"x.y\"\nrisk_class = \"unspecified\"\nbody = \"uptime\"\n",
    // An enum slot.
    "[[template]]\nname = \"svc.act\"\nrisk_class = \"mutate\"\nbody = \"systemctl {{e}} nginx\"\n\n\
     [[template.slots]]\nname = \"e\"\ntype = \"enum\"\nvalues = [\"a\"]\n",
    // A path slot.
    "[[template]]\nname = \"log.show\"\nrisk_class = \"read\"\nbody = \"cat {{p}}\"\n\n\
     [[template.slots]]\nname = \"p\"\ntype = \"path\"\n",
    // A placeholder with whitespace inside the braces.
    "[[template]]\nname = \"svc.act\"\nrisk_class = \"mutate\"\nbody = \"systemctl {{ e }} nginx\"\n\n\
     [[template.slots]]\nname = \"e\"\ntype = \"enum\"\nvalues = [\"start\", \"stop\"]\n",
    // A Native name compiles; only the loader refuses it.
    "[[template]]\nname = \"file.read\"\nrisk_class = \"read\"\nbody = \"uptime\"\n",
];

fn name_ok(s: &str, allow_dot: bool) -> bool {
    let mut chars = s.chars();
    chars.next().is_some_and(|c| c.is_ascii_lowercase())
        && chars.all(|c| {
            c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || (allow_dot && c == '.')
        })
}

/// The acceptance rules `compile` documents, restated independently of relay-ops'
/// private predicates. Every clause is a necessary condition of `compile`
/// returning Ok, never a sufficient one.
///
/// "Referenced" is weakened to "the body contains `{{`" and "the slot name is a
/// substring of the body": the placeholder parser trims whitespace inside the
/// braces, so `{{ p }}` compiles, and `compile` refuses an unreferenced slot, so
/// both clauses hold for every accepted definition.
pub fn def_contract_holds(def: &TemplateDef) -> Result<(), &'static str> {
    if !name_ok(&def.name, true) || def.name == "raw_exec" {
        return Err("name is not ^[a-z][a-z0-9_.]*$ or is raw_exec");
    }
    if def.body.is_empty() {
        return Err("body is empty");
    }
    if def.body.len() > 64 * 1024 {
        return Err("body exceeds 64 KiB");
    }
    if def.slots.len() > 64 {
        return Err("more than 64 slots");
    }
    for (i, slot) in def.slots.iter().enumerate() {
        if !name_ok(&slot.name, false) {
            return Err("slot name is not ^[a-z][a-z0-9_]*$");
        }
        if def.slots[..i].iter().any(|s| s.name == slot.name) {
            return Err("duplicate slot name");
        }
        if let SlotType::Enum(values) = &slot.ty {
            if values.is_empty() || values.iter().any(String::is_empty) {
                return Err("enum slot is empty or holds an empty value");
            }
        }
        if !def.body.contains(slot.name.as_str()) {
            return Err("slot name does not occur in the body");
        }
    }
    if !def.slots.is_empty() && !def.body.contains("{{") {
        return Err("slots declared but the body holds no placeholder");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use relay_ops::operations::template::compile;

    fn parse(text: &str) -> Result<TemplateFileMirror, toml::de::Error> {
        toml::from_str(text)
    }

    #[test]
    fn shipped_template_files_parse_and_compile() {
        for text in [
            include_str!("../../packaging/templates.d/relay-read/catalog.toml"),
            include_str!("../../templates.example.toml"),
        ] {
            let file = parse(text).expect("shipped template file parses");
            assert!(!file.template.is_empty());
            for def in &file.template {
                compile(def).unwrap_or_else(|e| panic!("{} does not compile: {e}", def.name));
                def_contract_holds(def).unwrap_or_else(|e| panic!("{}: {e}", def.name));
            }
        }
    }

    #[test]
    fn mirror_matches_the_loader_on_unknown_keys() {
        let valid = "name = \"x.y\"\nrisk_class = \"read\"\nbody = \"uptime\"\n";
        assert!(parse(&format!("[[templates]]\n{valid}")).is_err());
        assert!(parse(&format!("version = 1\n[[template]]\n{valid}")).is_err());
        // `TemplateDef` sets no deny_unknown_fields, so the loader ignores an extra
        // key inside `[[template]]` as well, and the mirror shares that type. If
        // relay-ops ever adds it, this expectation flips together with the loader's.
        assert!(parse(&format!("[[template]]\n{valid}description = \"x\"\n")).is_ok());
    }

    #[test]
    fn body_slots_select_by_bit() {
        assert!(body_slots(0x00).is_empty());
        let names = |sel| -> Vec<String> { body_slots(sel).into_iter().map(|s| s.name).collect() };
        assert_eq!(names(0x05), ["p", "i"]);
        assert_eq!(names(0x0f), ["p", "n", "i", "e"]);
    }

    #[test]
    fn whitespace_padded_placeholders_compile_and_hold_the_contract() {
        for body in ["cat {{ p }}", "cat {{\tp}}", "cat {{p}}"] {
            let def = body_def(0x01, body);
            compile(&def).unwrap_or_else(|e| panic!("{body:?}: {e}"));
            def_contract_holds(&def).unwrap_or_else(|e| panic!("{body:?}: {e}"));
        }
    }

    #[test]
    fn every_seed_that_compiles_holds_the_contract() {
        let mut defs: Vec<(String, TemplateDef)> = BODY_SEEDS
            .iter()
            .map(|(sel, body)| (format!("{body:?}"), body_def(*sel, body)))
            .collect();
        for text in FILE_SEEDS {
            if let Ok(file) = parse(text) {
                defs.extend(file.template.into_iter().map(|d| (d.name.clone(), d)));
            }
        }
        for (label, def) in &defs {
            if compile(def).is_ok() {
                def_contract_holds(def).unwrap_or_else(|e| panic!("{label}: {e}"));
            }
        }
        for body in ["cat {{p}}", "cat {{ p }}", "df -P -T"] {
            let (sel, _) = BODY_SEEDS
                .iter()
                .find(|(_, b)| *b == body)
                .unwrap_or_else(|| panic!("seed {body:?} missing"));
            compile(&body_def(*sel, body)).unwrap_or_else(|e| panic!("{body:?}: {e}"));
        }
    }

    #[test]
    fn def_contract_rejects_known_bad() {
        let mut named = body_def(0x01, "cat {{p}}");
        named.name = "raw_exec".into();
        let empty_body = body_def(0x00, "");
        let mut bad_slot = body_def(0x01, "cat {{p}}");
        bad_slot.slots[0].name = "P".into();
        let mut dup = body_def(0x01, "cat {{p}}");
        dup.slots.push(dup.slots[0].clone());
        let mut empty_enum = body_def(0x01, "cat {{p}}");
        empty_enum.slots[0].ty = SlotType::Enum(vec![String::new()]);
        let no_braces = body_def(0x01, "cat");
        let absent = body_def(0x01, "cat {{q}}");
        for (label, def) in [
            ("raw_exec name", named),
            ("empty body", empty_body),
            ("slot P", bad_slot),
            ("duplicate slot", dup),
            ("empty enum value", empty_enum),
            ("no placeholder", no_braces),
            ("slot name absent", absent),
        ] {
            assert!(def_contract_holds(&def).is_err(), "{label}");
        }
    }
}
