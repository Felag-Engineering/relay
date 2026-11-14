//! Fuzzes Template file parsing (through the loader's own serde on
//! `TemplateDef`) and `template::compile`, including the body lexer and the
//! code-position classifier compile runs. It never renders, invokes or reads the
//! compiled script: the substitution oracle belongs to the render target.
//!
//! A crash here is a Template-load finding: file it, never paper over it.
//!
//! Input: byte 0 with bit 7 set is file mode. The rest is UTF-8 TOML, parsed as
//! `TemplateFileMirror`, and each `[[template]]` is compiled. Byte 0 with bit 7
//! clear is body mode: the rest is the body of `body_def(sel, rest)`, so the
//! lexer is reached without TOML.
#![no_main]

use libfuzzer_sys::fuzz_target;
use relay_daemon_fuzz::template_oracle::{body_def, def_contract_holds, TemplateFileMirror};
use relay_ops::operations::registry::ResolvedOp;
use relay_ops::operations::template::{compile, SlotType};
use relay_proto::RiskClass;

/// The most definitions one file-mode input compiles.
const MAX_DEFS: usize = 64;

fn check(def: &relay_ops::operations::template::TemplateDef) {
    let Ok(op) = compile(def) else {
        // A refusal is the correct outcome for most inputs.
        return;
    };

    // T1: compile accepted a definition its own contract refuses.
    if let Err(why) = def_contract_holds(def) {
        panic!("compile accepted {:?}, contract says: {why}", def.name);
    }
    // T2.
    assert_eq!(ResolvedOp::name(&op), def.name);
    // T3: the risk class is mandatory and no input sets or loosens it (invariant 13).
    assert_eq!(ResolvedOp::risk(&op), RiskClass::from(def.risk_class));
    assert_ne!(ResolvedOp::risk(&op), RiskClass::Unspecified);
    // T4: the positional order Policy evaluates.
    let want: Vec<(&str, &SlotType)> = def.slots.iter().map(|s| (s.name.as_str(), &s.ty)).collect();
    assert_eq!(op.slot_specs(), want);
    // T5: a Path slot missing here would skip ADR-0018's precondition (invariant 3).
    let paths: Vec<usize> = def
        .slots
        .iter()
        .enumerate()
        .filter(|(_, s)| matches!(s.ty, SlotType::Path))
        .map(|(i, _)| i)
        .collect();
    assert_eq!(op.path_slot_positions(), paths);
    assert_eq!(ResolvedOp::path_arg_positions(&op), paths);
}

fuzz_target!(|data: &[u8]| {
    let Some((&sel, rest)) = data.split_first() else {
        return;
    };
    let Ok(rest) = std::str::from_utf8(rest) else {
        return;
    };
    if sel & 0x80 != 0 {
        let Ok(file) = toml::from_str::<TemplateFileMirror>(rest) else {
            return;
        };
        if file.template.len() > MAX_DEFS {
            return;
        }
        for def in &file.template {
            check(def);
        }
    } else {
        check(&body_def(sel, rest));
    }
});
