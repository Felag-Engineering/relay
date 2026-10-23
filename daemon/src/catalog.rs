//! Binding tests for the **shipped read catalog** — the first-party template
//! pack installed with the daemon package (ADR-0021).
//!
//! The catalog itself is data, not code: `packaging/templates.d/relay-read/`.
//! This module is where that data is held to the same bar as the code around
//! it, so a hand-edit to a shipped template fails a test instead of shipping:
//!
//! - every template compiles, is `read`-class, and is one of the seven the ADR
//!   names (no quiet additions, no quiet drops);
//! - each name is bound by the ledger to its canonical body and risk class
//!   (ADR-0021 amendment 2026-10-15);
//! - the shipped default Policy (`policy.default.toml`, ADR-0022) allows every
//!   one of them, so "a freshly enrolled Node answers the whole catalog with
//!   zero local authoring" is verified, not asserted;
//! - the confidentiality deny-list covers the catalog's path-taking template
//!   exactly as it covers `file.read` — including the non-canonical spellings
//!   that ADR-0018 exists to defeat.
//!
//! Both files are `include_str!`'d, so the test binds the bytes that are
//! packaged, not a copy that can drift.

#![cfg(test)]

use crate::gen::RiskClass;
use crate::operations::registry::ResolvedOp;
use crate::operations::template::{
    compile, RiskClassDef, SlotDef, SlotType, TemplateDef, TemplateError,
};
use crate::policy::{from_toml_str, path_is_canonical, Decision, Policy};

/// The shipped catalog, exactly as packaged.
const CATALOG: &str = include_str!("../packaging/templates.d/relay-read/catalog.toml");

/// The ledger beside the catalog, exactly as committed.
const LEDGER: &str = include_str!("../packaging/relay-read-catalog.ledger");

/// The shipped default Policy, exactly as packaged (ADR-0022).
const DEFAULT_POLICY: &str = include_str!("../policy.default.toml");

/// The seven `read` Operations ADR-0021 names for the catalog. Sorted.
const EXPECTED: [&str; 7] = [
    "disk.usage",
    "file.checksum",
    "log.tail",
    "net.listening",
    "pkg.inventory",
    "proc.list",
    "service.status",
];

#[derive(serde::Deserialize)]
struct CatalogFile {
    template: Vec<TemplateDef>,
}

fn catalog() -> Vec<TemplateDef> {
    toml::from_str::<CatalogFile>(CATALOG)
        .expect("the shipped catalog must parse")
        .template
}

fn default_policy() -> Policy {
    from_toml_str(DEFAULT_POLICY).expect("the shipped default Policy must parse and compile")
}

fn allows(policy: &Policy, name: &str, args: &[&str]) -> bool {
    let owned: Vec<String> = args.iter().map(|s| s.to_string()).collect();
    matches!(policy.evaluate(name, &owned), Decision::Allow(_))
}

/// The catalog is exactly the seven templates the ADR names — every one
/// compiling, every one `read`. A drift in either direction fails here.
#[test]
fn catalog_is_the_seven_read_templates() {
    let defs = catalog();
    let mut names: Vec<String> = defs.iter().map(|d| d.name.clone()).collect();
    names.sort();
    assert_eq!(names, EXPECTED, "the shipped catalog's name set changed");

    for def in &defs {
        let op = compile(def)
            .unwrap_or_else(|e| panic!("shipped template {:?} must compile: {e}", def.name));
        assert_eq!(
            op.risk(),
            RiskClass::Read,
            "shipped template {:?} must be read-class (ADR-0021)",
            def.name
        );
    }
}

/// Every caller-fillable slot is a *constrained* type, and the bounded log
/// tail's line cap is template-fixed — not a slot a caller could raise.
#[test]
fn catalog_slots_are_constrained_and_the_log_tail_bound_is_fixed() {
    for def in catalog() {
        let op = compile(&def).expect("compiles");
        for (name, ty) in op.slot_specs() {
            assert!(
                matches!(ty.type_name(), "identifier" | "path" | "enum"),
                "shipped template {:?} slot {name:?} has type {:?}; the catalog takes only \
                 constrained slot types",
                def.name,
                ty.type_name()
            );
        }
        if def.name == "log.tail" {
            let slots: Vec<&str> = op.slot_specs().iter().map(|(n, _)| *n).collect();
            assert_eq!(
                slots,
                ["unit"],
                "log.tail must take ONLY a unit; its line cap is author-fixed"
            );
            assert!(
                def.body.contains("--lines=200"),
                "log.tail's line cap must be a literal in the body, not a slot"
            );
        }
    }
}

/// The scripts the shipped catalog runs, pinned: a slot is a quoted positional
/// parameter and a slot-free body is run byte for byte (ADR-0021 amendment).
#[test]
fn catalog_scripts_are_fixed() {
    for def in catalog() {
        let op = compile(&def).expect("compiles");
        let want = match def.name.as_str() {
            "service.status" => {
                "systemctl show --no-pager --property=Id,LoadState,ActiveState,SubState,Result,UnitFileState,MainPID,ExecMainStatus,NRestarts,ExecMainStartTimestamp -- \"$1\""
            }
            "log.tail" => "journalctl --no-pager --quiet --output=short-iso-precise --utc --lines=200 --unit \"$1\"",
            "file.checksum" => "sha256sum -- \"$1\"",
            _ => def.body.as_str(),
        };
        assert_eq!(
            op.script(),
            want,
            "script of shipped template {:?}",
            def.name
        );
    }
}

/// The acceptance line: a Node with the shipped catalog and the shipped default
/// Policy answers all seven with zero local authoring.
#[test]
fn the_default_policy_allows_every_shipped_template() {
    let policy = default_policy();

    assert!(allows(&policy, "proc.list", &[]));
    assert!(allows(&policy, "disk.usage", &[]));
    assert!(allows(&policy, "net.listening", &[]));
    assert!(allows(&policy, "pkg.inventory", &[]));
    assert!(allows(&policy, "service.status", &["nginx"]));
    assert!(allows(&policy, "log.tail", &["nginx"]));
    assert!(allows(&policy, "file.checksum", &["/etc/os-release"]));
}

/// The other half of the acceptance line: none of the catalog can be
/// parameterized into reading a deny-listed path under the shipped Policy.
#[test]
fn the_default_policy_denies_the_catalog_over_confidential_paths() {
    let policy = default_policy();

    for path in [
        "/etc/shadow",
        "/etc/gshadow",
        "/etc/ssh/ssh_host_ed25519_key",
        "/root/.ssh/id_rsa",
        "/etc/relay-daemon/relay-daemon.env",
        "/var/lib/relay-daemon/key.pem",
        "/proc/self/environ",
        "/proc/kcore",
    ] {
        assert!(
            !allows(&policy, "file.checksum", &[path]),
            "file.checksum of {path} must be denied by the shipped default Policy — a digest \
             is a content oracle"
        );
        assert!(
            !allows(&policy, "file.read", &[path]),
            "file.read of {path} must stay denied (ADR-0022)"
        );
    }
}

/// ADR-0018's lesson applied to the template tier: the exact-path denies above
/// must also refuse non-canonical spellings. The dispatch gate enforces this
/// for a template's `path` slot before Policy runs, using the same predicate
/// the engine applies to `file.read` — so both halves are checked here.
#[test]
fn non_canonical_spellings_of_a_denied_path_do_not_slip_through() {
    let policy = default_policy();

    for spelling in [
        "/etc/../etc/shadow",
        "//etc/shadow",
        "/etc/./shadow",
        "/etc/shadow/",
    ] {
        // The gate: a template `path` argument in non-canonical form never
        // reaches the allow pass (dispatch::gate_and_invoke).
        assert!(
            !path_is_canonical(spelling),
            "{spelling} must be rejected as non-canonical before Policy is consulted"
        );
        // The engine: file.read's own precondition, unchanged.
        assert!(
            !allows(&policy, "file.read", &[spelling]),
            "file.read of {spelling} must be denied as non-canonical (ADR-0018)"
        );
    }
}

/// A template name is not vocabulary: the shipped Policy's catalog rules are
/// inert on a Node without the pack, which is what makes them safe to ship
/// fleet-wide. (Dispatch reports `unsupported` there — see dispatch.rs.)
#[test]
fn catalog_policy_rules_do_not_create_vocabulary() {
    let policy = default_policy();
    // Policy would allow it...
    assert!(allows(&policy, "proc.list", &[]));
    // ...but the vocabulary lookup is what decides whether it exists, and no
    // native Operation by that name exists.
    assert!(crate::operations::risk_class("proc.list").is_none());
}

/// The shipped pack is the example of a clean Template set: no body draws a
/// load error or a `policy check` warning.
#[test]
fn catalog_has_no_code_position_errors_or_warnings() {
    let report = crate::templates::lint_dir(std::path::Path::new(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/packaging/templates.d"
    )));
    assert!(
        report.findings.is_empty(),
        "findings: {:?}",
        report.findings
    );
    assert_eq!(report.names.len(), EXPECTED.len());
    for def in catalog() {
        let op = compile(&def).unwrap_or_else(|e| panic!("{}: {e}", def.name));
        assert!(
            op.warnings().is_empty(),
            "{}: {:?}",
            def.name,
            op.warnings()
        );
    }
}

// ---------------------------------------------------------------------------
// The ledger: a released name is bound to its body and risk class.
// ---------------------------------------------------------------------------

/// SHA-256 (lowercase hex) of a Template's canonical body: its body text and
/// its ordered slot declarations, as the daemon parsed them. It is independent
/// of TOML layout and comments and of the engine's rendering (it hashes
/// `def.body`, not the rendered script). The name is the ledger key and the
/// risk class is a ledger column in clear, so neither is hashed (ADR-0021
/// amendment 2026-10-15).
///
/// Destructuring is exhaustive: a new field or variant fails to compile here
/// until someone decides whether it belongs in the canonical body.
fn canonical_body_digest(def: &TemplateDef) -> Result<String, TemplateError> {
    use std::fmt::Write as _;

    compile(def)?;
    let TemplateDef {
        name: _,
        risk_class: _,
        body,
        slots,
    } = def;

    // Length-prefixed, so the stream is injective.
    fn field(buf: &mut Vec<u8>, x: &str) {
        buf.extend_from_slice(x.len().to_string().as_bytes());
        buf.push(b'\n');
        buf.extend_from_slice(x.as_bytes());
    }
    fn count(buf: &mut Vec<u8>, n: usize) {
        buf.extend_from_slice(n.to_string().as_bytes());
        buf.push(b'\n');
    }

    let mut buf = b"relay-template-body-v1\n".to_vec();
    field(&mut buf, body);
    count(&mut buf, slots.len());
    for slot in slots {
        let SlotDef { name, ty } = slot;
        field(&mut buf, name);
        let (tag, values): (&str, &[String]) = match ty {
            SlotType::Identifier => ("identifier", &[]),
            SlotType::Integer => ("integer", &[]),
            SlotType::Path => ("path", &[]),
            SlotType::Enum(values) => ("enum", values),
        };
        field(&mut buf, tag);
        count(&mut buf, values.len());
        for value in values {
            field(&mut buf, value);
        }
    }

    let digest = ring::digest::digest(&ring::digest::SHA256, &buf);
    let mut hex = String::with_capacity(64);
    for b in digest.as_ref() {
        write!(hex, "{b:02x}").expect("writing to a String cannot fail");
    }
    Ok(hex)
}

struct LedgerEntry {
    name: String,
    class: String,
    digest: String,
    withdrawn: bool,
}

fn is_ledger_name(s: &str) -> bool {
    let mut chars = s.chars();
    matches!(chars.next(), Some('a'..='z'))
        && chars.all(|c| matches!(c, 'a'..='z' | '0'..='9' | '_' | '.'))
}

/// Parses the ledger under the grammar in its header: four single-space
/// separated fields per line, `#` comments only at column 0, LF line endings,
/// each name at most once. The error names the 1-based line.
fn parse_ledger(text: &str) -> Result<Vec<LedgerEntry>, String> {
    if text.contains('\r') {
        return Err("ledger contains a carriage return; LF line endings only".into());
    }
    let mut entries: Vec<LedgerEntry> = Vec::new();
    for (i, line) in text.lines().enumerate() {
        let n = i + 1;
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if line.trim() != line {
            return Err(format!("line {n}: leading or trailing whitespace"));
        }
        let fields: Vec<&str> = line.split(' ').collect();
        let [name, class, digest, status] = fields[..] else {
            return Err(format!(
                "line {n}: want exactly four single-space separated fields, found {}",
                fields.len()
            ));
        };
        if !is_ledger_name(name) {
            return Err(format!("line {n}: bad name {name:?}"));
        }
        if !matches!(class, "read" | "mutate") {
            return Err(format!("line {n}: bad risk class {class:?}"));
        }
        if digest.len() != 64
            || !digest
                .bytes()
                .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
        {
            return Err(format!("line {n}: digest is not 64 lowercase hex"));
        }
        let withdrawn = match status {
            "active" => false,
            "withdrawn" => true,
            _ => return Err(format!("line {n}: bad status {status:?}")),
        };
        if entries.iter().any(|e| e.name == name) {
            return Err(format!("line {n}: duplicate name {name:?}"));
        }
        entries.push(LedgerEntry {
            name: name.into(),
            class: class.into(),
            digest: digest.into(),
            withdrawn,
        });
    }
    Ok(entries)
}

fn class_word(c: RiskClassDef) -> &'static str {
    match c {
        RiskClassDef::Read => "read",
        RiskClassDef::Mutate => "mutate",
    }
}

/// Every way `defs` and `ledger` disagree; empty when the ledger binds the
/// catalog. A catalog name missing from the ledger carries the line to append.
fn ledger_mismatches(defs: &[TemplateDef], ledger: &str) -> Vec<String> {
    let entries = match parse_ledger(ledger) {
        Ok(e) => e,
        Err(e) => return vec![format!("malformed ledger: {e}")],
    };
    let mut out = Vec::new();
    for def in defs {
        let digest = match canonical_body_digest(def) {
            Ok(d) => d,
            Err(e) => {
                out.push(format!(
                    "{}: does not compile, so has no digest: {e}",
                    def.name
                ));
                continue;
            }
        };
        let class = class_word(def.risk_class);
        match entries.iter().find(|e| e.name == def.name) {
            None => out.push(format!(
                "{}: no ledger entry; append this line: {} {class} {digest} active",
                def.name, def.name
            )),
            Some(e) if e.withdrawn => out.push(format!(
                "{}: the ledger marks this name withdrawn; a withdrawn name is never re-added",
                def.name
            )),
            Some(e) => {
                if e.digest != digest {
                    out.push(format!(
                        "{}: body digest is {digest}, ledger has {}",
                        def.name, e.digest
                    ));
                }
                if e.class != class {
                    out.push(format!(
                        "{}: risk class is {class}, ledger has {}",
                        def.name, e.class
                    ));
                }
            }
        }
    }
    for e in entries.iter().filter(|e| !e.withdrawn) {
        if !defs.iter().any(|d| d.name == e.name) {
            out.push(format!(
                "{}: active in the ledger but absent from the catalog; mark it withdrawn",
                e.name
            ));
        }
    }
    out
}

/// DI-30: every catalog name is bound, in the committed ledger, to its
/// canonical body digest and risk class.
#[test]
fn catalog_names_match_ledger() {
    let defs = catalog();
    let mismatches = ledger_mismatches(&defs, LEDGER);
    assert!(
        mismatches.is_empty(),
        "catalog and ledger disagree:\n{}",
        mismatches.join("\n")
    );

    // What the loader installs from templates.d must be exactly catalog.toml's
    // names, so a second pack file cannot carry a name the ledger never sees.
    let report = crate::templates::lint_dir(std::path::Path::new(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/packaging/templates.d"
    )));
    assert!(
        report.findings.is_empty(),
        "findings: {:?}",
        report.findings
    );
    let mut loaded = report.names.clone();
    loaded.sort();
    let mut catalog_names: Vec<String> = defs.iter().map(|d| d.name.clone()).collect();
    catalog_names.sort();
    assert_eq!(
        loaded, catalog_names,
        "templates.d installs names catalog.toml does not hold"
    );
}

mod ledger_tests {
    use super::*;

    const DIGEST_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    fn one(text: &str) -> TemplateDef {
        toml::from_str::<CatalogFile>(text)
            .expect("test TOML parses")
            .template
            .remove(0)
    }

    fn digest(text: &str) -> String {
        canonical_body_digest(&one(text)).unwrap()
    }

    const T: &str = r#"
[[template]]
name = "t.one"
risk_class = "read"
body = "ls -- {{dir}}"
[[template.slots]]
name = "dir"
type = "path"
"#;

    fn two_slots(ty_a: &str, ty_b: &str) -> String {
        format!(
            r#"
[[template]]
name = "t.two"
risk_class = "read"
body = "echo {{{{a}}}} {{{{b}}}}"
[[template.slots]]
name = "a"
{ty_a}
[[template.slots]]
name = "b"
{ty_b}
"#
        )
    }

    #[test]
    fn canonical_body_digest_ignores_toml_layout() {
        let relaid = r#"
# a comment
[[template]]
risk_class   = "read"
name = "t.one"
body = 'ls -- {{dir}}'   # trailing

[[template.slots]]
type = "path"
name   = "dir"
"#;
        assert_eq!(digest(T), digest(relaid));
    }

    #[test]
    fn canonical_body_digest_changes_with_body_or_slots() {
        let base = digest(T);
        assert_ne!(base, digest(&T.replace("ls --", "ls -l --")));
        assert_ne!(base, digest(&T.replace("\"path\"", "\"identifier\"")));

        let id = "type = \"identifier\"";
        let en1 = "type = \"enum\"\nvalues = [\"x\"]";
        let en2 = "type = \"enum\"\nvalues = [\"x\", \"y\"]";
        let en2_swapped = "type = \"enum\"\nvalues = [\"y\", \"x\"]";
        assert_ne!(digest(&two_slots(id, en1)), digest(&two_slots(id, en2)));
        assert_ne!(
            digest(&two_slots(id, en2)),
            digest(&two_slots(id, en2_swapped))
        );
        assert_ne!(digest(&two_slots(id, en1)), digest(&two_slots(en1, id)));

        // The class is bound by the ledger column, not the digest.
        assert_eq!(base, digest(&T.replace("\"read\"", "\"mutate\"")));
    }

    #[test]
    fn canonical_body_digest_refuses_a_template_that_does_not_compile() {
        let unused = one(r#"
[[template]]
name = "t.bad"
risk_class = "read"
body = "true"
[[template.slots]]
name = "x"
type = "identifier"
"#);
        assert!(matches!(
            canonical_body_digest(&unused),
            Err(TemplateError::UnusedSlot { .. })
        ));
    }

    // Proves DI-30.
    #[test]
    fn ledger_check_refuses_a_changed_body() {
        let ledger = format!("t.one read {DIGEST_A} active\n");
        let m = ledger_mismatches(&[one(T)], &ledger);
        assert_eq!(m.len(), 1, "{m:?}");
        assert!(m[0].contains("body digest"), "{m:?}");
    }

    // Proves DI-30.
    #[test]
    fn ledger_check_refuses_a_changed_risk_class() {
        let ledger = format!("t.one mutate {} active\n", digest(T));
        let m = ledger_mismatches(&[one(T)], &ledger);
        assert_eq!(m.len(), 1, "{m:?}");
        assert!(m[0].contains("risk class"), "{m:?}");
    }

    // Proves DI-30.
    #[test]
    fn ledger_check_accepts_a_withdrawn_name_absent_from_the_catalog() {
        let ledger = format!(
            "t.one read {} active\ngone.name read {DIGEST_A} withdrawn\n",
            digest(T)
        );
        assert!(ledger_mismatches(&[one(T)], &ledger).is_empty());
    }

    // Proves DI-30.
    #[test]
    fn ledger_check_refuses_a_withdrawn_name_back_in_the_catalog() {
        let ledger = format!("t.one read {} withdrawn\n", digest(T));
        let m = ledger_mismatches(&[one(T)], &ledger);
        assert_eq!(m.len(), 1, "{m:?}");
        assert!(m[0].contains("withdrawn"), "{m:?}");
    }

    #[test]
    fn ledger_check_refuses_a_catalog_name_missing_from_the_ledger() {
        let m = ledger_mismatches(&[one(T)], "# empty\n");
        assert_eq!(m.len(), 1, "{m:?}");
        let line = format!("t.one read {} active", digest(T));
        assert!(m[0].contains(&line), "{m:?}");
    }

    #[test]
    fn ledger_check_refuses_an_active_entry_dropped_from_the_catalog() {
        let ledger = format!("t.one read {DIGEST_A} active\n");
        let m = ledger_mismatches(&[], &ledger);
        assert_eq!(m.len(), 1, "{m:?}");
        assert!(m[0].contains("absent from the catalog"), "{m:?}");
    }

    #[test]
    fn ledger_check_refuses_a_malformed_line() {
        let upper = DIGEST_A.to_uppercase();
        for bad in [
            format!("t.one read {DIGEST_A} active # note\n"),
            format!("t.one read {DIGEST_A} active\r\n"),
            format!("t.one read {DIGEST_A}\n"),
            format!("t.one read {DIGEST_A} retired\n"),
            format!(" t.one read {DIGEST_A} active\n"),
            format!("t.one read {upper} active\n"),
        ] {
            let m = ledger_mismatches(&[], &bad);
            assert_eq!(m.len(), 1, "{bad:?}: {m:?}");
            assert!(m[0].starts_with("malformed ledger"), "{bad:?}: {m:?}");
        }
    }

    #[test]
    fn ledger_check_refuses_a_duplicate_name() {
        let ledger = format!("t.one read {DIGEST_A} active\nt.one read {DIGEST_A} withdrawn\n");
        let m = ledger_mismatches(&[], &ledger);
        assert_eq!(m.len(), 1, "{m:?}");
        assert!(m[0].contains("duplicate"), "{m:?}");
    }
}
