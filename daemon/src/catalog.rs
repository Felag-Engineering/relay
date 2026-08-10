//! Binding tests for the **shipped read catalog** — the first-party template
//! pack installed with the daemon package (issue #293, ADR-0021).
//!
//! The catalog itself is data, not code: `packaging/templates.d/relay-read/`.
//! This module is where that data is held to the same bar as the code around
//! it, so a hand-edit to a shipped template fails a test instead of shipping:
//!
//! - every template compiles, is `read`-class, and is one of the seven the ADR
//!   names (no quiet additions, no quiet drops);
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
use crate::operations::template::{compile, TemplateDef};
use crate::policy::{from_toml_str, path_is_canonical, Decision, Policy};

/// The shipped catalog, exactly as packaged.
const CATALOG: &str = include_str!("../packaging/templates.d/relay-read/catalog.toml");

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
/// tail's line cap is template-fixed — not a slot a caller could raise
/// (#293: "line/byte caps are template-fixed, not wire-fillable").
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
        "/etc/relay-daemon/policy.toml",
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
