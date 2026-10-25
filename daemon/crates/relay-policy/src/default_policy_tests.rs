#![cfg(test)]
//! ---------------------------------------------------------------------------
//! Shipped default Policy tests (ADR-0022)
//!
//! The shipped default file (`daemon/policy.default.toml`) is validated here
//! against the REAL engine — the same `from_toml_str` the fail-closed loader
//! uses and the same `lint` that backs `relay-daemon policy check` — so the
//! posture ADR-0022 records (read pre-allowed, confidentiality deny-list
//! authoritative, mutate + Raw Exec opt-in) is CI-enforced, not aspirational.
//! ---------------------------------------------------------------------------

use super::*;

/// The shipped default Policy file, included verbatim so the checked-in
/// artifact is exactly what these tests validate.
const DEFAULT: &str = include_str!("../../../policy.default.toml");

/// The full confidentiality deny-list ADR-0022 records, in canonical form
/// (ADR-0018). `deny_list_mirrors_adr_0022_exactly` asserts the file
/// carries exactly this set, so file, ADR, and tests cannot drift apart
/// silently.
const DENY_LISTED_PATHS: &[&str] = &[
    // Local credential databases.
    "/etc/shadow",
    "/etc/shadow-",
    "/etc/gshadow",
    "/etc/gshadow-",
    // Host key material.
    "/etc/ssh/ssh_host_rsa_key",
    "/etc/ssh/ssh_host_ecdsa_key",
    "/etc/ssh/ssh_host_ed25519_key",
    "/etc/ssh/ssh_host_dsa_key",
    "/etc/krb5.keytab",
    // Root's default SSH private keys.
    "/root/.ssh/id_rsa",
    "/root/.ssh/id_ecdsa",
    "/root/.ssh/id_ed25519",
    "/root/.ssh/id_dsa",
    // Distribution-default TLS private keys (ADR-0022, amended 2026-10-21).
    "/etc/ssl/private/ssl-cert-snakeoil.key",
    "/etc/pki/tls/private/localhost.key",
    // The daemon's own secret-bearing files (ADR-0022, amended 2026-10-16).
    "/etc/relay-daemon/relay-daemon.env",
    "/var/lib/relay-daemon/key.pem",
    // Kernel/process memory and environment oracles.
    "/proc/kcore",
    "/dev/mem",
    "/dev/kmem",
    "/proc/self/mem",
    "/proc/self/environ",
];

fn default_policy() -> Policy {
    from_toml_str(DEFAULT).expect("policy.default.toml must parse with the fail-closed loader")
}

use crate::test_support::args;

#[test]
fn default_file_parses_with_real_loader() {
    default_policy();
}

#[test]
fn default_file_lints_clean() {
    // Same check `relay-daemon policy check --templates <shipped pack>`
    // performs: no parse error, no findings (the wildcard-allow + partial
    // deny-list is a PARTIAL shadow and must not be flagged).
    //
    // The template names are supplied because the shipped file now names
    // the shipped read catalog's Operations (issue #293): they are real
    // vocabulary on a Node with the pack installed, which is exactly the
    // Node this file is shipped to. Linting it WITHOUT them is checked
    // below — it must warn, never error, since the linter cannot see the
    // target Node's template root (ADR-0021).
    let names: Vec<String> = SHIPPED_TEMPLATE_NAMES
        .iter()
        .map(|s| s.to_string())
        .collect();
    let report = lint_with_vocabulary(DEFAULT, &names, true);
    assert!(
        report.parse_error.is_none(),
        "default file must parse cleanly; got {:?}",
        report.parse_error
    );
    assert!(
        report.findings.is_empty(),
        "default file must lint with zero findings; got {:?}",
        report.findings
    );
}

/// Linting the shipped file with no template root supplied: the catalog
/// names cannot be confirmed, so they warn (naming the fix) and never
/// error — a pipeline that lints the shipped default without pointing at
/// the pack must not fail (ADR-0021's per-Node vocabulary, issue #292).
#[test]
fn default_file_without_a_template_root_warns_but_does_not_error() {
    let report = lint(DEFAULT);
    assert!(!report.has_errors(), "got {:?}", report.findings);
    assert!(
        report.has_warnings(),
        "the catalog names must at least be surfaced; got {:?}",
        report.findings
    );
    for f in &report.findings {
        assert!(
            f.message.contains("--templates"),
            "every such warning must name the fix; got {:?}",
            f.message
        );
    }
}

/// The catalog names the shipped default Policy allows, as a list this test
/// module owns; `catalog.rs` binds the same names to the packaged pack, so
/// the two files cannot drift apart silently.
const SHIPPED_TEMPLATE_NAMES: [&str; 7] = [
    "proc.list",
    "disk.usage",
    "net.listening",
    "pkg.inventory",
    "service.status",
    "log.tail",
    "file.checksum",
];

// -- Read class pre-allowed (ADR-0022) ---------------------------------

#[test]
fn system_facts_is_allowed_with_zero_authoring() {
    let policy = default_policy();
    assert_eq!(
        policy.evaluate(operations::SYSTEM_FACTS, &[]),
        Decision::Allow(Rule::OperationAllow {
            operation: operations::SYSTEM_FACTS.to_string()
        }),
        "a freshly enrolled Node must answer system.facts out of the box"
    );
}

#[test]
fn file_read_of_innocuous_paths_is_allowed() {
    let policy = default_policy();
    for path in ["/etc/hostname", "/etc/os-release", "/var/log/syslog"] {
        assert_eq!(
            policy.evaluate(operations::FILE_READ, &args(&[path])),
            Decision::Allow(Rule::OperationAllow {
                operation: operations::FILE_READ.to_string()
            }),
            "file.read {path} must be allowed by the shipped default"
        );
    }
}

// -- Confidentiality deny-list (deny-beats-allow) ----------------------

#[test]
fn every_deny_listed_path_is_denied_with_attribution() {
    let policy = default_policy();
    for path in DENY_LISTED_PATHS {
        let decision = policy.evaluate(operations::FILE_READ, &args(&[path]));
        assert_eq!(
            decision,
            Decision::Deny {
                reason: format!(
                    "denied by explicit rule for operation '{}'",
                    operations::FILE_READ
                ),
                rule: Some(Rule::OperationDeny {
                    operation: operations::FILE_READ.to_string()
                }),
            },
            "file.read {path} must be denied by an ATTRIBUTED deny rule \
                 (deny-beats-allow over the wildcard read allow)"
        );
    }
}

// Proves DI-28.
#[test]
fn deny_list_mirrors_adr_0022_exactly() {
    // Set equality both ways: a path added to the file without the
    // ADR/test being updated fails here, and so does a path silently
    // dropped from the file.
    let policy = default_policy();
    let in_file: std::collections::BTreeSet<String> = policy
        .deny_rules()
        .iter()
        .filter(|r| r.name == operations::FILE_READ)
        .flat_map(|r| r.args.iter().flatten().cloned())
        .collect();
    let expected: std::collections::BTreeSet<String> =
        DENY_LISTED_PATHS.iter().map(|s| s.to_string()).collect();
    assert_eq!(
        in_file, expected,
        "policy.default.toml's file.read deny values must exactly mirror \
             the ADR-0022 deny-list pinned in this test (ADR-0022, amended 2026-10-16)"
    );
    let checksum_in_file: std::collections::BTreeSet<String> = policy
        .deny_rules()
        .iter()
        .filter(|r| r.name == "file.checksum")
        .flat_map(|r| r.args.iter().flatten().cloned())
        .collect();
    assert_eq!(
        checksum_in_file, expected,
        "every file.read deny must be mirrored exactly on file.checksum \
             (ADR-0022): a digest confirms a guessed file byte-for-byte"
    );
}

// Proves DI-28.
#[test]
fn default_policy_denies_only_secret_bearing_own_files() {
    let policy = default_policy();
    let both = [operations::FILE_READ, "file.checksum"];

    for path in [
        "/var/lib/relay-daemon/key.pem",
        "/etc/relay-daemon/relay-daemon.env",
        "/proc/self/environ",
    ] {
        for name in both {
            assert!(
                matches!(
                    policy.evaluate(name, &args(&[path])),
                    Decision::Deny {
                        rule: Some(Rule::OperationDeny { .. }),
                        ..
                    }
                ),
                "{name} {path} must be denied by an explicit rule"
            );
        }
    }

    for path in [
        "/etc/relay-daemon/policy.toml",
        "/etc/relay-daemon/ca-bundle.pem",
        "/var/lib/relay-daemon/ca_bundle.pem",
        "/var/lib/relay-daemon/cert.pem",
        "/usr/bin/relay-daemon",
        "/usr/local/bin/relay-daemon",
        "/usr/lib/systemd/system/relay-daemon.service",
        "/etc/systemd/system/relay-daemon.service",
        "/etc/systemd/system/relay-daemon.service.d/override.conf",
        "/etc/relay-daemon/templates.d/relay-read/catalog.toml",
    ] {
        for name in both {
            assert!(
                matches!(policy.evaluate(name, &args(&[path])), Decision::Allow(_)),
                "{name} {path} holds no secret and must not be denied"
            );
        }
    }
}

#[test]
fn lexical_evasions_of_deny_listed_paths_are_denied() {
    // Non-canonical spellings never reach string matching: ADR-0018's
    // canonical-form precondition denies them outright.
    let policy = default_policy();
    for path in [
        "/etc/../etc/shadow",
        "//etc/shadow",
        "/etc/shadow/",
        "/etc/./shadow",
        "/var/lib/relay-daemon//key.pem",
    ] {
        assert!(
            matches!(
                policy.evaluate(operations::FILE_READ, &args(&[path])),
                Decision::Deny { .. }
            ),
            "non-canonical spelling {path} must be denied (ADR-0018)"
        );
    }
}

// -- Mutate class + Raw Exec stay opt-in -------------------------------

#[test]
fn mutate_operations_are_denied_by_default() {
    let policy = default_policy();
    for (name, invocation_args) in [
        (operations::SERVICE_RESTART, vec!["nginx"]),
        (operations::PKG_INSTALL, vec!["nginx", ""]),
    ] {
        let decision = policy.evaluate(name, &args(&invocation_args));
        assert!(
            matches!(decision, Decision::Deny { rule: None, .. }),
            "{name} must be deny-by-default (no shipped mutate allow); got {decision:?}"
        );
    }
}

#[test]
fn raw_exec_is_denied_by_default() {
    let policy = default_policy();
    assert!(
        !policy.raw_exec_enabled(),
        "the shipped default must carry no [raw_exec] allow patterns"
    );
    let decision = policy.evaluate_raw_exec(&args(&["/usr/bin/uptime"]));
    assert!(
        matches!(decision, Decision::Deny { rule: None, .. }),
        "Raw Exec must be deny-by-default under the shipped default; got {decision:?}"
    );
}
