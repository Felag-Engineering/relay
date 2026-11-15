//! Fuzzes the Native Operation argument path: the named-args to positional
//! mapping that both Policy and the handler read (ADR-0011), and each validated
//! argument's real validator against the schema the Relay advertises to an
//! AI-agent (ADR-0015). The argv builders are the handlers' own pure seams and
//! never execute.
//!
//! A crash here is an argument-injection finding (invariant 1): file it, never
//! paper over it.
//!
//! Input: byte 0 selects the REGISTRY entry (modulo its length). The rest is
//! UTF-8, `SEP`-separated values, one per declared argument, then extra
//! key/value pairs.
#![no_main]

use libfuzzer_sys::fuzz_target;
use relay_daemon_fuzz::arg_oracle::{bound_validator, operation_from_fields, schema_admits, Bound};
use relay_ops::operations::pkg_install::{install_argv, PackageManager};
use relay_ops::operations::registry::ResolvedOp;
use relay_ops::operations::schema::OP_ARG_PATH;
use relay_ops::operations::service_restart::restart_argv;

fn check_pkg_install(entry: &relay_ops::operations::registry::OpRegistration, p: &[String]) {
    let name = &p[0];
    let version = Some(p[1].as_str()).filter(|v| !v.is_empty());
    let expect_ok = schema_admits(&entry.args[0], name)
        && version.is_none_or(|v| schema_admits(&entry.args[1], v));
    for (mgr, program, sep) in [
        (PackageManager::Apt, "apt-get", '='),
        (PackageManager::Dnf, "dnf", '-'),
        (PackageManager::Yum, "yum", '-'),
    ] {
        let r = install_argv(mgr, name, version);
        assert_eq!(
            r.is_ok(),
            expect_ok,
            "validator and advertised schema disagree: name {name:?}, version {version:?}"
        );
        let Ok(argv) = r else {
            continue;
        };
        assert_eq!(argv.len(), 4, "{argv:?}");
        assert_eq!(argv[0], program, "arguments changed which command runs");
        assert_eq!(&argv[1..3], ["install", "-y"], "{argv:?}");
        let want = match version {
            Some(v) => format!("{name}{sep}{v}"),
            None => name.clone(),
        };
        assert_eq!(argv[3], want, "{argv:?}");
        assert!(!argv[3].starts_with('-'), "option injection: {argv:?}");
        // apt reads a trailing '-' or '+' as a remove/install modifier.
        assert!(
            argv[3]
                .chars()
                .last()
                .is_some_and(|c| c.is_ascii_alphanumeric()),
            "action modifier injection: {argv:?}"
        );
    }
}

fuzz_target!(|data: &[u8]| {
    let Some((&sel, rest)) = data.split_first() else {
        return;
    };
    let Ok(rest) = std::str::from_utf8(rest) else {
        return;
    };
    if rest.chars().count() > 8192 {
        return;
    }
    let (entry, op) = operation_from_fields(sel, rest);
    let p = entry.positional_args(&op);

    // A1: the mapping.
    assert_eq!(p.len(), entry.args.len());
    for (i, arg) in entry.args.iter().enumerate() {
        let want = op.args.get(arg.key).cloned().unwrap_or_default();
        assert_eq!(p[i], want, "position {i} ({})", arg.key);
    }
    assert_eq!(ResolvedOp::positional_args(entry, &op), p);

    // A2: path positions.
    let paths: Vec<usize> = entry
        .args
        .iter()
        .enumerate()
        .filter(|(_, a)| a.key == OP_ARG_PATH)
        .map(|(i, _)| i)
        .collect();
    assert_eq!(ResolvedOp::path_arg_positions(entry), paths);
    for &i in &paths {
        assert!(entry.args[i].charset.is_none());
    }

    // A3: a validated argument without a binding fails here, so being bound
    // means being fuzzed. A4 and A5 run on the binding, not on the entry's name.
    for (i, arg) in entry.args.iter().enumerate() {
        if arg.charset.is_none() {
            continue;
        }
        let Some(bound) = bound_validator(entry.name, arg.key) else {
            panic!(
                "{}.{} is validated but not bound in arg_oracle",
                entry.name, arg.key
            );
        };
        match bound {
            // A4.
            Bound::UnitName => {
                let r = restart_argv(&p[i]);
                assert_eq!(
                    r.is_ok(),
                    schema_admits(arg, &p[i]),
                    "validator and advertised schema disagree: {:?}",
                    p[i]
                );
                if let Ok(argv) = r {
                    assert_eq!(argv, ["systemctl", "restart", p[i].as_str()]);
                }
            }
            // A5 checks name and version together, from the name's binding.
            Bound::PkgName => check_pkg_install(entry, &p),
            Bound::PkgVersion => {}
        }
    }
});
