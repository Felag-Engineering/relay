//! Binds the schema the Relay advertises to an AI-agent (ADR-0015) to what the
//! real Native validators enforce, over arbitrary strings rather than the
//! single-character byte space the relay-ops proof test covers.
//!
//! [`schema_admits`] is a test reference, not a validator the daemon uses.

use std::collections::HashMap;

use relay_ops::operations::registry::{OpRegistration, REGISTRY};
use relay_ops::operations::schema::{ArgSpec, OP_ARG_NAME, OP_ARG_UNIT, OP_ARG_VERSION};
use relay_ops::operations::{PKG_INSTALL, SERVICE_RESTART};
use relay_proto::Operation;

use crate::policy_oracle::fields;

/// Whether the advertised `spec` admits `v`. Unconstrained data admits anything.
pub fn schema_admits(spec: &ArgSpec, v: &str) -> bool {
    let Some(cs) = &spec.charset else {
        return true;
    };
    if v.is_empty() || !v.chars().all(|c| cs.contains(c)) {
        return false;
    }
    if spec.no_leading_dash && v.starts_with('-') {
        return false;
    }
    if spec.first_last_alnum {
        let alnum = |c: Option<char>| c.is_some_and(|c| c.is_ascii_alphanumeric());
        if !alnum(v.chars().next()) || !alnum(v.chars().last()) {
            return false;
        }
    }
    true
}

/// The real validators this harness drives. `ArgSpec`'s validator field is
/// private, so each is bound by (Operation name, argument key).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Bound {
    UnitName,
    PkgName,
    PkgVersion,
}

/// The validator behind `(op, key)`, if the argument is validated.
pub fn bound_validator(op: &str, key: &str) -> Option<Bound> {
    match (op, key) {
        (SERVICE_RESTART, OP_ARG_UNIT) => Some(Bound::UnitName),
        (PKG_INSTALL, OP_ARG_NAME) => Some(Bound::PkgName),
        (PKG_INSTALL, OP_ARG_VERSION) => Some(Bound::PkgVersion),
        _ => None,
    }
}

/// Frame one `fuzz_operation_args` input. `sel` picks the REGISTRY entry (modulo
/// its length). Field `i` of `rest`'s [`fields`] is the value of the entry's
/// argument `i`; a key with no field is absent. The fields after those are
/// extra `(key, value)` pairs inserted afterwards, so a later insert overrides
/// an earlier one, and an odd trailing key gets `""`.
pub fn operation_from_fields(sel: u8, rest: &str) -> (&'static OpRegistration, Operation) {
    let entry = &REGISTRY[sel as usize % REGISTRY.len()];
    let parts = if rest.is_empty() {
        Vec::new()
    } else {
        fields(rest)
    };
    let mut args = HashMap::new();
    let declared = entry.args.len();
    for (spec, value) in entry.args.iter().zip(parts.iter()) {
        args.insert(spec.key.to_string(), value.clone());
    }
    let mut extra = parts.into_iter().skip(declared);
    while let Some(key) = extra.next() {
        args.insert(key, extra.next().unwrap_or_default());
    }
    (
        entry,
        Operation {
            name: entry.name.to_string(),
            args,
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use relay_ops::operations::pkg_install::{install_argv, PackageManager};
    use relay_ops::operations::service_restart::restart_argv;

    #[test]
    fn every_validated_arg_is_bound() {
        for entry in REGISTRY.iter() {
            for arg in entry.args {
                if arg.charset.is_some() {
                    assert!(
                        bound_validator(entry.name, arg.key).is_some(),
                        "{}.{} is validated but not bound",
                        entry.name,
                        arg.key
                    );
                }
            }
        }
    }

    fn spec(op: &str, key: &str) -> &'static ArgSpec {
        let entry = REGISTRY.iter().find(|e| e.name == op).unwrap();
        entry.args.iter().find(|a| a.key == key).unwrap()
    }

    #[test]
    fn schema_admits_agrees_on_known_cases() {
        let unit = spec(SERVICE_RESTART, OP_ARG_UNIT);
        for (v, ok) in [("nginx", true), ("-h", false), ("", false), ("a b", false)] {
            assert_eq!(schema_admits(unit, v), ok, "unit {v:?}");
            assert_eq!(restart_argv(v).is_ok(), ok, "real unit {v:?}");
        }
        let name = spec(PKG_INSTALL, OP_ARG_NAME);
        for v in ["foo-", "foo+", "-foo"] {
            assert!(!schema_admits(name, v), "name {v:?}");
            assert!(install_argv(PackageManager::Apt, v, None).is_err(), "{v:?}");
        }
        let version = spec(PKG_INSTALL, OP_ARG_VERSION);
        for (v, ok) in [("1:2.3~rc1", true), ("1.0-", false)] {
            assert_eq!(schema_admits(version, v), ok, "version {v:?}");
            assert_eq!(
                install_argv(PackageManager::Apt, "nginx", Some(v)).is_ok(),
                ok,
                "real version {v:?}"
            );
        }
    }
}
