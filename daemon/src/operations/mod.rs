//! Native Operation vocabulary for the relay-daemon (ADR-0001, ADR-0012).
//!
//! Every Operation in this module is **argv-only or data-only** — the argument
//! can never change which command runs (ADR-0001 invariant #1). Risk classes
//! (ADR-0012) classify blast radius for the v1 vocabulary:
//!
//! | Name               | Kind      | Risk class |
//! |--------------------|-----------|------------|
//! | `system.facts`     | read      | READ       |
//! | `file.read`        | read      | READ       |
//! | `service.restart`  | mutate    | MUTATE     |
//! | `pkg.install`      | mutate    | MUTATE     |
//!
//! Risk class is **blast-radius classification only**, not a Policy substitute —
//! Policy (ADR-0002, deny-by-default, argument-level) applies identically to
//! both READ and MUTATE Operations.

pub mod file_read;
pub mod pkg_install;
pub mod registry;
pub mod schema;
pub mod service_restart;
pub mod system_facts;
pub mod template;

use crate::gen::RiskClass;

// ---------------------------------------------------------------------------
// Name constants — re-exported from `relay_policy::natives`, the single source of
// the vocabulary strings (Policy needs them too, and cannot depend on this crate).
// ---------------------------------------------------------------------------

pub use relay_policy::natives::{FILE_READ, PKG_INSTALL, SERVICE_RESTART, SYSTEM_FACTS};

// ---------------------------------------------------------------------------
// Vocabulary views over the registry ([`registry::REGISTRY`] — the single
// name→(handler, arg-shape, risk class) table, issue #289; ADR-0012).
// ---------------------------------------------------------------------------

/// Returns all v1 Operation descriptors in canonical order, derived from
/// [`registry::REGISTRY`] — the one place a reviewer verifies the full
/// name→class mapping; misclassification is security-relevant (ADR-0012).
///
/// Only referenced in tests; the dispatch pipeline resolves entries from the
/// same registry directly. Compiled only under test.
#[cfg(test)]
pub fn descriptors() -> Vec<crate::gen::OperationDescriptor> {
    registry::REGISTRY
        .iter()
        .map(|e| crate::gen::OperationDescriptor {
            name: e.name.to_string(),
            risk_class: e.risk as i32,
        })
        .collect()
}

/// Returns the [`RiskClass`] for a named Operation, or `None` if the name is
/// not in the v1 vocabulary — a [`registry::lookup`] view.
///
/// Called by [`crate::scheduler::Scheduler::classify`] to route Tasks to the
/// correct concurrency gate, and by the Policy linter's unknown-name check
/// (Policy itself evaluates at the dispatch layer, not here).
pub fn risk_class(name: &str) -> Option<RiskClass> {
    registry::lookup(name).map(|e| e.risk)
}

// ---------------------------------------------------------------------------
// Shared error type
// ---------------------------------------------------------------------------

/// Errors produced by Operation argument validation.
///
/// Maps to `OUTCOME_FAILURE` (exit_code -1, error text in stderr) — distinct
/// from `OUTCOME_DENIED_BY_POLICY`, which is a Policy-engine concern.
#[derive(Debug, thiserror::Error)]
pub enum OperationError {
    #[error("invalid unit name '{0}': only [A-Za-z0-9@._-] are allowed, no leading '-'")]
    InvalidUnitName(String),

    #[error("invalid package name '{0}': only [A-Za-z0-9+._-] are allowed; must start and end alphanumeric")]
    InvalidPackageName(String),

    #[error(
        "invalid package version '{0}': only [A-Za-z0-9+.:~_-] are allowed; must start and end alphanumeric"
    )]
    InvalidPackageVersion(String),

    #[error("unsupported package manager: no supported apt/dnf/yum binary found on this Node")]
    UnsupportedPackageManager,
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn descriptors_returns_four_in_order() {
        let descs = descriptors();
        assert_eq!(descs.len(), 4);

        assert_eq!(descs[0].name, SYSTEM_FACTS);
        assert_eq!(descs[1].name, FILE_READ);
        assert_eq!(descs[2].name, SERVICE_RESTART);
        assert_eq!(descs[3].name, PKG_INSTALL);

        // Pin raw i32 values against the proto contract.
        assert_eq!(descs[0].risk_class, RiskClass::Read as i32);
        assert_eq!(descs[0].risk_class, 1); // RISK_CLASS_READ
        assert_eq!(descs[1].risk_class, RiskClass::Read as i32);
        assert_eq!(descs[1].risk_class, 1); // RISK_CLASS_READ
        assert_eq!(descs[2].risk_class, RiskClass::Mutate as i32);
        assert_eq!(descs[2].risk_class, 2); // RISK_CLASS_MUTATE
        assert_eq!(descs[3].risk_class, RiskClass::Mutate as i32);
        assert_eq!(descs[3].risk_class, 2); // RISK_CLASS_MUTATE
    }

    #[test]
    fn risk_class_lookup() {
        assert_eq!(risk_class(SYSTEM_FACTS), Some(RiskClass::Read));
        assert_eq!(risk_class(FILE_READ), Some(RiskClass::Read));
        assert_eq!(risk_class(SERVICE_RESTART), Some(RiskClass::Mutate));
        assert_eq!(risk_class(PKG_INSTALL), Some(RiskClass::Mutate));
        assert_eq!(risk_class("nope"), None);
        assert_eq!(risk_class(""), None);
    }
}
