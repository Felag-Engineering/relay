//! Native Operation vocabulary for the relay-daemon (ADR-0001, ADR-0012).
//!
//! Every Operation in this module is **argv-only or data-only** — the argument
//! can never change which command runs (ADR-0001 invariant 1). Risk classes
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
mod template_body;
mod template_code;

use crate::gen::RiskClass;

// ---------------------------------------------------------------------------
// Name constants — re-exported from `relay_policy::natives`, the single source of
// the vocabulary strings (Policy needs them too, and cannot depend on this crate).
// ---------------------------------------------------------------------------

pub use relay_policy::natives::{FILE_READ, PKG_INSTALL, SERVICE_RESTART, SYSTEM_FACTS};

// ---------------------------------------------------------------------------
// Vocabulary views over the registry ([`registry::REGISTRY`] — the single
// name→(handler, arg-shape, risk class) table; ADR-0012, ADR-0021).
// ---------------------------------------------------------------------------

/// Returns the [`RiskClass`] for a named Operation, or `None` if the name is
/// not in the v1 vocabulary — a [`registry::lookup`] view.
///
/// Called by the bin's `scheduler::Scheduler::classify` to route Tasks to the
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
    fn risk_class_lookup() {
        assert_eq!(risk_class(SYSTEM_FACTS), Some(RiskClass::Read));
        assert_eq!(risk_class(FILE_READ), Some(RiskClass::Read));
        assert_eq!(risk_class(SERVICE_RESTART), Some(RiskClass::Mutate));
        assert_eq!(risk_class(PKG_INSTALL), Some(RiskClass::Mutate));
        assert_eq!(risk_class("nope"), None);
        assert_eq!(risk_class(""), None);
    }
}
