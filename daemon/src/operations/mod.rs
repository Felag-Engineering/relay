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
//!
//! Risk class is **blast-radius classification only**, not a Policy substitute —
//! Policy (ADR-0002, deny-by-default, argument-level) applies identically to
//! both READ and MUTATE Operations.

pub mod file_read;
pub mod service_restart;
pub mod system_facts;

use crate::gen::{OperationDescriptor, RiskClass};

// ---------------------------------------------------------------------------
// Name constants — single source of the vocabulary strings.
// ---------------------------------------------------------------------------

/// Wire name for the `system.facts` Operation.
pub const SYSTEM_FACTS: &str = "system.facts";

/// Wire name for the `file.read` Operation.
pub const FILE_READ: &str = "file.read";

/// Wire name for the `service.restart` Operation.
pub const SERVICE_RESTART: &str = "service.restart";

// ---------------------------------------------------------------------------
// Risk-class registry — one place a reviewer verifies all name→class mappings
// against the proto comment at gleipnir.proto (ADR-0012).
// ---------------------------------------------------------------------------

/// Returns all v1 Operation descriptors in canonical order.
///
/// A reviewer can verify the full name→class mapping here in one place;
/// misclassification is security-relevant (ADR-0012).
///
/// Only referenced in tests; the dispatch pipeline routes by name string.
#[allow(dead_code)]
pub fn descriptors() -> Vec<OperationDescriptor> {
    vec![
        OperationDescriptor {
            name: SYSTEM_FACTS.to_string(),
            risk_class: RiskClass::Read as i32,
        },
        OperationDescriptor {
            name: FILE_READ.to_string(),
            risk_class: RiskClass::Read as i32,
        },
        OperationDescriptor {
            name: SERVICE_RESTART.to_string(),
            risk_class: RiskClass::Mutate as i32,
        },
    ]
}

/// Returns the [`RiskClass`] for a named Operation, or `None` if the name is
/// not in the v1 vocabulary.
///
/// Called by [`crate::scheduler::Scheduler::classify`] to route Tasks to the
/// correct concurrency gate. The dispatch pipeline routes by name string, not
/// by risk class (Policy evaluates at the dispatch layer, not here).
pub fn risk_class(name: &str) -> Option<RiskClass> {
    match name {
        SYSTEM_FACTS | FILE_READ => Some(RiskClass::Read),
        SERVICE_RESTART => Some(RiskClass::Mutate),
        _ => None,
    }
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
    #[error("invalid unit name '{0}': only [A-Za-z0-9@._-] are allowed")]
    InvalidUnitName(String),
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn descriptors_returns_three_in_order() {
        let descs = descriptors();
        assert_eq!(descs.len(), 3);

        assert_eq!(descs[0].name, SYSTEM_FACTS);
        assert_eq!(descs[1].name, FILE_READ);
        assert_eq!(descs[2].name, SERVICE_RESTART);

        // Pin raw i32 values against the proto contract.
        assert_eq!(descs[0].risk_class, RiskClass::Read as i32);
        assert_eq!(descs[0].risk_class, 1); // RISK_CLASS_READ
        assert_eq!(descs[1].risk_class, RiskClass::Read as i32);
        assert_eq!(descs[1].risk_class, 1); // RISK_CLASS_READ
        assert_eq!(descs[2].risk_class, RiskClass::Mutate as i32);
        assert_eq!(descs[2].risk_class, 2); // RISK_CLASS_MUTATE
    }

    #[test]
    fn risk_class_lookup() {
        assert_eq!(risk_class(SYSTEM_FACTS), Some(RiskClass::Read));
        assert_eq!(risk_class(FILE_READ), Some(RiskClass::Read));
        assert_eq!(risk_class(SERVICE_RESTART), Some(RiskClass::Mutate));
        assert_eq!(risk_class("nope"), None);
        assert_eq!(risk_class(""), None);
    }
}
