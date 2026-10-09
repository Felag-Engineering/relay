//! The daemon's Operation vocabulary (ADR-0001, ADR-0012, ADR-0021, #889): the
//! registry, the argument schema, Template Operations and the Template loader,
//! the four Native Operations, and Raw Exec.
//!
//! Read-only by construction: this crate's `clippy.toml` bans filesystem writes
//! (invariant 2), so Templates, the trust-root loader, can be read here and never
//! written. Spawning is not done here either: every handler reaches a process only
//! through relay-exec's executor.
//!
//! That ban covers IN-PROCESS writes only. A spawned child is not bound by it: it
//! is bounded by Policy, the Templates, `selfref` and the unit's `ProtectSystem`.
//! The one way this crate can ask for a child is an `ExecRequest`, so
//! `tests/clippy_write_ban.rs` pins every construction site per file.

// Crate-private aliases so the `crate::x::...` paths in the moved files resolve
// unchanged (#889).
pub(crate) use relay_exec::{executor, limits, not_executed};
pub(crate) use relay_policy as policy;
pub(crate) use relay_policy::hardened_open;
pub(crate) use relay_proto as gen;
#[cfg(test)]
pub(crate) use relay_test_support as test_support;

pub mod operations;
pub mod raw_exec;
pub mod templates;

#[cfg(feature = "ban-probe")]
#[allow(dead_code)]
#[path = "../ban_probe.rs"]
mod ban_probe;
