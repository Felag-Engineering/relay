//! The only crate in the daemon workspace that spawns a process (AGENTS.md
//! invariant 1, #889).
//!
//! `executor` builds every child from an argv already fixed by Policy or a
//! Template, never through `/bin/sh`; `cancel` is the in-flight cancel registry
//! the executor honours; `limits` holds the wire-immutable `setrlimit` bounds
//! applied to the child. The crate's `clippy.toml` bans filesystem writes and
//! every `Command::new` but the one sanctioned site in `executor`, which carries
//! an explicit allow; `tests/clippy_write_ban.rs` pins that allow and refuses a
//! second spawn site anywhere in the workspace.

// Crate-private aliases so the `crate::x::...` paths in the moved files resolve
// unchanged.
pub(crate) use relay_proto as gen;
#[cfg(test)]
pub(crate) use relay_test_support as test_support;

pub mod cancel;
pub mod executor;
pub mod limits;
pub mod not_executed;

#[cfg(feature = "ban-probe")]
#[allow(dead_code)]
#[path = "../ban_probe.rs"]
mod ban_probe;
