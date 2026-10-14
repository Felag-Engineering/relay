//! The daemon's connection to the Relay (ADR-0005, ADR-0006): the mTLS
//! identity and its sanctioned on-disk writer, enrollment, certificate renewal,
//! and the Tunnel's channel and reconnect backoff.
//!
//! Not read-only: `identity` persists the Node's key and certificate, which is why
//! this crate inherits the workspace's exec ban but not the filesystem-write ban
//! (`tests/policy_never_opened_for_write.rs` allowlists that one file).

// Crate-private aliases so the `crate::x::...` paths in the moved files resolve
// unchanged.
pub(crate) use relay_log as log_field;
pub(crate) use relay_proto as gen;
#[cfg(test)]
pub(crate) use relay_test_support as test_support;

use std::time::{SystemTime, UNIX_EPOCH};

pub mod enroll;
pub mod identity;
pub mod renew;
pub mod tunnel;

/// Returns a pseudo-random sample in [0, 1) using only `std` — no extra crates.
///
/// Uses the sub-second nanoseconds of `SystemTime::now()` XOR'd with the
/// process ID. The XOR with `std::process::id()` ensures that a bulk-restarted
/// fleet whose daemons all start within the same second produces distinct jitter
/// values rather than reconverging on the same send time.
pub fn rand_unit() -> f64 {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .subsec_nanos();
    // XOR in the PID so daemons started in the same second diverge.
    let mixed = (nanos ^ std::process::id()) % 1_000_000_000;
    mixed as f64 / 1e9
}
