//! Shared harness for the relay-daemon wire-fuzzing targets (issues #238/#252).
//!
//! The daemon trusts a pinned-CA Relay (ADR-0005/0006) but still parses every
//! byte it receives; the prost-generated decode path is therefore the
//! untrusted-bytes entry point. The externally-reachable inbound messages —
//! and this crate's fuzz surface — are:
//!
//! * [`pb::RelayMessage`]   — the Tunnel stream envelope the Relay pushes down
//!   (Ping / TaskRequest / TaskCancel / PolicyQuery and everything nested in
//!   them: Operation arg maps, RawExec argv, timeouts).
//! * [`pb::EnrollResponse`] — the certless enrollment response (ADR-0006):
//!   parsed *before* mTLS identity exists, over server-authenticated TLS only,
//!   making it the earliest-parsed wire input in the daemon's lifecycle.
//! * [`pb::RenewResponse`]  — the mTLS renewal response, same certificate /
//!   ca_bundle shape.
//!
//! What #218's stable-toolchain proptest suite covers is the layer *above*
//! decoding (Policy evaluation, dispatch classification, validators) with
//! bounded strategies over already-decoded structures. This crate covers the
//! layer #218 explicitly deferred: coverage-guided exploration of the raw
//! byte-level decode itself, hunting panics, OOM, and unbounded recursion.
//!
//! Two further targets (#897) fuzz the Policy engine checks a Task's arguments
//! reach: the Raw Exec argv gate (ADR-0019) and the canonical-path precondition
//! (ADR-0018). They drive Policy only through `Policy::decide` (invariant 12),
//! never the test-only `evaluate` shims; they spawn no process and touch no
//! filesystem. Their shared helpers live in [`policy_oracle`].
//!
//! Only failure modes are asserted (panic / crash / OOM / roundtrip
//! inconsistency); a plain `Err` from `decode` is the correct outcome for
//! malformed bytes and is never a finding.

/// Prost-generated wire types, from the workspace's relay-proto crate (ADR-0007:
/// generated once from /proto, never hand-edited).
pub use relay_proto as pb;

pub mod policy_oracle;

use prost::Message;

/// Decode `data` as `M`; on success, re-encode and decode again, asserting the
/// roundtrip reproduces an identical message.
///
/// The primary oracle is "no panic / no crash / no OOM" inside prost's decode
/// path (libFuzzer supplies the memory/time limits). The roundtrip is a cheap
/// secondary oracle that also drags the generated `encode` path and derived
/// `PartialEq` through the fuzzer, and would surface a decode that silently
/// produces a message it cannot faithfully re-serialize.
pub fn decode_roundtrip<M>(data: &[u8])
where
    // prost 0.14 dropped `Debug` as a supertrait of `Message`; the generated types
    // still implement it, and `assert_eq!` needs it to print a failing pair.
    M: Message + Default + PartialEq + std::fmt::Debug,
{
    let Ok(msg) = M::decode(data) else {
        // Malformed bytes correctly rejected: the expected case, not a finding.
        return;
    };
    let encoded = msg.encode_to_vec();
    let redecoded =
        M::decode(encoded.as_slice()).expect("re-decoding prost's own encoding must succeed");
    assert_eq!(
        msg, redecoded,
        "decode(encode(m)) must reproduce the identical message"
    );
}
