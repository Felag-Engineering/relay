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
//! Three further targets fuzz the parsers a Node's own root-owned files reach
//! (Policy compose and lint, Template file parsing and compile) and the Native
//! argument validators against their advertised schema. None opens a file,
//! spawns a process or reaches Template render. Their helpers live in
//! [`policy_oracle`], [`template_oracle`] and [`arg_oracle`].
//!
//! `fuzz_template_render` reaches Template render through `ResolvedOp::invoke`
//! with a recording Runner. It spawns no process and opens only its own
//! executable, as a path-slot value. Its models live in [`render_oracle`].
//!
//! Only failure modes are asserted (panic / crash / OOM / roundtrip
//! inconsistency); a plain `Err` from `decode` is the correct outcome for
//! malformed bytes and is never a finding.

/// Prost-generated wire types, from the workspace's relay-proto crate (ADR-0007:
/// generated once from /proto, never hand-edited).
pub use relay_proto as pb;

pub mod arg_oracle;
pub mod policy_oracle;
pub mod render_oracle;
pub mod template_oracle;

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

/// The fuzz crate names relay-exec for the `ExecRequest` type only, and nothing
/// here may run a process: invariant 1 is the property under test, so the
/// harness must never execute. This scans every source file of the crate for a
/// code line that calls the executor or spawns a process, and fails when a source
/// file is added without being listed, so a new target cannot dodge the scan.
#[cfg(test)]
mod no_process_guard {
    const SOURCES: &[(&str, &str)] = &[
        ("src/arg_oracle.rs", include_str!("arg_oracle.rs")),
        ("src/lib.rs", include_str!("lib.rs")),
        ("src/policy_oracle.rs", include_str!("policy_oracle.rs")),
        ("src/render_oracle.rs", include_str!("render_oracle.rs")),
        ("src/template_oracle.rs", include_str!("template_oracle.rs")),
        (
            "examples/gen_corpus.rs",
            include_str!("../examples/gen_corpus.rs"),
        ),
        (
            "fuzz_targets/fuzz_enroll_response_decode.rs",
            include_str!("../fuzz_targets/fuzz_enroll_response_decode.rs"),
        ),
        (
            "fuzz_targets/fuzz_operation_args.rs",
            include_str!("../fuzz_targets/fuzz_operation_args.rs"),
        ),
        (
            "fuzz_targets/fuzz_path_canonical.rs",
            include_str!("../fuzz_targets/fuzz_path_canonical.rs"),
        ),
        (
            "fuzz_targets/fuzz_policy_compose.rs",
            include_str!("../fuzz_targets/fuzz_policy_compose.rs"),
        ),
        (
            "fuzz_targets/fuzz_raw_exec_gate.rs",
            include_str!("../fuzz_targets/fuzz_raw_exec_gate.rs"),
        ),
        (
            "fuzz_targets/fuzz_relay_message_decode.rs",
            include_str!("../fuzz_targets/fuzz_relay_message_decode.rs"),
        ),
        (
            "fuzz_targets/fuzz_renew_response_decode.rs",
            include_str!("../fuzz_targets/fuzz_renew_response_decode.rs"),
        ),
        (
            "fuzz_targets/fuzz_template_compile.rs",
            include_str!("../fuzz_targets/fuzz_template_compile.rs"),
        ),
        (
            "fuzz_targets/fuzz_template_render.rs",
            include_str!("../fuzz_targets/fuzz_template_render.rs"),
        ),
    ];

    // Split so that this file does not match its own scan.
    const FORBIDDEN: [&str; 3] = [
        concat!("executor", "::execute"),
        concat!("std", "::process"),
        concat!("Command", "::new"),
    ];

    #[test]
    fn no_source_runs_a_process() {
        for (path, text) in SOURCES {
            for (n, line) in text.lines().enumerate() {
                if line.trim_start().starts_with("//") {
                    continue;
                }
                for pat in FORBIDDEN {
                    assert!(
                        !line.contains(pat),
                        "{path}:{}: `{pat}` in a fuzz crate source",
                        n + 1
                    );
                }
            }
        }
    }

    #[test]
    fn every_source_file_is_scanned() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        let mut on_disk = Vec::new();
        for dir in ["src", "fuzz_targets", "examples"] {
            for entry in std::fs::read_dir(root.join(dir)).expect("read source dir") {
                let name = entry.expect("dir entry").file_name();
                let name = name.to_string_lossy();
                if name.ends_with(".rs") {
                    on_disk.push(format!("{dir}/{name}"));
                }
            }
        }
        on_disk.sort();
        let mut listed: Vec<String> = SOURCES.iter().map(|(p, _)| p.to_string()).collect();
        listed.sort();
        assert_eq!(on_disk, listed, "list every source file in SOURCES");
    }
}
