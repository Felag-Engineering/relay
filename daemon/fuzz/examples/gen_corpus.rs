//! Regenerates the committed seed corpus under `corpus/<target>/` from
//! representative, well-formed encoded messages (issues #238/#252).
//!
//! Run from `daemon/fuzz/` (works on stable — only cargo-fuzz itself needs
//! nightly):
//!
//! ```text
//! cargo run --example gen_corpus
//! ```
//!
//! The two Policy targets (`fuzz_raw_exec_gate`, `fuzz_path_canonical`) are
//! text-framed rather than prost-encoded; their seeds are byte-stable.
//!
//! All field values are fixed, so re-running is byte-stable except for one
//! caveat: prost encodes `map` fields in HashMap iteration order, so the
//! two-entry `pkg.install` args map may serialize its entries in either order.
//! That churn is harmless — both orderings decode to the identical message,
//! and seeds are coverage starting points for libFuzzer's mutator, not test
//! vectors.

use std::collections::HashMap;
use std::fs;
use std::path::Path;

use prost::Message;
use relay_daemon_fuzz::pb::{
    policy_query, relay_message, task_request, EnrollResponse, Label, Operation, Ping, PolicyQuery,
    RawExec, RelayMessage, RenewResponse, RiskClass, TaskCancel, TaskRequest,
};
use relay_daemon_fuzz::policy_oracle::SEP;

fn write_seed(dir: &Path, name: &str, bytes: &[u8]) {
    fs::create_dir_all(dir).expect("create corpus dir");
    fs::write(dir.join(name), bytes).expect("write seed");
    println!("wrote {}/{} ({} bytes)", dir.display(), name, bytes.len());
}

fn main() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("corpus");

    // --- fuzz_relay_message_decode: one seed per RelayMessage body arm ------
    let dir = root.join("fuzz_relay_message_decode");

    let ping = RelayMessage {
        body: Some(relay_message::Body::Ping(Ping {
            unix_millis: 1_754_500_000_000,
        })),
    };
    write_seed(&dir, "ping", &ping.encode_to_vec());

    let task_operation = RelayMessage {
        body: Some(relay_message::Body::Task(TaskRequest {
            task_id: "task-0000000000000001".into(),
            action: Some(task_request::Action::Operation(Operation {
                name: "service.restart".into(),
                args: HashMap::from([("name".to_string(), "nginx".to_string())]),
            })),
            timeout_seconds: 30,
            // A non-zero class, so the decode fuzzer's seeds exercise field 5
            // (ADR-0042).
            risk_class: RiskClass::Mutate as i32,
        })),
    };
    write_seed(&dir, "task_operation", &task_operation.encode_to_vec());

    let task_raw_exec = RelayMessage {
        body: Some(relay_message::Body::Task(TaskRequest {
            task_id: "task-0000000000000002".into(),
            action: Some(task_request::Action::RawExec(RawExec {
                argv: vec!["/usr/bin/uptime".into()],
            })),
            timeout_seconds: 60,
            risk_class: RiskClass::Read as i32,
        })),
    };
    write_seed(&dir, "task_raw_exec", &task_raw_exec.encode_to_vec());

    let task_cancel = RelayMessage {
        body: Some(relay_message::Body::TaskCancel(TaskCancel {
            task_id: "task-0000000000000001".into(),
        })),
    };
    write_seed(&dir, "task_cancel", &task_cancel.encode_to_vec());

    let policy_query_operation = RelayMessage {
        body: Some(relay_message::Body::PolicyQuery(PolicyQuery {
            query_id: "query-0001".into(),
            action: Some(policy_query::Action::Operation(Operation {
                name: "pkg.install".into(),
                args: HashMap::from([
                    ("name".to_string(), "htop".to_string()),
                    ("version".to_string(), "3.3.0".to_string()),
                ]),
            })),
        })),
    };
    write_seed(
        &dir,
        "policy_query_operation",
        &policy_query_operation.encode_to_vec(),
    );

    let policy_query_raw_exec = RelayMessage {
        body: Some(relay_message::Body::PolicyQuery(PolicyQuery {
            query_id: "query-0002".into(),
            action: Some(policy_query::Action::RawExec(RawExec {
                argv: vec!["/usr/bin/systemctl".into(), "status".into(), "nginx".into()],
            })),
        })),
    };
    write_seed(
        &dir,
        "policy_query_raw_exec",
        &policy_query_raw_exec.encode_to_vec(),
    );

    // --- fuzz_enroll_response_decode ---------------------------------------
    let dir = root.join("fuzz_enroll_response_decode");
    let enroll = EnrollResponse {
        node_id: "node-2f9a1c".into(),
        certificate: b"-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n".to_vec(),
        ca_bundle: b"-----BEGIN CERTIFICATE-----\nMIIC\n-----END CERTIFICATE-----\n".to_vec(),
        assigned_labels: vec![Label {
            key: "relay:env".into(),
            value: "prod".into(),
        }],
    };
    write_seed(&dir, "enroll_response", &enroll.encode_to_vec());

    // --- fuzz_renew_response_decode ----------------------------------------
    let dir = root.join("fuzz_renew_response_decode");
    let renew = RenewResponse {
        node_id: "node-2f9a1c".into(),
        certificate: b"-----BEGIN CERTIFICATE-----\nMIID\n-----END CERTIFICATE-----\n".to_vec(),
        ca_bundle: b"-----BEGIN CERTIFICATE-----\nMIIC\n-----END CERTIFICATE-----\n".to_vec(),
    };
    write_seed(&dir, "renew_response", &renew.encode_to_vec());

    write_policy_seeds(&root);
}

/// One `fuzz_raw_exec_gate` seed: the Policy selector byte, then the argv with
/// its elements separated by `SEP`. An empty argv is the selector alone.
fn argv_seed(sel: u8, argv: &[&str]) -> Vec<u8> {
    let mut out = vec![sel];
    out.extend_from_slice(argv.join(&SEP.to_string()).as_bytes());
    out
}

/// Seeds for the two text-framed Policy targets (#897). Byte-stable.
fn write_policy_seeds(root: &Path) {
    // --- fuzz_raw_exec_gate -------------------------------------------------
    // Selectors: 0 DotAll, 1 DotAllWithDeny, 2 Anchored, 3 DenyAll,
    // 4 Unanchored. Rows are
    // ported from relay-policy's `redteam_cases()` (raw_exec_redteam),
    // `argv0_refused_unless_single_program_token` and
    // `whitespace_in_any_argv_element_refused_naming_its_index`.
    let dir = root.join("fuzz_raw_exec_gate");
    let mut rows: Vec<(u8, Vec<&str>)> = vec![
        (2, vec!["/usr/bin/systemctl", "restart", "nginx"]),
        (2, vec!["/usr/bin/uptime"]),
        (2, vec!["/usr/bin/systemctl", "restart nginx"]),
        (2, vec!["/usr/bin/systemctl restart nginx"]),
        (
            2,
            vec![
                "/usr/bin/systemctl",
                "restart",
                "nginx",
                ";",
                "touch",
                "/tmp/pwn",
            ],
        ),
        (
            2,
            vec![
                "/bin/rm",
                "-rf",
                "/var/log",
                "&&",
                "/usr/bin/systemctl",
                "restart",
                "nginx",
            ],
        ),
        (2, vec!["/bin/sh", "-c", "/usr/bin/systemctl restart nginx"]),
        (1, vec!["systemctl", "restart", "nginx", "--force x"]),
        (1, vec!["systemctl", "restart", "nginx", "--force"]),
        (1, vec!["prog x", "--force"]),
        (1, vec!["rm"]),
        (0, vec!["systemctl\0x", "nginx"]),
        (0, vec!["a", "", "b"]),
        (0, vec!["a", ""]),
        (0, vec!["", "x"]),
        (0, vec!["a\u{200b}b", "x"]),
        (0, vec!["a\u{feff}b", "x"]),
        (0, vec!["a\u{180e}b", "x"]),
        (0, vec!["a\u{1c}b", "x"]),
        (0, vec![]),
        (3, vec!["/usr/bin/uptime"]),
    ];
    for bad in [
        "",
        "systemctl restart",
        "\t",
        "\n",
        "\r",
        "\u{a0}",
        " systemctl",
        "systemctl ",
    ] {
        rows.push((0, vec![bad, "nginx"]));
    }
    for x in [
        "a b",
        "a\tb",
        "a\nb",
        "a\rb",
        "a\u{a0}b",
        "a\u{2028}b",
        " a",
        "a ",
    ] {
        rows.push((0, vec!["prog", "ok", x]));
    }
    // Unanchored: the two exact Allows, then near-misses a substring or
    // multiline match would wrongly allow (ADR-0019 whole-command anchoring).
    rows.extend([
        (4, vec!["/usr/bin/uptime"]),
        (4, vec!["/usr/bin/id"]),
        (4, vec!["/usr/bin/uptime", "x"]),
        (4, vec!["x", "/usr/bin/uptime"]),
        (4, vec!["/usr/bin/uptimex"]),
        (4, vec!["x\n/usr/bin/id"]),
        (4, vec!["/usr/bin/id\n"]),
        (4, vec!["/usr/bin/id", "x"]),
    ]);
    for (i, (sel, argv)) in rows.iter().enumerate() {
        write_seed(&dir, &format!("argv_{i:02}"), &argv_seed(*sel, argv));
    }

    // --- fuzz_path_canonical ------------------------------------------------
    // Sources: ADR-0018, relay-policy `file_read_path_cases()` and
    // `precondition_runs_before_deny_for_template_path_positions`. The joined
    // rows are built with SEP (U+001F), so they drive the multi-position oracle.
    let dir = root.join("fuzz_path_canonical");
    let joined = |parts: &[&str]| parts.join(&SEP.to_string());
    let paths: Vec<String> = vec![
        "/".into(),
        "/etc/shadow".into(),
        "/etc/hostname".into(),
        joined(&["/etc/hostname", "extra"]),
        "/etc/../etc/shadow".into(),
        "//etc/shadow".into(),
        "/etc//shadow".into(),
        "/etc/./shadow".into(),
        "/etc/shadow/".into(),
        "/var/../etc".into(),
        "/.".into(),
        "/..".into(),
        "/a/.../b".into(),
        "relative".into(),
        "".into(),
        "etc/shadow".into(),
        "/proc/self/root/etc/shadow".into(),
        "/tmp/a b".into(),
        "/tmp/a\nb".into(),
        "/etc/shadow\0x".into(),
        "/\u{202e}x".into(),
        joined(&["/ok", "/a//b", "/c/."]),
        joined(&["/ok", "/fine"]),
    ];
    for (i, p) in paths.iter().enumerate() {
        write_seed(&dir, &format!("path_{i:02}"), p.as_bytes());
    }
}
