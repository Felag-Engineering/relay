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
}
