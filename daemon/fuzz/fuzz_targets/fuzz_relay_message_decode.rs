//! Fuzzes the daemon's primary inbound envelope: `RelayMessage`, the message
//! the Relay pushes down the Tunnel stream (ADR-0005). Covers everything the
//! envelope nests — Ping, TaskRequest (Operation arg maps / RawExec argv),
//! TaskCancel, PolicyQuery — since prost decodes the whole tree in one call.
#![no_main]

use libfuzzer_sys::fuzz_target;
use relay_daemon_fuzz::{decode_roundtrip, pb::RelayMessage};

fuzz_target!(|data: &[u8]| {
    decode_roundtrip::<RelayMessage>(data);
});
