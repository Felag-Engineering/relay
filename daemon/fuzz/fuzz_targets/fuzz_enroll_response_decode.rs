//! Fuzzes `EnrollResponse` decoding: the certless enrollment path (ADR-0006).
//! This response is parsed before the daemon holds any mTLS identity — over
//! server-authenticated TLS only — making it the earliest wire input the
//! daemon ever decodes.
#![no_main]

use libfuzzer_sys::fuzz_target;
use relay_daemon_fuzz::{decode_roundtrip, pb::EnrollResponse};

fuzz_target!(|data: &[u8]| {
    decode_roundtrip::<EnrollResponse>(data);
});
