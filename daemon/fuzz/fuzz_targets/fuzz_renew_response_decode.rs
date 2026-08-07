//! Fuzzes `RenewResponse` decoding: the mTLS certificate-renewal path
//! (ADR-0006). Same certificate/ca_bundle shape as EnrollResponse but a
//! distinct generated type, so it gets its own small, focused target.
#![no_main]

use libfuzzer_sys::fuzz_target;
use relay_daemon_fuzz::{decode_roundtrip, pb::RenewResponse};

fuzz_target!(|data: &[u8]| {
    decode_roundtrip::<RenewResponse>(data);
});
