//! The wire types generated from /proto/relay/v1/relay.proto (ADR-0007).
//!
//! Generated here once, for the daemon and the fuzz crate alike. The lint
//! suppression is confined to the generated module: `tests/clippy_write_ban.rs`
//! pins this file to exactly these items (and the ban-probe mount), so no
//! hand-written code can sit under it.

#[cfg(feature = "ban-probe")]
#[allow(dead_code)]
#[path = "../ban_probe.rs"]
mod ban_probe;

mod generated {
    #![allow(dead_code, unused_imports, clippy::all)]
    include!(concat!(env!("OUT_DIR"), "/relay.v1.rs"));
}

pub use generated::*;
