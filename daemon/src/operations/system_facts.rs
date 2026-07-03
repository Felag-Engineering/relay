//! `system.facts` Operation — gathers OS, kernel, arch, hostname, and non-loopback
//! IP addresses from the running Node at Task time.
//!
//! This gathers a richer [`Facts`] at runtime than `config.rs`, which fills only
//! `hostname/os/arch` at startup from environment variables. Reconciling the two
//! sources (config.rs Hello path vs. system.facts Task result) is dispatch wiring
//! that lands in a later issue (#82) — this module does not touch config.rs.
//!
//! No subprocess is spawned: `os`/`arch` come from `std::env::consts`, and
//! `kernel`/`hostname` are read directly from `/proc/sys/kernel/` — data the
//! kernel already exposes as plain files. Spawning `uname`/`hostname` would be a
//! gratuitous process for data available via a single `read(2)`.
//!
//! IP addresses are enumerated via `libc::getifaddrs` (no new crate, no subprocess,
//! no fragile `/proc/net` parsing). The single `unsafe` block is bounded and
//! safety-annotated below.

#![allow(dead_code)]

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::ptr;

use crate::gen::Facts;

/// Gathers the [`Facts`] fields from the running Node.
///
/// Fallbacks are applied field-by-field so a partial `/proc` mount (container
/// environment) does not produce an empty result:
/// - `hostname`: `/proc/sys/kernel/hostname` → `$HOSTNAME` env var → `"unknown-node"`
/// - `kernel`:   `/proc/sys/kernel/osrelease` → `""` (empty string)
pub fn gather_facts() -> Facts {
    let os = std::env::consts::OS.to_string();
    let arch = std::env::consts::ARCH.to_string();
    let hostname = read_proc_trimmed("/proc/sys/kernel/hostname")
        .or_else(|| std::env::var("HOSTNAME").ok())
        .unwrap_or_else(|| "unknown-node".to_string());
    let kernel = read_proc_trimmed("/proc/sys/kernel/osrelease").unwrap_or_default();
    let ip_addresses = local_ip_addresses();

    Facts {
        os,
        arch,
        hostname,
        kernel,
        ip_addresses,
    }
}

/// Reads a `/proc` pseudo-file, trims whitespace, and returns `None` on any
/// I/O error or if the trimmed result is empty.
fn read_proc_trimmed(path: &str) -> Option<String> {
    let raw = std::fs::read_to_string(path).ok()?;
    let trimmed = raw.trim().to_string();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed)
    }
}

/// Enumerates all non-loopback IP addresses on the Node's network interfaces
/// using `libc::getifaddrs`.
///
/// Returns an empty `Vec` if the syscall fails or no non-loopback addresses
/// are found (e.g. in a containerized CI runner with only a loopback interface).
fn local_ip_addresses() -> Vec<String> {
    let mut addrs: Vec<String> = Vec::new();
    let mut ifap: *mut libc::ifaddrs = ptr::null_mut();

    // Safety: `getifaddrs` writes a kernel-allocated linked list into `ifap`.
    // We traverse it read-only (no mutable aliasing) using `read_unaligned` to
    // avoid any alignment assumption. `freeifaddrs` at the end releases the list;
    // we call it unconditionally even when the walk produces no addresses.
    // No references into the list outlive the `unsafe` block.
    unsafe {
        if libc::getifaddrs(&mut ifap) != 0 {
            return vec![];
        }

        let mut cur = ifap;
        while !cur.is_null() {
            let ifa = &*cur;

            if !ifa.ifa_addr.is_null() {
                // sa_family identifies the address family; it sits at the start of
                // every sockaddr variant and is safe to read directly.
                let family = (*ifa.ifa_addr).sa_family as libc::c_int;

                if family == libc::AF_INET {
                    // Safety: AF_INET guarantees ifa_addr points to sockaddr_in.
                    // read_unaligned avoids UB if the pointer's alignment is looser
                    // than sockaddr_in's natural alignment.
                    let sin: libc::sockaddr_in =
                        ptr::read_unaligned(ifa.ifa_addr as *const libc::sockaddr_in);
                    // sin_addr.s_addr is in network byte order (big-endian).
                    // u32::from_be converts to native byte order so that
                    // Ipv4Addr::from(u32) (which calls to_be_bytes internally)
                    // reconstructs the correct octets on little-endian x86_64.
                    let ip = Ipv4Addr::from(u32::from_be(sin.sin_addr.s_addr));
                    if !IpAddr::V4(ip).is_loopback() {
                        addrs.push(ip.to_string());
                    }
                } else if family == libc::AF_INET6 {
                    // Safety: AF_INET6 guarantees ifa_addr points to sockaddr_in6.
                    let sin6: libc::sockaddr_in6 =
                        ptr::read_unaligned(ifa.ifa_addr as *const libc::sockaddr_in6);
                    // sin6_addr.s6_addr is [u8; 16] already in network byte order;
                    // Ipv6Addr::from([u8; 16]) is directly correct, no conversion needed.
                    let ip = Ipv6Addr::from(sin6.sin6_addr.s6_addr);
                    if !IpAddr::V6(ip).is_loopback() {
                        addrs.push(ip.to_string());
                    }
                }
            }

            cur = ifa.ifa_next;
        }

        libc::freeifaddrs(ifap);
    }

    addrs.sort();
    addrs.dedup();
    addrs
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;

    #[test]
    fn gather_facts_populates_core_fields() {
        let facts = gather_facts();
        assert_eq!(
            facts.os,
            std::env::consts::OS,
            "os must match std::env::consts::OS"
        );
        assert!(!facts.os.is_empty(), "os must be non-empty");
        assert!(!facts.arch.is_empty(), "arch must be non-empty");
        assert!(!facts.hostname.is_empty(), "hostname must be non-empty");
        // On a Linux box with a mounted /proc the kernel release is always non-empty.
        assert!(
            !facts.kernel.is_empty(),
            "kernel must be non-empty on a Linux box with /proc"
        );
    }

    #[test]
    fn gather_facts_ips_are_valid_non_loopback() {
        let facts = gather_facts();
        for ip_str in &facts.ip_addresses {
            let ip: IpAddr = ip_str.parse().expect("each IP in facts must be valid");
            assert!(
                !ip.is_loopback(),
                "loopback address {ip} must not appear in facts"
            );
        }
        // Do NOT assert non-empty: a containerized CI runner may have only a loopback
        // interface, which is filtered out → empty list is valid.
    }
}
