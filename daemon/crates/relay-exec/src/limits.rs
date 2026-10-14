//! Daemon-local, wire-immutable `setrlimit` bounds on a Task's spawned child, and
//! the shared io-error renderer (moved from the bin's config.rs).

/// `setrlimit` bounds applied to every spawned child (`executor::execute`'s
/// `pre_exec` hook). Daemon-local and wire-immutable: the Relay can never set
/// or raise these over the wire (invariant 11 analog for the daemon;
/// ADR-0002/0004) — they are a compile-time constant like the bin's
/// `config::MAX_OUTPUT_BYTES` output cap, not env-derived. A Policy/env-tunable value is
/// future work; the operator's runtime lever today is the systemd unit
/// (`TasksMax=`, an optional `MemoryMax=` drop-in).
///
/// `None` leaves that resource unbounded (inherits the process's own limit);
/// `Some(v)` sets `rlim_cur == rlim_max == v`, so the child is always bounded
/// even when the inherited hard limit is unlimited (deny-closed: a setrlimit
/// failure aborts the spawn rather than ever running a child with a
/// weaker-than-configured limit — see `executor::apply_rlimits`).
#[derive(Clone, Copy, Debug)]
pub struct ResourceLimits {
    /// `RLIMIT_NPROC` — processes/threads per real UID.
    pub nproc: Option<u64>,
    /// `RLIMIT_DATA` — brk + anonymous mmap (NOT `RLIMIT_AS`; file-backed mmap
    /// is uncounted so package-manager mmap'd reads aren't capped by this).
    pub data_bytes: Option<u64>,
    /// `RLIMIT_NOFILE` — open file descriptors.
    pub nofile: Option<u64>,
    /// `RLIMIT_CPU` — CPU-seconds backstop above the wall-clock Task timeout;
    /// bounds CPU-bound (spin/compute) runaways only, not sleeping/hung-I/O
    /// children (those are bounded by the existing wall-clock timeout kill).
    pub cpu_seconds: Option<u64>,
    /// `RLIMIT_FSIZE` — largest single file a child may write.
    pub fsize_bytes: Option<u64>,
}

impl ResourceLimits {
    /// The shipped default profile: a single generous global cap sized to
    /// contain a fork/allocation/fd/write bomb while giving the heaviest
    /// legitimate Operation (`pkg.install`'s package-manager fan-out) ample
    /// headroom.
    pub const DEFAULT: ResourceLimits = ResourceLimits {
        nproc: Some(2048),
        data_bytes: Some(2 * 1024 * 1024 * 1024), // 2 GiB
        nofile: Some(4096),
        cpu_seconds: Some(600),
        fsize_bytes: Some(4 * 1024 * 1024 * 1024), // 4 GiB
    };
}

impl Default for ResourceLimits {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// Renders an `io::Error`'s human message without the trailing `" (os error N)"`.
///
/// E.g. `NotFound` -> `"No such file or directory"`, not
/// `"No such file or directory (os error 2)"`. Used to build subject-naming
/// error strings (`spawn <argv0>: <reason>`, `read <path>: <reason>`) without
/// noisy errno suffixes. Errors without a raw OS error code pass through unchanged.
pub fn clean_io_error(e: &std::io::Error) -> String {
    let s = e.to_string();
    if e.raw_os_error().is_some() {
        if let Some(idx) = s.rfind(" (os error ") {
            return s[..idx].to_string();
        }
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- clean_io_error ------------------------------------------------------

    #[test]
    fn clean_io_error_strips_os_error_suffix() {
        let e = std::io::Error::from_raw_os_error(2); // ENOENT
        let cleaned = clean_io_error(&e);
        assert!(
            cleaned.contains("No such file or directory"),
            "got {cleaned:?}"
        );
        assert!(!cleaned.contains("(os error"), "got {cleaned:?}");
    }

    #[test]
    fn clean_io_error_non_os_error_passthrough() {
        let e = std::io::Error::other("boom");
        assert_eq!(clean_io_error(&e), "boom");
    }

    // --- ResourceLimits::DEFAULT ---------------------------------------------

    #[test]
    fn resource_limits_default_is_bounded() {
        let d = ResourceLimits::DEFAULT;
        assert!(d.nproc.is_some(), "nproc must be bounded, not unlimited");
        assert!(
            d.data_bytes.is_some(),
            "data_bytes must be bounded, not unlimited"
        );
        assert!(d.nofile.is_some(), "nofile must be bounded, not unlimited");
        assert!(
            d.cpu_seconds.is_some(),
            "cpu_seconds must be bounded, not unlimited"
        );
        assert!(
            d.fsize_bytes.is_some(),
            "fsize_bytes must be bounded, not unlimited"
        );
    }
}
