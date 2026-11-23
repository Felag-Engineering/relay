//! The repository-file readers shared by the daemon's offline proofs over files that are not
//! Rust source (workflows, the Dockerfiles, compose stacks, units, maintainer scripts): where the
//! repository root is, a read that panics with the path, a regex that panics with its pattern,
//! and the text with its full-line `#` comments dropped. One copy, so the proofs cannot drift
//! apart on what counts as a comment.
//!
//! Every failure panics. A proof whose read silently yields nothing checks less than it claims.
//!
//! Mounted with `#[path]`, as `source_walk.rs` is, so Cargo does not build it as a test crate of
//! its own. `maintainer_scripts.rs` reads through it, so a crate that mounts that module mounts
//! this one beside it. Each proof uses only part of it.
#![allow(dead_code)]

use regex::Regex;
use std::path::{Path, PathBuf};

/// The repository root, the parent of `daemon/`.
pub fn repo() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("daemon/ has a parent")
        .to_path_buf()
}

/// The text of `path`.
pub fn read(path: &Path) -> String {
    std::fs::read_to_string(path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
}

/// `pattern` compiled.
pub fn re(pattern: &str) -> Regex {
    Regex::new(pattern).unwrap_or_else(|e| panic!("regex {pattern}: {e}"))
}

/// `text` without its full-line `#` comments, every kept line newline-terminated, so prose
/// that names a property never satisfies an assertion on it.
pub fn code(text: &str) -> String {
    text.lines()
        .filter(|l| !l.trim_start().starts_with('#'))
        .map(|l| format!("{l}\n"))
        .collect()
}
