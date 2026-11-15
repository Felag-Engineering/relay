//! The source walk shared by the daemon's structural guards: which directories hold the
//! workspace's Rust source, and every file under one of them. One copy, so the guards cannot
//! drift apart on what they read.
//!
//! Every read failure panics. A guard whose walk silently skips a directory it could not read
//! scans less than it claims and passes on nothing.
//!
//! Mounted with `#[path]`, as `maintainer_scripts.rs` is, so Cargo does not build it as a test
//! crate of its own. Each guard uses only part of it.
#![allow(dead_code)]

use std::path::{Path, PathBuf};

/// The daemon workspace root, `daemon/`.
pub fn daemon() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// Every file under `dir`, recursively, in directory-listing order.
pub fn files_under(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    walk(dir, &mut out);
    out
}

fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(dir).unwrap_or_else(|e| panic!("read {}: {e}", dir.display())) {
        let path = entry
            .unwrap_or_else(|e| panic!("read an entry of {}: {e}", dir.display()))
            .path();
        if path.is_dir() {
            walk(&path, out);
        } else {
            out.push(path);
        }
    }
}

/// Every `.rs` file under `dir`, recursively, in directory-listing order.
pub fn rust_files_under(dir: &Path) -> Vec<PathBuf> {
    files_under(dir)
        .into_iter()
        .filter(|p| p.extension().is_some_and(|e| e == "rs"))
        .collect()
}

/// `daemon/src`, then each workspace member's `crates/<member>/src` in name order. Members are
/// found by listing `crates/`, so a new member is read without editing any guard.
pub fn workspace_src_roots() -> Vec<PathBuf> {
    let crates = daemon().join("crates");
    let mut members: Vec<PathBuf> = std::fs::read_dir(&crates)
        .unwrap_or_else(|e| panic!("read {}: {e}", crates.display()))
        .map(|e| {
            e.unwrap_or_else(|e| panic!("read an entry of {}: {e}", crates.display()))
                .path()
        })
        .filter(|p| p.is_dir())
        .collect();
    members.sort();
    let mut roots = vec![daemon().join("src")];
    roots.extend(members.into_iter().map(|m| m.join("src")));
    roots
}

/// [`workspace_src_roots`] without the test-support crate, which only dev-dependencies reach:
/// the source that builds the shipped daemon.
pub fn production_src_roots() -> Vec<PathBuf> {
    let test_support = daemon().join("crates").join("relay-test-support");
    workspace_src_roots()
        .into_iter()
        .filter(|root| !root.starts_with(&test_support))
        .collect()
}

/// Every `.rs` file under each of `roots`, sorted. A root that holds none fails the test: the
/// walk is broken, not the tree clean.
pub fn rust_files_in(roots: &[PathBuf]) -> Vec<PathBuf> {
    let mut files = Vec::new();
    for root in roots {
        let found = rust_files_under(root);
        assert!(
            !found.is_empty(),
            "{} holds no .rs file; the walk is broken",
            root.display()
        );
        files.extend(found);
    }
    files.sort();
    files
}
