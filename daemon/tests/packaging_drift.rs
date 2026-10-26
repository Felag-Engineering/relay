//! Keeps `daemon/packaging/relay-daemon.env.example` honest against the code
//! (#362).
//!
//! This test has a specific origin: the sample was missing FOUR environment
//! variables that had been added to the daemon after it was written
//! (`RELAY_STATE_DIR`, `RELAY_ENROLL_ADDRESS`, `RELAY_HEARTBEAT_INTERVAL_SECS`,
//! `RELAY_SHUTDOWN_GRACE_SECS`), and nothing noticed for several milestones.
//!
//! That is the failure mode worth guarding. A sample config is the first thing
//! an operator copies, and one that silently omits a setting does not read as
//! incomplete — it reads as though the setting does not exist. The operator
//! then runs with a default they never chose and cannot find.
//!
//! It checks COVERAGE, not values: every operator-facing `RELAY_*` the daemon
//! reads must be mentioned somewhere in the sample, commented out or not. What
//! a default should be is a judgement the sample makes; whether an operator can
//! discover the setting at all is not.
//!
//! It also pins the shipped unit's binary path (DI-40).
//!
//! Its counterpart on the Relay side is
//! `relay/cmd/relay/packaging_drift_test.go`. Two toolchains, two files, one
//! rule.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

/// `RELAY_*` name PREFIXES deliberately absent from the operator-facing sample.
///
/// Prefixes rather than exact names, because both families below are
/// open-ended by construction — the build stamps are referenced as
/// `RELAY_BUILD_*` in prose as well as individually, and the executor's
/// env-inheritance fixture carries a random suffix. Neither family is ever
/// operator configuration.
///
/// Each carries a reason, because "add it to the exemption list" is the easy
/// way to defeat this test, and a prefix exempts more than a name does.
fn exemptions() -> BTreeMap<&'static str, &'static str> {
    BTreeMap::from([
        // Injected at compile time by the release build, never set on a host.
        (
            "RELAY_BUILD_",
            "build stamps, set by the linker rather than an operator",
        ),
        // Set by the executor's own test to prove a secret in the daemon's
        // environment is NOT inherited by a spawned Task. Carries a random
        // suffix, and is a fixture rather than configuration.
        (
            "RELAY_TEST_",
            "test fixtures, never read from a real environment",
        ),
    ])
}

/// Reports whether `name` is covered by an exemption prefix.
fn is_exempt(name: &str) -> bool {
    exemptions().keys().any(|prefix| name.starts_with(prefix))
}

/// Extracts whole `RELAY_*` tokens. Matching whole tokens rather than
/// substrings matters: a substring check is satisfied by any longer name that
/// happens to contain the one being looked for, so a typo in the sample would
/// pass while shipping a setting no operator can use.
fn relay_names(text: &str) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    let bytes = text.as_bytes();
    let mut i = 0;
    while let Some(start) = text[i..].find("RELAY_") {
        let start = i + start;
        let mut end = start + "RELAY_".len();
        while end < bytes.len()
            && (bytes[end].is_ascii_uppercase()
                || bytes[end].is_ascii_digit()
                || bytes[end] == b'_')
        {
            end += 1;
        }
        if end > start + "RELAY_".len() {
            out.insert(text[start..end].to_string());
        }
        i = end.max(start + 1);
    }
    out
}

/// Every Rust source in the workspace: the bin's `src/` and each member's
/// `crates/<member>/src/`, found by listing `crates/` so a new member is read
/// without editing this test (#889).
fn workspace_sources(root: &Path) -> Vec<PathBuf> {
    let mut members: Vec<_> = std::fs::read_dir(root.join("crates"))
        .expect("read crates dir")
        .map(|e| e.expect("dir entry").path())
        .filter(|p| p.is_dir())
        .collect();
    members.sort();
    let mut roots = vec![root.join("src")];
    roots.extend(members.into_iter().map(|m| m.join("src")));
    let mut files = Vec::new();
    for dir in &roots {
        let before = files.len();
        source_files(dir, &mut files);
        assert!(
            files.len() > before,
            "{} holds no .rs file; the scan is broken",
            dir.display()
        );
    }
    files
}

fn source_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            source_files(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

// Proves DI-7.
#[test]
fn env_example_covers_the_config_surface() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));

    let sample_path = root.join("packaging/relay-daemon.env.example");
    let sample = std::fs::read_to_string(&sample_path).unwrap_or_else(|e| {
        panic!(
            "read {}: {e} — the sample config is part of the shipped surface; \
             if it moved, move this test with it rather than deleting it",
            sample_path.display()
        )
    });
    let documented = relay_names(&sample);

    let files = workspace_sources(&root);
    assert!(
        !files.is_empty(),
        "no Rust sources found — this test is scanning nothing"
    );

    let mut missing: Vec<String> = Vec::new();
    let mut found_any = false;

    for file in &files {
        let Ok(text) = std::fs::read_to_string(file) else {
            continue;
        };
        for name in relay_names(&text) {
            found_any = true;
            if is_exempt(&name) || documented.contains(&name) {
                continue;
            }
            let rel = file.strip_prefix(&root).unwrap_or(file);
            missing.push(format!("  {name} (read by {})", rel.display()));
        }
    }

    assert!(
        found_any,
        "no RELAY_* names found in daemon/src and daemon/crates/*/src — this test is scanning nothing"
    );

    missing.sort();
    missing.dedup();
    assert!(
        missing.is_empty(),
        "these environment variables are read by the daemon but appear nowhere in \
         daemon/packaging/relay-daemon.env.example:\n{}\n\n\
         An operator copying that sample cannot discover a setting it never mentions. \
         Add each one (commented out is fine, with a line saying what it does and what \
         happens if it is left at the default), or add it to exemptions() with a reason.",
        missing.join("\n")
    );
}

/// Stops the exemption list from becoming the place drift hides: an exemption
/// for a name the daemon no longer reads is stale, and the next person adding
/// one has no way to tell.
// Proves DI-7.
#[test]
fn exemptions_are_real() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let files = workspace_sources(&root);

    let mut referenced = BTreeSet::new();
    for file in &files {
        if let Ok(text) = std::fs::read_to_string(file) {
            referenced.extend(relay_names(&text));
        }
    }

    for (prefix, why) in exemptions() {
        assert!(
            referenced.iter().any(|name| name.starts_with(prefix)),
            "exemptions() lists the prefix {prefix:?} ({why:?}) but nothing in daemon/src and daemon/crates/*/src \
             starts with it — a stale exemption is where the next real drift hides"
        );
    }
}

/// The shipped example carries no join line, live or commented out: the join
/// string is never placed in the environment file, which holds no secret. The
/// example may still name `RELAY_JOIN` in prose, as a setting the daemon refuses.
// Proves DI-43.
#[test]
fn env_example_has_no_join_line() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("packaging/relay-daemon.env.example");
    let sample =
        std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    let offending: Vec<&str> = sample
        .lines()
        .map(str::trim)
        .filter(|line| {
            let line = line.strip_prefix('#').unwrap_or(line).trim_start();
            line.strip_prefix("RELAY_JOIN")
                .is_some_and(|rest| rest.trim_start().starts_with('='))
        })
        .collect();
    assert!(
        offending.is_empty(),
        "the example must carry no RELAY_JOIN assignment, live or commented out: {offending:?}"
    );
    assert!(
        sample.contains("RELAY_JOIN"),
        "the example names RELAY_JOIN in prose as a setting the daemon refuses"
    );
}

/// The shipped unit starts the daemon from `/usr/bin` (DI-40), where the package
/// installs it.
#[test]
fn unit_execstart_is_usr_bin() {
    let unit_path =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("packaging/relay-daemon.service");
    let unit = std::fs::read_to_string(&unit_path).unwrap_or_else(|e| {
        panic!(
            "read {}: {e} — the unit is part of the shipped surface; \
             if it moved, move this test with it rather than deleting it",
            unit_path.display()
        )
    });

    let execstart: Vec<&str> = unit
        .lines()
        .map(str::trim)
        .filter(|l| l.starts_with("ExecStart="))
        .collect();
    assert_eq!(
        execstart,
        ["ExecStart=/usr/bin/relay-daemon"],
        "the shipped unit must carry exactly one ExecStart, at /usr/bin (DI-40)"
    );
}

/// The install creates the Policy directory empty and never writes into it
/// again (DI-36): `postinst.sh` creates `$POLICY_DIR` in exactly one place, a
/// bare `mkdir -m 0755` guarded by `! exists`, and no maintainer script or
/// installed-file list names a path under it. A structural check, because the
/// executable counterpart (`scripts/package-guard-test.sh`'s `-d $e/policy.d`
/// assertion after `postinst`) is a shell test that the spec-proof scan, which
/// reads only `relay/` and `daemon/` Rust and Go, does not see.
// Proves DI-36.
#[test]
fn install_creates_the_policy_directory_empty_and_never_writes_into_it() {
    let packaging = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("packaging");
    let read = |path: &Path| {
        std::fs::read_to_string(path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
    };
    let postinst = read(&packaging.join("scripts/postinst.sh"));

    // (d) Floor against a vacuous pass: the script does name the directory.
    assert!(
        postinst.contains("POLICY_DIR=\"$ETC/policy.d\""),
        "postinst.sh must still assign POLICY_DIR; this test would otherwise prove nothing"
    );

    // (a) One creation, and it is a bare mkdir.
    let creates = regex::Regex::new(
        r"\b(mkdir|install|touch|cp|mv|ln|tee|place|rsync|dd)\b.*\$\{?POLICY_DIR\b",
    )
    .unwrap();
    let lines: Vec<&str> = postinst.lines().collect();
    let creating: Vec<usize> = lines
        .iter()
        .enumerate()
        .filter(|(_, l)| !l.trim_start().starts_with('#') && creates.is_match(l))
        .map(|(i, _)| i)
        .collect();
    assert_eq!(
        creating.len(),
        1,
        "postinst.sh must create the Policy directory in exactly one line: {creating:?}"
    );
    let at = creating[0];
    assert_eq!(
        lines[at].trim(),
        "mkdir -m 0755 \"$POLICY_DIR\"",
        "the Policy directory is created empty, 0755, with nothing written into it"
    );

    // (b) ... and only when it is absent.
    let guard = lines[..at]
        .iter()
        .rev()
        .map(|l| l.trim())
        .find(|l| !l.is_empty())
        .expect("a line precedes the mkdir");
    assert_eq!(
        guard, "if ! exists \"$POLICY_DIR\"; then",
        "the mkdir must be guarded by the directory not existing"
    );

    // (c) Nothing names a path under the directory: no script, no file list.
    let under = regex::Regex::new(r"policy\.d/|\$POLICY_DIR/|\$\{POLICY_DIR\}/").unwrap();
    let mut checked = 0;
    for (dir, suffix) in [("scripts", ".sh"), ("expected", ".files")] {
        for entry in std::fs::read_dir(packaging.join(dir)).unwrap() {
            let path = entry.unwrap().path();
            if !path.to_string_lossy().ends_with(suffix) {
                continue;
            }
            checked += 1;
            for (n, line) in read(&path).lines().enumerate() {
                assert!(
                    !under.is_match(line),
                    "{}:{} names a path under the Policy directory, which the install must \
                     never write into: {line}",
                    path.display(),
                    n + 1
                );
            }
        }
    }
    assert!(
        checked >= 6,
        "expected the maintainer scripts and file lists, saw {checked}"
    );
}

/// The shipped unit keeps `/etc`, and so the Policy directory in it, read-only
/// (the unit's sandbox claim covers the rest): exactly one `ProtectSystem=strict`, and no directive
/// that re-opens a path in or above `/etc/relay-daemon` for writing.
#[test]
fn unit_keeps_the_policy_directory_read_only() {
    let unit_path =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("packaging/relay-daemon.service");
    let unit = std::fs::read_to_string(&unit_path)
        .unwrap_or_else(|e| panic!("read {}: {e}", unit_path.display()));
    let lines: Vec<&str> = unit
        .lines()
        .map(str::trim)
        .filter(|l| !l.starts_with('#'))
        .collect();

    let strict = lines
        .iter()
        .filter(|l| **l == "ProtectSystem=strict")
        .count();
    assert_eq!(
        strict, 1,
        "the unit must carry exactly one ProtectSystem=strict"
    );

    for line in lines {
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        if !matches!(
            key,
            "ReadWritePaths" | "ReadWriteDirectories" | "BindPaths" | "TemporaryFileSystem"
        ) {
            continue;
        }
        for path in value.split_whitespace() {
            let path = path.trim_start_matches(['-', '+', '!']);
            let path = path.split(':').next().unwrap_or(path);
            assert!(
                path != "/" && path != "/etc" && !path.starts_with("/etc/"),
                "{line:?} re-opens {path} for writing, which puts the Policy directory in reach"
            );
        }
    }
}
