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
//! It also reads the daemon package's maintainer scripts, manifest and baselines, and pins what
//! the install does and never does with the unit, the Policy and the environment file.
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

/// The shipped read catalog is part of the relay-daemon package: one manifest builds the
/// .deb and the .rpm, the catalog is a plain package-owned file (never `config`), and it is
/// the only regular file the package owns under `/etc`, so the live Policy and the environment
/// file stay unowned. The content guard compares these baselines with what `dpkg-deb` and
/// `rpm` read from every release package; `scripts/package-guard-test.sh` and the install
/// matrix are the executable counterparts, which the spec-proof scan does not see.
// Proves DI-29.
#[test]
fn the_daemon_package_carries_the_catalog_as_plain_package_files() {
    let packaging = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("packaging");
    let read = |path: PathBuf| {
        std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
    };
    let names = |dir: &str| -> Vec<String> {
        let mut out: Vec<String> = std::fs::read_dir(packaging.join(dir))
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        out.sort();
        out
    };

    // No separate catalog package: one manifest, and every baseline is the daemon's.
    assert_eq!(names("nfpm"), ["relay-daemon.yaml"]);
    for name in names("expected") {
        assert!(
            name == "README.md" || name.starts_with("relay-daemon."),
            "expected/{name} is a baseline for a package other than relay-daemon"
        );
    }

    let catalog_deb = "-rw-r--r-- root/root ./etc/relay-daemon/templates.d/relay-read/catalog.toml";
    let catalog_rpm =
        "-rw-r--r-- root:root caps=(none) /etc/relay-daemon/templates.d/relay-read/catalog.toml";
    for (file, line, under_etc) in [
        ("expected/relay-daemon.deb.files", catalog_deb, "./etc/"),
        ("expected/relay-daemon.rpm.files", catalog_rpm, "/etc/"),
    ] {
        let listing = read(packaging.join(file));
        assert!(
            listing.lines().any(|l| l == line),
            "{file} must list the catalog as {line:?}"
        );
        let etc_files: Vec<&str> = listing
            .lines()
            .filter(|l| {
                l.starts_with('-')
                    && l.rsplit(' ')
                        .next()
                        .is_some_and(|p| p.starts_with(under_etc))
            })
            .collect();
        assert_eq!(
            etc_files,
            [line],
            "{file}: the catalog must be the only regular file under /etc"
        );
    }

    // The manifest sources the catalog from the repository and declares nothing as configuration.
    let manifest = read(packaging.join("nfpm/relay-daemon.yaml"));
    let lines: Vec<&str> = manifest.lines().map(str::trim).collect();
    let src = lines
        .iter()
        .position(|l| *l == "- src: \"@SRC@/daemon/packaging/templates.d/relay-read/catalog.toml\"")
        .expect("the manifest must source the catalog from the repository");
    assert_eq!(
        lines[src + 1],
        "dst: /etc/relay-daemon/templates.d/relay-read/catalog.toml"
    );
    let config = regex::Regex::new(r#"type:\s*"?config"#).unwrap();
    assert!(
        !lines.iter().any(|l| config.is_match(l)),
        "no manifest entry may be `config` or `config|noreplace`: the Templates are package-owned plain files"
    );
}

/// The daemon package replaces and conflicts with the retired `relay-read` package (rpm:
/// obsoletes and conflicts), so an upgrade from a build that shipped it takes over its one
/// file and removes it, leaving one copy of each Template. The guard holds every release
/// package to these baselines.
#[test]
fn the_daemon_package_replaces_and_conflicts_with_the_retired_catalog_package() {
    let expected = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("packaging/expected");
    let lines_of = |file: &str| -> Vec<String> {
        let path = expected.join(file);
        std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
            .lines()
            .map(str::to_owned)
            .collect()
    };

    let deb = lines_of("relay-daemon.deb.relations");
    for want in ["Replaces: relay-read", "Conflicts: relay-read"] {
        assert!(deb.iter().any(|l| l == want), "deb relations lack {want:?}");
    }
    let rpm = lines_of("relay-daemon.rpm.relations");
    for want in ["obsoletes: relay-read", "conflicts: relay-read"] {
        assert!(rpm.iter().any(|l| l == want), "rpm relations lack {want:?}");
    }
    assert!(
        !rpm.iter().any(|l| l == "provides: relay-read"),
        "the daemon package must not provide the retired name"
    );
}

/// Removing the daemon package takes its payload and keeps configuration and state. The
/// package manager removes what the file lists name (the binary, the unit and the catalog),
/// and the lists name neither the Policy, the Policy directory, the environment file nor
/// anything under `/var`. Purge deletes only what the marker says the package created,
/// through literal paths: every `rm`, `rmdir` and `unlink` in `postrm.sh` is pinned here,
/// each behind its `created` test. `.rpm` removal prints the paths to delete by hand and
/// deletes no state. A structural check, because the executable counterparts are shell
/// tests that the spec-proof scan does not see.
// Proves DI-50.
#[test]
fn removing_the_daemon_package_takes_its_payload_and_keeps_configuration_and_state() {
    let packaging = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("packaging");
    let read = |rel: &str| {
        let path = packaging.join(rel);
        std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
    };

    for file in [
        "expected/relay-daemon.deb.files",
        "expected/relay-daemon.rpm.files",
    ] {
        let listing = read(file);
        for owned in [
            "/usr/bin/relay-daemon",
            "/usr/lib/systemd/system/relay-daemon.service",
            "/etc/relay-daemon/templates.d/relay-read/catalog.toml",
        ] {
            assert!(
                listing.lines().any(|l| l.ends_with(owned)),
                "{file} must list {owned}, so removal takes it"
            );
        }
        // The shipped examples under /usr/share are payload; the live files are not.
        for kept in ["policy.toml", "policy.d", "relay-daemon.env", "/var/"] {
            let hits: Vec<&str> = listing
                .lines()
                .filter(|l| {
                    let path = l.rsplit(' ').next().unwrap_or("");
                    path.contains(kept) && !path.contains("/usr/share/")
                })
                .collect();
            assert!(
                hits.is_empty(),
                "{file} lists {hits:?}, which removal would take: configuration and state are kept"
            );
        }
    }

    let postrm = read("scripts/postrm.sh");
    for literal in [
        "ETC=/etc/relay-daemon",
        "STATE=/var/lib/relay-daemon",
        "MARKER_DIR=/var/lib/relay-daemon-package",
    ] {
        assert!(
            postrm.lines().any(|l| l == literal),
            "postrm.sh must assign {literal}: every deletion goes through a literal path"
        );
    }

    let lines: Vec<&str> = postrm
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .collect();
    let deleting = regex::Regex::new(r"\b(rm|rmdir|unlink)\b").unwrap();
    let found: Vec<&str> = lines
        .iter()
        .copied()
        .filter(|l| deleting.is_match(l))
        .collect();
    assert_eq!(
        found,
        [
            "rm -f \"$MARKER\"",
            "rmdir \"$MARKER_DIR\" 2>/dev/null || true",
            "rmdir \"$ETC/policy.d\" 2>/dev/null \\",
            "rm -f \"$ETC/policy.toml\"",
            "if created env; then rm -f \"$ETC/relay-daemon.env\"; fi",
            "rmdir \"$ETC\" 2>/dev/null \\",
            "rm -rf \"$STATE\"",
        ],
        "postrm.sh deletes something this test does not pin"
    );
    // Each of these deletions sits directly behind the marker's say-so.
    for (deletion, guard) in [
        (
            "rmdir \"$ETC/policy.d\" 2>/dev/null \\",
            "if created policy-dir && plain_dir \"$ETC/policy.d\"; then",
        ),
        (
            "rm -f \"$ETC/policy.toml\"",
            "if created policy && ! exists \"$ETC/policy.d\"; then",
        ),
        ("rmdir \"$ETC\" 2>/dev/null \\", "if created etc; then"),
        (
            "rm -rf \"$STATE\"",
            "if created state && plain_dir \"$STATE\"; then",
        ),
    ] {
        let at = lines.iter().position(|l| *l == deletion).unwrap();
        assert_eq!(lines[at - 1], guard, "{deletion} must follow {guard}");
    }

    // The .rpm removal arm prints the leftovers and deletes nothing.
    let arm: Vec<&str> = postrm
        .lines()
        .skip_while(|l| *l != "  0)")
        .take_while(|l| !l.contains(";;"))
        .collect();
    assert!(
        !arm.is_empty(),
        "postrm.sh must keep its `0)` (.rpm removal) arm"
    );
    assert!(
        !arm.iter()
            .any(|l| deleting.is_match(l) || l.contains("purge")),
        "the .rpm removal arm deletes no state and must not purge: {arm:?}"
    );
    assert!(
        arm.iter().any(|l| l.trim() == "leftovers"),
        "the .rpm removal arm must print the paths left to delete by hand"
    );
}

/// Purge keeps the Policy file the package placed while the Policy directory survives, which it
/// does only while it holds an entry. `postrm.sh` tries to remove the directory first, deletes
/// the Policy file only if the directory is gone, and says what it kept. A later install places
/// no default beside an existing Policy directory, so deleting the file would leave the
/// fragments without the shipped denies. The directory is removed only when the package created
/// it, so one the package did not create is never removed and its Policy file is kept. `.rpm`
/// removal deletes no configuration and warns against deleting the file alone. A structural
/// check: it cannot show that the directory is present when the gate runs. The executable
/// counterpart is the install matrix's purge cycle, which the spec-proof scan does not see.
// Proves DI-50.
#[test]
fn purge_keeps_the_policy_file_while_the_policy_directory_holds_a_fragment() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("packaging/scripts/postrm.sh");
    let postrm =
        std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    let lines: Vec<&str> = postrm
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .collect();

    let delete_file = lines
        .iter()
        .position(|l| *l == "rm -f \"$ETC/policy.toml\"")
        .expect("postrm.sh must delete the Policy file somewhere");
    assert_eq!(
        lines
            .iter()
            .filter(|l| **l == "rm -f \"$ETC/policy.toml\"")
            .count(),
        1,
        "the Policy file is deleted in exactly one place"
    );
    assert_eq!(
        lines[delete_file - 1],
        "if created policy && ! exists \"$ETC/policy.d\"; then",
        "the Policy file is deleted only behind the marker and only once the directory is gone"
    );
    assert_eq!(
        lines[delete_file + 1],
        "elif created policy && exists \"$ETC/policy.toml\"; then",
        "a Policy file kept beside a surviving directory must be a distinct branch"
    );
    assert!(
        lines[delete_file + 2].starts_with("echo ")
            && lines[delete_file + 2].contains("$ETC/policy.toml kept"),
        "purge must say it kept the Policy file"
    );

    let try_directory = lines
        .iter()
        .position(|l| *l == "rmdir \"$ETC/policy.d\" 2>/dev/null \\")
        .expect("postrm.sh must try to remove the Policy directory");
    assert!(
        try_directory < delete_file,
        "the directory's emptiness must be decided before the Policy file is touched"
    );

    let arm: Vec<&str> = postrm
        .lines()
        .skip_while(|l| *l != "  0)")
        .take_while(|l| !l.contains(";;"))
        .collect();
    assert!(
        arm.iter()
            .any(|l| l.contains("$ETC/policy.toml") && l.contains("$ETC/policy.d")),
        ".rpm removal must warn to delete the Policy file only together with the Policy directory"
    );
}

/// The shipped unit keeps `/etc`, and so the Policy directory in it, read-only
/// (the unit's sandbox claim covers the rest): exactly one `ProtectSystem=strict`, and no
/// directive that re-opens a path in or above `/etc/relay-daemon` for writing.
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

// ---- structural readers for maintainer scripts, manifests and baselines ----

fn re(pattern: &str) -> regex::Regex {
    regex::Regex::new(pattern).unwrap_or_else(|e| panic!("regex {pattern}: {e}"))
}

fn read_text(path: &Path) -> String {
    std::fs::read_to_string(path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
}

/// The trimmed, non-empty lines that are not full-line comments.
fn commands(text: &str) -> Vec<String> {
    text.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(String::from)
        .collect()
}

/// The command lines of the four maintainer scripts under `dir`, by script name.
fn script_commands(dir: &Path) -> Vec<(&'static str, Vec<String>)> {
    ["preinst", "postinst", "prerm", "postrm"]
        .into_iter()
        .map(|name| (name, commands(&read_text(&dir.join(format!("{name}.sh"))))))
        .collect()
}

/// Whether `line` starts or restarts a unit, by systemctl, `service`, or the Debian helpers.
fn starts_a_unit(line: &str) -> bool {
    re(r"\bsystemctl\b(?:\s+-{1,2}[A-Za-z-]+(?:=\S+)?)*\s+(?:start|restart|try-restart|reload-or-restart|try-reload-or-restart|isolate)\b")
        .is_match(line)
        || (re(r"\bsystemctl\b").is_match(line)
            && re(r"\benable\b").is_match(line)
            && line.contains("--now"))
        || re(r"\bservice\s+\S+\s+(?:start|restart|try-restart|force-reload)\b").is_match(line)
        || re(r"\b(?:invoke-rc\.d|deb-systemd-invoke)\b").is_match(line)
}

/// Whether `line` changes whether a unit is enabled, by any route that reaches the same state.
fn enables_a_unit(line: &str) -> bool {
    re(r"\bsystemctl\b.*\b(?:enable|reenable|preset|preset-all|link|add-wants)\b").is_match(line)
        || re(r"\b(?:deb-systemd-helper|update-rc\.d|chkconfig)\b").is_match(line)
        || re(r"\bln\b[^|;&]*\.wants/").is_match(line)
}

/// Whether `line` writes to a path `target` names: a redirect into it on any line, or one of
/// the writing commands naming it on a line that is not an echo or printf.
fn writes_to(line: &str, target: &regex::Regex) -> bool {
    let t = target.as_str();
    if re(&format!(r#">>?\s*"?[^\s;|&]*?(?:{t})"#)).is_match(line) {
        return true;
    }
    if matches!(line.split_whitespace().next(), Some("echo" | "printf")) {
        return false;
    }
    re(&format!(
        r"(?:\b(?:cp|mv|install|tee|ln|place|touch|dd|rsync|truncate)\b|\bsed\s+-i\b)[^|;&]*(?:{t})"
    ))
    .is_match(line)
}

/// The index of the one line equal to `exact`.
fn at(lines: &[String], exact: &str) -> usize {
    let hits: Vec<usize> = lines
        .iter()
        .enumerate()
        .filter(|(_, l)| l.as_str() == exact)
        .map(|(i, _)| i)
        .collect();
    assert_eq!(
        hits.len(),
        1,
        "expected exactly one line `{exact}`: {lines:#?}"
    );
    hits[0]
}

/// The command lines of the shell function whose header line is `header`, up to its closing
/// brace, a line that is exactly `}`.
fn body(text: &str, header: &str) -> Vec<String> {
    let lines = commands(text);
    let start = at(&lines, header);
    let mut out = Vec::new();
    for line in &lines[start + 1..] {
        if line == "}" {
            return out;
        }
        out.push(line.clone());
    }
    panic!("`{header}` has no closing brace");
}

const FIRST_INSTALL_GATE: [&str; 6] = [
    "if [ \"$first_install\" != yes ]; then",
    "if systemd_running; then",
    "systemctl daemon-reload || true",
    "fi",
    "exit 0",
    "fi",
];

/// The index of the gate's closing `fi`: past it, a postinst runs on a first install only.
fn first_install_gate_end(lines: &[String]) -> usize {
    let start = at(lines, FIRST_INSTALL_GATE[0]);
    let block: Vec<&str> = lines[start..start + FIRST_INSTALL_GATE.len()]
        .iter()
        .map(String::as_str)
        .collect();
    assert_eq!(
        block, FIRST_INSTALL_GATE,
        "an upgrade or reinstall runs daemon-reload and nothing else"
    );
    start + FIRST_INSTALL_GATE.len() - 1
}

/// The `case "${1:-}" in` arms that follow it, up to `esac`.
fn case_arms(lines: &[String]) -> Vec<String> {
    let start = at(lines, "case \"${1:-}\" in");
    let end = lines[start..]
        .iter()
        .position(|l| l == "esac")
        .expect("the case statement ends");
    lines[start + 1..start + end].to_vec()
}

/// The paths of a baseline's regular files, for the `dpkg-deb` and `rpm` listing formats.
fn regular_entries(baseline: &str) -> Vec<String> {
    baseline
        .lines()
        .filter(|l| l.starts_with('-'))
        .filter_map(|l| l.split_whitespace().last())
        .map(|p| p.trim_start_matches('.').to_string())
        .collect()
}

fn files_under(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(dir)
        .unwrap_or_else(|e| panic!("read {}: {e}", dir.display()))
        .flatten()
    {
        let path = entry.path();
        if path.is_dir() {
            files_under(&path, out);
        } else {
            out.push(path);
        }
    }
}

/// A prerm that stops and disables the unit on removal and does nothing on any other call.
fn assert_prerm_stops_and_disables_on_removal_only(prerm: &[String]) {
    let systemctl: Vec<&str> = prerm
        .iter()
        .filter(|l| l.starts_with("systemctl"))
        .map(String::as_str)
        .collect();
    assert_eq!(
        systemctl,
        [
            "systemctl stop \"$UNIT\" || true",
            "systemctl --no-reload disable \"$UNIT\" || true"
        ],
        "prerm stops and disables the unit and does nothing else with it"
    );
    assert_eq!(
        case_arms(prerm),
        ["remove | 0) ;;", "*) exit 0 ;;"],
        "prerm acts on removal only; an upgrade changes nothing"
    );
}

/// Lookalike lines the two unit matchers must tell apart.
fn assert_unit_matchers_tell_the_verbs_apart() {
    for line in [
        "systemctl start \"$UNIT\"",
        "systemctl --no-block restart relay-daemon.service",
        "systemctl try-reload-or-restart relay.service",
        "systemctl enable --now \"$UNIT\"",
        "service relay-daemon start",
        "service relay restart || true",
        "invoke-rc.d relay-daemon start",
        "deb-systemd-invoke start relay.service",
    ] {
        assert!(starts_a_unit(line), "starts_a_unit must match: {line}");
    }
    for line in [
        "systemctl daemon-reload || true",
        "systemctl preset \"$UNIT\" || true",
        "systemctl stop \"$UNIT\" || true",
        "systemctl --no-reload disable \"$UNIT\" || true",
        "systemctl enable \"$UNIT\"",
        "systemd_running() { [ -d /run/systemd/system ]; }",
    ] {
        assert!(!starts_a_unit(line), "starts_a_unit must not match: {line}");
    }
    for line in [
        "systemctl enable \"$UNIT\"",
        "systemctl reenable relay.service",
        "systemctl preset-all",
        "systemctl link /opt/relay.service",
        "systemctl --now enable relay.service",
        "deb-systemd-helper enable relay.service",
        "chkconfig relay on",
        "update-rc.d relay defaults",
        "ln -s /usr/lib/systemd/system/relay.service /etc/systemd/system/multi-user.target.wants/relay.service",
    ] {
        assert!(enables_a_unit(line), "enables_a_unit must match: {line}");
    }
    for line in [
        "systemctl --no-reload disable \"$UNIT\" || true",
        "systemctl daemon-reload || true",
        "systemctl stop \"$UNIT\" || true",
        "if ln \"$tmp\" \"$dst\" 2>/dev/null; then",
        "echo \"enable the unit by hand\" >&2",
    ] {
        assert!(
            !enables_a_unit(line),
            "enables_a_unit must not match: {line}"
        );
    }
}

// ---- the daemon package's install behaviour: unit, Policy, environment file ----

/// The daemon package installs the binary and the hardened unit, and no maintainer script
/// starts the unit. The one enabling act is `systemctl preset`, run by `postinst` on a first
/// install only, behind the systemd-running and root-only-directory checks; an upgrade runs
/// `daemon-reload` and nothing else, and `prerm` acts on removal only. The unit restarts only
/// on failure and no `.path` or `.timer` unit watches for an identity, so an enabled unit with
/// no identity is the daemon's clean exit, which `exit_rule.rs` proves. A structural check:
/// the executable counterparts are the install matrix and the shell package tests, which the
/// spec-proof scan does not see.
// Proves DI-25.
#[test]
fn the_daemon_package_installs_its_unit_never_starts_it_and_enables_it_only_on_a_first_install() {
    let packaging = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("packaging");

    // (a) The binary and the unit are regular files of both packages; nothing watches.
    for baseline in ["relay-daemon.deb.files", "relay-daemon.rpm.files"] {
        let entries = regular_entries(&read_text(&packaging.join("expected").join(baseline)));
        for want in [
            "/usr/bin/relay-daemon",
            "/usr/lib/systemd/system/relay-daemon.service",
        ] {
            assert!(
                entries.iter().any(|e| e == want),
                "{baseline} lists {want} as a regular file: {entries:?}"
            );
        }
        assert!(
            entries
                .iter()
                .all(|e| !e.ends_with(".path") && !e.ends_with(".timer")),
            "{baseline} lists a .path or .timer unit, which would start the daemon: {entries:?}"
        );
    }
    assert_eq!(
        regular_entries(
            "-rwxr-xr-x root/root ./usr/bin/x\ndrwxr-xr-x root/root ./usr/\n\
             -rw-r--r-- root:root caps=(none) /etc/y\ndrwxr-xr-x root:root caps=(none) /etc/z"
        ),
        ["/usr/bin/x", "/etc/y"],
        "the baseline reader keeps regular files of both listing formats and nothing else"
    );
    let mut shipped = Vec::new();
    files_under(&packaging, &mut shipped);
    assert!(shipped.len() > 10, "the packaging tree was not read");
    assert!(
        shipped
            .iter()
            .all(|p| { !p.extension().is_some_and(|e| e == "path" || e == "timer") }),
        "packaging ships a .path or .timer unit"
    );
    let manifest: Vec<String> = commands(&read_text(&packaging.join("nfpm/relay-daemon.yaml")))
        .iter()
        .map(|l| l.trim_start_matches("- ").to_string())
        .collect();
    for (src, dst) in [
        ("src: \"@DAEMON_BIN@\"", "dst: /usr/bin/relay-daemon"),
        (
            "src: \"@SRC@/daemon/packaging/relay-daemon.service\"",
            "dst: /usr/lib/systemd/system/relay-daemon.service",
        ),
    ] {
        assert_eq!(
            manifest[at(&manifest, src) + 1],
            dst,
            "the manifest installs {src} at {dst}"
        );
    }

    // (b) No script starts a unit, and the one enabling line is postinst's preset.
    let scripts = script_commands(&packaging.join("scripts"));
    let mut enabling = Vec::new();
    for (name, lines) in &scripts {
        for line in lines {
            assert!(
                !starts_a_unit(line),
                "{name}.sh starts the daemon, which the package never does: {line}"
            );
            if enables_a_unit(line) {
                enabling.push((*name, line.as_str()));
            }
        }
    }
    assert_eq!(
        enabling,
        [("postinst", "systemctl preset \"$UNIT\" || true")],
        "the distribution's presets are the only thing that enables the unit"
    );

    // (c) postinst: the preset is past the first-install gate, inside both checks.
    let postinst = &scripts.iter().find(|(n, _)| *n == "postinst").unwrap().1;
    for pinned in [
        "UNIT=relay-daemon.service",
        "systemd_running() { [ -d /run/systemd/system ]; }",
    ] {
        at(postinst, pinned);
    }
    assert_eq!(
        case_arms(postinst),
        [
            "configure) [ -z \"${2:-}\" ] && first_install=yes ;;",
            "1) first_install=yes ;;",
            "[0-9]*) ;;",
            "*) exit 0 ;;"
        ],
        "only a .deb configure with no old version and an .rpm $1 of 1 is a first install"
    );
    let case_at = at(postinst, "case \"${1:-}\" in");
    assert!(
        case_at > 0 && postinst[case_at - 1] == "first_install=no",
        "first_install starts as no, on the line before the case"
    );
    assert_eq!(
        postinst
            .iter()
            .filter(|l| l.contains("first_install=yes"))
            .count(),
        2,
        "first_install=yes is set in the two pinned arms and nowhere else"
    );
    let gate_end = first_install_gate_end(postinst);
    let preset = at(postinst, "systemctl preset \"$UNIT\" || true");
    assert!(
        preset > gate_end,
        "the preset runs past the first-install gate"
    );
    assert_eq!(
        postinst[preset - 3..preset],
        [
            "if systemd_running; then",
            "systemctl daemon-reload || true",
            "if [ \"$etc_ok\" = yes ]; then"
        ],
        "the preset runs only where systemd runs and /etc/relay-daemon is root-only"
    );

    // (d) prerm acts on removal only.
    assert_prerm_stops_and_disables_on_removal_only(
        &scripts.iter().find(|(n, _)| *n == "prerm").unwrap().1,
    );

    // (e) The unit restarts only on failure and installs into multi-user.target.
    let unit = read_text(&packaging.join("relay-daemon.service"));
    let unit_lines = commands(&unit);
    let restarts: Vec<&str> = unit_lines
        .iter()
        .filter(|l| l.starts_with("Restart="))
        .map(String::as_str)
        .collect();
    assert_eq!(
        restarts,
        ["Restart=on-failure"],
        "the unit restarts on failure only"
    );
    assert!(
        !unit_lines
            .iter()
            .any(|l| l.starts_with("RestartForceExitStatus=")),
        "no RestartForceExitStatus revives a clean exit"
    );
    let install = unit_lines
        .iter()
        .skip_while(|l| *l != "[Install]")
        .skip(1)
        .map(String::as_str)
        .collect::<Vec<_>>();
    assert_eq!(install, ["WantedBy=multi-user.target"]);

    // (f) The matchers tell the verbs apart.
    assert_unit_matchers_tell_the_verbs_apart();
}

const POLICY_TARGET: &str = r"\$\{?POLICY\b\}?|policy\.toml\b";
const ENV_TARGET: &str = r#"\$\{?ENV_FILE\b\}?|relay-daemon\.env(?:["'\s;)]|$)"#;
const DST_TARGET: &str = r"\$\{?dst\b\}?";

/// The lines of `scripts` that write to `target`, as `(script, line)`.
fn writers<'a>(
    scripts: &'a [(&'static str, Vec<String>)],
    target: &str,
) -> Vec<(&'static str, &'a str)> {
    let target = re(target);
    scripts
        .iter()
        .flat_map(|(name, lines)| {
            lines
                .iter()
                .filter(|l| writes_to(l, &target))
                .map(|l| (*name, l.as_str()))
                .collect::<Vec<_>>()
        })
        .collect()
}

/// `place` links a fully written temporary file into place with a plain `ln`, which fails where
/// the destination exists, so no placement rewrites a file; and the file is owned by root and
/// given its mode before it is linked.
fn assert_place_never_overwrites_and_owns_before_linking(place: &[String]) {
    let ln = at(place, "if ln \"$tmp\" \"$dst\" 2>/dev/null; then");
    let own = at(
        place,
        "if ! { chown -h root:root \"$tmp\" && chmod \"$mode\" \"$tmp\"; }; then",
    );
    assert!(
        own < ln,
        "the file is chowned and chmodded before it is linked"
    );
    let links: Vec<&String> = place.iter().filter(|l| re(r"\bln\b").is_match(l)).collect();
    assert_eq!(links.len(), 1, "place links exactly once: {place:?}");
    assert!(
        !re(r"\bln\s+(?:-\S*f|--force)").is_match(&place[ln]),
        "a forced link would replace an existing file"
    );
    let dst = re(DST_TARGET);
    let to_dst: Vec<&String> = place.iter().filter(|l| writes_to(l, &dst)).collect();
    assert_eq!(
        to_dst,
        [&place[ln]],
        "nothing but the link writes the destination: no mv, cp or redirect"
    );
}

/// The default Policy is placed once, by the one `place` line in `postinst`, only when preinst
/// saw neither a Policy directory nor a Policy file, and `place` never replaces a file. No
/// script writes the Policy path anywhere else, and no package file list owns it.
// Proves DI-26.
#[test]
fn the_default_policy_is_placed_only_where_no_policy_file_or_directory_existed() {
    let packaging = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("packaging");
    let scripts = script_commands(&packaging.join("scripts"));
    let lines_of = |name: &str| &scripts.iter().find(|(n, _)| *n == name).unwrap().1;

    // (a) preinst records what existed, on a first install only.
    let preinst = lines_of("preinst");
    assert_eq!(
        case_arms(preinst),
        [
            "install) [ -z \"${2:-}\" ] && first_install=yes ;;",
            "1) first_install=yes ;;"
        ]
    );
    let gate = at(preinst, "[ \"$first_install\" = yes ] || exit 0");
    for marker in [
        "exists /etc/relay-daemon/policy.d && echo \"existed policy-dir\"",
        "exists /etc/relay-daemon/policy.toml && echo \"existed policy\"",
    ] {
        assert!(
            at(preinst, marker) > gate,
            "preinst records `{marker}` only after the first-install gate"
        );
    }

    // (b) postinst places it in one line, after the gate, behind both absence checks.
    let postinst = lines_of("postinst");
    let places: Vec<usize> = postinst
        .iter()
        .enumerate()
        .filter(|(_, l)| l.contains("place \"$POLICY\""))
        .map(|(i, _)| i)
        .collect();
    assert_eq!(places.len(), 1, "the Policy is placed in exactly one line");
    let place_at = places[0];
    assert_eq!(
        postinst[place_at],
        "if place \"$POLICY\" 0644 \"$SHARE/policy.default.toml\"; then"
    );
    assert_eq!(
        postinst[place_at - 1],
        "if [ \"$have_marker\" = yes ] && ! marked \"existed policy-dir\" && ! exists \"$POLICY\"; then",
        "placed only if no Policy directory existed before the install and no Policy file exists"
    );
    assert!(place_at > first_install_gate_end(postinst));

    // (c) place links and never replaces.
    let place_fn = body(
        &read_text(&packaging.join("scripts/postinst.sh")),
        "place() {",
    );
    assert_place_never_overwrites_and_owns_before_linking(&place_fn);

    // (d) Across every script, only that line writes the Policy path.
    assert_eq!(
        writers(&scripts, POLICY_TARGET),
        [("postinst", postinst[place_at].as_str())],
        "nothing else installs, upgrades or removes by writing the live Policy"
    );

    // (e) The package owns no live Policy.
    for baseline in ["relay-daemon.deb.files", "relay-daemon.rpm.files"] {
        let text = read_text(&packaging.join("expected").join(baseline));
        assert!(
            !text.contains("/etc/relay-daemon/policy.toml"),
            "{baseline} lists the live Policy"
        );
    }
    assert!(
        !read_text(&packaging.join("nfpm/relay-daemon.yaml"))
            .contains("dst: /etc/relay-daemon/policy.toml"),
        "the manifest installs the live Policy"
    );

    // (f) The matcher tells a write from a mention.
    let policy = re(POLICY_TARGET);
    for line in [
        "cp \"$SHARE/policy.default.toml\" \"$POLICY\"",
        "cat x > \"$ETC/policy.toml\"",
        "echo y >> \"${POLICY}\"",
        "install -m 0644 a /etc/relay-daemon/policy.toml",
        "if place \"$POLICY\" 0644 \"$SHARE/policy.default.toml\"; then",
    ] {
        assert!(writes_to(line, &policy), "must match: {line}");
    }
    for line in [
        "mkdir -m 0755 \"$POLICY_DIR\"",
        "rm -f \"$ETC/policy.toml\"",
        "echo \"relay-daemon: $ETC/policy.toml kept: a later install places no default Policy\"",
        "POLICY=\"$ETC/policy.toml\"",
        "exists /etc/relay-daemon/policy.toml && echo \"existed policy\"",
    ] {
        assert!(!writes_to(line, &policy), "must not match: {line}");
    }
}

/// The environment file is placed once, in one `place` line after the first-install gate and
/// only if none exists, as a root-owned 0600 copy of the shipped example, and no script and no
/// package file list writes it again.
// Proves DI-27.
#[test]
fn the_environment_file_is_placed_once_root_0600_and_never_rewritten() {
    let packaging = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("packaging");
    let scripts = script_commands(&packaging.join("scripts"));
    let postinst = &scripts.iter().find(|(n, _)| *n == "postinst").unwrap().1;

    // (a) One placement, guarded by absence, after the gate, with the mode and umask set.
    let places: Vec<usize> = postinst
        .iter()
        .enumerate()
        .filter(|(_, l)| l.contains("place \"$ENV_FILE\""))
        .map(|(i, _)| i)
        .collect();
    assert_eq!(
        places.len(),
        1,
        "the environment file is placed in one line"
    );
    let place_at = places[0];
    assert_eq!(
        postinst[place_at],
        "if place \"$ENV_FILE\" 0600 \"$SHARE/relay-daemon.env.example\"; then"
    );
    assert_eq!(
        postinst[place_at - 1],
        "if ! exists \"$ENV_FILE\"; then",
        "placed only if none exists"
    );
    assert!(place_at > first_install_gate_end(postinst));
    at(postinst, "ENV_FILE=\"$ETC/relay-daemon.env\"");
    at(postinst, "umask 077");

    // (b) place owns the file as root with its mode before it links, and never replaces.
    let place_fn = body(
        &read_text(&packaging.join("scripts/postinst.sh")),
        "place() {",
    );
    assert_place_never_overwrites_and_owns_before_linking(&place_fn);

    // (c) Across every script, only that line writes the file.
    assert_eq!(
        writers(&scripts, ENV_TARGET),
        [("postinst", postinst[place_at].as_str())],
        "nothing else writes the environment file"
    );

    // (d) The package owns no environment file.
    for baseline in ["relay-daemon.deb.files", "relay-daemon.rpm.files"] {
        let entries = regular_entries(&read_text(&packaging.join("expected").join(baseline)));
        assert!(
            !entries
                .iter()
                .any(|e| e == "/etc/relay-daemon/relay-daemon.env"),
            "{baseline} lists the live environment file"
        );
    }

    // (e) The matcher tells a write from the shipped example's name.
    let env = re(ENV_TARGET);
    for line in [
        "cp a \"$ETC/relay-daemon.env\"",
        "echo X=1 >> \"$ENV_FILE\"",
        "cat x > /etc/relay-daemon/relay-daemon.env",
        "if place \"$ENV_FILE\" 0600 \"$SHARE/relay-daemon.env.example\"; then",
    ] {
        assert!(writes_to(line, &env), "must match: {line}");
    }
    for line in [
        "echo x > \"$ETC/relay-daemon.env.example\"",
        "cp a \"$SHARE/relay-daemon.env.example\" /tmp/x",
        "if created env; then rm -f \"$ETC/relay-daemon.env\"; fi",
        "ENV_FILE=\"$ETC/relay-daemon.env\"",
        "exists /etc/relay-daemon/relay-daemon.env && echo \"existed env\"",
    ] {
        assert!(!writes_to(line, &env), "must not match: {line}");
    }
}
