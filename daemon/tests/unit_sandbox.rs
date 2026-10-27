//! Offline proof of the shipped systemd unit's sandbox (DI-3) and that no package payload or
//! release attachment relaxes it (DI-5).
//!
//! The unit and the package lists are read as text: a unit cannot be started in a test. The
//! unit's syscall filter is deliberately not asserted here; it is checked by hand on a real
//! systemd host. DI-5's "never shipped" half is what is proven; that the relaxing drop-in is
//! documented is not asserted by a test.

use regex::Regex;
use std::path::{Path, PathBuf};

fn repo() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("daemon/ has a parent")
        .to_path_buf()
}

fn read(path: &Path) -> String {
    std::fs::read_to_string(path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
}

/// The non-comment lines of the unit as (section, key, value).
fn unit_directives() -> Vec<(String, String, String)> {
    let mut section = String::new();
    let mut out = Vec::new();
    for line in read(&repo().join("daemon/packaging/relay-daemon.service")).lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        if let Some(name) = line.strip_prefix('[').and_then(|l| l.strip_suffix(']')) {
            section = name.to_string();
            continue;
        }
        let (key, value) = line
            .split_once('=')
            .unwrap_or_else(|| panic!("unit line is not Key=Value: {line}"));
        out.push((
            section.clone(),
            key.trim().to_string(),
            value.trim().to_string(),
        ));
    }
    out
}

/// The `[Service]` values of `key`, in file order.
fn service_values(directives: &[(String, String, String)], key: &str) -> Vec<String> {
    directives
        .iter()
        .filter(|(s, k, _)| s == "Service" && k == key)
        .map(|(_, _, v)| v.clone())
        .collect()
}

// Proves DI-3.
#[test]
fn unit_is_root_with_dac_read_search_only_and_ro_system_dirs() {
    let directives = unit_directives();
    let service = directives.iter().filter(|(s, _, _)| s == "Service").count();
    assert!(service >= 10, "parsed only {service} [Service] directives");

    assert_eq!(
        service_values(&directives, "User"),
        ["root"],
        "runs as root"
    );
    assert!(
        !service_values(&directives, "DynamicUser")
            .iter()
            .any(|v| matches!(v.as_str(), "yes" | "true" | "1" | "on")),
        "a dynamic user is not root"
    );

    let caps = service_values(&directives, "CapabilityBoundingSet");
    assert_eq!(caps.len(), 1, "one bounding set: {caps:?}");
    assert_eq!(
        caps[0].split_whitespace().collect::<Vec<_>>(),
        ["CAP_DAC_READ_SEARCH"],
        "the bounding set is CAP_DAC_READ_SEARCH and nothing else, not inverted"
    );

    assert_eq!(
        service_values(&directives, "ProtectSystem"),
        ["strict"],
        "/usr, /etc, /boot and the rest of the file system tree are read-only"
    );

    // StateDirectory= is the only writable path. A path the unit makes writable again must
    // not be the root or anything under the system directories. A bind mount is writable at
    // its destination, so both sides of `source[:destination[:options]]` are checked.
    for key in [
        "ReadWritePaths",
        "ReadWriteDirectories",
        "BindPaths",
        "TemporaryFileSystem",
    ] {
        for value in service_values(&directives, key) {
            for entry in value.split_whitespace() {
                let paths = entry
                    .trim_start_matches(['-', '+', '!'])
                    .split(':')
                    .filter(|field| field.starts_with('/'));
                for path in paths {
                    let path = path.trim_end_matches('/');
                    let under = |dir: &str| path == dir || path.starts_with(&format!("{dir}/"));
                    assert!(
                        !path.is_empty()
                            && !path.split('/').any(|c| c == "..")
                            && !["/usr", "/etc", "/boot"].iter().any(|d| under(d)),
                        "{key}={value} re-opens a system directory for writing"
                    );
                }
            }
        }
    }

    // Exec prefixes combine (`-+`, `@+`, `:!`); `+` and `!` among them leave the sandbox.
    for (section, key, value) in &directives {
        if section == "Service" && key.starts_with("Exec") {
            let prefix: String = value
                .chars()
                .take_while(|c| matches!(c, '-' | '@' | ':' | '+' | '!'))
                .collect();
            assert!(
                !prefix.contains(['+', '!']),
                "{key}={value} runs outside the sandbox and the bounding set"
            );
        }
    }
    assert!(
        service_values(&directives, "PermissionsStartOnly").is_empty(),
        "no part of the start escapes the sandbox"
    );
}

/// A package payload path, normalised from a `.files` line: the last field, without the
/// deb listing's leading `.` or a trailing `/`.
fn payload_path(line: &str) -> Option<String> {
    let field = line.split_whitespace().last()?;
    let path = field.strip_prefix('.').unwrap_or(field);
    Some(path.trim_end_matches('/').to_string())
}

/// Only the unit itself, under the system unit directory, may sit in a `systemd` directory
/// of a package: no drop-in (`*.service.d`), no `/etc` or `/run` override, no preset.
fn assert_no_relaxing_path(path: &str, origin: &str) {
    assert!(
        !path.contains(".service.d"),
        "{origin}: {path} is a drop-in for a unit (DI-5)"
    );
    if !path.split('/').any(|c| c == "systemd") {
        return;
    }
    let allowed = path == "/usr/lib/systemd"
        || path == "/usr/lib/systemd/system"
        || path
            .strip_prefix("/usr/lib/systemd/system/")
            .is_some_and(|name| name.ends_with(".service") && !name.contains('/'));
    assert!(
        allowed,
        "{origin}: {path} puts something other than a unit file in a systemd directory (DI-5)"
    );
}

fn files_in(dir: &Path, suffix: &str) -> Vec<PathBuf> {
    let mut out: Vec<PathBuf> = std::fs::read_dir(dir)
        .unwrap_or_else(|e| panic!("read {}: {e}", dir.display()))
        .map(|e| e.expect("dir entry").path())
        .filter(|p| p.is_file() && p.to_string_lossy().ends_with(suffix))
        .collect();
    out.sort();
    out
}

fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(dir).unwrap_or_else(|e| panic!("read {}: {e}", dir.display())) {
        let path = entry.expect("dir entry").path();
        if path.is_dir() {
            out.push(path.clone());
            walk(&path, out);
        } else {
            out.push(path);
        }
    }
}

/// Non-comment lines of a maintainer script.
fn script_code(path: &Path) -> Vec<String> {
    read(path)
        .lines()
        .filter(|l| !l.trim_start().starts_with('#'))
        .map(str::to_string)
        .collect()
}

// Proves DI-5.
#[test]
fn no_relaxing_drop_in_is_shipped() {
    let root = repo();
    let unit = "/usr/lib/systemd/system/relay-daemon.service";

    // Package payloads, as the guard's committed listings record them.
    let mut lists = Vec::new();
    for dir in ["daemon/packaging/expected", "relay/packaging/expected"] {
        lists.extend(files_in(&root.join(dir), ".files"));
    }
    assert!(
        lists.len() >= 3,
        "only {} payload lists: {lists:?}",
        lists.len()
    );
    let mut daemon_lists = 0;
    for list in &lists {
        let text = read(list);
        let origin = list.display().to_string();
        let paths: Vec<String> = text.lines().filter_map(payload_path).collect();
        assert!(!paths.is_empty(), "{origin} lists nothing");
        for path in &paths {
            assert_no_relaxing_path(path, &origin);
        }
        let is_daemon_list = list
            .file_name()
            .is_some_and(|n| n.to_string_lossy().starts_with("relay-daemon."));
        if is_daemon_list {
            daemon_lists += 1;
            assert!(
                paths.iter().any(|p| p == unit),
                "{origin} does not carry the unit, so the scan saw the wrong list"
            );
        }
    }
    assert!(
        daemon_lists >= 2,
        "a deb and an rpm relay-daemon list are expected"
    );

    // Package manifests.
    let dst = Regex::new(r"^\s*-?\s*dst:\s*(\S+)").expect("regex");
    let mut dsts = Vec::new();
    for dir in ["daemon/packaging/nfpm", "relay/packaging/nfpm"] {
        for manifest in files_in(&root.join(dir), ".yaml") {
            for line in read(&manifest).lines() {
                if let Some(c) = dst.captures(line) {
                    let path = c[1].trim_matches(['"', '\'']).to_string();
                    assert_no_relaxing_path(&path, &manifest.display().to_string());
                    dsts.push(path);
                }
            }
        }
    }
    assert!(
        dsts.iter().any(|p| p == unit),
        "the relay-daemon manifest installs the unit: {dsts:?}"
    );

    // Maintainer scripts neither place nor edit a drop-in.
    let mut scripts = 0;
    for dir in ["daemon/packaging/scripts", "relay/packaging/scripts"] {
        for script in files_in(&root.join(dir), ".sh") {
            scripts += 1;
            for line in script_code(&script) {
                for banned in [".service.d", "systemctl edit", "systemctl set-property"] {
                    assert!(
                        !line.contains(banned),
                        "{} relaxes the unit ({banned}): {line}",
                        script.display()
                    );
                }
            }
        }
    }
    assert!(scripts >= 4, "only {scripts} maintainer scripts were read");

    // The repository's packaging tree carries no drop-in either.
    let mut tree = Vec::new();
    walk(&root.join("daemon/packaging"), &mut tree);
    assert!(tree.len() >= 10, "walked only {tree:?}");
    for path in &tree {
        let name = path.file_name().map(|n| n.to_string_lossy().into_owned());
        let name = name.unwrap_or_default();
        assert!(
            !name.ends_with(".service.d"),
            "{} is a drop-in directory",
            path.display()
        );
        assert!(
            path.is_dir() || !name.ends_with(".conf"),
            "{} is a drop-in file",
            path.display()
        );
    }

    // Release attachments: the workflow stages standalone files into dist/.
    let workflow: String = read(&root.join(".github/workflows/release.yml"))
        .lines()
        .filter(|l| !l.trim_start().starts_with('#'))
        .map(|l| format!("{l}\n"))
        .collect();
    assert!(
        !workflow.contains(".service.d"),
        "the release stages a drop-in"
    );
    let cp = Regex::new(r#"\bcp\s+\S+\s+"?dist/([^"\s]*)"?(\s|$)"#).expect("regex");
    let staged: Vec<String> = workflow
        .lines()
        .filter_map(|l| cp.captures(l).map(|c| c[1].to_string()))
        .collect();
    assert!(staged.len() >= 5, "only {staged:?} staged into dist/");
    assert!(
        staged.iter().any(|n| n == "relay-daemon.service"),
        "the unit is attached: {staged:?}"
    );
    for name in &staged {
        assert!(
            !(name.ends_with(".conf") || name.ends_with(".d") || name.ends_with(".d/")),
            "the release attaches a drop-in: dist/{name}"
        );
    }
}
