//! Structural guards for two absences the Node connection promises: the
//! daemon never listens, and it trusts only the CA it pinned. Neither can be
//! shown by driving a connection, so each scans the daemon's non-test source,
//! and each is armed by a fixture that must produce a hit.
//!
//! # It proves
//!
//! * (a) no non-test source under `src/` or `crates/*/src` (the dev-only
//!   `relay-test-support` crate apart) names a listener or a server: a TCP, UDP or
//!   Unix socket listener, a `bind` or `listen` call, or tonic's `Server`. The daemon
//!   is a gRPC client and opens its one stream outward.
//! * (b) the daemon trusts only the CA it pinned: `Cargo.lock` holds no crate that
//!   loads the operating system's or a public root store, no manifest enables tonic's
//!   native- or webpki-roots features, and no non-test source asks for either store.
//!
//! # It cannot see
//!
//! The scan is lexical. It strips comments and the contents of string and character
//! literals (plain, raw and byte-raw: `"..."`, `r#"..."#`, `br"..."`), and then drops
//! `#[cfg(test)]` items, files whose leading inner attributes include
//! `#![cfg(test)]`, and files mounted only by a `#[cfg(test)] mod x;`. It does not
//! see a name built by a macro or a path alias that hides a listener's type name, and
//! it treats a `#[cfg(test)]` that does not sit directly on an item (a field, a
//! statement, an argument) as production code. A dependency that listens on the
//! daemon's behalf is out of its reach: tonic's server half is compiled into the
//! daemon, because its `transport` feature carries both halves.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use regex::Regex;
use toml::Value;

#[path = "common/source_walk.rs"]
mod source_walk;

use source_walk::{daemon, production_src_roots, rust_files_in};

/// `src` with comments removed and string and character literal contents
/// emptied, so a name inside a comment or a string is not read as code.
fn code_only(src: &str) -> String {
    let b = src.as_bytes();
    let is_ident = |c: u8| c.is_ascii_alphanumeric() || c == b'_';
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        let c = b[i];
        let next = b.get(i + 1).copied();
        if c == b'/' && next == Some(b'/') {
            while i < b.len() && b[i] != b'\n' {
                i += 1;
            }
        } else if c == b'/' && next == Some(b'*') {
            let mut depth = 0;
            while i < b.len() {
                if b[i] == b'/' && b.get(i + 1) == Some(&b'*') {
                    depth += 1;
                    i += 2;
                } else if b[i] == b'*' && b.get(i + 1) == Some(&b'/') {
                    depth -= 1;
                    i += 2;
                    if depth == 0 {
                        break;
                    }
                } else {
                    i += 1;
                }
            }
        } else if c == b'r'
            && (i == 0
                || !is_ident(b[i - 1])
                || (b[i - 1] == b'b' && (i == 1 || !is_ident(b[i - 2]))))
            && matches!(next, Some(b'#' | b'"'))
        {
            let mut j = i + 1;
            while b.get(j) == Some(&b'#') {
                j += 1;
            }
            if b.get(j) != Some(&b'"') {
                out.push(c);
                i += 1;
                continue;
            }
            let hashes = j - (i + 1);
            let mut k = j + 1;
            while k < b.len()
                && !(b[k] == b'"' && b[k + 1..].iter().take(hashes).all(|h| *h == b'#'))
            {
                k += 1;
            }
            out.extend_from_slice(b"\"\"");
            i = (k + 1 + hashes).min(b.len());
        } else if c == b'"' {
            let mut k = i + 1;
            while k < b.len() && b[k] != b'"' {
                k += if b[k] == b'\\' { 2 } else { 1 };
            }
            out.extend_from_slice(b"\"\"");
            i = (k + 1).min(b.len());
        } else if c == b'\'' {
            // A character literal, or else a lifetime or label.
            let end = if next == Some(b'\\') {
                b[i + 2..]
                    .iter()
                    .skip(1)
                    .position(|x| *x == b'\'')
                    .map(|p| i + 4 + p)
            } else {
                let width = src[i + 1..].chars().next().map_or(0, char::len_utf8);
                (width > 0 && b.get(i + 1 + width) == Some(&b'\'')).then_some(i + 1 + width + 1)
            };
            match end {
                Some(end) => {
                    out.extend_from_slice(b"''");
                    i = end;
                }
                None => {
                    out.push(c);
                    i += 1;
                }
            }
        } else {
            out.push(c);
            i += 1;
        }
    }
    String::from_utf8(out).expect("stripping whole literals keeps the text valid UTF-8")
}

/// The attribute and item keywords that make a `#[cfg(test)]` a gate on an item.
const ITEM: &str = r"(?:pub(?:\([^)]*\))?\s+)?(?:mod|fn|use|impl|struct|enum|const|static|trait|type|async|unsafe|extern)\b";

/// Offset just past the item whose keyword has been consumed: its `;`, or its
/// balanced `{}` block, whichever comes first outside any parentheses or brackets.
fn item_end(s: &str) -> usize {
    let (mut braces, mut nest) = (0usize, 0usize);
    for (i, c) in s.char_indices() {
        match c {
            '(' | '[' => nest += 1,
            ')' | ']' => nest = nest.saturating_sub(1),
            ';' if braces == 0 && nest == 0 => return i + 1,
            '{' => braces += 1,
            '}' => {
                braces = braces.saturating_sub(1);
                if braces == 0 {
                    return i + 1;
                }
            }
            _ => {}
        }
    }
    s.len()
}

/// `code` without its `#[cfg(test)]` items.
fn without_test_items(code: &str) -> String {
    let gate = Regex::new(&format!(
        r"(?m)^[ \t]*#\[cfg\(test\)\]\s*(?:#\[[^\]]*\]\s*)*{ITEM}"
    ))
    .unwrap();
    let mut out = String::new();
    let mut rest = code;
    while let Some(m) = gate.find(rest) {
        out.push_str(&rest[..m.start()]);
        let after = &rest[m.end()..];
        rest = &after[item_end(after)..];
    }
    out.push_str(rest);
    out
}

/// Whether `code` opens with `#![cfg(test)]` among its leading inner attributes.
/// One further down, in an inline module, gates only that module.
fn is_test_file(code: &str) -> bool {
    for line in code.lines().map(str::trim).filter(|l| !l.is_empty()) {
        if line == "#![cfg(test)]" {
            return true;
        }
        if !line.starts_with("#![") {
            return false;
        }
    }
    false
}

/// The production code of one file: nothing when the whole file is test code.
fn production_code(src: &str) -> String {
    let code = code_only(src);
    if is_test_file(&code) {
        return String::new();
    }
    without_test_items(&code)
}

/// The files `parent` mounts with `mod name;`, only the `#[cfg(test)]` ones when
/// `test_only` is set.
fn mounted(parent: &Path, code: &str, test_only: bool) -> Vec<PathBuf> {
    let re = if test_only {
        Regex::new(r"(?m)^[ \t]*#\[cfg\(test\)\]\s*(?:#\[[^\]]*\]\s*)*(?:pub(?:\([^)]*\))?\s+)?mod\s+(\w+)\s*;").unwrap()
    } else {
        Regex::new(r"\bmod\s+(\w+)\s*;").unwrap()
    };
    let dir = parent.parent().expect("a file has a parent");
    let stem = parent
        .file_stem()
        .and_then(|s| s.to_str())
        .expect("utf-8 file name");
    let base = if matches!(stem, "lib" | "main" | "mod") {
        dir.to_path_buf()
    } else {
        dir.join(stem)
    };
    re.captures_iter(code)
        .flat_map(|c| {
            let name = c[1].to_string();
            [
                base.join(format!("{name}.rs")),
                base.join(&name).join("mod.rs"),
            ]
        })
        .filter(|p| p.is_file())
        .collect()
}

/// Every file of the scanned trees that is test code as a whole, with the files
/// only such a file mounts.
fn test_only_files(files: &[(PathBuf, String)]) -> BTreeSet<PathBuf> {
    let mut excluded = BTreeSet::new();
    let mut work: Vec<PathBuf> = Vec::new();
    for (path, src) in files {
        let code = code_only(src);
        if is_test_file(&code) {
            work.push(path.clone());
        }
        work.extend(mounted(path, &code, true));
    }
    while let Some(path) = work.pop() {
        if !excluded.insert(path.clone()) {
            continue;
        }
        if let Ok(src) = fs::read_to_string(&path) {
            work.extend(mounted(&path, &code_only(&src), false));
        }
    }
    excluded
}

/// The production code of every scanned file, keyed by path.
fn scanned() -> (Vec<(PathBuf, String)>, BTreeSet<PathBuf>) {
    let paths = rust_files_in(&production_src_roots());
    let files: Vec<(PathBuf, String)> = paths
        .into_iter()
        .map(|p| {
            let src =
                fs::read_to_string(&p).unwrap_or_else(|e| panic!("read {}: {e}", p.display()));
            (p, src)
        })
        .collect();
    let excluded = test_only_files(&files);
    let production = files
        .iter()
        .filter(|(p, _)| !excluded.contains(p))
        .map(|(p, src)| (p.clone(), production_code(src)))
        .collect();
    (production, excluded)
}

/// What a daemon that listens would name.
const LISTENERS: &[&str] = &[
    r"\bTcpListener\b",
    r"\bUdpSocket\b",
    r"\bUnixListener\b",
    r"\bUnixDatagram\b",
    r"\bTcpIncoming\b",
    r"\btransport::Server\b",
    r"\bServer::builder\b",
    r"\bserve_with\w*",
    r"\bbind\s*\(",
    r"\blisten\s*\(",
];

/// What a daemon that trusts a store other than its pinned CA would name.
const ROOT_STORES: &[&str] = &[
    r"\bwith_native_roots\b",
    r"\bwith_webpki_roots\b",
    r"\bwith_enabled_roots\b",
    r"\brustls_native_certs\b",
    r"\bwebpki_roots\b",
    r"\brustls_platform_verifier\b",
];

/// Each match of any of `patterns` in `code`, as `pattern -> matched text`.
fn hits(code: &str, patterns: &[&str]) -> Vec<String> {
    patterns
        .iter()
        .flat_map(|p| {
            Regex::new(p)
                .unwrap()
                .find_iter(code)
                .map(|m| m.as_str().to_string())
                .collect::<Vec<_>>()
        })
        .collect()
}

/// The daemon opens its connection outward and never listens: no non-test source
/// names a listener, a socket bind, or tonic's server. A scanner that finds
/// nothing proves nothing alone, so `the_listener_scan_finds_a_listener` arms it.
///
/// Proves NC-1.
#[test]
fn the_daemon_never_listens_on_an_inbound_port() {
    let (production, excluded) = scanned();
    assert!(
        production.len() > 20,
        "the scan saw only {} files; it is not reading the daemon's source",
        production.len()
    );
    assert!(
        excluded
            .iter()
            .any(|p| p.ends_with("loader_hardening_tests.rs")),
        "the scan no longer recognises the test-only module that binds a Unix socket"
    );
    let mut found = Vec::new();
    for (path, code) in &production {
        for hit in hits(code, LISTENERS) {
            found.push(format!(
                "{}: {hit}",
                path.strip_prefix(daemon()).unwrap().display()
            ));
        }
    }
    assert!(
        found.is_empty(),
        "non-test daemon source names a listener (ADR-0005: the daemon dials out and never listens):\n{}",
        found.join("\n")
    );
}

/// Arms the scan above: it finds each listener pattern, and ignores the same
/// text in a comment, a string, a `#[cfg(test)]` item or a `#![cfg(test)]` file,
/// without letting a `#[cfg(test)]` on a field hide the code after it.
#[test]
fn the_listener_scan_finds_a_listener() {
    for listener in [
        r#"fn f() { let _ = TcpListener::bind("0.0.0.0:1"); }"#,
        "fn f() { let _ = std::net::UdpSocket::bind(a); }",
        "use tokio::net::UnixListener;",
        "fn f() { tonic::transport::Server::builder(); }",
        "async fn f(s: S) { s.serve_with_incoming(i).await }",
        "fn f() { socket.listen(8); }",
    ] {
        assert!(
            !hits(&production_code(listener), LISTENERS).is_empty(),
            "the scan missed a listener in: {listener}"
        );
    }
    for harmless in [
        "// TcpListener::bind(a)\nfn f() {}",
        r#"fn f() { let _ = "TcpListener::bind"; }"#,
        "/* UdpSocket */ fn f() {}",
        "#[cfg(test)]\nmod tests {\n fn f() { TcpListener::bind(a); }\n}\nfn g() {}",
        "#![cfg(test)]\nfn f() { TcpListener::bind(a); }",
        "#[cfg(test)]\nuse tokio::net::TcpListener;\nfn g() {}",
        "#![allow(dead_code)]\n#![cfg(test)]\nfn f() { TcpListener::bind(a); }",
        "fn f() { let _ = br#\"TcpListener::bind\"#; }",
    ] {
        assert!(
            hits(&production_code(harmless), LISTENERS).is_empty(),
            "the scan read test code, a comment or a string as a listener in: {harmless}"
        );
    }
    let after_field = "struct S {\n #[cfg(test)]\n x: u8,\n}\nfn g() { TcpListener::bind(a); }";
    assert!(
        !hits(&production_code(after_field), LISTENERS).is_empty(),
        "a #[cfg(test)] on a field hid the production code after it"
    );
    let after_byte_raw = "fn f() { let _ = br\"\\\"; }\nfn g() { TcpListener::bind(a); }";
    assert!(
        !hits(&production_code(after_byte_raw), LISTENERS).is_empty(),
        "a backslash in a byte raw string was read as an escape and hid the code after it"
    );
    let inline_inner_attr =
        "fn f() { TcpListener::bind(a); }\nmod m {\n #![cfg(test)]\n fn h() {}\n}";
    assert!(
        !hits(&production_code(inline_inner_attr), LISTENERS).is_empty(),
        "a #![cfg(test)] inside an inline module dropped the whole file"
    );
    let after_test_mod =
        "#[cfg(test)]\nmod tests { fn f() { let _ = '{'; } }\nfn g() { TcpListener::bind(a); }";
    assert!(
        !hits(&production_code(after_test_mod), LISTENERS).is_empty(),
        "a brace inside a character literal ended the test module early or late"
    );
}

/// Crates whose job is to load the operating system's or a public root store.
const ROOT_STORE_CRATES: &[&str] = &[
    "webpki-roots",
    "rustls-native-certs",
    "rustls-platform-verifier",
    "openssl-probe",
    "native-tls",
    "openssl",
    "openssl-sys",
];

/// tonic's features that load such a store.
const ROOT_STORE_FEATURES: &[&str] = &["tls-native-roots", "tls-webpki-roots", "tls-roots"];

fn package_names(lock: &str) -> BTreeSet<String> {
    let lock: Value = toml::from_str(lock).expect("Cargo.lock parses");
    lock["package"]
        .as_array()
        .expect("Cargo.lock lists packages")
        .iter()
        .map(|p| {
            p["name"]
                .as_str()
                .expect("a package has a name")
                .to_string()
        })
        .collect()
}

/// Whether any manifest string enables `feature`, spelled bare or as
/// `crate/feature` or `crate?/feature`.
fn enables(strings: &[String], feature: &str) -> bool {
    strings
        .iter()
        .any(|s| s == feature || s.ends_with(&format!("/{feature}")))
}

/// Every string in a manifest, wherever it sits, so a feature is found whether it
/// is listed on a dependency, in the workspace table or in a `[features]` entry.
fn strings(v: &Value, out: &mut Vec<String>) {
    match v {
        Value::String(s) => out.push(s.clone()),
        Value::Array(a) => a.iter().for_each(|x| strings(x, out)),
        Value::Table(t) => t.values().for_each(|x| strings(x, out)),
        _ => {}
    }
}

fn manifest_strings(manifests: &[&str]) -> Vec<String> {
    let mut out = Vec::new();
    for m in manifests {
        strings(
            &toml::from_str::<Value>(m).expect("a manifest parses"),
            &mut out,
        );
    }
    out
}

fn manifests() -> Vec<String> {
    let mut paths = vec![daemon().join("Cargo.toml")];
    let mut members: Vec<PathBuf> = fs::read_dir(daemon().join("crates"))
        .expect("read daemon/crates")
        .flatten()
        .map(|e| e.path().join("Cargo.toml"))
        .filter(|p| p.is_file())
        .collect();
    members.sort();
    paths.extend(members);
    paths
        .iter()
        .map(|p| fs::read_to_string(p).unwrap_or_else(|e| panic!("read {}: {e}", p.display())))
        .collect()
}

/// The daemon verifies the Relay against the CA it pinned and trusts no system or
/// public roots: no crate that loads such a store is in the build, no manifest
/// enables tonic's features that do, and no non-test source asks for one. The
/// pinned-CA refusal itself is shown by `wrong_ca_relay_is_refused`.
///
/// Proves NC-4.
#[test]
fn the_daemon_trusts_only_the_pinned_ca() {
    let lock = fs::read_to_string(daemon().join("Cargo.lock")).expect("read Cargo.lock");
    let packages = package_names(&lock);
    for name in ROOT_STORE_CRATES {
        assert!(
            !packages.contains(*name),
            "Cargo.lock holds `{name}`, a crate that loads a root store the daemon must not trust"
        );
    }

    let manifests = manifests();
    let manifest_refs: Vec<&str> = manifests.iter().map(String::as_str).collect();
    let features = manifest_strings(&manifest_refs);
    for feature in ROOT_STORE_FEATURES {
        assert!(
            !enables(&features, feature),
            "a manifest enables `{feature}`, which loads a root store besides the pinned CA"
        );
    }

    let (production, _) = scanned();
    let mut found = Vec::new();
    for (path, code) in &production {
        for hit in hits(code, ROOT_STORES) {
            found.push(format!(
                "{}: {hit}",
                path.strip_prefix(daemon()).unwrap().display()
            ));
        }
    }
    assert!(
        found.is_empty(),
        "non-test daemon source asks for a root store besides the pinned CA:\n{}",
        found.join("\n")
    );
}

/// Arms the guard above on a lock file, a manifest and a source line that each
/// do what it forbids.
#[test]
fn the_root_store_guard_finds_a_root_store() {
    let lock = "[[package]]\nname = \"webpki-roots\"\nversion = \"1.0.0\"\n";
    assert!(package_names(lock).contains("webpki-roots"));

    let manifest =
        "[dependencies]\ntonic = { version = \"0.14\", features = [\"tls-native-roots\"] }\n";
    assert!(manifest_strings(&[manifest])
        .iter()
        .any(|s| s == "tls-native-roots"));
    let workspace = "[workspace.dependencies]\ntonic = { version = \"0.14\", features = [\"tls-webpki-roots\"] }\n";
    assert!(manifest_strings(&[workspace])
        .iter()
        .any(|s| s == "tls-webpki-roots"));

    assert!(!hits(
        &production_code("fn f() { cfg.with_native_roots(); }"),
        ROOT_STORES
    )
    .is_empty());
    let forwarded =
        "[features]\nroots = [\"tonic/tls-native-roots\", \"tonic?/tls-webpki-roots\"]\n";
    let strings = manifest_strings(&[forwarded]);
    assert!(enables(&strings, "tls-native-roots"));
    assert!(enables(&strings, "tls-webpki-roots"));
    assert!(!enables(&strings, "tls-roots"));

    assert!(hits(
        &production_code("// with_native_roots\nfn f() {}"),
        ROOT_STORES
    )
    .is_empty());
}
