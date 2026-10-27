//! Offline proof that the daemon loads its Policy and Templates once, at start, with no
//! in-place reload (DI-15).
//!
//! Behaviour cannot show an absence: a test that edits a Policy file and sees nothing
//! happen passes for any number of reasons. So the property is pinned structurally. Every
//! call that constructs a Policy or a Template set from disk or text sits in the start
//! sequence or in an offline subcommand that exits, and nothing wraps either in a cell
//! that could swap it, nor listens for a signal or a file change that could ask for it.
//! Reading production text only: test modules are cut, and `//` lines are dropped.

use regex::Regex;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

const REASON: &str = "DI-15: Policy and Templates are loaded once, at start, and a runtime reload is \
                      never added. If this is a legitimate change to the start sequence, update the \
                      pinned set; if it is a second load path, it is the defect";

fn daemon() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(dir).unwrap_or_else(|e| panic!("read {}: {e}", dir.display())) {
        let path = entry.expect("dir entry").path();
        if path.is_dir() {
            rust_files(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

/// `daemon/src` and every crate's `src`, except the test-support crate, which only
/// dev-dependencies reach.
fn sources() -> Vec<PathBuf> {
    let mut out = Vec::new();
    rust_files(&daemon().join("src"), &mut out);
    let mut crates: Vec<_> = std::fs::read_dir(daemon().join("crates"))
        .expect("read crates")
        .map(|e| e.expect("crate entry").path())
        .filter(|p| p.file_name().is_some_and(|n| n != "relay-test-support"))
        .collect();
    crates.sort();
    for c in crates {
        if c.join("src").is_dir() {
            rust_files(&c.join("src"), &mut out);
        }
    }
    out.sort();
    out
}

/// The production lines of a file, or `None` for a file that is all test code. Removes the
/// brace-balanced span of every column-0 `#[cfg(test)]` that introduces an inline module
/// (a `use`, a fn or a `mod x;` under the attribute removes nothing), scanning on after
/// each, and drops `//` lines.
fn production_lines(text: &str) -> Option<Vec<String>> {
    let lines: Vec<&str> = text.lines().collect();
    let first = lines
        .iter()
        .find(|l| !l.trim().is_empty() && !l.trim_start().starts_with("//"));
    if first.is_some_and(|l| l.starts_with("#![cfg(test)]")) {
        return None;
    }
    let inline_mod = Regex::new(r"^(pub(\([a-z]+\))?\s+)?mod\s+\w+\s*\{\s*$").expect("regex");
    let mut out = Vec::new();
    let mut i = 0;
    while i < lines.len() {
        let line = lines[i];
        if line.trim_end() == "#[cfg(test)]" {
            let mut j = i + 1;
            let mut depth = 0i32;
            while j < lines.len() {
                let t = lines[j].trim();
                if depth > 0 || t.starts_with("#[") {
                    depth += t.matches('[').count() as i32 - t.matches(']').count() as i32;
                } else if !(t.is_empty() || t.starts_with("//")) {
                    break;
                }
                j += 1;
            }
            if j < lines.len() && inline_mod.is_match(lines[j].trim_end()) {
                i = module_end(&lines, j) + 1;
                continue;
            }
        }
        if !line.trim_start().starts_with("//") {
            out.push(line.to_string());
        }
        i += 1;
    }
    Some(out)
}

/// Where a scan of Rust source stands between characters.
enum Lex {
    Code,
    Block(u32),
    Str,
    /// Inside a raw string closed by `"` and this many `#`.
    Raw(usize),
}

/// The index of the line holding the `}` that closes the module opened on line `open`.
/// Braces in strings, raw strings, char literals and comments do not count.
fn module_end(lines: &[&str], open: usize) -> usize {
    let mut depth = 0i32;
    let mut state = Lex::Code;
    for (n, line) in lines.iter().enumerate().skip(open) {
        let c: Vec<char> = line.chars().collect();
        let mut i = 0;
        while i < c.len() {
            let next = c.get(i + 1).copied();
            match state {
                Lex::Block(d) => match (c[i], next) {
                    ('*', Some('/')) => {
                        state = if d == 1 { Lex::Code } else { Lex::Block(d - 1) };
                        i += 2;
                    }
                    ('/', Some('*')) => {
                        state = Lex::Block(d + 1);
                        i += 2;
                    }
                    _ => i += 1,
                },
                Lex::Str => match c[i] {
                    '\\' => i += 2,
                    '"' => {
                        state = Lex::Code;
                        i += 1;
                    }
                    _ => i += 1,
                },
                Lex::Raw(hashes) => {
                    let closes = c[i] == '"'
                        && c[i + 1..].iter().take_while(|&&x| x == '#').count() >= hashes;
                    if closes {
                        state = Lex::Code;
                        i += 1 + hashes;
                    } else {
                        i += 1;
                    }
                }
                Lex::Code => match c[i] {
                    '/' if next == Some('/') => break,
                    '/' if next == Some('*') => {
                        state = Lex::Block(1);
                        i += 2;
                    }
                    '"' => {
                        state = Lex::Str;
                        i += 1;
                    }
                    'r' if i == 0 || !(c[i - 1].is_alphanumeric() || c[i - 1] == '_') => {
                        let hashes = c[i + 1..].iter().take_while(|&&x| x == '#').count();
                        if c.get(i + 1 + hashes) == Some(&'"') {
                            state = Lex::Raw(hashes);
                            i += 2 + hashes;
                        } else {
                            i += 1;
                        }
                    }
                    // A char literal closes within the line; a lifetime does not.
                    '\'' => {
                        let close = if next == Some('\\') {
                            c[i + 2..]
                                .iter()
                                .position(|&x| x == '\'')
                                .map(|p| i + 2 + p)
                        } else {
                            Some(i + 2).filter(|&k| c.get(k) == Some(&'\''))
                        };
                        i = close.map_or(i + 1, |k| k + 1);
                    }
                    '{' => {
                        depth += 1;
                        i += 1;
                    }
                    '}' => {
                        depth -= 1;
                        if depth == 0 {
                            return n;
                        }
                        i += 1;
                    }
                    _ => i += 1,
                },
            }
        }
    }
    panic!("the module opened on line {} never closes", open + 1);
}

/// The lines from the one starting a function to its closing column-0 brace.
fn body<'a>(lines: &'a [String], signature: &str) -> &'a [String] {
    let start = lines
        .iter()
        .position(|l| l.starts_with(signature))
        .unwrap_or_else(|| panic!("no `{signature}` in production text"));
    let len = lines[start..]
        .iter()
        .position(|l| l == "}")
        .unwrap_or_else(|| panic!("`{signature}` never closes"));
    &lines[start..=start + len]
}

fn count(lines: &[String], re: &Regex) -> usize {
    lines.iter().filter(|l| re.is_match(l)).count()
}

// Proves DI-15.
#[test]
fn policy_and_templates_are_loaded_only_at_start() {
    let root = daemon();
    let mut production: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut raw_files = 0;
    for path in sources() {
        raw_files += 1;
        let text = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
        if let Some(lines) = production_lines(&text) {
            let rel = path.strip_prefix(&root).expect("under daemon/");
            production.insert(rel.to_string_lossy().into_owned(), lines);
        }
    }
    assert!(
        production.len() >= 20,
        "scanned {} files of {raw_files}",
        production.len()
    );

    // Every constructor call outside its own definition, per file.
    let constructors: [(&str, Regex, Regex); 5] = [
        ("load_policy", r"\bload_policy\(", r"\bfn\s+load_policy\("),
        (
            "from_toml_str",
            r"\bfrom_toml_str\(",
            r"\bfn\s+from_toml_str\(",
        ),
        ("compose", r"\bcompose\(", r"\bfn\s+compose\("),
        (
            "compose_fragments",
            r"\bcompose_fragments\(",
            r"\bfn\s+compose_fragments\(",
        ),
        (
            "TemplateSet::load",
            r"TemplateSet::load\w*\(",
            r"\bfn\s+load\w*\(",
        ),
    ]
    .map(|(name, call, def)| {
        (
            name,
            Regex::new(call).expect("regex"),
            Regex::new(def).expect("regex"),
        )
    });
    let mut calls: BTreeMap<(String, &str), usize> = BTreeMap::new();
    for (file, lines) in &production {
        for (name, call, def) in &constructors {
            let n = lines
                .iter()
                .filter(|l| call.is_match(l) && !def.is_match(l))
                .count();
            if n > 0 {
                calls.insert((file.clone(), *name), n);
            }
        }
    }
    let expected: BTreeMap<(String, &str), usize> = [
        // The start sequence.
        ("src/main.rs", "load_policy", 1),
        ("src/main.rs", "from_toml_str", 1),
        ("src/main.rs", "TemplateSet::load", 1),
        // The offline `policy check` and `policy explain` subcommands.
        ("src/policy_check.rs", "compose", 1),
        ("src/policy_check.rs", "compose_fragments", 1),
        ("src/policy_check.rs", "from_toml_str", 1),
        ("src/policy_check.rs", "TemplateSet::load", 1),
        // The loader's own composition, inside from_toml_str and load_policy.
        ("crates/relay-policy/src/lib.rs", "compose", 2),
        ("crates/relay-policy/src/lib.rs", "compose_fragments", 1),
        // The Template set's fail-closed loader.
        ("crates/relay-ops/src/templates.rs", "TemplateSet::load", 1),
    ]
    .into_iter()
    .map(|(f, c, n)| ((f.to_string(), c), n))
    .collect();
    assert_eq!(calls, expected, "{REASON}");

    // Where the start sequence loads.
    let main = &production["src/main.rs"];
    let main_body = body(main, "async fn main(");
    let startup_body = body(main, "fn startup_policy(");
    let load_policy = Regex::new(r"\bload_policy\(").unwrap();
    let load_templates = Regex::new(r"TemplateSet::load_or_fail_closed\(").unwrap();
    let from_toml = Regex::new(r"\bfrom_toml_str\(").unwrap();
    let startup_call = Regex::new(r"\bstartup_policy\(").unwrap();
    assert_eq!(
        count(main_body, &load_policy),
        1,
        "{REASON}: load_policy outside main"
    );
    assert_eq!(
        count(main_body, &load_templates),
        1,
        "{REASON}: Templates loaded outside main"
    );
    assert_eq!(
        count(startup_body, &from_toml),
        1,
        "{REASON}: from_toml_str outside startup_policy"
    );
    let calls_of_startup = count(main, &startup_call) - count(startup_body, &startup_call);
    assert_eq!(
        calls_of_startup, 1,
        "{REASON}: startup_policy is called once"
    );
    assert_eq!(
        count(main_body, &startup_call),
        1,
        "{REASON}: startup_policy outside main"
    );

    // The offline subcommands run and exit: they never leave a loaded Policy behind.
    let offline = Regex::new(r"\bpolicy_check::").unwrap();
    let mut refs = 0;
    for (file, lines) in &production {
        let hits: Vec<usize> = (0..lines.len())
            .filter(|&i| offline.is_match(&lines[i]))
            .collect();
        if file != "src/main.rs" {
            assert!(hits.is_empty(), "{REASON}: {file} reaches policy_check");
            continue;
        }
        for i in hits {
            refs += 1;
            let line = &lines[i];
            assert!(
                main_body.contains(line),
                "{REASON}: policy_check used outside main: {line}"
            );
            let after = &lines[i + 1..lines.len().min(i + 3)];
            assert!(
                after.iter().any(|l| l.contains("std::process::exit(")),
                "{REASON}: policy_check does not exit: {line}"
            );
        }
    }
    assert!(
        refs >= 2,
        "found {refs} policy_check references, expected run and run_explain"
    );

    // No mechanism that could ask for a reload or swap a held value.
    let swappable =
        Regex::new(r"(RwLock|Mutex|ArcSwap\w*)\s*<[^>]*\b(Policy|TemplateSet)\b").unwrap();
    for (file, lines) in &production {
        for line in lines {
            assert!(
                !line.contains("inotify") && !line.contains("notify::"),
                "{REASON}: {file} watches files: {line}"
            );
            assert!(
                !swappable.is_match(line),
                "{REASON}: {file} holds a Policy or Template set in a swappable cell: {line}"
            );
            assert!(
                !line.contains("SignalKind::hangup") || file == "src/join.rs",
                "{REASON}: {file} handles SIGHUP: {line}"
            );
        }
    }
    assert!(
        production["src/join.rs"]
            .iter()
            .any(|l| l.contains("SignalKind::hangup")),
        "the SIGHUP scan no longer sees the one-shot join handler"
    );
}
