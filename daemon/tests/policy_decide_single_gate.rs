//! Structural guard for #898: Policy is decided in exactly one function, and
//! Raw Exec runs only behind the gate that calls it.
//!
//! `Policy::decide` is the only Policy evaluation (invariants 1, 3 and 12). The
//! `RawExecPermit` type makes an ungated call to `run_raw_exec` fail to compile
//! outside relay-policy; this scan covers what a type cannot — inside
//! relay-policy the permit's field is visible crate-wide — and pins the call
//! shapes, so a new route to Raw Exec, or a second `decide` call, lands in front
//! of a reviewer instead of passing silently.
//!
//! # It proves
//!
//! * (a) `decide` has exactly one call site per entry path: apply (`policy_gate`),
//!   plan (`decide_query`), the self-reference lint (`probe_allows`),
//!   `file.read`'s layer-2 recheck (`file_read_via`) and a Template `path`
//!   slot's (`recheck_resolved_path`);
//! * (b) nothing outside `Policy::decide` calls an `evaluate*` method, and
//!   `decide` calls each of the eight private passes exactly once;
//! * (c) a `RawExecPermit` is constructed in one place (`decide`), and
//!   `run_raw_exec`, the permit field, `.invoke(` and `.handler)(` each occur
//!   only where the plan says;
//! * (d) every pinned site still exists (so none of the above is vacuous), the
//!   registry's Raw Exec handler is an inert refusal, and `RawExecPermit` has no
//!   derive, one inherent fn (`into_argv`) and no trait impl but `fmt::Debug`;
//! * (e) the scanner itself, on synthetic text.
//!
//! # It cannot see
//!
//! * a call through a renamed import, a macro, or a function pointer;
//! * a second construction of a permit that avoids the spellings (c1) matches,
//!   including one through a type alias (`type P = RawExecPermit; P { argv }`);
//! * test code: `#[cfg(test)]` items, files under a file-level `#![cfg(test)]`
//!   (an inner one in a `mod { }` masks only that module) and the
//!   `test-util`-gated shims are masked, because they are not in the shipped
//!   binary (`test-util` is enabled only from the bin's `[dev-dependencies]`,
//!   which `clippy_write_ban.rs` pins);
//! * where a masked item ends, beyond a heuristic: it stops at an unmatched
//!   closer, but a `<` after whitespace is a comparison and not a generic (so
//!   `-> <T as X>::Y` ends its item early, leaving test code visible, which
//!   over-counts and fails loudly), and a masked extent holding a second
//!   top-level `fn` panics rather than blanking it.
//!
//! It scans `daemon/src` and every `daemon/crates/*/src`, minus `ban_probe.rs`
//! files, which `clippy_write_ban.rs` excludes the same way.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use regex::Regex;

fn daemon() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// Same rule as `clippy_write_ban.rs`'s `is_probe_file`.
fn is_probe_file(rel: &str) -> bool {
    rel.starts_with("crates/") && rel.ends_with("/ban_probe.rs")
}

/// Every production-candidate source file as (path relative to `daemon/`, text).
fn sources() -> Vec<(String, String)> {
    fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
        for e in fs::read_dir(dir).expect("read source dir") {
            let p = e.expect("dir entry").path();
            if p.is_dir() {
                walk(&p, out);
            } else if p.extension().is_some_and(|x| x == "rs") {
                out.push(p);
            }
        }
    }
    let mut roots = vec![daemon().join("src")];
    for member in fs::read_dir(daemon().join("crates")).expect("read crates dir") {
        let src = member.expect("crate dir").path().join("src");
        if src.is_dir() {
            roots.push(src);
        }
    }
    let mut files = Vec::new();
    for root in roots {
        walk(&root, &mut files);
    }
    files.sort();
    files
        .into_iter()
        .filter_map(|p| {
            let rel = p
                .strip_prefix(daemon())
                .expect("under daemon/")
                .to_string_lossy()
                .replace('\\', "/");
            if is_probe_file(&rel) {
                return None;
            }
            let text = fs::read_to_string(&p).unwrap_or_else(|e| panic!("read {rel}: {e}"));
            Some((rel, text))
        })
        .collect()
}

fn is_ident(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

fn utf8_len(lead: u8) -> usize {
    match lead {
        0..=0x7f => 1,
        0xc0..=0xdf => 2,
        0xe0..=0xef => 3,
        _ => 4,
    }
}

fn blank(out: &mut [u8], from: usize, to: usize) {
    let to = to.min(out.len());
    if from >= to {
        return;
    }
    for byte in &mut out[from..to] {
        if *byte != b'\n' {
            *byte = b' ';
        }
    }
}

/// Blanks comments (including doc comments and nested block comments), the
/// contents of string, raw-string and byte-string literals, and char literals —
/// but not lifetimes. Byte-for-byte aligned with the input, so an offset in the
/// result is an offset in the original.
fn scrub(src: &str) -> String {
    let b = src.as_bytes();
    let n = b.len();
    let mut out = b.to_vec();
    let mut i = 0;
    while i < n {
        let c = b[i];
        if c == b'/' && i + 1 < n && b[i + 1] == b'/' {
            let end = b[i..].iter().position(|&x| x == b'\n').map_or(n, |p| i + p);
            blank(&mut out, i, end);
            i = end;
            continue;
        }
        if c == b'/' && i + 1 < n && b[i + 1] == b'*' {
            let mut j = i + 2;
            let mut depth = 1;
            while j < n && depth > 0 {
                if b[j] == b'/' && j + 1 < n && b[j + 1] == b'*' {
                    depth += 1;
                    j += 2;
                } else if b[j] == b'*' && j + 1 < n && b[j + 1] == b'/' {
                    depth -= 1;
                    j += 2;
                } else {
                    j += 1;
                }
            }
            blank(&mut out, i, j);
            i = j;
            continue;
        }
        let raw_prefix_ok = c == b'r'
            && (i == 0
                || !is_ident(b[i - 1])
                || (b[i - 1] == b'b' && (i < 2 || !is_ident(b[i - 2]))));
        if raw_prefix_ok {
            let mut j = i + 1;
            let mut hashes = 0;
            while j < n && b[j] == b'#' {
                hashes += 1;
                j += 1;
            }
            if j < n && b[j] == b'"' {
                let closer: Vec<u8> = std::iter::once(b'"')
                    .chain(std::iter::repeat_n(b'#', hashes))
                    .collect();
                let mut k = j + 1;
                while k < n && !b[k..].starts_with(&closer) {
                    k += 1;
                }
                blank(&mut out, j + 1, k);
                i = (k + closer.len()).min(n);
                continue;
            }
        }
        if c == b'"' {
            let mut j = i + 1;
            while j < n && b[j] != b'"' {
                if b[j] == b'\\' {
                    j += 1;
                }
                j += 1;
            }
            blank(&mut out, i + 1, j.min(n));
            i = j + 1;
            continue;
        }
        if c == b'\'' && i + 1 < n {
            if b[i + 1] == b'\\' {
                let mut j = i + 3;
                while j < n && b[j] != b'\'' {
                    j += 1;
                }
                blank(&mut out, i + 1, j.min(n));
                i = j + 1;
                continue;
            }
            let len = utf8_len(b[i + 1]);
            if i + 1 + len < n && b[i + 1 + len] == b'\'' {
                blank(&mut out, i + 1, i + 1 + len);
                i += 2 + len;
                continue;
            }
            // A lifetime: left alone.
        }
        i += 1;
    }
    String::from_utf8(out).expect("blanking whole literals keeps UTF-8 valid")
}

/// Index of the `}` matching the `{` at `open`, over scrubbed text.
fn match_brace(b: &[u8], open: usize) -> usize {
    let mut depth = 0;
    for (k, &c) in b.iter().enumerate().skip(open) {
        match c {
            b'{' => depth += 1,
            b'}' => {
                depth -= 1;
                if depth == 0 {
                    return k;
                }
            }
            _ => {}
        }
    }
    b.len().saturating_sub(1)
}

/// The end (exclusive) of the item that follows a `#[cfg(..)]` attribute ending
/// at `from`: past further attributes, then to the first depth-0 `;` or `,`, the
/// `}` matching the first depth-0 `{`, or — for the last field, variant or arm
/// of a block — the unmatched `}` closing the enclosing block (not consumed).
/// Depth counts `()`, `[]` and generic `<>` (not `->` or `=>`), so the commas of
/// `fn f<A, B>(..)` do not end the item early.
fn item_extent(b: &[u8], from: usize) -> usize {
    let n = b.len();
    let mut i = from;
    loop {
        while i < n && b[i].is_ascii_whitespace() {
            i += 1;
        }
        if i + 1 < n && b[i] == b'#' && b[i + 1] == b'[' {
            let mut depth = 0;
            while i < n {
                match b[i] {
                    b'[' => depth += 1,
                    b']' => {
                        depth -= 1;
                        if depth == 0 {
                            i += 1;
                            break;
                        }
                    }
                    _ => {}
                }
                i += 1;
            }
        } else {
            break;
        }
    }
    let mut depth = 0i32;
    let mut angle = 0i32;
    // After a depth-0 `=>` the item is a match arm: what follows is an
    // expression, where `<` and `>` are comparisons and not generics.
    let mut in_arm_body = false;
    while i < n {
        match b[i] {
            b'(' | b'[' => depth += 1,
            b')' | b']' if depth == 0 => return i,
            b')' | b']' => depth -= 1,
            // rustfmt spaces comparison operators, so a generic opener always
            // follows an identifier, `:` or `::`.
            b'<' if depth == 0
                && !in_arm_body
                && i > 0
                && (is_ident(b[i - 1]) || b[i - 1] == b':') =>
            {
                angle += 1;
            }
            b'>' if depth == 0 && i > 0 && b[i - 1] == b'=' => {
                in_arm_body = true;
                angle = 0;
            }
            b'>' if depth == 0 && i > 0 && b[i - 1] != b'-' && !in_arm_body => {
                if angle == 0 {
                    return i;
                }
                angle -= 1;
            }
            b';' if depth == 0 => return i + 1,
            b',' if depth == 0 && angle == 0 => return i + 1,
            b'}' if depth == 0 => return i,
            b'{' if depth == 0 => return match_brace(b, i) + 1,
            _ => {}
        }
        i += 1;
    }
    n
}

/// Fails closed when the extent masked for one `#[cfg(test)]` attribute holds
/// the start of a further item: a `fn` outside any braces of its own, after
/// the first. A well-formed extent is one item, whose nested fns sit in its
/// braces; two top-level fns mean the extent ran past its item and the mask
/// would silently blank production code.
fn check_one_item(scrubbed: &str, from: usize, end: usize) -> Result<(), String> {
    let fn_start = Regex::new(r"\bfn\s+[A-Za-z_]").unwrap();
    let region = &scrubbed[from..end];
    let mut top_level = 0;
    for m in fn_start.find_iter(region) {
        let before = &region[..m.start()];
        if before.matches('{').count() > before.matches('}').count() {
            continue;
        }
        top_level += 1;
        if top_level > 1 {
            return Err(format!(
                "offset {from}: the extent masked for a test attribute holds a second item (`fn` at offset {}); the scanner's item extent is wrong here",
                from + m.start()
            ));
        }
    }
    Ok(())
}

/// Index of the `{` of the innermost block that encloses `pos`, if any.
fn enclosing_open_brace(b: &[u8], pos: usize) -> Option<usize> {
    let mut depth = 0;
    for k in (0..pos).rev() {
        match b[k] {
            b'}' => depth += 1,
            b'{' if depth == 0 => return Some(k),
            b'{' => depth -= 1,
            _ => {}
        }
    }
    None
}

/// Whether the `#![cfg(test)]` at `at` is a file-level attribute: only whitespace
/// and other inner attributes may precede it. Anywhere else it is a module-level
/// inner attribute and covers only that module.
fn is_file_level(sb: &[u8], at: usize) -> bool {
    let mut i = 0;
    while i < at {
        if sb[i].is_ascii_whitespace() {
            i += 1;
        } else if sb[i..].starts_with(b"#![") {
            let mut depth = 0;
            while i < sb.len() {
                match sb[i] {
                    b'[' => depth += 1,
                    b']' => {
                        depth -= 1;
                        if depth == 0 {
                            i += 1;
                            break;
                        }
                    }
                    _ => {}
                }
                i += 1;
            }
        } else {
            return false;
        }
    }
    i == at
}

/// Blanks everything compiled only for tests: a whole file under a file-level
/// `#![cfg(test)]`, the body of a module carrying an inner `#![cfg(test)]`, and
/// the item after each `#[cfg(test)]` or
/// `#[cfg(any(test, feature = "test-util"))]`. `original` is searched for the
/// attribute (its `"test-util"` literal is blank in `scrubbed`); a match counts
/// only where `scrubbed` still has the `#`, i.e. outside comments and strings.
fn mask_tests(original: &str, scrubbed: &str) -> Result<String, String> {
    let attr = Regex::new(
        r#"#\[cfg\(\s*test\s*\)\]|#\[cfg\(\s*any\(\s*test\s*,\s*feature\s*=\s*"test-util"\s*\)\s*\)\]"#,
    )
    .unwrap();
    let whole_file = Regex::new(r"#!\[cfg\(\s*test\s*\)\]").unwrap();
    let sb = scrubbed.as_bytes();
    let mut out = sb.to_vec();
    for m in whole_file.find_iter(original) {
        if sb[m.start()] != b'#' {
            continue;
        }
        if is_file_level(sb, m.start()) {
            let len = out.len();
            blank(&mut out, 0, len);
            return Ok(String::from_utf8(out).unwrap());
        }
        if let Some(open) = enclosing_open_brace(sb, m.start()) {
            blank(&mut out, open, match_brace(sb, open) + 1);
        }
    }
    for m in attr.find_iter(original) {
        if sb[m.start()] != b'#' {
            continue;
        }
        let end = item_extent(sb, m.end());
        check_one_item(scrubbed, m.end(), end)?;
        blank(&mut out, m.start(), end);
    }
    Ok(String::from_utf8(out).expect("blanking keeps UTF-8 valid"))
}

struct FnInfo {
    name: String,
    /// `fn` through the end of the header (before the body's `{` or the `;`).
    header: (usize, usize),
    body: Option<(usize, usize)>,
}

fn fn_infos(text: &str) -> Vec<FnInfo> {
    let re = Regex::new(r"\bfn\s+([A-Za-z_][A-Za-z0-9_]*)").unwrap();
    let b = text.as_bytes();
    let mut out = Vec::new();
    for cap in re.captures_iter(text) {
        let whole = cap.get(0).unwrap();
        let mut depth = 0i32;
        let mut i = whole.end();
        let mut body = None;
        let mut header_end = b.len();
        while i < b.len() {
            match b[i] {
                b'(' | b'[' => depth += 1,
                b')' | b']' => depth -= 1,
                b';' if depth == 0 => {
                    header_end = i;
                    break;
                }
                b'{' if depth == 0 => {
                    header_end = i;
                    body = Some((i, match_brace(b, i)));
                    break;
                }
                _ => {}
            }
            i += 1;
        }
        out.push(FnInfo {
            name: cap[1].to_string(),
            header: (whole.start(), header_end),
            body,
        });
    }
    out
}

/// The innermost `fn` whose body contains `pos`. Closures and `async` blocks
/// are not `fn`s, so a hit inside one belongs to its enclosing `fn`.
fn enclosing_fn(text: &str, pos: usize) -> Option<String> {
    fn_infos(text)
        .into_iter()
        .filter_map(|f| f.body.map(|(open, close)| (f.name, open, close)))
        .filter(|(_, open, close)| *open < pos && pos < *close)
        .max_by_key(|(_, open, _)| *open)
        .map(|(name, _, _)| name)
}

/// A source file reduced to its production text.
struct Prod {
    rel: String,
    text: String,
}

fn production() -> Vec<Prod> {
    sources()
        .into_iter()
        .map(|(rel, original)| {
            let scrubbed = scrub(&original);
            assert_eq!(
                scrubbed.len(),
                original.len(),
                "{rel}: scrub must stay aligned"
            );
            let text = mask_tests(&original, &scrubbed).unwrap_or_else(|e| panic!("{rel}: {e}"));
            Prod { rel, text }
        })
        .collect()
}

type Counts = BTreeMap<(String, String), usize>;

fn counts(prod: &[Prod], re: &Regex, keep: impl Fn(&str, usize) -> bool) -> Counts {
    let mut out = Counts::new();
    for p in prod {
        for m in re.find_iter(&p.text) {
            if !keep(&p.text, m.start()) {
                continue;
            }
            let func = enclosing_fn(&p.text, m.start()).unwrap_or_else(|| "<outside fn>".into());
            *out.entry((p.rel.clone(), func)).or_insert(0) += 1;
        }
    }
    out
}

fn expect(pairs: &[(&str, &str, usize)]) -> Counts {
    pairs
        .iter()
        .map(|(f, func, n)| ((f.to_string(), func.to_string()), *n))
        .collect()
}

fn show(c: &Counts) -> String {
    c.iter()
        .map(|((f, func), n)| format!("  {f}::{func} x{n}"))
        .collect::<Vec<_>>()
        .join("\n")
}

fn assert_counts(what: &str, got: Counts, want: Counts) {
    assert_eq!(
        got,
        want,
        "{what}\n got:\n{}\nwant:\n{}",
        show(&got),
        show(&want)
    );
}

const POLICY_LIB: &str = "crates/relay-policy/src/lib.rs";
const REGISTRY: &str = "crates/relay-ops/src/operations/registry.rs";
const TEMPLATE: &str = "crates/relay-ops/src/operations/template.rs";

// ---------------------------------------------------------------------------
// (a) one `decide` call per entry path
// ---------------------------------------------------------------------------

#[test]
fn decide_has_exactly_one_call_site_per_entry_path() {
    let re = Regex::new(r"\.decide\s*\(|\bPolicy::decide\b").unwrap();
    assert_counts(
        "Policy::decide must be called from exactly one function per entry path",
        counts(&production(), &re, |_, _| true),
        expect(&[
            ("src/dispatch.rs", "policy_gate", 1),
            ("src/dispatch.rs", "decide_query", 1),
            ("src/selfref.rs", "probe_allows", 1),
            (REGISTRY, "file_read_via", 1),
            (TEMPLATE, "recheck_resolved_path", 1),
        ]),
    );
}

// ---------------------------------------------------------------------------
// (b) only `decide` calls the passes
// ---------------------------------------------------------------------------

const PASSES: [&str; 8] = [
    "evaluate_path_precondition",
    "evaluate_operation_deny",
    "evaluate_operation_allow",
    "evaluate_operation_default",
    "evaluate_raw_exec_deny",
    "evaluate_raw_exec_guard",
    "evaluate_raw_exec_allow",
    "evaluate_raw_exec_default",
];

#[test]
fn only_decide_calls_evaluate() {
    let re = Regex::new(r"(?:\.|\bPolicy::|\bSelf::)(evaluate\w*)\s*\(").unwrap();
    let prod = production();
    assert_counts(
        "no function other than Policy::decide may call an evaluate* method",
        counts(&prod, &re, |_, _| true),
        expect(&[(POLICY_LIB, "decide", PASSES.len())]),
    );
    let lib = prod
        .iter()
        .find(|p| p.rel == POLICY_LIB)
        .expect("relay-policy lib.rs");
    let mut seen: BTreeMap<String, usize> = BTreeMap::new();
    for cap in re.captures_iter(&lib.text) {
        *seen.entry(cap[1].to_string()).or_insert(0) += 1;
    }
    let want: BTreeMap<String, usize> = PASSES.iter().map(|p| (p.to_string(), 1)).collect();
    assert_eq!(
        seen, want,
        "decide must call each of the eight passes exactly once"
    );
}

// ---------------------------------------------------------------------------
// (c) Raw Exec runs only behind the gate
// ---------------------------------------------------------------------------

/// A use of the `raw_exec_permit` field: `.raw_exec_permit`, or the name as a
/// destructuring binding: shorthand (`raw_exec_permit,` / `raw_exec_permit }`) or
/// renamed (`raw_exec_permit: p`, `: mut p`, `: Some(p)`, `: _`). A struct literal
/// `raw_exec_permit: None` is not a touch: it only builds an `Explained` that
/// carries no permit. That exemption rests on `None` being the capitalised
/// literal: a lowercase binding such as `raw_exec_permit: none` counts as a touch.
const FIELD_TOUCH: &str = r"\.raw_exec_permit\b|\braw_exec_permit\s*(?:[,}]|:\s*(?:Some\b|(?:ref\s+|mut\s+)*[a-z_]\w*\s*[,}]))";

/// Offsets of every construction-shaped `RawExecPermit {` / `Self {` in `text`
/// that is not a type or impl header.
fn permit_construction_hits(text: &str) -> Vec<usize> {
    let site = Regex::new(r"\b(?:RawExecPermit|Self)\s*\{").unwrap();
    let header = Regex::new(r"(?:\bstruct\s+|\bimpl(?:<[^>]*>)?\s+|\bfor\s+)$").unwrap();
    site.find_iter(text)
        .filter(|m| !header.is_match(&text[..m.start()]))
        .map(|m| m.start())
        .collect()
}

#[test]
fn raw_exec_runs_only_behind_the_policy_gate() {
    let prod = production();

    // (c1) The permit is constructed in exactly one place, in every file that
    // names the type: field form, shorthand and `Self { .. }` alike.
    let mentions = Regex::new(r"\bRawExecPermit\b").unwrap();
    let mut c1 = Counts::new();
    for p in prod.iter().filter(|p| mentions.is_match(&p.text)) {
        for start in permit_construction_hits(&p.text) {
            let func = enclosing_fn(&p.text, start).unwrap_or_else(|| "<outside fn>".into());
            *c1.entry((p.rel.clone(), func)).or_insert(0) += 1;
        }
    }
    assert_counts(
        "(c1) a RawExecPermit may be constructed only in Policy::decide",
        c1,
        expect(&[(POLICY_LIB, "decide", 1)]),
    );

    // (c2) `run_raw_exec` is called once, from the Raw Exec gate.
    let run = Regex::new(r"\brun_raw_exec\s*\(").unwrap();
    let is_def = Regex::new(r"\bfn\s+$").unwrap();
    assert_counts(
        "(c2) run_raw_exec may be called only from gate_and_invoke_raw_exec",
        counts(&prod, &run, |text, at| !is_def.is_match(&text[..at])),
        expect(&[("src/dispatch.rs", "gate_and_invoke_raw_exec", 1)]),
    );

    // (c3) The permit field is written once (the mint) and read once (the gate);
    // destructuring it counts as a touch too.
    let field = Regex::new(FIELD_TOUCH).unwrap();
    assert_counts(
        "(c3) .raw_exec_permit may be touched only by decide (write) and the Raw Exec gate (read)",
        counts(&prod, &field, |_, _| true),
        expect(&[
            (POLICY_LIB, "decide", 1),
            ("src/dispatch.rs", "gate_and_invoke_raw_exec", 1),
        ]),
    );

    // (c4) One handler invocation in the whole workspace.
    let invoke = Regex::new(r"\.invoke\s*\(").unwrap();
    assert_counts(
        "(c4) a registry handler may be invoked only from gate_and_invoke",
        counts(&prod, &invoke, |_, _| true),
        expect(&[("src/dispatch.rs", "gate_and_invoke", 1)]),
    );

    // (c5) One direct call of a handler pointer.
    let handler = Regex::new(r"\.handler\s*\)\s*\(").unwrap();
    assert_counts(
        "(c5) a handler pointer may be called only by ResolvedOp::invoke",
        counts(&prod, &handler, |_, _| true),
        expect(&[(REGISTRY, "invoke", 1)]),
    );
}

// ---------------------------------------------------------------------------
// (d) the pins are not vacuous, and the permit stays closed
// ---------------------------------------------------------------------------

fn find<'a>(prod: &'a [Prod], rel: &str) -> &'a Prod {
    prod.iter()
        .find(|p| p.rel == rel)
        .unwrap_or_else(|| panic!("{rel} must exist"))
}

#[test]
fn pinned_sites_exist() {
    let prod = production();

    for (rel, func) in [
        ("src/dispatch.rs", "policy_gate"),
        ("src/dispatch.rs", "decide_query"),
        ("src/dispatch.rs", "gate_and_invoke"),
        ("src/dispatch.rs", "gate_and_invoke_raw_exec"),
        ("src/selfref.rs", "probe_allows"),
        (REGISTRY, "file_read_via"),
        (TEMPLATE, "recheck_resolved_path"),
        (REGISTRY, "invoke"),
        (POLICY_LIB, "decide"),
    ] {
        let fns = fn_infos(&find(&prod, rel).text);
        assert!(
            fns.iter().any(|f| f.name == func && f.body.is_some()),
            "{rel} must define fn {func}: a pin on a missing fn would pass vacuously"
        );
    }

    // The registry's Raw Exec handler is an inert refusal: its body names no
    // runner, executor or Policy.
    let registry = find(&prod, REGISTRY);
    let stub = fn_infos(&registry.text)
        .into_iter()
        .find(|f| f.name == "raw_exec_refused_without_permit")
        .expect("registry.rs must define fn raw_exec_refused_without_permit");
    let (open, close) = stub.body.expect("the stub has a body");
    let forbidden =
        Regex::new(r"\b(?:runner|execute|run_raw_exec|ExecRequest)\b|\.policy\b").unwrap();
    let body = &registry.text[open..=close];
    assert!(
        !forbidden.is_match(body),
        "the Raw Exec registry handler must stay an inert refusal; it names {:?}",
        forbidden.find(body).map(|m| m.as_str())
    );

    // RawExecPermit: defined once in relay-policy, no derive.
    let lib = find(&prod, POLICY_LIB);
    let def = Regex::new(r"\bstruct\s+RawExecPermit\b").unwrap();
    let at = def
        .find(&lib.text)
        .expect("relay-policy lib.rs must define struct RawExecPermit")
        .start();
    let lead_start = lib.text[..at].rfind(['}', ';']).map_or(0, |k| k + 1);
    assert!(
        !lib.text[lead_start..at].contains("derive"),
        "RawExecPermit must carry no #[derive]: Clone, Default and Deserialize would each mint permits"
    );

    // Inherent impls: exactly one fn, `into_argv`, never returning Self.
    let inherent = Regex::new(r"\bimpl(?:<[^>]*>)?\s+RawExecPermit\s*\{").unwrap();
    let mut inherent_blocks = 0;
    for p in &prod {
        for m in inherent.find_iter(&p.text) {
            inherent_blocks += 1;
            let open = m.end() - 1;
            let close = match_brace(p.text.as_bytes(), open);
            let block = &p.text[open..=close];
            let fns = fn_infos(block);
            let names: Vec<&str> = fns.iter().map(|f| f.name.as_str()).collect();
            assert_eq!(
                names,
                ["into_argv"],
                "{}: an inherent impl of RawExecPermit may hold only into_argv",
                p.rel
            );
            for f in &fns {
                assert!(
                    !block[f.header.0..f.header.1].contains("Self"),
                    "{}: fn {} in an impl of RawExecPermit must not return Self",
                    p.rel,
                    f.name
                );
            }
        }
    }
    assert_eq!(
        inherent_blocks, 1,
        "exactly one inherent impl of RawExecPermit"
    );

    // Trait impls: fmt::Debug only (no From, Default, Clone, Deserialize).
    let trait_impl =
        Regex::new(r"\bimpl(?:<[^>]*>)?\s+([\w:<>, ]+?)\s+for\s+RawExecPermit\b").unwrap();
    let mut traits = Vec::new();
    for p in &prod {
        for cap in trait_impl.captures_iter(&p.text) {
            traits.push(cap[1].split_whitespace().collect::<String>());
        }
    }
    assert_eq!(
        traits,
        ["fmt::Debug"],
        "RawExecPermit may implement only fmt::Debug"
    );

    // No fn other than `decide` returns a permit (directly or wrapped).
    for p in prod
        .iter()
        .filter(|p| p.rel.starts_with("crates/relay-policy/src/"))
    {
        for f in fn_infos(&p.text) {
            let header = &p.text[f.header.0..f.header.1];
            let returns_permit = header
                .split_once("->")
                .is_some_and(|(_, ret)| ret.contains("RawExecPermit"));
            assert!(
                !returns_permit || f.name == "decide",
                "{}: fn {} returns a RawExecPermit; only Policy::decide may mint one",
                p.rel,
                f.name
            );
        }
    }
}

// ---------------------------------------------------------------------------
// (e) the scanner itself
// ---------------------------------------------------------------------------

fn prod_of(src: &str) -> String {
    mask_tests(src, &scrub(src)).expect("synthetic source masks cleanly")
}

#[test]
fn scanner_self_test() {
    // Comments, doc comments and strings are ignored.
    let src = "// .decide(\n/// .decide(\n/* a /* nested .decide( */ .decide( */\n\
               let s = \".decide(\"; let r = r#\".decide(\"#; let b = b\".decide(\";\n\
               let c = '\"'; fn real() { x.decide(y); }\n";
    let p = prod_of(src);
    assert_eq!(p.matches(".decide(").count(), 1, "{p}");
    assert_eq!(p.len(), src.len());

    // Lifetimes survive; char literals are blanked.
    let p = prod_of("fn f<'a>(x: &'a str) -> char { 'x' }");
    assert!(p.contains("<'a>") && p.contains("&'a str"), "{p}");

    // cfg(test) and test-util items are masked, other cfgs are not.
    let src = "#[cfg(test)]\nmod t { fn a() { x.decide(1); } }\n\
               #[cfg(any(test, feature = \"test-util\"))]\nimpl P { fn b() { x.decide(2); } }\n\
               #[cfg(feature = \"x\")]\nfn c() { x.decide(3); }\n\
               #[cfg(test)]\nuse foo::bar;\nfn d() { x.decide(4); }\n";
    let p = prod_of(src);
    assert!(!p.contains("decide(1)") && !p.contains("decide(2)"), "{p}");
    assert!(p.contains("decide(3)") && p.contains("decide(4)"), "{p}");

    // A cfg(test) attribute inside a comment masks nothing.
    let p = prod_of("// #[cfg(test)]\nfn e() { x.decide(5); }\n");
    assert!(p.contains("decide(5)"), "{p}");

    // `#![cfg(test)]` masks the whole file.
    let p = prod_of("#![cfg(test)]\nfn f() { x.decide(6); }\n");
    assert!(!p.contains("decide"), "{p}");

    // An inner `#![cfg(test)]` in a module masks only that module's body.
    let p = prod_of("mod m { #![cfg(test)] }\nfn p() { x.decide(1) }\n");
    assert!(p.contains("decide(1)"), "{p}");
    let p = prod_of("mod m { #![cfg(test)] fn t() { x.decide(7) } }\nfn p() { x.decide(1) }\n");
    assert!(!p.contains("decide(7)") && p.contains("decide(1)"), "{p}");
    // ...whereas other inner attributes before it still make it file-level.
    let p = prod_of("//! doc\n#![allow(dead_code)]\n#![cfg(test)]\nfn f() { x.decide(8); }\n");
    assert!(!p.contains("decide"), "{p}");

    // A `#[cfg(test)]` field, variant or arm ends at its `,` or the closing `}`.
    let p = prod_of("struct S { #[cfg(test)] a: u8, b: u8 }\nfn p() { x.decide(2) }\n");
    assert!(p.contains("decide(2)") && p.contains("b: u8"), "{p}");
    let p = prod_of("struct S { b: u8, #[cfg(test)] a: u8 }\nfn p() { x.decide(2) }\n");
    assert!(p.contains("decide(2)") && p.contains("b: u8"), "{p}");
    let p = prod_of("enum E { #[cfg(test)] A(u8), B }\nfn p() { x.decide(2) }\n");
    assert!(p.contains("decide(2)") && p.contains(" B "), "{p}");
    // Generic commas do not end a masked fn early.
    let p = prod_of("#[cfg(test)]\nfn g<A, B>(a: A) { x.decide(9) }\nfn p() { x.decide(2) }\n");
    assert!(!p.contains("decide(9)") && p.contains("decide(2)"), "{p}");

    // An unmatched `)`, `]` or generic `>` ends a masked item, as `}` does.
    let p = prod_of("fn p(a: u8, #[cfg(test)] b: u8) { x.decide(1) }");
    assert!(p.contains("decide(1)"), "{p}");
    let p = prod_of("fn p<#[cfg(test)] T>() { x.decide(2) }");
    assert!(p.contains("decide(2)"), "{p}");
    let p = prod_of("match k { #[cfg(test)] 0 if a < b => (), _ => { x.decide(3) } }");
    assert!(p.contains("decide(3)"), "{p}");
    let p = prod_of("match k { #[cfg(test)] 0 if a<b => (), _ => { x.decide(3) } }");
    assert!(p.contains("decide(3)"), "{p}");
    let p = prod_of("enum E { #[cfg(test)] A = 1 < 2, B }\nfn p() { x.decide(9) }");
    assert!(p.contains(" B ") && p.contains("decide(9)"), "{p}");
    let p = prod_of("struct T(u8, #[cfg(test)] u8);\nfn p() { x.decide(4) }");
    assert!(p.contains("decide(4)"), "{p}");
    let p = prod_of("#[cfg(test)]\nfn g() -> Vec<u8> { x.decide(5) }\nfn p() { x.decide(6) }");
    assert!(!p.contains("decide(5)") && p.contains("decide(6)"), "{p}");

    // The mask fails closed when an extent swallows a second item.
    let src = "#[cfg(test)]\nconst X: [u8; 1] = [0\nfn a() {}\nfn b() { x.decide(1) }\n";
    let err = mask_tests(src, &scrub(src)).expect_err("two top-level fns must fail closed");
    assert!(err.contains("offset"), "{err}");
    // ...while a masked fn with nested fns in its braces is one item.
    let p = prod_of("#[cfg(test)]\nfn a() { fn inner() {} x.decide(7) }\nfn p() { x.decide(8) }");
    assert!(!p.contains("decide(7)") && p.contains("decide(8)"), "{p}");

    // (c3)'s field pattern sees access and destructuring alike.
    let touch = Regex::new(FIELD_TOUCH).unwrap();
    for hit in [
        "e.raw_exec_permit",
        "let Explained { raw_exec_permit, .. } = e;",
        "let Explained { raw_exec_permit: p, .. } = e;",
        "let Explained { x, raw_exec_permit } = e;",
        "let Explained { raw_exec_permit: mut p, .. } = e;",
        "let Explained { raw_exec_permit: Some(p), .. } = e;",
        "let Explained { raw_exec_permit: _, .. } = e;",
    ] {
        assert!(touch.is_match(hit), "{hit:?} must count as a field touch");
    }
    assert!(!touch.is_match("Explained { raw_exec_permit: None, pass }"));
    assert!(!touch.is_match("pub raw_exec_permit: Option<RawExecPermit>,"));

    // enclosing_fn sees through closures and async blocks.
    let src = "fn outer() { let f = |a| { x.decide(a) }; let g = async move { y.decide(1) }; }\n\
               fn other() { z.decide(2) }\n";
    let p = prod_of(src);
    let first = p.find("x.decide").unwrap();
    let second = p.find("y.decide").unwrap();
    let third = p.find("z.decide").unwrap();
    assert_eq!(enclosing_fn(&p, first).as_deref(), Some("outer"));
    assert_eq!(enclosing_fn(&p, second).as_deref(), Some("outer"));
    assert_eq!(enclosing_fn(&p, third).as_deref(), Some("other"));
    assert_eq!(enclosing_fn(&p, 0), None);

    // A fn with a `[T; N]` parameter still finds its body.
    let p = prod_of("fn arr(x: [u8; 3]) -> u8 { x.decide(1) }");
    assert_eq!(
        enclosing_fn(&p, p.find("decide").unwrap()).as_deref(),
        Some("arr")
    );

    // (c1)'s prefix filter drops type and impl headers, keeps constructions.
    for dropped in [
        "pub struct RawExecPermit { argv: Vec<String> }",
        "impl RawExecPermit { }",
        "impl fmt::Debug for RawExecPermit { }",
    ] {
        assert!(
            permit_construction_hits(dropped).is_empty(),
            "{dropped:?} must not count as a construction"
        );
    }
    for kept in [
        "let p = RawExecPermit { argv };",
        "let p = RawExecPermit { argv: v };",
        "fn new(argv: Vec<String>) -> Self { Self { argv } }",
    ] {
        assert!(
            !permit_construction_hits(kept).is_empty(),
            "{kept:?} must count as a construction"
        );
    }

    // A probe file can never flip a count, and the exclusion cannot widen.
    assert!(is_probe_file("crates/relay-policy/src/ban_probe.rs"));
    assert!(!is_probe_file("src/ban_probe.rs"));
    assert!(!is_probe_file("crates/relay-policy/src/lib.rs"));
}
