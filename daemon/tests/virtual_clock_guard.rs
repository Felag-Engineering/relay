//! Structural guard for the virtual-clock rule (#639): a test that depends on a
//! timer already being elapsed on its first poll must run on virtual time.
//!
//! # Origin
//!
//! #637. `scheduler::tests::free_gate_timeout_beats_permit_biased` set a
//! deadline of `Instant::now() - 1ms` on a REAL clock and relied on the sleep
//! arm being Ready on the first poll. It passed about 370 runs in a row locally
//! and failed on a loaded CI runner.
//!
//! # The rule
//!
//! A test that depends on a timer already being elapsed on its first poll must
//! use `#[tokio::test(start_paused = true)]`, plus `tokio::time::advance` where
//! it needs ordering. On a real clock, "already elapsed" depends on how fresh
//! the timer driver's processed tick is, and tokio's resolution is 1ms, so a
//! sub-second margin sits on the boundary.
//!
//! # The mechanism
//!
//! `executor.rs`'s `timeout_beats_buffered_cancel_biased` (test 11) is the
//! authoritative write-up. Its key clause: "a new entry is only fast-pathed as
//! `Elapsed` when its deadline is strictly before the driver's already-processed
//! tick". Read it before writing a racing-arm test.
//!
//! # Which clock is guarded
//!
//! `start_paused` virtualises only `tokio::time::Instant`. `std::time::Instant`
//! is always the real clock and cannot feed a tokio timer without an explicit
//! `tokio::time::Instant::from_std`. So a deadline written as
//! `std::time::Instant::now() +/- margin` is a real-clock poll bound, not a
//! timer deadline, and `start_paused` would be no remedy for it: the guard
//! skips that fully-qualified form.
//!
//! The guard flags `tokio::time::Instant::now()` and a bare `Instant::now()`.
//! A bare `Instant` is ambiguous without resolving `use` statements, so it is
//! treated conservatively as tokio. If a bare `Instant` that is really std is
//! flagged, spell it `std::time::Instant::now()`, which states plainly that it
//! is a real-clock bound and not a timer.
//!
//! # It proves
//!
//! No `#[tokio::test]` under `daemon/src` or `daemon/tests` that lacks
//! `start_paused = true` builds a deadline as a tokio-clock `Instant::now()`
//! plus or minus a sub-second literal `Duration` (subject to the limits below).
//!
//! # It cannot see
//!
//! (a) A margin held in a variable or computed
//!     (`let m = Duration::from_millis(1); now() - m`).
//! (b) A deadline built in a helper fn outside the test body, such as
//!     `far_deadline()`.
//! (c) `checked_sub`, `checked_add` and `saturating_*` forms.
//! (d) Hand-built runtimes, i.e. `tokio::runtime::Builder::new_current_thread()`
//!     inside a `#[test]` (`dispatch.rs` and `operations/file_read.rs` have some;
//!     none is timing-racy today).
//! (e) Timing races that do not involve an `Instant::now()` deadline at all.
//! (f) `tokio::time::Instant::from_std(std::time::Instant::now() - small)`,
//!     which goes through the excluded std form.
//! (g) A test that writes `std::time::Instant` explicitly but still converts
//!     the result into a tokio timer, which is (f) by another route.
//!
//! `flavor = "multi_thread"` tests cannot take `start_paused`, because tokio
//! restricts it to current_thread. A flagged multi_thread test has to be
//! restructured, not annotated.
//!
//! # No allowlist
//!
//! A flagged test is converted, never exempted. If a genuine exception ever
//! appears it needs a reasoned exemption list in the `packaging_drift.rs` style,
//! added in front of a reviewer.

use regex::Regex;
use std::ops::Range;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

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

fn is_ident(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

/// Index just past the closing `"` of a (non-raw) string whose content starts
/// at `start`. Each backslash escape is consumed as a pair.
fn skip_string(b: &[u8], start: usize) -> usize {
    let mut k = start;
    while k < b.len() {
        match b[k] {
            b'\\' => k += 2,
            b'"' => return k + 1,
            _ => k += 1,
        }
    }
    panic!("virtual_clock_guard: unterminated string literal");
}

/// Index just past the closing `'` of a char literal whose opening quote is at
/// `q`, or `None` when it is not one (a lifetime or loop label).
fn char_literal_end(src: &str, q: usize) -> Option<usize> {
    let b = src.as_bytes();
    match b.get(q + 1)? {
        b'\\' => {
            // Escaped: consume the escaped char, then run to the closing quote.
            // This covers `'\''`, `'\\'`, `'\n'`, `'\x7f'` and `'\u{7B}'`.
            let mut k = q + 3;
            while k < b.len() && b[k] != b'\'' && b[k] != b'\n' {
                k += 1;
            }
            if b.get(k) != Some(&b'\'') {
                panic!("virtual_clock_guard: unterminated escaped char literal");
            }
            Some(k + 1)
        }
        b'\'' => None,
        _ => {
            let ch = src[q + 1..].chars().next()?;
            let close = q + 1 + ch.len_utf8();
            (b.get(close) == Some(&b'\'')).then_some(close + 1)
        }
    }
}

/// Blank the contents of comments and literals with spaces, keeping
/// delimiters, newlines and byte length, so offsets and line numbers survive.
fn scrub(src: &str) -> String {
    let b = src.as_bytes();
    let n = b.len();
    let mut out = b.to_vec();
    let blank = |out: &mut Vec<u8>, from: usize, to: usize| {
        for byte in &mut out[from..to] {
            if *byte != b'\n' {
                *byte = b' ';
            }
        }
    };
    let mut i = 0;
    while i < n {
        let c = b[i];
        if c == b'/' && b.get(i + 1) == Some(&b'/') {
            let s = i;
            while i < n && b[i] != b'\n' {
                i += 1;
            }
            blank(&mut out, s, i);
        } else if c == b'/' && b.get(i + 1) == Some(&b'*') {
            let s = i;
            let mut depth = 1;
            i += 2;
            while i < n && depth > 0 {
                if b[i] == b'/' && b.get(i + 1) == Some(&b'*') {
                    depth += 1;
                    i += 2;
                } else if b[i] == b'*' && b.get(i + 1) == Some(&b'/') {
                    depth -= 1;
                    i += 2;
                } else {
                    i += 1;
                }
            }
            blank(&mut out, s, i);
        } else if c == b'"' {
            let end = skip_string(b, i + 1);
            blank(&mut out, i + 1, end - 1);
            i = end;
        } else if c == b'\'' {
            match char_literal_end(src, i) {
                Some(end) => {
                    blank(&mut out, i + 1, end - 1);
                    i = end;
                }
                None => i += 1, // lifetime or loop label: code
            }
        } else if is_ident(c) && (i == 0 || !is_ident(b[i - 1])) {
            let mut j = i;
            while j < n && is_ident(b[j]) {
                j += 1;
            }
            let word = &src[i..j];
            match word {
                "r" | "br" | "cr" => {
                    let hashes = b[j..].iter().take_while(|&&h| h == b'#').count();
                    if b.get(j + hashes) == Some(&b'"') {
                        let open = j + hashes;
                        let mut k = open + 1;
                        let end = loop {
                            if k >= n {
                                panic!("virtual_clock_guard: unterminated raw string");
                            }
                            if b[k] == b'"'
                                && b[k + 1..].iter().take_while(|&&h| h == b'#').count() >= hashes
                            {
                                break k;
                            }
                            k += 1;
                        };
                        blank(&mut out, open + 1, end);
                        i = end + 1 + hashes;
                        continue;
                    }
                    // A raw identifier such as `r#type`: code.
                }
                "b" | "c" if b.get(j) == Some(&b'"') => {
                    let end = skip_string(b, j + 1);
                    blank(&mut out, j + 1, end - 1);
                    i = end;
                    continue;
                }
                "b" if b.get(j) == Some(&b'\'') => {
                    let Some(end) = char_literal_end(src, j) else {
                        panic!("virtual_clock_guard: malformed byte literal");
                    };
                    blank(&mut out, j + 1, end - 1);
                    i = end;
                    continue;
                }
                _ => {}
            }
            i = j;
        } else {
            i += 1;
        }
    }
    String::from_utf8(out).expect("scrub only writes ASCII spaces over whole literals")
}

struct TokioTest {
    file: String,
    name: String,
    paused: bool,
    body: Range<usize>,
}

fn line_of(text: &str, offset: usize) -> usize {
    text[..offset].bytes().filter(|&c| c == b'\n').count() + 1
}

fn tokio_tests(file: &str, scrubbed: &str) -> Vec<TokioTest> {
    static ATTR: OnceLock<Regex> = OnceLock::new();
    static FUNC: OnceLock<Regex> = OnceLock::new();
    static PAUSED: OnceLock<Regex> = OnceLock::new();
    let attr = ATTR.get_or_init(|| {
        Regex::new(r"#\[\s*(?:::)?tokio::test\s*(?:\((?P<args>[^)]*)\))?\s*\]").unwrap()
    });
    let func = FUNC.get_or_init(|| Regex::new(r"\bfn\s+(?P<name>\w+)").unwrap());
    let paused_re = PAUSED.get_or_init(|| Regex::new(r"start_paused\s*=\s*true").unwrap());

    let b = scrubbed.as_bytes();
    let mut tests = Vec::new();
    for m in attr.captures_iter(scrubbed) {
        let whole = m.get(0).unwrap();
        let line = line_of(scrubbed, whole.start());
        let paused = m
            .name("args")
            .is_some_and(|a| paused_re.is_match(a.as_str()));
        let Some(f) = func.captures(&scrubbed[whole.end()..]) else {
            panic!("virtual_clock_guard: tokio test with no following fn at {file}:{line}");
        };
        let name_m = f.name("name").unwrap();
        let name = name_m.as_str().to_string();
        let after_name = whole.end() + name_m.end();
        let Some(open_rel) = scrubbed[after_name..].find('{') else {
            panic!("virtual_clock_guard: unbalanced braces scanning tokio test {file}:{line}");
        };
        let open = after_name + open_rel;
        let mut depth = 0usize;
        let mut close = None;
        for (k, &c) in b.iter().enumerate().skip(open) {
            match c {
                b'{' => depth += 1,
                b'}' => {
                    depth -= 1;
                    if depth == 0 {
                        close = Some(k);
                        break;
                    }
                }
                _ => {}
            }
        }
        let Some(close) = close else {
            panic!("virtual_clock_guard: unbalanced braces scanning tokio test {file}:{line}");
        };
        tests.push(TokioTest {
            file: file.to_string(),
            name,
            paused,
            body: open..close + 1,
        });
    }
    tests
}

/// Sub-second literal deadlines built from a tokio-clock `Instant::now()`:
/// `(byte offset, matched text)`. Explicit `std::time::Instant` is skipped.
fn sub_second_deadlines(body: &str) -> Vec<(usize, String)> {
    static RE: OnceLock<Regex> = OnceLock::new();
    let re = RE.get_or_init(|| {
        Regex::new(
            r"(?:^|[^\w])(?P<path>(?:std::time::|tokio::time::)?)Instant::now\(\)\s*[-+]\s*(?:(?:std|tokio)::time::)?Duration::(?:(?P<unit>from_millis|from_micros|from_nanos|from_secs_f32|from_secs_f64)\(\s*(?P<n>[0-9][0-9_]*(?:\.[0-9]+)?(?:[eE][-+]?[0-9_]+)?)(?:u8|u16|u32|u64|u128|usize|f32|f64)?\s*\)|(?P<zero>ZERO))",
        )
        .unwrap()
    });
    let mut hits = Vec::new();
    for m in re.captures_iter(body) {
        if &m["path"] == "std::time::" {
            continue;
        }
        let sub_second = if m.name("zero").is_some() {
            true
        } else {
            let n: f64 = m["n"].replace('_', "").parse().unwrap();
            match &m["unit"] {
                "from_millis" => n < 1_000.0,
                "from_micros" => n < 1_000_000.0,
                "from_nanos" => n < 1_000_000_000.0,
                _ => n < 1.0, // from_secs_f32 / from_secs_f64
            }
        };
        if !sub_second {
            continue;
        }
        // Report from the `path` group: the match itself may start with the
        // one non-word character that anchors `Instant`.
        let start = m.name("path").unwrap().start();
        let end = m.get(0).unwrap().end();
        let text = body[start..end]
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ");
        hits.push((start, text));
    }
    hits
}

/// The guard pipeline on one source text: every unpaused tokio test's
/// sub-second deadlines as `"<file>:<line> in `<fn>`: `<text>`"`.
fn unpaused_hits(file: &str, src: &str) -> Vec<String> {
    let scrubbed = scrub(src);
    let mut out = Vec::new();
    for t in tokio_tests(file, &scrubbed) {
        if t.paused {
            continue;
        }
        for (off, text) in sub_second_deadlines(&scrubbed[t.body.clone()]) {
            let line = line_of(&scrubbed, t.body.start + off);
            out.push(format!("{}:{line} in `{}`: `{text}`", t.file, t.name));
        }
    }
    out
}

fn tree_files() -> Vec<(String, String)> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut files = Vec::new();
    for sub in ["src", "tests"] {
        source_files(&root.join(sub), &mut files);
    }
    files.sort();
    files
        .into_iter()
        .filter(|p| p.file_name().is_some_and(|f| f != "virtual_clock_guard.rs"))
        .map(|p| {
            let rel = p
                .strip_prefix(root)
                .unwrap()
                .to_string_lossy()
                .replace('\\', "/");
            let text = std::fs::read_to_string(&p).unwrap();
            (rel, text)
        })
        .collect()
}

#[test]
fn sub_second_real_clock_deadlines_require_start_paused() {
    let violations: Vec<String> = tree_files()
        .iter()
        .flat_map(|(rel, text)| unpaused_hits(rel, text))
        .collect();
    assert!(
        violations.is_empty(),
        "tokio tests with a sub-second Instant::now() deadline on a real clock:\n  {}\n\n\
         A timer is only already-elapsed on its first poll if its deadline is strictly \
         before the driver's processed tick, which a loaded runner does not keep fresh \
         (#637). Remedies:\n\
         * use #[tokio::test(start_paused = true)] (see executor.rs \
         `timeout_beats_buffered_cancel_biased` and #637 for why);\n\
         * if the Instant is really std (a real-clock poll bound, not a timer), spell it \
         `std::time::Instant::now()`;\n\
         * a multi_thread test cannot be paused and must be restructured.\n\
         The rule is written up in this file's module doc.",
        violations.join("\n  ")
    );
}

#[test]
fn scanner_sees_the_real_tree() {
    let mut all = Vec::new();
    let mut templates_scrubbed = None;
    for (rel, text) in tree_files() {
        let scrubbed = scrub(&text);
        if rel == "src/templates.rs" {
            templates_scrubbed = Some(scrubbed.clone());
        }
        let tests = tokio_tests(&rel, &scrubbed);
        for t in tests {
            let deadlines = sub_second_deadlines(&scrubbed[t.body.clone()]).len();
            all.push((t, deadlines));
        }
    }

    // A floor against the scanner breaking (the tree has about 125 today), not
    // a census.
    assert!(
        all.len() >= 110,
        "scanner found only {} tokio tests",
        all.len()
    );

    let find = |file: &str, name: &str| {
        all.iter()
            .find(|(t, _)| t.file == file && t.name == name)
            .unwrap_or_else(|| panic!("{file} `{name}` not found by the scanner"))
    };
    let (racing, deadlines) = find("src/scheduler.rs", "free_gate_timeout_beats_permit_biased");
    assert!(racing.paused, "start_paused not detected on real code");
    assert!(
        *deadlines >= 1,
        "sub-second deadline not detected on real code"
    );
    let (queued, _) = find("src/scheduler.rs", "queued_timeout_returns_timeout");
    assert!(
        queued.paused,
        "queued_timeout_returns_timeout must run on virtual time"
    );

    let templates = templates_scrubbed.expect("src/templates.rs not scanned");
    assert!(
        templates.contains("r#type"),
        "raw identifier `r#type` must survive scrubbing as code"
    );
}

fn case(attr: &str, body: &str) -> String {
    format!("{attr}\nasync fn t() {{\n{body}\n}}\n")
}

#[test]
fn guard_fixtures() {
    const UNPAUSED: &str = "#[tokio::test]";
    const PAUSED: &str = "#[tokio::test(start_paused = true)]";
    let ms1 = r##"let d = tokio::time::Instant::now() - Duration::from_millis(1);"##;
    let bare_ms1 = r##"let d = Instant::now() - Duration::from_millis(1);"##;

    let fixtures: Vec<(&str, String, usize)> = vec![
        ("unpaused tokio 1ms", case(UNPAUSED, ms1), 1),
        ("paused tokio 1ms", case(PAUSED, ms1), 0),
        (
            "bare Instant 999ms plus",
            case(
                UNPAUSED,
                r##"let d = Instant::now() + std::time::Duration::from_millis(999);"##,
            ),
            1,
        ),
        (
            "explicit std Instant is excluded",
            case(
                UNPAUSED,
                r##"let d = std::time::Instant::now() - Duration::from_millis(1);"##,
            ),
            0,
        ),
        (
            "identifier ending in Instant is not Instant",
            case(
                UNPAUSED,
                r##"let d = MyInstant::now() - Duration::from_millis(1);"##,
            ),
            0,
        ),
        (
            "1_000 ms is the boundary",
            case(
                UNPAUSED,
                r##"let d = Instant::now() - Duration::from_millis(1_000);"##,
            ),
            0,
        ),
        (
            "whole seconds",
            case(
                UNPAUSED,
                r##"let a = Instant::now() + Duration::from_secs(1);
                let b = Instant::now() + Duration::from_secs(100);"##,
            ),
            0,
        ),
        (
            "Duration::ZERO",
            case(UNPAUSED, r##"let d = Instant::now() - Duration::ZERO;"##),
            1,
        ),
        (
            "500 micros",
            case(
                UNPAUSED,
                r##"let d = Instant::now() - Duration::from_micros(500);"##,
            ),
            1,
        ),
        (
            "1 nano",
            case(
                UNPAUSED,
                r##"let d = Instant::now() - Duration::from_nanos(1);"##,
            ),
            1,
        ),
        (
            "typed suffix millis",
            case(
                UNPAUSED,
                r##"let d = Instant::now() - Duration::from_millis(1u64);"##,
            ),
            1,
        ),
        (
            "underscore typed suffix millis",
            case(
                UNPAUSED,
                r##"let d = Instant::now() - Duration::from_millis(1_u64);"##,
            ),
            1,
        ),
        (
            "typed suffix whole second is not sub-second",
            case(
                UNPAUSED,
                r##"let d = Instant::now() - Duration::from_millis(1_000u64);"##,
            ),
            0,
        ),
        (
            "exponent float",
            case(
                UNPAUSED,
                r##"let d = Instant::now() - Duration::from_secs_f64(1e-3);"##,
            ),
            1,
        ),
        (
            "exponent float above one second",
            case(
                UNPAUSED,
                r##"let d = Instant::now() - Duration::from_secs_f64(1e3);"##,
            ),
            0,
        ),
        (
            "leading :: on the attribute",
            case("#[::tokio::test]", ms1),
            1,
        ),
        (
            "0.5 secs f64",
            case(
                UNPAUSED,
                r##"let d = Instant::now() - Duration::from_secs_f64(0.5);"##,
            ),
            1,
        ),
        (
            "split over two lines",
            case(
                UNPAUSED,
                "let d = Instant::now()\n    - Duration::from_millis(1);",
            ),
            1,
        ),
        (
            "only in a line comment",
            case(
                UNPAUSED,
                r##"// Instant::now() - Duration::from_millis(1)"##,
            ),
            0,
        ),
        (
            "only in a string",
            case(
                UNPAUSED,
                r##"let s = "Instant::now() - Duration::from_millis(1)";"##,
            ),
            0,
        ),
        (
            "only in a raw string",
            case(
                UNPAUSED,
                r###"let s = r#"Instant::now() - Duration::from_millis(1)"#;"###,
            ),
            0,
        ),
        (
            "raw string with an inner quote-hash",
            case(
                UNPAUSED,
                r###"let s = r##"a "# Instant::now() - Duration::from_millis(1)"##;"###,
            ),
            0,
        ),
        (
            "raw identifier does not open a raw string",
            case(
                UNPAUSED,
                "let s = S { r#type: 1 };\nlet d = Instant::now() - Duration::from_millis(1);",
            ),
            1,
        ),
        (
            "multi_thread cannot be exempted",
            case(
                r##"#[tokio::test(flavor = "multi_thread", worker_threads = 2)]"##,
                ms1,
            ),
            1,
        ),
        (
            "plain #[test] is not a tokio test",
            case("#[test]", bare_ms1),
            0,
        ),
        (
            "extra attribute between tokio::test and fn",
            case("#[tokio::test]\n#[should_panic]", ms1),
            1,
        ),
        (
            "adjacent tests are bounded by braces",
            format!(
                "{}\n{}",
                case(PAUSED, ms1),
                case(UNPAUSED, r##"let x = 1;"##)
            ),
            0,
        ),
        (
            "brace literals do not affect depth",
            case(
                UNPAUSED,
                r##"let a = '{';
                let b = '\u{7B}';
                let c = "}";
                let d = Instant::now() - Duration::from_millis(1);"##,
            ),
            1,
        ),
        (
            "lifetime is not a char literal",
            case(
                UNPAUSED,
                r##"fn f<'a>(x: &'a str) -> &'a str { x }
                let d = Instant::now() - Duration::from_millis(1);"##,
            ),
            1,
        ),
    ];

    // The reported position starts at the `Instant`, not at the anchoring char.
    let hits = unpaused_hits(
        "fixture.rs",
        &case(UNPAUSED, "Instant::now() - Duration::ZERO;"),
    );
    assert_eq!(
        hits,
        ["fixture.rs:3 in `t`: `Instant::now() - Duration::ZERO`"]
    );

    for (label, src, expected) in fixtures {
        let hits = unpaused_hits("fixture.rs", &src);
        assert_eq!(hits.len(), expected, "fixture `{label}`: got {hits:?}");
    }
}

#[test]
#[should_panic(expected = "virtual_clock_guard: unbalanced braces")]
fn unbalanced_test_body_panics_rather_than_passing() {
    let src = "#[tokio::test]\nasync fn t() {\n    let x = 1;\n";
    tokio_tests("fixture.rs", &scrub(src));
}

#[test]
#[should_panic(expected = "virtual_clock_guard: malformed byte literal")]
fn malformed_byte_literal_panics_rather_than_passing() {
    scrub("fn f() { let x = b'ab'; }");
}

#[test]
#[should_panic(expected = "virtual_clock_guard: tokio test with no following fn")]
fn attribute_without_fn_panics_rather_than_passing() {
    tokio_tests("fixture.rs", &scrub("#[tokio::test]\n"));
}

#[test]
#[should_panic(expected = "virtual_clock_guard: unterminated escaped char literal")]
fn unterminated_escaped_char_literal_panics_rather_than_passing() {
    scrub("fn f() { let x = '\\xZZ; }");
}
