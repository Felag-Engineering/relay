//! Structural guard for #914: a string that came off the wire must not reach a
//! journald line unescaped, because one event must stay one line (a newline in
//! a Relay-supplied `node_id` could otherwise forge a `relay_daemon::allow`
//! record). Every wire-derived log field goes through `log_field::untrusted` /
//! `untrusted_list` (Debug escaping plus a length cap).
//!
//! `clippy.toml`'s `disallowed-methods` cannot express "this field of this
//! macro must be wrapped", so this test scans every workspace `src/` for `tracing`
//! macros instead, as `policy_never_opened_for_write.rs` scans for file opens.
//!
//! # It proves
//!
//! * every field of every production `tracing` macro call that names one of
//!   the macros in `macro_re` (bare, `tracing::`- or `::tracing::`-qualified,
//!   with `()`, `[]` or `{}`) in `daemon/src` and `daemon/crates/*/src` is either
//!   wrapped in `log_field::untrusted` / `untrusted_list` (called with no `%`
//!   or `?` sigil: a sigil on a wrapped value fails deliberately), or is an
//!   exact entry in [`LOCAL_FIELDS`] keyed by (file, field, normalised
//!   expression, message literal) with an exact count. A new `error = %e` in a
//!   file that already has an allowlisted one fails, because the key or the
//!   count differs;
//! * every entry in [`LOCAL_FIELDS`] is still seen exactly `count` times, so
//!   the list cannot go stale;
//! * an argument shape the scanner does not recognise (a string-literal field
//!   name, a garbage argument) and a format argument after the message that is
//!   not wrapped both fail rather than pass;
//! * the scan sees the daemon's log sites at all (a floor), so a broken
//!   matcher cannot pass vacuously.
//!
//! # It cannot see
//!
//! * `#[tracing::instrument]` (which records function arguments as span
//!   fields) and `Span::record`;
//! * values logged through a renamed `tracing` import, a wrapper macro, or the
//!   `log` crate;
//! * `println!` / `eprintln!`: `version.rs`'s banner (local), and
//!   `policy_check.rs`'s CLI output (operator-invoked, not the journal path);
//! * `main()`'s `Result<(), Box<dyn Error>>` exit path. Rust prints
//!   `Error: {:?}` to stderr when `main` returns `Err`: that is Debug-escaped
//!   (one line) but NOT length-capped, and its errors are config/identity
//!   errors;
//! * `cfg` forms other than a bare `#[cfg(test)]`: scanned as production, so
//!   only a loud false positive;
//! * data flow. An allowlisted (file, field, expr, message) whose expression
//!   later starts holding wire data without its text changing. The `why`
//!   column is the reviewed claim, and a reviewer must check it against the
//!   call site;
//! * this lexer is an independent copy of the approach in
//!   `policy_never_opened_for_write.rs`, not shared code. A fix to one does not
//!   reach the other.

use std::collections::BTreeMap;
use std::fs;
use std::ops::Range;
use std::path::Path;

use regex::Regex;

/// A reviewed local-only field: (file, relative to `daemon/`, field, normalised
/// expression, message literal, count, why). NO wire-derived field belongs
/// here; wrap it instead.
type LocalField = (
    &'static str,
    &'static str,
    &'static str,
    &'static str,
    usize,
    &'static str,
);

const LOCAL_FIELDS: &[LocalField] = &[
    (
        "crates/relay-transport/src/enroll.rs",
        "hostname",
        "hostname",
        "already enrolled, reusing persisted identity",
        1,
        "local hostname (operator host)",
    ),
    (
        "crates/relay-transport/src/enroll.rs",
        "hostname",
        "hostname",
        "enrollment complete",
        1,
        "local hostname (operator host)",
    ),
    (
        "crates/relay-transport/src/enroll.rs",
        "hostname",
        "hostname",
        "starting enrollment",
        1,
        "local hostname (operator host)",
    ),
    (
        "crates/relay-transport/src/enroll.rs",
        "label_count",
        "label_count",
        "enrollment complete",
        1,
        "count",
    ),
    (
        "crates/relay-transport/src/enroll.rs",
        "label_count",
        "label_count",
        "starting enrollment",
        1,
        "count",
    ),
    (
        "src/main.rs",
        "cap",
        "MAX_INFLIGHT_TASKS",
        "refusing Task: daemon at in-flight backstop",
        1,
        "compile-time const",
    ),
    (
        "src/main.rs",
        "drained",
        "summary.drained",
        "graceful shutdown: in-flight Tasks drained",
        1,
        "count",
    ),
    (
        "src/main.rs",
        "error",
        "%e",
        "policy load failed; using deny-all policy (fail closed)",
        1,
        "PolicyError from the local root-owned Policy file",
    ),
    (
        "src/main.rs",
        "fingerprint",
        "%p.fingerprint()",
        "policy loaded",
        1,
        "local SHA-256 hex of the Policy file",
    ),
    (
        "src/main.rs",
        "in_flight",
        "summary.in_flight",
        "graceful shutdown: in-flight Tasks drained",
        1,
        "count",
    ),
    (
        "src/main.rs",
        "killed",
        "summary.killed",
        "graceful shutdown: in-flight Tasks drained",
        1,
        "count",
    ),
    (
        "src/main.rs",
        "path",
        "%config.policy_path.display()",
        "policy load failed; using deny-all policy (fail closed)",
        1,
        "operator-set Policy path",
    ),
    (
        "src/main.rs",
        "path",
        "%config.policy_path.display()",
        "policy loaded",
        1,
        "operator-set Policy path",
    ),
    (
        "src/main.rs",
        "reason",
        "ctx.shutdown.reason()",
        "graceful shutdown: in-flight Tasks drained",
        1,
        "static signal name from the shutdown module",
    ),
    (
        "src/main.rs",
        "relay",
        "%config.relay_addr",
        "Relay closed stream; reconnecting",
        1,
        "operator-set relay address: RELAY_ADDRESS, or the value the daemon persisted from it at enrollment (validated https, no whitespace or control characters)",
    ),
    (
        "src/main.rs",
        "relay",
        "%config.relay_addr",
        "Relay rejected stream open; will retry",
        1,
        "operator-set relay address: RELAY_ADDRESS, or the value the daemon persisted from it at enrollment (validated https, no whitespace or control characters)",
    ),
    (
        "src/main.rs",
        "relay",
        "%config.relay_addr",
        "relay-daemon starting",
        1,
        "operator-set relay address: RELAY_ADDRESS, or the value the daemon persisted from it at enrollment (validated https, no whitespace or control characters)",
    ),
    (
        "src/main.rs",
        "relay",
        "%config.relay_addr",
        "stream dropped mid-session; reconnecting",
        1,
        "operator-set relay address: RELAY_ADDRESS, or the value the daemon persisted from it at enrollment (validated https, no whitespace or control characters)",
    ),
    (
        "src/main.rs",
        "scheme",
        "%scheme",
        "endpoint scheme invalid (must be https); refusing to connect",
        1,
        "operator-set relay address scheme",
    ),
    (
        "src/main.rs",
        "unix_millis",
        "ping.unix_millis",
        "received Ping from Relay",
        1,
        "i64 from Ping; an integer cannot carry text",
    ),
    (
        "crates/relay-policy/src/lib.rs",
        "mode",
        "format!(\"{mode:#o}\")",
        "policy file is group/world-writable; refusing to load (fail closed)",
        1,
        "file mode integer",
    ),
    (
        "crates/relay-policy/src/lib.rs",
        "path",
        "%path.display()",
        "policy file is group/world-writable; refusing to load (fail closed)",
        1,
        "operator-set Policy path",
    ),
    (
        "crates/relay-policy/src/lib.rs",
        "path",
        "%path.display()",
        "policy file is not a regular file; refusing to load (fail closed)",
        1,
        "operator-set Policy path",
    ),
    (
        "crates/relay-policy/src/lib.rs",
        "path",
        "%path.display()",
        "policy file is not owned by root or the daemon euid; refusing to load (fail closed)",
        1,
        "operator-set Policy path",
    ),
    (
        "crates/relay-policy/src/lib.rs",
        "path",
        "%path.display()",
        "policy file path is a symlink; refusing to follow (fail closed)",
        1,
        "operator-set Policy path",
    ),
    (
        "crates/relay-policy/src/lib.rs",
        "uid",
        "uid",
        "policy file is not owned by root or the daemon euid; refusing to load (fail closed)",
        1,
        "file owner integer",
    ),
    (
        "crates/relay-policy/src/decision_log.rs",
        "argc",
        "f.argc",
        "policy allowed",
        1,
        "count",
    ),
    (
        "crates/relay-policy/src/decision_log.rs",
        "argc",
        "f.argc",
        "{message}",
        1,
        "count",
    ),
    (
        "crates/relay-policy/src/decision_log.rs",
        "argv_digest",
        "%f.argv_digest",
        "policy allowed",
        1,
        "local SHA-256 hex",
    ),
    (
        "crates/relay-policy/src/decision_log.rs",
        "argv_digest",
        "%f.argv_digest",
        "{message}",
        1,
        "local SHA-256 hex",
    ),
    (
        "crates/relay-policy/src/decision_log.rs",
        "message",
        "{message}",
        "{message}",
        1,
        "&'static str by the emit_deny signature",
    ),
    (
        "crates/relay-policy/src/decision_log.rs",
        "policy_fingerprint",
        "%f.policy_fingerprint",
        "policy allowed",
        1,
        "local SHA-256 hex of the Policy file",
    ),
    (
        "crates/relay-policy/src/decision_log.rs",
        "policy_fingerprint",
        "%f.policy_fingerprint",
        "{message}",
        1,
        "local SHA-256 hex of the Policy file",
    ),
    (
        "crates/relay-policy/src/decision_log.rs",
        "risk_class",
        "risk_class_str(f.risk_class)",
        "policy allowed",
        1,
        "&'static str from RiskClass",
    ),
    (
        "crates/relay-policy/src/decision_log.rs",
        "risk_class",
        "risk_class_str(f.risk_class)",
        "{message}",
        1,
        "&'static str from RiskClass",
    ),
    (
        "crates/relay-policy/src/decision_log.rs",
        "rule",
        "?rule",
        "policy allowed",
        1,
        "Rule built only after the wire name equals a Policy-file name: Policy-authored content",
    ),
    (
        "crates/relay-policy/src/decision_log.rs",
        "rule",
        "rule.map(tracing::field::debug)",
        "{message}",
        1,
        "Rule built only after the wire name equals a Policy-file name: Policy-authored content",
    ),
    (
        "crates/relay-policy/src/decision_log.rs",
        "tier",
        "f.tier.as_str()",
        "policy allowed",
        1,
        "&'static str from Tier",
    ),
    (
        "crates/relay-policy/src/decision_log.rs",
        "tier",
        "f.tier.as_str()",
        "{message}",
        1,
        "&'static str from Tier",
    ),
    (
        "src/shutdown.rs",
        "HANDLERS_INSTALLED_MSG",
        "{HANDLERS_INSTALLED_MSG}",
        "{HANDLERS_INSTALLED_MSG}",
        1,
        "const message text",
    ),
    (
        "src/shutdown.rs",
        "reason",
        "reason",
        "shutdown signal received; beginning graceful drain",
        1,
        "&'static str, \"SIGTERM\" or \"SIGINT\"",
    ),
    (
        "crates/relay-ops/src/templates.rs",
        "error",
        "%e",
        "failed to load template set; continuing with NO Template Operations (fail closed)",
        1,
        "error from local root-owned Template files",
    ),
    (
        "crates/relay-ops/src/templates.rs",
        "path",
        "%entry.path().display()",
        "template path is not valid UTF-8; skipped",
        1,
        "directory entry of the local Template root",
    ),
    (
        "crates/relay-ops/src/templates.rs",
        "path",
        "%pack_path.display()",
        "template pack contains a nested directory; not traversed (packs are one level deep)",
        1,
        "directory entry of the local Template root",
    ),
    (
        "crates/relay-ops/src/templates.rs",
        "root",
        "%root.display()",
        "failed to load template set; continuing with NO Template Operations (fail closed)",
        1,
        "operator-set Template root",
    ),
    (
        "crates/relay-ops/src/templates.rs",
        "root",
        "%root.display()",
        "loaded template set",
        1,
        "operator-set Template root",
    ),
    (
        "crates/relay-ops/src/templates.rs",
        "template_set_fingerprint",
        "%set.fingerprint()",
        "loaded template set",
        1,
        "local SHA-256 hex of the Template set",
    ),
    (
        "crates/relay-ops/src/templates.rs",
        "templates",
        "set.len()",
        "loaded template set",
        1,
        "count",
    ),
    (
        "crates/relay-transport/src/tunnel.rs",
        "relay",
        "relay",
        "Relay unreachable; will retry",
        1,
        "operator-set relay address from the EnvironmentFile",
    ),
    (
        "crates/relay-transport/src/tunnel.rs",
        "relay",
        "relay",
        "TLS handshake rejected by Relay — client cert untrusted, expired, or revoked; will retry",
        1,
        "operator-set relay address from the EnvironmentFile",
    ),
    (
        "crates/relay-transport/src/tunnel.rs",
        "relay",
        "relay",
        "connect failed; will retry",
        1,
        "operator-set relay address from the EnvironmentFile",
    ),
    (
        "crates/relay-transport/src/tunnel.rs",
        "retry_in",
        "?retry_in",
        "Relay unreachable; will retry",
        1,
        "Duration",
    ),
    (
        "crates/relay-transport/src/tunnel.rs",
        "retry_in",
        "?retry_in",
        "TLS handshake rejected by Relay — client cert untrusted, expired, or revoked; will retry",
        1,
        "Duration",
    ),
    (
        "crates/relay-transport/src/tunnel.rs",
        "retry_in",
        "?retry_in",
        "connect failed; will retry",
        1,
        "Duration",
    ),
];

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct Key {
    file: String,
    field: String,
    expr: String,
    message: String,
}

#[derive(Default)]
struct Scan {
    sites: usize,
    /// Unwrapped fields, with the 1-based line of each occurrence.
    unwrapped: BTreeMap<Key, Vec<usize>>,
    violations: Vec<String>,
}

/// Blanks every comment and the contents of every string, byte string, raw
/// string and char literal, preserving byte length and newlines so offsets and
/// line numbers match the original.
fn scrub(src: &str) -> String {
    let b = src.as_bytes();
    let n = b.len();
    let mut out = b.to_vec();
    let mut i = 0;

    fn blank(out: &mut [u8], from: usize, to: usize) {
        for byte in &mut out[from..to] {
            if *byte != b'\n' {
                *byte = b' ';
            }
        }
    }
    let is_ident = |c: u8| c.is_ascii_alphanumeric() || c == b'_';

    while i < n {
        let c = b[i];
        if c == b'/' && b.get(i + 1) == Some(&b'/') {
            let end = b[i..].iter().position(|&x| x == b'\n').map_or(n, |p| i + p);
            blank(&mut out, i, end);
            i = end;
        } else if c == b'/' && b.get(i + 1) == Some(&b'*') {
            let mut depth = 0;
            let mut j = i;
            while j < n {
                if b[j] == b'/' && b.get(j + 1) == Some(&b'*') {
                    depth += 1;
                    j += 2;
                } else if b[j] == b'*' && b.get(j + 1) == Some(&b'/') {
                    depth -= 1;
                    j += 2;
                    if depth == 0 {
                        break;
                    }
                } else {
                    j += 1;
                }
            }
            blank(&mut out, i, j);
            i = j;
        } else if matches!(c, b'r' | b'b' | b'c') && (i == 0 || !is_ident(b[i - 1])) {
            // Prefix of a raw string, byte string, C string or byte char.
            let mut j = i;
            if c != b'r' && matches!(b.get(j + 1), Some(b'"') | Some(b'\'')) {
                i += 1; // the quote is handled on the next iteration
                continue;
            }
            if c != b'r' {
                j += 1;
            }
            if b.get(j) == Some(&b'r') {
                let mut k = j + 1;
                while b.get(k) == Some(&b'#') {
                    k += 1;
                }
                let hashes = k - (j + 1);
                if b.get(k) == Some(&b'"') {
                    let mut term = vec![b'"'];
                    term.extend(std::iter::repeat_n(b'#', hashes));
                    let body = k + 1;
                    let end = b[body..]
                        .windows(term.len())
                        .position(|w| w == term.as_slice())
                        .map_or(n, |p| body + p);
                    blank(&mut out, body, end);
                    i = (end + term.len()).min(n);
                    continue;
                }
                // `r#ident` is a raw identifier: code.
            }
            i += 1;
        } else if c == b'"' {
            let mut j = i + 1;
            while j < n && b[j] != b'"' {
                j += if b[j] == b'\\' { 2 } else { 1 };
            }
            let j = j.min(n);
            blank(&mut out, i + 1, j);
            i = j + 1;
        } else if c == b'\'' {
            // Decided in chars, not bytes: `'é'` is a char literal.
            let Some(next) = src[i + 1..].chars().next() else {
                break;
            };
            if next == '\\' {
                let esc = src[i + 2..].chars().next().map_or(0, char::len_utf8);
                let start = i + 2 + esc;
                let end = b[start..]
                    .iter()
                    .position(|&x| x == b'\'')
                    .map_or(n, |p| start + p);
                blank(&mut out, i + 1, end);
                i = end + 1;
            } else if b.get(i + 1 + next.len_utf8()) == Some(&b'\'') {
                blank(&mut out, i + 1, i + 1 + next.len_utf8());
                i += next.len_utf8() + 2;
            } else {
                i += 1; // a lifetime or label
            }
        } else {
            i += 1;
        }
    }
    String::from_utf8(out).expect("blanking whole runs keeps UTF-8 valid")
}

/// Index just past the delimiter matching the opener at `open`.
fn matching_close(s: &str, open: usize) -> Option<usize> {
    let mut depth = 0usize;
    for (k, c) in s.bytes().enumerate().skip(open) {
        match c {
            b'(' | b'[' | b'{' => depth += 1,
            b')' | b']' | b'}' => {
                depth -= 1;
                if depth == 0 {
                    return Some(k + 1);
                }
            }
            _ => {}
        }
    }
    None
}

fn line_of(src: &str, offset: usize) -> usize {
    src[..offset].bytes().filter(|&c| c == b'\n').count() + 1
}

/// Ranges of `#[cfg(test)]`-governed items in scrubbed text. A file with an
/// inner `#![cfg(test)]` is all test code.
fn strip_test_items(rel: &str, scrubbed: &str) -> Vec<Range<usize>> {
    let inner = Regex::new(r"#!\[\s*cfg\s*\(\s*test\s*\)\s*\]").unwrap();
    if inner.is_match(scrubbed) {
        return std::iter::once(0..scrubbed.len()).collect();
    }
    let attr = Regex::new(r"#\[\s*cfg\s*\(\s*test\s*\)\s*\]").unwrap();
    let keyword = Regex::new(
        r"^(?:pub\s*(?:\([^)]*\)\s*)?)?(?:use|mod|fn|const|static|struct|enum|impl|trait|type|async|unsafe|extern|macro_rules)\b",
    )
    .unwrap();
    let mut ranges: Vec<Range<usize>> = Vec::new();
    for m in attr.find_iter(scrubbed) {
        if ranges.last().is_some_and(|r| m.start() < r.end) {
            continue; // inside an item already removed
        }
        let mut p = m.end();
        loop {
            p += scrubbed[p..].len() - scrubbed[p..].trim_start().len();
            if scrubbed[p..].starts_with("#[") {
                p = matching_close(scrubbed, p + 1).expect("unbalanced attribute");
            } else {
                break;
            }
        }
        assert!(
            keyword.is_match(&scrubbed[p..]),
            "{rel}:{}: cfg(test) on a non-item; extend the scanner",
            line_of(scrubbed, m.start())
        );
        let mut depth = 0usize;
        let mut end = scrubbed.len();
        for (k, c) in scrubbed.bytes().enumerate().skip(p) {
            match c {
                b';' if depth == 0 => {
                    end = k + 1;
                    break;
                }
                b'{' if depth == 0 => {
                    end = matching_close(scrubbed, k).expect("unbalanced item body");
                    break;
                }
                b'(' | b'[' | b'{' => depth += 1,
                b')' | b']' | b'}' => depth -= 1,
                _ => {}
            }
        }
        ranges.push(m.start()..end);
    }
    ranges
}

fn blanked(text: &str, ranges: &[Range<usize>]) -> String {
    let mut out = text.as_bytes().to_vec();
    for r in ranges {
        for byte in &mut out[r.clone()] {
            if *byte != b'\n' {
                *byte = b' ';
            }
        }
    }
    String::from_utf8(out).expect("blanking whole runs keeps UTF-8 valid")
}

fn scan_source(rel: &str, src: &str) -> Scan {
    let scrubbed = scrub(src);
    let removed = strip_test_items(rel, &scrubbed);
    let scrubbed = blanked(&scrubbed, &removed);
    let src = blanked(src, &removed);

    let macro_re = Regex::new(
        r"(?:^|[^A-Za-z0-9_:])(?:::)?(?:tracing::)?(?:trace|debug|info|warn|error|event|span|trace_span|debug_span|info_span|warn_span|error_span)!\s*[(\[{]",
    )
    .unwrap();
    let meta_re = Regex::new(r"^(?:target|parent|name)\s*:(?:$|[^:])").unwrap();
    let level_re = Regex::new(r"^(?:tracing::)?Level::\w+$").unwrap();
    let literal_re = Regex::new(r##"^(?:r#*)?"[ \n]*"#*$"##).unwrap();
    let field_re = Regex::new(r"^([?%])?\s*([A-Za-z_][\w.]*)\s*(?:=\s*((?s:.+)))?$").unwrap();
    let capture_re = Regex::new(r"\{([A-Za-z_]\w*)(?::[^}]*)?\}").unwrap();
    let call_re = Regex::new(r"^(?:crate::)?log_field::untrusted(?:_list)?\(").unwrap();
    let map_re =
        Regex::new(r"^[A-Za-z_][\w.]*\.map\((?:crate::)?log_field::untrusted(?:_list)?\)$")
            .unwrap();
    // Wrapped only when the call is the WHOLE expression, so a trailing
    // `.to_string()` or `+ x` does not pass.
    let is_wrapped = |expr: &str| {
        if map_re.is_match(expr) {
            return true;
        }
        let scrubbed = scrub(expr);
        call_re
            .find(&scrubbed)
            .is_some_and(|m| matching_close(&scrubbed, m.end() - 1) == Some(scrubbed.len()))
    };

    let mut scan = Scan::default();
    for m in macro_re.find_iter(&scrubbed) {
        scan.sites += 1;
        let open = m.end() - 1; // the `(`, `[` or `{`
        let site_line = line_of(&src, open);
        let Some(close) = matching_close(&scrubbed, open) else {
            scan.violations
                .push(format!("{rel}:{site_line}: unbalanced macro call"));
            continue;
        };
        // Split the body on top-level commas, as byte ranges.
        let mut args: Vec<Range<usize>> = Vec::new();
        let (mut depth, mut start) = (0usize, open + 1);
        for (k, c) in scrubbed.bytes().enumerate().take(close - 1).skip(open + 1) {
            match c {
                b'(' | b'[' | b'{' => depth += 1,
                b')' | b']' | b'}' => depth -= 1,
                b',' if depth == 0 => {
                    args.push(start..k);
                    start = k + 1;
                }
                _ => {}
            }
        }
        args.push(start..close - 1);

        // (field, normalised expr, line) for each field; (message, formats).
        let mut fields: Vec<(String, String, usize)> = Vec::new();
        let mut message: Option<String> = None;
        let mut bad = |what: &str, text: &str, line: usize| {
            scan.violations
                .push(format!("{rel}:{line}: {what}: `{}`", text.trim()));
        };
        let last = args.len() - 1;
        for (idx, r) in args.iter().enumerate() {
            let scr = scrubbed[r.clone()].trim();
            let org = src[r.clone()].trim();
            let line = line_of(
                &src,
                r.start + (src[r.clone()].len() - src[r.clone()].trim_start().len()),
            );
            let normalised: String = org.chars().filter(|c| !c.is_ascii_whitespace()).collect();
            if scr.is_empty() {
                if idx != last {
                    bad("empty argument", org, line);
                }
                continue;
            }
            if meta_re.is_match(org) || level_re.is_match(org) {
                continue;
            }
            if literal_re.is_match(scr) && message.is_none() {
                let text = &org[org.find('"').unwrap() + 1..org.rfind('"').unwrap()];
                message = Some(text.to_string());
                for cap in capture_re.captures_iter(&text.replace("{{", "").replace("}}", "")) {
                    let ident = cap[1].to_string();
                    fields.push((ident.clone(), format!("{{{ident}}}"), line));
                }
                continue;
            }
            if message.is_some() {
                if !is_wrapped(&normalised) {
                    bad("unwrapped format argument", org, line);
                }
                continue;
            }
            let Some(caps) = field_re.captures(org) else {
                bad("unrecognised argument shape", org, line);
                continue;
            };
            let sigil = caps.get(1).map_or("", |s| s.as_str());
            let name = caps[2].to_string();
            let expr = match caps.get(3) {
                Some(v) => v
                    .as_str()
                    .chars()
                    .filter(|c| !c.is_ascii_whitespace())
                    .collect(),
                None => format!("{sigil}{name}"),
            };
            fields.push((name, expr, line));
        }
        let message = message.unwrap_or_default();
        for (field, expr, line) in fields {
            if is_wrapped(&expr) {
                continue;
            }
            scan.unwrapped
                .entry(Key {
                    file: rel.to_string(),
                    field,
                    expr,
                    message: message.clone(),
                })
                .or_default()
                .push(line);
        }
    }
    scan
}

/// Every workspace `src/` root: the bin's, plus each `crates/<member>/src`, found by
/// listing the directory so a new member is walked without editing this test.
fn src_roots() -> Vec<std::path::PathBuf> {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut roots = vec![manifest.join("src")];
    let mut members: Vec<_> = fs::read_dir(manifest.join("crates"))
        .expect("read crates dir")
        .map(|e| e.expect("dir entry").path())
        .filter(|p| p.is_dir())
        .collect();
    members.sort();
    roots.extend(members.into_iter().map(|m| m.join("src")));
    roots
}

fn source_files() -> Vec<(String, String)> {
    fn walk(dir: &Path, manifest: &Path, out: &mut Vec<(String, String)>) {
        for entry in fs::read_dir(dir).expect("read src dir") {
            let path = entry.expect("dir entry").path();
            if path.is_dir() {
                walk(&path, manifest, out);
            } else if path.extension().is_some_and(|e| e == "rs") {
                let rel = path
                    .strip_prefix(manifest)
                    .unwrap()
                    .components()
                    .map(|c| c.as_os_str().to_string_lossy().into_owned())
                    .collect::<Vec<_>>()
                    .join("/");
                out.push((rel, fs::read_to_string(&path).expect("read source")));
            }
        }
    }
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut out = Vec::new();
    for root in src_roots() {
        let before = out.len();
        walk(&root, manifest, &mut out);
        assert!(
            out.len() > before,
            "{} holds no .rs file; the walk is broken",
            root.display()
        );
    }
    out.sort();
    out
}

fn scan_tree() -> (usize, usize, BTreeMap<Key, Vec<usize>>, Vec<String>) {
    let (mut sites, mut files) = (0, 0);
    let mut unwrapped: BTreeMap<Key, Vec<usize>> = BTreeMap::new();
    let mut violations = Vec::new();
    for (rel, src) in source_files() {
        let scan = scan_source(&rel, &src);
        if scan.sites > 0 {
            files += 1;
        }
        sites += scan.sites;
        for (k, lines) in scan.unwrapped {
            unwrapped.entry(k).or_default().extend(lines);
        }
        violations.extend(scan.violations);
    }
    (sites, files, unwrapped, violations)
}

#[test]
fn every_tracing_field_is_escaped_or_reviewed_local() {
    let (_, _, unwrapped, violations) = scan_tree();
    let mut failures = violations;
    for (key, lines) in &unwrapped {
        let allowed = LOCAL_FIELDS
            .iter()
            .find(|e| (e.0, e.1, e.2, e.3) == (&key.file, &key.field, &key.expr, &key.message))
            .map_or(0, |e| e.4);
        if lines.len() > allowed {
            failures.push(format!(
                "{}:{:?}: field `{}` = `{}` (message {:?}) is neither wrapped in \
                 log_field::untrusted nor an allowlisted local field ({} seen, {} allowed)",
                key.file,
                lines,
                key.field,
                key.expr,
                key.message,
                lines.len(),
                allowed
            ));
        }
    }
    assert!(
        failures.is_empty(),
        "wire-derived log fields must go through log_field::untrusted (#914):\n{}",
        failures.join("\n")
    );
}

#[test]
fn local_fields_allowlist_counts_are_exact() {
    let (_, _, unwrapped, _) = scan_tree();
    let mut stale = Vec::new();
    for (file, field, expr, message, count, _why) in LOCAL_FIELDS {
        let seen = unwrapped
            .iter()
            .find(|(k, _)| {
                (
                    k.file.as_str(),
                    k.field.as_str(),
                    k.expr.as_str(),
                    k.message.as_str(),
                ) == (*file, *field, *expr, *message)
            })
            .map_or(0, |(_, v)| v.len());
        if seen != *count {
            stale.push(format!(
                "{file}: `{field}` = `{expr}` (message {message:?}): allowlisted {count}, seen {seen}"
            ));
        }
    }
    assert!(
        stale.is_empty(),
        "stale LOCAL_FIELDS entries:\n{}",
        stale.join("\n")
    );
}

#[test]
fn scan_sees_the_daemons_log_sites() {
    let (sites, files, _, _) = scan_tree();
    assert!(
        sites >= SITE_FLOOR,
        "only {sites} log sites seen; the matcher is broken"
    );
    assert!(files >= 8, "only {files} files with log sites seen");
}

/// Today: 43 production sites in 9 files. A few below, so a broken matcher or an
/// over-eager stripper cannot pass vacuously.
const SITE_FLOOR: usize = 40;

fn recorded(src: &str) -> Vec<(String, String, String)> {
    scan_source("t.rs", src)
        .unwrapped
        .into_keys()
        .map(|k| (k.field, k.expr, k.message))
        .collect()
}

fn one(field: &str, expr: &str, message: &str) -> Vec<(String, String, String)> {
    vec![(field.into(), expr.into(), message.into())]
}

#[test]
fn scanner_fixtures() {
    // Wrapped passes; unwrapped is recorded.
    assert_eq!(
        recorded(r#"error!(received = %node_id, "x");"#),
        one("received", "%node_id", "x")
    );
    assert!(recorded(r#"error!(received = log_field::untrusted(&node_id), "x");"#).is_empty());
    assert!(recorded(r#"warn!(args = args.map(log_field::untrusted_list), "m");"#).is_empty());
    assert_eq!(
        recorded("tracing::warn!(\n task_id = ?id,\n \"m\"\n);"),
        one("task_id", "?id", "m")
    );

    // Trailing comma: two fields, a message, no empty-argument violation.
    let s = scan_source("t.rs", "warn!(\n a = ?b,\n c = 1,\n \"m\",\n);");
    assert_eq!(s.unwrapped.len(), 2);
    assert!(s.violations.is_empty(), "{:?}", s.violations);
    assert!(s.unwrapped.keys().all(|k| k.message == "m"));

    // Shorthand and inline captures.
    assert_eq!(
        recorded(r#"info!(node_id, "m");"#),
        one("node_id", "node_id", "m")
    );
    assert_eq!(
        recorded(r#"info!(%node_id, "m");"#),
        one("node_id", "%node_id", "m")
    );
    assert_eq!(
        recorded(r#"info!("{node_id}");"#),
        one("node_id", "{node_id}", "{node_id}")
    );
    assert!(recorded(r#"info!("{{x}}");"#).is_empty());

    // Format arguments after the message are never allowlisted.
    assert_eq!(
        scan_source("t.rs", r#"info!("{}", x);"#).violations.len(),
        1
    );
    assert!(
        scan_source("t.rs", r#"info!("{}", log_field::untrusted(&x));"#)
            .violations
            .is_empty()
    );

    // A format! value is a field value, never the message.
    assert_eq!(
        recorded(r#"error!(mode = format!("{mode:#o}"), "m");"#),
        one("mode", r#"format!("{mode:#o}")"#, "m")
    );

    // Fail closed on shapes the scanner does not understand.
    assert_eq!(
        scan_source("t.rs", r#"info!("some.field" = %x, "m");"#)
            .violations
            .len(),
        1
    );
    assert_eq!(
        scan_source("t.rs", r#"info!(+++, "m");"#).violations.len(),
        1
    );
    // The wrapped call must be the whole expression.
    assert_eq!(
        recorded(r#"info!(a = log_field::untrusted(&x).to_string(), "m");"#).len(),
        1
    );
    assert!(recorded(r#"info!(a = log_field::untrusted(")"), "m");"#).is_empty());

    // Path-qualified and brace/bracket macro forms are seen.
    assert_eq!(
        recorded(r#"::tracing::warn!(a = %b, "m");"#),
        one("a", "%b", "m")
    );
    assert_eq!(recorded(r#"warn!{a = %b, "m"}"#), one("a", "%b", "m"));
    assert_eq!(recorded(r#"warn![a = %b, "m"]"#), one("a", "%b", "m"));

    // A sigil on a wrapped value is not the wrapped form.
    assert_eq!(
        recorded(r#"info!(a = %log_field::untrusted(&x), "m");"#).len(),
        1
    );

    // Not seen.
    for src in [
        "// info!(x = %y)",
        "/* /* info!(x = %y) */ */",
        r#"let s = "info!(x = %y)";"#,
        r##"let s = r#"info!(x = %y)"#;"##,
        r#"eprintln!("{x}");"#,
        r#"println!("{x}");"#,
        "my_error!(x);",
    ] {
        assert_eq!(scan_source("t.rs", src).sites, 0, "{src}");
    }

    // Lifetimes, char literals and raw identifiers do not derail the lexer.
    for src in [
        r#"fn f<'a>(s: &'a str) { info!(n = %s, "m"); }"#,
        r#"let q = '"'; info!(n = %s, "m");"#,
        r#"let c = 'é'; info!(n = %s, "m");"#,
        r#"let c = '…'; info!(n = %s, "m");"#,
        r#"let c = '\''; info!(n = %s, "m");"#,
        r#"let r#type = 1; info!(n = %s, "m");"#,
        r##"let s = br#"a"b"#; info!(n = %s, "m");"##,
    ] {
        let s = scan_source("t.rs", src);
        assert_eq!(s.sites, 1, "{src}");
        assert_eq!(s.unwrapped.len(), 1, "{src}");
    }

    // cfg(test) items are removed whole; only the governed item.
    assert_eq!(
        scan_source(
            "t.rs",
            r#"#[cfg(test)] mod t { fn f() { warn!(a = %b, "m"); } }"#
        )
        .sites,
        0
    );
    assert_eq!(
        scan_source(
            "t.rs",
            "#[cfg(test)]\nuse x::y;\nfn p() { warn!(a = %b, \"m\"); }"
        )
        .sites,
        1
    );
    assert_eq!(
        scan_source(
            "t.rs",
            "#[cfg(test)]\n#[allow(dead_code)]\nconst C: &str = \"x\";\nfn p() { info!(a = %b, \"m\"); }"
        )
        .sites,
        1
    );
    assert_eq!(
        scan_source("t.rs", "#![cfg(test)]\nfn p() { info!(a = %b, \"m\"); }").sites,
        0
    );
}

#[test]
#[should_panic(expected = "cfg(test) on a non-item")]
fn cfg_test_on_a_non_item_is_a_loud_failure() {
    scan_source("t.rs", "match x { #[cfg(test)] A => {} }");
}
