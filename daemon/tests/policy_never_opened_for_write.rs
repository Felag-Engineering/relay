//! Structural guard for invariant 2 (ADR-0002): the Relay may query a Node's
//! Policy but may never modify it, and the daemon enforces that on its own
//! side by never opening the Policy file for write (#674).
//!
//! Invariant 2 today rests on two things: the `toml` dependency is compiled
//! parse-only (`Cargo.toml`: `default-features = false, features = ["parse"]`
//! — no serializer, so the daemon cannot even encode a Policy back to disk),
//! and the Relay-side oneof test (`policy_immutability_test.go`). Nothing in
//! `daemon/` asserted the daemon's OWN half: that no code path opens the
//! Policy path with a write flag. This test closes that gap by scanning
//! every workspace `src/` (`daemon/src` and `daemon/crates/*/src`) rather than using `strace` — ptrace is unavailable in the
//! hermetic `cargo test` runner and the strict-umask CI runs, and `strace`
//! only observes the paths one test run happens to exercise, not every path
//! the source admits.
//!
//! # It proves
//!
//! * no daemon code path opens or mutates a file, except the three reviewed
//!   writers (`crates/relay-transport/src/identity.rs`, `src/dedup.rs`,
//!   `src/join/env_file.rs`) and
//!   the dev-only
//!   `relay-test-support` fixtures, and none of those is a module that names
//!   the Policy path — subject to the limits below;
//! * the Policy path is named only by three non-writing modules
//!   (`src/config.rs`, `src/main.rs`, `src/selfref.rs`);
//! * the loader's open call names no write flag: the Policy loader
//!   (relay-policy's `lib.rs`) and the Template Operation loader
//!   (`crates/relay-ops/src/templates.rs`) open their files only through the shared hardened
//!   open (relay-policy's `hardened_open.rs`),
//!   whose single `OpenOptions` chain is `.read(true)` plus
//!   `O_NOFOLLOW | O_NONBLOCK` and nothing else, and none of the three modules
//!   has a write site at all.
//!
//! # It cannot see
//!
//! (a) A spawned child process rewriting `policy.toml` — including an
//!     Operation or Raw Exec Task that an operator's Policy permits. That is
//!     owned by the `selfref.rs` lint plus `ProtectSystem=strict`, by design
//!     (ADR-0021 amendment), not by this guard.
//! (b) The Policy path reaching an allowlisted writer through a new
//!     indirection — for example `main.rs` passing `config.policy_path` into
//!     an `identity` or `dedup` function. There is no data-flow analysis:
//!     [`policy_path_reaches_only_the_read_only_loader`] guarantees only that
//!     no WRITER module names the path itself.
//! (c) An `OpenOptions` that sets `append`/`create`/`truncate` from a
//!     NON-LITERAL argument without also calling `.write(..)`. These names
//!     collide with `Vec`/`String`/`DirBuilder` methods of the same name, so
//!     only a literal `true` argument is matched.
//! (d) Code under a `cfg` form other than a bare `#[cfg(test)]` (for example
//!     `cfg(any(test, ..))`). It is scanned as production, so this can only
//!     cause a loud false positive, never a silent miss.
//! (e) Macro-generated code, and writes performed through a crate that wraps
//!     a filesystem syscall. `rustix` IS a production dependency
//!     (`Cargo.toml`), but only with `features = ["process", "termios"]` — no `fs`
//!     feature, so it exposes no filesystem-write API for this guard to miss.
//!     Cargo unifies features across the whole workspace, so that holds only
//!     while NO member enables `fs` or `use-libc`; `clippy_write_ban.rs`
//!     asserts no member's rustix entry carries a `features` key;
//!     `tempfile` and `nix` are not production dependencies at all today.
//! (f) A `#[path = ".."] mod x;` pointing OUTSIDE the walked `src/`
//!     roots, or an `include!` of a file outside them — including
//!     `include!(concat!(env!("OUT_DIR"), "/relay.v1.rs"))` in relay-proto's
//!     `lib.rs`, which pulls prost's generated code in at build time and is
//!     never walked by [`source_files`], and the sanctioned
//!     `#[path = "../ban_probe.rs"]` probe modules, which sit outside `src/`
//!     and are compiled only with the `ban-probe` feature; a renamed `fs` import (`use std::fs as
//!     f; f::write(..)`); or a nested-path `use` (`use std::{fs::write}`).
//!     (A `#[cfg(test)] mod foo;` pointing at a file still inside
//!     `daemon/src` is walked as ordinary production by [`source_files`]'s
//!     directory recursion regardless of that attribute — a loud false
//!     positive if `foo.rs` has a write site, never a silent miss; it does
//!     not belong on this list.) None of these three appear in the tree
//!     today; each would be a silent miss if one were added.
//! (g) The libc/`fs::`/`use` write-pattern lists in [`patterns`] are
//!     ENUMERATED by name, not exhaustive against every current or future
//!     libc write syscall, and a numeric-literal open flag (for example
//!     `.custom_flags(0o2)` for `O_WRONLY`) is unseen — only the named
//!     `O_*` constants are matched.
//!
//! The read-only crates' `clippy.toml` write ban is the compiler-checked
//! counterpart of this lexer, and `clippy_write_ban.rs` guards that ban. This
//! file is kept whole on purpose (it still covers the bin's modules that name
//! the Policy path, and the pinned open chain); shrinking it is a follow-up.
//!
//! Its counterpart on the Relay side proving the secrets-in-logs half of the
//! same audit gap is `relay/internal/accounts/secret_logging_guard_test.go`.

use regex::Regex;
use std::collections::BTreeMap;
use std::ops::Range;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

// ---------------------------------------------------------------------------
// scrub: a byte-length-preserving lexer that blanks the CONTENTS of comments
// and literals, keeping every delimiter (quotes, comment markers, raw-string
// openers/closers) as code.
// ---------------------------------------------------------------------------

/// Blanks `c` into `out`: a newline stays a newline (so line numbers survive
/// scrubbing), anything else becomes `c.len_utf8()` ASCII spaces (so byte
/// offsets survive scrubbing even across a multi-byte char).
fn push_blanked(out: &mut String, c: char) {
    if c == '\n' {
        out.push('\n');
    } else {
        for _ in 0..c.len_utf8() {
            out.push(' ');
        }
    }
}

/// Consumes a `delim`-delimited literal with backslash escapes, starting at
/// `chars[i] == delim`. Used for plain/byte/C strings and for a char
/// literal's escape form (`delim == '\''`). Escapes are handled as a single
/// "blank this pair" step: correct for distinguishing an escaped delimiter
/// from a real terminator without understanding every escape form, and safe
/// because nothing inside an escape sequence (hex digits, `{`, `}`) is a
/// delimiter or a backslash itself.
fn consume_quoted(chars: &[char], mut i: usize, delim: char, out: &mut String) -> usize {
    let n = chars.len();
    out.push(delim);
    i += 1;
    while i < n {
        let c = chars[i];
        if c == '\\' && i + 1 < n {
            push_blanked(out, c);
            push_blanked(out, chars[i + 1]);
            i += 2;
            continue;
        }
        if c == delim {
            out.push(delim);
            i += 1;
            break;
        }
        push_blanked(out, c);
        i += 1;
    }
    i
}

/// Consumes a char literal or byte-char literal, starting at `chars[i] ==
/// '\''`, distinguishing an escape (`'\''`, `'\n'`, `'\u{7B}'`) from a
/// one-char literal (`'{'`, `'é'` — char-wise, not byte-wise, so a
/// multi-byte char works) from — when `allow_lifetime` is true — a lifetime
/// or loop label (`'a`, `'static`, `'outer:`), which is code, not a literal,
/// and is therefore emitted unblanked.
fn consume_char_like(chars: &[char], i: usize, out: &mut String, allow_lifetime: bool) -> usize {
    let n = chars.len();
    if chars.get(i + 1) == Some(&'\\') {
        return consume_quoted(chars, i, '\'', out);
    }
    if i + 1 < n && chars.get(i + 2) == Some(&'\'') {
        out.push('\'');
        push_blanked(out, chars[i + 1]);
        out.push('\'');
        return i + 3;
    }
    if allow_lifetime {
        out.push('\'');
        let mut j = i + 1;
        while j < n && (chars[j].is_alphanumeric() || chars[j] == '_') {
            out.push(chars[j]);
            j += 1;
        }
        if j < n && chars[j] == ':' {
            out.push(':');
            j += 1;
        }
        return j;
    }
    // Malformed byte-char fallback (not valid Rust): emit the quote and
    // advance by one rather than loop forever.
    out.push('\'');
    i + 1
}

/// Consumes a raw string's content and closing delimiter, starting right at
/// the opening `"` (`chars[i] == '"'`), given `hashes` — the number of `#`
/// the opener carried. Closes at the first `"` followed by AT LEAST `hashes`
/// `#` characters (Rust's own rule); a `"` followed by fewer does not close
/// it and is blanked as content, so `r##"..."#..."##` does not close early on
/// the inner single-hash occurrence.
fn consume_raw_string(chars: &[char], mut i: usize, hashes: usize, out: &mut String) -> usize {
    let n = chars.len();
    out.push('"');
    i += 1;
    while i < n {
        if chars[i] == '"' {
            let mut run = 0usize;
            while i + 1 + run < n && chars[i + 1 + run] == '#' {
                run += 1;
            }
            if run >= hashes {
                out.push('"');
                for _ in 0..hashes {
                    out.push('#');
                }
                return i + 1 + hashes;
            }
            push_blanked(out, '"');
            for _ in 0..run {
                push_blanked(out, '#');
            }
            i += 1 + run;
            continue;
        }
        push_blanked(out, chars[i]);
        i += 1;
    }
    i
}

/// Blanks the CONTENTS of every comment and literal in `src`, keeping every
/// delimiter as code and preserving `src`'s exact byte length (asserted at
/// the end) so every byte offset into the result lines up with `src`.
///
/// A raw-string prefix (`r`, `b`, `c`, `br`, `cr`) is recognized only at an
/// identifier boundary — which "maximal munch" identifier reading gives for
/// free: an identifier is always read to its full extent before being
/// compared against the prefix set, so `b1010` (a binary-literal-looking
/// token) or `br` used as a plain variable name never gets treated as a
/// prefix mid-token. A raw string additionally requires the run of `#` after
/// the prefix to be followed by `"` — otherwise it is code, which is what
/// keeps `r#type` (a raw identifier; production code, `templates.rs`) from
/// being misread as opening a raw string that runs to the next quote-hash
/// sequence and silently blanking real code. (An identifier ending in
/// `r`/`b`/`c` immediately followed by a quote, with no operator or
/// whitespace between them, is not valid Rust outside these prefix forms, so
/// there is no ambiguity left once maximal munch and the trailing-quote
/// check are both applied.)
fn scrub(src: &str) -> String {
    let chars: Vec<char> = src.chars().collect();
    let n = chars.len();
    let mut out = String::with_capacity(src.len());
    let mut i = 0usize;

    while i < n {
        let c = chars[i];

        // Line comment (including `///` and `//!` doc comments).
        if c == '/' && chars.get(i + 1) == Some(&'/') {
            out.push('/');
            out.push('/');
            i += 2;
            while i < n && chars[i] != '\n' {
                push_blanked(&mut out, chars[i]);
                i += 1;
            }
            continue;
        }

        // Block comment, with nesting.
        if c == '/' && chars.get(i + 1) == Some(&'*') {
            out.push('/');
            out.push('*');
            i += 2;
            let mut depth = 1i32;
            while i < n && depth > 0 {
                if chars[i] == '/' && chars.get(i + 1) == Some(&'*') {
                    out.push('/');
                    out.push('*');
                    depth += 1;
                    i += 2;
                } else if chars[i] == '*' && chars.get(i + 1) == Some(&'/') {
                    out.push('*');
                    out.push('/');
                    depth -= 1;
                    i += 2;
                } else {
                    push_blanked(&mut out, chars[i]);
                    i += 1;
                }
            }
            continue;
        }

        // Plain string literal.
        if c == '"' {
            i = consume_quoted(&chars, i, '"', &mut out);
            continue;
        }

        // Char literal, byte char (handled via the "b" prefix below), or a
        // lifetime/loop label.
        if c == '\'' {
            i = consume_char_like(&chars, i, &mut out, true);
            continue;
        }

        // Identifier, read to its full extent (maximal munch), then checked
        // against the string-prefix set.
        if c.is_alphabetic() || c == '_' {
            let start = i;
            let mut j = i;
            while j < n && (chars[j].is_alphanumeric() || chars[j] == '_') {
                j += 1;
            }
            let ident: String = chars[start..j].iter().collect();

            match ident.as_str() {
                "b" if chars.get(j) == Some(&'"') => {
                    out.push('b');
                    i = consume_quoted(&chars, j, '"', &mut out);
                    continue;
                }
                "b" if chars.get(j) == Some(&'\'') => {
                    out.push('b');
                    i = consume_char_like(&chars, j, &mut out, false);
                    continue;
                }
                "c" if chars.get(j) == Some(&'"') => {
                    out.push('c');
                    i = consume_quoted(&chars, j, '"', &mut out);
                    continue;
                }
                "r" | "br" | "cr" => {
                    let mut k = j;
                    let mut hashes = 0usize;
                    while k < n && chars[k] == '#' {
                        hashes += 1;
                        k += 1;
                    }
                    if chars.get(k) == Some(&'"') {
                        for ch in ident.chars() {
                            out.push(ch);
                        }
                        for _ in 0..hashes {
                            out.push('#');
                        }
                        i = consume_raw_string(&chars, k, hashes, &mut out);
                        continue;
                    }
                    // Not a raw string: fall through and emit the identifier
                    // as ordinary code (covers `r#type`, a raw identifier —
                    // "r" is emitted here, and the following "#type" is
                    // scanned as ordinary code on the next iterations).
                    for ch in ident.chars() {
                        out.push(ch);
                    }
                    i = j;
                    continue;
                }
                _ => {
                    for ch in ident.chars() {
                        out.push(ch);
                    }
                    i = j;
                    continue;
                }
            }
        }

        // Ordinary code: whitespace, punctuation, digits, operators.
        out.push(c);
        i += 1;
    }

    debug_assert_eq!(
        out.len(),
        src.len(),
        "scrub must preserve byte length exactly"
    );
    out
}

// ---------------------------------------------------------------------------
// strip_test_items: computes the KEPT (production) byte spans of a scrubbed
// file, dropping every #[cfg(test)]-governed item and skipping a whole file
// carrying #![cfg(test)].
// ---------------------------------------------------------------------------

fn skip_ws(bytes: &[u8], mut pos: usize) -> usize {
    while pos < bytes.len() && bytes[pos].is_ascii_whitespace() {
        pos += 1;
    }
    pos
}

/// Consumes one bracketed span starting at `bytes[open_pos] == b'['`,
/// tracking `[`/`]` depth so a span containing its own nested brackets (for
/// example an attribute whose value is an array literal, `#[my_attr(list =
/// [1, 2, 3])]` — though none appear before a `#[cfg(test)]` in this tree
/// today) is skipped whole. Returns the position just past the matching `]`.
fn skip_bracketed(bytes: &[u8], open_pos: usize) -> usize {
    let mut i = open_pos;
    let mut depth = 0i32;
    while i < bytes.len() {
        let b = bytes[i];
        i += 1;
        match b {
            b'[' => depth += 1,
            b']' => {
                depth -= 1;
                if depth == 0 {
                    break;
                }
            }
            _ => {}
        }
    }
    i
}

/// Consumes one `#[...]` outer attribute starting at `bytes[pos] == b'#'`.
fn skip_one_attribute(bytes: &[u8], pos: usize) -> usize {
    skip_bracketed(bytes, pos + 1) // pos + 1 is '['
}

/// Consumes one `#![...]` inner attribute starting at `bytes[pos] == b'#'`.
fn skip_one_inner_attribute(bytes: &[u8], pos: usize) -> usize {
    skip_bracketed(bytes, pos + 2) // pos + 2 is '[', past the '!'
}

/// Reports whether `scrubbed[0..up_to]` consists ONLY of whitespace, comment
/// shells (already blanked by [`scrub`] to their delimiters plus interior
/// spaces), and `#![...]` inner attributes — the only preamble that makes a
/// `#![cfg(test)]` found there a CRATE-level, whole-file marker (review
/// non-blocking item 1). Without this anchor, `#![cfg(test)]` appearing
/// anywhere in a file — for example as a module's own inner attribute,
/// `mod tests { #![cfg(test)] .. }`, itself nested inside otherwise
/// production code — would incorrectly skip the WHOLE file as test-only,
/// hiding every production write site in it. That shape does not exist in
/// the tree today; anchoring to the preamble turns it into a correctly
/// scanned file instead of a silent whole-file miss.
fn is_preamble(scrubbed: &str, up_to: usize) -> bool {
    let bytes = scrubbed.as_bytes();
    let mut i = 0usize;
    while i < up_to {
        match bytes[i] {
            b' ' | b'\t' | b'\r' | b'\n' => i += 1,
            b'/' if bytes.get(i + 1) == Some(&b'/') => {
                i += 2;
                while i < up_to && bytes[i] != b'\n' {
                    i += 1;
                }
            }
            b'/' if bytes.get(i + 1) == Some(&b'*') => {
                i += 2;
                let mut depth = 1i32;
                while i + 1 < up_to && depth > 0 {
                    if bytes[i] == b'/' && bytes.get(i + 1) == Some(&b'*') {
                        depth += 1;
                        i += 2;
                    } else if bytes[i] == b'*' && bytes.get(i + 1) == Some(&b'/') {
                        depth -= 1;
                        i += 2;
                    } else {
                        i += 1;
                    }
                }
            }
            b'#' if bytes.get(i + 1) == Some(&b'!') && bytes.get(i + 2) == Some(&b'[') => {
                i = skip_one_inner_attribute(bytes, i);
            }
            _ => return false,
        }
    }
    true
}

/// Consumes one parenthesized span starting at `bytes[open_pos] == b'('`,
/// tracking `(`/`)` depth. Returns the position just past the matching `)`.
/// Used only for a `pub(..)` visibility modifier (`pub(crate)`, `pub(super)`,
/// `pub(in some::path)`).
fn skip_parens(bytes: &[u8], open_pos: usize) -> usize {
    let mut i = open_pos;
    let mut depth = 0i32;
    while i < bytes.len() {
        let b = bytes[i];
        i += 1;
        match b {
            b'(' => depth += 1,
            b')' => {
                depth -= 1;
                if depth == 0 {
                    break;
                }
            }
            _ => {}
        }
    }
    i
}

/// Reads one ASCII word (`[A-Za-z0-9_]+`) starting at `bytes[pos]`, returning
/// it and the position just past it. Every item-leading keyword is ASCII, so
/// a word starting mid multi-byte character (which never happens here, since
/// `pos` always sits on a byte [`skip_ws`] or a keyword match left it on) or
/// containing none of those bytes reads as `""` and matches nothing in
/// [`looks_like_item_start`].
fn read_word(bytes: &[u8], pos: usize) -> (&str, usize) {
    let start = pos;
    let mut p = pos;
    while p < bytes.len() && (bytes[p].is_ascii_alphanumeric() || bytes[p] == b'_') {
        p += 1;
    }
    (
        std::str::from_utf8(&bytes[start..p]).expect("ASCII word is always valid UTF-8"),
        p,
    )
}

/// Reports whether the governed text starting at `bytes[pos]` — right after
/// a `#[cfg(test)]` and any further attributes have been skipped — begins
/// with a Rust item's leading keyword: optionally `pub` or `pub(..)`, then
/// one of `mod`, `fn`, `async`, `const`, `unsafe`, `extern`, `use`, `impl`,
/// `struct`, `enum`, `union`, `trait`, `type`, `static`, or `macro_rules!`.
///
/// This is the PRIMARY defense (code review, cycle 2 BLOCKING) against a
/// `#[cfg(test)]` attached to something that is not a whole item — a match
/// arm, an enum variant, a struct field, a struct-expression field, or a fn
/// parameter — every one of which fails this check and is rejected here,
/// before [`scan_item_end`] ever runs, regardless of whether the shape
/// happens to drive `scan_item_end`'s own depth count negative.
fn looks_like_item_start(bytes: &[u8], pos: usize) -> bool {
    let (first, first_end) = read_word(bytes, pos);
    let (word, next) = if first == "pub" {
        let mut p = skip_ws(bytes, first_end);
        if p < bytes.len() && bytes[p] == b'(' {
            p = skip_ws(bytes, skip_parens(bytes, p));
        }
        read_word(bytes, p)
    } else {
        (first, first_end)
    };

    match word {
        "mod" | "fn" | "async" | "const" | "unsafe" | "extern" | "use" | "impl" | "struct"
        | "enum" | "union" | "trait" | "type" | "static" => true,
        "macro_rules" => bytes.get(next) == Some(&b'!'),
        _ => false,
    }
}

/// Scans forward from an item's first token, tracking `{}()[]` depth, and
/// returns the position just past the end of the item: a `;` at depth 0 (a
/// `use` statement, a unit struct, ...) or a `}` that brings depth back to 0
/// (a fn/mod/impl body). Safe to run directly on the SCRUBBED text because
/// string/comment content is already blanked to spaces — a TOML fixture
/// string containing a stray `{` cannot desynchronize this count.
///
/// The PRIMARY defense against a `#[cfg(test)]` attached to something that is
/// not a whole item is [`looks_like_item_start`], called by
/// `strip_test_items` BEFORE this function ever runs — not the depth assert
/// below. A match arm followed by a braced sibling arm (`match x {
/// #[cfg(test)] 0 => g(), _ => { std::fs::write(p, b); } }`), an enum
/// variant followed by a struct-like variant, or a struct-expression field
/// followed by a block-valued field all balance depth back to exactly 0 at
/// the WRONG (but validly balanced) point instead of ever going negative, so
/// this assert alone would silently accept the wrong span for any of them
/// (code review, cycle 2 BLOCKING) — it does not cover those shapes.
///
/// Panics if `depth` ever goes negative: that still catches whatever shape
/// DOES drive it negative directly — for example a struct field whose own
/// enclosing `}` closes before this scan has opened any nested brace of its
/// own. Continuing past that point would scan into the NEXT real item and
/// could silently consume its closing delimiter, stripping a production
/// write site as if it were test-only. Panicking turns that into a loud test
/// failure instead of a silent false negative; kept as a second line of
/// defense alongside `looks_like_item_start`, not the only one.
fn scan_item_end(bytes: &[u8], start: usize) -> usize {
    let mut depth = 0i32;
    let mut i = start;
    while i < bytes.len() {
        match bytes[i] {
            b'{' | b'(' | b'[' => depth += 1,
            b'}' | b')' | b']' => {
                depth -= 1;
                assert!(
                    depth >= 0,
                    "#[cfg(test)] on a non-item at byte {start} (a `{}` at byte {i} brought \
                     depth below zero) — this attribute is not on a struct/enum item, a `use` \
                     statement, or a fn/mod/impl body (for example a struct field, an enum \
                     variant, or a fn parameter); extend strip_test_items to recognize the \
                     enclosing item instead of silently scanning past its end",
                    bytes[i] as char
                );
                if depth == 0 && bytes[i] == b'}' {
                    return i + 1;
                }
            }
            b';' if depth == 0 => return i + 1,
            _ => {}
        }
        i += 1;
    }
    bytes.len()
}

/// Subtracts `removed` (merged first) from `[0, len)`, returning what
/// remains: the KEPT (production) spans.
fn kept_from_removed(len: usize, mut removed: Vec<Range<usize>>) -> Vec<Range<usize>> {
    removed.sort_by_key(|r| r.start);
    let mut merged: Vec<Range<usize>> = Vec::new();
    for r in removed {
        if let Some(last) = merged.last_mut() {
            if r.start <= last.end {
                last.end = last.end.max(r.end);
                continue;
            }
        }
        merged.push(r);
    }

    let mut kept = Vec::new();
    let mut cursor = 0;
    for r in merged {
        if r.start > cursor {
            kept.push(cursor..r.start);
        }
        cursor = cursor.max(r.end);
    }
    if cursor < len {
        kept.push(cursor..len);
    }
    kept
}

/// Returns the KEPT (production) byte spans of `scrubbed`, or `None` when the
/// file carries a crate-level `#![cfg(test)]` (today only `catalog.rs`) and
/// is skipped whole. "Crate-level" means the `#![cfg(test)]` is found in the
/// file's PREAMBLE — nothing but whitespace, comments, and other `#![...]`
/// inner attributes before it ([`is_preamble`]) — not merely anywhere in the
/// file; otherwise a module's own inner attribute deep in an otherwise
/// production file would incorrectly skip the whole file (review
/// non-blocking item 1).
///
/// Several files have MULTIPLE `#[cfg(test)]` blocks with production code
/// after them (`policy.rs` has six, `identity.rs` four, `templates.rs`
/// three), so this finds every occurrence rather than stopping at the first.
/// Only the bare `#[cfg(test)]` form is recognized; `cfg(any(test, ..))` or
/// `cfg(all(..))` is left alone and scanned as production — a loud false
/// positive if one is ever added, never a silent miss (none exist today).
fn strip_test_items(scrubbed: &str) -> Option<Vec<Range<usize>>> {
    static INNER_CFG_TEST: OnceLock<Regex> = OnceLock::new();
    let inner_re =
        INNER_CFG_TEST.get_or_init(|| Regex::new(r"#!\[\s*cfg\s*\(\s*test\s*\)\s*\]").unwrap());
    if let Some(m) = inner_re.find(scrubbed) {
        if is_preamble(scrubbed, m.start()) {
            return None;
        }
    }

    static OUTER_CFG_TEST: OnceLock<Regex> = OnceLock::new();
    let outer_re =
        OUTER_CFG_TEST.get_or_init(|| Regex::new(r"#\[\s*cfg\s*\(\s*test\s*\)\s*\]").unwrap());

    let bytes = scrubbed.as_bytes();
    let len = bytes.len();
    let mut removed: Vec<Range<usize>> = Vec::new();

    for m in outer_re.find_iter(scrubbed) {
        let attr_start = m.start();
        let mut cursor = m.end();
        loop {
            cursor = skip_ws(bytes, cursor);
            if cursor + 1 < len && bytes[cursor] == b'#' && bytes[cursor + 1] == b'[' {
                cursor = skip_one_attribute(bytes, cursor);
            } else {
                break;
            }
        }
        let item_start = skip_ws(bytes, cursor);
        assert!(
            looks_like_item_start(bytes, item_start),
            "#[cfg(test)] on a non-item at byte {attr_start} (the governed text at byte \
             {item_start} does not begin with an item keyword) — this attribute is not on a \
             struct/enum item, a `use` statement, or a fn/mod/impl body (for example a match \
             arm, an enum variant, a struct field, a struct-expression field, or a fn \
             parameter); extend strip_test_items to recognize the enclosing item instead of \
             silently scanning past its end"
        );
        let item_end = scan_item_end(bytes, item_start);
        removed.push(attr_start..item_end);
    }

    Some(kept_from_removed(len, removed))
}

/// Replaces every byte outside `kept` with an ASCII space (newlines kept, so
/// line numbers survive), leaving `kept` untouched. Applied to both the
/// scrubbed and the original text with the SAME spans — sound because span
/// boundaries always sit on ASCII structural bytes (`#`, `[`, `]`, `;`,
/// `{`, `}`, whitespace), which `scrub` never changes the position or byte
/// count of, and a multi-byte char is blanked whole or not at all.
fn mask(text: &str, kept: &[Range<usize>]) -> String {
    let bytes = text.as_bytes();
    let mut out = bytes.to_vec();
    let mut is_kept = vec![false; bytes.len()];
    for r in kept {
        for i in r.clone() {
            if i < is_kept.len() {
                is_kept[i] = true;
            }
        }
    }
    for (i, b) in out.iter_mut().enumerate() {
        if !is_kept[i] && *b != b'\n' {
            *b = b' ';
        }
    }
    String::from_utf8(out).expect(
        "mask: replacing non-kept bytes with ASCII spaces must preserve UTF-8 validity, \
         because span boundaries sit on ASCII bytes and a multi-byte char is blanked whole",
    )
}

// ---------------------------------------------------------------------------
// write_sites: the write-pattern catalogue.
// ---------------------------------------------------------------------------

fn line_of(text: &str, byte_offset: usize) -> usize {
    text.as_bytes()[..byte_offset]
        .iter()
        .filter(|&&b| b == b'\n')
        .count()
        + 1
}

struct Pattern {
    name: &'static str,
    re: Regex,
}

/// Every pattern here has zero production hits outside the pinned allowlist
/// today (verified by reading, and by [`production_write_sites_are_exactly_the_allowlist`]
/// against the real tree). Patterns are deliberately widened where there is
/// no name collision (`.write(<any>)`, the libc mutators, chown,
/// `.set_permissions(`, the `std::os::unix::fs`/`libc` imports) and kept
/// literal-only where there is one (`append`/`create`/`create_new`/
/// `truncate`, which collide with `Vec`/`String`/`DirBuilder` methods of the
/// same name).
fn patterns() -> &'static Vec<Pattern> {
    static PATTERNS: OnceLock<Vec<Pattern>> = OnceLock::new();
    PATTERNS.get_or_init(|| {
        let p = |name: &'static str, pat: &str| Pattern {
            name,
            re: Regex::new(pat).unwrap_or_else(|e| panic!("bad pattern {name:?}: {e}")),
        };
        vec![
            p(
                ".append(true)",
                r"\.append\(\s*true\s*\)",
            ),
            p(
                ".create(true)",
                r"\.create\(\s*true\s*\)",
            ),
            p(
                ".create_new(true)",
                r"\.create_new\(\s*true\s*\)",
            ),
            p(
                ".truncate(true)",
                r"\.truncate\(\s*true\s*\)",
            ),
            p(
                "raw open flag O_*",
                r"\bO_(WRONLY|RDWR|CREAT|TRUNC|APPEND|TMPFILE)\b",
            ),
            p(
                "libc write/mutate call",
                r"\blibc::(open|openat|openat2|creat|write|pwrite|writev|unlink|unlinkat|rename|renameat|renameat2|mkdir|mkdirat|mkfifo|mkfifoat|mknod|mknodat|chmod|fchmod|fchmodat|chown|fchown|lchown|fchownat|truncate|ftruncate|link|linkat|symlink|symlinkat|remove|rmdir|fallocate|syscall)(64)?\b",
            ),
            p("File::create(_new)", r"\bFile::create(_new)?\("),
            p(
                "fs:: path writer",
                r"\bfs::(write|rename|copy|remove_file|remove_dir|remove_dir_all|create_dir|create_dir_all|set_permissions|hard_link|symlink|soft_link|chown|lchown|fchown)\(",
            ),
            p("DirBuilder::new(", r"\bDirBuilder::new\("),
            p(".set_len(", r"\.set_len\("),
            p(".set_permissions(", r"\.set_permissions\("),
            p(
                "use std/tokio fs writer import",
                r"use\s+(std|tokio)::(os::unix::)?fs::[^;]*\b(write|rename|copy|remove_file|remove_dir|remove_dir_all|create_dir|create_dir_all|set_permissions|hard_link|symlink|soft_link|chown|lchown|fchown)\b",
            ),
            p(
                "use libc writer import",
                r"use\s+libc::[^;]*\b(open|openat|openat2|creat|write|pwrite|writev|unlink|unlinkat|rename|renameat|renameat2|mkdir|mkdirat|mkfifo|mkfifoat|mknod|mknodat|chmod|fchmod|fchmodat|chown|fchown|lchown|fchownat|truncate|ftruncate|link|linkat|symlink|symlinkat|remove|rmdir|fallocate|syscall)(64)?\b",
            ),
        ]
    })
}

/// The `.write(` pattern is separate from [`patterns`] because it alone needs
/// its argument inspected: it fires for ANY non-empty argument (`true`, a
/// variable, an expression — `.write(buf)` on an `io::Write` handle is
/// intended to fire too) except the literal `false`. An empty `.write()`
/// (`RwLock::write`) never matches at all, because the pattern requires at
/// least one non-space, non-close-paren character before the close paren.
fn write_arg_pattern() -> &'static Regex {
    static WRITE_ARG: OnceLock<Regex> = OnceLock::new();
    WRITE_ARG.get_or_init(|| Regex::new(r"\.write\(\s*([^)\s][^)]*)\)").unwrap())
}

/// Scans `text` (production, scrubbed source) for every write pattern,
/// returning `(line, pattern name)` for each hit with whitespace-tolerant
/// matching so a multi-line `OpenOptions` chain is caught on the line its
/// `.write(true)` (or equivalent) call sits on.
fn write_sites(text: &str) -> Vec<(usize, &'static str)> {
    let mut hits: Vec<(usize, &'static str)> = Vec::new();

    for caps in write_arg_pattern().captures_iter(text) {
        let arg = caps.get(1).unwrap().as_str().trim();
        if arg == "false" {
            continue;
        }
        let m = caps.get(0).unwrap();
        hits.push((line_of(text, m.start()), ".write(<non-literal-false>)"));
    }

    for pat in patterns() {
        for m in pat.re.find_iter(text) {
            hits.push((line_of(text, m.start()), pat.name));
        }
    }

    hits.sort();
    hits.dedup();
    hits
}

// ---------------------------------------------------------------------------
// File walking / pipeline
// ---------------------------------------------------------------------------

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

struct FileView {
    /// Path relative to `daemon/`, forward-slash (e.g. `"src/main.rs"`,
    /// `"crates/relay-policy/src/lib.rs"`).
    rel: String,
    prod_scrubbed: String,
    prod_original: String,
}

/// The `src/` roots this guard walks: the bin's, and every workspace member's
/// `crates/<member>/src`, found by listing `crates/` so a new member is walked
/// without editing this test (#889).
fn src_roots(manifest: &Path) -> Vec<PathBuf> {
    let mut members: Vec<PathBuf> = std::fs::read_dir(manifest.join("crates"))
        .expect("read daemon/crates")
        .map(|e| e.expect("dir entry").path())
        .filter(|p| p.is_dir())
        .collect();
    members.sort();
    let mut roots = vec![manifest.join("src")];
    roots.extend(members.into_iter().map(|m| m.join("src")));
    roots
}

/// Walks every workspace `src/` root, scrubbing and stripping every file, and
/// skipping a file that is test-only (`#![cfg(test)]`, today only `catalog.rs`).
fn daemon_src_files() -> Vec<FileView> {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let mut paths = Vec::new();
    for dir in src_roots(&root) {
        let before = paths.len();
        source_files(&dir, &mut paths);
        assert!(
            paths.len() > before,
            "{} holds no .rs file — the walk is broken",
            dir.display()
        );
    }
    paths.sort();

    let mut views = Vec::new();
    for path in paths {
        let original = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
        let scrubbed = scrub(&original);
        let Some(kept) = strip_test_items(&scrubbed) else {
            continue;
        };
        let prod_scrubbed = mask(&scrubbed, &kept);
        let prod_original = mask(&original, &kept);
        let rel = path
            .strip_prefix(&root)
            .unwrap_or(&path)
            .to_string_lossy()
            .replace('\\', "/");
        views.push(FileView {
            rel,
            prod_scrubbed,
            prod_original,
        });
    }
    views
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// The modules that open or name the Policy file must never write to the
/// filesystem: relay-policy's `lib.rs` (`load_policy`, the Policy file's loader),
/// its `hardened_open.rs` (`open_hardened`, the one open `load_policy` goes
/// through — `.read(true)` plus `custom_flags(O_NOFOLLOW|O_NONBLOCK)`, pinned
/// by [`trust_files_open_only_through_the_read_only_hardened_open`]),
/// `templates.rs` (Template Operation files, the same locally-rooted trust
/// root beside `policy.toml` and the other caller of that open),
/// `policy_check.rs` (reads the Policy file under check with
/// `read_to_string`), and `config.rs`, `main.rs`, `selfref.rs` (the only
/// modules that name the Policy path).
#[test]
fn policy_modules_never_write() {
    let targets = [
        "crates/relay-policy/src/lib.rs",
        "crates/relay-policy/src/hardened_open.rs",
        "crates/relay-policy/src/decision_log.rs",
        "crates/relay-policy/src/model.rs",
        "crates/relay-policy/src/natives.rs",
        "crates/relay-ops/src/templates.rs",
        "src/policy_check.rs",
        "src/config.rs",
        "src/selfref.rs",
        "src/main.rs",
    ];
    let views = daemon_src_files();

    let mut checked = 0;
    let mut failures = Vec::new();
    for view in &views {
        if !targets.contains(&view.rel.as_str()) {
            continue;
        }
        checked += 1;
        for (line, pattern) in write_sites(&view.prod_scrubbed) {
            failures.push(format!("  {}:{line}: {pattern}", view.rel));
        }
    }
    assert_eq!(
        checked,
        targets.len(),
        "expected to find all of {targets:?} under daemon/, found {checked} — the guard must \
         actually inspect the modules it claims to"
    );

    assert!(
        failures.is_empty(),
        "invariant 2 (ADR-0002): the Relay may query a Node's Policy but may never modify it, \
         and these daemon modules must never write to the filesystem — a write-site pattern \
         matched:\n{}",
        failures.join("\n")
    );
}

/// The set of `src/`-relative files with at least one production write site
/// must equal this pinned allowlist, checked in both directions — following
/// `TestPlaintext_RevealCallSitesAreEnumerated`
/// (`relay/internal/accounts/tokens_test.go`). A new write site anywhere else
/// fails with a message naming what to do about it; a stale allowlist entry
/// also fails, because it would stop guarding anything.
#[test]
fn production_write_sites_are_exactly_the_allowlist() {
    let allowlist: BTreeMap<&str, &str> = BTreeMap::from([
        (
            "crates/relay-transport/src/identity.rs",
            "the mTLS key/cert write, rename and DirBuilder — persist_identity/write_atomic \
             (ADR-0006)",
        ),
        (
            "src/dedup.rs",
            "the at-most-once marker store — DedupStore::open/record (ADR-0004)",
        ),
        (
            "src/join/env_file.rs",
            "`relay-daemon join` replacing the environment file — write_atomically, a \
             temporary file renamed over it, and removing its own stale temporaries (DI-37)",
        ),
        (
            "crates/relay-test-support/src/lib.rs",
            "dev-only fixtures; never a normal dependency (tests/clippy_write_ban.rs)",
        ),
    ]);

    let views = daemon_src_files();
    let mut with_sites: BTreeMap<String, Vec<(usize, &'static str)>> = BTreeMap::new();
    for view in &views {
        let sites = write_sites(&view.prod_scrubbed);
        if !sites.is_empty() {
            with_sites.insert(view.rel.clone(), sites);
        }
    }

    for (file, sites) in &with_sites {
        if !allowlist.contains_key(file.as_str()) {
            let detail = sites
                .iter()
                .map(|(l, p)| format!("  {file}:{l}: {p}"))
                .collect::<Vec<_>>()
                .join("\n");
            panic!(
                "{file} has a write site that is not in the pinned allowlist — a new write \
                 site is a place the Policy path could be handed to; review it against \
                 invariant 2 (ADR-0002), then add it to the allowlist here with a reason:\n{detail}"
            );
        }
    }
    for (file, reason) in &allowlist {
        assert!(
            with_sites.contains_key(*file),
            "{file} is in the write-site allowlist ({reason:?}) but has no detected write site \
             — a stale entry stops guarding anything"
        );
    }
}

/// (i) The files whose production text names the Policy path must be exactly
/// `{src/config.rs, src/main.rs, src/selfref.rs}`: the identifier `policy_path` in the
/// scrubbed text, or the literal `"RELAY_POLICY_PATH"` in the original text
/// (scrub blanks string contents, so the scrubbed text can never show it).
/// `selfref.rs` uses the path only as a probe STRING for
/// `Policy::evaluate_raw_exec` and never opens it — [`policy_modules_never_write`]
/// covers that it does not write.
///
/// (ii) That set must not intersect the write-site allowlist: a writer must
/// never also be the module that names the Policy path.
///
/// (iii) `main.rs`'s production text must still hand the path to the
/// read-only loader — `load_policy(&config.policy_path)` — at least once.
/// (Reduced from checking every occurrence's shape, per plan review: that
/// broke on harmless refactors like logging the path differently, and did
/// not reliably catch the real risk anyway — `main.rs` passing
/// `config.policy_path` into an allowlisted writer function, which is listed
/// under "cannot see" in the module doc comment.)
#[test]
fn policy_path_reaches_only_the_read_only_loader() {
    static POLICY_PATH_IDENT: OnceLock<Regex> = OnceLock::new();
    let ident_re = POLICY_PATH_IDENT.get_or_init(|| Regex::new(r"\bpolicy_path\b").unwrap());

    let write_allowlist = [
        "crates/relay-transport/src/identity.rs",
        "src/dedup.rs",
        "src/join/env_file.rs",
        "crates/relay-test-support/src/lib.rs",
    ];
    let expected = ["src/config.rs", "src/main.rs", "src/selfref.rs"];

    let views = daemon_src_files();

    let mut naming: Vec<String> = Vec::new();
    for view in &views {
        let names_ident = ident_re.is_match(&view.prod_scrubbed);
        let names_literal = view.prod_original.contains("\"RELAY_POLICY_PATH\"");
        if names_ident || names_literal {
            naming.push(view.rel.clone());
        }
    }
    naming.sort();

    let mut expected_sorted: Vec<String> = expected.iter().map(|s| s.to_string()).collect();
    expected_sorted.sort();
    assert_eq!(
        naming, expected_sorted,
        "the files whose production text names the Policy path must be exactly \
         {{src/config.rs, src/main.rs, src/selfref.rs}} — either a new module now reaches the Policy path \
         (review against invariant 2), or one of the three stopped naming it (stale check)"
    );

    for f in &naming {
        assert!(
            !write_allowlist.contains(&f.as_str()),
            "{f} both names the Policy path and appears in the write-site allowlist — that is \
             exactly the invariant-2 shape this guard exists to catch: a writer that is also \
             the module handling the Policy path"
        );
    }

    static LOAD_POLICY_CALL: OnceLock<Regex> = OnceLock::new();
    let call_re = LOAD_POLICY_CALL
        .get_or_init(|| Regex::new(r"load_policy\(\s*&config\.policy_path\s*\)").unwrap());
    let main_view = views
        .iter()
        .find(|v| v.rel == "src/main.rs")
        .expect("src/main.rs not found under daemon/");
    assert!(
        call_re.is_match(&main_view.prod_scrubbed),
        "main.rs must still hand the Policy path to the read-only loader via \
         load_policy(&config.policy_path)"
    );
}

/// The Policy file and every Template Operation file are opened only through
/// relay-policy's `hardened_open.rs` `open_hardened`, and that open names no write flag.
///
/// (i) `crates/relay-policy/src/hardened_open.rs`'s production text has exactly one `OpenOptions`
/// and exactly one `.open(` call, and they form exactly the chain
/// `OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW |
/// libc::O_NONBLOCK).open(path)` — so a write, append, create or truncate
/// flag (or any other flag) cannot be added to the open without failing here,
/// on top of [`policy_modules_never_write`] scanning the module for every
/// write pattern.
///
/// (ii) relay-policy's `lib.rs` and `crates/relay-ops/src/templates.rs` have no opener of their
/// own in production (`OpenOptions`, `File::open`, `File::options`), `lib.rs`
/// has no path-based `fs::read`/`fs::read_to_string` and `templates.rs` exactly
/// one (its linter's), and each still hands its path to `open_hardened` — so
/// the loaders cannot drift back to a private open that (i) does not see.
#[test]
fn trust_files_open_only_through_the_read_only_hardened_open() {
    let views = daemon_src_files();
    let view = |rel: &str| {
        views
            .iter()
            .find(|v| v.rel == rel)
            .unwrap_or_else(|| panic!("{rel} not found under daemon/"))
    };

    let helper = &view("crates/relay-policy/src/hardened_open.rs").prod_scrubbed;
    let open_options = Regex::new(r"\bOpenOptions\b").unwrap();
    let open_call = Regex::new(r"\.open\(").unwrap();
    let chain = Regex::new(
        r"\bOpenOptions::new\(\s*\)\s*\.read\(\s*true\s*\)\s*\.custom_flags\(\s*libc::O_NOFOLLOW\s*\|\s*libc::O_NONBLOCK\s*\)\s*\.open\(\s*path\s*\)",
    )
    .unwrap();
    assert_eq!(
        open_options.find_iter(helper).count(),
        1,
        "relay-policy's hardened_open.rs must name OpenOptions exactly once in production — the one \
         read-only hardened open (invariant 2)"
    );
    assert_eq!(
        open_call.find_iter(helper).count(),
        1,
        "relay-policy's hardened_open.rs must have exactly one .open( call in production"
    );
    assert!(
        chain.is_match(helper),
        "relay-policy's hardened_open.rs open must be exactly OpenOptions::new().read(true)\
         .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK).open(path) — no write, append, \
         create or truncate flag, and no other flag, on the Policy/template open (invariant 2)"
    );

    let private_open = Regex::new(r"\bOpenOptions\b|\bFile::(open|options)\b").unwrap();
    let path_read = Regex::new(r"\bfs::read(_to_string)?\(").unwrap();
    let delegates = Regex::new(r"\bopen_hardened\(\s*path\s*\)").unwrap();
    // (file, how many `fs::read`/`fs::read_to_string` calls it may have):
    // `crates/relay-ops/src/templates.rs` has exactly one, `lint_dir`'s deliberately ungated read
    // for the pre-deployment linter (`relay-daemon policy check`), which never
    // feeds the runtime template set; a second one fails here for review.
    for (rel, allowed_path_reads) in [
        ("crates/relay-policy/src/lib.rs", 0usize),
        ("crates/relay-ops/src/templates.rs", 1usize),
    ] {
        let text = &view(rel).prod_scrubbed;
        let hits: Vec<usize> = private_open
            .find_iter(text)
            .map(|m| line_of(text, m.start()))
            .collect();
        assert!(
            hits.is_empty(),
            "{rel} opens a file itself in production (lines {hits:?}) — the Policy and \
             template loaders must open only through hardened_open::open_hardened, the one \
             read-only open this guard pins"
        );
        let reads: Vec<usize> = path_read
            .find_iter(text)
            .map(|m| line_of(text, m.start()))
            .collect();
        assert_eq!(
            reads.len(),
            allowed_path_reads,
            "{rel} has {} path-based fs::read/fs::read_to_string call(s) in production (lines \
             {reads:?}), want {allowed_path_reads} — a new ungated read beside the hardened \
             loader needs review against invariant 2",
            reads.len()
        );
        assert!(
            delegates.is_match(text),
            "{rel} must still hand its path to hardened_open::open_hardened(path)"
        );
    }
}

/// Runs `scrub`/`strip_test_items`/`mask`/`write_sites` over inline sources —
/// "a guard nobody has seen fail", proving every rule actually fires and that
/// every allowed shape does not, the same discipline as the Go fixtures
/// (`no_dispatch_test.go`'s `TestDispatchViolations_Fixtures`).
#[test]
fn guard_fixtures() {
    fn sites_from_source(src: &str) -> Vec<(usize, &'static str)> {
        let scrubbed = scrub(src);
        let kept = strip_test_items(&scrubbed)
            .expect("fixture unexpectedly looked like a whole #![cfg(test)] file");
        let prod = mask(&scrubbed, &kept);
        write_sites(&prod)
    }

    fn line_containing(src: &str, needle: &str) -> usize {
        src.lines()
            .position(|l| l.contains(needle))
            .map(|i| i + 1)
            .unwrap_or_else(|| panic!("fixture source has no line containing {needle:?}:\n{src}"))
    }

    // -- cfg(test) stripping --------------------------------------------

    // A cfg(test) mod tests whose body calls std::fs::write with a string
    // argument containing a close brace produces no sites, even with the
    // brace inside the string.
    {
        let src = r#"
#[cfg(test)]
mod tests {
    fn t() {
        std::fs::write("path", "some text with a } brace").unwrap();
    }
}
"#;
        assert!(
            sites_from_source(src).is_empty(),
            "a close brace inside a cfg(test) fixture string must not unbalance the stripper"
        );
    }

    // fn g() {} + a cfg(test) fn t() calling File::create + fn h() calling
    // fs::write produces exactly one site, on h's line: production code
    // after a mid-file test item is still scanned.
    {
        let src = "fn g() {}\n\
                    #[cfg(test)]\n\
                    fn t() { std::fs::File::create(\"x\").unwrap(); }\n\
                    fn h() { std::fs::write(\"y\", \"z\").unwrap(); }\n";
        let sites = sites_from_source(src);
        assert_eq!(
            sites,
            vec![(line_containing(src, "fs::write"), "fs:: path writer")],
            "production code after a mid-file #[cfg(test)] item must still be scanned"
        );
    }

    // -- raw identifiers (review BLOCKING 2) -----------------------------

    // `S { r#type: 1 }` on line 1, fs::write on line 2: detected only on
    // line 2.
    {
        let src = "fn k() { let x = S { r#type: 1 }; }\n\
                    fn h() { std::fs::write(p, b); }\n";
        let sites = sites_from_source(src);
        assert_eq!(
            sites,
            vec![(line_containing(src, "fs::write"), "fs:: path writer")],
            "a raw identifier (r#type) must not be misread as opening a raw string that \
             swallows the next line's real write site"
        );
    }

    // `let r#match = 1;` followed by File::create(p) is detected.
    {
        let src = "fn f() {\n    let r#match = 1;\n    std::fs::File::create(p);\n}\n";
        let sites = sites_from_source(src);
        assert_eq!(
            sites,
            vec![(line_containing(src, "File::create"), "File::create(_new)")]
        );
    }

    // `let br = 1; let cr = 2;` followed by fs::rename(a, b) is detected:
    // identifiers ending in r are not string prefixes.
    {
        let src = "fn f() {\n    let br = 1;\n    let cr = 2;\n    std::fs::rename(a, b);\n}\n";
        let sites = sites_from_source(src);
        assert_eq!(
            sites,
            vec![(line_containing(src, "fs::rename"), "fs:: path writer")]
        );
    }

    // -- raw strings with hashes ------------------------------------------

    // An r##-raw string whose content contains a quote followed by ONE hash
    // and the text fs::write(, then fs::copy(a, b) after the literal,
    // produces exactly one site (copy). A quote plus a single hash inside
    // the literal does not close an r## string.
    {
        let src =
            "fn f() {\n    let s = r##\"abc \"# fs::write( def\"##;\n    fs::copy(a, b);\n}\n";
        let sites = sites_from_source(src);
        assert_eq!(
            sites,
            vec![(line_containing(src, "fs::copy"), "fs:: path writer")],
            "a single hash after a quote inside an r## literal must not close the raw string \
             early, and the literal's fs::write( text must stay blanked"
        );
    }

    // A br#-raw string containing fs::write( produces no sites.
    {
        let src = "fn f() {\n    let s = br#\"fs::write(\"#;\n}\n";
        assert!(sites_from_source(src).is_empty());
    }

    // A b-string containing fs::write( produces no sites.
    {
        let src = "fn f() {\n    let s = b\"fs::write(\";\n}\n";
        assert!(sites_from_source(src).is_empty());
    }

    // -- OpenOptions chains and .write( argument filtering -----------------

    // An OpenOptions::new() chain over four lines, .read(true) then
    // .write(true) then .open(p), is detected on the .write line.
    {
        let src = "fn f(p: &str) {\n    std::fs::OpenOptions::new()\n        .read(true)\n        .write(true)\n        .open(p)\n        .unwrap();\n}\n";
        let sites = sites_from_source(src);
        assert_eq!(
            sites,
            vec![(
                line_containing(src, ".write(true)"),
                ".write(<non-literal-false>)"
            )]
        );
    }

    // .write(flag) is detected.
    {
        let src = "fn a(x: &mut std::fs::File, flag: bool) {\n    x.write(flag);\n}\n";
        assert_eq!(sites_from_source(src).len(), 1);
    }
    // .write(false) is not.
    {
        let src = "fn b(x: &mut std::fs::File) {\n    x.write(false);\n}\n";
        assert!(sites_from_source(src).is_empty());
    }
    // A multi-line .write(\n false\n) is also not detected.
    {
        let src = "fn b(x: &mut std::fs::File) {\n    x.write(\n        false\n    );\n}\n";
        assert!(
            sites_from_source(src).is_empty(),
            "a literal false spread across lines must still be excluded"
        );
    }
    // lock.write() (RwLock::write, no argument) is not.
    {
        let src = "fn c(lock: &std::sync::RwLock<i32>) {\n    let _ = lock.write();\n}\n";
        assert!(sites_from_source(src).is_empty());
    }

    // -- widened patterns: custom_flags, libc, chown, set_permissions ------

    {
        let src = "fn a(o: std::fs::OpenOptions) { o.custom_flags(libc::O_RDWR); }\n";
        assert!(!sites_from_source(src).is_empty());
    }
    {
        let src = "fn b(c: i32) { unsafe { libc::unlink(c as *const i8); } }\n";
        assert!(!sites_from_source(src).is_empty());
    }
    // libc::creat64 (an LFS 64-bit variant) and libc::remove (security review
    // finding 1: the alternation missed both the `64` suffix and this name).
    {
        let src = "fn e(p: *const i8) { unsafe { libc::creat64(p, 0o644); } }\n";
        assert!(!sites_from_source(src).is_empty());
    }
    {
        let src = "fn f(p: *const i8) { unsafe { libc::remove(p); } }\n";
        assert!(!sites_from_source(src).is_empty());
    }
    {
        let src =
            "fn c(p: &std::path::Path) { std::os::unix::fs::chown(p, None, None).unwrap(); }\n";
        assert!(!sites_from_source(src).is_empty());
    }
    {
        let src = "fn d(f: &std::fs::File, perm: std::fs::Permissions) { f.set_permissions(perm).unwrap(); }\n";
        assert!(!sites_from_source(src).is_empty());
    }

    // -- import patterns -----------------------------------------------

    {
        let src = "use std::fs::write;\n";
        assert!(!sites_from_source(src).is_empty());
    }
    {
        let src = "use std::os::unix::fs::symlink;\n";
        assert!(!sites_from_source(src).is_empty());
    }
    {
        let src = "use std::fs::{self, OpenOptions};\n";
        assert!(sites_from_source(src).is_empty());
    }
    {
        let src = "use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};\n";
        assert!(
            sites_from_source(src).is_empty(),
            "importing the *Ext traits is not itself a write site; only the flags are"
        );
    }

    // -- comments ---------------------------------------------------------

    {
        let src = "// File::create( in a line comment\nfn f() {}\n";
        assert!(sites_from_source(src).is_empty());
    }
    {
        let src = "/// fs::write( in a doc comment\nfn f() {}\n";
        assert!(sites_from_source(src).is_empty());
    }
    // A nested block comment whose inner comment closes first and whose
    // outer body then contains fs::write(, followed by fs::copy(a, b) after
    // the outer close, produces exactly the copy site.
    {
        let src = "/* outer text /* inner File::create( */ still outer, fs::write( more outer text */\nfn h() { fs::copy(a, b); }\n";
        let sites = sites_from_source(src);
        assert_eq!(
            sites,
            vec![(line_containing(src, "fs::copy"), "fs:: path writer")],
            "text inside a nested block comment, on either side of the inner close, must stay \
             blanked; code after the whole comment closes must still be scanned"
        );
    }

    // -- escaped quote inside a plain string -------------------------------

    {
        let src = "fn f() {\n    let s = \"abc \\\" fs::write( def\";\n}\n";
        assert!(
            sites_from_source(src).is_empty(),
            "an escaped quote must not end the string early"
        );
    }

    // -- lifetimes and loop labels -----------------------------------------

    {
        let src = "fn f<'a>(x: &'a str) {\n    'outer: loop {\n        fs::rename(a, b);\n        break 'outer;\n    }\n}\n";
        let sites = sites_from_source(src);
        assert_eq!(
            sites,
            vec![(line_containing(src, "fs::rename"), "fs:: path writer")],
            "a lifetime parameter and a loop label must not be misread as char literals"
        );
    }

    // -- char literals must not unbalance the stripper ---------------------

    {
        let src = "const A: char = '{';\n\
                    const B: char = '\\'';\n\
                    const C: char = '\\u{7B}';\n\
                    const D: char = '\u{e9}';\n\
                    #[cfg(test)]\n\
                    mod t {\n    fn x() {}\n}\n\
                    fn h() { fs::write(p, b); }\n";
        let sites = sites_from_source(src);
        assert_eq!(
            sites,
            vec![(line_containing(src, "fs::write"), "fs:: path writer")],
            "an open-brace char literal, an escaped quote, a unicode escape, and a non-ASCII \
             char must all be blanked without unbalancing the #[cfg(test)] stripper's depth count"
        );
    }

    // -- is_symlink( must not match the symlink( patterns -------------------

    {
        let src = "fn f(meta: std::fs::Metadata) -> bool { meta.file_type().is_symlink() }\n";
        assert!(
            sites_from_source(src).is_empty(),
            "is_symlink( must not match a symlink( pattern — the underscore is a word character"
        );
    }

    // -- whole-file #![cfg(test)] is skipped --------------------------------

    {
        let src = "#![cfg(test)]\nfn f() { std::fs::write(\"a\", \"b\").unwrap(); }\n";
        let scrubbed = scrub(src);
        assert!(
            strip_test_items(&scrubbed).is_none(),
            "a file starting with #![cfg(test)] must be skipped whole"
        );
    }

    // -- #![cfg(test)] preamble anchoring (review non-blocking item 1) -----

    // A doc-comment preamble (catalog.rs's own shape: several `//!` lines,
    // a blank line, then `#![cfg(test)]`) is still skipped whole.
    {
        let src = "//! Binding tests for something.\n\
                    //!\n\
                    //! More doc comment.\n\
                    \n\
                    #![cfg(test)]\n\
                    fn f() { std::fs::write(\"a\", \"b\").unwrap(); }\n";
        let scrubbed = scrub(src);
        assert!(
            strip_test_items(&scrubbed).is_none(),
            "a #![cfg(test)] preceded only by doc comments and blank lines must still skip the \
             whole file, matching catalog.rs's own shape"
        );
    }

    // A #![cfg(test)] that is NOT in the preamble — here, a module's own
    // inner attribute after real production code — must NOT skip the whole
    // file: the production fs::write above it must still be found.
    {
        let src = "fn h() { std::fs::write(p, b); }\n\
                    mod tests {\n    #![cfg(test)]\n    fn t() {}\n}\n";
        let scrubbed = scrub(src);
        let kept = strip_test_items(&scrubbed);
        assert!(
            kept.is_some(),
            "a #![cfg(test)] that is not in the file's preamble must not skip the whole file"
        );
        let sites = write_sites(&mask(&scrubbed, &kept.unwrap()));
        assert_eq!(
            sites,
            vec![(line_containing(src, "fs::write"), "fs:: path writer")],
            "the production fs::write above a mid-file #![cfg(test)] must still be found"
        );
    }

    // -- non-ASCII byte-length preservation (review item 3) -----------------

    {
        let src = "// em dash \u{2014} and e-acute \u{e9} in a comment\n\
                    const S: &str = \"caf\u{e9} \u{2014} more\";\n\
                    #[cfg(test)]\n\
                    mod t {\n    const P: &str = \"RELAY_POLICY_PATH\";\n}\n\
                    const REAL: &str = \"RELAY_POLICY_PATH\";\n\
                    fn h() { fs::write(p, b); }\n";
        let scrubbed = scrub(src);
        assert_eq!(
            scrubbed.len(),
            src.len(),
            "scrub must preserve byte length even with multi-byte characters in comments and \
             strings"
        );
        let expected_line = line_containing(src, "fs::write");
        let sites = write_sites(&mask(
            &scrubbed,
            &strip_test_items(&scrubbed).expect("not a whole-file #![cfg(test)] fixture"),
        ));
        assert_eq!(
            sites,
            vec![(expected_line, "fs:: path writer")],
            "the reported line number must survive non-ASCII content"
        );

        let kept = strip_test_items(&scrubbed).unwrap();
        let prod_original = mask(src, &kept);
        assert!(
            prod_original.contains("\"RELAY_POLICY_PATH\""),
            "the production RELAY_POLICY_PATH literal must survive masking byte for byte"
        );
        let test_region_start = src.find("mod t {").unwrap();
        let test_region_end = src.find("const REAL").unwrap();
        assert!(
            !prod_original[test_region_start..test_region_end].contains("RELAY_POLICY_PATH"),
            "the RELAY_POLICY_PATH literal inside the cfg(test) module must be blanked"
        );
    }

    // -- non-vacuity: ties the fixtures to the real tree --------------------

    let views = daemon_src_files();
    assert!(
        views.len() >= 20,
        "walked only {} daemon source files, want >= 20 — the guard must actually inspect a \
         realistic tree",
        views.len()
    );
    let policy_view = views
        .iter()
        .find(|v| v.rel == "crates/relay-policy/src/lib.rs")
        .expect("relay-policy's lib.rs not found under daemon/crates");
    assert!(
        policy_view.prod_scrubbed.contains("load_policy"),
        "relay-policy's lib.rs production text must still contain load_policy"
    );
    let templates_view = views
        .iter()
        .find(|v| v.rel == "crates/relay-ops/src/templates.rs")
        .expect("crates/relay-ops/src/templates.rs not found under daemon/");
    assert!(
        templates_view.prod_scrubbed.contains("r#type"),
        "crates/relay-ops/src/templates.rs's production text must still contain the raw identifier r#type — this \
         is what ties the raw-identifier fixture above to a real production file rather than \
         only a synthetic one"
    );
}

/// A `#[cfg(test)]` attribute on a non-item — a struct field here — has no
/// matching item boundary. [`looks_like_item_start`] rejects it directly
/// (the field name `a` is not an item keyword), before `scan_item_end` ever
/// runs; without that check, the struct's own closing `}` would bring
/// `scan_item_end`'s depth below zero instead of back to exactly zero.
/// Continuing past that point would scan the "item" into the struct's OWN
/// closing brace and beyond, silently treating the next real item — `fn h`'s
/// production `std::fs::write` below — as if it were part of the
/// `#[cfg(test)]`-governed region and stripping it from the write-site scan.
/// `strip_test_items` panics instead, so this shows up as a loud test
/// failure rather than a silent false negative in
/// [`policy_modules_never_write`] or [`production_write_sites_are_exactly_the_allowlist`].
#[test]
#[should_panic(expected = "on a non-item")]
fn cfg_test_on_a_struct_field_panics_rather_than_silently_mis_scanning() {
    let src = "struct S {\n    #[cfg(test)]\n    a: u8,\n    b: u8,\n}\n\
               fn h() { std::fs::write(p, b); }\n";
    let scrubbed = scrub(src);
    let _ = strip_test_items(&scrubbed);
}

/// A `#[cfg(test)]` attribute on a match arm (code review, cycle 2 BLOCKING):
/// unlike the struct-field case above, `scan_item_end`'s depth assert alone
/// would NOT catch this — the governed text `0 => g(), _ => { .. } }` opens
/// and closes a brace for the following `_` arm's block, balancing back to
/// exactly 0 at that `}` without ever going negative, so it would silently
/// treat `0 => g(), _ => { std::fs::write(p, b); }` as the "item" and strip
/// the production write site inside the `_` arm. `looks_like_item_start`
/// rejects it instead: `0` is not an item keyword.
#[test]
#[should_panic(expected = "on a non-item")]
fn cfg_test_on_a_match_arm_panics_rather_than_silently_mis_scanning() {
    let src = "fn f(x: i32) {\n    match x {\n        #[cfg(test)]\n        0 => g(),\n        \
               _ => { std::fs::write(p, b); }\n    }\n}\n";
    let scrubbed = scrub(src);
    let _ = strip_test_items(&scrubbed);
}

/// A `#[cfg(test)]` attribute on an enum variant, immediately followed by a
/// struct-like variant (code review, cycle 2 BLOCKING): the same
/// wrong-but-balanced shape as the match-arm case above — the struct-like
/// variant's own `{ .. }` body balances `scan_item_end`'s depth back to 0
/// without ever going negative, so the assert there alone would not catch
/// it. `looks_like_item_start` rejects it instead: `Unit` is not an item
/// keyword.
#[test]
#[should_panic(expected = "on a non-item")]
fn cfg_test_on_an_enum_variant_before_a_struct_like_variant_panics_rather_than_silently_mis_scanning(
) {
    let src = "enum E {\n    #[cfg(test)]\n    Unit,\n    Struct { a: u8 },\n}\n\
               fn h() { std::fs::write(p, b); }\n";
    let scrubbed = scrub(src);
    let _ = strip_test_items(&scrubbed);
}
