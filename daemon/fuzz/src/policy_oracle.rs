//! Pure helpers shared by the Policy fuzz targets and `gen_corpus` (#897).
//!
//! Everything here is a fixed harness Policy or a tiny reference function used
//! as a test oracle. None of it evaluates Policy: the only evaluator is the
//! real `Policy::decide` (invariant 12, ADR-0011), called by the targets.

use std::sync::OnceLock;

use relay_policy::{from_toml_str, Policy};

/// Separates the elements of an argv (or the positional arguments of an
/// Operation) inside a fuzz input. U+001F is neither NUL nor `char::is_whitespace`,
/// so NUL and every Unicode whitespace character stay reachable inside an element.
/// U+001F itself can never appear inside an element (it is the framing separator);
/// the engine allows it and it is not White_Space, so the property is unaffected.
pub const SEP: char = '\u{1f}';

/// Split `s` into its [`SEP`]-separated fields.
pub fn fields(s: &str) -> Vec<String> {
    s.split(SEP).map(str::to_string).collect()
}

/// The Raw Exec Policies `fuzz_raw_exec_gate` runs under, picked by one input byte.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RawExecFixture {
    /// Allows anything the whitespace guard lets through.
    DotAll,
    /// As `DotAll`, plus a per-element and a substring deny.
    DotAllWithDeny,
    /// Two anchored allow patterns, the shape an operator writes.
    Anchored,
    /// No `[raw_exec]` section: everything is denied.
    DenyAll,
    /// Allow patterns written without anchors; fuzzes ADR-0019's whole-command
    /// auto-anchoring, so only the exact commands may be allowed.
    Unanchored,
}

fn compile_fixed(toml: &str) -> Policy {
    from_toml_str(toml).expect("fixed harness policy")
}

/// The fixture selected by `sel % 5`, with its Policy.
pub fn raw_exec_policy(sel: u8) -> (RawExecFixture, &'static Policy) {
    static DOT_ALL: OnceLock<Policy> = OnceLock::new();
    static DOT_ALL_WITH_DENY: OnceLock<Policy> = OnceLock::new();
    static ANCHORED: OnceLock<Policy> = OnceLock::new();
    static DENY_ALL: OnceLock<Policy> = OnceLock::new();
    static UNANCHORED: OnceLock<Policy> = OnceLock::new();
    match sel % 5 {
        0 => (
            RawExecFixture::DotAll,
            DOT_ALL.get_or_init(|| compile_fixed("[raw_exec]\nallow = ['(?s).*']\n")),
        ),
        1 => (
            RawExecFixture::DotAllWithDeny,
            DOT_ALL_WITH_DENY.get_or_init(|| {
                compile_fixed("[raw_exec]\nallow = ['(?s).*']\ndeny = ['^--force$', 'rm']\n")
            }),
        ),
        2 => (
            RawExecFixture::Anchored,
            ANCHORED.get_or_init(|| {
                compile_fixed(
                    "[raw_exec]\nallow = ['^/usr/bin/systemctl (status|restart) [A-Za-z0-9@._-]+$', '^/usr/bin/uptime$']\n",
                )
            }),
        ),
        3 => (
            RawExecFixture::DenyAll,
            DENY_ALL.get_or_init(|| compile_fixed("")),
        ),
        _ => (
            RawExecFixture::Unanchored,
            UNANCHORED.get_or_init(|| {
                compile_fixed("[raw_exec]\nallow = ['/usr/bin/uptime', '(?m)^/usr/bin/id$']\n")
            }),
        ),
    }
}

/// `file.read` allowed for any single argument.
pub fn path_policy_allow_any() -> &'static Policy {
    static P: OnceLock<Policy> = OnceLock::new();
    P.get_or_init(|| {
        compile_fixed("[[operation]]\nname = \"file.read\"\nallowed_args = [[\"*\"]]\n")
    })
}

/// As [`path_policy_allow_any`], plus a deny of the whole `file.read` Operation.
pub fn path_policy_deny_wins() -> &'static Policy {
    static P: OnceLock<Policy> = OnceLock::new();
    P.get_or_init(|| {
        compile_fixed(
            "[[operation]]\nname = \"file.read\"\nallowed_args = [[\"*\"]]\n\n\
             [[deny]]\nname = \"file.read\"\nargs = []\n",
        )
    })
}

/// No rules at all: deny-by-default.
pub fn deny_all() -> &'static Policy {
    static P: OnceLock<Policy> = OnceLock::new();
    P.get_or_init(|| compile_fixed(""))
}

/// A reference lexical normaliser for an absolute path: drops empty and `.`
/// segments, resolves `..`. Hand-written rather than `std::path`, whose
/// `Components` silently drops interior `.` and collapses `//` and so would
/// mask exactly the drift this oracle exists to catch.
pub fn lexical_normalise(p: &str) -> String {
    let mut stack: Vec<&str> = Vec::new();
    for seg in p.split('/') {
        match seg {
            "" | "." => {}
            ".." => {
                stack.pop();
            }
            s => stack.push(s),
        }
    }
    if stack.is_empty() {
        "/".to_string()
    } else {
        format!("/{}", stack.join("/"))
    }
}

/// Whether any segment after the leading one is empty, `.` or `..`. True of the
/// bare root `/` (its trailing empty segment), which `path_is_canonical`
/// accepts as a special case.
pub fn has_bad_segment(p: &str) -> bool {
    p.split('/')
        .skip(1)
        .any(|s| s.is_empty() || s == "." || s == "..")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalise_known_cases() {
        for (input, want) in [
            ("/", "/"),
            ("/etc/../etc/shadow", "/etc/shadow"),
            ("//a//b/", "/a/b"),
            ("/..", "/"),
            ("/a/./b", "/a/b"),
            ("/a/.../b", "/a/.../b"),
            ("/a b", "/a b"),
        ] {
            assert_eq!(lexical_normalise(input), want, "input {input:?}");
        }
    }

    #[test]
    fn bad_segments() {
        assert!(has_bad_segment("/a//b"));
        assert!(has_bad_segment("/a/"));
        assert!(has_bad_segment("/a/./b"));
        assert!(has_bad_segment("/.."));
        assert!(!has_bad_segment("/a/.../b"));
        // The bare root is accepted by a special case in `path_is_canonical`,
        // so callers test `p == "/"` before this.
        assert!(has_bad_segment("/"));
        assert!(!has_bad_segment("/a"));
    }

    #[test]
    fn fields_split_on_sep_only() {
        assert_eq!(
            fields("a b\u{1f}\u{0}"),
            vec!["a b".to_string(), "\0".to_string()]
        );
    }

    #[test]
    fn fixtures_compile() {
        for sel in 0..5u8 {
            raw_exec_policy(sel);
        }
        path_policy_allow_any();
        path_policy_deny_wins();
        deny_all();
    }
}
