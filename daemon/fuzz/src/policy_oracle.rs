//! Pure helpers shared by the Policy fuzz targets and `gen_corpus` (#897).
//!
//! Everything here is a fixed harness Policy or a tiny reference function used
//! as a test oracle. None of it evaluates Policy: the only evaluator is the
//! real `Policy::decide` (invariant 12, ADR-0011), called by the targets.

use std::sync::OnceLock;

use relay_policy::{from_toml_str, Fragment, Policy};

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

/// The most Policy fragments `fuzz_policy_compose` composes in one input.
pub const MAX_FRAGMENTS: usize = 8;

/// Frame one `fuzz_policy_compose` input: bit 0 of `sel` says whether there is a
/// Policy file, `rest` is the [`SEP`]-separated fields (none at all when empty).
///
/// With the bit set the Policy file is the first field, or the empty text when
/// there are no fields; every other field is a fragment. A fragment at input
/// index `i` of `n` is named `{n-1-i:02}.toml`, so the input order is the reverse
/// of the composition order and `compose`'s own sort is exercised. The caller
/// bounds the fragment count by [`MAX_FRAGMENTS`].
pub fn policy_sources(sel: u8, rest: &str) -> (Option<String>, Vec<Fragment>) {
    let mut parts = if rest.is_empty() {
        Vec::new()
    } else {
        fields(rest)
    };
    let file = if sel & 1 == 1 {
        Some(if parts.is_empty() {
            String::new()
        } else {
            parts.remove(0)
        })
    } else {
        None
    };
    let n = parts.len();
    let fragments = parts
        .into_iter()
        .enumerate()
        .map(|(i, text)| Fragment {
            name: format!("{:02}.toml", n - 1 - i),
            text,
        })
        .collect();
    (file, fragments)
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
    fn policy_sources_frames_file_and_fragments() {
        let sep = SEP;
        let (file, frags) = policy_sources(1, &format!("a{sep}b{sep}c"));
        assert_eq!(file.as_deref(), Some("a"));
        let got: Vec<(&str, &str)> = frags
            .iter()
            .map(|f| (f.name.as_str(), f.text.as_str()))
            .collect();
        assert_eq!(got, vec![("01.toml", "b"), ("00.toml", "c")]);

        let (file, frags) = policy_sources(1, "");
        assert_eq!(file.as_deref(), Some(""));
        assert!(frags.is_empty());

        let (file, frags) = policy_sources(0, "");
        assert_eq!(file, None);
        assert!(frags.is_empty());

        let (file, frags) = policy_sources(0, "x");
        assert_eq!(file, None);
        assert_eq!(frags.len(), 1);
        assert_eq!(
            (frags[0].name.as_str(), frags[0].text.as_str()),
            ("00.toml", "x")
        );
    }

    /// The positive control for the parity oracle: the shipped Policies load and
    /// lint clean, so a parity failure is not just "everything is refused".
    #[test]
    fn shipped_policies_compose() {
        for text in [
            include_str!("../../policy.default.toml"),
            include_str!("../../policy.example.toml"),
        ] {
            relay_policy::compose(text, &[]).expect("shipped policy composes");
            assert!(!relay_policy::lint_composed(text, &[], &[], false).has_errors());
        }
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
