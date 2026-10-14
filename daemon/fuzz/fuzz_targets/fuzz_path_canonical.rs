//! Fuzzes the canonical-path check and the Policy path precondition
//! (ADR-0018 layer 1, invariant 3): every path `path_is_canonical` accepts is
//! its own lexical normalisation, and `Policy::decide` refuses every path it
//! rejects before any deny or allow rule is read.
//!
//! `path_is_canonical` accepts NUL, control and bidi characters by design
//! (a residual ADR-0018 records); the oracles do not treat that as a defect.
//!
//! A crash here is a path-deny evasion finding: file it, never paper over it.
//!
//! Input: UTF-8; the whole input is the path. If it contains U+001F it is also
//! split on it, to drive several path positions of one Operation at once.
#![no_main]

use libfuzzer_sys::fuzz_target;
use relay_daemon_fuzz::policy_oracle::{
    deny_all, fields, has_bad_segment, lexical_normalise, path_policy_allow_any,
    path_policy_deny_wins, SEP,
};
use relay_policy::{path_is_canonical, Decision, MatchedOn, Pass, Request};

fuzz_target!(|data: &[u8]| {
    let Ok(p) = std::str::from_utf8(data) else {
        return;
    };
    if p.len() > 8192 {
        return;
    }

    // Oracle A: the definition.
    let c = path_is_canonical(p);
    let abs = p.starts_with('/');
    assert_eq!(c, abs && lexical_normalise(p) == p, "definition: {p:?}");
    if c {
        assert!(abs, "{p:?}");
        assert!(
            p == "/" || (!p.ends_with('/') && !has_bad_segment(p)),
            "accepted a path with a bad segment or trailing slash: {p:?}"
        );
    } else if abs && p != "/" {
        assert!(
            p.ends_with('/') || has_bad_segment(p),
            "rejected a path with no bad segment: {p:?}"
        );
    }
    if abs {
        let n = lexical_normalise(p);
        assert!(
            path_is_canonical(&n),
            "normalisation not canonical: {p:?} -> {n:?}"
        );
        assert_eq!(
            lexical_normalise(&n),
            n,
            "normalisation not idempotent: {p:?}"
        );
    }

    // Oracle B: decide refuses every rejected path at the precondition.
    let positional = [p.to_string()];
    let request = Request::Operation {
        name: "file.read",
        positional: &positional,
        path_positions: &[0],
    };
    for (which, policy) in [
        ("allow_any", path_policy_allow_any()),
        ("deny_wins", path_policy_deny_wins()),
        ("deny_all", deny_all()),
    ] {
        let e = policy.decide(&request);
        if !c {
            assert!(
                matches!(e.decision, Decision::Deny { .. }),
                "{which}: {p:?}"
            );
            assert_eq!(e.pass, Pass::Precondition, "{which}: {p:?}");
            assert_eq!(
                e.matched_on,
                MatchedOn::NonCanonicalPath { position: 0 },
                "{which}: {p:?}"
            );
            assert!(
                e.rule.is_none() && e.raw_exec_permit.is_none(),
                "{which}: {p:?}"
            );
            continue;
        }
        assert_ne!(
            e.pass,
            Pass::Precondition,
            "{which}: canonical path refused: {p:?}"
        );
        match which {
            "allow_any" => assert_eq!(e.pass, Pass::Allow, "{p:?}"),
            "deny_wins" => {
                assert_eq!(e.pass, Pass::Deny, "{p:?}");
                assert_eq!(e.matched_on, MatchedOn::WholeOperation, "{p:?}");
            }
            _ => {
                assert_eq!(e.pass, Pass::Default, "{p:?}");
                assert_eq!(e.matched_on, MatchedOn::NoAllowRule, "{p:?}");
            }
        }
    }

    // Oracle C: several path positions; the first non-canonical one is named,
    // and a trailing out-of-range position is ignored.
    if !p.contains(SEP) {
        return;
    }
    let parts = fields(p);
    if parts.len() > 8 {
        return;
    }
    let positions: Vec<usize> = (0..=parts.len()).collect();
    let e = deny_all().decide(&Request::Operation {
        name: "fz.paths",
        positional: &parts,
        path_positions: &positions,
    });
    match parts.iter().position(|s| !path_is_canonical(s)) {
        Some(k) => {
            assert_eq!(e.pass, Pass::Precondition, "{parts:?}");
            assert_eq!(
                e.matched_on,
                MatchedOn::NonCanonicalPath { position: k },
                "{parts:?}"
            );
        }
        None => assert_eq!(e.pass, Pass::Default, "{parts:?}"),
    }
});
