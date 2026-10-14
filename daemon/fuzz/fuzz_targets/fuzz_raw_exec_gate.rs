//! Fuzzes the Raw Exec argv gate (ADR-0001, ADR-0019) through the real
//! `Policy::decide`: allow patterns match `argv.join(" ")`, so an Allow is only
//! sound if no two distinct argvs share a joined form.
//!
//! The property is the one the engine documents (ADR-0019 amendment item 2 and
//! the "whitespace guard" in relay-policy): once the gate has Allowed, no
//! element contains a `char::is_whitespace` character and argv[0] is non-empty,
//! so `join(" ")` split on `' '` gives back exactly the argv. An empty later
//! element is a legal Allow, so the split is on `' '`, never `split_whitespace`.
//! NUL and the other non-White_Space control characters are also designed
//! Allows (NUL fails closed at execv) and are not asserted against.
//!
//! A crash here is an invariant-1 bypass finding: file it, never paper over it.
//!
//! Input: byte 0 selects the Policy fixture (mod 5); the rest is UTF-8 and is
//! the argv, its elements separated by U+001F.
#![no_main]

use libfuzzer_sys::fuzz_target;
use relay_daemon_fuzz::policy_oracle::{fields, raw_exec_policy, RawExecFixture};
use relay_policy::{Decision, MatchedOn, Pass, Request};

fuzz_target!(|data: &[u8]| {
    let Some((&sel, rest)) = data.split_first() else {
        return;
    };
    let Ok(rest) = std::str::from_utf8(rest) else {
        return;
    };
    if rest.chars().count() > 4096 {
        return;
    }
    let argv: Vec<String> = if rest.is_empty() {
        Vec::new()
    } else {
        fields(rest)
    };
    if argv.len() > 64 {
        return;
    }
    let (fixture, policy) = raw_exec_policy(sel);

    let e = policy.decide(&Request::RawExec { argv: &argv });
    let allowed = matches!(e.decision, Decision::Allow(_));

    assert_eq!(
        e.raw_exec_permit.is_some(),
        allowed,
        "a permit is minted exactly on Allow: {argv:?}"
    );

    if argv.is_empty() {
        assert_eq!(e.pass, Pass::Precondition, "empty argv");
        assert_eq!(e.matched_on, MatchedOn::EmptyArgv, "empty argv");
    }

    let has_ws = |s: &String| s.chars().any(char::is_whitespace);
    let guard_clean = !argv.is_empty() && !argv[0].is_empty() && !argv.iter().any(has_ws);

    if e.pass == Pass::Guard {
        let first = argv
            .iter()
            .enumerate()
            .position(|(i, a)| (i == 0 && a.is_empty()) || has_ws(a))
            .expect("guard refused an argv with no offending element");
        assert_eq!(
            e.matched_on,
            MatchedOn::WhitespaceElement { index: first },
            "guard names the first offending element: {argv:?}"
        );
    }

    // Positive control: without it a gate that denied everything would pass
    // every other oracle here.
    if fixture == RawExecFixture::DotAll && guard_clean {
        assert!(
            allowed,
            "guard-clean argv refused under allow-all: {argv:?}"
        );
    }

    if !allowed {
        return;
    }

    assert_eq!(e.pass, Pass::Allow, "{argv:?}");
    assert_eq!(e.matched_on, MatchedOn::WholeCommand, "{argv:?}");
    assert!(e.rule.is_some(), "an Allow names its rule: {argv:?}");
    assert!(
        guard_clean,
        "Allowed an argv the guard must refuse: {argv:?}"
    );

    let permit = e.raw_exec_permit.expect("checked above");
    assert_eq!(
        permit.into_argv(),
        argv,
        "the permit carries the argv decided"
    );

    // INJECTIVITY: the `guard_clean` assertion on every Allow, above, is what
    // enforces it. The join/split round-trip below states its consequence and
    // cannot fail on its own: the joined form the allow regex saw names exactly
    // this argv.
    let joined = argv.join(" ");
    assert_eq!(
        joined.split(' ').collect::<Vec<_>>(),
        argv,
        "join/split is not the identity on an Allowed argv: {argv:?}"
    );
    // The deny pass's canonical elements agree with the raw ones.
    assert_eq!(
        joined.split_whitespace().collect::<Vec<_>>(),
        argv.iter()
            .filter(|a| !a.is_empty())
            .map(String::as_str)
            .collect::<Vec<_>>(),
        "canonical elements differ from raw elements: {argv:?}"
    );

    match fixture {
        RawExecFixture::DotAll => {}
        RawExecFixture::DotAllWithDeny => {
            assert!(
                !argv.iter().any(|a| a == "--force")
                    && !joined.split_whitespace().any(|a| a == "--force"),
                "Allowed an argv a deny pattern must catch: {argv:?}"
            );
            assert!(
                !joined.contains("rm"),
                "Allowed a joined command containing 'rm': {argv:?}"
            );
        }
        RawExecFixture::Anchored => {
            let uptime = argv.len() == 1 && argv[0] == "/usr/bin/uptime";
            let systemctl = argv.len() == 3
                && argv[0] == "/usr/bin/systemctl"
                && (argv[1] == "status" || argv[1] == "restart")
                && !argv[2].is_empty()
                && argv[2]
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || "@._-".contains(c));
            assert!(
                uptime || systemctl,
                "anchored allow admitted an argv outside its patterns: {argv:?}"
            );
        }
        RawExecFixture::Unanchored => {
            // Fuzzes ADR-0019's whole-command auto-anchoring: the engine wraps
            // every allow pattern in \A(?:...)\z, so these unanchored and `(?m)^$`
            // patterns may admit only these exact commands, never a substring
            // or one line of a multiline argv.
            assert!(
                argv == ["/usr/bin/uptime"] || argv == ["/usr/bin/id"],
                "unanchored allow admitted an argv outside its patterns: {argv:?}"
            );
        }
        RawExecFixture::DenyAll => panic!("deny-all Policy allowed {argv:?}"),
    }
});
