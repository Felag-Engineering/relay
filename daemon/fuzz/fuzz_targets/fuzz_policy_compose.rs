//! Fuzzes the Policy parse/compile path behind `load_policy` (`compose` and
//! `compose_fragments`) and the linter, never the hardened open. The headline
//! oracle is parity: with an incomplete vocabulary (`vocabulary_complete` false)
//! the linter reports an error exactly when the loader refuses. A complete
//! vocabulary (`policy check --templates`) only adds Errors, so it can fail a
//! file `compose` accepts but never pass one it refuses.
//!
//! A crash here is a Policy-load finding: file it, never paper over it.
//!
//! Input: byte 0 selects whether there is a Policy file (bit 0). The rest is
//! UTF-8, `SEP`-separated fields: the Policy file first when present, then the
//! Policy fragments.
#![no_main]

use libfuzzer_sys::fuzz_target;
use relay_daemon_fuzz::policy_oracle::{policy_sources, MAX_FRAGMENTS};
use relay_policy::{compose, compose_fragments, lint_composed, lint_fragments, Decision, Request};

fuzz_target!(|data: &[u8]| {
    let Some((&sel, rest)) = data.split_first() else {
        return;
    };
    let Ok(rest) = std::str::from_utf8(rest) else {
        return;
    };
    if rest.len() > 64 * 1024 {
        return;
    }
    let (file, frags) = policy_sources(sel, rest);
    if frags.len() > MAX_FRAGMENTS {
        return;
    }

    let loaded = match &file {
        Some(f) => compose(f, &frags),
        None => compose_fragments(&frags),
    };
    // `vocabulary_complete = false` makes every unknown name a Warning, so the only
    // Errors left are parse failures and invalid regexes: what `compose` refuses.
    let report = match &file {
        Some(f) => lint_composed(f, &frags, &[], false),
        None => lint_fragments(&frags, &[], false),
    };

    // P1: parity.
    assert_eq!(
        loaded.is_ok(),
        !report.has_errors(),
        "lint and load disagree: load {:?}, findings {:?}, parse errors {:?}",
        loaded.as_ref().err(),
        report.findings,
        report.parse_errors
    );

    // P2: report shape.
    assert_eq!(
        report.parse_error.is_some(),
        !report.parse_errors.is_empty()
    );
    if report.parse_error.is_some() {
        assert!(report.findings.is_empty(), "parse error beside findings");
    }
    assert!(report.parse_errors.len() <= frags.len() + usize::from(file.is_some()));

    let Ok(policy) = loaded else {
        return;
    };

    // P3.
    let fp = policy.fingerprint();
    assert!(
        fp.len() == 64 && fp.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')),
        "fingerprint is not 64 lowercase hex: {fp:?}"
    );
    assert_eq!(policy.composed_without_policy_file(), file.is_none());

    // P4: composition order is by fragment name, not input order.
    if frags.len() >= 2 {
        let mut reversed = frags.clone();
        reversed.reverse();
        let again = match &file {
            Some(f) => compose(f, &reversed),
            None => compose_fragments(&reversed),
        }
        .expect("the same sources in another input order compose");
        assert_eq!(policy.fingerprint(), again.fingerprint());
        assert_eq!(policy.raw_allow_patterns(), again.raw_allow_patterns());
        assert_eq!(policy.raw_deny_patterns(), again.raw_deny_patterns());
        assert_eq!(
            policy.operation_allow_rules(),
            again.operation_allow_rules()
        );
        assert_eq!(policy.deny_rules(), again.deny_rules());
    }

    // P5: deny-by-default (invariant 3), through `decide` only (invariant 12).
    const PROBE: &str = "relay.fuzz.unnamed";
    if !policy.allowed_operations().iter().any(|n| n == PROBE) {
        let verdict = policy.decide(&Request::Operation {
            name: PROBE,
            positional: &[],
            path_positions: &[],
        });
        assert!(
            matches!(verdict.decision, Decision::Deny { .. }),
            "an unnamed Operation was not denied"
        );
        assert!(verdict.raw_exec_permit.is_none());
    }
    if !policy.raw_exec_enabled() {
        let argv = vec!["/usr/bin/id".to_string()];
        let verdict = policy.decide(&Request::RawExec { argv: &argv });
        assert!(
            matches!(verdict.decision, Decision::Deny { .. }),
            "Raw Exec was allowed with no [raw_exec] section"
        );
        assert!(verdict.raw_exec_permit.is_none());
    }
});
