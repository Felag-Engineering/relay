#![cfg(test)]
//! ---------------------------------------------------------------------------
//! Property tests (issue #218) — bounded proptest fuzzing of the Policy engine
//! ---------------------------------------------------------------------------
//!
//! Red-team posture: this suite ATTACKS `evaluate`/`evaluate_raw_exec` for
//! panics and invariant violations. It asserts only invariants the engine
//! already implements — deny-by-default (PB1) and deny-beats-allow (PB2, PB3)
//! — and never reimplements Policy evaluation (ADR-0011): every oracle below
//! calls the real engine and compares against a literal-string mirror of its
//! documented semantics (`Policy::evaluate` / `Policy::evaluate_raw_exec`).
//! A drift between an oracle and the engine is a TEST bug — fix the test,
//! never the engine (see the module CONSTRAINTS note).
//!
//! Regression seeds (#259): proptest persists a failing case to
//! `daemon/proptest-regressions/<module path>.txt`, and that directory is
//! deliberately TRACKED. A seed file is a counterexample: commit it with the fix
//! so it replays for everyone, and never delete one as noise. A seed that
//! encodes an oracle bug rather than an engine bug may be removed only in the
//! change that fixes the oracle, after the case is promoted into a named test.
//!
//! This module is a sibling of `mod tests`, `mod raw_exec_redteam`, and
//! `mod loader_hardening_tests` above; it never edits them and builds its own
//! fixtures from literal TOML rather than reaching into a private sibling
//! module's helpers.
use super::*;
use proptest::prelude::*;

// -------------------------------------------------------------------
// Bounded strategies
// -------------------------------------------------------------------

/// One argv/arg element: full-Unicode (including control chars), 0-8
/// chars — bounded but wide enough to probe the panic surface.
fn arb_argv_elem() -> impl Strategy<Value = String> {
    prop::collection::vec(any::<char>(), 0..8).prop_map(|cs| cs.into_iter().collect())
}

/// A bounded argv/args vector, 0-6 elements.
fn arb_argv() -> impl Strategy<Value = Vec<String>> {
    prop::collection::vec(arb_argv_elem(), 0..6)
}

/// An operation name: usually one of the four known names, occasionally
/// an arbitrary string (unknown-operation coverage).
fn arb_op_name() -> impl Strategy<Value = String> {
    prop_oneof![
        Just(operations::SYSTEM_FACTS.to_string()),
        Just(operations::FILE_READ.to_string()),
        Just(operations::SERVICE_RESTART.to_string()),
        Just(operations::PKG_INSTALL.to_string()),
        arb_argv_elem(),
    ]
}

/// A TOML- and regex-literal-safe token: no escaping needed when spliced
/// into a generated Policy TOML string or a regex pattern.
fn arb_safe_token() -> impl Strategy<Value = String> {
    prop::string::string_regex("[A-Za-z0-9._@-]{1,8}").unwrap()
}

// -------------------------------------------------------------------
// PB1 — evaluate / evaluate_raw_exec never panic; an empty Policy denies
// everything by default (ADR-0002 invariant 3).
// -------------------------------------------------------------------

/// A hand-written, richer fixed Policy for PB1's panic-surface coverage
/// only — similar in shape to `policy.example.toml`. Deliberately NOT
/// `super::tests::make_query_test_policy()`: that helper is private to a
/// sibling test module and unreachable from here; this is a
/// self-contained literal built fresh in this module.
const RICHER_POLICY_TOML: &str = r#"
[[operation]]
name = "service.restart"
allowed_args = [["nginx", "php-fpm"]]

[[operation]]
name = "pkg.install"
allowed_args = [["nginx", "curl"], ["*"]]

[[operation]]
name = "system.facts"
allowed_args = []

[[deny]]
name = "file.read"
args = [["/etc/shadow"]]

[raw_exec]
allow = ["^/usr/bin/systemctl (status|restart) [A-Za-z0-9@._-]+$"]
deny = ["--force", "\\brm\\b"]
"#;

fn richer_policy() -> Policy {
    from_toml_str(RICHER_POLICY_TOML).expect("hand-written richer policy must parse")
}

// -------------------------------------------------------------------
// PB3 fixture — Raw Exec deny-beats-allow (`evaluate_raw_exec`).
// -------------------------------------------------------------------

fn raw_exec_pb3_policy() -> Policy {
    from_toml_str("[raw_exec]\nallow = [\".*\"]\ndeny = [\"secret\"]\n")
        .expect("PB3 fixed raw_exec policy must parse")
}

// -------------------------------------------------------------------
// PB4 fixture — the whitespace guard in isolation, no deny at all.
// -------------------------------------------------------------------

fn raw_exec_pb4_policy() -> Policy {
    // DOTALL (`(?s)`), unlike PB3's plain `.*`, so this policy's allow
    // pass would admit ANY argv (newlines included) if it ever ran —
    // isolating the guard as the only thing that can produce a Deny.
    from_toml_str("[raw_exec]\nallow = ['(?s).*']\n").expect("PB4 fixed raw_exec policy must parse")
}

/// `denied` paired with an `arg` that is drawn from `denied` itself about
/// half the time (via `prop::sample::select`) and from the same
/// `arb_safe_token()` domain otherwise. Independent sampling of `arg` and
/// `denied` makes a `denied.contains(&arg)` hit astronomically unlikely
/// (~0.12% observed) because the token space is large, so the deny
/// branch of `op_deny_beats_allow` almost never fired; biasing `arg`
/// toward an actual element of `denied` makes both oracle branches fire
/// at a normal rate without changing the oracle itself.
fn denied_and_arg() -> impl Strategy<Value = (Vec<String>, String)> {
    prop::collection::vec(arb_safe_token(), 1..4).prop_flat_map(|denied| {
        let arg = prop_oneof![prop::sample::select(denied.clone()), arb_safe_token()];
        (Just(denied), arg)
    })
}

/// `arb_argv()`, but with the literal deny token ("secret" or a
/// substring match "run-secret-now") injected as an occasional element,
/// so `raw_exec_deny_beats_allow`'s deny (`hits`) branch fires reliably
/// instead of relying on wide-Unicode `arb_argv_elem()` to ever emit the
/// literal ASCII word "secret" (observed: 0 times in 12,800 cases).
fn arb_argv_with_secret() -> impl Strategy<Value = Vec<String>> {
    prop::collection::vec(
        prop_oneof![
            arb_argv_elem(),
            Just("secret".to_string()),
            Just("run-secret-now".to_string()),
        ],
        0..6,
    )
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    // ---------------------------------------------------------------
    // PB1 `evaluate_never_panics_and_deny_by_default`
    // ---------------------------------------------------------------
    #[test]
    fn evaluate_never_panics_and_deny_by_default(
        name in arb_op_name(),
        args in arb_argv(),
        argv in arb_argv(),
    ) {
        let empty = from_toml_str("").expect("empty policy string must parse (deny-all)");

        prop_assert!(
            matches!(empty.evaluate(&name, &args), Decision::Deny { .. }),
            "an empty Policy must deny-by-default for every operation/args pair"
        );
        prop_assert!(
            matches!(empty.evaluate_raw_exec(&argv), Decision::Deny { .. }),
            "an empty Policy must deny-by-default for every Raw Exec argv"
        );

        // Panic-surface only against a richer fixed Policy — no oracle here,
        // the point is only that neither call panics on arbitrary Unicode
        // input; PB2/PB3 below own the narrower deny-beats-allow oracles.
        let richer = richer_policy();
        let _ = richer.evaluate(&name, &args);
        let _ = richer.evaluate_raw_exec(&argv);
    }

    // ---------------------------------------------------------------
    // PB2 `op_deny_beats_allow` — mirrors policy.rs:705-790 exactly.
    // ---------------------------------------------------------------
    #[test]
    fn op_deny_beats_allow((denied, arg) in denied_and_arg()) {
        let denied_toml = denied
            .iter()
            .map(|d| format!("{d:?}"))
            .collect::<Vec<_>>()
            .join(", ");
        let toml = format!(
            "[[operation]]\nname = \"op\"\nallowed_args = [[\"*\"]]\n\n\
             [[deny]]\nname = \"op\"\nargs = [[{denied_toml}]]\n"
        );
        let policy = from_toml_str(&toml)
            .unwrap_or_else(|e| panic!("generated TOML {toml:?} failed to parse: {e}"));

        let decision = policy.evaluate("op", std::slice::from_ref(&arg));

        if denied.contains(&arg) {
            prop_assert!(
                matches!(decision, Decision::Deny { .. }),
                "denied arg {arg:?} in {denied:?} must be denied despite the wildcard allow"
            );
        } else {
            prop_assert!(
                matches!(decision, Decision::Allow(_)),
                "arg {arg:?} not in denied set {denied:?} must be allowed by the wildcard"
            );
        }
    }

    // ---------------------------------------------------------------
    // PB3 `raw_exec_deny_beats_allow` — mirrors `evaluate_raw_exec`
    // exactly, including the ADR-0019 whitespace guard (amended
    // 2026-09-16 to cover every element, not just argv[0]).
    // ---------------------------------------------------------------
    #[test]
    fn raw_exec_deny_beats_allow(argv in arb_argv_with_secret()) {
        let policy = raw_exec_pb3_policy();
        let decision = policy.evaluate_raw_exec(&argv);

        if argv.is_empty() {
            // Empty argv rule: always denied, before any allow/deny
            // pattern is even consulted.
            let is_deny = matches!(decision, Decision::Deny { .. });
            prop_assert!(is_deny, "empty argv must always be denied");
        } else {
            // Mirrors the engine's order exactly: deny pass, then the
            // whitespace guard, then the allow pass.
            //
            // "secret" is a literal regex, so is_match <=> contains; deny
            // is tested against the joined string, any raw element, OR any
            // canonical element (ADR-0019 — for a substring pattern this
            // third disjunct is implied by the joined one, since every
            // canonical element is a substring of the joined string; it is
            // spelled out so the oracle mirrors the engine's three
            // disjuncts rather than a simplification of them).
            let joined = argv.join(" ");
            let hits = joined.contains("secret")
                || argv.iter().any(|a| a.contains("secret"))
                || joined.split_whitespace().any(|c| c.contains("secret"));
            // The guard: argv[0] must be non-empty, and EVERY element
            // (including argv[0]) must carry no `char::is_whitespace`
            // char. `arb_argv_elem()` is full-Unicode and 0-8 chars, so it
            // generates both empty and whitespace-bearing elements
            // regularly, in every position.
            let guarded = argv[0].is_empty()
                || argv.iter().any(|a| a.chars().any(char::is_whitespace));
            if hits {
                // Deny-beats-allow AND deny-beats-guard: a deny pattern
                // keeps its attribution even when the guard would also fire.
                let attributed = matches!(
                    decision,
                    Decision::Deny { rule: Some(Rule::RawExecDeny { .. }), .. }
                );
                prop_assert!(
                    attributed,
                    "argv containing 'secret' must be denied by the deny pattern, with the \
                     pattern attributed, despite the .* allow (and despite the whitespace \
                     guard)"
                );
            } else if guarded {
                let is_guard_deny = matches!(
                    &decision,
                    Decision::Deny { rule: None, reason } if reason.starts_with("raw exec argv[")
                );
                prop_assert!(
                    is_guard_deny,
                    "an empty argv[0], or any element carrying whitespace, with no deny hit \
                     must be refused by the ADR-0019 guard"
                );
            } else {
                // No element carries whitespace, so the joined string has
                // no newline (the join separator is an ASCII space, not a
                // newline) and `.*` (no DOTALL) matches all of it.
                let is_allow = matches!(decision, Decision::Allow(_));
                prop_assert!(is_allow, "argv not containing 'secret' must be allowed by .*");
            }
        }
    }

    // ---------------------------------------------------------------
    // PB4 `raw_exec_whitespace_element_never_allowed` — the whitespace
    // guard in isolation: no deny pattern exists at all, and the allow
    // pattern is permissive enough (DOTALL) to admit anything the guard
    // does not refuse first.
    // ---------------------------------------------------------------
    #[test]
    fn raw_exec_whitespace_element_never_allowed(argv in arb_argv()) {
        let policy = raw_exec_pb4_policy();
        let decision = policy.evaluate_raw_exec(&argv);

        if !argv.is_empty() {
            let guarded = argv[0].is_empty()
                || argv.iter().any(|a| a.chars().any(char::is_whitespace));
            if guarded {
                let is_guard_deny = matches!(
                    &decision,
                    Decision::Deny { rule: None, reason } if reason.starts_with("raw exec argv[")
                );
                prop_assert!(
                    is_guard_deny,
                    "an empty argv[0], or any element carrying whitespace, must be refused \
                     by the whitespace guard; got {decision:?}"
                );
            } else {
                prop_assert!(
                    matches!(decision, Decision::Allow(_)),
                    "with no deny pattern and a DOTALL allow, a whitespace-clean, \
                     non-empty-argv[0] argv must be allowed; got {decision:?}"
                );
            }
        }
    }
}
