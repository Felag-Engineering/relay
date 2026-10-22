#![cfg(test)]
//! ---------------------------------------------------------------------------
//! Raw Exec red-team harness (issue #214)
//! ---------------------------------------------------------------------------

//! Adversarial, table-driven red-team suite against `evaluate_raw_exec`'s
//! matching model: regex anchoring, argv-join ambiguity, and the deny/allow
//! asymmetry (deny is tested against the joined command, any raw element, OR
//! any canonical element; allow is now tested against the WHOLE joined
//! command — ADR-0019, amended 2026-09-16 — and every argv element is guarded
//! against whitespace before the allow pass runs at all).
//!
//! Test-only: this module never touches `evaluate_raw_exec`, `from_toml_str`,
//! `compile_regexes`, the loader, or the lint code above. It asserts current
//! behavior (green rows, some of which document accepted footguns rather than
//! bugs). The one genuine deny-evasion bypass it found (#227) was committed as
//! a standalone `#[ignore]`d test while the fix was an open ADR-gated decision;
//! that decision is ADR-0019 (canonical-element deny matching + the argv[0]
//! whitespace guard), so the test is now enabled and pins the fix, with the
//! neighbouring shapes added as Axis 7 rows. The #214 "documented-intended"
//! unanchored-allow footgun this module used to pin as accepted was removed
//! outright by the 2026-09-16 amendment: an unanchored allow pattern now
//! matches the whole command, so it can no longer admit a hostile argv merely
//! because the pattern text appears somewhere inside the joined string.
//!
//! `redteam_cases()` is the single extension point later red-team issues
//! (e.g. argv-smuggling/encoding) append rows to.
//!
//! Issue #223 appended three further axes on top of #214's anchoring/join
//! baseline above: interpreter smuggling (argv[0] / permitted wrapper),
//! whitespace/control bytes against the space-join, and encoding/inert-data
//! (regex-as-if-shell footguns). That red-team pass found NO new genuine
//! bypass — every appended row is a green regression, either fail-closed
//! (safe) or a documented operator footgun where the engine matches exactly
//! what the pattern literally says. The one tracked bypass against
//! `evaluate_raw_exec` was #227 (element-merge deny evasion), fixed under
//! ADR-0019 and pinned by the Axis 7 rows and
//! `deny_element_merge_closed_by_canonical_elements` below; #236 is a
//! file.read (structured-Operation, `evaluate()`) finding covered by the
//! second table further below in this module — it is unrelated to the Raw
//! Exec argv gate this section's `redteam_cases()` covers. No `#[ignore]`d
//! bypass remains in either table.
use super::*;

// The shared `args` helper, renamed to Raw Exec vocabulary.
use crate::test_support::args as argv;

/// Coarse red-team classification of a Raw Exec `Decision`: does the
/// command run, is it denied by a specific rule, refused by the ADR-0019
/// `argv[0]` guard, or denied by default. Deliberately coarser than
/// `Decision` itself — the exact `reason` string is owned by the
/// golden-reason tests in `mod tests`, and on this path by
/// `argv0_refused_unless_single_program_token` and
/// `deny_reason_names_the_matched_form_and_text` below, not by this
/// harness.
#[derive(Debug, Clone, Copy)]
enum Expect {
    /// `Decision::Allow(_)`.
    Allow,
    /// `Decision::Deny` with a specific `Rule::RawExecDeny` attributed.
    DenyByPattern,
    /// `Decision::Deny` with `rule: None` from the ADR-0019 whitespace
    /// guard: `argv[0]` empty or containing whitespace, or ANY other
    /// element containing whitespace (amended 2026-09-16). Structurally
    /// identical to `DenyByDefault` in `Decision`, so the table
    /// distinguishes the two by the reason starting with `"raw exec
    /// argv["`.
    DenyByGuard,
    /// `Decision::Deny` with `rule: None` because no allow pattern
    /// matched — and specifically *not* the whitespace guard.
    DenyByDefault,
}

/// One red-team case: a self-contained Policy fixture, an argv, and the
/// expected coarse decision. `redteam_cases()` is the extension point for
/// follow-up red-team issues to append rows to.
struct Case {
    name: &'static str,
    policy_toml: &'static str,
    argv: &'static [&'static str],
    expect: Expect,
    note: &'static str,
}

fn redteam_cases() -> Vec<Case> {
    vec![
            // --- Axis 1: regex anchoring / unanchored substring -------------
            Case {
                name: "anchored_allow_rejects_suffix_injection",
                policy_toml: "[raw_exec]\nallow = [\"^/usr/bin/systemctl (status|restart) [A-Za-z0-9@._-]+$\"]\n",
                argv: &["/usr/bin/systemctl", "restart", "nginx", ";", "touch", "/tmp/pwn"],
                expect: Expect::DenyByDefault,
                note: "trailing tokens appended after the injected command break the anchored $, so the anchored allow correctly refuses the suffix-injection attempt",
            },
            Case {
                name: "anchored_allow_rejects_prefix_injection",
                policy_toml: "[raw_exec]\nallow = [\"^/usr/bin/systemctl (status|restart) [A-Za-z0-9@._-]+$\"]\n",
                argv: &["/bin/sh", "-c", "/usr/bin/systemctl restart nginx"],
                expect: Expect::DenyByGuard,
                note: "argv[2] \"/usr/bin/systemctl restart nginx\" carries whitespace, so the ADR-0019 whitespace guard now refuses this before any allow pattern runs; the anchored-^ coverage this row used to pin moved to anchored_allow_blocks_same_foreign_argv0 below, whose argv has no whitespace and so reaches the (now full-match) allow pass",
            },
            Case {
                name: "unanchored_allow_full_match_denies_foreign_argv0",
                policy_toml: "[raw_exec]\nallow = [\"/usr/bin/systemctl (status|restart) nginx\"]\n",
                argv: &["/bin/rm", "-rf", "/var/log", "&&", "/usr/bin/systemctl", "restart", "nginx"],
                expect: Expect::DenyByDefault,
                note: "the #214 unanchored-substring footgun this row used to document as intended is gone: an allow pattern now matches the WHOLE joined command (ADR-0019, amended 2026-09-16), so a pattern that merely APPEARS as a substring of the joined command no longer admits the hostile argv whose real argv[0] is /bin/rm",
            },
            Case {
                name: "anchored_allow_blocks_same_foreign_argv0",
                policy_toml: "[raw_exec]\nallow = [\"^/usr/bin/systemctl (status|restart) [A-Za-z0-9@._-]+$\"]\n",
                argv: &["/bin/rm", "-rf", "/var/log", "&&", "/usr/bin/systemctl", "restart", "nginx"],
                expect: Expect::DenyByDefault,
                note: "paired contrast with unanchored_allow_full_match_denies_foreign_argv0: the identical hostile argv is refused whether the allow pattern is anchored or not, since full-match is now enforced either way",
            },
            // --- Axis 2: argv-join ambiguity ---------------------------------
            Case {
                name: "join_collapse_two_args_same_decision_two_elements",
                policy_toml: "[raw_exec]\nallow = [\"^/usr/bin/systemctl (status|restart) [A-Za-z0-9@._-]+$\"]\n",
                argv: &["/usr/bin/systemctl", "restart", "nginx"],
                expect: Expect::Allow,
                note: "the intended three-element shape; paired with join_collapse_two_args_same_decision_merged_element, which used to get the identical decision from the same joined string but is now refused by the ADR-0019 whitespace guard before the two argvs can be confused (R10 closed)",
            },
            Case {
                name: "join_collapse_two_args_same_decision_merged_element",
                policy_toml: "[raw_exec]\nallow = [\"^/usr/bin/systemctl (status|restart) [A-Za-z0-9@._-]+$\"]\n",
                argv: &["/usr/bin/systemctl", "restart nginx"],
                expect: Expect::DenyByGuard,
                note: "argv[1] \"restart nginx\" carries whitespace, so the ADR-0019 whitespace guard (amended 2026-09-16) refuses this before the allow pass ever runs — no two distinct argvs can share a joined form anymore (R10 closed)",
            },
            Case {
                name: "join_single_element_whole_command",
                policy_toml: "[raw_exec]\nallow = [\"^/usr/bin/systemctl (status|restart) [A-Za-z0-9@._-]+$\"]\n",
                argv: &["/usr/bin/systemctl restart nginx"],
                expect: Expect::DenyByGuard,
                note: "was the sharpest 'what the gate cannot see' row under #214 (a single argv element containing the whole command joins to the same string and was ALLOWED, though execv's real target is a literal filename containing spaces); the ADR-0019 argv[0]-whitespace guard now refuses it before any pattern is consulted — argv[0] is the program, and the joined form must not be able to disguise which program that is (invariant #1). Deny carries rule: None (a fail-closed precondition, not a matched deny pattern)",
            },
            // --- Axis 3: deny/allow asymmetry --------------------------------
            Case {
                name: "deny_matches_joined_only",
                policy_toml: "[raw_exec]\nallow = [\"^systemctl .+$\"]\ndeny = [\"restart nginx\"]\n",
                argv: &["systemctl", "restart", "nginx"],
                expect: Expect::DenyByPattern,
                note: "duplicates the existing raw_exec_deny_matches_joined_string_only test in mod tests (policy.rs:1121-1143); kept here only to seed the self-contained extensible table with the joined disjunct of the deny pass",
            },
            Case {
                name: "deny_matches_per_element_only_beats_allow",
                policy_toml: "[raw_exec]\nallow = [\"^systemctl restart nginx --force$\"]\ndeny = [\"^--force$\"]\n",
                argv: &["systemctl", "restart", "nginx", "--force"],
                expect: Expect::DenyByPattern,
                note: "the allow pattern is anchored to match this exact joined command, so the allow pass alone would let it through, but the deny pass runs first (deny-beats-allow) and the anchored deny ^--force$ fires on the --force argv element even though it does not match the joined string; exercises the per-element disjunct of the deny pass",
            },
            Case {
                name: "allow_joined_only_is_fail_closed",
                policy_toml: "[raw_exec]\nallow = [\"^nginx$\"]\n",
                argv: &["systemctl", "restart", "nginx"],
                expect: Expect::DenyByDefault,
                note: "key red-team result: the deny/allow asymmetry cannot widen allow — an allow pattern that matches only an individual argv element ('nginx') never fires because the allow pass tests the joined string only (policy.rs:765-771); the gate stays fail-closed",
            },
            // --- Axis 4: interpreter smuggling (argv[0] / permitted wrapper) ---
            Case {
                name: "interp_anchored_allow_rejects_shell_wrapper_argv0",
                policy_toml: "[raw_exec]\nallow = [\"^/usr/bin/ansible-playbook /etc/ansible/site.yml$\"]\n",
                argv: &["/bin/sh", "-c", "/usr/bin/ansible-playbook /etc/ansible/site.yml"],
                expect: Expect::DenyByGuard,
                note: "interpreter-flavored sibling of anchored_allow_rejects_prefix_injection: argv[2] carries whitespace, so the ADR-0019 whitespace guard refuses this before the allow pass ever runs",
            },
            Case {
                name: "interp_unanchored_allow_full_match_denies_shell_argv0",
                policy_toml: "[raw_exec]\nallow = [\"/usr/bin/ansible-playbook\"]\n",
                argv: &["/bin/sh", "-c", "/usr/bin/ansible-playbook"],
                expect: Expect::DenyByDefault,
                note: "no argv element carries whitespace, so this row isolates full-match rather than the guard: the allow pattern must now match the WHOLE joined command (ADR-0019, amended 2026-09-16), and \"/usr/bin/ansible-playbook\" alone does not equal \"/bin/sh -c /usr/bin/ansible-playbook\" — the #214 substring-admits-a-shell-argv0 footgun this row used to pin as intended is gone",
            },
            Case {
                name: "interp_shell_c_script_with_spaces_refused_by_guard",
                policy_toml: "[raw_exec]\nallow = [\"/usr/bin/ansible-playbook\"]\n",
                argv: &["/bin/sh", "-c", "/usr/bin/ansible-playbook --check"],
                expect: Expect::DenyByGuard,
                note: "the pre-amendment argv for interp_unanchored_allow_full_match_denies_shell_argv0: argv[2] \"/usr/bin/ansible-playbook --check\" carries whitespace, so the ADR-0019 guard refuses it before the (now full-match) allow pass would even get to say no",
            },
            Case {
                name: "interp_env_wrapper_full_anchor_allows_intended",
                policy_toml: "[raw_exec]\nallow = [\"^/usr/bin/env python3 /opt/deploy/run.py$\"]\n",
                argv: &["/usr/bin/env", "python3", "/opt/deploy/run.py"],
                expect: Expect::Allow,
                note: "documented-intended baseline: the intended env-wrapped invocation, fully anchored end-to-end, is allowed; pairs with interp_env_wrapper_argv0_anchor_admits_arbitrary_interpreter to show that anchoring the WHOLE command (not just argv[0]) is what makes this safe",
            },
            Case {
                name: "interp_env_wrapper_argv0_anchor_admits_arbitrary_interpreter",
                policy_toml: "[raw_exec]\nallow = [\"^/usr/bin/env .*$\"]\n",
                argv: &["/usr/bin/env", "bash", "-c", "id"],
                expect: Expect::Allow,
                note: "KEY interpreter-smuggling result, materially higher severity than the others, and it SURVIVES full-match: even a pattern anchored end-to-end (^...$) is INSUFFICIENT when argv[0] is an exec-wrapper (/usr/bin/env) and the author writes a trailing .*, because env re-dispatches to argv[1] and thus reaches bash — a plausible, seemingly-careful anchored allow still yields arbitrary command execution; not a code bug (the engine matched the pattern exactly; the regex engine has no model of which binaries re-dispatch, and denylisting them would be an ADR-gated binary-semantics change), so no finding is filed, but operator guidance is: anchor the WHOLE command for wrapper interpreters (env, xargs, nice, timeout, sudo, nohup, setsid, ...), never just argv[0]+space, and never a trailing .*",
            },
            Case {
                name: "interp_env_wrapper_prefix_only_allow_now_denied",
                policy_toml: "[raw_exec]\nallow = [\"^/usr/bin/env \"]\n",
                argv: &["/usr/bin/env", "bash", "-c", "id"],
                expect: Expect::DenyByDefault,
                note: "the OLD R4 pattern (anchored at argv[0]+space only, no trailing .* and no closing $): under full-match this no longer admits anything, since \"^/usr/bin/env \" cannot match the whole command \"/usr/bin/env bash -c id\" end-to-end. Contrast interp_env_wrapper_argv0_anchor_admits_arbitrary_interpreter, whose trailing .* is what keeps the re-dispatch footgun alive under full-match",
            },
            // --- Axis 5: whitespace / control bytes vs the space-join (policy.rs:813) ---
            Case {
                name: "ctl_tab_in_arg_breaks_anchored_class_allow",
                policy_toml: "[raw_exec]\nallow = [\"^/usr/bin/systemctl (status|restart) [A-Za-z0-9@._-]+$\"]\n",
                argv: &["/usr/bin/systemctl", "restart", "nginx\tevil"],
                expect: Expect::DenyByGuard,
                note: "argv[2] \"nginx<TAB>evil\" carries whitespace, so the ADR-0019 whitespace guard refuses this before any allow pattern runs; the original allow-side pin (the character class rejects the tab) is now moot, since the guard fires first",
            },
            Case {
                name: "ctl_cr_in_arg_breaks_anchored_class_allow",
                policy_toml: "[raw_exec]\nallow = [\"^/usr/bin/systemctl (status|restart) [A-Za-z0-9@._-]+$\"]\n",
                argv: &["/usr/bin/systemctl", "restart", "nginx\revil"],
                expect: Expect::DenyByGuard,
                note: "same mechanism as ctl_tab_in_arg_breaks_anchored_class_allow with an embedded carriage return instead of a tab: the ADR-0019 whitespace guard now refuses this before any allow pattern runs, so the original allow-side pin is moot",
            },
            Case {
                name: "ctl_nul_in_arg_breaks_anchored_class_allow",
                policy_toml: "[raw_exec]\nallow = [\"^/usr/bin/systemctl (status|restart) [A-Za-z0-9@._-]+$\"]\n",
                argv: &["/usr/bin/systemctl", "restart", "nginx\0"],
                expect: Expect::DenyByDefault,
                note: "NUL is not Unicode whitespace, so the ADR-0019 guard does not fire; an embedded NUL still cannot satisfy [class]$ at the gate, so this fails closed too — independently, any NUL anywhere in argv also fails closed at execv, pinned end-to-end by raw_exec.rs::nul_in_argv_fails_closed_at_executor",
            },
            Case {
                name: "ctl_newline_in_arg_dot_does_not_cross",
                policy_toml: "[raw_exec]\nallow = [\"^/usr/bin/systemctl restart .+$\"]\n",
                argv: &["/usr/bin/systemctl", "restart", "nginx\n; rm -rf /"],
                expect: Expect::DenyByGuard,
                note: "argv[2] carries an embedded newline, so the ADR-0019 whitespace guard refuses this before any allow pattern runs; the original allow-side pin (RE2-style `.` not crossing a newline) is now moot, since the guard fires first",
            },
            Case {
                name: "ctl_trailing_newline_defeats_dollar_anchor",
                policy_toml: "[raw_exec]\nallow = [\"^/usr/bin/systemctl restart nginx$\"]\n",
                argv: &["/usr/bin/systemctl", "restart", "nginx\n"],
                expect: Expect::DenyByGuard,
                note: "argv[2] \"nginx\\n\" carries a trailing newline, so the ADR-0019 whitespace guard refuses this before any allow pattern runs; the original allow-side pin (the non-multiline $ semantics) is now moot, since the guard fires first",
            },
            Case {
                name: "ctl_slash_s_matches_unicode_nbsp",
                policy_toml: "[raw_exec]\nallow = ['(?s).*']\ndeny = ['y\\sz']\n",
                argv: &["x", "y\u{00A0}z"],
                expect: Expect::DenyByPattern,
                note: "semantics pin, moved to the DENY side: an NBSP-bearing element can no longer reach the allow pass at all (the ADR-0019 guard would refuse it first), so the \\s-matches-U+00A0-NBSP pin now lives on a deny, which the deny pass evaluates before the guard ever runs. Unicode-mode \\s (the regex crate default) matches NBSP in addition to tab/CR/LF; operator relevance: a \\s-based deny DOES catch NBSP used as a separator",
            },
            Case {
                name: "ctl_slash_s_does_not_match_nul",
                policy_toml: "[raw_exec]\nallow = ['^x y\\sz$']\n",
                argv: &["x", "y\0z"],
                expect: Expect::DenyByDefault,
                note: "semantics pin, paired with ctl_slash_s_matches_unicode_nbsp (a different fixture now — that row moved its \\s pin to a deny since an NBSP-bearing element can no longer reach the allow pass): \\s does NOT match NUL, so an operator writing \\s to catch 'any separator' catches NBSP/tab/CR/LF but not NUL; NUL is likewise not Unicode whitespace, so it neither trips the ADR-0019 guard nor splits a canonical element. Independently inert either way, since a NUL-bearing argv fails closed at execv regardless (executor test). NOT a new finding",
            },
            Case {
                name: "ctl_join_emits_ascii_space_matched_by_slash_s",
                policy_toml: "[raw_exec]\nallow = ['^/bin/rm -rf /$']\ndeny = ['rm\\s+-rf']\n",
                argv: &["/bin/rm", "-rf", "/"],
                expect: Expect::DenyByPattern,
                note: "positive pin: the space-join always emits ASCII 0x20 between elements (attacker-uncontrolled at the token boundary), which \\s+ matches, so a cross-token \\s-based deny fires on this canonical argv (deny-beats-allow); NUL-in-argv is independently inert regardless of any deny/allow outcome — any NUL anywhere in argv fails closed at execv, pinned by raw_exec.rs::nul_in_argv_fails_closed_at_executor, so it never reaches execution",
            },
            Case {
                name: "ctl_homoglyph_fails_anchored_ascii_allow_closed",
                policy_toml: "[raw_exec]\nallow = [\"^/usr/bin/systemctl restart nginx$\"]\n",
                argv: &["/usr/bin/systemctl", "restart", "ng\u{0456}nx"],
                expect: Expect::DenyByDefault,
                note: "a homoglyph in \"ng\u{0456}nx\" (Cyrillic U+0456, not Latin 'i') cannot satisfy an ASCII-literal allow — different bytes, no match, fail-closed — and cannot reach the real nginx unit either, since it is a different byte sequence; homoglyphs are inert to the argv gate, they never widen an allow",
            },
            // --- Axis 6: encoding / inert data + regex-as-if-shell footguns ---
            Case {
                name: "enc_dollar_paren_deny_matches_literal_inert",
                policy_toml: "[raw_exec]\nallow = ['^/bin/echo .+$']\ndeny = ['\\$\\(']\n",
                argv: &["/bin/echo", "$(id)"],
                expect: Expect::DenyByPattern,
                note: "regex-as-if-shell footgun: an operator writes deny = \\$\\( believing it 'blocks command substitution'; under argv exec there is NO shell (ADR-0001), so \"$(id)\" is inert literal data to /bin/echo — there was never a substitution to block. The deny DOES fire, on the literal characters, giving false confidence AND a false positive (it would also block a legitimate command that merely prints \"$(\"). Fold into #225. NOT a code bug",
            },
            Case {
                name: "enc_ampersand_deny_matches_literal_inert",
                policy_toml: "[raw_exec]\nallow = [\"^/bin/echo .+$\"]\ndeny = [\"&&\"]\n",
                argv: &["/bin/echo", "&&", "id"],
                expect: Expect::DenyByPattern,
                note: "regex-as-if-shell footgun, same class as enc_dollar_paren_deny_matches_literal_inert: deny = && ('block chaining') fires on the literal \"&&\" element, but /bin/echo receives \"&&\" and \"id\" as two literal, inert arguments — no shell chaining occurs. False-confidence footgun for &&/|/; deny patterns. Fold into #225. NOT a code bug",
            },
            Case {
                name: "enc_percent_encoding_is_literal_data",
                policy_toml: "[raw_exec]\nallow = [\"^/bin/echo .+$\"]\n",
                argv: &["/bin/echo", "%2fetc%2fshadow"],
                expect: Expect::Allow,
                note: "argv-is-data pin: percent-encoding is never decoded by the argv gate or the executor; \"%2fetc%2fshadow\" is literal bytes, not \"/etc/shadow\". Percent-encoding buys an attacker nothing at the argv gate — there is no decoding layer. A deny listing \"/etc/shadow\" would not match this either; expected, they are different strings, and Raw Exec does no decoding (any decoding is the target program's business, out of scope)",
            },
            Case {
                name: "enc_backslash_escapes_are_literal_data",
                policy_toml: "[raw_exec]\nallow = [\"^/bin/echo .+$\"]\n",
                argv: &["/bin/echo", "\\x2f\\t"],
                expect: Expect::Allow,
                note: "argv-is-data pin: backslash escape sequences are NOT C-unescaped anywhere on this path; argv carries the literal backslash bytes (\\x2f\\t is the 6 literal characters backslash-x-2-f-backslash-t, not a slash and a tab). `.+` matches them (no newline present), so the anchored allow admits it — pins that backslash-encoding is inert data",
            },
            Case {
                name: "enc_ifs_token_is_literal_not_expanded",
                policy_toml: "[raw_exec]\nallow = [\"^/bin/echo .+$\"]\n",
                argv: &["/bin/echo", "$IFS"],
                expect: Expect::Allow,
                note: "argv-is-data pin: $IFS (like $HOME, backticks) is a literal argv token to the gate; there is no shell, so no variable expansion or word-splitting ever happens (ADR-0001). The gate sees the literal string \"$IFS\"; the executor passes it literally too, re-pinned end-to-end by raw_exec.rs::argv_is_data_not_shell_expanded",
            },
            // --- Axis 7: argv canonicalization before the deny pass (#227 / ADR-0019) ---
            //
            // Every row below uses the #227 fixture: an anchored allow written
            // for the merged joined command plus the most precise deny an
            // operator can write for the flag (`^--force$`). Before ADR-0019
            // each merge/padding shape ALLOWED; the canonical-element disjunct
            // (joined re-split on whitespace) denies them all.
            Case {
                name: "canon_element_merge_denied",
                policy_toml: "[raw_exec]\nallow = [\"^systemctl restart nginx --force x$\"]\ndeny = [\"^--force$\"]\n",
                argv: &["systemctl", "restart", "nginx", "--force x"],
                expect: Expect::DenyByPattern,
                note: "the #227 reproduction, table form: merging the denied token into the next element leaves the joined string (and so the allow) intact and defeats the raw-element deny, but the canonical elements are [systemctl, restart, nginx, --force, x] and ^--force$ fires on --force (ADR-0019)",
            },
            Case {
                name: "canon_unmerged_form_still_denied",
                policy_toml: "[raw_exec]\nallow = [\"^systemctl restart nginx --force x$\"]\ndeny = [\"^--force$\"]\n",
                argv: &["systemctl", "restart", "nginx", "--force", "x"],
                expect: Expect::DenyByPattern,
                note: "control for canon_element_merge_denied: the honest, unmerged argv was denied before ADR-0019 (raw-element pass) and still is — monotonic in the deny direction, nothing that denied stops denying",
            },
            Case {
                name: "canon_merged_form_deny_still_fires_via_raw_element",
                policy_toml: "[raw_exec]\nallow = [\"^systemctl restart nginx --force x$\"]\ndeny = [\"^--force x$\"]\n",
                argv: &["systemctl", "restart", "nginx", "--force x"],
                expect: Expect::DenyByPattern,
                note: "proves the RAW-element pass is still live and was not replaced by the canonical one: a deny anchored to the merged element (^--force x$) matches neither the joined command (anchors) nor any canonical element ([--force], [x]) — only the raw element \"--force x\". Dropping the raw pass would silently lose this deny path",
            },
            Case {
                name: "canon_merged_form_deny_does_not_cover_unmerged_argv",
                policy_toml: "[raw_exec]\nallow = [\"^systemctl restart nginx --force x$\"]\ndeny = [\"^--force x$\"]\n",
                argv: &["systemctl", "restart", "nginx", "--force", "x"],
                expect: Expect::Allow,
                note: "honest limit, paired with canon_merged_form_deny_still_fires_via_raw_element: a deny anchored to a merged element is NARROW — it does not cover the unmerged argv, whose elements are \"--force\" and \"x\". Not a regression and not a bypass of anything ADR-0019 claims: the correct deny for this operator is ^--force$, which after ADR-0019 covers both shapes",
            },
            Case {
                name: "canon_leading_trailing_whitespace_merge_denied",
                policy_toml: "[raw_exec]\nallow = [\"^systemctl restart nginx .*$\"]\ndeny = [\"^--force$\"]\n",
                argv: &["systemctl", "restart", "nginx", "  --force  "],
                expect: Expect::DenyByPattern,
                note: "padding the denied token with leading/trailing whitespace inside one element does not survive canonicalization — split_whitespace discards leading and trailing runs, so the canonical element is exactly \"--force\" and the anchored deny fires",
            },
            Case {
                name: "canon_repeated_whitespace_merge_denied",
                policy_toml: "[raw_exec]\nallow = [\"^systemctl restart nginx .*$\"]\ndeny = [\"^--force$\"]\n",
                argv: &["systemctl", "restart", "nginx", "--force     x"],
                expect: Expect::DenyByPattern,
                note: "a repeated-whitespace run between the merged tokens collapses under split_whitespace (runs are one separator, no empty canonical elements), so the deny still sees a bare \"--force\"",
            },
            Case {
                name: "canon_tab_separator_merge_denied",
                policy_toml: "[raw_exec]\nallow = [\"^systemctl restart nginx .*$\"]\ndeny = [\"^--force$\"]\n",
                argv: &["systemctl", "restart", "nginx", "--force\tx"],
                expect: Expect::DenyByPattern,
                note: "TAB is Unicode whitespace, so it is a canonical-element separator even though the space-join never emits one: the merged element splits into [--force, x] and the anchored deny fires. Contrast ctl_tab_in_arg_breaks_anchored_class_allow, where a tab defeats an anchored ALLOW — canonicalization is deny-side only",
            },
            Case {
                name: "canon_newline_separator_merge_denied",
                policy_toml: "[raw_exec]\nallow = [\"^systemctl restart nginx (.|\\n)*$\"]\ndeny = [\"^--force$\"]\n",
                argv: &["systemctl", "restart", "nginx", "--force\nx"],
                expect: Expect::DenyByPattern,
                note: "LF likewise splits the merged element. The allow here spells (.|\\n)* because RE2-style `.` does not cross a newline (ctl_newline_in_arg_dot_does_not_cross) — the point of the row is that the deny fires even where an allow WOULD have matched, so the allow must genuinely match",
            },
            Case {
                name: "canon_cr_separator_merge_denied",
                policy_toml: "[raw_exec]\nallow = [\"^systemctl restart nginx .*$\"]\ndeny = [\"^--force$\"]\n",
                argv: &["systemctl", "restart", "nginx", "--force\rx"],
                expect: Expect::DenyByPattern,
                note: "CR splits the merged element too (Unicode whitespace), so a CR-separated merge is denied like the space- and tab-separated forms",
            },
            Case {
                name: "canon_nbsp_separator_merge_denied",
                policy_toml: "[raw_exec]\nallow = [\"^systemctl restart nginx .*$\"]\ndeny = [\"^--force$\"]\n",
                argv: &["systemctl", "restart", "nginx", "--force\u{00A0}x"],
                expect: Expect::DenyByPattern,
                note: "U+00A0 NBSP is Unicode whitespace, so split_whitespace treats it as a separator and the merge is denied; consistent with ctl_slash_s_matches_unicode_nbsp (the same Unicode notion of whitespace the regex crate's \\s uses) and with the ADR-0019 argv[0] guard, which is written against the same predicate",
            },
            Case {
                name: "canon_empty_elements_do_not_perturb_split",
                policy_toml: "[raw_exec]\nallow = [\"^systemctl .*$\"]\ndeny = [\"^--force$\"]\n",
                argv: &["systemctl", "", "restart", "nginx", "", "--force x"],
                expect: Expect::DenyByPattern,
                note: "empty argv elements inject extra spaces into the join (\"systemctl  restart nginx  --force x\") but produce NO empty canonical elements (split_whitespace skips runs), so a merged token surrounded by empty elements is still canonicalized to a bare \"--force\" and denied",
            },
            Case {
                name: "canon_three_token_merge_denied",
                policy_toml: "[raw_exec]\nallow = [\"^systemctl restart nginx --force x$\"]\ndeny = [\"^--force$\"]\n",
                argv: &["systemctl", "restart nginx --force x"],
                expect: Expect::DenyByPattern,
                note: "the whole tail collapsed into ONE element (four tokens merged): the joined string is unchanged so the anchored allow still matches, but canonicalization recovers every token and the anchored deny fires. argv[0] is clean here, so this is the canonical pass doing the work, not the ADR-0019 argv[0] guard",
            },
            Case {
                name: "guard_argv0_whitespace_refused_though_joined_form_allows",
                policy_toml: "[raw_exec]\nallow = [\"^systemctl restart nginx$\"]\n",
                argv: &["systemctl restart", "nginx"],
                expect: Expect::DenyByGuard,
                note: "ADR-0019 companion guard: the joined form \"systemctl restart nginx\" matches the anchored allow, but argv[0] is the literal two-word string \"systemctl restart\" — NOT the program the operator authorized (execv would look for a file of that name, which is ENOENT unless someone planted one). Refused with rule: None and a reason naming argv[0]. Pairs with guard_argv0_clean_same_joined_form_allowed",
            },
            Case {
                name: "guard_argv0_clean_same_joined_form_allowed",
                policy_toml: "[raw_exec]\nallow = [\"^systemctl restart nginx$\"]\n",
                argv: &["systemctl", "restart", "nginx"],
                expect: Expect::Allow,
                note: "control for guard_argv0_whitespace_refused_though_joined_form_allows: the identical joined string with a single-token argv[0] is still allowed — the guard rejects only the ambiguity about WHICH program runs, it does not narrow legitimate Raw Exec whose argv[0] is a single token",
            },
            Case {
                name: "guard_empty_argv0_refused",
                policy_toml: "[raw_exec]\nallow = [\"^ nginx$\"]\n",
                argv: &["", "nginx"],
                expect: Expect::DenyByGuard,
                note: "an EMPTY argv[0] is not a program either: the join emits a leading space so a (peculiar) allow can match, but execv would get \"\" and fail with ENOENT. Refusing it at the gate removes a 'Policy said yes' audit record for a command that can never run — same guard, same monotonic direction",
            },
            // --- ADR-0019 (amended 2026-09-16): the guard now covers EVERY
            // element, not just argv[0]. `allow = ['(?s).*']` and no deny, so
            // only the guard itself can produce a Deny on these rows.
            Case {
                name: "guard_tab_in_later_element_refused",
                policy_toml: "[raw_exec]\nallow = ['(?s).*']\n",
                argv: &["systemctl", "restart", "nginx\tx"],
                expect: Expect::DenyByGuard,
                note: "a tab in a NON-argv[0] element is refused by the amended guard before the (fully permissive) allow pattern is ever consulted",
            },
            Case {
                name: "guard_nbsp_in_later_element_refused",
                policy_toml: "[raw_exec]\nallow = ['(?s).*']\n",
                argv: &["systemctl", "restart", "nginx\u{00A0}x"],
                expect: Expect::DenyByGuard,
                note: "U+00A0 NBSP is Unicode whitespace, so a NON-argv[0] element carrying it is refused by the amended guard, same as a tab or newline",
            },
            Case {
                name: "guard_newline_in_later_element_refused",
                policy_toml: "[raw_exec]\nallow = ['(?s).*']\n",
                argv: &["systemctl", "restart", "nginx\nx"],
                expect: Expect::DenyByGuard,
                note: "a newline in a NON-argv[0] element is refused by the amended guard, even though the permissive `(?s).*` allow would otherwise match it (dot-matches-newline) — the guard runs before the allow pass",
            },
            Case {
                name: "guard_empty_later_element_allowed",
                policy_toml: "[raw_exec]\nallow = ['(?s).*']\n",
                argv: &["systemctl", "", "restart"],
                expect: Expect::Allow,
                note: "an empty element past argv[0] is NOT refused (only emptiness AT argv[0] is): the guard only checks non-argv[0] elements for whitespace, and an empty string contains none",
            },
            Case {
                name: "guard_runs_after_deny_pass_so_attribution_is_kept",
                policy_toml: "[raw_exec]\nallow = [\".*\"]\ndeny = [\"^--force$\"]\n",
                argv: &["prog x", "--force"],
                expect: Expect::DenyByPattern,
                note: "ordering pin: argv[0] here trips the guard AND a deny pattern matches. The deny pass runs first, so the Deny is attributed to ^--force$ (rule: Some) rather than collapsing to the guard's rule: None — same outcome either way, but the operator keeps the more specific explanation. Reordering the guard ahead of the deny pass flips this row to DenyByGuard",
            },
        ]
}

#[test]
fn raw_exec_redteam_table() {
    for case in redteam_cases() {
        let policy = from_toml_str(case.policy_toml)
            .unwrap_or_else(|e| panic!("case {}: policy TOML failed to parse: {e}", case.name));
        let decision = policy.evaluate_raw_exec(&argv(case.argv));
        // `DenyByGuard` and `DenyByDefault` are both `Deny { rule: None }`;
        // the ADR-0019 whitespace guard is the one whose reason starts
        // with "raw exec argv[", and each expectation asserts the
        // *absence* of the other.
        let matched = match (case.expect, &decision) {
            (Expect::Allow, Decision::Allow(_)) => true,
            (
                Expect::DenyByPattern,
                Decision::Deny {
                    rule: Some(Rule::RawExecDeny { .. }),
                    ..
                },
            ) => true,
            (Expect::DenyByGuard, Decision::Deny { rule: None, reason }) => {
                reason.starts_with("raw exec argv[")
            }
            (Expect::DenyByDefault, Decision::Deny { rule: None, reason }) => {
                !reason.starts_with("raw exec argv[")
            }
            _ => false,
        };
        assert!(
            matched,
            "case {}: {}: expected {:?}, got {decision:?}",
            case.name, case.note, case.expect
        );
    }
}

// -------------------------------------------------------------------
// Cross-axis (Axis 2 x Axis 3) — finding #227, RESOLVED by ADR-0019
// -------------------------------------------------------------------
//
// A deny rule could be evaded by merging the denied token into an
// adjacent argv element: an anchored per-element deny (`^--force$`)
// only ever saw the exact element `--force`, so appending anything to
// that element ("--force x") slipped past both the joined-string
// disjunct and the per-element disjunct of the deny pass, while an
// anchored allow pattern written for the merged form still matched the
// joined command. That defeated a deny rule outright — more severe than
// the unanchored-allow footgun above, which only ever over-widens an
// allow — and, unlike that footgun, it was not fixable by operator
// anchoring discipline: the operator wrote the most precise rule
// available and still lost.
//
// RESOLVED by ADR-0019: the deny pass now also runs over the CANONICAL
// elements (`argv.join(" ").split_whitespace()`), in addition to the
// joined string and the raw elements. This test was `#[ignore]`d while
// the finding was open; it now pins the fix. The neighbouring shapes
// (padding, tab/LF/CR/NBSP separators, empty elements, three-token
// merge, and the raw-element pass still firing on a merged-form deny)
// are the Axis 7 rows in `redteam_cases()` above.
#[test]
fn deny_element_merge_closed_by_canonical_elements() {
    let policy = from_toml_str(
        "[raw_exec]\nallow = [\"^systemctl restart nginx --force x$\"]\ndeny = [\"^--force$\"]\n",
    )
    .expect("policy must parse");

    // The exact #227 reproduction: merged form must now be denied, and
    // denied *by the deny pattern* (not by deny-by-default) — the allow
    // still matches the joined string, so only the deny pass can stop it.
    let decision = policy.evaluate_raw_exec(&argv(&["systemctl", "restart", "nginx", "--force x"]));
    assert!(
        matches!(
            &decision,
            Decision::Deny {
                rule: Some(Rule::RawExecDeny { pattern }),
                ..
            } if pattern == "^--force$"
        ),
        "anchored per-element deny ^--force$ must not be evadable by merging the denied \
             token into an adjacent argv element (#227 / ADR-0019); got {decision:?}"
    );

    // The unmerged form stays denied — the change is monotonic in the
    // deny direction, it never turns a Deny into an Allow.
    let unmerged =
        policy.evaluate_raw_exec(&argv(&["systemctl", "restart", "nginx", "--force", "x"]));
    assert!(
        matches!(unmerged, Decision::Deny { .. }),
        "the unmerged argv must remain denied; got {unmerged:?}"
    );
}

// -------------------------------------------------------------------
// ADR-0019 companion guard — argv[0] must be one non-empty program token
// -------------------------------------------------------------------
//
// The joined form is a lossy projection of argv: `["systemctl restart",
// "nginx"]` joins identically to the legitimate three-element form, so an
// allow pattern can approve a joined string whose argv[0] is not the
// program that will actually execute. Invariant 1 is that an argument
// must never change *which* command runs; for Raw Exec that is argv[0].
// The guard is fail-closed, so the Deny carries `rule: None` and a reason
// naming argv[0]; it runs AFTER the deny pass (so an attributable deny
// keeps its attribution) and BEFORE the allow pass. Since the 2026-09-16
// amendment the same guard also covers every OTHER argv element (a
// non-empty element carrying whitespace is refused too) — this test keeps
// its original argv[0]-only scope; the every-element case is
// `whitespace_in_any_argv_element_refused_naming_its_index` below.
#[test]
fn argv0_refused_unless_single_program_token() {
    // A permissive allow and no deny, so nothing but the guard can produce
    // the Deny.
    let policy = from_toml_str("[raw_exec]\nallow = [\".*\"]\n").expect("policy must parse");

    // Every Unicode-whitespace shape, in every position within argv[0],
    // plus the empty argv[0].
    for bad in [
        "",                                 // empty: not a program at all
        "systemctl restart",                // interior ASCII space (the #227-adjacent shape)
        "systemctl\trestart",               // interior tab
        "systemctl\nrestart",               // interior newline
        "systemctl\rrestart",               // interior carriage return
        "systemctl\u{00A0}restart",         // interior NBSP (Unicode whitespace)
        " systemctl",                       // leading space
        "systemctl ",                       // trailing space
        "/usr/bin/systemctl restart nginx", // the whole command as one element
    ] {
        let decision = policy.evaluate_raw_exec(&argv(&[bad, "nginx"]));
        assert!(
            matches!(
                &decision,
                Decision::Deny { rule: None, reason }
                if reason.contains("argv[0]")
            ),
            "argv[0] {bad:?} is not a single non-empty program token and must be refused \
                 with an argv[0] reason (ADR-0019); got {decision:?}"
        );
    }

    // Control: the same permissive allow admits a clean argv[0], so the
    // guard is what rejects the cases above — and NUL, which is not
    // Unicode whitespace, is not caught by this guard (it fails closed
    // later, at execv — raw_exec.rs::nul_in_argv_fails_closed_at_executor).
    for good in ["systemctl", "systemctl\0x"] {
        let decision = policy.evaluate_raw_exec(&argv(&[good, "nginx"]));
        assert!(
            matches!(decision, Decision::Allow(_)),
            "argv[0] {good:?} is a single non-empty token with no whitespace and must not \
                 be caught by the ADR-0019 guard; got {decision:?}"
        );
    }

    // Ordering: the guard runs after the deny pass, so a command that a
    // deny pattern claims keeps the pattern attribution instead of
    // collapsing to the guard's rule: None.
    let with_deny = from_toml_str("[raw_exec]\nallow = [\".*\"]\ndeny = [\"^--force$\"]\n")
        .expect("policy must parse");
    let decision = with_deny.evaluate_raw_exec(&argv(&["prog x", "--force"]));
    assert!(
        matches!(
            &decision,
            Decision::Deny {
                rule: Some(Rule::RawExecDeny { pattern }),
                ..
            } if pattern == "^--force$"
        ),
        "an argv that trips BOTH the deny pass and the argv[0] guard must be attributed to \
             the deny pattern (deny pass runs first); got {decision:?}"
    );
}

// -------------------------------------------------------------------
// Whitespace guard — ADR-0019, amended 2026-09-16: EVERY argv element,
// not just argv[0]
// -------------------------------------------------------------------
//
// Once an allow pattern must match the WHOLE joined command, an argument
// that carries whitespace can shift what the pattern is really matching
// against without the gate seeing an element boundary move. This test
// pins the every-element half of the guard; `argv0_refused_unless_
// single_program_token` above keeps pinning the argv[0]-only half.
#[test]
fn whitespace_in_any_argv_element_refused_naming_its_index() {
    let policy = from_toml_str("[raw_exec]\nallow = ['(?s).*']\n").expect("policy must parse");

    // Every Unicode-whitespace shape, plus leading/trailing ASCII space,
    // in a NON-argv[0] element (argv[2]) — must be refused, naming the
    // index and pointing to a Template Operation as the remedy.
    for bad in [
        "a b",
        "a\tb",
        "a\nb",
        "a\rb",
        "a\u{00A0}b",
        "a\u{2028}b",
        " a",
        "a ",
    ] {
        let decision = policy.evaluate_raw_exec(&argv(&["prog", "ok", bad]));
        assert!(
            matches!(
                &decision,
                Decision::Deny { rule: None, reason }
                if reason.contains("argv[2]") && reason.contains("Template")
            ),
            "argv[2] {bad:?} carries whitespace and must be refused, naming the index and \
                 a Template Operation as the remedy; got {decision:?}"
        );
    }

    // The FIRST offending element is named, not a later one.
    let decision = policy.evaluate_raw_exec(&argv(&["prog", "a b", "c d"]));
    match &decision {
        Decision::Deny { rule: None, reason } => {
            assert!(
                reason.contains("argv[1]"),
                "the first offending element (argv[1]) must be named; got {reason:?}"
            );
            assert!(
                !reason.contains("argv[2]"),
                "only the FIRST offending element may be named, not a later one too; \
                     got {reason:?}"
            );
        }
        other => panic!("expected a Deny; got {other:?}"),
    }

    // An empty element past argv[0] is allowed — only argv[0]'s emptiness
    // is refused.
    let decision = policy.evaluate_raw_exec(&argv(&["prog", "", "x"]));
    assert!(
        matches!(decision, Decision::Allow(_)),
        "an empty NON-argv[0] element must not be refused; got {decision:?}"
    );

    // NUL is not Unicode whitespace, so it does not trip this guard
    // either (it fails closed later, at execv).
    let decision = policy.evaluate_raw_exec(&argv(&["prog", "a\0b"]));
    assert!(
        matches!(decision, Decision::Allow(_)),
        "a NUL-bearing element must not be refused by the whitespace guard; got {decision:?}"
    );

    // Ordering: the deny pass still runs first and keeps its attribution
    // even when the guard would also fire on the same argv.
    let with_deny = from_toml_str("[raw_exec]\nallow = ['(?s).*']\ndeny = ['^--force$']\n")
        .expect("policy must parse");
    let decision = with_deny.evaluate_raw_exec(&argv(&["prog", "--force x"]));
    assert!(
        matches!(
            &decision,
            Decision::Deny {
                rule: Some(Rule::RawExecDeny { pattern }),
                ..
            } if pattern == "^--force$"
        ),
        "an argv that trips BOTH the deny pass and the whitespace guard must be attributed \
             to the deny pattern (deny pass runs first); got {decision:?}"
    );
}

// -------------------------------------------------------------------
// Deny reasons name which form matched, and the text it matched
// -------------------------------------------------------------------
//
// The reason is `PolicyVerdict.deciding_rule` verbatim (dispatch.rs
// `decision_to_verdict`), so it is the wire-visible explanation in
// PolicyQuery, plan mode and `policy check`. A canonical element need not
// appear anywhere in argv, so a bare "denied by pattern X" is not
// reconcilable against the argv the caller sent.
#[test]
fn deny_reason_names_the_matched_form_and_text() {
    let policy = from_toml_str(
            "[raw_exec]\nallow = [\".*\"]\ndeny = [\"restart nginx\", \"^--force x$\", \"^--force$\"]\n",
        )
        .expect("policy must parse");

    // (argv, expected fragment of the reason)
    let cases: &[(&[&str], &str)] = &[
        (
            &["systemctl", "restart", "nginx"],
            "raw exec denied by pattern \"restart nginx\" \
                 (matched joined command \"systemctl restart nginx\")",
        ),
        (
            &["systemctl", "--force x"],
            "raw exec denied by pattern \"^--force x$\" (matched argv element \"--force x\")",
        ),
        (
            &["systemctl", "--force y"],
            "raw exec denied by pattern \"^--force$\" (matched canonical element \"--force\")",
        ),
    ];

    for (command, expected) in cases {
        let decision = policy.evaluate_raw_exec(&argv(command));
        match &decision {
            Decision::Deny { reason, .. } => assert_eq!(
                reason, expected,
                "the deny reason for {command:?} must name the matched form and text"
            ),
            other => panic!("{command:?} must be denied; got {other:?}"),
        }
    }

    // Form precedence is contract, not incidental: a pattern that matches
    // more than one form must report the FIRST form in the documented
    // order (joined command, then raw argv element, then canonical
    // element), since that is the most concrete thing the caller sent.
    // Without these two rows, swapping arms in `first_raw_deny_match`
    // leaves the whole suite green while silently changing both the label
    // and the quoted text an operator sees.
    let precedence: &[(&str, &[&str], &str)] = &[
        (
            // Matches the joined command AND the raw element "prog".
            "prog",
            &["prog", "x"],
            "raw exec denied by pattern \"prog\" (matched joined command \"prog x\")",
        ),
        (
            // Anchored at ^, so it cannot match the joined command
            // ("prog …"), but matches the raw element "--force x" AND the
            // canonical element "--force".
            "^--force",
            &["prog", "--force x"],
            "raw exec denied by pattern \"^--force\" (matched argv element \"--force x\")",
        ),
    ];
    for (pattern, command, expected) in precedence {
        let policy = from_toml_str(&format!("[raw_exec]\ndeny = [{pattern:?}]\n"))
            .expect("policy must parse");
        match &policy.evaluate_raw_exec(&argv(command)) {
            Decision::Deny { reason, .. } => assert_eq!(
                reason, expected,
                "a pattern matching several forms must report the first form in the \
                     documented order (joined, raw element, canonical element)"
            ),
            other => panic!("{command:?} must be denied; got {other:?}"),
        }
    }

    // Caller-controlled text is bounded on the two reasons that quote
    // it: a `.*`-style deny against a long joined command, and the
    // ADR-0019 argv[0] guard — which is the cheaper one to provoke,
    // since it needs no allow and no deny pattern (an empty Policy still
    // emits it). The later-element guard reason (added by the
    // 2026-09-16 amendment) does NOT quote the caller's text at all — a
    // Raw Exec argument can carry a secret (e.g. an `Authorization:
    // Bearer <token>` header value), and this reason lands verbatim in
    // `deciding_rule`, the Task result and the daemon log — so it is
    // checked separately below, against a short secret rather than these
    // `long_texts` fixtures (see that check for why).
    //
    // The fixtures are deliberately NOT uniform-width: with an ASCII byte
    // ahead of 4-byte codepoints, byte index REASON_FRAGMENT_BUDGET falls
    // INSIDE a character, so a future `&text[..BUDGET]` "simplification"
    // panics here (on attacker-controlled argv) instead of passing.
    let mixed_width = format!("x{}", "🔥".repeat(1024));
    let combining = format!("x{}", "e\u{0301}".repeat(1024));
    let long_texts = [
        ("ascii", "x".repeat(4096)),
        ("mixed-width 4-byte codepoints", mixed_width),
        ("combining marks", combining),
    ];

    let wide = from_toml_str("[raw_exec]\ndeny = [\"^x\"]\n").expect("policy must parse");
    let empty_policy = from_toml_str("").expect("an empty policy must parse");

    // The property that matters is INDEPENDENCE from caller size, not a
    // magic number: the same input four times longer must produce the
    // byte-identical reason. An absolute cap is asserted too, generous
    // enough for `{:?}` escaping — a combining mark quotes as `\u{301}`,
    // so an escaped character can be ~10 times its own width. That
    // expansion is bounded by the fragment budget; the caller's length is
    // not a factor either way.
    const REASON_CHAR_CAP: usize = 1_500;

    let reason_of = |decision: Decision, which: &str, label: &str| -> String {
        match decision {
            Decision::Deny { reason, .. } => reason,
            other => panic!("{which} ({label}): must be denied; got {other:?}"),
        }
    };

    for (label, text) in &long_texts {
        let longer = text.repeat(4);
        for (which, short, long) in [
            // 1. deny-matched text (needs a deny pattern).
            (
                "deny reason",
                reason_of(wide.evaluate_raw_exec(&argv(&[text])), "deny reason", label),
                reason_of(
                    wide.evaluate_raw_exec(&argv(&[&longer])),
                    "deny reason",
                    label,
                ),
            ),
            // 2. the argv[0] guard reason: the same text with a space
            //    appended so the guard fires, against a Policy with NO
            //    patterns at all — the cheapest reason to provoke.
            (
                "guard reason",
                reason_of(
                    empty_policy.evaluate_raw_exec(&argv(&[&format!("{text} ")])),
                    "guard reason",
                    label,
                ),
                reason_of(
                    empty_policy.evaluate_raw_exec(&argv(&[&format!("{longer} ")])),
                    "guard reason",
                    label,
                ),
            ),
        ] {
            assert!(
                short.contains('…'),
                "{which} ({label}): an over-long fragment must be truncated and marked; \
                     got {short:?}"
            );
            assert_eq!(
                short, long,
                "{which} ({label}): a 4x longer argv must produce the identical reason — \
                     the caller must not be able to size an audit record"
            );
            assert!(
                short.chars().count() < REASON_CHAR_CAP,
                "{which} ({label}): the reason must stay small; got {} chars ({} bytes)",
                short.chars().count(),
                short.len()
            );
        }
    }

    // The later-element guard reason must name the offending index and
    // must NEVER quote the caller's argument text, since a Raw Exec
    // argument can carry a secret (e.g. an `Authorization: Bearer
    // <token>` header value). This is deliberately a SHORT secret, not
    // one of the `long_texts` fixtures above: those all exceed the
    // `REASON_FRAGMENT_BUDGET` (120-character) fragment budget, so the
    // pre-fix code — which quoted up to that budget and truncated the
    // rest — would ALSO fail to find the whole fixture in its
    // (truncated) reason, making `!reason.contains(candidate)` pass
    // against the old, buggy behaviour and prove nothing. A secret well
    // under that budget is quoted in full by the pre-fix code, so
    // finding it absent here is what actually distinguishes "never
    // quoted" from "a truncated quote that happens not to contain the
    // whole fixture". See
    // `raw_exec::secret_bearing_whitespace_argument_never_appears_in_deny_reason`
    // for the end-to-end property, through `run_raw_exec`'s Task result
    // rather than `evaluate_raw_exec` alone.
    let secret = "Authorization: Bearer s3cr3t-value";
    let secret_argv = argv(&["prog", "-H", secret]);
    let reason = reason_of(
        empty_policy.evaluate_raw_exec(&secret_argv),
        "later-element guard reason",
        "short secret",
    );
    assert!(
        reason.contains("argv[2]"),
        "later-element guard reason: must name the offending index; got {reason:?}"
    );
    assert!(
        !reason.contains(secret),
        "later-element guard reason: must never quote the caller's argument text, which \
             may hold a secret; got {reason:?}"
    );
}

// The structured-Operation deny reasons quote caller text too (the args
// rendering and a non-canonical path), and must be bounded the same way
// as the Raw Exec ones above (#258). Same property as the bound checks in
// `deny_reason_names_the_matched_form_and_text`: a 4x longer input yields
// the byte-identical reason, never an absolute byte length.
#[test]
fn structured_operation_deny_reasons_are_bounded() {
    // Non-uniform width, so byte index REASON_FRAGMENT_BUDGET falls inside
    // a character and a byte-slice "simplification" panics here.
    let long_texts = [
        ("ascii", "x".repeat(4096)),
        (
            "mixed-width 4-byte codepoints",
            format!("x{}", "🔥".repeat(1024)),
        ),
        ("combining marks", format!("x{}", "e\u{0301}".repeat(1024))),
    ];

    // service.restart is allowed only for nginx/php-fpm there, so any
    // other arg is a deny-by-default with `rule: None`.
    let example = from_toml_str(include_str!("../../../policy.example.toml"))
        .expect("the example policy must parse");
    // An EMPTY Policy still emits the non-canonical-path reason: the
    // cheapest one to provoke.
    let empty_policy = from_toml_str("").expect("an empty policy must parse");

    // `{:?}` escaping expands a combining mark to `\u{301}`, so a
    // character cap rather than a byte cap, generous enough for that.
    const REASON_CHAR_CAP: usize = 1_500;

    let deny_of = |decision: Decision, which: &str, label: &str| -> (String, Option<Rule>) {
        match decision {
            Decision::Deny { reason, rule } => (reason, rule),
            other => panic!("{which} ({label}): must be denied; got {other:?}"),
        }
    };

    for (label, text) in &long_texts {
        let longer = text.repeat(4);
        let path = format!("/./{text}");
        let longer_path = format!("/./{longer}");
        for (which, suffix, short, long) in [
            (
                "args-mismatch reason",
                "for operation 'service.restart'",
                deny_of(
                    example.evaluate("service.restart", &argv(&[text])),
                    "args-mismatch reason",
                    label,
                ),
                deny_of(
                    example.evaluate("service.restart", &argv(&[&longer])),
                    "args-mismatch reason",
                    label,
                ),
            ),
            (
                "non-canonical path reason",
                "is not in canonical form (ADR-0018)",
                deny_of(
                    empty_policy.evaluate("file.read", &argv(&[&path])),
                    "non-canonical path reason",
                    label,
                ),
                deny_of(
                    empty_policy.evaluate("file.read", &argv(&[&longer_path])),
                    "non-canonical path reason",
                    label,
                ),
            ),
        ] {
            let (short, short_rule) = short;
            let (long, _) = long;
            assert!(
                short.contains('…'),
                "{which} ({label}): an over-long fragment must be truncated and marked; \
                     got {short:?}"
            );
            assert_eq!(
                short, long,
                "{which} ({label}): a 4x longer input must produce the identical reason — \
                     the caller must not be able to size an audit record"
            );
            assert!(
                short.chars().count() < REASON_CHAR_CAP,
                "{which} ({label}): the reason must stay small; got {} chars ({} bytes)",
                short.chars().count(),
                short.len()
            );
            assert!(
                short.contains(suffix),
                "{which} ({label}): truncation must hit only the quoted fragment, not the \
                     fixed text after it; got {short:?}"
            );
            assert!(
                short_rule.is_none(),
                "{which} ({label}): outcome and attribution are unchanged — a plain \
                     deny-by-default carries no rule; got {short_rule:?}"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Structured-Operation path-argument red-team (issue #215)
// ---------------------------------------------------------------------------
//
// This second table drives `Policy::evaluate` (the structured-Operation
// path, policy.rs:705) via `evaluate("file.read", ...)`, NOT
// `evaluate_raw_exec` above. `file.read` takes a filesystem-path
// argument and is the representative case for path-taking Operations.
// It asserts the documented-intended behaviors GREEN (exact-string deny
// fires on the exact literal, wildcard allow admits an ordinary path,
// arg-count mismatch is deny-by-default) and captures the confirmed
// exact-string-deny path bypass as a separate `#[ignore]`d test below,
// rather than fixing it here — see the comment above that test.

/// Shared fixture: mirrors the shipped example policy's `file.read`
/// rules (policy.example.toml:56-85) — a `["*"]` wildcard allow paired
/// with an exact-string `[[deny]]` for `/etc/shadow` — inlined so this
/// table stays self-contained, like the Raw Exec fixtures above.
const FILE_READ_SHADOW_POLICY: &str =
    "[[operation]]\nname = \"file.read\"\nallowed_args = [[\"*\"]]\n\n\
         [[deny]]\nname = \"file.read\"\nargs = [[\"/etc/shadow\"]]\n";

/// Coarse red-team classification of a structured-Operation `Decision`,
/// mirroring `Expect` above but over `Policy::evaluate`'s
/// `Rule::Operation*` variants. Kept separate from `Expect` because the
/// two entry points return different `Rule` variants (RawExec* vs
/// Operation*), so a shared enum would be wrong.
#[derive(Debug, Clone, Copy)]
enum PathExpect {
    /// `Decision::Allow(Rule::OperationAllow { .. })`.
    Allow,
    /// `Decision::Deny` with a specific `Rule::OperationDeny` attributed.
    DenyByRule,
    /// `Decision::Deny` with `rule: None` (no allow rule matched).
    DenyByDefault,
}

/// One structured-op path-argument red-team case: a self-contained
/// Policy fixture, an Operation name + argv, and the expected coarse
/// decision. `op` is always "file.read" today but carried per-row for
/// legibility and to let later red-team issues extend this table to
/// other path-taking Operations. Reuses the module's `argv` helper for
/// `args`, so no new helper is needed.
struct PathCase {
    name: &'static str,
    policy_toml: &'static str,
    op: &'static str,
    args: &'static [&'static str],
    expect: PathExpect,
    note: &'static str,
}

/// The GREEN extension point: documented-intended structured-op
/// behaviors against `FILE_READ_SHADOW_POLICY`.
///
/// Deliberately does NOT include a zero-arg row: under this fixture the
/// `/etc/shadow` deny fires *vacuously* on a shorter invocation
/// (policy.rs:726-732, see vacuous_deny_fires_on_shorter_invocation), so
/// a zero-arg `file.read` call is `DenyByRule`, not `DenyByDefault` — a
/// zero-arg row expecting `DenyByDefault` would be wrong here.
fn file_read_path_cases() -> Vec<PathCase> {
    vec![
            PathCase {
                name: "exact_string_deny_fires_on_exact_path",
                policy_toml: FILE_READ_SHADOW_POLICY,
                op: "file.read",
                args: &["/etc/shadow"],
                expect: PathExpect::DenyByRule,
                note: "documented-intended: the [[deny]] protects the EXACT literal /etc/shadow; deny-beats-allow fires (policy.rs:731)",
            },
            PathCase {
                name: "wildcard_allow_admits_ordinary_path",
                policy_toml: FILE_READ_SHADOW_POLICY,
                op: "file.read",
                args: &["/etc/hostname"],
                expect: PathExpect::Allow,
                note: "documented-intended: the [\"*\"] wildcard admits any path the exact deny does not list (mirrors arg_constraint_wildcard_allows_any_path, policy.rs:1034)",
            },
            PathCase {
                name: "wrong_arg_count_two_args_deny_by_default",
                policy_toml: FILE_READ_SHADOW_POLICY,
                op: "file.read",
                args: &["/etc/hostname", "extra"],
                expect: PathExpect::DenyByDefault,
                note: "documented-intended: two args vs the one-arg allow shape → count mismatch → deny-by-default (policy.rs:751)",
            },
        ]
}

#[test]
fn file_read_path_redteam_table() {
    for case in file_read_path_cases() {
        let policy = from_toml_str(case.policy_toml)
            .unwrap_or_else(|e| panic!("case {}: policy TOML failed to parse: {e}", case.name));
        let decision = policy.evaluate(case.op, &argv(case.args));
        let matched = matches!(
            (case.expect, &decision),
            (
                PathExpect::Allow,
                Decision::Allow(Rule::OperationAllow { .. })
            ) | (
                PathExpect::DenyByRule,
                Decision::Deny {
                    rule: Some(Rule::OperationDeny { .. }),
                    ..
                },
            ) | (PathExpect::DenyByDefault, Decision::Deny { rule: None, .. })
        );
        assert!(
            matched,
            "case {}: {}: expected {:?}, got {decision:?}",
            case.name, case.note, case.expect
        );
    }
}

// -------------------------------------------------------------------
// Finding #236 — exact-string [[deny]] for file.read /etc/shadow evaded
// by any non-canonical path spelling — RESOLVED by ADR-0018.
// -------------------------------------------------------------------
//
// Root cause: `Policy::evaluate`'s deny pass compares each argument by
// exact byte equality (`denied_vals.contains(&args[i])`, policy.rs:731)
// with NO path canonicalization anywhere in daemon/src (grep-confirmed:
// zero `canonicalize`/`read_link` hits). The `file.read` executor
// delegates path restriction to Policy entirely and then `File::open`s
// the literal string (operations/file_read.rs:15-17, 34/52), so the
// kernel resolves `..`/`//`/`.`/`/proc/self/root` only *after* the deny
// has already been evaded. So every alternate spelling of /etc/shadow
// slips the exact-string deny and is admitted by the `["*"]` allow.
//
// RESOLVED by ADR-0018: `Policy::evaluate` now fail-closes on a
// non-canonical `file.read` path (layer 1) and the executor re-checks the
// resolved target off the open descriptor (layer 2). This test was
// `#[ignore]`d while the finding was open; it now pins the layer-1 fix.
//
// Symlink / bind-mount / Unicode-normalization siblings: at the Policy
// string layer a symlink or bind-mount alias is simply a DIFFERENT
// literal the deny does not list — the SAME root cause — but only fully
// demonstrable through the executor against a real filesystem (out of
// scope here, confined to policy.rs). They are documented here and in
// finding #236, not asserted as string-layer rows. `/etc/Shadow`
// (case/Unicode) is canonical *form* and fs-fold-dependent: its
// desired=Deny only holds on a case-folding/normalizing mount, and
// canonical-form matching (like canonicalize) folds `..`/`.`/`//`/symlinks
// but never case or Unicode. ADR-0018 records it as a narrow residual, so
// it is not asserted here.
#[test]
fn noncanonical_path_denied_by_canonical_form_precondition() {
    // Only the LEXICAL respellings — the ones the canonical-form
    // precondition (ADR-0018 layer 1) closes at the Policy layer.
    // `/proc/self/root/...`, `/proc/<pid>/root/...`, and symlinks are
    // canonical *form* and are closed by the executor re-checking the
    // resolved target (ADR-0018 layer 2 — see operations/file_read.rs
    // `resolved_target_recheck_*` tests). `/etc/Shadow` (case/Unicode) is
    // canonical form and fs-fold-dependent; ADR-0018 records it as a
    // narrow residual, so it is not asserted here.
    const LEXICAL_EVASIONS: &[(&str, &str)] = &[
        ("/etc/../etc/shadow", "parent-dir traversal"),
        ("//etc/shadow", "doubled leading slash"),
        ("/etc//shadow", "doubled interior slash"),
        ("/etc/./shadow", "dot segment"),
        ("/etc/shadow/", "trailing slash"),
    ];

    let policy = from_toml_str(FILE_READ_SHADOW_POLICY).expect("policy must parse");
    for (path, why) in LEXICAL_EVASIONS {
        let decision = policy.evaluate("file.read", &argv(&[path]));
        assert!(
            matches!(decision, Decision::Deny { .. }),
            "non-canonical path must be denied by the canonical-form precondition \
                 ({why}: {path:?}, finding #236 / ADR-0018); got {decision:?}"
        );
    }

    // The canonical spelling stays denied — by its [[deny]] rule, proving
    // the precondition does not shadow the real deny.
    assert!(
        matches!(
            policy.evaluate("file.read", &argv(&["/etc/shadow"])),
            Decision::Deny { .. }
        ),
        "canonical /etc/shadow must remain denied by its [[deny]] rule"
    );
}
