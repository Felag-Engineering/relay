//! Offline lint coverage for the dev-fleet fixtures (#389, #452): the THREE
//! Policy files and the demo Template pack that give the dev fleet a real,
//! callable mutate (`docker/fixtures/policy.web.toml`,
//! `docker/fixtures/policy.db.toml`, `docker/fixtures/policy.bastion.toml`,
//! `docker/fixtures/templates.d/relay-demo/catalog.toml`), plus (#452) the
//! two fleets that use them: deploy/test (3 Nodes) and deploy/demo (9 Nodes).
//!
//! Hermetic: no Docker, no root, no network. `daemon/tests/**` is not on
//! `docs/agents/security-surface.txt` (confirmed with
//! `scripts/security-surface.sh`), so this is the right place for a fixture
//! gate that `make test` / `make verify` already run without a Makefile change.
//!
//! Verification honesty (issue #389's binding comment, extended by #452):
//! CI never invokes Docker and `make test` is hermetic, so no automated test
//! here can prove the demo service, or a nine-Node fleet, actually runs. What
//! this file DOES prove: (a) the daemon's own Policy/Template loader — the
//! thing that actually gates dispatch — accepts all three fixtures and the
//! pack, and the allow/deny verdicts the demo relies on are exactly what the
//! real binary returns (5.1-5.5 below); (b) the two fleets' compose files and
//! the docs are internally consistent as FILES — the test fleet is exactly the
//! demo fleet's first three Nodes, a roster that matches what's documented, Selector cardinalities
//! that keep an unparked mutate reachable at nine Nodes (5.6-5.9 below). It
//! proves nothing about a RUNNING fleet: that a real `busybox httpd`
//! restarts, that nine containers enroll, that an approval actually
//! releases a Plan — all of that is a human's job against a real Docker
//! fleet; see docs/dev-fleet.md.
//!
//! The daemon is a bin-only crate (no `src/lib.rs`), so 5.1-5.5 drive it
//! through the compiled binary — `env!("CARGO_BIN_EXE_relay-daemon")` —
//! exactly like `daemon/tests/shutdown_signal.rs`. 5.6-5.9 (plus
//! `x_daemon_base_anchor_declares_no_ports_and_no_profiles`, added by #452
//! review S3) read `../deploy/{test,demo}/docker-compose.yml` and the docs as
//! plain text; the daemon crate has no relationship to either file, but no
//! better hermetic home exists for these assertions without standing up a
//! new package, and co-locating them keeps the compose <-> fixture <->
//! Dockerfile triangle in one place.

// Integration tests can only drive the bin-only daemon through its compiled binary,
// so spawning it is the point; clippy.toml's spawn ban is for the daemon's own code.
#![allow(clippy::disallowed_methods)]

mod common;

use common::TempDir;
use regex::Regex;
use std::collections::{BTreeMap, BTreeSet};
use std::ops::Range;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::Command;

fn fixtures_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../docker/fixtures")
}

/// Copies the committed fixtures into a scratch directory and `chmod`s them
/// to 0644 (0755 for directories) before returning its paths.
///
/// This is not tidiness — it is correctness. `--would-allow` resolves the
/// vocabulary through the HARDENED loader (`TemplateSet::load`), which
/// refuses a group/world-writable or foreign-owned template file. Git
/// checkout modes come from the developer's umask, so umask 002 — or
/// `make verify` in a container running as root over a uid-1000 bind mount —
/// would otherwise turn this test red on an unmodified tree. Copying still
/// proves the committed bytes, because the copy is byte-for-byte; only the
/// mode is forced, exactly as the daemon image's `COPY --chmod=0644` does.
struct Fixtures {
    _tmp: TempDir,
    policy_web: PathBuf,
    policy_db: PathBuf,
    policy_bastion: PathBuf,
    templates_dir: PathBuf,
}

fn copy_fixtures() -> Fixtures {
    let tmp = TempDir::new("fixtures");
    std::fs::create_dir_all(tmp.path()).expect("create scratch dir");

    let root = fixtures_root();
    let policy_web = tmp.path().join("policy.web.toml");
    let policy_db = tmp.path().join("policy.db.toml");
    let policy_bastion = tmp.path().join("policy.bastion.toml");
    let templates_dir = tmp.path().join("templates.d");
    let pack_dir = templates_dir.join("relay-demo");

    std::fs::copy(root.join("policy.web.toml"), &policy_web)
        .unwrap_or_else(|e| panic!("copy policy.web.toml: {e}"));
    std::fs::copy(root.join("policy.db.toml"), &policy_db)
        .unwrap_or_else(|e| panic!("copy policy.db.toml: {e}"));
    std::fs::copy(root.join("policy.bastion.toml"), &policy_bastion)
        .unwrap_or_else(|e| panic!("copy policy.bastion.toml: {e}"));
    std::fs::create_dir_all(&pack_dir).expect("create templates.d/relay-demo");
    std::fs::copy(
        root.join("templates.d/relay-demo/catalog.toml"),
        pack_dir.join("catalog.toml"),
    )
    .unwrap_or_else(|e| panic!("copy templates.d/relay-demo/catalog.toml: {e}"));

    for f in [
        &policy_web,
        &policy_db,
        &policy_bastion,
        &pack_dir.join("catalog.toml"),
    ] {
        std::fs::set_permissions(f, std::fs::Permissions::from_mode(0o644))
            .unwrap_or_else(|e| panic!("chmod 0644 {}: {e}", f.display()));
    }
    for d in [tmp.path(), &templates_dir, &pack_dir] {
        std::fs::set_permissions(d, std::fs::Permissions::from_mode(0o755))
            .unwrap_or_else(|e| panic!("chmod 0755 {}: {e}", d.display()));
    }

    Fixtures {
        _tmp: tmp,
        policy_web,
        policy_db,
        policy_bastion,
        templates_dir,
    }
}

fn policy_check(args: &[&str]) -> (i32, String) {
    let bin = env!("CARGO_BIN_EXE_relay-daemon");
    let output = Command::new(bin)
        .arg("policy")
        .arg("check")
        .args(args)
        .output()
        .unwrap_or_else(|e| panic!("spawn {bin} policy check: {e}"));
    let code = output.status.code().unwrap_or(-1);
    let mut combined = String::from_utf8_lossy(&output.stdout).into_owned();
    combined.push_str(&String::from_utf8_lossy(&output.stderr));
    (code, combined)
}

/// The non-strict lint proves the pack parses, compiles, shadows no Native,
/// and declares valid risk classes — but `lint_dir` does NOT use the hardened
/// loader (with a 0664 catalog it still exits 0 with no new findings), so
/// this assertion alone does not prove the daemon's real vocabulary. The
/// `--would-allow` assertions below are what exercise the loader the daemon
/// actually runs at dispatch time.
#[test]
fn all_three_policy_files_lint_clean_with_the_template_pack() {
    let fx = copy_fixtures();

    for policy in [&fx.policy_web, &fx.policy_db, &fx.policy_bastion] {
        let (code, out) = policy_check(&[
            policy.to_str().unwrap(),
            "--templates",
            fx.templates_dir.to_str().unwrap(),
        ]);
        assert_eq!(code, 0, "policy check {} failed:\n{out}", policy.display());
        assert!(
            !out.lines().any(|l| l.starts_with("error:")),
            "policy check {} emitted an error line:\n{out}",
            policy.display()
        );
    }
}

/// The hardened-loader assertion: the demo Raw Exec allow matches
/// start/restart/status on the web fixture and is refused by deny-by-default
/// on the db fixture, `stop` is refused on both, and the pre-existing
/// `service.restart sshd` deny beat survives unchanged.
#[test]
fn raw_exec_verdicts_match_the_web_db_split() {
    let fx = copy_fixtures();
    let templates = fx.templates_dir.to_str().unwrap();

    for verb in ["start", "restart", "status"] {
        let (code, out) = policy_check(&[
            fx.policy_web.to_str().unwrap(),
            "--templates",
            templates,
            "--would-allow",
            "raw-exec",
            "--",
            "/usr/local/bin/dev-fleet-service",
            verb,
        ]);
        assert_eq!(
            code, 0,
            "web policy should ALLOW dev-fleet-service {verb}:\n{out}"
        );
        assert!(out.contains("would-allow: ALLOW"), "{out}");

        let (code, out) = policy_check(&[
            fx.policy_db.to_str().unwrap(),
            "--templates",
            templates,
            "--would-allow",
            "raw-exec",
            "--",
            "/usr/local/bin/dev-fleet-service",
            verb,
        ]);
        assert_eq!(
            code, 2,
            "db policy should DENY dev-fleet-service {verb}:\n{out}"
        );
        assert!(
            out.contains("deny-by-default: no raw_exec allow pattern matched"),
            "{out}"
        );
    }

    // There is deliberately no `stop` subcommand at all, and no Policy allow
    // for one — the AI-agent must be able to repair the fleet and never to
    // break it (the fault is injected out of band by #622).
    for policy in [&fx.policy_web, &fx.policy_db] {
        let (code, out) = policy_check(&[
            policy.to_str().unwrap(),
            "--templates",
            templates,
            "--would-allow",
            "raw-exec",
            "--",
            "/usr/local/bin/dev-fleet-service",
            "stop",
        ]);
        assert_eq!(
            code,
            2,
            "{} should DENY dev-fleet-service stop:\n{out}",
            policy.display()
        );
        assert!(
            out.contains(
                "DENY (deciding rule: deny-by-default: no raw_exec allow pattern matched)"
            ),
            "{out}"
        );
    }

    // The pre-existing deny beat survives unchanged on both fixtures.
    for policy in [&fx.policy_web, &fx.policy_db] {
        let (code, out) = policy_check(&[
            policy.to_str().unwrap(),
            "--templates",
            templates,
            "--would-allow",
            "operation",
            "service.restart",
            "unit=sshd",
        ]);
        assert_eq!(
            code,
            2,
            "{} should DENY service.restart unit=sshd:\n{out}",
            policy.display()
        );
    }
}

/// The bastion fixture (#452, the `role=bastion` Node) has no `[raw_exec]`
/// section at all, so every Raw Exec command falls through to
/// deny-by-default — including the demo service's own repair verb and the
/// (inert on this image) systemctl allow the web/db fixtures carry.
#[test]
fn bastion_fixture_denies_every_raw_exec() {
    let fx = copy_fixtures();
    let templates = fx.templates_dir.to_str().unwrap();

    let cases: &[&[&str]] = &[
        &["/usr/local/bin/dev-fleet-service", "start"],
        &["/usr/local/bin/dev-fleet-service", "restart"],
        &["/usr/local/bin/dev-fleet-service", "status"],
        &["/usr/bin/systemctl", "status", "nginx"],
    ];

    for argv in cases {
        let mut args = vec![
            fx.policy_bastion.to_str().unwrap(),
            "--templates",
            templates,
            "--would-allow",
            "raw-exec",
            "--",
        ];
        args.extend_from_slice(argv);

        let (code, out) = policy_check(&args);
        assert_eq!(code, 2, "bastion should DENY {argv:?}:\n{out}");
        assert!(
            out.contains("deny-by-default: no raw_exec allow pattern matched"),
            "{out}"
        );
    }
}

/// The mixed-result beats, proven at the daemon's own evaluator rather than
/// asserted in prose: the bastion allows exactly the documented
/// `file.read /etc/os-release` and `system.facts`, and denies everything
/// else — including the demo service's state file and `service.restart` —
/// that the web/db fixtures allow.
#[test]
fn bastion_allows_exactly_the_documented_read_and_nothing_else() {
    let fx = copy_fixtures();
    let templates = fx.templates_dir.to_str().unwrap();
    let policies: &[(&str, &PathBuf)] = &[
        ("web", &fx.policy_web),
        ("db", &fx.policy_db),
        ("bastion", &fx.policy_bastion),
    ];

    // file.read /etc/os-release: ALLOW on all three — the documented
    // walkthrough must keep working on the narrow fixture too.
    for (label, policy) in policies {
        let (code, out) = policy_check(&[
            policy.to_str().unwrap(),
            "--templates",
            templates,
            "--would-allow",
            "operation",
            "file.read",
            "path=/etc/os-release",
        ]);
        assert_eq!(
            code, 0,
            "{label} should ALLOW file.read /etc/os-release:\n{out}"
        );
        assert!(out.contains("would-allow: ALLOW"), "{out}");
    }

    // file.read of the demo service's own state file: ALLOW on web/db
    // (wildcard file.read allow), DENY on bastion (exact-path allow only).
    // This is the read-side mixed result the demo's beat (b) depends on.
    for (label, policy, want_code) in [
        ("web", &fx.policy_web, 0),
        ("db", &fx.policy_db, 0),
        ("bastion", &fx.policy_bastion, 2),
    ] {
        let (code, out) = policy_check(&[
            policy.to_str().unwrap(),
            "--templates",
            templates,
            "--would-allow",
            "operation",
            "file.read",
            "path=/var/lib/dev-fleet-service/state",
        ]);
        assert_eq!(
            code, want_code,
            "{label} file.read /var/lib/dev-fleet-service/state verdict wrong:\n{out}"
        );
    }

    // system.facts: ALLOW on all three — the fleet-wide happy path stays
    // all-success at nine Nodes.
    for (label, policy) in policies {
        let (code, out) = policy_check(&[
            policy.to_str().unwrap(),
            "--templates",
            templates,
            "--would-allow",
            "operation",
            "system.facts",
        ]);
        assert_eq!(code, 0, "{label} should ALLOW system.facts:\n{out}");
    }

    // service.restart nginx: ALLOW on web/db, DENY on bastion — the
    // structured-mutate half of the demo's refusal beat.
    for (label, policy, want_code) in [
        ("web", &fx.policy_web, 0),
        ("db", &fx.policy_db, 0),
        ("bastion", &fx.policy_bastion, 2),
    ] {
        let (code, out) = policy_check(&[
            policy.to_str().unwrap(),
            "--templates",
            templates,
            "--would-allow",
            "operation",
            "service.restart",
            "unit=nginx",
        ]);
        assert_eq!(
            code, want_code,
            "{label} service.restart unit=nginx verdict wrong:\n{out}"
        );
    }

    // file.read /etc/shadow: DENY on bastion. #452 review C2: the fixture's
    // headline `[[deny]]` rule (see the comment above it in
    // policy.bastion.toml) had no direct test — this exercises it. The
    // VERDICT is unchanged whether or not the rule is present (`/etc/shadow`
    // sits outside the one `file.read` allow, so deny-by-default would
    // refuse it anyway); what the rule changes is that the deny pass, which
    // runs first on every call, decides it explicitly.
    let (code, out) = policy_check(&[
        fx.policy_bastion.to_str().unwrap(),
        "--templates",
        templates,
        "--would-allow",
        "operation",
        "file.read",
        "path=/etc/shadow",
    ]);
    assert_eq!(code, 2, "bastion should DENY file.read /etc/shadow:\n{out}");
    assert!(
        out.contains("denied by explicit rule for operation 'file.read'"),
        "bastion file.read /etc/shadow should be decided by the explicit deny rule, \
         not deny-by-default:\n{out}"
    );

    // svc.restart (Template Operation): DENY on bastion. #452 review NB7:
    // `svc_restart_is_in_the_web_vocabulary_and_absent_from_db` covers
    // web/db; bastion had no direct case.
    let (code, out) = policy_check(&[
        fx.policy_bastion.to_str().unwrap(),
        "--templates",
        templates,
        "--would-allow",
        "operation",
        "svc.restart",
    ]);
    assert_eq!(code, 2, "bastion should DENY svc.restart:\n{out}");
}

/// The demo Template pack is visible in the web Node's Policy vocabulary and
/// absent from the db Node's — proof that the hardened loader accepted the
/// pack, not merely that the file parses.
#[test]
fn svc_restart_is_in_the_web_vocabulary_and_absent_from_db() {
    let fx = copy_fixtures();
    let templates = fx.templates_dir.to_str().unwrap();

    let (code, out) = policy_check(&[
        fx.policy_web.to_str().unwrap(),
        "--templates",
        templates,
        "--would-allow",
        "operation",
        "svc.restart",
    ]);
    assert_eq!(code, 0, "web should ALLOW svc.restart:\n{out}");
    assert!(out.contains("would-allow: ALLOW"), "{out}");

    let (code, out) = policy_check(&[
        fx.policy_db.to_str().unwrap(),
        "--templates",
        templates,
        "--would-allow",
        "operation",
        "svc.restart",
    ]);
    assert_eq!(code, 2, "db should DENY svc.restart:\n{out}");
}

/// The hermetic half of #622's discovery read (the live half — that the row
/// really disappears after the out-of-band kill — is a human's job against a
/// real fleet; see docs/dev-fleet.md). `file.read /proc/net/tcp` is how the
/// fault (a killed `busybox httpd`) is meant to be FOUND: it is read-class,
/// unparked, and the web fixture's wildcard `file.read` allow covers it like
/// any other path. This proves the daemon's own Policy engine — the thing
/// that actually gates dispatch — agrees, both for the raw path an operator
/// would type and for `/proc/1/net/tcp`, an instance of the resolved form
/// ADR-0018 layer 2 re-checks (`file.read` resolves the *target* path, which
/// in general is `/proc/<pid>/net/tcp` for whatever PID is doing the
/// reading; `1` is not assumed for daemons in general — it is what this dev
/// fleet's daemon happens to be, because docker/daemon-entrypoint.sh execs it
/// so it becomes the container's PID 1). Both ALLOW identically here
/// — this fixture Policy draws no distinction between them — so this is not
/// evidence that layer 2 is a no-op in general, only that it is not the
/// thing that would refuse this particular read.
#[test]
fn web_policy_allows_reading_the_socket_table() {
    let fx = copy_fixtures();
    let templates = fx.templates_dir.to_str().unwrap();

    for path in ["/proc/net/tcp", "/proc/1/net/tcp"] {
        let (code, out) = policy_check(&[
            fx.policy_web.to_str().unwrap(),
            "--templates",
            templates,
            "--would-allow",
            "operation",
            "file.read",
            &format!("path={path}"),
        ]);
        assert_eq!(code, 0, "web should ALLOW file.read {path}:\n{out}");
        assert!(out.contains("would-allow: ALLOW"), "{out}");
    }

    // The bastion fixture's file.read allow is the single exact path
    // /etc/os-release (see bastion_allows_exactly_the_documented_read_and_nothing_else):
    // it has an allow rule for file.read, just not one that matches THIS
    // path, so /proc/net/tcp is refused by "no allow rule matched args" —
    // not the plain deny-by-default a Node with no file.read allow at all
    // would report for the same call.
    let (code, out) = policy_check(&[
        fx.policy_bastion.to_str().unwrap(),
        "--templates",
        templates,
        "--would-allow",
        "operation",
        "file.read",
        "path=/proc/net/tcp",
    ]);
    assert_eq!(
        code, 2,
        "bastion should DENY file.read /proc/net/tcp:\n{out}"
    );
    assert!(
        out.contains("no allow rule matched args")
            && out.contains("allow rules exist for other arguments"),
        "{out}"
    );
}

/// `--strict` also emits a summary line (`error: lint warnings present and
/// --strict was given`) that names no operation, so a naive `grep -c warning`
/// over-counts by one. This scopes the assertion to lines beginning
/// `warning:`, asserts the count is exactly 3 on web/db, and that all of them
/// name `file.read` — the three read targets under the fixtures' wildcard
/// `file.read` allow: the environment file (`/etc/relay-daemon/relay-daemon.env`),
/// the identity private key (`/var/lib/relay-daemon/key.pem`), and the temporary
/// file the daemon writes a new identity key to
/// (`/var/lib/relay-daemon/key.pem.tmp`). If this count ever moves, the correct
/// response is to read the new finding, not to raise the number.
///
/// The bastion fixture (#452) is asserted separately: predicted **0** — it
/// has no wildcard `file.read` and no `[raw_exec]` section, so none of
/// `selfref.rs`'s probes can match. **Observe it; do not pin a guess.** If
/// this ever reports a non-zero count, read the finding before changing the
/// assertion: a self-reference warning on the narrow fixture means it
/// reaches the daemon's own trust root, which is the opposite of why it
/// exists.
#[test]
fn strict_warning_counts_are_pinned_per_fixture() {
    let fx = copy_fixtures();
    let templates = fx.templates_dir.to_str().unwrap();

    for policy in [&fx.policy_web, &fx.policy_db] {
        let (code, out) = policy_check(&[
            policy.to_str().unwrap(),
            "--templates",
            templates,
            "--strict",
        ]);
        assert_eq!(
            code,
            1,
            "{} --strict should fail on the pre-existing self-reference warnings:\n{out}",
            policy.display()
        );

        let warnings: Vec<&str> = out.lines().filter(|l| l.starts_with("warning:")).collect();
        assert_eq!(
            warnings.len(),
            3,
            "{} --strict warning count changed; read the new finding, don't raise this number:\n{out}",
            policy.display()
        );
        for w in &warnings {
            assert!(
                w.contains("name=\"file.read\""),
                "unexpected non-file.read warning in {}:\n{w}",
                policy.display()
            );
        }

        // The --strict summary line names no operation; whitelist it by text
        // rather than folding it into the warning count above.
        assert!(
            out.lines()
                .any(|l| l == "error: lint warnings present and --strict was given"),
            "{} missing the expected --strict summary line:\n{out}",
            policy.display()
        );
    }

    let (code, out) = policy_check(&[
        fx.policy_bastion.to_str().unwrap(),
        "--templates",
        templates,
        "--strict",
    ]);
    assert_eq!(
        code, 0,
        "bastion --strict should exit clean (predicted 0 warnings):\n{out}"
    );
    assert!(
        !out.lines().any(|l| l.starts_with("warning:")),
        "bastion --strict emitted a warning; that means the fixture reaches the \
         daemon's own trust root, which is the opposite of why it exists:\n{out}"
    );
}

/// The committed allow pattern and the committed template bodies must all
/// name the same script path, so a rename cannot silently split them (see
/// "Ordering risk" in the implementation plan).
#[test]
fn policy_allow_and_template_bodies_agree_on_the_script_path() {
    const SCRIPT: &str = "/usr/local/bin/dev-fleet-service";

    let root = fixtures_root();
    let policy_web =
        std::fs::read_to_string(root.join("policy.web.toml")).expect("read policy.web.toml");
    let catalog = std::fs::read_to_string(root.join("templates.d/relay-demo/catalog.toml"))
        .expect("read templates.d/relay-demo/catalog.toml");

    assert!(
        policy_web.contains(SCRIPT),
        "policy.web.toml no longer names {SCRIPT}"
    );
    assert!(
        catalog.contains(SCRIPT),
        "templates.d/relay-demo/catalog.toml no longer names {SCRIPT}"
    );
}

/// The script half of "both layers say the same thing about `stop`". The
/// `raw_exec_verdicts_match_the_web_db_split` test above proves the POLICY
/// half (both fixtures DENY it); this proves the script itself has no `stop`
/// case arm to allow in the first place — there is deliberately no `stop`
/// subcommand at all, not merely no Policy allow for one.
#[test]
fn the_script_has_no_stop_subcommand() {
    let root = fixtures_root();
    let script =
        std::fs::read_to_string(root.join("dev-fleet-service")).expect("read dev-fleet-service");

    assert!(
        !script.contains("stop)"),
        "dev-fleet-service gained a `stop)` case arm; the AI-agent must be able to \
         repair the fleet and never to break it (the fault is injected out of \
         band by #622) — if `stop` is now intentional, the Policy allow needs \
         updating too, in both policy.web.toml and policy.db.toml"
    );
}

// ---------------------------------------------------------------------------
// #452: `demo` compose profile additivity and roster consistency.
//
// These tests (5.6-5.9 in the implementation plan) read the fleets' compose files
// and the docs as plain text — they
// prove properties of FILES, never of a running fleet.
// ---------------------------------------------------------------------------

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("..")
}

const DEMO_COMPOSE: &str = "deploy/demo/docker-compose.yml";
const TEST_COMPOSE: &str = "deploy/test/docker-compose.yml";

fn read_compose_lines(file: &str) -> Vec<String> {
    let path = repo_root().join(file);
    std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
        .lines()
        .map(str::to_string)
        .collect()
}

/// Finds the body span of a top-level (0-indent) mapping key: the header
/// line `<key>:` must sit at column 0. Returns the half-open range of line
/// indices strictly between the header and the next top-level key (or EOF).
///
/// Two clauses in the span-end rule are easy to get wrong, and both are
/// load-bearing against the real file (#452 review findings N1/N2):
///   - a BLANK line (empty, or all whitespace) is NOT a terminator. Blank
///     lines sit inside `services:`'s span, and the natural reading of "a line beginning
///     with a character that is neither whitespace nor `#`" is vacuously
///     TRUE for `""` — which would end the span after the very first
///     service.
///   - a 0-indent COMMENT line (starts with `#`) is NOT a terminator either.
///     `services:`'s span ends with exactly one of these, immediately
///     before `volumes:` — harmless today because it trails the last
///     service, but wrong the moment a comment lands mid-span.
///
/// The terminator is therefore the first line whose first character is
/// neither whitespace nor `#`.
fn top_level_span(lines: &[String], key: &str) -> Range<usize> {
    let header = format!("{key}:");
    let start = lines
        .iter()
        .position(|l| l.trim_end() == header)
        .unwrap_or_else(|| panic!("a compose file has no top-level `{header}` key"));
    let body_start = start + 1;
    let mut body_end = lines.len();
    for (offset, line) in lines[body_start..].iter().enumerate() {
        match line.chars().next() {
            None => continue,                         // blank line — not a terminator (N2)
            Some(c) if c.is_whitespace() => continue, // nested content
            Some('#') => continue,                    // 0-indent comment — not a terminator (N2)
            Some(_) => {
                body_end = body_start + offset;
                break;
            }
        }
    }
    body_start..body_end
}

/// Finds the body span of the `x-daemon-base:` anchor (#452 review S3): the
/// same span-scoped approach as `top_level_span`, but the anchor's header
/// line carries trailing content (`x-daemon-base: &daemon-base`), never a
/// bare `<key>:`, so it needs its own start match rather than reusing
/// `top_level_span` directly. The anchor sits ABOVE `services:` in the file
/// (#452 review S3: `test_fleet_is_the_demo_fleets_first_three_nodes` and
/// `demo_roster_matches_the_documented_fleet` both scan only the `services:`
/// span, so a `ports:` or `profiles:` line placed here — sharing YAML merge
/// key `<<` with every daemon service — is invisible to both).
fn x_daemon_base_span(lines: &[String]) -> Range<usize> {
    let start = lines
        .iter()
        .position(|l| l.starts_with("x-daemon-base:"))
        .expect("a compose file has no `x-daemon-base:` anchor");
    let body_start = start + 1;
    let mut body_end = lines.len();
    for (offset, line) in lines[body_start..].iter().enumerate() {
        match line.chars().next() {
            None => continue,
            Some(c) if c.is_whitespace() => continue,
            Some('#') => continue,
            Some(_) => {
                body_end = body_start + offset;
                break;
            }
        }
    }
    body_start..body_end
}

struct ComposeService {
    name: String,
    body: Range<usize>,
}

/// Splits the `services:` span into named blocks, using EXACTLY the header
/// shape `^  ([A-Za-z0-9._-]+):\s*$` — never an ignore list (#452 5.6: an
/// ignore list would let a service escape the test-versus-demo comparison).
///
/// The `^  [^ #]` scan below is not merely how headers are found — it is
/// also the guard against reintroducing review finding N1: a comment
/// TRAILING a header line (e.g. `  daemon-8:  # the narrow bastion Node`)
/// would sit at 2-indent and start with a non-space, non-`#` character, so
/// it is caught here as a candidate header — and then FAILS to match the
/// strict header shape (trailing content after the `:` that isn't all
/// whitespace), which is treated as a hard error rather than silently
/// skipped. A comment must sit on its own line ABOVE the header it
/// annotates (matching `daemon-1`'s existing style) or this panics.
fn parse_compose_services(lines: &[String]) -> Vec<ComposeService> {
    let span = top_level_span(lines, "services");
    let candidate_re = Regex::new(r"^  [^ #]").unwrap();
    let header_re = Regex::new(r"^  ([A-Za-z0-9._-]+):\s*$").unwrap();

    let mut headers: Vec<(String, usize)> = Vec::new();
    for i in span.clone() {
        let line = &lines[i];
        if !candidate_re.is_match(line) {
            continue;
        }
        match header_re.captures(line) {
            Some(caps) => headers.push((caps[1].to_string(), i)),
            None => panic!(
                "compose file line {}: unrecognised service-header shape: {line:?} — \
                 a per-service comment must sit on its own line ABOVE the header, \
                 never trailing on it (#452 review N1)",
                i + 1
            ),
        }
    }

    headers
        .iter()
        .enumerate()
        .map(|(idx, (name, header_line))| {
            let body_start = header_line + 1;
            let body_end = headers.get(idx + 1).map(|(_, l)| *l).unwrap_or(span.end);
            ComposeService {
                name: name.clone(),
                body: body_start..body_end,
            }
        })
        .collect()
}

/// The names declared directly under the top-level `volumes:` map, found
/// with the SAME structural approach as `parse_compose_services` (#452
/// review N4: the `volumes:` span needs the identical span-scoped
/// treatment 5.7 needs, not a weaker one).
fn top_level_volume_names(lines: &[String]) -> BTreeSet<String> {
    let span = top_level_span(lines, "volumes");
    let candidate_re = Regex::new(r"^  [^ #]").unwrap();
    let header_re = Regex::new(r"^  ([A-Za-z0-9._-]+):\s*$").unwrap();

    lines[span]
        .iter()
        .enumerate()
        .filter(|(_, l)| candidate_re.is_match(l))
        .map(|(i, l)| {
            header_re
                .captures(l)
                .unwrap_or_else(|| {
                    panic!("compose file: unrecognised volume-key shape at line {i}: {l:?}")
                })
                .get(1)
                .unwrap()
                .as_str()
                .to_string()
        })
        .collect()
}

/// Extracts the value of a `<key><whitespace>"<value>"` line (e.g.
/// `hostname: "dev-node-4"` or `RELAY_NODE_LABELS: "role=web,env=prod"`)
/// from a service body, stripping surrounding quotes. `key` must include
/// the trailing colon. Returns the first match.
fn extract_value(body: &[String], key: &str) -> Option<String> {
    body.iter().find_map(|l| {
        l.trim_start()
            .strip_prefix(key)
            .map(|rest| rest.trim().trim_matches('"').to_string())
    })
}

/// One row of the documented nine-Node roster (implementation plan item 4).
struct RosterEntry {
    service: &'static str,
    hostname: &'static str,
    labels: &'static str,
    policy: &'static str,
    state_volume: &'static str,
}

const ROSTER: &[RosterEntry] = &[
    RosterEntry {
        service: "daemon-1",
        hostname: "dev-node-1",
        labels: "role=web",
        policy: "policy.web.toml",
        state_volume: "daemon1-state",
    },
    RosterEntry {
        service: "daemon-2",
        hostname: "dev-node-2",
        labels: "role=web",
        policy: "policy.web.toml",
        state_volume: "daemon2-state",
    },
    RosterEntry {
        service: "daemon-3",
        hostname: "dev-node-3",
        labels: "role=db",
        policy: "policy.db.toml",
        state_volume: "daemon3-state",
    },
    RosterEntry {
        service: "daemon-4",
        hostname: "dev-node-4",
        labels: "role=web,env=prod",
        policy: "policy.web.toml",
        state_volume: "daemon4-state",
    },
    RosterEntry {
        service: "daemon-5",
        hostname: "dev-node-5",
        labels: "role=web,env=prod",
        policy: "policy.web.toml",
        state_volume: "daemon5-state",
    },
    RosterEntry {
        service: "daemon-6",
        hostname: "dev-node-6",
        labels: "role=web,env=staging",
        policy: "policy.web.toml",
        state_volume: "daemon6-state",
    },
    RosterEntry {
        service: "daemon-7",
        hostname: "dev-node-7",
        labels: "role=db,env=prod",
        policy: "policy.db.toml",
        state_volume: "daemon7-state",
    },
    RosterEntry {
        service: "daemon-8",
        hostname: "dev-node-8",
        labels: "role=bastion,env=prod",
        policy: "policy.bastion.toml",
        state_volume: "daemon8-state",
    },
    RosterEntry {
        service: "daemon-9",
        hostname: "dev-node-9",
        labels: "role=web,env=staging",
        policy: "policy.web.toml",
        state_volume: "daemon9-state",
    },
];

/// 5.6: the test fleet is exactly the demo fleet's control plane and first three
/// Nodes, and neither file selects services by profile. Every test-fleet service is
/// identical, comments aside, to the same-named demo service, so the two cannot drift apart: a
/// change to the Relay, a one-shot or daemon-1..3 is made in both files or this fails.
/// No `profiles:` key appears anywhere, because the fleet a file brings up must be the
/// file, not an argument.
#[test]
fn test_fleet_is_the_demo_fleets_first_three_nodes() {
    let demo = read_compose_lines(DEMO_COMPOSE);
    let test = read_compose_lines(TEST_COMPOSE);
    let demo_services = parse_compose_services(&demo);
    let test_services = parse_compose_services(&test);

    for (file, lines) in [(DEMO_COMPOSE, &demo), (TEST_COMPOSE, &test)] {
        for l in lines.iter() {
            assert!(
                !l.trim_start().starts_with("profiles:"),
                "{file} declares `profiles:` ({l:?}); each fleet is its own file"
            );
        }
    }

    let names: BTreeSet<&str> = test_services.iter().map(|s| s.name.as_str()).collect();
    let expected: BTreeSet<&str> = [
        "relay",
        "relay-config",
        "init",
        "daemon-1",
        "daemon-2",
        "daemon-3",
    ]
    .into_iter()
    .collect();
    assert_eq!(
        names, expected,
        "{TEST_COMPOSE} must hold exactly these services"
    );

    for t in &test_services {
        let d = demo_services
            .iter()
            .find(|d| d.name == t.name)
            .unwrap_or_else(|| panic!("{DEMO_COMPOSE} has no `{}` service", t.name));
        let body = |lines: &[String], r: &Range<usize>| -> Vec<String> {
            lines[r.clone()]
                .iter()
                .filter(|l| !l.trim().is_empty() && !l.trim_start().starts_with('#'))
                .cloned()
                .collect()
        };
        assert_eq!(
            body(&test, &t.body),
            body(&demo, &d.body),
            "`{}` differs between {TEST_COMPOSE} and {DEMO_COMPOSE}; change both",
            t.name
        );
    }
    assert_eq!(
        x_daemon_base_span(&test)
            .map(|i| test[i].clone())
            .collect::<Vec<_>>(),
        x_daemon_base_span(&demo)
            .map(|i| demo[i].clone())
            .collect::<Vec<_>>(),
        "the x-daemon-base anchor differs between {TEST_COMPOSE} and {DEMO_COMPOSE}"
    );
}

/// #452 review S3: the `x-daemon-base` anchor sits above `services:` and is
/// shared by every daemon via the YAML merge key `<<`, so a `ports:` mapping
/// placed there would publish every daemon on every interface at once
/// (verified against the real Compose resolver), and a `profiles:` key there
/// would make the fleet an argument instead of the file. Neither guard above can see
/// this span; this is the one that does.
#[test]
fn x_daemon_base_anchor_declares_no_ports_and_no_profiles() {
    let lines = read_compose_lines(DEMO_COMPOSE);
    let span = x_daemon_base_span(&lines);

    for line in &lines[span] {
        let trimmed = line.trim_start();
        assert!(
            !trimmed.starts_with("ports:"),
            "x-daemon-base anchor declares `ports:` — every daemon would publish on \
             every interface (#452 review S3): {line:?}"
        );
        assert!(
            !trimmed.starts_with("profiles:"),
            "x-daemon-base anchor declares `profiles:` — the fleet would be decided by \
             an argument, invisible to the per-service comparison (#452 review S3): {line:?}"
        );
    }
}

/// 5.7: compose <-> fixture <-> Dockerfile consistency for every Node in the
/// documented roster — label/Policy pairing, a unique hostname and state
/// volume, that state volume declared under the top-level `volumes:` map,
/// and that the named Policy file both exists under `docker/fixtures/` and
/// is `COPY`'d in `docker/daemon.Dockerfile`. The Dockerfile assertion is
/// the fail-closed guard named in the plan's "Ordering risk": a compose
/// block pointing at a file the image never copied does not fail loudly —
/// the daemon warns and falls back to deny-all, which looks like a working
/// Node that refuses everything.
///
/// The loop below only looks `ROSTER`'s entries *up* in the compose file —
/// it never asks the converse. #452 review C1: a demo compose daemon
/// service absent from `ROSTER` was invisible to every test in this file
/// (`5.8` computes its cardinalities from `ROSTER` alone, never the file —
/// see its own comment). The `assert_eq!` after the loop closes that: it
/// derives the daemon-service set from the compose file itself (every
/// service that mounts something at `:/var/lib/relay-daemon`) and requires
/// it to equal `ROSTER`'s service set exactly, in both directions.
#[test]
fn demo_roster_matches_the_documented_fleet() {
    let lines = read_compose_lines(DEMO_COMPOSE);
    let services = parse_compose_services(&lines);
    let declared_volumes = top_level_volume_names(&lines);
    let dockerfile_path = repo_root().join("docker/daemon.Dockerfile");
    let dockerfile = std::fs::read_to_string(&dockerfile_path)
        .unwrap_or_else(|e| panic!("read {}: {e}", dockerfile_path.display()));

    let mut seen_state_volumes = BTreeSet::new();

    for entry in ROSTER {
        let svc = services
            .iter()
            .find(|s| s.name == entry.service)
            .unwrap_or_else(|| panic!("{DEMO_COMPOSE} has no `{}` service", entry.service));
        let body = &lines[svc.body.clone()];

        let hostname = extract_value(body, "hostname:")
            .unwrap_or_else(|| panic!("{}: no hostname:", entry.service));
        assert_eq!(
            hostname, entry.hostname,
            "{}: hostname mismatch",
            entry.service
        );

        let labels = extract_value(body, "RELAY_NODE_LABELS:")
            .unwrap_or_else(|| panic!("{}: no RELAY_NODE_LABELS:", entry.service));
        assert_eq!(
            labels, entry.labels,
            "{}: RELAY_NODE_LABELS mismatch",
            entry.service
        );

        let policy_path = extract_value(body, "RELAY_POLICY_PATH:")
            .unwrap_or_else(|| panic!("{}: no RELAY_POLICY_PATH:", entry.service));
        let policy_file = policy_path.rsplit('/').next().unwrap();
        assert_eq!(
            policy_file, entry.policy,
            "{}: RELAY_POLICY_PATH mismatch",
            entry.service
        );

        let state_volume = body
            .iter()
            .find_map(|l| {
                l.trim_start()
                    .strip_prefix("- ")
                    .and_then(|rest| rest.strip_suffix(":/var/lib/relay-daemon"))
            })
            .unwrap_or_else(|| panic!("{}: no daemonN-state mount", entry.service));
        assert_eq!(
            state_volume, entry.state_volume,
            "{}: state volume mismatch",
            entry.service
        );
        assert!(
            seen_state_volumes.insert(state_volume.to_string()),
            "{} reuses a state volume already claimed by another service",
            entry.service
        );

        assert!(
            declared_volumes.contains(entry.state_volume),
            "{}'s state volume `{}` is not declared under the top-level volumes: map",
            entry.service,
            entry.state_volume
        );

        let fixture_path = repo_root().join("docker/fixtures").join(entry.policy);
        assert!(
            fixture_path.exists(),
            "{}'s Policy file {} does not exist under docker/fixtures/ — a compose \
             block pointing at a file the image never copies does not fail loudly \
             (deny-all fallback)",
            entry.service,
            entry.policy
        );
        assert!(
            dockerfile.contains(&format!("fixtures/{}", entry.policy)),
            "{}'s Policy file {} is not COPY'd in docker/daemon.Dockerfile",
            entry.service,
            entry.policy
        );
    }

    // This does NOT independently prove daemon-1..3 are untouched — the loop
    // above already does that, by checking each against ROSTER's own
    // daemon-1..3 entries (which are the base fleet's documented values
    // verbatim). All this guards against is ROSTER itself being edited to
    // drop one of them, which would silently narrow every assertion this
    // file makes about the base fleet.
    for base in ["daemon-1", "daemon-2", "daemon-3"] {
        assert!(
            ROSTER.iter().any(|e| e.service == base),
            "ROSTER must keep asserting the base fleet's {base}, unchanged"
        );
    }

    // #452 review C1: the converse of the loop above. Derive the set of
    // daemon services directly from the demo compose file — every service
    // whose body mounts something at `:/var/lib/relay-daemon`, the mount
    // every daemon service declares regardless of profile — and require it
    // to equal ROSTER's service set exactly. Without this, a compose service
    // that ROSTER never mentions is invisible to every test in this file: a
    // rogue block can reuse another Node's hostname, mount another Node's
    // state volume, or point RELAY_POLICY_PATH at a file that doesn't exist
    // — which does not fail loudly. A missing Policy file with no fragment
    // makes the daemon `warn!` and fall back to a deny-all Policy
    // (`startup_policy` in daemon/src/main.rs), so that Node enrolls, reports
    // healthy, and refuses everything.
    let compose_daemons: BTreeSet<String> = services
        .iter()
        .filter(|s| {
            lines[s.body.clone()]
                .iter()
                .any(|l| l.trim_end().ends_with(":/var/lib/relay-daemon"))
        })
        .map(|s| s.name.clone())
        .collect();
    let roster_daemons: BTreeSet<String> = ROSTER.iter().map(|e| e.service.to_string()).collect();
    assert_eq!(
        compose_daemons, roster_daemons,
        "the demo compose file declares a daemon service ROSTER doesn't know about (or \
         ROSTER names one the compose file doesn't) — a new daemon service must be \
         added to ROSTER in this file, or it is invisible to every test here (#452 \
         review C1)"
    );
}

/// 5.8: from the same roster, a fan-out-1 Selector must survive at nine
/// Nodes. The approval gate's `min_fan_out: 2` means the straight-through
/// (unparked) mutate beat exists only if a Selector of cardinality 1 does —
/// this is what stops a later roster edit deleting it silently.
///
/// This proves a property of `ROSTER` (the Rust constant above) — it never
/// reads the demo compose file, so on its own it proves nothing about the
/// COMPOSE FILE (#452 review C1 corrects an earlier version of this comment
/// that claimed otherwise). `ROSTER` is tied back to the file by 5.7
/// (`demo_roster_matches_the_documented_fleet`), which checks both that
/// every `ROSTER` entry's labels match the compose block it names AND — as
/// of the C1 fix — that the compose file declares no daemon service `ROSTER`
/// doesn't know about. A cardinality wrong here, with 5.7 green, means
/// `ROSTER` itself was transcribed wrong from the file it mirrors.
///
/// Also not a property of the registry: `Selector.Resolve` iterates the real
/// registry (`reg.List()`), and `relay-data` is a named volume that survives
/// `compose down`. A stale Node from an old experiment gives fan-out 2 on
/// stage while this test stays green — the mitigation for that is
/// operational (the doc's `down -v` + `list_nodes(...)` check before the
/// beat), not code.
#[test]
fn a_single_node_selector_survives_at_nine_nodes() {
    let label_sets: Vec<BTreeMap<&str, &str>> = ROSTER
        .iter()
        .map(|e| {
            e.labels
                .split(',')
                .map(|kv| kv.split_once('=').unwrap())
                .collect()
        })
        .collect();

    let count = |pred: &dyn Fn(&BTreeMap<&str, &str>) -> bool| {
        label_sets.iter().filter(|s| pred(s)).count()
    };

    assert_eq!(
        count(&|s| s.get("role") == Some(&"web")),
        6,
        "role=web count"
    );
    assert_eq!(count(&|s| s.get("role") == Some(&"db")), 2, "role=db count");
    assert_eq!(
        count(&|s| s.get("role") == Some(&"bastion")),
        1,
        "role=bastion count"
    );
    assert_eq!(
        count(&|s| s.get("role") == Some(&"db") && s.get("env") == Some(&"prod")),
        1,
        "role=db, env=prod count"
    );
}

/// The Makefile's `DEMO_WEB_NODES` (what `make demo-fault` validates its targets
/// against) is a hand-kept copy of `ROSTER`'s `role=web` entries; this turns
/// the "must match" comment beside it into a test.
#[test]
fn makefile_demo_web_nodes_match_the_roster() {
    let path = repo_root().join("Makefile");
    let makefile =
        std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    let line = makefile
        .lines()
        .find_map(|l| l.strip_prefix("DEMO_WEB_NODES :="))
        .expect("Makefile has no `DEMO_WEB_NODES :=` line");
    let in_makefile: BTreeSet<&str> = line.split_whitespace().collect();
    let in_roster: BTreeSet<&str> = ROSTER
        .iter()
        .filter(|e| e.labels.split(',').any(|l| l == "role=web"))
        .map(|e| e.service)
        .collect();
    assert_eq!(
        in_makefile, in_roster,
        "Makefile DEMO_WEB_NODES drifted from ROSTER's role=web Nodes"
    );
}

/// 5.9: doc drift guard, in the same spirit as
/// `policy_allow_and_template_bodies_agree_on_the_script_path` above — every
/// demo Node and the bastion fixture must be named in the demo runbook,
/// `docs/operations/demo-fleet.md` (moved out of `docs/dev-fleet.md`).
/// This catches an ADDED Node that was never documented; it cannot catch a
/// STALE sentence about the old three-Node fleet (those are named edits in
/// the implementation plan, not a cheap assertion).
#[test]
fn docs_dev_fleet_documents_every_demo_node() {
    let doc_path = repo_root().join("docs/operations/demo-fleet.md");
    let doc = std::fs::read_to_string(&doc_path)
        .unwrap_or_else(|e| panic!("read {}: {e}", doc_path.display()));

    for n in 4..=9 {
        let needle = format!("dev-node-{n}");
        assert!(
            doc.contains(&needle),
            "docs/operations/demo-fleet.md never mentions {needle}"
        );
    }
    assert!(
        doc.contains("policy.bastion.toml"),
        "docs/operations/demo-fleet.md never mentions policy.bastion.toml"
    );
}
