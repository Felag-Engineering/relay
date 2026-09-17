//! Offline lint coverage for the dev-fleet fixtures (#389): the two Policy
//! files and the demo Template pack that give the dev fleet a real, callable
//! mutate (`docker/fixtures/policy.web.toml`, `docker/fixtures/policy.db.toml`,
//! `docker/fixtures/templates.d/relay-demo/catalog.toml`).
//!
//! Hermetic: no Docker, no root, no network. `daemon/tests/**` is not on
//! `docs/agents/security-surface.txt` (confirmed with
//! `scripts/security-surface.sh`), so this is the right place for a fixture
//! gate that `make test` / `make verify` already run without a Makefile change.
//!
//! Verification honesty (issue #389's binding comment): CI never invokes
//! Docker and `make test` is hermetic, so no automated test here can prove the
//! demo service actually runs. What this test DOES prove is that the daemon's
//! own Policy/Template loader — the thing that actually gates dispatch —
//! accepts both fixtures and the pack, and that the allow/deny verdicts this
//! plan relies on are exactly what the real binary returns. The rest (a real
//! `busybox httpd`, a real restart, a real approval) is a human's job against
//! a real Docker fleet; see docs/dev-fleet.md.
//!
//! The daemon is a bin-only crate (no `src/lib.rs`), so this drives it through
//! the compiled binary — `env!("CARGO_BIN_EXE_relay-daemon")` — exactly like
//! `daemon/tests/shutdown_signal.rs`.

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

/// A unique scratch directory that removes itself on drop. Copied from the
/// pattern in `daemon/tests/shutdown_signal.rs` rather than pulling in a
/// `tempfile` dependency the daemon crate does not have.
struct TempDir(PathBuf);

impl TempDir {
    fn new(label: &str) -> Self {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "relay-daemon-dev-fleet-fixtures-test-{label}-{}-{nanos}",
            std::process::id()
        ));
        TempDir(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

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
    templates_dir: PathBuf,
}

fn copy_fixtures() -> Fixtures {
    let tmp = TempDir::new("fixtures");
    std::fs::create_dir_all(tmp.path()).expect("create scratch dir");

    let root = fixtures_root();
    let policy_web = tmp.path().join("policy.web.toml");
    let policy_db = tmp.path().join("policy.db.toml");
    let templates_dir = tmp.path().join("templates.d");
    let pack_dir = templates_dir.join("relay-demo");

    std::fs::copy(root.join("policy.web.toml"), &policy_web)
        .unwrap_or_else(|e| panic!("copy policy.web.toml: {e}"));
    std::fs::copy(root.join("policy.db.toml"), &policy_db)
        .unwrap_or_else(|e| panic!("copy policy.db.toml: {e}"));
    std::fs::create_dir_all(&pack_dir).expect("create templates.d/relay-demo");
    std::fs::copy(
        root.join("templates.d/relay-demo/catalog.toml"),
        pack_dir.join("catalog.toml"),
    )
    .unwrap_or_else(|e| panic!("copy templates.d/relay-demo/catalog.toml: {e}"));

    for f in [&policy_web, &policy_db, &pack_dir.join("catalog.toml")] {
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
fn both_policy_files_lint_clean_with_the_template_pack() {
    let fx = copy_fixtures();

    for policy in [&fx.policy_web, &fx.policy_db] {
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
    // for one — the agent must be able to repair the fleet and never to
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

/// The replacement for the issue's requested `--strict` gate (BLOCKING 3 /
/// deviation (c) in the implementation plan): `--strict` also emits a summary
/// line (`error: lint warnings present and --strict was given`) that names no
/// operation, so a naive `grep -c warning` over-counts by one. This scopes
/// the assertion to lines beginning `warning:`, asserts the count is exactly
/// 7, and that all 7 name `file.read` — the self-reference findings the
/// fixture's wildcard `file.read` allow produces (documented, pre-existing,
/// unrelated to this issue's change; see deviation (c) in the plan). The 7th
/// is the `current_exe()` self-reference target, which is
/// `target/<profile>/relay-daemon` under `cargo test`, never
/// `/usr/local/bin/relay-daemon` — so 7 is stable here. If this count ever
/// moves, the correct response is to read the new finding, not to raise the
/// number.
#[test]
fn strict_emits_exactly_seven_file_read_self_reference_warnings() {
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
            7,
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
        "dev-fleet-service gained a `stop)` case arm; the agent must be able to \
         repair the fleet and never to break it (the fault is injected out of \
         band by #622) — if `stop` is now intentional, the Policy allow needs \
         updating too, in both policy.web.toml and policy.db.toml"
    );
}
