//! The Policy directory, driven through the compiled binary (DI-20, DI-36,
//! DI-46).
//!
//! A fragment the daemon refuses to start on really stops the process, with a
//! non-zero exit and a journal line that names the fragment; a missing Policy
//! file beside fragments loads the fragments alone; and `policy check` agrees
//! with the daemon's own loader over the same files, printing the Policy
//! fingerprint it computes. The loader's composition rules are proved at the
//! crate level, in `relay-policy`; this file proves what only a real process
//! can: the exit, the journal and the CLI.

// Spawning the compiled binary is the point; clippy.toml's spawn ban is for the
// daemon's own code.
#![allow(clippy::disallowed_methods)]

mod common;

use common::TempDir;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

const ALLOW_NGINX: &str = "\
[[operation]]
name = \"service.restart\"
allowed_args = [[\"nginx\"]]
";
const ALLOW_SSHD: &str = "\
[[operation]]
name = \"service.restart\"
allowed_args = [[\"sshd\"]]
";
const DENY_PHP: &str = "\
[[deny]]
name = \"service.restart\"
args = [[\"php-fpm\"]]
";

/// A self-signed identity in the on-disk layout `load_identity` expects. The
/// same layout `exit_rule.rs` seeds; kept local because a shared copy in
/// `common` would be dead code in every other test crate that declares it.
fn seed_identity(dir: &Path) {
    std::fs::create_dir_all(dir).expect("create state dir");
    let kp = rcgen::KeyPair::generate().expect("keygen");
    let cert = rcgen::CertificateParams::new(vec!["test-node".to_string()])
        .expect("params")
        .self_signed(&kp)
        .expect("self-signed")
        .pem();
    let files = [
        ("key.pem", kp.serialize_pem()),
        ("cert.pem", cert.clone()),
        ("ca_bundle.pem", cert),
        ("node_id", "test-node-id".to_string()),
    ];
    for (name, body) in files {
        std::fs::write(dir.join(name), body).expect("write identity file");
    }
}

fn set_mode(path: &Path, mode: u32) {
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).expect("chmod");
}

/// A Policy file and its Policy directory beside it, both made explicitly
/// 0o644 / 0o755: directory creation follows the umask, and CI runs strict
/// umasks.
struct Node {
    root: TempDir,
}

impl Node {
    fn new(label: &str, policy: &str) -> Node {
        let node = Node::without_policy_file(label);
        node.write(&node.policy(), policy);
        node
    }

    /// A Node whose Policy directory exists, empty, beside no Policy file.
    fn without_policy_file(label: &str) -> Node {
        let root = TempDir::new(label);
        std::fs::create_dir_all(root.path()).expect("create the config dir");
        set_mode(root.path(), 0o755);
        let node = Node { root };
        std::fs::create_dir(node.dir()).expect("create the Policy directory");
        set_mode(&node.dir(), 0o755);
        node
    }

    fn policy(&self) -> PathBuf {
        self.root.path().join("policy.toml")
    }

    fn dir(&self) -> PathBuf {
        self.root.path().join("policy.d")
    }

    fn write(&self, path: &Path, text: &str) {
        std::fs::write(path, text).expect("write a Policy file");
        set_mode(path, 0o644);
    }

    fn fragment(&self, name: &str, text: &str) {
        self.write(&self.dir().join(name), text);
    }
}

// Proves DI-36.
#[test]
fn a_symlinked_policy_fragment_refuses_start() {
    let state = TempDir::new("policy-dir-state");
    seed_identity(state.path());
    let node = Node::new("policy-dir-refuse", ALLOW_NGINX);
    std::os::unix::fs::symlink(node.policy(), node.dir().join("evil.toml")).unwrap();

    // A closed port: a daemon that did not refuse would retry the dial for ever.
    let mut child = Command::new(env!("CARGO_BIN_EXE_relay-daemon"))
        .env_clear()
        .env("RELAY_STATE_DIR", state.path())
        .env("RELAY_ADDRESS", "https://127.0.0.1:1")
        .env("RELAY_POLICY_PATH", node.policy())
        .env("RUST_LOG", "info")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn relay-daemon");

    let deadline = Instant::now() + Duration::from_secs(10);
    let status = loop {
        if let Some(status) = child.try_wait().expect("poll the daemon") {
            break status;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("the daemon kept running with a symlinked Policy fragment");
        }
        std::thread::sleep(Duration::from_millis(50));
    };

    let out = child.wait_with_output().expect("collect the output");
    let all = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        !status.success(),
        "must exit non-zero, got {status:?}: {all}"
    );
    assert!(all.contains("refusing to start"), "output: {all}");
    assert!(all.contains("evil.toml"), "output: {all}");
}

/// `policy check` prints the fingerprint the loader computes over the same
/// files, so an operator can compare it with a Node's.
// Proves DI-46.
#[test]
fn check_prints_the_fingerprint_the_daemon_loads() {
    let node = Node::new("policy-dir-fingerprint", ALLOW_NGINX);

    let check = |with_dir: bool| -> String {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_relay-daemon"));
        cmd.env_clear().args(["policy", "check"]).arg(node.policy());
        if with_dir {
            cmd.arg("--policy-dir").arg(node.dir());
        }
        let out = cmd.output().expect("spawn relay-daemon policy check");
        assert!(
            out.status.success(),
            "policy check failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8(out.stdout)
            .expect("UTF-8 stdout")
            .lines()
            .find_map(|l| l.strip_prefix("fingerprint: "))
            .expect("a fingerprint: line")
            .to_string()
    };

    // An empty directory: the fingerprint is the Policy file's own, which is
    // sha256sum of the file.
    let file_only = relay_policy::from_toml_str(ALLOW_NGINX).unwrap();
    assert_eq!(check(true), file_only.fingerprint());
    assert_eq!(check(false), file_only.fingerprint());

    // With fragments, it is the one the daemon's loader computes.
    node.fragment("10-sshd.toml", ALLOW_SSHD);
    node.fragment("20-deny.toml", DENY_PHP);
    let loaded = relay_policy::load_policy(&node.policy(), &node.dir()).expect("loads");
    assert_ne!(loaded.fingerprint(), file_only.fingerprint());
    assert_eq!(check(true), loaded.fingerprint());
    assert_ne!(
        check(false),
        loaded.fingerprint(),
        "a fingerprint printed without --policy-dir does not match a Node with fragments"
    );
}

/// `policy check` over a file plus its directory, returning the exit code and
/// stderr.
fn check_with(node: &Node, extra: &[&str]) -> (Option<i32>, String) {
    let (code, _stdout, stderr) = check_output(node, extra);
    (code, stderr)
}

/// `policy check` over `node`'s Policy file, returning the exit code, stdout
/// and stderr.
fn check_output(node: &Node, extra: &[&str]) -> (Option<i32>, String, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_relay-daemon"))
        .env_clear()
        .args(["policy", "check"])
        .arg(node.policy())
        .args(extra)
        .output()
        .expect("spawn relay-daemon policy check");
    (
        out.status.code(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

/// `policy check` over `node`'s Policy file and Policy directory.
fn check_dir(node: &Node, extra: &[&str]) -> (Option<i32>, String, String) {
    let dir = node.dir();
    let mut args = vec!["--policy-dir", dir.to_str().expect("a UTF-8 temp path")];
    args.extend_from_slice(extra);
    check_output(node, &args)
}

/// The value of the `fingerprint:` line `policy check` printed, if any.
fn printed_fingerprint(stdout: &str) -> Option<&str> {
    stdout.lines().find_map(|l| l.strip_prefix("fingerprint: "))
}

fn stop(mut child: Child) {
    let _ = child.kill();
    let _ = child.wait();
}

/// Starts the daemon on `node`'s Policy, against a closed port so it never
/// connects, and watches its journal until a line holds `until`, the process
/// exits, or ten seconds pass. Returns the exit status if it exited (a daemon
/// still running is stopped) and everything it logged.
fn run_daemon(node: &Node, until: &str) -> (Option<ExitStatus>, String) {
    let state = TempDir::new("policy-dir-state");
    seed_identity(state.path());
    let journal_dir = TempDir::new("policy-dir-journal");
    std::fs::create_dir_all(journal_dir.path()).expect("create the journal dir");
    let journal = journal_dir.path().join("daemon.log");
    let log = std::fs::File::create(&journal).expect("create the journal file");

    let mut child = Command::new(env!("CARGO_BIN_EXE_relay-daemon"))
        .env_clear()
        .env("RELAY_STATE_DIR", state.path())
        .env("RELAY_ADDRESS", "https://127.0.0.1:1")
        .env("RELAY_POLICY_PATH", node.policy())
        .env("RUST_LOG", "info")
        .stdin(Stdio::null())
        .stdout(log.try_clone().expect("clone the journal handle"))
        .stderr(log)
        .spawn()
        .expect("spawn relay-daemon");

    let read = || std::fs::read_to_string(&journal).unwrap_or_default();
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if let Some(status) = child.try_wait().expect("poll the daemon") {
            return (Some(status), read());
        }
        let all = read();
        if all.contains(until) || Instant::now() >= deadline {
            stop(child);
            return (None, all);
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// The deny-all fallback's journal line (`startup_policy` in the daemon).
const DENY_ALL_LINE: &str = "using deny-all policy";

fn fragment(name: &str, text: &str) -> relay_policy::Fragment {
    relay_policy::Fragment {
        name: name.to_string(),
        text: text.to_string(),
    }
}

// Proves DI-20.
#[test]
fn a_missing_policy_file_beside_fragments_loads_the_fragments_alone() {
    let node = Node::without_policy_file("policy-dir-no-file");
    node.fragment("10-sshd.toml", ALLOW_SSHD);
    node.fragment("20-deny.toml", DENY_PHP);

    let loaded =
        relay_policy::load_policy(&node.policy(), &node.dir()).expect("the fragments load alone");
    let composed = relay_policy::compose_fragments(&[
        fragment("10-sshd.toml", ALLOW_SSHD),
        fragment("20-deny.toml", DENY_PHP),
    ])
    .expect("composes");
    assert_eq!(loaded.fingerprint(), composed.fingerprint());

    let (exited, all) = run_daemon(&node, "policy loaded");
    assert!(exited.is_none(), "the daemon must keep running: {all}");
    assert!(
        all.contains("policy loaded") && all.contains(loaded.fingerprint()),
        "the journal reports the fragments' fingerprint: {all}"
    );
    assert!(!all.contains(DENY_ALL_LINE), "journal: {all}");

    assert!(
        all.contains("no policy file; composing the Policy directory's fragments alone"),
        "the daemon says it runs without the Policy file's denies: {all}"
    );

    let (code, stdout, stderr) = check_dir(&node, &[]);
    assert_eq!(code, Some(0), "stderr: {stderr}");
    assert_eq!(
        printed_fingerprint(&stdout),
        Some(loaded.fingerprint()),
        "policy check prints the fingerprint the daemon loads; stderr: {stderr}"
    );
    assert!(
        stderr.contains("warning: ") && stderr.contains("does not exist; checking the fragments"),
        "a missing Policy file is called out, not passed silently: {stderr}"
    );

    // A mistyped <file> cannot pass a strict gate.
    let (code, stdout, stderr) = check_dir(&node, &["--strict"]);
    assert_eq!(code, Some(1), "stderr: {stderr}");
    assert_eq!(printed_fingerprint(&stdout), None);

    // Without --policy-dir there is nothing to check: a missing file is an error.
    let (code, stdout, _) = check_output(&node, &[]);
    assert_eq!(code, Some(1));
    assert_eq!(printed_fingerprint(&stdout), None);
}

// Proves DI-20.
#[test]
fn a_missing_policy_file_with_no_fragment_is_deny_all() {
    let node = Node::without_policy_file("policy-dir-nothing");

    let (exited, all) = run_daemon(&node, DENY_ALL_LINE);
    assert!(exited.is_none(), "deny-all, not a refusal: {all}");
    assert!(all.contains(DENY_ALL_LINE), "journal: {all}");

    let (code, stdout, stderr) = check_dir(&node, &[]);
    assert_eq!(code, Some(1), "stderr: {stderr}");
    assert_eq!(printed_fingerprint(&stdout), None);
    assert!(
        stderr.contains("holds no Policy fragment") && stderr.contains("deny-all"),
        "stderr: {stderr}"
    );
}

// Proves DI-20.
#[test]
fn a_missing_policy_file_with_a_refused_fragment_refuses_start() {
    let node = Node::without_policy_file("policy-dir-no-file-refused");
    node.fragment("10-sshd.toml", ALLOW_SSHD);
    std::os::unix::fs::symlink(
        node.dir().join("10-sshd.toml"),
        node.dir().join("evil.toml"),
    )
    .unwrap();

    let (exited, all) = run_daemon(&node, "policy loaded");
    let status = exited.unwrap_or_else(|| panic!("the daemon kept running: {all}"));
    assert!(!status.success(), "must exit non-zero: {all}");
    assert!(
        all.contains("refusing to start") && all.contains("evil.toml"),
        "journal: {all}"
    );

    let (code, stdout, stderr) = check_dir(&node, &[]);
    assert_eq!(code, Some(1), "stderr: {stderr}");
    assert_eq!(printed_fingerprint(&stdout), None);
    assert!(stderr.contains("evil.toml"), "stderr: {stderr}");
}

// Proves DI-20.
#[test]
fn an_unreadable_policy_file_beside_fragments_is_deny_all() {
    // Unparsable.
    let unparsable = Node::new("policy-dir-bad-file", "this is = = not toml");
    unparsable.fragment("10-sshd.toml", ALLOW_SSHD);
    // Not a file at all: a directory where the Policy file should be.
    let not_a_file = Node::without_policy_file("policy-dir-file-is-dir");
    std::fs::create_dir(not_a_file.policy()).expect("create a directory at the Policy path");
    set_mode(&not_a_file.policy(), 0o755);
    not_a_file.fragment("10-sshd.toml", ALLOW_SSHD);
    // A dangling symlink is not a missing Policy file: the loader refuses to
    // follow it, and `policy check` must not take it for missing.
    let dangling = Node::without_policy_file("policy-dir-file-dangling");
    std::os::unix::fs::symlink("/nonexistent", dangling.policy()).unwrap();
    dangling.fragment("10-sshd.toml", ALLOW_SSHD);

    for node in [&unparsable, &not_a_file, &dangling] {
        let (exited, all) = run_daemon(node, DENY_ALL_LINE);
        assert!(exited.is_none(), "deny-all, not a refusal: {all}");
        assert!(all.contains(DENY_ALL_LINE), "journal: {all}");
        assert!(!all.contains("policy loaded"), "journal: {all}");

        let (code, stdout, stderr) = check_dir(node, &[]);
        assert_eq!(code, Some(1), "stderr: {stderr}");
        assert_eq!(printed_fingerprint(&stdout), None);
    }
}

/// An unknown Policy key is a load error, so the Policy is deny-all; the
/// journal line that says so names the key, in the Policy file or a fragment.
#[test]
fn an_unknown_policy_key_is_deny_all_and_the_journal_names_it() {
    let in_file = Node::new(
        "policy-dir-unknown-key-file",
        &format!("{ALLOW_NGINX}\n[[denny]]\nname = \"service.restart\"\n"),
    );
    let in_fragment = Node::new("policy-dir-unknown-key-fragment", ALLOW_NGINX);
    in_fragment.fragment("90-deny.toml", "[raw_exec]\nenabeld = true\n");

    for (node, key) in [(&in_file, "denny"), (&in_fragment, "enabeld")] {
        let (exited, all) = run_daemon(node, DENY_ALL_LINE);
        assert!(exited.is_none(), "deny-all, not a refusal: {all}");
        let line = all
            .lines()
            .find(|l| l.contains(DENY_ALL_LINE))
            .unwrap_or_else(|| panic!("no deny-all line: {all}"));
        assert!(
            line.contains(key),
            "the deny-all line names {key:?}: {line}"
        );
    }
}

/// `policy check` refuses a symlinked `--policy-dir` as the daemon does, so a
/// layout that would take the Node offline cannot pass the gate.
// Proves DI-46.
#[test]
fn check_refuses_a_symlinked_or_non_directory_policy_dir() {
    let node = Node::new("policy-dir-symlinked-dir", ALLOW_NGINX);
    node.fragment("10-sshd.toml", ALLOW_SSHD);
    let linked = node.root.path().join("linked.d");
    std::os::unix::fs::symlink(node.dir(), &linked).unwrap();
    let a_file = node.root.path().join("file.d");
    node.write(&a_file, ALLOW_SSHD);

    for (dir, expected) in [
        (&linked, "the Policy directory is a symlink"),
        (&a_file, "the Policy directory is not a directory"),
    ] {
        let refused = relay_policy::load_policy(&node.policy(), dir)
            .expect_err("the daemon refuses this Policy directory");
        assert!(refused.refuses_start(), "got {refused:?}");
        assert!(refused.to_string().contains(expected), "got {refused}");

        for extra in [&[][..], &["--strict"][..]] {
            let mut args = vec!["--policy-dir", dir.to_str().unwrap()];
            args.extend_from_slice(extra);
            let (code, stdout, stderr) = check_output(&node, &args);
            assert_eq!(code, Some(1), "{dir:?} {extra:?}: stderr: {stderr}");
            assert_eq!(
                printed_fingerprint(&stdout),
                None,
                "{dir:?} {extra:?}: no fingerprint for a refused layout; stdout: {stdout}"
            );
            assert!(
                stderr.contains(&refused.to_string()),
                "{dir:?} {extra:?}: the loader's own error; stderr: {stderr}"
            );
        }
    }
}

/// A Policy file that is a symlink to a valid Policy is refused by the loader,
/// which runs deny-all on it, so `policy check` refuses it too, with the
/// loader's own error, with or without the Policy directory.
#[test]
fn check_refuses_a_symlinked_policy_file() {
    let node = Node::without_policy_file("policy-dir-symlinked-file");
    let real = node.root.path().join("real-policy.toml");
    node.write(&real, ALLOW_NGINX);
    std::os::unix::fs::symlink(&real, node.policy()).unwrap();
    node.fragment("10-sshd.toml", ALLOW_SSHD);

    let (exited, all) = run_daemon(&node, DENY_ALL_LINE);
    assert!(exited.is_none(), "deny-all, not a refusal: {all}");
    assert!(all.contains(DENY_ALL_LINE), "journal: {all}");

    let refusal = relay_policy::PolicyError::SymlinkPath.to_string();
    for extra in [&[][..], &["--strict"][..]] {
        for with_dir in [false, true] {
            let (code, stdout, stderr) = if with_dir {
                check_dir(&node, extra)
            } else {
                check_output(&node, extra)
            };
            assert_eq!(code, Some(1), "dir {with_dir} {extra:?}: stderr: {stderr}");
            assert_eq!(printed_fingerprint(&stdout), None, "stdout: {stdout}");
            assert!(
                stderr.contains(&refusal),
                "the loader's own error; stderr: {stderr}"
            );
        }
    }
}

/// A mistyped table in a deny-only fragment is a parse error, not a silent
/// no-op that leaves the allow standing.
#[test]
fn check_fails_on_an_unknown_key_in_a_fragment() {
    let node = Node::new("policy-dir-unknown-key", ALLOW_NGINX);
    node.fragment(
        "90-deny.toml",
        "[[denny]]\nname = \"service.restart\"\nargs = []\n",
    );
    let policy_dir = node.dir();
    let (code, stderr) = check_with(&node, &["--policy-dir", policy_dir.to_str().unwrap()]);
    assert_eq!(code, Some(1), "stderr: {stderr}");
    assert!(
        stderr.contains("error: \"90-deny.toml\": ") && stderr.contains("denny"),
        "stderr: {stderr}"
    );
}

#[test]
fn check_escapes_a_fragment_name_in_its_errors() {
    let node = Node::new("policy-dir-escaped-name", ALLOW_NGINX);
    node.fragment("a\nb.toml", "not = = toml");
    let policy_dir = node.dir();
    let (code, stderr) = check_with(&node, &["--policy-dir", policy_dir.to_str().unwrap()]);
    assert_eq!(code, Some(1), "stderr: {stderr}");
    assert!(stderr.contains("\"a\\nb.toml\": "), "stderr: {stderr}");
    assert!(!stderr.contains("a\nb.toml"), "stderr: {stderr:?}");
}

/// Without `--policy-dir` the result covers the file alone, and `check` says
/// so when the directory beside the file holds fragments.
#[test]
fn check_without_policy_dir_warns_when_the_directory_is_populated() {
    let node = Node::new("policy-dir-uncovered", ALLOW_NGINX);

    let (code, stderr) = check_with(&node, &["--strict"]);
    assert_eq!(code, Some(0), "an empty directory is quiet: {stderr}");
    assert!(stderr.is_empty(), "stderr: {stderr}");

    node.fragment("10-sshd.toml", ALLOW_SSHD);
    let (code, stderr) = check_with(&node, &[]);
    assert_eq!(code, Some(0), "a warning alone does not fail: {stderr}");
    assert!(
        stderr.contains("warning: ")
            && stderr.contains("--policy-dir was not given")
            && stderr.contains("covers the Policy file alone"),
        "stderr: {stderr}"
    );

    let (code, stderr) = check_with(&node, &["--strict"]);
    assert_eq!(code, Some(1), "--strict fails on the warning: {stderr}");

    let policy_dir = node.dir();
    let (code, stderr) = check_with(
        &node,
        &["--strict", "--policy-dir", policy_dir.to_str().unwrap()],
    );
    assert_eq!(code, Some(0), "naming the directory clears it: {stderr}");
    assert!(stderr.is_empty(), "stderr: {stderr}");
}
