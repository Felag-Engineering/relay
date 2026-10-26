//! The Policy directory, driven through the compiled binary (DI-36, DI-46).
//!
//! A fragment the daemon refuses to start on really stops the process, with a
//! non-zero exit and a journal line that names the fragment; and `policy check`
//! prints the Policy fingerprint the daemon's own loader computes over the same
//! files. The loader's composition rules are proved at the crate level, in
//! `relay-policy`; this file proves what only a real process can: the exit and
//! the CLI.

// Spawning the compiled binary is the point; clippy.toml's spawn ban is for the
// daemon's own code.
#![allow(clippy::disallowed_methods)]

mod common;

use common::TempDir;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
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
        let root = TempDir::new(label);
        std::fs::create_dir_all(root.path()).expect("create the config dir");
        set_mode(root.path(), 0o755);
        let node = Node { root };
        node.write(&node.policy(), policy);
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
    let out = Command::new(env!("CARGO_BIN_EXE_relay-daemon"))
        .env_clear()
        .args(["policy", "check"])
        .arg(node.policy())
        .args(extra)
        .output()
        .expect("spawn relay-daemon policy check");
    (
        out.status.code(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
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
