//! Offline proof of what the release workflow promises about the relay-daemon: a static
//! binary for both architectures, built twice from different paths and refused unless the
//! two builds are byte-identical, listed in a keylessly signed `SHA256SUMS` (DI-1), and no
//! workflow that publishes the daemon as a container image (DI-2). It also proves the
//! packages' release half: gated on the install matrix, attached under `SHA256SUMS` with an
//! SBOM each, built twice and unsigned (DI-24, RC-23), and the Ansible role's release half and
//! the matrix's hash-locked ansible-core and release-mode role (DI-45), reading
//! `install-matrix.yml` as well, and the role's restart handler with the matrix's fragment run
//! (DI-47), reading the role, its test fixture and the matrix script.
//!
//! A workflow cannot run in a test, so the files are read as text and the assertions are on
//! properties of the job graph, never on exact lines: a reworded step stays green, a removed
//! guard does not. Spec-proof harvests only Rust and Go tests, which is why this is a test
//! over the file and not a script. Full-line `#` comments are dropped before any assertion,
//! so prose that names a property never satisfies it. Hermetic: no network, no Docker, and
//! nothing is spawned.
//!
//! The refusal is a property of the graph, sound because GitHub skips a job when a job it
//! needs failed: the comparing job gates every privileged job, and no job on those chains
//! carries a status-function condition or `continue-on-error` that would run it past a
//! failure.

use regex::Regex;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

type Jobs = BTreeMap<String, String>;

const IMAGE: &str = "ghcr.io/felag-engineering/relay";

fn repo() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("daemon/ has a parent")
        .to_path_buf()
}

fn read(path: &Path) -> String {
    std::fs::read_to_string(path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
}

fn re(pattern: &str) -> Regex {
    Regex::new(pattern).unwrap_or_else(|e| panic!("regex {pattern}: {e}"))
}

/// The file without its full-line `#` comments.
fn code(text: &str) -> String {
    text.lines()
        .filter(|l| !l.trim_start().starts_with('#'))
        .map(|l| format!("{l}\n"))
        .collect()
}

/// The lines of `text`, each backslash continuation joined to the line it continues.
fn logical(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut pending = String::new();
    for line in text.lines() {
        let trimmed = line.trim_end();
        if let Some(head) = trimmed.strip_suffix('\\') {
            pending.push_str(head.trim_start());
            pending.push(' ');
            continue;
        }
        if pending.is_empty() {
            out.push(trimmed.to_string());
        } else {
            pending.push_str(trimmed.trim_start());
            out.push(std::mem::take(&mut pending));
        }
    }
    if !pending.is_empty() {
        out.push(pending);
    }
    out
}

/// Each job's text, from the `jobs:` key on.
fn jobs(text: &str) -> Jobs {
    let header = re(r"^  ([A-Za-z0-9_-]+):\s*$");
    let mut out = Jobs::new();
    let mut current: Option<String> = None;
    let mut in_jobs = false;
    for line in text.lines() {
        if line == "jobs:" {
            in_jobs = true;
            continue;
        }
        if !in_jobs {
            continue;
        }
        if !line.is_empty() && !line.starts_with(' ') {
            in_jobs = false;
            continue;
        }
        if let Some(c) = header.captures(line) {
            current = Some(c[1].to_string());
            out.entry(c[1].to_string()).or_default();
            continue;
        }
        if let Some(name) = &current {
            let body = out.get_mut(name).expect("job entry exists");
            body.push_str(line);
            body.push('\n');
        }
    }
    out
}

/// The job-level `needs:`, in the scalar or flow-list form.
fn needs(job: &str) -> Vec<String> {
    let Some(c) = re(r"(?m)^ {4}needs:[ \t]*(.*?)[ \t]*$").captures(job) else {
        return Vec::new();
    };
    c[1].trim_matches(|ch| ch == '[' || ch == ']')
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

fn ancestors(all: &Jobs, name: &str) -> BTreeSet<String> {
    let mut seen = BTreeSet::new();
    let mut stack = vec![name.to_string()];
    while let Some(n) = stack.pop() {
        for parent in needs(all.get(&n).unwrap_or_else(|| panic!("no job {n}"))) {
            if seen.insert(parent.clone()) {
                stack.push(parent);
            }
        }
    }
    seen
}

/// The job-level `if:` (four spaces); a step-level `if:` sits deeper.
fn job_if(job: &str) -> Option<String> {
    re(r"(?m)^ {4}if:[ \t]*(.*?)[ \t]*$")
        .captures(job)
        .map(|c| c[1].to_string())
}

/// The job-level permission grants, comments stripped.
fn perms(job: &str) -> BTreeMap<String, String> {
    let header = re(r"^ {4}permissions:\s*$");
    let mut out = BTreeMap::new();
    let mut inside = false;
    for line in job.lines() {
        if !inside {
            inside = header.is_match(line);
            continue;
        }
        if line.trim().is_empty() {
            continue;
        }
        if line.len() - line.trim_start().len() < 6 {
            break;
        }
        let bare = line.split('#').next().unwrap_or("");
        if let Some((k, v)) = bare.split_once(':') {
            out.insert(k.trim().to_string(), v.trim().to_string());
        }
    }
    out
}

/// The job's steps, each from its `- ` line to the next step.
fn steps(job: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for line in job.lines() {
        if line.starts_with("      - ") {
            out.push(String::new());
        }
        if let Some(step) = out.last_mut() {
            step.push_str(line);
            step.push('\n');
        }
    }
    out
}

fn grants_privilege(job: &str) -> bool {
    perms(job)
        .iter()
        .any(|(k, v)| v == "write" && matches!(k.as_str(), "id-token" | "contents" | "packages"))
}

fn release() -> Jobs {
    let text = code(&read(&repo().join(".github/workflows/release.yml")));
    // A workflow-level grant is inherited by every job without its own block, and the
    // privileged-job set below reads job-level blocks only.
    let top_level: Vec<&str> = text
        .lines()
        .filter(|l| l.starts_with("permissions:"))
        .map(|l| l.split('#').next().unwrap_or("").trim())
        .collect();
    assert_eq!(
        top_level,
        ["permissions: {}"],
        "the workflow grants nothing at its top level"
    );
    let all = jobs(&text);
    assert!(all.len() >= 5, "release.yml parsed to {:?}", all.keys());
    for (name, job) in &all {
        assert!(
            !re(r"(?m)^ {4}permissions:[ \t]*[^\s{#]").is_match(job),
            "job {name} states permissions inline; keep them a block so the graph check sees them"
        );
    }
    all
}

/// The `build` job's matrix `include:` entries, as (arch, daemon triple, platform).
fn matrix_includes(build: &str) -> Vec<(String, String, String)> {
    re(r"(?s)-\s*arch:\s*(\S+).*?daemon_triple:\s*(\S+).*?platform:\s*(\S+)")
        .captures_iter(build)
        .map(|c| (c[1].to_string(), c[2].to_string(), c[3].to_string()))
        .collect()
}

/// The one job satisfying `pred`, which receives the job's name and its text.
fn only<'a>(
    all: &'a Jobs,
    what: &str,
    pred: impl Fn(&str, &str) -> bool,
) -> (&'a String, &'a String) {
    let found: Vec<_> = all.iter().filter(|(n, j)| pred(n, j)).collect();
    assert_eq!(
        found.len(),
        1,
        "expected exactly one job to be {what}, found {:?}",
        found.iter().map(|(n, _)| *n).collect::<Vec<_>>()
    );
    found[0]
}

/// The comparing job, found by what it does and not by its name.
fn comparing_job(all: &Jobs) -> (&String, &String) {
    only(all, "the one that compares the two builds", |_, j| {
        needs(j).iter().any(|n| n == "build")
            && j.contains("for arch in x86_64 aarch64")
            && j.contains("cmp ")
            && j.contains("exit \"${fail}\"")
    })
}

// Proves DI-1.
#[test]
fn release_daemon_is_static_musl_for_both_architectures() {
    let all = release();
    let build = &all["build"];

    let includes = matrix_includes(build);
    let want: BTreeSet<(String, String, String)> = [
        ("x86_64", "x86_64-unknown-linux-musl", "linux-amd64"),
        ("aarch64", "aarch64-unknown-linux-musl", "linux-arm64"),
    ]
    .iter()
    .map(|(a, t, p)| (a.to_string(), t.to_string(), p.to_string()))
    .collect();
    assert_eq!(
        includes.iter().cloned().collect::<BTreeSet<_>>(),
        want,
        "the daemon is built for x86_64 and aarch64, each as a static musl target"
    );
    assert!(
        re(r"(?m)^\s+DAEMON_TRIPLE:\s*\$\{\{\s*matrix\.daemon_triple\s*\}\}").is_match(build),
        "the build target comes from the matrix's musl triple"
    );

    let release_build = logical(build)
        .into_iter()
        .find(|l| l.contains("make build-daemon-release"))
        .expect("the build job runs make build-daemon-release");
    assert!(
        re(r#"RELEASE_DAEMON_TARGET="?\$\{?DAEMON_TRIPLE\}?"?(\s|$)"#).is_match(&release_build)
            || release_build.contains("matrix.daemon_triple"),
        "the release daemon is built for the matrix triple: {release_build}"
    );
    let build_step = steps(build)
        .into_iter()
        .find(|s| s.contains("make build-daemon-release"))
        .expect("a step builds the daemon");
    assert!(
        build_step.contains("cd \"$SRC\""),
        "the daemon is built from the pass's own checkout path"
    );

    let static_step = steps(build)
        .into_iter()
        .find(|s| re(r"\bldd\b").is_match(s))
        .expect("a step checks the binaries with ldd");
    for needle in ["print-release-daemon-bin", "statically linked", "exit"] {
        assert!(
            static_step.contains(needle),
            "the static guard names {needle}: {static_step}"
        );
    }
}

// Proves DI-1.
#[test]
fn release_refuses_unless_two_builds_from_different_paths_are_identical() {
    let all = release();
    let build = &all["build"];

    let passes: Vec<String> = re(r"(?m)^\s+pass:\s*\[([^\]]*)\]")
        .captures(build)
        .expect("the build matrix has a pass list")[1]
        .split(',')
        .map(|s| s.trim().to_string())
        .collect();
    assert_eq!(passes.len(), 2, "two builds of the same commit: {passes:?}");

    let src = re(r"(?m)^\s+SRC:\s*(.*)$")
        .captures(build)
        .expect("the build job names its checkout path")[1]
        .to_string();
    assert!(
        src.contains("matrix.pass"),
        "the path varies by pass: {src}"
    );
    let paths = re(r"&&\s*'([^']*)'\s*\|\|\s*'([^']*)'")
        .captures(&src)
        .unwrap_or_else(|| panic!("SRC is `<pass test> && '<a>' || '<b>'`: {src}"));
    assert!(
        !paths[1].is_empty() && !paths[2].is_empty() && paths[1] != paths[2],
        "the two passes build from different paths: {src}"
    );
    let checkout = steps(build)
        .into_iter()
        .find(|s| s.contains("actions/checkout"))
        .expect("the build job checks out the source");
    assert!(
        checkout.contains("path: ${{ env.SRC }}"),
        "the checkout lands at the pass's path: {checkout}"
    );

    let (c_name, c) = comparing_job(&all);
    for needle in ["bin-${arch}-primary", "bin-${arch}-rebuild", "/relay-*"] {
        assert!(
            c.contains(needle),
            "the comparing job {c_name} compares the primary pass's files with the rebuild's ({needle})"
        );
    }
    let compare = steps(c)
        .into_iter()
        .find(|s| s.contains("cmp "))
        .expect("a step compares the binaries");
    assert!(
        compare.contains("fail=1"),
        "a difference sets the failure flag: {compare}"
    );
    assert_eq!(
        compare.trim_end().lines().last().map(str::trim),
        Some("exit \"${fail}\""),
        "the comparing step ends by exiting on the failure flag"
    );

    // The refusal: GitHub skips a job whose needed job failed, unless its own condition
    // runs it past that.
    let privileged: Vec<&String> = all
        .iter()
        .filter(|(_, j)| grants_privilege(j))
        .map(|(n, _)| n)
        .collect();
    assert!(!privileged.is_empty(), "no job holds a privilege to guard");
    for p in privileged {
        let chain = ancestors(&all, p);
        assert!(
            chain.contains(c_name.as_str()),
            "privileged job {p} does not need the comparing job {c_name} (DI-1)"
        );
        let mut checked = chain.clone();
        checked.insert(p.clone());
        for j in &checked {
            let text = &all[j];
            if let Some(cond) = job_if(text) {
                for status in ["always()", "cancelled()", "failure()"] {
                    assert!(
                        !cond.contains(status),
                        "job {j} on {p}'s chain runs past a failed build: if: {cond}"
                    );
                }
            }
            assert!(
                !re(r"(?m)^ {4}continue-on-error:").is_match(text),
                "job {j} on {p}'s chain continues on error"
            );
        }
    }
    assert!(
        !c.contains("continue-on-error"),
        "the comparing job {c_name} cannot continue past a difference"
    );
    assert!(
        all.values().any(|j| job_if(j).is_some()),
        "no job-level condition was parsed, so the status-function check saw nothing"
    );
}

// Proves DI-1.
#[test]
fn release_sums_list_both_daemons_and_are_signed_keylessly() {
    let all = release();
    let build = &all["build"];

    assert!(
        logical(build).iter().any(|l| re(
            r#"\bcp\s+\S+\s+"dist/relay-daemon-\$\{version\}-\$\{PLATFORM\}""#
        )
        .is_match(l)),
        "each build stages the daemon as relay-daemon-<version>-<platform>"
    );
    let platforms: BTreeSet<(String, String)> = matrix_includes(build)
        .into_iter()
        .map(|(arch, _, platform)| (arch, platform))
        .collect();
    assert_eq!(
        platforms,
        [("x86_64", "linux-amd64"), ("aarch64", "linux-arm64")]
            .iter()
            .map(|(a, p)| (a.to_string(), p.to_string()))
            .collect(),
        "both architectures are staged under a platform name"
    );

    let (c_name, c) = comparing_job(&all);
    let assemble = steps(c)
        .into_iter()
        .find(|s| {
            logical(s).iter().any(|l| {
                re(r#"\bcp\s+bins/bin-"?\$\{arch\}"?-primary/relay-\*\s+dist/?(\s|$)"#).is_match(l)
            })
        })
        .unwrap_or_else(|| panic!("{c_name} copies the primary pass's relay-* into dist"));
    assert!(
        assemble.contains("for arch in x86_64 aarch64"),
        "the release set is assembled for both architectures"
    );

    let writes_sums = re(r#"(^|[^>])>\s*"?SHA256SUMS"?(\s|$)"#);
    let (w_name, w) = only(&all, "the writer of SHA256SUMS", |_, j| {
        logical(j)
            .iter()
            .any(|l| l.contains("sha256sum") && l.contains("relay-*") && writes_sums.is_match(l))
    });
    let handoff = |job: &str, action: &str| {
        steps(job)
            .into_iter()
            .any(|s| s.contains(action) && s.contains("name: release-dist"))
    };
    assert!(
        handoff(w, "actions/upload-artifact"),
        "{w_name} uploads the release-dist artifact it wrote SHA256SUMS into"
    );

    let (s_name, s) = only(&all, "the signer of SHA256SUMS", |_, j| {
        perms(j).get("id-token").is_some_and(|v| v == "write") && j.contains("cosign sign-blob")
    });
    assert!(
        ancestors(&all, s_name).contains(w_name.as_str()),
        "{s_name} signs only after {w_name} wrote SHA256SUMS"
    );
    assert!(
        handoff(s, "actions/download-artifact"),
        "{s_name} signs the release-dist artifact it downloaded"
    );
    let sign = logical(s)
        .into_iter()
        .find(|l| l.contains("cosign sign-blob"))
        .expect("signing step");
    assert!(
        sign.split_whitespace()
            .last()
            .is_some_and(|t| t.ends_with("SHA256SUMS")),
        "the blob signed is SHA256SUMS, not its bundle: {sign}"
    );

    let yml = code(&read(&repo().join(".github/workflows/release.yml")));
    let cosign: Vec<String> = logical(&yml)
        .into_iter()
        .filter(|l| re(r"\bcosign\s+(sign|sign-blob|verify|verify-blob)\b").is_match(l))
        .collect();
    assert!(cosign.len() >= 3, "cosign commands parsed: {cosign:?}");
    for line in &cosign {
        assert!(
            !re(r"\s--key(\s|=|$)").is_match(line),
            "signing is keyless, no --key: {line}"
        );
    }

    let verify = steps(s)
        .into_iter()
        .find(|st| st.contains("cosign verify-blob"))
        .unwrap_or_else(|| panic!("{s_name} verifies what it signed"));
    let verify_line = logical(&verify)
        .into_iter()
        .find(|l| l.contains("cosign verify-blob"))
        .expect("verify-blob command");
    let arg = re(r#"--certificate-identity\s+("[^"]*"|\S+)"#)
        .captures(&verify_line)
        .expect("verify-blob pins a certificate identity")[1]
        .trim_matches('"')
        .to_string();
    let identity = match re(r"^\$\{?(\w+)\}?$").captures(&arg) {
        Some(var) => re(&format!(r#"(?m)^\s*{}="([^"]*)""#, &var[1]))
            .captures(&verify)
            .unwrap_or_else(|| panic!("cannot resolve ${} in the verify step", &var[1]))[1]
            .to_string(),
        None => arg,
    };
    assert!(
        identity.contains("/.github/workflows/release.yml@"),
        "the signature must come from this workflow: {identity}"
    );
    assert!(
        verify_line
            .contains("--certificate-oidc-issuer https://token.actions.githubusercontent.com"),
        "the signature must come from GitHub's OIDC issuer: {verify_line}"
    );

    let releasers: Vec<_> = all
        .iter()
        .filter(|(_, j)| perms(j).get("contents").is_some_and(|v| v == "write"))
        .collect();
    assert!(!releasers.is_empty(), "no job writes the Release");
    for (name, _) in releasers {
        assert!(
            ancestors(&all, name).contains(s_name.as_str()),
            "{name} attaches the sums without needing the signer {s_name}"
        );
    }
}

// Proves DI-2.
#[test]
fn no_workflow_publishes_a_daemon_container_image() {
    let root = repo().join(".github");
    let mut files = Vec::new();
    for dir in ["workflows", "actions"] {
        collect_files(&root.join(dir), &mut files);
    }
    assert!(files.len() >= 4, "scanned only {files:?}");

    let ghcr = re(r"ghcr\.io/[A-Za-z0-9._/-]+");
    let publishes = re(r"docker\s+push|docker/build-push-action|--push\b|type=registry|push=true");
    let build_cmd = re(r"\bdocker\s+(buildx\s+)?build\b");
    let file_flag = re(r#"(?:^|\s)(?:--file|-f)(?:=|\s+)"?([^"\s]+)"#);
    let image_env = re(r"(?m)^\s*IMAGE:\s*(\S+)");

    for path in &files {
        let text = code(&read(path));
        let name = path.display();
        for line in logical(&text) {
            assert!(
                !line.contains("daemon.Dockerfile"),
                "{name}: the daemon is never delivered as a container (DI-2); daemon.Dockerfile is the \
                 dev fleet's image and no workflow builds it: {line}"
            );
            for m in ghcr.find_iter(&line) {
                assert_eq!(
                    m.as_str(),
                    IMAGE,
                    "{name}: the only registry path a workflow names is the Relay's image: {line}"
                );
            }
            assert!(
                !publishes.is_match(&line),
                "{name}: publishes an image: {line}"
            );
            for (at, _) in line.match_indices("docker://") {
                assert!(
                    line[at + "docker://".len()..].starts_with("${IMAGE}"),
                    "{name}: an image reference other than ${{IMAGE}}: {line}"
                );
            }
            if build_cmd.is_match(&line) {
                for f in file_flag.captures_iter(&line) {
                    assert!(
                        !f[1].contains("daemon"),
                        "{name}: an image build from a daemon Dockerfile: {line}"
                    );
                }
            }
        }
        for m in image_env.captures_iter(&text) {
            assert_eq!(&m[1], IMAGE, "{name}: IMAGE names the Relay's image");
        }
    }

    // The scan provably saw the publishing path.
    let yml = code(&read(&repo().join(".github/workflows/release.yml")));
    let builds: Vec<String> = logical(&yml)
        .into_iter()
        .filter(|l| l.contains("docker buildx build"))
        .collect();
    assert_eq!(builds.len(), 1, "release.yml builds one image: {builds:?}");
    assert_eq!(
        &file_flag
            .captures(&builds[0])
            .expect("the build names a Dockerfile")[1],
        "docker/relay.Dockerfile"
    );
    assert!(
        logical(&yml).iter().any(|l| l.contains("skopeo copy")
            && l.split_whitespace()
                .last()
                .is_some_and(|d| d.trim_matches('"').starts_with("docker://${IMAGE}"))),
        "release.yml pushes with skopeo to ${{IMAGE}}"
    );
    let publishers: Vec<_> = jobs(&yml)
        .into_iter()
        .filter(|(_, j)| perms(j).get("packages").is_some_and(|v| v == "write"))
        .collect();
    assert!(!publishers.is_empty(), "no job pushes to the registry");
    for (name, job) in publishers {
        assert!(
            image_env.captures_iter(&job).any(|m| &m[1] == IMAGE),
            "{name} holds packages: write without being pinned to the Relay's image"
        );
    }
}

fn collect_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let entries = std::fs::read_dir(dir).unwrap_or_else(|e| panic!("read {}: {e}", dir.display()));
    for entry in entries {
        let path = entry.expect("dir entry").path();
        if path.is_dir() {
            collect_files(&path, out);
        } else {
            out.push(path);
        }
    }
}

// ---- the packages and the Ansible role: the release half of DI-24, RC-23 and DI-45 ----

/// The install matrix's jobs, with the same top-level grant-nothing assertion as `release()`.
fn matrix() -> Jobs {
    let text = code(&read(&repo().join(".github/workflows/install-matrix.yml")));
    let top_level: Vec<&str> = text
        .lines()
        .filter(|l| l.starts_with("permissions:"))
        .map(|l| l.split('#').next().unwrap_or("").trim())
        .collect();
    assert_eq!(
        top_level,
        ["permissions: {}"],
        "the install matrix grants nothing at its top level"
    );
    let all = jobs(&text);
    assert!(
        all.len() >= 5,
        "install-matrix.yml parsed to {:?}",
        all.keys()
    );
    all
}

/// The `key: value` lines under a job's `with:` (a reusable-workflow call's inputs).
fn with_inputs(job: &str) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    let mut inside = false;
    for line in job.lines() {
        if !inside {
            inside = line == "    with:";
            continue;
        }
        if line.trim().is_empty() {
            continue;
        }
        if line.len() - line.trim_start().len() < 6 {
            break;
        }
        if let Some((k, v)) = line.trim().split_once(':') {
            out.insert(k.trim().to_string(), v.trim().to_string());
        }
    }
    out
}

/// A step's own `if:`.
fn step_if(step: &str) -> Option<String> {
    re(r"(?m)^ {8}if:[ \t]*(.*?)[ \t]*$")
        .captures(step)
        .map(|c| c[1].to_string())
}

/// Whether the shell glob `glob` (`*`, `?` and literals) matches the whole of `name`.
fn glob_matches(glob: &str, name: &str) -> bool {
    let mut pattern = String::from("^");
    for ch in glob.chars() {
        match ch {
            '*' => pattern.push_str(".*"),
            '?' => pattern.push('.'),
            other => pattern.push_str(&regex::escape(&other.to_string())),
        }
    }
    pattern.push('$');
    re(&pattern).is_match(name)
}

/// The job that calls the install matrix.
fn matrix_call(all: &Jobs) -> (&String, &String) {
    only(all, "the caller of the install matrix", |_, j| {
        re(r"(?m)^ {4}uses:[ \t]*\./\.github/workflows/install-matrix\.yml[ \t]*$").is_match(j)
    })
}

/// The index of the first step of `job` satisfying `pred`.
fn step_index(job: &str, what: &str, pred: impl Fn(&str) -> bool) -> usize {
    steps(job)
        .iter()
        .position(|s| pred(s))
        .unwrap_or_else(|| panic!("no step {what}"))
}

/// The index of the first logical line of `lines` matching `pattern`.
fn line_index(lines: &[String], what: &str, pattern: &Regex) -> usize {
    lines
        .iter()
        .position(|l| pattern.is_match(l))
        .unwrap_or_else(|| panic!("no line {what}"))
}

/// A step that downloads the release's artifact compares the digest of its SHA256SUMS with the
/// one the comparing job reported (through the environment), before it trusts a line of it.
fn assert_sums_digest_checked_first(step: &str, what: &str) {
    assert!(
        re(r"(?m)^\s+RELEASE_SUMS_SHA256:\s*\$\{\{\s*inputs\.release-sums-sha256\s*\}\}\s*$")
            .is_match(step),
        "{what} takes the expected digest from the input through its environment: {step}"
    );
    let lines = logical(step);
    let digest = line_index(
        &lines,
        "computing the digest of the downloaded SHA256SUMS",
        &re(r"sha256sum\s+release/SHA256SUMS"),
    );
    let compare = line_index(
        &lines,
        "comparing the digest",
        &re(r#"\[\s+"\$actual"\s+=\s+"\$RELEASE_SUMS_SHA256"\s+\]"#),
    );
    let listed = line_index(
        &lines,
        "checking a file against SHA256SUMS",
        &re(r"package-guard\.sh\s+listed\s+release/SHA256SUMS"),
    );
    assert!(
        digest < compare && compare < listed,
        "{what} compares the downloaded SHA256SUMS' digest before it trusts a line of it: {lines:?}"
    );
}

// Proves DI-24, RC-23.
#[test]
fn release_publishes_nothing_unless_the_install_matrix_passes_on_its_packages() {
    let all = release();
    let (c_name, c) = comparing_job(&all);
    let (m_name, m) = matrix_call(&all);

    // The matrix is handed the artifact the signer and the Release publish, and the version
    // the comparing job stamped.
    let inputs = with_inputs(m);
    let upload = steps(c)
        .into_iter()
        .find(|s| {
            s.contains("actions/upload-artifact") && re(r"(?m)^\s+path:\s*dist/?\s*$").is_match(s)
        })
        .expect("the comparing job uploads dist/");
    let artifact = re(r"(?m)^\s+name:\s*(\S+)")
        .captures(&upload)
        .expect("the upload is named")[1]
        .to_string();
    assert_eq!(
        inputs.get("release-dist"),
        Some(&artifact),
        "the matrix tests the artifact that is published"
    );
    assert_eq!(
        inputs.get("release-version"),
        Some(&format!("${{{{ needs.{c_name}.outputs.version }}}}")),
        "the matrix is told the version the comparing job stamped"
    );
    assert_eq!(
        inputs.get("release-sums-sha256"),
        Some(&format!("${{{{ needs.{c_name}.outputs.sums_sha256 }}}}")),
        "the matrix is told the digest of the SHA256SUMS the comparing job wrote"
    );
    assert!(
        needs(m).iter().any(|n| n == c_name.as_str()),
        "the matrix runs after {c_name}, on its output"
    );
    let granted = perms(m);
    assert!(
        granted.values().all(|v| v != "write")
            && granted.get("contents").is_some_and(|v| v == "read"),
        "the matrix call holds no write privilege: {granted:?}"
    );

    // Every job that can publish waits for the matrix, and nothing on its chain runs past a
    // failure.
    let privileged: Vec<&String> = all
        .iter()
        .filter(|(_, j)| grants_privilege(j))
        .map(|(n, _)| n)
        .collect();
    assert!(!privileged.is_empty(), "no job holds a privilege to guard");
    for p in privileged {
        let chain = ancestors(&all, p);
        assert!(
            chain.contains(m_name.as_str()),
            "privileged job {p} does not need the install matrix {m_name} (DI-24)"
        );
        let mut checked = chain.clone();
        checked.insert(p.clone());
        for j in &checked {
            let text = &all[j];
            if let Some(cond) = job_if(text) {
                for status in ["always()", "cancelled()", "failure()"] {
                    assert!(
                        !cond.contains(status),
                        "job {j} on {p}'s chain runs past a failed matrix: if: {cond}"
                    );
                }
                assert!(
                    !re(r"success\(\)\s*\|\|").is_match(&cond),
                    "job {j} on {p}'s chain runs past a failed matrix through `success() ||`: if: {cond}"
                );
            }
            assert!(
                !re(r"(?m)^ {4}continue-on-error:").is_match(text),
                "job {j} on {p}'s chain continues on error"
            );
        }
    }

    // Inside the matrix: in release mode it tests the release's bytes, not a rebuild.
    let raw = code(&read(&repo().join(".github/workflows/install-matrix.yml")));
    for input in ["release-dist", "release-version", "release-sums-sha256"] {
        assert!(
            re(&format!(r"(?m)^ {{6}}{input}:\s*$")).is_match(&raw),
            "install-matrix.yml declares the {input} input"
        );
    }
    let mx = matrix();
    let build_steps = steps(&mx["build"]);
    let download = build_steps
        .iter()
        .find(|s| {
            s.contains("actions/download-artifact")
                && s.contains("name: ${{ inputs.release-dist }}")
        })
        .expect("the build job downloads the release's artifact");
    assert_eq!(
        step_if(download).as_deref(),
        Some("inputs.release-dist != ''"),
        "the download happens only in release mode"
    );
    let rebuilds: Vec<&String> = build_steps
        .iter()
        .filter(|s| {
            logical(s)
                .iter()
                .any(|l| l.contains("build-packages.sh") && l.contains("pkgs/new"))
        })
        .collect();
    assert!(
        !rebuilds.is_empty(),
        "the build job builds a new set outside release mode"
    );
    for s in rebuilds {
        assert_eq!(
            step_if(s).as_deref(),
            Some("inputs.release-dist == ''"),
            "a rebuild of the new set runs only outside release mode: {s}"
        );
    }
    let take = build_steps
        .iter()
        .find(|s| {
            step_if(s).as_deref() == Some("inputs.release-dist != ''") && s.contains("pkgs/new")
        })
        .expect("a release-mode step puts the release's packages into pkgs/new");
    for needle in [
        "package-guard.sh listed release/SHA256SUMS",
        "cp ",
        "RELEASE_VERSION",
        "pkgs/VERSION",
    ] {
        assert!(
            take.contains(needle),
            "the release-mode step names {needle}: {take}"
        );
    }
    // Exactly the architecture's four packages (relay-daemon and relay, each .deb and .rpm).
    assert!(
        logical(take)
            .iter()
            .any(|l| re(r#""\$\{#files\[@\]\}"\s+-eq\s+4\b"#).is_match(l)),
        "the release-mode step refuses anything but four packages: {take}"
    );
    assert_sums_digest_checked_first(take, "the release-mode package step");

    // The other rows consume the build job's packages and rebuild nothing.
    for (name, job) in &mx {
        assert!(
            !job.contains("continue-on-error"),
            "matrix job {name} cannot continue past a failure"
        );
        if let Some(cond) = job_if(job) {
            for status in ["always()", "cancelled()", "failure()"] {
                assert!(
                    !cond.contains(status),
                    "matrix job {name} runs past a failed row: if: {cond}"
                );
            }
        }
        assert!(
            !grants_privilege(job),
            "matrix job {name} holds a write privilege"
        );
        if name == "build" {
            continue;
        }
        assert!(
            needs(job).iter().any(|n| n == "build"),
            "matrix job {name} runs on build's packages"
        );
        assert!(
            steps(job)
                .iter()
                .any(|s| s.contains("actions/download-artifact")
                    && s.contains("install-matrix-packages-")),
            "matrix job {name} downloads build's packages"
        );
        assert!(
            !job.contains("build-packages.sh"),
            "matrix job {name} builds no package of its own"
        );
    }

    // An input reaches a shell only through the environment, never the script text.
    let value_or_condition =
        re(r"^\s*(?:-\s+)?[A-Za-z0-9_-]+:\s*\$\{\{\s*inputs\.[a-z0-9-]+\s*\}\}\s*$|^\s*if:");
    for line in raw.lines().filter(|l| l.contains("${{ inputs.")) {
        assert!(
            value_or_condition.is_match(line),
            "an input is interpolated into more than a value or a condition: {line}"
        );
    }
}

// Proves DI-24, RC-23.
#[test]
fn release_attaches_every_package_and_its_sbom_under_sha256sums() {
    let all = release();
    let (c_name, c) = comparing_job(&all);
    let lines = logical(c);

    // A guarded package is copied into the release set, after every guard on it.
    let guard_step = step_index(c, "guarding the packages", |s| {
        s.contains("package-guard.sh") && s.contains("no-config")
    });
    let guard = &steps(c)[guard_step];
    let gl = logical(guard);
    let copy = line_index(
        &gl,
        "copying a package into dist/",
        &re(r#"\bcp\s+"\$\{f\}"\s+"?dist/"#),
    );
    for (what, pattern) in [
        ("same", r"\bsame\b"),
        ("content", r"\bcontent\b"),
        ("no-config", r"\bno-config\b"),
        ("listed", r"\blisted\b"),
    ] {
        let last = gl
            .iter()
            .rposition(|l| l.contains("guard") && re(pattern).is_match(l))
            .unwrap_or_else(|| panic!("the guard step runs `{what}`"));
        assert!(
            last < copy,
            "`{what}` runs before the package is copied: {gl:?}"
        );
    }
    assert!(
        guard.contains("-eq 8"),
        "exactly eight packages (two per architecture and family) are staged"
    );
    assert!(
        !steps(c)
            .iter()
            .any(|s| re(r"(?m)^\s+name:\s*packages\s*$").is_match(s)),
        "no second artifact carries the packages"
    );

    // Each package gets an SBOM, after the guard.
    let sbom_step = step_index(c, "writing SBOMs for the packages", |s| {
        s.contains("dist/*.deb")
            && s.contains("dist/*.rpm")
            && s.contains("spdx-json=${f}.spdx.json")
    });
    assert!(
        sbom_step > guard_step,
        "the SBOMs describe guarded packages"
    );

    // The role is staged, then the sums are written after everything they must list.
    let role_step = step_index(c, "staging the Ansible role", |s| {
        s.contains("dist/relay_daemon-${VERSION}.tar.gz") && s.contains("tar ")
    });
    let writes_sums = re(r#"(^|[^>])>\s*"?SHA256SUMS"?(\s|$)"#);
    let writer_step = step_index(c, "writing SHA256SUMS", |s| {
        logical(s)
            .iter()
            .any(|l| l.contains("sha256sum") && l.contains("relay-*") && writes_sums.is_match(l))
    });
    assert!(
        writer_step > guard_step && writer_step > sbom_step && writer_step > role_step,
        "SHA256SUMS is written after the packages, their SBOMs and the role are in dist/ ({c_name})"
    );
    let writer = logical(&steps(c)[writer_step]);
    let writer_line = writer
        .iter()
        .find(|l| l.contains("sha256sum") && l.contains("relay-*") && writes_sums.is_match(l))
        .expect("the writer line");
    let globs: Vec<&str> = writer_line
        .split_whitespace()
        .skip_while(|t| *t != "sha256sum")
        .skip(1)
        .take_while(|t| *t != ">")
        .collect();
    let mut names: Vec<String> = Vec::new();
    for deb in ["relay-daemon_1.2.3-1", "relay_1.2.3-1"] {
        for arch in ["amd64", "arm64"] {
            names.push(format!("{deb}_{arch}.deb"));
        }
    }
    for rpm in ["relay-daemon-1.2.3-1", "relay-1.2.3-1"] {
        for arch in ["x86_64", "aarch64"] {
            names.push(format!("{rpm}.{arch}.rpm"));
        }
    }
    let sboms: Vec<String> = names.iter().map(|n| format!("{n}.spdx.json")).collect();
    names.extend(sboms);
    names.extend(
        [
            "relay_daemon-1.2.3.tar.gz",
            "relay-1.2.3-linux-amd64",
            "relay-daemon-1.2.3-linux-arm64.spdx.json",
            "relay.service",
            "relay.toml.example",
            "relay-daemon.service",
            "relay-daemon.env.example",
        ]
        .map(String::from),
    );
    for name in &names {
        assert!(
            globs.iter().any(|g| glob_matches(g, name)),
            "SHA256SUMS would not list {name}; the writer's globs are {globs:?}"
        );
    }

    // Anything left unlisted, or named in a way GitHub rewrites, stops the job.
    // A published release's names are ^[A-Za-z0-9._-]+$: only a dry run may carry a "+".
    let writer_text = &steps(c)[writer_step];
    assert!(
        re(r"(?m)^\s+[A-Z_]+:\s*\$\{\{\s*github\.event_name == 'push' && startsWith\(github\.ref, 'refs/tags/v'\)\s*\}\}\s*$")
            .is_match(writer_text),
        "the name guard learns whether this is a tag push through the environment: {writer_text}"
    );
    assert!(
        writer.iter().any(|l| l.contains("^[A-Za-z0-9._+-]+$")),
        "a dry run's names may carry a plus: {writer:?}"
    );
    assert!(
        writer
            .iter()
            .any(|l| { l.contains("pattern='^[A-Za-z0-9._-]+$'") && l.contains("!= \"true\"") }),
        "a tag push's names may not carry a plus: {writer:?}"
    );
    let writer_at = line_index(&lines, "the SHA256SUMS writer", &writes_sums);
    let name_check = line_index(&lines, "checking file names", &re(r"A-Za-z0-9"));
    assert!(
        name_check < writer_at,
        "file names are checked before the sums are written"
    );
    let find = lines
        .iter()
        .enumerate()
        .skip(writer_at)
        .find(|(_, l)| l.contains("find dist") && l.contains("SHA256SUMS"))
        .expect("every file in dist/ is collected after the sums are written")
        .0;
    assert!(
        lines
            .iter()
            .skip(find)
            .any(|l| l.contains("package-guard.sh listed dist/SHA256SUMS")),
        "every collected file is checked against dist/SHA256SUMS"
    );

    // What was listed is what is uploaded, signed and attached.
    let upload_step = step_index(c, "uploading the release set", |s| {
        s.contains("actions/upload-artifact") && re(r"(?m)^\s+path:\s*dist/?\s*$").is_match(s)
    });
    assert!(
        upload_step > writer_step,
        "dist/ is uploaded after SHA256SUMS is final"
    );
    let (_, releaser) = only(&all, "the job that writes the Release", |_, j| {
        perms(j).get("contents").is_some_and(|v| v == "write")
    });
    let attach: Vec<String> = logical(releaser)
        .into_iter()
        .filter(|l| l.contains("gh release") && l.contains("dist/*"))
        .collect();
    assert!(
        attach.iter().any(|l| l.contains("gh release create"))
            && attach.iter().any(|l| l.contains("gh release upload")),
        "the Release is created or updated with every file in dist/: {attach:?}"
    );
}

// Proves DI-24, RC-23.
#[test]
fn release_signs_and_tests_only_the_sha256sums_the_comparing_job_wrote() {
    let all = release();
    let (c_name, c) = comparing_job(&all);

    // The comparing job exports the digest of the SHA256SUMS it uploads, computed once the
    // completeness check has passed.
    let output = re(
        r"(?m)^ {6}sums_sha256:\s*\$\{\{\s*steps\.([A-Za-z0-9_-]+)\.outputs\.([A-Za-z0-9_-]+)\s*\}\}\s*$",
    )
    .captures(c)
    .unwrap_or_else(|| panic!("{c_name} exports sums_sha256 from a step output"));
    let (step_id, key) = (output[1].to_string(), output[2].to_string());
    let writer = steps(c)
        .into_iter()
        .find(|s| re(&format!(r"(?m)^\s+id:\s*{step_id}\s*$")).is_match(s))
        .unwrap_or_else(|| panic!("no step has id {step_id}"));
    let lines = logical(&writer);
    let completeness = line_index(
        &lines,
        "checking every file is listed",
        &re(r"package-guard\.sh\s+listed\s+dist/SHA256SUMS"),
    );
    let export = line_index(
        &lines,
        "exporting the digest",
        &re(&format!(
            r#"{key}=.*sha256sum\s+dist/SHA256SUMS.*>>\s*"\$GITHUB_OUTPUT""#
        )),
    );
    assert!(
        completeness < export,
        "the digest of dist/SHA256SUMS is exported after the completeness check: {lines:?}"
    );

    // The signer compares it with the file it downloaded before it appends to, or signs, it.
    let (_, signer) = only(&all, "the job that signs", |_, j| {
        j.contains("cosign sign-blob")
    });
    assert!(
        needs(signer).iter().any(|n| n == c_name.as_str()),
        "the signer reads {c_name}'s output, so it needs it"
    );
    let st = steps(signer);
    let download = step_index(signer, "downloading the release set", |s| {
        s.contains("actions/download-artifact") && s.contains("name: release-dist")
    });
    let compare = step_index(signer, "comparing the SHA256SUMS digest", |s| {
        logical(s)
            .iter()
            .any(|l| re(r#"\[\s+"\$\{actual\}"\s+=\s+"\$\{SUMS_SHA256\}"\s+\]"#).is_match(l))
    });
    let compare_text = &st[compare];
    assert!(
        re(&format!(
            r"(?m)^\s+SUMS_SHA256:\s*\$\{{\{{\s*needs\.{c_name}\.outputs\.sums_sha256\s*\}}\}}\s*$"
        ))
        .is_match(compare_text)
            && compare_text.contains("sha256sum dist/SHA256SUMS"),
        "the signer compares dist/SHA256SUMS with {c_name}'s digest, through its environment: {compare_text}"
    );
    let appends = step_index(signer, "appending to SHA256SUMS", |s| {
        logical(s)
            .iter()
            .any(|l| re(r">>\s*SHA256SUMS").is_match(l))
    });
    let signs = step_index(signer, "signing SHA256SUMS", |s| {
        s.contains("cosign sign-blob")
    });
    assert!(
        download < compare && compare <= appends && appends < signs,
        "download, then compare, then append, then sign: {download} {compare} {appends} {signs}"
    );
    // github-release attaches every file in dist/, so the signer refuses a file the signed
    // sums do not list: after the last append and before signing, the files present must be
    // exactly the files listed.
    let complete = step_index(
        signer,
        "checking dist/ and SHA256SUMS list the same files",
        |s| {
            let l = logical(s);
            l.iter().any(|l| {
                re(r"find\s+\.\s+-maxdepth\s+1\s+-type\s+f\s+!\s+-name\s+SHA256SUMS").is_match(l)
            }) && l
                .iter()
                .any(|l| re(r#"\[\s+"\$\{present\}"\s+=\s+"\$\{listed\}"\s+\]"#).is_match(l))
        },
    );
    assert!(
        appends <= complete && complete < signs,
        "the completeness check follows the last append and precedes signing: {appends} {complete} {signs}"
    );
    if complete == appends {
        let in_step = logical(&st[complete]);
        let append = line_index(&in_step, "appending", &re(r">>\s*SHA256SUMS"));
        let check = line_index(&in_step, "checking", &re(r#"\[\s+"\$\{present\}""#));
        assert!(
            append < check,
            "the completeness check follows the append: {:?}",
            st[complete]
        );
    }
    if compare == appends {
        let in_step = logical(compare_text);
        let first = line_index(&in_step, "comparing", &re(r#"\[\s+"\$\{actual\}""#));
        let append = line_index(&in_step, "appending", &re(r">>\s*SHA256SUMS"));
        assert!(
            first < append,
            "the digest is compared before the first append: {compare_text}"
        );
    }
}

// Proves DI-24.
#[test]
fn release_signing_waits_on_the_owner_recording_every_decision() {
    let all = release();
    let (_, signer) = only(&all, "the job that signs", |_, j| {
        j.contains("cosign sign-blob")
    });
    let st = steps(signer);
    let gate = step_index(signer, "gating on the owner's decisions", |s| {
        s.contains("vars.RELEASE_UNIT_SYSCALL_FILTER_SIGNED_OFF")
    });
    let gate_text = &st[gate];
    for variable in [
        "RELEASE_PUBLIC_REKOR_ACCEPTED",
        "RELEASE_ATTESTATIONS_AVAILABLE",
        "RELEASE_UNIT_SYSCALL_FILTER_SIGNED_OFF",
    ] {
        assert!(
            re(&format!(
                r"(?m)^\s+[A-Z_]+:\s*\$\{{\{{\s*vars\.{variable}\s*\}}\}}\s*$"
            ))
            .is_match(gate_text),
            "the gate reads {variable} through its environment: {gate_text}"
        );
    }
    // The syscall-filter variable must be exactly "true", and an unset one is an error.
    let name =
        re(r"(?m)^\s+([A-Z_]+):\s*\$\{\{\s*vars\.RELEASE_UNIT_SYSCALL_FILTER_SIGNED_OFF\s*\}\}")
            .captures(gate_text)
            .expect("the syscall-filter variable is bound")[1]
            .to_string();
    assert!(
        logical(gate_text).iter().any(|l| {
            l.contains(&format!("\"${{{name}}}\" = \"true\"")) && l.contains("exit 1")
        }),
        "the gate refuses unless {name} is `true`: {gate_text}"
    );
    // Nothing that publishes or reads a credential runs before the gate.
    let publishing =
        re(r"cosign|skopeo|docker login|attest-build-provenance|upload-artifact|GH_TOKEN");
    for (i, step) in st.iter().enumerate().take(gate) {
        assert!(
            !publishing.is_match(step),
            "step {i} publishes or holds a credential before the owner's decisions are checked: {step}"
        );
    }
}

// Proves DI-24, RC-23.
#[test]
fn release_packages_are_built_twice_compared_wrap_the_binary_and_carry_no_signature() {
    let all = release();
    let build = &all["build"];
    let (_, c) = comparing_job(&all);

    // Both passes build the packages from the staged binaries.
    let package_step = steps(build)
        .into_iter()
        .find(|s| s.contains("build-packages.sh"))
        .expect("the build job builds the packages");
    assert_eq!(
        step_if(&package_step),
        None,
        "both passes build the packages"
    );
    let pl = logical(&package_step).join("\n");
    for needle in [
        "dist/relay-daemon-${version}-${PLATFORM}",
        "--relay \"dist/relay-${version}-${PLATFORM}\"",
        "SHA256SUMS.packages.${ARCH}",
    ] {
        assert!(pl.contains(needle), "the package step names {needle}: {pl}");
    }

    // The comparing job compares them as it compares the binaries.
    let compare = steps(c)
        .into_iter()
        .find(|s| s.contains("cmp "))
        .expect("a step compares the passes");
    let cl = logical(&compare);
    assert!(
        cl.iter().any(|l| re(
            r#"\bdiff\s+"\$\{a\}/SHA256SUMS\.packages\.\$\{arch\}"\s+"\$\{b\}/SHA256SUMS\.packages\.\$\{arch\}""#
        )
        .is_match(l)),
        "the packages' sums are compared between passes: {cl:?}"
    );
    assert!(
        cl.iter()
            .any(|l| re(r#"\bcmp\s+"\$\{f\}"\s+"\$\{b\}/packages/"#).is_match(l)),
        "each package is compared byte for byte: {cl:?}"
    );
    assert!(
        compare.contains("fail=1"),
        "a difference sets the failure flag"
    );

    // They wrap the guarded binary, byte for byte.
    let guard_step = steps(c)
        .into_iter()
        .find(|s| s.contains("package-guard.sh") && s.contains("no-config"))
        .expect("the comparing job guards the packages");
    let gl = logical(&guard_step);
    for (what, pattern) in [
        (
            "the daemon binary",
            r#"\bsame\s+"\$\{f\}"\s+/usr/bin/relay-daemon\s+"\$\{bin\}""#,
        ),
        (
            "the Relay binary",
            r#"\bsame\s+"\$\{f\}"\s+/usr/bin/relay\s+"\$\{relay_bin\}""#,
        ),
        (
            "the daemon package's content",
            r#"\bcontent\s+"\$\{f\}"\s+relay-daemon\s"#,
        ),
        (
            "the Relay package's content",
            r#"\bcontent\s+"\$\{f\}"\s+relay\s"#,
        ),
    ] {
        assert!(
            gl.iter().any(|l| re(pattern).is_match(l)),
            "the guard checks {what}: {gl:?}"
        );
    }

    // No package is signed on its own: SHA256SUMS is the one thing signed.
    let signers = re(r"\b(rpmsign|dpkg-sig|debsigs|gpg)\b|\brpm\s+--(addsign|resign)\b");
    for file in ["release.yml", "install-matrix.yml"] {
        let text = code(&read(&repo().join(".github/workflows").join(file)));
        for line in logical(&text) {
            assert!(
                !signers.is_match(&line),
                "{file} signs a package, which carries no signature before v1.0.0 (DI-24): {line}"
            );
            if re(r"\bcosign\s+sign-blob\b").is_match(&line) {
                assert!(
                    line.split_whitespace()
                        .last()
                        .is_some_and(|t| t.ends_with("SHA256SUMS")),
                    "{file} signs something other than SHA256SUMS: {line}"
                );
            }
        }
    }
    for manifest in [
        "daemon/packaging/nfpm/relay-daemon.yaml",
        "relay/packaging/nfpm/relay.yaml",
    ] {
        let text = code(&read(&repo().join(manifest)));
        assert!(
            !re(r"(?m)^\s*(signature|key_file)\s*:").is_match(&text),
            "{manifest} configures a package signature"
        );
    }
}

// Proves DI-45.
#[test]
fn release_attaches_the_ansible_role_and_the_matrix_runs_it_with_hash_locked_ansible_core() {
    let all = release();
    let (_, c) = comparing_job(&all);

    // The release builds the role from the tagged commit and checks it against the checkout.
    let role_step = step_index(c, "staging the Ansible role", |s| {
        s.contains("dist/relay_daemon-${VERSION}.tar.gz") && s.contains("tar ")
    });
    let rl = logical(&steps(c)[role_step]);
    let tar = rl
        .iter()
        .find(|l| l.contains("tar ") && l.contains("--sort=name"))
        .unwrap_or_else(|| panic!("the role is tarred in sorted order: {rl:?}"));
    for needle in [
        "--sort=name",
        "--mtime=",
        "--owner=0",
        "--group=0",
        "--numeric-owner",
        "-C daemon/packaging/ansible",
        "relay_daemon",
    ] {
        assert!(
            tar.contains(needle),
            "the role's tar line names {needle}: {tar}"
        );
    }
    assert!(
        re(r"\bgzip\s+-\w*n").is_match(tar),
        "the role is compressed without a name or timestamp: {tar}"
    );
    assert!(
        rl.iter()
            .any(|l| l.contains("diff -r") && l.contains("daemon/packaging/ansible/relay_daemon")),
        "the tarball's extraction is compared with the checkout's role: {rl:?}"
    );
    let writes_sums = re(r#"(^|[^>])>\s*"?SHA256SUMS"?(\s|$)"#);
    let writer_step = step_index(c, "writing SHA256SUMS", |s| {
        logical(s)
            .iter()
            .any(|l| l.contains("sha256sum") && l.contains("relay-*") && writes_sums.is_match(l))
    });
    assert!(
        role_step < writer_step,
        "the role is in dist/ before SHA256SUMS is written"
    );

    // The matrix installs a hash-locked ansible-core before it runs the role, from the
    // release's own tarball.
    let mx = matrix();
    let job = &mx["ansible-role"];
    assert!(
        !job.contains("pipx install"),
        "ansible-core is not installed unlocked"
    );
    for line in logical(job) {
        if re(r"\bpip3?\s+install\b").is_match(&line) {
            assert!(
                line.contains("--require-hashes"),
                "an install without hash checking: {line}"
            );
        }
    }
    let st = steps(job);
    let install = st
        .iter()
        .position(|s| {
            s.contains("--require-hashes")
                && s.contains("-r daemon/packaging/ansible/test/requirements.txt")
        })
        .expect("a step installs the locked requirements with --require-hashes");
    let installer = logical(&st[install]).join("\n");
    assert!(
        installer.contains("--no-deps") && installer.contains("--only-binary"),
        "only what the lock names is installed, and no sdist is built: {installer}"
    );
    assert!(
        st[install].contains("ansible-playbook") && st[install].contains("--version"),
        "the install step checks the version the venv reports"
    );
    let on_path = st
        .iter()
        .position(|s| {
            s.contains("command -v")
                && s.contains("ansible-playbook")
                && s.contains("ansible-vault")
                && s.contains("$RUNNER_TEMP/ansible/bin")
        })
        .expect("a step checks that the locked tools are the ones on PATH");
    let run = st
        .iter()
        .position(|s| s.contains("install-matrix-ansible-role.sh"))
        .expect("a step runs the role");
    assert!(
        install < on_path && on_path < run,
        "the locked ansible-core is installed and resolved before the role runs"
    );
    assert!(
        st.iter().any(|s| s.contains("actions/download-artifact")
            && s.contains("name: ${{ inputs.release-dist }}")),
        "the job downloads the release's artifact"
    );
    assert_sums_digest_checked_first(&st[run], "the role step");
    let run_lines = logical(&st[run]);
    assert!(
        run_lines
            .iter()
            .any(|l| l.contains("package-guard.sh listed") && l.contains("SHA256SUMS")),
        "the tarball is checked against the SHA256SUMS that gets signed: {run_lines:?}"
    );
    assert!(
        st[run].contains("relay_daemon-") && run_lines.iter().any(|l| l.contains("tar -x")),
        "the release's role tarball is extracted"
    );
    assert!(
        run_lines.iter().any(|l| re(
            r#"install-matrix-ansible-role\.sh\s+"\$PWD/pkgs"\s+"\$RUNNER_TEMP/[^"]+""#
        )
        .is_match(l)),
        "the role runs from the extracted tarball, not the checkout: {run_lines:?}"
    );

    // The lock itself: every requirement is pinned and carries at least one hash.
    let lock = read(&repo().join("daemon/packaging/ansible/test/requirements.txt"));
    let pin = re(r"^[A-Za-z0-9._-]+==[A-Za-z0-9.!+_-]+$");
    let hash = re(r"^--hash=sha256:[0-9a-f]{64}$");
    let mut names = Vec::new();
    for line in logical(&lock) {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut tokens = line.split_whitespace();
        let first = tokens.next().expect("a requirement");
        assert!(
            pin.is_match(first),
            "a requirement that is not name==version: {line}"
        );
        let hashes: Vec<&str> = tokens.collect();
        assert!(
            !hashes.is_empty() && hashes.iter().all(|h| hash.is_match(h)),
            "{first} carries sha256 hashes and nothing else: {line}"
        );
        names.push(first.to_string());
    }
    assert!(
        names.iter().any(|n| n.starts_with("ansible-core==")),
        "the lock names ansible-core: {names:?}"
    );
}

// Proves DI-47.
#[test]
fn the_ansible_role_restarts_the_daemon_when_a_fragment_changes_and_the_matrix_proves_the_new_fingerprint(
) {
    let ansible = repo().join("daemon/packaging/ansible");

    // The role carries exactly one handler, and it restarts the unit.
    let handler = code(&read(&ansible.join("relay_daemon/handlers/main.yml")));
    assert_eq!(
        handler.matches("- name:").count(),
        1,
        "the role carries one handler: {handler}"
    );
    assert!(
        re(r"(?m)^- name: Restart relay-daemon\s*$").is_match(&handler),
        "the handler is named Restart relay-daemon: {handler}"
    );
    assert!(
        re(r"ansible\.builtin\.systemd(_service)?:").is_match(&handler)
            && re(r"(?m)^\s+name: relay-daemon\s*$").is_match(&handler)
            && re(r"(?m)^\s+state: restarted\s*$").is_match(&handler),
        "the handler restarts the relay-daemon unit: {handler}"
    );

    // The role still places no fragment (DI-45) and notifies nothing itself.
    let mut files = Vec::new();
    collect_files(&ansible.join("relay_daemon"), &mut files);
    for file in files
        .iter()
        .filter(|f| f.file_name().is_some_and(|n| n != "README.md"))
    {
        let text = code(&read(file));
        assert!(
            !text.contains("policy.d") && !text.contains("/etc/relay-daemon/policy"),
            "the role names no Policy path: {}",
            file.display()
        );
    }
    let tasks = code(&read(&ansible.join("relay_daemon/tasks/main.yml")));
    assert!(
        !tasks.contains("notify:"),
        "no task of the role notifies the handler"
    );

    // The fixture is an operator's play: the role, then a task of its own that writes a fragment
    // and notifies the role's handler by its role-qualified name.
    let fixture = code(&read(&ansible.join("test/policy-fragment.yml")));
    assert!(
        re(r"(?m)^\s+- relay_daemon\s*$").is_match(&fixture),
        "the fixture applies the role: {fixture}"
    );
    for needle in [
        "dest: /etc/relay-daemon/policy.d/",
        "notify: relay_daemon : Restart relay-daemon",
        "owner: root",
        "mode: \"0644\"",
    ] {
        assert!(
            fixture.contains(needle),
            "the fixture holds {needle}: {fixture}"
        );
    }
    assert!(
        !fixture.contains("backup:"),
        "a backup copy would be composed as a fragment"
    );

    // The matrix script runs that fixture on the enrolled Node and checks the restart and the
    // fingerprint the Relay reports.
    let script = code(&read(
        &repo().join("scripts/install-matrix-ansible-role.sh"),
    ));
    let lines: Vec<&str> = script.lines().collect();
    let run_b = lines
        .iter()
        .position(|l| l.starts_with("play run-b.log"))
        .expect("the script runs run B");
    let run_f = lines
        .iter()
        .position(|l| l.starts_with("play_with") && l.contains("test/policy-fragment.yml"))
        .expect("the script runs the fragment play");
    assert!(run_b < run_f, "the fragment play runs on the enrolled Node");
    assert!(
        lines
            .iter()
            .filter(|l| l.starts_with("check DI-47"))
            .count()
            >= 4,
        "the script checks DI-47 at least four ways"
    );
    for needle in [
        "RUNNING HANDLER [relay_daemon : Restart relay-daemon]",
        "MainPID",
        "policy check",
        "--policy-dir /etc/relay-daemon/policy.d",
        "/api/v1/nodes/",
        "policy_fingerprint",
    ] {
        assert!(script.contains(needle), "the script holds {needle}");
    }

    // The matrix runs that script.
    let mx = matrix();
    assert!(
        steps(&mx["ansible-role"])
            .iter()
            .any(|s| s.contains("install-matrix-ansible-role.sh")),
        "the install matrix runs the role script"
    );
}
