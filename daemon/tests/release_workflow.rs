//! Offline proof of what the release workflow promises about the relay-daemon: a static
//! binary for both architectures, built twice from different paths and refused unless the
//! two builds are byte-identical, listed in a keylessly signed `SHA256SUMS` (DI-1), and no
//! workflow that publishes the daemon as a container image (DI-2).
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
