//! Offline structural proof of the Relay container image and its deployment stack, in Rust.
//!
//! `scripts/compose-floor-check.sh` renders the committed stacks with `docker compose config`
//! and checks them with `jq`; the spec-proof scan reads only Go and Rust tests, so it does not
//! see that script. This file mirrors a subset of it, the production stack's pin rules (P1 no
//! `build:`, P2 the published image by digest) and the floor rules F1 to F6, on the text of
//! `deploy/production/docker-compose.yml`, and the Dockerfile rules D1 to D3 on
//! `docker/relay.Dockerfile`. The development stacks stay with the shell check, which also
//! holds the healthcheck and port rules.
//!
//! Rules G1 to G3 are the Dockerfile counterpart of what `scripts/release-image-guard.sh`
//! checks on the built archive (the entrypoint, the user and the one binary the image carries);
//! they are not a mirror of it, since the guard reads the archive and these read the file that
//! builds it.
//!
//! No YAML crate: a new dev-dependency would touch the dependency manifests. The compose model
//! is line-based and anchored on the file's indentation, so every rule is also run against
//! mutated copies of the shipped text, each of which must be refused for the rule it breaks.

use regex::Regex;
use std::path::{Path, PathBuf};

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

fn collapse(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// The text without its full-line `#` comments.
fn code(text: &str) -> String {
    text.lines()
        .filter(|l| !l.trim_start().starts_with('#'))
        .map(|l| format!("{l}\n"))
        .collect()
}

/// `text` with the one occurrence of `from` replaced by `to`; the result always differs.
fn mutate(text: &str, from: &str, to: &str) -> String {
    assert_eq!(
        text.matches(from).count(),
        1,
        "the mutation anchor `{from}` must occur exactly once"
    );
    let out = text.replacen(from, to, 1);
    assert_ne!(out, text, "the mutation changed nothing");
    out
}

/// `text` with the one match of `pattern` replaced by `to`; the result always differs.
fn mutate_re(text: &str, pattern: &str, to: &str) -> String {
    let regex = re(pattern);
    assert_eq!(
        regex.find_iter(text).count(),
        1,
        "the mutation pattern `{pattern}` must match exactly once"
    );
    let out = regex.replace(text, to).into_owned();
    assert_ne!(out, text, "the mutation changed nothing");
    out
}

// ---- the compose model ----

struct Mount {
    kind: String,
    source: String,
    target: String,
    read_only: bool,
}

/// Each service of the `services:` section, as (name, body), comments dropped.
fn services(text: &str) -> Vec<(String, String)> {
    let header = re(r"^  ([A-Za-z0-9_-]+):\s*$");
    let mut out: Vec<(String, String)> = Vec::new();
    let mut inside = false;
    for line in code(text).lines() {
        if line == "services:" {
            inside = true;
            continue;
        }
        if !inside {
            continue;
        }
        if !line.is_empty() && !line.starts_with(' ') {
            break;
        }
        if let Some(c) = header.captures(line) {
            out.push((c[1].to_string(), String::new()));
        } else if let Some((_, body)) = out.last_mut() {
            body.push_str(line);
            body.push('\n');
        }
    }
    out
}

/// A service's scalar key (four spaces deep), quotes dropped.
fn key(body: &str, name: &str) -> Option<String> {
    re(&format!(r#"(?m)^ {{4}}{name}:[ \t]*"?([^"\n]*?)"?[ \t]*$"#))
        .captures(body)
        .map(|c| c[1].to_string())
}

/// A service's list or map key as entries: each entry's first line, then its continuation
/// lines. A flow list gives one single-line entry per element; `[]` and `{}` give none.
fn items(body: &str, name: &str) -> Vec<Vec<String>> {
    let lines: Vec<&str> = body.lines().collect();
    let head = re(&format!(r"^ {{4}}{name}:[ \t]*(.*?)[ \t]*$"));
    let Some(start) = lines.iter().position(|l| head.is_match(l)) else {
        return Vec::new();
    };
    let rest = head.captures(lines[start]).expect("head matched")[1].to_string();
    if rest == "{}" {
        return Vec::new();
    }
    if let Some(flow) = rest.strip_prefix('[').and_then(|r| r.strip_suffix(']')) {
        return flow
            .split(',')
            .map(|s| s.trim().trim_matches('"').to_string())
            .filter(|s| !s.is_empty())
            .map(|s| vec![s])
            .collect();
    }
    if !rest.is_empty() {
        return vec![vec![rest]];
    }
    let mut out: Vec<Vec<String>> = Vec::new();
    for line in &lines[start + 1..] {
        if line.trim().is_empty() {
            continue;
        }
        let indent = line.len() - line.trim_start().len();
        if indent <= 4 {
            break;
        }
        let text = line.trim();
        if indent == 6 {
            let entry = text.strip_prefix("- ").unwrap_or(text);
            out.push(vec![entry.trim_matches('"').to_string()]);
        } else if let Some(last) = out.last_mut() {
            last.push(text.to_string());
        }
    }
    out
}

fn flat(entries: Vec<Vec<String>>) -> Vec<String> {
    entries.into_iter().map(|mut e| e.remove(0)).collect()
}

/// A service's `volumes:` entries, in the long form or the short `source:target[:options]` form.
fn mounts(body: &str) -> Vec<Mount> {
    let long = re(r"^(?:type|source|target|read_only|bind|volume|tmpfs):");
    items(body, "volumes")
        .into_iter()
        .map(|entry| {
            if long.is_match(&entry[0]) {
                let field = |k: &str| {
                    entry
                        .iter()
                        .find_map(|l| l.strip_prefix(&format!("{k}: ")))
                        .map(|v| v.trim().trim_matches('"').to_string())
                };
                return Mount {
                    kind: field("type").unwrap_or_default(),
                    source: field("source").unwrap_or_default(),
                    target: field("target").unwrap_or_default(),
                    read_only: field("read_only").as_deref() == Some("true"),
                };
            }
            let parts: Vec<&str> = entry[0].split(':').collect();
            Mount {
                kind: if parts[0].starts_with(['/', '.', '$', '~']) {
                    "bind"
                } else {
                    "volume"
                }
                .to_string(),
                source: parts[0].to_string(),
                target: parts.get(1).copied().unwrap_or_default().to_string(),
                read_only: parts
                    .get(2)
                    .is_some_and(|o| o.split(',').any(|x| x == "ro")),
            }
        })
        .collect()
}

const PUBLISHED_PIN: &str =
    r"^ghcr\.io/felag-engineering/relay(:[A-Za-z0-9_][A-Za-z0-9_.-]{0,127})?@sha256:[0-9a-f]{64}$";

/// A service that runs the Relay image: it names the published repository, or builds the
/// Relay's Dockerfile.
fn is_relay_image(body: &str) -> bool {
    key(body, "image")
        .is_some_and(|i| re(r"^ghcr\.io/felag-engineering/relay(?:[:@]|$)").is_match(&i))
        || items(body, "build")
            .iter()
            .flatten()
            .any(|l| l.ends_with("docker/relay.Dockerfile"))
}

/// The violations of the production stack's rules, as `<service>: <rule>: <what>`.
fn compose_violations(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut relay_services = 0;
    let volumes_section = code(text)
        .split_once("\nvolumes:\n")
        .map(|(_, rest)| rest.to_string())
        .unwrap_or_default();
    for (name, body) in services(text) {
        let mut fail = |rule: &str, what: &str| out.push(format!("{name}: {rule}: {what}"));
        if !items(&body, "build").is_empty() {
            fail(
                "P1",
                "the stack builds nothing; it runs only published images",
            );
        }
        if !is_relay_image(&body) {
            continue;
        }
        relay_services += 1;
        let image = key(&body, "image").unwrap_or_default();
        if !re(PUBLISHED_PIN).is_match(&image) {
            fail(
                "P2",
                "the Relay image is not the published repository pinned by digest",
            );
        }
        if !items(&body, "environment").is_empty() || !items(&body, "env_file").is_empty() {
            fail("F1", "the Relay has an environment or an env_file");
        }
        let mounts = mounts(&body);
        let config: Vec<&Mount> = mounts
            .iter()
            .filter(|m| m.target == "/etc/relay/relay.toml" || m.target == "/etc/relay")
            .collect();
        if config.is_empty() {
            fail("F2", "relay.toml is not mounted");
        } else if config.iter().any(|m| !m.read_only) {
            fail("F2", "the relay.toml mount is not read_only");
        }
        for m in mounts.iter().filter(|m| m.target != "/var/lib/relay") {
            if !m.read_only {
                fail("F3", &format!("the mount at {} is not read_only", m.target));
            }
        }
        if mounts.iter().any(|m| m.kind == "tmpfs") {
            fail("F3", "a tmpfs volume is not allowed");
        }
        let state: Vec<&Mount> = mounts
            .iter()
            .filter(|m| m.target == "/var/lib/relay")
            .collect();
        if state.len() != 1 {
            fail("F4", "expected exactly one mount at /var/lib/relay");
        } else {
            if state[0].kind != "volume" {
                fail("F4", "the state mount is not a named volume");
            }
            if state[0].read_only {
                fail("F4", "the state volume is not writable");
            }
            let declared = re(&format!(
                r"(?s)(?:^|\n)  {}:\n((?:    [^\n]*\n)*)",
                regex::escape(&state[0].source)
            ))
            .captures(&volumes_section)
            .map(|c| c[1].to_string());
            if !declared.is_some_and(|d| d.contains("    external: true")) {
                fail("F4", "the state volume is not declared external");
            }
        }
        if key(&body, "read_only").as_deref() != Some("true") {
            fail("F5", "the root filesystem is not read_only");
        }
        if flat(items(&body, "tmpfs"))
            .iter()
            .any(|t| t.split(':').next() != Some("/tmp"))
        {
            fail("F5", "tmpfs may only be /tmp");
        }
        if !flat(items(&body, "cap_drop")).iter().any(|c| c == "ALL") {
            fail("F5", "cap_drop does not contain ALL");
        }
        if !items(&body, "cap_add").is_empty() {
            fail("F5", "cap_add must be empty");
        }
        if key(&body, "privileged").as_deref() == Some("true") {
            fail("F5", "privileged");
        }
        let security = flat(items(&body, "security_opt"));
        if !security
            .iter()
            .any(|s| s == "no-new-privileges:true" || s == "no-new-privileges")
        {
            fail("F5", "security_opt lacks no-new-privileges");
        }
        if security
            .iter()
            .any(|s| re("unconfined|disable").is_match(s))
        {
            fail("F5", "security_opt lifts a confinement");
        }
        for k in ["pid", "ipc", "network_mode"] {
            if key(&body, k).as_deref() == Some("host") {
                fail("F5", &format!("{k}: host shares a host namespace"));
            }
        }
        if !items(&body, "devices").is_empty() || !items(&body, "volumes_from").is_empty() {
            fail("F5", "devices and volumes_from are not allowed");
        }
        if key(&body, "user").as_deref() != Some("10001:10001") {
            fail("F5", "user must be exactly 10001:10001");
        }
        if !items(&body, "secrets").is_empty() || !items(&body, "configs").is_empty() {
            fail("F6", "secrets and configs are not modelled");
        }
    }
    if relay_services == 0 {
        out.push("-: C0: no Relay service found, so nothing was checked".to_string());
    }
    out
}

fn refused_for(text: &str, rule: &str) -> bool {
    compose_violations(text)
        .iter()
        .any(|v| v.contains(&format!(": {rule}: ")))
}

fn production_compose() -> String {
    read(&repo().join("deploy/production/docker-compose.yml"))
}

/// The deployment stack runs only the published Relay image, pinned by its digest, with the
/// configuration as a read-only mount, one durable external volume, a read-only root
/// filesystem, every capability dropped, no environment and an unprivileged user. Each rule is
/// also run against copies of the shipped text with one property broken, and each must be
/// refused for that rule.
// Proves RC-7, RC-27.
#[test]
fn the_deployment_stack_pins_the_published_image_by_digest_read_only_with_no_capabilities() {
    let shipped = production_compose();
    let violations = compose_violations(&shipped);
    assert!(
        violations.is_empty(),
        "the shipped stack breaks: {violations:#?}"
    );

    // The parse is not vacuous: it saw the one Relay service and what is shipped.
    let stack = services(&shipped);
    assert_eq!(stack.len(), 1, "one service, the Relay");
    let body = &stack[0].1;
    assert!(is_relay_image(body));
    assert!(re(PUBLISHED_PIN).is_match(&key(body, "image").unwrap()));
    let mounts = mounts(body);
    let targets: Vec<(&str, bool)> = mounts
        .iter()
        .map(|m| (m.target.as_str(), m.read_only))
        .collect();
    assert_eq!(
        targets,
        [("/etc/relay/relay.toml", true), ("/var/lib/relay", false)]
    );
    assert_eq!(mounts[0].kind, "bind");
    assert_eq!(mounts[1].kind, "volume");
    let guide = collapse(&read(&repo().join("docs/operations/relay-install.md")));
    let compose_section = guide
        .split_once("## 7. Running it with Docker Compose")
        .expect("the install guide has the Docker Compose section")
        .1;
    for wording in [
        "`ca.dir = \"/var/lib/relay/ca\"`",
        "`store.path = \"/var/lib/relay/relay.db\"`",
    ] {
        assert!(
            compose_section.contains(wording),
            "the Docker Compose section keeps the CA and the store on the one state volume: {wording}"
        );
    }
    assert_eq!(flat(items(body, "cap_drop")), ["ALL"]);
    assert_eq!(flat(items(body, "tmpfs")), ["/tmp"]);
    assert_eq!(key(body, "user").as_deref(), Some("10001:10001"));
    assert!(items(body, "environment").is_empty());

    // Valid variations stay valid: the tag is optional.
    let untagged = mutate_re(
        &shipped,
        r"(?m)^(    image: ghcr\.io/felag-engineering/relay):[^@\n]+@",
        "${1}@",
    );
    assert!(compose_violations(&untagged).is_empty());

    // Each broken property is refused for its rule. The anchors are the service's own four
    // space keys, never the mount's eight space ones.
    let cases: Vec<(&str, String)> = vec![
        (
            "P2",
            mutate_re(
                &shipped,
                r"(?m)^(    image: \S+?)@sha256:[0-9a-f]{64}$",
                "$1",
            ),
        ),
        (
            "P2",
            mutate_re(&shipped, r"(?m)^(    image: \S+@sha256:)[0-9a-f]", "${1}A"),
        ),
        (
            "P2",
            mutate_re(
                &shipped,
                r"(?m)^(    image: \S+@sha256:[0-9a-f]{63})[0-9a-f]$",
                "$1",
            ),
        ),
        (
            "C0",
            mutate_re(
                &shipped,
                r"(?m)^(    image: ghcr\.io/felag-engineering/)relay",
                "${1}relay-dev",
            ),
        ),
        (
            "P1",
            mutate(
                &shipped,
                "    user: \"10001:10001\"\n",
                "    build: .\n    user: \"10001:10001\"\n",
            ),
        ),
        (
            "F5",
            mutate(
                &shipped,
                "\n    read_only: true\n",
                "\n    read_only: false\n",
            ),
        ),
        (
            "F2",
            mutate(
                &shipped,
                "        read_only: true\n        bind:",
                "        bind:",
            ),
        ),
        (
            "F5",
            mutate(&shipped, "cap_drop: [ALL]", "cap_drop: [NET_RAW]"),
        ),
        (
            "F5",
            mutate(
                &shipped,
                "    cap_drop: [ALL]\n",
                "    cap_drop: [ALL]\n    cap_add: [SYS_ADMIN]\n",
            ),
        ),
        (
            "F1",
            mutate(
                &shipped,
                "\n    read_only: true\n    tmpfs:",
                "\n    environment:\n      RELAY_HOSTNAME: x\n    read_only: true\n    tmpfs:",
            ),
        ),
        (
            "F4",
            mutate(
                &shipped,
                "      - relay-data:/var/lib/relay\n",
                "      - relay-data:/var/lib/relay\n      - other-data:/var/lib/relay\n",
            ),
        ),
        (
            "F3",
            mutate(
                &shipped,
                "      - relay-data:/var/lib/relay\n",
                "      - relay-data:/var/lib/relay\n      - /srv/x:/data\n",
            ),
        ),
        (
            "F4",
            mutate(&shipped, "    external: true\n", "    driver: local\n"),
        ),
        (
            "F5",
            mutate(&shipped, "    user: \"10001:10001\"", "    user: \"0:0\""),
        ),
        (
            "F5",
            mutate(
                &shipped,
                "      - \"no-new-privileges:true\"\n",
                "      - \"seccomp:unconfined\"\n",
            ),
        ),
        (
            "F6",
            mutate(
                &shipped,
                "    pids_limit: 512\n",
                "    pids_limit: 512\n    secrets:\n      - s\n",
            ),
        ),
    ];
    for (rule, text) in &cases {
        assert!(
            refused_for(text, rule),
            "a stack with the {rule} property broken is not refused for it: {:#?}",
            compose_violations(text)
        );
    }
}

// ---- the Dockerfile model ----

struct Stage {
    name: String,
    parent: String,
    lines: Vec<String>,
}

/// The stages of a Dockerfile: comments dropped, continuations joined, whitespace collapsed.
fn stages(text: &str) -> Vec<Stage> {
    let mut joined: Vec<String> = Vec::new();
    let mut pending = String::new();
    for raw in text.lines() {
        let line = raw.trim_end_matches('\r');
        if line.trim_start().starts_with('#') {
            continue;
        }
        if let Some(head) = line.trim_end().strip_suffix('\\') {
            pending.push_str(head);
            pending.push(' ');
            continue;
        }
        pending.push_str(line);
        let done = collapse(&std::mem::take(&mut pending));
        if !done.is_empty() {
            joined.push(done);
        }
    }
    let mut out: Vec<Stage> = Vec::new();
    for line in joined {
        let words: Vec<&str> = line.split(' ').collect();
        if words[0].eq_ignore_ascii_case("FROM") {
            let mut parent = "";
            let mut name = String::new();
            let mut rest = words[1..].iter().filter(|w| !w.starts_with("--"));
            while let Some(w) = rest.next() {
                if w.eq_ignore_ascii_case("AS") {
                    name = rest.next().map(|n| n.to_lowercase()).unwrap_or_default();
                    break;
                }
                parent = *w;
            }
            out.push(Stage {
                name,
                parent: parent.to_string(),
                lines: Vec::new(),
            });
        } else if let Some(stage) = out.last_mut() {
            stage.lines.push(line);
        }
    }
    out
}

fn stage_chain<'a>(all: &'a [Stage], name: &str) -> Vec<&'a Stage> {
    let mut chain = Vec::new();
    let mut next = all.iter().find(|s| s.name == name);
    while let Some(stage) = next {
        chain.push(stage);
        next = all.iter().find(|s| s.name == stage.parent);
    }
    chain
}

/// The last instruction `word` of the stage or its nearest ancestor that has one.
fn effective(all: &[Stage], name: &str, word: &str) -> Option<String> {
    stage_chain(all, name).iter().find_map(|s| {
        s.lines
            .iter()
            .rev()
            .find_map(|l| l.strip_prefix(&format!("{word} ")).map(String::from))
    })
}

fn dockerfile_violations(text: &str) -> Vec<String> {
    let all = stages(text);
    let mut out = Vec::new();
    if all.is_empty() {
        return vec!["C0: the stage parser found no stage".to_string()];
    }
    for stage in &all {
        for line in &stage.lines {
            if !(line.starts_with("ENV ") || line.starts_with("ARG ")) {
                continue;
            }
            for token in line.split(' ').skip(1) {
                if token
                    .split('=')
                    .next()
                    .is_some_and(|k| k.starts_with("RELAY_"))
                {
                    out.push(format!("D1: stage {} sets {token}", stage.name));
                }
            }
        }
    }
    for want in ["runtime", "release", "dev-fleet"] {
        if !all.iter().any(|s| s.name == want) {
            out.push(format!("D2: {want} is not a stage"));
            continue;
        }
        let user = effective(&all, want, "USER").unwrap_or_else(|| "(root)".to_string());
        if user != "10001:10001" {
            out.push(format!("D2: stage {want} ends as {user}, not 10001:10001"));
        }
    }
    if all.last().is_some_and(|s| s.name != "runtime") {
        out.push("D3: the last stage is not runtime".to_string());
    }
    if effective(&all, "release", "ENTRYPOINT").as_deref() != Some("[\"/usr/local/bin/relay\"]") {
        out.push("G1: the release entrypoint is not the Relay binary".to_string());
    }
    let ancestry: Vec<String> = stage_chain(&all, "release")
        .iter()
        .flat_map(|s| s.lines.iter())
        .filter(|l| l.starts_with("RUN "))
        .cloned()
        .collect();
    let ancestry = ancestry.join(" ; ");
    for (what, pattern) in [
        ("a group of id 10001", r"\baddgroup\b[^;]*-g 10001\b"),
        ("a user of id 10001", r"\badduser\b[^;]*-u 10001\b"),
        (
            "the state directory owned by the user, 0700",
            r"\binstall -d -o relay -g relay -m 0700 /var/lib/relay(?:\s|$)",
        ),
    ] {
        if !re(pattern).is_match(&ancestry) {
            out.push(format!("G2: the release ancestry does not create {what}"));
        }
    }
    if let Some(release) = all.iter().find(|s| s.name == "release") {
        if release.lines.iter().any(|l| l.starts_with("RUN ")) {
            out.push("G3: the release stage runs a command".to_string());
        }
        let copies: Vec<&String> = release
            .lines
            .iter()
            .filter(|l| l.starts_with("COPY "))
            .collect();
        let one_binary = re(r"^COPY --from=release-binary --chmod=0755 \S+ /usr/local/bin/relay$");
        if copies.len() != 1 || !one_binary.is_match(copies[0]) {
            out.push("G3: the release stage does not copy exactly the released binary".to_string());
        }
    }
    out
}

fn docker_refused_for(text: &str, rule: &str) -> bool {
    dockerfile_violations(text)
        .iter()
        .any(|v| v.starts_with(&format!("{rule}: ")))
}

/// The image's Dockerfile names no `RELAY_*` setting in any stage, runs every stage a Relay can
/// run from as the unprivileged user, ends on the runtime stage, and builds the published
/// stage from the unprivileged one with the released binary copied in and nothing run: the
/// configuration arrives as a mount and nothing about the floor is baked in. Each rule is run
/// against copies with one property broken.
// Proves RC-7, RC-27.
#[test]
fn the_relay_image_carries_no_configuration_and_runs_unprivileged() {
    let shipped = read(&repo().join("docker/relay.Dockerfile"));
    let violations = dockerfile_violations(&shipped);
    assert!(
        violations.is_empty(),
        "the Dockerfile breaks: {violations:#?}"
    );
    let all = stages(&shipped);
    assert!(all.len() >= 7, "the stage parser read {} stages", all.len());
    assert_eq!(all.last().unwrap().name, "runtime");
    assert_eq!(
        effective(&all, "release", "USER").as_deref(),
        Some("10001:10001")
    );
    assert_eq!(
        effective(&all, "dev-fleet", "USER").as_deref(),
        Some("10001:10001"),
        "the last USER of the stage wins over the root one before it"
    );

    // The parser on lookalikes.
    let tiny = "FROM a AS one\nUSER 5\nFROM one AS two\nRUN x \\\n  && y\nFROM scratch\n";
    let parsed = stages(tiny);
    assert_eq!(
        parsed.iter().map(|s| s.name.as_str()).collect::<Vec<_>>(),
        ["one", "two", ""]
    );
    assert_eq!(parsed[1].parent, "one");
    assert_eq!(parsed[1].lines, ["RUN x && y"]);
    assert_eq!(effective(&parsed, "two", "USER").as_deref(), Some("5"));
    assert_eq!(effective(&parsed, "one", "ENTRYPOINT"), None);

    let after_release = "FROM unprivileged AS release\n";
    let cases: Vec<(&str, String)> = vec![
        (
            "D1",
            mutate(
                &shipped,
                after_release,
                &format!("{after_release}ENV RELAY_HOSTNAME=x\n"),
            ),
        ),
        (
            "D1",
            mutate(
                &shipped,
                after_release,
                &format!("{after_release}ARG RELAY_CA_DIR\n"),
            ),
        ),
        (
            "D2",
            mutate(
                &shipped,
                after_release,
                &format!("{after_release}USER root\n"),
            ),
        ),
        ("D3", format!("{shipped}FROM scratch AS extra\n")),
        (
            "G1",
            mutate(
                &shipped,
                "ENTRYPOINT [\"/usr/local/bin/relay\"]",
                "ENTRYPOINT [\"/bin/sh\"]",
            ),
        ),
        (
            "G2",
            mutate(&shipped, "-m 0700 /var/lib/relay", "-m 0755 /var/lib/relay"),
        ),
        (
            "G3",
            mutate(
                &shipped,
                "COPY --from=release-binary",
                "RUN true\nCOPY --from=release-binary",
            ),
        ),
        ("G3", mutate(&shipped, "--chmod=0755 ", "")),
    ];
    for (rule, text) in &cases {
        assert!(
            docker_refused_for(text, rule),
            "a Dockerfile with the {rule} property broken is not refused for it: {:#?}",
            dockerfile_violations(text)
        );
    }
}

fn says_not_production_before_review(text: &str) -> bool {
    re(r"(?i)\bnot called production until\b[^.]*\bhardening review\b").is_match(text)
}

fn claims_production(text: &str) -> bool {
    re(r"(?i)\bproduction[- ]ready\b|\bis (?:now )?(?:a )?production\b").is_match(text)
}

/// The deployment stack's own header and the install guide each say it is not called
/// production until a human hardening review has closed, and neither calls it production or
/// production ready.
// Proves RC-27.
#[test]
fn the_deployment_stack_is_not_called_production_before_its_hardening_review() {
    for text in [
        "It is NOT called production until a human hardening review of this deployment has closed",
        "is not called production until its hardening review has closed",
    ] {
        assert!(
            says_not_production_before_review(text),
            "must match: {text}"
        );
    }
    for text in [
        "It is called production once a hardening review closes",
        "not called production until it ships. The hardening review follows",
        "a hardening review closed; not called production",
    ] {
        assert!(
            !says_not_production_before_review(text),
            "must not match: {text}"
        );
    }
    for text in [
        "This stack is production ready",
        "this is a production stack",
        "It is now production",
        "Production-ready since v1",
    ] {
        assert!(claims_production(text), "must match: {text}");
    }
    for text in [
        "deploy/production/docker-compose.yml",
        "is a minimal production file",
        "not called production until its hardening review has closed",
    ] {
        assert!(!claims_production(text), "must not match: {text}");
    }

    let compose = production_compose();
    let header: String = compose
        .lines()
        .take_while(|l| l.starts_with('#') || l.trim().is_empty())
        .map(|l| l.trim_start_matches('#'))
        .collect::<Vec<_>>()
        .join(" ");
    let guide = read(&repo().join("docs/operations/relay-install.md"));
    for (what, text) in [
        ("the compose file's header", collapse(&header)),
        ("the install guide", collapse(&guide)),
    ] {
        assert!(
            says_not_production_before_review(&text),
            "{what} says the stack is not called production until its hardening review"
        );
        assert!(
            !claims_production(&text),
            "{what} calls the stack production"
        );
    }
}
