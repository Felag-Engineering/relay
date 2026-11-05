//! Offline structural proof of what the Relay package's maintainer scripts, manifest and file
//! lists deliver: the account, the unit, the configuration guide, the configuration written
//! once, and the purge that moves the CA and the store aside together. It reads
//! `relay/packaging/` from the repository root, next to `daemon/`.
//!
//! The executable counterparts are `scripts/relay-package-scripts-test.sh` and the install
//! matrix, both shell, which the spec-proof scan does not see: it reads only Go and Rust
//! tests. Every matcher below is checked against lookalike lines that must and must not match.
//! The settings the generated file carries are proven by the Relay's own Go tests; this file
//! proves the file is written once and is never package-owned.

use std::path::{Path, PathBuf};

fn relay_packaging() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("daemon/ has a parent")
        .join("relay/packaging")
}

// ---- structural readers for maintainer scripts, manifests and baselines ----

fn re(pattern: &str) -> regex::Regex {
    regex::Regex::new(pattern).unwrap_or_else(|e| panic!("regex {pattern}: {e}"))
}

fn read_text(path: &Path) -> String {
    std::fs::read_to_string(path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
}

/// The trimmed, non-empty lines that are not full-line comments.
fn commands(text: &str) -> Vec<String> {
    text.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(String::from)
        .collect()
}

/// The command lines of the four maintainer scripts under `dir`, by script name.
fn script_commands(dir: &Path) -> Vec<(&'static str, Vec<String>)> {
    ["preinst", "postinst", "prerm", "postrm"]
        .into_iter()
        .map(|name| (name, commands(&read_text(&dir.join(format!("{name}.sh"))))))
        .collect()
}

/// Whether `line` starts or restarts a unit, by systemctl, `service`, or the Debian helpers.
fn starts_a_unit(line: &str) -> bool {
    re(r"\bsystemctl\b(?:\s+-{1,2}[A-Za-z-]+(?:=\S+)?)*\s+(?:start|restart|try-restart|reload-or-restart|try-reload-or-restart|isolate)\b")
        .is_match(line)
        || (re(r"\bsystemctl\b").is_match(line)
            && re(r"\benable\b").is_match(line)
            && line.contains("--now"))
        || re(r"\bservice\s+\S+\s+(?:start|restart|try-restart|force-reload)\b").is_match(line)
        || re(r"\b(?:invoke-rc\.d|deb-systemd-invoke)\b").is_match(line)
}

/// Whether `line` changes whether a unit is enabled, by any route that reaches the same state.
fn enables_a_unit(line: &str) -> bool {
    re(r"\bsystemctl\b.*\b(?:enable|reenable|preset|preset-all|link|add-wants)\b").is_match(line)
        || re(r"\b(?:deb-systemd-helper|update-rc\.d|chkconfig)\b").is_match(line)
        || re(r"\bln\b[^|;&]*\.wants/").is_match(line)
}

/// Whether `line` writes to a path `target` names: a redirect into it on any line, or one of
/// the writing commands naming it on a line that is not an echo or printf.
fn writes_to(line: &str, target: &regex::Regex) -> bool {
    let t = target.as_str();
    if re(&format!(r#">>?\s*"?[^\s;|&]*?(?:{t})"#)).is_match(line) {
        return true;
    }
    if matches!(line.split_whitespace().next(), Some("echo" | "printf")) {
        return false;
    }
    re(&format!(
        r"(?:\b(?:cp|mv|install|tee|ln|place|touch|dd|rsync|truncate)\b|\bsed\s+-i\b)[^|;&]*(?:{t})"
    ))
    .is_match(line)
}

/// The index of the one line equal to `exact`.
fn at(lines: &[String], exact: &str) -> usize {
    let hits: Vec<usize> = lines
        .iter()
        .enumerate()
        .filter(|(_, l)| l.as_str() == exact)
        .map(|(i, _)| i)
        .collect();
    assert_eq!(
        hits.len(),
        1,
        "expected exactly one line `{exact}`: {lines:#?}"
    );
    hits[0]
}

/// The command lines of the shell function whose header line is `header`, up to its closing
/// brace, a line that is exactly `}`.
fn body(text: &str, header: &str) -> Vec<String> {
    let lines = commands(text);
    let start = at(&lines, header);
    let mut out = Vec::new();
    for line in &lines[start + 1..] {
        if line == "}" {
            return out;
        }
        out.push(line.clone());
    }
    panic!("`{header}` has no closing brace");
}

const FIRST_INSTALL_GATE: [&str; 6] = [
    "if [ \"$first_install\" != yes ]; then",
    "if systemd_running; then",
    "systemctl daemon-reload || true",
    "fi",
    "exit 0",
    "fi",
];

/// The index of the gate's closing `fi`: past it, a postinst runs on a first install only.
fn first_install_gate_end(lines: &[String]) -> usize {
    let start = at(lines, FIRST_INSTALL_GATE[0]);
    let block: Vec<&str> = lines[start..start + FIRST_INSTALL_GATE.len()]
        .iter()
        .map(String::as_str)
        .collect();
    assert_eq!(
        block, FIRST_INSTALL_GATE,
        "an upgrade or reinstall runs daemon-reload and nothing else"
    );
    start + FIRST_INSTALL_GATE.len() - 1
}

/// The `case "${1:-}" in` arms that follow it, up to `esac`.
fn case_arms(lines: &[String]) -> Vec<String> {
    let start = at(lines, "case \"${1:-}\" in");
    let end = lines[start..]
        .iter()
        .position(|l| l == "esac")
        .expect("the case statement ends");
    lines[start + 1..start + end].to_vec()
}

/// What sets `first_install` in a postinst: only a `.deb` configure with no old version and an
/// `.rpm` `$1` of 1 are a first install; any other call exits.
fn assert_postinst_first_install_arms(postinst: &[String]) {
    assert_eq!(
        case_arms(postinst),
        [
            "configure) [ -z \"${2:-}\" ] && first_install=yes ;;",
            "1) first_install=yes ;;",
            "[0-9]*) ;;",
            "*) exit 0 ;;"
        ],
        "only a .deb configure with no old version and an .rpm $1 of 1 is a first install"
    );
    let case_at = at(postinst, "case \"${1:-}\" in");
    assert!(
        case_at > 0 && postinst[case_at - 1] == "first_install=no",
        "first_install starts as no, on the line before the case"
    );
    assert_eq!(
        postinst
            .iter()
            .filter(|l| l.contains("first_install=yes"))
            .count(),
        2,
        "first_install=yes is set in the two pinned arms and nowhere else"
    );
}

/// The paths of a baseline's regular files, for the `dpkg-deb` and `rpm` listing formats.
fn regular_entries(baseline: &str) -> Vec<String> {
    baseline
        .lines()
        .filter(|l| l.starts_with('-'))
        .filter_map(|l| l.split_whitespace().last())
        .map(|p| p.trim_start_matches('.').to_string())
        .collect()
}

/// A prerm that stops and disables the unit on removal and does nothing on any other call.
fn assert_prerm_stops_and_disables_on_removal_only(prerm: &[String]) {
    let systemctl: Vec<&str> = prerm
        .iter()
        .filter(|l| l.starts_with("systemctl"))
        .map(String::as_str)
        .collect();
    assert_eq!(
        systemctl,
        [
            "systemctl stop \"$UNIT\" || true",
            "systemctl --no-reload disable \"$UNIT\" || true"
        ],
        "prerm stops and disables the unit and does nothing else with it"
    );
    assert_eq!(
        case_arms(prerm),
        ["remove | 0) ;;", "*) exit 0 ;;"],
        "prerm acts on removal only; an upgrade changes nothing"
    );
}

/// Lookalike lines the two unit matchers must tell apart.
fn assert_unit_matchers_tell_the_verbs_apart() {
    for line in [
        "systemctl start \"$UNIT\"",
        "systemctl --no-block restart relay-daemon.service",
        "systemctl try-reload-or-restart relay.service",
        "systemctl enable --now \"$UNIT\"",
        "service relay-daemon start",
        "service relay restart || true",
        "invoke-rc.d relay-daemon start",
        "deb-systemd-invoke start relay.service",
    ] {
        assert!(starts_a_unit(line), "starts_a_unit must match: {line}");
    }
    for line in [
        "systemctl daemon-reload || true",
        "systemctl preset \"$UNIT\" || true",
        "systemctl stop \"$UNIT\" || true",
        "systemctl --no-reload disable \"$UNIT\" || true",
        "systemctl enable \"$UNIT\"",
        "systemd_running() { [ -d /run/systemd/system ]; }",
    ] {
        assert!(!starts_a_unit(line), "starts_a_unit must not match: {line}");
    }
    for line in [
        "systemctl enable \"$UNIT\"",
        "systemctl reenable relay.service",
        "systemctl preset-all",
        "systemctl link /opt/relay.service",
        "systemctl --now enable relay.service",
        "deb-systemd-helper enable relay.service",
        "chkconfig relay on",
        "update-rc.d relay defaults",
        "ln -s /usr/lib/systemd/system/relay.service /etc/systemd/system/multi-user.target.wants/relay.service",
    ] {
        assert!(enables_a_unit(line), "enables_a_unit must match: {line}");
    }
    for line in [
        "systemctl --no-reload disable \"$UNIT\" || true",
        "systemctl daemon-reload || true",
        "systemctl stop \"$UNIT\" || true",
        "if ln \"$tmp\" \"$dst\" 2>/dev/null; then",
        "echo \"enable the unit by hand\" >&2",
    ] {
        assert!(
            !enables_a_unit(line),
            "enables_a_unit must not match: {line}"
        );
    }
}

fn lines_of<'a>(scripts: &'a [(&'static str, Vec<String>)], name: &str) -> &'a [String] {
    &scripts.iter().find(|(n, _)| *n == name).unwrap().1
}

/// The manifest's `src`/`dst` lines, `- ` markers dropped.
fn manifest_lines(packaging: &Path) -> Vec<String> {
    commands(&read_text(&packaging.join("nfpm/relay.yaml")))
        .iter()
        .map(|l| l.trim_start_matches("- ").to_string())
        .collect()
}

/// The `dst:` line that follows each `src:` line equal to `src`.
fn dsts_of(manifest: &[String], src: &str) -> Vec<String> {
    manifest
        .iter()
        .enumerate()
        .filter(|(_, l)| l.as_str() == src)
        .map(|(i, _)| manifest[i + 1].clone())
        .collect()
}

/// Whether `line` runs a first-boot command of the Relay.
fn runs_first_boot_command(line: &str) -> bool {
    line.contains("/usr/bin/relay")
        || re(r"(?:^|[\s;&|(])(?:/usr/bin/)?relay\s+(?:init|bootstrap-token|console-password)\b")
            .is_match(line)
}

/// Whether `text` carries something that looks like a secret: a join string or a PEM block.
fn carries_a_secret(text: &str) -> bool {
    re(r"glp_[A-Za-z0-9_-]*|-----BEGIN").is_match(text)
}

/// The Relay package installs the account definition, the binary, the hardened unit and the
/// configuration guide (also as documentation); `postinst` makes the account before it creates
/// anything, prints a guide that names the first-boot command and carries no secret, and its
/// one enabling act is `systemctl preset`, past the first-install gate and only where systemd
/// runs. No script starts the Relay or runs the first-boot command.
// Proves RC-24.
#[test]
fn the_relay_package_installs_its_account_unit_and_guide_and_only_enables_it() {
    let packaging = relay_packaging();
    let scripts = script_commands(&packaging.join("scripts"));
    let postinst = lines_of(&scripts, "postinst");

    // (a) The payload, in both packages and in the manifest.
    for baseline in ["relay.deb.files", "relay.rpm.files"] {
        let entries = regular_entries(&read_text(&packaging.join("expected").join(baseline)));
        for want in [
            "/usr/bin/relay",
            "/usr/lib/systemd/system/relay.service",
            "/usr/lib/sysusers.d/relay.conf",
            "/usr/share/relay/configuration-guide.txt",
            "/usr/share/doc/relay/configuration-guide.txt",
        ] {
            assert!(
                entries.iter().any(|e| e == want),
                "{baseline} lists {want} as a regular file: {entries:?}"
            );
        }
    }
    let manifest = manifest_lines(&packaging);
    let guide_src = "src: \"@SRC@/relay/packaging/configuration-guide.txt\"";
    assert_eq!(
        dsts_of(&manifest, guide_src),
        [
            "dst: /usr/share/relay/configuration-guide.txt",
            "dst: /usr/share/doc/relay/configuration-guide.txt"
        ],
        "the guide is installed twice, as the kept copy and as documentation"
    );
    assert_eq!(
        dsts_of(&manifest, "src: \"@SRC@/relay/packaging/relay.service\""),
        ["dst: /usr/lib/systemd/system/relay.service"]
    );
    assert_eq!(
        dsts_of(
            &manifest,
            "src: \"@SRC@/relay/packaging/relay.sysusers.conf\""
        ),
        ["dst: /usr/lib/sysusers.d/relay.conf"]
    );
    assert_eq!(
        dsts_of(&manifest, "src: \"@RELAY_BIN@\""),
        ["dst: /usr/bin/relay"]
    );

    // (b) The account definition is one system user, with its group.
    assert_eq!(
        commands(&read_text(&packaging.join("relay.sysusers.conf"))),
        ["u relay - \"Relay fleet-administration control plane\" - -"]
    );

    // (c) postinst makes the account first, and fails before anything else if it cannot.
    at(postinst, "SYSUSERS=/usr/lib/sysusers.d/relay.conf");
    let account = at(postinst, "if ! ensure_account; then exit 1; fi");
    for later in [
        "mkdir -m 0755 \"$ETC\"",
        "if ! place_config; then",
        "if ! place_state; then",
    ] {
        assert!(
            at(postinst, later) > account,
            "`{later}` runs only after the account exists"
        );
    }
    let postinst_text = read_text(&packaging.join("scripts/postinst.sh"));
    let ensure = body(&postinst_text, "ensure_account() {");
    at(&ensure, "systemd-sysusers \"$SYSUSERS\" || true");
    assert!(ensure.iter().any(|l| l.starts_with("useradd --system ")));
    at(
        &ensure,
        "if getent passwd relay >/dev/null 2>&1 && getent group relay >/dev/null 2>&1; then",
    );
    let state = body(&postinst_text, "place_state() {");
    at(&state, "mkdir -m 0700 \"$STATE\" || return 1");
    assert!(state
        .iter()
        .any(|l| l == "chown -h relay:relay \"$STATE\" || return 1"));

    // (d) The guide is printed on a first install, names the first-boot command, warns about
    // imaging, and carries no secret.
    at(postinst, "SHARE=/usr/share/relay");
    assert_postinst_first_install_arms(postinst);
    let gate_end = first_install_gate_end(postinst);
    let prints: Vec<usize> = postinst
        .iter()
        .enumerate()
        .filter(|(_, l)| l.starts_with("cat \"$SHARE/configuration-guide.txt\""))
        .map(|(i, _)| i)
        .collect();
    assert_eq!(prints.len(), 1, "postinst prints the guide once");
    assert!(prints[0] > gate_end);
    let guide = read_text(&packaging.join("configuration-guide.txt"));
    let guide = guide.split_whitespace().collect::<Vec<_>>().join(" ");
    assert!(guide.contains("relay init"), "the guide names `relay init`");
    let imaging = re(
        r"(?i)never capture an image[^.]*after the relay has first started[^.]*:[^.]*ca private key",
    );
    assert!(
        imaging.is_match(&guide),
        "the guide warns never to image the host after the first start: {guide}"
    );
    assert!(!carries_a_secret(&guide), "the guide carries no secret");
    for text in [
        "Never capture an image or snapshot of this host after the Relay has first started: the CA private key",
        "never capture an image of it, because after the relay has first started: the ca private key travels",
    ] {
        assert!(imaging.is_match(text), "must match: {text}");
    }
    for text in [
        "You may capture an image after the Relay has first started: the CA private key travels",
        "Never capture an image. Wait until after the Relay has first started: the CA private key",
        "Never capture an image after the Relay has first started, the CA private key travels",
    ] {
        assert!(!imaging.is_match(text), "must not match: {text}");
    }
    for text in [
        "glp_join_abc",
        "-----BEGIN PRIVATE KEY-----",
        "token glp_ x",
    ] {
        assert!(carries_a_secret(text), "must match: {text}");
    }
    assert!(!carries_a_secret("sudo -u relay relay init --admin <name>"));

    // (e) The one enabling line is the preset, past the gate, where systemd runs.
    at(postinst, "UNIT=relay.service");
    at(
        postinst,
        "systemd_running() { [ -d /run/systemd/system ]; }",
    );
    let mut enabling = Vec::new();
    for (name, lines) in &scripts {
        for line in lines {
            if enables_a_unit(line) {
                enabling.push((*name, line.as_str()));
            }
            // (f) Nothing starts the Relay.
            assert!(
                !starts_a_unit(line),
                "{name}.sh starts the Relay, which the package never does: {line}"
            );
        }
    }
    assert_eq!(
        enabling,
        [("postinst", "systemctl preset \"$UNIT\" || true")],
        "the distribution's presets are the only thing that enables the unit"
    );
    let preset = at(postinst, "systemctl preset \"$UNIT\" || true");
    assert!(preset > gate_end);
    assert_eq!(
        postinst[preset - 2..preset],
        [
            "if systemd_running; then",
            "systemctl daemon-reload || true"
        ],
        "the preset runs only where systemd runs"
    );
    assert_prerm_stops_and_disables_on_removal_only(lines_of(&scripts, "prerm"));

    // (g) Nothing runs the first-boot command, an echo included.
    for (name, lines) in &scripts {
        for line in lines {
            assert!(
                !runs_first_boot_command(line),
                "{name}.sh runs the first-boot command, which only a person at a terminal does: {line}"
            );
        }
    }
    for line in [
        "sudo -u relay relay init --admin x",
        "/usr/bin/relay init",
        "relay bootstrap-token --x",
        "echo done; relay console-password",
    ] {
        assert!(runs_first_boot_command(line), "must match: {line}");
    }
    for line in [
        "useradd --system --user-group --no-create-home --home-dir / --shell /usr/sbin/nologin \\",
        "--comment \"Relay fleet-administration control plane\" relay || true",
        "getent passwd relay >/dev/null 2>&1",
        "chown -h relay:relay \"$STATE\" || return 1",
        "echo \"relay: then install the package again\" >&2",
    ] {
        assert!(!runs_first_boot_command(line), "must not match: {line}");
    }

    // (h) The unit matchers tell the verbs apart.
    assert_unit_matchers_tell_the_verbs_apart();
}

/// The lines of `scripts` that write to `target`, as `(script, line)`.
fn writers<'a>(
    scripts: &'a [(&'static str, Vec<String>)],
    target: &str,
) -> Vec<(&'static str, &'a str)> {
    let target = re(target);
    scripts
        .iter()
        .flat_map(|(name, lines)| {
            lines
                .iter()
                .filter(|l| writes_to(l, &target))
                .map(|l| (*name, l.as_str()))
                .collect::<Vec<_>>()
        })
        .collect()
}

const CONFIG_TARGET: &str = r#"\$\{?CONFIG\b\}?|relay\.toml(?:["'\s;)]|$)"#;

/// The configuration file is written once, by the one `ln` line in `place_config`, called once
/// past the first-install gate, and that function returns before writing if a file exists. No
/// other line of any script writes the path, and neither package list owns anything under
/// `/etc`, so no upgrade has a package-owned file to rewrite. The file is made from the
/// shipped template with the host's fully qualified name.
// Proves RC-25.
#[test]
fn the_relay_package_writes_its_configuration_once_and_never_owns_it() {
    let packaging = relay_packaging();
    let scripts = script_commands(&packaging.join("scripts"));
    let postinst = lines_of(&scripts, "postinst");
    let postinst_text = read_text(&packaging.join("scripts/postinst.sh"));

    // (a) One call, past the gate; the function keeps a file that exists.
    at(postinst, "CONFIG=\"$ETC/relay.toml\"");
    assert_postinst_first_install_arms(postinst);
    let call = at(postinst, "if ! place_config; then");
    assert!(call > first_install_gate_end(postinst));
    let place = body(&postinst_text, "place_config() {");
    assert_eq!(
        place[..3],
        [
            "if exists \"$CONFIG\"; then",
            "if marked \"created config\"; then CONFIG_STATUS=kept-own; else CONFIG_STATUS=kept; fi",
            "return 0"
        ],
        "an existing file is kept and nothing is written"
    );

    // (b) Only the link writes the path, and it is not forced.
    assert_eq!(
        writers(&scripts, CONFIG_TARGET),
        [("postinst", "if ! ln \"$tmp\" \"$CONFIG\"; then")],
        "nothing else writes the configuration file"
    );
    let config = re(CONFIG_TARGET);
    for line in [
        "cp x \"$CONFIG\"",
        "cat t > /etc/relay/relay.toml",
        "sed -i s/a/b/ /etc/relay/relay.toml",
        "if ! ln \"$tmp\" \"$CONFIG\"; then",
    ] {
        assert!(writes_to(line, &config), "must match: {line}");
    }
    for line in [
        "sed \"s|^hostname|$line|\" \"$SHARE/relay.toml.in\" > \"$tmp\" \\",
        "CONFIG_STATUS=generated",
        "echo \"relay: directory, mode 0755, then write $CONFIG (root:relay 0640) from\" >&2",
        "exists \"$ETC/relay.toml\" && echo \"existed config\"",
    ] {
        assert!(!writes_to(line, &config), "must not match: {line}");
    }

    // (c) The certificate hostname is the host's fully qualified name, from the template.
    assert!(body(&postinst_text, "host_fqdn() {")
        .iter()
        .any(|l| l == "name=$(timeout \"$HOSTNAME_TIMEOUT\" hostname -f 2>/dev/null) || return 1"));
    at(postinst, "HOSTNAME_TIMEOUT=10");
    at(&place, "fqdn=$(host_fqdn) || fqdn=\"\"");
    assert!(
        place
            .iter()
            .any(|l| l
                .starts_with(r#"sed "s|^hostname = \"@FQDN@\"\$|$line|" "$SHARE/relay.toml.in""#)),
        "the template's hostname line is the one replaced: {place:?}"
    );
    let template = commands(&read_text(&packaging.join("relay.toml.in")));
    let hostname = at(&template, "hostname = \"@FQDN@\"");
    assert_eq!(template[hostname - 1], "[tls]");

    // (d) Nothing under /etc is package-owned.
    for baseline in ["relay.deb.files", "relay.rpm.files"] {
        let text = read_text(&packaging.join("expected").join(baseline));
        assert!(
            !text.contains("/etc/") && !text.contains(" ./etc"),
            "{baseline} lists something under /etc"
        );
    }
    let manifest = manifest_lines(&packaging);
    assert!(
        manifest
            .iter()
            .all(|l| !l.starts_with("dst: /etc") && l != "type: config"),
        "the manifest installs configuration the package manager would preserve"
    );
    let preinst = lines_of(&scripts, "preinst");
    assert_eq!(
        case_arms(preinst),
        [
            "install) [ -z \"${2:-}\" ] && first_install=yes ;;",
            "1) first_install=yes ;;"
        ]
    );
    assert!(
        at(
            preinst,
            "exists \"$ETC/relay.toml\" && echo \"existed config\""
        ) > at(preinst, "[ \"$first_install\" = yes ] || exit 0"),
        "preinst records an existing file on a first install only"
    );
}

const DELETING: &str = r"\b(?:rm|rmdir|unlink|shred)\b|\bfind\b.*-delete\b";

/// Purge moves the state directory, with the CA and the store inside it, aside in one rename to
/// a root-owned 0700 sibling, after re-owning it in place of the relay account's reach, and
/// before it removes any configuration; where the directory is a mount point it is re-owned in
/// place, and where it is a symbolic link nothing is moved or re-owned. The only deletions are
/// the marker and the configuration and directory the package created, and no script removes
/// the account. Removal deletes nothing and prints what is left.
// Proves RC-26.
#[test]
fn purge_moves_the_ca_and_store_aside_together_and_deletes_only_what_the_package_created() {
    let packaging = relay_packaging();
    let scripts = script_commands(&packaging.join("scripts"));
    let postrm = lines_of(&scripts, "postrm");
    let postrm_text = read_text(&packaging.join("scripts/postrm.sh"));

    // (a) The deletions are four lines, none of them the state directory.
    let deleting = re(DELETING);
    let deletions: Vec<&str> = postrm
        .iter()
        .filter(|l| deleting.is_match(l))
        .map(String::as_str)
        .collect();
    assert_eq!(
        deletions,
        [
            "rm -f \"$MARKER\"",
            "rmdir \"$MARKER_DIR\" 2>/dev/null || true",
            "if created config; then rm -f \"$CONFIG\"; fi",
            "rmdir \"$ETC\" 2>/dev/null \\"
        ]
    );
    assert!(
        deletions
            .iter()
            .all(|l| !l.contains("STATE") && !l.contains("$dst")),
        "no deletion names the state directory or its destination"
    );
    for line in [
        "rm -rf \"$STATE\"",
        "unlink /var/lib/relay/ca/ca-key.pem",
        "shred -u k",
        "find /var/lib/relay -type f -delete",
    ] {
        assert!(deleting.is_match(line), "must match: {line}");
    }
    for line in [
        "echo \"relay: removed. The configuration, the state directory and the relay account were kept;\"",
        "forget_marker",
        "rmdir_helper=1",
        "find /var/lib/relay -type f -name '*.pem'",
    ] {
        assert!(!deleting.is_match(line), "must not match: {line}");
    }

    // (b) Each deletion sits behind the package-created guard.
    let config_rm = at(postrm, "if created config; then rm -f \"$CONFIG\"; fi");
    assert_eq!(postrm[config_rm - 1], "elif plain_dir \"$ETC\"; then");
    let etc_rm = at(postrm, "rmdir \"$ETC\" 2>/dev/null \\");
    assert_eq!(postrm[etc_rm - 1], "if created etc; then");
    assert_eq!(
        body(&postrm_text, "created() {"),
        [
            "[ -f \"$MARKER\" ] && grep -qx \"created $1\" \"$MARKER\" && ! grep -qx \"existed $1\" \"$MARKER\""
        ],
        "a path is the package's to delete only if it created it and it did not exist before"
    );
    let preinst = lines_of(&scripts, "preinst");
    let gate = at(preinst, "[ \"$first_install\" = yes ] || exit 0");
    for marker in [
        "exists \"$ETC\" && echo \"existed etc\"",
        "exists \"$ETC/relay.toml\" && echo \"existed config\"",
        "exists \"$STATE\" && echo \"existed state\"",
    ] {
        assert!(
            at(preinst, marker) > gate,
            "`{marker}` is recorded on a first install only"
        );
    }

    // (c) The account is never removed.
    let account_removal = re(r"\b(?:userdel|groupdel|deluser|delgroup)\b");
    for (name, lines) in &scripts {
        for line in lines {
            assert!(
                !account_removal.is_match(line),
                "{name}.sh removes the account, which no script does: {line}"
            );
        }
    }
    assert!(account_removal.is_match("userdel relay"));
    assert!(account_removal.is_match("groupdel relay"));
    assert!(!account_removal.is_match("useradd --system relay"));

    // (d) The move: symlink untouched, lock, re-own, mount point re-owned in place, then one
    // rename to a sibling and where it went.
    let mv = body(&postrm_text, "move_state_aside() {");
    let symlink = at(&mv, "if [ -L \"$STATE\" ]; then");
    assert!(mv[symlink + 1].starts_with("echo \"relay: $STATE is a symlink;"));
    assert_eq!(mv[symlink + 2], "return 0");
    assert_eq!(mv[symlink + 3], "fi");
    let chown = at(&mv, "chown -h root:root \"$STATE\" || return 1");
    let chmod = at(&mv, "chmod 0700 \"$STATE\" || return 1");
    let find = at(
        &mv,
        "find \"$STATE\" -xdev \\( -type d -o -links 1 \\) -exec chown -h root:root {} + || return 1",
    );
    let mount = at(&mv, "if is_mount_point \"$STATE\"; then");
    let in_place = mv[mount..]
        .iter()
        .position(|l| l.contains("re-owned in place"))
        .expect("the mount-point branch says it re-owned in place");
    let mount_return = mv[mount..].iter().position(|l| l == "return 0").unwrap();
    let mount_end = mv[mount..].iter().position(|l| l == "fi").unwrap();
    assert!(in_place < mount_return && mount_return < mount_end);
    let dst = at(
        &mv,
        "dst=\"$STATE.purged-$(date -u +%Y%m%dT%H%M%SZ)\" || return 1",
    );
    let rename = at(&mv, "mv -T -- \"$STATE\" \"$dst\" || return 1");
    assert!(mv[rename + 1].starts_with("echo \"relay: moved $STATE"));
    assert!(mv[rename + 1].contains("$dst"));
    assert!(
        symlink < chown
            && chown < chmod
            && chmod < find
            && find < mount
            && mount + mount_end < dst
            && dst < rename,
        "the state is locked to root before it is renamed, and a mount point never is"
    );
    for line in mv.iter().filter(|l| re(r"\bchown\b").is_match(l)) {
        assert!(
            line.contains("chown -h "),
            "every chown leaves a link alone: {line}"
        );
    }
    for line in mv.iter().filter(|l| re(r"\bfind\b").is_match(l)) {
        assert!(
            line.contains(" -xdev "),
            "every find stays on one filesystem: {line}"
        );
    }
    assert_eq!(
        mv.iter().filter(|l| re(r"\bmv\b").is_match(l)).count(),
        1,
        "the CA and the store are renamed together, in one move"
    );

    // (e) Purge moves first, and stops before removing any configuration if that fails.
    let purge = body(&postrm_text, "purge() {");
    assert_eq!(purge[0], "if ! move_state_aside; then");
    assert!(purge[1].starts_with("echo \"relay: purge stopped"));
    assert_eq!(purge[2], "exit 1");
    assert_eq!(purge[3], "fi");
    assert!(
        at(&purge, "if created config; then rm -f \"$CONFIG\"; fi") > 3,
        "no configuration is removed before the state is moved"
    );

    // (f) Removal deletes nothing and says what is left.
    at(postrm, "remove) reload ;;");
    at(postrm, "purge) purge ;;");
    let arm_start = at(postrm, "0)");
    let arm_end = arm_start
        + postrm[arm_start..]
            .iter()
            .position(|l| l == ";;")
            .expect("the arm ends");
    let arm = &postrm[arm_start + 1..arm_end];
    for needed in ["reload", "forget_marker", "leftovers"] {
        assert!(
            arm.iter().any(|l| l == needed),
            "the rpm removal arm runs {needed}"
        );
    }
    assert!(arm.iter().any(|l| l.starts_with("echo \"relay: removed.")));
    let touching = re(&format!(
        r"{DELETING}|\b(?:mv|chown|chmod|purge|move_state_aside)\b"
    ));
    for line in arm.iter().filter(|l| l.as_str() != "forget_marker") {
        assert!(
            !touching.is_match(line),
            "the rpm removal arm touches state: {line}"
        );
    }
    at(
        &body(&postrm_text, "leftovers() {"),
        "for p in \"$CONFIG\" \"$ETC\" \"$STATE\"; do",
    );

    // (g) The CA and the store live inside the state directory, so one move takes both.
    at(postrm, "STATE=/var/lib/relay");
    let template = commands(&read_text(&packaging.join("relay.toml.in")));
    for (section, line) in [
        ("[ca]", "dir = \"/var/lib/relay/ca\""),
        ("[store]", "path = \"/var/lib/relay/relay.db\""),
    ] {
        assert_eq!(template[at(&template, section) + 1], line);
    }
}
