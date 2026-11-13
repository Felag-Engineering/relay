//! Structural readers for the maintainer scripts, nfpm manifests and file-list baselines of
//! both packages, shared by `packaging_drift.rs` (the daemon package) and `relay_packaging.rs`
//! (the Relay package). One copy, so the matchers that decide what counts as starting,
//! enabling or writing to something cannot drift apart between the two packages' proofs.
//!
//! Mounted with `#[path]`, as `shell_runner.rs` is, so Cargo does not build it as a test crate
//! of its own.

use std::path::Path;

pub fn re(pattern: &str) -> regex::Regex {
    regex::Regex::new(pattern).unwrap_or_else(|e| panic!("regex {pattern}: {e}"))
}

pub fn read_text(path: &Path) -> String {
    std::fs::read_to_string(path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
}

/// The trimmed, non-empty lines that are not full-line comments.
pub fn commands(text: &str) -> Vec<String> {
    text.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(String::from)
        .collect()
}

/// The command lines of the four maintainer scripts under `dir`, by script name.
pub fn script_commands(dir: &Path) -> Vec<(&'static str, Vec<String>)> {
    ["preinst", "postinst", "prerm", "postrm"]
        .into_iter()
        .map(|name| (name, commands(&read_text(&dir.join(format!("{name}.sh"))))))
        .collect()
}

/// Whether `line` starts or restarts a unit, by systemctl, `service`, or the Debian helpers.
pub fn starts_a_unit(line: &str) -> bool {
    re(r"\bsystemctl\b(?:\s+-{1,2}[A-Za-z-]+(?:=\S+)?)*\s+(?:start|restart|try-restart|reload-or-restart|try-reload-or-restart|isolate)\b")
        .is_match(line)
        || (re(r"\bsystemctl\b").is_match(line)
            && re(r"\benable\b").is_match(line)
            && line.contains("--now"))
        || re(r"\bservice\s+\S+\s+(?:start|restart|try-restart|force-reload)\b").is_match(line)
        || re(r"\b(?:invoke-rc\.d|deb-systemd-invoke)\b").is_match(line)
}

/// Whether `line` changes whether a unit is enabled, by any route that reaches the same state.
pub fn enables_a_unit(line: &str) -> bool {
    re(r"\bsystemctl\b.*\b(?:enable|reenable|preset|preset-all|link|add-wants)\b").is_match(line)
        || re(r"\b(?:deb-systemd-helper|update-rc\.d|chkconfig)\b").is_match(line)
        || re(r"\bln\b[^|;&]*\.wants/").is_match(line)
}

/// Whether `line` writes to a path `target` names: a redirect into it on any line, or one of
/// the writing commands naming it on a line that is not an echo or printf.
pub fn writes_to(line: &str, target: &regex::Regex) -> bool {
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
pub fn at(lines: &[String], exact: &str) -> usize {
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
pub fn body(text: &str, header: &str) -> Vec<String> {
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

/// The index of the gate's closing `fi`: past it, a postinst runs on a first install only.
pub fn first_install_gate_end(lines: &[String]) -> usize {
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
pub fn case_arms(lines: &[String]) -> Vec<String> {
    let start = at(lines, "case \"${1:-}\" in");
    let end = lines[start..]
        .iter()
        .position(|l| l == "esac")
        .expect("the case statement ends");
    lines[start + 1..start + end].to_vec()
}

const FIRST_INSTALL_GATE: [&str; 6] = [
    "if [ \"$first_install\" != yes ]; then",
    "if systemd_running; then",
    "systemctl daemon-reload || true",
    "fi",
    "exit 0",
    "fi",
];

/// The paths of a baseline's regular files, for the `dpkg-deb` and `rpm` listing formats.
pub fn regular_entries(baseline: &str) -> Vec<String> {
    baseline
        .lines()
        .filter(|l| l.starts_with('-'))
        .filter_map(|l| l.split_whitespace().last())
        .map(|p| p.trim_start_matches('.').to_string())
        .collect()
}

/// A prerm that stops and disables the unit on removal and does nothing on any other call.
pub fn assert_prerm_stops_and_disables_on_removal_only(prerm: &[String]) {
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
pub fn assert_unit_matchers_tell_the_verbs_apart() {
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

/// The lines of `scripts` that write to `target`, as `(script, line)`.
pub fn writers<'a>(
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
