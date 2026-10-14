//! Self-reference lint — "does this Policy let the wire rewrite the wire's own
//! gate?" (landed with #292's `policy check` tooling pass).
//!
//! # The gap this closes
//!
//! Policy is deny-by-default, and the hardened unit's `ProtectSystem=strict`
//! makes `/etc` read-only inside the daemon's mount namespace, so a compromised
//! daemon process cannot rewrite its own Policy (see
//! `docs/operations/daemon-privilege-posture.md`). But nothing warned an
//! operator who *authors* an allow rule whose reach includes the daemon's own
//! trust root — a Raw Exec allow regex broad enough to run `sed -i` on
//! `policy.toml`, or a `file.read` allow over the state dir's private key. On a
//! Node not running the hardened unit (a dev fleet, a bare `ExecStart`), such a
//! rule lets a jailbroken AI-agent or a compromised Relay widen its own Policy —
//! defeating ADR-0002's guarantee by operator foot-gun rather than over the wire.
//!
//! This lint catches that in the IaC pipeline, before deploy.
//!
//! # How it decides: probes through the live engine, never a second matcher
//!
//! The lint does **not** parse allow patterns or reason about what a regex
//! "means" — that road is exactly what ADR-0018/0019 had to keep patching.
//! Instead it asks the **real** Policy engine the same question a dispatch
//! would: it builds concrete probe actions that touch the daemon's own trust
//! root and decides each through `Policy::decide`. A finding therefore always means "this exact
//! action would be allowed on that Node" — never a guess, and deny-beats-allow
//! is honored for free because the engine applies it.
//!
//! # What it can and cannot promise
//!
//! A finding is **proof** that a self-referential action is permitted. The
//! absence of findings is **not** proof of the converse: the probe set covers
//! the plausible shapes (edit in place, overwrite, copy over, remove, redirect,
//! read), and a sufficiently creative command could reach the same files in a
//! shape not probed. It is a foot-gun detector, defense-in-depth *under* the
//! mount-namespace protection — not a boundary.
//!
//! # Why no hardcoded daemon-side deny floor
//!
//! #287 also floated an always-on daemon-side deny for its own config
//! directory. Deliberately not implemented — see the ADR-0021 amendment for the
//! full reasoning; in short: a path-string floor is the bypassable mechanism
//! ADR-0018/0019 spent two ADRs hardening, it cannot distinguish a legitimate
//! audit read from a rewrite, and it would silently override an explicit
//! operator allow — a surprise in the privileged exec path. The enforcement
//! boundary stays the filesystem (root-owned files, `ProtectSystem=strict`);
//! this lint makes the foot-gun visible where it is authored.

use std::path::PathBuf;

use crate::config;
use crate::enroll::state_dir_from_env;
use crate::operations::FILE_READ;
use crate::policy::{Decision, LintFinding, LintSeverity, Policy, Request, Rule};

/// One protected target: a path inside the daemon's own trust root, and what it
/// means for Policy's reach to include it — separately for a *read* (the
/// structured-Operation probes, which only disclose) and for a *write* (the Raw
/// Exec probes, which can modify). Conflating the two would tell an operator
/// that a `file.read` rule "rewrites the gate", which is false and trains them
/// to ignore the lint.
struct Target {
    path: PathBuf,
    /// Why reading this path matters.
    read: &'static str,
    /// Why writing this path matters.
    write: &'static str,
}

/// The daemon's own trust root, as this machine is configured.
///
/// Derived from the same env-var accessors the daemon itself uses
/// (`RELAY_POLICY_PATH`, `RELAY_TEMPLATE_DIR`, `RELAY_STATE_DIR`) so a lint run
/// on the target Node describes that Node, plus the packaged defaults so a lint
/// run in CI — where none of those are set — still covers a standard install.
fn targets(template_names: &[String]) -> Vec<Target> {
    let policy_path = std::env::var("RELAY_POLICY_PATH")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("/etc/relay-daemon/policy.toml"));
    let template_dir = config::template_dir_from_env();
    let state_dir = state_dir_from_env();

    let _ = template_names; // reserved: per-template probing uses the names below

    let mut targets = vec![
        Target {
            path: policy_path,
            read: "this daemon's own Policy file — discloses exactly which actions are \
                   permitted here, which is reconnaissance for what to attempt",
            write: "this daemon's own Policy file — a rule that can write it lets the wire \
                    rewrite the wire's own gate (ADR-0002)",
        },
        Target {
            path: template_dir.join("pack.toml"),
            read: "this daemon's Template Operation files — discloses the Node's vocabulary",
            write: "this daemon's Template Operation files — writing one adds vocabulary \
                    without an operator (ADR-0021)",
        },
        Target {
            path: state_dir.join("key.pem"),
            read: "this Node's private key — reading it is identity theft (ADR-0006)",
            write: "this Node's private key — writing it is impersonation (ADR-0006)",
        },
        Target {
            path: state_dir.join("cert.pem"),
            read: "this Node's identity certificate (ADR-0006)",
            write: "this Node's identity certificate — replacing it breaks or redirects the \
                    Node's identity (ADR-0006)",
        },
        Target {
            path: PathBuf::from("/usr/local/bin/relay-daemon"),
            read: "the daemon binary itself",
            write: "the daemon binary itself — writing it replaces the enforcement engine \
                    (ADR-0014: upgrades come from config management, never from the wire)",
        },
        Target {
            path: PathBuf::from("/etc/systemd/system/relay-daemon.service"),
            read: "the daemon's systemd unit — discloses the privilege posture in force",
            write: "the daemon's systemd unit — writing it removes the hardening the \
                    privilege posture depends on",
        },
    ];

    // The daemon's own binary as actually installed, when it differs from the
    // packaged default (a dev-fleet build, a distro path).
    if let Ok(exe) = std::env::current_exe() {
        if !targets.iter().any(|t| t.path == exe) {
            targets.push(Target {
                path: exe,
                read: "the daemon binary itself, at the path this check is running from",
                write: "the daemon binary itself, at the path this check is running from — \
                        writing it replaces the enforcement engine (ADR-0014)",
            });
        }
    }

    targets
}

/// Raw Exec probe shapes: concrete argv vectors that reach `path`, spanning
/// edit-in-place, overwrite, copy/move over, delete, redirect, permission
/// change, and plain read. Each is evaluated by the real engine.
///
/// The redirect probe is a whitespace-free `:>path` (truncate), not
/// `echo x > path`: since the ADR-0019 amendment (2026-09-16) any argv
/// element carrying whitespace is refused before an allow pattern ever runs,
/// so a script containing a space could never be Allowed and a Policy like
/// `^/bin/sh -c .*$` would silently stop being flagged by this probe.
fn raw_exec_probes(path: &str) -> Vec<Vec<String>> {
    let v = |parts: &[&str]| parts.iter().map(|s| s.to_string()).collect::<Vec<String>>();
    vec![
        v(&["/usr/bin/sed", "-i", "s/a/b/", path]),
        v(&["/bin/cp", "/tmp/x", path]),
        v(&["/bin/mv", "/tmp/x", path]),
        v(&["/bin/rm", "-f", path]),
        v(&["/usr/bin/tee", path]),
        v(&["/bin/chmod", "0666", path]),
        v(&["/bin/ln", "-sf", "/tmp/x", path]),
        v(&["/bin/sh", "-c", &format!(":>{path}")]),
        v(&["/bin/cat", path]),
    ]
}

/// Lints `policy` for reach into the daemon's own trust root.
///
/// `path_slot_ops` are the Template Operations that declare a `path` slot
/// (`TemplateLintReport::path_slot_names`) — the only templates a path can
/// legitimately be passed to. A unit-name or enum slot rejects a path at the
/// template's own typed gate, so probing those would report a reach that cannot
/// exist. Native `file.read` is always probed.
///
/// Every finding is a `Warning` (`--strict` turns it into a pipeline failure),
/// matching #287's proposal: this is an authoring smell, not an invalid file.
pub fn lint(policy: &Policy, path_slot_ops: &[String]) -> Vec<LintFinding> {
    let mut findings = Vec::new();

    for target in targets(path_slot_ops) {
        let path = target.path.to_string_lossy().to_string();

        // --- structured Operations: file.read, plus any supplied template ---
        let mut op_names: Vec<&str> = vec![FILE_READ];
        op_names.extend(path_slot_ops.iter().map(String::as_str));
        for name in op_names {
            // A single-argument probe: the arg-shape a path-taking Operation
            // (and a path-slotted template) presents to the Policy engine.
            let probe = Request::Operation {
                name,
                // The one argument is the path, so position 0 is the path slot
                // for every probed Operation (no `path_arg_positions()` needed).
                positional: std::slice::from_ref(&path),
                path_positions: &[0],
            };
            if let Some(rule) = probe_allows(policy, &probe) {
                findings.push(LintFinding {
                    severity: LintSeverity::Warning,
                    location: format!("[[operation]] (name={name:?})"),
                    message: format!(
                        "self-reference: Policy allows {name} of {path} — {}. \
                         Deny it explicitly ([[deny]] beats allow) or narrow the allowed args. \
                         (Matched rule: {rule:?}.)",
                        target.read
                    ),
                });
                // One finding per (target, operation): the point is made.
                break;
            }
        }

        // --- Raw Exec: probe the plausible reach shapes ---
        for argv in raw_exec_probes(&path) {
            if let Some(rule) = probe_allows(policy, &Request::RawExec { argv: &argv }) {
                findings.push(LintFinding {
                    severity: LintSeverity::Warning,
                    location: "[raw_exec].allow".to_string(),
                    message: format!(
                        "self-reference: Policy allows the Raw Exec {argv:?} — {}. \
                         Narrow the allow regex, or add a [raw_exec] deny for this path \
                         (deny beats allow). (Matched pattern: {rule:?}.)",
                        target.write
                    ),
                });
                // One finding per target: further shapes would only repeat it.
                break;
            }
        }
    }

    findings
}

/// The lint's one `Policy::decide` call: the matched `Rule` when `probe` would
/// be allowed. A hypothetical never runs, so any Raw Exec permit drops here.
fn probe_allows(policy: &Policy, probe: &Request<'_>) -> Option<Rule> {
    match policy.decide(probe).decision {
        Decision::Allow(rule) => Some(rule),
        Decision::Deny { .. } => None,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::from_toml_str;

    /// The #287 headline case: a Raw Exec allow broad enough to edit the
    /// daemon's own Policy file is flagged.
    #[test]
    fn flags_raw_exec_reach_into_the_config_dir() {
        let policy = from_toml_str(
            r#"
[raw_exec]
allow = ["^/usr/bin/sed .*$"]
"#,
        )
        .expect("policy parses");

        let findings = lint(&policy, &[]);
        assert!(
            findings
                .iter()
                .any(|f| f.message.contains("/etc/relay-daemon/policy.toml")),
            "expected a finding naming the Policy file; got {findings:#?}"
        );
        assert!(findings.iter().all(|f| f.severity == LintSeverity::Warning));
    }

    /// The `/bin/sh -c :>path` redirect probe still reaches the daemon's own
    /// Policy file once allow patterns require a full match (ADR-0019,
    /// amended 2026-09-16): the probe was changed from `echo x > path` to a
    /// whitespace-free `:>path` specifically so it can still be Allowed and
    /// this lint's shell-redirect coverage stays live.
    #[test]
    fn flags_shell_redirect_reach_under_full_match() {
        let policy = from_toml_str(
            r#"
[raw_exec]
allow = ["^/bin/sh -c .*$"]
"#,
        )
        .expect("policy parses");

        let findings = lint(&policy, &[]);
        assert!(
            findings
                .iter()
                .any(|f| f.message.contains("/etc/relay-daemon/policy.toml")),
            "expected a finding naming the Policy file; got {findings:#?}"
        );
    }

    /// file.read over the state dir is identity-material disclosure, not just a
    /// config read — flagged too.
    #[test]
    fn flags_file_read_reach_into_the_state_dir() {
        let policy = from_toml_str(
            r#"
[[operation]]
name = "file.read"
allowed_args = [["*"]]
"#,
        )
        .expect("policy parses");

        let findings = lint(&policy, &[]);
        assert!(
            findings.iter().any(|f| f.message.contains("key.pem")),
            "expected a finding naming the private key; got {findings:#?}"
        );
    }

    /// deny-beats-allow is honored for free, because the lint asks the real
    /// engine: an explicit deny for the daemon's own paths silences the finding.
    #[test]
    fn an_explicit_deny_silences_the_finding() {
        let wide = from_toml_str(
            r#"
[[operation]]
name = "file.read"
allowed_args = [["*"]]
"#,
        )
        .expect("policy parses");
        assert!(
            !lint(&wide, &[]).is_empty(),
            "sanity: the wide rule is flagged"
        );

        // Deny exactly the paths this machine's target set names — including
        // the current-exe target, which is the test binary here — so the
        // assertion is hermetic rather than dependent on where cargo built it.
        let denied_paths: Vec<String> = targets(&[])
            .iter()
            .map(|t| format!("{:?}", t.path.to_string_lossy()))
            .collect();
        let denied = from_toml_str(&format!(
            r#"
[[operation]]
name = "file.read"
allowed_args = [["*"]]

[[deny]]
name = "file.read"
args = [[{}]]
"#,
            denied_paths.join(", ")
        ))
        .expect("policy parses");

        let findings = lint(&denied, &[]);
        assert!(
            findings.is_empty(),
            "an explicit deny for every named path must silence every finding; got {findings:#?}"
        );
    }

    /// A narrow, well-scoped Policy produces no findings — the lint must not
    /// cry wolf on the shape operators are supposed to write.
    #[test]
    fn a_narrow_policy_is_clean() {
        let policy = from_toml_str(
            r#"
[[operation]]
name = "service.restart"
allowed_args = [["nginx"]]

[[operation]]
name = "file.read"
allowed_args = [["/etc/os-release"]]

[raw_exec]
allow = ["^/usr/bin/systemctl (status|restart) [A-Za-z0-9@._-]+$"]
"#,
        )
        .expect("policy parses");

        assert!(
            lint(&policy, &[]).is_empty(),
            "a narrow Policy must produce no self-reference findings"
        );
    }

    /// A path-slotted template is probed like file.read: a template Policy rule
    /// wide enough to reach the daemon's own files is the same foot-gun.
    #[test]
    fn flags_a_path_slotted_template_rule_reaching_the_config_dir() {
        let policy = from_toml_str(
            r#"
[[operation]]
name = "file.checksum"
allowed_args = [["*"]]
"#,
        )
        .expect("policy parses");

        let findings = lint(&policy, &["file.checksum".to_string()]);
        assert!(
            findings
                .iter()
                .any(|f| f.location.contains("file.checksum")),
            "expected a finding for the path-slotted template rule; got {findings:#?}"
        );
    }

    /// ...but a template whose slots are unit names, not paths, is NOT probed
    /// with a path: its own typed gate would reject one, so a finding would be
    /// a reach that cannot exist. A lint that cries wolf gets ignored.
    #[test]
    fn does_not_flag_a_template_with_no_path_slot() {
        let policy = from_toml_str(
            r#"
[[operation]]
name = "log.tail"
allowed_args = [["*"]]
"#,
        )
        .expect("policy parses");

        let findings = lint(&policy, &[]); // log.tail declares no path slot
        assert!(
            findings.iter().all(|f| !f.location.contains("log.tail")),
            "a unit-slotted template must not be probed with a path; got {findings:#?}"
        );
    }

    /// A read probe and a write probe explain themselves differently: a
    /// `file.read` rule discloses, it does not rewrite the gate. Telling an
    /// operator otherwise trains them to ignore the lint.
    #[test]
    fn read_and_write_findings_are_worded_for_what_they_actually_do() {
        let read_only = from_toml_str(
            r#"
[[operation]]
name = "file.read"
allowed_args = [["*"]]
"#,
        )
        .expect("policy parses");
        let findings = lint(&read_only, &[]);
        assert!(
            findings
                .iter()
                .all(|f| !f.message.contains("rewrite the wire")),
            "a read rule must not be described as rewriting the gate; got {findings:#?}"
        );

        let writable = from_toml_str(
            r#"
[raw_exec]
allow = ["^/usr/bin/sed .*$"]
"#,
        )
        .expect("policy parses");
        let findings = lint(&writable, &[]);
        assert!(
            findings
                .iter()
                .any(|f| f.message.contains("rewrite the wire")),
            "a write-capable Raw Exec rule must say so; got {findings:#?}"
        );
    }

    /// An empty Policy (deny-all) can reach nothing.
    #[test]
    fn deny_all_is_clean() {
        let policy = from_toml_str("").expect("empty policy parses");
        assert!(lint(&policy, &[]).is_empty());
    }
}
