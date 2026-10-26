//! Self-reference lint — "does this Policy let the wire reach the daemon's own
//! secrets, or rewrite the wire's own gate?"
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
//! rule lets a jailbroken AI-agent or a compromised Relay widen its own Policy or
//! steal its identity — defeating ADR-0002's guarantee by operator foot-gun
//! rather than over the wire.
//!
//! This lint catches that in the IaC pipeline, before deploy.
//!
//! # Reads probe secrets; writes probe the trust root
//!
//! The two halves differ on purpose (ADR-0021, amended 2026-10-16):
//!
//! - **Reads** — `file.read`, `file.checksum` and any supplied path-taking
//!   Template — are probed only against the files that hold a secret: the
//!   identity private key and the environment file. Reading a file that holds no
//!   secret is never a finding.
//! - **Writes** — the Raw Exec shapes — are probed against the whole packaged
//!   trust root by exact path: the Policy file, the directory holding it, the
//!   Policy directory (`policy.d`), the environment file, the state directory's
//!   key, certificate, CA bundle and persisted address, the template root, the
//!   binary and the unit files.
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
//! absence of findings is **not** proof of the converse: write probes name
//! exact paths, so a drop-in or a Policy fragment under some name inside
//! `policy.d` is not tried (the `policy.d` probe names the directory itself;
//! the control is a `[raw_exec]` deny over the Policy directory), and the probe
//! set covers the plausible shapes (edit in place, overwrite, copy over,
//! remove, redirect, permission change, symlink) while a
//! sufficiently creative command could reach the same files in a shape not
//! probed (residual R38 in `docs/security/threat-model.md`). It is a foot-gun
//! detector, defense-in-depth *under* the mount-namespace protection — not a
//! boundary.
//!
//! # Why no hardcoded daemon-side deny floor
//!
//! An always-on daemon-side deny for its own config directory is
//! deliberately not implemented — see the ADR-0021 amendment for the
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

/// The packaged Policy file, used when `RELAY_POLICY_PATH` is unset.
const DEFAULT_POLICY_PATH: &str = "/etc/relay-daemon/policy.toml";
/// The packaged environment file named by the unit's `EnvironmentFile=`.
const ENV_FILE: &str = "/etc/relay-daemon/relay-daemon.env";
/// Where the package installs the daemon binary.
const PACKAGED_BINARY: &str = "/usr/bin/relay-daemon";
/// Where the package installs the systemd unit.
const PACKAGED_UNIT: &str = "/usr/lib/systemd/system/relay-daemon.service";
/// An administrator's full override of the unit.
const OVERRIDE_UNIT: &str = "/etc/systemd/system/relay-daemon.service";
/// An administrator's drop-in over the unit.
const OVERRIDE_DROP_IN: &str = "/etc/systemd/system/relay-daemon.service.d/override.conf";
/// The shipped catalog's path-taking Template, which is a read probe next to
/// `file.read` whether or not `--templates` supplies it.
const FILE_CHECKSUM: &str = "file.checksum";

/// One protected target: a path inside the daemon's own trust root, and what it
/// means for Policy's reach to include it. Every target is write-probed; only a
/// file that holds a secret is read-probed. Conflating the two would tell an
/// operator that a `file.read` rule "rewrites the gate", which is false and
/// trains them to ignore the lint.
struct Target {
    path: PathBuf,
    /// Why reading this path matters. `Some` only where the file holds a
    /// secret; `None` means the path is write-probed only.
    read: Option<&'static str>,
    /// Why writing this path matters.
    write: &'static str,
}

/// Where this machine's trust root lives. Built from the environment by `lint`,
/// and fixed by tests so they never read process-global state that other tests
/// mutate.
struct Roots {
    policy_path: PathBuf,
    policy_dir: PathBuf,
    state_dir: PathBuf,
    template_dir: PathBuf,
    /// The running binary, when it is known.
    exe: Option<PathBuf>,
}

/// The daemon's own trust root as `roots` describes it.
fn targets_at(roots: &Roots) -> Vec<Target> {
    let mut targets = vec![Target {
        path: roots.policy_path.clone(),
        read: None,
        write: "this daemon's own Policy file — a rule that can write it lets the wire \
                rewrite the wire's own gate (ADR-0002)",
    }];

    if let Some(dir) = roots
        .policy_path
        .parent()
        .filter(|d| !d.as_os_str().is_empty())
    {
        targets.push(Target {
            path: dir.to_path_buf(),
            read: None,
            write: "the directory holding this daemon's Policy file and Policy directory — \
                    replacing or removing it replaces the Policy (ADR-0002)",
        });
    }
    targets.push(Target {
        path: roots.policy_dir.clone(),
        read: None,
        write: "this daemon's Policy directory — a rule that can write into it adds, \
                replaces or removes a Policy fragment, which lets the wire rewrite the \
                wire's own gate (ADR-0002)",
    });

    targets.extend([
        Target {
            path: PathBuf::from(ENV_FILE),
            read: Some(
                "this daemon's environment file — it configures the daemon; kept from the \
                 wire as defence in depth",
            ),
            write: "this daemon's environment file — writing it injects configuration into \
                    the daemon's next start",
        },
        Target {
            path: roots.state_dir.join("key.pem"),
            read: Some("this Node's private key — reading it is identity theft (ADR-0006)"),
            write: "this Node's private key — writing it is impersonation (ADR-0006)",
        },
        Target {
            path: roots.state_dir.join("cert.pem"),
            read: None,
            write: "this Node's identity certificate — replacing it breaks or redirects the \
                    Node's identity (ADR-0006)",
        },
        Target {
            path: roots.state_dir.join("ca_bundle.pem"),
            read: None,
            write: "this Node's pinned CA bundle — replacing it changes which Relay the daemon \
                    trusts (ADR-0005, ADR-0006)",
        },
        Target {
            path: roots.state_dir.join(crate::identity::PERSISTED_ADDR_FILE),
            read: None,
            write: "this Node's persisted Relay address — writing it redirects the daemon to \
                    another Relay",
        },
        Target {
            path: roots.template_dir.clone(),
            read: None,
            write: "this daemon's Template Operation directory — writing into it adds \
                    vocabulary without an operator (ADR-0021)",
        },
        Target {
            path: PathBuf::from(PACKAGED_BINARY),
            read: None,
            write: "the daemon binary itself — writing it replaces the enforcement engine \
                    (ADR-0014: upgrades come from config management, never from the wire)",
        },
        Target {
            path: PathBuf::from(PACKAGED_UNIT),
            read: None,
            write: "the daemon's packaged systemd unit — writing it removes the hardening the \
                    privilege posture depends on",
        },
        Target {
            path: PathBuf::from(OVERRIDE_UNIT),
            read: None,
            write: "the daemon's override systemd unit — writing it removes the hardening the \
                    privilege posture depends on",
        },
        Target {
            path: PathBuf::from(OVERRIDE_DROP_IN),
            read: None,
            write: "the daemon's systemd drop-in — writing it removes the hardening the \
                    privilege posture depends on",
        },
    ]);

    // The daemon's own binary as actually installed, when it differs from the
    // packaged path (a dev-fleet build, a distro path): the answer is then the
    // same from a CI checkout as from `/usr/bin`.
    if let Some(exe) = &roots.exe {
        if !targets.iter().any(|t| &t.path == exe) {
            targets.push(Target {
                path: exe.clone(),
                read: None,
                write: "the daemon binary itself, at the path this check is running from — \
                        writing it replaces the enforcement engine (ADR-0014)",
            });
        }
    }

    targets
}

/// Raw Exec probe shapes: concrete argv vectors that write `path`, spanning
/// edit-in-place, overwrite, copy/move over, delete, redirect, permission
/// change, and symlink. Each is evaluated by the real engine.
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
    ]
}

/// Lints `policy` for reach into the daemon's own trust root.
///
/// `path_slot_ops` are the Template Operations that declare a `path` slot
/// (`TemplateLintReport::path_slot_names`) — the only templates a path can
/// legitimately be passed to. A unit-name or enum slot rejects a path at the
/// template's own typed gate, so probing those would report a reach that cannot
/// exist. `file.read` and `file.checksum` are always probed.
///
/// The roots are derived from the same env-var accessors the daemon itself uses
/// (`RELAY_POLICY_PATH`, `RELAY_TEMPLATE_DIR`, `RELAY_STATE_DIR`) so a lint run
/// on the target Node describes that Node, plus the packaged paths so a lint
/// run in CI — where none of those are set — still covers a standard install.
///
/// Every finding is a `Warning` (`--strict` turns it into a pipeline failure),
/// matching the ADR-0021 amendment: this is an authoring smell, not an invalid file.
pub fn lint(policy: &Policy, path_slot_ops: &[String]) -> Vec<LintFinding> {
    let policy_path = std::env::var("RELAY_POLICY_PATH")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(DEFAULT_POLICY_PATH));
    let roots = Roots {
        policy_dir: config::policy_dir_beside(&policy_path),
        policy_path,
        state_dir: state_dir_from_env(),
        template_dir: config::template_dir_from_env(),
        exe: std::env::current_exe().ok(),
    };
    lint_at(policy, path_slot_ops, &roots)
}

/// `lint` over explicit roots; reads no environment.
fn lint_at(policy: &Policy, path_slot_ops: &[String], roots: &Roots) -> Vec<LintFinding> {
    let mut findings = Vec::new();

    let mut op_names: Vec<&str> = vec![FILE_READ, FILE_CHECKSUM];
    for name in path_slot_ops {
        if !op_names.contains(&name.as_str()) {
            op_names.push(name);
        }
    }

    for target in targets_at(roots) {
        let path = target.path.to_string_lossy().to_string();

        // --- structured Operations: reads of a secret-bearing file only ---
        if let Some(why) = target.read {
            for &name in &op_names {
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
                            "self-reference: Policy allows {name} of {path} — {why}. \
                             Reading it discloses a secret; deny it explicitly ([[deny]] beats \
                             allow) or narrow the allowed args. (Matched rule: {rule:?}.)"
                        ),
                    });
                    // One finding per target: the point is made.
                    break;
                }
            }
        }

        // --- Raw Exec: probe the plausible write shapes ---
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

    const FAKE_EXE: &str = "/opt/relay-test/bin/relay-daemon";

    const WILDCARD_READS: &str = r#"
[[operation]]
name = "file.read"
allowed_args = [["*"]]

[[operation]]
name = "file.checksum"
allowed_args = [["*"]]
"#;

    const SED_ALLOW: &str = r#"
[raw_exec]
allow = ["^/usr/bin/sed .*$"]
"#;

    /// The packaged defaults and a fixed fake exe, so no test here reads
    /// `RELAY_*` or `current_exe` while the config tests mutate the environment.
    fn packaged() -> Roots {
        Roots {
            policy_path: PathBuf::from(DEFAULT_POLICY_PATH),
            policy_dir: PathBuf::from("/etc/relay-daemon/policy.d"),
            state_dir: PathBuf::from("/var/lib/relay-daemon"),
            template_dir: PathBuf::from("/etc/relay-daemon/templates.d"),
            exe: Some(PathBuf::from(FAKE_EXE)),
        }
    }

    fn parse(toml: &str) -> Policy {
        from_toml_str(toml).expect("policy parses")
    }

    /// The paths a set of read findings names, taken from the " of PATH — "
    /// fragment of the message.
    fn read_finding_paths(findings: &[LintFinding]) -> std::collections::BTreeSet<String> {
        findings
            .iter()
            .filter(|f| f.location.starts_with("[[operation]]"))
            .map(|f| {
                // Relies on the prefix "Policy allows {name} of " holding no earlier " of ".
                let rest = f
                    .message
                    .split(" of ")
                    .nth(1)
                    .expect("message names a path");
                rest.split(" — ")
                    .next()
                    .expect("path precedes the reason")
                    .to_string()
            })
            .collect()
    }

    /// A Raw Exec allow broad enough to edit the daemon's own Policy file is
    /// flagged.
    #[test]
    fn flags_raw_exec_reach_into_the_config_dir() {
        let policy = parse(
            r#"
[raw_exec]
allow = ["^/usr/bin/sed .*$"]
"#,
        );

        let findings = lint_at(&policy, &[], &packaged());
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
    /// amended 2026-09-16): the probe is a whitespace-free `:>path` specifically
    /// so it can still be Allowed and this lint's shell-redirect coverage stays
    /// live.
    #[test]
    fn flags_shell_redirect_reach_under_full_match() {
        let policy = parse(
            r#"
[raw_exec]
allow = ["^/bin/sh -c .*$"]
"#,
        );

        let findings = lint_at(&policy, &[], &packaged());
        assert!(
            findings
                .iter()
                .any(|f| f.message.contains("/etc/relay-daemon/policy.toml")),
            "expected a finding naming the Policy file; got {findings:#?}"
        );
    }

    /// file.read over the state dir is identity-material disclosure — flagged.
    #[test]
    fn flags_file_read_reach_into_the_state_dir() {
        let policy = parse(
            r#"
[[operation]]
name = "file.read"
allowed_args = [["*"]]
"#,
        );

        let findings = lint_at(&policy, &[], &packaged());
        assert!(
            findings.iter().any(|f| f.message.contains("key.pem")),
            "expected a finding naming the private key; got {findings:#?}"
        );
    }

    /// deny-beats-allow is honored for free, because the lint asks the real
    /// engine: an explicit deny for the secret-bearing paths silences the finding.
    #[test]
    fn an_explicit_deny_silences_the_finding() {
        let wide = parse(
            r#"
[[operation]]
name = "file.read"
allowed_args = [["*"]]
"#,
        );
        assert!(
            !lint_at(&wide, &[], &packaged()).is_empty(),
            "sanity: the wide rule is flagged"
        );

        let denied_paths: Vec<String> = targets_at(&packaged())
            .iter()
            .filter(|t| t.read.is_some())
            .map(|t| format!("{:?}", t.path.to_string_lossy()))
            .collect();
        let denied = parse(&format!(
            r#"
[[operation]]
name = "file.read"
allowed_args = [["*"]]

[[deny]]
name = "file.read"
args = [[{}]]
"#,
            denied_paths.join(", ")
        ));

        let findings = lint_at(&denied, &[], &packaged());
        assert!(
            findings.is_empty(),
            "an explicit deny for every secret-bearing path must silence every finding; \
             got {findings:#?}"
        );
    }

    /// A narrow, well-scoped Policy produces no findings — the lint must not
    /// cry wolf on the shape operators are supposed to write.
    #[test]
    fn a_narrow_policy_is_clean() {
        let policy = parse(
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
        );

        assert!(
            lint_at(&policy, &[], &packaged()).is_empty(),
            "a narrow Policy must produce no self-reference findings"
        );
    }

    /// A path-slotted template is probed like file.read: a template Policy rule
    /// wide enough to reach a secret is the same foot-gun.
    #[test]
    fn flags_a_path_slotted_template_rule_reaching_the_config_dir() {
        let policy = parse(
            r#"
[[operation]]
name = "file.checksum"
allowed_args = [["*"]]
"#,
        );

        let findings = lint_at(&policy, &["file.checksum".to_string()], &packaged());
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
        let policy = parse(
            r#"
[[operation]]
name = "log.tail"
allowed_args = [["*"]]
"#,
        );

        let findings = lint_at(&policy, &[], &packaged()); // log.tail declares no path slot
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
        let read_only = parse(
            r#"
[[operation]]
name = "file.read"
allowed_args = [["*"]]
"#,
        );
        let findings = lint_at(&read_only, &[], &packaged());
        assert!(!findings.is_empty(), "sanity: the read rule is flagged");
        assert!(
            findings
                .iter()
                .all(|f| !f.message.contains("rewrite the wire")),
            "a read rule must not be described as rewriting the gate; got {findings:#?}"
        );

        let findings = lint_at(&parse(SED_ALLOW), &[], &packaged());
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
        let policy = parse("");
        assert!(lint_at(&policy, &[], &packaged()).is_empty());
    }

    /// Reads stop at secrets: with wildcard reads allowed, only the identity
    /// private key and the environment file are findings.
    // Proves DI-39.
    #[test]
    fn lint_read_probes_stop_at_secrets() {
        let findings = lint_at(&parse(WILDCARD_READS), &[], &packaged());

        assert!(
            findings
                .iter()
                .all(|f| f.location.contains("file.read") || f.location.contains("file.checksum")),
            "got {findings:#?}"
        );
        let named = read_finding_paths(&findings);
        let expected: std::collections::BTreeSet<String> =
            ["/var/lib/relay-daemon/key.pem", ENV_FILE]
                .iter()
                .map(|s| s.to_string())
                .collect();
        assert_eq!(named, expected, "got {findings:#?}");

        for not_a_secret in [
            DEFAULT_POLICY_PATH,
            "/etc/relay-daemon/templates.d",
            "/var/lib/relay-daemon/cert.pem",
            "/var/lib/relay-daemon/ca_bundle.pem",
            "/var/lib/relay-daemon/relay_addr",
            PACKAGED_BINARY,
            PACKAGED_UNIT,
            OVERRIDE_UNIT,
            OVERRIDE_DROP_IN,
            FAKE_EXE,
        ] {
            assert!(
                findings.iter().all(|f| !f.message.contains(not_a_secret)),
                "a read of {not_a_secret} holds no secret and must not be a finding; \
                 got {findings:#?}"
            );
        }
    }

    /// `file.checksum` is a read probe on every run, not only when `--templates`
    /// supplies it.
    // Proves DI-39.
    #[test]
    fn checksum_is_probed_without_templates() {
        let policy = parse(
            r#"
[[operation]]
name = "file.checksum"
allowed_args = [["*"]]
"#,
        );
        let findings = lint_at(&policy, &[], &packaged());

        assert_eq!(findings.len(), 2, "got {findings:#?}");
        assert!(
            findings
                .iter()
                .all(|f| f.location.contains("file.checksum")),
            "got {findings:#?}"
        );
        let named = read_finding_paths(&findings);
        assert!(
            named.contains("/var/lib/relay-daemon/key.pem"),
            "got {named:?}"
        );
        assert!(named.contains(ENV_FILE), "got {named:?}");
    }

    /// Writes cover the packaged trust root by exact path: one finding per
    /// target, every one a Raw Exec finding.
    // Proves DI-39.
    #[test]
    fn lint_write_probes_cover_packaged_trust_root() {
        let findings = lint_at(&parse(SED_ALLOW), &[], &packaged());

        let expected = [
            DEFAULT_POLICY_PATH,
            "/etc/relay-daemon",
            "/etc/relay-daemon/policy.d",
            ENV_FILE,
            "/var/lib/relay-daemon/key.pem",
            "/var/lib/relay-daemon/cert.pem",
            "/var/lib/relay-daemon/ca_bundle.pem",
            "/var/lib/relay-daemon/relay_addr",
            "/etc/relay-daemon/templates.d",
            PACKAGED_BINARY,
            PACKAGED_UNIT,
            OVERRIDE_UNIT,
            OVERRIDE_DROP_IN,
            FAKE_EXE,
        ];
        for path in expected {
            // The probe argv's final element is the path, so a longer path
            // cannot satisfy the check for a directory that prefixes it.
            let needle = format!("{path:?}]");
            let matching = findings
                .iter()
                .filter(|f| f.location == "[raw_exec].allow" && f.message.contains(&needle))
                .count();
            assert_eq!(
                matching, 1,
                "expected one write finding for {path}; got {findings:#?}"
            );
        }
        assert_eq!(findings.len(), expected.len(), "got {findings:#?}");
        assert!(
            findings
                .iter()
                .all(|f| !f.location.starts_with("[[operation]]")),
            "a Raw Exec allow must not raise a read finding; got {findings:#?}"
        );
        assert!(
            findings.iter().all(|f| {
                !f.message.contains("/usr/local/bin/relay-daemon")
                    && !f.message.contains("pack.toml")
            }),
            "got {findings:#?}"
        );
    }

    /// The running binary is a write probe only.
    // Proves DI-39.
    #[test]
    fn current_exe_is_a_write_probe_only() {
        let reads = lint_at(&parse(WILDCARD_READS), &[], &packaged());
        assert!(
            reads.iter().all(|f| !f.message.contains(FAKE_EXE)),
            "got {reads:#?}"
        );

        let writes = lint_at(&parse(SED_ALLOW), &[], &packaged());
        let naming_exe = writes
            .iter()
            .filter(|f| f.message.contains(FAKE_EXE))
            .count();
        assert_eq!(naming_exe, 1, "got {writes:#?}");
    }

    /// An exe equal to a packaged path is one target, not two.
    // Proves DI-39.
    #[test]
    fn exe_equal_to_a_packaged_path_is_not_duplicated() {
        let roots = Roots {
            exe: Some(PathBuf::from(PACKAGED_BINARY)),
            ..packaged()
        };
        let count = targets_at(&roots)
            .iter()
            .filter(|t| t.path == std::path::Path::new(PACKAGED_BINARY))
            .count();
        assert_eq!(count, 1);
    }
}
