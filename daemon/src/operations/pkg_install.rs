//! `pkg.install` Operation — installs a package via the system package manager:
//! `["apt-get", "install", "-y", <pkgspec>]` (Debian/Ubuntu) or
//! `["dnf"|"yum", "install", "-y", <pkgspec>]` (Fedora/RHEL/CentOS).
//!
//! The package name and (optional) version are each **validated against a
//! strict charset before any argv is built** — the argument can never change
//! which command runs (ADR-0001). An unsupported distro (no apt-get/dnf/yum
//! found) yields a structured `OUTCOME_FAILURE`, never a panic.
//!
//! `install_argv` is the pure primary test seam: tests call it directly to
//! assert the exact argv without spawning a package manager. The async
//! `pkg_install_with_manager` accepts an injectable `run` closure and an
//! injectable `mgr: Option<PackageManager>` so the apt/dnf/yum/unsupported
//! paths are all testable without touching a real package manager.
//!
//! KNOWN LIMITATION: only `-y` (non-interactive) is passed; `DEBIAN_FRONTEND=
//! noninteractive` is deferred — `ExecRequest` has no env field (out of scope
//! for this issue). KNOWN LIMITATION: the dnf/yum `name-version` pkgspec is a
//! simplification of full NEVRA syntax — harmless, since it is never exec'd in
//! CI (all executor-touching tests inject a fake runner).

use std::path::Path;
use std::time::Duration;

use tokio::sync::oneshot;

use crate::executor::ExecRequest;
use crate::gen::{Outcome, TaskResult};

/// The system package manager, detected by which binary is present on the Node.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PackageManager {
    Apt,
    Dnf,
    Yum,
}

impl PackageManager {
    /// The argv[0] program name for this package manager.
    fn command(self) -> &'static str {
        match self {
            PackageManager::Apt => "apt-get",
            PackageManager::Dnf => "dnf",
            PackageManager::Yum => "yum",
        }
    }
}

/// Validates that `name` is a safe package name.
///
/// 1. Rejects empty strings.
/// 2. Requires the name to *start and end* with an alphanumeric character.
///    A leading `-` (e.g. `--reinstall`) is an option to the package manager
///    itself, not a package name — argv does not prevent option injection.
///    A trailing `-` or `+` is a per-package action modifier to apt
///    (`apt-get install foo-` REMOVES `foo`; `foo+` marks it for install) —
///    an interior-only charset would let an argument change which action
///    runs, violating ADR-0001 invariant 1. Debian/RPM package names never
///    legitimately start or end with `-`, `+`, `.`, or `_` anyway.
/// 3. Rejects any interior character outside `[A-Za-z0-9+._-]`. Notably
///    excludes `=` so a name can never smuggle an apt `name=version`
///    pkgspec separator.
///
/// `pub(crate)`: also called directly by `operations::schema`'s exhaustive
/// byte-space proof test, which binds the schema's independently-declared
/// charset to this real validator (ADR-0015) without rewriting it.
pub(crate) fn validate_pkg_name(name: &str) -> Result<(), super::OperationError> {
    let invalid = || Err(super::OperationError::InvalidPackageName(name.to_string()));

    let Some(first) = name.chars().next() else {
        return invalid();
    };
    if !first.is_ascii_alphanumeric() {
        return invalid();
    }
    // `unwrap` is safe: `first` above proves `name` is non-empty.
    let last = name.chars().next_back().unwrap();
    if !last.is_ascii_alphanumeric() {
        return invalid();
    }
    if !name
        .chars()
        .all(|c| matches!(c, 'A'..='Z' | 'a'..='z' | '0'..='9' | '+' | '.' | '_' | '-'))
    {
        return invalid();
    }
    Ok(())
}

/// Validates that `version` is a safe package version.
///
/// Interior characters allow a charset wide enough for real version strings
/// (epoch, tilde pre-release suffixes): `[A-Za-z0-9+._:~-]`. But the *first
/// and last* characters must be alphanumeric (`[A-Za-z0-9]`) — apt strips a
/// trailing `+`/`-` modifier off the whole `name=version` token before
/// splitting on `=`, so a version like `1.0-` turns `nginx=1.0-` into a
/// REMOVE of `nginx`, and a leading `-` risks option injection. This is the
/// same install→remove flip [`validate_pkg_name`] closes on the name side,
/// now closed on the version side.
///
/// `pub(crate)`: also called directly by `operations::schema`'s exhaustive
/// byte-space proof test, which binds the schema's independently-declared
/// charset to this real validator (ADR-0015) without rewriting it.
pub(crate) fn validate_pkg_version(version: &str) -> Result<(), super::OperationError> {
    let invalid = || {
        Err(super::OperationError::InvalidPackageVersion(
            version.to_string(),
        ))
    };

    let Some(first) = version.chars().next() else {
        return invalid();
    };
    if !first.is_ascii_alphanumeric() {
        return invalid();
    }
    // `unwrap` is safe: `first` above proves `version` is non-empty.
    let last = version.chars().next_back().unwrap();
    if !last.is_ascii_alphanumeric() {
        return invalid();
    }
    if !version
        .chars()
        .all(|c| matches!(c, 'A'..='Z' | 'a'..='z' | '0'..='9' | '+' | '.' | ':' | '~' | '_' | '-'))
    {
        return invalid();
    }
    Ok(())
}

/// Validates `name` (and `version`, if present) and returns the exact argv for
/// `<mgr> install -y <pkgspec>`.
///
/// This is the **primary test seam** — tested directly and never executes.
/// Validation always runs BEFORE the pkgspec is built (ADR-0001 invariant #1):
/// an invalid name or version returns `Err` with no argv constructed.
///
/// pkgspec shape: Apt uses `name` or `name=version`; Dnf/Yum use `name` or
/// `name-version` (a simplification of full NEVRA — see module docs).
pub fn install_argv(
    mgr: PackageManager,
    name: &str,
    version: Option<&str>,
) -> Result<Vec<String>, super::OperationError> {
    validate_pkg_name(name)?;
    if let Some(v) = version {
        validate_pkg_version(v)?;
    }

    let pkgspec = match (mgr, version) {
        (PackageManager::Apt, Some(v)) => format!("{name}={v}"),
        (PackageManager::Apt, None) => name.to_string(),
        (PackageManager::Dnf | PackageManager::Yum, Some(v)) => format!("{name}-{v}"),
        (PackageManager::Dnf | PackageManager::Yum, None) => name.to_string(),
    };

    Ok(vec![
        mgr.command().to_string(),
        "install".to_string(),
        "-y".to_string(),
        pkgspec,
    ])
}

/// Detects the system package manager by binary presence — no process spawned.
///
/// Prefers apt-get, then dnf, then yum. Returns `None` when no supported
/// binary is present (unsupported distro).
pub fn detect_package_manager() -> Option<PackageManager> {
    if Path::new("/usr/bin/apt-get").exists() {
        Some(PackageManager::Apt)
    } else if Path::new("/usr/bin/dnf").exists() {
        Some(PackageManager::Dnf)
    } else if Path::new("/usr/bin/yum").exists() {
        Some(PackageManager::Yum)
    } else {
        None
    }
}

/// Validates `name`/`version` against `mgr`, builds the argv, and delegates
/// execution to `run`. Injectable core: `mgr` and `run` are both parameters,
/// so apt, dnf, yum, and the unsupported-distro path are all unit-testable
/// without touching a real package manager.
///
/// `mgr: None` (no supported package manager detected) short-circuits to
/// `OUTCOME_FAILURE(UnsupportedPackageManager)` — `run` is **never called**,
/// no process spawned, no panic.
///
/// `cancel` is threaded into the [`ExecRequest`] so the executor can kill the
/// process group on an in-flight cancel signal (ADR-0013). If `mgr` is `None`
/// or the name/version fails validation, `cancel` is dropped (no process
/// spawned) and `run` is **never called**.
#[allow(clippy::too_many_arguments)]
pub async fn pkg_install_with_manager<F, Fut>(
    task_id: String,
    mgr: Option<PackageManager>,
    name: &str,
    version: Option<&str>,
    timeout: Duration,
    max_output_bytes: usize,
    cancel: Option<oneshot::Receiver<()>>,
    run: F,
) -> TaskResult
where
    F: FnOnce(ExecRequest) -> Fut,
    Fut: std::future::Future<Output = TaskResult>,
{
    let Some(mgr) = mgr else {
        // cancel drops naturally here — unsupported distro, no process spawned.
        return TaskResult {
            task_id,
            outcome: Outcome::Failure as i32,
            exit_code: -1,
            stdout: vec![],
            stderr: super::OperationError::UnsupportedPackageManager
                .to_string()
                .into_bytes(),
            truncated: false,
            duration_millis: 0,
        };
    };

    let argv = match install_argv(mgr, name, version) {
        Ok(v) => v,
        Err(e) => {
            // cancel drops naturally here — invalid name/version, no process spawned.
            return TaskResult {
                task_id,
                outcome: Outcome::Failure as i32,
                exit_code: -1,
                stdout: vec![],
                stderr: e.to_string().into_bytes(),
                truncated: false,
                duration_millis: 0,
            };
        }
    };

    let req = ExecRequest {
        task_id,
        argv,
        timeout,
        max_output_bytes,
        cancel,
    };
    run(req).await
}

/// Production entry point: detects the package manager, then delegates to
/// [`pkg_install_with_manager`]. Signature mirrors
/// [`crate::operations::service_restart::service_restart`].
pub async fn pkg_install<F, Fut>(
    task_id: String,
    name: &str,
    version: Option<&str>,
    timeout: Duration,
    max_output_bytes: usize,
    cancel: Option<oneshot::Receiver<()>>,
    run: F,
) -> TaskResult
where
    F: FnOnce(ExecRequest) -> Fut,
    Fut: std::future::Future<Output = TaskResult>,
{
    pkg_install_with_manager(
        task_id,
        detect_package_manager(),
        name,
        version,
        timeout,
        max_output_bytes,
        cancel,
        run,
    )
    .await
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    };

    // -----------------------------------------------------------------------
    // install_argv: exact argv (ACCEPTANCE-CRITICAL)
    // -----------------------------------------------------------------------

    #[test]
    fn install_argv_apt_no_version_exact() {
        let argv = install_argv(PackageManager::Apt, "nginx", None).unwrap();
        assert_eq!(
            argv,
            ["apt-get", "install", "-y", "nginx"],
            "install_argv(Apt, nginx, None) must produce exactly [apt-get, install, -y, nginx]"
        );
    }

    #[test]
    fn install_argv_apt_with_version_exact() {
        let argv = install_argv(PackageManager::Apt, "nginx", Some("1.18.0")).unwrap();
        assert_eq!(
            argv,
            ["apt-get", "install", "-y", "nginx=1.18.0"],
            "apt pkgspec with version must be name=version"
        );
    }

    #[test]
    fn install_argv_dnf_no_version_exact() {
        let argv = install_argv(PackageManager::Dnf, "nginx", None).unwrap();
        assert_eq!(argv, ["dnf", "install", "-y", "nginx"]);
    }

    #[test]
    fn install_argv_dnf_with_version_exact() {
        let argv = install_argv(PackageManager::Dnf, "nginx", Some("1.18.0")).unwrap();
        assert_eq!(
            argv,
            ["dnf", "install", "-y", "nginx-1.18.0"],
            "dnf pkgspec with version must be name-version"
        );
    }

    #[test]
    fn install_argv_yum_no_version_exact() {
        let argv = install_argv(PackageManager::Yum, "nginx", None).unwrap();
        assert_eq!(argv, ["yum", "install", "-y", "nginx"]);
    }

    #[test]
    fn install_argv_yum_with_version_exact() {
        let argv = install_argv(PackageManager::Yum, "nginx", Some("1.18.0")).unwrap();
        assert_eq!(
            argv,
            ["yum", "install", "-y", "nginx-1.18.0"],
            "yum pkgspec with version must be name-version"
        );
    }

    // -----------------------------------------------------------------------
    // install_argv: valid name/version acceptance set
    // -----------------------------------------------------------------------

    #[test]
    fn install_argv_accepts_valid_names() {
        // NOTE: real Debian package "g++" is intentionally NOT in this list —
        // it ends in `+`, which the trailing-modifier fix below now rejects.
        for name in &["nginx", "curl", "php-fpm", "lib_foo", "libc6.1", "a"] {
            assert!(
                install_argv(PackageManager::Apt, name, None).is_ok(),
                "expected Ok for valid package name {:?}",
                name
            );
        }
    }

    #[test]
    fn install_argv_accepts_valid_versions() {
        for version in &["2.3", "1:2.3~beta", "1.0-2", "1"] {
            assert!(
                install_argv(PackageManager::Apt, "nginx", Some(version)).is_ok(),
                "expected Ok for valid package version {:?}",
                version
            );
        }
    }

    // -----------------------------------------------------------------------
    // install_argv: invalid name rejection set (→ Err(InvalidPackageName))
    // -----------------------------------------------------------------------

    #[test]
    fn install_argv_rejects_invalid_names() {
        let bad = [
            "",                // empty
            "--force",         // leading dash / option injection
            "nginx; rm -rf /", // semicolon + shell metacharacters
            "$(reboot)",       // command substitution
            "`id`",            // backtick substitution
            "a b",             // whitespace
            "a/b",             // path separator
            "nginx=evil",      // apt name=version separator injection
            "a\nb",            // newline
            "nginx-",          // trailing dash: apt "install foo-" REMOVES foo
            "nginx+",          // trailing plus: apt per-package install modifier
            "a-",              // trailing dash, single leading alnum
            "-nginx",          // leading dash / option injection
            "nginx.",          // trailing dot
            "_nginx",          // leading underscore
        ];
        for name in &bad {
            assert!(
                install_argv(PackageManager::Apt, name, None).is_err(),
                "expected Err(InvalidPackageName) for {:?}",
                name
            );
        }
    }

    // -----------------------------------------------------------------------
    // install_argv: invalid version rejection set (→ Err(InvalidPackageVersion))
    // -----------------------------------------------------------------------

    #[test]
    fn install_argv_rejects_invalid_versions() {
        let bad = [
            "",              // empty
            "-force",        // leading dash / option injection
            "1.0; rm -rf /", // semicolon + shell metacharacters
            "$(reboot)",     // command substitution
            "a b",           // whitespace
            "1.0-",          // trailing dash: apt "install foo=1.0-" REMOVES foo
            "1.0+",          // trailing plus: apt per-package install modifier
            "1.0~",          // trailing tilde: not alphanumeric
            ":1.0",          // leading colon: not alphanumeric
        ];
        for version in &bad {
            assert!(
                install_argv(PackageManager::Apt, "nginx", Some(version)).is_err(),
                "expected Err(InvalidPackageVersion) for {:?}",
                version
            );
        }
    }

    // -----------------------------------------------------------------------
    // fake-runner: records argv, returns canned Success, never spawns a real
    // package manager
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn fake_runner_records_argv_and_never_spawns() {
        let recorded = Arc::new(Mutex::new(Vec::<String>::new()));
        let rec = recorded.clone();

        let result = pkg_install_with_manager(
            "t1".to_string(),
            Some(PackageManager::Apt),
            "nginx",
            None,
            Duration::from_secs(5),
            1024,
            None, // cancel: uncancellable in tests
            move |req| {
                *rec.lock().unwrap() = req.argv.clone();
                let task_id = req.task_id.clone();
                async move {
                    TaskResult {
                        task_id,
                        outcome: Outcome::Success as i32,
                        exit_code: 0,
                        stdout: vec![],
                        stderr: vec![],
                        truncated: false,
                        duration_millis: 0,
                    }
                }
            },
        )
        .await;

        assert_eq!(
            *recorded.lock().unwrap(),
            ["apt-get", "install", "-y", "nginx"],
            "fake runner must receive exactly [apt-get, install, -y, nginx]"
        );
        assert_eq!(
            result.outcome,
            Outcome::Success as i32,
            "canned Success must be returned"
        );
    }

    // -----------------------------------------------------------------------
    // short-circuit: invalid name → Failure, runner never called
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn short_circuit_on_invalid_name() {
        let runner_called = Arc::new(AtomicBool::new(false));
        let called = runner_called.clone();

        let result = pkg_install_with_manager(
            "t2".to_string(),
            Some(PackageManager::Apt),
            "bad;name",
            None,
            Duration::from_secs(5),
            1024,
            None, // cancel: uncancellable in tests
            move |req| {
                called.store(true, Ordering::SeqCst);
                let task_id = req.task_id.clone();
                async move {
                    TaskResult {
                        task_id,
                        outcome: Outcome::Success as i32,
                        exit_code: 0,
                        stdout: vec![],
                        stderr: vec![],
                        truncated: false,
                        duration_millis: 0,
                    }
                }
            },
        )
        .await;

        assert!(
            !runner_called.load(Ordering::SeqCst),
            "runner must not be called when the package name is invalid"
        );
        assert_eq!(
            result.outcome,
            Outcome::Failure as i32,
            "invalid package name must yield OUTCOME_FAILURE"
        );
        assert_eq!(result.exit_code, -1);
        assert!(
            !result.stderr.is_empty(),
            "stderr must contain the validation error"
        );
    }

    // -----------------------------------------------------------------------
    // short-circuit: no supported package manager → Failure, runner never
    // called, no panic
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn short_circuit_on_unsupported_package_manager() {
        let runner_called = Arc::new(AtomicBool::new(false));
        let called = runner_called.clone();

        let result = pkg_install_with_manager(
            "t3".to_string(),
            None, // no supported package manager detected
            "nginx",
            None,
            Duration::from_secs(5),
            1024,
            None, // cancel: uncancellable in tests
            move |req| {
                called.store(true, Ordering::SeqCst);
                let task_id = req.task_id.clone();
                async move {
                    TaskResult {
                        task_id,
                        outcome: Outcome::Success as i32,
                        exit_code: 0,
                        stdout: vec![],
                        stderr: vec![],
                        truncated: false,
                        duration_millis: 0,
                    }
                }
            },
        )
        .await;

        assert!(
            !runner_called.load(Ordering::SeqCst),
            "runner must not be called when no package manager is supported"
        );
        assert_eq!(
            result.outcome,
            Outcome::Failure as i32,
            "unsupported package manager must yield OUTCOME_FAILURE, not a panic"
        );
        assert_eq!(result.exit_code, -1);
        assert!(
            !result.stderr.is_empty(),
            "stderr must explain the unsupported-package-manager failure"
        );
    }

    // -----------------------------------------------------------------------
    // detect_package_manager: smoke test — never panics, returns Some or None
    // -----------------------------------------------------------------------

    #[test]
    fn detect_package_manager_does_not_panic() {
        // Whatever this dev/CI box has (or doesn't have) installed, detection
        // must complete without panicking and return a well-formed Option.
        let _ = detect_package_manager();
    }
}
