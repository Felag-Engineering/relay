//! ADR-0018 layer 2 on a Template's `path` slot: before the command runs, the
//! daemon opens the value without blocking, refuses anything but a regular
//! file, and asks Policy again about the target the descriptor actually names,
//! handing the command that resolved path.
//!
//! Each test drives the production `ResolvedOp::invoke` of a compiled
//! `file.checksum` Template, the shipped catalog's path Template, with a real
//! Policy and a recording runner that spawns nothing. Invoke runs after the
//! dispatch gate, so these isolate layer 2: the aliases here are canonical in
//! form and would pass layer 1's precondition and an exact-path deny's string
//! compare.

#[path = "common/shell_runner.rs"]
mod shell_runner;

use std::sync::mpsc;
use std::sync::Mutex;
use std::time::Duration;

use relay_exec::executor::ExecRequest;
use relay_ops::operations::registry::{OpCtx, OpFuture, ResolvedOp, Runner};
use relay_ops::operations::template::{compile, RiskClassDef, SlotDef, SlotType, TemplateDef};
use relay_policy::Policy;
use relay_proto::{Operation, Outcome, TaskResult};
use shell_runner::path_fixtures;

/// Records every request it is handed and reports success without spawning.
#[derive(Default)]
struct Recording(Mutex<Vec<Vec<String>>>);

impl Recording {
    fn argvs(&self) -> Vec<Vec<String>> {
        self.0.lock().unwrap().clone()
    }
}

impl Runner for Recording {
    fn run(&self, req: ExecRequest) -> OpFuture<'static> {
        self.0.lock().unwrap().push(req.argv.clone());
        let task_id = req.task_id;
        Box::pin(async move {
            TaskResult {
                task_id,
                outcome: Outcome::Success as i32,
                ..Default::default()
            }
        })
    }
}

fn checksum_template() -> TemplateDef {
    TemplateDef {
        name: "file.checksum".to_string(),
        risk_class: RiskClassDef::Read,
        body: "sha256sum -- {{path}}".to_string(),
        slots: vec![SlotDef {
            name: "path".to_string(),
            ty: SlotType::Path,
        }],
    }
}

/// Any path, except an exact-path deny on `denied`: the shipped default
/// Policy's shape.
fn policy_denying(denied: &str) -> Policy {
    relay_policy::from_toml_str(&format!(
        r#"
[[operation]]
name = "file.checksum"
allowed_args = [["*"]]

[[deny]]
name = "file.checksum"
args = [["{denied}"]]
"#
    ))
    .expect("the policy parses")
}

/// Invokes `file.checksum` on `path` with a Task timeout of `timeout`.
async fn checksum(
    policy: &Policy,
    path: &str,
    timeout: Duration,
    runner: &Recording,
) -> TaskResult {
    let op = compile(&checksum_template()).expect("file.checksum compiles");
    let operation = Operation {
        name: "file.checksum".to_string(),
        args: [("path".to_string(), path.to_string())].into(),
    };
    op.invoke(OpCtx {
        task_id: "t-recheck".to_string(),
        positional: op.positional_args(&operation),
        timeout,
        max_output_bytes: 1 << 16,
        policy,
        cancel: None,
        runner,
    })
    .await
}

fn stderr(r: &TaskResult) -> String {
    String::from_utf8_lossy(&r.stderr).into_owned()
}

/// Runs `checksum` on its own thread and runtime, and fails if it does not
/// answer within five seconds although its Task timeout is a minute: a
/// regression to a blocking open then fails here instead of hanging the suite.
fn checksum_promptly(policy_denied: &str, path: &str) -> (TaskResult, usize) {
    let (policy_denied, path) = (policy_denied.to_string(), path.to_string());
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("build a test runtime");
        let runner = Recording::default();
        let policy = policy_denying(&policy_denied);
        let result = runtime.block_on(checksum(&policy, &path, Duration::from_secs(60), &runner));
        let _ = tx.send((result, runner.argvs().len()));
    });
    rx.recv_timeout(Duration::from_secs(5))
        .expect("the Template must answer promptly, not wait out its timeout")
}

#[tokio::test]
async fn a_proc_self_root_alias_of_a_denied_file_is_denied_by_policy() {
    let (_guard, root) = path_fixtures("recheck-proc-alias", &["/secret"]);
    let denied = format!("{root}/secret");
    let policy = policy_denying(&denied);
    let runner = Recording::default();

    // Control: the direct spelling resolves to itself and is denied.
    let direct = checksum(&policy, &denied, Duration::from_secs(5), &runner).await;
    assert_eq!(direct.outcome, Outcome::DeniedByPolicy as i32);

    let alias = format!("/proc/self/root{denied}");
    let r = checksum(&policy, &alias, Duration::from_secs(5), &runner).await;
    assert_eq!(
        r.outcome,
        Outcome::DeniedByPolicy as i32,
        "a /proc/self/root alias of a denied file must be denied; stderr={:?}",
        stderr(&r)
    );
    // One runner served both calls, so this covers the control and the alias.
    assert!(
        runner.argvs().is_empty(),
        "neither denied Task reaches the runner"
    );
}

#[tokio::test]
async fn a_symlink_to_a_denied_file_is_denied_by_policy() {
    let (_guard, root) = path_fixtures("recheck-symlink", &["/secret"]);
    let denied = format!("{root}/secret");
    let link = format!("{root}/innocent-link");
    std::os::unix::fs::symlink(&denied, &link).expect("create the symlink");
    let policy = policy_denying(&denied);
    let runner = Recording::default();

    let r = checksum(&policy, &link, Duration::from_secs(5), &runner).await;
    assert_eq!(
        r.outcome,
        Outcome::DeniedByPolicy as i32,
        "a symlink whose target is denied must be denied; stderr={:?}",
        stderr(&r)
    );
    assert!(
        runner.argvs().is_empty(),
        "a denied Task never reaches the runner"
    );
}

#[test]
fn a_fifo_is_refused_promptly() {
    let (_guard, root) = path_fixtures("recheck-fifo", &[]);
    let fifo = format!("{root}/fifo");
    let c_path = std::ffi::CString::new(fifo.clone()).expect("no NUL in the path");
    // SAFETY: `mkfifo` reads a NUL-terminated path that outlives the call and a
    // mode; no memory is shared or retained.
    let rc = unsafe { libc::mkfifo(c_path.as_ptr(), 0o600) };
    assert_eq!(rc, 0, "mkfifo: {}", std::io::Error::last_os_error());

    // A FIFO with no writer would block a plain open forever.
    let (r, runs) = checksum_promptly("/nothing-is-denied", &fifo);
    assert_eq!(
        r.outcome,
        Outcome::Failure as i32,
        "stderr={:?}",
        stderr(&r)
    );
    assert!(
        stderr(&r).contains("not a regular file"),
        "{:?}",
        stderr(&r)
    );
    assert_eq!(runs, 0, "a refused path never reaches the runner");
}

#[test]
fn a_character_device_is_refused_promptly() {
    let (r, runs) = checksum_promptly("/nothing-is-denied", "/dev/null");
    assert_eq!(
        r.outcome,
        Outcome::Failure as i32,
        "stderr={:?}",
        stderr(&r)
    );
    assert!(
        stderr(&r).contains("not a regular file"),
        "{:?}",
        stderr(&r)
    );
    assert_eq!(runs, 0, "a refused path never reaches the runner");
}

#[tokio::test]
async fn an_allowed_regular_file_runs() {
    let (_guard, root) = path_fixtures("recheck-allowed", &["/secret", "/notes"]);
    let policy = policy_denying(&format!("{root}/secret"));
    let runner = Recording::default();

    let notes = format!("{root}/notes");
    let r = checksum(&policy, &notes, Duration::from_secs(5), &runner).await;
    assert_eq!(
        r.outcome,
        Outcome::Success as i32,
        "stderr={:?}",
        stderr(&r)
    );
    let argvs = runner.argvs();
    assert_eq!(argvs.len(), 1);
    assert_eq!(argvs[0][4], notes);
}

#[tokio::test]
async fn the_command_receives_the_resolved_path_not_the_requested_spelling() {
    let (_guard, root) = path_fixtures("recheck-resolved", &["/secret", "/notes"]);
    let notes = format!("{root}/notes");
    let link = format!("{root}/notes-link");
    std::os::unix::fs::symlink(&notes, &link).expect("create the symlink");
    let policy = policy_denying(&format!("{root}/secret"));

    for requested in [link.clone(), format!("/proc/self/root{notes}")] {
        let runner = Recording::default();
        let r = checksum(&policy, &requested, Duration::from_secs(5), &runner).await;
        assert_eq!(
            r.outcome,
            Outcome::Success as i32,
            "stderr={:?}",
            stderr(&r)
        );
        let argvs = runner.argvs();
        assert_eq!(argvs.len(), 1);
        assert_eq!(
            argvs[0][4], notes,
            "{requested:?} must reach the command as its resolved target"
        );
        assert_ne!(argvs[0][4], requested);
    }
}
