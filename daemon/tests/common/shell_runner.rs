//! Runs a compiled Template through the production invoke and executor path
//! under a chosen real shell, for the tests that must see what a shell does
//! with a rendered argv.
//!
//! `ResolvedOp::invoke` renders the argv; [`ShellRunner`] then swaps the leading
//! `/bin/sh` for the shell under test and hands the request to
//! `relay_exec::executor::execute`, the same executor production uses. A shell
//! that is not installed fails the test: a skipped shell is not a passed shell.
#![allow(dead_code)]

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

use relay_exec::executor::{execute, ExecRequest};
use relay_exec::limits::ResourceLimits;
use relay_ops::operations::registry::{OpCtx, OpFuture, ResolvedOp, Runner};
use relay_ops::operations::template::{compile, RiskClassDef, SlotDef, SlotType, TemplateDef};
use relay_proto::{Operation, TaskResult};

/// A shell under test: a label for failure messages and the argv that starts it.
#[derive(Clone)]
pub struct Shell {
    pub label: &'static str,
    pub argv: Vec<String>,
}

fn installed(candidates: &[&str], name: &str) -> String {
    candidates
        .iter()
        .find(|p| Path::new(p).exists())
        .unwrap_or_else(|| panic!("{name} is not installed; the red-team suite requires it"))
        .to_string()
}

/// dash, bash, and bash in POSIX mode. Panics if one is missing.
pub fn shells() -> Vec<Shell> {
    let dash = installed(&["/usr/bin/dash", "/bin/dash"], "dash");
    let bash = installed(&["/usr/bin/bash", "/bin/bash"], "bash");
    vec![
        Shell {
            label: "dash",
            argv: vec![dash],
        },
        Shell {
            label: "bash",
            argv: vec![bash.clone()],
        },
        Shell {
            label: "bash --posix",
            argv: vec![bash, "--posix".to_string()],
        },
    ]
}

/// A [`Runner`] that executes a rendered Template argv under `shell`, optionally
/// with a fixed `PATH` (via `env`) so stub programs stand in for the real ones.
#[derive(Clone)]
pub struct ShellRunner {
    shell: Vec<String>,
    path: Option<PathBuf>,
}

impl ShellRunner {
    pub fn new(shell: &Shell) -> Self {
        ShellRunner {
            shell: shell.argv.clone(),
            path: None,
        }
    }

    pub fn with_path(shell: &Shell, path: &Path) -> Self {
        ShellRunner {
            shell: shell.argv.clone(),
            path: Some(path.to_path_buf()),
        }
    }
}

impl Runner for ShellRunner {
    fn run(&self, mut req: ExecRequest) -> OpFuture<'static> {
        assert_eq!(req.argv[0], "/bin/sh", "a Template always runs /bin/sh -c");
        let mut argv = Vec::new();
        if let Some(path) = &self.path {
            argv.push("/usr/bin/env".to_string());
            argv.push(format!("PATH={}", path.display()));
        }
        argv.extend(self.shell.iter().cloned());
        argv.extend(req.argv.drain(1..));
        req.argv = argv;
        Box::pin(execute(req))
    }
}

/// A one-slot `read` Template named `t.probe` whose slot `p` is a `Path`.
pub fn path_template(body: &str) -> TemplateDef {
    TemplateDef {
        name: "t.probe".to_string(),
        risk_class: RiskClassDef::Read,
        body: body.to_string(),
        slots: vec![SlotDef {
            name: "p".to_string(),
            ty: SlotType::Path,
        }],
    }
}

/// Compile `def` and invoke it through the production `ResolvedOp::invoke`.
pub async fn invoke(def: &TemplateDef, args: &[(&str, &str)], runner: &ShellRunner) -> TaskResult {
    let op = compile(def).unwrap_or_else(|e| panic!("{:?} must compile: {e}", def.body));
    let operation = Operation {
        name: def.name.clone(),
        args: args
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect::<HashMap<_, _>>(),
    };
    let positional = op.positional_args(&operation);
    let policy = relay_policy::from_toml_str("").expect("an empty Policy parses");
    op.invoke(OpCtx {
        task_id: "t-shell".to_string(),
        positional,
        timeout: Duration::from_secs(20),
        max_output_bytes: 1 << 16,
        policy: &policy,
        cancel: None,
        runner,
    })
    .await
}

/// Execute an arbitrary `/bin/sh -c`-shaped argv (`["/bin/sh", "-c", cmd, ..]`)
/// under the runner's shell. Used to run the retired rendering for comparison.
pub async fn run_sh_argv(runner: &ShellRunner, argv: Vec<String>) -> TaskResult {
    runner
        .run(ExecRequest {
            task_id: "t-retired".to_string(),
            argv,
            timeout: Duration::from_secs(20),
            max_output_bytes: 1 << 16,
            cancel: None,
            limits: ResourceLimits::DEFAULT,
        })
        .await
}

/// The retired rendering: POSIX single-quote each value and splice it over its
/// `{{name}}` placeholder. It models the mechanism the positional-parameter
/// rendering replaced, so tests can show the old behaviour on the same inputs.
pub fn retired_splice(body: &str, values: &[(&str, &str)]) -> String {
    let mut cmd = body.to_string();
    for (name, value) in values {
        let quoted = format!("'{}'", value.replace('\'', "'\\''"));
        cmd = cmd.replace(&format!("{{{{{name}}}}}"), &quoted);
    }
    cmd
}

pub fn stdout(r: &TaskResult) -> String {
    String::from_utf8_lossy(&r.stdout).into_owned()
}

pub fn stderr(r: &TaskResult) -> String {
    String::from_utf8_lossy(&r.stderr).into_owned()
}
