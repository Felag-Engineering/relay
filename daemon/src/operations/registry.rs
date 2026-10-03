//! The single Operation-vocabulary registry: `name → (handler, arg-shape,
//! risk class)` (issue #289; ADR-0001, ADR-0012, ADR-0015).
//!
//! [`REGISTRY`] is the one table every consumer of the vocabulary reads:
//!
//! - **dispatch** (`dispatch.rs`) resolves an inbound `Operation` to its
//!   [`OpRegistration`] and invokes its `handler` — no per-name match arms;
//! - **arg mapping** ([`OpRegistration::positional_args`]) derives the
//!   named-args → positional mapping from the entry's declared arg-shape,
//!   feeding both Policy evaluation and execution (ADR-0011: one mapping,
//!   no drift between "would allow" and "actually allows");
//! - **risk class** ([`super::risk_class`]) is a registry lookup (ADR-0012);
//! - **vocabulary discovery** ([`super::descriptors`] and
//!   [`super::schema::schemas`] — the ADR-0015 golden-schema source) derives
//!   from the same entries, in the same canonical order.
//!
//! Adding an Operation is therefore a *registration* — one [`OpRegistration`]
//! appended here (plus its arg-shape in `schema.rs` and, for charset-validated
//! args, the ADR-0015 proof-test binding) — with no dispatch edits. This is
//! the prerequisite seam for the v0.2.0 template tier, which registers
//! Template Operations instead of growing match arms.
//!
//! **Raw Exec** ([`RAW_EXEC`]) resolves through the same entry type and the
//! same handler-invocation seam, but is deliberately **not** in the by-name
//! table: it is reachable only from the `TaskRequest`/`PolicyQuery` protocol
//! oneof arm, never as an `Operation` name. A wire `Operation` literally named
//! `"raw_exec"` therefore stays an *unknown name* — deny-by-default — exactly
//! as before this registry existed (the restrictive option).

use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

use tokio::sync::oneshot;

use super::schema::{self, ArgSpec};
use crate::executor::ExecRequest;
use crate::gen::{Operation, Outcome, RawExec, RiskClass, TaskResult};
use crate::operations::file_read::{file_read, PathCheck};
use crate::operations::pkg_install::pkg_install;
use crate::operations::service_restart::service_restart;
use crate::operations::system_facts::{format_facts_as_kv, gather_facts};
use crate::policy::{Decision, Policy};
use crate::raw_exec::run_raw_exec;

// ---------------------------------------------------------------------------
// Handler plumbing
// ---------------------------------------------------------------------------

/// The boxed future an Operation handler (or [`Runner`]) returns.
///
/// `Send` because the whole dispatch pipeline runs inside `tokio::spawn`
/// (main.rs tunnel loop).
pub type OpFuture<'a> = Pin<Box<dyn Future<Output = TaskResult> + Send + 'a>>;

/// An Operation handler: a plain `fn` pointer (so the registry can be a
/// `static` table) from an [`OpCtx`] to the Task's result.
pub type Handler = for<'a> fn(OpCtx<'a>) -> OpFuture<'a>;

/// Everything a handler may use, assembled by dispatch AFTER the Policy gate
/// has allowed the action (Raw Exec excepted: its regex gate lives inside
/// `run_raw_exec`, unchanged).
pub struct OpCtx<'a> {
    /// The Task's unique id, echoed into the returned [`TaskResult`].
    pub task_id: String,
    /// The positional arg vector ([`OpRegistration::positional_args`]) — the
    /// exact vector the Policy engine evaluated. For [`RAW_EXEC`] this
    /// carries the raw argv verbatim instead.
    pub positional: Vec<String>,
    /// Remaining wall-clock budget (single clock from receipt, ADR-0004).
    pub timeout: Duration,
    /// Per-stream output byte cap (ADR-0004), decided at the dispatch layer.
    pub max_output_bytes: usize,
    /// The loaded Policy — read-only (ADR-0002). Needed by `file.read`'s
    /// resolved-path re-check (ADR-0018 layer 2) and Raw Exec's regex gate.
    pub policy: &'a Policy,
    /// In-flight cancel receiver (ADR-0013); handlers that spawn no process
    /// drop it naturally.
    pub cancel: Option<oneshot::Receiver<()>>,
    /// The process-spawning seam: [`crate::executor::execute`] in production,
    /// a recording fake in tests (type-erased so handlers can live in a
    /// `static` table while dispatch stays generic for test injection).
    pub runner: &'a dyn Runner,
}

/// Type-erased process-runner seam (the `run` closure of dispatch, made
/// object-safe so [`Handler`] fn pointers can call it).
///
/// `Sync` because the handler future holding `&dyn Runner` must stay `Send`.
pub trait Runner: Sync {
    fn run(&self, req: ExecRequest) -> OpFuture<'static>;
}

/// Adapts any `Fn(ExecRequest) -> Future<TaskResult>` closure (the existing
/// dispatch test seam, and `executor::execute` itself) into a [`Runner`].
pub struct FnRunner<F>(pub F);

impl<F, Fut> Runner for FnRunner<F>
where
    F: Fn(ExecRequest) -> Fut + Sync,
    Fut: Future<Output = TaskResult> + Send + 'static,
{
    fn run(&self, req: ExecRequest) -> OpFuture<'static> {
        Box::pin((self.0)(req))
    }
}

// ---------------------------------------------------------------------------
// The registration record
// ---------------------------------------------------------------------------

/// One Operation's registration: `name → (handler, arg-shape, risk class)`.
///
/// `Copy` (all fields are `'static` references, a fieldless-enum value, or a
/// `fn` pointer) so tests can extend a copy of the table without touching the
/// production `static`.
#[derive(Clone, Copy)]
pub struct OpRegistration {
    /// Wire name (`Operation.name`).
    pub name: &'static str,
    /// ADR-0012 risk class. Blast-radius classification only — never a Policy
    /// substitute. Misclassification is security-relevant.
    pub risk: RiskClass,
    /// Declared arg-shape, in positional order — the same [`ArgSpec`] rows the
    /// ADR-0015 golden schema is generated from (single source of truth).
    pub args: &'static [ArgSpec],
    /// The execution entry point, invoked by dispatch after the Policy gate.
    pub handler: Handler,
}

// ---------------------------------------------------------------------------
// The uniform resolution contract — `name → (handler, arg-shape, risk class)`
// as a trait, so the vocabulary can hold BOTH the static Native Operations and
// the runtime-loaded Template Operations behind one lookup (issue #290, ADR-0021).
// ---------------------------------------------------------------------------

/// The behavior dispatch needs from a resolved vocabulary entry, independent of
/// whether it is a Native Operation ([`OpRegistration`], a `'static` `fn`-pointer
/// handler) or a Template Operation
/// ([`crate::operations::template::TemplateOp`], a runtime value carrying a
/// compiled shell template).
///
/// Dispatch's Policy gate + handler invocation
/// ([`crate::dispatch`]'s `gate_and_invoke`) is written once against
/// `&dyn ResolvedOp`, so:
///
/// - **Policy parity is structural**: both kinds derive their positional args
///   through [`ResolvedOp::positional_args`] and are gated by the same
///   `policy.evaluate(name, positional)` call — a Template Operation is denied,
///   allowed, and argument-constrained exactly like a Native Operation
///   (deny-by-default, deny-beats-allow), because the Policy engine is
///   name-agnostic and there is only one gate.
/// - **Adding a template is a registration, not a dispatch edit**: a new
///   `TemplateOp` implements this trait and resolves through the same lookup —
///   no per-name match arm (the #310 seam, extended; proven by the structural
///   test in dispatch.rs).
///
/// `Send + Sync` because a resolved entry is borrowed across the `.await` inside
/// `tokio::spawn` (the tunnel loop).
pub trait ResolvedOp: Send + Sync {
    /// The wire/Policy name. Part of the resolved contract; consumed by the
    /// per-Node vocabulary discovery and classification (issue #291).
    fn name(&self) -> &str;
    /// ADR-0012 risk class — the third element of `name → (handler, arg-shape,
    /// risk class)`. Consumed by the per-Node scheduler classification
    /// (`scheduler::Scheduler::classify`) and by discovery; native dispatch
    /// reads the concrete `OpRegistration::risk` field directly.
    fn risk(&self) -> RiskClass;
    /// Named-args → positional vector, in the entry's declared order. MUST be
    /// the exact vector Policy evaluates (ADR-0011: no drift between "would
    /// allow" and "actually allows").
    fn positional_args(&self, op: &Operation) -> Vec<String>;
    /// Positions of `path`-typed arguments, which the dispatch gate holds to
    /// ADR-0018's canonical-form precondition before Policy evaluates them
    /// (issue #293).
    ///
    /// Empty by default. Native Operations return empty because the engine
    /// already applies the precondition to `file.read` by name — the one
    /// native path argument; Template Operations report their `path` slots, so
    /// an exact-path deny holds against non-canonical spellings there too.
    fn path_arg_positions(&self) -> Vec<usize> {
        Vec::new()
    }
    /// Execute, AFTER the Policy gate has allowed the action. For a Native
    /// Operation this is its `fn`-pointer handler; for a Template Operation it
    /// validates + quotes the parameters and runs the rendered `/bin/sh -c`.
    fn invoke<'a>(&'a self, ctx: OpCtx<'a>) -> OpFuture<'a>;
}

impl ResolvedOp for OpRegistration {
    fn name(&self) -> &str {
        self.name
    }

    fn risk(&self) -> RiskClass {
        self.risk
    }

    fn positional_args(&self, op: &Operation) -> Vec<String> {
        // Delegate to the inherent method (the single mapping definition).
        OpRegistration::positional_args(self, op)
    }

    fn invoke<'a>(&'a self, ctx: OpCtx<'a>) -> OpFuture<'a> {
        (self.handler)(ctx)
    }
}

impl OpRegistration {
    /// Maps an `Operation`'s named args to the positional vector the Policy
    /// engine expects, in this entry's declared arg order; a missing key maps
    /// to `""` (matched by a Policy `"*"` wildcard rule).
    ///
    /// This is the **single definition** of the arg-map → positional mapping:
    /// both the execution path (`dispatch::handle_operation`) and the query
    /// path (`dispatch::evaluate_policy_query`) derive args through it, so a
    /// PolicyQuery verdict can never diverge from what dispatch decides
    /// (ADR-0011).
    pub fn positional_args(&self, op: &Operation) -> Vec<String> {
        self.args
            .iter()
            .map(|a| op.args.get(a.key).cloned().unwrap_or_default())
            .collect()
    }
}

// ---------------------------------------------------------------------------
// The table
// ---------------------------------------------------------------------------

/// The v1 Operation vocabulary, in canonical order (the ADR-0015 golden-schema
/// order). A reviewer can verify every name→(handler, arg-shape, risk class)
/// mapping here in one place.
pub static REGISTRY: [OpRegistration; 4] = [
    OpRegistration {
        name: super::SYSTEM_FACTS,
        risk: RiskClass::Read,
        args: &schema::SYSTEM_FACTS_ARGS,
        handler: system_facts_handler,
    },
    OpRegistration {
        name: super::FILE_READ,
        risk: RiskClass::Read,
        args: &schema::FILE_READ_ARGS,
        handler: file_read_handler,
    },
    OpRegistration {
        name: super::SERVICE_RESTART,
        risk: RiskClass::Mutate,
        args: &schema::SERVICE_RESTART_ARGS,
        handler: service_restart_handler,
    },
    OpRegistration {
        name: super::PKG_INSTALL,
        risk: RiskClass::Mutate,
        args: &schema::PKG_INSTALL_ARGS,
        handler: pkg_install_handler,
    },
];

/// The Raw Exec entry — same record type and handler seam as the native
/// Operations, but **never** part of the by-name table (see module doc): it is
/// resolved only from the `TaskRequest` protocol oneof arm. Always
/// `RiskClass::Mutate` (ADR-0012 — arbitrary commands take the strict lane by
/// definition; pinned by test below).
pub static RAW_EXEC: OpRegistration = OpRegistration {
    name: "raw_exec",
    risk: RiskClass::Mutate,
    args: &[],
    handler: raw_exec_handler,
};

/// Looks up a name in the production [`REGISTRY`].
pub fn lookup(name: &str) -> Option<&'static OpRegistration> {
    lookup_in(&REGISTRY, name)
}

/// Looks up a name in an explicit entry slice — the seam the structural test
/// (dispatch.rs) uses to prove a new Operation needs only a registration.
/// Production callers go through [`lookup`], which binds [`REGISTRY`].
pub fn lookup_in<'r>(entries: &'r [OpRegistration], name: &str) -> Option<&'r OpRegistration> {
    entries.iter().find(|e| e.name == name)
}

// ---------------------------------------------------------------------------
// Handlers — the bodies formerly inlined as dispatch.rs match arms, moved
// verbatim (issue #289 pure refactor; no behavior change).
// ---------------------------------------------------------------------------

// The data-only Natives (`system.facts`, `file.read`) spawn no process, but
// their work is blocking syscalls — file reads, getifaddrs(3) — that a hung
// mount can stall indefinitely. They run that work on the blocking pool
// (`run_blocking`), never on a tokio worker thread the tunnel and heartbeat
// share, and bound it by the Task's remaining wall-clock budget
// (`within_task_timeout`, ADR-0004). Cancel is irrelevant to them: there is no
// process group to kill, and the receiver drops with the context.

fn system_facts_handler(ctx: OpCtx<'_>) -> OpFuture<'_> {
    Box::pin(async move {
        let OpCtx {
            task_id, timeout, ..
        } = ctx;
        let work = async {
            let stdout = run_blocking(|| format_facts_as_kv(&gather_facts())).await;
            TaskResult {
                task_id: task_id.clone(),
                outcome: Outcome::Success as i32,
                exit_code: 0,
                stdout,
                stderr: vec![],
                truncated: false,
                duration_millis: 0,
            }
        };
        within_task_timeout(&task_id, timeout, work).await
    })
}

fn file_read_handler(ctx: OpCtx<'_>) -> OpFuture<'_> {
    Box::pin(async move {
        let OpCtx {
            task_id,
            positional,
            timeout,
            max_output_bytes,
            policy,
            ..
        } = ctx;
        let path = positional.into_iter().next().unwrap_or_default();
        // ADR-0018 layer 2: file_read resolves the target it opens and calls
        // back here to re-evaluate Policy on the RESOLVED path, closing
        // `/proc`-magic and symlink evasions that are canonical in form and
        // so pass layer 1.
        let work = file_read(
            task_id.clone(),
            path,
            max_output_bytes,
            |resolved| match policy.evaluate(super::FILE_READ, &[resolved.to_string()]) {
                Decision::Deny { reason, .. } => PathCheck::Denied(reason),
                Decision::Allow(_) => PathCheck::Allowed,
            },
        );
        within_task_timeout(&task_id, timeout, work).await
    })
}

/// Runs blocking work on tokio's blocking pool and returns its value, keeping
/// it off the async worker threads (see the data-only Natives above).
///
/// A panic in `work` is resumed on the caller, exactly as if `work` had run
/// inline. The blocking pool only fails to run `work` when the runtime is
/// shutting down, which takes the Task with it.
pub(crate) async fn run_blocking<T, F>(work: F) -> T
where
    F: FnOnce() -> T + Send + 'static,
    T: Send + 'static,
{
    match tokio::task::spawn_blocking(work).await {
        Ok(value) => value,
        Err(err) => match err.try_into_panic() {
            Ok(panic) => std::panic::resume_unwind(panic),
            Err(err) => panic!("blocking work did not run: {err}"),
        },
    }
}

/// Bounds a data-only Native's `work` by the Task's remaining wall-clock
/// budget (ADR-0004).
///
/// On expiry the Task reports `OUTCOME_TIMEOUT` with exit code `-1` and no
/// output — the outcome a timed-out command reports. The blocking syscall
/// itself cannot be interrupted, so its blocking-pool thread stays occupied
/// until the kernel returns; but the Task, its concurrency permit and the
/// async worker threads are all released on time.
async fn within_task_timeout(
    task_id: &str,
    timeout: Duration,
    work: impl Future<Output = TaskResult>,
) -> TaskResult {
    let started = tokio::time::Instant::now();
    match tokio::time::timeout(timeout, work).await {
        Ok(result) => result,
        Err(_elapsed) => TaskResult {
            task_id: task_id.to_string(),
            outcome: Outcome::Timeout as i32,
            exit_code: -1,
            stdout: vec![],
            stderr: vec![],
            truncated: false,
            duration_millis: started.elapsed().as_millis() as i64,
        },
    }
}

fn service_restart_handler(ctx: OpCtx<'_>) -> OpFuture<'_> {
    Box::pin(async move {
        let OpCtx {
            task_id,
            positional,
            timeout,
            max_output_bytes,
            cancel,
            runner,
            ..
        } = ctx;
        let unit = positional.into_iter().next().unwrap_or_default();
        service_restart(task_id, &unit, timeout, max_output_bytes, cancel, |req| {
            runner.run(req)
        })
        .await
    })
}

fn pkg_install_handler(ctx: OpCtx<'_>) -> OpFuture<'_> {
    Box::pin(async move {
        let OpCtx {
            task_id,
            positional,
            timeout,
            max_output_bytes,
            cancel,
            runner,
            ..
        } = ctx;
        let mut it = positional.into_iter();
        let name = it.next().unwrap_or_default();
        let version = it.next().filter(|v| !v.is_empty());
        pkg_install(
            task_id,
            &name,
            version.as_deref(),
            timeout,
            max_output_bytes,
            cancel,
            |req| runner.run(req),
        )
        .await
    })
}

fn raw_exec_handler(ctx: OpCtx<'_>) -> OpFuture<'_> {
    Box::pin(async move {
        let OpCtx {
            task_id,
            positional,
            timeout,
            max_output_bytes,
            policy,
            cancel,
            ..
        } = ctx;
        // Raw Exec: fully gated by Policy regex before any spawn (ADR-0001,
        // ADR-0002) — the gate lives inside run_raw_exec, unchanged.
        let raw = RawExec { argv: positional };
        run_raw_exec(task_id, &raw, timeout, max_output_bytes, policy, cancel).await
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;
    use crate::operations::schema::{OP_ARG_NAME, OP_ARG_PATH, OP_ARG_UNIT, OP_ARG_VERSION};

    // A data-only Native whose blocking work hangs — standing in for a read on a
    // hung mount — reports OUTCOME_TIMEOUT at the Task's timeout, and the
    // runtime keeps serving other Tasks meanwhile. `#[tokio::test]` is a
    // single-threaded runtime: before the fix the work ran inline on that one
    // thread, so the timer could not fire, nothing else could run, and the
    // Task returned SUCCESS only once the work gave up after 5 s.
    #[tokio::test]
    async fn hung_blocking_work_times_out_without_stalling_the_runtime() {
        let (release, hung) = std::sync::mpsc::channel::<()>();
        // Another Task's work, on the same single-threaded runtime.
        let other = tokio::spawn(tokio::task::yield_now());

        let started = std::time::Instant::now();
        let result = within_task_timeout("t-hung", Duration::from_millis(200), async {
            run_blocking(move || {
                let _ = hung.recv_timeout(Duration::from_secs(5));
                TaskResult {
                    task_id: "t-hung".to_string(),
                    outcome: Outcome::Success as i32,
                    ..Default::default()
                }
            })
            .await
        })
        .await;
        let elapsed = started.elapsed();
        let other_ran = other.is_finished();
        let _ = release.send(()); // let the blocked thread go

        assert_eq!(result.outcome, Outcome::Timeout as i32);
        assert_eq!(result.exit_code, -1);
        assert!(result.stdout.is_empty());
        assert!(
            elapsed < Duration::from_secs(2),
            "the Task must end at its timeout, not when the blocking work does: {elapsed:?}"
        );
        assert!(
            other_ran,
            "another Task must run while the blocking work is stuck"
        );
    }

    fn op(name: &str, args: &[(&str, &str)]) -> Operation {
        Operation {
            name: name.to_string(),
            args: args
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect::<HashMap<_, _>>(),
        }
    }

    #[test]
    fn registry_pins_the_v1_vocabulary_in_canonical_order() {
        let names: Vec<&str> = REGISTRY.iter().map(|e| e.name).collect();
        assert_eq!(
            names,
            [
                super::super::SYSTEM_FACTS,
                super::super::FILE_READ,
                super::super::SERVICE_RESTART,
                super::super::PKG_INSTALL,
            ],
        );
        assert_eq!(REGISTRY[0].risk, RiskClass::Read);
        assert_eq!(REGISTRY[1].risk, RiskClass::Read);
        assert_eq!(REGISTRY[2].risk, RiskClass::Mutate);
        assert_eq!(REGISTRY[3].risk, RiskClass::Mutate);
    }

    #[test]
    fn raw_exec_entry_is_mutate_and_never_a_named_operation() {
        // ADR-0012: Raw Exec is ALWAYS mutate — pinned, not derived.
        assert_eq!(RAW_EXEC.risk, RiskClass::Mutate);
        // The restrictive choice (module doc): the Raw Exec entry is not in
        // the by-name table, so a wire Operation named "raw_exec" stays an
        // unknown name (deny-by-default), exactly as before the registry.
        assert!(lookup(RAW_EXEC.name).is_none());
        assert!(lookup("raw_exec").is_none());
    }

    #[test]
    fn lookup_unknown_names_is_none() {
        assert!(lookup("nope").is_none());
        assert!(lookup("").is_none());
    }

    /// Pins the v1 arg-map → positional contract the old per-name match in
    /// dispatch.rs implemented, now derived from each entry's arg-shape —
    /// byte-identical inputs to the Policy engine (issue #289 no-behavior-
    /// change proof at the mapping level).
    #[test]
    fn positional_args_mapping_matches_v1_contract() {
        let facts = lookup(super::super::SYSTEM_FACTS).unwrap();
        assert_eq!(
            facts.positional_args(&op(super::super::SYSTEM_FACTS, &[])),
            Vec::<String>::new()
        );

        let fr = lookup(super::super::FILE_READ).unwrap();
        assert_eq!(
            fr.positional_args(&op(super::super::FILE_READ, &[(OP_ARG_PATH, "/etc/hosts")])),
            ["/etc/hosts"]
        );
        // Missing path maps to "" (deny-by-default unless a "*" rule matches).
        assert_eq!(fr.positional_args(&op(super::super::FILE_READ, &[])), [""]);

        let sr = lookup(super::super::SERVICE_RESTART).unwrap();
        assert_eq!(
            sr.positional_args(&op(
                super::super::SERVICE_RESTART,
                &[(OP_ARG_UNIT, "nginx")]
            )),
            ["nginx"]
        );

        let pi = lookup(super::super::PKG_INSTALL).unwrap();
        // Stable 2-position schema: [name, version]; version defaults to ""
        // when absent — matched by a Policy "*" wildcard rule (ADR-0011).
        assert_eq!(
            pi.positional_args(&op(
                super::super::PKG_INSTALL,
                &[(OP_ARG_NAME, "nginx"), (OP_ARG_VERSION, "1.18.0")]
            )),
            ["nginx", "1.18.0"]
        );
        assert_eq!(
            pi.positional_args(&op(super::super::PKG_INSTALL, &[(OP_ARG_NAME, "nginx")])),
            ["nginx", ""]
        );
    }

    /// Unknown arg keys are ignored (the mapping reads only the declared
    /// arg-shape) — same as the old explicit match, which read only the
    /// contract keys.
    #[test]
    fn positional_args_ignores_undeclared_keys() {
        let sr = lookup(super::super::SERVICE_RESTART).unwrap();
        assert_eq!(
            sr.positional_args(&op(
                super::super::SERVICE_RESTART,
                &[(OP_ARG_UNIT, "nginx"), ("bogus", "x")]
            )),
            ["nginx"]
        );
    }
}
