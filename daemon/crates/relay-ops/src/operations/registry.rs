//! The single Operation-vocabulary registry: `name → (handler, arg-shape,
//! risk class)` (ADR-0001, ADR-0012, ADR-0015).
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

use tokio::sync::{oneshot, Semaphore};

use super::schema::{self, ArgSpec};
use crate::executor::ExecRequest;
use crate::gen::{Operation, Outcome, RiskClass, TaskResult};
use crate::not_executed::not_executed;
use crate::operations::file_read::{file_read, PathCheck};
use crate::operations::pkg_install::pkg_install;
use crate::operations::service_restart::service_restart;
use crate::operations::system_facts::{format_facts_as_kv, gather_facts};
use crate::policy::{Decision, Policy, Request};

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
/// has allowed the action. Raw Exec does not use it: dispatch gates it and
/// calls `run_raw_exec` with a permit.
pub struct OpCtx<'a> {
    /// The Task's unique id, echoed into the returned [`TaskResult`].
    pub task_id: String,
    /// The positional arg vector ([`OpRegistration::positional_args`]) — the
    /// exact vector the Policy engine evaluated.
    pub positional: Vec<String>,
    /// Remaining wall-clock budget (single clock from receipt, ADR-0004).
    pub timeout: Duration,
    /// Per-stream output byte cap (ADR-0004), decided at the dispatch layer.
    pub max_output_bytes: usize,
    /// The loaded Policy — read-only (ADR-0002). Read only by `file.read`'s
    /// resolved-path re-check (ADR-0018 layer 2).
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
// the runtime-loaded Template Operations behind one lookup (ADR-0021).
// ---------------------------------------------------------------------------

/// The behavior dispatch needs from a resolved vocabulary entry, independent of
/// whether it is a Native Operation ([`OpRegistration`], a `'static` `fn`-pointer
/// handler) or a Template Operation
/// ([`crate::operations::template::TemplateOp`], a runtime value carrying a
/// compiled shell template).
///
/// Dispatch's Policy gate + handler invocation
/// (the bin's `dispatch::gate_and_invoke`) is written once against
/// `&dyn ResolvedOp`, so:
///
/// - **Policy parity is structural**: both kinds derive their positional args
///   through [`ResolvedOp::positional_args`] and are gated by the same
///   `policy.decide(..)` call — a Template Operation is denied,
///   allowed, and argument-constrained exactly like a Native Operation
///   (deny-by-default, deny-beats-allow), because the Policy engine is
///   name-agnostic and there is only one gate.
/// - **Adding a template is a registration, not a dispatch edit**: a new
///   `TemplateOp` implements this trait and resolves through the same lookup —
///   no per-name match arm (proven by the structural test in dispatch.rs).
///
/// `Send + Sync` because a resolved entry is borrowed across the `.await` inside
/// `tokio::spawn` (the tunnel loop).
pub trait ResolvedOp: Send + Sync {
    /// The wire/Policy name. Part of the resolved contract; consumed by the
    /// per-Node vocabulary discovery and classification.
    fn name(&self) -> &str;
    /// ADR-0012 risk class — the third element of `name → (handler, arg-shape,
    /// risk class)`. Consumed by the per-Node scheduler classification
    /// (`scheduler::Scheduler::classify`) and by discovery; native dispatch
    /// reads the concrete `OpRegistration::risk` field directly.
    fn risk(&self) -> RiskClass;
    /// The execution tier, named in the Node's Policy decision log.
    fn tier(&self) -> crate::policy::decision_log::Tier;
    /// Named-args → positional vector, in the entry's declared order. MUST be
    /// the exact vector Policy evaluates (ADR-0011: no drift between "would
    /// allow" and "actually allows").
    fn positional_args(&self, op: &Operation) -> Vec<String>;
    /// Positions of `path`-typed arguments, which `Policy::decide` holds to
    /// ADR-0018's canonical-form precondition before any rule is read: they
    /// travel in the `Request` as `path_positions`.
    ///
    /// Empty by default. A Native Operation reports the positions of its
    /// `path`-keyed arguments (`file.read`'s only); a Template Operation
    /// reports its `path` slots, so an exact-path deny holds against
    /// non-canonical spellings there too.
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

    // RAW_EXEC is never resolved through `ResolvedOp`/`gate_and_invoke` (it is
    // not in the by-name table); dispatch's Raw Exec gate names its own tier.
    fn tier(&self) -> crate::policy::decision_log::Tier {
        crate::policy::decision_log::Tier::Native
    }

    fn positional_args(&self, op: &Operation) -> Vec<String> {
        // Delegate to the inherent method (the single mapping definition).
        OpRegistration::positional_args(self, op)
    }

    fn path_arg_positions(&self) -> Vec<usize> {
        self.args
            .iter()
            .enumerate()
            .filter(|(_, a)| a.key == schema::OP_ARG_PATH)
            .map(|(i, _)| i)
            .collect()
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

/// The Raw Exec entry — same record type as the native Operations, but
/// **never** part of the by-name table (see module doc): it is resolved only
/// from the `TaskRequest` protocol oneof arm. Always `RiskClass::Mutate`
/// (ADR-0012 — arbitrary commands take the strict lane by definition; pinned
/// by test below). Its `handler` is an inert refusal: Raw Exec runs through
/// dispatch's Policy gate plus `run_raw_exec(permit, ..)`, never through this
/// entry.
pub static RAW_EXEC: OpRegistration = OpRegistration {
    name: "raw_exec",
    risk: RiskClass::Mutate,
    args: &[],
    handler: raw_exec_refused_without_permit,
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
// Handlers
// ---------------------------------------------------------------------------

// The data-only Natives (`system.facts`, `file.read`) spawn no process, but
// their work is blocking syscalls — file reads, getifaddrs(3) — that a hung
// mount can stall indefinitely. They run that work on the blocking pool behind
// a small gate (`BlockingGate`), never on a tokio worker thread the tunnel and
// heartbeat share, and bound it by the Task's remaining wall-clock budget
// (`within_task_timeout`, ADR-0004). Cancel is irrelevant to them: there is no
// process group to kill, and the receiver drops with the context.
//
// Each handler is a thin binding of a `*_via` function to the production gate,
// so a test can drive the real handler body through a gate it controls.

fn system_facts_handler(ctx: OpCtx<'_>) -> OpFuture<'_> {
    system_facts_via(BlockingGate::data_only(), ctx)
}

fn file_read_handler(ctx: OpCtx<'_>) -> OpFuture<'_> {
    file_read_via(BlockingGate::data_only(), ctx)
}

fn system_facts_via(gate: BlockingGate, ctx: OpCtx<'_>) -> OpFuture<'_> {
    Box::pin(async move {
        let OpCtx {
            task_id, timeout, ..
        } = ctx;
        let work = async {
            let stdout = gate.run(|| format_facts_as_kv(&gather_facts())).await;
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

/// `file.read`'s `path` argument is positional index 0; the layer-2 recheck
/// holds the resolved path to the same canonical-form precondition as layer 1.
/// A test pins this to the registration's own `path`-keyed arg.
const FILE_READ_PATH_POSITIONS: [usize; 1] = [0];

fn file_read_via(gate: BlockingGate, ctx: OpCtx<'_>) -> OpFuture<'_> {
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
        let work = file_read(gate, task_id.clone(), path, max_output_bytes, |resolved| {
            let resolved_owned = resolved.to_string();
            let request = Request::Operation {
                name: super::FILE_READ,
                positional: std::slice::from_ref(&resolved_owned),
                path_positions: &FILE_READ_PATH_POSITIONS,
            };
            match policy.decide(&request).decision {
                Decision::Deny { reason, .. } => PathCheck::Denied(reason),
                Decision::Allow(_) => PathCheck::Allowed,
            }
        });
        within_task_timeout(&task_id, timeout, work).await
    })
}

/// Fixed upper bound on concurrent read Tasks per Node.
///
/// Not configurable in this milestone (ADR-0004 amendment). A future ADR may
/// expose this as a Policy field; for now this constant is the sole definition.
pub const READ_CONCURRENCY: usize = 4;

/// How many data-only blocking calls may be in flight at once, stuck or not.
///
/// A Task's timeout ends the Task but cannot interrupt a blocking syscall: a
/// read on a hung NFS or FUSE mount keeps its blocking-pool thread until the
/// kernel returns. Without a bound, repeating such a read would pin a new
/// thread per Task until tokio's pool limit (512) is full, after which every
/// `spawn_blocking` in the process queues — DNS resolution on reconnect among
/// them — and the Node falls off the fleet.
///
/// Sized to [`READ_CONCURRENCY`]: both data-only Natives are `read`-class, so
/// the read lane never runs more than that many at once, and a healthy Node
/// never waits here — a call's permit is released before its Task finishes.
/// It also restores the bound that held before this work moved off the async
/// workers, when a stuck read kept its read-lane slot: at most four stuck
/// calls, while the rest of the blocking pool stays free.
pub(crate) const DATA_ONLY_BLOCKING_CAP: usize = READ_CONCURRENCY;

static DATA_ONLY_BLOCKING: Semaphore = Semaphore::const_new(DATA_ONLY_BLOCKING_CAP);

/// A bound on blocking work in flight: runs work on tokio's blocking pool,
/// keeping it off the async worker threads, only once a permit is free.
///
/// The permit moves into the blocking closure and is released when the work
/// returns — not when the Task gives up on it — so stuck work keeps counting
/// against the bound. Waiting for a permit is part of the Task's work, inside
/// its timeout: a Task that cannot get one in time reports `OUTCOME_TIMEOUT`.
#[derive(Clone, Copy)]
pub(crate) struct BlockingGate(&'static Semaphore);

impl BlockingGate {
    /// The process-wide gate the data-only Natives share.
    pub(crate) fn data_only() -> Self {
        Self(&DATA_ONLY_BLOCKING)
    }

    /// Runs `work` on the blocking pool once a permit is free, and returns its
    /// value. A panic in `work` is resumed on the caller, exactly as if `work`
    /// had run inline. The blocking pool only fails to run `work` when the
    /// runtime is shutting down, which takes the Task with it.
    pub(crate) async fn run<T, F>(self, work: F) -> T
    where
        F: FnOnce() -> T + Send + 'static,
        T: Send + 'static,
    {
        let permit = self
            .0
            .acquire()
            .await
            .expect("the blocking gate is never closed");
        let joined = tokio::task::spawn_blocking(move || {
            let _permit = permit; // held until the work returns
            work()
        })
        .await;
        match joined {
            Ok(value) => value,
            Err(err) => match err.try_into_panic() {
                Ok(panic) => std::panic::resume_unwind(panic),
                Err(err) => panic!("blocking work did not run: {err}"),
            },
        }
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

/// The [`RAW_EXEC`] entry's handler: an inert refusal.
///
/// Raw Exec runs through dispatch's Policy gate and `run_raw_exec(permit, ..)`,
/// which needs a `RawExecPermit` only `Policy::decide` can mint. This entry has
/// no such permit, so reaching it by any route (`RAW_EXEC.invoke(ctx)`, an
/// aliased `(e.handler)(ctx)`) must run nothing. It drops the context unread;
/// a structural guard (`policy_decide_single_gate`) pins that its body names
/// no runner, executor or Policy.
fn raw_exec_refused_without_permit(ctx: OpCtx<'_>) -> OpFuture<'_> {
    Box::pin(async move {
        // No log field: relay-ops has no wire-string escaper (`log_field` lives
        // with the bin), and the message alone says all there is to say.
        tracing::error!("raw exec reached the registry handler without a Policy permit; refusing");
        not_executed(
            ctx.task_id,
            Outcome::Failure,
            "raw exec runs only through the dispatch Policy gate",
        )
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
        let result = within_task_timeout(
            "t-hung",
            Duration::from_millis(200),
            test_gate(1).run(hung_work(hung)),
        )
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

    /// A gate of `permits` that only this test uses, so filling it never stalls
    /// another test's data-only work on the process-wide gate.
    fn test_gate(permits: usize) -> BlockingGate {
        BlockingGate(Box::leak(Box::new(Semaphore::new(permits))))
    }

    /// Blocking work standing in for a syscall on a hung mount: it blocks its
    /// thread until released, or its sender is dropped (5 s at most).
    fn hung_work(hung: std::sync::mpsc::Receiver<()>) -> impl FnOnce() -> TaskResult + Send {
        move || {
            let _ = hung.recv_timeout(Duration::from_secs(5));
            TaskResult {
                outcome: Outcome::Success as i32,
                ..Default::default()
            }
        }
    }

    // Stuck blocking work is capped. A timed-out Task's syscall keeps its
    // blocking-pool thread, so without a cap every repeat of a read on a hung
    // mount pins another thread until tokio's pool (512) is full and every
    // `spawn_blocking` in the process — DNS on reconnect among them — queues
    // forever. Once the cap's worth of work is stuck, the next data-only Task
    // must time out promptly *without starting its work*, an unrelated
    // `spawn_blocking` must still run, and the permits must come back when the
    // stuck calls return.
    #[tokio::test]
    async fn stuck_blocking_work_is_capped_and_the_pool_stays_free() {
        let gate = test_gate(DATA_ONLY_BLOCKING_CAP);
        let mut releases = Vec::new();
        for _ in 0..DATA_ONLY_BLOCKING_CAP {
            let (release, hung) = std::sync::mpsc::channel::<()>();
            releases.push(release);
            let stuck = within_task_timeout(
                "t-stuck",
                Duration::from_millis(50),
                gate.run(hung_work(hung)),
            )
            .await;
            assert_eq!(stuck.outcome, Outcome::Timeout as i32);
        }
        assert_eq!(
            gate.0.available_permits(),
            0,
            "a timed-out call that is still stuck must keep its permit"
        );

        let started = std::time::Instant::now();
        let ran = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let ran_in_work = std::sync::Arc::clone(&ran);
        let next = within_task_timeout(
            "t-next",
            Duration::from_millis(200),
            gate.run(move || {
                ran_in_work.store(true, std::sync::atomic::Ordering::SeqCst);
                TaskResult::default()
            }),
        )
        .await;
        assert_eq!(next.outcome, Outcome::Timeout as i32);
        assert!(started.elapsed() < Duration::from_secs(2));
        assert!(
            !ran.load(std::sync::atomic::Ordering::SeqCst),
            "work past the cap must never reach the blocking pool"
        );

        let unrelated =
            tokio::time::timeout(Duration::from_secs(5), tokio::task::spawn_blocking(|| 42))
                .await
                .expect("an unrelated spawn_blocking must still run")
                .expect("it must not panic");
        assert_eq!(unrelated, 42);

        // Releasing the stuck calls returns their permits.
        drop(releases);
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while gate.0.available_permits() < DATA_ONLY_BLOCKING_CAP {
            assert!(
                std::time::Instant::now() < deadline,
                "the permits of returned calls must be released"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    /// Refuses to spawn: the data-only Natives never run a process.
    struct NoProcess;
    impl Runner for NoProcess {
        fn run(&self, _req: ExecRequest) -> OpFuture<'static> {
            panic!("a data-only Native must not spawn a process")
        }
    }

    type Via = for<'a> fn(BlockingGate, OpCtx<'a>) -> OpFuture<'a>;

    // The real handler bodies route their work through the bounded path: with
    // a gate that has no free permit they can only time out, and with a free
    // permit the same body completes. (The registered handlers are one-line
    // bindings of these bodies to the process-wide gate.) A body that ran its
    // blocking work any other way would succeed against the closed gate.
    #[tokio::test]
    async fn data_only_handlers_route_through_the_blocking_gate() {
        let policy = crate::policy::from_toml_str(
            r#"
[[operation]]
name = "file.read"
allowed_args = [["*"]]
"#,
        )
        .expect("parse policy");
        let tmp = crate::test_support::TempFile::new("gate-route", b"routed");
        let cases: [(&str, Via, Vec<String>); 2] = [
            (super::super::SYSTEM_FACTS, system_facts_via, vec![]),
            (super::super::FILE_READ, file_read_via, vec![tmp.path_str()]),
        ];
        for (name, via, positional) in cases {
            let ctx = |timeout| OpCtx {
                task_id: format!("t-{name}"),
                positional: positional.clone(),
                timeout,
                max_output_bytes: 1024,
                policy: &policy,
                cancel: None,
                runner: &NoProcess,
            };

            let closed = via(test_gate(0), ctx(Duration::from_millis(100))).await;
            assert_eq!(
                closed.outcome,
                Outcome::Timeout as i32,
                "{name} must wait on the blocking gate"
            );

            let open = via(test_gate(1), ctx(Duration::from_secs(5))).await;
            assert_eq!(
                open.outcome,
                Outcome::Success as i32,
                "{name}: stderr={:?}",
                String::from_utf8_lossy(&open.stderr)
            );
        }
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

    /// The Policy linter asks `relay_policy::natives::is_native` where it used
    /// to ask the registry (#889); this keeps the two vocabularies one set.
    #[test]
    fn registry_names_are_exactly_the_native_names() {
        let mut registry: Vec<&str> = REGISTRY.iter().map(|e| e.name).collect();
        let mut natives: Vec<&str> = relay_policy::natives::NATIVE_NAMES.to_vec();
        registry.sort_unstable();
        natives.sort_unstable();
        assert_eq!(registry, natives);
        assert!(REGISTRY
            .iter()
            .all(|e| relay_policy::natives::is_native(e.name)));
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
    fn native_path_positions_are_exactly_file_read_0() {
        for entry in REGISTRY.iter().chain(std::iter::once(&RAW_EXEC)) {
            let expected: Vec<usize> = if entry.name == super::super::FILE_READ {
                vec![0]
            } else {
                vec![]
            };
            assert_eq!(
                ResolvedOp::path_arg_positions(entry),
                expected,
                "{}",
                entry.name
            );
        }
    }

    #[test]
    fn file_read_layer2_positions_match_registration() {
        let fr = lookup(super::super::FILE_READ).unwrap();
        assert_eq!(
            FILE_READ_PATH_POSITIONS.to_vec(),
            ResolvedOp::path_arg_positions(fr)
        );
    }

    /// Records whether the process seam was reached; it spawns nothing.
    struct FlagRunner(std::sync::atomic::AtomicBool);
    impl Runner for FlagRunner {
        fn run(&self, req: ExecRequest) -> OpFuture<'static> {
            self.0.store(true, std::sync::atomic::Ordering::SeqCst);
            let task_id = req.task_id;
            Box::pin(async move {
                TaskResult {
                    task_id,
                    outcome: Outcome::Success as i32,
                    exit_code: 0,
                    stdout: vec![],
                    stderr: vec![],
                    truncated: false,
                    duration_millis: 0,
                }
            })
        }
    }

    // Raw Exec runs only through dispatch's Policy gate and a `RawExecPermit`.
    // The registry entry has no permit, so even under an allow-everything Policy
    // every route to its handler must refuse and run nothing.
    #[tokio::test]
    async fn raw_exec_entry_refuses_without_permit() {
        let policy =
            crate::policy::from_toml_str("[raw_exec]\nallow = [\"^.*$\"]\n").expect("parse policy");
        let runner = FlagRunner(std::sync::atomic::AtomicBool::new(false));
        let ctx = || OpCtx {
            task_id: "t-raw-stub".to_string(),
            positional: vec!["/bin/true".to_string()],
            timeout: Duration::from_secs(5),
            max_output_bytes: 1024,
            policy: &policy,
            cancel: None,
            runner: &runner,
        };

        let via_handler = (RAW_EXEC.handler)(ctx()).await;
        let via_invoke = RAW_EXEC.invoke(ctx()).await;

        for result in [via_handler, via_invoke] {
            assert_eq!(result.outcome, Outcome::Failure as i32);
            assert_eq!(result.task_id, "t-raw-stub");
            assert!(result.stdout.is_empty());
        }
        assert!(
            !runner.0.load(std::sync::atomic::Ordering::SeqCst),
            "the registry entry must never reach the process runner"
        );
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
