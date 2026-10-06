//! Per-Node concurrency scheduler: mutate Tasks strictly serial, read Tasks
//! bounded-parallel (ADR-0004 concurrency amendment, ADR-0012, ADR-0013).
//!
//! Two independent [`tokio::sync::Semaphore`]s gate the two risk lanes:
//! - `mutate_gate`: permits = 1 — mutate Tasks are strictly serial per Node.
//! - `read_gate`: permits = [`READ_CONCURRENCY`] — read Tasks run concurrently
//!   up to the fixed bound.
//!
//! Two separate semaphores give read+mutate concurrency: a read Task and a
//! mutate Task may hold their respective gates simultaneously.
//!
//! # Queued-Task lifecycle
//!
//! [`Scheduler::acquire`] blocks until the caller's risk-class gate has an
//! available permit, the Task's deadline expires, or an explicit cancel signal
//! fires. Dropping the losing [`tokio::sync::Semaphore::acquire`] future is
//! cancel-safe — tokio removes the caller from the semaphore queue without
//! consuming a slot.
//!
//! # ADR references
//!
//! - ADR-0004: at-most-once. `acquire` is called INSIDE `DedupStore::run_once`'s
//!   closure, so a Task whose deadline expires or is cancelled while queued still
//!   gets its `task_id` recorded. Its id is deduplicated on re-send.
//! - ADR-0012: risk class drives the concurrency lane, not Policy. Policy
//!   applies identically after a slot is acquired.
//! - ADR-0013: honest cancel/race. [`queued_cancel`] mirrors `recv_cancel` in
//!   executor.rs — a dropped sender (deregister) maps to `pending()` and can
//!   NEVER trigger a spurious cancel. Only `CancelRegistry::cancel` (an explicit
//!   `send(())`) fires the cancel arm.

use std::sync::Arc;

use tokio::sync::oneshot;
use tokio::sync::{Semaphore, SemaphorePermit};

use crate::gen::{task_request, RiskClass, TaskRequest};
use crate::operations;
use crate::operations::registry::ResolvedOp;
use crate::templates::TemplateSet;

/// Fixed upper bound on concurrent read Tasks per Node.
///
/// Not configurable in this milestone (ADR-0004 amendment). A future ADR may
/// expose this as a Policy field; for now this constant is the sole definition.
pub const READ_CONCURRENCY: usize = 4;

/// Risk class for a Task, used to route it to the correct semaphore gate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Class {
    /// Read-only Operation (e.g. `system.facts`, `file.read`).
    /// Bounded-parallel: up to [`READ_CONCURRENCY`] may run simultaneously.
    Read,
    /// Mutating Operation, Raw Exec, or unknown/missing action.
    /// Strictly serial: at most one runs at a time per Node.
    Mutate,
}

/// What happened to a Task that left the queue without acquiring a slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QueuedOutcome {
    /// The Task's deadline expired while waiting in the queue.
    Timeout,
    /// An explicit cancel signal arrived while the Task was queued.
    Cancelled,
}

/// Per-Node concurrency scheduler.
///
/// Wrap in [`Arc`] (via [`Scheduler::new`]) and pass a clone into each spawned
/// Task so all concurrent Tasks on this Node share the same gates.
pub struct Scheduler {
    /// Gate for mutate Tasks. Permits = 1: strictly serial.
    mutate_gate: Semaphore,
    /// Gate for read Tasks. Permits = [`READ_CONCURRENCY`]: bounded-parallel.
    read_gate: Semaphore,
}

impl Scheduler {
    /// Creates a new scheduler wrapped in an [`Arc`] for shared ownership.
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            mutate_gate: Semaphore::new(1),
            read_gate: Semaphore::new(READ_CONCURRENCY),
        })
    }

    /// Returns the semaphore gate for `class`.
    fn gate(&self, class: Class) -> &Semaphore {
        match class {
            Class::Read => &self.read_gate,
            Class::Mutate => &self.mutate_gate,
        }
    }

    /// Classifies a [`TaskRequest`] into a risk [`Class`].
    ///
    /// - `RawExec` → always [`Class::Mutate`] (arbitrary-command path, ADR-0001).
    /// - `Operation` → the Node's effective vocabulary: [`operations::risk_class`]
    ///   for a Native Operation, then the loaded [`TemplateSet`] for a Template
    ///   Operation's authored `risk_class` (ADR-0012/0021 — a `mutate` template
    ///   takes the serial lane exactly like a native one). A name in neither
    ///   falls to [`Class::Mutate`] (strict lane; dispatch reports
    ///   `unsupported` without executing, so the gate is held only momentarily).
    /// - Missing action → [`Class::Mutate`] (protocol error; dispatch returns
    ///   FAILURE without executing, releasing the gate immediately).
    pub fn classify(task: &TaskRequest, templates: &TemplateSet) -> Class {
        match &task.action {
            Some(task_request::Action::RawExec(_)) => Class::Mutate,
            Some(task_request::Action::Operation(op)) => {
                let risk = operations::risk_class(&op.name)
                    .or_else(|| templates.lookup(&op.name).map(|t| t.risk()));
                match risk {
                    Some(RiskClass::Read) => Class::Read,
                    // Mutate, Unspecified, or a name outside this Node's
                    // vocabulary → strict (mutate) lane. An unsupported name
                    // never executes; the gate is held only momentarily.
                    Some(RiskClass::Mutate) | Some(RiskClass::Unspecified) | None => Class::Mutate,
                }
            }
            None => Class::Mutate,
        }
    }

    /// Acquires a concurrency slot for a Task.
    ///
    /// Blocks until one of (in priority order):
    ///
    /// 1. **Cancel** (biased highest): an explicit `send(())` on the paired
    ///    cancel sender → returns `Err(QueuedOutcome::Cancelled)`.
    /// 2. **Deadline** (biased second): `deadline` expires while queued →
    ///    returns `Err(QueuedOutcome::Timeout)`.
    /// 3. **Slot available**: the risk-class gate has a free permit →
    ///    returns `Ok(permit)`. The caller MUST hold the permit across execution
    ///    (keeping the gate occupied while the Task runs).
    ///
    /// Biased ordering (cancel > timeout > permit) ensures that an explicit cancel
    /// or an expired deadline wins over a just-freed permit; the Task NEVER begins
    /// execution after either event.
    ///
    /// Dropping the losing `gate.acquire()` future is cancel-safe: tokio removes
    /// the caller from the semaphore queue, freeing the slot for the next Task.
    ///
    /// # Cancel borrow semantics (ADR-0013)
    ///
    /// `cancel` is borrowed (not moved): if the permit arm wins, `cancel` is
    /// still `Some(rx)` and can be forwarded to the executor for the in-flight
    /// cancel path. A dropped sender (deregister) resolves to `Err` inside
    /// [`queued_cancel`], which maps to `pending()` — only an explicit `send(())`
    /// can trigger the cancel arm.
    pub async fn acquire<'a>(
        &'a self,
        class: Class,
        deadline: tokio::time::Instant,
        cancel: &mut Option<oneshot::Receiver<()>>,
    ) -> Result<SemaphorePermit<'a>, QueuedOutcome> {
        tokio::select! {
            biased;
            _ = queued_cancel(cancel) => Err(QueuedOutcome::Cancelled),
            _ = tokio::time::sleep_until(deadline) => Err(QueuedOutcome::Timeout),
            p = self.gate(class).acquire() => Ok(p.expect("scheduler gates are never closed")),
        }
    }
}

/// Resolves only when an explicit `send(())` fires on the paired cancel sender.
///
/// Mirrors `recv_cancel` in executor.rs (ADR-0013 honest-race contract):
/// - `Some(rx)` + `Ok(())` → resolves immediately (explicit cancel signal).
/// - `Some(rx)` + `Err(_)` → sender was dropped (deregister); maps to
///   `pending()` — never resolves. A dropped sender MUST NOT trigger cancellation.
/// - `None` → maps to `pending()` — uncancellable path.
///
/// **Borrow-only** (`&mut Option<Receiver<()>>`): if another `select!` arm wins,
/// the future is dropped and the borrow is released. The receiver remains
/// `Some(rx)` and is forwarded to the executor for the in-flight cancel path.
async fn queued_cancel(cancel: &mut Option<oneshot::Receiver<()>>) {
    match cancel.as_mut() {
        Some(rx) => match (&mut *rx).await {
            Ok(()) => {}
            Err(_) => std::future::pending::<()>().await,
        },
        None => std::future::pending::<()>().await,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::time::Duration;

    use tokio::sync::oneshot;

    use super::*;
    use crate::gen::{task_request, Operation, RawExec, TaskRequest};
    use crate::operations;

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    fn make_task(action: task_request::Action) -> TaskRequest {
        TaskRequest {
            risk_class: 0,
            task_id: "t".to_string(),
            timeout_seconds: 5,
            action: Some(action),
        }
    }

    fn make_operation_task(name: &str) -> TaskRequest {
        make_task(task_request::Action::Operation(Operation {
            name: name.to_string(),
            args: Default::default(),
        }))
    }

    fn make_raw_exec_task() -> TaskRequest {
        make_task(task_request::Action::RawExec(RawExec {
            argv: vec!["/bin/echo".to_string()],
        }))
    }

    fn make_no_action_task() -> TaskRequest {
        TaskRequest {
            risk_class: 0,
            task_id: "t".to_string(),
            timeout_seconds: 5,
            action: None,
        }
    }

    fn far_deadline() -> tokio::time::Instant {
        tokio::time::Instant::now() + Duration::from_secs(60)
    }

    // -----------------------------------------------------------------------
    // classify() matrix
    // -----------------------------------------------------------------------

    #[test]
    fn classify_raw_exec_is_mutate() {
        assert_eq!(
            Scheduler::classify(&make_raw_exec_task(), TemplateSet::empty_static()),
            Class::Mutate
        );
    }

    #[test]
    fn classify_file_read_is_read() {
        assert_eq!(
            Scheduler::classify(
                &make_operation_task(operations::FILE_READ),
                TemplateSet::empty_static()
            ),
            Class::Read
        );
    }

    #[test]
    fn classify_system_facts_is_read() {
        assert_eq!(
            Scheduler::classify(
                &make_operation_task(operations::SYSTEM_FACTS),
                TemplateSet::empty_static()
            ),
            Class::Read
        );
    }

    #[test]
    fn classify_service_restart_is_mutate() {
        assert_eq!(
            Scheduler::classify(
                &make_operation_task(operations::SERVICE_RESTART),
                TemplateSet::empty_static()
            ),
            Class::Mutate
        );
    }

    #[test]
    fn classify_unknown_operation_is_mutate() {
        assert_eq!(
            Scheduler::classify(
                &make_operation_task("completely.unknown"),
                TemplateSet::empty_static()
            ),
            Class::Mutate
        );
    }

    /// A Template Operation is classified from its authored `risk_class`
    /// (ADR-0012/0021): a `mutate` template takes the strictly-serial lane like
    /// any native mutate, a `read` template joins the bounded-parallel lane.
    #[test]
    fn classify_reads_the_template_vocabulary() {
        use crate::operations::template::{RiskClassDef, TemplateDef};

        let templates = TemplateSet::for_test(&[
            TemplateDef {
                name: "disk.usage".to_string(),
                risk_class: RiskClassDef::Read,
                body: "df -PT".to_string(),
                slots: vec![],
            },
            TemplateDef {
                name: "cache.flush".to_string(),
                risk_class: RiskClassDef::Mutate,
                body: "sync".to_string(),
                slots: vec![],
            },
        ]);

        assert_eq!(
            Scheduler::classify(&make_operation_task("disk.usage"), &templates),
            Class::Read,
        );
        assert_eq!(
            Scheduler::classify(&make_operation_task("cache.flush"), &templates),
            Class::Mutate,
        );
        // The same names on a Node without the pack: strict lane (they report
        // `unsupported` without executing, so the gate is held momentarily).
        assert_eq!(
            Scheduler::classify(&make_operation_task("disk.usage"), &TemplateSet::empty()),
            Class::Mutate,
        );
    }

    #[test]
    fn classify_none_action_is_mutate() {
        assert_eq!(
            Scheduler::classify(&make_no_action_task(), TemplateSet::empty_static()),
            Class::Mutate
        );
    }

    // -----------------------------------------------------------------------
    // AC1: mutate gate is strictly serial (observed max concurrent == 1)
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn ac1_mutate_serial_max_concurrent_one() {
        let sched = Scheduler::new();
        let current = Arc::new(AtomicUsize::new(0));
        let peak = Arc::new(AtomicUsize::new(0));
        let deadline = far_deadline();

        let mut handles = Vec::new();
        for _ in 0..2 {
            let sched = Arc::clone(&sched);
            let current = Arc::clone(&current);
            let peak = Arc::clone(&peak);
            handles.push(tokio::spawn(async move {
                let mut cancel = None;
                let _permit = sched
                    .acquire(Class::Mutate, deadline, &mut cancel)
                    .await
                    .expect("mutate acquire must succeed");
                let n = current.fetch_add(1, Ordering::SeqCst) + 1;
                peak.fetch_max(n, Ordering::SeqCst);
                tokio::time::sleep(Duration::from_millis(20)).await;
                current.fetch_sub(1, Ordering::SeqCst);
                // _permit drops here, releasing the gate for the next Task
            }));
        }
        for h in handles {
            h.await.expect("task must not panic");
        }

        assert_eq!(
            peak.load(Ordering::SeqCst),
            1,
            "mutate gate must be strictly serial: max concurrent holders must be 1"
        );
    }

    // -----------------------------------------------------------------------
    // AC2: read gate is bounded-parallel (max concurrent == READ_CONCURRENCY)
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn ac2_read_bounded_max_four() {
        let sched = Scheduler::new();
        let current = Arc::new(AtomicUsize::new(0));
        let peak = Arc::new(AtomicUsize::new(0));
        let deadline = far_deadline();

        // Spawn READ_CONCURRENCY+1 read tasks. The first READ_CONCURRENCY acquire
        // immediately; the (READ_CONCURRENCY+1)th waits for one to release.
        let mut handles = Vec::new();
        for _ in 0..(READ_CONCURRENCY + 1) {
            let sched = Arc::clone(&sched);
            let current = Arc::clone(&current);
            let peak = Arc::clone(&peak);
            handles.push(tokio::spawn(async move {
                let mut cancel = None;
                let _permit = sched
                    .acquire(Class::Read, deadline, &mut cancel)
                    .await
                    .expect("read acquire must succeed");
                let n = current.fetch_add(1, Ordering::SeqCst) + 1;
                peak.fetch_max(n, Ordering::SeqCst);
                // Hold the permit long enough for all READ_CONCURRENCY tasks
                // to have incremented before any decrement — ensures the peak
                // is observable.
                tokio::time::sleep(Duration::from_millis(30)).await;
                current.fetch_sub(1, Ordering::SeqCst);
            }));
        }
        for h in handles {
            h.await.expect("task must not panic");
        }

        assert_eq!(
            peak.load(Ordering::SeqCst),
            READ_CONCURRENCY,
            "read gate must cap at READ_CONCURRENCY ({READ_CONCURRENCY}) concurrent holders"
        );
    }

    // -----------------------------------------------------------------------
    // M3: pin READ_CONCURRENCY to the ADR-0012 contract value (4), not just
    // symbolically (ac2_read_bounded_max_four above asserts peak ==
    // READ_CONCURRENCY, which stays green even if the constant is changed).
    // -----------------------------------------------------------------------

    #[test]
    fn read_concurrency_bound_is_four() {
        assert_eq!(READ_CONCURRENCY, 4, "ADR-0012 pins the read bound to 4");
    }

    // -----------------------------------------------------------------------
    // AC3: read and mutate may run concurrently (peak >= 2)
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn ac3_read_and_mutate_concurrent() {
        let sched = Scheduler::new();
        let current = Arc::new(AtomicUsize::new(0));
        let peak = Arc::new(AtomicUsize::new(0));
        let deadline = far_deadline();

        let sched_r = Arc::clone(&sched);
        let cur_r = Arc::clone(&current);
        let pk_r = Arc::clone(&peak);
        let t_read = tokio::spawn(async move {
            let mut cancel = None;
            let _permit = sched_r
                .acquire(Class::Read, deadline, &mut cancel)
                .await
                .expect("read acquire must succeed");
            let n = cur_r.fetch_add(1, Ordering::SeqCst) + 1;
            pk_r.fetch_max(n, Ordering::SeqCst);
            tokio::time::sleep(Duration::from_millis(50)).await;
            cur_r.fetch_sub(1, Ordering::SeqCst);
        });

        let sched_m = Arc::clone(&sched);
        let cur_m = Arc::clone(&current);
        let pk_m = Arc::clone(&peak);
        let t_mutate = tokio::spawn(async move {
            let mut cancel = None;
            let _permit = sched_m
                .acquire(Class::Mutate, deadline, &mut cancel)
                .await
                .expect("mutate acquire must succeed");
            let n = cur_m.fetch_add(1, Ordering::SeqCst) + 1;
            pk_m.fetch_max(n, Ordering::SeqCst);
            tokio::time::sleep(Duration::from_millis(50)).await;
            cur_m.fetch_sub(1, Ordering::SeqCst);
        });

        t_read.await.expect("read task must not panic");
        t_mutate.await.expect("mutate task must not panic");

        assert!(
            peak.load(Ordering::SeqCst) >= 2,
            "a read and a mutate Task must be able to run concurrently: peak must be >= 2"
        );
    }

    // -----------------------------------------------------------------------
    // Queued-timeout: acquire with an expired deadline → Err(Timeout)
    // -----------------------------------------------------------------------

    #[tokio::test(start_paused = true)]
    async fn queued_timeout_returns_timeout() {
        let sched = Scheduler::new();
        // Occupy the mutate gate so the next acquire must queue (not acquire immediately).
        let mut blocker_cancel = None;
        let _blocker = sched
            .acquire(Class::Mutate, far_deadline(), &mut blocker_cancel)
            .await
            .expect("blocker must acquire");

        // The blocker means the permit arm is never Ready, so on a real clock this
        // test was not racy. It still runs on virtual time: delete the blocker and
        // it becomes the #637 bug, and virtual time makes "already expired" exact
        // rather than dependent on timer phase. An expired deadline yields Timeout
        // because the select is biased (cancel > timeout > permit) and the sleep
        // arm is Ready first. tests/virtual_clock_guard.rs enforces the rule.
        let past = tokio::time::Instant::now() - Duration::from_millis(1);
        let mut cancel = None;
        let result = sched.acquire(Class::Mutate, past, &mut cancel).await;
        assert!(
            matches!(result, Err(QueuedOutcome::Timeout)),
            "expired deadline must yield Err(Timeout); got {result:?}"
        );
    }

    // -----------------------------------------------------------------------
    // Queued-cancel: fire rx while blocked → Err(Cancelled)
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn queued_cancel_returns_cancelled() {
        let sched = Scheduler::new();
        // Occupy the mutate gate so the acquire blocks.
        let mut blocker_cancel = None;
        let _blocker = sched
            .acquire(Class::Mutate, far_deadline(), &mut blocker_cancel)
            .await
            .expect("blocker must acquire");

        let (tx, rx) = oneshot::channel::<()>();
        let mut cancel = Some(rx);

        // Fire cancel after a short delay (after acquire is blocked).
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(10)).await;
            let _ = tx.send(());
        });

        let result = sched
            .acquire(Class::Mutate, far_deadline(), &mut cancel)
            .await;
        assert!(
            matches!(result, Err(QueuedOutcome::Cancelled)),
            "explicit cancel signal must yield Err(Cancelled); got {result:?}"
        );
    }

    // -----------------------------------------------------------------------
    // biased; tiebreak — BOTH select arms ready on the first poll
    //
    // Every test above arranges for only one arm to be ready (the gate is
    // either occupied so only the timeout/cancel arm can fire, or free with
    // no competing cancel/deadline), so `biased;` at scheduler.rs:149 can be
    // deleted and the suite stays green. These pin it: the gate is left FREE
    // (permit arm ready) while a cancel is pre-buffered / the deadline is
    // already expired (cancel/timeout arm also ready) — both arms are Ready
    // on the very first poll, so only `biased;` decides the winner.
    //
    // Looped 64x with a fresh channel each iteration: with `biased;` every
    // iteration deterministically picks the higher-priority arm; without it,
    // tokio's non-biased select rotates the starting branch pseudo-randomly
    // (not a 50/50 coin flip — for this 3-arm select the cancel arm only
    // starts first on ~1/3 of polls), so the winner varies across iterations
    // and the loop's assertion fails near-certainly.
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn free_gate_cancel_beats_permit_biased() {
        let sched = Scheduler::new();
        for _ in 0..64 {
            // Pre-buffer the cancel BEFORE acquire so the cancel arm is
            // Ready (not just eventually-ready) on the first poll.
            let (tx, rx) = oneshot::channel::<()>();
            tx.send(()).expect("buffered send to an open receiver");
            let mut cancel = Some(rx);

            // mutate_gate has its 1 permit free (never occupied here), so the
            // permit arm is also Ready on the first poll.
            let result = sched
                .acquire(Class::Mutate, far_deadline(), &mut cancel)
                .await;
            assert!(
                matches!(result, Err(QueuedOutcome::Cancelled)),
                "with biased;, a pre-buffered cancel must beat a simultaneously-free \
                 permit deterministically; got {result:?}"
            );
        }
    }

    // start_paused is LOAD-BEARING, not tidiness. On a real clock this test's
    // premise — "an already-expired deadline is Ready on the FIRST poll" — is
    // decided by where the deadline lands relative to a tokio timer tick, and
    // tokio's resolution is 1ms, so a 1ms margin sits exactly on that boundary.
    // When the sleep arm is not Ready first, the free permit arm (always Ready)
    // wins and the assertion below fires. That is a property of the test's
    // setup, never of `acquire`. It went green ~370 consecutive local runs,
    // including under full CPU load, and red on a loaded CI runner (#637);
    // dropping the margin to 0ms reproduces it locally every time.
    //
    // Virtual time makes "already expired" exact instead of phase-dependent:
    // Instant::now() is frozen, so now() - 1ms is unambiguously a past tick and
    // the sleep is elapsed on the first poll. The sibling test at
    // queued_timeout_returns_timeout also runs paused, and
    // tests/virtual_clock_guard.rs enforces the rule.
    #[tokio::test(start_paused = true)]
    async fn free_gate_timeout_beats_permit_biased() {
        let sched = Scheduler::new();
        for _ in 0..64 {
            // Already-expired deadline: the sleep_until arm is Ready on the
            // first poll. No cancel handle — queued_cancel is pending() forever.
            let past = tokio::time::Instant::now() - Duration::from_millis(1);
            let mut cancel = None;

            // mutate_gate has its 1 permit free, so the permit arm is also
            // Ready on the first poll.
            let result = sched.acquire(Class::Mutate, past, &mut cancel).await;
            assert!(
                matches!(result, Err(QueuedOutcome::Timeout)),
                "with biased;, an already-expired deadline must beat a simultaneously-free \
                 permit deterministically; got {result:?}"
            );
        }
    }
}
