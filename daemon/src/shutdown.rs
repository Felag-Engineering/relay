//! Graceful shutdown primitives: SIGTERM/SIGINT drain with a
//! bounded grace period.
//!
//! Mirrors the focused-module pattern of `cancel.rs`/`scheduler.rs`. This
//! module owns the shutdown signal, the in-flight Task gauge, and the drain
//! logic; the tunnel wiring (stream close, the single log line) lives in
//! `main.rs::run_tunnel`/`reconnect_loop` so `drain()` stays unit-testable in
//! isolation from any tunnel/tx/log types.
//!
//! # At-most-once (ADR-0004, invariant 4)
//!
//! Nothing here re-dispatches or retries a Task. The drain only lets a
//! running Task finish naturally or kills it at grace expiry via the
//! already-vetted [`CancelRegistry`](crate::cancel::CancelRegistry) honest-race
//! path (ADR-0013); the dedup marker was already recorded before execution
//! started (`dedup::run_once`), so a killed Task is deduplicated on any
//! re-send after restart.

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::sync::Notify;
use tokio::time::timeout;

use crate::cancel::CancelRegistry;

/// Default grace period (seconds) when `RELAY_SHUTDOWN_GRACE_SECS` is absent
/// or invalid.
const DEFAULT_GRACE_SECS: u64 = 30;

/// Bound for phase-2 (grace-expiry) kills to land and their results to flush.
/// Must exceed the executor's `TERM_GRACE` (5s SIGTERM->SIGKILL) so a killed
/// child has time to actually die and its result to be sent before we give up
/// waiting.
const KILL_FLUSH_BUDGET: Duration = Duration::from_secs(7);

/// Bound for the post-half-close inbound read that confirms the outbound
/// TaskResults reached the wire.
pub const FLUSH_CONFIRM_BUDGET: Duration = Duration::from_secs(3);

/// Parses the shutdown grace period from an optional env-var string.
///
/// Mirrors `main::parse_interval_secs`: any positive integer -> that many
/// seconds; absent, unparsable, or zero -> [`DEFAULT_GRACE_SECS`].
fn parse_grace_secs(raw: Option<&str>) -> Duration {
    let secs = raw
        .and_then(|s| s.parse::<u64>().ok())
        .filter(|&n| n > 0)
        .unwrap_or(DEFAULT_GRACE_SECS);
    Duration::from_secs(secs)
}

/// Reads `RELAY_SHUTDOWN_GRACE_SECS` and returns the configured grace period,
/// defaulting to [`DEFAULT_GRACE_SECS`] on absence or invalid input.
pub fn grace_period() -> Duration {
    parse_grace_secs(std::env::var("RELAY_SHUTDOWN_GRACE_SECS").ok().as_deref())
}

/// The line emitted once SIGTERM/SIGINT are installed. Load-bearing for
/// operators (it marks the instant the daemon became signal-responsive) and
/// for `tests/shutdown_signal.rs`, which waits for it rather than guessing at
/// a startup delay.
pub const HANDLERS_INSTALLED_MSG: &str = "signal handlers installed; graceful shutdown armed";

/// Installs the SIGTERM/SIGINT handlers and spawns a background task that
/// triggers `shutdown` when one arrives.
///
/// **Registration happens synchronously, before the task is spawned.** This is
/// not a stylistic choice: `tokio::signal::unix::signal` is what replaces a
/// signal's default disposition, and until it has been called SIGTERM *kills*
/// the process rather than draining it. Registering inside the spawned task —
/// as this did originally — left a window between process start and the
/// scheduler first polling that task in which a SIGTERM aborted the daemon
/// outright, skipping the ADR-0004 drain entirely.
///
/// The window is small and needs an early signal to hit — a fast
/// `systemctl restart`, or an orchestrator stopping a pod that has only just
/// started. It is also exactly the kind of thing that shows up as an
/// unreproducible "the daemon sometimes dies hard on restart", so it is closed
/// here rather than documented.
///
/// Must be called from within a Tokio runtime (`signal` requires one).
pub fn spawn_signal_listener(shutdown: Shutdown) {
    use tokio::signal::unix::{signal, SignalKind};

    let mut term = signal(SignalKind::terminate()).expect("install SIGTERM handler");
    let mut int = signal(SignalKind::interrupt()).expect("install SIGINT handler");

    // Emitted only after both handlers are in place, so anything waiting on
    // this line knows the daemon will drain rather than die.
    tracing::info!("{HANDLERS_INSTALLED_MSG}");

    tokio::spawn(async move {
        let reason = tokio::select! {
            _ = term.recv() => "SIGTERM",
            _ = int.recv() => "SIGINT",
        };
        tracing::warn!(reason, "shutdown signal received; beginning graceful drain");
        shutdown.trigger(reason);
    });
}

// ---------------------------------------------------------------------------
// Shutdown signal
// ---------------------------------------------------------------------------

struct ShutdownInner {
    requested: AtomicBool,
    notify: Notify,
    reason: Mutex<&'static str>,
}

/// Cheaply-cloneable shutdown signal shared across `reconnect_loop`/`run_tunnel`.
///
/// Backed by an `AtomicBool` + `Notify` double-check (not `tokio::watch`) so it
/// can be safely re-created each `select!` iteration and raced against
/// `connect_mtls` without `watch`'s "changed since last seen" version
/// subtleties.
#[derive(Clone)]
pub struct Shutdown(Arc<ShutdownInner>);

impl Shutdown {
    /// Creates a new, untriggered shutdown signal.
    pub fn new() -> Self {
        Self(Arc::new(ShutdownInner {
            requested: AtomicBool::new(false),
            notify: Notify::new(),
            reason: Mutex::new(""),
        }))
    }

    /// Records `reason`, marks the signal requested, and wakes every waiter.
    fn trigger(&self, reason: &'static str) {
        *self.0.reason.lock().expect("Shutdown Mutex not poisoned") = reason;
        self.0.requested.store(true, Ordering::Release);
        self.0.notify.notify_waiters();
    }

    /// Returns whether shutdown has been requested.
    pub fn is_requested(&self) -> bool {
        self.0.requested.load(Ordering::Acquire)
    }

    /// Returns the reason the shutdown was triggered (`""` if not yet
    /// requested).
    pub fn reason(&self) -> &'static str {
        *self.0.reason.lock().expect("Shutdown Mutex not poisoned")
    }

    /// Resolves once shutdown has been requested; resolves immediately if it
    /// already has been.
    ///
    /// `Notify`'s double-check pattern makes this cancel-safe: it is safe to
    /// re-create and race against another future in a `select!` on every
    /// loop iteration without losing a wakeup.
    pub async fn requested_fut(&self) {
        if self.is_requested() {
            return;
        }
        let notified = self.0.notify.notified();
        if self.is_requested() {
            return;
        }
        notified.await;
    }
}

impl Default for Shutdown {
    fn default() -> Self {
        Self::new()
    }
}

/// Sleeps for `delay`, but returns early (`true`) if `shutdown` is requested
/// first. Used to make `reconnect_loop`'s backoff sleeps shutdown-responsive.
pub async fn sleep_or_shutdown(delay: Duration, shutdown: &Shutdown) -> bool {
    tokio::select! {
        biased;
        _ = shutdown.requested_fut() => true,
        _ = tokio::time::sleep(delay) => false,
    }
}

// ---------------------------------------------------------------------------
// In-flight gauge
// ---------------------------------------------------------------------------

#[derive(Default)]
struct InflightInner {
    count: AtomicUsize,
    idle: Notify,
}

/// Counts Tasks currently in flight, spanning the whole spawned task
/// including the final `tx.send(TaskResult)` — unlike
/// [`CancelRegistry`](crate::cancel::CancelRegistry), which deregisters
/// *before* the result is sent. This is what makes `wait_idle()` a correct
/// "all results enqueued" signal for the drain.
#[derive(Clone, Default)]
pub struct Inflight(Arc<InflightInner>);

impl Inflight {
    /// Marks one Task as in flight; the count decrements when the returned
    /// guard is dropped.
    pub fn enter(&self) -> InflightGuard {
        self.0.count.fetch_add(1, Ordering::AcqRel);
        InflightGuard(Arc::clone(&self.0))
    }

    /// Returns the current in-flight count.
    pub fn count(&self) -> usize {
        self.0.count.load(Ordering::Acquire)
    }

    /// Resolves once the in-flight count reaches zero; resolves immediately
    /// if it already is.
    pub async fn wait_idle(&self) {
        loop {
            if self.count() == 0 {
                return;
            }
            let notified = self.0.idle.notified();
            if self.count() == 0 {
                return;
            }
            notified.await;
        }
    }
}

/// RAII guard returned by [`Inflight::enter`]; decrements the gauge on drop
/// and wakes any `wait_idle()` waiter when the count reaches zero.
pub struct InflightGuard(Arc<InflightInner>);

impl Drop for InflightGuard {
    fn drop(&mut self) {
        if self.0.count.fetch_sub(1, Ordering::AcqRel) == 1 {
            self.0.idle.notify_waiters();
        }
    }
}

// ---------------------------------------------------------------------------
// ShutdownContext bundle
// ---------------------------------------------------------------------------

/// Bundles the shutdown signal, the in-flight gauge, and the grace period
/// into a single cheaply-cloneable value.
///
/// `reconnect_loop` and `run_tunnel` take this ONE parameter instead of three
/// separate ones so neither crosses the `clippy::too_many_arguments` gate
/// (`reconnect_loop` has no existing allow and would reach 9 args with three
/// separate params; bundling keeps it at 7, under the >7 fire threshold).
#[derive(Clone)]
pub struct ShutdownContext {
    pub shutdown: Shutdown,
    pub inflight: Inflight,
    pub grace: Duration,
    /// The in-flight Task cancel registry, shared by `Arc` across every
    /// reconnect for the process's lifetime. Living here — rather
    /// than being recreated inside each `run_tunnel` — is what lets a
    /// `TaskCancel`, or the shutdown drain's grace-expiry kill, reach a Task
    /// that outlived the connection which started it.
    pub registry: CancelRegistry,
}

// ---------------------------------------------------------------------------
// Drain
// ---------------------------------------------------------------------------

/// Summary of a completed drain, logged once by `run_tunnel`.
pub struct DrainSummary {
    /// In-flight Task count observed at the start of the drain.
    pub in_flight: usize,
    /// Number of in-flight Tasks that finished naturally within the grace
    /// period.
    pub drained: usize,
    /// Number of registry entries the drain ATTEMPTED to cancel at grace
    /// expiry (`CancelRegistry::cancel_all`'s return value) — NOT a count of
    /// children confirmed killed. Per the ADR-0013 honest-race contract, a
    /// Task finishing in the same instant makes its `send(())` a no-op, so
    /// `killed` is an upper bound on force-terminated Tasks. Log-only; no
    /// correctness dependence on this number.
    pub killed: usize,
}

/// Drains in-flight Tasks: waits up to `grace` for all of them to finish
/// naturally, then force-cancels whatever remains.
///
/// Phase 1 — natural completion: if every in-flight Task finishes (including
/// its `tx.send(TaskResult)`) within `grace`, returns immediately with
/// `killed: 0`.
///
/// Phase 2 — grace expired: cancels every entry still held in `registry`
/// (reusing the vetted `CancelRegistry::cancel_all` honest-race path, which
/// fires each in-flight executor's `recv_cancel` -> `kill_group_graceful` ->
/// `OUTCOME_CANCELLED`), then waits up to `KILL_FLUSH_BUDGET` for those kills
/// to land and their results to flush.
///
/// Intentionally free of tunnel/tx/log types so it is unit-testable in
/// isolation; the tunnel wiring and the single shutdown log line live in
/// `run_tunnel`.
pub async fn drain(
    inflight: &Inflight,
    registry: &CancelRegistry,
    grace: Duration,
) -> DrainSummary {
    let in_flight = inflight.count();

    if timeout(grace, inflight.wait_idle()).await.is_ok() {
        return DrainSummary {
            in_flight,
            drained: in_flight,
            killed: 0,
        };
    }

    let killed = registry.cancel_all();
    let _ = timeout(KILL_FLUSH_BUDGET, inflight.wait_idle()).await;

    DrainSummary {
        in_flight,
        drained: in_flight.saturating_sub(killed),
        killed,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // parse_grace_secs
    // -----------------------------------------------------------------------

    #[test]
    fn parse_grace_none_defaults_to_30s() {
        assert_eq!(parse_grace_secs(None), Duration::from_secs(30));
    }

    #[test]
    fn parse_grace_valid_value() {
        assert_eq!(parse_grace_secs(Some("10")), Duration::from_secs(10));
    }

    #[test]
    fn parse_grace_zero_defaults_to_30s() {
        assert_eq!(parse_grace_secs(Some("0")), Duration::from_secs(30));
    }

    #[test]
    fn parse_grace_unparsable_defaults_to_30s() {
        assert_eq!(parse_grace_secs(Some("abc")), Duration::from_secs(30));
    }

    // -----------------------------------------------------------------------
    // Inflight
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn inflight_enter_increments_and_drop_decrements() {
        let inflight = Inflight::default();
        assert_eq!(inflight.count(), 0);
        let guard = inflight.enter();
        assert_eq!(inflight.count(), 1);
        drop(guard);
        assert_eq!(inflight.count(), 0);
    }

    #[tokio::test]
    async fn inflight_wait_idle_returns_immediately_when_empty() {
        let inflight = Inflight::default();
        // Must not hang: no guard held.
        tokio::time::timeout(Duration::from_millis(200), inflight.wait_idle())
            .await
            .expect("wait_idle must return immediately when count == 0");
    }

    #[tokio::test]
    async fn inflight_wait_idle_wakes_after_guard_dropped() {
        let inflight = Inflight::default();
        let guard = inflight.enter();

        let waiter = {
            let inflight = inflight.clone();
            tokio::spawn(async move { inflight.wait_idle().await })
        };

        // Give the waiter a moment to register on Notify before we drop.
        tokio::time::sleep(Duration::from_millis(20)).await;
        drop(guard);

        tokio::time::timeout(Duration::from_millis(500), waiter)
            .await
            .expect("wait_idle must wake after the held guard is dropped")
            .expect("waiter task must not panic");
    }

    // -----------------------------------------------------------------------
    // Shutdown
    // -----------------------------------------------------------------------

    #[test]
    fn shutdown_starts_unrequested() {
        let shutdown = Shutdown::new();
        assert!(!shutdown.is_requested());
    }

    #[test]
    fn shutdown_trigger_sets_requested_and_reason() {
        let shutdown = Shutdown::new();
        shutdown.trigger("SIGTERM");
        assert!(shutdown.is_requested());
        assert_eq!(shutdown.reason(), "SIGTERM");
    }

    #[tokio::test]
    async fn shutdown_requested_fut_completes_after_trigger() {
        let shutdown = Shutdown::new();
        shutdown.trigger("SIGINT");
        tokio::time::timeout(Duration::from_millis(200), shutdown.requested_fut())
            .await
            .expect("requested_fut must resolve once already triggered");
    }

    #[tokio::test]
    async fn shutdown_requested_fut_wakes_on_later_trigger() {
        let shutdown = Shutdown::new();
        let waiter = {
            let shutdown = shutdown.clone();
            tokio::spawn(async move { shutdown.requested_fut().await })
        };
        tokio::time::sleep(Duration::from_millis(20)).await;
        shutdown.trigger("SIGTERM");
        tokio::time::timeout(Duration::from_millis(500), waiter)
            .await
            .expect("requested_fut must wake once triggered")
            .expect("waiter task must not panic");
    }

    #[tokio::test]
    async fn sleep_or_shutdown_returns_false_without_trigger() {
        let shutdown = Shutdown::new();
        let won = sleep_or_shutdown(Duration::from_millis(30), &shutdown).await;
        assert!(!won, "no trigger fired; the sleep should win");
    }

    #[tokio::test]
    async fn sleep_or_shutdown_returns_true_when_triggered_first() {
        let shutdown = Shutdown::new();
        shutdown.trigger("SIGTERM");
        let won = sleep_or_shutdown(Duration::from_secs(30), &shutdown).await;
        assert!(won, "shutdown was already triggered; it should win");
    }

    // -----------------------------------------------------------------------
    // drain
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn drain_natural_completion_before_grace_expiry() {
        let inflight = Inflight::default();
        let registry = CancelRegistry::new();

        let guard = inflight.enter();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(50)).await;
            drop(guard);
        });

        let start = tokio::time::Instant::now();
        let summary = drain(&inflight, &registry, Duration::from_secs(5)).await;
        assert!(
            start.elapsed() < Duration::from_secs(5),
            "drain must return promptly once the Task finishes naturally, took {:?}",
            start.elapsed()
        );
        assert_eq!(summary.in_flight, 1);
        assert_eq!(summary.drained, 1);
        assert_eq!(summary.killed, 0);
    }

    // Proves DI-14.
    #[tokio::test]
    async fn drain_grace_expiry_kills_remaining() {
        let inflight = Inflight::default();
        let registry = CancelRegistry::new();

        let cancel_rx = registry
            .register("stuck-task")
            .expect("register stuck-task");
        let guard = inflight.enter();
        // The "stuck" task only releases its guard once it receives the
        // cancel signal — deterministic, like the executor cancel tests.
        tokio::spawn(async move {
            let _ = cancel_rx.await;
            drop(guard);
        });

        let summary = drain(&inflight, &registry, Duration::from_millis(100)).await;
        assert_eq!(summary.in_flight, 1);
        assert_eq!(summary.killed, 1);
        assert_eq!(summary.drained, 0);
    }
}
