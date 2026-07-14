//! In-flight Task cancel registry — connects the inbound tunnel loop to a running
//! execute call via a tokio oneshot channel (ADR-0013).
//!
//! # Honest-race contract
//!
//! The sender is inserted into the registry **before** the Task is spawned.
//! `cancel` delivers an explicit `send(())` — a dropped sender (deregister) resolves
//! to `Err`, which `recv_cancel` in executor.rs maps to `std::future::pending()`,
//! NEVER to cancel. Only `CancelRegistry::cancel` can trigger cancellation; dropping
//! the registry or calling `deregister` cannot.
//!
//! # Dedup interaction (ADR-0004)
//!
//! `CancelRegistry` is dedup-agnostic. Cancellation fires inside the dedup `run_once`
//! closure, after the task_id marker is durably recorded. A cancelled id stays in the
//! dedup store; a re-send is deduplicated (at-most-once).

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use tokio::sync::oneshot;

/// Shared, cheaply-cloneable registry of in-flight Task cancellation handles.
///
/// Interior-mutable: `Arc<Mutex<...>>` so the registry can be shared across the
/// inbound loop (cancel sender) and the per-Task spawned task (receiver / deregister).
///
/// **Never hold the Mutex guard across an `.await`** — clippy::await_holding_lock.
#[derive(Clone, Default)]
pub struct CancelRegistry(Arc<Mutex<HashMap<String, oneshot::Sender<()>>>>);

impl CancelRegistry {
    /// Creates a new, empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers `task_id` as in-flight and returns the cancel receiver.
    ///
    /// The receiver is passed into the spawned Task's `ExecRequest.cancel`.
    /// The corresponding sender stays in the registry until `cancel` or `deregister`.
    ///
    /// If a sender for the same `task_id` already exists (a bug — re-registration
    /// without deregistration), the old sender is overwritten and dropped. Dropping a
    /// sender resolves the old receiver to `Err`, which `recv_cancel` maps to
    /// `pending()` — the old in-flight task cannot be accidentally cancelled.
    pub fn register(&self, task_id: &str) -> oneshot::Receiver<()> {
        let (tx, rx) = oneshot::channel();
        self.0
            .lock()
            .expect("CancelRegistry Mutex not poisoned")
            .insert(task_id.to_string(), tx);
        rx
    }

    /// Removes the sender for `task_id` (idempotent).
    ///
    /// Called by the spawned Task after `dispatch` returns so the handle is not
    /// left dangling. Dropping the sender resolves the receiver to `Err`, which
    /// `recv_cancel` maps to `pending()` — no cancellation effect.
    pub fn deregister(&self, task_id: &str) {
        self.0
            .lock()
            .expect("CancelRegistry Mutex not poisoned")
            .remove(task_id);
    }

    /// Sends the cancel signal for `task_id`.
    ///
    /// If the id is unknown or already finished (deregistered), this is a safe
    /// no-op — `remove` returns `None` and no send is attempted. Uses explicit
    /// `send(())` — never signals by dropping — so only this method can trigger
    /// cancellation; deregister/drop cannot.
    pub fn cancel(&self, task_id: &str) {
        if let Some(tx) = self
            .0
            .lock()
            .expect("CancelRegistry Mutex not poisoned")
            .remove(task_id)
        {
            // Ignore send error: the receiver may have already resolved (honest race).
            let _ = tx.send(());
        }
    }

    /// Sends the cancel signal to every currently-registered Task and empties
    /// the registry. Used at graceful-shutdown grace expiry to force-terminate
    /// whatever is still in flight (issue #177).
    ///
    /// Returns the number of entries the registry held at the time of the
    /// call — i.e. the number of cancels ATTEMPTED, not a count of children
    /// confirmed killed. Per the honest-race contract, a Task that finishes
    /// concurrently with this call may already have been deregistered (so it
    /// is not counted) or may see its `send(())` land as a harmless no-op if
    /// its own `recv_cancel` has already resolved by the time it's delivered
    /// (ADR-0013) — either way, the returned count is an upper bound on
    /// force-terminated Tasks, log-only, with no correctness dependence.
    pub fn cancel_all(&self) -> usize {
        let mut map = self.0.lock().expect("CancelRegistry Mutex not poisoned");
        let n = map.len();
        for (_id, tx) in map.drain() {
            // Ignore send error: the receiver may have already resolved (honest race).
            let _ = tx.send(());
        }
        n
    }
}

#[cfg(test)]
mod tests {
    use super::CancelRegistry;

    /// register → cancel delivers Ok(()) on the receiver.
    #[tokio::test]
    async fn register_then_cancel_delivers() {
        let registry = CancelRegistry::new();
        let rx = registry.register("t1");
        registry.cancel("t1");
        assert!(
            rx.await.is_ok(),
            "cancel must deliver Ok(()) to the registered receiver"
        );
    }

    /// cancel for an unknown task_id is a no-op (no panic, no crash).
    #[test]
    fn cancel_unknown_id_is_noop() {
        let registry = CancelRegistry::new();
        // Must not panic.
        registry.cancel("nonexistent");
    }

    /// deregister → cancel: deregister drops the sender; a subsequent cancel
    /// finds no entry and is a no-op. The receiver resolves to Err (sender dropped),
    /// never Ok (explicit cancel signal).
    #[tokio::test]
    async fn deregister_then_cancel_is_noop() {
        let registry = CancelRegistry::new();
        let rx = registry.register("t2");
        registry.deregister("t2");
        registry.cancel("t2"); // must be a no-op; sender already removed

        // The receiver was never sent to — it resolves to Err because the sender
        // was dropped by deregister (not by cancel's explicit send).
        assert!(
            rx.await.is_err(),
            "after deregister, the receiver must resolve to Err (no explicit send)"
        );
    }

    /// cancel_all delivers to every registered receiver, returns the count,
    /// and empties the registry.
    #[tokio::test]
    async fn cancel_all_delivers_to_all_and_empties_registry() {
        let registry = CancelRegistry::new();
        let rx_a = registry.register("a");
        let rx_b = registry.register("b");
        let rx_c = registry.register("c");

        let n = registry.cancel_all();
        assert_eq!(n, 3, "cancel_all must return the number of entries held");

        assert!(rx_a.await.is_ok(), "a must receive the cancel signal");
        assert!(rx_b.await.is_ok(), "b must receive the cancel signal");
        assert!(rx_c.await.is_ok(), "c must receive the cancel signal");

        // The registry is now empty: a following cancel is a no-op.
        registry.cancel("a"); // must not panic
    }

    /// cancel_all on an empty registry is a no-op that returns 0.
    #[test]
    fn cancel_all_on_empty_registry_returns_zero() {
        let registry = CancelRegistry::new();
        assert_eq!(registry.cancel_all(), 0);
    }
}
