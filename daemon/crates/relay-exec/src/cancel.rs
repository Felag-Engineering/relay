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
//!
//! # Lifetime across reconnects
//!
//! A single registry is shared by `Arc` across every reconnect for the process's
//! lifetime (it lives in the bin's `shutdown::ShutdownContext`), so a
//! `TaskCancel` — or a shutdown-kill — for a Task that outlives the connection that
//! started it still reaches that Task's executor. When it was recreated per-connection,
//! such a cancel hit a fresh empty registry and was a silent no-op.
//!
//! Sharing the registry means the Relay's at-most-once **redelivery** of a still-in-flight
//! `task_id` (a resend after a reconnect, before it has seen the result) now collides with
//! the live entry. [`register`](CancelRegistry::register) is therefore **first-writer-wins**:
//! it inserts only if the id is absent and returns `None` when a still-live prior lifecycle
//! already owns the entry. The duplicate is left to the dedup store to make benign, and —
//! because it does not own the entry — it must NOT deregister it (that would remove the live
//! Task's cancel handle). Only the owning lifecycle deregisters.

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

    /// Registers `task_id` as in-flight and returns the cancel receiver, or
    /// `None` if the id is already registered by a still-live lifecycle.
    ///
    /// **First-writer-wins.** With a process-lifetime registry shared
    /// across reconnects, the Relay's at-most-once redelivery of a still-in-flight
    /// `task_id` reaches `register` while the original entry is still present. The
    /// original owns the live cancel handle, so it must not be clobbered: on a
    /// collision this inserts nothing and returns `None`. The caller spawns the
    /// duplicate anyway (the dedup store makes it a benign no-op) but, holding no
    /// registration, must NOT deregister — see `run_tunnel`.
    ///
    /// On success the receiver is passed into the spawned Task's `ExecRequest.cancel`,
    /// and the sender stays in the registry until `cancel` or `deregister`.
    pub fn register(&self, task_id: &str) -> Option<oneshot::Receiver<()>> {
        let mut map = self.0.lock().expect("CancelRegistry Mutex not poisoned");
        if map.contains_key(task_id) {
            // A still-live prior lifecycle owns this id (cross-reconnect redelivery
            // or an in-connection duplicate). Leave its cancel handle intact.
            return None;
        }
        let (tx, rx) = oneshot::channel();
        map.insert(task_id.to_string(), tx);
        Some(rx)
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
    /// whatever is still in flight.
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
        let rx = registry.register("t1").expect("first register owns the id");
        registry.cancel("t1");
        assert!(
            rx.await.is_ok(),
            "cancel must deliver Ok(()) to the registered receiver"
        );
    }

    /// First-writer-wins (issue #337): a second register of a still-live id
    /// returns None and leaves the original's cancel handle intact.
    #[tokio::test]
    async fn second_register_of_live_id_returns_none_and_preserves_the_owner() {
        let registry = CancelRegistry::new();
        let rx_owner = registry
            .register("dup")
            .expect("first register owns the id");
        assert!(
            registry.register("dup").is_none(),
            "a second register of a live id must not clobber the owner"
        );
        // The owner's handle still works: cancel reaches it, not a dropped Err.
        registry.cancel("dup");
        assert!(
            rx_owner.await.is_ok(),
            "the original receiver must still receive the explicit cancel"
        );
        // Once the owner releases the id, it can be registered afresh.
        assert!(
            registry.register("dup").is_some(),
            "after cancel cleared the entry, the id is registrable again"
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
        let rx = registry.register("t2").expect("first register owns the id");
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
        let rx_a = registry.register("a").expect("register a");
        let rx_b = registry.register("b").expect("register b");
        let rx_c = registry.register("c").expect("register c");

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

    /// Cross-reconnect (issue #337): each `run_tunnel` uses its own *clone* of
    /// the one shared registry. A Task registered on connection A's clone must
    /// still be cancellable through connection B's clone — the property that
    /// was broken when the registry was recreated per-connection.
    #[tokio::test]
    async fn a_task_registered_on_one_clone_is_cancellable_through_another() {
        let shared = CancelRegistry::new();

        // Connection A registers a long-running Task, then its stream drops.
        let conn_a = shared.clone();
        let rx = conn_a
            .register("long-task")
            .expect("first register owns the id");

        // Connection B is a fresh clone of the SAME shared registry (what
        // reconnect_loop hands the next run_tunnel). The operator's TaskCancel
        // arrives here.
        let conn_b = shared.clone();
        conn_b.cancel("long-task");

        assert!(
            rx.await.is_ok(),
            "cancel on the reconnected clone must reach the Task from the prior connection"
        );
    }
}
