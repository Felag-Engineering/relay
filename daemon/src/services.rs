//! The daemon's per-process shared services, bundled as one value.

use std::sync::Arc;

use crate::dedup::DedupStore;
use crate::policy::Policy;
use crate::scheduler::Scheduler;
use crate::templates::TemplateSet;

/// The objects every Task on this Node shares: the live Policy, the loaded
/// Template Operations, the dedup store and the concurrency scheduler.
///
/// Constructed exactly **once per process**, in `main`, before the first
/// connect, and shared (as `Arc<Services>`) across every reconnect and every
/// spawned per-Task future for the process's whole lifetime. Nothing here is
/// ever rebuilt on a reconnect:
///
/// - `dedup` surviving a reconnect is what makes Task execution at-most-once
///   across a Relay redelivery (ADR-0004, invariant 4) — a per-connection
///   store would forget every task_id the previous stream had seen.
/// - `scheduler` surviving a reconnect keeps the mutate lane strictly serial
///   across connections: a Task still running from a dropped stream holds its
///   permit against one from the new stream (ADR-0012).
/// - `policy` and `templates` are locally rooted and never settable over the
///   wire (ADR-0002, ADR-0021), so the fingerprints reported in `Hello` are
///   stable across a reconnect.
///
/// This is plumbing only: it owns the four objects and decides nothing. The
/// dedup → schedule → Policy → execute ordering lives in `dispatch`.
pub struct Services {
    /// The live Policy (ADR-0002/0011).
    pub policy: Policy,
    /// This Node's Template Operations (ADR-0021).
    pub templates: TemplateSet,
    /// The at-most-once task_id store (ADR-0004).
    pub dedup: DedupStore,
    /// The per-risk-class concurrency gates (ADR-0012). An `Arc` because that
    /// is the shape [`Scheduler::new`] hands out.
    pub scheduler: Arc<Scheduler>,
}
