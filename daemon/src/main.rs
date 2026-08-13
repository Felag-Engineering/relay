use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tonic::transport::Channel;
use tracing::{debug, error, info, warn};

mod cancel;
mod catalog;
mod config;
mod dedup;
mod dispatch;
mod enroll;
mod executor;
mod identity;
mod operations;
mod policy;
mod policy_check;
mod raw_exec;
mod renew;
mod scheduler;
mod selfref;
mod shutdown;
mod templates;
mod tunnel;
mod version;

use cancel::CancelRegistry;
use config::Config;
use scheduler::Scheduler;
use shutdown::{Inflight, Shutdown, ShutdownContext};
use tunnel::{Backoff, RECONNECT_BACKOFF_BASE, RECONNECT_BACKOFF_CAP};

#[allow(dead_code, unused_imports, clippy::all)]
mod gen {
    include!(concat!(env!("OUT_DIR"), "/relay.v1.rs"));
}

use gen::{
    daemon_message, relay_message, tunnel_client::TunnelClient, ArgMatcher, DaemonMessage,
    DenyRule, Facts, Heartbeat, Hello, OperationRule, PolicySnapshot,
};

fn now_millis() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64
}

/// Parses the heartbeat interval from an optional env-var string.
///
/// Returns `Duration::from_secs(secs)` for any positive integer; falls back to
/// 30 seconds when the input is absent, unparsable, or zero. Minimum floor is
/// 1 second (automatically satisfied because zero → 30).
fn parse_interval_secs(raw: Option<&str>) -> Duration {
    let secs = raw
        .and_then(|s| s.parse::<u64>().ok())
        .filter(|&n| n > 0)
        .unwrap_or(30);
    Duration::from_secs(secs)
}

/// Reads `RELAY_HEARTBEAT_INTERVAL_SECS` and returns the configured interval,
/// defaulting to 30 seconds on absence or invalid input.
fn heartbeat_interval() -> Duration {
    parse_interval_secs(
        std::env::var("RELAY_HEARTBEAT_INTERVAL_SECS")
            .ok()
            .as_deref(),
    )
}

/// Applies symmetric jitter to `interval`.
///
/// `jitter_frac` is the fraction of the interval to jitter by (e.g. 0.2 → ±20%).
/// `sample` must be in [0, 1); it is multiplied to produce a delay in
/// `[interval*(1-jitter_frac), interval*(1+jitter_frac)]`.
fn heartbeat_delay(interval: Duration, jitter_frac: f64, sample: f64) -> Duration {
    let scale = (1.0 + jitter_frac * (sample * 2.0 - 1.0)).max(0.0);
    interval.mul_f64(scale)
}

/// Returns a pseudo-random sample in [0, 1) using only `std` — no extra crates.
///
/// Uses the sub-second nanoseconds of `SystemTime::now()` XOR'd with the
/// process ID. The XOR with `std::process::id()` ensures that a bulk-restarted
/// fleet whose daemons all start within the same second produces distinct jitter
/// values rather than reconverging on the same send time.
pub(crate) fn rand_unit() -> f64 {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .subsec_nanos();
    // XOR in the PID so daemons started in the same second diverge.
    let mixed = (nanos ^ std::process::id()) % 1_000_000_000;
    mixed as f64 / 1e9
}

/// Acquires an enrolled identity before connecting to the Relay.
///
/// Fail closed: if no enrollment token is configured and no persisted identity
/// exists in state_dir, this returns an error rather than falling back to a
/// plaintext dial (ADR-0005, invariant #6).
async fn acquire_identity(
    config: &Config,
) -> Result<crate::identity::Identity, Box<dyn std::error::Error>> {
    let identity = match enroll::EnrollConfig::from_config(config)? {
        Some(cfg) => enroll::ensure_enrolled(&cfg).await?,
        None => identity::load_identity(&config.state_dir)?.ok_or(
            "no enrolled identity in state dir; refusing to connect (fail closed, no plaintext)",
        )?,
    };
    Ok(identity)
}

/// Assembles a `PolicySnapshot` from the live, loaded Policy for the Relay to
/// display.
///
/// Report-only / display-only (ADR-0002, ADR-0011): every field is read
/// straight from `policy`'s own accessors — no re-evaluation, nothing
/// Relay-derived. `policy_fingerprint` calls the SAME [`policy::Policy::fingerprint`]
/// Hello uses, so a snapshot and the Hello sent from the same `Policy` always
/// agree. `operation_rules` and `deny_rules` are verbatim mirrors of every
/// `[[operation]]`/`[[deny]]` block (file order, no dedup, no evaluation).
fn policy_snapshot(policy: &policy::Policy) -> PolicySnapshot {
    PolicySnapshot {
        raw_exec_enabled: policy.raw_exec_enabled(),
        raw_allow_patterns: policy.raw_allow_patterns(),
        raw_deny_patterns: policy.raw_deny_patterns(),
        allowed_operations: policy.allowed_operations(),
        policy_fingerprint: policy.fingerprint().to_string(),
        operation_rules: policy
            .operation_allow_rules()
            .into_iter()
            .map(|r| OperationRule {
                name: r.name,
                allowed_args: r
                    .allowed_args
                    .into_iter()
                    .map(|values| ArgMatcher { values })
                    .collect(),
            })
            .collect(),
        deny_rules: policy
            .deny_rules()
            .into_iter()
            .map(|r| DenyRule {
                name: r.name,
                args: r
                    .args
                    .into_iter()
                    .map(|values| ArgMatcher { values })
                    .collect(),
            })
            .collect(),
    }
}

/// The outcome of one `run_tunnel` session, reported to `reconnect_loop` so it
/// can decide whether to reset the reconnect backoff.
///
/// "Healthy" = `client.open()` succeeded (TLS handshake AND the gRPC bidi
/// stream both came up). A revoked or wrong-CA Node never gets this far — it
/// fails inside `connect_mtls`, before `run_tunnel` is even called — so that
/// case can never reset the backoff and correctly ramps to the cap.
enum TunnelExit {
    /// `open()`/Hello send failed — the stream never authenticated. The
    /// backoff is NOT reset.
    NotEstablished(Box<dyn std::error::Error + Send + Sync>),
    /// The Relay closed the stream cleanly after a healthy `open()`. The
    /// backoff IS reset.
    ClosedClean,
    /// The stream errored mid-session after a healthy `open()`. The backoff
    /// IS reset.
    DroppedMidSession(Box<dyn std::error::Error + Send + Sync>),
    /// A shutdown signal was received; in-flight Tasks were drained (or
    /// killed at grace expiry) and the stream was closed cleanly. The caller
    /// must NOT reconnect — the process is exiting (issue #177).
    ShutdownComplete,
}

/// Hard upper bound on Tasks the daemon will hold in flight at once, across all
/// risk classes (issue #338).
///
/// This is a **local DoS backstop, not a throughput knob** — the sibling of
/// `scheduler::READ_CONCURRENCY`. The scheduler bounds how many Tasks *execute*
/// concurrently (mutate serial, read bounded-parallel); it does not bound how
/// many the daemon will *accept and park* waiting for a slot. Without this cap,
/// a Relay that ignores its own blast-radius limit — or a compromised one —
/// could stream unbounded Tasks and grow the daemon's parked-task set (each an
/// allocated future, a cancel-registry entry, and an inflight guard) until the
/// privileged daemon is starved of memory. ADR-0004's blast cap lives on the
/// Relay; this is the daemon-side floor that does not trust the Relay to have
/// enforced it.
///
/// Fixed and deliberately generous: far above any legitimate concurrent fan-out
/// to a single Node, low enough to bound worst-case memory. Not configurable
/// this milestone — a constant backstop cannot be raised over the wire, which
/// is the point (cf. invariant #11, config never rises from the control plane).
const MAX_INFLIGHT_TASKS: usize = 1024;

/// Sends the initial Hello, followed by a `PolicySnapshot` of the live Policy
/// (report-only, ADR-0002/0011), drives the heartbeat loop, and processes
/// inbound messages from the Relay until the stream closes or errors.
///
/// Returns a [`TunnelExit`] describing why the session ended rather than a
/// bare `Result`, so the caller (`reconnect_loop`) can tell a healthy session
/// (stream opened, later closed or dropped — reset the backoff) apart from a
/// stream that never got established (Hello/`open()` failed — do not reset).
///
/// Inbound `RelayMessage` handling:
/// - `Task`: registered in the cancel registry BEFORE spawning, then dispatched
///   through the dedup → scheduler → Policy → execute pipeline in a detached task
///   so the loop keeps reading and can receive `TaskCancel` messages
///   (ADR-0001/0002/0004/0013). The scheduler gates concurrency by risk class:
///   mutate Tasks are strictly serial; read Tasks are bounded-parallel (up to
///   `READ_CONCURRENCY`). Queue-wait time counts against the Task's timeout clock
///   (started at receipt). Exactly one `TaskResult` is emitted per Task in every
///   path: executed, queued-timeout, queued-cancel, in-flight-cancel, dedup-benign.
///   Admission is capped at [`MAX_INFLIGHT_TASKS`]: a Task arriving while the
///   daemon is already at that many in flight is refused inline with an
///   `OUTCOME_FAILURE` result and never registered, spawned, or deduplicated
///   (safe to retry) — the daemon-side backstop to the Relay's blast cap.
/// - `TaskCancel`: delivers the cancel signal to the in-flight Task's executor via
///   the cancel registry (ADR-0013). If the task_id is unknown or already finished,
///   this is a safe no-op. The inbound loop NEVER touches the scheduler, so
///   TaskCancel delivery is never blocked by a running Task.
/// - `PolicyQuery`: evaluated inline against the loaded Policy (ADR-0011). No dedup,
///   no executor — structurally incapable of recording a marker or spawning a process.
/// - Other message types: silently ignored for forward-compatibility.
///
/// Policy, DedupStore, and Scheduler are passed as `Arc` so spawned per-Task tasks
/// are `'static`.
#[allow(clippy::too_many_arguments)]
async fn run_tunnel(
    channel: Channel,
    identity: &crate::identity::Identity,
    facts: Facts,
    node_labels: Vec<(String, String)>,
    interval: Duration,
    policy: Arc<policy::Policy>,
    templates: Arc<templates::TemplateSet>,
    dedup: Arc<dedup::DedupStore>,
    scheduler: Arc<Scheduler>,
    ctx: &ShutdownContext,
) -> TunnelExit {
    let mut client = TunnelClient::new(channel);
    let (tx, rx) = mpsc::channel::<DaemonMessage>(32);

    // Send Hello as the first outbound message on the bidi stream.
    // node_id is the Relay-assigned identity (from the enrolled cert CN),
    // aligning the app-layer identity with the transport-layer client cert
    // (ADR-0006 amendment 2).
    if tx
        .send(DaemonMessage {
            body: Some(daemon_message::Body::Hello(Hello {
                node_id: identity.node_id.clone(),
                // The build-stamped version (issue #249, ADR-0014): this is the
                // sole input to the Relay's minimum-daemon-version dispatch
                // gate, so it is always valid semver and always ordered
                // truthfully against the release it precedes — see version.rs.
                daemon_version: version::version().to_string(),
                facts: Some(facts),
                labels: enroll::node_labels_to_proto(&node_labels),
                policy_fingerprint: policy.fingerprint().to_string(),
                // Beside the Policy fingerprint, from the same live set the
                // dispatch path resolves against (ADR-0021): the Relay's
                // fleet-wide template-drift signal. Report-only — templates are
                // locally rooted and never settable over the wire (ADR-0002).
                template_set_fingerprint: templates.fingerprint().to_string(),
            })),
        })
        .await
        .is_err()
    {
        return TunnelExit::NotEstablished("failed to buffer Hello/PolicySnapshot".into());
    }

    // Send the effective PolicySnapshot immediately after Hello: report-only,
    // for the Relay's display cache (ADR-0002/0011). Hello's `policy_fingerprint`
    // is a summary; this is the full snapshot, from the same live `policy`.
    if tx
        .send(DaemonMessage {
            body: Some(daemon_message::Body::Policy(policy_snapshot(&policy))),
        })
        .await
        .is_err()
    {
        return TunnelExit::NotEstablished("failed to buffer Hello/PolicySnapshot".into());
    }

    // ...and the TemplateSnapshot right after it: this Node's Template
    // Operation vocabulary, for the Relay's per-Node discovery view (ADR-0021,
    // issue #291). Report-only, from the same live set dispatch resolves
    // against, refreshed on every (re)connect exactly like the Policy view.
    if tx
        .send(DaemonMessage {
            body: Some(daemon_message::Body::Templates(templates.snapshot())),
        })
        .await
        .is_err()
    {
        return TunnelExit::NotEstablished("failed to buffer Hello/TemplateSnapshot".into());
    }

    // Background task: emit a Heartbeat at a configurable, jittered interval.
    // Jitter spreads send times across a bulk-restarted fleet so daemons do not
    // all arrive at the Relay simultaneously. RELAY_HEARTBEAT_INTERVAL_SECS
    // configures the base interval (default 30 s); each iteration re-samples so
    // the spread is maintained over the lifetime of the connection.
    let tx_hb = tx.clone();
    let hb_handle = tokio::spawn(async move {
        loop {
            tokio::time::sleep(heartbeat_delay(interval, 0.2, rand_unit())).await;
            if tx_hb
                .send(DaemonMessage {
                    body: Some(daemon_message::Body::Heartbeat(Heartbeat {
                        unix_millis: now_millis(),
                    })),
                })
                .await
                .is_err()
            {
                break;
            }
        }
    });
    // Keep tx alive for the inbound loop (Task results are sent on it).
    // The heartbeat task has its own tx_hb clone; this tx is for Task results.
    // hb_handle is aborted on graceful shutdown (below) to release tx_hb
    // promptly so the outbound stream half-closes without waiting on it.

    let response = match client.open(ReceiverStream::new(rx)).await {
        Ok(response) => response,
        Err(status) => return TunnelExit::NotEstablished(Box::new(status)),
    };
    let mut inbound = response.into_inner();

    // First inbound message must be the Relay's Ping (handshake confirmation).
    // The stream is healthy from here on: open() succeeded, so a failure below
    // is a mid-session drop, not a failed stream establishment.
    match inbound.message().await {
        Ok(Some(msg)) => match msg.body {
            Some(relay_message::Body::Ping(ping)) => {
                info!(unix_millis = ping.unix_millis, "received Ping from Relay");
            }
            Some(_) => error!("expected Ping as first RelayMessage"),
            None => error!("received empty RelayMessage body"),
        },
        Ok(None) => return TunnelExit::ClosedClean,
        Err(e) => return TunnelExit::DroppedMidSession(Box::new(e)),
    }

    // Cancel registry: maps in-flight task_ids to their cancel senders.
    // Registration happens BEFORE spawn so no TaskCancel can arrive in a window
    // where the task is in flight but not yet registered.
    //
    // Shared by Arc across every reconnect (issue #337): it is owned by `ctx`
    // for the process's lifetime, so a TaskCancel — or the drain's grace-expiry
    // kill — for a Task that outlives its originating connection still reaches
    // that Task's executor. Recreating it per-connection made such a cancel a
    // silent no-op against a fresh empty registry.
    let registry = ctx.registry.clone();

    // Drive the inbound stream. Spawning a detached task per Task keeps the loop
    // readable so TaskCancel and PolicyQuery messages can arrive while a Task is
    // in flight or queued. The inbound loop never touches the scheduler.
    //
    // The `ctx.shutdown` arm ONLY breaks — it must not move `tx`/`inbound`, or
    // the borrow checker rejects it against the inbound-message arm below. All
    // non-shutdown exits `return` directly, so the code after this loop is
    // reached only via the shutdown break (issue #177).
    loop {
        tokio::select! {
            biased;
            _ = ctx.shutdown.requested_fut() => {
                break;
            }
            msg = inbound.message() => match msg {
            Ok(Some(msg)) => {
                match msg.body {
                    Some(relay_message::Body::Task(task_req)) => {
                        // Admission backstop (issue #338): refuse the Task if the
                        // daemon is already at MAX_INFLIGHT_TASKS. The check is
                        // race-free from the admit side because this inbound loop
                        // is single-threaded — nothing else enters the inflight
                        // gauge, and `enter()` below happens on this same task
                        // after the check. A refused Task is NOT registered in the
                        // cancel registry and NOT recorded in the DedupStore: it
                        // never ran, so a later re-send must remain free to execute
                        // (ADR-0004). We keep reading the stream (send the result
                        // inline and `continue`) rather than applying backpressure,
                        // so TaskCancel/PolicyQuery keep flowing while at capacity.
                        if ctx.inflight.count() >= MAX_INFLIGHT_TASKS {
                            warn!(
                                task_id = %task_req.task_id,
                                cap = MAX_INFLIGHT_TASKS,
                                "refusing Task: daemon at in-flight backstop",
                            );
                            if tx
                                .send(DaemonMessage {
                                    body: Some(daemon_message::Body::TaskResult(
                                        dispatch::overloaded_result(task_req.task_id),
                                    )),
                                })
                                .await
                                .is_err()
                            {
                                return TunnelExit::DroppedMidSession("outbound closed".into());
                            }
                            continue;
                        }
                        // Capture the true receipt time before spawning. The scheduler
                        // uses this as the single clock origin for the Task's timeout
                        // budget, covering both queue-wait time and execution time.
                        let received_at = tokio::time::Instant::now();
                        let task_id = task_req.task_id.clone();
                        // Register BEFORE spawn: eliminates the window where
                        // a TaskCancel could arrive before the registry entry exists.
                        //
                        // First-writer-wins (issue #337): if the id is already
                        // registered — the Relay redelivered a still-in-flight
                        // task_id across a reconnect — `register` returns None and
                        // leaves the live owner's cancel handle intact. We still
                        // spawn (the dedup store makes the duplicate a benign
                        // no-op) but, owning no registration, must NOT deregister
                        // it: doing so would strip the live Task's cancel handle.
                        let cancel_rx = registry.register(&task_id);
                        let owns_registration = cancel_rx.is_some();
                        // Counts this Task from acceptance until its result is
                        // enqueued on `tx` (below) — spans strictly more than the
                        // cancel registry entry, which deregisters BEFORE the
                        // send. This makes inflight-idle a correct "all results
                        // enqueued" signal for the graceful-shutdown drain
                        // (issue #177).
                        let guard = ctx.inflight.enter();
                        let policy = Arc::clone(&policy);
                        let templates = Arc::clone(&templates);
                        let dedup = Arc::clone(&dedup);
                        let scheduler = Arc::clone(&scheduler);
                        let registry = registry.clone();
                        let tx = tx.clone();
                        tokio::spawn(async move {
                            // dispatch handles the full pipeline: dedup → schedule
                            // (acquire per-risk-class slot, block until available or
                            // timeout/cancel) → Policy → execute. The scheduler gate is
                            // held across execution; the inbound loop never touches it,
                            // so TaskCancel delivery is never blocked.
                            let result = dispatch::dispatch(
                                &task_req,
                                &policy,
                                &templates,
                                &dedup,
                                &scheduler,
                                received_at,
                                cancel_rx,
                            )
                            .await;
                            // Deregister before sending the result so a subsequent
                            // TaskCancel for this id is a clean no-op — but ONLY if
                            // this lifecycle owns the registration. A redelivered
                            // duplicate (owns_registration == false) must leave the
                            // live owner's entry alone (issue #337).
                            if owns_registration {
                                registry.deregister(&task_id);
                            }
                            if tx
                                .send(DaemonMessage {
                                    body: Some(daemon_message::Body::TaskResult(result)),
                                })
                                .await
                                .is_err()
                            {
                                error!("outbound channel closed while sending TaskResult");
                            }
                            // Dropped last: the guard must outlive the send above so
                            // the drain's `wait_idle()` only wakes once the result is
                            // actually enqueued.
                            drop(guard);
                        });
                    }
                    Some(relay_message::Body::TaskCancel(tc)) => {
                        // Deliver cancel signal to the in-flight Task (if any).
                        // Unknown/finished task_id → no-op (ADR-0013).
                        // Emits nothing: the spawned Task itself sends the one TaskResult.
                        registry.cancel(&tc.task_id);
                    }
                    Some(relay_message::Body::PolicyQuery(query)) => {
                        // Read-only Policy evaluation (ADR-0011): no dedup, no executor.
                        // `policy` is an Arc<Policy> here; &policy deref-coerces to &Policy.
                        let verdict = dispatch::evaluate_policy_query(&query, &policy, &templates);
                        if tx
                            .send(DaemonMessage {
                                body: Some(daemon_message::Body::PolicyVerdict(verdict)),
                            })
                            .await
                            .is_err()
                        {
                            return TunnelExit::DroppedMidSession("outbound closed".into());
                        }
                    }
                    Some(_) | None => {
                        // Forward-compatibility: ignore unknown message types.
                    }
                }
            }
            Ok(None) => return TunnelExit::ClosedClean,
            Err(e) => return TunnelExit::DroppedMidSession(Box::new(e)),
            },
        }
    }

    // Reached only via the shutdown break above: stop accepting new Tasks
    // (the loop is gone), drain whatever is in flight under the bounded grace
    // period, then close the outbound stream cleanly (issue #177).
    //
    // hb_handle is aborted BEFORE the drain so its `tx_hb` clone is released
    // promptly — otherwise it would keep the outbound stream open and the
    // post-close inbound read below would never see `None` within its budget.
    hb_handle.abort();
    let summary = shutdown::drain(&ctx.inflight, &registry, ctx.grace).await;
    info!(
        reason = ctx.shutdown.reason(),
        in_flight = summary.in_flight,
        drained = summary.drained,
        killed = summary.killed,
        "graceful shutdown: in-flight Tasks drained"
    );
    // Drop the last outbound sender: half-closes the request stream so the
    // Relay sees end-of-stream once its buffered TaskResults are consumed.
    drop(tx);
    // Confirm the buffered TaskResults flushed onto the wire — but only if
    // something was actually in flight. When nothing was in flight, nothing
    // was enqueued on `tx` after the handshake, so there is nothing to
    // confirm; skipping the read here gives an immediate clean exit on an
    // idle shutdown instead of an up-to-`FLUSH_CONFIRM_BUDGET` wait.
    if summary.in_flight > 0 {
        let _ = tokio::time::timeout(shutdown::FLUSH_CONFIRM_BUDGET, async {
            while let Ok(Some(_)) = inbound.message().await {}
        })
        .await;
    }
    TunnelExit::ShutdownComplete
}

/// Drives the daemon's connect → run → reconnect lifecycle forever, so the
/// process survives Relay restarts and revocation instead of exiting
/// (issue #176).
///
/// `startup_identity` is the identity `acquire_identity` produced at process
/// start (the ONLY enrollment path — never called again here). On every
/// iteration the identity is reloaded from disk to adopt any cert the renew
/// task rotated in the meantime (ADR-0006 Amendment 3: "adopted on the next
/// connect"), falling back to `startup_identity` if the reload finds nothing
/// or errors; this NEVER re-enrolls.
///
/// `policy`, `templates`, `dedup`, and `scheduler` are constructed once by the
/// caller and shared by `Arc` across every reconnect within this process's
/// lifetime, so the at-most-once dedup state survives reconnects (ADR-0004) and
/// the reported Policy/template fingerprints are stable across a reconnect.
///
/// The cert-renewal background task is rebound to the fresh channel and
/// freshly-reloaded identity on every successful connect: tonic's `Channel`
/// bakes the TLS client identity in at `connect()` and its internal
/// `Reconnect` redial reuses that stale cert forever, so a once-spawned renew
/// task would keep redialing with the original/aging cert after any Relay
/// restart and silently, permanently break cert rotation. Aborting the
/// previous renew task mid-renewal is safe: `perform_renewal_with`'s
/// `persist_identity` write has no intervening `.await`, so there is no torn
/// write — the new task simply reschedules from the current cert.
///
/// `connect_mtls`/`build_channel` are never weakened here (invariant #6): a
/// wrong-CA or revoked Relay/Node is refused at every attempt, just logged
/// and retried instead of exiting the process. The one exception is
/// `IdentityError::EndpointScheme`, a non-transient configuration error that
/// can never succeed on retry — that remains fatal (fail closed).
///
/// `ctx` (issue #177) carries the graceful-shutdown signal, the in-flight
/// gauge, and the grace period as one bundle rather than three separate
/// params — see `ShutdownContext`'s doc comment for why. A signal that
/// arrives while disconnected (no live stream, so no Task can possibly be in
/// flight) exits immediately; one arriving mid-connect races `connect_mtls`
/// so the daemon never blocks past the grace period waiting on an unreachable
/// Relay. Neither path can violate at-most-once (ADR-0004): both fire only
/// before any Task could have been accepted.
#[allow(clippy::too_many_arguments)]
async fn reconnect_loop(
    config: &Config,
    startup_identity: identity::Identity,
    policy: Arc<policy::Policy>,
    templates: Arc<templates::TemplateSet>,
    dedup: Arc<dedup::DedupStore>,
    scheduler: Arc<Scheduler>,
    interval: Duration,
    ctx: ShutdownContext,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut backoff = Backoff::new(RECONNECT_BACKOFF_BASE, RECONNECT_BACKOFF_CAP);
    let mut renew_handle: Option<tokio::task::JoinHandle<()>> = None;

    loop {
        // A signal that arrived while disconnected: no live stream, so no
        // Task can be in flight — exit immediately (issue #177).
        if ctx.shutdown.is_requested() {
            return Ok(());
        }

        // Reload identity from disk to adopt any cert the renew task rotated;
        // fall back to the startup identity on None/Err. NEVER re-enroll here.
        let identity = identity::load_identity(&config.state_dir)
            .ok()
            .flatten()
            .unwrap_or_else(|| startup_identity.clone());

        // Race the connect against shutdown: `build_channel` sets no
        // connect_timeout, so without this race a signal arriving mid-connect
        // to an unreachable Relay would be invisible until connect() resolves
        // (issue #177). No Task is at risk pre-connect, so returning here is
        // invariant-#4-safe.
        let outcome = tokio::select! {
            biased;
            _ = ctx.shutdown.requested_fut() => return Ok(()),
            res = tunnel::connect_mtls(
                config.endpoint.clone(),
                config.relay_domain.clone(),
                &identity,
            ) => res,
        };

        match outcome {
            Ok(channel) => {
                // Rebind the renew task to the fresh channel + freshly-reloaded
                // identity on every reconnect (ADR-0006 Amendment 3 — see doc
                // comment above for why a once-spawned renew task would break
                // cert rotation across Relay restarts).
                if let Some(h) = renew_handle.take() {
                    h.abort();
                }
                renew_handle = Some(tokio::spawn(renew::run(
                    channel.clone(),
                    config.state_dir.clone(),
                    identity.clone(),
                )));

                match run_tunnel(
                    channel,
                    &identity,
                    config.facts.clone(),
                    config.node_labels.clone(),
                    interval,
                    Arc::clone(&policy),
                    Arc::clone(&templates),
                    Arc::clone(&dedup),
                    Arc::clone(&scheduler),
                    &ctx,
                )
                .await
                {
                    TunnelExit::ClosedClean => {
                        info!(relay = %config.relay_addr, "Relay closed stream; reconnecting");
                        backoff.reset();
                    }
                    TunnelExit::DroppedMidSession(e) => {
                        warn!(relay = %config.relay_addr, "stream dropped mid-session; reconnecting");
                        debug!(error = ?e, "mid-session drop detail");
                        backoff.reset();
                    }
                    TunnelExit::NotEstablished(e) => {
                        warn!(relay = %config.relay_addr, "Relay rejected stream open; will retry");
                        debug!(error = ?e, "stream-open failure detail");
                    }
                    TunnelExit::ShutdownComplete => {
                        if let Some(h) = renew_handle.take() {
                            h.abort();
                        }
                        info!("graceful shutdown complete; exiting");
                        return Ok(());
                    }
                }
                let delay = backoff.next_delay(rand_unit());
                if shutdown::sleep_or_shutdown(delay, &ctx.shutdown).await {
                    return Ok(());
                }
            }
            Err(identity::IdentityError::EndpointScheme { scheme }) => {
                // Fatal, non-transient config error: retrying can never
                // succeed. Fail closed and exit loudly (invariant #6).
                error!(%scheme, "endpoint scheme invalid (must be https); refusing to connect");
                return Err(Box::new(identity::IdentityError::EndpointScheme { scheme }));
            }
            Err(e) => {
                let delay = backoff.next_delay(rand_unit());
                tunnel::log_connect_failure(&e, &config.relay_addr, delay);
                if shutdown::sleep_or_shutdown(delay, &ctx.shutdown).await {
                    return Ok(());
                }
            }
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // `policy check` is a fully offline/synchronous subcommand (issue #93):
    // it must never dial the Relay or require an identity, so it is
    // intercepted before Config/network/identity/tracing setup below. It runs
    // before tracing_subscriber::fmt().init(), so policy_check::run must print
    // directly to stdout/stderr — a tracing::* call here would be silently
    // dropped. `args.get(1)/.get(2)` (not direct indexing) keeps normal
    // `relay-daemon` startup (argv len == 1) panic-free.
    let args: Vec<String> = std::env::args().collect();

    // `--version` is the same kind of fully offline, synchronous subcommand as
    // `policy check` / `dump-operation-schema` below (issue #249): it prints
    // the build stamp and exits, touching no Config, identity, network, or
    // tracing. It is checked first so an operator can always identify a binary
    // regardless of how the rest of the process would fail.
    //
    // The three accepted spellings are deliberately IDENTICAL to the Relay's
    // (relay/cmd/relay/main.go): the two binaries are operated together, and an
    // operator should never have to remember which one wants a single dash.
    // `-version` is the Go `flag` package's idiom, `-V` the short form.
    if matches!(
        args.get(1).map(String::as_str),
        Some("--version") | Some("-version") | Some("-V")
    ) {
        let code = version::run();
        std::process::exit(code);
    }

    if args.get(1).map(String::as_str) == Some("policy")
        && args.get(2).map(String::as_str) == Some("check")
    {
        let code = policy_check::run(&args);
        std::process::exit(code);
    }

    // `dump-operation-schema` (ADR-0015) is the same kind of fully offline,
    // synchronous subcommand as `policy check` above: it prints the canonical
    // Operation schema JSON (operations::schema) and exits, so it too is
    // intercepted before Config/network/identity/tracing setup.
    if args.get(1).map(String::as_str) == Some("dump-operation-schema") {
        let code = operations::schema::run();
        std::process::exit(code);
    }

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    // rustls 0.23 requires an explicit process-level CryptoProvider. ring is the
    // only compiled provider (aws-lc-rs excluded in Cargo.toml); install it here
    // as the explicit process default, matching rcgen's ring backend.
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("rustls CryptoProvider installation must succeed at startup");

    let config = Config::from_env();

    // Acquire the enrolled identity before proceeding. Fail closed: if no
    // token is configured and no persisted identity exists, refuse to connect
    // rather than fall back to a plaintext dial (ADR-0005, invariant #6).
    let identity = acquire_identity(&config).await?;

    info!(relay = %config.relay_addr, node_id = %identity.node_id, "relay-daemon starting");

    // Open the dedup store before connecting (fail closed: must be writable).
    let dedup = Arc::new(dedup::DedupStore::open(&config.state_dir)?);

    // Load Policy from the configured path (fail closed on any error).
    // If the file is absent or unreadable, fall back to a deny-all Policy
    // with a warning rather than refusing to start. A daemon with no policy
    // file denies every Task, which is the most restrictive safe default.
    let policy = Arc::new(match policy::load_policy(&config.policy_path) {
        Ok(p) => {
            info!(path = %config.policy_path.display(), fingerprint = %p.fingerprint(), "policy loaded");
            p
        }
        Err(e) => {
            tracing::warn!(
                path = %config.policy_path.display(),
                error = %e,
                "policy load failed; using deny-all policy (fail closed)"
            );
            // from_toml_str("") produces a valid deny-all Policy: no allow
            // rules → every evaluate call returns Deny{rule: None}.
            policy::from_toml_str("").expect("empty TOML must produce deny-all Policy")
        }
    });

    // Load this Node's Template Operations from the local root-owned template
    // root (ADR-0021, issue #291) — the same trust root as Policy, never the
    // wire. A missing root simply means "no templates installed"; any other
    // failure leaves the Node with NO Template Operations and an `unloadable`
    // fingerprint, so a broken set is visible fleet-wide instead of silently
    // serving a partial vocabulary (fail closed).
    let templates = Arc::new(templates::TemplateSet::load_or_fail_closed(
        &config.template_dir,
    ));

    // Per-Node concurrency scheduler (issue #91, ADR-0012):
    // mutate Tasks are strictly serial (Semaphore(1));
    // read Tasks are bounded-parallel (Semaphore(READ_CONCURRENCY = 4)).
    // The inbound loop never touches the scheduler — cancel delivery is
    // never blocked by a running or queued Task.
    let scheduler = Scheduler::new();

    // dedup/policy/scheduler are constructed ONCE here and shared by Arc across
    // every reconnect inside reconnect_loop, so at-most-once dedup state
    // (ADR-0004) survives reconnects within this process's lifetime. The renew
    // task is no longer spawned here — reconnect_loop rebinds it to the fresh
    // channel + identity on every successful connect (ADR-0006 Amendment 3).
    let interval = heartbeat_interval();

    // Graceful shutdown (issue #177): a signal listener triggers `shutdown`
    // on SIGTERM/SIGINT; `reconnect_loop`/`run_tunnel` react to it, draining
    // any in-flight Task under the bounded `grace` period before exiting.
    let shutdown = Shutdown::new();
    shutdown::spawn_signal_listener(shutdown.clone());
    let ctx = ShutdownContext {
        shutdown,
        inflight: Inflight::default(),
        grace: shutdown::grace_period(),
        // One registry for the whole process, shared across every reconnect so
        // cancellation survives a reconnect (issue #337).
        registry: CancelRegistry::new(),
    };

    reconnect_loop(
        &config, identity, policy, templates, dedup, scheduler, interval, ctx,
    )
    .await?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        gen::Facts, heartbeat_delay, now_millis, parse_interval_secs, policy_snapshot, ArgMatcher,
        DenyRule,
    };
    use crate::policy;
    use std::time::Duration;

    #[test]
    fn facts_struct_construction() {
        let facts = Facts {
            hostname: "test-node".to_string(),
            os: "linux".to_string(),
            kernel: String::new(),
            arch: "x86_64".to_string(),
            ip_addresses: vec![],
        };
        assert_eq!(facts.hostname, "test-node");
        assert_eq!(facts.os, "linux");
        assert_eq!(facts.arch, "x86_64");
        assert!(facts.ip_addresses.is_empty());
    }

    #[test]
    fn now_millis_is_positive() {
        assert!(now_millis() > 0);
    }

    // -----------------------------------------------------------------------
    // parse_interval_secs
    // -----------------------------------------------------------------------

    #[test]
    fn parse_interval_none_defaults_to_30s() {
        assert_eq!(parse_interval_secs(None), Duration::from_secs(30));
    }

    #[test]
    fn parse_interval_valid_value() {
        assert_eq!(parse_interval_secs(Some("10")), Duration::from_secs(10));
    }

    #[test]
    fn parse_interval_zero_defaults_to_30s() {
        assert_eq!(parse_interval_secs(Some("0")), Duration::from_secs(30));
    }

    #[test]
    fn parse_interval_unparsable_defaults_to_30s() {
        assert_eq!(parse_interval_secs(Some("abc")), Duration::from_secs(30));
    }

    // -----------------------------------------------------------------------
    // heartbeat_delay
    // -----------------------------------------------------------------------

    #[test]
    fn heartbeat_delay_bounds_and_midpoint() {
        let interval = Duration::from_secs(10);
        let frac = 0.2_f64;

        // sample=0.0 → scale = (1 + 0.2*(0*2-1)).max(0) = (1-0.2).max(0) = 0.8 → lower bound
        let lower = heartbeat_delay(interval, frac, 0.0);
        assert_eq!(
            lower,
            Duration::from_secs_f64(8.0),
            "sample=0.0 must give lower bound"
        );

        // sample=0.5 → scale = (1 + 0.2*(0.5*2-1)).max(0) = (1+0).max(0) = 1.0 → exactly interval
        let mid = heartbeat_delay(interval, frac, 0.5);
        assert_eq!(mid, interval, "sample=0.5 must give exactly interval");

        // sample=1.0 → scale = (1 + 0.2*(1*2-1)).max(0) = (1+0.2).max(0) = 1.2 → upper bound
        let upper = heartbeat_delay(interval, frac, 1.0);
        assert_eq!(
            upper,
            Duration::from_secs_f64(12.0),
            "sample=1.0 must give upper bound"
        );

        // All results must be within [interval*(1-frac), interval*(1+frac)].
        let min_delay = interval.mul_f64(1.0 - frac);
        let max_delay = interval.mul_f64(1.0 + frac);
        assert!(
            lower >= min_delay && lower <= max_delay,
            "lower out of bounds: {lower:?}"
        );
        assert!(
            mid >= min_delay && mid <= max_delay,
            "mid out of bounds: {mid:?}"
        );
        assert!(
            upper >= min_delay && upper <= max_delay,
            "upper out of bounds: {upper:?}"
        );
    }

    // -----------------------------------------------------------------------
    // policy_snapshot (#151)
    // -----------------------------------------------------------------------

    const FIXTURE: &str = include_str!("../policy.example.toml");

    #[test]
    fn policy_snapshot_from_fixture_populates_all_fields() {
        let p = policy::from_toml_str(FIXTURE).expect("fixture must parse");
        let snapshot = policy_snapshot(&p);

        assert_eq!(snapshot.raw_exec_enabled, p.raw_exec_enabled());
        assert_eq!(snapshot.raw_allow_patterns, p.raw_allow_patterns());
        assert_eq!(snapshot.raw_deny_patterns, p.raw_deny_patterns());
        assert_eq!(snapshot.allowed_operations, p.allowed_operations());
        assert_eq!(snapshot.policy_fingerprint, p.fingerprint());

        // operation_rules / deny_rules must map 1:1 to the accessors: same
        // name + ArgMatcher.values per position, in file order.
        let expected_rules = p.operation_allow_rules();
        assert_eq!(snapshot.operation_rules.len(), expected_rules.len());
        for (got, want) in snapshot.operation_rules.iter().zip(expected_rules.iter()) {
            assert_eq!(got.name, want.name);
            let got_args: Vec<Vec<String>> =
                got.allowed_args.iter().map(|m| m.values.clone()).collect();
            assert_eq!(got_args, want.allowed_args);
        }
        // The wildcard rule (file.read -> ["*"]) must be carried verbatim.
        let file_read = snapshot
            .operation_rules
            .iter()
            .find(|r| r.name == "file.read")
            .expect("fixture has a file.read allow rule");
        assert_eq!(
            file_read.allowed_args,
            vec![ArgMatcher {
                values: vec!["*".to_string()]
            }]
        );

        let expected_denies = p.deny_rules();
        assert_eq!(snapshot.deny_rules.len(), expected_denies.len());
        for (got, want) in snapshot.deny_rules.iter().zip(expected_denies.iter()) {
            assert_eq!(got.name, want.name);
            let got_args: Vec<Vec<String>> = got.args.iter().map(|m| m.values.clone()).collect();
            assert_eq!(got_args, want.args);
        }
        // The /etc/shadow deny must be present verbatim.
        assert_eq!(
            snapshot.deny_rules,
            vec![DenyRule {
                name: "file.read".to_string(),
                args: vec![ArgMatcher {
                    values: vec!["/etc/shadow".to_string()]
                }],
            }]
        );
    }

    #[test]
    fn policy_snapshot_fingerprint_matches_hello() {
        // The key consistency guarantee: the snapshot's fingerprint must be
        // identical to the fingerprint Hello sends, since both are computed
        // from the same policy.fingerprint() call on the same Arc<Policy>.
        let p = policy::from_toml_str(FIXTURE).expect("fixture must parse");
        assert_eq!(policy_snapshot(&p).policy_fingerprint, p.fingerprint());
    }
}
