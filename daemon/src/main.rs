use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tokio::sync::{mpsc, Semaphore};
use tokio_stream::wrappers::ReceiverStream;
use tonic::transport::Channel;
use tracing::{error, info};

mod cancel;
mod config;
mod dedup;
mod dispatch;
mod enroll;
mod executor;
mod identity;
mod operations;
mod policy;
mod raw_exec;
mod renew;
mod tunnel;

use cancel::CancelRegistry;
use config::Config;

#[allow(dead_code, unused_imports, clippy::all)]
mod gen {
    include!(concat!(env!("OUT_DIR"), "/gleipnir.v1.rs"));
}

use gen::{
    daemon_message, relay_message, tunnel_client::TunnelClient, DaemonMessage, Facts, Heartbeat,
    Hello,
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

/// Sends the initial Hello, drives the heartbeat loop, and processes inbound
/// messages from the Relay until the stream closes or errors.
///
/// Inbound `RelayMessage` handling:
/// - `Task`: registered in the cancel registry BEFORE spawning, then dispatched
///   through the dedup → Policy → execute pipeline in a detached task so the loop
///   keeps reading and can receive `TaskCancel` messages (ADR-0001/0002/0004/0013).
///   Exactly one `TaskResult` is emitted — either the real outcome or Cancelled.
///   Each spawned task acquires the `execution_gate` permit before calling dispatch,
///   serializing execution to one Task at a time (temporary backstop preserving the
///   pre-cancel inline-await behavior; issue #91 replaces this with the per-risk-class
///   scheduler: mutate serial, read bounded-parallel).
/// - `TaskCancel`: delivers the cancel signal to the in-flight Task's executor via
///   the cancel registry (ADR-0013). If the task_id is unknown or already finished,
///   this is a safe no-op. The inbound loop NEVER waits on `execution_gate`, so
///   TaskCancel delivery is never blocked by a running Task.
/// - Other message types: silently ignored for forward-compatibility.
///
/// Policy and DedupStore are passed as `Arc` so spawned per-Task tasks are `'static`.
#[allow(clippy::too_many_arguments)]
async fn run_tunnel(
    channel: Channel,
    identity: &crate::identity::Identity,
    facts: Facts,
    node_labels: Vec<(String, String)>,
    interval: Duration,
    policy: Arc<policy::Policy>,
    dedup: Arc<dedup::DedupStore>,
    execution_gate: Arc<Semaphore>,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut client = TunnelClient::new(channel);
    let (tx, rx) = mpsc::channel::<DaemonMessage>(32);

    // Send Hello as the first outbound message on the bidi stream.
    // node_id is the Relay-assigned identity (from the enrolled cert CN),
    // aligning the app-layer identity with the transport-layer client cert
    // (ADR-0006 amendment 2).
    tx.send(DaemonMessage {
        body: Some(daemon_message::Body::Hello(Hello {
            node_id: identity.node_id.clone(),
            daemon_version: env!("CARGO_PKG_VERSION").to_string(),
            facts: Some(facts),
            labels: enroll::node_labels_to_proto(&node_labels),
            policy_fingerprint: policy.fingerprint().to_string(),
        })),
    })
    .await?;

    // Background task: emit a Heartbeat at a configurable, jittered interval.
    // Jitter spreads send times across a bulk-restarted fleet so daemons do not
    // all arrive at the Relay simultaneously. RELAY_HEARTBEAT_INTERVAL_SECS
    // configures the base interval (default 30 s); each iteration re-samples so
    // the spread is maintained over the lifetime of the connection.
    let tx_hb = tx.clone();
    tokio::spawn(async move {
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

    let response = client.open(ReceiverStream::new(rx)).await?;
    let mut inbound = response.into_inner();

    // First inbound message must be the Relay's Ping (handshake confirmation).
    match inbound.message().await? {
        Some(msg) => match msg.body {
            Some(relay_message::Body::Ping(ping)) => {
                info!(unix_millis = ping.unix_millis, "received Ping from Relay");
            }
            Some(_) => error!("expected Ping as first RelayMessage"),
            None => error!("received empty RelayMessage body"),
        },
        None => error!("stream ended before receiving Ping"),
    }

    // Cancel registry: maps in-flight task_ids to their cancel senders.
    // Registration happens BEFORE spawn so no TaskCancel can arrive in a window
    // where the task is in flight but not yet registered.
    let registry = CancelRegistry::new();

    // Drive the inbound stream. Spawning a detached task per Task keeps the loop
    // readable so TaskCancel messages can arrive while a Task is in flight.
    // Single-flight contract (#82) bounds concurrency at one Task per Node until
    // the scheduler issue (#91) arrives — the loop has no queue.
    loop {
        match inbound.message().await {
            Ok(Some(msg)) => {
                match msg.body {
                    Some(relay_message::Body::Task(task_req)) => {
                        let task_id = task_req.task_id.clone();
                        // Register BEFORE spawn: eliminates the window where
                        // a TaskCancel could arrive before the registry entry exists.
                        let cancel_rx = registry.register(&task_id);
                        let policy = Arc::clone(&policy);
                        let dedup = Arc::clone(&dedup);
                        let registry = registry.clone();
                        let tx = tx.clone();
                        let gate = Arc::clone(&execution_gate);
                        tokio::spawn(async move {
                            // Acquire the execution gate before dispatching.
                            // This re-serializes Task execution to one-at-a-time,
                            // preserving the pre-cycle-1 inline-await behavior while
                            // keeping the inbound loop free to read TaskCancel messages
                            // (the loop never touches the semaphore, so cancel delivery
                            // is never blocked by a running Task).
                            //
                            // Temporary backstop: issue #91 will replace this with a
                            // per-risk-class scheduler (mutate serial, read
                            // bounded-parallel). The semaphore is never closed, so
                            // expect() is safe here.
                            let _permit = gate
                                .acquire()
                                .await
                                .expect("execution_gate semaphore must not be closed");
                            let result =
                                dispatch::dispatch(&task_req, &policy, &dedup, Some(cancel_rx))
                                    .await;
                            // Deregister before sending the result so a subsequent
                            // TaskCancel for this id is a clean no-op.
                            registry.deregister(&task_id);
                            if tx
                                .send(DaemonMessage {
                                    body: Some(daemon_message::Body::TaskResult(result)),
                                })
                                .await
                                .is_err()
                            {
                                error!("outbound channel closed while sending TaskResult");
                            }
                            // _permit drops here, releasing the gate for the next Task.
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
                        let verdict = dispatch::evaluate_policy_query(&query, &policy);
                        if tx
                            .send(DaemonMessage {
                                body: Some(daemon_message::Body::PolicyVerdict(verdict)),
                            })
                            .await
                            .is_err()
                        {
                            error!("outbound channel closed while sending PolicyVerdict");
                            break;
                        }
                    }
                    Some(_) | None => {
                        // Forward-compatibility: ignore unknown message types.
                    }
                }
            }
            Ok(None) => {
                info!("Relay closed stream, shutting down");
                break;
            }
            Err(e) => {
                error!(error = %e, "stream error");
                break;
            }
        }
    }

    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
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

    // connect_mtls is the authoritative fail-closed check for the https scheme
    // (validate_endpoint_scheme inside build_channel); config.endpoint already
    // carries the http→https normalization from Config::from_env.
    let channel = tunnel::connect_mtls(
        config.endpoint.clone(),
        config.relay_domain.clone(),
        &identity,
    )
    .await?;

    // Spawn the cert-renewal background task. It rides the same mTLS channel so
    // the Relay authenticates it via the current client cert (no token). The renewed
    // cert is written atomically to state_dir and adopted on the next connect_mtls
    // (process restart or reconnect). The live session continues with the old cert —
    // TLS does not re-validate certs mid-session and the renewal margin (3.5–7 days)
    // ensures no connectivity gap (ADR-0006 Amendment 3).
    tokio::spawn(renew::run(
        channel.clone(),
        config.state_dir.clone(),
        identity.clone(),
    ));

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

    // Process-wide execution gate: 1 permit serializes Task execution to
    // one-at-a-time, matching the implicit serialization of the old
    // inline-await loop. Temporary backstop until issue #91 introduces the
    // per-risk-class scheduler (mutate serial, read bounded-parallel).
    let execution_gate = Arc::new(Semaphore::new(1));

    let interval = heartbeat_interval();
    run_tunnel(
        channel,
        &identity,
        config.facts.clone(),
        config.node_labels.clone(),
        interval,
        policy,
        dedup,
        execution_gate,
    )
    .await?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{gen::Facts, heartbeat_delay, now_millis, parse_interval_secs};
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
}
