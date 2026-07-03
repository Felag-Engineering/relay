use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tonic::transport::Channel;
use tracing::{error, info};

mod config;
mod enroll;
mod identity;
mod policy;
mod renew;
mod tunnel;

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
async fn run_tunnel(
    channel: Channel,
    identity: &crate::identity::Identity,
    facts: Facts,
    node_labels: Vec<(String, String)>,
    interval: Duration,
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
    drop(tx);

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

    // Drive the inbound stream; Task dispatch will be handled here in future milestones.
    loop {
        match inbound.message().await {
            Ok(Some(_)) => {}
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

    let interval = heartbeat_interval();
    run_tunnel(
        channel,
        &identity,
        config.facts.clone(),
        config.node_labels.clone(),
        interval,
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
