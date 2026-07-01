use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tracing::{error, info};

mod enroll;
mod tunnel;

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

fn relay_addr() -> String {
    let args: Vec<String> = std::env::args().collect();
    for window in args.windows(2) {
        if window[0] == "--relay" {
            return window[1].clone();
        }
    }
    std::env::var("RELAY_ADDR").unwrap_or_else(|_| "http://127.0.0.1:7654".to_string())
}

/// Returns the Node's hostname for use in Facts. This is a human-readable
/// descriptor, not the Relay-assigned identity. Do not substitute
/// `identity.node_id` here — that is a UUID assigned by the Relay (ADR-0006).
fn hostname() -> String {
    std::env::var("HOSTNAME").unwrap_or_else(|_| "unknown-node".to_string())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    // rustls 0.23 requires an explicit process-level CryptoProvider because both
    // ring and aws-lc-rs are compiled in; install ring to match rcgen's backend.
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("rustls CryptoProvider installation must succeed at startup");

    let addr = relay_addr();

    // Acquire the enrolled identity before proceeding. Fail closed: if no
    // token is configured and no persisted identity exists, refuse to connect
    // rather than fall back to a plaintext dial (ADR-0005, invariant #6).
    let identity = match enroll::EnrollConfig::from_env()? {
        Some(cfg) => enroll::ensure_enrolled(&cfg).await?,
        None => enroll::load_identity(&enroll::state_dir_from_env())?.ok_or(
            "no enrolled identity in state dir; refusing to connect (fail closed, no plaintext)",
        )?,
    };

    info!(relay = %addr, node_id = %identity.node_id, "relay-daemon starting");

    let facts = Facts {
        // Facts.hostname is a human-readable hostname descriptor, not the
        // Relay-assigned identity UUID (see node_id field on Hello below).
        hostname: hostname(),
        os: std::env::consts::OS.to_string(),
        arch: std::env::consts::ARCH.to_string(),
        kernel: String::new(),
        ip_addresses: vec![],
    };

    // Force http:// → https:// so existing --relay/RELAY_ADDR inputs work;
    // https:// endpoints pass through unchanged. validate_endpoint_scheme
    // inside connect_mtls is the authoritative fail-closed check.
    let endpoint = addr.replacen("http://", "https://", 1);
    let domain = std::env::var("RELAY_DOMAIN").ok();
    let channel = tunnel::connect_mtls(endpoint, domain, &identity).await?;
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
            labels: vec![],
        })),
    })
    .await?;

    // Background task: emit a Heartbeat every 30 seconds.
    let tx_hb = tx.clone();
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_secs(30)).await;
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

#[cfg(test)]
mod tests {
    use super::{gen::Facts, now_millis};

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
}
