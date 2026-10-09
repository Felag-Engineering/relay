//! mTLS Tunnel connection. Isolated so subsequent milestones (#29, #31) can build on it.

use std::time::Duration;

use tonic::transport::{Channel, Identity as TlsIdentity};
use tracing::{debug, warn};

use crate::identity::IdentityError;
use crate::log_field;

type Result<T, E = crate::identity::IdentityError> = std::result::Result<T, E>;

/// Establishes a mutual-TLS channel to the Relay's Tunnel service.
///
/// The Relay's server certificate is verified against `id.ca_bundle_pem` — the
/// sole trust root. No system roots are consulted (tonic's `tls-ring` feature only,
/// not `tls-native-roots`/`tls-webpki-roots`), so a wrong-CA Relay is refused at the
/// TLS handshake. `connect()` is eager (not lazy): a mismatched server cert
/// fails immediately, not on the first RPC.
///
/// Fails closed on any non-`https://` endpoint (ADR-0005, invariant #6).
pub async fn connect_mtls(
    endpoint: String,
    domain: Option<String>,
    id: &crate::identity::Identity,
) -> Result<Channel> {
    let client_identity = TlsIdentity::from_pem(id.cert_pem.as_bytes(), id.key_pem.as_bytes());
    crate::identity::build_channel(
        endpoint,
        domain,
        id.ca_bundle_pem.as_bytes(),
        Some(client_identity),
    )
    .await
}

// ---------------------------------------------------------------------------
// Reconnect backoff (issue #176)
// ---------------------------------------------------------------------------

/// Base delay for the first reconnect attempt.
pub const RECONNECT_BACKOFF_BASE: Duration = Duration::from_secs(1);
/// Backoff ceiling — reached at attempt 5 for a 1 s base (1,2,4,8,16,30,...).
pub const RECONNECT_BACKOFF_CAP: Duration = Duration::from_secs(30);

/// Jittered exponential backoff for the daemon's reconnect loop.
///
/// `attempt` counts consecutive connect failures since the last healthy
/// session (or since construction). `reset()` is called by the caller after
/// a healthy session (client.open() succeeded), so a daemon that connects
/// fine and later drops reconnects quickly, while one that can never
/// authenticate (revoked/wrong-CA) ramps to `cap` and stays there.
pub struct Backoff {
    base: Duration,
    cap: Duration,
    attempt: u32,
}

impl Backoff {
    pub fn new(base: Duration, cap: Duration) -> Self {
        Self {
            base,
            cap,
            attempt: 0,
        }
    }

    /// Deterministic, un-jittered delay for the current attempt count.
    ///
    /// factor = 2^attempt (capped at 2^32 to avoid shift overflow); the result
    /// is saturating-multiplied against `base` and clamped to `cap`. For
    /// `(base=1s, cap=30s)` the sequence is 1,2,4,8,16,30,30,… seconds.
    pub fn base_delay(&self) -> Duration {
        let factor = 1u64 << self.attempt.min(32);
        let ms = (self.base.as_millis() as u64)
            .saturating_mul(factor)
            .min(self.cap.as_millis() as u64);
        Duration::from_millis(ms)
    }

    /// Advances the attempt counter and returns an equal-jittered delay for
    /// the PRE-advance attempt count, i.e. based on `base_delay()` as it was
    /// before this call.
    ///
    /// `sample` must be in `[0, 1)` (see `crate::rand_unit`).
    pub fn next_delay(&mut self, sample: f64) -> Duration {
        let d = self.base_delay();
        self.attempt = self.attempt.saturating_add(1);
        jitter(d, sample)
    }

    /// Resets the attempt counter to 0. Called after a healthy session.
    pub fn reset(&mut self) {
        self.attempt = 0;
    }
}

/// Equal jitter: returns a delay in `[base/2, base]`, `sample` in `[0, 1)`.
fn jitter(base: Duration, sample: f64) -> Duration {
    let half = base / 2;
    half + half.mul_f64(sample)
}

// ---------------------------------------------------------------------------
// Failure classification (issue #176)
// ---------------------------------------------------------------------------

/// Best-effort classification of a connect failure. Never load-bearing for
/// correctness — resilience (retry-forever) never depends on getting this
/// right, only the log line's legibility does.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum ConnectFailure {
    /// Relay host/port unreachable (TCP refused, DNS failure, timeout, …).
    Unreachable,
    /// TLS handshake rejected the peer (untrusted/expired/revoked cert, …).
    TlsRejected,
    /// Anything else.
    Other,
}

/// Concatenates `err.to_string()` and every `.source()` Display in the error
/// chain, lowercased. Transport/TLS errors only — never identity material —
/// so logging the chain at debug leaks no secrets.
fn error_chain_lower(err: &dyn std::error::Error) -> String {
    let mut chain = err.to_string();
    let mut cause = err.source();
    while let Some(c) = cause {
        chain.push(' ');
        chain.push_str(&c.to_string());
        cause = c.source();
    }
    chain.to_lowercase()
}

/// Pure classifier over an already-lowercased error chain string — the
/// unit-test seam. TLS tokens are checked FIRST since some (e.g. "expired")
/// could otherwise be mistaken for other categories.
pub(crate) fn classify_chain(chain: &str) -> ConnectFailure {
    const TLS_TOKENS: &[&str] = &[
        "certificate",
        "handshake",
        "revoked",
        "unknown ca",
        "unknownca",
        "bad_certificate",
        "expired",
        "invalid peer",
    ];
    if TLS_TOKENS.iter().any(|t| chain.contains(t)) {
        return ConnectFailure::TlsRejected;
    }

    const UNREACHABLE_TOKENS: &[&str] = &[
        "refused",
        "connect",
        "dns",
        "timed out",
        "no route",
        "unreachable",
    ];
    if UNREACHABLE_TOKENS.iter().any(|t| chain.contains(t)) {
        return ConnectFailure::Unreachable;
    }

    ConnectFailure::Other
}

/// Classifies a `connect_mtls` failure by walking its error chain.
///
/// `IdentityError::Channel` is `#[error(transparent)]` over
/// `tonic::transport::Error`, so `.source()` reaches the hyper/rustls cause —
/// e.g. "invalid peer certificate: CertRevoked" for revocation, "tcp connect
/// error: Connection refused" for a down Relay.
pub(crate) fn classify_connect_error(err: &IdentityError) -> ConnectFailure {
    classify_chain(&error_chain_lower(err))
}

/// Logs one legible, single-line warning per failure class (Display only,
/// never a `{:?}` dump above debug). The full debug chain is logged
/// separately at `debug` level for troubleshooting.
pub fn log_connect_failure(err: &IdentityError, relay: &str, retry_in: Duration) {
    match classify_connect_error(err) {
        ConnectFailure::Unreachable => {
            warn!(relay, ?retry_in, "Relay unreachable; will retry");
        }
        ConnectFailure::TlsRejected => {
            warn!(
                relay,
                ?retry_in,
                "TLS handshake rejected by Relay — client cert untrusted, expired, or revoked; will retry"
            );
        }
        ConnectFailure::Other => {
            warn!(
                relay,
                ?retry_in,
                error = log_field::untrusted(&err.to_string()),
                "connect failed; will retry"
            );
        }
    }
    debug!(
        error = log_field::untrusted(&format!("{err:?}")),
        "connect failure detail"
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use tokio::net::TcpListener;
    use tokio::time::Duration;

    /// Generate a self-signed cert+key pair with the given DNS SAN via rcgen.
    fn make_self_signed(san: &str) -> (String, String) {
        let kp = rcgen::KeyPair::generate().expect("keygen");
        let cert_pem = rcgen::CertificateParams::new(vec![san.to_string()])
            .expect("params")
            .self_signed(&kp)
            .expect("self_signed")
            .pem();
        (kp.serialize_pem(), cert_pem)
    }

    /// Build a throwaway `Identity` whose `ca_bundle_pem` is set to `ca_pem`.
    /// The client cert/key are a fresh self-signed pair; the server uses
    /// `with_no_client_auth` so they are never verified.
    fn make_identity_with_ca(ca_pem: &str) -> crate::identity::Identity {
        let (key_pem, cert_pem) = make_self_signed("client");
        crate::identity::Identity {
            node_id: "test-node".to_string(),
            key_pem,
            cert_pem,
            ca_bundle_pem: ca_pem.to_string(),
        }
    }

    /// Spins up a throwaway TLS server presenting CA-A, dials it with a
    /// client pinning a different CA-B, and returns the resulting
    /// `IdentityError`. Shared by `wrong_ca_relay_is_refused` (Debug-string
    /// assertion) and `classify_real_wrong_ca_error_is_tls_rejected`
    /// (classifier assertion) so both tests exercise the exact same real
    /// handshake rejection rather than a synthetic string.
    ///
    /// The server uses `with_no_client_auth` to isolate the failure to the
    /// client-side CA-pinning check — the test proves the client rejects the
    /// server's cert, not the other way around.
    async fn dial_with_mismatched_ca() -> IdentityError {
        use rustls::pki_types::pem::PemObject;
        use rustls::pki_types::{CertificateDer, PrivateKeyDer};
        use rustls::ServerConfig;
        use tokio_rustls::TlsAcceptor;

        // rustls 0.23 requires an explicit process-level CryptoProvider. ring is
        // the only compiled provider (aws-lc-rs excluded in Cargo.toml), matching
        // rcgen's backend. `install_default` is idempotent: Err means another test
        // won first.
        let _ = rustls::crypto::ring::default_provider().install_default();

        // CA-A: the server will present this self-signed cert.
        let (ca_a_key_pem, ca_a_cert_pem) = make_self_signed("localhost");

        let ca_a_certs: Vec<CertificateDer<'static>> =
            CertificateDer::pem_slice_iter(ca_a_cert_pem.as_bytes())
                .collect::<std::result::Result<Vec<_>, _>>()
                .expect("parse server cert");
        let ca_a_key: PrivateKeyDer<'static> =
            PrivateKeyDer::from_pem_slice(ca_a_key_pem.as_bytes()).expect("parse server key");

        // Server config: no client auth so the failure is on the client side.
        let server_config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(ca_a_certs, ca_a_key)
            .expect("server config");
        let acceptor = TlsAcceptor::from(Arc::new(server_config));

        // Ephemeral port — OS picks one so parallel test runs don't collide.
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let port = listener.local_addr().expect("local_addr").port();

        // Accept exactly one TCP connection; the TLS handshake will abort when
        // the client rejects CA-A, so we ignore the acceptor result.
        tokio::spawn(async move {
            if let Ok((stream, _)) = listener.accept().await {
                let _ = acceptor.accept(stream).await;
            }
        });

        // CA-B: a different self-signed cert — the client pins this.
        let (_, ca_b_cert_pem) = make_self_signed("other-relay");
        let id = make_identity_with_ca(&ca_b_cert_pem);

        let outcome = tokio::time::timeout(
            Duration::from_secs(5),
            connect_mtls(
                format!("https://127.0.0.1:{}", port),
                Some("localhost".to_string()),
                &id,
            ),
        )
        .await;

        // outer Ok: resolved within 5 s (no CI hang).
        // inner Err: pinned-CA mismatch refused by the client.
        let Ok(dial_result) = outcome else {
            panic!("dial did not resolve within the timeout: {outcome:?}");
        };
        dial_result.expect_err("a Relay serving a cert from an unpinned CA must be refused")
    }

    /// Acceptance criterion for #28: a Relay presenting CA-A is refused when
    /// the client pins a different CA-B.
    #[tokio::test]
    async fn wrong_ca_relay_is_refused() {
        let err = dial_with_mismatched_ca().await;
        let debug = format!("{err:?}");
        assert!(
            debug.contains("InvalidCertificate") || debug.to_lowercase().contains("invalid peer certificate"),
            "wrong-CA dial must fail with a certificate-validation error (CA pin), not a generic transport error: {debug}"
        );
    }

    /// A non-https endpoint is rejected before any network dial is attempted.
    #[tokio::test]
    async fn http_endpoint_is_rejected() {
        let (_, ca_pem) = make_self_signed("test");
        let id = make_identity_with_ca(&ca_pem);
        let result = connect_mtls("http://127.0.0.1:1".to_string(), None, &id).await;
        assert!(result.is_err(), "http:// endpoint must be rejected");
        assert!(
            result.unwrap_err().to_string().contains("http"),
            "error should mention the bad scheme"
        );
    }

    // -----------------------------------------------------------------------
    // Backoff (issue #176)
    // -----------------------------------------------------------------------

    #[test]
    fn backoff_progression_caps() {
        let mut b = Backoff::new(Duration::from_secs(1), Duration::from_secs(30));
        let expected = [
            (0u32, 1u64),
            (1, 2),
            (2, 4),
            (3, 8),
            (4, 16),
            (5, 30),
            (6, 30),
            (10, 30),
        ];
        for (attempt, secs) in expected {
            b.attempt = attempt;
            assert_eq!(
                b.base_delay(),
                Duration::from_secs(secs),
                "attempt {attempt} should be {secs}s"
            );
        }
    }

    #[test]
    fn backoff_next_delay_advances_and_jitter_bounds() {
        let mut b = Backoff::new(Duration::from_secs(1), Duration::from_secs(30));
        // Sequence of base_delay()s consumed by successive next_delay() calls,
        // in seconds: 1,2,4,8,16,30,30 (cap reached at attempt 5, matching
        // backoff_progression_caps). Alternate samples across [0, 1) so both
        // ends of the jitter range are exercised.
        let expected_base_secs = [1u64, 2, 4, 8, 16, 30, 30];
        for (i, base_secs) in expected_base_secs.into_iter().enumerate() {
            let base = Duration::from_secs(base_secs);
            let sample = if i % 2 == 0 { 0.0 } else { 0.999 };
            let delay = b.next_delay(sample);
            assert!(
                delay >= base / 2 && delay <= base,
                "next_delay({sample}) for base {base_secs}s must be in [{:?}, {:?}], got {:?}",
                base / 2,
                base,
                delay
            );
        }
        // The loop above drove `attempt` through 7 advances (0..=6); base_delay()
        // now reflects attempt 7, still at the cap.
        assert_eq!(b.base_delay(), Duration::from_secs(30));
    }

    #[test]
    fn backoff_reset_returns_to_base() {
        let mut b = Backoff::new(Duration::from_secs(1), Duration::from_secs(30));
        b.next_delay(0.0);
        b.next_delay(0.0);
        b.next_delay(0.0);
        assert_eq!(
            b.base_delay(),
            Duration::from_secs(8),
            "after 3 next_delay() calls, base_delay() should be 8s"
        );
        b.reset();
        assert_eq!(
            b.base_delay(),
            Duration::from_secs(1),
            "reset() should return base_delay() to 1s"
        );
    }

    // -----------------------------------------------------------------------
    // classify_chain / classify_connect_error (issue #176)
    // -----------------------------------------------------------------------

    #[test]
    fn classify_chain_connection_refused_is_unreachable() {
        assert_eq!(
            classify_chain("tcp connect error: connection refused (os error 111)"),
            ConnectFailure::Unreachable
        );
    }

    #[test]
    fn classify_chain_revoked_is_tls_rejected() {
        assert_eq!(
            classify_chain("received fatal alert: certificaterevoked"),
            ConnectFailure::TlsRejected
        );
    }

    #[test]
    fn classify_chain_unknown_ca_is_tls_rejected() {
        assert_eq!(
            classify_chain("invalid peer certificate: unknownca"),
            ConnectFailure::TlsRejected
        );
    }

    #[test]
    fn classify_chain_expired_is_tls_rejected() {
        assert_eq!(
            classify_chain("certificate expired"),
            ConnectFailure::TlsRejected
        );
    }

    #[test]
    fn classify_chain_unrecognized_is_other() {
        assert_eq!(
            classify_chain("some unexpected transport error"),
            ConnectFailure::Other
        );
    }

    /// Reuses the real TLS harness from `wrong_ca_relay_is_refused` (not a
    /// synthetic string) to guard against the production classifier falling
    /// through to `Other` for every real handshake rejection.
    #[tokio::test]
    async fn classify_real_wrong_ca_error_is_tls_rejected() {
        let err = dial_with_mismatched_ca().await;
        assert_eq!(
            classify_connect_error(&err),
            ConnectFailure::TlsRejected,
            "a real wrong-CA handshake rejection must classify as TlsRejected, got chain: {}",
            error_chain_lower(&err)
        );
    }
}
