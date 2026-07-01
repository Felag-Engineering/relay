//! mTLS Tunnel connection. Isolated so subsequent milestones (#29, #31) can build on it.

use tonic::transport::{Channel, Identity as TlsIdentity};

type Result<T, E = Box<dyn std::error::Error>> = std::result::Result<T, E>;

/// Establishes a mutual-TLS channel to the Relay's Tunnel service.
///
/// The Relay's server certificate is verified against `id.ca_bundle_pem` — the
/// sole trust root. No system roots are consulted (tonic's `tls` feature only,
/// not `tls-roots`/`tls-webpki-roots`), so a wrong-CA Relay is refused at the
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

    /// Acceptance criterion for #28: a Relay presenting CA-A is refused when
    /// the client pins a different CA-B.
    ///
    /// The server uses `with_no_client_auth` to isolate the failure to the
    /// client-side CA-pinning check — the test proves the client rejects the
    /// server's cert, not the other way around.
    #[tokio::test]
    async fn wrong_ca_relay_is_refused() {
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
            rustls_pemfile::certs(&mut ca_a_cert_pem.as_bytes())
                .collect::<std::result::Result<Vec<_>, _>>()
                .expect("parse server cert");
        let ca_a_key: PrivateKeyDer<'static> =
            rustls_pemfile::private_key(&mut ca_a_key_pem.as_bytes())
                .expect("parse server key")
                .expect("server key present");

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
        let err =
            dial_result.expect_err("a Relay serving a cert from an unpinned CA must be refused");
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
}
