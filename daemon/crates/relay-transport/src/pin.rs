//! Pins the Relay's CA from a join string's fingerprint before enrollment sends
//! anything (ADR-0031). A TLS handshake against the enrollment endpoint finds the
//! presented chain certificate whose SHA-256 over DER equals the pin, then verifies
//! the leaf against that certificate alone, server name included. Only the
//! handshake is sent; the Enrollment Token travels later, on a connection whose
//! one trust root is the CA returned here.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use base64::Engine as _;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::client::WebPkiServerVerifier;
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{CertificateError, DigitallySignedStruct, RootCertStore, SignatureScheme};

use crate::identity::{validate_endpoint_scheme, IdentityError};

/// How long one TCP connect, read or write of the pinning handshake may take.
const PROBE_TIMEOUT: Duration = Duration::from_secs(10);

/// Why the Relay's CA could not be pinned. No variant carries the join string or
/// the Enrollment Token.
#[derive(Debug, thiserror::Error)]
pub enum PinError {
    #[error("the Relay's CA does not match the join string's CA fingerprint; nothing was sent")]
    Mismatch,
    #[error(transparent)]
    Endpoint(#[from] IdentityError),
    #[error("enrollment endpoint is not https://host:port")]
    BadEndpoint,
    #[error("pinning handshake with the Relay failed: {0}")]
    Tls(rustls::Error),
    #[error("pinning handshake with the Relay failed: {0}")]
    Io(#[from] std::io::Error),
}

/// What the verifier saw, read back after the handshake.
#[derive(Default)]
enum Outcome {
    #[default]
    NotReached,
    Mismatch,
    Pinned(CertificateDer<'static>),
}

/// The pinning verifier: the presented chain must hold a certificate whose
/// SHA-256 over DER is `pin`, and the leaf must verify against that certificate
/// alone, server name included. No other root is consulted.
pub(crate) struct PinVerifier {
    pin: [u8; 32],
    provider: Arc<CryptoProvider>,
    outcome: Mutex<Outcome>,
}

impl std::fmt::Debug for PinVerifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PinVerifier").finish_non_exhaustive()
    }
}

impl PinVerifier {
    pub(crate) fn new(pin: [u8; 32], provider: Arc<CryptoProvider>) -> Self {
        Self {
            pin,
            provider,
            outcome: Mutex::new(Outcome::NotReached),
        }
    }

    fn record(&self, outcome: Outcome) {
        if let Ok(mut slot) = self.outcome.lock() {
            *slot = outcome;
        }
    }

    fn take(&self) -> Outcome {
        self.outcome
            .lock()
            .map(|mut slot| std::mem::take(&mut *slot))
            .unwrap_or_default()
    }
}

/// SHA-256 over `der`.
pub(crate) fn sha256(der: &[u8]) -> [u8; 32] {
    let digest = ring::digest::digest(&ring::digest::SHA256, der);
    let mut out = [0u8; 32];
    out.copy_from_slice(digest.as_ref());
    out
}

impl ServerCertVerifier for PinVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let Some(root) = intermediates.iter().find(|c| sha256(c) == self.pin) else {
            self.record(Outcome::Mismatch);
            return Err(rustls::Error::InvalidCertificate(
                CertificateError::UnknownIssuer,
            ));
        };
        let root = root.clone().into_owned();
        let mut roots = RootCertStore::empty();
        roots.add(root.clone())?;
        let inner = WebPkiServerVerifier::builder_with_provider(
            Arc::new(roots),
            Arc::clone(&self.provider),
        )
        .build()
        .map_err(|e| rustls::Error::General(e.to_string()))?;
        // No intermediates, deliberately: the leaf must be signed directly by the
        // pinned CA, and any other chain fails closed.
        let verified =
            inner.verify_server_cert(end_entity, &[], server_name, ocsp_response, now)?;
        self.record(Outcome::Pinned(root));
        Ok(verified)
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// The host of `uri` as a TLS server name: an IPv6 literal without its
/// brackets, so it is checked against an IP SAN. `None` for an empty host.
pub(crate) fn uri_host(uri: &tonic::transport::Uri) -> Option<&str> {
    let host = uri.host()?;
    let host = host
        .strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host);
    (!host.is_empty()).then_some(host)
}

/// Splits `https://host:port` into the host and port to dial. IPv6 hosts keep
/// no brackets.
fn host_port(endpoint: &str) -> Result<(String, u16), PinError> {
    let uri: tonic::transport::Uri = endpoint.parse().map_err(|_| PinError::BadEndpoint)?;
    let host = uri_host(&uri).ok_or(PinError::BadEndpoint)?;
    Ok((host.to_string(), uri.port_u16().unwrap_or(443)))
}

fn connect(host: &str, port: u16) -> Result<TcpStream, std::io::Error> {
    let addrs: Vec<SocketAddr> = (host, port).to_socket_addrs()?.collect();
    let mut last = std::io::Error::new(
        std::io::ErrorKind::NotFound,
        "the enrollment endpoint resolved to no address",
    );
    for addr in addrs {
        match TcpStream::connect_timeout(&addr, PROBE_TIMEOUT) {
            Ok(stream) => return Ok(stream),
            Err(e) => last = e,
        }
    }
    Err(last)
}

/// Runs the pinning handshake against `endpoint` and returns the pinned CA
/// certificate. The server name checked is `domain` when set, else the endpoint's
/// host. Sends nothing but the TLS handshake and its close.
pub(crate) async fn fetch_pinned_ca(
    endpoint: &str,
    domain: Option<&str>,
    pin: &[u8; 32],
) -> Result<CertificateDer<'static>, PinError> {
    validate_endpoint_scheme(endpoint)?;
    let (host, port) = host_port(endpoint)?;
    let name = domain.map(str::to_string).unwrap_or_else(|| host.clone());
    let server_name = ServerName::try_from(name).map_err(|_| PinError::BadEndpoint)?;
    let pin = *pin;
    tokio::task::spawn_blocking(move || probe(&host, port, server_name, pin))
        .await
        .map_err(|e| PinError::Io(std::io::Error::other(e.to_string())))?
}

fn probe(
    host: &str,
    port: u16,
    server_name: ServerName<'static>,
    pin: [u8; 32],
) -> Result<CertificateDer<'static>, PinError> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let verifier = Arc::new(PinVerifier::new(pin, Arc::clone(&provider)));
    let mut config = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(PinError::Tls)?
        .dangerous()
        .with_custom_certificate_verifier(verifier.clone())
        .with_no_client_auth();
    // The Relay's node plane is gRPC; grpc-go refuses a handshake that
    // negotiates no ALPN.
    config.alpn_protocols = vec![b"h2".to_vec()];

    let mut tcp = connect(host, port)?;
    tcp.set_read_timeout(Some(PROBE_TIMEOUT))?;
    tcp.set_write_timeout(Some(PROBE_TIMEOUT))?;
    let mut conn =
        rustls::ClientConnection::new(Arc::new(config), server_name).map_err(PinError::Tls)?;

    let handshake = drive_handshake(&mut conn, &mut tcp);
    match (verifier.take(), handshake) {
        (Outcome::Mismatch, _) => Err(PinError::Mismatch),
        (Outcome::Pinned(root), Ok(())) => {
            conn.send_close_notify();
            let _ = conn.complete_io(&mut tcp);
            Ok(root)
        }
        (_, Err(e)) => Err(e),
        (Outcome::NotReached, Ok(())) => Err(PinError::Tls(rustls::Error::General(
            "handshake finished without certificate verification".into(),
        ))),
    }
}

fn drive_handshake<S: Read + Write>(
    conn: &mut rustls::ClientConnection,
    sock: &mut S,
) -> Result<(), PinError> {
    while conn.is_handshaking() {
        match conn.complete_io(sock) {
            Ok(_) => {}
            Err(e) => {
                // complete_io wraps a TLS failure in an io::Error; surface the
                // rustls error itself where there is one.
                return Err(
                    match e.get_ref().and_then(|i| i.downcast_ref::<rustls::Error>()) {
                        Some(tls) => PinError::Tls(tls.clone()),
                        None => PinError::Io(e),
                    },
                );
            }
        }
    }
    Ok(())
}

/// PEM text for one DER certificate.
pub(crate) fn pem_encode_cert(der: &[u8]) -> String {
    let b64 = base64::engine::general_purpose::STANDARD.encode(der);
    let mut out = String::from("-----BEGIN CERTIFICATE-----\n");
    for chunk in b64.as_bytes().chunks(64) {
        out.push_str(std::str::from_utf8(chunk).unwrap_or_default());
        out.push('\n');
    }
    out.push_str("-----END CERTIFICATE-----\n");
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::pki_types::pem::PemObject;

    /// A CA's DER and a leaf for `leaf_name` signed by it, as PEM.
    struct TestPki {
        ca_der: CertificateDer<'static>,
        leaf_pem: String,
    }

    fn test_pki(leaf_name: &str) -> TestPki {
        let ca_key = rcgen::KeyPair::generate().expect("ca key");
        let mut ca_params = rcgen::CertificateParams::new(vec![]).expect("ca params");
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let ca_cert = ca_params.self_signed(&ca_key).expect("ca cert");
        let leaf_key = rcgen::KeyPair::generate().expect("leaf key");
        let leaf = rcgen::CertificateParams::new(vec![leaf_name.to_string()])
            .expect("leaf params")
            .signed_by(&leaf_key, &rcgen::Issuer::from_params(&ca_params, &ca_key))
            .expect("leaf cert");
        TestPki {
            ca_der: ca_cert.der().clone(),
            leaf_pem: leaf.pem(),
        }
    }

    fn verify(pki: &TestPki, pin: [u8; 32], name: &str) -> (Result<(), rustls::Error>, Outcome) {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let v = PinVerifier::new(pin, provider);
        let leaf = CertificateDer::from_pem_slice(pki.leaf_pem.as_bytes()).expect("leaf der");
        let name = ServerName::try_from(name.to_string()).expect("name");
        let r = v
            .verify_server_cert(
                &leaf,
                std::slice::from_ref(&pki.ca_der),
                &name,
                &[],
                UnixTime::now(),
            )
            .map(|_| ());
        (r, v.take())
    }

    #[test]
    fn pin_matching_presented_root_verifies_the_leaf() {
        let pki = test_pki("localhost");
        let (r, outcome) = verify(&pki, sha256(&pki.ca_der), "localhost");
        r.expect("a matching pin and server name verifies");
        assert!(matches!(outcome, Outcome::Pinned(ref d) if d == &pki.ca_der));
    }

    #[test]
    fn pin_mismatch_is_refused_and_recorded() {
        let pki = test_pki("localhost");
        let (r, outcome) = verify(&pki, [0u8; 32], "localhost");
        assert!(r.is_err());
        assert!(matches!(outcome, Outcome::Mismatch));
    }

    #[test]
    fn pin_match_with_wrong_server_name_is_refused() {
        let pki = test_pki("localhost");
        let (r, outcome) = verify(&pki, sha256(&pki.ca_der), "not-the-relay.example");
        assert!(r.is_err(), "the leaf must match the server name");
        assert!(!matches!(outcome, Outcome::Pinned(_)));
    }

    #[test]
    fn leaf_from_another_ca_is_refused_even_when_the_pinned_root_is_presented() {
        let pki = test_pki("localhost");
        let other = test_pki("localhost");
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let v = PinVerifier::new(sha256(&pki.ca_der), provider);
        let foreign_leaf =
            CertificateDer::from_pem_slice(other.leaf_pem.as_bytes()).expect("leaf der");
        let name = ServerName::try_from("localhost").expect("name");
        let r = v.verify_server_cert(
            &foreign_leaf,
            std::slice::from_ref(&pki.ca_der),
            &name,
            &[],
            UnixTime::now(),
        );
        assert!(r.is_err());
    }

    #[test]
    fn pem_encode_round_trips() {
        let pki = test_pki("localhost");
        let pem = pem_encode_cert(&pki.ca_der);
        let back = CertificateDer::from_pem_slice(pem.as_bytes()).expect("parse");
        assert_eq!(back, pki.ca_der);
    }

    #[test]
    fn host_port_parses_endpoints() {
        assert_eq!(
            host_port("https://relay.example:7654").unwrap(),
            ("relay.example".to_string(), 7654)
        );
        assert_eq!(
            host_port("https://[::1]:7654").unwrap(),
            ("::1".to_string(), 7654)
        );
        assert_eq!(
            host_port("https://127.0.0.1:7654").unwrap(),
            ("127.0.0.1".to_string(), 7654)
        );
        assert_eq!(
            host_port("https://[2001:db8::1]:7443").unwrap(),
            ("2001:db8::1".to_string(), 7443)
        );
    }
}
