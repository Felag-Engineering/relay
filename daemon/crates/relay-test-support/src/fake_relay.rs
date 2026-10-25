//! A fake Relay Enrollment service over real TLS, for the tests that enroll a Node
//! against one. It presents `[leaf, CA]` the way the Relay's node plane does, counts
//! the `Enroll` calls it receives, and records the Enrollment Tokens and labels it
//! saw. It writes no file and spawns no process.
//!
//! Each [`pki`] call mints a fresh CA, so two fakes have distinct CAs.

use std::convert::Infallible;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use relay_proto::{EnrollRequest, EnrollResponse};
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::CertificateSigningRequestDer;
use tonic::codegen::{http, BoxFuture, Context, Poll, Service};
use tonic::transport::server::{ServerTlsConfig, TcpIncoming};
use tonic::transport::{Identity as TlsIdentity, Server};
use x509_parser::prelude::FromDer;

/// A CA and a leaf it signed.
pub struct Pki {
    pub ca_pem: String,
    pub ca_der: Vec<u8>,
    ca_params: rcgen::CertificateParams,
    ca_key: rcgen::KeyPair,
    leaf_pem: String,
    leaf_key_pem: String,
}

/// Mints a CA and a leaf for `leaf_name`.
pub fn pki(leaf_name: &str) -> Pki {
    let ca_key = rcgen::KeyPair::generate().expect("ca key");
    let mut ca_params = rcgen::CertificateParams::new(vec![]).expect("ca params");
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    let ca = ca_params.self_signed(&ca_key).expect("ca cert");
    let leaf_key = rcgen::KeyPair::generate().expect("leaf key");
    let leaf = rcgen::CertificateParams::new(vec![leaf_name.to_string()])
        .expect("leaf params")
        .signed_by(&leaf_key, &rcgen::Issuer::from_params(&ca_params, &ca_key))
        .expect("leaf cert");
    Pki {
        ca_pem: ca.pem(),
        ca_der: ca.der().to_vec(),
        ca_params,
        ca_key,
        leaf_pem: leaf.pem(),
        leaf_key_pem: leaf_key.serialize_pem(),
    }
}

/// What the fake Relay saw.
#[derive(Default)]
pub struct Seen {
    pub enroll_calls: AtomicUsize,
    /// The Enrollment Token of each `Enroll` call.
    pub tokens: Mutex<Vec<String>>,
    /// The labels of each `Enroll` call, exactly as received (`node:` prefixed).
    pub self_labels: Mutex<Vec<(String, String)>>,
}

impl Seen {
    pub fn calls(&self) -> usize {
        self.enroll_calls.load(Ordering::SeqCst)
    }
}

/// What the fake answers `Enroll` with.
#[derive(Clone)]
enum Answer {
    /// Signs the CSR and returns this CA bundle.
    Enrolled { ca_bundle_pem: Arc<String> },
    /// Refuses with a message carrying a control character, so a test can check
    /// that Relay-supplied text is escaped before it is shown.
    Rejected,
}

/// The message [`start_rejecting_relay`] refuses with: it contains an ESC byte.
pub const REJECTION_MESSAGE: &str = "token \u{1b}[31mrejected";

#[derive(Clone)]
struct FakeEnrollment {
    seen: Arc<Seen>,
    ca_params: Arc<rcgen::CertificateParams>,
    ca_key: Arc<rcgen::KeyPair>,
    answer: Answer,
}

impl tonic::server::UnaryService<EnrollRequest> for FakeEnrollment {
    type Response = EnrollResponse;
    type Future = BoxFuture<tonic::Response<EnrollResponse>, tonic::Status>;

    fn call(&mut self, req: tonic::Request<EnrollRequest>) -> Self::Future {
        let this = self.clone();
        Box::pin(async move {
            let req = req.into_inner();
            this.seen.enroll_calls.fetch_add(1, Ordering::SeqCst);
            this.seen
                .tokens
                .lock()
                .unwrap()
                .push(req.enrollment_token.clone());
            this.seen.self_labels.lock().unwrap().extend(
                req.self_labels
                    .iter()
                    .map(|l| (l.key.clone(), l.value.clone())),
            );
            let ca_bundle_pem = match &this.answer {
                Answer::Enrolled { ca_bundle_pem } => ca_bundle_pem,
                Answer::Rejected => {
                    return Err(tonic::Status::permission_denied(REJECTION_MESSAGE))
                }
            };
            let csr = String::from_utf8(req.csr).expect("csr utf8");
            let cert = sign_csr(&csr, &this.ca_params, &this.ca_key);
            Ok(tonic::Response::new(EnrollResponse {
                node_id: "node-join-test".to_string(),
                certificate: cert.pem().into_bytes(),
                ca_bundle: ca_bundle_pem.as_bytes().to_vec(),
                ..Default::default()
            }))
        })
    }
}

impl Service<http::Request<tonic::body::Body>> for FakeEnrollment {
    type Response = http::Response<tonic::body::Body>;
    type Error = Infallible;
    type Future = BoxFuture<Self::Response, Infallible>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Infallible>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: http::Request<tonic::body::Body>) -> Self::Future {
        let svc = self.clone();
        Box::pin(async move {
            if req.uri().path() != "/relay.v1.Enrollment/Enroll" {
                return Ok(tonic::Status::unimplemented("not Enroll").into_http());
            }
            let mut grpc = tonic::server::Grpc::new(tonic_prost::ProstCodec::default());
            Ok(grpc.unary(svc, req).await)
        })
    }
}

async fn start(server: &Pki, answer: Answer) -> (u16, Arc<Seen>) {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let incoming = TcpIncoming::bind("127.0.0.1:0".parse().unwrap()).expect("bind");
    let port = incoming.local_addr().expect("local_addr").port();
    let seen = Arc::new(Seen::default());
    let svc = FakeEnrollment {
        seen: Arc::clone(&seen),
        ca_params: Arc::new(server.ca_params.clone()),
        ca_key: Arc::new(rcgen::KeyPair::from_pem(&server.ca_key.serialize_pem()).expect("ca key")),
        answer,
    };
    let chain = format!("{}{}", server.leaf_pem, server.ca_pem);
    let tls = ServerTlsConfig::new().identity(TlsIdentity::from_pem(chain, &server.leaf_key_pem));
    let builder = Server::builder().tls_config(tls).expect("server tls");
    tokio::spawn(async move {
        let _ = builder.serve_with_incoming(svc, incoming).await;
    });
    (port, seen)
}

/// Starts the fake Relay presenting `server`'s leaf and CA, answering `Enroll`
/// with `ca_bundle_pem` as the CA bundle. Returns its port and what it saw.
pub async fn start_fake_relay(server: &Pki, ca_bundle_pem: String) -> (u16, Arc<Seen>) {
    start(
        server,
        Answer::Enrolled {
            ca_bundle_pem: Arc::new(ca_bundle_pem),
        },
    )
    .await
}

/// As [`start_fake_relay`], but every `Enroll` is refused with
/// `PERMISSION_DENIED` and [`REJECTION_MESSAGE`].
pub async fn start_rejecting_relay(server: &Pki) -> (u16, Arc<Seen>) {
    start(server, Answer::Rejected).await
}

/// A listener that accepts connections and never answers, so a TLS handshake
/// against it stays pending for as long as the returned task lives.
pub async fn start_silent_listener() -> (u16, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let port = listener.local_addr().expect("local_addr").port();
    let task = tokio::spawn(async move {
        let mut held = Vec::new();
        while let Ok((socket, _)) = listener.accept().await {
            held.push(socket);
        }
    });
    (port, task)
}

/// A CSR's SubjectPublicKeyInfo, adapted to rcgen's signing API.
struct CsrPublicKey(Vec<u8>);

impl rcgen::PublicKeyData for CsrPublicKey {
    fn der_bytes(&self) -> &[u8] {
        &self.0
    }
    fn algorithm(&self) -> &'static rcgen::SignatureAlgorithm {
        &rcgen::PKCS_ECDSA_P256_SHA256
    }
}

/// Parses and signs `csr_pem` as the CA self-signed from `ca_params`/`ca_kp`,
/// after checking its self-signature and that it carries the P-256/ecdsa-
/// with-SHA256, empty-subject shape the daemon's `build_keypair_and_csr` produces.
///
/// Signs without rcgen's `x509-parser` dev feature, which would bring a second
/// ASN.1 stack (x509-parser 0.16) into Cargo.lock. The leaf gets the CSR's (empty)
/// subject and no extensions.
pub fn sign_csr(
    csr_pem: &str,
    ca_params: &rcgen::CertificateParams,
    ca_kp: &rcgen::KeyPair,
) -> rcgen::Certificate {
    let der = CertificateSigningRequestDer::from_pem_slice(csr_pem.as_bytes()).expect("CSR PEM");
    let (remainder, csr) =
        x509_parser::certification_request::X509CertificationRequest::from_der(der.as_ref())
            .expect("parse CSR");
    assert!(remainder.is_empty(), "trailing bytes after CSR DER");

    // Checks the CSR's self-signature, as the Relay does.
    csr.verify_signature().expect("CSR self-signature");

    let subject_pki = &csr.certification_request_info.subject_pki;
    assert_eq!(
        subject_pki.algorithm.algorithm,
        x509_parser::oid_registry::OID_KEY_TYPE_EC_PUBLIC_KEY,
        "CSR public key is not an EC key"
    );
    // A future key-type or curve change should fail loudly here instead of
    // being mis-signed as P-256.
    let curve_oid = subject_pki
        .algorithm
        .parameters
        .as_ref()
        .expect("EC SPKI carries curve parameters")
        .as_oid()
        .expect("curve parameters are an OID");
    assert_eq!(
        curve_oid,
        x509_parser::oid_registry::OID_EC_P256,
        "CSR public key is not on the P-256 curve"
    );
    assert_eq!(
        csr.signature_algorithm.algorithm,
        x509_parser::oid_registry::OID_SIG_ECDSA_WITH_SHA256,
        "CSR is not signed with ecdsa-with-SHA256"
    );
    assert!(
        csr.certification_request_info
            .subject
            .iter_rdn()
            .next()
            .is_none(),
        "CSR subject must be empty; the helper would otherwise drop it"
    );

    // CertificateParams::default() sets CN=rcgen self signed cert, which would
    // give the leaf the same subject as its issuer; the CSR's empty subject is
    // what the Relay's CA would keep.
    let mut params = rcgen::CertificateParams::default();
    params.distinguished_name = rcgen::DistinguishedName::new();

    params
        .signed_by(
            &CsrPublicKey(subject_pki.subject_public_key.data.to_vec()),
            &rcgen::Issuer::from_params(ca_params, ca_kp),
        )
        .expect("sign CSR")
}
