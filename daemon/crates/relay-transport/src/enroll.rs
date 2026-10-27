//! Bootstrap enrollment: generates an ECDSA P-256 keypair + CSR, pins the Relay's
//! CA from the join string's fingerprint, calls the Relay's `Enrollment.Enroll` RPC
//! over TLS trusting only that CA, and persists the returned identity. Idempotent:
//! a re-run on an already-enrolled Node is a no-op (ADR-0006, ADR-0031).

use std::future::Future;
use std::path::{Path, PathBuf};

use tracing::info;

use crate::gen::{enrollment_client::EnrollmentClient, EnrollRequest, Facts, Label};
use crate::identity::{
    build_channel, build_keypair_and_csr, cert_pubkey_matches_key, load_identity, persist_identity,
    persist_relay_addr, validate_endpoint_scheme, validate_relay_addr, Identity, IdentityError,
};
use crate::join_string::JoinString;
use crate::log_field;
use crate::pin::{fetch_pinned_ca, pem_encode_cert, PinError};

type Result<T, E = EnrollError> = std::result::Result<T, E>;

/// Typed error for enrollment and renewal RPC paths.
///
/// Wraps `IdentityError` via `#[from]` so the Send+Sync guarantee propagates
/// through `renew::run` (a `tokio::spawn`-ed task) without a `.to_string()` bridge.
#[derive(Debug, thiserror::Error)]
pub enum EnrollError {
    #[error(transparent)]
    Identity(#[from] IdentityError),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    // Boxed to keep the enum size reasonable (tonic::Status is ~176 bytes).
    #[error(transparent)]
    Rpc(Box<tonic::Status>),
    #[error(transparent)]
    Utf8(#[from] std::string::FromUtf8Error),
    #[error("node_id mismatch: expected {expected}, got {received}")]
    NodeIdMismatch { expected: String, received: String },
    #[error(transparent)]
    Pin(#[from] PinError),
    #[error("the Relay returned a CA bundle that is not the pinned CA; nothing was persisted")]
    CaBundleMismatch,
    /// A failure after the Relay answered `Enroll`: it has issued a certificate and
    /// spent the token's use, so a Node record may exist that this Node never holds.
    #[error(transparent)]
    AfterIssue(Box<EnrollError>),
}

impl EnrollError {
    /// Whether the error arose after the Relay answered `Enroll`, so that a Node
    /// record may exist.
    pub fn relay_may_have_recorded(&self) -> bool {
        matches!(self, EnrollError::AfterIssue(_))
    }
}

/// Marks `e` as a failure after the Relay answered.
fn after_issue(e: impl Into<EnrollError>) -> EnrollError {
    EnrollError::AfterIssue(Box::new(e.into()))
}

// Manual From impl because #[from] on Box<tonic::Status> would generate
// From<Box<tonic::Status>>, not From<tonic::Status>.
impl From<tonic::Status> for EnrollError {
    fn from(s: tonic::Status) -> Self {
        EnrollError::Rpc(Box::new(s))
    }
}

/// Configuration for the enrollment bootstrap step, constructed by `relay-daemon
/// join` (the bin's `config::join_enroll_config`) from the join string it read.
pub struct EnrollConfig {
    /// The decoded join string: the CA fingerprint pinned before anything is sent,
    /// and the Enrollment Token, never logged. Only the redacting type is held.
    pub join: JoinString,
    /// gRPC endpoint of the Relay's Enrollment service (e.g. `https://relay:7654`).
    pub endpoint: String,
    /// Node-plane Relay address persisted with the identity at enrollment
    /// (ADR-0031 decision 4); the Tunnel's dial target, not the enrollment endpoint.
    pub relay_addr: String,
    /// TLS SNI server name override for cert verification (optional).
    pub tls_server_name: Option<String>,
    /// Directory where key.pem, cert.pem, ca_bundle.pem, and node_id are persisted.
    pub state_dir: PathBuf,
    /// Node-space labels (bare `key=value`; `node:` prefix is added at send time).
    pub node_labels: Vec<(String, String)>,
    /// Facts gathered from the local environment.
    pub facts: Facts,
}

/// The unit's state directory (`StateDirectory=relay-daemon`), where the daemon
/// keeps its identity unless `RELAY_STATE_DIR` names another.
pub const DEFAULT_STATE_DIR: &str = "/var/lib/relay-daemon";

/// Returns the daemon's state directory: `RELAY_STATE_DIR` env var or
/// [`DEFAULT_STATE_DIR`]; an empty value counts as unset, as it does for
/// `relay-daemon join`. Called by `Config::from_env` so that the startup plan
/// and the Tunnel identity load always agree on the state directory without a
/// second env read.
pub fn state_dir_from_env() -> PathBuf {
    match std::env::var("RELAY_STATE_DIR") {
        Ok(dir) if !dir.is_empty() => PathBuf::from(dir),
        _ => PathBuf::from(DEFAULT_STATE_DIR),
    }
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Reads `RELAY_NODE_LABELS` from the environment and returns bare (key, value)
/// pairs. The `node:` prefix is stripped here and re-applied at send time by
/// `node_labels_to_proto`, so there is exactly one prefixing site.
pub fn node_labels_from_env() -> Vec<(String, String)> {
    std::env::var("RELAY_NODE_LABELS")
        .map(|v| parse_node_labels(&v))
        .unwrap_or_default()
}

/// Converts bare (key, value) label pairs to proto Labels, adding the mandatory
/// `node:` prefix. This is the single prefixing site for node-space labels
/// (ADR-0006 two-namespace invariant: a daemon can never inject relay: labels).
pub fn node_labels_to_proto(labels: &[(String, String)]) -> Vec<Label> {
    labels
        .iter()
        .map(|(k, v)| Label {
            key: format!("node:{}", k),
            value: v.clone(),
        })
        .collect()
}

/// Parses a comma-separated `key=value` label list into bare pairs, stripping
/// any `node:` prefix that would otherwise be double-applied at send time.
/// Malformed or empty entries are silently skipped.
pub fn parse_node_labels(raw: &str) -> Vec<(String, String)> {
    raw.split(',')
        .filter_map(|entry| {
            let entry = entry.trim();
            if entry.is_empty() {
                return None;
            }
            // Strip leading "node:" so we never double-prefix at send time.
            let entry = entry.strip_prefix("node:").unwrap_or(entry);
            let mut parts = entry.splitn(2, '=');
            let key = parts.next()?.to_string();
            if key.is_empty() {
                return None;
            }
            let value = parts.next().unwrap_or("").to_string();
            Some((key, value))
        })
        .collect()
}

/// Longest `node:` label key the Relay accepts, in bytes.
const MAX_LABEL_KEY_LEN: usize = 63;
/// Longest `node:` label value the Relay accepts, in bytes.
const MAX_LABEL_VALUE_LEN: usize = 255;

/// Whether the Relay would accept this bare `node:` label at ingress: a
/// non-empty key of at most 63 bytes, a value of at most 255, and only ASCII
/// letters, digits, `.`, `_` and `-` in either. Mirrors the Relay's own rule
/// (`registry.WellFormedNodeLabel`). The daemon applies it only to its default
/// labels, so a default can never get an enrollment refused; declared labels are
/// left for the Relay to judge.
fn well_formed_node_label(key: &str, value: &str) -> bool {
    let allowed = |b: &u8| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-');
    !key.is_empty()
        && key.len() <= MAX_LABEL_KEY_LEN
        && value.len() <= MAX_LABEL_VALUE_LEN
        && key.as_bytes().iter().all(allowed)
        && value.as_bytes().iter().all(allowed)
}

/// `declared` (`RELAY_NODE_LABELS`) with the daemon's default labels added:
/// `node:hostname`, `node:os` and `node:arch`, from `facts`. A declared key
/// replaces the default of the same name. A default that is not a well-formed
/// `node:` label is left out and its key returned, never its value. Declared
/// labels come back untouched.
pub fn with_default_node_labels(
    declared: Vec<(String, String)>,
    facts: &Facts,
) -> (Vec<(String, String)>, Vec<&'static str>) {
    let defaults = [
        ("hostname", &facts.hostname),
        ("os", &facts.os),
        ("arch", &facts.arch),
    ];
    let mut labels = declared;
    let mut left_out = Vec::new();
    for (key, value) in defaults {
        if labels.iter().any(|(declared_key, _)| declared_key == key) {
            continue;
        }
        if well_formed_node_label(key, value) {
            labels.push((key.to_string(), value.clone()));
        } else {
            left_out.push(key);
        }
    }
    (labels, left_out)
}

/// Calls the Relay's `Enrollment.Enroll` RPC. No client certificate is used — this
/// is the certless bootstrap path (ADR-0006 §2). The CA is pinned first, from the
/// join string's fingerprint, and the token is sent only on a connection whose
/// sole trust root is that CA; there is no trust-on-first-use (ADR-0031).
///
/// Takes all config as owned values so callers can move-capture from `EnrollConfig`
/// without lifetime issues.
async fn call_enroll_owned(
    endpoint: String,
    pin: [u8; 32],
    mut token: zeroize::Zeroizing<String>,
    tls_server_name: Option<String>,
    node_labels: Vec<(String, String)>,
    facts: Facts,
    csr_pem: String,
) -> Result<(String, String, String)> {
    // Defense-in-depth: re-validate even if the caller bypassed from_env.
    validate_endpoint_scheme(&endpoint)?;

    let ca_der = fetch_pinned_ca(&endpoint, tls_server_name.as_deref(), &pin).await?;
    let ca_pem = pem_encode_cert(&ca_der);
    let channel = build_channel(endpoint, tls_server_name, ca_pem.as_bytes(), None).await?;

    let self_labels = node_labels_to_proto(&node_labels);

    let req = EnrollRequest {
        // Moved out, not cloned: the wiped holder is left empty.
        enrollment_token: std::mem::take(&mut *token),
        csr: csr_pem.into_bytes(),
        self_labels,
        facts: Some(facts),
    };

    let resp = EnrollmentClient::new(channel)
        .enroll(tonic::Request::new(req))
        .await?
        .into_inner();

    // EnrollResponse.certificate and .ca_bundle are proto `bytes` (Vec<u8>).
    // Both should be UTF-8 PEM; propagate an error if they aren't.
    let cert_pem = String::from_utf8(resp.certificate).map_err(after_issue)?;
    let ca_bundle_pem = String::from_utf8(resp.ca_bundle).map_err(after_issue)?;
    check_ca_bundle(&ca_bundle_pem, &ca_der).map_err(after_issue)?;

    Ok((resp.node_id, cert_pem, ca_bundle_pem))
}

/// Refuses a returned CA bundle unless it is exactly the pinned CA: one
/// certificate, byte-identical DER. What is persisted as `ca_bundle.pem` then
/// trusts nothing the join string did not pin.
fn check_ca_bundle(ca_bundle_pem: &str, pinned: &[u8]) -> Result<()> {
    use rustls_pki_types::pem::PemObject;
    use rustls_pki_types::CertificateDer;
    let certs: Vec<CertificateDer<'static>> =
        CertificateDer::pem_slice_iter(ca_bundle_pem.as_bytes())
            .collect::<std::result::Result<_, _>>()
            .map_err(|_| EnrollError::CaBundleMismatch)?;
    match certs.as_slice() {
        [only] if only.as_ref() == pinned => Ok(()),
        _ => Err(EnrollError::CaBundleMismatch),
    }
}

/// Orchestrates enrollment, separated from the RPC for testability.
///
/// If a valid identity is already persisted in `state_dir`, returns it immediately
/// without generating a CSR or contacting the Relay. Otherwise: generates a
/// keypair + CSR, calls `enroller(csr_pem)`, persists the returned identity.
///
/// The only await is `enroller`, and persistence is synchronous after it, so
/// dropping this future (a timeout, an interrupt) persists nothing: `relay-daemon
/// join` relies on that.
async fn ensure_enrolled_with<F, Fut>(
    state_dir: &Path,
    relay_addr: &str,
    hostname: &str,
    label_count: usize,
    enroller: F,
) -> Result<Identity>
where
    F: FnOnce(String) -> Fut,
    Fut: Future<Output = Result<(String, String, String)>>,
{
    if let Some(identity) = load_identity(state_dir)? {
        info!(
            node_id = log_field::untrusted(&identity.node_id),
            hostname, "already enrolled, reusing persisted identity"
        );
        return Ok(identity);
    }

    // Refuse a malformed address before the single-use Enrollment Token is spent.
    validate_relay_addr(relay_addr)?;

    info!(hostname, label_count, "starting enrollment");
    let (key_pem, csr_pem) = build_keypair_and_csr()?;
    let (node_id, cert_pem, ca_bundle_pem) = enroller(csr_pem).await?;

    let identity = Identity {
        node_id: node_id.clone(),
        key_pem,
        cert_pem,
        ca_bundle_pem,
    };
    // Fail closed: verify the Relay-returned certificate's public key corresponds
    // to the key we just generated, *before* persisting. Mirrors the renewal path
    // (renew.rs); a cert whose SPKI doesn't match our private key is unusable and
    // must never be written to disk (a misbehaving/compromised Relay otherwise
    // locks the Node out until the next boot's load-time check catches it).
    cert_pubkey_matches_key(&identity.cert_pem, &identity.key_pem).map_err(after_issue)?;
    // Address first, then identity: every identity this code persists has an
    // address. The already-enrolled branch above never writes it (no backfill; DI-44).
    persist_relay_addr(state_dir, relay_addr).map_err(after_issue)?;
    persist_identity(state_dir, &identity).map_err(after_issue)?;
    info!(
        node_id = log_field::untrusted(&node_id),
        hostname, label_count, "enrollment complete"
    );
    Ok(identity)
}

/// Performs the enrollment bootstrap step for this Node.
///
/// Idempotent: if a valid identity is already on disk in `cfg.state_dir`, returns
/// it immediately without generating a new CSR or contacting the Relay.
/// The mTLS Tunnel connection lives separately in `tunnel::connect_mtls`.
pub async fn ensure_enrolled(cfg: &EnrollConfig) -> Result<Identity> {
    // Clone the fields call_enroll_owned needs so the async closure captures
    // owned data and avoids a lifetime tangle with &EnrollConfig.
    let endpoint = cfg.endpoint.clone();
    let pin = *cfg.join.ca_fingerprint();
    // Wiped if the call ends before the request is built (a pin mismatch). Once
    // the string moves into the request, it and the tonic, h2 and rustls buffers
    // it passes through hold the token unwiped.
    let token = zeroize::Zeroizing::new(cfg.join.enrollment_token().to_string());
    let tls_server_name = cfg.tls_server_name.clone();
    let node_labels = cfg.node_labels.clone();
    let facts = cfg.facts.clone();

    ensure_enrolled_with(
        &cfg.state_dir,
        &cfg.relay_addr,
        &cfg.facts.hostname,
        cfg.node_labels.len(),
        move |csr_pem| {
            call_enroll_owned(
                endpoint,
                pin,
                token,
                tls_server_name,
                node_labels,
                facts,
                csr_pem,
            )
        },
    )
    .await
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::mode_assert;
    use crate::identity::test_ca::self_signed_identity;
    use crate::identity::{load_identity, load_relay_addr, persist_identity, IdentityError};
    use crate::test_support::TempDir;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;

    const ADDR: &str = "https://relay.test:7654";

    // Compile-time Send+Sync assertion for EnrollError.
    fn _assert_enroll_error_send_sync() {
        fn _assert<T: Send + Sync>() {}
        _assert::<EnrollError>();
    }

    // -----------------------------------------------------------------------
    // parse_node_labels
    // -----------------------------------------------------------------------

    #[test]
    fn parse_labels_simple() {
        let labels = parse_node_labels("role=web,env=prod");
        assert_eq!(
            labels,
            vec![
                ("role".to_string(), "web".to_string()),
                ("env".to_string(), "prod".to_string()),
            ]
        );
    }

    #[test]
    fn parse_labels_strips_node_prefix() {
        // A "node:" prefix must not be double-applied.
        let labels = parse_node_labels("node:role=web");
        assert_eq!(labels, vec![("role".to_string(), "web".to_string())]);
    }

    // Proves DI-9.
    #[test]
    fn parse_labels_skips_empty_and_garbage() {
        // "=bad" has empty key → skipped; empty comma entries → skipped.
        let labels = parse_node_labels(",=bad,,env=staging,");
        assert_eq!(labels, vec![("env".to_string(), "staging".to_string())]);
    }

    // -----------------------------------------------------------------------
    // with_default_node_labels / well_formed_node_label
    // -----------------------------------------------------------------------

    fn facts(hostname: &str, os: &str, arch: &str) -> Facts {
        Facts {
            hostname: hostname.to_string(),
            os: os.to_string(),
            arch: arch.to_string(),
            ..Default::default()
        }
    }

    fn pair(key: &str, value: &str) -> (String, String) {
        (key.to_string(), value.to_string())
    }

    #[test]
    fn default_labels_are_hostname_os_and_arch_from_the_facts() {
        let (labels, left_out) =
            with_default_node_labels(vec![], &facts("web-01", "linux", "x86_64"));
        assert_eq!(
            labels,
            vec![
                pair("hostname", "web-01"),
                pair("os", "linux"),
                pair("arch", "x86_64"),
            ]
        );
        assert!(left_out.is_empty());
    }

    #[test]
    fn default_labels_follow_the_declared_labels() {
        let (labels, _) = with_default_node_labels(
            vec![pair("role", "web")],
            &facts("web-01", "linux", "x86_64"),
        );
        assert_eq!(labels.len(), 4);
        assert_eq!(labels[0], pair("role", "web"));
        assert_eq!(labels[1], pair("hostname", "web-01"));
    }

    #[test]
    fn a_declared_label_replaces_the_default_of_the_same_key() {
        let declared = parse_node_labels("node:os=ubuntu,hostname=web-01");
        let (labels, left_out) = with_default_node_labels(declared, &facts("box", "linux", "arm"));
        assert_eq!(
            labels,
            vec![
                pair("os", "ubuntu"),
                pair("hostname", "web-01"),
                pair("arch", "arm"),
            ]
        );
        assert!(left_out.is_empty());
    }

    #[test]
    fn an_ill_formed_default_is_left_out_and_named_by_its_key() {
        for bad in ["bad host".to_string(), "h".repeat(256)] {
            let (labels, left_out) =
                with_default_node_labels(vec![], &facts(&bad, "linux", "x86_64"));
            assert_eq!(labels, vec![pair("os", "linux"), pair("arch", "x86_64")]);
            assert_eq!(left_out, vec!["hostname"]);
        }
    }

    #[test]
    fn a_declared_label_is_never_judged_by_the_default_rule() {
        let declared = vec![pair("role", "web, relay:x=y")];
        let (labels, left_out) =
            with_default_node_labels(declared.clone(), &facts("web-01", "linux", "x86_64"));
        assert_eq!(&labels[..1], declared.as_slice());
        assert!(left_out.is_empty());
    }

    // Mirrors the Relay's TestWellFormedNodeLabel table.
    #[test]
    fn well_formed_node_label_mirrors_the_relay_rule() {
        let cases: [(String, String, bool); 8] = [
            ("role".into(), "web".into(), true),
            ("k".repeat(63), "v".repeat(255), true),
            ("k".repeat(64), "web".into(), false),
            ("role".into(), "v".repeat(256), false),
            ("role".into(), "web, relay:quarantine=on".into(), false),
            (String::new(), "web".into(), false),
            ("role".into(), String::new(), true),
            ("role".into(), "caf\u{e9}".into(), false),
        ];
        for (key, value, want) in cases {
            assert_eq!(
                well_formed_node_label(&key, &value),
                want,
                "key {key:?} value {value:?}"
            );
        }
    }

    // -----------------------------------------------------------------------
    // Idempotency: pre-written identity → enroller is NOT called
    // -----------------------------------------------------------------------

    // Proves EN-32.
    #[tokio::test]
    async fn idempotency_no_op_when_identity_present() {
        let dir = TempDir::new("idempotent");
        let id = self_signed_identity("node-test-aabbccdd");
        persist_identity(dir.path(), &id).expect("persist_identity");

        let enroller_called = Arc::new(AtomicBool::new(false));
        let flag = enroller_called.clone();

        let result = ensure_enrolled_with(dir.path(), ADDR, "test-host", 0, move |_csr_pem| {
            flag.store(true, Ordering::SeqCst);
            async move {
                panic!("enroller must not be called for an already-enrolled Node");
            }
        })
        .await
        .expect("ensure_enrolled_with should succeed");

        assert!(
            !enroller_called.load(Ordering::SeqCst),
            "enroller was called despite valid persisted identity"
        );
        assert_eq!(result.node_id, id.node_id);
    }

    // -----------------------------------------------------------------------
    // Fresh enroll: empty dir + mock enroller → files persisted correctly
    // -----------------------------------------------------------------------

    // Proves EN-32.
    #[tokio::test]
    async fn fresh_enroll_persists_identity() {
        let dir = TempDir::new("fresh");

        let canned_node_id = "node-fresh-001122".to_string();
        let nid = canned_node_id.clone();

        // The enroller signs the CSR with a test CA so the issued cert's public key
        // matches the freshly generated keypair — required for load_identity to pass
        // the key/cert correspondence check (FIX A, FIND-1).
        let result = ensure_enrolled_with(
            dir.path(),
            ADDR,
            "test-host",
            2,
            move |csr_pem| async move {
                let ca_kp = rcgen::KeyPair::generate().expect("ca keygen");
                let ca_params = rcgen::CertificateParams::new(vec![]).expect("ca params");
                let ca_cert = ca_params.self_signed(&ca_kp).expect("ca cert");
                let issued = crate::identity::test_ca::sign_csr(&csr_pem, &ca_params, &ca_kp);
                Ok((nid, issued.pem(), ca_cert.pem()))
            },
        )
        .await
        .expect("ensure_enrolled_with should succeed");

        assert_eq!(result.node_id, canned_node_id);
        assert!(
            result.cert_pem.contains("BEGIN CERTIFICATE"),
            "cert_pem must be a valid PEM certificate block"
        );

        // Files must be persisted with correct permissions. The modes
        // persist_identity declares are ceilings, not exact values — the
        // process umask may tighten them, nothing may widen them (see
        // identity::write_atomic).
        mode_assert::assert_within(
            &dir.path().join("key.pem"),
            0o600,
            0o077,
            "key.pem after fresh enroll",
        );
        for name in ["cert.pem", "ca_bundle.pem", "node_id"] {
            mode_assert::assert_within(&dir.path().join(name), 0o644, 0o022, name);
        }

        // load_identity must see the freshly written identity (key/cert match passes).
        let loaded = load_identity(dir.path())
            .expect("load_identity error")
            .expect("load_identity should return Some");
        assert_eq!(loaded.node_id, canned_node_id);
    }

    // Proves EN-8, DI-44.
    #[tokio::test]
    async fn persisted_address_written_at_enrollment() {
        let dir = TempDir::new("fresh-addr");
        ensure_enrolled_with(
            dir.path(),
            ADDR,
            "test-host",
            0,
            move |csr_pem| async move {
                let ca_kp = rcgen::KeyPair::generate().expect("ca keygen");
                let ca_params = rcgen::CertificateParams::new(vec![]).expect("ca params");
                let ca_cert = ca_params.self_signed(&ca_kp).expect("ca cert");
                let issued = crate::identity::test_ca::sign_csr(&csr_pem, &ca_params, &ca_kp);
                Ok(("node-addr-001".to_string(), issued.pem(), ca_cert.pem()))
            },
        )
        .await
        .expect("ensure_enrolled_with should succeed");

        assert_eq!(
            load_relay_addr(dir.path())
                .expect("load_relay_addr")
                .as_deref(),
            Some(ADDR)
        );
        mode_assert::assert_within(
            &dir.path().join(crate::identity::PERSISTED_ADDR_FILE),
            0o644,
            0o022,
            "relay_addr after fresh enroll",
        );
    }

    #[tokio::test]
    async fn enrolled_node_without_persisted_address_is_not_backfilled() {
        let dir = TempDir::new("no-backfill");
        // The shape of a Node enrolled before the address was persisted.
        persist_identity(dir.path(), &self_signed_identity("node-old-aabbccdd"))
            .expect("persist_identity");

        let called = Arc::new(AtomicBool::new(false));
        let flag = called.clone();
        ensure_enrolled_with(dir.path(), ADDR, "test-host", 0, move |_csr| {
            flag.store(true, Ordering::SeqCst);
            async move { panic!("enroller must not be called for an already-enrolled Node") }
        })
        .await
        .expect("ensure_enrolled_with should succeed");

        assert!(!called.load(Ordering::SeqCst));
        assert_eq!(load_relay_addr(dir.path()).expect("load_relay_addr"), None);
    }

    #[tokio::test]
    async fn malformed_relay_addr_is_refused_before_the_enroller_runs() {
        let dir = TempDir::new("bad-addr-before-enroll");
        let called = Arc::new(AtomicBool::new(false));
        let flag = called.clone();
        let result = ensure_enrolled_with(
            dir.path(),
            "http://relay.test:7654",
            "test-host",
            0,
            move |_csr| {
                flag.store(true, Ordering::SeqCst);
                async move { panic!("enroller must not run for a malformed relay address") }
            },
        )
        .await;

        assert!(result.is_err());
        assert!(!called.load(Ordering::SeqCst));
        assert_eq!(load_relay_addr(dir.path()).expect("load_relay_addr"), None);
    }

    // Proves EN-33.
    #[tokio::test]
    async fn fresh_enroll_fails_closed_on_key_cert_mismatch() {
        let dir = TempDir::new("fresh-mismatch");

        // A misbehaving/compromised Relay returns a certificate whose public key
        // does NOT correspond to the key the daemon just generated. Enrollment must
        // fail closed BEFORE persisting anything — parity with the renewal path,
        // which already enforces this (see perform_renewal_with in renew.rs).
        let result = ensure_enrolled_with(
            dir.path(),
            ADDR,
            "test-host",
            0,
            move |_csr_pem| async move {
                // Cert for an unrelated keypair, ignoring the daemon's CSR.
                let other_kp = rcgen::KeyPair::generate().expect("other keygen");
                let other_cert = rcgen::CertificateParams::new(vec![])
                    .expect("other params")
                    .self_signed(&other_kp)
                    .expect("other cert")
                    .pem();
                Ok(("node-mismatch".to_string(), other_cert.clone(), other_cert))
            },
        )
        .await;

        assert!(
            result.is_err(),
            "a cert whose SPKI does not match the generated key must fail closed"
        );
        let e = match result {
            Err(e) => e,
            Ok(_) => unreachable!(),
        };
        assert!(
            matches!(&e, EnrollError::AfterIssue(inner)
                if matches!(**inner, EnrollError::Identity(IdentityError::PubkeyMismatch))),
            "expected AfterIssue(Identity(PubkeyMismatch)), got {e:?}"
        );
        assert!(e.relay_may_have_recorded());
        // Nothing may be written to disk on a failed enrollment.
        assert!(
            !dir.path().join("key.pem").exists(),
            "no key.pem may be persisted when enrollment fails closed"
        );
        assert!(
            !dir.path()
                .join(crate::identity::PERSISTED_ADDR_FILE)
                .exists(),
            "no relay_addr may be persisted when enrollment fails closed"
        );
        assert!(
            load_identity(dir.path())
                .expect("load_identity error")
                .is_none(),
            "no identity may be persisted when enrollment fails closed"
        );
    }

    /// `prepare_state_dir` then `roll_back` leaves the directory as it was found,
    /// whichever way the enrollment between them failed. No claim cites this: it
    /// proves the helper the claims' tests rely on.
    #[tokio::test]
    async fn prepare_and_roll_back_restore_the_dir_as_found() {
        use crate::identity::{persist_relay_addr, prepare_state_dir};

        // A missing two-level directory: prepare creates both, roll_back removes both.
        let base = TempDir::created("rollback-missing");
        let dir = base.path().join("a").join("b");
        let prepared = prepare_state_dir(&dir).expect("prepare");
        assert!(dir.is_dir());
        assert!(prepared.roll_back().is_empty());
        assert!(!base.path().join("a").exists(), "both levels are gone");

        // A directory that already holds an address and a stray file: the address
        // is restored byte for byte and the stray file is never touched.
        let dir = TempDir::created("rollback-seeded");
        let relay_addr = dir.path().join(crate::identity::PERSISTED_ADDR_FILE);
        std::fs::write(&relay_addr, "https://old.example:443").unwrap();
        std::fs::write(dir.path().join("stray"), "keep").unwrap();
        let prepared = prepare_state_dir(dir.path()).expect("prepare");
        persist_relay_addr(dir.path(), "https://new.example:443").expect("persist");
        assert!(prepared.roll_back().is_empty());
        assert_eq!(
            std::fs::read_to_string(&relay_addr).unwrap(),
            "https://old.example:443"
        );
        assert_eq!(
            std::fs::read_to_string(dir.path().join("stray")).unwrap(),
            "keep"
        );

        // An enrollment that fails in the middle of persisting: key, cert and CA
        // are renamed in before node_id fails, because node_id.tmp is a non-empty
        // directory. roll_back removes what was written and leaves what was there.
        let dir = TempDir::created("rollback-mid-persist");
        let blocker = dir.path().join("node_id.tmp");
        std::fs::create_dir(&blocker).unwrap();
        std::fs::write(blocker.join("inside"), "keep").unwrap();
        let prepared = prepare_state_dir(dir.path()).expect("prepare");
        let result = ensure_enrolled_with(
            dir.path(),
            ADDR,
            "test-host",
            0,
            move |csr_pem| async move {
                let ca_kp = rcgen::KeyPair::generate().expect("ca keygen");
                let ca_params = rcgen::CertificateParams::new(vec![]).expect("ca params");
                let ca_cert = ca_params.self_signed(&ca_kp).expect("ca cert");
                let issued = crate::identity::test_ca::sign_csr(&csr_pem, &ca_params, &ca_kp);
                Ok(("node-mid".to_string(), issued.pem(), ca_cert.pem()))
            },
        )
        .await;
        assert!(result.is_err(), "node_id cannot be written");
        assert!(
            dir.path().join("key.pem").exists(),
            "the persist got that far"
        );
        assert!(prepared.roll_back().is_empty());
        for name in ["key.pem", "cert.pem", "ca_bundle.pem", "node_id"] {
            assert!(
                !dir.path().join(name).exists(),
                "{name} must be rolled back"
            );
        }
        assert!(!dir
            .path()
            .join(crate::identity::PERSISTED_ADDR_FILE)
            .exists());
        assert!(
            blocker.join("inside").exists(),
            "node_id.tmp existed before"
        );

        // Something it could not remove is reported, not hidden.
        let base = TempDir::created("rollback-leftover");
        let dir = base.path().join("x").join("y");
        let prepared = prepare_state_dir(&dir).expect("prepare");
        std::fs::write(dir.join("filled"), "x").unwrap();
        assert_eq!(prepared.roll_back(), vec![dir.clone()]);
        assert!(dir.join("filled").exists());
    }

    /// The `node_id` the Relay returns at enrollment is logged; a newline in it
    /// must not start a second journal line (#914).
    #[tokio::test]
    async fn newline_in_enrolled_node_id_yields_one_log_line() {
        let (buf, _guard) = crate::test_support::trace_capture::capture_fmt();

        let dir = TempDir::new("enroll-log-injection");
        let hostile = "node-1\nFORGED relay_daemon::allow: policy allowed\r\nFORGED2".to_string();
        let nid = hostile.clone();

        ensure_enrolled_with(
            dir.path(),
            ADDR,
            "test-host",
            2,
            move |csr_pem| async move {
                let ca_kp = rcgen::KeyPair::generate().expect("ca keygen");
                let ca_params = rcgen::CertificateParams::new(vec![]).expect("ca params");
                let ca_cert = ca_params.self_signed(&ca_kp).expect("ca cert");
                let issued = crate::identity::test_ca::sign_csr(&csr_pem, &ca_params, &ca_kp);
                Ok((nid, issued.pem(), ca_cert.pem()))
            },
        )
        .await
        .expect("ensure_enrolled_with should succeed");

        let text = String::from_utf8(buf.0.lock().unwrap().clone()).unwrap();
        let complete: Vec<&str> = text
            .lines()
            .filter(|l| l.contains("enrollment complete"))
            .collect();
        assert_eq!(complete.len(), 1, "{text:?}");
        assert!(!text.contains('\r'), "{text:?}");
        assert!(!text.lines().any(|l| l.starts_with("FORGED")), "{text:?}");
        assert!(complete[0].contains("\\n"), "{text:?}");
    }
}

/// Compile-time guarantee that the secret-bearing `EnrollConfig` (which holds
/// the Enrollment Token in `token`) never derives `Debug`. The manual
/// `NoDebug` impl below conflicts (E0119) with the blanket impl the instant
/// `EnrollConfig` gains a `Debug` impl, turning a silent secret-leak
/// regression into a build failure. Pins the ADR-0006 "never logged"
/// guarantee at the type level (issue #222).
#[cfg(test)]
mod no_debug_guard {
    use super::EnrollConfig;
    use std::fmt::Debug;

    trait NoDebug {}
    impl<T: Debug> NoDebug for T {}
    impl NoDebug for EnrollConfig {}

    fn assert_no_debug<T: NoDebug>() {}

    #[test]
    fn enroll_config_does_not_derive_debug() {
        assert_no_debug::<EnrollConfig>();
    }
}

/// The join-string enrollment path against a fake Relay over real TLS
/// (`relay_test_support::fake_relay`): the server presents `[leaf, CA]` the way
/// the Relay's node plane does and counts the `Enroll` calls it receives.
#[cfg(test)]
mod join_enroll {
    use super::*;
    use crate::identity::{load_identity, load_relay_addr};
    use crate::pin::sha256;
    use crate::test_support::fake_relay::{
        pki, start_fake_relay, start_fake_relay_on_ipv6_loopback,
    };
    use crate::test_support::TempDir;
    use rustls_pki_types::pem::PemObject;
    use rustls_pki_types::CertificateDer;
    use std::sync::atomic::Ordering;
    use std::time::Duration;

    fn enroll_cfg(port: u16, pin: [u8; 32], state_dir: &Path) -> EnrollConfig {
        let endpoint = format!("https://127.0.0.1:{port}");
        EnrollConfig {
            join: JoinString::new(
                format!("127.0.0.1:{port}"),
                pin,
                "tok-join-secret".to_string(),
            ),
            endpoint: endpoint.clone(),
            relay_addr: endpoint,
            tls_server_name: Some("localhost".to_string()),
            state_dir: state_dir.to_path_buf(),
            node_labels: vec![],
            facts: Facts {
                hostname: "join-test".to_string(),
                ..Default::default()
            },
        }
    }

    /// As [`enroll_cfg`], dialling the IPv6 loopback with no server name override.
    fn enroll_cfg_ipv6(port: u16, pin: [u8; 32], state_dir: &Path) -> EnrollConfig {
        let endpoint = format!("https://[::1]:{port}");
        EnrollConfig {
            join: JoinString::new(format!("[::1]:{port}"), pin, "tok-join-secret".to_string()),
            endpoint: endpoint.clone(),
            relay_addr: endpoint,
            tls_server_name: None,
            ..enroll_cfg(port, pin, state_dir)
        }
    }

    async fn enroll(cfg: &EnrollConfig) -> Result<Identity> {
        tokio::time::timeout(Duration::from_secs(20), ensure_enrolled(cfg))
            .await
            .expect("enrollment did not finish within the timeout")
    }

    // Proves DI-43, EN-7.
    #[tokio::test]
    async fn pin_match_enrolls() {
        let server = pki("localhost");
        let (port, seen) = start_fake_relay(&server, server.ca_pem.clone()).await;
        let dir = TempDir::new("join-pin-match");

        let cfg = enroll_cfg(port, sha256(&server.ca_der), dir.path());
        let id = enroll(&cfg).await.expect("a matching pin enrolls");

        assert_eq!(id.node_id, "node-join-test");
        assert_eq!(seen.enroll_calls.load(Ordering::SeqCst), 1);
        assert_eq!(
            *seen.tokens.lock().unwrap(),
            vec!["tok-join-secret".to_string()]
        );
        // The CA bundle lands in the state directory: no CA path is configured.
        let persisted = std::fs::read_to_string(dir.path().join("ca_bundle.pem")).unwrap();
        let der = CertificateDer::from_pem_slice(persisted.as_bytes()).expect("ca pem");
        assert_eq!(der.as_ref(), server.ca_der.as_slice());
        assert!(load_identity(dir.path()).unwrap().is_some());
        assert_eq!(
            load_relay_addr(dir.path()).unwrap().as_deref(),
            Some(cfg.relay_addr.as_str())
        );
    }

    // Proves DI-43, EN-7, EN-27.
    #[tokio::test]
    async fn pin_mismatch_sends_no_token() {
        let server = pki("localhost");
        let (port, seen) = start_fake_relay(&server, server.ca_pem.clone()).await;
        let dir = TempDir::new("join-pin-mismatch");

        // The pin names some other CA.
        let other = pki("localhost");
        let cfg = enroll_cfg(port, sha256(&other.ca_der), dir.path());
        let err = enroll(&cfg)
            .await
            .err()
            .expect("a pin mismatch must refuse");

        assert!(
            matches!(err, EnrollError::Pin(PinError::Mismatch)),
            "want Pin(Mismatch), got {err:?}"
        );
        assert!(!format!("{err} {err:?}").contains("tok-join-secret"));
        assert_eq!(
            seen.enroll_calls.load(Ordering::SeqCst),
            0,
            "nothing may reach Enroll before the pin matches"
        );
        assert!(seen.tokens.lock().unwrap().is_empty());
        assert!(load_identity(dir.path()).unwrap().is_none());
        assert_eq!(load_relay_addr(dir.path()).unwrap(), None);
    }

    // Proves EN-7.
    #[tokio::test]
    async fn pin_match_with_wrong_server_name_sends_no_token() {
        let server = pki("some-other-host");
        let (port, seen) = start_fake_relay(&server, server.ca_pem.clone()).await;
        let dir = TempDir::new("join-pin-wrong-name");

        let cfg = enroll_cfg(port, sha256(&server.ca_der), dir.path());
        assert!(enroll(&cfg).await.is_err());
        assert_eq!(seen.enroll_calls.load(Ordering::SeqCst), 0);
    }

    // Regression for #1187: an IPv6 literal is verified against the certificate's
    // IP SAN, by both the pinning probe and the Enroll channel.
    #[tokio::test]
    async fn ipv6_literal_relay_enrolls_by_its_ip_san_with_no_server_name() {
        let server = pki("::1");
        let Some((port, seen)) =
            start_fake_relay_on_ipv6_loopback(&server, server.ca_pem.clone()).await
        else {
            return;
        };
        let dir = TempDir::new("join-ipv6-enrolls");

        let cfg = enroll_cfg_ipv6(port, sha256(&server.ca_der), dir.path());
        enroll(&cfg)
            .await
            .expect("an IPv6 literal whose certificate names it enrolls");

        assert_eq!(seen.calls(), 1);
        assert!(load_identity(dir.path()).unwrap().is_some());
        assert_eq!(
            load_relay_addr(dir.path()).unwrap().as_deref(),
            Some(format!("https://[::1]:{port}").as_str())
        );
    }

    // Regression for #1187. The pin matches, so only the name check can refuse
    // this, and the pinning probe does: it strips the brackets and verifies the
    // name before any Enroll channel is built. It guards EN-7 for an IPv6
    // literal; the channel's own refusal is proved in tunnel.rs.
    #[tokio::test]
    async fn ipv6_literal_relay_whose_certificate_lacks_that_ip_sends_no_token() {
        let server = pki("2001:db8::1");
        let Some((port, seen)) =
            start_fake_relay_on_ipv6_loopback(&server, server.ca_pem.clone()).await
        else {
            return;
        };
        let dir = TempDir::new("join-ipv6-wrong-ip");

        let cfg = enroll_cfg_ipv6(port, sha256(&server.ca_der), dir.path());
        assert!(enroll(&cfg).await.is_err());
        assert_eq!(seen.calls(), 0);
        assert!(seen.tokens.lock().unwrap().is_empty());
        assert!(load_identity(dir.path()).unwrap().is_none());
    }

    // Proves DI-43.
    #[tokio::test]
    async fn ca_bundle_mismatch_refused() {
        let server = pki("localhost");
        let other = pki("localhost");
        // The Relay answers with a bundle that is not the CA it presented.
        let (port, seen) = start_fake_relay(&server, other.ca_pem.clone()).await;
        let dir = TempDir::new("join-bundle-mismatch");

        let cfg = enroll_cfg(port, sha256(&server.ca_der), dir.path());
        let err = enroll(&cfg)
            .await
            .err()
            .expect("a mismatched bundle must refuse");

        assert!(
            matches!(&err, EnrollError::AfterIssue(inner)
                if matches!(**inner, EnrollError::CaBundleMismatch)),
            "want AfterIssue(CaBundleMismatch), got {err:?}"
        );
        assert!(err.relay_may_have_recorded());
        assert_eq!(seen.enroll_calls.load(Ordering::SeqCst), 1);
        assert!(load_identity(dir.path()).unwrap().is_none());
        for name in ["key.pem", "cert.pem", "ca_bundle.pem", "node_id"] {
            assert!(
                !dir.path().join(name).exists(),
                "{name} must not be persisted"
            );
        }
    }

    #[test]
    fn ca_bundle_with_the_pinned_ca_and_another_is_refused() {
        let a = pki("localhost");
        let b = pki("localhost");
        let both = format!("{}{}", a.ca_pem, b.ca_pem);
        assert!(check_ca_bundle(&a.ca_pem, &a.ca_der).is_ok());
        assert!(matches!(
            check_ca_bundle(&both, &a.ca_der),
            Err(EnrollError::CaBundleMismatch)
        ));
        assert!(matches!(
            check_ca_bundle("", &a.ca_der),
            Err(EnrollError::CaBundleMismatch)
        ));
    }
}
