//! Bootstrap enrollment: generates an ECDSA P-256 keypair + CSR, calls the Relay's
//! `Enrollment.Enroll` RPC over CA-pinned server-authenticated TLS, and persists
//! the returned identity. Idempotent: a re-run on an already-enrolled Node is a
//! no-op (ADR-0006).

use std::fs;
use std::future::Future;
use std::path::{Path, PathBuf};

use tracing::info;

use crate::gen::{enrollment_client::EnrollmentClient, EnrollRequest, Facts, Label};
use crate::identity::{
    build_channel, build_keypair_and_csr, cert_pubkey_matches_key, load_identity, persist_identity,
    persist_relay_addr, validate_endpoint_scheme, validate_relay_addr, Identity, IdentityError,
};
use crate::log_field;

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
}

// Manual From impl because #[from] on Box<tonic::Status> would generate
// From<Box<tonic::Status>>, not From<tonic::Status>.
impl From<tonic::Status> for EnrollError {
    fn from(s: tonic::Status) -> Self {
        EnrollError::Rpc(Box::new(s))
    }
}

/// Configuration for the enrollment bootstrap step. Constructed by the bin's
/// `config::enroll_config`; that returns `None` when enrollment is not
/// configured, leaving the existing Tunnel path intact.
pub struct EnrollConfig {
    /// Enrollment Token — never logged.
    pub token: String,
    /// gRPC endpoint of the Relay's Enrollment service (e.g. `https://relay:7654`).
    pub endpoint: String,
    /// Node-plane Relay address persisted with the identity at enrollment
    /// (ADR-0031 decision 4); the Tunnel's dial target, not the enrollment endpoint.
    pub relay_addr: String,
    /// TLS SNI server name override for cert verification (optional).
    pub relay_domain: Option<String>,
    /// Path to the pinned CA PEM bundle used to authenticate the Relay at bootstrap.
    pub ca_bundle_path: PathBuf,
    /// Directory where key.pem, cert.pem, ca_bundle.pem, and node_id are persisted.
    pub state_dir: PathBuf,
    /// Node-space labels (bare `key=value`; `node:` prefix is added at send time).
    pub node_labels: Vec<(String, String)>,
    /// Facts gathered from the local environment.
    pub facts: Facts,
}

/// Returns the daemon's state directory: `RELAY_STATE_DIR` env var or the
/// default `/var/lib/relay-daemon`. Called by `Config::from_env` so that
/// enrollment bootstrap and the Tunnel identity load always agree on the
/// state directory without a second env read.
pub fn state_dir_from_env() -> PathBuf {
    PathBuf::from(
        std::env::var("RELAY_STATE_DIR").unwrap_or_else(|_| "/var/lib/relay-daemon".to_string()),
    )
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
pub(crate) fn parse_node_labels(raw: &str) -> Vec<(String, String)> {
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

/// Calls the Relay's `Enrollment.Enroll` RPC over CA-pinned server-authenticated
/// TLS. No client certificate is used — this is the certless bootstrap path
/// (ADR-0006 §2). Bootstrap trust is pinned to `ca_bundle_path`; there is no
/// trust-on-first-use.
///
/// Takes all config as owned values so callers can move-capture from `EnrollConfig`
/// without lifetime issues.
async fn call_enroll_owned(
    endpoint: String,
    token: String,
    relay_domain: Option<String>,
    ca_bundle_path: PathBuf,
    node_labels: Vec<(String, String)>,
    facts: Facts,
    csr_pem: String,
) -> Result<(String, String, String)> {
    // Defense-in-depth: re-validate even if the caller bypassed from_env.
    validate_endpoint_scheme(&endpoint)?;

    let ca_bytes = fs::read(&ca_bundle_path)?;
    let channel = build_channel(endpoint, relay_domain, &ca_bytes, None).await?;

    let self_labels = node_labels_to_proto(&node_labels);

    let req = EnrollRequest {
        enrollment_token: token,
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
    let cert_pem = String::from_utf8(resp.certificate)?;
    let ca_bundle_pem = String::from_utf8(resp.ca_bundle)?;

    Ok((resp.node_id, cert_pem, ca_bundle_pem))
}

/// Orchestrates enrollment, separated from the RPC for testability.
///
/// If a valid identity is already persisted in `state_dir`, returns it immediately
/// without generating a CSR or contacting the Relay. Otherwise: generates a
/// keypair + CSR, calls `enroller(csr_pem)`, persists the returned identity.
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
    cert_pubkey_matches_key(&identity.cert_pem, &identity.key_pem)?;
    // Address first, then identity: every identity this code persists has an
    // address. The already-enrolled branch above never writes it (no backfill; DI-38).
    persist_relay_addr(state_dir, relay_addr)?;
    persist_identity(state_dir, &identity)?;
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
    let token = cfg.token.clone();
    let relay_domain = cfg.relay_domain.clone();
    let ca_bundle_path = cfg.ca_bundle_path.clone();
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
                token,
                relay_domain,
                ca_bundle_path,
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

    #[test]
    fn parse_labels_skips_empty_and_garbage() {
        // "=bad" has empty key → skipped; empty comma entries → skipped.
        let labels = parse_node_labels(",=bad,,env=staging,");
        assert_eq!(labels, vec![("env".to_string(), "staging".to_string())]);
    }

    // -----------------------------------------------------------------------
    // Idempotency: pre-written identity → enroller is NOT called
    // -----------------------------------------------------------------------

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
            matches!(&e, EnrollError::Identity(IdentityError::PubkeyMismatch)),
            "expected Identity(PubkeyMismatch) variant"
        );
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
