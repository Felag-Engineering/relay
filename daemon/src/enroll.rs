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
    validate_endpoint_scheme, Identity,
};

type Result<T, E = Box<dyn std::error::Error>> = std::result::Result<T, E>;

/// Configuration for the enrollment bootstrap step, read from environment variables.
///
/// Constructed via `from_env`; returns `None` when enrollment is not configured,
/// leaving the existing Tunnel path intact.
pub struct EnrollConfig {
    /// Enrollment Token — never logged.
    pub token: String,
    /// gRPC endpoint of the Relay's Enrollment service (e.g. `https://relay:7654`).
    pub endpoint: String,
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
/// default `/var/lib/relay-daemon`. Used by both `EnrollConfig::from_env`
/// (enrollment bootstrap) and `main` (Tunnel identity load) so the two paths
/// always agree on the state directory without a second read.
pub fn state_dir_from_env() -> PathBuf {
    PathBuf::from(
        std::env::var("RELAY_STATE_DIR").unwrap_or_else(|_| "/var/lib/relay-daemon".to_string()),
    )
}

impl EnrollConfig {
    /// Reads enrollment configuration from environment variables.
    ///
    /// Returns `Ok(None)` when `RELAY_ENROLLMENT_TOKEN` or
    /// `RELAY_CA_BUNDLE_PATH` are absent or empty, so callers can skip the
    /// enrollment step and fall through to the existing Tunnel path.
    ///
    /// Environment keys:
    /// - `RELAY_ENROLLMENT_TOKEN` — required; never logged
    /// - `RELAY_ENROLL_ENDPOINT`  — default: derive `https://` from `RELAY_ADDR`
    /// - `RELAY_DOMAIN`           — optional TLS SNI override
    /// - `RELAY_CA_BUNDLE_PATH`   — required; path to pinned bootstrap CA
    /// - `RELAY_STATE_DIR`        — default: `/var/lib/relay-daemon`
    /// - `RELAY_NODE_LABELS`      — comma-separated `key=value` pairs
    pub fn from_env() -> Result<Option<EnrollConfig>> {
        let token = match std::env::var("RELAY_ENROLLMENT_TOKEN") {
            Ok(v) if !v.is_empty() => v,
            _ => return Ok(None),
        };
        let ca_bundle_str = match std::env::var("RELAY_CA_BUNDLE_PATH") {
            Ok(v) if !v.is_empty() => v,
            _ => return Ok(None),
        };

        let relay_addr =
            std::env::var("RELAY_ADDR").unwrap_or_else(|_| "http://127.0.0.1:7654".to_string());
        let endpoint = std::env::var("RELAY_ENROLL_ENDPOINT")
            .unwrap_or_else(|_| relay_addr.replacen("http://", "https://", 1));

        // Fail closed: TLS (and therefore CA pinning) is only active when the
        // scheme is exactly "https". An "http://" endpoint silently skips TLS
        // in tonic, exposing the enrollment token and the Node's pinned trust
        // root to a MITM.
        validate_endpoint_scheme(&endpoint)?;

        let relay_domain = std::env::var("RELAY_DOMAIN").ok();
        let state_dir = state_dir_from_env();
        let node_labels = node_labels_from_env();

        let hostname = std::env::var("HOSTNAME").unwrap_or_else(|_| "unknown-node".to_string());
        let facts = Facts {
            hostname,
            os: std::env::consts::OS.to_string(),
            arch: std::env::consts::ARCH.to_string(),
            kernel: String::new(),
            ip_addresses: vec![],
        };

        Ok(Some(EnrollConfig {
            token,
            endpoint,
            relay_domain,
            ca_bundle_path: PathBuf::from(ca_bundle_str),
            state_dir,
            node_labels,
            facts,
        }))
    }
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Reads `RELAY_NODE_LABELS` from the environment and returns bare (key, value)
/// pairs. The `node:` prefix is stripped here and re-applied at send time by
/// `node_labels_to_proto`, so there is exactly one prefixing site.
pub(crate) fn node_labels_from_env() -> Vec<(String, String)> {
    std::env::var("RELAY_NODE_LABELS")
        .map(|v| parse_node_labels(&v))
        .unwrap_or_default()
}

/// Converts bare (key, value) label pairs to proto Labels, adding the mandatory
/// `node:` prefix. This is the single prefixing site for node-space labels
/// (ADR-0006 two-namespace invariant: a daemon can never inject relay: labels).
pub(crate) fn node_labels_to_proto(labels: &[(String, String)]) -> Vec<Label> {
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
    hostname: &str,
    label_count: usize,
    enroller: F,
) -> Result<Identity>
where
    F: FnOnce(String) -> Fut,
    Fut: Future<Output = Result<(String, String, String)>>,
{
    if let Some(identity) = load_identity(state_dir)? {
        info!(node_id = %identity.node_id, hostname, "already enrolled, reusing persisted identity");
        return Ok(identity);
    }

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
    persist_identity(state_dir, &identity)?;
    info!(node_id = %node_id, hostname, label_count, "enrollment complete");
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
    use crate::identity::{load_identity, persist_identity, Identity};
    use std::os::unix::fs::MetadataExt;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;

    // A temp dir that removes itself on drop, for test isolation.
    struct TempDir(PathBuf);
    impl TempDir {
        fn new(label: &str) -> Self {
            use std::time::{SystemTime, UNIX_EPOCH};
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let path = std::env::temp_dir().join(format!(
                "relay-test-{}-{}-{}",
                label,
                std::process::id(),
                nanos
            ));
            TempDir(path)
        }
        fn path(&self) -> &Path {
            &self.0
        }
    }
    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    /// Build a well-formed self-signed Identity using rcgen, so that
    /// `load_identity`'s `rustls_pemfile` validation passes.
    fn make_test_identity() -> Result<Identity> {
        let kp = rcgen::KeyPair::generate()?;
        let cert_pem = rcgen::CertificateParams::new(vec![])?
            .self_signed(&kp)?
            .pem();
        Ok(Identity {
            node_id: "node-test-aabbccdd".to_string(),
            key_pem: kp.serialize_pem(),
            cert_pem: cert_pem.clone(),
            ca_bundle_pem: cert_pem,
        })
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
        let id = make_test_identity().expect("make_test_identity");
        persist_identity(dir.path(), &id).expect("persist_identity");

        let enroller_called = Arc::new(AtomicBool::new(false));
        let flag = enroller_called.clone();

        let result = ensure_enrolled_with(dir.path(), "test-host", 0, move |_csr_pem| {
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
        let result = ensure_enrolled_with(dir.path(), "test-host", 2, move |csr_pem| async move {
            let ca_kp = rcgen::KeyPair::generate().expect("ca keygen");
            let ca_cert = rcgen::CertificateParams::new(vec![])
                .expect("ca params")
                .self_signed(&ca_kp)
                .expect("ca cert");
            let csr_params =
                rcgen::CertificateSigningRequestParams::from_pem(&csr_pem).expect("parse CSR");
            let issued = csr_params.signed_by(&ca_cert, &ca_kp).expect("sign CSR");
            Ok((nid, issued.pem(), ca_cert.pem()))
        })
        .await
        .expect("ensure_enrolled_with should succeed");

        assert_eq!(result.node_id, canned_node_id);
        assert!(
            result.cert_pem.contains("BEGIN CERTIFICATE"),
            "cert_pem must be a valid PEM certificate block"
        );

        // Files must be persisted with correct permissions.
        assert_eq!(
            fs::metadata(dir.path().join("key.pem")).unwrap().mode() & 0o777,
            0o600,
            "key.pem must be 0600 after fresh enroll"
        );
        for name in ["cert.pem", "ca_bundle.pem", "node_id"] {
            assert_eq!(
                fs::metadata(dir.path().join(name)).unwrap().mode() & 0o777,
                0o644,
                "{} must be 0644 after fresh enroll",
                name
            );
        }

        // load_identity must see the freshly written identity (key/cert match passes).
        let loaded = load_identity(dir.path())
            .expect("load_identity error")
            .expect("load_identity should return Some");
        assert_eq!(loaded.node_id, canned_node_id);
    }

    #[tokio::test]
    async fn fresh_enroll_fails_closed_on_key_cert_mismatch() {
        let dir = TempDir::new("fresh-mismatch");

        // A misbehaving/compromised Relay returns a certificate whose public key
        // does NOT correspond to the key the daemon just generated. Enrollment must
        // fail closed BEFORE persisting anything — parity with the renewal path,
        // which already enforces this (see perform_renewal_with in renew.rs).
        let result = ensure_enrolled_with(dir.path(), "test-host", 0, move |_csr_pem| async move {
            // Cert for an unrelated keypair, ignoring the daemon's CSR.
            let other_kp = rcgen::KeyPair::generate().expect("other keygen");
            let other_cert = rcgen::CertificateParams::new(vec![])
                .expect("other params")
                .self_signed(&other_kp)
                .expect("other cert")
                .pem();
            Ok(("node-mismatch".to_string(), other_cert.clone(), other_cert))
        })
        .await;

        assert!(
            result.is_err(),
            "a cert whose SPKI does not match the generated key must fail closed"
        );
        // Nothing may be written to disk on a failed enrollment.
        assert!(
            !dir.path().join("key.pem").exists(),
            "no key.pem may be persisted when enrollment fails closed"
        );
        assert!(
            load_identity(dir.path())
                .expect("load_identity error")
                .is_none(),
            "no identity may be persisted when enrollment fails closed"
        );
    }
}
