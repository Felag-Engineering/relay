//! Bootstrap enrollment: generates an ECDSA P-256 keypair + CSR, calls the Relay's
//! `Enrollment.Enroll` RPC over CA-pinned server-authenticated TLS, and persists
//! the returned identity. Idempotent: a re-run on an already-enrolled Node is a
//! no-op (ADR-0006).

use std::fs::{self, OpenOptions};
use std::future::Future;
use std::io::Write;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use tonic::transport::{Certificate, Channel, ClientTlsConfig};
use tracing::info;

use crate::gen::{enrollment_client::EnrollmentClient, EnrollRequest, Facts, Label};

type Result<T, E = Box<dyn std::error::Error>> = std::result::Result<T, E>;

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// The persisted Node identity produced by a successful enrollment.
pub struct Identity {
    pub node_id: String,
    /// PKCS#8 PEM private key — never logged.
    pub key_pem: String,
    /// PEM client certificate.
    pub cert_pem: String,
    /// PEM CA bundle pinned for subsequent Relay connections.
    pub ca_bundle_pem: String,
}

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
        let state_dir = PathBuf::from(
            std::env::var("RELAY_STATE_DIR")
                .unwrap_or_else(|_| "/var/lib/relay-daemon".to_string()),
        );
        let node_labels = std::env::var("RELAY_NODE_LABELS")
            .map(|v| parse_node_labels(&v))
            .unwrap_or_default();

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

/// Returns `Ok(())` when `endpoint` begins with `"https://"`, otherwise an
/// error. Called early in `from_env` and again defensively in
/// `call_enroll_owned` so there is no path to building a plaintext gRPC
/// channel regardless of how `EnrollConfig` was constructed.
fn validate_endpoint_scheme(endpoint: &str) -> Result<()> {
    if endpoint.starts_with("https://") {
        return Ok(());
    }
    let scheme = endpoint
        .find("://")
        .map(|i| &endpoint[..i])
        .unwrap_or("(none)");
    Err(format!("enroll endpoint must use https (got: {})", scheme).into())
}

/// Parses a comma-separated `key=value` label list into bare pairs, stripping
/// any `node:` prefix that would otherwise be double-applied at send time.
/// Malformed or empty entries are silently skipped.
fn parse_node_labels(raw: &str) -> Vec<(String, String)> {
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

/// Generates an ECDSA P-256 keypair and a PEM CSR for it.
///
/// Returns `(key_pem, csr_pem)`. The CSR subject is intentionally empty:
/// the Relay CA ignores it and sets `CN = node_id` authoritatively (ADR-0006).
fn build_keypair_and_csr() -> Result<(String, String)> {
    let key_pair = rcgen::KeyPair::generate()?;
    let mut params = rcgen::CertificateParams::new(vec![])?;
    params.distinguished_name = rcgen::DistinguishedName::new();
    let csr = params.serialize_request(&key_pair)?;
    Ok((key_pair.serialize_pem(), csr.pem()?))
}

/// Checks whether a valid persisted identity exists in `dir`.
///
/// Returns `Some(Identity)` only if all four files (`key.pem`, `cert.pem`,
/// `ca_bundle.pem`, `node_id`) exist and both the cert and key parse
/// successfully via `rustls_pemfile`. "Valid" means present-and-well-formed;
/// expiry checking is a separate ROADMAP item (v0.0.2 cert rotation).
fn load_identity(dir: &Path) -> Result<Option<Identity>> {
    let key_path = dir.join("key.pem");
    let cert_path = dir.join("cert.pem");
    let ca_bundle_path = dir.join("ca_bundle.pem");
    let node_id_path = dir.join("node_id");

    // All four files must be present for a complete identity.
    for p in [&key_path, &cert_path, &ca_bundle_path, &node_id_path] {
        if !p.exists() {
            return Ok(None);
        }
    }

    let key_pem = fs::read_to_string(&key_path)?;
    let cert_pem = fs::read_to_string(&cert_path)?;
    let ca_bundle_pem = fs::read_to_string(&ca_bundle_path)?;
    let node_id = fs::read_to_string(&node_id_path)?.trim().to_string();

    // cert.pem must contain at least one parseable DER certificate block.
    let mut cert_reader = cert_pem.as_bytes();
    let certs: Vec<_> =
        rustls_pemfile::certs(&mut cert_reader).collect::<std::result::Result<Vec<_>, _>>()?;
    if certs.is_empty() {
        return Ok(None);
    }

    // key.pem must contain a parseable private key.
    let mut key_reader = key_pem.as_bytes();
    if rustls_pemfile::private_key(&mut key_reader)?.is_none() {
        return Ok(None);
    }

    Ok(Some(Identity {
        node_id,
        key_pem,
        cert_pem,
        ca_bundle_pem,
    }))
}

/// Persists an `Identity` to `dir` with restrictive Unix permissions.
///
/// File modes: `key.pem` → 0600 (private key), all others → 0644.
/// The directory is created at mode 0700 if absent.
/// Each file is written atomically: a `.tmp` sibling with the target mode is
/// written first, then renamed into place.
fn persist_identity(dir: &Path, id: &Identity) -> Result<()> {
    // Create the state dir (mode 0700) if it doesn't exist yet.
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)?;

    write_atomic(dir, "key.pem", id.key_pem.as_bytes(), 0o600)?;
    write_atomic(dir, "cert.pem", id.cert_pem.as_bytes(), 0o644)?;
    write_atomic(dir, "ca_bundle.pem", id.ca_bundle_pem.as_bytes(), 0o644)?;
    write_atomic(dir, "node_id", id.node_id.as_bytes(), 0o644)?;

    Ok(())
}

/// Writes `content` to `dir/name` atomically with the given Unix permission mode.
///
/// Creates a `.tmp` sibling (removing any stale leftover from a previous crashed
/// run first) with `O_CREAT|O_EXCL`, writes content, then renames into place.
/// The mode is applied at creation so the file is never briefly visible with
/// wrong permissions.
fn write_atomic(dir: &Path, name: &str, content: &[u8], mode: u32) -> Result<()> {
    let tmp_path = dir.join(format!("{}.tmp", name));
    let final_path = dir.join(name);

    // Remove any stale .tmp left by a previous crashed run (best-effort).
    let _ = fs::remove_file(&tmp_path);

    {
        let mut f = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(mode)
            .open(&tmp_path)?;
        f.write_all(content)?;
    }

    fs::rename(&tmp_path, &final_path)?;
    Ok(())
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

    let mut tls = ClientTlsConfig::new().ca_certificate(Certificate::from_pem(&ca_bytes));
    if let Some(domain) = relay_domain {
        tls = tls.domain_name(domain);
    }

    let channel = Channel::from_shared(endpoint)?
        .tls_config(tls)?
        .connect()
        .await?;

    let self_labels: Vec<Label> = node_labels
        .iter()
        .map(|(k, v)| Label {
            // Re-apply the "node:" prefix enforced by handler.go:77 (ADR-0006
            // two-namespace invariant: a daemon can never inject relay: labels).
            key: format!("node:{}", k),
            value: v.clone(),
        })
        .collect();

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
    persist_identity(state_dir, &identity)?;
    info!(node_id = %node_id, hostname, label_count, "enrollment complete");
    Ok(identity)
}

/// Performs the enrollment bootstrap step for this Node.
///
/// Idempotent: if a valid identity is already on disk in `cfg.state_dir`, returns
/// it immediately without generating a new CSR or contacting the Relay.
/// mTLS Tunnel connect is out of scope here (#28).
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
    // validate_endpoint_scheme
    // -----------------------------------------------------------------------

    #[test]
    fn endpoint_scheme_accepts_https() {
        assert!(validate_endpoint_scheme("https://relay.example.com:7654").is_ok());
        assert!(validate_endpoint_scheme("https://127.0.0.1:7654").is_ok());
    }

    #[test]
    fn endpoint_scheme_rejects_http() {
        let err = validate_endpoint_scheme("http://relay.example.com:7654")
            .expect_err("http:// must be rejected");
        assert!(
            err.to_string().contains("http"),
            "error message should mention the bad scheme, got: {}",
            err
        );
    }

    #[test]
    fn endpoint_scheme_rejects_no_scheme() {
        let err = validate_endpoint_scheme("relay.example.com:7654")
            .expect_err("schemeless endpoint must be rejected");
        assert!(
            err.to_string().contains("none"),
            "error message should say (none) for a schemeless endpoint, got: {}",
            err
        );
    }

    #[test]
    fn endpoint_scheme_rejects_grpc_scheme() {
        // grpc:// (or any non-https scheme) must also be rejected.
        let err =
            validate_endpoint_scheme("grpc://relay:7654").expect_err("grpc:// must be rejected");
        assert!(
            err.to_string().contains("grpc"),
            "error message should mention the bad scheme, got: {}",
            err
        );
    }

    // -----------------------------------------------------------------------
    // build_keypair_and_csr
    // -----------------------------------------------------------------------

    #[test]
    fn build_keypair_and_csr_shape() {
        let (key_pem, csr_pem) = build_keypair_and_csr().expect("keypair+csr generation failed");
        assert!(
            key_pem.starts_with("-----BEGIN PRIVATE KEY-----"),
            "key_pem should be PKCS#8 PEM, got: {:.60}",
            key_pem
        );
        assert!(
            csr_pem.contains("BEGIN CERTIFICATE REQUEST"),
            "csr_pem should be a CSR PEM block, got: {:.60}",
            csr_pem
        );
    }

    // -----------------------------------------------------------------------
    // persist_identity + file modes + load round-trip
    // -----------------------------------------------------------------------

    #[test]
    fn persist_and_load_round_trip() {
        let dir = TempDir::new("persist");
        let id = make_test_identity().expect("make_test_identity");

        persist_identity(dir.path(), &id).expect("persist_identity");

        // All four files must exist.
        for name in ["key.pem", "cert.pem", "ca_bundle.pem", "node_id"] {
            assert!(dir.path().join(name).exists(), "{} must exist", name);
        }

        // File permission checks (Unix mode bits).
        assert_eq!(
            fs::metadata(dir.path().join("key.pem")).unwrap().mode() & 0o777,
            0o600,
            "key.pem must be 0600"
        );
        for name in ["cert.pem", "ca_bundle.pem", "node_id"] {
            assert_eq!(
                fs::metadata(dir.path().join(name)).unwrap().mode() & 0o777,
                0o644,
                "{} must be 0644",
                name
            );
        }

        // load_identity must return the same Identity byte-for-byte.
        let loaded = load_identity(dir.path())
            .expect("load_identity should not error")
            .expect("load_identity should return Some");
        assert_eq!(loaded.node_id, id.node_id);
        assert_eq!(loaded.key_pem, id.key_pem);
        assert_eq!(loaded.cert_pem, id.cert_pem);
        assert_eq!(loaded.ca_bundle_pem, id.ca_bundle_pem);
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

        // Build a canned valid cert using rcgen so load_identity validation passes.
        let kp = rcgen::KeyPair::generate().expect("keygen");
        let canned_cert = rcgen::CertificateParams::new(vec![])
            .expect("params")
            .self_signed(&kp)
            .expect("self_signed")
            .pem();
        let canned_ca = canned_cert.clone();
        let canned_node_id = "node-fresh-001122".to_string();

        let nid = canned_node_id.clone();
        let cert = canned_cert.clone();
        let ca = canned_ca.clone();

        let result = ensure_enrolled_with(dir.path(), "test-host", 2, move |_csr_pem| async move {
            Ok((nid, cert, ca))
        })
        .await
        .expect("ensure_enrolled_with should succeed");

        assert_eq!(result.node_id, canned_node_id);
        assert_eq!(result.cert_pem, canned_cert);

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

        // load_identity must see the freshly written identity.
        let loaded = load_identity(dir.path())
            .expect("load_identity error")
            .expect("load_identity should return Some");
        assert_eq!(loaded.node_id, canned_node_id);
    }
}
