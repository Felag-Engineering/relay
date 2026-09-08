//! Node identity primitives and shared gRPC channel builder.
//!
//! Holds the persisted identity type, crypto helpers (keypair/CSR generation,
//! SPKI correspondence check), identity load/persist helpers, and the single
//! CA-pinned `build_channel` entry point used by both the enrollment bootstrap
//! path (`enroll.rs`) and the mTLS tunnel (`tunnel.rs`).

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::Path;

use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use tonic::transport::{Certificate, Channel, ClientTlsConfig, Endpoint, Identity as TlsIdentity};

type Result<T, E = IdentityError> = std::result::Result<T, E>;

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// Typed error for identity primitives.
///
/// All variants are `Send + Sync` so `renew::run` (a `tokio::spawn`-ed task)
/// can carry them across `.await` without a `.to_string()` bridge.
#[derive(Debug, thiserror::Error)]
pub enum IdentityError {
    #[error("enroll endpoint must use https (got: {scheme})")]
    EndpointScheme { scheme: String },
    #[error(transparent)]
    Crypto(#[from] rcgen::Error),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error("PEM parse error: {0}")]
    Pem(#[from] rustls_pki_types::pem::Error),
    #[error("cert_pem contains no certificate")]
    NoCertificate,
    #[error("cert parse error: {0}")]
    CertParse(String),
    #[error("cert public key (SubjectPublicKeyInfo) does not correspond to private key")]
    PubkeyMismatch,
    #[error("certificate has a pre-epoch timestamp: {ts}")]
    PreEpoch { ts: i64 },
    #[error(transparent)]
    Channel(#[from] tonic::transport::Error),
}

/// The persisted Node identity produced by a successful enrollment.
#[derive(Clone)]
pub struct Identity {
    pub node_id: String,
    /// PKCS#8 PEM private key — never logged.
    pub key_pem: String,
    /// PEM client certificate.
    pub cert_pem: String,
    /// PEM CA bundle pinned for subsequent Relay connections.
    pub ca_bundle_pem: String,
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Returns `Ok(())` when `endpoint` begins with `"https://"`, otherwise an
/// error. Called early in `from_env`, again defensively in `call_enroll_owned`
/// (defense-in-depth), and inside `build_channel` as the authoritative
/// fail-closed guard for every gRPC connection (enrollment and mTLS tunnel).
pub(crate) fn validate_endpoint_scheme(endpoint: &str) -> Result<()> {
    if endpoint.starts_with("https://") {
        return Ok(());
    }
    let scheme = endpoint
        .find("://")
        .map(|i| &endpoint[..i])
        .unwrap_or("(none)");
    Err(IdentityError::EndpointScheme {
        scheme: scheme.to_string(),
    })
}

/// Generates an ECDSA P-256 keypair and a PEM CSR for it.
///
/// Returns `(key_pem, csr_pem)`. The CSR subject is intentionally empty:
/// the Relay CA ignores it and sets `CN = node_id` authoritatively (ADR-0006).
pub(crate) fn build_keypair_and_csr() -> Result<(String, String)> {
    let key_pair = rcgen::KeyPair::generate()?;
    let mut params = rcgen::CertificateParams::new(vec![])?;
    params.distinguished_name = rcgen::DistinguishedName::new();
    let csr = params.serialize_request(&key_pair)?;
    Ok((key_pair.serialize_pem(), csr.pem()?))
}

/// Verifies that `cert_pem`'s SubjectPublicKeyInfo (SPKI) corresponds to the private key
/// in `key_pem` by comparing their raw SPKI DER bytes.
///
/// A mismatch indicates a torn-write (crash between the key.pem and cert.pem atomic
/// renames) or a misbehaving/compromised Relay that returned a cert whose public key
/// does not match the freshly generated keypair. Either way the caller must fail closed —
/// do not use a mismatched identity for a TLS handshake that would fail silently.
pub(crate) fn cert_pubkey_matches_key(cert_pem: &str, key_pem: &str) -> Result<()> {
    // rcgen loads the private key and returns its SubjectPublicKeyInfo as DER bytes.
    let kp = rcgen::KeyPair::from_pem(key_pem)?;
    let key_spki_der = kp.public_key_der();

    // x509-parser parses the cert and exposes the raw SPKI DER via .raw (RFC 5280 §4.1).
    let ders: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(cert_pem.as_bytes())
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let der = ders.first().ok_or(IdentityError::NoCertificate)?;
    let (_, cert) = x509_parser::parse_x509_certificate(der)
        .map_err(|e| IdentityError::CertParse(format!("{e:?}")))?;
    let cert_spki_raw = cert.tbs_certificate.subject_pki.raw;

    if key_spki_der.as_slice() != cert_spki_raw {
        return Err(IdentityError::PubkeyMismatch);
    }
    Ok(())
}

/// Checks whether a valid persisted identity exists in `dir`.
///
/// Returns `Some(Identity)` only if all four files (`key.pem`, `cert.pem`,
/// `ca_bundle.pem`, `node_id`) exist and both the cert and key parse
/// successfully via `rustls_pki_types`. "Valid" means present-and-well-formed;
/// expiry checking is a separate ROADMAP item (v0.0.2 cert rotation).
///
/// Returns `Err` if the cert's public key does not correspond to the private key,
/// converting a torn-write lockout into a diagnosable error (FIX A, FIND-1).
pub fn load_identity(dir: &Path) -> Result<Option<Identity>> {
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

    // cert.pem must contain at least one parseable DER certificate block. A
    // malformed block surfaces as an Err from the iterator and is treated as
    // "no valid identity here" (re-enroll), matching the prior rustls_pemfile
    // behaviour where an unreadable cert yielded nothing.
    let certs = CertificateDer::pem_slice_iter(cert_pem.as_bytes())
        .collect::<std::result::Result<Vec<_>, _>>()
        .unwrap_or_default();
    if certs.is_empty() {
        return Ok(None);
    }

    // key.pem must contain a parseable private key. Absent or unreadable is,
    // likewise, "no valid identity" rather than a hard error — the caller then
    // enrolls fresh (the same outcome rustls_pemfile's `None` produced).
    if PrivateKeyDer::from_pem_slice(key_pem.as_bytes()).is_err() {
        return Ok(None);
    }

    // FIX A (FIND-1): Verify the cert's SPKI corresponds to the private key.
    // A crash between the individual key.pem/cert.pem atomic renames leaves
    // new-key+old-cert (or old-key+new-cert) on disk; rather than silently
    // presenting a broken identity to TLS, return a clear error here.
    cert_pubkey_matches_key(&cert_pem, &key_pem)?;

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
pub(crate) fn persist_identity(dir: &Path, id: &Identity) -> Result<()> {
    // Create the state dir (mode 0700) if it doesn't exist yet.
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)?;

    write_atomic(dir, "key.pem", id.key_pem.as_bytes(), 0o600)?;
    write_atomic(dir, "cert.pem", id.cert_pem.as_bytes(), 0o644)?;
    write_atomic(dir, "ca_bundle.pem", id.ca_bundle_pem.as_bytes(), 0o644)?;
    write_atomic(dir, "node_id", id.node_id.as_bytes(), 0o644)?;

    // fsync the directory so the four renames above are themselves durable.
    // Each write_atomic fsync'd its file's *contents* before renaming; this
    // fsyncs the *directory entry* changes. Without it, a power loss after
    // persist_identity returns could still lose a rename — leaving an
    // incomplete identity that load_identity treats as "no identity" and
    // re-enrolls, or (across two files) a torn pair. See write_atomic.
    fsync_dir(dir)?;

    Ok(())
}

/// fsyncs a directory so that name changes within it (creations, renames) are
/// durable. Opening a directory read-only and calling `sync_all` on the handle
/// is the portable POSIX way to flush directory metadata.
fn fsync_dir(dir: &Path) -> Result<()> {
    // O_RDONLY is the correct and only portable mode for a directory fd.
    let d = OpenOptions::new().read(true).open(dir)?;
    d.sync_all()?;
    Ok(())
}

/// Writes `content` to `dir/name` atomically **and durably** with the given
/// Unix permission mode.
///
/// Creates a `.tmp` sibling (removing any stale leftover from a previous crashed
/// run first) with `O_CREAT|O_EXCL`, writes content, **fsyncs the file**, then
/// renames into place. The mode is applied at creation so the file is never
/// briefly visible with wrong permissions.
///
/// `mode` is a **ceiling, deliberately left umask-masked.** `OpenOptions::mode`
/// is masked by the process umask, so a stricter umask lands a stricter file —
/// the safe direction for all four identity files, and left alone on purpose.
/// Do **not** add a umask-proof `set_permissions` call after it. That is the
/// flat prohibition of ADR-0036: `chmod` is not umask-masked, so it overrides
/// the operator on their own Node, and node code never does that — not even
/// where the declared mode is tight enough that forcing it could only tighten
/// (the narrower rule this file used to cite, superseded with the three sites
/// that relied on it). Here the looser direction is immediate anyway: forcing
/// `0644` would hand an operator running `umask 077` a world-readable
/// `cert.pem`. The tests assert the direction (no bit beyond the declared mode,
/// and the security-relevant bits clear), never exact equality; asserting
/// equality is what would make the suite umask-dependent and push its "fix"
/// in the loosening direction.
///
/// The fsync before the rename is the load-bearing part for durability: without
/// it, on a crash the filesystem may make the rename durable while the file's
/// *contents* are still only in the page cache — the classic "zero-length file
/// after power loss" trap. fsyncing first guarantees that if the renamed name
/// is visible after a crash, its bytes are on disk too. The caller
/// (persist_identity) then fsyncs the directory to make the rename itself
/// durable.
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
        // Flush contents to disk BEFORE the rename, not after — see the doc
        // comment. sync_all is fsync(2): data + inode metadata.
        f.sync_all()?;
    }

    fs::rename(&tmp_path, &final_path)?;
    Ok(())
}

/// Builds a CA-pinned gRPC channel to the Relay. `ca_pem` is the sole trust
/// root (no system roots — tonic `tls` feature only, ADR-0005 invariant #6).
/// When `client_identity` is `Some`, the channel presents a client cert (mTLS
/// Tunnel/renew path); when `None`, it is the certless enrollment bootstrap
/// path (ADR-0006 §2). `connect()` is eager so a wrong-CA Relay is refused at
/// handshake, not on first RPC. Fails closed on any non-`https://` endpoint.
pub(crate) async fn build_channel(
    endpoint: String,
    domain: Option<String>,
    ca_pem: &[u8],
    client_identity: Option<TlsIdentity>,
) -> Result<Channel> {
    validate_endpoint_scheme(&endpoint)?;
    let mut tls = ClientTlsConfig::new().ca_certificate(Certificate::from_pem(ca_pem));
    if let Some(id) = client_identity {
        tls = tls.identity(id);
    }
    if let Some(d) = domain {
        tls = tls.domain_name(d);
    }
    Ok(Endpoint::from_shared(endpoint)?
        .tls_config(tls)?
        .connect()
        .await?)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// Test-only permission assertions shared by `identity.rs`, `enroll.rs` and
/// `dedup.rs` — the one Rust shape for this check, so a third is not invented
/// (ADR-0036; its Go counterpart is `assertModeWithin` in `relay/internal/ca`).
///
/// Every declared mode in node code is a **ceiling**, not an exact value (see
/// `write_atomic`), so these check the two properties that are
/// actually load-bearing: no bit set beyond the declared mode (a regression
/// that *widens* a file — a forced `set_permissions`, a dropped `.mode()`, a
/// looser constant — fails under every umask), and the security-relevant bits
/// clear outright.
///
/// The second check is not redundant with the first: the declared ceiling is
/// passed in by the caller, so it survives being edited. The forbidden-bit
/// floor is what still fails if someone widens `persist_identity` *and* raises
/// the ceiling here to match.
///
/// Callers pass the ceiling as a **literal, never the production constant**:
/// derived from the constant it rises in lockstep with any edit to it, and the
/// check can then never fail on a widened one (#509, ADR-0036).
#[cfg(test)]
pub(crate) mod mode_assert {
    use std::os::unix::fs::MetadataExt;
    use std::path::Path;

    /// Asserts `path` carries no permission bit beyond `declared`, and none of
    /// `forbidden`.
    pub(crate) fn assert_within(path: &Path, declared: u32, forbidden: u32, what: &str) {
        let mode = std::fs::metadata(path)
            .unwrap_or_else(|e| panic!("stat {}: {}", path.display(), e))
            .mode()
            & 0o777;
        assert_eq!(
            mode & !declared & 0o777,
            0,
            "{} must be no looser than {:04o} (the umask may tighten it, nothing may \
             widen it) — got {:04o}",
            what,
            declared,
            mode
        );
        assert_eq!(
            mode & forbidden,
            0,
            "{} must have none of {:04o} set — got {:04o}",
            what,
            forbidden,
            mode
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    // Compile-time Send+Sync assertion for IdentityError.
    fn _assert_identity_error_send_sync() {
        fn _assert<T: Send + Sync>() {}
        _assert::<IdentityError>();
    }

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
    /// `load_identity`'s PEM validation passes.
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
        assert!(
            matches!(err, IdentityError::EndpointScheme { .. }),
            "expected EndpointScheme variant, got: {:?}",
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
        assert!(
            matches!(err, IdentityError::EndpointScheme { .. }),
            "expected EndpointScheme variant, got: {:?}",
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
        assert!(
            matches!(err, IdentityError::EndpointScheme { .. }),
            "expected EndpointScheme variant, got: {:?}",
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

        // File permission checks (Unix mode bits). The declared modes are
        // ceilings, not exact values: the process umask may tighten them and
        // nothing may widen them (see write_atomic).
        //
        // key.pem — declared 0600, and never readable by group or world.
        mode_assert::assert_within(&dir.path().join("key.pem"), 0o600, 0o077, "key.pem");
        // cert.pem / ca_bundle.pem / node_id are public material (a
        // certificate, a CA bundle, an identifier) — declared 0644, and never
        // writable by group or world.
        for name in ["cert.pem", "ca_bundle.pem", "node_id"] {
            mode_assert::assert_within(&dir.path().join(name), 0o644, 0o022, name);
        }

        // No .tmp siblings survive a clean persist: every temp file was
        // renamed into place, so a torn write is only ever possible mid-crash,
        // never as steady state.
        for name in ["key.pem", "cert.pem", "ca_bundle.pem", "node_id"] {
            let tmp = dir.path().join(format!("{}.tmp", name));
            assert!(
                !tmp.exists(),
                "{}.tmp must not survive a clean persist",
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

    // Durability path (FIND #341): persist_identity fsyncs each file before
    // renaming and fsyncs the directory afterward. A unit test cannot observe
    // fsync (it needs a power-loss fault injector), so this exercises the two
    // properties that ARE observable: fsync_dir succeeds against a real
    // directory, and a persist immediately followed by an independent reopen
    // reads the exact bytes back. It is a guard against the durability path
    // regressing into an error rather than a proof of crash-safety.
    #[test]
    fn persist_fsyncs_without_error_and_reloads() {
        let dir = TempDir::new("persist-durable");
        let id = make_test_identity().expect("make_test_identity");

        // persist_identity creates the directory, so it must run before
        // fsync_dir can be exercised on it (TempDir::new only computes a path).
        persist_identity(dir.path(), &id).expect("persist_identity");

        // fsync_dir against the now-existing directory must succeed — the same
        // call persist_identity makes internally.
        fsync_dir(dir.path()).expect("fsync_dir on a real directory");

        // Re-read through the public API rather than the in-memory Identity,
        // so we exercise the on-disk bytes the fsync path just committed.
        let reloaded = load_identity(dir.path())
            .expect("load after durable persist")
            .expect("identity present");
        assert_eq!(reloaded.cert_pem, id.cert_pem);
        assert_eq!(reloaded.key_pem, id.key_pem);
    }

    // -----------------------------------------------------------------------
    // FIX A (FIND-1): load_identity with mismatched key/cert returns Err
    // -----------------------------------------------------------------------

    #[test]
    fn load_identity_key_cert_mismatch_returns_err() {
        let dir = TempDir::new("key-cert-mismatch");

        // kp1's private key + kp2's self-signed cert → mismatched pair.
        // Simulates a torn-write where a crash left new-key and old-cert on disk.
        let kp1 = rcgen::KeyPair::generate().expect("keygen1");
        let kp2 = rcgen::KeyPair::generate().expect("keygen2");
        let cert2 = rcgen::CertificateParams::new(vec![])
            .expect("params")
            .self_signed(&kp2)
            .expect("cert2");

        let id = Identity {
            node_id: "node-mismatch-test".to_string(),
            key_pem: kp1.serialize_pem(),
            cert_pem: cert2.pem(),
            ca_bundle_pem: cert2.pem(),
        };
        persist_identity(dir.path(), &id).expect("persist mismatched identity");

        let result = load_identity(dir.path());
        assert!(
            result.is_err(),
            "load_identity with mismatched key/cert must return Err"
        );
        let e = match result {
            Err(e) => e,
            Ok(_) => unreachable!(),
        };
        assert!(
            matches!(&e, IdentityError::PubkeyMismatch),
            "expected PubkeyMismatch variant, got: {:?}",
            e
        );
        assert!(
            e.to_string().contains("public key"),
            "error must mention public key mismatch, got: {e}"
        );
    }
}

/// Compile-time guarantee that the secret-bearing `Identity` (which holds
/// the Node PKCS#8 private key in `key_pem`) never derives `Debug`. The
/// manual `NoDebug` impl below conflicts (E0119) with the blanket impl the
/// instant `Identity` gains a `Debug` impl, turning a silent secret-leak
/// regression into a build failure. Pins the ADR-0006 "never logged"
/// guarantee at the type level (issue #222).
#[cfg(test)]
mod no_debug_guard {
    use super::Identity;
    use std::fmt::Debug;

    trait NoDebug {}
    impl<T: Debug> NoDebug for T {}
    impl NoDebug for Identity {}

    fn assert_no_debug<T: NoDebug>() {}

    #[test]
    fn identity_does_not_derive_debug() {
        assert_no_debug::<Identity>();
    }
}
