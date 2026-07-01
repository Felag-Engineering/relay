//! Cert renewal: schedules and performs mTLS-authenticated certificate rotation
//! over the daemon's existing Relay connection (issue #31, ADR-0006 Amendment 3).
//!
//! The daemon renews its short-lived identity certificate before expiry by
//! generating a new keypair + CSR and calling `Enrollment.Renew` over its
//! current mTLS channel. The Relay derives node_id from the verified client cert
//! (never the CSR). Renewal is jittered at 50–75% of cert lifetime so 100k+
//! nodes spread their renewals over time.

use std::future::Future;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use tonic::transport::Channel;
use tracing::{error, info};

use crate::enroll::EnrollError;
use crate::gen::{enrollment_client::EnrollmentClient, RenewRequest};
use crate::identity::{
    build_keypair_and_csr, cert_pubkey_matches_key, persist_identity, Identity, IdentityError,
};

// Renewal is triggered at a random fraction of [50%, 75%] through the cert lifetime.
// For a 336h (14-day) cert this means renewal at [168h, 252h], leaving [84h, 168h]
// (3.5–7 days) of margin for retries and fleet spread.
const RENEW_FRACTION_MIN: f64 = 0.5;
const RENEW_FRACTION_MAX: f64 = 0.75;

// FIX B (FIND-2): When the cert is already past its renewal window (overdue), spread
// the first renewal over this wider window rather than ~60 s to prevent a fleet
// that all went overdue during a single Relay outage from stampeding the Relay
// simultaneously on recovery.
const OVERDUE_JITTER_MAX_SECS: u64 = 600; // 10 minutes

// Hard ceiling for the compute_retry_backoff formula. The effective maximum produced
// by that formula is ~36 min (base 1800 s × 1.2 jitter scale), not 1 hour — this
// ceiling is never reached in practice but guards against future formula changes.
// FIX C (FIND-3): comment now agrees with the actual ~36 min effective cap.
const MAX_RETRY_BACKOFF: Duration = Duration::from_secs(3600);

/// Parses the first certificate in `cert_pem` and returns `(not_before, not_after)`
/// as `SystemTime` values.
///
/// Uses `ASN1Time::timestamp()` from x509-parser so there is no direct dependency
/// on the `time` crate in this file.
pub(crate) fn cert_validity(
    cert_pem: &str,
) -> std::result::Result<(SystemTime, SystemTime), IdentityError> {
    // Collect the first DER-encoded certificate block from the PEM.
    let der_certs: Vec<_> = rustls_pemfile::certs(&mut cert_pem.as_bytes())
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let der = der_certs.first().ok_or(IdentityError::NoCertificate)?;

    let (_, cert) = x509_parser::parse_x509_certificate(der)
        .map_err(|e| IdentityError::CertParse(format!("{e:?}")))?;

    // ASN1Time::timestamp() returns Unix seconds as i64 — no `time` crate dependency needed.
    let ts_to_system_time = |ts: i64| -> std::result::Result<SystemTime, IdentityError> {
        if ts >= 0 {
            Ok(SystemTime::UNIX_EPOCH + Duration::from_secs(ts as u64))
        } else {
            Err(IdentityError::PreEpoch { ts })
        }
    };

    let nb_ts = cert.validity().not_before.timestamp();
    let na_ts = cert.validity().not_after.timestamp();

    Ok((ts_to_system_time(nb_ts)?, ts_to_system_time(na_ts)?))
}

/// Computes how long to sleep before renewing, given cert bounds and a jitter sample.
///
/// `sample` must be in [0.0, 1.0]. A sample of 0 triggers at 50% of lifetime; 1.0
/// triggers at 75%. If the computed renewal point is already in the past, returns
/// `Duration::ZERO` so the caller proceeds immediately (with its own small jitter
/// to avoid a simultaneous herd on overdue certs).
pub(crate) fn compute_renew_delay(
    not_before: SystemTime,
    not_after: SystemTime,
    now: SystemTime,
    sample: f64,
) -> Duration {
    let total = match not_after.duration_since(not_before) {
        Ok(d) => d,
        Err(_) => return Duration::ZERO, // cert already expired or malformed
    };

    let frac = RENEW_FRACTION_MIN + sample * (RENEW_FRACTION_MAX - RENEW_FRACTION_MIN);
    let offset = total.mul_f64(frac);

    let renew_at = not_before + offset;
    renew_at.duration_since(now).unwrap_or(Duration::ZERO)
}

/// Performs a single renewal using the provided `renewer` closure (dependency-injection
/// seam for testing). Mirrors the shape of `ensure_enrolled_with` in enroll.rs.
///
/// `renewer` receives the new CSR PEM and returns `(node_id, cert_pem, ca_bundle_pem)`.
/// If `node_id` from the response does not match `current.node_id`, this function
/// logs the mismatch and returns `Err` WITHOUT writing anything to disk — the more
/// restrictive option (ADR-0006: identity = verified client cert CN, never self-reported).
pub(crate) async fn perform_renewal_with<F, Fut>(
    state_dir: &Path,
    current: &Identity,
    renewer: F,
) -> std::result::Result<Identity, EnrollError>
where
    F: FnOnce(String) -> Fut,
    Fut: Future<Output = std::result::Result<(String, String, String), EnrollError>>,
{
    let (key_pem, csr_pem) = build_keypair_and_csr()?;
    let (node_id, cert_pem, ca_bundle_pem) = renewer(csr_pem).await?;

    // Defense in depth: the Relay sets node_id from the verified TLS peer cert CN,
    // but we assert it here too. A mismatch indicates something unexpected — refuse
    // to overwrite the persisted identity with a mismatched cert.
    if node_id != current.node_id {
        error!(
            expected = %current.node_id,
            received = %node_id,
            "renewal response node_id does not match persisted node_id; refusing to persist"
        );
        return Err(EnrollError::NodeIdMismatch {
            expected: current.node_id.clone(),
            received: node_id,
        });
    }

    // FIX A (FIND-1 + FIND-3): Verify the returned cert's SubjectPublicKeyInfo
    // corresponds to the freshly generated keypair. A mismatch would mean the Relay
    // returned a cert for a different key — which would lock this Node out of mTLS.
    // Fail closed: keep the current working identity rather than persisting a broken one.
    if let Err(e) = cert_pubkey_matches_key(&cert_pem, &key_pem) {
        error!(
            error = %e,
            "renewal cert public key does not correspond to new keypair; refusing to persist"
        );
        return Err(EnrollError::Identity(e));
    }

    // If the Relay returned an empty ca_bundle, keep the current one.
    let ca_bundle = if ca_bundle_pem.is_empty() {
        current.ca_bundle_pem.clone()
    } else {
        ca_bundle_pem
    };

    let new_identity = Identity {
        node_id,
        key_pem,
        cert_pem,
        ca_bundle_pem: ca_bundle,
    };

    persist_identity(state_dir, &new_identity)?;
    Ok(new_identity)
}

/// Background renewal loop. Runs for the lifetime of the process, sleeping until
/// the cert is 50–75% through its lifetime, then calling `Enrollment.Renew` over
/// the existing mTLS channel.
///
/// On RPC failure, retries with bounded jittered backoff (~24–36 min; see
/// `compute_retry_backoff`). Never gives up while the cert still has time remaining:
/// the large renewal margin (3.5–7 days before expiry for a 14-day cert) provides
/// room for extended outages.
///
/// The renewed identity is written atomically to `state_dir` and is authoritative
/// for the next `connect_mtls` call (process restart or reconnect). The live mTLS
/// session continues with the old cert until then — TLS does not re-validate certs
/// mid-session and the renewal margin ensures no gap (ADR-0006 Amendment 3).
pub async fn run(channel: Channel, state_dir: PathBuf, mut identity: Identity) {
    loop {
        // Parse the current cert validity to compute the renewal delay.
        let validity = cert_validity(&identity.cert_pem);
        let (not_before, not_after) = match validity {
            Ok(v) => v,
            Err(e) => {
                error!(error = %e, "failed to parse cert validity; retrying in 1 hour");
                // Drop e before the await so the future remains Send.
                drop(e);
                tokio::time::sleep(MAX_RETRY_BACKOFF).await;
                continue;
            }
        };

        let now = SystemTime::now();
        let delay = compute_renew_delay(not_before, not_after, now, crate::rand_unit());

        if delay.is_zero() {
            // Already past the renewal window (e.g. after a multi-day Relay outage).
            // Spread over OVERDUE_JITTER_MAX_SECS rather than ~60 s so a fleet of
            // 100k+ nodes does not stampede the Relay simultaneously on recovery.
            let jitter =
                Duration::from_secs((crate::rand_unit() * OVERDUE_JITTER_MAX_SECS as f64) as u64);
            tokio::time::sleep(jitter).await;
        } else {
            tokio::time::sleep(delay).await;
        }

        info!(node_id = %identity.node_id, "initiating cert renewal");

        let ch = channel.clone();
        let node_id_for_closure = identity.node_id.clone();
        let result = perform_renewal_with(&state_dir, &identity, move |csr_pem| {
            let ch = ch.clone();
            let node_id = node_id_for_closure.clone();
            async move {
                let req = RenewRequest {
                    csr: csr_pem.into_bytes(),
                };
                let resp = EnrollmentClient::new(ch)
                    .renew(tonic::Request::new(req))
                    .await?
                    .into_inner();

                let cert_pem = String::from_utf8(resp.certificate)?;
                let ca_bundle_pem = String::from_utf8(resp.ca_bundle)?;

                // Sanity-check: resp.node_id should match the identity we presented.
                if !resp.node_id.is_empty() && resp.node_id != node_id {
                    return Err(EnrollError::NodeIdMismatch {
                        expected: node_id,
                        received: resp.node_id,
                    });
                }

                Ok((resp.node_id, cert_pem, ca_bundle_pem))
            }
        })
        .await;

        match result {
            Ok(new_identity) => {
                info!(node_id = %new_identity.node_id, "cert renewal successful");
                identity = new_identity;
                // Loop immediately to recompute the next delay from the fresh cert.
            }
            Err(e) => {
                // Log and back off; never give up (cert still has days of margin).
                error!(error = %e, "cert renewal failed; will retry");
                let backoff = compute_retry_backoff(crate::rand_unit());
                // Drop e before the await so the future remains Send.
                drop(e);
                tokio::time::sleep(backoff).await;
            }
        }
    }
}

/// Computes a jittered retry backoff. Base of 30 minutes with ±20% jitter;
/// effective range ~24–36 min. `sample` in [0, 1).
fn compute_retry_backoff(sample: f64) -> Duration {
    let base = Duration::from_secs(1800);
    let scale = (1.0 + 0.2 * (sample * 2.0 - 1.0)).max(0.0);
    base.mul_f64(scale).min(MAX_RETRY_BACKOFF)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::MetadataExt;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;

    use crate::enroll::EnrollError;
    use crate::identity::{load_identity, persist_identity, IdentityError};

    /// A temp dir that removes itself on drop, for test isolation.
    struct TempDir(PathBuf);
    impl TempDir {
        fn new(label: &str) -> Self {
            use std::time::{SystemTime, UNIX_EPOCH};
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let path = std::env::temp_dir().join(format!(
                "relay-renew-test-{}-{}-{}",
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

    /// Build a well-formed self-signed Identity for tests.
    fn make_test_identity(node_id: &str) -> crate::identity::Identity {
        let kp = rcgen::KeyPair::generate().expect("keygen");
        let cert_pem = rcgen::CertificateParams::new(vec![])
            .expect("params")
            .self_signed(&kp)
            .expect("self_signed")
            .pem();
        crate::identity::Identity {
            node_id: node_id.to_string(),
            key_pem: kp.serialize_pem(),
            cert_pem: cert_pem.clone(),
            ca_bundle_pem: cert_pem,
        }
    }

    /// Build a self-signed cert with rcgen that has a specific NotBefore/NotAfter,
    /// specified as Unix timestamps in seconds.
    fn make_cert_with_unix_validity(not_before_secs: i64, not_after_secs: i64) -> String {
        use rcgen::{CertificateParams, KeyPair};

        // Convert Unix seconds to time::OffsetDateTime (rcgen requires this type).
        let nb = time::OffsetDateTime::from_unix_timestamp(not_before_secs)
            .expect("valid not_before timestamp");
        let na = time::OffsetDateTime::from_unix_timestamp(not_after_secs)
            .expect("valid not_after timestamp");

        let kp = KeyPair::generate().expect("keygen");
        let mut params = CertificateParams::new(vec![]).expect("params");
        params.not_before = nb;
        params.not_after = na;
        params.self_signed(&kp).expect("self_signed").pem()
    }

    // -----------------------------------------------------------------------
    // compute_renew_delay
    // -----------------------------------------------------------------------

    #[test]
    fn compute_renew_delay_sample_zero_is_50pct() {
        let not_before = SystemTime::UNIX_EPOCH;
        let not_after = not_before + Duration::from_secs(3600); // 1h cert
        let now = not_before; // exactly at issuance

        // sample=0 → frac=0.5 → renew_at = not_before + 0.5*total = 1800s
        let delay = compute_renew_delay(not_before, not_after, now, 0.0);
        assert_eq!(
            delay,
            Duration::from_secs(1800),
            "sample=0 must give 50% point"
        );
    }

    #[test]
    fn compute_renew_delay_sample_one_is_75pct() {
        let not_before = SystemTime::UNIX_EPOCH;
        let not_after = not_before + Duration::from_secs(3600);
        let now = not_before;

        // sample=1 → frac=0.75 → renew_at = not_before + 0.75*total = 2700s
        let delay = compute_renew_delay(not_before, not_after, now, 1.0);
        assert_eq!(
            delay,
            Duration::from_secs(2700),
            "sample=1 must give 75% point"
        );
    }

    #[test]
    fn compute_renew_delay_result_within_window() {
        let not_before = SystemTime::UNIX_EPOCH;
        let not_after = not_before + Duration::from_secs(3600);
        let now = not_before;

        let min_delay = Duration::from_secs(1800); // 50%
        let max_delay = Duration::from_secs(2700); // 75%

        for sample in [0.0, 0.25, 0.5, 0.75, 1.0] {
            let delay = compute_renew_delay(not_before, not_after, now, sample);
            assert!(
                delay >= min_delay && delay <= max_delay,
                "sample={} produced delay {:?} outside [{:?}, {:?}]",
                sample,
                delay,
                min_delay,
                max_delay
            );
        }
    }

    #[test]
    fn compute_renew_delay_already_past_returns_zero() {
        let not_before = SystemTime::UNIX_EPOCH;
        let not_after = not_before + Duration::from_secs(3600);
        // now = not_after: cert is already expired — renewal window is well past
        let delay = compute_renew_delay(not_before, not_after, not_after, 0.5);
        assert_eq!(delay, Duration::ZERO, "expired cert must return zero delay");
    }

    // -----------------------------------------------------------------------
    // cert_validity
    // -----------------------------------------------------------------------

    #[test]
    fn cert_validity_round_trip() {
        // Use known timestamps well after the Unix epoch. ASN.1 time has second
        // precision, so we allow ±1s tolerance.
        let nb_secs: i64 = 1_700_000_000;
        let na_secs: i64 = 1_701_209_600;

        let cert_pem = make_cert_with_unix_validity(nb_secs, na_secs);
        let (parsed_nb, parsed_na) = cert_validity(&cert_pem).expect("cert_validity");

        let expected_nb = SystemTime::UNIX_EPOCH + Duration::from_secs(nb_secs as u64);
        let expected_na = SystemTime::UNIX_EPOCH + Duration::from_secs(na_secs as u64);

        let diff_nb = if parsed_nb > expected_nb {
            parsed_nb.duration_since(expected_nb).unwrap()
        } else {
            expected_nb.duration_since(parsed_nb).unwrap()
        };
        let diff_na = if parsed_na > expected_na {
            parsed_na.duration_since(expected_na).unwrap()
        } else {
            expected_na.duration_since(parsed_na).unwrap()
        };

        assert!(
            diff_nb <= Duration::from_secs(1),
            "not_before off by {:?}",
            diff_nb
        );
        assert!(
            diff_na <= Duration::from_secs(1),
            "not_after off by {:?}",
            diff_na
        );
    }

    // -----------------------------------------------------------------------
    // perform_renewal_with — happy path
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn perform_renewal_happy_path() {
        let dir = TempDir::new("renew-happy");
        let current = make_test_identity("node-abc-001");

        // Pre-seed the state dir with the current identity so load_identity can verify.
        persist_identity(dir.path(), &current).expect("persist current identity");

        let nid = "node-abc-001".to_string();

        // The renewer signs the CSR with a test CA so the issued cert's public key
        // corresponds to the freshly generated keypair (as a real Relay would do).
        // This is required for the pubkey correspondence check (FIX A, FIND-1+FIND-3).
        let renewed = perform_renewal_with(dir.path(), &current, move |csr_pem| async move {
            let ca_kp = rcgen::KeyPair::generate().expect("ca keygen");
            let ca_cert = rcgen::CertificateParams::new(vec![])
                .expect("ca params")
                .self_signed(&ca_kp)
                .expect("ca cert");
            let csr_params =
                rcgen::CertificateSigningRequestParams::from_pem(&csr_pem).expect("parse CSR");
            let issued = csr_params.signed_by(&ca_cert, &ca_kp).expect("sign CSR");
            Ok::<_, EnrollError>((nid, issued.pem(), ca_cert.pem()))
        })
        .await
        .expect("perform_renewal_with should succeed");

        // node_id must be unchanged.
        assert_eq!(renewed.node_id, "node-abc-001");
        // A new key must have been generated (not the same PEM as the current identity).
        assert_ne!(
            renewed.key_pem, current.key_pem,
            "renewal must generate a new keypair"
        );
        // The renewed cert must be a valid PEM certificate.
        assert!(
            renewed.cert_pem.contains("BEGIN CERTIFICATE"),
            "renewed cert_pem must be a PEM certificate block"
        );

        // Disk must reflect the new identity (and pass the pubkey check in load_identity).
        let loaded = load_identity(dir.path())
            .expect("load_identity error")
            .expect("load_identity should return Some");
        assert_eq!(loaded.node_id, "node-abc-001");
        assert_eq!(loaded.cert_pem, renewed.cert_pem);

        // key.pem must still be 0600.
        let mode = fs::metadata(dir.path().join("key.pem"))
            .expect("key.pem metadata")
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600, "key.pem must be 0600 after renewal");
    }

    // -----------------------------------------------------------------------
    // perform_renewal_with — pubkey mismatch refuses to persist (FIX A)
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn perform_renewal_pubkey_mismatch_refuses_persist() {
        let dir = TempDir::new("renew-pubkey-mismatch");
        let current = make_test_identity("node-pubkey-check");
        persist_identity(dir.path(), &current).expect("persist current identity");
        let original_cert = current.cert_pem.clone();

        // The renewer returns a cert from a DIFFERENT keypair than the one generated
        // internally by perform_renewal_with — simulates a misbehaving/compromised
        // Relay returning a cert that does not match the new keypair.
        let result = perform_renewal_with(dir.path(), &current, |_csr_pem| async move {
            let foreign_kp = rcgen::KeyPair::generate().expect("foreign keygen");
            let foreign_cert = rcgen::CertificateParams::new(vec![])
                .expect("params")
                .self_signed(&foreign_kp)
                .expect("self_signed")
                .pem();
            // Correct node_id so only the pubkey check (not the node_id check) fires.
            Ok::<_, EnrollError>((
                "node-pubkey-check".to_string(),
                foreign_cert.clone(),
                foreign_cert,
            ))
        })
        .await;

        assert!(result.is_err(), "pubkey mismatch must return Err, got Ok");
        // Avoid unwrap_err(), which requires the Ok type (Identity) to be Debug;
        // Identity intentionally does not derive Debug (it holds a private key).
        let e = match result {
            Err(e) => e,
            Ok(_) => unreachable!(),
        };
        assert!(
            matches!(&e, EnrollError::Identity(IdentityError::PubkeyMismatch)),
            "expected Identity(PubkeyMismatch) variant"
        );
        assert!(
            e.to_string().contains("public key"),
            "error must mention public key mismatch, got: {e}"
        );

        // The on-disk identity must be UNCHANGED — fail closed.
        let loaded = load_identity(dir.path())
            .expect("load_identity error")
            .expect("identity file should still exist");
        assert_eq!(
            loaded.cert_pem, original_cert,
            "on-disk cert must not change after a pubkey mismatch rejection"
        );
        assert_eq!(loaded.node_id, "node-pubkey-check");
    }

    // -----------------------------------------------------------------------
    // perform_renewal_with — node_id mismatch refuses to persist
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn perform_renewal_node_id_mismatch_refuses_persist() {
        let dir = TempDir::new("renew-mismatch");
        let current = make_test_identity("node-abc-001");
        persist_identity(dir.path(), &current).expect("persist current identity");

        // Capture the original cert PEM so we can verify the file is untouched.
        let original_cert = current.cert_pem.clone();

        let renewer_called = Arc::new(AtomicBool::new(false));
        let flag = renewer_called.clone();

        let result = perform_renewal_with(dir.path(), &current, move |_csr_pem| {
            flag.store(true, Ordering::SeqCst);
            async move {
                let kp = rcgen::KeyPair::generate().expect("keygen");
                let cert = rcgen::CertificateParams::new(vec![])
                    .expect("params")
                    .self_signed(&kp)
                    .expect("self_signed")
                    .pem();
                // Return a DIFFERENT node_id — simulates a Relay misbehaving.
                Ok::<_, EnrollError>(("node-DIFFERENT-999".to_string(), cert.clone(), cert))
            }
        })
        .await;

        assert!(result.is_err(), "node_id mismatch must return Err, got Ok");
        // Avoid unwrap_err(), which requires the Ok type (Identity) to be Debug;
        // Identity intentionally does not derive Debug (it holds a private key).
        let e = match result {
            Err(e) => e,
            Ok(_) => unreachable!(),
        };
        assert!(
            matches!(e, EnrollError::NodeIdMismatch { .. }),
            "expected NodeIdMismatch variant"
        );
        assert!(
            renewer_called.load(Ordering::SeqCst),
            "renewer should have been called"
        );

        // The on-disk identity must be UNCHANGED.
        let loaded = load_identity(dir.path())
            .expect("load_identity error")
            .expect("identity file should still exist");
        assert_eq!(
            loaded.cert_pem, original_cert,
            "on-disk cert must not change after a mismatch rejection"
        );
        assert_eq!(loaded.node_id, "node-abc-001");
    }
}
